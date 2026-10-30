#include "3gpp/emergency/IceAgent.hpp"
#include "3gpp/common/ByteStream.hpp"
#include <random>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace gpp::emergency {

// ============================================================================
// IceCandidate Implementation
// ============================================================================

std::string IceCandidate::to_sdp() const {
    // a=candidate:<foundation> <component> <transport> <priority> <ip> <port> typ <type>
    // [raddr <rel-addr> rport <rel-port>] [tcptype <tcptype>]
    std::ostringstream oss;
    oss << "a=candidate:" << foundation << " " << component_id << " "
        << (transport == IceTransport::UDP ? "UDP" : "TCP") << " "
        << priority << " ";

    if (address.family == StunAddressFamily::IPv4) {
        oss << static_cast<int>(address.addr[12]) << "."
            << static_cast<int>(address.addr[13]) << "."
            << static_cast<int>(address.addr[14]) << "."
            << static_cast<int>(address.addr[15]);
    } else {
        // IPv6 - simplified
        oss << "::1";
    }
    oss << " " << address.port << " typ ";

    switch (type) {
        case IceCandidateType::Host: oss << "host"; break;
        case IceCandidateType::ServerReflexive: oss << "srflx"; break;
        case IceCandidateType::PeerReflexive: oss << "prflx"; break;
        case IceCandidateType::Relayed: oss << "relay"; break;
    }

    if (type == IceCandidateType::ServerReflexive || type == IceCandidateType::Relayed) {
        oss << " raddr " << related_address << " rport " << related_port;
    }

    if (transport == IceTransport::TCP && !transport_addr.empty()) {
        oss << " tcptype " << transport_addr;
    }

    return oss.str();
}

std::optional<IceCandidate> IceCandidate::from_sdp(const std::string& sdp_line) {
    // Parse "a=candidate:..." line
    if (sdp_line.rfind("a=candidate:", 0) != 0) return std::nullopt;

    IceCandidate cand;
    std::istringstream iss(sdp_line.substr(12)); // Skip "a=candidate:"

    std::string transport_str, type_str;
    iss >> cand.foundation >> cand.component_id >> transport_str >> cand.priority;

    std::string ip_str, typ_keyword;
    iss >> ip_str >> cand.address.port >> typ_keyword >> type_str;

    // typ_keyword should be "typ"
    (void)typ_keyword; // Suppress unused warning

    // Parse type string to enum
    if (type_str == "host") cand.type = IceCandidateType::Host;
    else if (type_str == "srflx") cand.type = IceCandidateType::ServerReflexive;
    else if (type_str == "prflx") cand.type = IceCandidateType::PeerReflexive;
    else if (type_str == "relay") cand.type = IceCandidateType::Relayed;

    // Parse IP
    if (ip_str.find(':') != std::string::npos) {
        cand.address.family = StunAddressFamily::IPv6;
        // Simplified - would need full IPv6 parsing
    } else {
        cand.address.family = StunAddressFamily::IPv4;
        // Parse IPv4
        int a, b, c, d;
        if (sscanf(ip_str.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
            cand.address.addr.fill(0);
            cand.address.addr[12] = a;
            cand.address.addr[13] = b;
            cand.address.addr[14] = c;
            cand.address.addr[15] = d;
        }
    }

    // Parse raddr/rport if present
    std::string token;
    while (iss >> token) {
        if (token == "raddr") iss >> cand.related_address;
        else if (token == "rport") iss >> cand.related_port;
        else if (token == "tcptype") iss >> cand.transport_addr;
    }

    return cand;
}

uint32_t IceCandidate::compute_priority(IceCandidateType type, uint16_t local_pref, uint8_t component_id) {
    uint32_t type_pref = 0;
    switch (type) {
        case IceCandidateType::Host: type_pref = 126; break;
        case IceCandidateType::ServerReflexive: type_pref = 110; break;
        case IceCandidateType::PeerReflexive: type_pref = 110; break;
        case IceCandidateType::Relayed: type_pref = 0; break;
    }
    return (type_pref << 24) | (static_cast<uint32_t>(local_pref) << 8) | (256 - component_id);
}

// ============================================================================
// IceAgent Implementation
// ============================================================================

IceAgent::IceAgent(const IceConfig& config, IceCallbacks callbacks)
    : config_(config), callbacks_(std::move(callbacks)) {
    // Generate ufrag/pwd if not provided
    if (config_.ufrag.empty() || config_.pwd.empty()) {
        auto creds = ice_sdp::generate_credentials();
        if (config_.ufrag.empty()) config_.ufrag = creds.first;
        if (config_.pwd.empty()) config_.pwd = creds.second;
    }
    // Generate tie-breaker for controlling role
    if (config_.role == IceRole::Controlling && config_.tie_breaker == 0) {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        config_.tie_breaker = gen();
    }
}

void IceAgent::start_gathering() {
    state_ = State::Gathering;
    gathering_start_time_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    gather_host_candidates();
    gather_srflx_candidates();
    gather_relay_candidates();

    // Transition to checking after gathering timeout or all candidates gathered
    // In real implementation, this would be async
}

void IceAgent::handle_stun_message(const StunXorAddress& src, const StunMessage& msg) {
    if (msg.header.msg_type == StunMessageType::BindingRequest) {
        handle_check_request(src, msg);
    } else if (msg.header.is_response()) {
        handle_check_response(src, msg);
    }
}

void IceAgent::handle_channel_data(uint16_t channel, const std::vector<uint8_t>& data) {
    // Handle TURN channel data - forward to application
}

void IceAgent::add_remote_candidate(const IceCandidate& candidate) {
    remote_candidates_.push_back(candidate);
    callbacks_.on_remote_candidate(candidate);

    // If we have both local and remote candidates, form checklist
    if (!local_candidates_.empty() && !remote_candidates_.empty() && state_ == State::Gathering) {
        form_checklist();
    }
}

void IceAgent::set_remote_credentials(const std::string& ufrag, const std::string& pwd) {
    remote_ufrag_ = ufrag;
    remote_pwd_ = pwd;

    // If checklist already formed, start checks
    if (state_ == State::Checking) {
        schedule_checks();
    }
}

std::optional<CandidatePair> IceAgent::get_nominated_pair() const {
    return nominated_pair_;
}

void IceAgent::tick(uint64_t now_ms) {
    last_tick_ = now_ms;

    switch (state_) {
        case State::Gathering: {
            if (now_ms - gathering_start_time_ > config_.gathering_timeout_ms) {
                form_checklist();
                state_ = State::Checking;
                schedule_checks();
            }
            break;
        }
        case State::Checking: {
            // Check for timed-out checks
            for (auto& pair : checklist_) {
                if (pair.check_state == IceCheckState::InProgress &&
                    now_ms - pair.last_check_time > config_.check_interval_ms * 2) {
                    // Retry
                    if (pair.retry_count < 7) {
                        send_check(pair);
                        pair.retry_count++;
                    } else {
                        pair.check_state = IceCheckState::Failed;
                        pair.state = IcePairState::Failed;
                    }
                }
            }

            // Check if all checks done
            bool all_done = true;
            for (const auto& pair : checklist_) {
                if (pair.state == IcePairState::Waiting || pair.state == IcePairState::InProgress) {
                    all_done = false;
                    break;
                }
            }

            if (all_done) {
                if (nominated_pair_) {
                    state_ = State::Completed;
                    callbacks_.on_nominated(*nominated_pair_);
                } else {
                    state_ = State::Failed;
                    callbacks_.on_failed("No nominated pair found");
                }
            }
            break;
        }
        case State::Completed:
        case State::Failed:
            break;
    }
}

void IceAgent::gather_host_candidates() {
    // In real implementation, enumerate local interfaces
    // For demo, add a single host candidate
    IceCandidate host;
    host.foundation = "1";
    host.component_id = 1;
    host.transport = IceTransport::UDP;
    host.address = StunXorAddress::from_ipv4(0x7F000001, 5000); // 127.0.0.1:5000
    host.type = IceCandidateType::Host;
    host.priority = IceCandidate::compute_priority(IceCandidateType::Host, 65535, 1);
    host.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    local_candidates_.push_back(host);
    callbacks_.on_local_candidate(host);
}

void IceAgent::gather_srflx_candidates() {
    if (config_.stun_server.hostname.empty()) return;

    // In real implementation, send STUN Binding Request to STUN server
    // For demo, simulate a server-reflexive candidate
    IceCandidate srflx;
    srflx.foundation = "1";
    srflx.component_id = 1;
    srflx.transport = IceTransport::UDP;
    srflx.address = StunXorAddress::from_ipv4(0xC0A80001, 6000); // 192.168.0.1:6000 (simulated public IP)
    srflx.type = IceCandidateType::ServerReflexive;
    srflx.related_address = "127.0.0.1";
    srflx.related_port = 5000;
    srflx.priority = IceCandidate::compute_priority(IceCandidateType::ServerReflexive, 65534, 1);
    srflx.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    local_candidates_.push_back(srflx);
    callbacks_.on_local_candidate(srflx);
}

void IceAgent::gather_relay_candidates() {
    if (config_.turn_server.hostname.empty()) return;

    // In real implementation, use TURN Allocate to get relayed address
    // For demo, simulate a relayed candidate
    IceCandidate relay;
    relay.foundation = "1";
    relay.component_id = 1;
    relay.transport = IceTransport::UDP;
    relay.address = StunXorAddress::from_ipv4(0xAC100064, 50000); // 172.16.0.100:50000 (TURN relay)
    relay.type = IceCandidateType::Relayed;
    relay.related_address = "192.168.0.1";
    relay.related_port = 6000;
    relay.priority = IceCandidate::compute_priority(IceCandidateType::Relayed, 65533, 1);
    relay.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    local_candidates_.push_back(relay);
    callbacks_.on_local_candidate(relay);
}

void IceAgent::form_checklist() {
    checklist_.clear();

    for (const auto& local : local_candidates_) {
        for (const auto& remote : remote_candidates_) {
            if (local.component_id != remote.component_id) continue;
            if (local.transport != remote.transport) continue;

            CandidatePair pair;
            pair.local = local;
            pair.remote = remote;
            pair.state = IcePairState::Frozen;
            pair.check_state = IceCheckState::Waiting;
            pair.priority = compute_pair_priority(local, remote);

            checklist_.push_back(pair);
        }
    }

    prioritize_checklist();
}

void IceAgent::prioritize_checklist() {
    std::sort(checklist_.begin(), checklist_.end(),
              [](const CandidatePair& a, const CandidatePair& b) {
                  return a.priority > b.priority;
              });

    // Unfreeze first pair for each foundation
    std::map<std::string, bool> foundation_unfrozen;
    for (auto& pair : checklist_) {
        std::string foundation = pair.local.foundation + "-" + pair.remote.foundation;
        if (!foundation_unfrozen[foundation]) {
            pair.state = IcePairState::Waiting;
            pair.check_state = IceCheckState::Waiting;
            foundation_unfrozen[foundation] = true;
        }
    }
}

void IceAgent::schedule_checks() {
    for (auto& pair : checklist_) {
        if (pair.state == IcePairState::Waiting && checks_in_progress_ < 3) {
            send_check(pair);
            checks_in_progress_++;
        }
    }
}

void IceAgent::send_check(const CandidatePair& pair) {
    StunMessage msg;
    msg.header.msg_type = StunMessageType::BindingRequest;
    msg.header.transaction_id = generate_transaction_id();

    // Add ICE credentials
    msg.add_username(remote_ufrag_ + ":" + config_.ufrag);
    msg.add_priority(pair.priority);

    if (config_.role == IceRole::Controlling) {
        msg.add_ice_controlling(config_.tie_breaker);
        msg.add_use_candidate(); // Controlling nominates
    } else {
        msg.add_ice_controlled(config_.tie_breaker);
    }

    msg.add_fingerprint();

    // Send via callback
    callbacks_.on_send_stun(pair.remote.address, msg.encode());

    // Update pair state
    auto it = std::find_if(checklist_.begin(), checklist_.end(),
                          [&pair](const CandidatePair& p) {
                              return p.local.address.addr == pair.local.address.addr &&
                                     p.local.address.port == pair.local.address.port &&
                                     p.remote.address.addr == pair.remote.address.addr &&
                                     p.remote.address.port == pair.remote.address.port;
                          });
    if (it != checklist_.end()) {
        it->check_state = IceCheckState::InProgress;
        it->last_check_time = last_tick_;
    }
    checks_in_progress_--;
}

void IceAgent::handle_check_response(const StunXorAddress& src, const StunMessage& resp) {
    auto pair_ptr = find_pair(src, resp.get_xor_mapped_address().value_or(StunXorAddress{}));
    if (!pair_ptr) return;

    CandidatePair* pair = *pair_ptr;

    if (resp.header.msg_type == StunMessageType::BindingResponse) {
        pair->check_state = IceCheckState::Succeeded;
        pair->state = IcePairState::Succeeded;

        // Check for nomination
        if (resp.has_use_candidate()) {
            nominate_pair(*pair);
        }
    } else {
        pair->check_state = IceCheckState::Failed;
        pair->state = IcePairState::Failed;
    }

    // Unfreeze next pairs with same foundation
    std::string foundation = pair->local.foundation + "-" + pair->remote.foundation;
    for (auto& p : checklist_) {
        if (p.state == IcePairState::Frozen) {
            std::string pf = p.local.foundation + "-" + p.remote.foundation;
            if (pf == foundation) {
                p.state = IcePairState::Waiting;
                p.check_state = IceCheckState::Waiting;
            }
        }
    }

    schedule_checks();
}

void IceAgent::handle_check_request(const StunXorAddress& src, const StunMessage& req) {
    // Find or create pair for this request
    auto mapped = req.get_xor_mapped_address();
    if (!mapped) return;

    auto pair_ptr = find_pair(*mapped, src);
    CandidatePair* pair = nullptr;

    if (pair_ptr) {
        pair = *pair_ptr;
    } else {
        // Create new peer-reflexive pair
        CandidatePair new_pair;
        // Find local candidate that matches mapped address
        for (const auto& local : local_candidates_) {
            if (local.address.port == mapped->port) {
                new_pair.local = local;
                break;
            }
        }
        new_pair.remote.address = src;
        new_pair.remote.component_id = 1;
        new_pair.remote.transport = IceTransport::UDP;
        new_pair.remote.type = IceCandidateType::PeerReflexive;
        new_pair.state = IcePairState::Waiting;
        new_pair.check_state = IceCheckState::Waiting;
        new_pair.priority = compute_pair_priority(new_pair.local, new_pair.remote);

        checklist_.push_back(new_pair);
        pair = &checklist_.back();
    }

    // Send response
    StunMessage resp = StunMessage::create_binding_response(req, pair->local.address);
    resp.add_fingerprint();
    callbacks_.on_send_stun(src, resp.encode());
}

void IceAgent::nominate_pair(CandidatePair& pair) {
    nominated_pair_ = pair;
    pair.state = IcePairState::Succeeded;
    pair.nominated_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void IceAgent::handle_nomination(const StunMessage& msg, CandidatePair& pair) {
    if (msg.has_use_candidate()) {
        nominate_pair(pair);
    }
}

std::optional<CandidatePair*> IceAgent::find_pair(const StunXorAddress& local, const StunXorAddress& remote) {
    for (auto& pair : checklist_) {
        if (pair.local.address.port == local.port &&
            pair.remote.address.port == remote.port) {
            return &pair;
        }
    }
    return std::nullopt;
}

uint64_t IceAgent::compute_pair_priority(const IceCandidate& local, const IceCandidate& remote) const {
    uint64_t G = local.priority;
    uint64_t D = remote.priority;
    uint64_t min_p = std::min(G, D);
    uint64_t max_p = std::max(G, D);
    return (min_p << 32) + (max_p << 1) + (G > D ? 1 : 0);
}

std::array<uint8_t, 12> IceAgent::generate_transaction_id() {
    std::array<uint8_t, 12> tid{};
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX);
    uint64_t v1 = dist(gen);
    uint32_t v2 = static_cast<uint32_t>(dist(gen));
    std::memcpy(tid.data(), &v1, 8);
    std::memcpy(tid.data() + 8, &v2, 4);
    return tid;
}

// ============================================================================
// ICE SDP Helpers Implementation
// ============================================================================

std::pair<std::string, std::string> ice_sdp::generate_credentials() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint32_t> dist32(0, UINT32_MAX);
    std::uniform_int_distribution<uint64_t> dist64(0, UINT64_MAX);

    // ufrag: 4+ chars, base64-ish
    std::string ufrag;
    const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 8; ++i) {
        ufrag += chars[dist32(gen) % 64];
    }

    // pwd: 22+ chars
    std::string pwd;
    for (int i = 0; i < 24; ++i) {
        pwd += chars[dist32(gen) % 64];
    }

    return {ufrag, pwd};
}

std::vector<IceCandidate> ice_sdp::parse_remote_candidates(const std::string& sdp) {
    std::vector<IceCandidate> candidates;
    std::istringstream iss(sdp);
    std::string line;
    while (std::getline(iss, line)) {
        if (auto cand = IceCandidate::from_sdp(line)) {
            candidates.push_back(*cand);
        }
    }
    return candidates;
}

std::string ice_sdp::generate_candidate_sdp(const std::vector<IceCandidate>& candidates,
                                             const std::string& ufrag,
                                             const std::string& pwd) {
    std::ostringstream oss;
    oss << "a=ice-ufrag:" << ufrag << "\r\n";
    oss << "a=ice-pwd:" << pwd << "\r\n";
    for (const auto& cand : candidates) {
        oss << cand.to_sdp() << "\r\n";
    }
    return oss.str();
}

std::string ice_sdp::generate_ice_media_section(const std::vector<IceCandidate>& candidates,
                                                 const std::string& ufrag,
                                                 const std::string& pwd,
                                                 const std::string& mid) {
    std::ostringstream oss;
    oss << "m=audio 9 RTP/SAVPF 0 8 101\r\n"; // Port 9 = discard (ICE will use different port)
    oss << "a=mid:" << mid << "\r\n";
    oss << "a=ice-ufrag:" << ufrag << "\r\n";
    oss << "a=ice-pwd:" << pwd << "\r\n";
    oss << "a=fingerprint:sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00\r\n";
    oss << "a=setup:actpass\r\n";
    for (const auto& cand : candidates) {
        oss << cand.to_sdp() << "\r\n";
    }
    return oss.str();
}

} // namespace gpp::emergency