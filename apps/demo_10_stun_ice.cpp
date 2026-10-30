#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <array>
#include <string>
#include <map>
#include <functional>
#include <atomic>

#include "3gpp/common/Logger.hpp"
#include "3gpp/common/PcapWriter.hpp"
#include "3gpp/common/ByteStream.hpp"
#include "3gpp/ip/IpAddress.hpp"
#include "3gpp/ip/Ipv4Header.hpp"
#include "3gpp/ip/UdpPacket.hpp"
#include "3gpp/ip/Socket.hpp"

#include "3gpp/emergency/StunMessage.hpp"
#include "3gpp/emergency/TurnMessage.hpp"
#include "3gpp/emergency/IceAgent.hpp"
#include "3gpp/emergency/EmergencySession.hpp"
#include "3gpp/emergency/EmergencyTypes.hpp"

using namespace gpp;
using namespace gpp::emergency;

static void dump_stun_to_pcap(common::PcapWriter& pcap,
                               const ip::Ipv4Address& src_ip, uint16_t src_port,
                               const ip::Ipv4Address& dst_ip, uint16_t dst_port,
                               const std::vector<uint8_t>& payload) {
    ip::Ipv4Header ip_hdr;
    ip_hdr.src_ip = src_ip;
    ip_hdr.dst_ip = dst_ip;
    ip_hdr.protocol = 17; // UDP

    ip::UdpPacket udp;
    udp.src_port = src_port;
    udp.dst_port = dst_port;
    udp.set_payload(payload);

    common::ByteStreamWriter writer;
    ip_hdr.total_length = static_cast<uint16_t>(20 + udp.length);
    ip_hdr.encode(writer);
    udp.encode(writer, &ip_hdr.src_ip, &ip_hdr.dst_ip);

    pcap.write_ipv4(writer.data());
}

// ============================================================================
// Simple STUN Server for demo
// ============================================================================
class StunServer {
public:
    StunServer(uint16_t port) : port_(port) {}

    void run() {
        ip::UdpSocket sock;
        if (!sock.bind("127.0.0.1", port_)) {
            GPP_LOG_ERROR("STUN_SRV", "Failed to bind to port " + std::to_string(port_));
            return;
        }
        GPP_LOG_INFO("STUN_SRV", "STUN Server listening on 127.0.0.1:" + std::to_string(port_));

        std::array<uint8_t, 2048> buf{};
        std::string client_host;
        uint16_t client_port = 0;

        while (running_) {
            ssize_t n = sock.recv_from(buf, client_host, client_port, 100);
            if (n > 0) {
                std::span<const uint8_t> data(buf.data(), static_cast<size_t>(n));
                auto msg = StunMessage::decode(data);
                if (msg) {
                    handle_request(sock, client_host, client_port, *msg);
                }
            }
        }
    }

    void stop() { running_ = false; }

private:
    uint16_t port_;
    std::atomic<bool> running_{true};

    void handle_request(ip::UdpSocket& sock, const std::string& client_host, uint16_t client_port, const StunMessage& req) {
        if (req.header.msg_type == StunMessageType::BindingRequest) {
            // Create response with XOR-MAPPED-ADDRESS
            StunXorAddress mapped = StunXorAddress::from_ipv4(0x7F000001, client_port); // 127.0.0.1
            StunMessage resp = StunMessage::create_binding_response(req, mapped);
            auto resp_bytes = resp.encode_with_fingerprint();

            sock.send_to(resp_bytes, client_host, client_port);
            GPP_LOG_INFO("STUN_SRV", "Sent Binding Response to " + client_host + ":" + std::to_string(client_port));
        }
        else if (req.header.msg_type == StunMessageType::AllocateRequest) {
            // TURN Allocate - create relay allocation
            StunXorAddress relayed = StunXorAddress::from_ipv4(0xC0A80064, 50000); // 192.168.0.100:50000
            StunXorAddress mapped = StunXorAddress::from_ipv4(0x7F000001, client_port);

            StunMessage resp;
            resp.header.msg_type = StunMessageType::AllocateResponse;
            resp.header.transaction_id = req.header.transaction_id;
            resp.add_xor_relayed_address(relayed);
            resp.add_xor_mapped_address(mapped);
            resp.add_lifetime(600);
            resp.add_fingerprint();

            auto resp_bytes = resp.encode();
            sock.send_to(resp_bytes, client_host, client_port);
            GPP_LOG_INFO("STUN_SRV", "Sent Allocate Response (relay=192.168.0.100:50000)");
        }
        else if (req.header.msg_type == StunMessageType::RefreshRequest) {
            StunMessage resp;
            resp.header.msg_type = StunMessageType::RefreshResponse;
            resp.header.transaction_id = req.header.transaction_id;
            resp.add_lifetime(600);
            resp.add_fingerprint();

            auto resp_bytes = resp.encode();
            sock.send_to(resp_bytes, client_host, client_port);
        }
        else if (req.header.msg_type == StunMessageType::CreatePermissionRequest) {
            StunMessage resp;
            resp.header.msg_type = StunMessageType::CreatePermissionResponse;
            resp.header.transaction_id = req.header.transaction_id;
            resp.add_fingerprint();

            auto resp_bytes = resp.encode();
            sock.send_to(resp_bytes, client_host, client_port);
        }
        else if (req.header.msg_type == StunMessageType::ChannelBindRequest) {
            StunMessage resp;
            resp.header.msg_type = StunMessageType::ChannelBindResponse;
            resp.header.transaction_id = req.header.transaction_id;
            resp.add_fingerprint();

            auto resp_bytes = resp.encode();
            sock.send_to(resp_bytes, client_host, client_port);
        }
    }
};

// ============================================================================
// ICE Agent Demo Helper
// ============================================================================
class IceDemoAgent {
public:
    IceDemoAgent(const std::string& name, IceRole role, const StunServerConfig& stun_config)
        : name_(name), role_(role) {

        IceConfig config;
        config.role = role;
        config.stun_server = stun_config;

        // Callbacks
        IceCallbacks callbacks;
        callbacks.on_local_candidate = [this](const IceCandidate& cand) {
            GPP_LOG_INFO(name_ + "_ICE", "Local candidate: " + cand.to_sdp());
            local_candidates_.push_back(cand);
        };
        callbacks.on_remote_candidate = [this](const IceCandidate& cand) {
            GPP_LOG_INFO(name_ + "_ICE", "Remote candidate: " + cand.to_sdp());
            remote_candidates_.push_back(cand);
        };
        callbacks.on_nominated = [this](const CandidatePair& pair) {
            GPP_LOG_INFO(name_ + "_ICE", "NOMINATED pair: " +
                           pair.local.address.to_string() + " <-> " + pair.remote.address.to_string());
            nominated_pair_ = pair;
        };
        callbacks.on_failed = [this](const std::string& reason) {
            GPP_LOG_ERROR(name_ + "_ICE", "ICE failed: " + reason);
        };
        callbacks.on_send_stun = [this](const StunXorAddress& dst, const std::vector<uint8_t>& data) {
            // In real implementation, send via UDP socket
            GPP_LOG_INFO(name_ + "_ICE", "Send STUN to " + dst.to_string() + " (" + std::to_string(data.size()) + " bytes)");
            // Simulate network delivery
            if (peer_agent_) {
                peer_agent_->inject_stun(dst, data);
            }
        };

        agent_ = std::make_unique<IceAgent>(config, std::move(callbacks));
    }

    void set_peer(IceDemoAgent* peer) { peer_agent_ = peer; }
    void start() { agent_->start_gathering(); }
    void inject_stun(const StunXorAddress& src, const std::vector<uint8_t>& data) {
        auto msg = StunMessage::decode(data);
        if (msg) agent_->handle_stun_message(src, *msg);
    }
    void add_remote_candidate(const IceCandidate& cand) { agent_->add_remote_candidate(cand); }
    void set_remote_credentials(const std::string& ufrag, const std::string& pwd) { agent_->set_remote_credentials(ufrag, pwd); }
    void tick(uint64_t now_ms) { agent_->tick(now_ms); }
    IceAgent::State state() const { return agent_->state(); }
    const std::vector<IceCandidate>& local_candidates() const { return local_candidates_; }
    std::optional<CandidatePair> nominated_pair() const { return nominated_pair_; }

private:
    std::string name_;
    IceRole role_;
    std::unique_ptr<IceAgent> agent_;
    IceDemoAgent* peer_agent_{nullptr};
    std::vector<IceCandidate> local_candidates_;
    std::vector<IceCandidate> remote_candidates_;
    std::optional<CandidatePair> nominated_pair_;
};

// ============================================================================
// Main Demo
// ============================================================================
int main() {
    common::Logger::instance().set_level(common::LogLevel::DEBUG);
    GPP_LOG_INFO("MAIN", "==================================================================");
    GPP_LOG_INFO("MAIN", " 3GPP Test Suite - Lesson 10: STUN/TURN/ICE + SOS Emergency ");
    GPP_LOG_INFO("MAIN", "==================================================================");

    common::PcapWriter pcap("output_10_stun_ice.pcap");

    // -----------------------------------------------------------------------
    // Part 1: STUN Binding Request/Response
    // -----------------------------------------------------------------------
    GPP_LOG_INFO("MAIN", "\n=== Part 1: STUN Binding Request/Response (RFC 5389) ===");

    // Start STUN server in background
    StunServer stun_server(3478);
    std::thread stun_thread([&]() { stun_server.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Client sends STUN Binding Request
    ip::UdpSocket client_sock;
    client_sock.bind("127.0.0.1", 0);
    uint16_t client_port = client_sock.local_port();
    GPP_LOG_INFO("CLIENT", "STUN Client on port " + std::to_string(client_port));

    StunMessage binding_req = StunMessage::create_binding_request({0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C});
    auto req_bytes = binding_req.encode_with_fingerprint();

    GPP_LOG_INFO("CLIENT", "Sending STUN Binding Request");
    client_sock.send_to(req_bytes, "127.0.0.1", 3478);
    dump_stun_to_pcap(pcap, ip::Ipv4Address(127,0,0,1), client_port, ip::Ipv4Address(127,0,0,1), 3478, req_bytes);

    // Receive response
    std::array<uint8_t, 2048> buf{};
    std::string server_host;
    uint16_t server_port = 0;
    ssize_t n = client_sock.recv_from(buf, server_host, server_port, 2000);
    if (n > 0) {
        std::vector<uint8_t> resp_data(buf.begin(), buf.begin() + n);
        dump_stun_to_pcap(pcap, ip::Ipv4Address(127,0,0,1), 3478, ip::Ipv4Address(127,0,0,1), client_port, resp_data);

        auto resp = StunMessage::decode(resp_data);
        if (resp) {
            auto xor_addr = resp->get_xor_mapped_address();
            if (xor_addr) {
                GPP_LOG_INFO("CLIENT", "Received Binding Response: Mapped Address = " + xor_addr->to_string());
            }
            GPP_LOG_INFO("CLIENT", "Fingerprint valid: " + std::string(resp->verify_fingerprint() ? "YES" : "NO"));
        }
    }

    stun_server.stop();
    stun_thread.join();

    // -----------------------------------------------------------------------
    // Part 2: TURN Allocate / Channel Bind
    // -----------------------------------------------------------------------
    GPP_LOG_INFO("MAIN", "\n=== Part 2: TURN Allocate & Channel Bind (RFC 8656) ===");

    TurnServerConfig turn_config;
    turn_config.hostname = "127.0.0.1";
    turn_config.port = 3478;
    turn_config.realm = "turn.example.com";
    turn_config.username = "user1";
    turn_config.password = "pass123";

    TurnClient turn_client(turn_config);

    // Allocate
    StunMessage alloc_req = turn_client.create_allocate_request(600, false, StunTransportProtocol::UDP);
    GPP_LOG_INFO("TURN_CL", "Created Allocate Request");

    // Simulate server response
    TurnServer turn_server(turn_config);
    TurnServer::AllocationRecord record;
    TurnAllocation allocation;
    auto alloc_resp = turn_server.handle_request(alloc_req, StunXorAddress::from_ipv4(0x7F000001, 50000), record);
    if (alloc_resp) {
        if (turn_client.handle_allocate_response(*alloc_resp, allocation)) {
            GPP_LOG_INFO("TURN_CL", "Allocation successful: Relay=" + allocation.relayed_address.to_string() +
                           ", Mapped=" + allocation.mapped_address.to_string() + ", Lifetime=" + std::to_string(allocation.lifetime));
        }
    }

    // Channel Bind
    StunMessage ch_bind = turn_client.create_channel_bind_request(allocation, 0x4000,
        StunXorAddress::from_ipv4(0x0A000002, 6000)); // Peer 10.0.0.2:6000
    GPP_LOG_INFO("TURN_CL", "Created ChannelBind Request for channel 0x4000");

    auto ch_bind_resp = turn_server.handle_request(ch_bind, StunXorAddress::from_ipv4(0x7F000001, 50000), record);
    if (ch_bind_resp) {
        GPP_LOG_INFO("TURN_CL", "ChannelBind Response received");
    }

    // Channel Data
    TurnChannelData ch_data = turn_client.create_channel_data(0x4000, {0x48, 0x65, 0x6C, 0x6C, 0x6F}); // "Hello"
    GPP_LOG_INFO("TURN_CL", "Created ChannelData: channel=0x4000, data=Hello");

    // -----------------------------------------------------------------------
    // Part 3: ICE Connectivity Checks
    // -----------------------------------------------------------------------
    GPP_LOG_INFO("MAIN", "\n=== Part 3: ICE Connectivity Checks (RFC 8445) ===");

    StunServerConfig stun_cfg;
    stun_cfg.hostname = "stun.example.com";
    stun_cfg.port = 3478;

    IceDemoAgent agent_a("UE_A", IceRole::Controlling, stun_cfg);
    IceDemoAgent agent_b("UE_B", IceRole::Controlled, stun_cfg);

    agent_a.set_peer(&agent_b);
    agent_b.set_peer(&agent_a);

    agent_a.start();
    agent_b.start();

    // Wait for gathering
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Exchange candidates
    for (const auto& cand : agent_a.local_candidates()) {
        agent_b.add_remote_candidate(cand);
    }
    for (const auto& cand : agent_b.local_candidates()) {
        agent_a.add_remote_candidate(cand);
    }

    // Exchange credentials
    agent_a.set_remote_credentials(agent_b.local_candidates().empty() ? "ufrag" : "ufrag_b", "pwd_b");
    agent_b.set_remote_credentials(agent_a.local_candidates().empty() ? "ufrag" : "ufrag_a", "pwd_a");

    // Run ICE checks
    uint64_t now = 0;
    for (int i = 0; i < 50; ++i) {
        now += 100;
        agent_a.tick(now);
        agent_b.tick(now);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    if (auto pair = agent_a.nominated_pair()) {
        GPP_LOG_INFO("MAIN", "ICE completed! Nominated pair established.");
    }

    // -----------------------------------------------------------------------
    // Part 4: Emergency Session (3GPP TS 23.167 / TS 24.229)
    // -----------------------------------------------------------------------
    GPP_LOG_INFO("MAIN", "\n=== Part 4: 3GPP Emergency Session (TS 23.167 / TS 24.229) ===");

    EmergencySessionConfig es_config;
    es_config.imsi = "001010123456789";
    es_config.impi = "user@emergency.test";
    es_config.impu = "sip:+15551234567@emergency.test";
    es_config.home_domain = "emergency.test";
    es_config.pcscf_addr = "127.0.0.1";
    es_config.pcscf_port = 5060;
    es_config.local_ip = "127.0.0.1";
    es_config.include_location = true;

    // Set initial location (simulated GPS)
    es_config.initial_location.type = LocationType::Geodetic;
    es_config.initial_location.geodetic.latitude = 37.7749;
    es_config.initial_location.geodetic.longitude = -122.4194;
    es_config.initial_location.geodetic.altitude = 10.0;
    es_config.initial_location.geodetic.horizontal_accuracy = 15.0;
    es_config.initial_location.geodetic.confidence = 95;

    // Location provider for updates
    int loc_counter = 0;
    es_config.location_provider = [&loc_counter]() -> LocationInfo {
        LocationInfo loc;
        loc.type = LocationType::Geodetic;
        loc.geodetic.latitude = 37.7749 + (loc_counter * 0.0001);
        loc.geodetic.longitude = -122.4194 + (loc_counter * 0.0001);
        loc.geodetic.altitude = 10.0 + loc_counter;
        loc.geodetic.horizontal_accuracy = 10.0;
        loc.geodetic.confidence = 95;
        loc_counter++;
        return loc;
    };

    EmergencySessionCallbacks es_callbacks;
    es_callbacks.on_send_sip = [&](const SipMessage& msg) {
        GPP_LOG_INFO("EMERG_SIP", "TX " + std::to_string(static_cast<int>(msg.method)) + ": " +
                       msg.request_uri.substr(0, std::min<size_t>(msg.request_uri.size(), 80)));
        // In real impl, send over UDP/TCP/TLS
    };
    es_callbacks.on_state_change = [&](EmergencySessionState state) {
        GPP_LOG_INFO("EMERG", "State changed: " + std::to_string(static_cast<int>(state)));
    };
    es_callbacks.on_media_negotiation = [&](const std::string& sdp) {
        GPP_LOG_INFO("EMERG", "Media negotiation - SDP offer generated");
    };
    es_callbacks.on_media_established = [&](const std::string& sdp) {
        GPP_LOG_INFO("EMERG", "Media established with remote SDP");
    };
    es_callbacks.on_location_update = [&](const LocationInfo& loc) {
        GPP_LOG_INFO("EMERG", "Location update: lat=" + std::to_string(loc.geodetic.latitude) +
                           ", lon=" + std::to_string(loc.geodetic.longitude));
    };
    es_callbacks.on_call_ended = [&](const std::string& reason) {
        GPP_LOG_INFO("EMERG", "Call ended: " + reason);
    };

    EmergencySession emergency_session(es_config, std::move(es_callbacks));

    // Start emergency registration
    emergency_session.start_emergency_registration();

    // Simulate registration response (200 OK)
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    SipMessage reg_resp;
    reg_resp.request_uri = "SIP/2.0 200 OK";
    reg_resp.add_header("Call-ID", es_config.impu);
    reg_resp.add_header("CSeq", "1 REGISTER");
    reg_resp.add_header("Contact", "<sip:user@127.0.0.1;transport=UDP>;+sip.instance=\"<urn:gsma:imei:000000000000000>\";reg-id=1");
    reg_resp.add_header("Expires", "3600");
    reg_resp.add_header("Record-Route", "<sip:pcscf.emergency.test;lr>");
    emergency_session.handle_sip_response(reg_resp, 1);

    // Start emergency call (Police)
    emergency_session.start_emergency_call(EmergencyCategory::Police);

    // Simulate call setup: 183 Session Progress with SDP
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    SipMessage invite_resp;
    invite_resp.request_uri = "SIP/2.0 183 Session Progress";
    invite_resp.add_header("Call-ID", es_config.impu);
    invite_resp.add_header("CSeq", "2 INVITE");
    invite_resp.add_header("Contact", "<sip:psap@emergency.test;transport=UDP>");
    invite_resp.add_header("Content-Type", "application/sdp");
    invite_resp.set_body(
        "v=0\r\n"
        "o=- 1234567890 1234567890 IN IP4 192.168.0.10\r\n"
        "s=PSAP\r\n"
        "c=IN IP4 192.168.0.10\r\n"
        "t=0 0\r\n"
        "m=audio 40000 RTP/AVP 97 98\r\n"
        "a=rtpmap:97 AMR-WB/16000\r\n"
        "a=rtpmap:98 AMR/8000\r\n"
        "a=sendrecv\r\n",
        "application/sdp");
    emergency_session.handle_sip_response(invite_resp, 2);

    // Simulate 200 OK
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    SipMessage ok_resp;
    ok_resp.request_uri = "SIP/2.0 200 OK";
    ok_resp.add_header("Call-ID", es_config.impu);
    ok_resp.add_header("CSeq", "2 INVITE");
    ok_resp.add_header("Contact", "<sip:psap@emergency.test;transport=UDP>");
    ok_resp.add_header("Session-Expires", "1800;refresher=uac");
    emergency_session.handle_sip_response(ok_resp, 2);

    // Simulate location update during call
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    LocationInfo update_loc;
    update_loc.type = LocationType::Geodetic;
    update_loc.geodetic.latitude = 37.7750;
    update_loc.geodetic.longitude = -122.4195;
    update_loc.geodetic.altitude = 12.0;
    update_loc.geodetic.horizontal_accuracy = 8.0;
    update_loc.geodetic.confidence = 97;
    emergency_session.send_location_update(update_loc);

    // End call
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    emergency_session.end_call("Normal call release");

    // -----------------------------------------------------------------------
    // Complete
    // -----------------------------------------------------------------------
    pcap.close();
    GPP_LOG_INFO("MAIN", "==================================================================");
    GPP_LOG_INFO("MAIN", "Lesson 10 STUN/TURN/ICE + SOS Emergency demo completed!");
    GPP_LOG_INFO("MAIN", "Trace written to output_10_stun_ice.pcap (" +
                         std::to_string(pcap.packet_count()) + " packets)");
    GPP_LOG_INFO("MAIN", "==================================================================");

    return 0;
}