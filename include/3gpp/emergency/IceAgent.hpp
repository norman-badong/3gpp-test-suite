#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <span>
#include <array>
#include <optional>
#include <chrono>
#include <functional>
#include <map>

#include "3gpp/emergency/StunMessage.hpp"
#include "3gpp/emergency/TurnMessage.hpp"

namespace gpp::emergency {

// ============================================================================
// ICE (RFC 8445) - Interactive Connectivity Establishment
// ============================================================================

/// ICE Candidate Types (RFC 8445 §5.1.1)
enum class IceCandidateType : uint8_t {
    Host        = 0,  // Direct IP:port of the host
    ServerReflexive = 1, // STUN-derived reflexive address
    PeerReflexive   = 2, // Learned from peer during connectivity checks
    Relayed         = 3, // TURN relayed address
};

/// ICE Candidate Transport (RFC 8445 §5.1.1)
enum class IceTransport : uint8_t {
    UDP = 17,
    TCP = 6,
};

/// ICE Candidate Component (RFC 8445 §5.1.1)
/// Component 1 = RTP, Component 2 = RTCP
enum class IceComponent : uint8_t {
    RTP  = 1,
    RTCP = 2,
};

/// ICE Candidate (RFC 8445 §5.1)
struct IceCandidate {
    std::string foundation{};       // Arbitrary string, same for candidates from same base
    uint32_t component_id{1};       // Component ID (1=RTP, 2=RTCP)
    IceTransport transport{IceTransport::UDP};
    uint32_t priority{0};           // Priority (RFC 8445 §5.1.2)
    StunXorAddress address{};       // Candidate address (host/srflx/relay)
    IceCandidateType type{IceCandidateType::Host};
    std::string related_address{};  // For srflx/relay: the base address
    uint16_t related_port{0};
    std::string transport_addr{};   // For TCP: "active"/"passive"/"so"
    uint64_t timestamp{0};          // Creation time

    [[nodiscard]] std::string to_sdp() const;  // RFC 8839 "a=candidate:" line
    static std::optional<IceCandidate> from_sdp(const std::string& sdp_line);

    // Priority calculation per RFC 8445 §5.1.2
    // priority = (2^24 * type_pref) + (2^8 * local_pref) + (2^0 * (256 - component_id))
    // type_pref: host=126, srflx=110, prflx=110, relay=0
    static uint32_t compute_priority(IceCandidateType type, uint16_t local_pref, uint8_t component_id);
};

/// ICE Role (RFC 8445 §5.2)
enum class IceRole : uint8_t {
    Controlling = 0,   // Initiator (chooses nominated pair)
    Controlled  = 1,   // Responder
};

/// ICE Checklist State (RFC 8445 §5.7)
enum class IceCheckState {
    Waiting,       // Not started
    InProgress,    // Connectivity check sent, waiting response
    Succeeded,     // Check succeeded
    Failed,        // Check failed
    Frozen,        // Waiting for another check to succeed
};

/// ICE Pair State (RFC 8445 §5.7)
enum class IcePairState {
    Frozen,
    Waiting,
    InProgress,
    Succeeded,
    Failed,
};

/// Candidate Pair (RFC 8445 §5.7)
struct CandidatePair {
    IceCandidate local{};
    IceCandidate remote{};
    IcePairState state{IcePairState::Frozen};
    IceCheckState check_state{IceCheckState::Waiting};
    uint64_t nominated_time{0};     // When nominated
    uint32_t priority{0};           // Pair priority = 2^32 * min(G,D) + 2 * max(G,D) + (G>D?1:0)
    int retry_count{0};
    uint64_t last_check_time{0};
};

/// STUN Server Config for ICE
struct StunServerConfig {
    std::string hostname{};
    uint16_t port{3478};
    std::string username{};         // Optional
    std::string password{};         // Optional
};

/// ICE Agent Configuration
struct IceConfig {
    IceRole role{IceRole::Controlling};
    std::string ufrag{};            // Local username fragment (min 4 chars)
    std::string pwd{};              // Local password (min 22 chars)
    uint64_t tie_breaker{0};        // 64-bit random for controlling role
    uint32_t gathering_timeout_ms{5000};
    uint32_t check_interval_ms{500};  // Ta interval
    uint32_t max_checks{100};
    uint32_t nomination_timeout_ms{10000};
    bool use_ice_lite{false};       // Lite implementation
    bool use_rtcp_mux{true};        // RTP/RTCP multiplexing (single component)
    StunServerConfig stun_server{}; // Optional STUN server for srflx
    TurnServerConfig turn_server{}; // Optional TURN server for relay
};

/// ICE Agent Callbacks
struct IceCallbacks {
    // Called when new local candidate gathered
    std::function<void(const IceCandidate&)> on_local_candidate;

    // Called when remote candidate received (from SDP)
    std::function<void(const IceCandidate&)> on_remote_candidate;

    // Called when pair nominated (ICE completed)
    std::function<void(const CandidatePair&)> on_nominated;

    // Called when ICE fails
    std::function<void(const std::string&)> on_failed;

    // Called to send STUN packet (UDP)
    std::function<void(const StunXorAddress& dst, const std::vector<uint8_t>& data)> on_send_stun;

    // Called to send TURN ChannelData
    std::function<void(uint16_t channel, const std::vector<uint8_t>& data)> on_send_channel_data;
};

/// ICE Agent - Main class for ICE processing
class IceAgent {
public:
    explicit IceAgent(const IceConfig& config, IceCallbacks callbacks);

    // Start ICE gathering
    void start_gathering();

    // Process incoming STUN message
    void handle_stun_message(const StunXorAddress& src, const StunMessage& msg);

    // Process incoming TURN ChannelData
    void handle_channel_data(uint16_t channel, const std::vector<uint8_t>& data);

    // Add remote candidate (from SDP)
    void add_remote_candidate(const IceCandidate& candidate);

    // Set remote ICE credentials
    void set_remote_credentials(const std::string& ufrag, const std::string& pwd);

    // Get local candidates for SDP
    [[nodiscard]] const std::vector<IceCandidate>& local_candidates() const { return local_candidates_; }

    // Get current nominated pair
    [[nodiscard]] std::optional<CandidatePair> get_nominated_pair() const;

    // Get ICE state
    enum class State { Gathering, Checking, Completed, Failed };
    [[nodiscard]] State state() const { return state_; }

    // Periodic timer tick (call every ~100ms)
    void tick(uint64_t now_ms);

    // Get local credentials for SDP
    [[nodiscard]] const std::string& local_ufrag() const { return config_.ufrag; }
    [[nodiscard]] const std::string& local_pwd() const { return config_.pwd; }

    // Utility methods (public for testing)
    [[nodiscard]] uint64_t compute_pair_priority(const IceCandidate& local, const IceCandidate& remote) const;

private:
    IceConfig config_;
    IceCallbacks callbacks_;
    State state_{State::Gathering};

    std::vector<IceCandidate> local_candidates_;
    std::vector<IceCandidate> remote_candidates_;
    std::vector<CandidatePair> checklist_;
    std::optional<CandidatePair> nominated_pair_;

    std::string remote_ufrag_;
    std::string remote_pwd_;

    uint64_t gathering_start_time_{0};
    uint64_t last_tick_{0};
    int checks_in_progress_{0};

    // Candidate gathering
    void gather_host_candidates();
    void gather_srflx_candidates();
    void gather_relay_candidates();

    // Checklist management
    void form_checklist();
    void prioritize_checklist();
    void schedule_checks();

    // Connectivity checks
    void send_check(const CandidatePair& pair);
    void handle_check_response(const StunXorAddress& src, const StunMessage& resp);
    void handle_check_request(const StunXorAddress& src, const StunMessage& req);

    // Nomination
    void nominate_pair(CandidatePair& pair);
    void handle_nomination(const StunMessage& msg, CandidatePair& pair);

    // Utilities
    std::optional<CandidatePair*> find_pair(const StunXorAddress& local, const StunXorAddress& remote);
    std::array<uint8_t, 12> generate_transaction_id();
};

/// ICE SDP Helpers (RFC 8839)
namespace ice_sdp {

/// Generate ICE ufrag/pwd
std::pair<std::string, std::string> generate_credentials();

/// Parse remote candidates from SDP
std::vector<IceCandidate> parse_remote_candidates(const std::string& sdp);

/// Generate local candidate SDP lines
std::string generate_candidate_sdp(const std::vector<IceCandidate>& candidates,
                                    const std::string& ufrag,
                                    const std::string& pwd);

/// Generate complete ICE SDP media section
std::string generate_ice_media_section(const std::vector<IceCandidate>& candidates,
                                        const std::string& ufrag,
                                        const std::string& pwd,
                                        const std::string& mid = "0");

} // namespace ice_sdp

} // namespace gpp::emergency