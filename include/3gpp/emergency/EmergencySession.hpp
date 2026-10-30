#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <span>
#include <optional>
#include <map>
#include <functional>

#include "3gpp/emergency/EmergencyTypes.hpp"
#include "3gpp/emergency/IceAgent.hpp"

namespace gpp::emergency {

// ============================================================================
// 3GPP Emergency Session (TS 23.167, TS 24.229, RFC 6442, RFC 3261)
// Integrates SIP emergency call flow with location conveyance (PIDF-LO)
// ============================================================================

/// Emergency Session State
enum class EmergencySessionState {
    Idle,
    Registering,
    Registered,
    Calling,
    Alerting,
    Connected,
    Releasing,
    Released,
    Failed,
};

/// Emergency SIP Message Type
enum class EmergencySipMethod {
    Register,
    Invite,
    Ack,
    Bye,
    Cancel,
    Options,
    Update,
    Prack,
    Refer,
    Notify,
    Subscribe,
    Publish,
    Message,
    Info,
};

/// Emergency Session Configuration
struct EmergencySessionConfig {
    // UE Identity
    std::string imsi{};                 // IMSI for emergency registration
    std::string impi{};                 // Private user identity
    std::string impu{};                 // Public user identity (sip: URI)
    std::string home_domain{};          // Home network domain

    // Emergency Service
    EmergencyCallContext call_context{};

    // Network
    std::string pcscf_addr{};           // P-CSCF address
    uint16_t pcscf_port{5060};
    std::string transport{"UDP"};       // UDP/TCP/TLS

    // Location
    bool include_location{true};
    LocationInfo initial_location{};    // Initial location at call setup
    std::function<LocationInfo()> location_provider{}; // Dynamic location updates

    // Media (for SDP)
    std::string local_ip{};             // Local IP for media
    uint16_t rtp_port_base{40000};      // Base RTP port
    std::vector<std::string> codecs{"AMR-WB", "AMR", "EVS"}; // Supported codecs

    // Timers
    uint32_t reg_expires{3600};         // Registration expiry
    uint32_t session_timer{1800};       // Session-Expires
    uint32_t min_se{90};                // Min-SE
};

/// PIDF-LO Presence Information (RFC 6442, RFC 4119)
/// Used for emergency location conveyance in SIP body
struct PidfLo {
    std::string entity{};               // Presence entity (sip: URI)
    std::string id{};                   // Unique tuple ID
    LocationInfo location{};            // Location data
    uint64_t timestamp{0};              // Location timestamp
    std::string method{"GPS"};          // Location method: GPS, A-GPS, ECID, etc.
    float confidence{0.95f};            // Confidence level

    [[nodiscard]] std::string to_xml() const;
    static std::optional<PidfLo> from_xml(const std::string& xml);
};

/// Geolocation Header (RFC 6442)
struct GeolocationHeader {
    std::string uri{};                  // CID or direct PIDF-LO
    std::string routing{"yes"};         // "yes" or "no"
    std::string purpose{"emergency"};   // Usually "emergency"

    [[nodiscard]] std::string to_header_value() const;
};

/// SIP Message for Emergency Session
struct SipMessage {
    EmergencySipMethod method{EmergencySipMethod::Invite};
    std::string request_uri{};
    std::map<std::string, std::string> headers{};
    std::string body{};
    std::string content_type{};

    // Helpers
    void add_header(const std::string& name, const std::string& value);
    std::optional<std::string> get_header(const std::string& name) const;
    void set_body(const std::string& body, const std::string& content_type);

    [[nodiscard]] std::string encode() const;
    static std::optional<SipMessage> decode(std::span<const uint8_t> data);
};

/// Emergency Session Callbacks
struct EmergencySessionCallbacks {
    // Called to send SIP message over transport
    std::function<void(const SipMessage&)> on_send_sip;

    // Called when session state changes
    std::function<void(EmergencySessionState)> on_state_change;

    // Called when media needs to be established (ICE)
    std::function<void(const std::string& sdp_offer)> on_media_negotiation;

    // Called when media established
    std::function<void(const std::string& remote_sdp)> on_media_established;

    // Called for location updates during call
    std::function<void(const LocationInfo&)> on_location_update;

    // Called when emergency call released
    std::function<void(const std::string& reason)> on_call_ended;
};

/// Emergency Session - Main class
class EmergencySession {
public:
    explicit EmergencySession(const EmergencySessionConfig& config, EmergencySessionCallbacks callbacks);

    // Start emergency registration
    void start_emergency_registration();

    // Start emergency call
    void start_emergency_call(EmergencyCategory category = EmergencyCategory::GeneralEmergency);

    // Handle incoming SIP response/request
    void handle_sip_message(const SipMessage& msg);

    // Handle incoming SIP response for transaction
    void handle_sip_response(const SipMessage& response, uint32_t cseq);

    // Send location update (during call)
    void send_location_update(const LocationInfo& location);

    // End emergency call
    void end_call(const std::string& reason = "Normal");

    // Get current state
    [[nodiscard]] EmergencySessionState state() const { return state_; }
    [[nodiscard]] const EmergencyCallContext& call_context() const { return config_.call_context; }

    // Process timer tick
    void tick(uint64_t now_sec);

private:
    EmergencySessionConfig config_;
    EmergencySessionCallbacks callbacks_;
    EmergencySessionState state_{EmergencySessionState::Idle};

    // Transaction state
    uint32_t cseq_{1};
    std::string call_id_;
    std::string from_tag_;
    std::string to_tag_;
    std::string route_set_;       // Route header from registration
    std::string contact_header_;  // Our Contact

    // Registration
    uint32_t reg_expires_{3600};
    uint64_t reg_expiry_time_{0};
    bool emergency_registered_{false};

    // Call state
    std::string remote_sdp_;
    bool media_established_{false};

    // Timers
    uint64_t session_timer_expires_{0};
    uint64_t last_keepalive_{0};

    // Registration
    void send_register();
    void handle_register_response(const SipMessage& resp);

    // Call setup
    void send_invite();
    void handle_invite_response(const SipMessage& resp);
    void send_ack(const SipMessage& invite_resp);

    // In-call
    void send_update_location(const LocationInfo& location);
    void send_bye(const std::string& reason);

    // Location
    PidfLo create_pidf_lo(const LocationInfo& loc) const;
    std::string create_multipart_body(const std::string& sdp, const PidfLo& pidf) const;

    // SDP
    std::string generate_sdp_offer() const;
    void parse_sdp_answer(const std::string& sdp);

    // Utilities
    std::string generate_call_id() const;
    std::string generate_tag() const;
    void transition_state(EmergencySessionState new_state);
};

/// Emergency Registration Manager (handles emergency registration per TS 24.229)
class EmergencyRegistrationManager {
public:
    struct RegistrationInfo {
        std::string impi{};
        std::string impu{};
        std::string home_domain{};
        std::string pcscf_addr{};
        uint16_t pcscf_port{5060};
        std::string transport{"UDP"};
        uint32_t expires{3600};
        bool emergency_only{true};  // Emergency registration (no IMS services)
    };

    using SendCallback = std::function<void(const SipMessage&)>;
    using StateCallback = std::function<void(bool registered, const std::string& reason)>;

    EmergencyRegistrationManager(const RegistrationInfo& info, SendCallback send_cb, StateCallback state_cb);

    void start();
    void handle_response(const SipMessage& resp);
    void handle_request(const SipMessage& req); // For re-registration
    void stop();
    void tick(uint64_t now_sec);

    [[nodiscard]] bool is_registered() const { return registered_; }
    [[nodiscard]] const std::string& route_set() const { return route_set_; }
    [[nodiscard]] const std::string& contact() const { return contact_; }

private:
    RegistrationInfo info_;
    SendCallback send_cb_;
    StateCallback state_cb_;

    bool registered_{false};
    std::string call_id_;
    std::string from_tag_;
    std::string route_set_;
    std::string contact_;
    uint32_t cseq_{1};
    uint64_t expiry_time_{0};

    void send_register();
    void schedule_re_register();
    std::string generate_call_id() const;
    std::string generate_tag() const;
};

} // namespace gpp::emergency