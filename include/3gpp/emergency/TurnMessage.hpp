#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <array>
#include <string>
#include <optional>

#include "3gpp/emergency/StunMessage.hpp"

namespace gpp::emergency {

// ============================================================================
// TURN (RFC 8656) - Traversal Using Relays around NAT
// Extends STUN with relay-specific methods and attributes
// ============================================================================

/// TURN Channel Number (RFC 8656 §11) - 0x4000 to 0x7FFE
constexpr uint16_t TURN_CHANNEL_MIN = 0x4000;
constexpr uint16_t TURN_CHANNEL_MAX = 0x7FFE;
constexpr uint32_t TURN_CHANNEL_BIND_TIMEOUT_MS = 600000; // 10 minutes default

/// TURN Allocation Flags
enum class TurnAllocateFlag : uint8_t {
    None          = 0,
    EvenPort      = 0x01,  // Request even port number
    Reservation   = 0x02,  // Reservation token present
};

/// TURN Permission Lifetime (RFC 8656 §9) - default 300 seconds
constexpr uint32_t TURN_DEFAULT_PERMISSION_LIFETIME = 300;
constexpr uint32_t TURN_DEFAULT_ALLOCATION_LIFETIME = 600;

/// TURN Channel Data Message (RFC 8656 §11)
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Channel Number        |           Length              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                    Application Data                           |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
struct TurnChannelData {
    uint16_t channel_number{0};      // 0x4000-0x7FFE
    uint16_t length{0};              // Length of application data
    std::vector<uint8_t> data{};     // Application payload

    [[nodiscard]] bool is_channel_data() const { return channel_number >= TURN_CHANNEL_MIN && channel_number <= TURN_CHANNEL_MAX; }
    [[nodiscard]] std::vector<uint8_t> encode() const;
    static std::optional<TurnChannelData> decode(std::span<const uint8_t> data, size_t& offset);
};

/// TURN Allocation State (RFC 8656 §6)
enum class TurnAllocationState {
    Idle,           // No allocation
    Allocated,      // Active allocation with relayed address
    Refreshing,     // Refresh in progress
    Expired,        // Allocation expired
};

/// TURN 5-Tuple for Permission (RFC 8656 §9)
struct Turn5Tuple {
    StunTransportProtocol protocol{StunTransportProtocol::UDP};
    StunXorAddress server_addr{};      // TURN server transport address
    StunXorAddress relayed_addr{};     // Allocated relayed address
    StunXorAddress peer_addr{};        // Peer address (for permission)
    uint16_t channel_number{0};        // Bound channel (if any)

    bool operator==(const Turn5Tuple& other) const;
};

/// TURN Allocation (RFC 8656 §6)
struct TurnAllocation {
    StunXorAddress relayed_address{};      // XOR-RELAYED-ADDRESS
    StunXorAddress mapped_address{};       // XOR-MAPPED-ADDRESS (client's reflexive)
    uint32_t lifetime{TURN_DEFAULT_ALLOCATION_LIFETIME};
    TurnAllocationState state{TurnAllocationState::Idle};
    std::vector<Turn5Tuple> permissions{}; // Active permissions
    uint64_t last_refresh_time{0};         // Unix timestamp
    std::string username{};                // For message integrity
    std::string realm{};                   // For message integrity
    std::string nonce{};                   // For message integrity
};

/// TURN Server Configuration
struct TurnServerConfig {
    std::string hostname{};
    uint16_t port{3478};
    StunTransportProtocol transport{StunTransportProtocol::UDP};
    std::string realm{"turn.example.com"};
    std::string username{};
    std::string password{}; // For long-term credential mechanism
    std::string nonce{};    // For message integrity (nonce from server)
    uint32_t default_lifetime{TURN_DEFAULT_ALLOCATION_LIFETIME};
    bool require_message_integrity{true};
};

/// TURN Client State Machine
class TurnClient {
public:
    explicit TurnClient(const TurnServerConfig& config);

    // Allocate a relay address
    StunMessage create_allocate_request(uint32_t lifetime = TURN_DEFAULT_ALLOCATION_LIFETIME,
                                         bool even_port = false,
                                         StunTransportProtocol proto = StunTransportProtocol::UDP);

    // Parse allocate response
    bool handle_allocate_response(const StunMessage& resp, TurnAllocation& allocation);

    // Refresh allocation (keep-alive)
    StunMessage create_refresh_request(const TurnAllocation& alloc, uint32_t lifetime = 0);

    // Create permission for peer
    StunMessage create_permission_request(const TurnAllocation& alloc, const StunXorAddress& peer_addr);

    // Channel bind
    StunMessage create_channel_bind_request(const TurnAllocation& alloc,
                                             uint16_t channel_number,
                                             const StunXorAddress& peer_addr);

    // Send data via channel (TURN ChannelData message)
    TurnChannelData create_channel_data(uint16_t channel_number, const std::vector<uint8_t>& app_data);

    // Send data via Send Indication (STUN indication with DATA attribute)
    StunMessage create_send_indication(const TurnAllocation& alloc,
                                        const StunXorAddress& peer_addr,
                                        const std::vector<uint8_t>& app_data);

    // Receive data via ChannelData
    std::optional<TurnChannelData> parse_channel_data(std::span<const uint8_t> data);

    // Receive data via Data Indication
    std::optional<std::pair<StunXorAddress, std::vector<uint8_t>>> parse_data_indication(const StunMessage& msg);

    // Generate credentials for MESSAGE-INTEGRITY
    std::vector<uint8_t> compute_message_integrity_key() const;

private:
    TurnServerConfig config_;
    std::array<uint8_t, 12> generate_transaction_id();
};

/// TURN Server-side allocation management
class TurnServer {
public:
    struct AllocationRecord {
        TurnAllocation allocation{};
        std::string client_username{};
        std::string client_realm{};
        uint64_t creation_time{0};
        uint64_t last_activity{0};
    };

    explicit TurnServer(const TurnServerConfig& config);

    // Handle incoming STUN message
    std::optional<StunMessage> handle_request(const StunMessage& req,
                                               const StunXorAddress& client_addr,
                                               AllocationRecord& record);

    // Handle ChannelData
    std::optional<TurnChannelData> handle_channel_data(const TurnChannelData& chdata,
                                                        AllocationRecord& record);

    // Cleanup expired allocations
    void cleanup_expired(uint64_t current_time);

private:
    TurnServerConfig config_;
    std::vector<AllocationRecord> allocations_;

    std::optional<StunMessage> handle_allocate(const StunMessage& req,
                                                const StunXorAddress& client_addr,
                                                AllocationRecord& record);
    std::optional<StunMessage> handle_refresh(const StunMessage& req,
                                               AllocationRecord& record);
    std::optional<StunMessage> handle_create_permission(const StunMessage& req,
                                                         AllocationRecord& record);
    std::optional<StunMessage> handle_channel_bind(const StunMessage& req,
                                                    AllocationRecord& record);
    bool verify_credentials(const StunMessage& req, const AllocationRecord& record) const;
    StunXorAddress allocate_relay_address();
};

} // namespace gpp::emergency