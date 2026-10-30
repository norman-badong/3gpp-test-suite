#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <array>
#include <string>
#include <optional>

#include "3gpp/common/ByteStream.hpp"

namespace gpp::emergency {

// ============================================================================
// STUN (RFC 5389) - Session Traversal Utilities for NAT
// ============================================================================

/// STUN Message Types (RFC 5389 §6)
enum class StunMessageType : uint16_t {
    // Binding methods
    BindingRequest        = 0x0001,
    BindingResponse       = 0x0101,
    BindingErrorResponse  = 0x0111,
    BindingIndication     = 0x0011,

    // TURN methods (RFC 8656) - handled in TurnMessage.hpp
    AllocateRequest       = 0x0003,
    AllocateResponse      = 0x0103,
    AllocateErrorResponse = 0x0113,
    RefreshRequest        = 0x0004,
    RefreshResponse       = 0x0104,
    RefreshErrorResponse  = 0x0114,
    CreatePermissionRequest  = 0x0005,
    CreatePermissionResponse = 0x0105,
    CreatePermissionErrorResponse = 0x0115,
    ChannelBindRequest    = 0x0006,
    ChannelBindResponse   = 0x0106,
    ChannelBindErrorResponse = 0x0116,
};

/// STUN Attribute Types (RFC 5389 §14.1, RFC 8656)
enum class StunAttributeType : uint16_t {
    MappedAddress         = 0x0001,
    ResponseAddress       = 0x0002, // deprecated
    ChangeRequest         = 0x0003, // deprecated
    SourceAddress         = 0x0004,
    ChangedAddress        = 0x0005,
    Username              = 0x0006,
    Password              = 0x0007,
    MessageIntegrity      = 0x0008,
    ErrorCode             = 0x0009,
    UnknownAttributes     = 0x000A,
    ReflectedFrom         = 0x000B,
    Realm                 = 0x0014,
    Nonce                 = 0x0015,
    XorMappedAddress      = 0x0020,
    Software              = 0x8022,
    AlternateServer       = 0x8023,
    Fingerprint           = 0x8028,

    // TURN attributes (RFC 8656)
    ChannelNumber         = 0x000C,
    Lifetime              = 0x000D,
    XorPeerAddress        = 0x0012,
    Data                  = 0x0013,
    XorRelayedAddress     = 0x0016,
    EvenPort              = 0x0017,
    RequestedTransport    = 0x0019,
    DontFragment          = 0x001A,
    ReservationToken      = 0x0022,
    Priority              = 0x0024,
    UseCandidate          = 0x0025,
    IceControlled         = 0x8029,
    IceControlling        = 0x802A,
};

/// STUN Transport Protocol (RFC 5389 §14.2)
enum class StunTransportProtocol : uint8_t {
    UDP = 17,
    TCP = 6,
};

/// STUN Address Family (RFC 5389 §14.2)
enum class StunAddressFamily : uint8_t {
    IPv4 = 0x01,
    IPv6 = 0x02,
};

/// STUN Error Code (RFC 5389 §15.11)
struct StunErrorCode {
    uint16_t error_class{0};   // 100-600
    uint16_t number{0};        // 0-99
    std::string reason{};

    [[nodiscard]] uint16_t full_code() const { return static_cast<uint16_t>(error_class * 100 + number); }
    static StunErrorCode from_full(uint16_t code) {
        StunErrorCode e;
        e.error_class = code / 100;
        e.number = code % 100;
        return e;
    }
};

/// STUN XOR-MAPPED-ADDRESS / MAPPED-ADDRESS attribute (RFC 5389 §15.1, §15.2)
struct StunXorAddress {
    StunAddressFamily family{StunAddressFamily::IPv4};
    uint16_t port{0};
    std::array<uint8_t, 16> addr{}; // IPv4 in last 4 bytes, IPv6 in all 16

    [[nodiscard]] std::string to_string() const;
    static StunXorAddress from_ipv4(uint32_t ip, uint16_t port);
    static StunXorAddress from_ipv6(const std::array<uint8_t, 16>& ip, uint16_t port);
};

/// STUN Message Header (RFC 5389 §6)
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |0 0|     STUN Message Type     |         Message Length        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Magic Cookie                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                     Transaction ID (96 bits)                  |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
struct StunHeader {
    StunMessageType msg_type{StunMessageType::BindingRequest};
    uint16_t length{0};              // Length of attributes only
    uint32_t magic_cookie{0x2112A442}; // Fixed per RFC 5389
    std::array<uint8_t, 12> transaction_id{}; // 96 bits

    [[nodiscard]] std::vector<uint8_t> encode() const;
    static std::optional<StunHeader> decode(std::span<const uint8_t> data, size_t& offset);
    [[nodiscard]] bool is_response() const;
    [[nodiscard]] bool is_error_response() const;
    [[nodiscard]] bool is_indication() const;
};

/// Generic STUN Attribute (TLV)
struct StunAttribute {
    StunAttributeType type{StunAttributeType::MappedAddress};
    std::vector<uint8_t> value{};

    [[nodiscard]] size_t encoded_size() const;
    [[nodiscard]] std::vector<uint8_t> encode() const;
    static std::optional<StunAttribute> decode(std::span<const uint8_t> data, size_t& offset);
};

/// Complete STUN Message
class StunMessage {
public:
    StunHeader header{};
    std::vector<StunAttribute> attributes{};

    // Encoding
    [[nodiscard]] std::vector<uint8_t> encode() const;
    [[nodiscard]] std::vector<uint8_t> encode_with_fingerprint() const;

    // Decoding
    static std::optional<StunMessage> decode(std::span<const uint8_t> data);

    // Attribute helpers
    void add_attribute(const StunAttribute& attr) { attributes.push_back(attr); }
    void add_xor_mapped_address(const StunXorAddress& addr);
    void add_mapped_address(const StunXorAddress& addr);
    void add_fingerprint();
    void add_message_integrity(const std::vector<uint8_t>& key); // HMAC-SHA1
    void add_software(const std::string& software);
    void add_error_code(const StunErrorCode& err);
    void add_realm(const std::string& realm);
    void add_nonce(const std::string& nonce);
    void add_username(const std::string& username);
    void add_priority(uint32_t priority);
    void add_use_candidate();
    void add_ice_controlling(uint64_t tie_breaker);
    void add_ice_controlled(uint64_t tie_breaker);
    void add_lifetime(uint32_t seconds);
    void add_channel_number(uint16_t channel);
    void add_data(const std::vector<uint8_t>& data);
    void add_xor_relayed_address(const StunXorAddress& addr);
    void add_requested_transport(StunTransportProtocol proto);
    void add_dont_fragment();
    void add_even_port();

    // Attribute getters
    std::optional<StunXorAddress> get_xor_mapped_address() const;
    std::optional<StunXorAddress> get_mapped_address() const;
    std::optional<std::string> get_software() const;
    std::optional<StunErrorCode> get_error_code() const;
    std::optional<std::string> get_realm() const;
    std::optional<std::string> get_nonce() const;
    std::optional<std::string> get_username() const;
    std::optional<uint32_t> get_priority() const;
    std::optional<uint16_t> get_channel_number() const;
    std::optional<std::vector<uint8_t>> get_data() const;
    std::optional<StunXorAddress> get_xor_relayed_address() const;
    std::optional<uint32_t> get_lifetime() const;
    std::optional<uint64_t> get_ice_controlling() const;
    std::optional<uint64_t> get_ice_controlled() const;
    bool has_use_candidate() const;
    bool has_dont_fragment() const;
    bool has_even_port() const;
    bool verify_fingerprint() const;
    bool verify_message_integrity(const std::vector<uint8_t>& key) const;

    // TURN-specific attribute getters
    std::optional<StunXorAddress> get_xor_peer_address() const;
    std::optional<StunTransportProtocol> get_requested_transport() const;

    // Factory methods
    static StunMessage create_binding_request(const std::array<uint8_t, 12>& tid);
    static StunMessage create_binding_response(const StunMessage& req, const StunXorAddress& mapped_addr);
    static StunMessage create_binding_error_response(const StunMessage& req, const StunErrorCode& err);

private:
    static uint16_t compute_crc32(const std::span<const uint8_t> data);
    static uint16_t compute_crc32_fast(const std::span<const uint8_t> data);
};

} // namespace gpp::emergency