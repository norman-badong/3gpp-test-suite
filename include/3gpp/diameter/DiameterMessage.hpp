#pragma once

#include "3gpp/diameter/DiameterAvp.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace gpp {
namespace diameter {

/**
 * Diameter Command Flags (RFC 6733 Section 3)
 */
constexpr uint8_t CMD_FLAG_REQUEST = 0x80;        // 'R' bit
constexpr uint8_t CMD_FLAG_PROXIABLE = 0x40;      // 'P' bit
constexpr uint8_t CMD_FLAG_ERROR = 0x20;          // 'E' bit
constexpr uint8_t CMD_FLAG_RETRANSMITTED = 0x10;  // 'T' bit

/**
 * Diameter Command Codes (RFC 6733, RFC 4006, 3GPP TS 29.272)
 */
constexpr uint32_t CMD_CAPABILITIES_EXCHANGE = 257;    // CER / CEA
constexpr uint32_t CMD_DEVICE_WATCHDOG = 280;          // DWR / DWA
constexpr uint32_t CMD_DISCONNECT_PEER = 282;          // DPR / DPA
constexpr uint32_t CMD_CREDIT_CONTROL = 272;           // CCR / CCA (RFC 4006)
constexpr uint32_t CMD_UPDATE_LOCATION = 316;          // ULR / ULA (3GPP S6a)
constexpr uint32_t CMD_CANCEL_LOCATION = 317;          // CLR / CLA (3GPP S6a)
constexpr uint32_t CMD_AUTHENTICATION_INFO = 318;      // AIR / AIA (3GPP S6a)
constexpr uint32_t CMD_PURGE_UE = 319;                 // PUR / PUA (3GPP S6a)

/**
 * Diameter Application IDs (RFC 6733, 3GPP TS 29.272)
 */
constexpr uint32_t APP_DIAMETER_COMMON = 0;            // Base Protocol
constexpr uint32_t APP_DIAMETER_CREDIT_CONTROL = 4;    // RFC 4006
constexpr uint32_t APP_3GPP_S6A = 16777251;            // 0x01000053 (3GPP TS 29.272)
constexpr uint32_t APP_3GPP_CX = 16777216;             // 0x01000000 (IMS TS 29.228)

/**
 * Diameter Result Codes (RFC 6733 Section 7.1)
 */
constexpr uint32_t DIAMETER_SUCCESS = 2001;
constexpr uint32_t DIAMETER_COMMAND_UNSUPPORTED = 3001;
constexpr uint32_t DIAMETER_UNABLE_TO_DELIVER = 3002;
constexpr uint32_t DIAMETER_REALM_NOT_SERVED = 3003;
constexpr uint32_t DIAMETER_TOO_BUSY = 3004;
constexpr uint32_t DIAMETER_AUTHENTICATION_REJECTED = 4001;
constexpr uint32_t DIAMETER_USER_UNKNOWN = 5001;

/**
 * Diameter Packet Header size is fixed at 20 bytes (RFC 6733 Section 3).
 */
constexpr size_t DIAMETER_HEADER_SIZE = 20;

/**
 * Diameter Message (Header + Sequence of AVPs)
 */
class DiameterMessage {
public:
    uint8_t version{1};
    uint8_t flags{0};
    uint32_t command_code{0};
    uint32_t application_id{0};
    uint32_t hop_by_hop_id{0};
    uint32_t end_to_end_id{0};
    std::vector<DiameterAvp> avps;

    DiameterMessage() = default;
    DiameterMessage(uint8_t flags, uint32_t command_code, uint32_t application_id,
                    uint32_t hop_by_hop_id, uint32_t end_to_end_id)
        : version(1), flags(flags), command_code(command_code),
          application_id(application_id), hop_by_hop_id(hop_by_hop_id),
          end_to_end_id(end_to_end_id) {}

    // Flags helpers
    [[nodiscard]] bool is_request() const { return (flags & CMD_FLAG_REQUEST) != 0; }
    [[nodiscard]] bool is_proxiable() const { return (flags & CMD_FLAG_PROXIABLE) != 0; }
    [[nodiscard]] bool is_error() const { return (flags & CMD_FLAG_ERROR) != 0; }
    [[nodiscard]] bool is_retransmitted() const { return (flags & CMD_FLAG_RETRANSMITTED) != 0; }

    void set_request(bool r) {
        if (r) flags |= CMD_FLAG_REQUEST;
        else flags &= ~CMD_FLAG_REQUEST;
    }

    void set_proxiable(bool p) {
        if (p) flags |= CMD_FLAG_PROXIABLE;
        else flags &= ~CMD_FLAG_PROXIABLE;
    }

    // AVP manipulation
    void add_avp(DiameterAvp avp) { avps.push_back(std::move(avp)); }

    [[nodiscard]] const DiameterAvp* find_avp(uint32_t code, std::optional<uint32_t> vendor = std::nullopt) const;
    [[nodiscard]] std::vector<const DiameterAvp*> find_all_avps(uint32_t code, std::optional<uint32_t> vendor = std::nullopt) const;

    // Serialization & Deserialization
    [[nodiscard]] std::vector<uint8_t> serialize() const;
    static std::optional<DiameterMessage> decode(const uint8_t* data, size_t length);
    static std::optional<DiameterMessage> decode(common::ByteStreamReader& reader);
};

} // namespace diameter
} // namespace gpp
