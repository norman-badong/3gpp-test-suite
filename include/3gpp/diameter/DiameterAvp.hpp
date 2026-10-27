#pragma once

#include "3gpp/common/ByteStream.hpp"
#include "3gpp/ip/IpAddress.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace gpp {
namespace diameter {

/**
 * Diameter AVP Flags (RFC 6733 Section 4.1)
 */
constexpr uint8_t AVP_FLAG_VENDOR = 0x80;    // 'V' bit: Vendor-Specific
constexpr uint8_t AVP_FLAG_MANDATORY = 0x40; // 'M' bit: Mandatory
constexpr uint8_t AVP_FLAG_PROTECTED = 0x20; // 'P' bit: Protected (encryption)

/**
 * Well-known Vendor IDs
 */
constexpr uint32_t VENDOR_3GPP = 10415; // 3GPP Vendor ID

/**
 * Well-known Standard Diameter Base AVP Codes (RFC 6733)
 */
constexpr uint32_t AVP_USER_NAME = 1;
constexpr uint32_t AVP_HOST_IP_ADDRESS = 257;
constexpr uint32_t AVP_AUTH_APPLICATION_ID = 258;
constexpr uint32_t AVP_ACCT_APPLICATION_ID = 259;
constexpr uint32_t AVP_VENDOR_SPECIFIC_APP_ID = 260;
constexpr uint32_t AVP_SESSION_ID = 263;
constexpr uint32_t AVP_ORIGIN_HOST = 264;
constexpr uint32_t AVP_SUPPORTED_VENDOR_ID = 265;
constexpr uint32_t AVP_VENDOR_ID = 266;
constexpr uint32_t AVP_RESULT_CODE = 268;
constexpr uint32_t AVP_PRODUCT_NAME = 269;
constexpr uint32_t AVP_DISCONNECT_CAUSE = 273;
constexpr uint32_t AVP_AUTH_SESSION_STATE = 277;
constexpr uint32_t AVP_ORIGIN_STATE_ID = 278;
constexpr uint32_t AVP_DESTINATION_REALM = 283;
constexpr uint32_t AVP_DESTINATION_HOST = 293;
constexpr uint32_t AVP_ORIGIN_REALM = 296;

/**
 * Well-known 3GPP S6a AVP Codes (TS 29.272)
 */
constexpr uint32_t AVP_VISITED_PLMN_ID = 1407;
constexpr uint32_t AVP_REQ_EUTRAN_AUTH_INFO = 1401;
constexpr uint32_t AVP_NUMBER_OF_REQ_VECTORS = 1402;
constexpr uint32_t AVP_IMMEDIATE_RESPONSE_PREF = 1412;
constexpr uint32_t AVP_AUTHENTICATION_INFO = 1413;
constexpr uint32_t AVP_E_UTRAN_VECTOR = 1414;
constexpr uint32_t AVP_ITEM_NUMBER = 1419;
constexpr uint32_t AVP_RAND = 1447;
constexpr uint32_t AVP_XRES = 1448;
constexpr uint32_t AVP_AUTN = 1449;
constexpr uint32_t AVP_KASME = 1450;

/**
 * Representation of a Diameter Attribute-Value Pair (AVP).
 */
class DiameterAvp {
public:
    uint32_t code{0};
    uint8_t flags{0};
    std::optional<uint32_t> vendor_id{std::nullopt};
    std::vector<uint8_t> data;

    DiameterAvp() = default;
    DiameterAvp(uint32_t code, uint8_t flags, std::optional<uint32_t> vendor_id, std::vector<uint8_t> data)
        : code(code), flags(flags), vendor_id(vendor_id), data(std::move(data)) {}

    // Convenience checkers
    [[nodiscard]] bool is_vendor_specific() const { return (flags & AVP_FLAG_VENDOR) != 0; }
    [[nodiscard]] bool is_mandatory() const { return (flags & AVP_FLAG_MANDATORY) != 0; }

    // Factory methods for standard data types
    static DiameterAvp create_unsigned32(uint32_t code, uint32_t val, bool mandatory = true,
                                         std::optional<uint32_t> vendor = std::nullopt);

    static DiameterAvp create_unsigned64(uint32_t code, uint64_t val, bool mandatory = true,
                                         std::optional<uint32_t> vendor = std::nullopt);

    static DiameterAvp create_integer32(uint32_t code, int32_t val, bool mandatory = true,
                                        std::optional<uint32_t> vendor = std::nullopt);

    static DiameterAvp create_string(uint32_t code, const std::string& str, bool mandatory = true,
                                     std::optional<uint32_t> vendor = std::nullopt);

    static DiameterAvp create_octet_string(uint32_t code, const std::vector<uint8_t>& bytes,
                                           bool mandatory = true, std::optional<uint32_t> vendor = std::nullopt);

    static DiameterAvp create_ipv4_address(uint32_t code, const ip::Ipv4Address& addr, bool mandatory = true,
                                           std::optional<uint32_t> vendor = std::nullopt);

    static DiameterAvp create_grouped(uint32_t code, const std::vector<DiameterAvp>& sub_avps,
                                      bool mandatory = true, std::optional<uint32_t> vendor = std::nullopt);

    // Extraction methods
    [[nodiscard]] uint32_t to_unsigned32() const;
    [[nodiscard]] uint64_t to_unsigned64() const;
    [[nodiscard]] int32_t to_integer32() const;
    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] std::vector<uint8_t> to_octet_string() const { return data; }
    [[nodiscard]] std::vector<DiameterAvp> to_grouped() const;

    // Binary serialization & deserialization
    [[nodiscard]] std::vector<uint8_t> serialize() const;
    static std::optional<DiameterAvp> decode(common::ByteStreamReader& reader);
};

} // namespace diameter
} // namespace gpp
