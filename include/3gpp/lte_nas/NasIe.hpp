#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <span>
#include <array>
#include <optional>

namespace gpp::lte_nas {

// Mobile Identity — IMSI encoding per TS 24.008 §10.5.1.4
struct MobileIdentity {
    std::string imsi; // e.g. "001010123456789"

    std::vector<uint8_t> encode() const;           // returns LV (length + value)
    static MobileIdentity decode_imsi(std::span<const uint8_t> lv); // reads LV
};

// GUTI — Globally Unique Temporary UE Identity
struct Guti {
    std::string mcc;         // e.g. "001"
    std::string mnc;         // e.g. "01"
    uint16_t    mme_group_id{1};
    uint8_t     mme_code{1};
    uint32_t    m_tmsi{0x12345678};

    std::vector<uint8_t> encode() const;                              // returns TLV with IEI=0x50
    static Guti decode(std::span<const uint8_t> data, size_t& offset); // reads TLV
};

// TAI List — Tracking Area Identity list
struct TaiList {
    std::string           mcc;  // e.g. "001"
    std::string           mnc;  // e.g. "01"
    std::vector<uint16_t> tacs; // list of TACs

    std::vector<uint8_t> encode() const;               // returns LV
    static TaiList decode(std::span<const uint8_t> lv);
};

// EPS QoS
struct EpsQoS {
    uint8_t qci{9};

    std::vector<uint8_t> encode() const;               // returns LV [0x01][qci]
    static EpsQoS decode(std::span<const uint8_t> lv);
};

// Access Point Name
struct AccessPointName {
    std::string apn; // e.g. "internet"

    std::vector<uint8_t> encode() const;                    // returns LV with label encoding
    static AccessPointName decode(std::span<const uint8_t> lv);
};

// PDN Address
struct PdnAddress {
    uint8_t                pdn_type{0x01}; // 0x01 = IPv4
    std::array<uint8_t, 4> ipv4{10, 0, 0, 1};

    std::vector<uint8_t> encode() const;               // returns LV [0x05][0x01][4 bytes]
    static PdnAddress decode(std::span<const uint8_t> lv);
};

} // namespace gpp::lte_nas
