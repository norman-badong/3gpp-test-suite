#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <span>
#include <array>
#include <optional>

namespace gpp::nr_nas {

// 5GS Mobile Identity — SUCI (Subscription Concealed Identifier, TS 24.501 §9.11.3.4)
struct Suci {
    std::string mcc{"001"};
    std::string mnc{"01"};
    uint16_t    routing_indicator{0};       // e.g. 0x0000
    uint8_t     protection_scheme{0};       // 0x0 = Null scheme
    uint8_t     home_network_pki{0};        // Public key ID
    std::string msin{"0123456789"};         // Subscriber identity

    [[nodiscard]] std::vector<uint8_t> encode() const; // returns 2-byte length + value
    static Suci decode(std::span<const uint8_t> data, size_t& offset);
};

// 5GS Mobile Identity — 5G-GUTI (TS 24.501 §9.11.3.4)
struct NrGuti {
    std::string mcc{"001"};
    std::string mnc{"01"};
    uint8_t     amf_region_id{1};           // 8 bits
    uint16_t    amf_set_id{1};              // 10 bits
    uint8_t     amf_pointer{1};             // 6 bits
    uint32_t    tmsi{0xABCD1234};           // 32-bit 5G-TMSI

    [[nodiscard]] std::vector<uint8_t> encode() const; // returns TLV (IEI=0x77)
    static NrGuti decode(std::span<const uint8_t> data, size_t& offset);
};

// S-NSSAI — Single Network Slice Selection Assistance Information (TS 24.501 §9.11.2.8)
struct SNssai {
    uint8_t                 sst{1};         // Slice/Service Type (1=eMBB, 2=URLLC, 3=MIoT)
    std::optional<uint32_t> sd{0x000001};   // 24-bit Slice Differentiator

    [[nodiscard]] std::vector<uint8_t> encode() const; // returns LV
    static SNssai decode(std::span<const uint8_t> lv);
};

// PDU Session Type (TS 24.501 §9.11.4.11)
enum class PduSessionType : uint8_t {
    Ipv4         = 0x01,
    Ipv6         = 0x02,
    Ipv4v6       = 0x03,
    Unstructured = 0x04,
    Ethernet     = 0x05,
};

// SSC Mode — Session and Service Continuity Mode (TS 24.501 §9.11.4.16)
enum class SscMode : uint8_t {
    Mode1 = 0x01,
    Mode2 = 0x02,
    Mode3 = 0x03,
};

// DNN — Data Network Name (TS 24.501 §9.11.2.1A)
struct Dnn {
    std::string dnn{"internet"};

    [[nodiscard]] std::vector<uint8_t> encode() const; // returns LV
    static Dnn decode(std::span<const uint8_t> lv);
};

// 5GS PDU Address (TS 24.501 §9.11.4.10)
struct NrPduAddress {
    uint8_t                pdu_type{0x01}; // IPv4
    std::array<uint8_t, 4> ipv4{10, 45, 0, 2};

    [[nodiscard]] std::vector<uint8_t> encode() const; // returns LV
    static NrPduAddress decode(std::span<const uint8_t> lv);
};

// Authorized QoS Rule / QFI (TS 24.501 §9.11.4.13)
struct NrQosRule {
    uint8_t qfi{1};                         // QoS Flow Identifier
    uint8_t five_qi{9};                     // 5QI (e.g. 9 = default best-effort)

    [[nodiscard]] std::vector<uint8_t> encode() const; // returns LV
    static NrQosRule decode(std::span<const uint8_t> lv);
};

} // namespace gpp::nr_nas
