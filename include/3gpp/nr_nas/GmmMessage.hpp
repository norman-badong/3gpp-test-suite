#pragma once

#include "NrNasCommon.hpp"
#include "NrNasIe.hpp"
#include <vector>
#include <span>

namespace gpp::nr_nas {

// 5GMM Registration Request (TS 24.501 §8.2.6)
struct RegistrationRequest {
    uint8_t              registration_type{0x01}; // 0x01 = Initial Registration
    uint8_t              ng_ksi{0x07};            // 0x07 = No key available
    Suci                 suci;
    std::vector<uint8_t> ue_security_capability;  // Raw bytes (e.g. 5G-EA, 5G-IA)
    std::vector<SNssai>  requested_nssai;
    std::vector<uint8_t> gsm_message_container;   // Piggybacked 5GSM PDU

    [[nodiscard]] std::vector<uint8_t> encode() const;
    static RegistrationRequest decode(std::span<const uint8_t> data);
};

// 5GMM Registration Accept (TS 24.501 §8.2.7)
struct RegistrationAccept {
    uint8_t              registration_result{0x01}; // 0x01 = 3GPP access
    NrGuti               guti;
    uint8_t              t3512_value{0x21};         // GPRS timer (e.g. 54 min)
    std::vector<SNssai>  allowed_nssai;
    std::vector<uint8_t> gsm_message_container;     // Embedded 5GSM Accept PDU

    [[nodiscard]] std::vector<uint8_t> encode() const;
    static RegistrationAccept decode(std::span<const uint8_t> data);
};

// 5GMM Registration Complete (TS 24.501 §8.2.8)
struct RegistrationComplete {
    std::vector<uint8_t> gsm_message_container;

    [[nodiscard]] std::vector<uint8_t> encode() const;
    static RegistrationComplete decode(std::span<const uint8_t> data);
};

} // namespace gpp::nr_nas
