#pragma once
#include "NasCommon.hpp"
#include "NasIe.hpp"
#include <vector>
#include <span>

namespace gpp::lte_nas {

// EMM Attach Request (TS 24.301 §8.2.4)
struct AttachRequest {
    uint8_t eps_attach_type{0x01};   // 0x01 = EPS Attach
    uint8_t nas_key_set_id{0x07};    // 0x07 = no key available
    MobileIdentity mobile_id;
    std::vector<uint8_t> ue_network_capability; // raw bytes
    std::vector<uint8_t> esm_message_container; // encoded ESM PDU

    std::vector<uint8_t> encode() const;
    static AttachRequest decode(std::span<const uint8_t> data);
};

// EMM Attach Accept (TS 24.301 §8.2.1)
struct AttachAccept {
    uint8_t eps_attach_result{0x01}; // 0x01 = EPS Only
    uint8_t t3412_value{0x21};       // 54 minutes
    TaiList tai_list;
    std::vector<uint8_t> esm_message_container;
    Guti guti;

    std::vector<uint8_t> encode() const;
    static AttachAccept decode(std::span<const uint8_t> data);
};

// EMM Attach Complete (TS 24.301 §8.2.3)
struct AttachComplete {
    std::vector<uint8_t> esm_message_container;

    std::vector<uint8_t> encode() const;
    static AttachComplete decode(std::span<const uint8_t> data);
};

} // namespace gpp::lte_nas
