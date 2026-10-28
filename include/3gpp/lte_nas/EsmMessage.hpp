#pragma once
#include "NasCommon.hpp"
#include "NasIe.hpp"
#include <vector>
#include <span>

namespace gpp::lte_nas {

// ESM PDN Connectivity Request (TS 24.301 §8.3.18)
struct PdnConnectivityRequest {
    uint8_t eps_bearer_id{0};
    uint8_t procedure_transaction_id{1};
    uint8_t pdn_type{0x01};    // IPv4
    uint8_t request_type{0x01}; // initial request

    std::vector<uint8_t> encode() const;
    static PdnConnectivityRequest decode(std::span<const uint8_t> data);
};

// ESM Activate Default EPS Bearer Context Request (TS 24.301 §8.3.6)
struct ActivateDefaultEpsBearerContextRequest {
    uint8_t eps_bearer_id{5};
    uint8_t procedure_transaction_id{1};
    EpsQoS qos;
    AccessPointName apn;
    PdnAddress pdn_address;

    std::vector<uint8_t> encode() const;
    static ActivateDefaultEpsBearerContextRequest decode(std::span<const uint8_t> data);
};

// ESM Activate Default EPS Bearer Context Accept (TS 24.301 §8.3.4)
struct ActivateDefaultEpsBearerContextAccept {
    uint8_t eps_bearer_id{5};
    uint8_t procedure_transaction_id{1};

    std::vector<uint8_t> encode() const;
    static ActivateDefaultEpsBearerContextAccept decode(std::span<const uint8_t> data);
};

} // namespace gpp::lte_nas
