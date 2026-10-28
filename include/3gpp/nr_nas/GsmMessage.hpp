#pragma once

#include "NrNasCommon.hpp"
#include "NrNasIe.hpp"
#include <vector>
#include <span>

namespace gpp::nr_nas {

// 5GSM PDU Session Establishment Request (TS 24.501 §8.3.1)
struct PduSessionEstablishmentRequest {
    uint8_t        pdu_session_id{1};           // 1 to 15
    uint8_t        procedure_transaction_id{1}; // 1 to 254
    PduSessionType session_type{PduSessionType::Ipv4};
    SscMode        ssc_mode{SscMode::Mode1};
    SNssai         s_nssai;
    Dnn            dnn;

    [[nodiscard]] std::vector<uint8_t> encode() const;
    static PduSessionEstablishmentRequest decode(std::span<const uint8_t> data);
};

// 5GSM PDU Session Establishment Accept (TS 24.501 §8.3.2)
struct PduSessionEstablishmentAccept {
    uint8_t        pdu_session_id{1};
    uint8_t        procedure_transaction_id{1};
    PduSessionType session_type{PduSessionType::Ipv4};
    SscMode        ssc_mode{SscMode::Mode1};
    NrQosRule      qos_rule;
    NrPduAddress   pdu_address;
    SNssai         s_nssai;
    Dnn            dnn;

    [[nodiscard]] std::vector<uint8_t> encode() const;
    static PduSessionEstablishmentAccept decode(std::span<const uint8_t> data);
};

// 5GSM PDU Session Establishment Reject (TS 24.501 §8.3.3)
struct PduSessionEstablishmentReject {
    uint8_t pdu_session_id{1};
    uint8_t procedure_transaction_id{1};
    uint8_t gsm_cause{0x1B}; // e.g. 0x1B = Missing or unknown DNN

    [[nodiscard]] std::vector<uint8_t> encode() const;
    static PduSessionEstablishmentReject decode(std::span<const uint8_t> data);
};

} // namespace gpp::nr_nas
