#include <3gpp/nr_nas/GsmMessage.hpp>
#include <stdexcept>

namespace gpp::nr_nas {

// ─── PduSessionEstablishmentRequest ─────────────────────────────────────────

std::vector<uint8_t> PduSessionEstablishmentRequest::encode() const {
    NrGsmHeader hdr{
        ExtendedProtocolDiscriminator::GSM,
        pdu_session_id,
        procedure_transaction_id,
        static_cast<uint8_t>(GsmMessageType::PduSessionEstablishmentRequest)
    };
    auto out = hdr.encode();

    // PDU session type (4 bits) | SSC mode (4 bits)
    out.push_back(static_cast<uint8_t>(
        (static_cast<uint8_t>(session_type) << 4) | (static_cast<uint8_t>(ssc_mode) & 0x0F)));

    // S-NSSAI LV
    auto s_bytes = s_nssai.encode();
    out.insert(out.end(), s_bytes.begin(), s_bytes.end());

    // DNN LV
    auto d_bytes = dnn.encode();
    out.insert(out.end(), d_bytes.begin(), d_bytes.end());

    return out;
}

PduSessionEstablishmentRequest PduSessionEstablishmentRequest::decode(
    std::span<const uint8_t> data) {
    size_t offset = 0;
    auto hdr = NrGsmHeader::decode(data, offset);
    if (hdr.epd != ExtendedProtocolDiscriminator::GSM ||
        hdr.message_type != static_cast<uint8_t>(GsmMessageType::PduSessionEstablishmentRequest)) {
        throw std::runtime_error("Invalid header for 5GSM PduSessionEstablishmentRequest");
    }

    if (data.size() < offset + 1) {
        throw std::runtime_error("PduSessionEstablishmentRequest truncated at session type/SSC mode");
    }
    PduSessionEstablishmentRequest req;
    req.pdu_session_id = hdr.pdu_session_id;
    req.procedure_transaction_id = hdr.procedure_transaction_id;

    uint8_t b = data[offset++];
    req.session_type = static_cast<PduSessionType>((b >> 4) & 0x0F);
    req.ssc_mode = static_cast<SscMode>(b & 0x0F);

    // S-NSSAI LV
    if (data.size() < offset + 1) {
        throw std::runtime_error("PduSessionEstablishmentRequest truncated at S-NSSAI len");
    }
    uint8_t snssai_len = data[offset];
    if (data.size() < offset + 1 + snssai_len) {
        throw std::runtime_error("PduSessionEstablishmentRequest truncated at S-NSSAI value");
    }
    req.s_nssai = SNssai::decode(data.subspan(offset, 1 + snssai_len));
    offset += 1 + snssai_len;

    // DNN LV
    if (data.size() < offset + 1) {
        throw std::runtime_error("PduSessionEstablishmentRequest truncated at DNN len");
    }
    uint8_t dnn_len = data[offset];
    if (data.size() < offset + 1 + dnn_len) {
        throw std::runtime_error("PduSessionEstablishmentRequest truncated at DNN value");
    }
    req.dnn = Dnn::decode(data.subspan(offset, 1 + dnn_len));
    offset += 1 + dnn_len;

    return req;
}

// ─── PduSessionEstablishmentAccept ──────────────────────────────────────────

std::vector<uint8_t> PduSessionEstablishmentAccept::encode() const {
    NrGsmHeader hdr{
        ExtendedProtocolDiscriminator::GSM,
        pdu_session_id,
        procedure_transaction_id,
        static_cast<uint8_t>(GsmMessageType::PduSessionEstablishmentAccept)
    };
    auto out = hdr.encode();

    // Selected PDU session type (4 bits) | Selected SSC mode (4 bits)
    out.push_back(static_cast<uint8_t>(
        (static_cast<uint8_t>(session_type) << 4) | (static_cast<uint8_t>(ssc_mode) & 0x0F)));

    // QoS Rule LV
    auto q_bytes = qos_rule.encode();
    out.insert(out.end(), q_bytes.begin(), q_bytes.end());

    // PDU Address LV
    auto p_bytes = pdu_address.encode();
    out.insert(out.end(), p_bytes.begin(), p_bytes.end());

    // S-NSSAI LV
    auto s_bytes = s_nssai.encode();
    out.insert(out.end(), s_bytes.begin(), s_bytes.end());

    // DNN LV
    auto d_bytes = dnn.encode();
    out.insert(out.end(), d_bytes.begin(), d_bytes.end());

    return out;
}

PduSessionEstablishmentAccept PduSessionEstablishmentAccept::decode(
    std::span<const uint8_t> data) {
    size_t offset = 0;
    auto hdr = NrGsmHeader::decode(data, offset);
    if (hdr.epd != ExtendedProtocolDiscriminator::GSM ||
        hdr.message_type != static_cast<uint8_t>(GsmMessageType::PduSessionEstablishmentAccept)) {
        throw std::runtime_error("Invalid header for 5GSM PduSessionEstablishmentAccept");
    }

    if (data.size() < offset + 1) {
        throw std::runtime_error("PduSessionEstablishmentAccept truncated at session type/SSC mode");
    }
    PduSessionEstablishmentAccept acc;
    acc.pdu_session_id = hdr.pdu_session_id;
    acc.procedure_transaction_id = hdr.procedure_transaction_id;

    uint8_t b = data[offset++];
    acc.session_type = static_cast<PduSessionType>((b >> 4) & 0x0F);
    acc.ssc_mode = static_cast<SscMode>(b & 0x0F);

    // QoS Rule LV
    if (data.size() < offset + 1) {
        throw std::runtime_error("PduSessionEstablishmentAccept truncated at QoS rule len");
    }
    uint8_t qos_len = data[offset];
    if (data.size() < offset + 1 + qos_len) {
        throw std::runtime_error("PduSessionEstablishmentAccept truncated at QoS rule value");
    }
    acc.qos_rule = NrQosRule::decode(data.subspan(offset, 1 + qos_len));
    offset += 1 + qos_len;

    // PDU Address LV
    if (data.size() < offset + 1) {
        throw std::runtime_error("PduSessionEstablishmentAccept truncated at PDU address len");
    }
    uint8_t addr_len = data[offset];
    if (data.size() < offset + 1 + addr_len) {
        throw std::runtime_error("PduSessionEstablishmentAccept truncated at PDU address value");
    }
    acc.pdu_address = NrPduAddress::decode(data.subspan(offset, 1 + addr_len));
    offset += 1 + addr_len;

    // S-NSSAI LV
    if (data.size() < offset + 1) {
        throw std::runtime_error("PduSessionEstablishmentAccept truncated at S-NSSAI len");
    }
    uint8_t snssai_len = data[offset];
    if (data.size() < offset + 1 + snssai_len) {
        throw std::runtime_error("PduSessionEstablishmentAccept truncated at S-NSSAI value");
    }
    acc.s_nssai = SNssai::decode(data.subspan(offset, 1 + snssai_len));
    offset += 1 + snssai_len;

    // DNN LV
    if (data.size() < offset + 1) {
        throw std::runtime_error("PduSessionEstablishmentAccept truncated at DNN len");
    }
    uint8_t dnn_len = data[offset];
    if (data.size() < offset + 1 + dnn_len) {
        throw std::runtime_error("PduSessionEstablishmentAccept truncated at DNN value");
    }
    acc.dnn = Dnn::decode(data.subspan(offset, 1 + dnn_len));
    offset += 1 + dnn_len;

    return acc;
}

// ─── PduSessionEstablishmentReject ──────────────────────────────────────────

std::vector<uint8_t> PduSessionEstablishmentReject::encode() const {
    NrGsmHeader hdr{
        ExtendedProtocolDiscriminator::GSM,
        pdu_session_id,
        procedure_transaction_id,
        static_cast<uint8_t>(GsmMessageType::PduSessionEstablishmentReject)
    };
    auto out = hdr.encode();
    out.push_back(gsm_cause);
    return out;
}

PduSessionEstablishmentReject PduSessionEstablishmentReject::decode(
    std::span<const uint8_t> data) {
    size_t offset = 0;
    auto hdr = NrGsmHeader::decode(data, offset);
    if (hdr.epd != ExtendedProtocolDiscriminator::GSM ||
        hdr.message_type != static_cast<uint8_t>(GsmMessageType::PduSessionEstablishmentReject)) {
        throw std::runtime_error("Invalid header for 5GSM PduSessionEstablishmentReject");
    }

    if (data.size() < offset + 1) {
        throw std::runtime_error("PduSessionEstablishmentReject truncated at cause");
    }
    PduSessionEstablishmentReject rej;
    rej.pdu_session_id = hdr.pdu_session_id;
    rej.procedure_transaction_id = hdr.procedure_transaction_id;
    rej.gsm_cause = data[offset++];
    return rej;
}

} // namespace gpp::nr_nas
