#include <3gpp/lte_nas/EsmMessage.hpp>
#include <stdexcept>

namespace gpp::lte_nas {

// ─── PdnConnectivityRequest ─────────────────────────────────────────────────

std::vector<uint8_t> PdnConnectivityRequest::encode() const {
    EsmHeader hdr{
        eps_bearer_id,
        ProtocolDiscriminator::ESM,
        procedure_transaction_id,
        static_cast<uint8_t>(EsmMessageType::PdnConnectivityRequest)
    };
    auto out = hdr.encode();

    // Request type (4 bits) | PDN type (4 bits)
    out.push_back(static_cast<uint8_t>((request_type << 4) | (pdn_type & 0x0F)));
    return out;
}

PdnConnectivityRequest PdnConnectivityRequest::decode(std::span<const uint8_t> data) {
    size_t offset = 0;
    auto hdr = EsmHeader::decode(data, offset);
    if (hdr.protocol_discriminator != ProtocolDiscriminator::ESM ||
        hdr.message_type != static_cast<uint8_t>(EsmMessageType::PdnConnectivityRequest)) {
        throw std::runtime_error("Invalid header for PdnConnectivityRequest");
    }

    if (data.size() < offset + 1) {
        throw std::runtime_error("PdnConnectivityRequest truncated at request/PDN type");
    }
    PdnConnectivityRequest req;
    req.eps_bearer_id = hdr.eps_bearer_id;
    req.procedure_transaction_id = hdr.procedure_transaction_id;

    uint8_t b = data[offset++];
    req.request_type = static_cast<uint8_t>(b >> 4);
    req.pdn_type = b & 0x0F;

    return req;
}

// ─── ActivateDefaultEpsBearerContextRequest ──────────────────────────────────

std::vector<uint8_t> ActivateDefaultEpsBearerContextRequest::encode() const {
    EsmHeader hdr{
        eps_bearer_id,
        ProtocolDiscriminator::ESM,
        procedure_transaction_id,
        static_cast<uint8_t>(EsmMessageType::ActivateDefaultEpsBearerContextRequest)
    };
    auto out = hdr.encode();

    // EPS QoS LV
    auto q = qos.encode();
    out.insert(out.end(), q.begin(), q.end());

    // Access Point Name LV
    auto a = apn.encode();
    out.insert(out.end(), a.begin(), a.end());

    // PDN Address LV
    auto p = pdn_address.encode();
    out.insert(out.end(), p.begin(), p.end());

    return out;
}

ActivateDefaultEpsBearerContextRequest ActivateDefaultEpsBearerContextRequest::decode(
    std::span<const uint8_t> data) {
    size_t offset = 0;
    auto hdr = EsmHeader::decode(data, offset);
    if (hdr.protocol_discriminator != ProtocolDiscriminator::ESM ||
        hdr.message_type != static_cast<uint8_t>(EsmMessageType::ActivateDefaultEpsBearerContextRequest)) {
        throw std::runtime_error("Invalid header for ActivateDefaultEpsBearerContextRequest");
    }

    ActivateDefaultEpsBearerContextRequest req;
    req.eps_bearer_id = hdr.eps_bearer_id;
    req.procedure_transaction_id = hdr.procedure_transaction_id;

    // EPS QoS LV
    if (data.size() < offset + 1) {
        throw std::runtime_error("ActivateDefaultEpsBearerContextRequest truncated at QoS len");
    }
    uint8_t qos_len = data[offset];
    if (data.size() < offset + 1 + qos_len) {
        throw std::runtime_error("ActivateDefaultEpsBearerContextRequest truncated at QoS value");
    }
    req.qos = EpsQoS::decode(data.subspan(offset, 1 + qos_len));
    offset += 1 + qos_len;

    // Access Point Name LV
    if (data.size() < offset + 1) {
        throw std::runtime_error("ActivateDefaultEpsBearerContextRequest truncated at APN len");
    }
    uint8_t apn_len = data[offset];
    if (data.size() < offset + 1 + apn_len) {
        throw std::runtime_error("ActivateDefaultEpsBearerContextRequest truncated at APN value");
    }
    req.apn = AccessPointName::decode(data.subspan(offset, 1 + apn_len));
    offset += 1 + apn_len;

    // PDN Address LV
    if (data.size() < offset + 1) {
        throw std::runtime_error("ActivateDefaultEpsBearerContextRequest truncated at PDN address len");
    }
    uint8_t pdn_len = data[offset];
    if (data.size() < offset + 1 + pdn_len) {
        throw std::runtime_error("ActivateDefaultEpsBearerContextRequest truncated at PDN address value");
    }
    req.pdn_address = PdnAddress::decode(data.subspan(offset, 1 + pdn_len));
    offset += 1 + pdn_len;

    return req;
}

// ─── ActivateDefaultEpsBearerContextAccept ──────────────────────────────────

std::vector<uint8_t> ActivateDefaultEpsBearerContextAccept::encode() const {
    EsmHeader hdr{
        eps_bearer_id,
        ProtocolDiscriminator::ESM,
        procedure_transaction_id,
        static_cast<uint8_t>(EsmMessageType::ActivateDefaultEpsBearerContextAccept)
    };
    return hdr.encode();
}

ActivateDefaultEpsBearerContextAccept ActivateDefaultEpsBearerContextAccept::decode(
    std::span<const uint8_t> data) {
    size_t offset = 0;
    auto hdr = EsmHeader::decode(data, offset);
    if (hdr.protocol_discriminator != ProtocolDiscriminator::ESM ||
        hdr.message_type != static_cast<uint8_t>(EsmMessageType::ActivateDefaultEpsBearerContextAccept)) {
        throw std::runtime_error("Invalid header for ActivateDefaultEpsBearerContextAccept");
    }
    ActivateDefaultEpsBearerContextAccept acc;
    acc.eps_bearer_id = hdr.eps_bearer_id;
    acc.procedure_transaction_id = hdr.procedure_transaction_id;
    return acc;
}

} // namespace gpp::lte_nas
