#include <3gpp/lte_nas/EmmMessage.hpp>
#include <stdexcept>

namespace gpp::lte_nas {

// ─── AttachRequest ──────────────────────────────────────────────────────────

std::vector<uint8_t> AttachRequest::encode() const {
    NasHeader hdr{
        SecurityHeaderType::PlainNas,
        ProtocolDiscriminator::EMM,
        static_cast<uint8_t>(EmmMessageType::AttachRequest)
    };
    auto out = hdr.encode();

    // NAS key set ID (4 bits) | EPS attach type (4 bits)
    out.push_back(static_cast<uint8_t>((nas_key_set_id << 4) | (eps_attach_type & 0x0F)));

    // Mobile Identity LV
    auto mi = mobile_id.encode();
    out.insert(out.end(), mi.begin(), mi.end());

    // UE network capability LV (1 byte length + value)
    out.push_back(static_cast<uint8_t>(ue_network_capability.size()));
    out.insert(out.end(), ue_network_capability.begin(), ue_network_capability.end());

    // ESM message container LV-E (2 bytes length + value)
    uint16_t esm_len = static_cast<uint16_t>(esm_message_container.size());
    out.push_back(static_cast<uint8_t>(esm_len >> 8));
    out.push_back(static_cast<uint8_t>(esm_len & 0xFF));
    out.insert(out.end(), esm_message_container.begin(), esm_message_container.end());

    return out;
}

AttachRequest AttachRequest::decode(std::span<const uint8_t> data) {
    size_t offset = 0;
    auto hdr = NasHeader::decode(data, offset);
    if (hdr.protocol_discriminator != ProtocolDiscriminator::EMM ||
        hdr.message_type != static_cast<uint8_t>(EmmMessageType::AttachRequest)) {
        throw std::runtime_error("Invalid header for AttachRequest");
    }

    if (data.size() < offset + 1) {
        throw std::runtime_error("AttachRequest truncated at key set / attach type");
    }
    AttachRequest req;
    req.nas_key_set_id = static_cast<uint8_t>(data[offset] >> 4);
    req.eps_attach_type = data[offset] & 0x0F;
    offset += 1;

    // Mobile Identity LV
    if (data.size() < offset + 1) {
        throw std::runtime_error("AttachRequest truncated at MobileIdentity length");
    }
    uint8_t mi_len = data[offset];
    if (data.size() < offset + 1 + mi_len) {
        throw std::runtime_error("AttachRequest truncated at MobileIdentity value");
    }
    req.mobile_id = MobileIdentity::decode_imsi(data.subspan(offset, 1 + mi_len));
    offset += 1 + mi_len;

    // UE network capability LV
    if (data.size() < offset + 1) {
        throw std::runtime_error("AttachRequest truncated at UE network capability length");
    }
    uint8_t ue_cap_len = data[offset++];
    if (data.size() < offset + ue_cap_len) {
        throw std::runtime_error("AttachRequest truncated at UE network capability value");
    }
    req.ue_network_capability.assign(data.begin() + static_cast<ptrdiff_t>(offset),
                                    data.begin() + static_cast<ptrdiff_t>(offset + ue_cap_len));
    offset += ue_cap_len;

    // ESM message container LV-E (2 bytes length)
    if (data.size() < offset + 2) {
        throw std::runtime_error("AttachRequest truncated at ESM container length");
    }
    uint16_t esm_len = static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
    offset += 2;
    if (data.size() < offset + esm_len) {
        throw std::runtime_error("AttachRequest truncated at ESM container value");
    }
    req.esm_message_container.assign(data.begin() + static_cast<ptrdiff_t>(offset),
                                     data.begin() + static_cast<ptrdiff_t>(offset + esm_len));
    offset += esm_len;

    return req;
}

// ─── AttachAccept ───────────────────────────────────────────────────────────

std::vector<uint8_t> AttachAccept::encode() const {
    NasHeader hdr{
        SecurityHeaderType::PlainNas,
        ProtocolDiscriminator::EMM,
        static_cast<uint8_t>(EmmMessageType::AttachAccept)
    };
    auto out = hdr.encode();

    // EPS attach result (spare 4 bits | result 4 bits)
    out.push_back(eps_attach_result & 0x0F);

    // T3412 value
    out.push_back(t3412_value);

    // TAI list LV
    auto tai = tai_list.encode();
    out.insert(out.end(), tai.begin(), tai.end());

    // ESM message container LV-E
    uint16_t esm_len = static_cast<uint16_t>(esm_message_container.size());
    out.push_back(static_cast<uint8_t>(esm_len >> 8));
    out.push_back(static_cast<uint8_t>(esm_len & 0xFF));
    out.insert(out.end(), esm_message_container.begin(), esm_message_container.end());

    // GUTI TLV (IEI = 0x50)
    auto g = guti.encode();
    out.insert(out.end(), g.begin(), g.end());

    return out;
}

AttachAccept AttachAccept::decode(std::span<const uint8_t> data) {
    size_t offset = 0;
    auto hdr = NasHeader::decode(data, offset);
    if (hdr.protocol_discriminator != ProtocolDiscriminator::EMM ||
        hdr.message_type != static_cast<uint8_t>(EmmMessageType::AttachAccept)) {
        throw std::runtime_error("Invalid header for AttachAccept");
    }

    if (data.size() < offset + 2) {
        throw std::runtime_error("AttachAccept truncated at result / T3412");
    }
    AttachAccept accept;
    accept.eps_attach_result = data[offset++] & 0x0F;
    accept.t3412_value = data[offset++];

    // TAI list LV
    if (data.size() < offset + 1) {
        throw std::runtime_error("AttachAccept truncated at TAI list length");
    }
    uint8_t tai_len = data[offset];
    if (data.size() < offset + 1 + tai_len) {
        throw std::runtime_error("AttachAccept truncated at TAI list value");
    }
    accept.tai_list = TaiList::decode(data.subspan(offset, 1 + tai_len));
    offset += 1 + tai_len;

    // ESM message container LV-E (2 bytes length)
    if (data.size() < offset + 2) {
        throw std::runtime_error("AttachAccept truncated at ESM container length");
    }
    uint16_t esm_len = static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
    offset += 2;
    if (data.size() < offset + esm_len) {
        throw std::runtime_error("AttachAccept truncated at ESM container value");
    }
    accept.esm_message_container.assign(data.begin() + static_cast<ptrdiff_t>(offset),
                                        data.begin() + static_cast<ptrdiff_t>(offset + esm_len));
    offset += esm_len;

    // GUTI TLV
    if (offset < data.size()) {
        accept.guti = Guti::decode(data, offset);
    }

    return accept;
}

// ─── AttachComplete ─────────────────────────────────────────────────────────

std::vector<uint8_t> AttachComplete::encode() const {
    NasHeader hdr{
        SecurityHeaderType::PlainNas,
        ProtocolDiscriminator::EMM,
        static_cast<uint8_t>(EmmMessageType::AttachComplete)
    };
    auto out = hdr.encode();

    // ESM message container LV-E
    uint16_t esm_len = static_cast<uint16_t>(esm_message_container.size());
    out.push_back(static_cast<uint8_t>(esm_len >> 8));
    out.push_back(static_cast<uint8_t>(esm_len & 0xFF));
    out.insert(out.end(), esm_message_container.begin(), esm_message_container.end());

    return out;
}

AttachComplete AttachComplete::decode(std::span<const uint8_t> data) {
    size_t offset = 0;
    auto hdr = NasHeader::decode(data, offset);
    if (hdr.protocol_discriminator != ProtocolDiscriminator::EMM ||
        hdr.message_type != static_cast<uint8_t>(EmmMessageType::AttachComplete)) {
        throw std::runtime_error("Invalid header for AttachComplete");
    }

    if (data.size() < offset + 2) {
        throw std::runtime_error("AttachComplete truncated at ESM container length");
    }
    uint16_t esm_len = static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
    offset += 2;
    if (data.size() < offset + esm_len) {
        throw std::runtime_error("AttachComplete truncated at ESM container value");
    }
    AttachComplete comp;
    comp.esm_message_container.assign(data.begin() + static_cast<ptrdiff_t>(offset),
                                      data.begin() + static_cast<ptrdiff_t>(offset + esm_len));
    return comp;
}

} // namespace gpp::lte_nas
