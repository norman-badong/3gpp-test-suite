#include <3gpp/nr_nas/GmmMessage.hpp>
#include <stdexcept>

namespace gpp::nr_nas {

// ─── RegistrationRequest ────────────────────────────────────────────────────

std::vector<uint8_t> RegistrationRequest::encode() const {
    NrNasHeader hdr{
        ExtendedProtocolDiscriminator::GMM,
        SecurityHeaderType::PlainNas,
        static_cast<uint8_t>(GmmMessageType::RegistrationRequest)
    };
    auto out = hdr.encode();

    // ngKSI (4 bits) | 5GS registration type (4 bits)
    out.push_back(static_cast<uint8_t>((ng_ksi << 4) | (registration_type & 0x0F)));

    // 5GS Mobile Identity (SUCI)
    auto suci_bytes = suci.encode();
    out.insert(out.end(), suci_bytes.begin(), suci_bytes.end());

    // UE security capability LV (1-byte length + value)
    out.push_back(static_cast<uint8_t>(ue_security_capability.size()));
    out.insert(out.end(), ue_security_capability.begin(), ue_security_capability.end());

    // Requested NSSAI (1-byte count of S-NSSAIs + each encoded S-NSSAI)
    out.push_back(static_cast<uint8_t>(requested_nssai.size()));
    for (const auto& snssai : requested_nssai) {
        auto s_bytes = snssai.encode();
        out.insert(out.end(), s_bytes.begin(), s_bytes.end());
    }

    // 5GSM message container LV-E (2-byte length + value)
    uint16_t gsm_len = static_cast<uint16_t>(gsm_message_container.size());
    out.push_back(static_cast<uint8_t>(gsm_len >> 8));
    out.push_back(static_cast<uint8_t>(gsm_len & 0xFF));
    out.insert(out.end(), gsm_message_container.begin(), gsm_message_container.end());

    return out;
}

RegistrationRequest RegistrationRequest::decode(std::span<const uint8_t> data) {
    size_t offset = 0;
    auto hdr = NrNasHeader::decode(data, offset);
    if (hdr.epd != ExtendedProtocolDiscriminator::GMM ||
        hdr.message_type != static_cast<uint8_t>(GmmMessageType::RegistrationRequest)) {
        throw std::runtime_error("Invalid header for 5GMM RegistrationRequest");
    }

    if (data.size() < offset + 1) {
        throw std::runtime_error("RegistrationRequest truncated at ngKSI/regType");
    }
    RegistrationRequest req;
    req.ng_ksi = static_cast<uint8_t>(data[offset] >> 4);
    req.registration_type = data[offset] & 0x0F;
    offset += 1;

    // SUCI
    req.suci = Suci::decode(data, offset);

    // UE security capability LV
    if (data.size() < offset + 1) {
        throw std::runtime_error("RegistrationRequest truncated at UE security capability length");
    }
    uint8_t sec_len = data[offset++];
    if (data.size() < offset + sec_len) {
        throw std::runtime_error("RegistrationRequest truncated at UE security capability value");
    }
    req.ue_security_capability.assign(data.begin() + static_cast<ptrdiff_t>(offset),
                                     data.begin() + static_cast<ptrdiff_t>(offset + sec_len));
    offset += sec_len;

    // Requested NSSAI
    if (data.size() < offset + 1) {
        throw std::runtime_error("RegistrationRequest truncated at requested NSSAI count");
    }
    uint8_t nssai_count = data[offset++];
    for (size_t i = 0; i < nssai_count; ++i) {
        if (data.size() < offset + 1) {
            throw std::runtime_error("RegistrationRequest truncated at S-NSSAI length");
        }
        uint8_t snssai_len = data[offset];
        if (data.size() < offset + 1 + snssai_len) {
            throw std::runtime_error("RegistrationRequest truncated at S-NSSAI value");
        }
        req.requested_nssai.push_back(SNssai::decode(data.subspan(offset, 1 + snssai_len)));
        offset += 1 + snssai_len;
    }

    // 5GSM message container LV-E (2-byte length)
    if (data.size() < offset + 2) {
        throw std::runtime_error("RegistrationRequest truncated at 5GSM container length");
    }
    uint16_t gsm_len = static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
    offset += 2;
    if (data.size() < offset + gsm_len) {
        throw std::runtime_error("RegistrationRequest truncated at 5GSM container value");
    }
    req.gsm_message_container.assign(data.begin() + static_cast<ptrdiff_t>(offset),
                                     data.begin() + static_cast<ptrdiff_t>(offset + gsm_len));
    offset += gsm_len;

    return req;
}

// ─── RegistrationAccept ─────────────────────────────────────────────────────

std::vector<uint8_t> RegistrationAccept::encode() const {
    NrNasHeader hdr{
        ExtendedProtocolDiscriminator::GMM,
        SecurityHeaderType::PlainNas,
        static_cast<uint8_t>(GmmMessageType::RegistrationAccept)
    };
    auto out = hdr.encode();

    // 5GS registration result (1 octet)
    out.push_back(registration_result & 0x0F);

    // 5G-GUTI TLV
    auto guti_bytes = guti.encode();
    out.insert(out.end(), guti_bytes.begin(), guti_bytes.end());

    // T3512 value (1 octet)
    out.push_back(t3512_value);

    // Allowed NSSAI (1-byte count of S-NSSAIs + each encoded S-NSSAI)
    out.push_back(static_cast<uint8_t>(allowed_nssai.size()));
    for (const auto& snssai : allowed_nssai) {
        auto s_bytes = snssai.encode();
        out.insert(out.end(), s_bytes.begin(), s_bytes.end());
    }

    // 5GSM message container LV-E (2-byte length + value)
    uint16_t gsm_len = static_cast<uint16_t>(gsm_message_container.size());
    out.push_back(static_cast<uint8_t>(gsm_len >> 8));
    out.push_back(static_cast<uint8_t>(gsm_len & 0xFF));
    out.insert(out.end(), gsm_message_container.begin(), gsm_message_container.end());

    return out;
}

RegistrationAccept RegistrationAccept::decode(std::span<const uint8_t> data) {
    size_t offset = 0;
    auto hdr = NrNasHeader::decode(data, offset);
    if (hdr.epd != ExtendedProtocolDiscriminator::GMM ||
        hdr.message_type != static_cast<uint8_t>(GmmMessageType::RegistrationAccept)) {
        throw std::runtime_error("Invalid header for 5GMM RegistrationAccept");
    }

    if (data.size() < offset + 1) {
        throw std::runtime_error("RegistrationAccept truncated at result");
    }
    RegistrationAccept accept;
    accept.registration_result = data[offset++] & 0x0F;

    // 5G-GUTI
    accept.guti = NrGuti::decode(data, offset);

    // T3512 value
    if (data.size() < offset + 1) {
        throw std::runtime_error("RegistrationAccept truncated at T3512");
    }
    accept.t3512_value = data[offset++];

    // Allowed NSSAI
    if (data.size() < offset + 1) {
        throw std::runtime_error("RegistrationAccept truncated at allowed NSSAI count");
    }
    uint8_t nssai_count = data[offset++];
    for (size_t i = 0; i < nssai_count; ++i) {
        if (data.size() < offset + 1) {
            throw std::runtime_error("RegistrationAccept truncated at S-NSSAI length");
        }
        uint8_t snssai_len = data[offset];
        if (data.size() < offset + 1 + snssai_len) {
            throw std::runtime_error("RegistrationAccept truncated at S-NSSAI value");
        }
        accept.allowed_nssai.push_back(SNssai::decode(data.subspan(offset, 1 + snssai_len)));
        offset += 1 + snssai_len;
    }

    // 5GSM message container LV-E (2-byte length)
    if (data.size() < offset + 2) {
        throw std::runtime_error("RegistrationAccept truncated at 5GSM container length");
    }
    uint16_t gsm_len = static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
    offset += 2;
    if (data.size() < offset + gsm_len) {
        throw std::runtime_error("RegistrationAccept truncated at 5GSM container value");
    }
    accept.gsm_message_container.assign(data.begin() + static_cast<ptrdiff_t>(offset),
                                       data.begin() + static_cast<ptrdiff_t>(offset + gsm_len));
    offset += gsm_len;

    return accept;
}

// ─── RegistrationComplete ───────────────────────────────────────────────────

std::vector<uint8_t> RegistrationComplete::encode() const {
    NrNasHeader hdr{
        ExtendedProtocolDiscriminator::GMM,
        SecurityHeaderType::PlainNas,
        static_cast<uint8_t>(GmmMessageType::RegistrationComplete)
    };
    auto out = hdr.encode();

    // 5GSM message container LV-E
    uint16_t gsm_len = static_cast<uint16_t>(gsm_message_container.size());
    out.push_back(static_cast<uint8_t>(gsm_len >> 8));
    out.push_back(static_cast<uint8_t>(gsm_len & 0xFF));
    out.insert(out.end(), gsm_message_container.begin(), gsm_message_container.end());

    return out;
}

RegistrationComplete RegistrationComplete::decode(std::span<const uint8_t> data) {
    size_t offset = 0;
    auto hdr = NrNasHeader::decode(data, offset);
    if (hdr.epd != ExtendedProtocolDiscriminator::GMM ||
        hdr.message_type != static_cast<uint8_t>(GmmMessageType::RegistrationComplete)) {
        throw std::runtime_error("Invalid header for 5GMM RegistrationComplete");
    }

    RegistrationComplete comp;
    if (offset + 2 <= data.size()) {
        uint16_t gsm_len = static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
        offset += 2;
        if (data.size() >= offset + gsm_len) {
            comp.gsm_message_container.assign(data.begin() + static_cast<ptrdiff_t>(offset),
                                              data.begin() + static_cast<ptrdiff_t>(offset + gsm_len));
        }
    }
    return comp;
}

} // namespace gpp::nr_nas
