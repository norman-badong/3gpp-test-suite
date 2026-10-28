#include <3gpp/nr_nas/NrNasCommon.hpp>
#include <stdexcept>

namespace gpp::nr_nas {

std::vector<uint8_t> NrNasHeader::encode() const {
    std::vector<uint8_t> out;
    out.reserve(3);
    out.push_back(static_cast<uint8_t>(epd));
    out.push_back(static_cast<uint8_t>((static_cast<uint8_t>(security_header_type) & 0x0F) << 4));
    out.push_back(message_type);
    return out;
}

NrNasHeader NrNasHeader::decode(std::span<const uint8_t> data, size_t& offset) {
    if (data.size() < offset + 3) {
        throw std::runtime_error("5GMM NAS header truncated");
    }
    NrNasHeader hdr;
    hdr.epd = static_cast<ExtendedProtocolDiscriminator>(data[offset]);
    hdr.security_header_type = static_cast<SecurityHeaderType>((data[offset + 1] >> 4) & 0x0F);
    hdr.message_type = data[offset + 2];
    offset += 3;
    return hdr;
}

std::vector<uint8_t> NrGsmHeader::encode() const {
    std::vector<uint8_t> out;
    out.reserve(4);
    out.push_back(static_cast<uint8_t>(epd));
    out.push_back(pdu_session_id);
    out.push_back(procedure_transaction_id);
    out.push_back(message_type);
    return out;
}

NrGsmHeader NrGsmHeader::decode(std::span<const uint8_t> data, size_t& offset) {
    if (data.size() < offset + 4) {
        throw std::runtime_error("5GSM header truncated");
    }
    NrGsmHeader hdr;
    hdr.epd = static_cast<ExtendedProtocolDiscriminator>(data[offset]);
    hdr.pdu_session_id = data[offset + 1];
    hdr.procedure_transaction_id = data[offset + 2];
    hdr.message_type = data[offset + 3];
    offset += 4;
    return hdr;
}

} // namespace gpp::nr_nas
