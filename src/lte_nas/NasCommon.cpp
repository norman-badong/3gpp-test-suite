#include <3gpp/lte_nas/NasCommon.hpp>
#include <stdexcept>

namespace gpp::lte_nas {

std::vector<uint8_t> NasHeader::encode() const {
    std::vector<uint8_t> out;
    out.reserve(2);
    uint8_t b0 = (static_cast<uint8_t>(security_header_type) << 4) |
                 (static_cast<uint8_t>(protocol_discriminator) & 0x0F);
    out.push_back(b0);
    out.push_back(message_type);
    return out;
}

NasHeader NasHeader::decode(std::span<const uint8_t> data, size_t& offset) {
    if (data.size() < offset + 2) {
        throw std::runtime_error("NAS header truncated");
    }
    NasHeader hdr;
    uint8_t b0 = data[offset];
    hdr.security_header_type = static_cast<SecurityHeaderType>(b0 >> 4);
    hdr.protocol_discriminator = static_cast<ProtocolDiscriminator>(b0 & 0x0F);
    hdr.message_type = data[offset + 1];
    offset += 2;
    return hdr;
}

std::vector<uint8_t> EsmHeader::encode() const {
    std::vector<uint8_t> out;
    out.reserve(3);
    uint8_t b0 = static_cast<uint8_t>((eps_bearer_id & 0x0F) << 4) |
                 (static_cast<uint8_t>(protocol_discriminator) & 0x0F);
    out.push_back(b0);
    out.push_back(procedure_transaction_id);
    out.push_back(message_type);
    return out;
}

EsmHeader EsmHeader::decode(std::span<const uint8_t> data, size_t& offset) {
    if (data.size() < offset + 3) {
        throw std::runtime_error("ESM header truncated");
    }
    EsmHeader hdr;
    uint8_t b0 = data[offset];
    hdr.eps_bearer_id = static_cast<uint8_t>(b0 >> 4);
    hdr.protocol_discriminator = static_cast<ProtocolDiscriminator>(b0 & 0x0F);
    hdr.procedure_transaction_id = data[offset + 1];
    hdr.message_type = data[offset + 2];
    offset += 3;
    return hdr;
}

} // namespace gpp::lte_nas
