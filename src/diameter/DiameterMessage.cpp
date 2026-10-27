#include "3gpp/diameter/DiameterMessage.hpp"

namespace gpp {
namespace diameter {

const DiameterAvp* DiameterMessage::find_avp(uint32_t code, std::optional<uint32_t> vendor) const {
    for (const auto& avp : avps) {
        if (avp.code == code) {
            if (!vendor.has_value() || avp.vendor_id == vendor) {
                return &avp;
            }
        }
    }
    return nullptr;
}

std::vector<const DiameterAvp*> DiameterMessage::find_all_avps(uint32_t code, std::optional<uint32_t> vendor) const {
    std::vector<const DiameterAvp*> result;
    for (const auto& avp : avps) {
        if (avp.code == code) {
            if (!vendor.has_value() || avp.vendor_id == vendor) {
                result.push_back(&avp);
            }
        }
    }
    return result;
}

std::vector<uint8_t> DiameterMessage::serialize() const {
    // 1. Serialize all AVPs first
    std::vector<uint8_t> avp_bytes;
    for (const auto& avp : avps) {
        auto b = avp.serialize();
        avp_bytes.insert(avp_bytes.end(), b.begin(), b.end());
    }

    uint32_t total_len = static_cast<uint32_t>(DIAMETER_HEADER_SIZE + avp_bytes.size());

    common::ByteStreamWriter writer;
    // Word 0: Version (8 bits) + Message Length (24 bits)
    uint32_t ver_and_len = (static_cast<uint32_t>(version) << 24) | (total_len & 0x00FFFFFF);
    writer.write_u32(ver_and_len);

    // Word 1: Command Flags (8 bits) + Command Code (24 bits)
    uint32_t flags_and_code = (static_cast<uint32_t>(flags) << 24) | (command_code & 0x00FFFFFF);
    writer.write_u32(flags_and_code);

    // Word 2: Application-ID (32 bits)
    writer.write_u32(application_id);

    // Word 3: Hop-by-Hop Identifier (32 bits)
    writer.write_u32(hop_by_hop_id);

    // Word 4: End-to-End Identifier (32 bits)
    writer.write_u32(end_to_end_id);

    // AVPs payload
    if (!avp_bytes.empty()) {
        writer.write_bytes(std::span<const uint8_t>(avp_bytes.data(), avp_bytes.size()));
    }

    return writer.data();
}

std::optional<DiameterMessage> DiameterMessage::decode(const uint8_t* data, size_t length) {
    if (!data || length < DIAMETER_HEADER_SIZE) {
        return std::nullopt;
    }
    common::ByteStreamReader reader(std::span<const uint8_t>(data, length));
    return decode(reader);
}

std::optional<DiameterMessage> DiameterMessage::decode(common::ByteStreamReader& reader) {
    if (reader.remaining() < DIAMETER_HEADER_SIZE) {
        return std::nullopt;
    }

    uint32_t ver_and_len = reader.read_u32();
    uint8_t version = static_cast<uint8_t>((ver_and_len >> 24) & 0xFF);
    uint32_t msg_length = ver_and_len & 0x00FFFFFF;

    if (msg_length < DIAMETER_HEADER_SIZE || (msg_length % 4) != 0) {
        return std::nullopt;
    }

    // Check if entire message is available in reader
    // Note: 4 bytes already read
    if (reader.remaining() < (msg_length - 4)) {
        return std::nullopt;
    }

    uint32_t flags_and_code = reader.read_u32();
    uint8_t flags = static_cast<uint8_t>((flags_and_code >> 24) & 0xFF);
    uint32_t command_code = flags_and_code & 0x00FFFFFF;

    uint32_t application_id = reader.read_u32();
    uint32_t hop_by_hop_id = reader.read_u32();
    uint32_t end_to_end_id = reader.read_u32();

    DiameterMessage msg(flags, command_code, application_id, hop_by_hop_id, end_to_end_id);
    msg.version = version;

    size_t avps_length = msg_length - DIAMETER_HEADER_SIZE;
    size_t start_remaining = reader.remaining();

    while (start_remaining - reader.remaining() < avps_length) {
        auto avp_opt = DiameterAvp::decode(reader);
        if (!avp_opt.has_value()) {
            break;
        }
        msg.add_avp(std::move(*avp_opt));
    }

    return msg;
}

} // namespace diameter
} // namespace gpp
