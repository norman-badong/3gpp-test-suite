#include "3gpp/diameter/DiameterAvp.hpp"
#include <cstring>
#include <stdexcept>

namespace gpp {
namespace diameter {

DiameterAvp DiameterAvp::create_unsigned32(uint32_t code, uint32_t val, bool mandatory,
                                           std::optional<uint32_t> vendor) {
    uint8_t flags = mandatory ? AVP_FLAG_MANDATORY : 0;
    if (vendor.has_value()) {
        flags |= AVP_FLAG_VENDOR;
    }
    common::ByteStreamWriter writer;
    writer.write_u32(val);
    return DiameterAvp(code, flags, vendor, writer.take_data());
}

DiameterAvp DiameterAvp::create_unsigned64(uint32_t code, uint64_t val, bool mandatory,
                                           std::optional<uint32_t> vendor) {
    uint8_t flags = mandatory ? AVP_FLAG_MANDATORY : 0;
    if (vendor.has_value()) {
        flags |= AVP_FLAG_VENDOR;
    }
    common::ByteStreamWriter writer;
    writer.write_u64(val);
    return DiameterAvp(code, flags, vendor, writer.take_data());
}

DiameterAvp DiameterAvp::create_integer32(uint32_t code, int32_t val, bool mandatory,
                                          std::optional<uint32_t> vendor) {
    uint8_t flags = mandatory ? AVP_FLAG_MANDATORY : 0;
    if (vendor.has_value()) {
        flags |= AVP_FLAG_VENDOR;
    }
    common::ByteStreamWriter writer;
    writer.write_u32(static_cast<uint32_t>(val));
    return DiameterAvp(code, flags, vendor, writer.take_data());
}

DiameterAvp DiameterAvp::create_string(uint32_t code, const std::string& str, bool mandatory,
                                       std::optional<uint32_t> vendor) {
    uint8_t flags = mandatory ? AVP_FLAG_MANDATORY : 0;
    if (vendor.has_value()) {
        flags |= AVP_FLAG_VENDOR;
    }
    std::vector<uint8_t> bytes(str.begin(), str.end());
    return DiameterAvp(code, flags, vendor, std::move(bytes));
}

DiameterAvp DiameterAvp::create_octet_string(uint32_t code, const std::vector<uint8_t>& bytes,
                                             bool mandatory, std::optional<uint32_t> vendor) {
    uint8_t flags = mandatory ? AVP_FLAG_MANDATORY : 0;
    if (vendor.has_value()) {
        flags |= AVP_FLAG_VENDOR;
    }
    return DiameterAvp(code, flags, vendor, bytes);
}

DiameterAvp DiameterAvp::create_ipv4_address(uint32_t code, const ip::Ipv4Address& addr, bool mandatory,
                                             std::optional<uint32_t> vendor) {
    uint8_t flags = mandatory ? AVP_FLAG_MANDATORY : 0;
    if (vendor.has_value()) {
        flags |= AVP_FLAG_VENDOR;
    }
    common::ByteStreamWriter writer;
    // Address family: 1 = IPv4 (2 octets)
    writer.write_u16(1);
    const auto& b = addr.bytes();
    writer.write_bytes(std::span<const uint8_t>(b.data(), b.size()));
    return DiameterAvp(code, flags, vendor, writer.take_data());
}

DiameterAvp DiameterAvp::create_grouped(uint32_t code, const std::vector<DiameterAvp>& sub_avps,
                                        bool mandatory, std::optional<uint32_t> vendor) {
    uint8_t flags = mandatory ? AVP_FLAG_MANDATORY : 0;
    if (vendor.has_value()) {
        flags |= AVP_FLAG_VENDOR;
    }
    std::vector<uint8_t> payload;
    for (const auto& sub : sub_avps) {
        auto sub_bytes = sub.serialize();
        payload.insert(payload.end(), sub_bytes.begin(), sub_bytes.end());
    }
    return DiameterAvp(code, flags, vendor, std::move(payload));
}

uint32_t DiameterAvp::to_unsigned32() const {
    if (data.size() < 4) return 0;
    common::ByteStreamReader reader(data);
    return reader.read_u32();
}

uint64_t DiameterAvp::to_unsigned64() const {
    if (data.size() < 8) return 0;
    common::ByteStreamReader reader(data);
    return reader.read_u64();
}

int32_t DiameterAvp::to_integer32() const {
    if (data.size() < 4) return 0;
    common::ByteStreamReader reader(data);
    return static_cast<int32_t>(reader.read_u32());
}

std::string DiameterAvp::to_string() const {
    return std::string(data.begin(), data.end());
}

std::vector<DiameterAvp> DiameterAvp::to_grouped() const {
    std::vector<DiameterAvp> list;
    common::ByteStreamReader reader(data);
    while (reader.remaining() >= 8) {
        auto avp_opt = DiameterAvp::decode(reader);
        if (!avp_opt.has_value()) {
            break;
        }
        list.push_back(std::move(*avp_opt));
    }
    return list;
}

std::vector<uint8_t> DiameterAvp::serialize() const {
    common::ByteStreamWriter writer;
    writer.write_u32(code);

    bool has_vendor = vendor_id.has_value() || ((flags & AVP_FLAG_VENDOR) != 0);
    uint8_t actual_flags = flags;
    if (has_vendor) {
        actual_flags |= AVP_FLAG_VENDOR;
    } else {
        actual_flags &= ~AVP_FLAG_VENDOR;
    }

    uint32_t header_len = has_vendor ? 12 : 8;
    uint32_t avp_len = header_len + static_cast<uint32_t>(data.size());

    // 1st byte is flags, next 3 bytes are length (24-bit integer)
    uint32_t flags_and_length = (static_cast<uint32_t>(actual_flags) << 24) | (avp_len & 0x00FFFFFF);
    writer.write_u32(flags_and_length);

    if (has_vendor) {
        writer.write_u32(vendor_id.value_or(0));
    }

    if (!data.empty()) {
        writer.write_bytes(std::span<const uint8_t>(data.data(), data.size()));
    }

    // Align to 4-byte boundary with zero padding
    size_t padding = (4 - (avp_len % 4)) % 4;
    for (size_t i = 0; i < padding; ++i) {
        writer.write_u8(0);
    }

    return writer.take_data();
}

std::optional<DiameterAvp> DiameterAvp::decode(common::ByteStreamReader& reader) {
    if (reader.remaining() < 8) {
        return std::nullopt;
    }

    uint32_t code = reader.read_u32();
    uint32_t flags_and_len = reader.read_u32();

    uint8_t flags = static_cast<uint8_t>((flags_and_len >> 24) & 0xFF);
    uint32_t avp_len = flags_and_len & 0x00FFFFFF;

    bool has_vendor = (flags & AVP_FLAG_VENDOR) != 0;
    uint32_t header_len = has_vendor ? 12 : 8;

    if (avp_len < header_len) {
        return std::nullopt;
    }

    std::optional<uint32_t> vendor = std::nullopt;
    if (has_vendor) {
        if (reader.remaining() < 4) {
            return std::nullopt;
        }
        vendor = reader.read_u32();
    }

    size_t data_len = avp_len - header_len;
    if (reader.remaining() < data_len) {
        return std::nullopt;
    }

    std::vector<uint8_t> data;
    if (data_len > 0) {
        auto span_bytes = reader.read_bytes(data_len);
        data.assign(span_bytes.begin(), span_bytes.end());
    }

    // Skip padding to 4-byte boundary
    size_t padding = (4 - (avp_len % 4)) % 4;
    if (reader.remaining() < padding) {
        return std::nullopt;
    }
    reader.skip(padding);

    return DiameterAvp(code, flags, vendor, std::move(data));
}

} // namespace diameter
} // namespace gpp
