#include "3gpp/ip/Ipv6Header.hpp"
#include <stdexcept>

namespace gpp::ip {

void Ipv6Header::encode(common::ByteStreamWriter& writer) const {
    // 4-bit Version + 8-bit Traffic Class + 20-bit Flow Label = 32 bits
    uint32_t v_tc_fl = (static_cast<uint32_t>(version & 0x0F) << 28) |
                       (static_cast<uint32_t>(traffic_class) << 20) |
                       (flow_label & 0x0FFFFF);
    writer.write_u32(v_tc_fl);

    // Payload length (16 bits)
    writer.write_u16(payload_length);

    // Next Header (8 bits)
    writer.write_u8(next_header);

    // Hop Limit (8 bits)
    writer.write_u8(hop_limit);

    // Source IPv6 (16 bytes)
    writer.write_bytes(src_ip.bytes());

    // Destination IPv6 (16 bytes)
    writer.write_bytes(dst_ip.bytes());
}

Ipv6Header Ipv6Header::decode(common::ByteStreamReader& reader) {
    if (reader.remaining() < FixedHeaderSize) {
        throw std::runtime_error("Ipv6Header: buffer too small for IPv6 header (expected 40 bytes)");
    }

    Ipv6Header hdr;
    uint32_t v_tc_fl = reader.read_u32();
    hdr.version = static_cast<uint8_t>((v_tc_fl >> 28) & 0x0F);
    hdr.traffic_class = static_cast<uint8_t>((v_tc_fl >> 20) & 0xFF);
    hdr.flow_label = v_tc_fl & 0x0FFFFF;

    if (hdr.version != 6) {
        throw std::runtime_error("Ipv6Header: Invalid IP version (expected 6, got " + std::to_string(hdr.version) + ")");
    }

    hdr.payload_length = reader.read_u16();
    hdr.next_header = reader.read_u8();
    hdr.hop_limit = reader.read_u8();

    auto src_span = reader.read_bytes(16);
    std::array<uint8_t, 16> src_arr{};
    std::copy(src_span.begin(), src_span.end(), src_arr.begin());
    hdr.src_ip = Ipv6Address(src_arr);

    auto dst_span = reader.read_bytes(16);
    std::array<uint8_t, 16> dst_arr{};
    std::copy(dst_span.begin(), dst_span.end(), dst_arr.begin());
    hdr.dst_ip = Ipv6Address(dst_arr);

    return hdr;
}

} // namespace gpp::ip
