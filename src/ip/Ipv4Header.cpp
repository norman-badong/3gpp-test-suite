#include "3gpp/ip/Ipv4Header.hpp"
#include "3gpp/ip/Checksum.hpp"
#include <stdexcept>

namespace gpp::ip {

void Ipv4Header::encode(common::ByteStreamWriter& writer, bool compute_checksum) const {
    size_t start_pos = writer.size();

    // Byte 0: Version (4) + IHL (4)
    uint8_t v_ihl = static_cast<uint8_t>((version << 4) | (ihl & 0x0F));
    writer.write_u8(v_ihl);

    // Byte 1: DSCP (6) + ECN (2)
    uint8_t tos = static_cast<uint8_t>(((dscp & 0x3F) << 2) | (ecn & 0x03));
    writer.write_u8(tos);

    // Bytes 2-3: Total length
    writer.write_u16(total_length);

    // Bytes 4-5: Identification
    writer.write_u16(identification);

    // Bytes 6-7: Flags (3 bits) + Fragment Offset (13 bits)
    uint16_t flags_offset = 0;
    if (flag_dont_fragment)  flags_offset |= (1 << 14);
    if (flag_more_fragments) flags_offset |= (1 << 13);
    flags_offset |= (fragment_offset & 0x1FFF);
    writer.write_u16(flags_offset);

    // Byte 8: TTL
    writer.write_u8(ttl);

    // Byte 9: Protocol
    writer.write_u8(protocol);

    // Bytes 10-11: Checksum placeholder (0 during calculation)
    size_t checksum_offset = writer.size();
    writer.write_u16(0);

    // Bytes 12-15: Source IP
    writer.write_bytes(src_ip.bytes());

    // Bytes 16-19: Destination IP
    writer.write_bytes(dst_ip.bytes());

    // Options (if any)
    if (!options.empty()) {
        writer.write_bytes(options);
    }

    if (compute_checksum) {
        size_t header_len = writer.size() - start_pos;
        std::span<const uint8_t> header_bytes(writer.data().data() + start_pos, header_len);
        uint16_t csum = Checksum::compute(header_bytes);
        writer.set_u16(checksum_offset, csum);
    } else {
        writer.set_u16(checksum_offset, checksum);
    }
}

Ipv4Header Ipv4Header::decode(common::ByteStreamReader& reader) {
    if (reader.remaining() < 20) {
        throw std::runtime_error("Ipv4Header: remaining bytes less than minimum IPv4 header (20 bytes)");
    }

    size_t start_pos = reader.tell();
    Ipv4Header hdr;

    uint8_t v_ihl = reader.read_u8();
    hdr.version = (v_ihl >> 4) & 0x0F;
    hdr.ihl = v_ihl & 0x0F;

    if (hdr.version != 4) {
        throw std::runtime_error("Ipv4Header: Invalid IP version (expected 4, got " + std::to_string(hdr.version) + ")");
    }
    if (hdr.ihl < 5) {
        throw std::runtime_error("Ipv4Header: Invalid IHL < 5 (" + std::to_string(hdr.ihl) + ")");
    }

    uint8_t tos = reader.read_u8();
    hdr.dscp = (tos >> 2) & 0x3F;
    hdr.ecn = tos & 0x03;

    hdr.total_length = reader.read_u16();
    hdr.identification = reader.read_u16();

    uint16_t flags_offset = reader.read_u16();
    hdr.flag_dont_fragment = (flags_offset & (1 << 14)) != 0;
    hdr.flag_more_fragments = (flags_offset & (1 << 13)) != 0;
    hdr.fragment_offset = flags_offset & 0x1FFF;

    hdr.ttl = reader.read_u8();
    hdr.protocol = reader.read_u8();
    hdr.checksum = reader.read_u16();

    auto src_span = reader.read_bytes(4);
    std::array<uint8_t, 4> src_arr{};
    std::copy(src_span.begin(), src_span.end(), src_arr.begin());
    hdr.src_ip = Ipv4Address(src_arr);

    auto dst_span = reader.read_bytes(4);
    std::array<uint8_t, 4> dst_arr{};
    std::copy(dst_span.begin(), dst_span.end(), dst_arr.begin());
    hdr.dst_ip = Ipv4Address(dst_arr);

    size_t total_header_bytes = hdr.ihl * 4;
    size_t read_so_far = reader.tell() - start_pos;
    if (total_header_bytes > read_so_far) {
        size_t opt_len = total_header_bytes - read_so_far;
        auto opt_span = reader.read_bytes(opt_len);
        hdr.options.assign(opt_span.begin(), opt_span.end());
    }

    return hdr;
}

} // namespace gpp::ip
