#include "3gpp/ip/TcpPacket.hpp"
#include "3gpp/ip/Checksum.hpp"
#include <stdexcept>

namespace gpp::ip {

uint16_t TcpFlags::to_u16() const {
    uint16_t f = 0;
    if (fin) f |= 0x01;
    if (syn) f |= 0x02;
    if (rst) f |= 0x04;
    if (psh) f |= 0x08;
    if (ack) f |= 0x10;
    if (urg) f |= 0x20;
    if (ece) f |= 0x40;
    if (cwr) f |= 0x80;
    return f;
}

TcpFlags TcpFlags::from_u16(uint16_t val) {
    TcpFlags f;
    f.fin = (val & 0x01) != 0;
    f.syn = (val & 0x02) != 0;
    f.rst = (val & 0x04) != 0;
    f.psh = (val & 0x08) != 0;
    f.ack = (val & 0x10) != 0;
    f.urg = (val & 0x20) != 0;
    f.ece = (val & 0x40) != 0;
    f.cwr = (val & 0x80) != 0;
    return f;
}

void TcpPacket::set_payload(std::span<const uint8_t> data) {
    payload.assign(data.begin(), data.end());
}

void TcpPacket::set_payload(std::string_view text) {
    payload.assign(text.begin(), text.end());
}

void TcpPacket::encode(common::ByteStreamWriter& writer,
                       const Ipv4Address* src_ip,
                       const Ipv4Address* dst_ip) const {
    size_t start_pos = writer.size();

    writer.write_u16(src_port);
    writer.write_u16(dst_port);
    writer.write_u32(seq_number);
    writer.write_u32(ack_number);

    // Data offset (4 bits) + Reserved (3 bits) + Flags (9 bits)
    // 16 bits total: (data_offset << 12) | flags
    uint16_t offset_flags = (static_cast<uint16_t>(data_offset & 0x0F) << 12) |
                            (flags.to_u16() & 0x01FF);
    writer.write_u16(offset_flags);

    writer.write_u16(window_size);

    size_t checksum_offset = writer.size();
    writer.write_u16(0); // Checksum placeholder

    writer.write_u16(urgent_pointer);

    if (!options.empty()) {
        writer.write_bytes(options);
    }

    if (!payload.empty()) {
        writer.write_bytes(payload);
    }

    if (src_ip && dst_ip) {
        size_t l4_len = writer.size() - start_pos;
        std::span<const uint8_t> l4_bytes(writer.data().data() + start_pos, l4_len);
        uint16_t csum = Checksum::compute_ipv4_pseudo_checksum(*src_ip, *dst_ip, 6 /* TCP */, static_cast<uint16_t>(l4_len), l4_bytes);
        writer.set_u16(checksum_offset, csum);
    } else if (checksum != 0) {
        writer.set_u16(checksum_offset, checksum);
    }
}

void TcpPacket::encode_ipv6(common::ByteStreamWriter& writer,
                            const Ipv6Address& src_ip,
                            const Ipv6Address& dst_ip) const {
    size_t start_pos = writer.size();

    writer.write_u16(src_port);
    writer.write_u16(dst_port);
    writer.write_u32(seq_number);
    writer.write_u32(ack_number);

    uint16_t offset_flags = (static_cast<uint16_t>(data_offset & 0x0F) << 12) |
                            (flags.to_u16() & 0x01FF);
    writer.write_u16(offset_flags);

    writer.write_u16(window_size);

    size_t checksum_offset = writer.size();
    writer.write_u16(0);

    writer.write_u16(urgent_pointer);

    if (!options.empty()) {
        writer.write_bytes(options);
    }

    if (!payload.empty()) {
        writer.write_bytes(payload);
    }

    size_t l4_len = writer.size() - start_pos;
    std::span<const uint8_t> l4_bytes(writer.data().data() + start_pos, l4_len);
    uint16_t csum = Checksum::compute_ipv6_pseudo_checksum(src_ip, dst_ip, 6 /* TCP */, static_cast<uint32_t>(l4_len), l4_bytes);
    writer.set_u16(checksum_offset, csum);
}

TcpPacket TcpPacket::decode(common::ByteStreamReader& reader) {
    if (reader.remaining() < MinHeaderSize) {
        throw std::runtime_error("TcpPacket: buffer too small for TCP header");
    }

    size_t start_pos = reader.tell();
    TcpPacket pkt;

    pkt.src_port = reader.read_u16();
    pkt.dst_port = reader.read_u16();
    pkt.seq_number = reader.read_u32();
    pkt.ack_number = reader.read_u32();

    uint16_t offset_flags = reader.read_u16();
    pkt.data_offset = static_cast<uint8_t>((offset_flags >> 12) & 0x0F);
    pkt.flags = TcpFlags::from_u16(offset_flags & 0x01FF);

    pkt.window_size = reader.read_u16();
    pkt.checksum = reader.read_u16();
    pkt.urgent_pointer = reader.read_u16();

    size_t header_len = pkt.data_offset * 4;
    size_t read_so_far = reader.tell() - start_pos;
    if (header_len > read_so_far) {
        size_t opt_len = header_len - read_so_far;
        auto opt_span = reader.read_bytes(opt_len);
        pkt.options.assign(opt_span.begin(), opt_span.end());
    }

    if (reader.remaining() > 0) {
        auto payload_span = reader.read_bytes(reader.remaining());
        pkt.payload.assign(payload_span.begin(), payload_span.end());
    }

    return pkt;
}

} // namespace gpp::ip
