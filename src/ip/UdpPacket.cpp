#include "3gpp/ip/UdpPacket.hpp"
#include "3gpp/ip/Checksum.hpp"
#include <stdexcept>

namespace gpp::ip {

void UdpPacket::set_payload(std::span<const uint8_t> data) {
    payload.assign(data.begin(), data.end());
    length = static_cast<uint16_t>(HeaderSize + payload.size());
}

void UdpPacket::set_payload(std::string_view text) {
    payload.assign(text.begin(), text.end());
    length = static_cast<uint16_t>(HeaderSize + payload.size());
}

void UdpPacket::encode(common::ByteStreamWriter& writer,
                       const Ipv4Address* src_ip,
                       const Ipv4Address* dst_ip) const {
    size_t start_pos = writer.size();

    writer.write_u16(src_port);
    writer.write_u16(dst_port);
    writer.write_u16(length);

    size_t checksum_offset = writer.size();
    writer.write_u16(0); // Checksum placeholder

    if (!payload.empty()) {
        writer.write_bytes(payload);
    }

    if (src_ip && dst_ip) {
        size_t l4_len = writer.size() - start_pos;
        std::span<const uint8_t> l4_bytes(writer.data().data() + start_pos, l4_len);
        uint16_t csum = Checksum::compute_ipv4_pseudo_checksum(*src_ip, *dst_ip, 17 /* UDP */, static_cast<uint16_t>(l4_len), l4_bytes);
        writer.set_u16(checksum_offset, csum);
    } else if (checksum != 0) {
        writer.set_u16(checksum_offset, checksum);
    }
}

void UdpPacket::encode_ipv6(common::ByteStreamWriter& writer,
                            const Ipv6Address& src_ip,
                            const Ipv6Address& dst_ip) const {
    size_t start_pos = writer.size();

    writer.write_u16(src_port);
    writer.write_u16(dst_port);
    writer.write_u16(length);

    size_t checksum_offset = writer.size();
    writer.write_u16(0);

    if (!payload.empty()) {
        writer.write_bytes(payload);
    }

    size_t l4_len = writer.size() - start_pos;
    std::span<const uint8_t> l4_bytes(writer.data().data() + start_pos, l4_len);
    uint16_t csum = Checksum::compute_ipv6_pseudo_checksum(src_ip, dst_ip, 17 /* UDP */, static_cast<uint32_t>(l4_len), l4_bytes);
    writer.set_u16(checksum_offset, csum);
}

UdpPacket UdpPacket::decode(common::ByteStreamReader& reader) {
    if (reader.remaining() < HeaderSize) {
        throw std::runtime_error("UdpPacket: buffer too small for UDP header");
    }

    UdpPacket pkt;
    pkt.src_port = reader.read_u16();
    pkt.dst_port = reader.read_u16();
    pkt.length = reader.read_u16();
    pkt.checksum = reader.read_u16();

    if (pkt.length < HeaderSize) {
        throw std::runtime_error("UdpPacket: invalid length < 8 in UDP header");
    }

    size_t payload_len = pkt.length - HeaderSize;
    if (payload_len > 0) {
        auto payload_span = reader.read_bytes(payload_len);
        pkt.payload.assign(payload_span.begin(), payload_span.end());
    }

    return pkt;
}

} // namespace gpp::ip
