#include "3gpp/ip/Checksum.hpp"

namespace gpp::ip {

void Checksum::accumulate(uint32_t& sum, std::span<const uint8_t> data) {
    size_t i = 0;
    while (i + 1 < data.size()) {
        uint16_t word = (static_cast<uint16_t>(data[i]) << 8) | static_cast<uint16_t>(data[i + 1]);
        sum += word;
        i += 2;
    }
    if (i < data.size()) {
        // Odd byte padded with 0 on the right
        uint16_t word = static_cast<uint16_t>(data[i]) << 8;
        sum += word;
    }
}

uint16_t Checksum::finalize(uint32_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum & 0xFFFF);
}

uint16_t Checksum::compute(std::span<const uint8_t> data) {
    uint32_t sum = 0;
    accumulate(sum, data);
    return finalize(sum);
}

uint16_t Checksum::compute_ipv4_pseudo_checksum(
    const Ipv4Address& src,
    const Ipv4Address& dst,
    uint8_t protocol,
    uint16_t l4_length,
    std::span<const uint8_t> l4_packet) {

    uint32_t sum = 0;

    // Pseudo-header:
    // Source IP (4 bytes)
    accumulate(sum, std::span<const uint8_t>(src.bytes().data(), 4));
    // Destination IP (4 bytes)
    accumulate(sum, std::span<const uint8_t>(dst.bytes().data(), 4));
    // Zero (1 byte) + Protocol (1 byte)
    sum += static_cast<uint16_t>(protocol);
    // L4 Length (2 bytes)
    sum += l4_length;

    // L4 packet body (header + payload)
    accumulate(sum, l4_packet);

    uint16_t result = finalize(sum);
    // In UDP, if computed checksum is 0, it is transmitted as 0xFFFF
    return (result == 0) ? 0xFFFF : result;
}

uint16_t Checksum::compute_ipv6_pseudo_checksum(
    const Ipv6Address& src,
    const Ipv6Address& dst,
    uint8_t next_header,
    uint32_t l4_length,
    std::span<const uint8_t> l4_packet) {

    uint32_t sum = 0;

    // Pseudo-header:
    // Source IPv6 (16 bytes)
    accumulate(sum, std::span<const uint8_t>(src.bytes().data(), 16));
    // Destination IPv6 (16 bytes)
    accumulate(sum, std::span<const uint8_t>(dst.bytes().data(), 16));
    // Upper-Layer Packet Length (32 bits)
    sum += (l4_length >> 16);
    sum += (l4_length & 0xFFFF);
    // 3 Zero bytes + Next Header (8 bits)
    sum += static_cast<uint16_t>(next_header);

    // L4 packet body
    accumulate(sum, l4_packet);

    uint16_t result = finalize(sum);
    return (result == 0) ? 0xFFFF : result;
}

} // namespace gpp::ip
