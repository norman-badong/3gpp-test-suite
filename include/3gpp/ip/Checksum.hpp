#pragma once

#include <cstdint>
#include <span>
#include "3gpp/ip/IpAddress.hpp"

namespace gpp::ip {

class Checksum {
public:
    // RFC 1071 standard one's complement Internet Checksum
    static uint16_t compute(std::span<const uint8_t> data);

    // Accumulates 16-bit words into a running 32-bit accumulator
    static void accumulate(uint32_t& accumulator, std::span<const uint8_t> data);

    // Finalize 32-bit accumulator into 16-bit one's complement checksum
    static uint16_t finalize(uint32_t accumulator);

    // Computes UDP/TCP pseudo-header checksum for IPv4
    static uint16_t compute_ipv4_pseudo_checksum(
        const Ipv4Address& src,
        const Ipv4Address& dst,
        uint8_t protocol,
        uint16_t l4_length,
        std::span<const uint8_t> l4_packet);

    // Computes UDP/TCP pseudo-header checksum for IPv6
    static uint16_t compute_ipv6_pseudo_checksum(
        const Ipv6Address& src,
        const Ipv6Address& dst,
        uint8_t next_header,
        uint32_t l4_length,
        std::span<const uint8_t> l4_packet);
};

} // namespace gpp::ip
