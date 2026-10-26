#pragma once

#include <cstdint>
#include <vector>
#include "3gpp/common/ByteStream.hpp"
#include "3gpp/ip/IpAddress.hpp"

namespace gpp::ip {

struct Ipv4Header {
    uint8_t version{4};
    uint8_t ihl{5};                     // Header length in 32-bit words (5 = 20 bytes)
    uint8_t dscp{0};                    // Differentiated Services Code Point (6 bits)
    uint8_t ecn{0};                     // Explicit Congestion Notification (2 bits)
    uint16_t total_length{20};          // Header + Payload
    uint16_t identification{0};
    bool flag_dont_fragment{true};
    bool flag_more_fragments{false};
    uint16_t fragment_offset{0};
    uint8_t ttl{64};
    uint8_t protocol{17};               // 17 = UDP, 6 = TCP, 1 = ICMP
    uint16_t checksum{0};
    Ipv4Address src_ip{Ipv4Address::Loopback};
    Ipv4Address dst_ip{Ipv4Address::Loopback};
    std::vector<uint8_t> options;

    void encode(common::ByteStreamWriter& writer, bool compute_checksum = true) const;
    static Ipv4Header decode(common::ByteStreamReader& reader);

    [[nodiscard]] size_t header_length_bytes() const { return ihl * 4; }
    [[nodiscard]] size_t payload_length_bytes() const {
        return (total_length >= header_length_bytes()) ? (total_length - header_length_bytes()) : 0;
    }
};

} // namespace gpp::ip
