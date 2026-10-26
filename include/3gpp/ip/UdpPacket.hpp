#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include "3gpp/common/ByteStream.hpp"
#include "3gpp/ip/IpAddress.hpp"

namespace gpp::ip {

struct UdpPacket {
    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint16_t length{8};                 // Header (8) + payload
    uint16_t checksum{0};
    std::vector<uint8_t> payload;

    static constexpr size_t HeaderSize = 8;

    void set_payload(std::span<const uint8_t> data);
    void set_payload(std::string_view text);

    // Encode without pseudo-header checksum or with IPv4 pseudo-header checksum
    void encode(common::ByteStreamWriter& writer,
                const Ipv4Address* src_ip = nullptr,
                const Ipv4Address* dst_ip = nullptr) const;

    // Encode with IPv6 pseudo-header checksum
    void encode_ipv6(common::ByteStreamWriter& writer,
                     const Ipv6Address& src_ip,
                     const Ipv6Address& dst_ip) const;

    static UdpPacket decode(common::ByteStreamReader& reader);
};

} // namespace gpp::ip
