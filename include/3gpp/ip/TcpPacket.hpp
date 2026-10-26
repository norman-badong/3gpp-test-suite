#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <string_view>
#include "3gpp/common/ByteStream.hpp"
#include "3gpp/ip/IpAddress.hpp"

namespace gpp::ip {

struct TcpFlags {
    bool fin{false};
    bool syn{false};
    bool rst{false};
    bool psh{false};
    bool ack{false};
    bool urg{false};
    bool ece{false};
    bool cwr{false};

    [[nodiscard]] uint16_t to_u16() const;
    static TcpFlags from_u16(uint16_t val);
};

struct TcpPacket {
    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint32_t seq_number{0};
    uint32_t ack_number{0};
    uint8_t data_offset{5};             // Header length in 32-bit words (5 = 20 bytes)
    TcpFlags flags;
    uint16_t window_size{65535};
    uint16_t checksum{0};
    uint16_t urgent_pointer{0};
    std::vector<uint8_t> options;
    std::vector<uint8_t> payload;

    static constexpr size_t MinHeaderSize = 20;

    void set_payload(std::span<const uint8_t> data);
    void set_payload(std::string_view text);

    void encode(common::ByteStreamWriter& writer,
                const Ipv4Address* src_ip = nullptr,
                const Ipv4Address* dst_ip = nullptr) const;

    void encode_ipv6(common::ByteStreamWriter& writer,
                     const Ipv6Address& src_ip,
                     const Ipv6Address& dst_ip) const;

    static TcpPacket decode(common::ByteStreamReader& reader);
};

} // namespace gpp::ip
