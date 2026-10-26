#include "3gpp/ip/IpAddress.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>

namespace gpp::ip {

const Ipv4Address Ipv4Address::Any{0, 0, 0, 0};
const Ipv4Address Ipv4Address::Loopback{127, 0, 0, 1};

const Ipv6Address Ipv6Address::Any = [] {
    std::array<uint8_t, 16> b{};
    return Ipv6Address(std::span<const uint8_t, 16>(b));
}();

const Ipv6Address Ipv6Address::Loopback = [] {
    std::array<uint8_t, 16> b{};
    b[15] = 1;
    return Ipv6Address(std::span<const uint8_t, 16>(b));
}();

Ipv4Address::Ipv4Address(uint32_t host_order_u32) {
    bytes_[0] = static_cast<uint8_t>((host_order_u32 >> 24) & 0xFF);
    bytes_[1] = static_cast<uint8_t>((host_order_u32 >> 16) & 0xFF);
    bytes_[2] = static_cast<uint8_t>((host_order_u32 >> 8) & 0xFF);
    bytes_[3] = static_cast<uint8_t>(host_order_u32 & 0xFF);
}

Ipv4Address::Ipv4Address(std::span<const uint8_t, 4> bytes) {
    std::copy(bytes.begin(), bytes.end(), bytes_.begin());
}

Ipv4Address Ipv4Address::from_string(std::string_view str) {
    std::string s(str);
    struct in_addr addr{};
    if (inet_pton(AF_INET, s.c_str(), &addr) <= 0) {
        throw std::invalid_argument("Invalid IPv4 address: " + s);
    }
    const auto* p = reinterpret_cast<const uint8_t*>(&addr.s_addr);
    return Ipv4Address(p[0], p[1], p[2], p[3]);
}

std::string Ipv4Address::to_string() const {
    char buf[INET_ADDRSTRLEN];
    struct in_addr addr{};
    std::memcpy(&addr.s_addr, bytes_.data(), 4);
    if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
        return "0.0.0.0";
    }
    return std::string(buf);
}

uint32_t Ipv4Address::to_u32() const {
    uint32_t net;
    std::memcpy(&net, bytes_.data(), 4);
    return net;
}

// -----------------------------------------------------------------
// IPv6
// -----------------------------------------------------------------

Ipv6Address::Ipv6Address(std::span<const uint8_t, 16> bytes) {
    std::copy(bytes.begin(), bytes.end(), bytes_.begin());
}

Ipv6Address Ipv6Address::from_string(std::string_view str) {
    std::string s(str);
    struct in6_addr addr{};
    if (inet_pton(AF_INET6, s.c_str(), &addr) <= 0) {
        throw std::invalid_argument("Invalid IPv6 address: " + s);
    }
    std::span<const uint8_t, 16> sp(reinterpret_cast<const uint8_t*>(&addr.s6_addr), 16);
    return Ipv6Address(sp);
}

std::string Ipv6Address::to_string() const {
    char buf[INET6_ADDRSTRLEN];
    struct in6_addr addr{};
    std::memcpy(&addr.s6_addr, bytes_.data(), 16);
    if (!inet_ntop(AF_INET6, &addr, buf, sizeof(buf))) {
        return "::";
    }
    return std::string(buf);
}

} // namespace gpp::ip
