#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <array>
#include <span>

namespace gpp::ip {

class Ipv4Address {
public:
    constexpr Ipv4Address() : bytes_{0, 0, 0, 0} {}
    constexpr Ipv4Address(uint8_t a, uint8_t b, uint8_t c, uint8_t d) : bytes_{a, b, c, d} {}
    explicit Ipv4Address(uint32_t host_order_u32);
    explicit Ipv4Address(std::span<const uint8_t, 4> bytes);

    static Ipv4Address from_string(std::string_view str);

    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] uint32_t to_u32() const; // Network order
    [[nodiscard]] const std::array<uint8_t, 4>& bytes() const { return bytes_; }

    bool operator==(const Ipv4Address& other) const = default;

    static const Ipv4Address Any;       // 0.0.0.0
    static const Ipv4Address Loopback;  // 127.0.0.1

private:
    std::array<uint8_t, 4> bytes_;
};

class Ipv6Address {
public:
    constexpr Ipv6Address() : bytes_{} {}
    explicit Ipv6Address(std::span<const uint8_t, 16> bytes);
    static Ipv6Address from_string(std::string_view str);

    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] const std::array<uint8_t, 16>& bytes() const { return bytes_; }

    bool operator==(const Ipv6Address& other) const = default;

    static const Ipv6Address Any;       // ::
    static const Ipv6Address Loopback;  // ::1

private:
    std::array<uint8_t, 16> bytes_{};
};

} // namespace gpp::ip
