#pragma once

#include <string>
#include <string_view>
#include <span>
#include <cstdint>
#include <fstream>
#include <vector>
#include <chrono>

namespace gpp::common {

enum class LinkType : uint32_t {
    ETHERNET = 1,     // DLT_EN10MB (Standard 10/100/1000 Ethernet)
    RAW_IP   = 101,   // DLT_RAW (Raw IPv4 or IPv6)
};

class PcapWriter {
public:
    explicit PcapWriter(std::string_view filename, LinkType link_type = LinkType::ETHERNET);
    ~PcapWriter();

    // Prevent copy
    PcapWriter(const PcapWriter&) = delete;
    PcapWriter& operator=(const PcapWriter&) = delete;

    // Move support
    PcapWriter(PcapWriter&&) noexcept;
    PcapWriter& operator=(PcapWriter&&) noexcept;

    // Writes raw packet buffer with timestamp
    bool write_packet(std::span<const uint8_t> packet_data,
                      uint32_t sec = 0,
                      uint32_t usec = 0);

    // Convenience helper: wraps IPv4 packet in synthetic Ethernet header and writes
    bool write_ipv4(std::span<const uint8_t> ipv4_packet);

    // Convenience helper: wraps IPv6 packet in synthetic Ethernet header and writes
    bool write_ipv6(std::span<const uint8_t> ipv6_packet);

    void close();
    [[nodiscard]] bool is_open() const { return file_.is_open(); }
    [[nodiscard]] size_t packet_count() const { return packet_count_; }
    [[nodiscard]] const std::string& filename() const { return filename_; }

private:
    std::string filename_;
    LinkType link_type_;
    std::ofstream file_;
    size_t packet_count_{0};

    void write_global_header();
};

} // namespace gpp::common
