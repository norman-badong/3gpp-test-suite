#include "3gpp/common/PcapWriter.hpp"
#include <cstring>

namespace gpp::common {

namespace {

// Little-endian write helper
inline void write_le16(char* buf, uint16_t val) {
    buf[0] = static_cast<char>(val & 0xFF);
    buf[1] = static_cast<char>((val >> 8) & 0xFF);
}

inline void write_le32(char* buf, uint32_t val) {
    buf[0] = static_cast<char>(val & 0xFF);
    buf[1] = static_cast<char>((val >> 8) & 0xFF);
    buf[2] = static_cast<char>((val >> 16) & 0xFF);
    buf[3] = static_cast<char>((val >> 24) & 0xFF);
}

} // namespace

PcapWriter::PcapWriter(std::string_view filename, LinkType link_type)
    : filename_(filename), link_type_(link_type) {
    file_.open(filename_, std::ios::binary | std::ios::out | std::ios::trunc);
    if (file_.is_open()) {
        write_global_header();
    }
}

PcapWriter::~PcapWriter() {
    close();
}

PcapWriter::PcapWriter(PcapWriter&& other) noexcept
    : filename_(std::move(other.filename_)),
      link_type_(other.link_type_),
      file_(std::move(other.file_)),
      packet_count_(other.packet_count_) {
    other.packet_count_ = 0;
}

PcapWriter& PcapWriter::operator=(PcapWriter&& other) noexcept {
    if (this != &other) {
        close();
        filename_ = std::move(other.filename_);
        link_type_ = other.link_type_;
        file_ = std::move(other.file_);
        packet_count_ = other.packet_count_;
        other.packet_count_ = 0;
    }
    return *this;
}

void PcapWriter::write_global_header() {
    char header[24];
    write_le32(header + 0, 0xa1b2c3d4);               // Magic number (standard microsecond PCAP)
    write_le16(header + 4, 2);                        // Major version 2
    write_le16(header + 6, 4);                        // Minor version 4
    write_le32(header + 8, 0);                        // GMT offset (0)
    write_le32(header + 12, 0);                       // Accuracy of timestamps
    write_le32(header + 16, 65535);                   // Snapshot length (max packet capture size)
    write_le32(header + 20, static_cast<uint32_t>(link_type_)); // Link-layer header type

    file_.write(header, sizeof(header));
}

bool PcapWriter::write_packet(std::span<const uint8_t> packet_data, uint32_t sec, uint32_t usec) {
    if (!file_.is_open()) return false;

    if (sec == 0 && usec == 0) {
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        sec = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(duration).count());
        usec = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::microseconds>(duration).count() % 1000000);
    }

    uint32_t len = static_cast<uint32_t>(packet_data.size());
    char pkt_header[16];
    write_le32(pkt_header + 0, sec);
    write_le32(pkt_header + 4, usec);
    write_le32(pkt_header + 8, len);
    write_le32(pkt_header + 12, len);

    file_.write(pkt_header, sizeof(pkt_header));
    file_.write(reinterpret_cast<const char*>(packet_data.data()), len);
    file_.flush();

    ++packet_count_;
    return true;
}

bool PcapWriter::write_ipv4(std::span<const uint8_t> ipv4_packet) {
    if (link_type_ == LinkType::RAW_IP) {
        return write_packet(ipv4_packet);
    }

    // Prepend 14-byte Ethernet header: Dst MAC, Src MAC, EtherType (0x0800 for IPv4)
    std::vector<uint8_t> frame;
    frame.reserve(14 + ipv4_packet.size());

    // Dst MAC: 02:00:00:00:00:02 (Locally administered)
    frame.insert(frame.end(), {0x02, 0x00, 0x00, 0x00, 0x00, 0x02});
    // Src MAC: 02:00:00:00:00:01
    frame.insert(frame.end(), {0x02, 0x00, 0x00, 0x00, 0x00, 0x01});
    // EtherType: 0x0800 (IPv4)
    frame.insert(frame.end(), {0x08, 0x00});

    frame.insert(frame.end(), ipv4_packet.begin(), ipv4_packet.end());
    return write_packet(frame);
}

bool PcapWriter::write_ipv6(std::span<const uint8_t> ipv6_packet) {
    if (link_type_ == LinkType::RAW_IP) {
        return write_packet(ipv6_packet);
    }

    // Prepend 14-byte Ethernet header with EtherType 0x86DD for IPv6
    std::vector<uint8_t> frame;
    frame.reserve(14 + ipv6_packet.size());

    // Dst MAC: 02:00:00:00:00:02
    frame.insert(frame.end(), {0x02, 0x00, 0x00, 0x00, 0x00, 0x02});
    // Src MAC: 02:00:00:00:00:01
    frame.insert(frame.end(), {0x02, 0x00, 0x00, 0x00, 0x00, 0x01});
    // EtherType: 0x86DD (IPv6)
    frame.insert(frame.end(), {0x86, 0xDD});

    frame.insert(frame.end(), ipv6_packet.begin(), ipv6_packet.end());
    return write_packet(frame);
}

void PcapWriter::close() {
    if (file_.is_open()) {
        file_.close();
    }
}

} // namespace gpp::common
