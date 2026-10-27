#include "3gpp/rtp/RtcpPacket.hpp"
#include <chrono>
#include <stdexcept>

namespace gpp::rtp {

namespace {

uint64_t current_ntp_timestamp() {
    // NTP epoch begins on January 1, 1900.
    // Unix epoch begins on January 1, 1970 (difference is 2,208,988,800 seconds).
    constexpr uint64_t NTP_OFFSET = 2208988800ULL;

    auto now = std::chrono::system_clock::now();
    auto dur = now.time_since_epoch();
    auto sec = std::chrono::duration_cast<std::chrono::seconds>(dur).count();
    auto usec = std::chrono::duration_cast<std::chrono::microseconds>(dur).count() % 1000000;

    uint32_t ntp_sec = static_cast<uint32_t>(sec + NTP_OFFSET);
    // Convert microseconds to 2^32 fractional parts
    uint32_t ntp_frac = static_cast<uint32_t>((static_cast<uint64_t>(usec) << 32) / 1000000);

    return (static_cast<uint64_t>(ntp_sec) << 32) | ntp_frac;
}

} // namespace

void ReceptionReport::encode(common::ByteStreamWriter& writer) const {
    writer.write_u32(ssrc);
    uint32_t lost_word = (static_cast<uint32_t>(fraction_lost) << 24) |
                         (static_cast<uint32_t>(cumulative_lost) & 0x00FFFFFF);
    writer.write_u32(lost_word);
    writer.write_u32(highest_seq_received);
    writer.write_u32(interarrival_jitter);
    writer.write_u32(last_sr_timestamp);
    writer.write_u32(delay_since_last_sr);
}

ReceptionReport ReceptionReport::decode(common::ByteStreamReader& reader) {
    if (reader.remaining() < 24) {
        throw std::runtime_error("ReceptionReport: insufficient buffer (< 24 bytes)");
    }
    ReceptionReport r;
    r.ssrc = reader.read_u32();
    uint32_t lost_word = reader.read_u32();
    r.fraction_lost = static_cast<uint8_t>((lost_word >> 24) & 0xFF);

    uint32_t raw_cum = lost_word & 0x00FFFFFF;
    if (raw_cum & 0x00800000) {
        // Sign-extend 24-bit negative
        r.cumulative_lost = static_cast<int32_t>(raw_cum | 0xFF000000);
    } else {
        r.cumulative_lost = static_cast<int32_t>(raw_cum);
    }

    r.highest_seq_received = reader.read_u32();
    r.interarrival_jitter = reader.read_u32();
    r.last_sr_timestamp = reader.read_u32();
    r.delay_since_last_sr = reader.read_u32();
    return r;
}

void SenderReport::encode(common::ByteStreamWriter& writer) const {
    size_t start_pos = writer.size();

    uint8_t rc = static_cast<uint8_t>(reports.size() & 0x1F);
    uint8_t byte0 = (2 << 6) | rc;
    writer.write_u8(byte0);
    writer.write_u8(static_cast<uint8_t>(RtcpType::SR));

    size_t len_offset = writer.size();
    writer.write_u16(0); // Length placeholder

    writer.write_u32(ssrc);
    writer.write_u32(static_cast<uint32_t>(ntp_timestamp >> 32));
    writer.write_u32(static_cast<uint32_t>(ntp_timestamp & 0xFFFFFFFF));
    writer.write_u32(rtp_timestamp);
    writer.write_u32(sender_packet_count);
    writer.write_u32(sender_octet_count);

    for (const auto& r : reports) {
        r.encode(writer);
    }

    size_t total_bytes = writer.size() - start_pos;
    uint16_t length_in_words = static_cast<uint16_t>((total_bytes / 4) - 1);
    writer.set_u16(len_offset, length_in_words);
}

SenderReport SenderReport::decode(common::ByteStreamReader& reader, uint8_t report_count) {
    if (reader.remaining() < 24) {
        throw std::runtime_error("SenderReport: buffer too small (< 24 bytes)");
    }
    SenderReport sr;
    sr.ssrc = reader.read_u32();
    uint32_t ntp_msw = reader.read_u32();
    uint32_t ntp_lsw = reader.read_u32();
    sr.ntp_timestamp = (static_cast<uint64_t>(ntp_msw) << 32) | ntp_lsw;
    sr.rtp_timestamp = reader.read_u32();
    sr.sender_packet_count = reader.read_u32();
    sr.sender_octet_count = reader.read_u32();

    for (uint8_t i = 0; i < report_count; ++i) {
        sr.reports.push_back(ReceptionReport::decode(reader));
    }
    return sr;
}

void ReceiverReport::encode(common::ByteStreamWriter& writer) const {
    size_t start_pos = writer.size();

    uint8_t rc = static_cast<uint8_t>(reports.size() & 0x1F);
    uint8_t byte0 = (2 << 6) | rc;
    writer.write_u8(byte0);
    writer.write_u8(static_cast<uint8_t>(RtcpType::RR));

    size_t len_offset = writer.size();
    writer.write_u16(0);

    writer.write_u32(ssrc);

    for (const auto& r : reports) {
        r.encode(writer);
    }

    size_t total_bytes = writer.size() - start_pos;
    uint16_t length_in_words = static_cast<uint16_t>((total_bytes / 4) - 1);
    writer.set_u16(len_offset, length_in_words);
}

ReceiverReport ReceiverReport::decode(common::ByteStreamReader& reader, uint8_t report_count) {
    if (reader.remaining() < 4) {
        throw std::runtime_error("ReceiverReport: buffer too small (< 4 bytes)");
    }
    ReceiverReport rr;
    rr.ssrc = reader.read_u32();

    for (uint8_t i = 0; i < report_count; ++i) {
        rr.reports.push_back(ReceptionReport::decode(reader));
    }
    return rr;
}

void SdesChunk::encode(common::ByteStreamWriter& writer) const {
    size_t start_pos = writer.size();

    // Byte 0: V=2, P=0, SC=1
    writer.write_u8((2 << 6) | 1);
    writer.write_u8(static_cast<uint8_t>(RtcpType::SDES));

    size_t len_offset = writer.size();
    writer.write_u16(0);

    writer.write_u32(ssrc);

    // Item Type: 1 (CNAME)
    writer.write_u8(1);
    writer.write_u8(static_cast<uint8_t>(cname.size()));
    writer.write_string(cname);

    // End item with 0x00
    writer.write_u8(0);

    // Pad to 32-bit (4-byte) boundary
    while ((writer.size() - start_pos) % 4 != 0) {
        writer.write_u8(0);
    }

    size_t total_bytes = writer.size() - start_pos;
    uint16_t length_in_words = static_cast<uint16_t>((total_bytes / 4) - 1);
    writer.set_u16(len_offset, length_in_words);
}

SdesChunk SdesChunk::decode(common::ByteStreamReader& reader) {
    if (reader.remaining() < 4) {
        throw std::runtime_error("SdesChunk: buffer too small (< 4 bytes)");
    }
    SdesChunk chunk;
    chunk.ssrc = reader.read_u32();

    while (!reader.empty()) {
        uint8_t item_type = reader.read_u8();
        if (item_type == 0) { // End of items list
            break;
        }
        uint8_t len = reader.read_u8();
        std::string val = reader.read_string(len);
        if (item_type == 1) { // CNAME
            chunk.cname = std::move(val);
        }
    }
    return chunk;
}

void CompoundRtcp::encode(common::ByteStreamWriter& writer) const {
    for (const auto& sr : sender_reports) {
        sr.encode(writer);
    }
    for (const auto& rr : receiver_reports) {
        rr.encode(writer);
    }
    for (const auto& sc : sdes_chunks) {
        sc.encode(writer);
    }
}

CompoundRtcp CompoundRtcp::decode(common::ByteStreamReader& reader) {
    CompoundRtcp comp;
    while (!reader.empty()) {
        if (reader.remaining() < 4) break;

        size_t pkt_start = reader.tell();
        uint8_t byte0 = reader.read_u8();
        uint8_t count = byte0 & 0x1F;
        auto type = static_cast<RtcpType>(reader.read_u8());
        uint16_t len_words = reader.read_u16();
        size_t total_pkt_bytes = static_cast<size_t>(len_words + 1) * 4;

        if (type == RtcpType::SR) {
            comp.sender_reports.push_back(SenderReport::decode(reader, count));
        } else if (type == RtcpType::RR) {
            comp.receiver_reports.push_back(ReceiverReport::decode(reader, count));
        } else if (type == RtcpType::SDES) {
            comp.sdes_chunks.push_back(SdesChunk::decode(reader));
        }

        // Advance to next packet based on length field
        size_t read_bytes = reader.tell() - pkt_start;
        if (total_pkt_bytes > read_bytes && reader.remaining() >= (total_pkt_bytes - read_bytes)) {
            reader.skip(total_pkt_bytes - read_bytes);
        }
    }
    return comp;
}

CompoundRtcp CompoundRtcp::make_sender_report(
    uint32_t ssrc,
    uint32_t rtp_timestamp,
    uint32_t packet_count,
    uint32_t octet_count,
    std::string_view cname) {

    CompoundRtcp comp;
    SenderReport sr;
    sr.ssrc = ssrc;
    sr.ntp_timestamp = current_ntp_timestamp();
    sr.rtp_timestamp = rtp_timestamp;
    sr.sender_packet_count = packet_count;
    sr.sender_octet_count = octet_count;
    comp.sender_reports.push_back(sr);

    SdesChunk sc;
    sc.ssrc = ssrc;
    sc.cname = std::string(cname);
    comp.sdes_chunks.push_back(sc);

    return comp;
}

CompoundRtcp CompoundRtcp::make_receiver_report(
    uint32_t receiver_ssrc,
    const ReceptionReport& report,
    std::string_view cname) {

    CompoundRtcp comp;
    ReceiverReport rr;
    rr.ssrc = receiver_ssrc;
    rr.reports.push_back(report);
    comp.receiver_reports.push_back(rr);

    SdesChunk sc;
    sc.ssrc = receiver_ssrc;
    sc.cname = std::string(cname);
    comp.sdes_chunks.push_back(sc);

    return comp;
}

} // namespace gpp::rtp
