#include "3gpp/rtp/RtpPacket.hpp"
#include <stdexcept>

namespace gpp::rtp {

void RtpPacket::set_payload(std::span<const uint8_t> data) {
    payload.assign(data.begin(), data.end());
}

void RtpPacket::set_payload(std::string_view text) {
    payload.assign(text.begin(), text.end());
}

void RtpPacket::encode(common::ByteStreamWriter& writer) const {
    // Byte 0: V (2), P (1), X (1), CC (4)
    uint8_t byte0 = static_cast<uint8_t>((version & 0x03) << 6);
    if (padding)   byte0 |= (1 << 5);
    if (extension) byte0 |= (1 << 4);
    uint8_t cc = static_cast<uint8_t>(std::min<size_t>(csrc_list.size(), 15));
    byte0 |= (cc & 0x0F);
    writer.write_u8(byte0);

    // Byte 1: M (1), PT (7)
    uint8_t byte1 = static_cast<uint8_t>(payload_type & 0x7F);
    if (marker) byte1 |= (1 << 7);
    writer.write_u8(byte1);

    // Sequence Number (16 bits)
    writer.write_u16(sequence_number);

    // Timestamp (32 bits)
    writer.write_u32(timestamp);

    // SSRC (32 bits)
    writer.write_u32(ssrc);

    // CSRC list (if any)
    for (size_t i = 0; i < cc; ++i) {
        writer.write_u32(csrc_list[i]);
    }

    // Payload
    if (!payload.empty()) {
        writer.write_bytes(payload);
    }
}

RtpPacket RtpPacket::decode(common::ByteStreamReader& reader) {
    if (reader.remaining() < FixedHeaderSize) {
        throw std::runtime_error("RtpPacket: buffer too small for 12-byte fixed header");
    }

    RtpPacket pkt;
    uint8_t byte0 = reader.read_u8();
    pkt.version = (byte0 >> 6) & 0x03;
    pkt.padding = (byte0 & (1 << 5)) != 0;
    pkt.extension = (byte0 & (1 << 4)) != 0;
    pkt.csrc_count = byte0 & 0x0F;

    if (pkt.version != 2) {
        throw std::runtime_error("RtpPacket: invalid RTP version " + std::to_string(pkt.version));
    }

    uint8_t byte1 = reader.read_u8();
    pkt.marker = (byte1 & 0x80) != 0;
    pkt.payload_type = byte1 & 0x7F;

    pkt.sequence_number = reader.read_u16();
    pkt.timestamp = reader.read_u32();
    pkt.ssrc = reader.read_u32();

    // Read CSRCs
    if (pkt.csrc_count > 0) {
        if (reader.remaining() < static_cast<size_t>(pkt.csrc_count * 4)) {
            throw std::runtime_error("RtpPacket: buffer truncated while reading CSRC list");
        }
        for (uint8_t i = 0; i < pkt.csrc_count; ++i) {
            pkt.csrc_list.push_back(reader.read_u32());
        }
    }

    // Read remaining as payload
    if (!reader.empty()) {
        auto p = reader.read_bytes(reader.remaining());
        pkt.payload.assign(p.begin(), p.end());
    }

    return pkt;
}

RtpPacket RtpPacket::make_amrwb_packet(
    uint32_t ssrc,
    uint16_t seq_num,
    uint32_t timestamp,
    bool marker) {

    RtpPacket pkt;
    pkt.version = 2;
    pkt.marker = marker;
    pkt.payload_type = 104; // Standard dynamic PT for AMR-WB in 3GPP VoLTE
    pkt.sequence_number = seq_num;
    pkt.timestamp = timestamp;
    pkt.ssrc = ssrc;

    // Construct 3GPP TS 26.201 / RFC 4867 AMR-WB Payload (Octet-aligned mode):
    // CMR (Codec Mode Request): 4 bits (e.g. 0x02 for Mode 2: 12.65 kbps) + 4 bits 0
    // TOC (Table of Contents): F=0 (last frame), FT=2 (Mode 2), Q=1 (good quality), 2 bits 0 -> 0x14
    // 32 bytes speech bits
    std::vector<uint8_t> amr_data(34, 0);
    amr_data[0] = 0x20; // CMR: 12.65 kbps
    amr_data[1] = 0x14; // TOC: Frame Type 2 (12.65 kbps), Q=1
    // Fill remaining with synthetic sinusoidal / speech pattern
    for (size_t i = 2; i < amr_data.size(); ++i) {
        amr_data[i] = static_cast<uint8_t>((i * 17 + seq_num) & 0xFF);
    }

    pkt.set_payload(amr_data);
    return pkt;
}

} // namespace gpp::rtp
