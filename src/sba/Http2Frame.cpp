#include "3gpp/sba/Http2Frame.hpp"
#include <stdexcept>

namespace gpp::sba {

void Http2FrameHeader::encode(common::ByteStreamWriter& writer) const {
    writer.write_u24(length & 0x00FFFFFF);
    writer.write_u8(static_cast<uint8_t>(type));
    writer.write_u8(flags);
    writer.write_u32(stream_id & 0x7FFFFFFF);
}

Http2FrameHeader Http2FrameHeader::decode(common::ByteStreamReader& reader) {
    if (reader.remaining() < HeaderSize) {
        throw std::runtime_error("Http2FrameHeader: buffer too small (< 9 bytes)");
    }

    Http2FrameHeader hdr;
    hdr.length = reader.read_u24();
    hdr.type = static_cast<FrameType>(reader.read_u8());
    hdr.flags = reader.read_u8();
    hdr.stream_id = reader.read_u32() & 0x7FFFFFFF;
    return hdr;
}

void Http2Frame::encode(common::ByteStreamWriter& writer) const {
    Http2FrameHeader h = header;
    h.length = static_cast<uint32_t>(payload.size());
    h.encode(writer);
    if (!payload.empty()) {
        writer.write_bytes(payload);
    }
}

Http2Frame Http2Frame::decode(common::ByteStreamReader& reader) {
    Http2Frame frame;
    frame.header = Http2FrameHeader::decode(reader);

    if (frame.header.length > 0) {
        if (reader.remaining() < frame.header.length) {
            throw std::runtime_error("Http2Frame: incomplete payload (expected " +
                                     std::to_string(frame.header.length) + ", remaining " +
                                     std::to_string(reader.remaining()) + ")");
        }
        auto sp = reader.read_bytes(frame.header.length);
        frame.payload.assign(sp.begin(), sp.end());
    }
    return frame;
}

Http2Frame Http2Frame::make_settings(const std::vector<std::pair<SettingId, uint32_t>>& settings, bool ack) {
    Http2Frame frame;
    frame.header.type = FrameType::SETTINGS;
    frame.header.stream_id = 0; // SETTINGS must always use stream 0
    frame.header.flags = ack ? FrameFlags::ACK : FrameFlags::NONE;

    if (!ack) {
        common::ByteStreamWriter writer;
        for (const auto& [id, val] : settings) {
            writer.write_u16(static_cast<uint16_t>(id));
            writer.write_u32(val);
        }
        frame.payload = writer.take_data();
    }
    frame.header.length = static_cast<uint32_t>(frame.payload.size());
    return frame;
}

Http2Frame Http2Frame::make_settings_ack() {
    return make_settings({}, true);
}

Http2Frame Http2Frame::make_headers(uint32_t stream_id, std::span<const uint8_t> hpack_block, bool end_stream, bool end_headers) {
    Http2Frame frame;
    frame.header.type = FrameType::HEADERS;
    frame.header.stream_id = stream_id;
    frame.header.flags = 0;
    if (end_stream)  frame.header.flags |= FrameFlags::END_STREAM;
    if (end_headers) frame.header.flags |= FrameFlags::END_HEADERS;

    frame.payload.assign(hpack_block.begin(), hpack_block.end());
    frame.header.length = static_cast<uint32_t>(frame.payload.size());
    return frame;
}

Http2Frame Http2Frame::make_data(uint32_t stream_id, std::span<const uint8_t> data, bool end_stream) {
    Http2Frame frame;
    frame.header.type = FrameType::DATA;
    frame.header.stream_id = stream_id;
    frame.header.flags = end_stream ? FrameFlags::END_STREAM : FrameFlags::NONE;
    frame.payload.assign(data.begin(), data.end());
    frame.header.length = static_cast<uint32_t>(frame.payload.size());
    return frame;
}

Http2Frame Http2Frame::make_ping(uint64_t opaque_data, bool ack) {
    Http2Frame frame;
    frame.header.type = FrameType::PING;
    frame.header.stream_id = 0;
    frame.header.flags = ack ? FrameFlags::ACK : FrameFlags::NONE;

    common::ByteStreamWriter writer;
    writer.write_u64(opaque_data);
    frame.payload = writer.take_data();
    frame.header.length = 8;
    return frame;
}

Http2Frame Http2Frame::make_goaway(uint32_t last_stream_id, Http2ErrorCode error_code, std::string_view debug_data) {
    Http2Frame frame;
    frame.header.type = FrameType::GOAWAY;
    frame.header.stream_id = 0;
    frame.header.flags = FrameFlags::NONE;

    common::ByteStreamWriter writer;
    writer.write_u32(last_stream_id & 0x7FFFFFFF);
    writer.write_u32(static_cast<uint32_t>(error_code));
    if (!debug_data.empty()) {
        writer.write_string(debug_data);
    }
    frame.payload = writer.take_data();
    frame.header.length = static_cast<uint32_t>(frame.payload.size());
    return frame;
}

Http2Frame Http2Frame::make_window_update(uint32_t stream_id, uint32_t window_size_increment) {
    Http2Frame frame;
    frame.header.type = FrameType::WINDOW_UPDATE;
    frame.header.stream_id = stream_id;
    frame.header.flags = FrameFlags::NONE;

    common::ByteStreamWriter writer;
    writer.write_u32(window_size_increment & 0x7FFFFFFF);
    frame.payload = writer.take_data();
    frame.header.length = 4;
    return frame;
}

} // namespace gpp::sba
