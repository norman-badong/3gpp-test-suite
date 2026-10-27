#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <string>
#include <string_view>
#include "3gpp/common/ByteStream.hpp"

namespace gpp::sba {

// RFC 7540 / RFC 9113 Connection Preface
inline constexpr std::string_view HTTP2_CLIENT_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// HTTP/2 Frame Types (RFC 7540 Section 11.2)
enum class FrameType : uint8_t {
    DATA          = 0x00,
    HEADERS       = 0x01,
    PRIORITY      = 0x02,
    RST_STREAM    = 0x03,
    SETTINGS      = 0x04,
    PUSH_PROMISE  = 0x05,
    PING          = 0x06,
    GOAWAY        = 0x07,
    WINDOW_UPDATE = 0x08,
    CONTINUATION  = 0x09,
};

// HTTP/2 Flags
namespace FrameFlags {
    inline constexpr uint8_t NONE         = 0x00;
    inline constexpr uint8_t END_STREAM   = 0x01; // DATA, HEADERS
    inline constexpr uint8_t ACK          = 0x01; // SETTINGS, PING
    inline constexpr uint8_t END_HEADERS  = 0x04; // HEADERS, PUSH_PROMISE, CONTINUATION
    inline constexpr uint8_t PADDED       = 0x08; // DATA, HEADERS
    inline constexpr uint8_t PRIORITY_SET = 0x20; // HEADERS
}

// HTTP/2 Settings Identifiers (RFC 7540 Section 6.5.2)
enum class SettingId : uint16_t {
    HEADER_TABLE_SIZE      = 0x01,
    ENABLE_PUSH            = 0x02,
    MAX_CONCURRENT_STREAMS = 0x03,
    INITIAL_WINDOW_SIZE    = 0x04,
    MAX_FRAME_SIZE         = 0x05,
    MAX_HEADER_LIST_SIZE   = 0x06,
};

// HTTP/2 Error Codes (RFC 7540 Section 7)
enum class Http2ErrorCode : uint32_t {
    NO_ERROR            = 0x00,
    PROTOCOL_ERROR      = 0x01,
    INTERNAL_ERROR      = 0x02,
    FLOW_CONTROL_ERROR  = 0x03,
    SETTINGS_TIMEOUT    = 0x04,
    STREAM_CLOSED       = 0x05,
    FRAME_SIZE_ERROR    = 0x06,
    REFUSED_STREAM      = 0x07,
    CANCEL              = 0x08,
    COMPRESSION_ERROR   = 0x09,
    CONNECT_ERROR       = 0x0A,
    ENHANCE_YOUR_CALM   = 0x0B,
    INADEQUATE_SECURITY = 0x0C,
    HTTP_1_1_REQUIRED   = 0x0D,
};

// Generic HTTP/2 Frame Header (9 octets)
struct Http2FrameHeader {
    uint32_t length{0};         // 24 bits
    FrameType type{FrameType::DATA};
    uint8_t flags{0};
    uint32_t stream_id{0};      // 31 bits

    static constexpr size_t HeaderSize = 9;

    void encode(common::ByteStreamWriter& writer) const;
    static Http2FrameHeader decode(common::ByteStreamReader& reader);
};

// Generic HTTP/2 Frame
struct Http2Frame {
    Http2FrameHeader header;
    std::vector<uint8_t> payload;

    void encode(common::ByteStreamWriter& writer) const;
    static Http2Frame decode(common::ByteStreamReader& reader);

    // Factory methods for common 5G SBA frames
    static Http2Frame make_settings(const std::vector<std::pair<SettingId, uint32_t>>& settings, bool ack = false);
    static Http2Frame make_settings_ack();
    static Http2Frame make_headers(uint32_t stream_id, std::span<const uint8_t> hpack_block, bool end_stream, bool end_headers = true);
    static Http2Frame make_data(uint32_t stream_id, std::span<const uint8_t> data, bool end_stream);
    static Http2Frame make_ping(uint64_t opaque_data, bool ack = false);
    static Http2Frame make_goaway(uint32_t last_stream_id, Http2ErrorCode error_code, std::string_view debug_data = "");
    static Http2Frame make_window_update(uint32_t stream_id, uint32_t window_size_increment);
};

} // namespace gpp::sba
