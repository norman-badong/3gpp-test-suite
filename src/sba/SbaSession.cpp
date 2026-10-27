#include "3gpp/sba/SbaSession.hpp"
#include "3gpp/common/Logger.hpp"

namespace gpp::sba {

SbaSession::SbaSession(TlsSocket& socket, bool is_client)
    : socket_(socket), is_client_(is_client) {}

bool SbaSession::read_exact(size_t num_bytes, std::vector<uint8_t>& out, int timeout_ms) {
    out.clear();
    out.reserve(num_bytes);

    // Consume from rx_buffer_ first if any
    if (!rx_buffer_.empty()) {
        size_t take = std::min(num_bytes, rx_buffer_.size());
        out.insert(out.end(), rx_buffer_.begin(), rx_buffer_.begin() + take);
        rx_buffer_.erase(rx_buffer_.begin(), rx_buffer_.begin() + take);
    }

    std::array<uint8_t, 2048> tmp{};
    while (out.size() < num_bytes) {
        size_t needed = num_bytes - out.size();
        ssize_t n = socket_.recv(std::span<uint8_t>(tmp.data(), std::min(needed, tmp.size())), timeout_ms);
        if (n <= 0) {
            return false;
        }
        out.insert(out.end(), tmp.begin(), tmp.begin() + n);
    }
    return true;
}

bool SbaSession::send_frame(const Http2Frame& frame) {
    common::ByteStreamWriter writer;
    frame.encode(writer);
    auto data = writer.data();
    ssize_t sent = socket_.send(data);
    return sent == static_cast<ssize_t>(data.size());
}

std::optional<Http2Frame> SbaSession::receive_frame(int timeout_ms) {
    // 1. Read 9-byte frame header
    std::vector<uint8_t> header_bytes;
    if (!read_exact(Http2FrameHeader::HeaderSize, header_bytes, timeout_ms)) {
        return std::nullopt;
    }

    common::ByteStreamReader r_hdr(header_bytes);
    Http2FrameHeader hdr = Http2FrameHeader::decode(r_hdr);

    Http2Frame frame;
    frame.header = hdr;

    // 2. Read payload if length > 0
    if (hdr.length > 0) {
        if (!read_exact(hdr.length, frame.payload, timeout_ms)) {
            return std::nullopt;
        }
    }
    return frame;
}

bool SbaSession::perform_handshake(int timeout_ms) {
    if (is_client_) {
        // 1. Client sends 24-byte connection preface
        std::span<const uint8_t> preface_span(
            reinterpret_cast<const uint8_t*>(HTTP2_CLIENT_PREFACE.data()),
            HTTP2_CLIENT_PREFACE.size());
        if (socket_.send(preface_span) != static_cast<ssize_t>(HTTP2_CLIENT_PREFACE.size())) {
            GPP_LOG_ERROR("SBA_CLIENT", "Failed to send HTTP/2 client preface");
            return false;
        }

        // 2. Client sends initial SETTINGS frame
        std::vector<std::pair<SettingId, uint32_t>> initial_settings = {
            { SettingId::MAX_CONCURRENT_STREAMS, 100 },
            { SettingId::INITIAL_WINDOW_SIZE, 65535 },
            { SettingId::ENABLE_PUSH, 0 } // Push not used in 5G SBA
        };
        if (!send_frame(Http2Frame::make_settings(initial_settings))) {
            GPP_LOG_ERROR("SBA_CLIENT", "Failed to send initial SETTINGS");
            return false;
        }

        // 3. Client receives Server SETTINGS
        auto srv_settings = receive_frame(timeout_ms);
        if (!srv_settings || srv_settings->header.type != FrameType::SETTINGS) {
            GPP_LOG_ERROR("SBA_CLIENT", "Did not receive server SETTINGS frame");
            return false;
        }

        // 4. Client sends SETTINGS ACK
        if (!send_frame(Http2Frame::make_settings_ack())) {
            GPP_LOG_ERROR("SBA_CLIENT", "Failed to send SETTINGS ACK");
            return false;
        }

        // 5. Client receives Server SETTINGS ACK
        auto srv_ack = receive_frame(timeout_ms);
        if (!srv_ack || srv_ack->header.type != FrameType::SETTINGS || (srv_ack->header.flags & FrameFlags::ACK) == 0) {
            GPP_LOG_ERROR("SBA_CLIENT", "Did not receive server SETTINGS ACK");
            return false;
        }

        GPP_LOG_INFO("SBA_CLIENT", "HTTP/2 connection established successfully with 5G SBA Server!");
        return true;
    } else {
        // Server side:
        // 1. Read 24-byte client preface
        std::vector<uint8_t> preface_buf;
        if (!read_exact(HTTP2_CLIENT_PREFACE.size(), preface_buf, timeout_ms)) {
            GPP_LOG_ERROR("SBA_SERVER", "Failed to read client preface");
            return false;
        }

        std::string_view recvd_preface(reinterpret_cast<const char*>(preface_buf.data()), preface_buf.size());
        if (recvd_preface != HTTP2_CLIENT_PREFACE) {
            GPP_LOG_ERROR("SBA_SERVER", "Invalid HTTP/2 client preface received");
            return false;
        }

        // 2. Read Client SETTINGS
        auto client_settings = receive_frame(timeout_ms);
        if (!client_settings || client_settings->header.type != FrameType::SETTINGS) {
            GPP_LOG_ERROR("SBA_SERVER", "Did not receive client SETTINGS");
            return false;
        }

        // 3. Server sends its SETTINGS
        std::vector<std::pair<SettingId, uint32_t>> srv_settings = {
            { SettingId::MAX_CONCURRENT_STREAMS, 250 },
            { SettingId::INITIAL_WINDOW_SIZE, 65535 }
        };
        if (!send_frame(Http2Frame::make_settings(srv_settings))) {
            return false;
        }

        // 4. Server sends SETTINGS ACK to client
        if (!send_frame(Http2Frame::make_settings_ack())) {
            return false;
        }

        // 5. Server receives Client SETTINGS ACK
        auto client_ack = receive_frame(timeout_ms);
        if (!client_ack || client_ack->header.type != FrameType::SETTINGS || (client_ack->header.flags & FrameFlags::ACK) == 0) {
            GPP_LOG_ERROR("SBA_SERVER", "Did not receive client SETTINGS ACK");
            return false;
        }

        GPP_LOG_INFO("SBA_SERVER", "HTTP/2 connection established successfully with 5G SBA Client!");
        return true;
    }
}

bool SbaSession::send_request(uint32_t stream_id, const SbaRequest& req) {
    std::vector<HeaderField> headers = {
        { ":method", req.method },
        { ":scheme", req.scheme },
        { ":path", req.path },
        { ":authority", req.authority },
        { "content-type", req.content_type },
        { "accept", "application/json" }
    };

    auto hpack_block = Hpack::encode(headers);
    bool has_body = !req.body.empty();

    // Send HEADERS
    auto hdr_frame = Http2Frame::make_headers(stream_id, hpack_block, !has_body /* end_stream if no body */);
    if (!send_frame(hdr_frame)) {
        return false;
    }

    // Send DATA if body present
    if (has_body) {
        std::span<const uint8_t> body_span(reinterpret_cast<const uint8_t*>(req.body.data()), req.body.size());
        auto data_frame = Http2Frame::make_data(stream_id, body_span, true /* end_stream */);
        if (!send_frame(data_frame)) {
            return false;
        }
    }
    return true;
}

std::optional<std::pair<uint32_t, SbaRequest>> SbaSession::receive_request(int timeout_ms) {
    auto frame_opt = receive_frame(timeout_ms);
    if (!frame_opt || frame_opt->header.type != FrameType::HEADERS) {
        return std::nullopt;
    }

    uint32_t stream_id = frame_opt->header.stream_id;
    bool end_stream = (frame_opt->header.flags & FrameFlags::END_STREAM) != 0;

    auto headers = Hpack::decode(frame_opt->payload);
    SbaRequest req;
    for (const auto& h : headers) {
        if (h.name == ":method") req.method = h.value;
        else if (h.name == ":path") req.path = h.value;
        else if (h.name == ":authority") req.authority = h.value;
        else if (h.name == ":scheme") req.scheme = h.value;
        else if (h.name == "content-type") req.content_type = h.value;
    }

    if (!end_stream) {
        // Read DATA frame
        auto data_frame_opt = receive_frame(timeout_ms);
        if (data_frame_opt && data_frame_opt->header.type == FrameType::DATA) {
            req.body.assign(reinterpret_cast<const char*>(data_frame_opt->payload.data()), data_frame_opt->payload.size());
        }
    }

    return std::make_pair(stream_id, req);
}

bool SbaSession::send_response(uint32_t stream_id, const SbaResponse& resp) {
    std::vector<HeaderField> headers = {
        { ":status", std::to_string(resp.status) },
        { "content-type", resp.content_type }
    };
    for (const auto& h : resp.headers) {
        headers.push_back(h);
    }

    auto hpack_block = Hpack::encode(headers);
    bool has_body = !resp.body.empty();

    auto hdr_frame = Http2Frame::make_headers(stream_id, hpack_block, !has_body /* end_stream if no body */);
    if (!send_frame(hdr_frame)) {
        return false;
    }

    if (has_body) {
        std::span<const uint8_t> body_span(reinterpret_cast<const uint8_t*>(resp.body.data()), resp.body.size());
        auto data_frame = Http2Frame::make_data(stream_id, body_span, true /* end_stream */);
        if (!send_frame(data_frame)) {
            return false;
        }
    }
    return true;
}

std::optional<SbaResponse> SbaSession::receive_response(int timeout_ms) {
    auto frame_opt = receive_frame(timeout_ms);
    if (!frame_opt || frame_opt->header.type != FrameType::HEADERS) {
        return std::nullopt;
    }

    bool end_stream = (frame_opt->header.flags & FrameFlags::END_STREAM) != 0;
    auto headers = Hpack::decode(frame_opt->payload);

    SbaResponse resp;
    resp.headers = headers;
    for (const auto& h : headers) {
        if (h.name == ":status") {
            resp.status = std::stoi(h.value);
        } else if (h.name == "content-type") {
            resp.content_type = h.value;
        }
    }

    if (!end_stream) {
        auto data_frame_opt = receive_frame(timeout_ms);
        if (data_frame_opt && data_frame_opt->header.type == FrameType::DATA) {
            resp.body.assign(reinterpret_cast<const char*>(data_frame_opt->payload.data()), data_frame_opt->payload.size());
        }
    }

    return resp;
}

} // namespace gpp::sba
