#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include "3gpp/sba/Http2Frame.hpp"
#include "3gpp/sba/Hpack.hpp"
#include "3gpp/sba/TlsSocket.hpp"

namespace gpp::sba {

struct SbaRequest {
    std::string method{"GET"};
    std::string path{"/"};
    std::string authority{"5gc.3gpp.local"};
    std::string scheme{"https"};
    std::string content_type{"application/json"};
    std::string body;
};

struct SbaResponse {
    int status{200};
    std::string content_type{"application/json"};
    std::string body;
    std::vector<HeaderField> headers;
};

class SbaSession {
public:
    explicit SbaSession(TlsSocket& socket, bool is_client);

    // Initial HTTP/2 connection handshake (preface + SETTINGS exchange)
    bool perform_handshake(int timeout_ms = 2000);

    // Send a 5G SBA HTTP/2 request (Client side)
    bool send_request(uint32_t stream_id, const SbaRequest& req);

    // Receive a 5G SBA HTTP/2 request (Server side)
    std::optional<std::pair<uint32_t, SbaRequest>> receive_request(int timeout_ms = 2000);

    // Send a 5G SBA HTTP/2 response (Server side)
    bool send_response(uint32_t stream_id, const SbaResponse& resp);

    // Receive a 5G SBA HTTP/2 response (Client side)
    std::optional<SbaResponse> receive_response(int timeout_ms = 2000);

    // Low-level HTTP/2 frame I/O
    bool send_frame(const Http2Frame& frame);
    std::optional<Http2Frame> receive_frame(int timeout_ms = 2000);

private:
    TlsSocket& socket_;
    bool is_client_;
    std::vector<uint8_t> rx_buffer_;

    bool read_exact(size_t num_bytes, std::vector<uint8_t>& out, int timeout_ms);
};

} // namespace gpp::sba
