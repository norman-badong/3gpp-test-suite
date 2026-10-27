#include "3gpp/diameter/DiameterStack.hpp"
#include <cstring>

namespace gpp {
namespace diameter {

bool DiameterConnection::send_message(const DiameterMessage& msg) {
    if (!socket_ || !socket_->is_valid()) {
        return false;
    }
    std::vector<uint8_t> bytes = msg.serialize();
    ssize_t sent = socket_->send(bytes);
    return sent == static_cast<ssize_t>(bytes.size());
}

std::optional<DiameterMessage> DiameterConnection::receive_message(std::chrono::milliseconds timeout) {
    if (!socket_ || !socket_->is_valid()) {
        return std::nullopt;
    }
    int timeout_ms = static_cast<int>(timeout.count());

    // 1. Read first 4 bytes to determine Version and Message-Length
    uint8_t prefix[4];
    size_t prefix_read = 0;
    while (prefix_read < 4) {
        std::span<uint8_t> span_buf(prefix + prefix_read, 4 - prefix_read);
        ssize_t rc = socket_->recv(span_buf, timeout_ms);
        if (rc <= 0) {
            return std::nullopt;
        }
        prefix_read += static_cast<size_t>(rc);
    }

    uint8_t version = prefix[0];
    if (version != 1) {
        return std::nullopt;
    }

    uint32_t msg_length = (static_cast<uint32_t>(prefix[1]) << 16) |
                          (static_cast<uint32_t>(prefix[2]) << 8)  |
                          static_cast<uint32_t>(prefix[3]);

    if (msg_length < DIAMETER_HEADER_SIZE || (msg_length % 4) != 0) {
        return std::nullopt;
    }

    // 2. Read the remainder of the message
    std::vector<uint8_t> full_msg(msg_length);
    std::memcpy(full_msg.data(), prefix, 4);

    size_t total_read = 4;
    while (total_read < msg_length) {
        std::span<uint8_t> span_buf(full_msg.data() + total_read, msg_length - total_read);
        ssize_t rc = socket_->recv(span_buf, timeout_ms);
        if (rc <= 0) {
            return std::nullopt;
        }
        total_read += static_cast<size_t>(rc);
    }

    return DiameterMessage::decode(full_msg.data(), full_msg.size());
}

} // namespace diameter
} // namespace gpp
