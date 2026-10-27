#pragma once

#include "3gpp/diameter/DiameterMessage.hpp"
#include "3gpp/ip/Socket.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <string>

namespace gpp {
namespace diameter {

/**
 * Standard Diameter TCP/SCTP port (RFC 6733)
 */
constexpr uint16_t DIAMETER_DEFAULT_PORT = 3868;

/**
 * Diameter Stream Framer / Connection Handler for exchanging messages over TCP.
 */
class DiameterConnection {
public:
    explicit DiameterConnection(std::unique_ptr<ip::TcpSocket> socket)
        : socket_(std::move(socket)) {}

    DiameterConnection(const DiameterConnection&) = delete;
    DiameterConnection& operator=(const DiameterConnection&) = delete;
    DiameterConnection(DiameterConnection&&) noexcept = default;
    DiameterConnection& operator=(DiameterConnection&&) noexcept = default;

    /**
     * Send a Diameter message over the connection.
     */
    bool send_message(const DiameterMessage& msg);

    /**
     * Receive one complete Diameter message from the connection (with timeout).
     */
    std::optional<DiameterMessage> receive_message(std::chrono::milliseconds timeout = std::chrono::milliseconds(2000));

    [[nodiscard]] bool is_valid() const { return socket_ && socket_->is_valid(); }
    void close() { if (socket_) socket_->close(); }
    [[nodiscard]] ip::TcpSocket* socket() { return socket_.get(); }

private:
    std::unique_ptr<ip::TcpSocket> socket_;
};

} // namespace diameter
} // namespace gpp
