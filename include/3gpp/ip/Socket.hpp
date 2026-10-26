#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <span>
#include <memory>

namespace gpp::ip {

class UdpSocket {
public:
    UdpSocket();
    ~UdpSocket();

    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    UdpSocket(UdpSocket&& other) noexcept;
    UdpSocket& operator=(UdpSocket&& other) noexcept;

    bool bind(std::string_view host, uint16_t port);
    ssize_t send_to(std::span<const uint8_t> data, std::string_view host, uint16_t port);
    ssize_t recv_from(std::span<uint8_t> buffer, std::string& src_host, uint16_t& src_port, int timeout_ms = -1);

    [[nodiscard]] uint16_t local_port() const;
    void close();
    [[nodiscard]] bool is_valid() const { return fd_ >= 0; }

private:
    int fd_{-1};
    int family_{2}; // AF_INET by default
};

class TcpSocket {
public:
    TcpSocket();
    explicit TcpSocket(int fd, int family);
    ~TcpSocket();

    TcpSocket(const TcpSocket&) = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;

    TcpSocket(TcpSocket&& other) noexcept;
    TcpSocket& operator=(TcpSocket&& other) noexcept;

    bool connect(std::string_view host, uint16_t port, int timeout_ms = 5000);
    ssize_t send(std::span<const uint8_t> data);
    ssize_t recv(std::span<uint8_t> buffer, int timeout_ms = -1);

    void close();
    [[nodiscard]] bool is_valid() const { return fd_ >= 0; }
    [[nodiscard]] int fd() const { return fd_; }

private:
    int fd_{-1};
    int family_{2};
};

class TcpListener {
public:
    TcpListener();
    ~TcpListener();

    TcpListener(const TcpListener&) = delete;
    TcpListener& operator=(const TcpListener&) = delete;

    TcpListener(TcpListener&& other) noexcept;
    TcpListener& operator=(TcpListener&& other) noexcept;

    bool listen(std::string_view host, uint16_t port, int backlog = 10);
    bool accept(TcpSocket& client_socket, std::string& client_host, uint16_t& client_port, int timeout_ms = -1);

    [[nodiscard]] uint16_t local_port() const;
    void close();
    [[nodiscard]] bool is_valid() const { return fd_ >= 0; }

private:
    int fd_{-1};
    int family_{2};
};

} // namespace gpp::ip
