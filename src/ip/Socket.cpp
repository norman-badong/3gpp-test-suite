#include "3gpp/ip/Socket.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <netdb.h>
#include <cstring>
#include <stdexcept>

namespace gpp::ip {

namespace {

int resolve_and_setup(std::string_view host, uint16_t port, int sock_type, struct sockaddr_storage& out_addr, socklen_t& out_len) {
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = sock_type;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

    std::string host_str(host);
    std::string port_str = std::to_string(port);

    struct addrinfo* res = nullptr;
    int rc = getaddrinfo(host_str.empty() ? nullptr : host_str.c_str(), port_str.c_str(), &hints, &res);
    if (rc != 0 || !res) {
        return -1;
    }

    std::memcpy(&out_addr, res->ai_addr, res->ai_addrlen);
    out_len = res->ai_addrlen;
    int family = res->ai_family;
    freeaddrinfo(res);
    return family;
}

void format_address(const struct sockaddr_storage& ss, std::string& out_host, uint16_t& out_port) {
    char host_buf[INET6_ADDRSTRLEN];
    if (ss.ss_family == AF_INET) {
        const auto* sin = reinterpret_cast<const struct sockaddr_in*>(&ss);
        inet_ntop(AF_INET, &sin->sin_addr, host_buf, sizeof(host_buf));
        out_host = host_buf;
        out_port = ntohs(sin->sin_port);
    } else if (ss.ss_family == AF_INET6) {
        const auto* sin6 = reinterpret_cast<const struct sockaddr_in6*>(&ss);
        inet_ntop(AF_INET6, &sin6->sin6_addr, host_buf, sizeof(host_buf));
        out_host = host_buf;
        out_port = ntohs(sin6->sin6_port);
    }
}

} // namespace

// -----------------------------------------------------------------
// UdpSocket
// -----------------------------------------------------------------

UdpSocket::UdpSocket() = default;

UdpSocket::~UdpSocket() {
    close();
}

UdpSocket::UdpSocket(UdpSocket&& other) noexcept
    : fd_(other.fd_), family_(other.family_) {
    other.fd_ = -1;
}

UdpSocket& UdpSocket::operator=(UdpSocket&& other) noexcept {
    if (this != &other) {
        close();
        fd_ = other.fd_;
        family_ = other.family_;
        other.fd_ = -1;
    }
    return *this;
}

void UdpSocket::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

bool UdpSocket::bind(std::string_view host, uint16_t port) {
    close();

    struct sockaddr_storage addr{};
    socklen_t addr_len = 0;
    family_ = resolve_and_setup(host, port, SOCK_DGRAM, addr, addr_len);
    if (family_ < 0) {
        return false;
    }

    fd_ = ::socket(family_, SOCK_DGRAM, 0);
    if (fd_ < 0) {
        return false;
    }

    int opt = 1;
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (::bind(fd_, reinterpret_cast<struct sockaddr*>(&addr), addr_len) < 0) {
        close();
        return false;
    }

    return true;
}

ssize_t UdpSocket::send_to(std::span<const uint8_t> data, std::string_view host, uint16_t port) {
    struct sockaddr_storage addr{};
    socklen_t addr_len = 0;
    int family = resolve_and_setup(host, port, SOCK_DGRAM, addr, addr_len);
    if (family < 0) {
        return -1;
    }

    if (fd_ < 0) {
        family_ = family;
        fd_ = ::socket(family_, SOCK_DGRAM, 0);
        if (fd_ < 0) return -1;
    }

    return ::sendto(fd_, data.data(), data.size(), 0, reinterpret_cast<struct sockaddr*>(&addr), addr_len);
}

ssize_t UdpSocket::recv_from(std::span<uint8_t> buffer, std::string& src_host, uint16_t& src_port, int timeout_ms) {
    if (fd_ < 0) return -1;

    if (timeout_ms >= 0) {
        struct pollfd pfd{};
        pfd.fd = fd_;
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, timeout_ms);
        if (ret <= 0) return ret; // 0 timeout, < 0 error
    }

    struct sockaddr_storage src_addr{};
    socklen_t addr_len = sizeof(src_addr);
    ssize_t n = ::recvfrom(fd_, buffer.data(), buffer.size(), 0, reinterpret_cast<struct sockaddr*>(&src_addr), &addr_len);
    if (n > 0) {
        format_address(src_addr, src_host, src_port);
    }
    return n;
}

uint16_t UdpSocket::local_port() const {
    if (fd_ < 0) return 0;
    struct sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
    if (getsockname(fd_, reinterpret_cast<struct sockaddr*>(&addr), &len) == 0) {
        if (addr.ss_family == AF_INET) {
            return ntohs(reinterpret_cast<struct sockaddr_in*>(&addr)->sin_port);
        } else if (addr.ss_family == AF_INET6) {
            return ntohs(reinterpret_cast<struct sockaddr_in6*>(&addr)->sin6_port);
        }
    }
    return 0;
}

// -----------------------------------------------------------------
// TcpSocket
// -----------------------------------------------------------------

TcpSocket::TcpSocket() = default;

TcpSocket::TcpSocket(int fd, int family) : fd_(fd), family_(family) {}

TcpSocket::~TcpSocket() {
    close();
}

TcpSocket::TcpSocket(TcpSocket&& other) noexcept
    : fd_(other.fd_), family_(other.family_) {
    other.fd_ = -1;
}

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
    if (this != &other) {
        close();
        fd_ = other.fd_;
        family_ = other.family_;
        other.fd_ = -1;
    }
    return *this;
}

void TcpSocket::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

bool TcpSocket::connect(std::string_view host, uint16_t port, int timeout_ms) {
    close();

    struct sockaddr_storage addr{};
    socklen_t addr_len = 0;
    family_ = resolve_and_setup(host, port, SOCK_STREAM, addr, addr_len);
    if (family_ < 0) return false;

    fd_ = ::socket(family_, SOCK_STREAM, 0);
    if (fd_ < 0) return false;

    // Set non-blocking for timeout connection
    int flags = fcntl(fd_, F_GETFL, 0);
    fcntl(fd_, F_SETFL, flags | O_NONBLOCK);

    int rc = ::connect(fd_, reinterpret_cast<struct sockaddr*>(&addr), addr_len);
    if (rc < 0 && errno != EINPROGRESS) {
        close();
        return false;
    }

    if (rc != 0) {
        struct pollfd pfd{};
        pfd.fd = fd_;
        pfd.events = POLLOUT;
        int ret = poll(&pfd, 1, timeout_ms);
        if (ret <= 0) {
            close();
            return false;
        }

        int err = 0;
        socklen_t err_len = sizeof(err);
        if (getsockopt(fd_, SOL_SOCKET, SO_ERROR, &err, &err_len) < 0 || err != 0) {
            close();
            return false;
        }
    }

    // Restore blocking
    fcntl(fd_, F_SETFL, flags);
    return true;
}

ssize_t TcpSocket::send(std::span<const uint8_t> data) {
    if (fd_ < 0) return -1;
    return ::send(fd_, data.data(), data.size(), MSG_NOSIGNAL);
}

ssize_t TcpSocket::recv(std::span<uint8_t> buffer, int timeout_ms) {
    if (fd_ < 0) return -1;

    if (timeout_ms >= 0) {
        struct pollfd pfd{};
        pfd.fd = fd_;
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, timeout_ms);
        if (ret <= 0) return ret;
    }

    return ::recv(fd_, buffer.data(), buffer.size(), 0);
}

// -----------------------------------------------------------------
// TcpListener
// -----------------------------------------------------------------

TcpListener::TcpListener() = default;

TcpListener::~TcpListener() {
    close();
}

TcpListener::TcpListener(TcpListener&& other) noexcept
    : fd_(other.fd_), family_(other.family_) {
    other.fd_ = -1;
}

TcpListener& TcpListener::operator=(TcpListener&& other) noexcept {
    if (this != &other) {
        close();
        fd_ = other.fd_;
        family_ = other.family_;
        other.fd_ = -1;
    }
    return *this;
}

void TcpListener::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

bool TcpListener::listen(std::string_view host, uint16_t port, int backlog) {
    close();

    struct sockaddr_storage addr{};
    socklen_t addr_len = 0;
    family_ = resolve_and_setup(host, port, SOCK_STREAM, addr, addr_len);
    if (family_ < 0) return false;

    fd_ = ::socket(family_, SOCK_STREAM, 0);
    if (fd_ < 0) return false;

    int opt = 1;
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (::bind(fd_, reinterpret_cast<struct sockaddr*>(&addr), addr_len) < 0) {
        close();
        return false;
    }

    if (::listen(fd_, backlog) < 0) {
        close();
        return false;
    }

    return true;
}

bool TcpListener::accept(TcpSocket& client_socket, std::string& client_host, uint16_t& client_port, int timeout_ms) {
    if (fd_ < 0) return false;

    if (timeout_ms >= 0) {
        struct pollfd pfd{};
        pfd.fd = fd_;
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, timeout_ms);
        if (ret <= 0) return false;
    }

    struct sockaddr_storage client_addr{};
    socklen_t addr_len = sizeof(client_addr);
    int client_fd = ::accept(fd_, reinterpret_cast<struct sockaddr*>(&client_addr), &addr_len);
    if (client_fd < 0) return false;

    format_address(client_addr, client_host, client_port);
    client_socket = TcpSocket(client_fd, family_);
    return true;
}

uint16_t TcpListener::local_port() const {
    if (fd_ < 0) return 0;
    struct sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
    if (getsockname(fd_, reinterpret_cast<struct sockaddr*>(&addr), &len) == 0) {
        if (addr.ss_family == AF_INET) {
            return ntohs(reinterpret_cast<struct sockaddr_in*>(&addr)->sin_port);
        } else if (addr.ss_family == AF_INET6) {
            return ntohs(reinterpret_cast<struct sockaddr_in6*>(&addr)->sin6_port);
        }
    }
    return 0;
}

} // namespace gpp::ip
