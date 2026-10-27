#pragma once

#include <string>
#include <string_view>
#include <span>
#include <memory>
#include <vector>
#include <cstdint>
#include "3gpp/ip/Socket.hpp"

// Forward declaration of OpenSSL types to avoid polluting headers
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

namespace gpp::sba {

class TlsContext {
public:
    enum class Role {
        CLIENT,
        SERVER
    };

    explicit TlsContext(Role role);
    ~TlsContext();

    TlsContext(const TlsContext&) = delete;
    TlsContext& operator=(const TlsContext&) = delete;

    TlsContext(TlsContext&& other) noexcept;
    TlsContext& operator=(TlsContext&& other) noexcept;

    // Configure ALPN (Application-Layer Protocol Negotiation, e.g. "h2")
    bool set_alpn_protocols(const std::vector<std::string>& protocols);

    // Generate in-memory self-signed X.509 certificate and private key (useful for server test mode)
    bool generate_self_signed_cert(std::string_view common_name = "5gc-sba.3gpp.local");

    [[nodiscard]] SSL_CTX* native_handle() const { return ctx_; }
    [[nodiscard]] Role role() const { return role_; }

private:
    Role role_;
    SSL_CTX* ctx_{nullptr};
    std::vector<uint8_t> wire_alpn_; // Wire format for ALPN (length-prefixed strings)

    static int alpn_select_callback(SSL* ssl,
                                    const unsigned char** out,
                                    unsigned char* outlen,
                                    const unsigned char* in,
                                    unsigned int inlen,
                                    void* arg);
};

class TlsSocket {
public:
    explicit TlsSocket(TlsContext& context);
    ~TlsSocket();

    TlsSocket(const TlsSocket&) = delete;
    TlsSocket& operator=(const TlsSocket&) = delete;

    TlsSocket(TlsSocket&& other) noexcept;
    TlsSocket& operator=(TlsSocket&& other) noexcept;

    // Client: Connect to host:port and perform TLS 1.3 handshake with ALPN negotiation
    bool connect(std::string_view host, uint16_t port, int timeout_ms = 5000);

    // Server: Accept incoming client socket and perform TLS 1.3 handshake
    bool accept(ip::TcpSocket&& raw_tcp_socket);

    // Send encrypted data
    ssize_t send(std::span<const uint8_t> data);

    // Receive decrypted data
    ssize_t recv(std::span<uint8_t> buffer, int timeout_ms = -1);

    // Returns negotiated ALPN string (e.g. "h2")
    [[nodiscard]] std::string negotiated_alpn() const;

    // Returns TLS version in use (e.g. "TLSv1.3")
    [[nodiscard]] std::string tls_version() const;

    void close();
    [[nodiscard]] bool is_valid() const;

private:
    TlsContext* context_{nullptr};
    SSL* ssl_{nullptr};
    ip::TcpSocket tcp_socket_;
};

} // namespace gpp::sba
