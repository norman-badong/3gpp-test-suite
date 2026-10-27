#include "3gpp/sba/TlsSocket.hpp"
#include "3gpp/common/Logger.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <poll.h>
#include <cstring>

namespace gpp::sba {

int TlsContext::alpn_select_callback(SSL*,
                                     const unsigned char** out,
                                     unsigned char* outlen,
                                     const unsigned char* in,
                                     unsigned int inlen,
                                     void* arg) {
    auto* self = static_cast<TlsContext*>(arg);
    if (!self || self->wire_alpn_.empty()) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    // SSL_select_next_proto compares server wire_alpn vs client offered protocols
    int ret = SSL_select_next_proto(
        const_cast<unsigned char**>(out),
        outlen,
        self->wire_alpn_.data(),
        static_cast<unsigned int>(self->wire_alpn_.size()),
        in,
        inlen);

    if (ret == OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_NOACK;
}

TlsContext::TlsContext(Role role) : role_(role) {
    const SSL_METHOD* method = (role == Role::CLIENT) ? TLS_client_method() : TLS_server_method();
    ctx_ = SSL_CTX_new(method);
    if (!ctx_) {
        GPP_LOG_ERROR("TLS_CTX", "Failed to create SSL_CTX");
        return;
    }

    // 3GPP TS 33.501 recommends TLS 1.3 for 5G SBA interfaces
    SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION);

    if (role == Role::CLIENT) {
        // In local test suite, allow self-signed test certificates
        SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
    }
}

TlsContext::~TlsContext() {
    if (ctx_) {
        SSL_CTX_free(ctx_);
        ctx_ = nullptr;
    }
}

TlsContext::TlsContext(TlsContext&& other) noexcept
    : role_(other.role_), ctx_(other.ctx_), wire_alpn_(std::move(other.wire_alpn_)) {
    other.ctx_ = nullptr;
}

TlsContext& TlsContext::operator=(TlsContext&& other) noexcept {
    if (this != &other) {
        if (ctx_) SSL_CTX_free(ctx_);
        role_ = other.role_;
        ctx_ = other.ctx_;
        wire_alpn_ = std::move(other.wire_alpn_);
        other.ctx_ = nullptr;
    }
    return *this;
}

bool TlsContext::set_alpn_protocols(const std::vector<std::string>& protocols) {
    if (!ctx_) return false;

    // Convert to wire format: length-prefixed strings, e.g. [2, 'h', '2']
    wire_alpn_.clear();
    for (const auto& proto : protocols) {
        if (proto.empty() || proto.size() > 255) return false;
        wire_alpn_.push_back(static_cast<uint8_t>(proto.size()));
        wire_alpn_.insert(wire_alpn_.end(), proto.begin(), proto.end());
    }

    if (role_ == Role::CLIENT) {
        // Client advertises ALPN
        if (SSL_CTX_set_alpn_protos(ctx_, wire_alpn_.data(), static_cast<unsigned int>(wire_alpn_.size())) != 0) {
            GPP_LOG_ERROR("TLS_CTX", "Failed to set client ALPN protocols");
            return false;
        }
    } else {
        // Server selects from offered ALPN
        SSL_CTX_set_alpn_select_cb(ctx_, alpn_select_callback, this);
    }
    return true;
}

bool TlsContext::generate_self_signed_cert(std::string_view common_name) {
    if (!ctx_) return false;

    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!pctx) return false;

    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    EVP_PKEY_CTX_free(pctx);

    X509* x509 = X509_new();
    if (!x509) {
        EVP_PKEY_free(pkey);
        return false;
    }

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // 1 year validity

    X509_set_pubkey(x509, pkey);

    X509_NAME* name = X509_get_subject_name(x509);
    std::string cn(common_name);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (const unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (const unsigned char*)"3GPP Test Suite", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)cn.c_str(), -1, -1, 0);
    X509_set_issuer_name(x509, name);

    if (X509_sign(x509, pkey, EVP_sha256()) <= 0) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return false;
    }

    SSL_CTX_use_certificate(ctx_, x509);
    SSL_CTX_use_PrivateKey(ctx_, pkey);

    X509_free(x509);
    EVP_PKEY_free(pkey);
    return true;
}

// -------------------------------------------------------------
// TlsSocket
// -------------------------------------------------------------

TlsSocket::TlsSocket(TlsContext& context) : context_(&context) {
    if (context.native_handle()) {
        ssl_ = SSL_new(context.native_handle());
    }
}

TlsSocket::~TlsSocket() {
    close();
}

TlsSocket::TlsSocket(TlsSocket&& other) noexcept
    : context_(other.context_),
      ssl_(other.ssl_),
      tcp_socket_(std::move(other.tcp_socket_)) {
    other.ssl_ = nullptr;
    other.context_ = nullptr;
}

TlsSocket& TlsSocket::operator=(TlsSocket&& other) noexcept {
    if (this != &other) {
        close();
        context_ = other.context_;
        ssl_ = other.ssl_;
        tcp_socket_ = std::move(other.tcp_socket_);
        other.ssl_ = nullptr;
        other.context_ = nullptr;
    }
    return *this;
}

void TlsSocket::close() {
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    tcp_socket_.close();
}

bool TlsSocket::is_valid() const {
    return ssl_ != nullptr && tcp_socket_.is_valid();
}

bool TlsSocket::connect(std::string_view host, uint16_t port, int timeout_ms) {
    if (!ssl_ || !context_) return false;

    if (!tcp_socket_.connect(host, port, timeout_ms)) {
        return false;
    }

    if (SSL_set_fd(ssl_, tcp_socket_.fd()) != 1) {
        return false;
    }

    // SNI (Server Name Indication)
    std::string h(host);
    SSL_set_tlsext_host_name(ssl_, h.c_str());

    if (SSL_connect(ssl_) <= 0) {
        close();
        return false;
    }
    return true;
}

bool TlsSocket::accept(ip::TcpSocket&& raw_tcp_socket) {
    if (!ssl_ || !context_) return false;

    tcp_socket_ = std::move(raw_tcp_socket);
    if (!tcp_socket_.is_valid()) return false;

    if (SSL_set_fd(ssl_, tcp_socket_.fd()) != 1) {
        return false;
    }

    if (SSL_accept(ssl_) <= 0) {
        close();
        return false;
    }
    return true;
}

ssize_t TlsSocket::send(std::span<const uint8_t> data) {
    if (!ssl_) return -1;
    int ret = SSL_write(ssl_, data.data(), static_cast<int>(data.size()));
    return ret > 0 ? ret : -1;
}

ssize_t TlsSocket::recv(std::span<uint8_t> buffer, int timeout_ms) {
    if (!ssl_) return -1;

    // Check if OpenSSL has unread buffered data first
    if (SSL_pending(ssl_) == 0 && timeout_ms >= 0) {
        struct pollfd pfd{};
        pfd.fd = tcp_socket_.fd();
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, timeout_ms);
        if (ret <= 0) return ret;
    }

    int ret = SSL_read(ssl_, buffer.data(), static_cast<int>(buffer.size()));
    return ret > 0 ? ret : -1;
}

std::string TlsSocket::negotiated_alpn() const {
    if (!ssl_) return "";
    const unsigned char* alpn = nullptr;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(ssl_, &alpn, &alpn_len);
    if (alpn && alpn_len > 0) {
        return std::string(reinterpret_cast<const char*>(alpn), alpn_len);
    }
    return "";
}

std::string TlsSocket::tls_version() const {
    if (!ssl_) return "";
    const char* v = SSL_get_version(ssl_);
    return v ? std::string(v) : "";
}

} // namespace gpp::sba
