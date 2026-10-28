#pragma once
#include <cstdint>
#include <span>
#include <vector>

namespace gpp::lte_nas {

enum class ProtocolDiscriminator : uint8_t {
    ESM = 0x02,
    EMM = 0x07,
};

enum class SecurityHeaderType : uint8_t {
    PlainNas                            = 0x00,
    IntegrityProtected                  = 0x01,
    IntegrityProtectedCiphered          = 0x02,
    IntegrityProtectedNewSecCtx         = 0x03,
    IntegrityProtectedCipheredNewSecCtx = 0x04,
};

enum class EmmMessageType : uint8_t {
    AttachRequest          = 0x41,
    AttachAccept           = 0x42,
    AttachComplete         = 0x43,
    AttachReject           = 0x44,
    AuthenticationRequest  = 0x52,
    AuthenticationResponse = 0x53,
    SecurityModeCommand    = 0x5D,
    SecurityModeComplete   = 0x5E,
};

enum class EsmMessageType : uint8_t {
    PdnConnectivityRequest                 = 0xD0,
    ActivateDefaultEpsBearerContextRequest = 0xC1,
    ActivateDefaultEpsBearerContextAccept  = 0xC2,
};

// NAS Header for EMM (TS 24.301 §9.8)
struct NasHeader {
    SecurityHeaderType    security_header_type{SecurityHeaderType::PlainNas};
    ProtocolDiscriminator protocol_discriminator{ProtocolDiscriminator::EMM};
    uint8_t               message_type{0};

    std::vector<uint8_t> encode() const;
    static NasHeader decode(std::span<const uint8_t> data, size_t& offset);
};

// ESM Header (TS 24.301 §9.9)
struct EsmHeader {
    uint8_t               eps_bearer_id{0};
    ProtocolDiscriminator protocol_discriminator{ProtocolDiscriminator::ESM};
    uint8_t               procedure_transaction_id{0};
    uint8_t               message_type{0};

    std::vector<uint8_t> encode() const;
    static EsmHeader decode(std::span<const uint8_t> data, size_t& offset);
};

} // namespace gpp::lte_nas
