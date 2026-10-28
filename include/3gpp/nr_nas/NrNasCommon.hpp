#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace gpp::nr_nas {

enum class ExtendedProtocolDiscriminator : uint8_t {
    GSM = 0x2E, // 5GS Session Management
    GMM = 0x7E, // 5GS Mobility Management
};

enum class SecurityHeaderType : uint8_t {
    PlainNas                            = 0x00,
    IntegrityProtected                  = 0x01,
    IntegrityProtectedCiphered          = 0x02,
    IntegrityProtectedNewSecCtx         = 0x03,
    IntegrityProtectedCipheredNewSecCtx = 0x04,
};

enum class GmmMessageType : uint8_t {
    RegistrationRequest                 = 0x41,
    RegistrationAccept                  = 0x42,
    RegistrationComplete                = 0x43,
    RegistrationReject                  = 0x44,
    DeregistrationRequestUeOriginating  = 0x47,
    DeregistrationAcceptUeOriginating   = 0x48,
    AuthenticationRequest               = 0x56,
    AuthenticationResponse              = 0x57,
    SecurityModeCommand                 = 0x5D,
    SecurityModeComplete                = 0x5E,
};

enum class GsmMessageType : uint8_t {
    PduSessionEstablishmentRequest = 0xC1,
    PduSessionEstablishmentAccept  = 0xC2,
    PduSessionEstablishmentReject  = 0xC3,
    PduSessionReleaseRequest       = 0xD1,
    PduSessionReleaseAccept        = 0xD2,
};

// Plain 5GMM NAS Header (TS 24.501 §9.1.1) — 3 octets
struct NrNasHeader {
    ExtendedProtocolDiscriminator epd{ExtendedProtocolDiscriminator::GMM};
    SecurityHeaderType            security_header_type{SecurityHeaderType::PlainNas};
    uint8_t                       message_type{0};

    [[nodiscard]] std::vector<uint8_t> encode() const;
    static NrNasHeader decode(std::span<const uint8_t> data, size_t& offset);
};

// 5GSM Header (TS 24.501 §9.1.2) — 4 octets
struct NrGsmHeader {
    ExtendedProtocolDiscriminator epd{ExtendedProtocolDiscriminator::GSM};
    uint8_t                       pdu_session_id{1};
    uint8_t                       procedure_transaction_id{1};
    uint8_t                       message_type{0};

    [[nodiscard]] std::vector<uint8_t> encode() const;
    static NrGsmHeader decode(std::span<const uint8_t> data, size_t& offset);
};

} // namespace gpp::nr_nas
