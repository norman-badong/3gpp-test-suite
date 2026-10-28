#pragma once

#include "RrcTypes.hpp"
#include "Asn1Aper.hpp"
#include <cstdint>
#include <vector>
#include <span>

namespace gpp::rrc {

// ─── RRC Setup Request (UL-CCCH) ────────────────────────────────────────────
// TS 38.331 §6.2.2 / TS 36.331 §6.2.2
struct RrcSetupRequest {
    InitialUeIdentityType ue_identity_type{InitialUeIdentityType::Ng5g_S_TMSI_Part1};
    uint64_t              ue_identity_val{0x456789ABCDULL}; // 39 bits
    EstablishmentCause    establishment_cause{EstablishmentCause::MoSignalling};
    bool                  spare{false};

    [[nodiscard]] std::vector<uint8_t> encode() const;
    static RrcSetupRequest decode(std::span<const uint8_t> data);
};

// ─── RRC Setup (DL-CCCH) ────────────────────────────────────────────────────
// TS 38.331 §6.2.2
struct RrcSetup {
    uint8_t              rrc_transaction_id{0}; // 0..3
    uint8_t              srb_identity{1};       // 1 = SRB1
    RlcMode              rlc_mode{RlcMode::AM};
    std::vector<uint8_t> master_cell_group;     // Cell group config bytes

    [[nodiscard]] std::vector<uint8_t> encode() const;
    static RrcSetup decode(std::span<const uint8_t> data);
};

// ─── RRC Setup Complete (UL-DCCH) ───────────────────────────────────────────
// TS 38.331 §6.2.2
struct RrcSetupComplete {
    uint8_t              rrc_transaction_id{0};   // 0..3
    uint8_t              selected_plmn_identity{1}; // 1..6
    std::vector<uint8_t> dedicated_nas_message;    // Embedded NAS PDU

    [[nodiscard]] std::vector<uint8_t> encode() const;
    static RrcSetupComplete decode(std::span<const uint8_t> data);
};

// ─── RRC Reconfiguration (DL-DCCH) ──────────────────────────────────────────
// TS 38.331 §6.2.2
struct RrcReconfiguration {
    uint8_t              rrc_transaction_id{0};
    uint8_t              drb_identity{1}; // 1 = DRB1
    uint8_t              qfi{1};          // QoS Flow ID
    std::vector<uint8_t> secondary_cell_group;

    [[nodiscard]] std::vector<uint8_t> encode() const;
    static RrcReconfiguration decode(std::span<const uint8_t> data);
};

// ─── RRC Reconfiguration Complete (UL-DCCH) ─────────────────────────────────
// TS 38.331 §6.2.2
struct RrcReconfigurationComplete {
    uint8_t rrc_transaction_id{0};

    [[nodiscard]] std::vector<uint8_t> encode() const;
    static RrcReconfigurationComplete decode(std::span<const uint8_t> data);
};

} // namespace gpp::rrc
