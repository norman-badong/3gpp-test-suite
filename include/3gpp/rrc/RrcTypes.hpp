#pragma once

#include <cstdint>
#include <string>

namespace gpp::rrc {

enum class EstablishmentCause : uint8_t {
    Emergency          = 0,
    HighPriorityAccess = 1,
    MtAccess           = 2,
    MoSignalling       = 3,
    MoData             = 4,
    MoVoiceCall        = 5,
    MoVideoCall        = 6,
    MoSMS              = 7,
};

enum class InitialUeIdentityType : uint8_t {
    Ng5g_S_TMSI_Part1 = 0, // 39-bit 5G-S-TMSI
    RandomValue       = 1, // 39-bit random value
};

enum class RlcMode : uint8_t {
    AM                   = 0, // Acknowledged Mode
    UM_BiDirectional     = 1, // Unacknowledged Mode Bi-directional
    UM_UniDirectional_UL = 2,
    UM_UniDirectional_DL = 3,
};

enum class PduChannelType : uint8_t {
    UL_CCCH = 0, // Uplink Common Control Channel
    DL_CCCH = 1, // Downlink Common Control Channel
    UL_DCCH = 2, // Uplink Dedicated Control Channel
    DL_DCCH = 3, // Downlink Dedicated Control Channel
};

} // namespace gpp::rrc
