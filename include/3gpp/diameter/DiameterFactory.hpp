#pragma once

#include "3gpp/diameter/DiameterMessage.hpp"

namespace gpp {
namespace diameter {

/**
 * EPS Authentication Vector for LTE E-UTRAN (TS 29.272 / TS 33.401).
 * Comprises RAND, XRES, AUTN, and KASME.
 */
struct EutranVector {
    std::vector<uint8_t> rand;   // 16 octets
    std::vector<uint8_t> xres;   // 8 octets
    std::vector<uint8_t> autn;   // 16 octets
    std::vector<uint8_t> kasme;  // 32 octets
};

/**
 * High-level Factory for constructing standard Diameter messages
 */
class DiameterFactory {
public:
    // --- Base Capabilities-Exchange (RFC 6733) ---
    static DiameterMessage create_cer(
        const std::string& origin_host,
        const std::string& origin_realm,
        const ip::Ipv4Address& host_ip,
        uint32_t vendor_id,
        const std::string& product_name,
        const std::vector<uint32_t>& auth_app_ids,
        uint32_t hop_id = 1001,
        uint32_t e2e_id = 2001
    );

    static DiameterMessage create_cea(
        const DiameterMessage& cer,
        uint32_t result_code,
        const std::string& origin_host,
        const std::string& origin_realm,
        const ip::Ipv4Address& host_ip,
        uint32_t vendor_id,
        const std::string& product_name,
        const std::vector<uint32_t>& auth_app_ids
    );

    // --- Base Device-Watchdog (RFC 6733) ---
    static DiameterMessage create_dwr(
        const std::string& origin_host,
        const std::string& origin_realm,
        uint32_t hop_id = 1002,
        uint32_t e2e_id = 2002
    );

    static DiameterMessage create_dwa(
        const DiameterMessage& dwr,
        uint32_t result_code,
        const std::string& origin_host,
        const std::string& origin_realm
    );

    // --- 3GPP S6a Authentication-Information (TS 29.272) ---
    static DiameterMessage create_s6a_air(
        const std::string& session_id,
        const std::string& origin_host,
        const std::string& origin_realm,
        const std::string& destination_realm,
        const std::string& user_name_imsi,
        const std::vector<uint8_t>& visited_plmn_id,
        uint32_t num_requested_vectors = 1,
        uint32_t hop_id = 1003,
        uint32_t e2e_id = 2003
    );

    static DiameterMessage create_s6a_aia(
        const DiameterMessage& air,
        uint32_t result_code,
        const std::string& origin_host,
        const std::string& origin_realm,
        const std::vector<EutranVector>& vectors
    );
};

} // namespace diameter
} // namespace gpp
