#include "3gpp/diameter/DiameterFactory.hpp"

namespace gpp {
namespace diameter {

DiameterMessage DiameterFactory::create_cer(
    const std::string& origin_host,
    const std::string& origin_realm,
    const ip::Ipv4Address& host_ip,
    uint32_t vendor_id,
    const std::string& product_name,
    const std::vector<uint32_t>& auth_app_ids,
    uint32_t hop_id,
    uint32_t e2e_id
) {
    DiameterMessage cer(CMD_FLAG_REQUEST, CMD_CAPABILITIES_EXCHANGE, APP_DIAMETER_COMMON, hop_id, e2e_id);

    cer.add_avp(DiameterAvp::create_string(AVP_ORIGIN_HOST, origin_host));
    cer.add_avp(DiameterAvp::create_string(AVP_ORIGIN_REALM, origin_realm));
    cer.add_avp(DiameterAvp::create_ipv4_address(AVP_HOST_IP_ADDRESS, host_ip));
    cer.add_avp(DiameterAvp::create_unsigned32(AVP_VENDOR_ID, vendor_id));
    cer.add_avp(DiameterAvp::create_string(AVP_PRODUCT_NAME, product_name));
    cer.add_avp(DiameterAvp::create_unsigned32(AVP_SUPPORTED_VENDOR_ID, VENDOR_3GPP));

    for (uint32_t app_id : auth_app_ids) {
        cer.add_avp(DiameterAvp::create_unsigned32(AVP_AUTH_APPLICATION_ID, app_id));
    }

    return cer;
}

DiameterMessage DiameterFactory::create_cea(
    const DiameterMessage& cer,
    uint32_t result_code,
    const std::string& origin_host,
    const std::string& origin_realm,
    const ip::Ipv4Address& host_ip,
    uint32_t vendor_id,
    const std::string& product_name,
    const std::vector<uint32_t>& auth_app_ids
) {
    DiameterMessage cea(0, CMD_CAPABILITIES_EXCHANGE, APP_DIAMETER_COMMON,
                        cer.hop_by_hop_id, cer.end_to_end_id);

    cea.add_avp(DiameterAvp::create_unsigned32(AVP_RESULT_CODE, result_code));
    cea.add_avp(DiameterAvp::create_string(AVP_ORIGIN_HOST, origin_host));
    cea.add_avp(DiameterAvp::create_string(AVP_ORIGIN_REALM, origin_realm));
    cea.add_avp(DiameterAvp::create_ipv4_address(AVP_HOST_IP_ADDRESS, host_ip));
    cea.add_avp(DiameterAvp::create_unsigned32(AVP_VENDOR_ID, vendor_id));
    cea.add_avp(DiameterAvp::create_string(AVP_PRODUCT_NAME, product_name));
    cea.add_avp(DiameterAvp::create_unsigned32(AVP_SUPPORTED_VENDOR_ID, VENDOR_3GPP));

    for (uint32_t app_id : auth_app_ids) {
        cea.add_avp(DiameterAvp::create_unsigned32(AVP_AUTH_APPLICATION_ID, app_id));
    }

    return cea;
}

DiameterMessage DiameterFactory::create_dwr(
    const std::string& origin_host,
    const std::string& origin_realm,
    uint32_t hop_id,
    uint32_t e2e_id
) {
    DiameterMessage dwr(CMD_FLAG_REQUEST, CMD_DEVICE_WATCHDOG, APP_DIAMETER_COMMON, hop_id, e2e_id);
    dwr.add_avp(DiameterAvp::create_string(AVP_ORIGIN_HOST, origin_host));
    dwr.add_avp(DiameterAvp::create_string(AVP_ORIGIN_REALM, origin_realm));
    return dwr;
}

DiameterMessage DiameterFactory::create_dwa(
    const DiameterMessage& dwr,
    uint32_t result_code,
    const std::string& origin_host,
    const std::string& origin_realm
) {
    DiameterMessage dwa(0, CMD_DEVICE_WATCHDOG, APP_DIAMETER_COMMON,
                        dwr.hop_by_hop_id, dwr.end_to_end_id);
    dwa.add_avp(DiameterAvp::create_unsigned32(AVP_RESULT_CODE, result_code));
    dwa.add_avp(DiameterAvp::create_string(AVP_ORIGIN_HOST, origin_host));
    dwa.add_avp(DiameterAvp::create_string(AVP_ORIGIN_REALM, origin_realm));
    return dwa;
}

DiameterMessage DiameterFactory::create_s6a_air(
    const std::string& session_id,
    const std::string& origin_host,
    const std::string& origin_realm,
    const std::string& destination_realm,
    const std::string& user_name_imsi,
    const std::vector<uint8_t>& visited_plmn_id,
    uint32_t num_requested_vectors,
    uint32_t hop_id,
    uint32_t e2e_id
) {
    DiameterMessage air(CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE,
                        CMD_AUTHENTICATION_INFO, APP_3GPP_S6A, hop_id, e2e_id);

    air.add_avp(DiameterAvp::create_string(AVP_SESSION_ID, session_id));
    air.add_avp(DiameterAvp::create_unsigned32(AVP_AUTH_SESSION_STATE, 1)); // NO_STATE_MAINTAINED
    air.add_avp(DiameterAvp::create_string(AVP_ORIGIN_HOST, origin_host));
    air.add_avp(DiameterAvp::create_string(AVP_ORIGIN_REALM, origin_realm));
    air.add_avp(DiameterAvp::create_string(AVP_DESTINATION_REALM, destination_realm));
    air.add_avp(DiameterAvp::create_string(AVP_USER_NAME, user_name_imsi));

    // Visited-PLMN-Id (TS 29.272 AVP 1400, Vendor 10415)
    air.add_avp(DiameterAvp::create_octet_string(AVP_VISITED_PLMN_ID, visited_plmn_id, true, VENDOR_3GPP));

    // Requested-EUTRAN-Authentication-Info (TS 29.272 AVP 1401, Vendor 10415)
    std::vector<DiameterAvp> req_vector_sub_avps;
    req_vector_sub_avps.push_back(DiameterAvp::create_unsigned32(
        AVP_NUMBER_OF_REQ_VECTORS, num_requested_vectors, true, VENDOR_3GPP));
    req_vector_sub_avps.push_back(DiameterAvp::create_unsigned32(
        AVP_IMMEDIATE_RESPONSE_PREF, 0, false, VENDOR_3GPP));

    air.add_avp(DiameterAvp::create_grouped(AVP_REQ_EUTRAN_AUTH_INFO, req_vector_sub_avps, true, VENDOR_3GPP));

    return air;
}

DiameterMessage DiameterFactory::create_s6a_aia(
    const DiameterMessage& air,
    uint32_t result_code,
    const std::string& origin_host,
    const std::string& origin_realm,
    const std::vector<EutranVector>& vectors
) {
    DiameterMessage aia(CMD_FLAG_PROXIABLE, CMD_AUTHENTICATION_INFO, APP_3GPP_S6A,
                        air.hop_by_hop_id, air.end_to_end_id);

    const auto* session_id_avp = air.find_avp(AVP_SESSION_ID);
    if (session_id_avp) {
        aia.add_avp(*session_id_avp);
    }

    aia.add_avp(DiameterAvp::create_unsigned32(AVP_AUTH_SESSION_STATE, 1));
    aia.add_avp(DiameterAvp::create_unsigned32(AVP_RESULT_CODE, result_code));
    aia.add_avp(DiameterAvp::create_string(AVP_ORIGIN_HOST, origin_host));
    aia.add_avp(DiameterAvp::create_string(AVP_ORIGIN_REALM, origin_realm));

    if (result_code == DIAMETER_SUCCESS && !vectors.empty()) {
        std::vector<DiameterAvp> vector_avps;
        uint32_t item_num = 0;
        for (const auto& vec : vectors) {
            std::vector<DiameterAvp> vec_sub_avps;
            vec_sub_avps.push_back(DiameterAvp::create_unsigned32(
                AVP_ITEM_NUMBER, item_num++, true, VENDOR_3GPP));
            vec_sub_avps.push_back(DiameterAvp::create_octet_string(
                AVP_RAND, vec.rand, true, VENDOR_3GPP));
            vec_sub_avps.push_back(DiameterAvp::create_octet_string(
                AVP_XRES, vec.xres, true, VENDOR_3GPP));
            vec_sub_avps.push_back(DiameterAvp::create_octet_string(
                AVP_AUTN, vec.autn, true, VENDOR_3GPP));
            vec_sub_avps.push_back(DiameterAvp::create_octet_string(
                AVP_KASME, vec.kasme, true, VENDOR_3GPP));

            vector_avps.push_back(DiameterAvp::create_grouped(
                AVP_E_UTRAN_VECTOR, vec_sub_avps, true, VENDOR_3GPP));
        }

        aia.add_avp(DiameterAvp::create_grouped(
            AVP_AUTHENTICATION_INFO, vector_avps, true, VENDOR_3GPP));
    }

    return aia;
}

} // namespace diameter
} // namespace gpp
