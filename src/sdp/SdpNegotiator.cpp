#include "3gpp/sdp/SdpNegotiator.hpp"

namespace gpp::sdp {

namespace {

MediaDirection negotiate_direction(MediaDirection offer_dir, MediaDirection local_pref) {
    if (offer_dir == MediaDirection::INACTIVE || local_pref == MediaDirection::INACTIVE) {
        return MediaDirection::INACTIVE;
    }
    if (offer_dir == MediaDirection::SENDONLY) {
        // Remote only sends -> Local can only receive
        return MediaDirection::RECVONLY;
    }
    if (offer_dir == MediaDirection::RECVONLY) {
        // Remote only receives -> Local can only send
        return MediaDirection::SENDONLY;
    }
    // Remote is sendrecv
    return local_pref;
}

} // namespace

SessionDescription SdpNegotiator::create_answer(
    const SessionDescription& offer,
    const NegotiatorConfig& config) {

    SessionDescription answer;
    answer.version = 0;
    answer.origin = OriginInfo{
        .username = "-",
        .session_id = offer.origin.session_id + 1,
        .session_version = offer.origin.session_version,
        .net_type = "IN",
        .addr_type = config.is_ipv6 ? "IP6" : "IP4",
        .unicast_address = config.local_address
    };
    answer.session_name = "3GPP VoLTE/VoNR Call Answer";
    answer.connection = ConnectionInfo{
        .net_type = "IN",
        .addr_type = config.is_ipv6 ? "IP6" : "IP4",
        .address = config.local_address
    };
    answer.start_time = 0;
    answer.stop_time = 0;

    for (const auto& offer_media : offer.media) {
        MediaDescription ans_media;
        ans_media.media_type = offer_media.media_type;
        ans_media.protocol = offer_media.protocol;
        ans_media.direction = negotiate_direction(offer_media.direction, config.local_direction);
        ans_media.ptime = offer_media.ptime;
        ans_media.maxptime = offer_media.maxptime;

        // Search for matching codecs in order of local preference
        std::vector<uint8_t> matched_pts;
        for (const auto& pref : config.preferred_codecs) {
            for (auto pt : offer_media.payload_types) {
                const auto* rtp = offer_media.find_rtpmap(pt);
                if (rtp) {
                    bool name_match = (rtp->encoding_name == pref.encoding_name);
                    bool rate_match = (pref.clock_rate == 0 || rtp->clock_rate == pref.clock_rate);
                    if (name_match && rate_match) {
                        matched_pts.push_back(pt);
                        ans_media.rtp_maps.push_back(*rtp);

                        const auto* fmtp = offer_media.find_fmtp(pt);
                        if (fmtp) {
                            ans_media.fmtps.push_back(*fmtp);
                        } else if (!pref.default_fmtp.empty()) {
                            ans_media.fmtps.push_back(Fmtp{pt, pref.default_fmtp});
                        }
                        break; // matched this preference
                    }
                }
            }
        }

        // Only add telephone-event (DTMF) if at least one primary audio codec matched
        if (!matched_pts.empty()) {
            for (auto pt : offer_media.payload_types) {
                const auto* rtp = offer_media.find_rtpmap(pt);
                if (rtp && rtp->encoding_name == "telephone-event") {
                    matched_pts.push_back(pt);
                    ans_media.rtp_maps.push_back(*rtp);
                    const auto* fmtp = offer_media.find_fmtp(pt);
                    if (fmtp) ans_media.fmtps.push_back(*fmtp);
                }
            }
        }

        if (matched_pts.empty()) {
            // Reject this media stream per RFC 3264 (no compatible codecs)
            ans_media.port = 0;
            ans_media.payload_types = offer_media.payload_types; // Echo offer payload types
        } else {
            ans_media.port = config.local_rtp_port;
            ans_media.payload_types = matched_pts;
        }

        answer.media.push_back(ans_media);
    }

    return answer;
}

} // namespace gpp::sdp
