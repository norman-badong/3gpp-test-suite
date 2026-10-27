#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <cstdint>

namespace gpp::sdp {

enum class MediaDirection {
    SENDRECV,
    SENDONLY,
    RECVONLY,
    INACTIVE
};

std::string_view to_string(MediaDirection dir);
MediaDirection media_direction_from_string(std::string_view str);

struct ConnectionInfo {
    std::string net_type{"IN"};
    std::string addr_type{"IP4"};
    std::string address{"127.0.0.1"};

    [[nodiscard]] std::string to_string() const;
    static ConnectionInfo parse(std::string_view line);
};

struct OriginInfo {
    std::string username{"-"};
    uint64_t session_id{100000};
    uint64_t session_version{1};
    std::string net_type{"IN"};
    std::string addr_type{"IP4"};
    std::string unicast_address{"127.0.0.1"};

    [[nodiscard]] std::string to_string() const;
    static OriginInfo parse(std::string_view line);
};

struct RtpMap {
    uint8_t payload_type{0};
    std::string encoding_name; // e.g. "AMR-WB", "AMR", "EVS", "telephone-event"
    uint32_t clock_rate{8000};
    uint32_t channels{1};

    [[nodiscard]] std::string to_string() const;
    static RtpMap parse(std::string_view line);
};

struct Fmtp {
    uint8_t payload_type{0};
    std::string parameters; // e.g. "octet-align=1; mode-change-capability=2"

    [[nodiscard]] std::string to_string() const;
    static Fmtp parse(std::string_view line);
};

struct MediaDescription {
    std::string media_type{"audio"};
    uint16_t port{0};
    std::string protocol{"RTP/AVP"};
    std::vector<uint8_t> payload_types;

    std::optional<ConnectionInfo> connection;
    std::vector<RtpMap> rtp_maps;
    std::vector<Fmtp> fmtps;
    MediaDirection direction{MediaDirection::SENDRECV};
    uint32_t ptime{0};    // Packet time in ms (e.g. 20)
    uint32_t maxptime{0}; // Max packet time in ms (e.g. 240)
    std::vector<std::pair<std::string, std::string>> custom_attributes;

    [[nodiscard]] const RtpMap* find_rtpmap(uint8_t pt) const;
    [[nodiscard]] const Fmtp* find_fmtp(uint8_t pt) const;
    [[nodiscard]] std::string serialize() const;
};

class SessionDescription {
public:
    int version{0}; // RFC 4566 v=0
    OriginInfo origin;
    std::string session_name{"3GPP IMS VoLTE/VoNR Call"};
    std::optional<ConnectionInfo> connection;
    uint64_t start_time{0};
    uint64_t stop_time{0};
    std::vector<MediaDescription> media;

    // Serialize to standard RFC 4566 SDP text (with \r\n endings)
    [[nodiscard]] std::string serialize() const;

    // Parse from RFC 4566 SDP text
    static SessionDescription parse(std::string_view sdp_text);

    // Helpers to quickly construct common 3GPP VoLTE / VoNR audio offers
    static SessionDescription make_volte_amrwb_offer(
        std::string_view ip_address,
        uint16_t rtp_port,
        bool is_ipv6 = false);

    static SessionDescription make_vonr_evs_offer(
        std::string_view ip_address,
        uint16_t rtp_port,
        bool is_ipv6 = false);
};

} // namespace gpp::sdp
