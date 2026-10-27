#include "3gpp/sdp/Sdp.hpp"
#include <sstream>
#include <algorithm>
#include <stdexcept>

namespace gpp::sdp {

namespace {

std::vector<std::string_view> split_lines(std::string_view text) {
    std::vector<std::string_view> lines;
    size_t start = 0;
    while (start < text.size()) {
        size_t end = text.find_first_of("\r\n", start);
        if (end == std::string_view::npos) {
            lines.push_back(text.substr(start));
            break;
        }
        if (end > start) {
            lines.push_back(text.substr(start, end - start));
        }
        start = end + 1;
        if (start < text.size() && text[end] == '\r' && text[start] == '\n') {
            ++start;
        }
    }
    return lines;
}

std::vector<std::string_view> split_whitespace(std::string_view text) {
    std::vector<std::string_view> tokens;
    size_t start = 0;
    while (start < text.size()) {
        while (start < text.size() && (text[start] == ' ' || text[start] == '\t')) {
            ++start;
        }
        if (start >= text.size()) break;
        size_t end = start;
        while (end < text.size() && text[end] != ' ' && text[end] != '\t') {
            ++end;
        }
        tokens.push_back(text.substr(start, end - start));
        start = end;
    }
    return tokens;
}

} // namespace

std::string_view to_string(MediaDirection dir) {
    switch (dir) {
        case MediaDirection::SENDRECV: return "sendrecv";
        case MediaDirection::SENDONLY: return "sendonly";
        case MediaDirection::RECVONLY: return "recvonly";
        case MediaDirection::INACTIVE: return "inactive";
    }
    return "sendrecv";
}

MediaDirection media_direction_from_string(std::string_view str) {
    if (str == "sendonly") return MediaDirection::SENDONLY;
    if (str == "recvonly") return MediaDirection::RECVONLY;
    if (str == "inactive") return MediaDirection::INACTIVE;
    return MediaDirection::SENDRECV;
}

std::string ConnectionInfo::to_string() const {
    return "c=" + net_type + " " + addr_type + " " + address + "\r\n";
}

ConnectionInfo ConnectionInfo::parse(std::string_view line) {
    ConnectionInfo ci;
    auto tokens = split_whitespace(line);
    if (tokens.size() >= 3) {
        ci.net_type = std::string(tokens[0]);
        ci.addr_type = std::string(tokens[1]);
        ci.address = std::string(tokens[2]);
    }
    return ci;
}

std::string OriginInfo::to_string() const {
    return "o=" + username + " " + std::to_string(session_id) + " " +
           std::to_string(session_version) + " " + net_type + " " +
           addr_type + " " + unicast_address + "\r\n";
}

OriginInfo OriginInfo::parse(std::string_view line) {
    OriginInfo oi;
    auto tokens = split_whitespace(line);
    if (tokens.size() >= 6) {
        oi.username = std::string(tokens[0]);
        oi.session_id = std::stoull(std::string(tokens[1]));
        oi.session_version = std::stoull(std::string(tokens[2]));
        oi.net_type = std::string(tokens[3]);
        oi.addr_type = std::string(tokens[4]);
        oi.unicast_address = std::string(tokens[5]);
    }
    return oi;
}

std::string RtpMap::to_string() const {
    std::string s = "a=rtpmap:" + std::to_string(payload_type) + " " + encoding_name + "/" + std::to_string(clock_rate);
    if (channels > 1) {
        s += "/" + std::to_string(channels);
    }
    s += "\r\n";
    return s;
}

RtpMap RtpMap::parse(std::string_view line) {
    // line after "rtpmap:": "<payload_type> <encoding_name>/<clock_rate>[/<channels>]"
    RtpMap map;
    auto tokens = split_whitespace(line);
    if (tokens.size() >= 2) {
        map.payload_type = static_cast<uint8_t>(std::stoi(std::string(tokens[0])));
        std::string_view enc_info = tokens[1];
        size_t slash1 = enc_info.find('/');
        if (slash1 != std::string_view::npos) {
            map.encoding_name = std::string(enc_info.substr(0, slash1));
            size_t slash2 = enc_info.find('/', slash1 + 1);
            if (slash2 != std::string_view::npos) {
                map.clock_rate = std::stoul(std::string(enc_info.substr(slash1 + 1, slash2 - slash1 - 1)));
                map.channels = std::stoul(std::string(enc_info.substr(slash2 + 1)));
            } else {
                map.clock_rate = std::stoul(std::string(enc_info.substr(slash1 + 1)));
                map.channels = 1;
            }
        }
    }
    return map;
}

std::string Fmtp::to_string() const {
    return "a=fmtp:" + std::to_string(payload_type) + " " + parameters + "\r\n";
}

Fmtp Fmtp::parse(std::string_view line) {
    // line after "fmtp:": "<payload_type> <parameters>"
    Fmtp fmtp;
    size_t space = line.find(' ');
    if (space != std::string_view::npos) {
        fmtp.payload_type = static_cast<uint8_t>(std::stoi(std::string(line.substr(0, space))));
        fmtp.parameters = std::string(line.substr(space + 1));
    }
    return fmtp;
}

const RtpMap* MediaDescription::find_rtpmap(uint8_t pt) const {
    for (const auto& r : rtp_maps) {
        if (r.payload_type == pt) return &r;
    }
    return nullptr;
}

const Fmtp* MediaDescription::find_fmtp(uint8_t pt) const {
    for (const auto& f : fmtps) {
        if (f.payload_type == pt) return &f;
    }
    return nullptr;
}

std::string MediaDescription::serialize() const {
    std::ostringstream ss;
    // m=<media> <port> <proto> <fmt> ...
    ss << "m=" << media_type << " " << port << " " << protocol;
    for (auto pt : payload_types) {
        ss << " " << static_cast<int>(pt);
    }
    ss << "\r\n";

    if (connection) {
        ss << connection->to_string();
    }

    for (const auto& rtp : rtp_maps) {
        ss << rtp.to_string();
        const auto* fmtp = find_fmtp(rtp.payload_type);
        if (fmtp) {
            ss << fmtp->to_string();
        }
    }

    // Include any fmtp that didn't have an rtpmap (rare, but supported)
    for (const auto& fmtp : fmtps) {
        if (!find_rtpmap(fmtp.payload_type)) {
            ss << fmtp.to_string();
        }
    }

    if (ptime > 0) {
        ss << "a=ptime:" << ptime << "\r\n";
    }
    if (maxptime > 0) {
        ss << "a=maxptime:" << maxptime << "\r\n";
    }

    ss << "a=" << to_string(direction) << "\r\n";

    for (const auto& [k, v] : custom_attributes) {
        ss << "a=" << k;
        if (!v.empty()) {
            ss << ":" << v;
        }
        ss << "\r\n";
    }

    return ss.str();
}

std::string SessionDescription::serialize() const {
    std::ostringstream ss;
    ss << "v=" << version << "\r\n";
    ss << origin.to_string();
    ss << "s=" << session_name << "\r\n";

    if (connection) {
        ss << connection->to_string();
    }

    ss << "t=" << start_time << " " << stop_time << "\r\n";

    for (const auto& m : media) {
        ss << m.serialize();
    }

    return ss.str();
}

SessionDescription SessionDescription::parse(std::string_view sdp_text) {
    SessionDescription desc;
    auto lines = split_lines(sdp_text);

    MediaDescription* current_media = nullptr;

    for (auto line : lines) {
        if (line.size() < 2 || line[1] != '=') continue;

        char type = line[0];
        std::string_view val = line.substr(2);

        switch (type) {
            case 'v':
                desc.version = std::stoi(std::string(val));
                break;
            case 'o':
                desc.origin = OriginInfo::parse(val);
                break;
            case 's':
                desc.session_name = std::string(val);
                break;
            case 'c': {
                auto conn = ConnectionInfo::parse(val);
                if (current_media) {
                    current_media->connection = conn;
                } else {
                    desc.connection = conn;
                }
                break;
            }
            case 't': {
                auto tokens = split_whitespace(val);
                if (tokens.size() >= 2) {
                    desc.start_time = std::stoull(std::string(tokens[0]));
                    desc.stop_time = std::stoull(std::string(tokens[1]));
                }
                break;
            }
            case 'm': {
                desc.media.emplace_back();
                current_media = &desc.media.back();

                auto tokens = split_whitespace(val);
                if (tokens.size() >= 3) {
                    current_media->media_type = std::string(tokens[0]);
                    current_media->port = static_cast<uint16_t>(std::stoi(std::string(tokens[1])));
                    current_media->protocol = std::string(tokens[2]);
                    for (size_t i = 3; i < tokens.size(); ++i) {
                        current_media->payload_types.push_back(static_cast<uint8_t>(std::stoi(std::string(tokens[i]))));
                    }
                }
                break;
            }
            case 'a': {
                if (!current_media) break;

                if (val.starts_with("rtpmap:")) {
                    current_media->rtp_maps.push_back(RtpMap::parse(val.substr(7)));
                } else if (val.starts_with("fmtp:")) {
                    current_media->fmtps.push_back(Fmtp::parse(val.substr(5)));
                } else if (val.starts_with("ptime:")) {
                    current_media->ptime = std::stoul(std::string(val.substr(6)));
                } else if (val.starts_with("maxptime:")) {
                    current_media->maxptime = std::stoul(std::string(val.substr(9)));
                } else if (val == "sendrecv" || val == "sendonly" || val == "recvonly" || val == "inactive") {
                    current_media->direction = media_direction_from_string(val);
                } else {
                    size_t colon = val.find(':');
                    if (colon != std::string_view::npos) {
                        current_media->custom_attributes.emplace_back(
                            std::string(val.substr(0, colon)),
                            std::string(val.substr(colon + 1)));
                    } else {
                        current_media->custom_attributes.emplace_back(std::string(val), "");
                    }
                }
                break;
            }
            default:
                break;
        }
    }

    return desc;
}

SessionDescription SessionDescription::make_volte_amrwb_offer(
    std::string_view ip_address,
    uint16_t rtp_port,
    bool is_ipv6) {

    SessionDescription desc;
    desc.origin.username = "-";
    desc.origin.session_id = 2026102701ULL;
    desc.origin.session_version = 1;
    desc.origin.net_type = "IN";
    desc.origin.addr_type = is_ipv6 ? "IP6" : "IP4";
    desc.origin.unicast_address = std::string(ip_address);

    desc.session_name = "3GPP VoLTE Call";

    desc.connection = ConnectionInfo{
        .net_type = "IN",
        .addr_type = is_ipv6 ? "IP6" : "IP4",
        .address = std::string(ip_address)
    };

    MediaDescription audio;
    audio.media_type = "audio";
    audio.port = rtp_port;
    audio.protocol = "RTP/AVP";
    audio.direction = MediaDirection::SENDRECV;
    audio.ptime = 20;
    audio.maxptime = 240;

    // 3GPP TS 26.114 VoLTE standard codecs:
    // Dynamic PT 104: AMR-WB 16kHz
    // Dynamic PT 102: AMR 8kHz
    // Dynamic PT 100: Telephone-Event (DTMF)
    audio.payload_types = {104, 102, 100};

    audio.rtp_maps.push_back({104, "AMR-WB", 16000, 1});
    audio.fmtps.push_back({104, "octet-align=1; mode-change-capability=2"});

    audio.rtp_maps.push_back({102, "AMR", 8000, 1});
    audio.fmtps.push_back({102, "octet-align=1; mode-change-capability=2"});

    audio.rtp_maps.push_back({100, "telephone-event", 8000, 1});
    audio.fmtps.push_back({100, "0-15"});

    desc.media.push_back(audio);
    return desc;
}

SessionDescription SessionDescription::make_vonr_evs_offer(
    std::string_view ip_address,
    uint16_t rtp_port,
    bool is_ipv6) {

    SessionDescription desc;
    desc.origin.username = "-";
    desc.origin.session_id = 2026102702ULL;
    desc.origin.session_version = 1;
    desc.origin.net_type = "IN";
    desc.origin.addr_type = is_ipv6 ? "IP6" : "IP4";
    desc.origin.unicast_address = std::string(ip_address);

    desc.session_name = "3GPP 5G VoNR EVS Call";

    desc.connection = ConnectionInfo{
        .net_type = "IN",
        .addr_type = is_ipv6 ? "IP6" : "IP4",
        .address = std::string(ip_address)
    };

    MediaDescription audio;
    audio.media_type = "audio";
    audio.port = rtp_port;
    audio.protocol = "RTP/AVP";
    audio.direction = MediaDirection::SENDRECV;
    audio.ptime = 20;
    audio.maxptime = 240;

    // 5G VoNR primary codec: EVS (Enhanced Voice Services, 3GPP TS 26.441)
    // Dynamic PT 108: EVS 16kHz
    // Dynamic PT 104: AMR-WB fallback
    audio.payload_types = {108, 104, 100};

    audio.rtp_maps.push_back({108, "EVS", 16000, 1});
    audio.fmtps.push_back({108, "br=13.2-24.4; bw=wb-swb"});

    audio.rtp_maps.push_back({104, "AMR-WB", 16000, 1});
    audio.fmtps.push_back({104, "octet-align=1"});

    audio.rtp_maps.push_back({100, "telephone-event", 16000, 1});
    audio.fmtps.push_back({100, "0-15"});

    desc.media.push_back(audio);
    return desc;
}

} // namespace gpp::sdp
