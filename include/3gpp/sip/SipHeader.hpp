#pragma once

#include <string>
#include <string_view>
#include <map>
#include <cstdint>
#include "3gpp/sip/SipUri.hpp"

namespace gpp::sip {

struct ViaHeader {
    std::string protocol{"SIP/2.0/UDP"};
    std::string sent_by_host{"127.0.0.1"};
    uint16_t sent_by_port{5060};
    std::string branch; // RFC 3261 magic cookie starts with "z9hG4bK"
    std::string received;
    int rport{-1}; // -1 if not present, >= 0 if present

    [[nodiscard]] std::string to_string() const;
    static ViaHeader parse(std::string_view text);
};

struct NameAddrHeader {
    std::string display_name;
    SipUri uri;
    std::string tag; // From/To tag
    int expires{-1}; // Contact expires parameter (-1 if absent)
    std::map<std::string, std::string> parameters;

    NameAddrHeader() = default;
    explicit NameAddrHeader(SipUri u, std::string disp = "", std::string t = "", int exp = -1)
        : display_name(std::move(disp)), uri(std::move(u)), tag(std::move(t)), expires(exp) {}

    [[nodiscard]] std::string to_string() const;
    static NameAddrHeader parse(std::string_view text);
};

struct CSeqHeader {
    uint32_t seq{1};
    std::string method{"INVITE"};

    [[nodiscard]] std::string to_string() const;
    static CSeqHeader parse(std::string_view text);
};

} // namespace gpp::sip
