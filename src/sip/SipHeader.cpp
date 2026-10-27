#include "3gpp/sip/SipHeader.hpp"
#include <sstream>

namespace gpp::sip {

namespace {

std::string trim(std::string_view s) {
    size_t start = s.find_first_not_of(" \t\r\n\"");
    if (start == std::string_view::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n\"");
    return std::string(s.substr(start, end - start + 1));
}

} // namespace

std::string ViaHeader::to_string() const {
    std::ostringstream ss;
    ss << protocol << " " << sent_by_host;
    if (sent_by_port != 0) {
        ss << ":" << sent_by_port;
    }
    if (!branch.empty()) {
        ss << ";branch=" << branch;
    }
    if (rport >= 0) {
        ss << ";rport";
        if (rport > 0) ss << "=" << rport;
    }
    if (!received.empty()) {
        ss << ";received=" << received;
    }
    return ss.str();
}

ViaHeader ViaHeader::parse(std::string_view text) {
    ViaHeader v;
    size_t space = text.find(' ');
    if (space == std::string_view::npos) return v;

    v.protocol = std::string(text.substr(0, space));
    text = text.substr(space + 1);

    size_t semi = text.find(';');
    std::string_view hostport = (semi != std::string_view::npos) ? text.substr(0, semi) : text;

    size_t colon = hostport.find(':');
    if (colon != std::string_view::npos) {
        v.sent_by_host = std::string(hostport.substr(0, colon));
        try {
            v.sent_by_port = static_cast<uint16_t>(std::stoul(std::string(hostport.substr(colon + 1))));
        } catch (...) {
            v.sent_by_port = 5060;
        }
    } else {
        v.sent_by_host = std::string(hostport);
        v.sent_by_port = 5060;
    }

    if (semi != std::string_view::npos) {
        std::string_view params = text.substr(semi + 1);
        while (!params.empty()) {
            size_t next_semi = params.find(';');
            std::string_view token = (next_semi != std::string_view::npos) ? params.substr(0, next_semi) : params;

            size_t eq = token.find('=');
            std::string_view key = (eq != std::string_view::npos) ? token.substr(0, eq) : token;
            std::string_view val = (eq != std::string_view::npos) ? token.substr(eq + 1) : "";

            if (key == "branch") {
                v.branch = std::string(val);
            } else if (key == "rport") {
                v.rport = val.empty() ? 0 : std::stoi(std::string(val));
            } else if (key == "received") {
                v.received = std::string(val);
            }

            if (next_semi == std::string_view::npos) break;
            params = params.substr(next_semi + 1);
        }
    }
    return v;
}

std::string NameAddrHeader::to_string() const {
    std::ostringstream ss;
    if (!display_name.empty()) {
        ss << "\"" << display_name << "\" ";
    }
    ss << "<" << uri.to_string() << ">";
    if (!tag.empty()) {
        ss << ";tag=" << tag;
    }
    if (expires >= 0) {
        ss << ";expires=" << expires;
    }
    for (const auto& [k, v] : parameters) {
        ss << ";" << k;
        if (!v.empty()) {
            ss << "=" << v;
        }
    }
    return ss.str();
}

NameAddrHeader NameAddrHeader::parse(std::string_view text) {
    NameAddrHeader h;
    size_t lt = text.find('<');
    size_t gt = text.find('>');

    if (lt != std::string_view::npos && gt != std::string_view::npos && gt > lt) {
        if (lt > 0) {
            h.display_name = trim(text.substr(0, lt));
        }
        h.uri = SipUri::parse(text.substr(lt + 1, gt - lt - 1));

        // Parse parameters after '>'
        if (gt + 1 < text.size() && text[gt + 1] == ';') {
            std::string_view params = text.substr(gt + 2);
            while (!params.empty()) {
                size_t next_semi = params.find(';');
                std::string_view token = (next_semi != std::string_view::npos) ? params.substr(0, next_semi) : params;

                size_t eq = token.find('=');
                std::string key = std::string((eq != std::string_view::npos) ? token.substr(0, eq) : token);
                std::string val = std::string((eq != std::string_view::npos) ? token.substr(eq + 1) : "");

                if (key == "tag") {
                    h.tag = val;
                } else if (key == "expires") {
                    h.expires = std::stoi(val);
                } else {
                    h.parameters[key] = val;
                }

                if (next_semi == std::string_view::npos) break;
                params = params.substr(next_semi + 1);
            }
        }
    } else {
        // Simple URI without angle brackets (e.g. sip:alice@domain)
        size_t semi = text.find(';');
        if (semi != std::string_view::npos) {
            h.uri = SipUri::parse(text.substr(0, semi));
            std::string_view params = text.substr(semi + 1);
            while (!params.empty()) {
                size_t next_semi = params.find(';');
                std::string_view token = (next_semi != std::string_view::npos) ? params.substr(0, next_semi) : params;
                size_t eq = token.find('=');
                std::string key = std::string((eq != std::string_view::npos) ? token.substr(0, eq) : token);
                std::string val = std::string((eq != std::string_view::npos) ? token.substr(eq + 1) : "");
                if (key == "tag") h.tag = val;
                else if (key == "expires") h.expires = std::stoi(val);
                else h.parameters[key] = val;

                if (next_semi == std::string_view::npos) break;
                params = params.substr(next_semi + 1);
            }
        } else {
            h.uri = SipUri::parse(text);
        }
    }

    return h;
}

std::string CSeqHeader::to_string() const {
    return std::to_string(seq) + " " + method;
}

CSeqHeader CSeqHeader::parse(std::string_view text) {
    CSeqHeader cs;
    size_t space = text.find(' ');
    if (space != std::string_view::npos) {
        cs.seq = static_cast<uint32_t>(std::stoul(std::string(text.substr(0, space))));
        cs.method = std::string(text.substr(space + 1));
    }
    return cs;
}

} // namespace gpp::sip
