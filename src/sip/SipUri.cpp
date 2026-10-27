#include "3gpp/sip/SipUri.hpp"
#include <sstream>

namespace gpp::sip {

SipUri::SipUri(std::string user, std::string host, uint16_t port, std::string scheme)
    : scheme_(std::move(scheme)), user_(std::move(user)), host_(std::move(host)), port_(port) {}

void SipUri::set_parameter(std::string key, std::string value) {
    parameters_[std::move(key)] = std::move(value);
}

std::string SipUri::get_parameter(const std::string& key) const {
    auto it = parameters_.find(key);
    return (it != parameters_.end()) ? it->second : "";
}

std::string SipUri::to_string() const {
    std::ostringstream ss;
    ss << scheme_ << ":";
    if (!user_.empty()) {
        ss << user_ << "@";
    }
    ss << host_;
    if (port_ != 5060 && port_ != 0) {
        ss << ":" << port_;
    }
    for (const auto& [k, v] : parameters_) {
        ss << ";" << k;
        if (!v.empty()) {
            ss << "=" << v;
        }
    }
    return ss.str();
}

SipUri SipUri::parse(std::string_view text) {
    SipUri uri;
    if (text.empty()) return uri;

    // Remove surrounding angle brackets '<...>' if present
    if (text.front() == '<' && text.back() == '>') {
        text = text.substr(1, text.size() - 2);
    }

    size_t scheme_pos = text.find(':');
    if (scheme_pos != std::string_view::npos) {
        uri.scheme_ = std::string(text.substr(0, scheme_pos));
        text = text.substr(scheme_pos + 1);
    }

    // Split parameters separated by ';'
    size_t param_pos = text.find(';');
    std::string_view core_part = (param_pos != std::string_view::npos) ? text.substr(0, param_pos) : text;

    if (param_pos != std::string_view::npos) {
        std::string_view params_str = text.substr(param_pos + 1);
        while (!params_str.empty()) {
            size_t next_semi = params_str.find(';');
            std::string_view token = (next_semi != std::string_view::npos) ? params_str.substr(0, next_semi) : params_str;

            size_t eq_pos = token.find('=');
            if (eq_pos != std::string_view::npos) {
                uri.set_parameter(std::string(token.substr(0, eq_pos)), std::string(token.substr(eq_pos + 1)));
            } else {
                uri.set_parameter(std::string(token), "");
            }

            if (next_semi == std::string_view::npos) break;
            params_str = params_str.substr(next_semi + 1);
        }
    }

    // Parse user@host:port from core_part
    size_t at_pos = core_part.find('@');
    if (at_pos != std::string_view::npos) {
        uri.user_ = std::string(core_part.substr(0, at_pos));
        core_part = core_part.substr(at_pos + 1);
    }

    size_t colon_pos = core_part.find(':');
    if (colon_pos != std::string_view::npos) {
        uri.host_ = std::string(core_part.substr(0, colon_pos));
        try {
            uri.port_ = static_cast<uint16_t>(std::stoul(std::string(core_part.substr(colon_pos + 1))));
        } catch (...) {
            uri.port_ = 5060;
        }
    } else {
        uri.host_ = std::string(core_part);
        uri.port_ = 5060;
    }

    return uri;
}

} // namespace gpp::sip
