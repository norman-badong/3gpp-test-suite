#pragma once

#include <string>
#include <string_view>
#include <map>
#include <cstdint>

namespace gpp::sip {

class SipUri {
public:
    SipUri() = default;
    SipUri(std::string user, std::string host, uint16_t port = 5060, std::string scheme = "sip");

    [[nodiscard]] const std::string& scheme() const { return scheme_; }
    [[nodiscard]] const std::string& user() const { return user_; }
    [[nodiscard]] const std::string& host() const { return host_; }
    [[nodiscard]] uint16_t port() const { return port_; }
    [[nodiscard]] const std::map<std::string, std::string>& parameters() const { return parameters_; }

    void set_parameter(std::string key, std::string value);
    [[nodiscard]] std::string get_parameter(const std::string& key) const;

    [[nodiscard]] std::string to_string() const;
    static SipUri parse(std::string_view text);

    bool operator==(const SipUri& other) const = default;

private:
    std::string scheme_{"sip"};
    std::string user_;
    std::string host_{"127.0.0.1"};
    uint16_t port_{5060};
    std::map<std::string, std::string> parameters_;
};

} // namespace gpp::sip
