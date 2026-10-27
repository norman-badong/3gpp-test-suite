#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <optional>
#include <cstdint>
#include "3gpp/sip/SipUri.hpp"
#include "3gpp/sip/SipHeader.hpp"
#include "3gpp/sdp/Sdp.hpp"

namespace gpp::sip {

enum class SipMessageType {
    REQUEST,
    RESPONSE
};

class SipMessage {
public:
    SipMessage() = default;

    // Type query
    [[nodiscard]] SipMessageType type() const { return type_; }
    [[nodiscard]] bool is_request() const { return type_ == SipMessageType::REQUEST; }
    [[nodiscard]] bool is_response() const { return type_ == SipMessageType::RESPONSE; }

    // Request fields
    [[nodiscard]] const std::string& method() const { return method_; }
    [[nodiscard]] const SipUri& request_uri() const { return request_uri_; }
    void set_request(std::string method, SipUri uri);

    // Response fields
    [[nodiscard]] int status_code() const { return status_code_; }
    [[nodiscard]] const std::string& reason_phrase() const { return reason_phrase_; }
    void set_response(int status_code, std::string reason_phrase);

    // Header management (case-insensitive)
    void set_header(std::string name, std::string value);
    void add_header(std::string name, std::string value);
    [[nodiscard]] std::string get_header(std::string_view name) const;
    [[nodiscard]] bool has_header(std::string_view name) const;
    [[nodiscard]] const std::vector<std::pair<std::string, std::string>>& headers() const { return headers_; }

    // Core typed header accessors
    [[nodiscard]] std::vector<ViaHeader> vias() const;
    void add_via(const ViaHeader& via);

    [[nodiscard]] NameAddrHeader from() const;
    void set_from(const NameAddrHeader& from);

    [[nodiscard]] NameAddrHeader to() const;
    void set_to(const NameAddrHeader& to);

    [[nodiscard]] std::vector<NameAddrHeader> contacts() const;
    void add_contact(const NameAddrHeader& contact);

    [[nodiscard]] std::string call_id() const;
    void set_call_id(std::string call_id);

    [[nodiscard]] CSeqHeader cseq() const;
    void set_cseq(const CSeqHeader& cseq);

    // Body
    [[nodiscard]] const std::string& body() const { return body_; }
    void set_body(std::string body, std::string content_type = "application/sdp");
    void set_sdp(const sdp::SessionDescription& sdp);
    [[nodiscard]] std::optional<sdp::SessionDescription> get_sdp() const;

    // Serialize / Parse
    [[nodiscard]] std::string serialize() const;
    static SipMessage parse(std::string_view text);

    // Factory builders for 3GPP VoLTE / VoNR procedures
    static SipMessage make_register(
        const SipUri& registrar_uri,
        const NameAddrHeader& from,
        const NameAddrHeader& to,
        const NameAddrHeader& contact,
        uint32_t cseq_number,
        std::string_view call_id,
        uint32_t expires = 3600);

    static SipMessage make_invite(
        const SipUri& request_uri,
        const NameAddrHeader& from,
        const NameAddrHeader& to,
        const NameAddrHeader& contact,
        uint32_t cseq_number,
        std::string_view call_id,
        const sdp::SessionDescription& offer);

    static SipMessage make_response(
        const SipMessage& request,
        int status_code,
        std::string_view reason_phrase,
        std::string_view to_tag = "");

    static SipMessage make_ack(
        const SipMessage& invite_request,
        const SipMessage& response_200);

    static SipMessage make_bye(
        const SipUri& request_uri,
        const NameAddrHeader& from,
        const NameAddrHeader& to,
        uint32_t cseq_number,
        std::string_view call_id);

private:
    SipMessageType type_{SipMessageType::REQUEST};
    std::string version_{"SIP/2.0"};

    // Request
    std::string method_{"INVITE"};
    SipUri request_uri_;

    // Response
    int status_code_{200};
    std::string reason_phrase_{"OK"};

    // Headers list (preserves order)
    std::vector<std::pair<std::string, std::string>> headers_;

    // Body
    std::string body_;

    static std::string normalize_header_name(std::string_view name);
};

} // namespace gpp::sip
