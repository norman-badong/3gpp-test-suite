#pragma once

#include <string>
#include <string_view>
#include <cstdint>
#include "3gpp/sip/SipMessage.hpp"

namespace gpp::sip {

enum class DialogState {
    IDLE,
    EARLY,        // 1xx provisional response with To tag
    CONFIRMED,    // 2xx final response acknowledged
    TERMINATED    // BYE sent or received
};

std::string_view to_string(DialogState state);

class SipDialog {
public:
    SipDialog() = default;

    // Caller: Initialize dialog from outgoing INVITE request
    void init_as_uac(const SipMessage& invite);

    // Callee: Initialize dialog from incoming INVITE request
    void init_as_uas(const SipMessage& invite, std::string_view local_tag);

    // Process incoming response (Caller side)
    void handle_response(const SipMessage& resp);

    // Process incoming request inside dialog (e.g. BYE or re-INVITE)
    void handle_request(const SipMessage& req);

    [[nodiscard]] DialogState state() const { return state_; }
    [[nodiscard]] const std::string& call_id() const { return call_id_; }
    [[nodiscard]] const std::string& local_tag() const { return local_tag_; }
    [[nodiscard]] const std::string& remote_tag() const { return remote_tag_; }
    [[nodiscard]] uint32_t local_cseq() const { return local_cseq_; }
    [[nodiscard]] uint32_t remote_cseq() const { return remote_cseq_; }
    [[nodiscard]] const SipUri& remote_target() const { return remote_target_; }

    // Create in-dialog requests
    [[nodiscard]] SipMessage make_ack() const;
    [[nodiscard]] SipMessage make_bye();

private:
    DialogState state_{DialogState::IDLE};
    bool is_uac_{true};
    std::string call_id_;
    std::string local_tag_;
    std::string remote_tag_;
    uint32_t local_cseq_{1};
    uint32_t remote_cseq_{0};

    NameAddrHeader local_party_;
    NameAddrHeader remote_party_;
    SipUri remote_target_;
    ViaHeader last_via_;
};

} // namespace gpp::sip
