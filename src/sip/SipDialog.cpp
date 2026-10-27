#include "3gpp/sip/SipDialog.hpp"

namespace gpp::sip {

std::string_view to_string(DialogState state) {
    switch (state) {
        case DialogState::IDLE: return "IDLE";
        case DialogState::EARLY: return "EARLY";
        case DialogState::CONFIRMED: return "CONFIRMED";
        case DialogState::TERMINATED: return "TERMINATED";
    }
    return "IDLE";
}

void SipDialog::init_as_uac(const SipMessage& invite) {
    is_uac_ = true;
    call_id_ = invite.call_id();
    local_party_ = invite.from();
    local_tag_ = local_party_.tag;
    remote_party_ = invite.to();
    local_cseq_ = invite.cseq().seq;
    state_ = DialogState::IDLE;

    auto vias = invite.vias();
    if (!vias.empty()) {
        last_via_ = vias[0];
    }
}

void SipDialog::init_as_uas(const SipMessage& invite, std::string_view local_tag) {
    is_uac_ = false;
    call_id_ = invite.call_id();
    remote_party_ = invite.from();
    remote_tag_ = remote_party_.tag;

    local_party_ = invite.to();
    local_tag_ = std::string(local_tag);
    local_party_.tag = local_tag_;

    remote_cseq_ = invite.cseq().seq;
    local_cseq_ = 100;

    auto contacts = invite.contacts();
    if (!contacts.empty()) {
        remote_target_ = contacts[0].uri;
    } else {
        remote_target_ = invite.request_uri();
    }

    state_ = DialogState::EARLY;
}

void SipDialog::handle_response(const SipMessage& resp) {
    if (call_id_.empty()) {
        call_id_ = resp.call_id();
    }

    // Capture remote tag from To header
    NameAddrHeader to_hdr = resp.to();
    if (!to_hdr.tag.empty()) {
        remote_tag_ = to_hdr.tag;
        remote_party_.tag = remote_tag_;
    }

    // Capture Contact header for target refresh
    auto contacts = resp.contacts();
    if (!contacts.empty()) {
        remote_target_ = contacts[0].uri;
    }

    int code = resp.status_code();
    if (code >= 101 && code <= 199) {
        if (!remote_tag_.empty()) {
            state_ = DialogState::EARLY;
        }
    } else if (code >= 200 && code <= 299) {
        state_ = DialogState::CONFIRMED;
    } else if (code >= 300) {
        state_ = DialogState::TERMINATED;
    }
}

void SipDialog::handle_request(const SipMessage& req) {
    if (req.method() == "BYE") {
        state_ = DialogState::TERMINATED;
    }
    remote_cseq_ = req.cseq().seq;
}

SipMessage SipDialog::make_ack() const {
    SipMessage ack;
    ack.set_request("ACK", remote_target_);

    ViaHeader via = last_via_;
    via.branch = via.branch + "-ack";
    ack.add_via(via);

    ack.set_header("Max-Forwards", "70");
    ack.set_from(local_party_);
    ack.set_to(remote_party_);
    ack.set_call_id(call_id_);
    ack.set_cseq(CSeqHeader{local_cseq_, "ACK"});
    return ack;
}

SipMessage SipDialog::make_bye() {
    ++local_cseq_;
    SipMessage bye;
    bye.set_request("BYE", remote_target_);

    ViaHeader via = last_via_;
    via.branch = "z9hG4bK-" + std::to_string(local_cseq_) + "-bye";
    bye.add_via(via);

    bye.set_header("Max-Forwards", "70");
    bye.set_from(local_party_);
    bye.set_to(remote_party_);
    bye.set_call_id(call_id_);
    bye.set_cseq(CSeqHeader{local_cseq_, "BYE"});

    state_ = DialogState::TERMINATED;
    return bye;
}

} // namespace gpp::sip
