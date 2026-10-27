#include "3gpp/sip/SipMessage.hpp"
#include <sstream>
#include <algorithm>
#include <stdexcept>

namespace gpp::sip {

namespace {

std::string to_lower(std::string_view s) {
    std::string res;
    res.reserve(s.size());
    for (char c : s) {
        res.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return res;
}

std::string trim(std::string_view s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return std::string(s.substr(start, end - start + 1));
}

} // namespace

std::string SipMessage::normalize_header_name(std::string_view name) {
    std::string lower = to_lower(trim(name));
    // Compact form mappings (RFC 3261 Section 7.3.3)
    if (lower == "v") return "via";
    if (lower == "f") return "from";
    if (lower == "t") return "to";
    if (lower == "i") return "call-id";
    if (lower == "m") return "contact";
    if (lower == "c") return "content-type";
    if (lower == "l") return "content-length";
    if (lower == "k") return "supported";
    return lower;
}

void SipMessage::set_request(std::string method, SipUri uri) {
    type_ = SipMessageType::REQUEST;
    method_ = std::move(method);
    request_uri_ = std::move(uri);
}

void SipMessage::set_response(int status_code, std::string reason_phrase) {
    type_ = SipMessageType::RESPONSE;
    status_code_ = status_code;
    reason_phrase_ = std::move(reason_phrase);
}

void SipMessage::set_header(std::string name, std::string value) {
    std::string norm = normalize_header_name(name);
    for (auto& [k, v] : headers_) {
        if (normalize_header_name(k) == norm) {
            v = std::move(value);
            return;
        }
    }
    headers_.emplace_back(std::move(name), std::move(value));
}

void SipMessage::add_header(std::string name, std::string value) {
    headers_.emplace_back(std::move(name), std::move(value));
}

std::string SipMessage::get_header(std::string_view name) const {
    std::string norm = normalize_header_name(name);
    for (const auto& [k, v] : headers_) {
        if (normalize_header_name(k) == norm) {
            return v;
        }
    }
    return "";
}

bool SipMessage::has_header(std::string_view name) const {
    std::string norm = normalize_header_name(name);
    for (const auto& [k, v] : headers_) {
        if (normalize_header_name(k) == norm) {
            return true;
        }
    }
    return false;
}

std::vector<ViaHeader> SipMessage::vias() const {
    std::vector<ViaHeader> res;
    for (const auto& [k, v] : headers_) {
        if (normalize_header_name(k) == "via") {
            res.push_back(ViaHeader::parse(v));
        }
    }
    return res;
}

void SipMessage::add_via(const ViaHeader& via) {
    add_header("Via", via.to_string());
}

NameAddrHeader SipMessage::from() const {
    return NameAddrHeader::parse(get_header("From"));
}

void SipMessage::set_from(const NameAddrHeader& from) {
    set_header("From", from.to_string());
}

NameAddrHeader SipMessage::to() const {
    return NameAddrHeader::parse(get_header("To"));
}

void SipMessage::set_to(const NameAddrHeader& to) {
    set_header("To", to.to_string());
}

std::vector<NameAddrHeader> SipMessage::contacts() const {
    std::vector<NameAddrHeader> res;
    for (const auto& [k, v] : headers_) {
        if (normalize_header_name(k) == "contact") {
            res.push_back(NameAddrHeader::parse(v));
        }
    }
    return res;
}

void SipMessage::add_contact(const NameAddrHeader& contact) {
    add_header("Contact", contact.to_string());
}

std::string SipMessage::call_id() const {
    return get_header("Call-ID");
}

void SipMessage::set_call_id(std::string cid) {
    set_header("Call-ID", std::move(cid));
}

CSeqHeader SipMessage::cseq() const {
    return CSeqHeader::parse(get_header("CSeq"));
}

void SipMessage::set_cseq(const CSeqHeader& cseq) {
    set_header("CSeq", cseq.to_string());
}

void SipMessage::set_body(std::string body, std::string content_type) {
    body_ = std::move(body);
    set_header("Content-Type", std::move(content_type));
    set_header("Content-Length", std::to_string(body_.size()));
}

void SipMessage::set_sdp(const sdp::SessionDescription& sdp) {
    set_body(sdp.serialize(), "application/sdp");
}

std::optional<sdp::SessionDescription> SipMessage::get_sdp() const {
    if (body_.empty()) return std::nullopt;
    std::string ct = get_header("Content-Type");
    if (ct.find("application/sdp") != std::string::npos) {
        return sdp::SessionDescription::parse(body_);
    }
    return std::nullopt;
}

std::string SipMessage::serialize() const {
    std::ostringstream ss;
    if (type_ == SipMessageType::REQUEST) {
        ss << method_ << " " << request_uri_.to_string() << " " << version_ << "\r\n";
    } else {
        ss << version_ << " " << status_code_ << " " << reason_phrase_ << "\r\n";
    }

    bool has_content_length = false;
    for (const auto& [k, v] : headers_) {
        std::string norm = normalize_header_name(k);
        if (norm == "content-length") {
            has_content_length = true;
            ss << "Content-Length: " << body_.size() << "\r\n";
        } else {
            ss << k << ": " << v << "\r\n";
        }
    }

    if (!has_content_length) {
        ss << "Content-Length: " << body_.size() << "\r\n";
    }

    ss << "\r\n";
    if (!body_.empty()) {
        ss << body_;
    }
    return ss.str();
}

SipMessage SipMessage::parse(std::string_view text) {
    SipMessage msg;
    if (text.empty()) return msg;

    // Split headers and body at first "\r\n\r\n" or "\n\n"
    size_t body_sep = text.find("\r\n\r\n");
    size_t sep_len = 4;
    if (body_sep == std::string_view::npos) {
        body_sep = text.find("\n\n");
        sep_len = 2;
    }

    std::string_view headers_part = (body_sep != std::string_view::npos) ? text.substr(0, body_sep) : text;
    if (body_sep != std::string_view::npos) {
        msg.body_ = std::string(text.substr(body_sep + sep_len));
    }

    // Split headers_part line by line
    std::vector<std::string_view> lines;
    size_t start = 0;
    while (start < headers_part.size()) {
        size_t end = headers_part.find_first_of("\r\n", start);
        if (end == std::string_view::npos) {
            lines.push_back(headers_part.substr(start));
            break;
        }
        lines.push_back(headers_part.substr(start, end - start));
        start = end + 1;
        if (start < headers_part.size() && headers_part[end] == '\r' && headers_part[start] == '\n') {
            ++start;
        }
    }

    if (lines.empty()) return msg;

    // Parse start line (Request Line or Status Line)
    std::string_view start_line = lines[0];
    if (start_line.starts_with("SIP/2.0")) {
        // Status line: SIP/2.0 <StatusCode> <ReasonPhrase>
        msg.type_ = SipMessageType::RESPONSE;
        size_t sp1 = start_line.find(' ');
        if (sp1 != std::string_view::npos) {
            size_t sp2 = start_line.find(' ', sp1 + 1);
            if (sp2 != std::string_view::npos) {
                msg.status_code_ = std::stoi(std::string(start_line.substr(sp1 + 1, sp2 - sp1 - 1)));
                msg.reason_phrase_ = std::string(start_line.substr(sp2 + 1));
            } else {
                msg.status_code_ = std::stoi(std::string(start_line.substr(sp1 + 1)));
                msg.reason_phrase_ = "";
            }
        }
    } else {
        // Request line: <Method> <Request-URI> SIP/2.0
        msg.type_ = SipMessageType::REQUEST;
        size_t sp1 = start_line.find(' ');
        if (sp1 != std::string_view::npos) {
            msg.method_ = std::string(start_line.substr(0, sp1));
            size_t sp2 = start_line.find(' ', sp1 + 1);
            if (sp2 != std::string_view::npos) {
                msg.request_uri_ = SipUri::parse(start_line.substr(sp1 + 1, sp2 - sp1 - 1));
            } else {
                msg.request_uri_ = SipUri::parse(start_line.substr(sp1 + 1));
            }
        }
    }

    // Parse headers (lines 1 to end)
    for (size_t i = 1; i < lines.size(); ++i) {
        std::string_view line = lines[i];
        if (line.empty()) continue;

        // Check for line folding (starts with space or tab)
        if ((line[0] == ' ' || line[0] == '\t') && !msg.headers_.empty()) {
            msg.headers_.back().second += " " + trim(line);
            continue;
        }

        size_t colon = line.find(':');
        if (colon != std::string_view::npos) {
            std::string name = trim(line.substr(0, colon));
            std::string val = trim(line.substr(colon + 1));
            msg.add_header(name, val);
        }
    }

    return msg;
}

SipMessage SipMessage::make_register(
    const SipUri& registrar_uri,
    const NameAddrHeader& from,
    const NameAddrHeader& to,
    const NameAddrHeader& contact,
    uint32_t cseq_number,
    std::string_view call_id,
    uint32_t expires) {

    SipMessage msg;
    msg.set_request("REGISTER", registrar_uri);

    ViaHeader via;
    via.sent_by_host = contact.uri.host();
    via.sent_by_port = contact.uri.port();
    via.branch = "z9hG4bK-" + std::to_string(cseq_number) + "-reg";
    via.rport = 0;
    msg.add_via(via);

    msg.set_header("Max-Forwards", "70");
    msg.set_from(from);
    msg.set_to(to);
    msg.set_call_id(std::string(call_id));
    msg.set_cseq(CSeqHeader{cseq_number, "REGISTER"});

    NameAddrHeader c = contact;
    c.expires = static_cast<int>(expires);
    msg.add_contact(c);

    msg.set_header("Expires", std::to_string(expires));
    msg.set_header("User-Agent", "3GPP-VoLTE-Client/1.0");
    msg.set_header("Supported", "path");
    msg.set_body(""); // No body in plain REGISTER
    return msg;
}

SipMessage SipMessage::make_invite(
    const SipUri& request_uri,
    const NameAddrHeader& from,
    const NameAddrHeader& to,
    const NameAddrHeader& contact,
    uint32_t cseq_number,
    std::string_view call_id,
    const sdp::SessionDescription& offer) {

    SipMessage msg;
    msg.set_request("INVITE", request_uri);

    ViaHeader via;
    via.sent_by_host = contact.uri.host();
    via.sent_by_port = contact.uri.port();
    via.branch = "z9hG4bK-" + std::to_string(cseq_number) + "-inv";
    via.rport = 0;
    msg.add_via(via);

    msg.set_header("Max-Forwards", "70");
    msg.set_from(from);
    msg.set_to(to);
    msg.set_call_id(std::string(call_id));
    msg.set_cseq(CSeqHeader{cseq_number, "INVITE"});
    msg.add_contact(contact);
    msg.set_header("Allow", "INVITE, ACK, CANCEL, BYE, NOTIFY, PRACK, UPDATE, REFER");
    msg.set_header("User-Agent", "3GPP-IMS-UE/1.0");

    msg.set_sdp(offer);
    return msg;
}

SipMessage SipMessage::make_response(
    const SipMessage& req,
    int status_code,
    std::string_view reason_phrase,
    std::string_view to_tag) {

    SipMessage resp;
    resp.set_response(status_code, std::string(reason_phrase));

    // Copy Via headers
    for (const auto& via : req.vias()) {
        resp.add_via(via);
    }

    resp.set_from(req.from());

    NameAddrHeader to_hdr = req.to();
    if (!to_tag.empty() && to_hdr.tag.empty()) {
        to_hdr.tag = std::string(to_tag);
    }
    resp.set_to(to_hdr);

    resp.set_call_id(req.call_id());
    resp.set_cseq(req.cseq());

    if (req.has_header("User-Agent")) {
        resp.set_header("Server", "3GPP-IMS-P-CSCF/1.0");
    }

    return resp;
}

SipMessage SipMessage::make_ack(
    const SipMessage& invite_req,
    const SipMessage& response_200) {

    SipMessage ack;
    // Callee contact is preferred target for ACK
    auto contacts = response_200.contacts();
    if (!contacts.empty()) {
        ack.set_request("ACK", contacts[0].uri);
    } else {
        ack.set_request("ACK", invite_req.request_uri());
    }

    if (!invite_req.vias().empty()) {
        ViaHeader v = invite_req.vias()[0];
        v.branch = v.branch + "-ack";
        ack.add_via(v);
    }

    ack.set_header("Max-Forwards", "70");
    ack.set_from(response_200.from());
    ack.set_to(response_200.to());
    ack.set_call_id(response_200.call_id());
    ack.set_cseq(CSeqHeader{invite_req.cseq().seq, "ACK"});

    return ack;
}

SipMessage SipMessage::make_bye(
    const SipUri& request_uri,
    const NameAddrHeader& from,
    const NameAddrHeader& to,
    uint32_t cseq_number,
    std::string_view call_id) {

    SipMessage bye;
    bye.set_request("BYE", request_uri);

    ViaHeader via;
    via.sent_by_host = from.uri.host();
    via.sent_by_port = from.uri.port();
    via.branch = "z9hG4bK-" + std::to_string(cseq_number) + "-bye";
    bye.add_via(via);

    bye.set_header("Max-Forwards", "70");
    bye.set_from(from);
    bye.set_to(to);
    bye.set_call_id(std::string(call_id));
    bye.set_cseq(CSeqHeader{cseq_number, "BYE"});

    return bye;
}

} // namespace gpp::sip
