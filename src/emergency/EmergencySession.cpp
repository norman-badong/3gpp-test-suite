#include "3gpp/emergency/EmergencySession.hpp"
#include "3gpp/common/ByteStream.hpp"
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace gpp::emergency {

// ============================================================================
// PidfLo Implementation
// ============================================================================

std::string PidfLo::to_xml() const {
    std::ostringstream oss;
    oss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    oss << "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" "
        << "xmlns:gp=\"urn:ietf:params:xml:ns:pidf:geopriv10\" "
        << "xmlns:gs=\"http://www.opengis.net/pidflo/1.0\" "
        << "xmlns:gml=\"http://www.opengis.net/gml\" "
        << "entity=\"" << entity << "\">\n";
    oss << "  <tuple id=\"" << id << "\">\n";
    oss << "    <gp:geopriv>\n";
    oss << "      <gp:location-info>\n";

    if (location.type == LocationType::Geodetic || location.type == LocationType::Both) {
        const auto& geo = location.geodetic;
        oss << "        <gs:Circle srsName=\"urn:ogc:def:crs:EPSG::4326\">\n";
        oss << std::fixed << std::setprecision(6);
        oss << "          <gml:pos>" << geo.latitude << " " << geo.longitude << "</gml:pos>\n";
        oss << std::setprecision(2);
        oss << "          <gs:radius>" << geo.horizontal_accuracy << "</gs:radius>\n";
        oss.unsetf(std::ios::floatfield);
        oss << "        </gs:Circle>\n";
    }

    if (location.type == LocationType::CivicAddress || location.type == LocationType::Both) {
        const auto& civ = location.civic;
        oss << "        <gs:civicAddress>\n";
        if (!civ.country.empty()) oss << "          <gp:country>" << civ.country << "</gp:country>\n";
        if (!civ.state.empty()) oss << "          <gp:A1>" << civ.state << "</gp:A1>\n";
        if (!civ.county.empty()) oss << "          <gp:A2>" << civ.county << "</gp:A2>\n";
        if (!civ.city.empty()) oss << "          <gp:A3>" << civ.city << "</gp:A3>\n";
        if (!civ.street.empty()) oss << "          <gp:A4>" << civ.street << "</gp:A4>\n";
        if (!civ.house_number.empty()) oss << "          <gp:A5>" << civ.house_number << "</gp:A5>\n";
        if (!civ.building.empty()) oss << "          <gp:A6>" << civ.building << "</gp:A6>\n";
        if (!civ.floor.empty()) oss << "          <gp:A7>" << civ.floor << "</gp:A7>\n";
        if (!civ.room.empty()) oss << "          <gp:A8>" << civ.room << "</gp:A8>\n";
        oss << "        </gs:civicAddress>\n";
    }

    oss << "      </gp:location-info>\n";
    oss << "      <gp:method>" << method << "</gp:method>\n";
    oss << "      <gp:confidence>" << std::fixed << std::setprecision(2) << confidence << "</gp:confidence>\n";
    oss << "    </gp:geopriv>\n";
    oss << "    <timestamp>" << timestamp << "</timestamp>\n";
    oss << "  </tuple>\n";
    oss << "</presence>\n";
    return oss.str();
}

std::optional<PidfLo> PidfLo::from_xml(const std::string& xml) {
    // Simplified - would need proper XML parser
    return std::nullopt;
}

// ============================================================================
// GeolocationHeader Implementation
// ============================================================================

std::string GeolocationHeader::to_header_value() const {
    std::ostringstream oss;
    oss << "<" << uri << ">;routing=" << routing << ";purpose=" << purpose;
    return oss.str();
}

// ============================================================================
// SipMessage Implementation
// ============================================================================

void SipMessage::add_header(const std::string& name, const std::string& value) {
    headers[name] = value;
}

std::optional<std::string> SipMessage::get_header(const std::string& name) const {
    auto it = headers.find(name);
    if (it != headers.end()) return it->second;
    return std::nullopt;
}

void SipMessage::set_body(const std::string& body_, const std::string& content_type_) {
    body = body_;
    content_type = content_type_;
    add_header("Content-Type", content_type_);
    add_header("Content-Length", std::to_string(body_.size()));
}

std::string SipMessage::encode() const {
    std::ostringstream oss;

    // Request/Status line
    std::string method_str;
    switch (method) {
        case EmergencySipMethod::Register: method_str = "REGISTER"; break;
        case EmergencySipMethod::Invite: method_str = "INVITE"; break;
        case EmergencySipMethod::Ack: method_str = "ACK"; break;
        case EmergencySipMethod::Bye: method_str = "BYE"; break;
        case EmergencySipMethod::Cancel: method_str = "CANCEL"; break;
        case EmergencySipMethod::Options: method_str = "OPTIONS"; break;
        case EmergencySipMethod::Update: method_str = "UPDATE"; break;
        case EmergencySipMethod::Prack: method_str = "PRACK"; break;
        case EmergencySipMethod::Refer: method_str = "REFER"; break;
        case EmergencySipMethod::Notify: method_str = "NOTIFY"; break;
        case EmergencySipMethod::Subscribe: method_str = "SUBSCRIBE"; break;
        case EmergencySipMethod::Publish: method_str = "PUBLISH"; break;
        case EmergencySipMethod::Message: method_str = "MESSAGE"; break;
        case EmergencySipMethod::Info: method_str = "INFO"; break;
    }

    if (!request_uri.empty()) {
        oss << method_str << " " << request_uri << " SIP/2.0\r\n";
    }

    // Headers
    for (const auto& [name, value] : headers) {
        oss << name << ": " << value << "\r\n";
    }

    oss << "\r\n";

    // Body
    if (!body.empty()) {
        oss << body;
    }

    return oss.str();
}

std::optional<SipMessage> SipMessage::decode(std::span<const uint8_t> data) {
    // Simplified SIP parser - in production use proper parser
    std::string str(reinterpret_cast<const char*>(data.data()), data.size());
    SipMessage msg;

    std::istringstream iss(str);
    std::string line;

    // First line
    if (!std::getline(iss, line)) return std::nullopt;
    if (line.back() == '\r') line.pop_back();

    std::istringstream first_line(line);
    std::string method_str;
    first_line >> method_str >> msg.request_uri;

    if (method_str == "REGISTER") msg.method = EmergencySipMethod::Register;
    else if (method_str == "INVITE") msg.method = EmergencySipMethod::Invite;
    else if (method_str == "ACK") msg.method = EmergencySipMethod::Ack;
    else if (method_str == "BYE") msg.method = EmergencySipMethod::Bye;
    else if (method_str == "CANCEL") msg.method = EmergencySipMethod::Cancel;
    else if (method_str == "OPTIONS") msg.method = EmergencySipMethod::Options;
    else if (method_str == "UPDATE") msg.method = EmergencySipMethod::Update;
    else if (method_str == "PRACK") msg.method = EmergencySipMethod::Prack;
    else if (method_str == "REFER") msg.method = EmergencySipMethod::Refer;
    else if (method_str == "NOTIFY") msg.method = EmergencySipMethod::Notify;
    else if (method_str == "SUBSCRIBE") msg.method = EmergencySipMethod::Subscribe;
    else if (method_str == "PUBLISH") msg.method = EmergencySipMethod::Publish;
    else if (method_str == "MESSAGE") msg.method = EmergencySipMethod::Message;
    else if (method_str == "INFO") msg.method = EmergencySipMethod::Info;
    else {
        // Response
        int status_code;
        first_line >> status_code;
        // Handle response parsing
    }

    // Headers
    while (std::getline(iss, line)) {
        if (line == "\r" || line.empty()) break;
        if (line.back() == '\r') line.pop_back();

        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name = line.substr(0, colon);
            std::string value = line.substr(colon + 1);
            // Trim whitespace
            while (!value.empty() && (value[0] == ' ' || value[0] == '\t')) value.erase(0, 1);
            msg.headers[name] = value;
        }
    }

    // Body
    std::ostringstream body_oss;
    while (std::getline(iss, line)) {
        body_oss << line << "\n";
    }
    msg.body = body_oss.str();
    if (!msg.body.empty() && msg.body.back() == '\n') msg.body.pop_back();

    return msg;
}

// ============================================================================
// EmergencySession Implementation
// ============================================================================

EmergencySession::EmergencySession(const EmergencySessionConfig& config, EmergencySessionCallbacks callbacks)
    : config_(config), callbacks_(std::move(callbacks)) {
    // Generate call ID
    call_id_ = generate_call_id();
    from_tag_ = generate_tag();
}

void EmergencySession::start_emergency_registration() {
    transition_state(EmergencySessionState::Registering);
    send_register();
}

void EmergencySession::start_emergency_call(EmergencyCategory category) {
    config_.call_context.category = category;
    config_.call_context.service_urn = EmergencyServiceUrn::from_category(category);
    config_.call_context.call_id = call_id_;
    config_.call_context.from_tag = from_tag_;

    // Get initial location if available
    if (config_.include_location && config_.location_provider) {
        config_.call_context.location = config_.location_provider();
    } else if (config_.include_location && config_.initial_location.has_location()) {
        config_.call_context.location = config_.initial_location;
    }

    transition_state(EmergencySessionState::Calling);
    send_invite();
}

void EmergencySession::handle_sip_message(const SipMessage& msg) {
    // Handle requests (re-INVITE, BYE, etc.)
    if (msg.method == EmergencySipMethod::Bye) {
        // Send 200 OK
        SipMessage resp;
        resp.method = EmergencySipMethod::Bye; // Response
        resp.request_uri = "SIP/2.0 200 OK";
        resp.add_header("Call-ID", call_id_);
        resp.add_header("CSeq", std::to_string(cseq_) + " BYE");
        callbacks_.on_send_sip(resp);
        transition_state(EmergencySessionState::Released);
        callbacks_.on_call_ended("Remote BYE");
    }
    else if (msg.method == EmergencySipMethod::Invite) {
        // re-INVITE (e.g., for hold/resume or location update)
        if (msg.get_header("Content-Type").has_value()) {
            // Parse SDP
            parse_sdp_answer(msg.body);
        }
    }
}

void EmergencySession::handle_sip_response(const SipMessage& response, uint32_t cseq) {
    auto status_line = response.request_uri; // For response, this holds status line
    int status_code = 0;
    std::istringstream iss(status_line);
    std::string sip_version;
    iss >> sip_version >> status_code;

    if (cseq == cseq_ - 1) { // Response to our last request
        if (state_ == EmergencySessionState::Registering) {
            handle_register_response(response);
        } else if (state_ == EmergencySessionState::Calling || state_ == EmergencySessionState::Alerting) {
            handle_invite_response(response);
        }
    }
}

void EmergencySession::send_location_update(const LocationInfo& location) {
    if (state_ != EmergencySessionState::Connected) return;

    config_.call_context.location = location;

    // Send UPDATE with new location
    send_update_location(location);
}

void EmergencySession::end_call(const std::string& reason) {
    if (state_ == EmergencySessionState::Released || state_ == EmergencySessionState::Idle) return;

    send_bye(reason);
    transition_state(EmergencySessionState::Releasing);
}

void EmergencySession::tick(uint64_t now_sec) {
    // Registration refresh
    if (emergency_registered_ && now_sec >= reg_expiry_time_ - 60) {
        send_register();
    }

    // Session timer refresh
    if (state_ == EmergencySessionState::Connected && session_timer_expires_ > 0 && now_sec >= session_timer_expires_ - 30) {
        // Send re-INVITE or UPDATE to refresh session
        send_update_location(config_.call_context.location);
    }

    // Location updates
    if (state_ == EmergencySessionState::Connected && config_.include_location && config_.location_provider) {
        if (now_sec - last_keepalive_ > 30) { // Every 30 seconds
            auto loc = config_.location_provider();
            if (loc.has_location()) {
                send_location_update(loc);
            }
            last_keepalive_ = now_sec;
        }
    }
}

// Private methods

void EmergencySession::send_register() {
    SipMessage msg;
    msg.method = EmergencySipMethod::Register;
    msg.request_uri = "sip:" + config_.home_domain;

    msg.add_header("Via", "SIP/2.0/" + config_.transport + " " + config_.local_ip + ";branch=z9hG4bK" + generate_tag());
    msg.add_header("Max-Forwards", "70");
    msg.add_header("To", "<sip:" + config_.impi + "@" + config_.home_domain + ">"); // Emergency registration uses IMPU
    msg.add_header("From", "<sip:" + config_.impi + "@" + config_.home_domain + ">;tag=" + from_tag_);
    msg.add_header("Call-ID", call_id_);
    msg.add_header("CSeq", std::to_string(cseq_++) + " REGISTER");
    msg.add_header("Contact", "<sip:" + config_.impu + "@" + config_.local_ip + ";transport=" + config_.transport + ">;+sip.instance=\"<urn:gsma:imei:000000000000000>\";reg-id=1");
    msg.add_header("Expires", std::to_string(config_.reg_expires));
    msg.add_header("Supported", "path, gruu, outbound");
    msg.add_header("User-Agent", "3GPP Test Suite Emergency Client");

    // Emergency registration indication
    msg.add_header("P-Access-Network-Info", "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=00000000");

    callbacks_.on_send_sip(msg);
}

void EmergencySession::handle_register_response(const SipMessage& resp) {
    auto status_line = resp.request_uri;
    int status_code = 0;
    std::istringstream iss(status_line);
    std::string sip_ver;
    iss >> sip_ver >> status_code;

    if (status_code == 200) {
        // Extract route set
        auto record_route = resp.get_header("Record-Route");
        if (record_route) route_set_ = *record_route;

        // Extract contact (for GRUU)
        auto contact = resp.get_header("Contact");
        if (contact) contact_header_ = *contact;

        // Extract expires
        auto expires = resp.get_header("Expires");
        if (expires) {
            reg_expires_ = std::stoul(*expires);
        }

        emergency_registered_ = true;
        reg_expiry_time_ = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() + reg_expires_;

        transition_state(EmergencySessionState::Registered);
    } else if (status_code == 401 || status_code == 407) {
        // Authentication challenge - in real implementation, re-send with credentials
        transition_state(EmergencySessionState::Failed);
        callbacks_.on_call_ended("Registration failed: " + std::to_string(status_code));
    } else {
        transition_state(EmergencySessionState::Failed);
        callbacks_.on_call_ended("Registration failed: " + std::to_string(status_code));
    }
}

void EmergencySession::send_invite() {
    SipMessage msg;
    msg.method = EmergencySipMethod::Invite;
    msg.request_uri = config_.call_context.service_urn.urn; // Emergency service URN

    msg.add_header("Via", "SIP/2.0/" + config_.transport + " " + config_.local_ip + ";branch=z9hG4bK" + generate_tag());
    msg.add_header("Max-Forwards", "70");
    msg.add_header("To", "<" + config_.call_context.service_urn.urn + ">");
    msg.add_header("From", "<sip:" + config_.impu + "@" + config_.home_domain + ">;tag=" + from_tag_);
    msg.add_header("Call-ID", call_id_);
    msg.add_header("CSeq", std::to_string(cseq_++) + " INVITE");
    msg.add_header("Contact", contact_header_.empty() ? "<sip:" + config_.impu + "@" + config_.local_ip + ";transport=" + config_.transport + ">" : contact_header_);

    // Route set from registration
    if (!route_set_.empty()) {
        msg.add_header("Route", route_set_);
    }

    // Emergency call headers
    msg.add_header("Priority", "emergency");
    msg.add_header("Accept", "application/sdp, application/pidf+xml");
    msg.add_header("Supported", "100rel, timer, replaces, gruu");
    msg.add_header("Session-Expires", std::to_string(config_.session_timer));
    msg.add_header("Min-SE", std::to_string(config_.min_se));
    msg.add_header("User-Agent", "3GPP Test Suite Emergency Client");

    // P-Asserted-Identity (if available)
    msg.add_header("P-Asserted-Identity", "<sip:" + config_.impu + "@" + config_.home_domain + ">");

    // Location conveyance (RFC 6442)
    if (config_.include_location && config_.call_context.location.has_location()) {
        auto pidf = create_pidf_lo(config_.call_context.location);
        std::string cid = "cid:location@" + call_id_;
        msg.add_header("Geolocation", "<" + cid + ">;routing=yes;purpose=emergency");
        msg.add_header("Content-Disposition", "render");
        msg.add_header("Content-ID", "<location@" + call_id_ + ">");

        // Create multipart body with SDP + PIDF-LO
        std::string sdp = generate_sdp_offer();
        std::string multipart = create_multipart_body(sdp, pidf);
        msg.set_body(multipart, "multipart/mixed;boundary=boundary_" + generate_tag());
    } else {
        // Just SDP
        std::string sdp = generate_sdp_offer();
        msg.set_body(sdp, "application/sdp");
    }

    callbacks_.on_send_sip(msg);
}

void EmergencySession::handle_invite_response(const SipMessage& resp) {
    auto status_line = resp.request_uri;
    int status_code = 0;
    std::istringstream iss(status_line);
    std::string sip_ver;
    iss >> sip_ver >> status_code;

    if (status_code == 100) {
        // Trying
    } else if (status_code == 180 || status_code == 183) {
        // Ringing / Session Progress
        transition_state(EmergencySessionState::Alerting);

        // Parse SDP if present (183 Session Progress)
        if (status_code == 183 && resp.get_header("Content-Type").has_value()) {
            parse_sdp_answer(resp.body);
        }
    } else if (status_code == 200) {
        // OK - Call established
        transition_state(EmergencySessionState::Connected);

        // Parse SDP answer
        if (resp.get_header("Content-Type").has_value()) {
            parse_sdp_answer(resp.body);
        }

        // Extract session timer
        auto se = resp.get_header("Session-Expires");
        if (se) {
            size_t pos = se->find(';');
            std::string val = (pos != std::string::npos) ? se->substr(0, pos) : *se;
            session_timer_expires_ = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count() + std::stoul(val);
        }

        // Send ACK for 2xx response (per RFC 3261, UAC core generates ACK for 2xx)
        send_ack(resp);

        callbacks_.on_media_established(remote_sdp_);
    } else if (status_code >= 300) {
        // Error
        transition_state(EmergencySessionState::Failed);
        auto reason = resp.get_header("Reason");
        callbacks_.on_call_ended(reason.value_or("Call failed: " + std::to_string(status_code)));
    }
}

void EmergencySession::send_ack(const SipMessage& invite_resp) {
    SipMessage msg;
    msg.method = EmergencySipMethod::Ack;
    msg.request_uri = config_.call_context.service_urn.urn;

    msg.add_header("Via", "SIP/2.0/" + config_.transport + " " + config_.local_ip + ";branch=z9hG4bK" + generate_tag());
    msg.add_header("Max-Forwards", "70");
    msg.add_header("To", invite_resp.get_header("To").value_or(""));
    msg.add_header("From", "<sip:" + config_.impu + "@" + config_.home_domain + ">;tag=" + from_tag_);
    msg.add_header("Call-ID", call_id_);
    msg.add_header("CSeq", std::to_string(cseq_ - 1) + " ACK"); // Same CSeq as INVITE

    if (!route_set_.empty()) {
        msg.add_header("Route", route_set_);
    }

    callbacks_.on_send_sip(msg);
}

void EmergencySession::send_update_location(const LocationInfo& location) {
    SipMessage msg;
    msg.method = EmergencySipMethod::Update;
    msg.request_uri = config_.call_context.service_urn.urn;

    msg.add_header("Via", "SIP/2.0/" + config_.transport + " " + config_.local_ip + ";branch=z9hG4bK" + generate_tag());
    msg.add_header("Max-Forwards", "70");
    msg.add_header("To", "<" + config_.call_context.service_urn.urn + ">" + (to_tag_.empty() ? "" : ";tag=" + to_tag_));
    msg.add_header("From", "<sip:" + config_.impu + "@" + config_.home_domain + ">;tag=" + from_tag_);
    msg.add_header("Call-ID", call_id_);
    msg.add_header("CSeq", std::to_string(cseq_++) + " UPDATE");
    msg.add_header("Contact", contact_header_.empty() ? "<sip:" + config_.impu + "@" + config_.local_ip + ";transport=" + config_.transport + ">" : contact_header_);

    if (!route_set_.empty()) {
        msg.add_header("Route", route_set_);
    }

    // Location in PIDF-LO
    auto pidf = create_pidf_lo(location);
    std::string cid = "cid:location@" + call_id_;
    msg.add_header("Geolocation", "<" + cid + ">;routing=yes;purpose=emergency");
    msg.add_header("Content-ID", "<location@" + call_id_ + ">");

    std::string multipart = create_multipart_body("", pidf);
    msg.set_body(multipart, "multipart/mixed;boundary=boundary_" + generate_tag());

    callbacks_.on_send_sip(msg);
    callbacks_.on_location_update(location);
}

void EmergencySession::send_bye(const std::string& reason) {
    SipMessage msg;
    msg.method = EmergencySipMethod::Bye;
    msg.request_uri = config_.call_context.service_urn.urn;

    msg.add_header("Via", "SIP/2.0/" + config_.transport + " " + config_.local_ip + ";branch=z9hG4bK" + generate_tag());
    msg.add_header("Max-Forwards", "70");
    msg.add_header("To", "<" + config_.call_context.service_urn.urn + ">" + (to_tag_.empty() ? "" : ";tag=" + to_tag_));
    msg.add_header("From", "<sip:" + config_.impu + "@" + config_.home_domain + ">;tag=" + from_tag_);
    msg.add_header("Call-ID", call_id_);
    msg.add_header("CSeq", std::to_string(cseq_++) + " BYE");
    msg.add_header("Reason", "SIP;cause=200;text=\"" + reason + "\"");

    if (!route_set_.empty()) {
        msg.add_header("Route", route_set_);
    }

    callbacks_.on_send_sip(msg);
    transition_state(EmergencySessionState::Releasing);
}

PidfLo EmergencySession::create_pidf_lo(const LocationInfo& loc) const {
    PidfLo pidf;
    pidf.entity = "sip:" + config_.impu + "@" + config_.home_domain;
    pidf.id = generate_tag();
    pidf.location = loc;
    pidf.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    pidf.method = "GPS";
    pidf.confidence = 0.95f;
    return pidf;
}

std::string EmergencySession::create_multipart_body(const std::string& sdp, const PidfLo& pidf) const {
    std::string boundary = "boundary_" + generate_tag();
    std::ostringstream oss;

    // SDP part
    if (!sdp.empty()) {
        oss << "--" << boundary << "\r\n";
        oss << "Content-Type: application/sdp\r\n";
        oss << "Content-Disposition: session\r\n\r\n";
        oss << sdp << "\r\n";
    }

    // PIDF-LO part
    oss << "--" << boundary << "\r\n";
    oss << "Content-Type: application/pidf+xml\r\n";
    oss << "Content-ID: <location@" << call_id_ << ">\r\n";
    oss << "Content-Disposition: render\r\n\r\n";
    oss << pidf.to_xml() << "\r\n";

    oss << "--" << boundary << "--\r\n";

    return oss.str();
}

std::string EmergencySession::generate_sdp_offer() const {
    std::ostringstream oss;
    uint64_t sess_id = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    uint64_t sess_ver = sess_id;

    oss << "v=0\r\n";
    oss << "o=- " << sess_id << " " << sess_ver << " IN IP4 " << config_.local_ip << "\r\n";
    oss << "s=Emergency Call\r\n";
    oss << "c=IN IP4 " << config_.local_ip << "\r\n";
    oss << "t=0 0\r\n";
    oss << "m=audio " << config_.rtp_port_base << " RTP/AVP ";

    for (size_t i = 0; i < config_.codecs.size(); ++i) {
        if (config_.codecs[i] == "AMR-WB") oss << "97";
        else if (config_.codecs[i] == "AMR") oss << "98";
        else if (config_.codecs[i] == "EVS") oss << "99";
        if (i + 1 < config_.codecs.size()) oss << " ";
    }
    oss << "\r\n";

    // Codec attributes
    for (const auto& codec : config_.codecs) {
        if (codec == "AMR-WB") {
            oss << "a=rtpmap:97 AMR-WB/16000/1\r\n";
            oss << "a=fmtp:97 mode-change-capability=2;max-red=220\r\n";
        } else if (codec == "AMR") {
            oss << "a=rtpmap:98 AMR/8000/1\r\n";
            oss << "a=fmtp:98 mode-change-capability=2;max-red=220\r\n";
        } else if (codec == "EVS") {
            oss << "a=rtpmap:99 EVS/16000/1\r\n";
            oss << "a=fmtp:99 br=5.9-13.2;bw=nb-wb;mode-set=0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15\r\n";
        }
    }

    oss << "a=ptime:20\r\n";
    oss << "a=maxptime:240\r\n";
    oss << "a=sendrecv\r\n";

    // ICE attributes (if ICE agent available)
    // Would be added by ICE agent callback

    return oss.str();
}

void EmergencySession::parse_sdp_answer(const std::string& sdp) {
    remote_sdp_ = sdp;
    media_established_ = true;

    // Parse remote ICE candidates, fingerprints, etc.
    // Simplified - in production use proper SDP parser
}

std::string EmergencySession::generate_call_id() const {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX);
    return std::to_string(dist(gen)) + "@" + config_.local_ip;
}

std::string EmergencySession::generate_tag() const {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);
    std::ostringstream oss;
    oss << std::hex << dist(gen);
    return oss.str();
}

void EmergencySession::transition_state(EmergencySessionState new_state) {
    if (state_ != new_state) {
        state_ = new_state;
        callbacks_.on_state_change(new_state);
    }
}

// ============================================================================
// EmergencyRegistrationManager Implementation
// ============================================================================

EmergencyRegistrationManager::EmergencyRegistrationManager(const RegistrationInfo& info,
                                                            SendCallback send_cb,
                                                            StateCallback state_cb)
    : info_(info), send_cb_(std::move(send_cb)), state_cb_(std::move(state_cb)) {
    call_id_ = generate_call_id();
    from_tag_ = generate_tag();
}

void EmergencyRegistrationManager::start() {
    send_register();
}

void EmergencyRegistrationManager::handle_response(const SipMessage& resp) {
    auto status_line = resp.request_uri;
    int status_code = 0;
    std::istringstream iss(status_line);
    std::string sip_ver;
    iss >> sip_ver >> status_code;

    if (status_code == 200) {
        auto record_route = resp.get_header("Record-Route");
        if (record_route) route_set_ = *record_route;

        auto contact = resp.get_header("Contact");
        if (contact) contact_ = *contact;

        auto expires = resp.get_header("Expires");
        if (expires) {
            uint32_t exp = std::stoul(*expires);
            expiry_time_ = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count() + exp;
        } else {
            expiry_time_ = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count() + info_.expires;
        }

        registered_ = true;
        state_cb_(true, "Registered");
        schedule_re_register();
    } else if (status_code == 401 || status_code == 407) {
        // Authentication needed - would retry with credentials
        state_cb_(false, "Authentication required");
    } else {
        state_cb_(false, "Registration failed: " + std::to_string(status_code));
    }
}

void EmergencyRegistrationManager::handle_request(const SipMessage& req) {
    // Handle re-registration from network
    if (req.method == EmergencySipMethod::Register) {
        // Send 200 OK
        SipMessage resp;
        resp.request_uri = "SIP/2.0 200 OK";
        resp.add_header("Via", req.get_header("Via").value_or(""));
        resp.add_header("To", req.get_header("To").value_or("") + ";tag=" + generate_tag());
        resp.add_header("From", req.get_header("From").value_or(""));
        resp.add_header("Call-ID", req.get_header("Call-ID").value_or(""));
        resp.add_header("CSeq", req.get_header("CSeq").value_or(""));
        resp.add_header("Contact", contact_);
        resp.add_header("Expires", std::to_string(info_.expires));
        send_cb_(resp);
    }
}

void EmergencyRegistrationManager::stop() {
    registered_ = false;
    state_cb_(false, "Stopped");
}

void EmergencyRegistrationManager::tick(uint64_t now_sec) {
    if (registered_ && now_sec >= expiry_time_ - 60) {
        send_register();
    }
}

void EmergencyRegistrationManager::send_register() {
    SipMessage msg;
    msg.method = EmergencySipMethod::Register;
    msg.request_uri = "sip:" + info_.home_domain;

    msg.add_header("Via", "SIP/2.0/" + info_.transport + " " + info_.pcscf_addr + ";branch=z9hG4bK" + generate_tag());
    msg.add_header("Max-Forwards", "70");
    msg.add_header("To", "<sip:" + info_.impi + "@" + info_.home_domain + ">");
    msg.add_header("From", "<sip:" + info_.impi + "@" + info_.home_domain + ">;tag=" + from_tag_);
    msg.add_header("Call-ID", call_id_);
    msg.add_header("CSeq", std::to_string(cseq_++) + " REGISTER");
    msg.add_header("Contact", "<sip:" + info_.impu + "@" + info_.pcscf_addr + ";transport=" + info_.transport + ">;+sip.instance=\"<urn:gsma:imei:000000000000000>\";reg-id=1");
    msg.add_header("Expires", std::to_string(info_.expires));
    msg.add_header("Supported", "path, gruu, outbound");
    msg.add_header("User-Agent", "3GPP Test Suite Emergency Client");
    msg.add_header("P-Access-Network-Info", "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=00000000");

    if (info_.emergency_only) {
        msg.add_header("P-Emergency-Info", "emergency");
    }

    send_cb_(msg);
}

void EmergencyRegistrationManager::schedule_re_register() {
    // Re-registration happens automatically in tick()
}

std::string EmergencyRegistrationManager::generate_call_id() const {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX);
    return std::to_string(dist(gen)) + "@" + info_.pcscf_addr;
}

std::string EmergencyRegistrationManager::generate_tag() const {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);
    std::ostringstream oss;
    oss << std::hex << dist(gen);
    return oss.str();
}

} // namespace gpp::emergency
