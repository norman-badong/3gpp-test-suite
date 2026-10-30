#include "3gpp/emergency/TurnMessage.hpp"
#include "3gpp/common/ByteStream.hpp"
#include <random>
#include <chrono>
#include <algorithm>
#include <cstring>

namespace gpp::emergency {

// ============================================================================
// TurnChannelData Implementation
// ============================================================================

std::vector<uint8_t> TurnChannelData::encode() const {
    common::ByteStreamWriter writer;
    writer.write_u16(channel_number);
    writer.write_u16(length);
    writer.write_bytes(data);
    return writer.take_data();
}

std::optional<TurnChannelData> TurnChannelData::decode(std::span<const uint8_t> data, size_t& offset) {
    if (offset + 4 > data.size()) return std::nullopt;

    common::ByteStreamReader reader(data.subspan(offset));
    TurnChannelData ch;
    ch.channel_number = reader.read_u16();
    ch.length = reader.read_u16();

    if (offset + 4 + ch.length > data.size()) return std::nullopt;

    ch.data.assign(data.subspan(offset + 4, ch.length).begin(), data.subspan(offset + 4, ch.length).end());
    offset += 4 + ch.length;
    return ch;
}

// ============================================================================
// Turn5Tuple Implementation
// ============================================================================

bool Turn5Tuple::operator==(const Turn5Tuple& other) const {
    return protocol == other.protocol &&
           server_addr.port == other.server_addr.port &&
           server_addr.addr == other.server_addr.addr &&
           relayed_addr.port == other.relayed_addr.port &&
           relayed_addr.addr == other.relayed_addr.addr &&
           peer_addr.port == other.peer_addr.port &&
           peer_addr.addr == other.peer_addr.addr;
}

// ============================================================================
// TurnClient Implementation
// ============================================================================

TurnClient::TurnClient(const TurnServerConfig& config) : config_(config) {}

std::array<uint8_t, 12> TurnClient::generate_transaction_id() {
    std::array<uint8_t, 12> tid{};
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX);
    uint64_t v1 = dist(gen);
    uint32_t v2 = static_cast<uint32_t>(dist(gen));
    std::memcpy(tid.data(), &v1, 8);
    std::memcpy(tid.data() + 8, &v2, 4);
    return tid;
}

StunMessage TurnClient::create_allocate_request(uint32_t lifetime, bool even_port, StunTransportProtocol proto) {
    StunMessage msg;
    msg.header.msg_type = StunMessageType::AllocateRequest;
    msg.header.transaction_id = generate_transaction_id();

    msg.add_requested_transport(proto);
    msg.add_lifetime(lifetime);
    if (even_port) msg.add_even_port();

    msg.add_fingerprint();
    return msg;
}

bool TurnClient::handle_allocate_response(const StunMessage& resp, TurnAllocation& allocation) {
    if (resp.header.msg_type != StunMessageType::AllocateResponse) {
        if (resp.header.msg_type == StunMessageType::AllocateErrorResponse) {
            auto err = resp.get_error_code();
            // Handle error
        }
        return false;
    }

    auto relayed = resp.get_xor_relayed_address();
    auto mapped = resp.get_xor_mapped_address();
    auto lifetime = resp.get_lifetime();

    if (relayed) allocation.relayed_address = *relayed;
    if (mapped) allocation.mapped_address = *mapped;
    if (lifetime) allocation.lifetime = *lifetime;

    allocation.state = TurnAllocationState::Allocated;
    allocation.username = config_.username;
    allocation.realm = config_.realm;
    allocation.nonce = config_.nonce;

    return true;
}

StunMessage TurnClient::create_refresh_request(const TurnAllocation& alloc, uint32_t lifetime) {
    StunMessage msg;
    msg.header.msg_type = StunMessageType::RefreshRequest;
    msg.header.transaction_id = generate_transaction_id();

    if (lifetime > 0) msg.add_lifetime(lifetime);
    msg.add_username(alloc.username);

    // Add MESSAGE-INTEGRITY
    auto key = compute_message_integrity_key();
    msg.add_message_integrity(key);
    msg.add_fingerprint();
    return msg;
}

StunMessage TurnClient::create_permission_request(const TurnAllocation& alloc, const StunXorAddress& peer_addr) {
    StunMessage msg;
    msg.header.msg_type = StunMessageType::CreatePermissionRequest;
    msg.header.transaction_id = generate_transaction_id();

    // Add XOR-PEER-ADDRESS
    StunAttribute attr;
    attr.type = StunAttributeType::XorPeerAddress;
    common::ByteStreamWriter writer;
    writer.write_u8(0);
    writer.write_u8(static_cast<uint8_t>(peer_addr.family));
    uint16_t xor_port = peer_addr.port ^ 0x2112;
    writer.write_u16(xor_port);
    if (peer_addr.family == StunAddressFamily::IPv4) {
        uint32_t ip = (static_cast<uint32_t>(peer_addr.addr[12]) << 24) |
                      (static_cast<uint32_t>(peer_addr.addr[13]) << 16) |
                      (static_cast<uint32_t>(peer_addr.addr[14]) << 8) |
                      static_cast<uint32_t>(peer_addr.addr[15]);
        uint32_t xor_ip = ip ^ 0x2112A442;
        writer.write_u32(xor_ip);
    } else {
        for (int i = 0; i < 16; i += 4) {
            uint32_t word = (static_cast<uint32_t>(peer_addr.addr[i]) << 24) |
                            (static_cast<uint32_t>(peer_addr.addr[i+1]) << 16) |
                            (static_cast<uint32_t>(peer_addr.addr[i+2]) << 8) |
                            static_cast<uint32_t>(peer_addr.addr[i+3]);
            uint32_t xor_word = word ^ 0x2112A442;
            writer.write_u32(xor_word);
        }
    }
    attr.value = writer.take_data();
    msg.add_attribute(attr);

    msg.add_username(alloc.username);
    auto key = compute_message_integrity_key();
    msg.add_message_integrity(key);
    msg.add_fingerprint();
    return msg;
}

StunMessage TurnClient::create_channel_bind_request(const TurnAllocation& alloc,
                                                     uint16_t channel_number,
                                                     const StunXorAddress& peer_addr) {
    StunMessage msg;
    msg.header.msg_type = StunMessageType::ChannelBindRequest;
    msg.header.transaction_id = generate_transaction_id();

    msg.add_channel_number(channel_number);

    // Add XOR-PEER-ADDRESS
    StunAttribute attr;
    attr.type = StunAttributeType::XorPeerAddress;
    common::ByteStreamWriter writer;
    writer.write_u8(0);
    writer.write_u8(static_cast<uint8_t>(peer_addr.family));
    uint16_t xor_port = peer_addr.port ^ 0x2112;
    writer.write_u16(xor_port);
    if (peer_addr.family == StunAddressFamily::IPv4) {
        uint32_t ip = (static_cast<uint32_t>(peer_addr.addr[12]) << 24) |
                      (static_cast<uint32_t>(peer_addr.addr[13]) << 16) |
                      (static_cast<uint32_t>(peer_addr.addr[14]) << 8) |
                      static_cast<uint32_t>(peer_addr.addr[15]);
        uint32_t xor_ip = ip ^ 0x2112A442;
        writer.write_u32(xor_ip);
    } else {
        for (int i = 0; i < 16; i += 4) {
            uint32_t word = (static_cast<uint32_t>(peer_addr.addr[i]) << 24) |
                            (static_cast<uint32_t>(peer_addr.addr[i+1]) << 16) |
                            (static_cast<uint32_t>(peer_addr.addr[i+2]) << 8) |
                            static_cast<uint32_t>(peer_addr.addr[i+3]);
            uint32_t xor_word = word ^ 0x2112A442;
            writer.write_u32(xor_word);
        }
    }
    attr.value = writer.take_data();
    msg.add_attribute(attr);

    msg.add_username(alloc.username);
    auto key = compute_message_integrity_key();
    msg.add_message_integrity(key);
    msg.add_fingerprint();
    return msg;
}

TurnChannelData TurnClient::create_channel_data(uint16_t channel_number, const std::vector<uint8_t>& app_data) {
    TurnChannelData ch;
    ch.channel_number = channel_number;
    ch.length = static_cast<uint16_t>(app_data.size());
    ch.data = app_data;
    return ch;
}

StunMessage TurnClient::create_send_indication(const TurnAllocation& alloc,
                                                const StunXorAddress& peer_addr,
                                                const std::vector<uint8_t>& app_data) {
    StunMessage msg;
    msg.header.msg_type = StunMessageType::BindingIndication; // Send indication uses indication class
    msg.header.transaction_id = generate_transaction_id();

    // XOR-PEER-ADDRESS
    StunAttribute attr;
    attr.type = StunAttributeType::XorPeerAddress;
    common::ByteStreamWriter writer;
    writer.write_u8(0);
    writer.write_u8(static_cast<uint8_t>(peer_addr.family));
    uint16_t xor_port = peer_addr.port ^ 0x2112;
    writer.write_u16(xor_port);
    if (peer_addr.family == StunAddressFamily::IPv4) {
        uint32_t ip = (static_cast<uint32_t>(peer_addr.addr[12]) << 24) |
                      (static_cast<uint32_t>(peer_addr.addr[13]) << 16) |
                      (static_cast<uint32_t>(peer_addr.addr[14]) << 8) |
                      static_cast<uint32_t>(peer_addr.addr[15]);
        uint32_t xor_ip = ip ^ 0x2112A442;
        writer.write_u32(xor_ip);
    } else {
        for (int i = 0; i < 16; i += 4) {
            uint32_t word = (static_cast<uint32_t>(peer_addr.addr[i]) << 24) |
                            (static_cast<uint32_t>(peer_addr.addr[i+1]) << 16) |
                            (static_cast<uint32_t>(peer_addr.addr[i+2]) << 8) |
                            static_cast<uint32_t>(peer_addr.addr[i+3]);
            uint32_t xor_word = word ^ 0x2112A442;
            writer.write_u32(xor_word);
        }
    }
    attr.value = writer.take_data();
    msg.add_attribute(attr);

    // DATA
    msg.add_data(app_data);
    msg.add_fingerprint();
    return msg;
}

std::optional<TurnChannelData> TurnClient::parse_channel_data(std::span<const uint8_t> data) {
    size_t offset = 0;
    return TurnChannelData::decode(data, offset);
}

std::optional<std::pair<StunXorAddress, std::vector<uint8_t>>> TurnClient::parse_data_indication(const StunMessage& msg) {
    if (msg.header.msg_type != StunMessageType::BindingIndication) return std::nullopt;

    auto peer = msg.get_xor_peer_address();
    auto data = msg.get_data();

    if (peer && data) {
        return std::make_pair(*peer, *data);
    }
    return std::nullopt;
}

std::vector<uint8_t> TurnClient::compute_message_integrity_key() const {
    // Long-term credential: key = SASLprep(username) ":" SASLprep(realm) ":" SASLprep(password)
    // For simplicity, using raw strings (production should use SASLprep)
    std::string key_str = config_.username + ":" + config_.realm + ":" + config_.password;
    return std::vector<uint8_t>(key_str.begin(), key_str.end());
}

// ============================================================================
// TurnServer Implementation
// ============================================================================

TurnServer::TurnServer(const TurnServerConfig& config) : config_(config) {}

std::optional<StunMessage> TurnServer::handle_request(const StunMessage& req,
                                                       const StunXorAddress& client_addr,
                                                       AllocationRecord& record) {
    switch (req.header.msg_type) {
        case StunMessageType::AllocateRequest:
            return handle_allocate(req, client_addr, record);
        case StunMessageType::RefreshRequest:
            return handle_refresh(req, record);
        case StunMessageType::CreatePermissionRequest:
            return handle_create_permission(req, record);
        case StunMessageType::ChannelBindRequest:
            return handle_channel_bind(req, record);
        default:
            return std::nullopt;
    }
}

std::optional<TurnChannelData> TurnServer::handle_channel_data(const TurnChannelData& chdata,
                                                                AllocationRecord& record) {
    // Find permission for this channel
    auto it = std::find_if(record.allocation.permissions.begin(), record.allocation.permissions.end(),
                          [chdata](const Turn5Tuple& p) { return p.channel_number == chdata.channel_number; });

    if (it == record.allocation.permissions.end()) {
        // No permission - drop silently per RFC 8656
        return std::nullopt;
    }

    record.last_activity = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    // Forward to peer (in real implementation, send via socket)
    // For now, just return the data for the caller to forward
    return chdata;
}

void TurnServer::cleanup_expired(uint64_t current_time) {
    allocations_.erase(
        std::remove_if(allocations_.begin(), allocations_.end(),
                       [current_time](const AllocationRecord& r) {
                           return current_time > r.creation_time + r.allocation.lifetime + 60; // Grace period
                       }),
        allocations_.end());
}

std::optional<StunMessage> TurnServer::handle_allocate(const StunMessage& req,
                                                        const StunXorAddress& client_addr,
                                                        AllocationRecord& record) {
    // Check if allocation already exists for this client
    if (record.allocation.state == TurnAllocationState::Allocated) {
        // Return existing allocation
        StunMessage resp = StunMessage::create_binding_response(req, record.allocation.relayed_address);
        resp.header.msg_type = StunMessageType::AllocateResponse;
        resp.add_xor_relayed_address(record.allocation.relayed_address);
        resp.add_xor_mapped_address(record.allocation.mapped_address);
        resp.add_lifetime(record.allocation.lifetime);
        resp.add_fingerprint();
        return resp;
    }

    // Parse requested transport
    auto transport = req.get_requested_transport();
    if (!transport || *transport != StunTransportProtocol::UDP) {
        StunErrorCode err = StunErrorCode::from_full(442); // Unsupported Transport Protocol
        return StunMessage::create_binding_error_response(req, err);
    }

    // Parse lifetime
    uint32_t lifetime = TURN_DEFAULT_ALLOCATION_LIFETIME;
    if (auto lt = req.get_lifetime()) {
        lifetime = std::min(*lt, config_.default_lifetime);
    }

    // Allocate relay address
    StunXorAddress relayed = allocate_relay_address();

    // Create allocation record
    record.allocation.relayed_address = relayed;
    record.allocation.mapped_address = client_addr;
    record.allocation.lifetime = lifetime;
    record.allocation.state = TurnAllocationState::Allocated;
    record.creation_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    record.last_activity = record.creation_time;

    // Get credentials
    auto username = req.get_username();
    auto realm = req.get_realm();
    auto nonce = req.get_nonce();

    if (username) record.client_username = *username;
    if (realm) record.client_realm = *realm;
    if (nonce) record.allocation.nonce = *nonce;

    // Build response
    StunMessage resp;
    resp.header.msg_type = StunMessageType::AllocateResponse;
    resp.header.transaction_id = req.header.transaction_id;
    resp.add_xor_relayed_address(relayed);
    resp.add_xor_mapped_address(client_addr);
    resp.add_lifetime(lifetime);
    resp.add_fingerprint();

    return resp;
}

std::optional<StunMessage> TurnServer::handle_refresh(const StunMessage& req, AllocationRecord& record) {
    if (record.allocation.state != TurnAllocationState::Allocated) {
        StunErrorCode err = StunErrorCode::from_full(437); // Allocation Mismatch
        return StunMessage::create_binding_error_response(req, err);
    }

    // Verify credentials
    if (!verify_credentials(req, record)) {
        StunErrorCode err = StunErrorCode::from_full(401); // Unauthorized
        return StunMessage::create_binding_error_response(req, err);
    }

    // Parse lifetime
    uint32_t lifetime = TURN_DEFAULT_ALLOCATION_LIFETIME;
    if (auto lt = req.get_lifetime()) {
        lifetime = std::min(*lt, config_.default_lifetime);
    }

    record.allocation.lifetime = lifetime;
    record.last_activity = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    StunMessage resp;
    resp.header.msg_type = StunMessageType::RefreshResponse;
    resp.header.transaction_id = req.header.transaction_id;
    resp.add_lifetime(lifetime);
    resp.add_fingerprint();
    return resp;
}

std::optional<StunMessage> TurnServer::handle_create_permission(const StunMessage& req, AllocationRecord& record) {
    if (record.allocation.state != TurnAllocationState::Allocated) {
        StunErrorCode err = StunErrorCode::from_full(437);
        return StunMessage::create_binding_error_response(req, err);
    }

    if (!verify_credentials(req, record)) {
        StunErrorCode err = StunErrorCode::from_full(401);
        return StunMessage::create_binding_error_response(req, err);
    }

    // Parse XOR-PEER-ADDRESS
    auto peer_addr = req.get_xor_peer_address();
    if (!peer_addr) {
        StunErrorCode err = StunErrorCode::from_full(400); // Bad Request
        return StunMessage::create_binding_error_response(req, err);
    }

    // Add permission
    Turn5Tuple perm;
    perm.protocol = StunTransportProtocol::UDP;
    perm.server_addr = record.allocation.relayed_address;
    perm.relayed_addr = record.allocation.relayed_address;
    perm.peer_addr = *peer_addr;
    perm.channel_number = 0;

    // Check if permission already exists
    auto it = std::find(record.allocation.permissions.begin(), record.allocation.permissions.end(), perm);
    if (it == record.allocation.permissions.end()) {
        record.allocation.permissions.push_back(perm);
    }

    record.last_activity = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    StunMessage resp;
    resp.header.msg_type = StunMessageType::CreatePermissionResponse;
    resp.header.transaction_id = req.header.transaction_id;
    resp.add_fingerprint();
    return resp;
}

std::optional<StunMessage> TurnServer::handle_channel_bind(const StunMessage& req, AllocationRecord& record) {
    if (record.allocation.state != TurnAllocationState::Allocated) {
        StunErrorCode err = StunErrorCode::from_full(437);
        return StunMessage::create_binding_error_response(req, err);
    }

    if (!verify_credentials(req, record)) {
        StunErrorCode err = StunErrorCode::from_full(401);
        return StunMessage::create_binding_error_response(req, err);
    }

    auto channel = req.get_channel_number();
    auto peer_addr = req.get_xor_peer_address();

    if (!channel || !peer_addr) {
        StunErrorCode err = StunErrorCode::from_full(400);
        return StunMessage::create_binding_error_response(req, err);
    }

    if (*channel < TURN_CHANNEL_MIN || *channel > TURN_CHANNEL_MAX) {
        StunErrorCode err = StunErrorCode::from_full(400);
        return StunMessage::create_binding_error_response(req, err);
    }

    // Update or create permission with channel binding
    Turn5Tuple perm;
    perm.protocol = StunTransportProtocol::UDP;
    perm.server_addr = record.allocation.relayed_address;
    perm.relayed_addr = record.allocation.relayed_address;
    perm.peer_addr = *peer_addr;
    perm.channel_number = *channel;

    auto it = std::find(record.allocation.permissions.begin(), record.allocation.permissions.end(), perm);
    if (it == record.allocation.permissions.end()) {
        record.allocation.permissions.push_back(perm);
    } else {
        it->channel_number = *channel;
    }

    record.last_activity = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    StunMessage resp;
    resp.header.msg_type = StunMessageType::ChannelBindResponse;
    resp.header.transaction_id = req.header.transaction_id;
    resp.add_fingerprint();
    return resp;
}

bool TurnServer::verify_credentials(const StunMessage& req, const AllocationRecord& record) const {
    if (!config_.require_message_integrity) return true;

    auto username = req.get_username();
    if (!username || *username != record.client_username) return false;

    // In real implementation, verify MESSAGE-INTEGRITY HMAC
    // For now, just check username matches
    return true;
}

StunXorAddress TurnServer::allocate_relay_address() {
    // In real implementation, allocate from pool
    // For demo, use a fixed address in the private range
    static uint16_t port_base = 50000;
    return StunXorAddress::from_ipv4(0xC0A80064, port_base++); // 192.168.0.100
}

} // namespace gpp::emergency