#include <3gpp/rrc/RrcMessage.hpp>

namespace gpp::rrc {

// ─── RrcSetupRequest ────────────────────────────────────────────────────────

std::vector<uint8_t> RrcSetupRequest::encode() const {
    AperWriter w;
    w.write_choice_index(static_cast<uint32_t>(ue_identity_type), 2, false);
    w.write_bit_string(ue_identity_val, 39);
    w.write_enumerated(static_cast<uint32_t>(establishment_cause), 8, false);
    w.write_boolean(spare);
    w.align_to_byte();
    return w.bytes();
}

RrcSetupRequest RrcSetupRequest::decode(std::span<const uint8_t> data) {
    AperReader r(data);
    RrcSetupRequest req;
    req.ue_identity_type = static_cast<InitialUeIdentityType>(r.read_choice_index(2, false));
    req.ue_identity_val = r.read_bit_string(39);
    req.establishment_cause = static_cast<EstablishmentCause>(r.read_enumerated(8, false));
    req.spare = r.read_boolean();
    return req;
}

// ─── RrcSetup ───────────────────────────────────────────────────────────────

std::vector<uint8_t> RrcSetup::encode() const {
    AperWriter w;
    w.write_constrained_integer(rrc_transaction_id, 0, 3);
    w.write_constrained_integer(srb_identity, 1, 3);
    w.write_enumerated(static_cast<uint32_t>(rlc_mode), 4, false);
    w.write_octet_string(master_cell_group);
    w.align_to_byte();
    return w.bytes();
}

RrcSetup RrcSetup::decode(std::span<const uint8_t> data) {
    AperReader r(data);
    RrcSetup setup;
    setup.rrc_transaction_id = static_cast<uint8_t>(r.read_constrained_integer(0, 3));
    setup.srb_identity = static_cast<uint8_t>(r.read_constrained_integer(1, 3));
    setup.rlc_mode = static_cast<RlcMode>(r.read_enumerated(4, false));
    setup.master_cell_group = r.read_octet_string();
    return setup;
}

// ─── RrcSetupComplete ───────────────────────────────────────────────────────

std::vector<uint8_t> RrcSetupComplete::encode() const {
    AperWriter w;
    w.write_constrained_integer(rrc_transaction_id, 0, 3);
    w.write_constrained_integer(selected_plmn_identity, 1, 6);
    w.write_octet_string(dedicated_nas_message);
    w.align_to_byte();
    return w.bytes();
}

RrcSetupComplete RrcSetupComplete::decode(std::span<const uint8_t> data) {
    AperReader r(data);
    RrcSetupComplete comp;
    comp.rrc_transaction_id = static_cast<uint8_t>(r.read_constrained_integer(0, 3));
    comp.selected_plmn_identity = static_cast<uint8_t>(r.read_constrained_integer(1, 6));
    comp.dedicated_nas_message = r.read_octet_string();
    return comp;
}

// ─── RrcReconfiguration ─────────────────────────────────────────────────────

std::vector<uint8_t> RrcReconfiguration::encode() const {
    AperWriter w;
    w.write_constrained_integer(rrc_transaction_id, 0, 3);
    w.write_constrained_integer(drb_identity, 1, 32);
    w.write_constrained_integer(qfi, 1, 64);
    w.write_octet_string(secondary_cell_group);
    w.align_to_byte();
    return w.bytes();
}

RrcReconfiguration RrcReconfiguration::decode(std::span<const uint8_t> data) {
    AperReader r(data);
    RrcReconfiguration reconf;
    reconf.rrc_transaction_id = static_cast<uint8_t>(r.read_constrained_integer(0, 3));
    reconf.drb_identity = static_cast<uint8_t>(r.read_constrained_integer(1, 32));
    reconf.qfi = static_cast<uint8_t>(r.read_constrained_integer(1, 64));
    reconf.secondary_cell_group = r.read_octet_string();
    return reconf;
}

// ─── RrcReconfigurationComplete ─────────────────────────────────────────────

std::vector<uint8_t> RrcReconfigurationComplete::encode() const {
    AperWriter w;
    w.write_constrained_integer(rrc_transaction_id, 0, 3);
    w.align_to_byte();
    return w.bytes();
}

RrcReconfigurationComplete RrcReconfigurationComplete::decode(std::span<const uint8_t> data) {
    AperReader r(data);
    RrcReconfigurationComplete comp;
    comp.rrc_transaction_id = static_cast<uint8_t>(r.read_constrained_integer(0, 3));
    return comp;
}

} // namespace gpp::rrc
