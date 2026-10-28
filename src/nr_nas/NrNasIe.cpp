#include <3gpp/nr_nas/NrNasIe.hpp>
#include <stdexcept>
#include <sstream>

namespace gpp::nr_nas {

namespace {

// Helper to encode PLMN (MCC + MNC) into 3 bytes
std::array<uint8_t, 3> encode_plmn(const std::string& mcc, const std::string& mnc) {
    if (mcc.size() != 3 || (mnc.size() != 2 && mnc.size() != 3)) {
        throw std::invalid_argument("Invalid MCC/MNC length");
    }
    uint8_t mcc1 = static_cast<uint8_t>(mcc[0] - '0');
    uint8_t mcc2 = static_cast<uint8_t>(mcc[1] - '0');
    uint8_t mcc3 = static_cast<uint8_t>(mcc[2] - '0');

    uint8_t mnc1 = static_cast<uint8_t>(mnc[0] - '0');
    uint8_t mnc2 = static_cast<uint8_t>(mnc[1] - '0');
    uint8_t mnc3 = (mnc.size() == 3) ? static_cast<uint8_t>(mnc[2] - '0') : 0x0F;

    std::array<uint8_t, 3> bytes{};
    bytes[0] = static_cast<uint8_t>((mcc2 << 4) | (mcc1 & 0x0F));
    bytes[1] = static_cast<uint8_t>((mnc3 << 4) | (mcc3 & 0x0F));
    bytes[2] = static_cast<uint8_t>((mnc2 << 4) | (mnc1 & 0x0F));
    return bytes;
}

// Helper to decode PLMN (MCC + MNC) from 3 bytes
void decode_plmn(std::span<const uint8_t> data, std::string& mcc, std::string& mnc) {
    if (data.size() < 3) {
        throw std::runtime_error("Truncated PLMN data");
    }
    uint8_t mcc1 = data[0] & 0x0F;
    uint8_t mcc2 = (data[0] >> 4) & 0x0F;
    uint8_t mcc3 = data[1] & 0x0F;
    uint8_t mnc3 = (data[1] >> 4) & 0x0F;
    uint8_t mnc1 = data[2] & 0x0F;
    uint8_t mnc2 = (data[2] >> 4) & 0x0F;

    mcc.clear();
    mcc.push_back(static_cast<char>('0' + mcc1));
    mcc.push_back(static_cast<char>('0' + mcc2));
    mcc.push_back(static_cast<char>('0' + mcc3));

    mnc.clear();
    mnc.push_back(static_cast<char>('0' + mnc1));
    mnc.push_back(static_cast<char>('0' + mnc2));
    if (mnc3 != 0x0F) {
        mnc.push_back(static_cast<char>('0' + mnc3));
    }
}

} // namespace

// ─── Suci ───────────────────────────────────────────────────────────────────

std::vector<uint8_t> Suci::encode() const {
    std::vector<uint8_t> val;
    val.reserve(16);

    bool odd = (msin.size() % 2) != 0;
    uint8_t type_byte = (odd ? 0x08 : 0x00) | 0x01; // type 001 = SUCI
    val.push_back(type_byte);

    auto plmn = encode_plmn(mcc, mnc);
    val.push_back(plmn[0]);
    val.push_back(plmn[1]);
    val.push_back(plmn[2]);

    // Routing indicator (2 octets)
    val.push_back(static_cast<uint8_t>(routing_indicator >> 8));
    val.push_back(static_cast<uint8_t>(routing_indicator & 0xFF));

    // Protection scheme & public key ID
    val.push_back(protection_scheme);
    val.push_back(home_network_pki);

    // Scheme output (MSIN digits BCD packed)
    size_t idx = 0;
    while (idx < msin.size()) {
        uint8_t low = static_cast<uint8_t>(msin[idx] - '0');
        uint8_t high = 0x0F;
        if (idx + 1 < msin.size()) {
            high = static_cast<uint8_t>(msin[idx + 1] - '0');
        }
        val.push_back(static_cast<uint8_t>((high << 4) | (low & 0x0F)));
        idx += 2;
    }

    uint16_t len = static_cast<uint16_t>(val.size());
    std::vector<uint8_t> out;
    out.reserve(2 + len);
    out.push_back(static_cast<uint8_t>(len >> 8));
    out.push_back(static_cast<uint8_t>(len & 0xFF));
    out.insert(out.end(), val.begin(), val.end());
    return out;
}

Suci Suci::decode(std::span<const uint8_t> data, size_t& offset) {
    if (data.size() < offset + 2) {
        throw std::runtime_error("SUCI length truncated");
    }
    uint16_t len = static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
    offset += 2;
    if (data.size() < offset + len || len < 8) {
        throw std::runtime_error("SUCI value truncated");
    }

    Suci res;
    uint8_t type_byte = data[offset];
    if ((type_byte & 0x07) != 0x01) {
        throw std::runtime_error("Mobile Identity is not SUCI");
    }

    decode_plmn(data.subspan(offset + 1, 3), res.mcc, res.mnc);

    res.routing_indicator = static_cast<uint16_t>((data[offset + 4] << 8) | data[offset + 5]);
    res.protection_scheme = data[offset + 6];
    res.home_network_pki = data[offset + 7];

    res.msin.clear();
    for (size_t i = 8; i < len; ++i) {
        uint8_t b = data[offset + i];
        uint8_t low = b & 0x0F;
        uint8_t high = (b >> 4) & 0x0F;
        if (low != 0x0F) {
            res.msin.push_back(static_cast<char>('0' + low));
        }
        if (high != 0x0F) {
            res.msin.push_back(static_cast<char>('0' + high));
        }
    }

    offset += len;
    return res;
}

// ─── NrGuti ─────────────────────────────────────────────────────────────────

std::vector<uint8_t> NrGuti::encode() const {
    std::vector<uint8_t> out;
    out.reserve(13);
    out.push_back(0x77); // IEI for 5G-GUTI
    out.push_back(11);   // length of value

    out.push_back(0xF2); // spare=1111, type=010 (5G-GUTI)

    auto plmn = encode_plmn(mcc, mnc);
    out.push_back(plmn[0]);
    out.push_back(plmn[1]);
    out.push_back(plmn[2]);

    out.push_back(amf_region_id);

    // AMF Set ID (10 bits) + AMF Pointer (6 bits)
    out.push_back(static_cast<uint8_t>((amf_set_id >> 2) & 0xFF));
    out.push_back(static_cast<uint8_t>(((amf_set_id & 0x03) << 6) | (amf_pointer & 0x3F)));

    // 5G-TMSI (4 octets)
    out.push_back(static_cast<uint8_t>((tmsi >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((tmsi >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((tmsi >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(tmsi & 0xFF));

    return out;
}

NrGuti NrGuti::decode(std::span<const uint8_t> data, size_t& offset) {
    if (data.size() < offset + 13) {
        throw std::runtime_error("5G-GUTI TLV truncated");
    }
    if (data[offset] != 0x77) {
        throw std::runtime_error("Invalid 5G-GUTI IEI");
    }
    uint8_t len = data[offset + 1];
    if (len != 11) {
        throw std::runtime_error("Invalid 5G-GUTI length");
    }

    NrGuti guti;
    decode_plmn(data.subspan(offset + 3, 3), guti.mcc, guti.mnc);

    guti.amf_region_id = data[offset + 6];

    uint16_t set_high = data[offset + 7];
    uint8_t set_low_ptr = data[offset + 8];
    guti.amf_set_id = static_cast<uint16_t>((set_high << 2) | ((set_low_ptr >> 6) & 0x03));
    guti.amf_pointer = set_low_ptr & 0x3F;

    guti.tmsi = (static_cast<uint32_t>(data[offset + 9]) << 24) |
                (static_cast<uint32_t>(data[offset + 10]) << 16) |
                (static_cast<uint32_t>(data[offset + 11]) << 8) |
                static_cast<uint32_t>(data[offset + 12]);

    offset += 13;
    return guti;
}

// ─── SNssai ─────────────────────────────────────────────────────────────────

std::vector<uint8_t> SNssai::encode() const {
    std::vector<uint8_t> out;
    if (sd.has_value()) {
        out.reserve(5);
        out.push_back(4); // length
        out.push_back(sst);
        out.push_back(static_cast<uint8_t>((*sd >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((*sd >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(*sd & 0xFF));
    } else {
        out.reserve(2);
        out.push_back(1); // length
        out.push_back(sst);
    }
    return out;
}

SNssai SNssai::decode(std::span<const uint8_t> lv) {
    if (lv.size() < 2) {
        throw std::runtime_error("S-NSSAI LV truncated");
    }
    uint8_t len = lv[0];
    if (lv.size() < static_cast<size_t>(1 + len)) {
        throw std::runtime_error("S-NSSAI length exceeds buffer");
    }
    SNssai nssai;
    nssai.sst = lv[1];
    if (len >= 4) {
        uint32_t val = (static_cast<uint32_t>(lv[2]) << 16) |
                       (static_cast<uint32_t>(lv[3]) << 8) |
                       static_cast<uint32_t>(lv[4]);
        nssai.sd = val;
    } else {
        nssai.sd = std::nullopt;
    }
    return nssai;
}

// ─── Dnn ────────────────────────────────────────────────────────────────────

std::vector<uint8_t> Dnn::encode() const {
    std::vector<uint8_t> val;
    std::stringstream ss(dnn);
    std::string token;
    while (std::getline(ss, token, '.')) {
        val.push_back(static_cast<uint8_t>(token.size()));
        for (char c : token) {
            val.push_back(static_cast<uint8_t>(c));
        }
    }
    std::vector<uint8_t> out;
    out.reserve(1 + val.size());
    out.push_back(static_cast<uint8_t>(val.size()));
    out.insert(out.end(), val.begin(), val.end());
    return out;
}

Dnn Dnn::decode(std::span<const uint8_t> lv) {
    if (lv.empty()) {
        throw std::runtime_error("DNN LV truncated");
    }
    uint8_t len = lv[0];
    if (lv.size() < static_cast<size_t>(1 + len)) {
        throw std::runtime_error("DNN length exceeds buffer");
    }

    Dnn res;
    res.dnn.clear();
    size_t pos = 1;
    size_t end = 1 + len;
    while (pos < end) {
        uint8_t label_len = lv[pos++];
        if (pos + label_len > end) {
            throw std::runtime_error("Malformed DNN label length");
        }
        if (!res.dnn.empty()) {
            res.dnn.push_back('.');
        }
        for (size_t i = 0; i < label_len; ++i) {
            res.dnn.push_back(static_cast<char>(lv[pos++]));
        }
    }
    return res;
}

// ─── NrPduAddress ───────────────────────────────────────────────────────────

std::vector<uint8_t> NrPduAddress::encode() const {
    return {0x05, pdu_type, ipv4[0], ipv4[1], ipv4[2], ipv4[3]};
}

NrPduAddress NrPduAddress::decode(std::span<const uint8_t> lv) {
    if (lv.size() < 6) {
        throw std::runtime_error("NrPduAddress LV truncated");
    }
    NrPduAddress addr;
    addr.pdu_type = lv[1] & 0x07;
    addr.ipv4 = {lv[2], lv[3], lv[4], lv[5]};
    return addr;
}

// ─── NrQosRule ──────────────────────────────────────────────────────────────

std::vector<uint8_t> NrQosRule::encode() const {
    return {0x02, qfi, five_qi};
}

NrQosRule NrQosRule::decode(std::span<const uint8_t> lv) {
    if (lv.size() < 3) {
        throw std::runtime_error("NrQosRule LV truncated");
    }
    NrQosRule rule;
    rule.qfi = lv[1];
    rule.five_qi = lv[2];
    return rule;
}

} // namespace gpp::nr_nas
