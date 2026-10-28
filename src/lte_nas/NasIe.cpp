#include <3gpp/lte_nas/NasIe.hpp>
#include <stdexcept>
#include <sstream>

namespace gpp::lte_nas {

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

// ─── MobileIdentity ──────────────────────────────────────────────────────────

std::vector<uint8_t> MobileIdentity::encode() const {
    if (imsi.empty()) {
        throw std::invalid_argument("Empty IMSI in MobileIdentity");
    }
    bool odd = (imsi.size() % 2) != 0;
    uint8_t val_len = static_cast<uint8_t>((imsi.size() + 2) / 2); // 1st digit in octet 1

    std::vector<uint8_t> out;
    out.reserve(1 + val_len);
    out.push_back(val_len);

    // Octet 1: digit1 | odd/even | type(001)
    uint8_t digit1 = static_cast<uint8_t>(imsi[0] - '0');
    uint8_t octet1 = (digit1 << 4) | (odd ? 0x08 : 0x00) | 0x01;
    out.push_back(octet1);

    size_t idx = 1;
    while (idx < imsi.size()) {
        uint8_t low = static_cast<uint8_t>(imsi[idx] - '0');
        uint8_t high = 0x0F;
        if (idx + 1 < imsi.size()) {
            high = static_cast<uint8_t>(imsi[idx + 1] - '0');
        }
        out.push_back(static_cast<uint8_t>((high << 4) | (low & 0x0F)));
        idx += 2;
    }
    return out;
}

MobileIdentity MobileIdentity::decode_imsi(std::span<const uint8_t> lv) {
    if (lv.size() < 2) {
        throw std::runtime_error("Truncated MobileIdentity LV");
    }
    uint8_t val_len = lv[0];
    if (lv.size() < static_cast<size_t>(1 + val_len)) {
        throw std::runtime_error("MobileIdentity LV length exceeds buffer");
    }
    uint8_t octet1 = lv[1];
    uint8_t type = octet1 & 0x07;
    if (type != 0x01) {
        throw std::runtime_error("MobileIdentity is not IMSI type");
    }

    MobileIdentity id;
    id.imsi.push_back(static_cast<char>('0' + ((octet1 >> 4) & 0x0F)));

    for (size_t i = 2; i <= val_len; ++i) {
        uint8_t b = lv[i];
        uint8_t low = b & 0x0F;
        uint8_t high = (b >> 4) & 0x0F;
        if (low != 0x0F) {
            id.imsi.push_back(static_cast<char>('0' + low));
        }
        if (high != 0x0F) {
            id.imsi.push_back(static_cast<char>('0' + high));
        }
    }
    return id;
}

// ─── Guti ───────────────────────────────────────────────────────────────────

std::vector<uint8_t> Guti::encode() const {
    std::vector<uint8_t> out;
    out.reserve(13);
    out.push_back(0x50); // IEI
    out.push_back(11);   // length of value

    // Octet 1 of value: 0xF6 (spare=1111, type=110)
    out.push_back(0xF6);

    // MCC/MNC (3 octets)
    auto plmn = encode_plmn(mcc, mnc);
    out.push_back(plmn[0]);
    out.push_back(plmn[1]);
    out.push_back(plmn[2]);

    // MME Group ID (2 octets)
    out.push_back(static_cast<uint8_t>(mme_group_id >> 8));
    out.push_back(static_cast<uint8_t>(mme_group_id & 0xFF));

    // MME Code (1 octet)
    out.push_back(mme_code);

    // M-TMSI (4 octets)
    out.push_back(static_cast<uint8_t>((m_tmsi >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((m_tmsi >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((m_tmsi >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(m_tmsi & 0xFF));

    return out;
}

Guti Guti::decode(std::span<const uint8_t> data, size_t& offset) {
    if (data.size() < offset + 13) {
        throw std::runtime_error("Truncated GUTI TLV");
    }
    if (data[offset] != 0x50) {
        throw std::runtime_error("Invalid GUTI IEI");
    }
    uint8_t len = data[offset + 1];
    if (len != 11) {
        throw std::runtime_error("Invalid GUTI length");
    }

    Guti g;
    decode_plmn(data.subspan(offset + 3, 3), g.mcc, g.mnc);

    g.mme_group_id = static_cast<uint16_t>((data[offset + 6] << 8) | data[offset + 7]);
    g.mme_code = data[offset + 8];
    g.m_tmsi = (static_cast<uint32_t>(data[offset + 9]) << 24) |
               (static_cast<uint32_t>(data[offset + 10]) << 16) |
               (static_cast<uint32_t>(data[offset + 11]) << 8) |
               static_cast<uint32_t>(data[offset + 12]);

    offset += 13;
    return g;
}

// ─── TaiList ────────────────────────────────────────────────────────────────

std::vector<uint8_t> TaiList::encode() const {
    if (tacs.empty()) {
        throw std::invalid_argument("Empty TACs list in TaiList");
    }
    // Type 00: non-consecutive TACs in 1 PLMN
    // Octet 1: 0x00 | (num_tacs - 1)
    // Octet 2..4: PLMN
    // Octet 5..: 2 bytes per TAC
    uint8_t val_len = static_cast<uint8_t>(1 + 3 + (2 * tacs.size()));
    std::vector<uint8_t> out;
    out.reserve(1 + val_len);
    out.push_back(val_len);

    uint8_t hdr = static_cast<uint8_t>((tacs.size() - 1) & 0x1F);
    out.push_back(hdr);

    auto plmn = encode_plmn(mcc, mnc);
    out.push_back(plmn[0]);
    out.push_back(plmn[1]);
    out.push_back(plmn[2]);

    for (uint16_t tac : tacs) {
        out.push_back(static_cast<uint8_t>(tac >> 8));
        out.push_back(static_cast<uint8_t>(tac & 0xFF));
    }
    return out;
}

TaiList TaiList::decode(std::span<const uint8_t> lv) {
    if (lv.size() < 2) {
        throw std::runtime_error("Truncated TaiList LV");
    }
    uint8_t val_len = lv[0];
    if (lv.size() < static_cast<size_t>(1 + val_len)) {
        throw std::runtime_error("TaiList LV length exceeds buffer");
    }
    if (val_len < 4) {
        throw std::runtime_error("TaiList value too short");
    }

    TaiList list;
    size_t count = static_cast<size_t>((lv[1] & 0x1F) + 1);
    decode_plmn(lv.subspan(2, 3), list.mcc, list.mnc);

    size_t pos = 5;
    for (size_t i = 0; i < count && pos + 2 <= static_cast<size_t>(1 + val_len); ++i) {
        uint16_t tac = static_cast<uint16_t>((lv[pos] << 8) | lv[pos + 1]);
        list.tacs.push_back(tac);
        pos += 2;
    }
    return list;
}

// ─── EpsQoS ─────────────────────────────────────────────────────────────────

std::vector<uint8_t> EpsQoS::encode() const {
    return {0x01, qci};
}

EpsQoS EpsQoS::decode(std::span<const uint8_t> lv) {
    if (lv.size() < 2) {
        throw std::runtime_error("Truncated EpsQoS LV");
    }
    EpsQoS q;
    q.qci = lv[1];
    return q;
}

// ─── AccessPointName ────────────────────────────────────────────────────────

std::vector<uint8_t> AccessPointName::encode() const {
    std::vector<uint8_t> val;
    std::stringstream ss(apn);
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

AccessPointName AccessPointName::decode(std::span<const uint8_t> lv) {
    if (lv.empty()) {
        throw std::runtime_error("Truncated AccessPointName LV");
    }
    uint8_t len = lv[0];
    if (lv.size() < static_cast<size_t>(1 + len)) {
        throw std::runtime_error("AccessPointName length exceeds buffer");
    }

    AccessPointName res;
    size_t pos = 1;
    size_t end = 1 + len;
    while (pos < end) {
        uint8_t label_len = lv[pos++];
        if (pos + label_len > end) {
            throw std::runtime_error("Malformed APN label length");
        }
        if (!res.apn.empty()) {
            res.apn.push_back('.');
        }
        for (size_t i = 0; i < label_len; ++i) {
            res.apn.push_back(static_cast<char>(lv[pos++]));
        }
    }
    return res;
}

// ─── PdnAddress ─────────────────────────────────────────────────────────────

std::vector<uint8_t> PdnAddress::encode() const {
    return {0x05, pdn_type, ipv4[0], ipv4[1], ipv4[2], ipv4[3]};
}

PdnAddress PdnAddress::decode(std::span<const uint8_t> lv) {
    if (lv.size() < 6) {
        throw std::runtime_error("Truncated PdnAddress LV");
    }
    PdnAddress addr;
    addr.pdn_type = lv[1] & 0x07;
    addr.ipv4 = {lv[2], lv[3], lv[4], lv[5]};
    return addr;
}

} // namespace gpp::lte_nas
