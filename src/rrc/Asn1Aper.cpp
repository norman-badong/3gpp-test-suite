#include <3gpp/rrc/Asn1Aper.hpp>
#include <cmath>

namespace gpp::rrc {

namespace {

size_t calculate_bits_for_range(uint64_t range) {
    if (range <= 1) return 0;
    size_t bits = 0;
    while ((1ULL << bits) < range) {
        ++bits;
    }
    return bits;
}

} // namespace

// ─── AperWriter ─────────────────────────────────────────────────────────────

void AperWriter::write_boolean(bool value) {
    writer_.write_bit(value);
}

void AperWriter::write_constrained_integer(int64_t value, int64_t min_val, int64_t max_val) {
    if (value < min_val || value > max_val) {
        throw std::out_of_range("Integer value out of APER range");
    }
    uint64_t range = static_cast<uint64_t>(max_val - min_val + 1);
    uint64_t offset = static_cast<uint64_t>(value - min_val);

    if (range <= 1) {
        return;
    }

    if (range <= 255) {
        size_t bits = calculate_bits_for_range(range);
        writer_.write_bits(offset, bits);
    } else if (range == 256) {
        writer_.pad_to_byte();
        writer_.write_bits(offset, 8);
    } else if (range <= 65536) {
        writer_.pad_to_byte();
        writer_.write_bits(offset, 16);
    } else {
        writer_.pad_to_byte();
        writer_.write_bits(offset, 32);
    }
}

void AperWriter::write_enumerated(uint32_t value, uint32_t count, bool extensible) {
    if (extensible) {
        writer_.write_bit(false); // extension bit = 0 (within root)
    }
    write_constrained_integer(static_cast<int64_t>(value), 0, static_cast<int64_t>(count - 1));
}

void AperWriter::write_choice_index(uint32_t index, uint32_t count, bool extensible) {
    if (extensible) {
        writer_.write_bit(false); // extension bit = 0 (root choice)
    }
    write_constrained_integer(static_cast<int64_t>(index), 0, static_cast<int64_t>(count - 1));
}

void AperWriter::write_bit_string(uint64_t bits, size_t num_bits) {
    writer_.write_bits(bits, num_bits);
}

void AperWriter::write_octet_string(std::span<const uint8_t> octets, bool fixed_length) {
    if (!fixed_length) {
        writer_.pad_to_byte();
        size_t len = octets.size();
        if (len < 128) {
            writer_.write_bits(static_cast<uint64_t>(len), 8);
        } else {
            uint8_t b0 = static_cast<uint8_t>(0x80 | ((len >> 8) & 0x3F));
            uint8_t b1 = static_cast<uint8_t>(len & 0xFF);
            writer_.write_bits(b0, 8);
            writer_.write_bits(b1, 8);
        }
    } else {
        writer_.pad_to_byte();
    }

    for (uint8_t b : octets) {
        writer_.write_bits(b, 8);
    }
}

void AperWriter::write_sequence_header(bool has_extensions, std::span<const bool> optionals) {
    if (has_extensions) {
        writer_.write_bit(false); // extension bit = 0 (no extension items)
    }
    for (bool opt : optionals) {
        writer_.write_bit(opt);
    }
}

void AperWriter::align_to_byte() {
    writer_.pad_to_byte();
}

// ─── AperReader ─────────────────────────────────────────────────────────────

AperReader::AperReader(std::span<const uint8_t> data)
    : reader_(data) {}

bool AperReader::read_boolean() {
    return reader_.read_bit();
}

int64_t AperReader::read_constrained_integer(int64_t min_val, int64_t max_val) {
    uint64_t range = static_cast<uint64_t>(max_val - min_val + 1);
    if (range <= 1) {
        return min_val;
    }

    if (range <= 255) {
        size_t bits = calculate_bits_for_range(range);
        uint64_t offset = reader_.read_bits(bits);
        return min_val + static_cast<int64_t>(offset);
    } else if (range == 256) {
        reader_.align_to_byte();
        uint64_t offset = reader_.read_bits(8);
        return min_val + static_cast<int64_t>(offset);
    } else if (range <= 65536) {
        reader_.align_to_byte();
        uint64_t offset = reader_.read_bits(16);
        return min_val + static_cast<int64_t>(offset);
    } else {
        reader_.align_to_byte();
        uint64_t offset = reader_.read_bits(32);
        return min_val + static_cast<int64_t>(offset);
    }
}

uint32_t AperReader::read_enumerated(uint32_t count, bool extensible) {
    if (extensible) {
        bool ext = reader_.read_bit();
        if (ext) {
            throw std::runtime_error("Enumerated extension not supported");
        }
    }
    return static_cast<uint32_t>(read_constrained_integer(0, static_cast<int64_t>(count - 1)));
}

uint32_t AperReader::read_choice_index(uint32_t count, bool extensible) {
    if (extensible) {
        bool ext = reader_.read_bit();
        if (ext) {
            throw std::runtime_error("Choice extension not supported");
        }
    }
    return static_cast<uint32_t>(read_constrained_integer(0, static_cast<int64_t>(count - 1)));
}

uint64_t AperReader::read_bit_string(size_t num_bits) {
    return reader_.read_bits(num_bits);
}

std::vector<uint8_t> AperReader::read_octet_string(size_t fixed_length) {
    size_t len = fixed_length;
    if (fixed_length == 0) {
        reader_.align_to_byte();
        uint8_t b0 = static_cast<uint8_t>(reader_.read_bits(8));
        if ((b0 & 0x80) == 0) {
            len = b0;
        } else {
            uint8_t b1 = static_cast<uint8_t>(reader_.read_bits(8));
            len = ((b0 & 0x3F) << 8) | b1;
        }
    } else {
        reader_.align_to_byte();
    }

    std::vector<uint8_t> out;
    out.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(static_cast<uint8_t>(reader_.read_bits(8)));
    }
    return out;
}

void AperReader::read_sequence_header(bool extensible, size_t num_optionals, std::vector<bool>& optionals_out) {
    if (extensible) {
        bool ext = reader_.read_bit();
        if (ext) {
            throw std::runtime_error("Sequence extension not supported");
        }
    }
    optionals_out.clear();
    optionals_out.reserve(num_optionals);
    for (size_t i = 0; i < num_optionals; ++i) {
        optionals_out.push_back(reader_.read_bit());
    }
}

void AperReader::align_to_byte() {
    reader_.align_to_byte();
}

} // namespace gpp::rrc
