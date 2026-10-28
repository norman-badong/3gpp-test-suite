#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <stdexcept>
#include "3gpp/common/BitBuffer.hpp"

namespace gpp::rrc {

class AperWriter {
public:
    AperWriter() = default;

    // ASN.1 APER Boolean (1 bit)
    void write_boolean(bool value);

    // ASN.1 APER Constrained Integer (min..max)
    void write_constrained_integer(int64_t value, int64_t min_val, int64_t max_val);

    // ASN.1 APER Enumerated (0 .. count - 1)
    void write_enumerated(uint32_t value, uint32_t count, bool extensible = false);

    // ASN.1 APER Choice Index (0 .. count - 1)
    void write_choice_index(uint32_t index, uint32_t count, bool extensible = false);

    // ASN.1 APER Fixed-size Bit String
    void write_bit_string(uint64_t bits, size_t num_bits);

    // ASN.1 APER Octet String
    void write_octet_string(std::span<const uint8_t> octets, bool fixed_length = false);

    // Sequence extension bit (0) + optional presence bits
    void write_sequence_header(bool has_extensions, std::span<const bool> optionals);

    // Complete and align to byte boundary
    void align_to_byte();

    [[nodiscard]] const std::vector<uint8_t>& bytes() const { return writer_.bytes(); }
    [[nodiscard]] size_t total_bits() const { return writer_.total_bits(); }

private:
    common::BitWriter writer_;
};

class AperReader {
public:
    explicit AperReader(std::span<const uint8_t> data);

    [[nodiscard]] bool read_boolean();

    [[nodiscard]] int64_t read_constrained_integer(int64_t min_val, int64_t max_val);

    [[nodiscard]] uint32_t read_enumerated(uint32_t count, bool extensible = false);

    [[nodiscard]] uint32_t read_choice_index(uint32_t count, bool extensible = false);

    [[nodiscard]] uint64_t read_bit_string(size_t num_bits);

    [[nodiscard]] std::vector<uint8_t> read_octet_string(size_t fixed_length = 0);

    void read_sequence_header(bool extensible, size_t num_optionals, std::vector<bool>& optionals_out);

    void align_to_byte();

    [[nodiscard]] size_t bits_remaining() const { return reader_.bits_remaining(); }

private:
    common::BitReader reader_;
};

} // namespace gpp::rrc
