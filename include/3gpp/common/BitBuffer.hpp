#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <stdexcept>

namespace gpp::common {

class BitWriter {
public:
    BitWriter() = default;

    // Writes up to 64 bits from `value` (MSB-first, standard in 3GPP telecom bit streams)
    void write_bits(uint64_t value, size_t num_bits);

    // Write a single bit (true = 1, false = 0)
    void write_bit(bool bit);

    // Pad with zeros to the next byte boundary
    void pad_to_byte();

    [[nodiscard]] const std::vector<uint8_t>& bytes() const { return bytes_; }
    [[nodiscard]] size_t total_bits() const { return total_bits_; }
    [[nodiscard]] size_t total_bytes() const { return (total_bits_ + 7) / 8; }

    void clear();

private:
    std::vector<uint8_t> bytes_;
    size_t total_bits_{0};
};

class BitReader {
public:
    explicit BitReader(std::span<const uint8_t> data, size_t bit_limit = 0);

    // Reads up to 64 bits (MSB-first)
    [[nodiscard]] uint64_t read_bits(size_t num_bits);

    // Reads a single bit
    [[nodiscard]] bool read_bit();

    // Align read cursor to the next byte boundary
    void align_to_byte();

    [[nodiscard]] size_t bits_remaining() const;
    [[nodiscard]] size_t bit_position() const { return bit_cursor_; }

private:
    std::span<const uint8_t> data_;
    size_t bit_cursor_{0};
    size_t bit_limit_{0};
};

} // namespace gpp::common
