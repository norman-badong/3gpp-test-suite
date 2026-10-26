#include "3gpp/common/BitBuffer.hpp"

namespace gpp::common {

void BitWriter::write_bit(bool bit) {
    size_t byte_idx = total_bits_ / 8;
    size_t bit_idx  = 7 - (total_bits_ % 8);

    if (byte_idx >= bytes_.size()) {
        bytes_.push_back(0);
    }

    if (bit) {
        bytes_[byte_idx] |= (1 << bit_idx);
    }
    ++total_bits_;
}

void BitWriter::write_bits(uint64_t value, size_t num_bits) {
    if (num_bits == 0) return;
    if (num_bits > 64) {
        throw std::invalid_argument("BitWriter::write_bits cannot write more than 64 bits at once");
    }

    for (size_t i = 0; i < num_bits; ++i) {
        size_t shift = num_bits - 1 - i;
        bool bit = ((value >> shift) & 1) != 0;
        write_bit(bit);
    }
}

void BitWriter::pad_to_byte() {
    size_t rem = total_bits_ % 8;
    if (rem != 0) {
        size_t pad = 8 - rem;
        for (size_t i = 0; i < pad; ++i) {
            write_bit(false);
        }
    }
}

void BitWriter::clear() {
    bytes_.clear();
    total_bits_ = 0;
}

// -------------------------------------------------------------
// BitReader
// -------------------------------------------------------------

BitReader::BitReader(std::span<const uint8_t> data, size_t bit_limit)
    : data_(data), bit_cursor_(0) {
    size_t max_bits = data.size() * 8;
    bit_limit_ = (bit_limit == 0 || bit_limit > max_bits) ? max_bits : bit_limit;
}

size_t BitReader::bits_remaining() const {
    return (bit_cursor_ < bit_limit_) ? (bit_limit_ - bit_cursor_) : 0;
}

bool BitReader::read_bit() {
    if (bit_cursor_ >= bit_limit_) {
        throw std::out_of_range("BitReader::read_bit out of bits");
    }

    size_t byte_idx = bit_cursor_ / 8;
    size_t bit_idx  = 7 - (bit_cursor_ % 8);
    ++bit_cursor_;

    return ((data_[byte_idx] >> bit_idx) & 1) != 0;
}

uint64_t BitReader::read_bits(size_t num_bits) {
    if (num_bits == 0) return 0;
    if (num_bits > 64) {
        throw std::invalid_argument("BitReader::read_bits cannot read more than 64 bits at once");
    }
    if (bits_remaining() < num_bits) {
        throw std::out_of_range("BitReader::read_bits insufficient bits remaining");
    }

    uint64_t result = 0;
    for (size_t i = 0; i < num_bits; ++i) {
        result = (result << 1) | (read_bit() ? 1 : 0);
    }
    return result;
}

void BitReader::align_to_byte() {
    size_t rem = bit_cursor_ % 8;
    if (rem != 0) {
        bit_cursor_ += (8 - rem);
        if (bit_cursor_ > bit_limit_) {
            bit_cursor_ = bit_limit_;
        }
    }
}

} // namespace gpp::common
