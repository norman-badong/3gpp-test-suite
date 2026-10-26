#include "3gpp/common/ByteStream.hpp"

namespace gpp::common {

ByteStreamWriter::ByteStreamWriter(size_t reserve_bytes) {
    buffer_.reserve(reserve_bytes);
}

void ByteStreamWriter::write_u8(uint8_t value) {
    buffer_.push_back(value);
}

void ByteStreamWriter::write_u16(uint16_t value) {
    buffer_.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buffer_.push_back(static_cast<uint8_t>(value & 0xFF));
}

void ByteStreamWriter::write_u24(uint32_t value) {
    buffer_.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    buffer_.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buffer_.push_back(static_cast<uint8_t>(value & 0xFF));
}

void ByteStreamWriter::write_u32(uint32_t value) {
    buffer_.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    buffer_.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    buffer_.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buffer_.push_back(static_cast<uint8_t>(value & 0xFF));
}

void ByteStreamWriter::write_u64(uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        buffer_.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
}

void ByteStreamWriter::write_bytes(std::span<const uint8_t> data) {
    buffer_.insert(buffer_.end(), data.begin(), data.end());
}

void ByteStreamWriter::write_string(std::string_view str) {
    buffer_.insert(buffer_.end(), str.begin(), str.end());
}

void ByteStreamWriter::set_u16(size_t offset, uint16_t value) {
    if (offset + 2 > buffer_.size()) {
        throw std::out_of_range("ByteStreamWriter::set_u16 offset out of range");
    }
    buffer_[offset]     = static_cast<uint8_t>((value >> 8) & 0xFF);
    buffer_[offset + 1] = static_cast<uint8_t>(value & 0xFF);
}

void ByteStreamWriter::set_u32(size_t offset, uint32_t value) {
    if (offset + 4 > buffer_.size()) {
        throw std::out_of_range("ByteStreamWriter::set_u32 offset out of range");
    }
    buffer_[offset]     = static_cast<uint8_t>((value >> 24) & 0xFF);
    buffer_[offset + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
    buffer_[offset + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
    buffer_[offset + 3] = static_cast<uint8_t>(value & 0xFF);
}

// -------------------------------------------------------------
// ByteStreamReader
// -------------------------------------------------------------

ByteStreamReader::ByteStreamReader(std::span<const uint8_t> data)
    : data_(data), cursor_(0) {}

void ByteStreamReader::ensure_available(size_t count) const {
    if (cursor_ + count > data_.size()) {
        throw std::out_of_range("ByteStreamReader: unexpected end of buffer (needed " +
                                std::to_string(count) + ", available " +
                                std::to_string(data_.size() - cursor_) + ")");
    }
}

uint8_t ByteStreamReader::read_u8() {
    ensure_available(1);
    return data_[cursor_++];
}

uint16_t ByteStreamReader::read_u16() {
    ensure_available(2);
    uint16_t val = (static_cast<uint16_t>(data_[cursor_]) << 8) |
                   static_cast<uint16_t>(data_[cursor_ + 1]);
    cursor_ += 2;
    return val;
}

uint32_t ByteStreamReader::read_u24() {
    ensure_available(3);
    uint32_t val = (static_cast<uint32_t>(data_[cursor_]) << 16) |
                   (static_cast<uint32_t>(data_[cursor_ + 1]) << 8) |
                    static_cast<uint32_t>(data_[cursor_ + 2]);
    cursor_ += 3;
    return val;
}

uint32_t ByteStreamReader::read_u32() {
    ensure_available(4);
    uint32_t val = (static_cast<uint32_t>(data_[cursor_]) << 24) |
                   (static_cast<uint32_t>(data_[cursor_ + 1]) << 16) |
                   (static_cast<uint32_t>(data_[cursor_ + 2]) << 8) |
                    static_cast<uint32_t>(data_[cursor_ + 3]);
    cursor_ += 4;
    return val;
}

uint64_t ByteStreamReader::read_u64() {
    ensure_available(8);
    uint64_t val = 0;
    for (size_t i = 0; i < 8; ++i) {
        val = (val << 8) | static_cast<uint64_t>(data_[cursor_ + i]);
    }
    cursor_ += 8;
    return val;
}

std::span<const uint8_t> ByteStreamReader::read_bytes(size_t count) {
    ensure_available(count);
    std::span<const uint8_t> result = data_.subspan(cursor_, count);
    cursor_ += count;
    return result;
}

std::string ByteStreamReader::read_string(size_t count) {
    ensure_available(count);
    std::string s(reinterpret_cast<const char*>(data_.data() + cursor_), count);
    cursor_ += count;
    return s;
}

uint8_t ByteStreamReader::peek_u8() const {
    ensure_available(1);
    return data_[cursor_];
}

uint16_t ByteStreamReader::peek_u16() const {
    ensure_available(2);
    return (static_cast<uint16_t>(data_[cursor_]) << 8) |
            static_cast<uint16_t>(data_[cursor_ + 1]);
}

void ByteStreamReader::skip(size_t count) {
    ensure_available(count);
    cursor_ += count;
}

void ByteStreamReader::seek(size_t position) {
    if (position > data_.size()) {
        throw std::out_of_range("ByteStreamReader::seek position exceeds buffer size");
    }
    cursor_ = position;
}

} // namespace gpp::common
