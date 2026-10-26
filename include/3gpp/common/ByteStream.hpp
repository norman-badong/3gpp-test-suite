#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <string>
#include <string_view>
#include <stdexcept>

namespace gpp::common {

class ByteStreamWriter {
public:
    ByteStreamWriter() = default;
    explicit ByteStreamWriter(size_t reserve_bytes);

    void write_u8(uint8_t value);
    void write_u16(uint16_t value);
    void write_u24(uint32_t value);
    void write_u32(uint32_t value);
    void write_u64(uint64_t value);

    void write_bytes(std::span<const uint8_t> data);
    void write_string(std::string_view str);

    // Overwrite at specific position (e.g. for length headers or checksums calculated after payload)
    void set_u16(size_t offset, uint16_t value);
    void set_u32(size_t offset, uint32_t value);

    [[nodiscard]] const std::vector<uint8_t>& data() const { return buffer_; }
    [[nodiscard]] std::vector<uint8_t> take_data() { return std::move(buffer_); }
    [[nodiscard]] size_t size() const { return buffer_.size(); }
    void clear() { buffer_.clear(); }

private:
    std::vector<uint8_t> buffer_;
};

class ByteStreamReader {
public:
    explicit ByteStreamReader(std::span<const uint8_t> data);

    [[nodiscard]] uint8_t read_u8();
    [[nodiscard]] uint16_t read_u16();
    [[nodiscard]] uint32_t read_u24();
    [[nodiscard]] uint32_t read_u32();
    [[nodiscard]] uint64_t read_u64();

    [[nodiscard]] std::span<const uint8_t> read_bytes(size_t count);
    [[nodiscard]] std::string read_string(size_t count);

    [[nodiscard]] uint8_t peek_u8() const;
    [[nodiscard]] uint16_t peek_u16() const;

    void skip(size_t count);
    void seek(size_t position);

    [[nodiscard]] size_t tell() const { return cursor_; }
    [[nodiscard]] size_t remaining() const { return cursor_ <= data_.size() ? data_.size() - cursor_ : 0; }
    [[nodiscard]] bool empty() const { return remaining() == 0; }
    [[nodiscard]] size_t total_size() const { return data_.size(); }

private:
    std::span<const uint8_t> data_;
    size_t cursor_{0};

    void ensure_available(size_t count) const;
};

} // namespace gpp::common
