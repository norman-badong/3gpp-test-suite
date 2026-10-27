#pragma once

#include <string>
#include <vector>
#include <span>
#include <cstdint>
#include <utility>
#include "3gpp/common/ByteStream.hpp"

namespace gpp::sba {

struct HeaderField {
    std::string name;
    std::string value;

    HeaderField() = default;
    HeaderField(std::string n, std::string v) : name(std::move(n)), value(std::move(v)) {}

    bool operator==(const HeaderField& other) const = default;
};

class Hpack {
public:
    // Static Table entry lookup (RFC 7541 Appendix A)
    struct StaticEntry {
        uint32_t index;
        const char* name;
        const char* value;
    };

    static const std::vector<StaticEntry>& static_table();

    // Encode a list of headers into an HPACK binary block
    static std::vector<uint8_t> encode(const std::vector<HeaderField>& headers);

    // Decode an HPACK binary block into a list of headers
    static std::vector<HeaderField> decode(std::span<const uint8_t> hpack_block);

    // Helpers for integer encoding/decoding with N-bit prefix
    static void encode_integer(common::ByteStreamWriter& writer, uint8_t prefix_mask, size_t prefix_bits, uint32_t value);
    static uint32_t decode_integer(common::ByteStreamReader& reader, size_t prefix_bits, uint8_t first_byte);

    // Helpers for string encoding/decoding (raw without Huffman for baseline)
    static void encode_string(common::ByteStreamWriter& writer, std::string_view str);
    static std::string decode_string(common::ByteStreamReader& reader);
};

} // namespace gpp::sba
