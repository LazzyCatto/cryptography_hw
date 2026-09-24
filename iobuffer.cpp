#include "iobuffer.h"

namespace minissh {
    template <>
    void _write_in_buffer(uint8_t* buffer, uint32_t& offset, const bool& value, bool skip_size) {
        buffer[offset++] = value ? 1 : 0;
    }

    template <>
    void _write_in_buffer(uint8_t* buffer, uint32_t& offset, const uint8_t& value, bool skip_size) {
        buffer[offset++] = value;
    }

    template <>
    void _write_in_buffer(uint8_t* buffer, uint32_t& offset, const byte16& value, bool skip_size) {
        for (size_t i = 0; i < 16; ++i) {
            buffer[offset++] = value[i];
        }
    }

    template <>
    void _write_in_buffer(uint8_t* buffer, uint32_t& offset, const uint32_t& value, bool skip_size) {
        buffer[offset++] = static_cast<uint8_t>((value >> 24) & 0xFF);
        buffer[offset++] = static_cast<uint8_t>((value >> 16) & 0xFF);
        buffer[offset++] = static_cast<uint8_t>((value >>  8) & 0xFF);
        buffer[offset++] = static_cast<uint8_t>((value      ) & 0xFF);
    }

    template <>
    void _write_in_buffer(uint8_t* buffer, uint32_t& offset, const uint64_t& value, bool skip_size) {
        buffer[offset++] = static_cast<uint8_t>((value >> 56) & 0xFF);
        buffer[offset++] = static_cast<uint8_t>((value >> 48) & 0xFF);
        buffer[offset++] = static_cast<uint8_t>((value >> 40) & 0xFF);
        buffer[offset++] = static_cast<uint8_t>((value >> 32) & 0xFF);
        buffer[offset++] = static_cast<uint8_t>((value >> 24) & 0xFF);
        buffer[offset++] = static_cast<uint8_t>((value >> 16) & 0xFF);
        buffer[offset++] = static_cast<uint8_t>((value >>  8) & 0xFF);
        buffer[offset++] = static_cast<uint8_t>((value      ) & 0xFF);
    }

    template <>
    void _write_in_buffer(uint8_t* buffer, uint32_t& offset, const std::string& value, bool skip_size) {
        if (!skip_size) {
            _write_in_buffer(buffer, offset, static_cast<uint32_t>(value.length()), false);
        }
        memcpy(buffer + offset, value.data(), value.length());
        offset += value.length();
    }

    template <>
    void _write_in_buffer(uint8_t* buffer, uint32_t& offset, const secure_buffer& value, bool skip_size) {
        if (!skip_size) {
            _write_in_buffer(buffer, offset, static_cast<uint32_t>(value.length()), false);
        }
        memcpy(buffer + offset, value.data(), value.length());
        offset += value.length();
    }

    template <>
    void _write_in_buffer(uint8_t* buffer, uint32_t& offset, const mpint& value, bool skip_size) {
        uint32_t size;
        if (skip_size) {
            value.to_wire(buffer + offset, &size);
        }
        value.to_wire(buffer + offset + 4, &size);
        _write_in_buffer(buffer, offset, size, false);
        offset += size;
    }
    
    template <>
    void _write_in_buffer(uint8_t* buffer, uint32_t& offset, const namelist& value, bool skip_size) {
        if (skip_size) {
            for (size_t i = 0; i < value.size(); ++i) {
                if (i > 0) {
                    buffer[offset++] = static_cast<uint8_t>(',');
                }
                memcpy(buffer + offset, value[i].data(), value[i].length());
                offset += value[i].length();
            }
            return;
        }
        uint32_t total_length = 0;
        for (size_t i = 0; i < value.size(); ++i) {
            if (i > 0) {
                buffer[offset + 4 + total_length++] = static_cast<uint8_t>(',');
            }
            memcpy(buffer + offset + 4 + total_length, value[i].data(), value[i].length());
            total_length += value[i].length();
        }
        _write_in_buffer(buffer, offset, total_length, false);
        offset += total_length;
    }

    template <>
    void _read_from_buffer(const uint8_t* buffer, uint32_t& offset, bool* out, bool skip_size) {
        *out = buffer[offset++];
    }

    template <>
    void _read_from_buffer(const uint8_t* buffer, uint32_t& offset, uint8_t* out, bool skip_size) {
        *out = buffer[offset++];
    }

    template <>
    void _read_from_buffer(const uint8_t* buffer, uint32_t& offset, byte16* out, bool skip_size) {
        for (size_t i = 0; i < 16; ++i) {
            (*out)[i] = buffer[offset++];
        }
    }

    template <>
    void _read_from_buffer(const uint8_t* buffer, uint32_t& offset, uint32_t* out, bool skip_size) {
        *out =
            (uint32_t(buffer[offset    ]) << 24) |
            (uint32_t(buffer[offset + 1]) << 16) |
            (uint32_t(buffer[offset + 2]) <<  8) |
            (uint32_t(buffer[offset + 3])      );
        offset += 4;
    }

    template <>
    void _read_from_buffer(const uint8_t* buffer, uint32_t& offset, uint64_t* out, bool skip_size) {
        *out =
            (uint64_t(buffer[offset    ]) << 56) |
            (uint64_t(buffer[offset + 1]) << 48) |
            (uint64_t(buffer[offset + 2]) << 40) |
            (uint64_t(buffer[offset + 3]) << 32) |
            (uint64_t(buffer[offset + 4]) << 24) |
            (uint64_t(buffer[offset + 5]) << 16) |
            (uint64_t(buffer[offset + 6]) <<  8) |
            (uint64_t(buffer[offset + 7])      );
        offset += 8;
    }

    template <>
    void _read_from_buffer(const uint8_t* buffer, uint32_t& offset, std::string* out, bool skip_size) {
        uint32_t size = 0;
        _read_from_buffer(buffer, offset, &size, false);
        *out = std::string(reinterpret_cast<const char*>(buffer + offset), size);
        offset += size;
    }

    template <>
    void _read_from_buffer(const uint8_t* buffer, uint32_t& offset, secure_buffer* out, bool skip_size) {
        uint32_t size = 0;
        _read_from_buffer(buffer, offset, &size, false);
        *out = secure_buffer(buffer + offset, size);
        offset += size;
    }

    template <>
    void _read_from_buffer(const uint8_t* buffer, uint32_t& offset, mpint* out, bool skip_size) {
        uint32_t size = 0;
        _read_from_buffer(buffer, offset, &size, false);
        *out = mpint::from_wire(buffer + offset, size);
        offset += size;
    }

    template <>
    void _read_from_buffer(const uint8_t* buffer, uint32_t& offset, namelist* out, bool skip_size) {
        uint32_t size = 0;
        _read_from_buffer(buffer, offset, &size, false);
        *out = namelist();
        int previous_string_cut = 0;
        for (int i = 0; i < size; ++i) {
            if (buffer[offset + i] == static_cast<uint8_t>(',')) {
                out->emplace_back(
                    reinterpret_cast<const char*>(buffer + offset + previous_string_cut),
                    i - previous_string_cut
                );
                previous_string_cut = i + 1;
            }
        }
        out->emplace_back(
            reinterpret_cast<const char*>(buffer + offset + previous_string_cut),
            size - previous_string_cut
        );
        offset += size;
    }
}
