#include "src/securebit.h"

namespace minissh {
    secure_buffer::secure_buffer(const uint8_t* buffer, size_t len) : secure_buffer{len} {
        if (_buffer) {
            memcpy(_buffer, buffer, _len);
        }
    }
    
    secure_buffer secure_buffer::cat(std::span<const secure_buffer> values) {
        size_t total_length = 0;
        for (const secure_buffer& value : values) {
            total_length += value._len;
        }
        secure_buffer new_buffer{total_length};
        total_length = 0;
        for (const secure_buffer& value : values) {
            memcpy(new_buffer.data() + total_length, value.data(), value._len);
            total_length += value._len;
        }
        return new_buffer;
    }

    bool operator==(const secure_buffer& lhs, const secure_buffer& rhs) {
        if (lhs._len != rhs._len) {
            return false;
        }
        for (size_t i = 0; i < lhs._len; ++i) {
            if (lhs._buffer[i] != rhs._buffer[i]) {
                return false;
            }
        }
        return true;
    }
}