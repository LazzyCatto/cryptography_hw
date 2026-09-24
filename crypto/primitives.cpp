#include "crypto/primitives.h"

namespace minissh {
    secure_buffer _i2osp(mpint value, uint32_t length) {
        if (value.sign()) {
            throw std::runtime_error("can not convert negative numbers");
        }
        uint32_t start = 7;
        while (((value.data()[value.size() / 8 - 1] >> (start * 8)) & 0xFF) == 0) {
            --start;
        }
        uint32_t value_len = value.size() + start - 7;

        if (value_len > length) {
            throw std::runtime_error("integer too large");
        }
        secure_buffer buffer{length};

        if (value_len < length) {
            memset(buffer.data(), 0, length - value_len);
        }
        for (uint32_t i = 0, j = 0; j < value_len; ++j) {
            uint64_t buff_data = (value.data()[i] >> ((j % 8) * 8)) & 0xFF;
            buffer.data()[length - 1 - j] = static_cast<uint8_t>(buff_data);
            if (j % 8 == 7) {
                ++i;
            }
        }

        return buffer;
    }

    mpint _os2ip(secure_buffer value) {
        return mpint{value};
    }
}
