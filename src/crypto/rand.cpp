#include "src/crypto/rand.h"

namespace minissh {
    void fill_random(uint8_t* buffer, uint32_t size) {
        uint32_t pos = 0;
        while (pos < size) {
            ssize_t r = getrandom(buffer + pos, size - pos, 0);
            if (r < 0) {
                if (errno == EINTR) continue;
                throw std::runtime_error(std::format("getrandom failed: {}", strerror(errno)));
            }
            pos += static_cast<uint32_t>(r);
        }
    }

    mpint get_random_mpint(uint32_t size) {
        uint32_t mpint_size = (size + sizeof(uint64_t) - 1) / sizeof(uint64_t);
        uint64_t* buffer = new uint64_t[size];
        fill_random(reinterpret_cast<uint8_t*>(buffer), size);
        return mpint{mpint_view{mpint_size, buffer, false}};
    }
}
