#ifndef HASH
#define HASH

#include <functional>

#include "src/connection/socket.h"

namespace minissh {
    secure_buffer sha_1(const secure_buffer&);
    secure_buffer sha_256(const secure_buffer&);

    uint32_t _sha_1_f(uint32_t t, uint32_t b, uint32_t c, uint32_t d);
}

#endif
