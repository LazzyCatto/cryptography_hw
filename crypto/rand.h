#ifndef RAND
#define RAND

#include "types/mpint.h"

#include <format>
#include <sys/random.h>
#include <stdexcept>

namespace minissh {
    void fill_random(uint8_t*, uint32_t);
    mpint get_random_mpint(uint32_t);
}

#endif
