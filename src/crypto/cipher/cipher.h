#ifndef CIPHER
#define CIPHER

#include <string>

#include "src/securebit.h"

namespace minissh {
    class cipher {
      public:
        virtual ~cipher() = default;
        virtual std::string name() const = 0;
        virtual uint32_t block_length() const = 0;
        virtual uint32_t key_length() const = 0;

        virtual void init(const secure_buffer&) = 0;

        virtual void encript(secure_buffer&) = 0;
        virtual void decript(secure_buffer&) = 0;

        virtual uint32_t decript_length(const uint8_t*) = 0;
    };
}

#endif
