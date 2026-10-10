#ifndef MAC
#define MAC

#include <functional>

#include "src/connection/socket.h"

namespace minissh {
    class mac {
      public:
        virtual ~mac() = default;
        virtual constexpr std::string name() const = 0;
        virtual constexpr uint32_t key_length() const = 0;
        virtual constexpr uint32_t mac_length() const = 0;

        virtual void init(const secure_buffer&) = 0;
        virtual secure_buffer gen_key() const = 0;

        virtual secure_buffer sign(uint32_t, const secure_buffer&) const = 0;
    };
}

#endif
