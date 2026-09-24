#ifndef HOSTKEY
#define HOSTKEY

#include <functional>

#include "connection/socket.h"

namespace minissh {
    class host_key {
      public:
        virtual ~host_key() = default;
        virtual constexpr std::string name() const = 0;

        virtual bool verify(
            const secure_buffer& h,
            const secure_buffer& ks,
            const secure_buffer& s
        ) const = 0;
    };
}

#endif
