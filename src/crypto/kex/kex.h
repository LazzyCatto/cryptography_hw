#ifndef KEX
#define KEX

#include <functional>

#include "src/connection/socket.h"

namespace minissh {
    using send_packet_fn = std::function<void(packet&&)>;

    class kex {
      public:
        virtual ~kex() = default;
        virtual std::string name() const = 0;

        virtual void init(
            const std::string& v_c,
            const std::string& v_s,
            const secure_buffer& i_c,
            const secure_buffer& i_s,
            send_packet_fn send
        ) = 0;

        virtual void on_message(const packet&) = 0;

        virtual bool is_done() const = 0;

        virtual mpint shared_secret() const = 0;
        virtual secure_buffer exchange_hash() const = 0;

        inline virtual secure_buffer host_key_blob() const { return secure_buffer{}; }
        inline virtual secure_buffer signature_blob() const { return secure_buffer{}; }
    };
}

#endif
