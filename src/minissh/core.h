#ifndef CORE
#define CORE

#include "src/minissh/transport.h"

#include <deque>
#include <memory>
#include <optional>

namespace minissh {
    struct message {
        std::string destination;
        secure_buffer data;
    };

    class core {
      public:
        core(std::unique_ptr<transport_layer> transport);
        ~core() { close(); }

        core(const core&) = delete;
        core(core&&) = default;

        core& operator=(const core&) = delete;
        core& operator=(core&&) = default;

        void run();
        void close();
        bool is_closed();

        void send_debug_message(const std::string&);
        void init_kex();
        void authorize(const std::string& username, const std::string& password);
        std::optional<message> read_tunnel();
        void write_in_tunnel(message&&);
        void connect(const std::string& secret_key);

      private:
        std::unique_ptr<transport_layer> _transport;
        std::deque<secure_buffer> _message_queue;

        void _request_service(const std::string&);

        void _transfer_data();
    };
}

#endif
