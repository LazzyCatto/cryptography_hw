#ifndef SERVER_TRANSPORT
#define SERVER_TRANSPORT

#include "src/connection/socket.h"
#include "src/minissh/numbers.h"
#include "src/minissh/registry.h"
#include <memory>

namespace minissh {
    class simple_server_transport_layer {
      public:
        simple_server_transport_layer(const char* host, const char* port, const char* protocol_name) :
            _closed{false},
            _socket{host, port},
            _client_protocol_name(protocol_name),
            _recv_counter{0},
            _send_counter{0},
            _first_kex{true}
        {
            _init();
        }
        ~simple_server_transport_layer() { close(); }

        simple_server_transport_layer(const simple_server_transport_layer&) = delete;
        simple_server_transport_layer(simple_server_transport_layer&&) = default;

        simple_server_transport_layer& operator=(const simple_server_transport_layer&) = delete;
        simple_server_transport_layer& operator=(simple_server_transport_layer&&) = default;

        void close() {
            if (!is_closed()) {
                LOG_INFO("close simple_server_transport_layer");
                _closed = true;
            }
        }

        bool is_closed() const noexcept { return _closed; }

        void send(packet&&);
        packet recv();
        packet recv_raw();

        void init_kex();

        uint32_t recv_counter() const { return _recv_counter; }
        uint32_t send_counter() const { return _send_counter; }

        template <typename T>
        T& get_socket() { return dynamic_cast<T&>(*_socket); }

      private:
        bool _closed;

        std::string _client_protocol_name;
        std::string _server_protocol_name;

        client_socket _socket;

        uint32_t _recv_counter;
        uint32_t _send_counter;

        struct algorythms {
            std::unique_ptr<server_kex> kex_algorithms = nullptr;
            std::unique_ptr<cipher> encryption_algorithms_client_to_server = nullptr;
            std::unique_ptr<cipher> encryption_algorithms_server_to_client = nullptr;
            std::unique_ptr<mac> mac_algorithms_client_to_server = nullptr;
            std::unique_ptr<mac> mac_algorithms_server_to_client = nullptr;
        } _selected_algos;

        secure_buffer _session_id;
        bool _first_kex;

        struct keys {
            secure_buffer encryption_key_client_to_server;
            secure_buffer encryption_key_server_to_client;
            secure_buffer integrity_key_client_to_server;
            secure_buffer integrity_key_server_to_client;
        } _keys;

        struct keyinit {
            uint8_t message_number;
            std::array<uint8_t, 16> cookie;
            namelist kex_algorithms;
            namelist server_host_key_algorithms;
            namelist encryption_algorithms_client_to_server;
            namelist encryption_algorithms_server_to_client;
            namelist mac_algorithms_client_to_server;
            namelist mac_algorithms_server_to_client;
        };

        struct newkeys {
            uint8_t message_number = MINISSH_NEWKEYS;
        };

        void _init();

        void _init_keys();
        void _init_algos();

        void _prepare_kex(algorythms*);
        void _prepare_protolcol_list(keyinit*) const;

        bool _select_server_kex(const keyinit& client, const keyinit& server, std::unique_ptr<server_kex>*) const;
        bool _select_cipher_server(const keyinit& client, const keyinit& server, std::unique_ptr<cipher>*) const;
        bool _select_cipher_client(const keyinit& client, const keyinit& server, std::unique_ptr<cipher>*) const;
        bool _select_mac_server(const keyinit& client, const keyinit& server, std::unique_ptr<mac>*) const;
        bool _select_mac_client(const keyinit& client, const keyinit& server, std::unique_ptr<mac>*) const;

        secure_buffer _get_key(const mpint&, const secure_buffer&, char, const secure_buffer&, uint32_t);

        std::string _try_read_string_from_buffer(const uint8_t*, uint32_t) const;
    };
}

#endif
