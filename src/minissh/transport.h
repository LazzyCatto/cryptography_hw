#ifndef TRANSPORT
#define TRANSPORT

#include "src/connection/socket.h"
#include "src/minissh/numbers.h"
#include "src/minissh/registry.h"

namespace minissh {
    class transport_layer {
      public:
        transport_layer(const char* host, const char* port, const char* protocol_name) :
            _closed{false},
            _socket{host, port},
            _client_protocol_name(protocol_name),
            _recv_counter{0},
            _send_counter{0}
        {
            _init();
        }
        transport_layer(const char* host, const char* port) : transport_layer(host, port, "SSH-2.0-minissh_1.0\r\n") {}
        transport_layer(const char* host) : transport_layer(host, "22") {}
        transport_layer() : transport_layer("localhost") {}
         ~transport_layer() { close(); }

        transport_layer(const transport_layer&) = delete;
        transport_layer(transport_layer&&);

        transport_layer& operator=(const transport_layer&) = delete;
        transport_layer& operator=(transport_layer&&);

        void close() {
            if (!_closed) {
                LOG_INFO("close client_transport_layer");
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

      private:
        bool _closed;

        std::string _client_protocol_name;
        std::string _server_protocol_name;

        client_socket _socket;

        uint32_t _recv_counter;
        uint32_t _send_counter;

        struct keyinit {
            uint8_t message_number;
            std::array<uint8_t, 16> cookie;
            minissh::namelist kex_algorithms;
            minissh::namelist server_host_key_algorithms;
            minissh::namelist encryption_algorithms_client_to_server;
            minissh::namelist encryption_algorithms_server_to_client;
            minissh::namelist mac_algorithms_client_to_server;
            minissh::namelist mac_algorithms_server_to_client;
        };

        struct algorythms {
            std::unique_ptr<kex> kex_algorithms = nullptr;
            std::unique_ptr<host_key> server_host_key_algorithms = nullptr;
            std::unique_ptr<cipher> encryption_algorithms_client_to_server = nullptr;
            std::unique_ptr<cipher> encryption_algorithms_server_to_client = nullptr;
            std::unique_ptr<mac> mac_algorithms_client_to_server = nullptr;
            std::unique_ptr<mac> mac_algorithms_server_to_client = nullptr;
        } _selected_algos;

        struct keys {
            secure_buffer encryption_key_client_to_server;
            secure_buffer encryption_key_server_to_client;
            secure_buffer integrity_key_client_to_server;
            secure_buffer integrity_key_server_to_client;
        } _keys;

        void _init();

        void _init_keys();
        void _init_algos();

        void _prepare_kex(algorythms*);
        void _prepare_protolcol_list(keyinit*) const;

        bool _select_kex(const keyinit& client, const keyinit& server, std::unique_ptr<kex>*) const;
        bool _select_host_key(const keyinit& client, const keyinit& server, std::unique_ptr<host_key>*) const;
        bool _select_cipher_server(const keyinit& client, const keyinit& server, std::unique_ptr<cipher>*) const;
        bool _select_cipher_client(const keyinit& client, const keyinit& server, std::unique_ptr<cipher>*) const;
        bool _select_mac_server(const keyinit& client, const keyinit& server, std::unique_ptr<mac>*) const;
        bool _select_mac_client(const keyinit& client, const keyinit& server, std::unique_ptr<mac>*) const;

        secure_buffer _get_key(const mpint&, char, const secure_buffer&);
        secure_buffer _get_mask(const mpint&, char, uint32_t);

        std::string _try_read_string_from_buffer(const uint8_t*, uint32_t) const;
    };
}

#endif
