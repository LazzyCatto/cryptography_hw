#ifndef TRANSPORT
#define TRANSPORT

#include "connection/socket.h"
#include "minissh/numbers.h"
#include "minissh/registry.h"

namespace minissh {
    struct keyinit {
        uint8_t message_number;
        std::array<uint8_t, 16> cookie;
        minissh::namelist kex_algorithms;
        minissh::namelist server_host_key_algorithms;
        minissh::namelist encryption_algorithms_client_to_server;
        minissh::namelist encryption_algorithms_server_to_client;
        minissh::namelist mac_algorithms_client_to_server;
        minissh::namelist mac_algorithms_server_to_client;
        minissh::namelist compression_algorithms_client_to_server;
        minissh::namelist compression_algorithms_server_to_client;
        minissh::namelist languages_client_to_server;
        minissh::namelist languages_server_to_client;
        bool first_kex_packet_follows;
        uint32_t extentions;
    };

    struct newkeys {
        uint8_t message_number = SSH_MSG_NEWKEYS;
    };

    class transport_layer {
      public:
        transport_layer(const char* host, const char* port, const char* protocol_name) :
            _socket{host, port},
            _client_protocol_name(protocol_name),
            _recv_counter{0},
            _send_counter{0},
            _first_kex{true}
        {
            if (!_init()) {
                LOG_ERROR("could not initialize transport layer.");
                throw std::runtime_error("could not initialize transport layer.");
            }
        }
        transport_layer(const char* host, const char* port) : transport_layer(host, port, "SSH-2.0-minissh_1.0\r\n") {}
        transport_layer(const char* host) : transport_layer(host, "22") {}
        transport_layer() : transport_layer("localhost") {}

        bool init_kex();

        packet recv_packet();
        void send_packet(packet&&);

        uint32_t recv_counter() const { return _recv_counter; }
        uint32_t send_counter() const { return _send_counter; }

      private:
        client_socket _socket;

        std::string _client_protocol_name;
        std::string _server_protocol_name;

        uint32_t _recv_counter;
        uint32_t _send_counter;

        struct algorythms {
            std::unique_ptr<kex> kex_algorithms = nullptr;
            std::unique_ptr<host_key> server_host_key_algorithms = nullptr;
            std::unique_ptr<cipher> encryption_algorithms_client_to_server = nullptr;
            std::unique_ptr<cipher> encryption_algorithms_server_to_client = nullptr;
            std::unique_ptr<mac> mac_algorithms_client_to_server = nullptr;
            std::unique_ptr<mac> mac_algorithms_server_to_client = nullptr;
        } _selected_algos;

        secure_buffer _session_id;
        bool _first_kex;

        struct keys {
            secure_buffer initial_iv_client_to_server;
            secure_buffer initial_iv_server_to_client;
            secure_buffer encryption_key_client_to_server;
            secure_buffer encryption_key_server_to_client;
            secure_buffer integrity_key_client_to_server;
            secure_buffer integrity_key_server_to_client;
        } _keys;

        bool _init();

        void _init_keys();
        void _init_algos();

        bool _prepare_kex(algorythms*);
        bool _prepare_protolcol_list(keyinit*) const;

        bool _select_kex(const keyinit& client, const keyinit& server, std::unique_ptr<kex>*) const;
        bool _select_host_key(const keyinit& client, const keyinit& server, std::unique_ptr<host_key>*) const;
        bool _select_cipher_server(const keyinit& client, const keyinit& server, std::unique_ptr<cipher>*) const;
        bool _select_cipher_client(const keyinit& client, const keyinit& server, std::unique_ptr<cipher>*) const;
        bool _select_mac_server(const keyinit& client, const keyinit& server, std::unique_ptr<mac>*) const;
        bool _select_mac_client(const keyinit& client, const keyinit& server, std::unique_ptr<mac>*) const;

        secure_buffer _get_key(const mpint&, const secure_buffer&, char, const secure_buffer&, uint32_t);
    };
}

#endif
