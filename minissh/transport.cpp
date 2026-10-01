#include "minissh/transport.h"

#include "crypto/hash.h"
#include "crypto/rand.h"
#include "minissh/numbers.h"
#include "logger.h"

namespace minissh {
    transport_layer::transport_layer(transport_layer&& other) {
        if (&other == this) {
            return;
        }

        _closed = other._closed;
        _client_protocol_name = std::move(other._client_protocol_name);
        _server_protocol_name = std::move(other._server_protocol_name);
        _socket = std::move(other._socket);
        _recv_counter = other._recv_counter;
        _send_counter = other._send_counter;
        _selected_algos = std::move(other._selected_algos);
        _session_id = std::move(other._session_id);
        _first_kex = other._first_kex;
        _keys = std::move(other._keys);

        other._closed = true;
    }

    transport_layer& transport_layer::operator=(transport_layer&& other) {
        if (&other == this) {
            return *this;
        }

        _closed = other._closed;
        _client_protocol_name = std::move(other._client_protocol_name);
        _server_protocol_name = std::move(other._server_protocol_name);
        _socket = std::move(other._socket);
        _recv_counter = other._recv_counter;
        _send_counter = other._send_counter;
        _selected_algos = std::move(other._selected_algos);
        _session_id = std::move(other._session_id);
        _first_kex = other._first_kex;
        _keys = std::move(other._keys);

        other._closed = true;

        return *this;
    }

    void transport_layer::init_kex() {
        LOG_INFO("start KEX init");
        algorythms selected_algos;
        _prepare_kex(&selected_algos);

        if (!selected_algos.kex_algorithms) {
            LOG_WARN("no KEX algrythm is used");
            return;
        }
        
        LOG_DEBUG("starting KEX loop");
        while (!selected_algos.kex_algorithms->is_done()) {
            packet server_kex_packet = recv();
            uint8_t msg_num = server_kex_packet.message_number();
            if (msg_num < 30 || msg_num >= 50) {
                throw std::runtime_error("invalid message number for kex");
            }
            selected_algos.kex_algorithms->on_message(server_kex_packet);
        }

        if (!selected_algos.server_host_key_algorithms) {
            LOG_WARN("no HOST KEY algrythm is used");
        } else {
            {
                std::string key_algorythm_name = _try_read_string_from_buffer(
                    selected_algos.kex_algorithms->host_key_blob().data(),
                    selected_algos.kex_algorithms->host_key_blob().length()
                );
                std::string signature_algorythm_name = _try_read_string_from_buffer(
                    selected_algos.kex_algorithms->signature_blob().data(),
                    selected_algos.kex_algorithms->signature_blob().length()
                );

                LOG_DEBUG(std::format("recieved \"{}\" as key algorythm", key_algorythm_name));
                LOG_DEBUG(std::format("recieved \"{}\" as signature algorythm", signature_algorythm_name));

                if (key_algorythm_name != selected_algos.server_host_key_algorithms->key_name()) {
                    throw std::runtime_error{"invalid key algorythm is used"};
                }

                if (signature_algorythm_name != selected_algos.server_host_key_algorithms->name()) {
                    throw std::runtime_error{"invalid signature algorythm is used"};
                }
            }

            LOG_INFO("checking signature...");
            bool verified = selected_algos.server_host_key_algorithms->verify(
                selected_algos.kex_algorithms->exchange_hash(),
                selected_algos.kex_algorithms->host_key_blob(),
                selected_algos.kex_algorithms->signature_blob()
            );
            if (!verified) {
                throw std::runtime_error{"signature is not verified!"};
            }
        }

        LOG_INFO("KEX done");
        send(packet{newkeys{}});
        packet new_keys_packet = recv();

        if (new_keys_packet.message_number() != MINISSH_NEWKEYS) {
            throw std::runtime_error{"failed to use new keys"};
        }

        LOG_DEBUG("setting up new keys...");
        _selected_algos = std::move(selected_algos);

        if (_first_kex) {
            LOG_INFO("first kex - setting up session_id");
            _session_id = _selected_algos.kex_algorithms->exchange_hash();
            _first_kex = false;
        }

        _init_keys();
        _init_algos();
    }

    packet transport_layer::recv() {
        bool use_mac = bool(_selected_algos.mac_algorithms_server_to_client);
        bool use_enc = bool(_selected_algos.encryption_algorithms_server_to_client);

        packet result;
        if (use_enc) {
            uint8_t size_bytes[4];
            _socket.recv_bytes(size_bytes, 4);

            uint32_t packet_length = _selected_algos.encryption_algorithms_server_to_client->decript_length(size_bytes);

            if (packet_length > 5000) {
                throw std::runtime_error("message too long, probably the encryption problem");
            }
            if ((packet_length + 4) % _selected_algos.encryption_algorithms_server_to_client->block_length() != 0) {
                throw std::runtime_error("message size is not multiple of block length");
            }

            secure_buffer encripted_data{packet_length + 4};
            memcpy(encripted_data.data(), size_bytes, 4);

            _socket.recv_bytes(encripted_data.data() + 4, packet_length);

            _selected_algos.encryption_algorithms_server_to_client->decript(encripted_data);
            uint8_t padding_length = encripted_data[4];

            if (padding_length < 4) {
                throw std::runtime_error("padding length must be at least 4");
            }
            if (padding_length >= packet_length - 1) {
                throw std::runtime_error("padding too long, probably the encryption problem");
            }
        
            uint32_t payload_length = packet_length - padding_length - 1;
            result = packet{payload_length, padding_length};
            memcpy(result.payload().data(), encripted_data.data() + 5, result.payload_length());
            memcpy(result.padding().data(), encripted_data.data() + packet_length - padding_length + 4, result.padding_length());
        } else {
            uint8_t size_bytes[5];
            _socket.recv_bytes(size_bytes, 5);

            uint32_t packet_length;
            uint8_t padding_length;
            uint32_t offset = 0;
            _read_from_buffer(size_bytes, offset, &packet_length);
            _read_from_buffer(size_bytes, offset, &padding_length);

            if (packet_length > 5000) {
                throw std::runtime_error("message too long, probably the littleendian format");
            }
            if ((packet_length + 4) % 8 != 0) {
                throw std::runtime_error("message size is not multiple of 8");
            }
            if (padding_length < 4) {
                throw std::runtime_error("padding length must be at least 4");
            }
            if (padding_length >= packet_length - 1) {
                throw std::runtime_error("padding too long");
            }

            uint32_t payload_length = packet_length - padding_length - 1;
            result = packet{payload_length, padding_length};
            _socket.recv_bytes(result.payload().data(), payload_length);
            _socket.recv_bytes(result.padding().data(), padding_length);
        }

        if (use_mac) {
            LOG_DEBUG(std::format("use \"{}\"", _selected_algos.mac_algorithms_server_to_client->name()));

            secure_buffer mac_sign{_selected_algos.mac_algorithms_server_to_client->mac_length()};
            _socket.recv_bytes(mac_sign.data(), mac_sign.length());

            secure_buffer target_sign = _selected_algos.mac_algorithms_server_to_client->sign(_recv_counter, result.main_packet());
            if (target_sign != mac_sign) {
                throw std::runtime_error("signature is not verified");
            }
        }

        LOG_DEBUG(std::format(
            "recieving packet id={}, msg_num={}",
            _recv_counter,
            msg_num_to_string(result.message_number())
        ));
        ++_recv_counter;
        return result;
    }

    void transport_layer::send(packet&& to_send) {
        LOG_DEBUG(std::format(
            "sending packet id={}, msg_number={}",
            _send_counter,
            msg_num_to_string(to_send.message_number())
        ));

        bool use_mac = bool(_selected_algos.mac_algorithms_client_to_server);
        bool use_enc = bool(_selected_algos.encryption_algorithms_client_to_server);

        if (use_enc) {
            to_send.set_padding_to_be_multiple(_selected_algos.encryption_algorithms_client_to_server->block_length());
        } else {
            to_send.set_padding_to_be_multiple();
        }

        secure_buffer mac_sign;
        if (use_mac) {
            LOG_DEBUG(std::format("use \"{}\"", _selected_algos.mac_algorithms_client_to_server->name()));

            mac_sign = std::move(_selected_algos.mac_algorithms_client_to_server->sign(_send_counter, to_send.main_packet()));
        }

        if (_selected_algos.encryption_algorithms_client_to_server) {
            LOG_DEBUG(std::format("use \"{}\"", _selected_algos.encryption_algorithms_client_to_server->name()));

            secure_buffer encrypt_data = to_send.main_packet();
            _selected_algos.encryption_algorithms_client_to_server->encript(encrypt_data);
            _socket.send_bytes(encrypt_data.data(), encrypt_data.length());
        } else {
            _socket.send_packet(to_send);
        }

        if (use_mac) {
            _socket.send_bytes(mac_sign.data(), mac_sign.length());
        }

        ++_send_counter;
    }

    void transport_layer::_init() {
        LOG_INFO("initializing transport layer");
        _socket.send_string(_client_protocol_name + '\n');
        _server_protocol_name = _socket.recv_string();
        
        std::string_view _formated_client_protocol_name{_client_protocol_name};
        _formated_client_protocol_name.remove_suffix(2);
        LOG_INFO(std::format("client_protocol_name : \"{}\"", _formated_client_protocol_name));
        std::string_view _formated_server_protocol_name{_server_protocol_name};
        _formated_server_protocol_name.remove_suffix(2);
        LOG_INFO(std::format("server_protocol_name : \"{}\"", _formated_server_protocol_name));

        if (!_server_protocol_name.starts_with("MINISSH-")) {
            throw std::runtime_error("invalid first message");
        }
    }

    void transport_layer::_init_keys() {
        LOG_DEBUG("initializing keys");
        LOG_DEBUG(std::format("K = {}", string_repr(_selected_algos.kex_algorithms->shared_secret())));
        LOG_DEBUG(std::format("H = {}", string_repr(_selected_algos.kex_algorithms->exchange_hash())));

        if (_selected_algos.encryption_algorithms_client_to_server) {
            _keys.initial_iv_client_to_server = _get_key(
                _selected_algos.kex_algorithms->shared_secret(),
                _selected_algos.kex_algorithms->exchange_hash(),
                'A',
                _session_id,
                _selected_algos.encryption_algorithms_client_to_server->iv_length()
            );
        }
        if (_selected_algos.encryption_algorithms_server_to_client) {
            _keys.initial_iv_server_to_client = _get_key(
                _selected_algos.kex_algorithms->shared_secret(),
                _selected_algos.kex_algorithms->exchange_hash(),
                'B',
                _session_id,
                _selected_algos.encryption_algorithms_server_to_client->iv_length()
            );
        }
        if (_selected_algos.encryption_algorithms_client_to_server) {
            _keys.encryption_key_client_to_server = _get_key(
                _selected_algos.kex_algorithms->shared_secret(),
                _selected_algos.kex_algorithms->exchange_hash(),
                'C',
                _session_id,
                _selected_algos.encryption_algorithms_client_to_server->key_length()
            );
        }
        if (_selected_algos.encryption_algorithms_server_to_client) {
            _keys.encryption_key_server_to_client = _get_key(
                _selected_algos.kex_algorithms->shared_secret(),
                _selected_algos.kex_algorithms->exchange_hash(),
                'D',
                _session_id,
                _selected_algos.encryption_algorithms_server_to_client->key_length()
            );
        }
        if (_selected_algos.mac_algorithms_client_to_server) {
            _keys.integrity_key_client_to_server = _get_key(
                _selected_algos.kex_algorithms->shared_secret(),
                _selected_algos.kex_algorithms->exchange_hash(),
                'E',
                _session_id,
                _selected_algos.mac_algorithms_client_to_server->key_length()
            );
        }
        if (_selected_algos.mac_algorithms_server_to_client) {
            _keys.integrity_key_server_to_client = _get_key(
                _selected_algos.kex_algorithms->shared_secret(),
                _selected_algos.kex_algorithms->exchange_hash(),
                'F',
                _session_id,
                _selected_algos.mac_algorithms_server_to_client->key_length()
            );
        }
    }

    void transport_layer::_init_algos() {
        LOG_DEBUG("initializing algorythms");

        if (_selected_algos.mac_algorithms_client_to_server) {
            _selected_algos.mac_algorithms_client_to_server->init(
                _keys.integrity_key_client_to_server
            );
        }

        if (_selected_algos.mac_algorithms_server_to_client) {
            _selected_algos.mac_algorithms_server_to_client->init(
                _keys.integrity_key_server_to_client
            );
        }

        if (_selected_algos.encryption_algorithms_client_to_server) {
            _selected_algos.encryption_algorithms_client_to_server->init(
                _keys.initial_iv_client_to_server,
                _keys.encryption_key_client_to_server
            );
        }

        if (_selected_algos.encryption_algorithms_server_to_client) {
            _selected_algos.encryption_algorithms_server_to_client->init(
                _keys.initial_iv_server_to_client,
                _keys.encryption_key_server_to_client
            );
        }
    }

    void transport_layer::_prepare_kex(algorythms* selected_algos) {
        LOG_DEBUG("preparing KEX");

        keyinit client_init_message{};
        _prepare_protolcol_list(&client_init_message);

        LOG_DEBUG("sending suitable protocol list");
        LOG_INFO(std::format("client to server: {}", string_repr(client_init_message)));

        packet client_init_packet{client_init_message};
        secure_buffer i_c = client_init_packet.payload();
        send(std::move(client_init_packet));

        LOG_DEBUG("recieving suitable protocol list");

        packet server_init_package = recv();
        secure_buffer i_s = server_init_package.payload();
        if (server_init_package.message_number() != MINISSH_KEXINIT) {
            throw std::runtime_error(std::format("invalid message number during kex : {}", static_cast<int>(server_init_package.message_number())));
        }

        keyinit server_init_message = server_init_package.to_struct<keyinit>();
        LOG_INFO(std::format("server to client: {}", string_repr(server_init_message)));

        if (!_select_kex(client_init_message, server_init_message, &selected_algos->kex_algorithms)) {
            throw std::runtime_error("no suitable kex was found");
        }
        if (!_select_host_key(client_init_message, server_init_message, &selected_algos->server_host_key_algorithms)) {
            throw std::runtime_error("no suitable host key was found");
        }
        if (!_select_cipher_server(client_init_message, server_init_message, &selected_algos->encryption_algorithms_server_to_client)) {
            throw std::runtime_error("no suitable cipher was found");
        }
        if (!_select_cipher_client(client_init_message, server_init_message, &selected_algos->encryption_algorithms_client_to_server)) {
            throw std::runtime_error("no suitable cipher was found");
        }
        if (!_select_mac_server(client_init_message, server_init_message, &selected_algos->mac_algorithms_server_to_client)) {
            throw std::runtime_error("no suitable mac was found");
        }
        if (!_select_mac_client(client_init_message, server_init_message, &selected_algos->mac_algorithms_client_to_server)) {
            throw std::runtime_error("no suitable mac was found");
        }

        if (selected_algos->kex_algorithms) {
            selected_algos->kex_algorithms->init(
                _client_protocol_name,
                _server_protocol_name,
                i_c,
                i_s,
                [this](packet&& to_send) { this->send(std::move(to_send)); }
            );
        } else {
            LOG_WARN("no KEX is used");
        }
    }

    void transport_layer::_prepare_protolcol_list(keyinit* result) const {
        result->message_number = MINISSH_KEXINIT;
        fill_random(result->cookie.data(), 16);
        result->kex_algorithms = kex_registry().get_value_names();
        result->server_host_key_algorithms = host_key_registry().get_value_names();
        result->encryption_algorithms_client_to_server = client_cipher_registry().get_value_names();
        result->encryption_algorithms_server_to_client = server_cipher_registry().get_value_names();
        result->mac_algorithms_client_to_server = client_mac_registry().get_value_names();
        result->mac_algorithms_server_to_client = server_mac_registry().get_value_names();
    }

    bool transport_layer::_select_kex(const keyinit& client, const keyinit& server, std::unique_ptr<kex>* result) const {
        for (const std::string& client_kex_algo : client.kex_algorithms) {
            for (const std::string& server_kex_algo : server.kex_algorithms) {
                if (client_kex_algo == server_kex_algo) {
                    if (client_kex_algo == "none") {
                        *result = nullptr;
                    }
                    *result = std::move(kex_registry().get_value(client_kex_algo));
                    return true;
                }
            }
        }
        return false;
    }

    bool transport_layer::_select_host_key(const keyinit& client, const keyinit& server, std::unique_ptr<host_key>* result) const {
        for (const std::string& client_host_key_algo : client.server_host_key_algorithms) {
            for (const std::string& server_host_key_algo : server.server_host_key_algorithms) {
                if (client_host_key_algo == server_host_key_algo) {
                    if (client_host_key_algo == "none") {
                        *result = nullptr;
                    }
                    *result = std::move(host_key_registry().get_value(client_host_key_algo));
                    return true;
                }
            }
        }
        return false;
    }

    bool transport_layer::_select_cipher_server(const keyinit& client, const keyinit& server, std::unique_ptr<cipher>* result) const {
        for (const std::string& client_encryption_algo : client.encryption_algorithms_server_to_client) {
            for (const std::string& server_encryption_algo : server.encryption_algorithms_server_to_client) {
                if (client_encryption_algo == server_encryption_algo) {
                    if (client_encryption_algo == "none") {
                        *result = nullptr;
                    }
                    *result = std::move(server_cipher_registry().get_value(client_encryption_algo));
                    return true;
                }
            }
        }
        return false;
    }

    bool transport_layer::_select_cipher_client(const keyinit& client, const keyinit& server, std::unique_ptr<cipher>* result) const {
        for (const std::string& client_encryption_algo : client.encryption_algorithms_client_to_server) {
            for (const std::string& server_encryption_algo : server.encryption_algorithms_client_to_server) {
                if (client_encryption_algo == server_encryption_algo) {
                    if (client_encryption_algo == "none") {
                        *result = nullptr;
                    }
                    *result = std::move(client_cipher_registry().get_value(client_encryption_algo));
                    return true;
                }
            }
        }
        return false;
    }

    bool transport_layer::_select_mac_server(const keyinit& client, const keyinit& server, std::unique_ptr<mac>* result) const {
        for (const std::string& client_mac_algo : client.mac_algorithms_server_to_client) {
            for (const std::string& server_mac_algo : server.mac_algorithms_server_to_client) {
                if (client_mac_algo == server_mac_algo) {
                    if (client_mac_algo == "none") {
                        *result = nullptr;
                    }
                    *result = std::move(server_mac_registry().get_value(client_mac_algo));
                    return true;
                }
            }
        }
        return false;
    }

    bool transport_layer::_select_mac_client(const keyinit& client, const keyinit& server, std::unique_ptr<mac>* result) const {
        for (const std::string& client_mac_algo : client.mac_algorithms_client_to_server) {
            for (const std::string& server_mac_algo : server.mac_algorithms_client_to_server) {
                if (client_mac_algo == server_mac_algo) {
                    if (client_mac_algo == "none") {
                        *result = nullptr;
                    }
                    *result = std::move(client_mac_registry().get_value(client_mac_algo));
                    return true;
                }
            }
        }
        return false;
    }

    secure_buffer transport_layer::_get_key(
        const mpint& k,
        const secure_buffer& h,
        char x,
        const secure_buffer& session_id,
        uint32_t desired_length
    ) {
        secure_buffer result = sha_256(secure_buffer::cat({
            get_secure_buffer_from_object(k),
            h,
            secure_buffer{reinterpret_cast<const uint8_t*>(&x), 1},
            session_id
        }));
        if (result.length() >= desired_length) {
            if (result.length() > desired_length) {
                return secure_buffer{result.data(), desired_length};
            }
            return result;
        }
        secure_buffer postfix = result;
        while (true) {
            secure_buffer kn = sha_256(secure_buffer::cat({
                get_secure_buffer_from_object(k),
                h,
                postfix
            }));
            postfix = secure_buffer::cat({
                postfix,
                kn
            });
            if (postfix.length() >= desired_length) {
                if (postfix.length() > desired_length) {
                    return secure_buffer{postfix.data(), desired_length};
                }
                return postfix;
            }
        }
    }

    std::string transport_layer::_try_read_string_from_buffer(const uint8_t* buffer, uint32_t max_length) const {
        uint32_t length;
        _read_from_buffer_no_offset(buffer, &length);

        if (length > max_length) {
            throw std::runtime_error("string too long");
        }

        return std::string(reinterpret_cast<const char*>(buffer), length);
    }
}
