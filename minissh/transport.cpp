#include "transport.h"

#include "crypto/hash.h"
#include "crypto/rand.h"

namespace minissh {
    bool transport_layer::init_kex() {
        LOG_INFO("start KEX init");
        algorythms selected_algos;
        if (!_prepare_kex(&selected_algos)) {
            LOG_WARN("failed to prepare kex");
            return false;
        }
        
        LOG_DEBUG("starting kex loop");
        while (!selected_algos.kex_algorithms->is_done()) {
            packet server_kex_packet = recv_packet();
            selected_algos.kex_algorithms->on_message(server_kex_packet);
        }

        {
            std::string key_algorythm_name;
            std::string signature_algorythm_name;

            _read_from_buffer_no_offset(selected_algos.kex_algorithms->host_key_blob().data(), &key_algorythm_name);
            _read_from_buffer_no_offset(selected_algos.kex_algorithms->signature_blob().data(), &signature_algorythm_name);

            LOG_INFO(std::format("recieved \"{}\" as key algorythm", key_algorythm_name));
            LOG_INFO(std::format("recieved \"{}\" as signature algorythm", signature_algorythm_name));
        }

        LOG_INFO("checking signature...");
        bool verified = selected_algos.server_host_key_algorithms->verify(
            selected_algos.kex_algorithms->exchange_hash(),
            selected_algos.kex_algorithms->host_key_blob(),
            selected_algos.kex_algorithms->signature_blob()
        );
        if (!verified) {
            LOG_WARN("signature is not verified!");
            return false;
        }

        LOG_INFO("KEX done");
        send_packet(packet{newkeys{}});
        packet new_keys_packet = recv_packet();

        if (new_keys_packet.message_number() != SSH_MSG_NEWKEYS) {
            LOG_WARN("failed to use new keys");
            return false;
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

        return true;
    }

    packet transport_layer::recv_packet() {
        LOG_DEBUG(std::format("recieving packet {}", _recv_counter));
        bool use_mac = bool(_selected_algos.mac_algorithms_server_to_client);
        bool use_enc = bool(_selected_algos.encryption_algorithms_server_to_client);

        packet result;
        if (use_enc) {
            LOG_DEBUG(std::format("use \"{}\"", _selected_algos.encryption_algorithms_server_to_client->name()));

            uint8_t size_bytes[4];
            _socket.recv_bytes(size_bytes, 4);

            uint32_t packet_length = _selected_algos.encryption_algorithms_server_to_client->decript_length(size_bytes);

            secure_buffer encripted_data{packet_length + 4};
            memcpy(encripted_data.data(), size_bytes, 4);

            _socket.recv_bytes(encripted_data.data() + 4, packet_length);

            _selected_algos.encryption_algorithms_server_to_client->decript(encripted_data);
            uint8_t padding = encripted_data[4];
        
            result = packet{packet_length - padding - 1, padding};
            memcpy(result.payload().data(), encripted_data.data() + 5, result.payload_length());
            memcpy(result.padding().data(), encripted_data.data() + packet_length - padding + 4, result.payload_length());
        } else {
            result = _socket.recv_packet();
        }

        if (use_mac) {
            LOG_DEBUG(std::format("use \"{}\"", _selected_algos.mac_algorithms_server_to_client->name()));

            secure_buffer mac_sign{_selected_algos.mac_algorithms_server_to_client->mac_length()};
            _socket.recv_bytes(mac_sign.data(), mac_sign.length());

            secure_buffer target_sign = _selected_algos.mac_algorithms_server_to_client->sign(_recv_counter, result.main_packet());
            if (target_sign != mac_sign) {
                LOG_ERROR("signature is not verified.");
                throw std::runtime_error("signature is not verified.");
            }
        }

        ++_recv_counter;
        return result;
    }

    void transport_layer::send_packet(packet&& to_send) {
        LOG_DEBUG(std::format("sending packet {}", _send_counter));
        LOG_DEBUG(std::format("msg_num: {}", static_cast<int>(to_send.message_number())));

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

    bool transport_layer::_init() {
        LOG_INFO("initializing transport layer");
        _socket.send_string(_client_protocol_name);
        _server_protocol_name = _socket.recv_string();

        LOG_INFO(std::format("client_protocol_name : \"{}\"", _client_protocol_name));
        LOG_INFO(std::format("server_protocol_name : \"{}\"", _server_protocol_name));

        return true;
    }

    void transport_layer::_init_keys() {
        LOG_DEBUG("initializing keys");

        _keys.initial_iv_client_to_server = _get_key(
            _selected_algos.kex_algorithms->shared_secret(),
            _selected_algos.kex_algorithms->exchange_hash(),
            'A',
            _session_id,
            _selected_algos.encryption_algorithms_client_to_server->iv_length()
        );
        _keys.initial_iv_server_to_client = _get_key(
            _selected_algos.kex_algorithms->shared_secret(),
            _selected_algos.kex_algorithms->exchange_hash(),
            'B',
            _session_id,
            _selected_algos.encryption_algorithms_server_to_client->iv_length()
        );
        _keys.encryption_key_client_to_server = _get_key(
            _selected_algos.kex_algorithms->shared_secret(),
            _selected_algos.kex_algorithms->exchange_hash(),
            'C',
            _session_id,
            _selected_algos.encryption_algorithms_client_to_server->key_length()
        );
        _keys.encryption_key_server_to_client = _get_key(
            _selected_algos.kex_algorithms->shared_secret(),
            _selected_algos.kex_algorithms->exchange_hash(),
            'D',
            _session_id,
            _selected_algos.encryption_algorithms_server_to_client->key_length()
        );
        _keys.integrity_key_client_to_server = _get_key(
            _selected_algos.kex_algorithms->shared_secret(),
            _selected_algos.kex_algorithms->exchange_hash(),
            'E',
            _session_id,
            _selected_algos.mac_algorithms_client_to_server->key_length()
        );
        _keys.integrity_key_server_to_client = _get_key(
            _selected_algos.kex_algorithms->shared_secret(),
            _selected_algos.kex_algorithms->exchange_hash(),
            'F',
            _session_id,
            _selected_algos.mac_algorithms_server_to_client->key_length()
        );
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

    bool transport_layer::_prepare_kex(algorythms* selected_algos) {
        LOG_DEBUG("preparing KEX");

        keyinit client_init_message{};
        _prepare_protolcol_list(&client_init_message);

        LOG_DEBUG("sending suitable protocol list");
        LOG_INFO(std::format("client to server: {}", string_repr(client_init_message)));

        packet client_init_packet{client_init_message};
        secure_buffer i_c = client_init_packet.payload();
        send_packet(std::move(client_init_packet));

        LOG_DEBUG("recieving suitable protocol list");

        packet server_init_package = recv_packet();
        secure_buffer i_s = server_init_package.payload();
        if (server_init_package.message_number() != SSH_MSG_KEXINIT) {
            LOG_INFO(std::format("invalid message number during kex : {}", static_cast<int>(server_init_package.message_number())));
            return false;
        }

        keyinit server_init_message = server_init_package.to_struct<keyinit>();
        LOG_INFO(std::format("server to client: {}", string_repr(server_init_message)));

        if (!_select_kex(client_init_message, server_init_message, &selected_algos->kex_algorithms)) {
            LOG_INFO("no suitable kex was found");
            return false;
        }
        if (!_select_host_key(client_init_message, server_init_message, &selected_algos->server_host_key_algorithms)) {
            LOG_INFO("no suitable host key was found");
            return false;
        }
        if (!_select_cipher_server(client_init_message, server_init_message, &selected_algos->encryption_algorithms_server_to_client)) {
            LOG_INFO("no suitable cipher was found");
            return false;
        }
        if (!_select_cipher_client(client_init_message, server_init_message, &selected_algos->encryption_algorithms_client_to_server)) {
            LOG_INFO("no suitable cipher was found");
            return false;
        }
        if (!_select_mac_server(client_init_message, server_init_message, &selected_algos->mac_algorithms_server_to_client)) {
            LOG_INFO("no suitable mac was found");
            return false;
        }
        if (!_select_mac_client(client_init_message, server_init_message, &selected_algos->mac_algorithms_client_to_server)) {
            LOG_INFO("no suitable mac was found");
            return false;
        }

        LOG_DEBUG(std::format("initializiing \"{}\"", selected_algos->kex_algorithms->name()));
        selected_algos->kex_algorithms->init(
            _client_protocol_name,
            _server_protocol_name,
            i_c,
            i_s,
            [this](packet&& to_send) { this->send_packet(std::move(to_send)); }
        );

        return true;
    }

    bool transport_layer::_prepare_protolcol_list(keyinit* result) const {
        result->message_number = SSH_MSG_KEXINIT;
        fill_random(result->cookie.data(), 16);
        result->kex_algorithms = kex_registry().get_value_names();
        result->server_host_key_algorithms = host_key_registry().get_value_names();
        result->encryption_algorithms_client_to_server = client_cipher_registry().get_value_names();
        result->encryption_algorithms_server_to_client = server_cipher_registry().get_value_names();
        result->mac_algorithms_client_to_server = client_mac_registry().get_value_names();
        result->mac_algorithms_server_to_client = server_mac_registry().get_value_names();
        result->compression_algorithms_client_to_server = {"none"};
        result->compression_algorithms_server_to_client = {"none"};
        result->languages_client_to_server = {};
        result->languages_server_to_client = {};
        result->first_kex_packet_follows = false;
        result->extentions = 0;

        return true;
    }

    bool transport_layer::_select_kex(const keyinit& client, const keyinit& server, std::unique_ptr<kex>* result) const {
        for (const std::string& client_kex_algo : client.kex_algorithms) {
            for (const std::string& server_kex_algo : server.kex_algorithms) {
                if (client_kex_algo == server_kex_algo) {
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
}
