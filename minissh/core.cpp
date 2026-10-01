#include "minissh/core.h"

#include <atomic>
#include <format>
#include <poll.h>
#include <thread>

#include "logger.h"

namespace minissh {
    namespace {
        struct text_message {
            uint8_t msg_num;
            std::string text;
        };

        struct data_message {
            uint8_t msg_num;
            secure_buffer data;
        };

        struct info_message {
            uint8_t msg_num;
        };
    }

    core::core(std::unique_ptr<transport_layer> transport) : _transport{std::move(transport)} {
        LOG_INFO("init core");
    }

    void core::run() {
        _request_service("channel_data");
        _transfer_data();
    }

    void core::close() {
        if (_transport && !_transport->is_closed()) {
            LOG_INFO("shutting down core");
            _transport->close();
        }
    }

    bool core::is_closed() {
        return !_transport || _transport->is_closed();
    }

    void core::send_debug_message(const std::string& text) {
        if (is_closed()) {
            throw std::runtime_error("closed");
        }

        _transport->send(packet{text_message{
            MINISSH_DEBUG,
            text
        }});
    }

    void core::init_kex() {
        if (is_closed()) {
            throw std::runtime_error("closed");
        }

        _transport->init_kex();
    }

    void core::authorize(const std::string& username, const std::string& password) {
        if (is_closed()) {
            throw std::runtime_error("closed");
        }

        _request_service("user_auth");

        struct user_auth_struct {
            uint8_t msg_num;
            std::string username;
            std::string password;
        } user_auth {
            MINISSH_USERAUTH_REQUEST,
            username,
            password
        };
        _transport->send(packet{user_auth});
        packet responce = _safe_recv();
        if (responce.message_number() == MINISSH_USERAUTH_FAILURE) {
            throw std::runtime_error("wrong password");
        }
        if (responce.message_number() == MINISSH_USERAUTH_SUCCESS) {
            _request_service("intercept");
            return;
        }
        throw std::runtime_error("authorize");
    }

    std::optional<message> core::read_tunnel() {
        if (is_closed()) {
            throw std::runtime_error("closed");
        }

        LOG_DEBUG("reading tunnel");
        _transport->send(packet{info_message{MINISSH_INTERCEPT_RECV_REQUEST}});
        packet responce = _safe_recv();
        if (responce.message_number() == MINISSH_INTERCEPT_FALIURE) {
            text_message text_msg = responce.to_struct<text_message>();
            LOG_INFO(text_msg.text);
            return std::nullopt;
        }
        if (responce.message_number() == MINISSH_INTERCEPT_SUCCESS) {
            struct intercept_message {
                uint8_t msg_num;
                std::string destination;
                secure_buffer data;
            } intercept_msg = responce.to_struct<intercept_message>();
            return message{intercept_msg.destination, intercept_msg.data};
        }
        throw std::runtime_error("read tunnel");
    }

    void core::write_in_tunnel(message&& mgs) {
        if (is_closed()) {
            throw std::runtime_error("closed");
        }

        struct intercept_message {
            uint8_t msg_num;
            std::string destination;
            secure_buffer data;
        } intercept_msg {
            MINISSH_INTERCEPT_SEND_REQUEST,
            mgs.destination,
            mgs.data
        };
        _transport->send(packet{intercept_msg});
        packet responce = _safe_recv();
        if (responce.message_number() == MINISSH_INTERCEPT_FALIURE) {
            text_message text_msg = responce.to_struct<text_message>();
            LOG_WARN(text_msg.text);
            return;
        }
        if (responce.message_number() == MINISSH_INTERCEPT_SUCCESS) {
            return;
        }
        throw std::runtime_error("write tunnel");
    }

    void core::connect(const std::string& secret_key) {
        if (is_closed()) {
            throw std::runtime_error("closed");
        }

        _request_service("connection");

        _transport->send(packet{text_message{
            MINISSH_SECRET_REQUEST,
            secret_key
        }});
        {
            packet responce = _safe_recv();
            if (responce.message_number() == MINISSH_SECRET_FALIURE) {
                throw std::runtime_error("wrong secret");
            }
            if (responce.message_number() != MINISSH_SECRET_SUCCESS) {
                throw std::runtime_error("connect");
            }
        }

        _transport->send(packet{info_message{MINISSH_CHANNEL_OPEN}});
        {
            packet responce = _safe_recv();
            if (responce.message_number() == MINISSH_CHANNEL_OPEN_FAILURE) {
                throw std::runtime_error("failed to open channel");
            }
            if (responce.message_number() != MINISSH_CHANNEL_OPEN_CONFIRMATION) {
                throw std::runtime_error("connect");
            }
        }
    }

    void core::_request_service(const std::string& service_name) {
        LOG_DEBUG(std::format("requesting service \"{}\"", service_name));

        if (is_closed()) {
            throw std::runtime_error("closed");
        }

        _transport->send(packet{text_message{
            MINISSH_REQUEST,
            service_name
        }});
        packet responce = _safe_recv();
        if (responce.message_number() == MINISSH_UNIMPLEMENTED) {
            throw std::runtime_error("unimplemented");
        }
        if (responce.message_number() == MINISSH_ACCEPT) {
            return;
        }
        throw std::runtime_error("request");
    }

    packet core::_safe_recv() {
        while (true) {
            packet recv_packet = _transport->recv();
            if (recv_packet.message_number() == MINISSH_DEBUG) {
                text_message text_msg = recv_packet.to_struct<text_message>();
                LOG_DEBUG(text_msg.text);
                continue;
            }
            if (recv_packet.message_number() == MINISSH_DISCONNECT) {
                text_message text_msg = recv_packet.to_struct<text_message>();
                LOG_INFO(std::format("disconnected, reason: \"{}\"", text_msg.text));
                close();
                throw std::runtime_error("closed");
            }
            return recv_packet;
        }
    }

    void core::_transfer_data() {
        std::atomic<bool> finished{false};

        std::thread reader([this, &finished] {
            LOG_DEBUG(std::format("reader thread={}", std::hash<std::thread::id>{}(std::this_thread::get_id())));
            try {
                while (!finished.load()) {
                    LOG_DEBUG("waiting for the packet");
                    packet p = _transport->recv();
                    switch (p.message_number()) {
                        case MINISSH_CHANNEL_DATA: {
                            data_message msg = p.to_struct<data_message>();
                            std::cout.write(
                                reinterpret_cast<const char*>(msg.data.data()),
                                static_cast<std::streamsize>(msg.data.length())
                            );
                            std::cout.flush();
                            break;
                        }
                        case MINISSH_DEBUG: {
                            text_message msg = p.to_struct<text_message>();
                            LOG_DEBUG(msg.text);
                            break;
                        }
                        case MINISSH_DISCONNECT: {
                            LOG_INFO("server disconnected");
                            finished.store(true);
                            return;
                        }
                        default: {
                            LOG_WARN(std::format(
                                "unexpected msg_num {} in data stream",
                                static_cast<int>(p.message_number())
                            ));
                            break;
                        }
                    }
                }
            } catch (const std::exception& e) {
                if (!finished.load()) {
                    LOG_ERROR(e.what());
                }
                finished.store(true);
            }
        });

        LOG_DEBUG(std::format("writer thread={}", std::hash<std::thread::id>{}(std::this_thread::get_id())));
        uint8_t buffer[4096];
        while (!finished.load()) {
            pollfd pfd{STDIN_FILENO, POLLIN, 0};
            int r = poll(&pfd, 1, 200);
            if (r < 0) {
                if (errno == EINTR) continue;
                LOG_ERROR("poll stdin failed");
                break;
            }
            if (r == 0) {
                continue;
            }

            if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) {
                break;
            }
            if (!(pfd.revents & POLLIN)) {
                continue;
            }

            ssize_t n = ::read(STDIN_FILENO, buffer, sizeof(buffer));
            if (n == 0) {
                break;
            }
            if (n < 0) {
                if (errno == EINTR || errno == EAGAIN) continue;
                break;
            }

            try {
                _transport->send(packet{data_message{
                    MINISSH_CHANNEL_DATA,
                    secure_buffer{buffer, static_cast<uint32_t>(n)}
                }});
            } catch (const std::exception& e) {
                LOG_ERROR(e.what());
                break;
            }
        }

        finished.store(true);
        try {
            if (_transport && !_transport->is_closed()) {
                _transport->close();
            }
        } catch (...) {}

        if (reader.joinable()) {
            reader.join();
        }
    }
}