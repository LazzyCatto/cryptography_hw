#include "connection/socket.h"

#include <cstring>
#include <format>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdexcept>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "logger.h"

namespace minissh {
    void packet::set_padding_to_be_multiple(uint8_t multiple) {
        u_int32_t current_length = 5 + payload_length();
        uint8_t needed_bits = multiple - static_cast<uint8_t>(current_length % multiple);
        if (needed_bits < 4) {
            needed_bits += multiple;
        }
        if (_padding.length() != needed_bits) {
            _padding = secure_buffer{needed_bits};
        }
    }

    void packet::set_payload(std::span<const msg_type> values) {
        size_t _payload_length = 0;
        for (const msg_type& value : values) {
            std::visit([&](const auto& alt) {
                _payload_length += _size_of(alt);
            }, value);
        }
        if (_payload_length == 0) return;

        _payload = secure_buffer(_payload_length);
        uint32_t offset = 0;
        for (const msg_type& value : values) {
            std::visit([&](const auto& alt) {
                _write_in_buffer(_payload.data(), offset, alt);
            }, value);
        }
    }

    secure_buffer packet::main_packet() const {
        secure_buffer out{packet_length() + 4};
        uint32_t offset = 0;
        _write_in_buffer(out.data(), offset, packet_length());
        _write_in_buffer(out.data(), offset, padding_length());
        _write_in_buffer(out.data(), offset, payload(), true);
        _write_in_buffer(out.data(), offset, padding(), true);
        return out;
    }

    uint8_t packet::message_number() const {
        if (_payload) {
            return _payload[0];
        }
        return 0;
    }

    // SOCKET

    int client_socket::_tcp_connect(const char* host, const char* port) {
        struct addrinfo hints{}, *res, *rp;

        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags    = 0;
        hints.ai_protocol = 0;

        int s = getaddrinfo(host, port, &hints, &res);
        if (s != 0) {
            throw std::runtime_error(std::format("getaddrinfo: {}", gai_strerror(s)));
        }

        int sfd = -1;
        for (rp = res; rp != nullptr; rp = rp->ai_next) {
            sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (sfd == -1) continue;

            if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1) {
                break;
            }
            close(sfd);
            sfd = -1;
        }

        int one = 1;
        setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        freeaddrinfo(res);

        if (rp == nullptr) {
            throw std::runtime_error(std::format("Could not connect to {}:{}", host, port));
        }
        return sfd;
    }

    void client_socket::send_bytes(const uint8_t* buffer, uint32_t size) const {
        size_t total = 0;
        while (total < size) {
            ssize_t n = send(_file_descriptor, buffer + total, size - total, MSG_NOSIGNAL);
            if (n < 0) {
                throw std::runtime_error(std::format("send failed: {}", strerror(errno)));
            }
            if (n == 0) {
                throw std::runtime_error("connection closed by server");
            }
            total += n;
        }
    }

    void client_socket::recv_bytes(uint8_t* buffer, uint32_t size) {
        size_t total = 0;
        while (total < size) {
            ssize_t n = recv(_file_descriptor, buffer + total, size - total, MSG_NOSIGNAL);
            if (n < 0) {
                throw std::runtime_error(std::format("recv failed: {}", strerror(errno)));
            }
            if (n == 0) {
                throw std::runtime_error("connection closed by server");
            }
            total += n;
        }
    }

    void client_socket::send_packet(const packet& packet) const {
        uint8_t buffer[5];
        uint32_t offset = 0;
        _write_in_buffer(buffer, offset, packet.packet_length());
        _write_in_buffer(buffer, offset, packet.padding_length());

        send_bytes(buffer, 5);
        send_bytes(packet.payload().data(), packet.payload_length());
        send_bytes(packet.padding().data(), packet.padding_length());
    }

    std::string client_socket::recv_string() {
        std::string result;
        while (true) {
            char byte;
            ssize_t n = recv(_file_descriptor, &byte, 1, MSG_NOSIGNAL);
            result += byte;
            if (n < 0) {
                throw std::runtime_error(std::format("recv failed: {}", strerror(errno)));
            }
            if (n == 0) {
                throw std::runtime_error("connection closed by server");
            }
            if (byte == '\n') {
                break;
            }
        }
        return result;
    }

    packet client_socket::recv_packet() {
        uint8_t buffer[5];
        recv_bytes(buffer, 5);

        uint32_t packet_length;
        uint8_t padding_length;

        uint32_t offset = 0;
        _read_from_buffer(buffer, offset, &packet_length);
        _read_from_buffer(buffer, offset, &padding_length);

        packet output(packet_length - padding_length - 1, padding_length);
        recv_bytes(output.payload().data(), output.payload_length());
        recv_bytes(output.padding().data(), output.padding_length());

        return output;
    }
}
