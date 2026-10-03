
#ifndef SOCKET
#define SOCKET

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <unistd.h>
#include <variant>
#include <vector>

#include "src/iobuffer.h"
#include "src/securebit.h"
#include "src/types/mpint.h"

namespace minissh {
    struct packet {
    public:
        packet() :
            _padding{0},
            _payload{0}
        {}
        packet(
            uint32_t payload_length,
            uint8_t padding_length
        ) :
            _padding{padding_length},
            _payload{payload_length}
        {}
        template <typename T>
        packet(const T& obj) : packet{} { set_payload(obj); }

        template<typename T>
        constexpr T to_struct() const {
            T result;
            u_int32_t offset = 0;
            _read_from_buffer(_payload.data(), offset, &result, true);
            return result;
        }

        constexpr uint32_t packet_length() const noexcept { return _payload.length() + _padding.length() + 1; }
        constexpr uint32_t payload_length() const noexcept { return _payload.length(); }
        constexpr uint8_t  padding_length() const noexcept { return _padding.length(); }
        secure_buffer payload() const noexcept { return _payload; }
        constexpr secure_buffer& payload() noexcept { return _payload; }
        secure_buffer padding() const noexcept { return _padding; }
        constexpr secure_buffer& padding() noexcept { return _padding; }

        secure_buffer main_packet() const;

        uint8_t message_number() const;

        template <typename T>
        void set_payload(const T& obj) {
            _payload = secure_buffer(_size_of(obj) - 4);
            uint32_t offset = 0;
            _write_in_buffer(_payload.data(), offset, obj, true);
        }

        void set_payload(std::initializer_list<msg_type> values) { set_payload(std::span<const msg_type>(values.begin(), values.size())); }
        void set_payload(std::span<const msg_type>);

        void set_padding_to_be_multiple(uint8_t = 8);

        friend void swap(packet& lhs, packet& rhs) noexcept {
            std::swap(lhs._padding, rhs._padding);
            std::swap(lhs._payload, rhs._payload);
        }

      private:
        secure_buffer _payload;
        secure_buffer _padding;
    };

    class client_socket {
      public:
        client_socket() : _file_descriptor{-1}, _mac_length{0} {}
        client_socket(const char* host, const char* port) : _file_descriptor{_tcp_connect(host, port)}, _mac_length{0} {}
        client_socket(const char* port) : client_socket("localhost", port) {}

        ~client_socket() {
            if (_file_descriptor >= 0) {
                close(_file_descriptor);
            }
        }

        client_socket(client_socket&& other) : client_socket{} { std::swap(*this, other); }
        client_socket& operator=(client_socket&& other) {
            client_socket temp{std::move(other)};
            std::swap(*this, temp);
            return *this;
        }

        client_socket(const client_socket&) = delete;
        client_socket& operator=(const client_socket&) = delete;

        int file_descriptor() const { return _file_descriptor; }
        uint32_t mac_length() const { return _mac_length; }

        void set_mac_length(uint32_t mac_length) { _mac_length = mac_length; } 

        void send_bytes(const uint8_t*, uint32_t) const;
        void send_string(const std::string& str) { send_bytes(reinterpret_cast<const uint8_t*>(str.c_str()), str.length()); }
        void send_packet(const packet&) const;

        void recv_bytes(uint8_t*, uint32_t);
        std::string recv_string();
        packet recv_packet();

        friend void swap(client_socket& lhs, client_socket& rhs) noexcept {
            std::swap(lhs._file_descriptor, rhs._file_descriptor);
            std::swap(lhs._mac_length, rhs._mac_length);
        }

      private:
        int _file_descriptor;
        uint32_t _mac_length;

        int _tcp_connect(const char*, const char*);
    };
}

#endif
