#ifndef NUMBERS
#define NUMBERS

#include <cstdint>

namespace minissh {
    inline constexpr uint8_t MINISSH_DISCONNECT = 1;
    inline constexpr uint8_t MINISSH_IGNORE = 2;
    inline constexpr uint8_t MINISSH_UNIMPLEMENTED = 3;
    inline constexpr uint8_t MINISSH_DEBUG = 4;
    inline constexpr uint8_t MINISSH_REQUEST = 5;
    inline constexpr uint8_t MINISSH_ACCEPT = 6;

    inline constexpr uint8_t MINISSH_KEXINIT = 20;
    inline constexpr uint8_t MINISSH_NEWKEYS = 21;

    inline constexpr uint8_t MINISSH_USERAUTH_REQUEST = 50;
    inline constexpr uint8_t MINISSH_USERAUTH_FAILURE = 51;
    inline constexpr uint8_t MINISSH_USERAUTH_SUCCESS = 52;

    inline constexpr uint8_t MINISSH_INTERCEPT_RECV_REQUEST = 60;
    inline constexpr uint8_t MINISSH_INTERCEPT_SEND_REQUEST = 61;
    inline constexpr uint8_t MINISSH_INTERCEPT_FALIURE = 62;
    inline constexpr uint8_t MINISSH_INTERCEPT_SUCCESS = 63;

    inline constexpr uint8_t MINISSH_SECRET_FALIURE = 70;
    inline constexpr uint8_t MINISSH_SECRET_SUCCESS = 71;

    inline constexpr uint8_t MINISSH_CHANNEL_OPEN = 90;
    inline constexpr uint8_t MINISSH_CHANNEL_OPEN_CONFIRMATION = 91;
    inline constexpr uint8_t MINISSH_CHANNEL_OPEN_FAILURE = 92;
    inline constexpr uint8_t MINISSH_CHANNEL_DATA = 94;
}

#endif
