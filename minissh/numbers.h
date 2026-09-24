#ifndef NUMBERS
#define NUMBERS

namespace minissh {
    inline constexpr uint8_t SSH_MSG_DISCONNECT = 1;
    inline constexpr uint8_t SSH_MSG_IGNORE = 2;
    inline constexpr uint8_t SSH_MSG_UNIMPLEMENTED = 3;
    inline constexpr uint8_t SSH_MSG_DEBUG = 4;
    inline constexpr uint8_t SSH_MSG_SERVICE_REQUEST = 5;
    inline constexpr uint8_t SSH_MSG_SERVICE_ACCEPT = 6;
    inline constexpr uint8_t SSH_MSG_KEXINIT = 20;
    inline constexpr uint8_t SSH_MSG_NEWKEYS = 21;
    inline constexpr uint8_t SSH_MSG_USERAUTH_REQUEST = 50;
    inline constexpr uint8_t SSH_MSG_USERAUTH_FAILURE = 51;
    inline constexpr uint8_t SSH_MSG_USERAUTH_SUCCESS = 52;
    inline constexpr uint8_t SSH_MSG_USERAUTH_BANNER = 53;
    inline constexpr uint8_t SSH_MSG_GLOBAL_REQUEST = 80;
    inline constexpr uint8_t SSH_MSG_REQUEST_SUCCESS = 81;
    inline constexpr uint8_t SSH_MSG_REQUEST_FAILURE = 82;
    inline constexpr uint8_t SSH_MSG_CHANNEL_OPEN = 90;
    inline constexpr uint8_t SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
    inline constexpr uint8_t SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
    inline constexpr uint8_t SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
    inline constexpr uint8_t SSH_MSG_CHANNEL_DATA = 94;
    inline constexpr uint8_t SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
    inline constexpr uint8_t SSH_MSG_CHANNEL_EOF = 96;
    inline constexpr uint8_t SSH_MSG_CHANNEL_CLOSE = 97;
    inline constexpr uint8_t SSH_MSG_CHANNEL_REQUEST = 98;
    inline constexpr uint8_t SSH_MSG_CHANNEL_SUCCESS = 99;
    inline constexpr uint8_t SSH_MSG_CHANNEL_FAILURE = 100;
}

#endif
