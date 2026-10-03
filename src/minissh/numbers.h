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

    inline constexpr uint8_t MINISSH_SECRET_REQUEST = 70;
    inline constexpr uint8_t MINISSH_SECRET_FALIURE = 71;
    inline constexpr uint8_t MINISSH_SECRET_SUCCESS = 72;

    inline constexpr uint8_t MINISSH_CHANNEL_OPEN = 90;
    inline constexpr uint8_t MINISSH_CHANNEL_OPEN_CONFIRMATION = 91;
    inline constexpr uint8_t MINISSH_CHANNEL_OPEN_FAILURE = 92;
    inline constexpr uint8_t MINISSH_CHANNEL_WINDOW_ADJUST = 93;
    inline constexpr uint8_t MINISSH_CHANNEL_DATA = 94;

    inline std::string msg_num_to_string(uint8_t msg_num) {
        switch (msg_num) {
            case MINISSH_DISCONNECT:
                return "MINISSH_DISCONNECT";
            case MINISSH_IGNORE:
                return "MINISSH_IGNORE";
            case MINISSH_UNIMPLEMENTED:
                return "MINISSH_UNIMPLEMENTED";
            case MINISSH_DEBUG:
                return "MINISSH_DEBUG";
            case MINISSH_REQUEST:
                return "MINISSH_REQUEST";
            case MINISSH_ACCEPT:
                return "MINISSH_ACCEPT";
            case MINISSH_KEXINIT:
                return "MINISSH_KEXINIT";
            case MINISSH_NEWKEYS:
                return "MINISSH_NEWKEYS";
            case MINISSH_USERAUTH_REQUEST:
                return "MINISSH_USERAUTH_REQUEST";
            case MINISSH_USERAUTH_FAILURE:
                return "MINISSH_USERAUTH_FAILURE";
            case MINISSH_USERAUTH_SUCCESS:
                return "MINISSH_USERAUTH_SUCCESS";
            case MINISSH_INTERCEPT_RECV_REQUEST:
                return "MINISSH_INTERCEPT_RECV_REQUEST";
            case MINISSH_INTERCEPT_SEND_REQUEST:
                return "MINISSH_INTERCEPT_SEND_REQUEST";
            case MINISSH_INTERCEPT_FALIURE:
                return "MINISSH_INTERCEPT_FALIURE";
            case MINISSH_INTERCEPT_SUCCESS:
                return "MINISSH_INTERCEPT_SUCCESS";
            case MINISSH_SECRET_REQUEST:
                return "MINISSH_SECRET_REQUEST";
            case MINISSH_SECRET_FALIURE:
                return "MINISSH_SECRET_FALIURE";
            case MINISSH_SECRET_SUCCESS:
                return "MINISSH_SECRET_SUCCESS";
            case MINISSH_CHANNEL_OPEN:
                return "MINISSH_CHANNEL_OPEN";
            case MINISSH_CHANNEL_OPEN_CONFIRMATION:
                return "MINISSH_CHANNEL_OPEN_CONFIRMATION";
            case MINISSH_CHANNEL_OPEN_FAILURE:
                return "MINISSH_CHANNEL_OPEN_FAILURE";
            case MINISSH_CHANNEL_WINDOW_ADJUST:
                return "MINISSH_CHANNEL_WINDOW_ADJUST";
            case MINISSH_CHANNEL_DATA:
                return "MINISSH_CHANNEL_DATA";
            default:
                return "UNSUPPORTED";
        }
    }
}

#endif
