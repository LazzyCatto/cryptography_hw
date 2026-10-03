#ifndef TERMINAL_MODE
#define TERMINAL_MODE

#include <termios.h>
#include <unistd.h>

namespace minissh {

    class terminal_raw_mode {
      public:
        terminal_raw_mode() {
            if (!isatty(STDIN_FILENO)) {
                return;
            }
            if (tcgetattr(STDIN_FILENO, &_saved) == -1) {
                return;
            }
            termios raw = _saved;
            cfmakeraw(&raw);
            raw.c_cc[VMIN]  = 1;
            raw.c_cc[VTIME] = 0;
            if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) == -1) {
                return;
            }
            _active = true;
        }

        ~terminal_raw_mode() {
            if (_active) {
                tcsetattr(STDIN_FILENO, TCSANOW, &_saved);
            }
        }

        terminal_raw_mode(const terminal_raw_mode&) = delete;
        terminal_raw_mode& operator=(const terminal_raw_mode&) = delete;

      private:
        termios _saved{};
        bool    _active = false;
    };
}

#endif
