#include "logger.h"

namespace minissh {
    void logger::init(const std::string& filename) {
        std::lock_guard<std::mutex> lock(log_mutex);
        if (log_file.is_open()) {
            log_file.close();
        }
        log_file.open(filename, std::ios::app);
    }

    void logger::log(loglevel level, const std::string& file, int line, const std::string& message) {
        std::lock_guard<std::mutex> lock(log_mutex);

        std::string to_log = get_timestamp() + 
                            " [" + loglevel_to_string(level) + "] " +
                            "[" + file + ":" + std::to_string(line) + "] " + 
                            message;

        std::cout << to_log << std::endl;

        if (log_file.is_open()) {
            log_file << to_log << std::endl;
        }
    }

    std::string logger::loglevel_to_string(loglevel level) {
        switch (level) {
            case loglevel::DEBUG:   return "DEBUG";
            case loglevel::INFO:    return "INFO";
            case loglevel::WARNING: return "WARNING";
            case loglevel::ERROR:   return "ERROR";
            default:                return "UNKNOWN";
        }
    }

    std::string logger::get_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    template <> std::string string_repr_with_indent(const bool& value, int indent) {
        std::stringstream ss;
        ss << std::string(indent, ' ') << (value ? "TRUE" : "FALSE");
        return ss.str();
    }
    template <> std::string string_repr_with_indent(const uint8_t& value, int indent) {
        std::stringstream ss;
        ss << std::string(indent, ' ')
            << "0x"
            << std::uppercase
            << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(value)
            << std::setfill(' ')
            << std::dec;
        return ss.str();
    }
    template <> std::string string_repr_with_indent(const uint32_t& value, int indent) {
        std::stringstream ss;
        ss << std::string(indent, ' ') << value;
        return ss.str();

    }
    template <> std::string string_repr_with_indent(const byte16& value, int indent) {
        std::stringstream ss;
        ss << std::string(indent, ' ') << "[";
        for (size_t i = 0; i < 16; ++i) {
            if (i > 0) {
                ss << ", ";
            }
            ss << "0x"
                << std::uppercase
                << std::hex
                << std::setw(2)
                << std::setfill('0')
                << static_cast<int>(value[i])
                << std::setfill(' ')
                << std::dec;
        }
        ss << "]";
        return ss.str();

    }
    template <> std::string string_repr_with_indent(const secure_buffer& value, int indent) {
        std::stringstream ss;
        ss << std::string(indent, ' ') << "[";
        for (size_t i = 0; i < value.length(); ++i) {
            if (i > 0) {
                ss << ", ";
            }
            ss << "0x"
                << std::uppercase
                << std::hex
                << std::setw(2)
                << std::setfill('0')
                << static_cast<int>(value[i])
                << std::setfill(' ')
                << std::dec;
        }
        ss << "]";
        return ss.str();

    }
    template <> std::string string_repr_with_indent(const mpint& value, int indent) {
        std::stringstream ss;
        ss << std::string(indent, ' ') << value;
        return ss.str();
    }
    template <> std::string string_repr_with_indent(const std::string& value, int indent) {
        std::stringstream ss;
        ss << std::string(indent, ' ') << value;
        return ss.str();
    }
    template <> std::string string_repr_with_indent(const namelist& value, int indent) {
        std::stringstream ss;
        ss << std::string(indent, ' ') << "[";
        for (size_t i = 0; i < value.size(); ++i) {
            if (i > 0) {
                ss << ", ";
            }
            ss << value[i];
        }
        ss << "]";
        return ss.str();
    }
}
