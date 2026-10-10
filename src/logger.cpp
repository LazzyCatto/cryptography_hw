#include "src/logger.h"

#include <regex>

namespace minissh {
    void logger::init(bool use_cin, const std::string& filename) {
        _use_cin = use_cin;
        if (!filename.empty()) {
            std::lock_guard<std::mutex> lock(_log_mutex);
            if (_log_file.is_open()) {
                _log_file.close();
            }
            _log_file.open(filename, std::ios::app);
        }
        log(
            minissh::loglevel::INFO,
            __FILE__,
            __LINE__,
            std::format("SLART NEW LOGGING SESSION")
        );
    }

    std::string _get_free_logger_name(fs::path path, std::string_view logger_name, int* logger_id) {
        fs::directory_iterator dir_iter{path};

        std::regex logger_regex(std::format("(^{}_\\d+\\.log$)", logger_name));
        std::regex int_regex{R"(\d+)"};
        int max_id = 0;
        for (fs::directory_entry dir_entry : dir_iter) {
            if (!dir_entry.is_regular_file()) {
                continue;
            }
            std::string filename = dir_entry.path().filename().string();
            if (!std::regex_match(filename, logger_regex)) {
                continue;
            }
            std::sregex_iterator it{filename.begin(), filename.end(), int_regex};
            std::sregex_iterator end;
            if (it == end) {
                continue;
            }
            int id = std::stoi(it->str());
            if (max_id < id) {
                max_id = id;
            }
        }
        ++max_id;
        if (logger_id) {
            *logger_id = max_id;
        }
        return path / std::format("{}_{}.log", logger_name, max_id);
    }

    void logger::log(loglevel level, const std::string& file, int line, const std::string& message) {
        std::lock_guard<std::mutex> lock(_log_mutex);

        std::string to_log = _get_timestamp() + 
                            " [" + _loglevel_to_string(level) + "] " +
                            "[" + file + ":" + std::to_string(line) + "] " + 
                            message;

        if (_use_cin) {
            std::cout << to_log << std::endl;
        }

        if (_log_file.is_open()) {
            _log_file << to_log << std::endl;
        }
    }

    std::string logger::_loglevel_to_string(loglevel level) {
        switch (level) {
            case loglevel::DEBUG:   return "DEBUG";
            case loglevel::INFO:    return "INFO";
            case loglevel::WARNING: return "WARNING";
            case loglevel::ERROR:   return "ERROR";
            default:                return "UNKNOWN";
        }
    }

    std::string logger::_get_timestamp() {
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
