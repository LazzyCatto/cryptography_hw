#ifndef LOGGER
#define LOGGER

#include <iostream>
#include <fstream>
#include <mutex>
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>

#include "src/iobuffer.h"
#include "src/securebit.h"
#include "src/types/mpint.h"

namespace minissh {
    enum class loglevel {
        DEBUG,
        INFO,
        WARNING,
        ERROR
    };

    class logger {
      public:
        static logger& get_instance() {
            static logger instance{};
            return instance;
        }

        logger(const logger&) = delete;
        logger& operator=(const logger&) = delete;
        logger(logger&&) = delete;
        logger& operator=(logger&&) = delete;

        void init(bool = true, const std::string& = "");
        void log(loglevel level, const std::string&, int, const std::string&);
      private:
        logger() = default;
        ~logger() {
            if (_log_file.is_open()) {
                _log_file.close();
            }
        }

        std::ofstream _log_file;
        std::mutex _log_mutex;

        bool _use_cin;

        std::string _loglevel_to_string(loglevel);
        std::string _get_timestamp();
    };

    template <typename T>
    std::string string_repr(const T&);
    template <typename T>
    std::string string_repr_with_indent(const T&, int);

    template <typename T>
    concept convertible_to_string = std::convertible_to<T, std::string>;

    template <> std::string string_repr_with_indent(const bool&, int);
    template <> std::string string_repr_with_indent(const uint8_t&, int);
    template <> std::string string_repr_with_indent(const uint32_t&, int);
    template <> std::string string_repr_with_indent(const byte16&, int);
    template <> std::string string_repr_with_indent(const secure_buffer&, int);
    template <> std::string string_repr_with_indent(const mpint&, int);
    template <> std::string string_repr_with_indent(const std::string&, int);
    template <> std::string string_repr_with_indent(const namelist&, int);
    template <convertible_to_string T>
    std::string string_repr_with_indent(const T& value, int indent) {
        std::stringstream ss;
        ss << std::string(indent, ' ') << std::string(value);
        return ss.str();
    }

    template <typename T>
    std::string string_repr(const T& value) {
        return string_repr_with_indent<T>(value, 0);
    }

    template <typename T>
    std::string string_repr_with_indent(const T& value, int indent) {
        std::stringstream ss;
        ss << std::string(indent, ' ') << "{\n";
        constexpr size_t fields_count = _count_fields<T>();
        auto tuple = _struct_to_tuple_converter<fields_count>::convert(value);
        std::apply([&](const auto&... fields) {
            ((ss << string_repr_with_indent(fields, indent + 2) << ";\n"), ...);
        }, tuple);
        ss << std::string(indent, ' ') << "}";
        return ss.str();
    }

    #define LOG_DEBUG(msg) minissh::logger::get_instance().log(minissh::loglevel::DEBUG, __FILE__, __LINE__, msg)
    #define LOG_INFO(msg)  minissh::logger::get_instance().log(minissh::loglevel::INFO, __FILE__, __LINE__, msg)
    #define LOG_WARN(msg)  minissh::logger::get_instance().log(minissh::loglevel::WARNING, __FILE__, __LINE__, msg)
    #define LOG_ERROR(msg) minissh::logger::get_instance().log(minissh::loglevel::ERROR, __FILE__, __LINE__, msg)
}

#endif
