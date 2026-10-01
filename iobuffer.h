#ifndef IOBUFFER
#define IOBUFFER

#include <variant>
#include <vector>
#include <tuple>

#include "securebit.h"
#include "types/mpint.h"

namespace minissh {
    using namelist = std::vector<std::string>;
    using byte16 = std::array<uint8_t, 16>;
    using msg_type = std::variant<bool, uint8_t, byte16, uint32_t, std::string, secure_buffer, namelist, mpint>;

    template <typename T>
    void _write_in_buffer(uint8_t*, uint32_t&, const T&, bool = false);

    template <typename T>
    void _read_from_buffer(const uint8_t*, uint32_t&, T*, bool = false);

    template <typename T>
    void _write_in_buffer_no_offset(uint8_t* buffer, const T& value, bool skip_size = false) {
        uint32_t offset = 0;
        _write_in_buffer(buffer, offset, value, skip_size);
    }

    template <typename T>
    void _read_from_buffer_no_offset(const uint8_t* buffer, T* value, bool skip_size = false) {
        uint32_t offset = 0;
        _read_from_buffer(buffer, offset, value, skip_size);
    }

    template <typename T>
    inline uint32_t _size_of(const T&);

    template <> inline uint32_t _size_of<bool>(const bool&) { return 1; }
    template <> inline uint32_t _size_of<uint8_t>(const uint8_t&) { return 1; }
    template <> inline uint32_t _size_of<byte16>(const byte16&) { return 16; }
    template <> inline uint32_t _size_of<uint16_t>(const uint16_t&) { return 2; }
    template <> inline uint32_t _size_of<uint32_t>(const uint32_t&) { return 4; }
    template <> inline uint32_t _size_of<std::string>(const std::string& value) { return value.length() + 4; }
    template <> inline uint32_t _size_of<secure_buffer>(const secure_buffer& value) { return value.length() + 4; }
    template <> inline uint32_t _size_of<mpint>(const mpint& value) { return value.wire_size() + 4; }
    template <> inline uint32_t _size_of<namelist>(const namelist& value) {
        uint32_t size = 4;
        for (size_t i = 0; i < value.size(); ++i) {
            size += value[i].length();
            if (i > 0) {
                ++size;
            }
        }
        return size;
    }

    struct _universal_initializer{
        const uint8_t* buffer;
        uint32_t& offset;

        template <typename T>
        operator T() const {
            T value;
            _read_from_buffer(buffer, offset, &value, false);
            return value;
        }
    };

    template <typename T, size_t... Is>
    constexpr auto _make_with_initializer_impl(const uint8_t* buffer, uint32_t& offset, std::index_sequence<Is...>) {
        return T{(static_cast<void>(Is), _universal_initializer{buffer, offset})...};
    }

    struct dummy_initializer{
        template <typename T>
        operator T() const { return T{}; }
    };
    template <typename T, size_t... Is>
    constexpr auto _count_impl(std::index_sequence<Is...>) -> decltype(T{(static_cast<void>(Is), dummy_initializer{})...}, std::true_type{});
    template <typename T, size_t... Is>
    constexpr std::false_type _count_impl(...);
    template <typename T, size_t N = 0>
    constexpr size_t _count_fields() {
        if constexpr (decltype(_count_impl<T>(std::make_index_sequence<N>{}))::value) {
            return _count_fields<T, N + 1>();
        } else {
            return N - 1;
        }
    }

    template <size_t N> struct _struct_to_tuple_converter;

#define DEF_N_TUPLE(n, ...) \
    template <> struct _struct_to_tuple_converter<n> { \
        template <typename T> \
        static auto convert(const T& obj) { \
            const auto& [__VA_ARGS__] = obj; \
            return std::tie(__VA_ARGS__); \
        } \
    };

DEF_N_TUPLE(1, a0)
DEF_N_TUPLE(2, a0, a1)
DEF_N_TUPLE(3, a0, a1, a2)
DEF_N_TUPLE(4, a0, a1, a2, a3)
DEF_N_TUPLE(5, a0, a1, a2, a3, a4)
DEF_N_TUPLE(6, a0, a1, a2, a3, a4, a5)
DEF_N_TUPLE(7, a0, a1, a2, a3, a4, a5, a6)
DEF_N_TUPLE(8, a0, a1, a2, a3, a4, a5, a6, a7)
DEF_N_TUPLE(9, a0, a1, a2, a3, a4, a5, a6, a7, a8)
DEF_N_TUPLE(10, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
DEF_N_TUPLE(11, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10)
DEF_N_TUPLE(12, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11)
DEF_N_TUPLE(13, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12)
DEF_N_TUPLE(14, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13)
DEF_N_TUPLE(15, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14)
DEF_N_TUPLE(16, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15)
DEF_N_TUPLE(17, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16)
DEF_N_TUPLE(18, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17)
DEF_N_TUPLE(19, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18)
    
    template <> void _write_in_buffer(uint8_t*, uint32_t&, const bool&, bool);
    template <> void _write_in_buffer(uint8_t*, uint32_t&, const uint8_t&, bool);
    template <> void _write_in_buffer(uint8_t*, uint32_t&, const byte16&, bool);
    template <> void _write_in_buffer(uint8_t*, uint32_t&, const uint32_t&, bool);
    template <> void _write_in_buffer(uint8_t*, uint32_t&, const uint16_t&, bool);
    template <> void _write_in_buffer(uint8_t*, uint32_t&, const uint64_t&, bool);
    template <> void _write_in_buffer(uint8_t*, uint32_t&, const std::string&, bool);
    template <> void _write_in_buffer(uint8_t*, uint32_t&, const secure_buffer&, bool);
    template <> void _write_in_buffer(uint8_t*, uint32_t&, const mpint&, bool);
    template <> void _write_in_buffer(uint8_t*, uint32_t&, const namelist&, bool);

    template <> void _read_from_buffer(const uint8_t*, uint32_t&, bool*, bool);
    template <> void _read_from_buffer(const uint8_t*, uint32_t&, uint8_t*, bool);
    template <> void _read_from_buffer(const uint8_t*, uint32_t&, byte16*, bool);
    template <> void _read_from_buffer(const uint8_t*, uint32_t&, uint32_t*, bool);
    template <> void _read_from_buffer(const uint8_t*, uint32_t&, uint16_t*, bool);
    template <> void _read_from_buffer(const uint8_t*, uint32_t&, uint64_t*, bool);
    template <> void _read_from_buffer(const uint8_t*, uint32_t&, std::string*, bool);
    template <> void _read_from_buffer(const uint8_t*, uint32_t&, secure_buffer*, bool);
    template <> void _read_from_buffer(const uint8_t*, uint32_t&, mpint*, bool);
    template <> void _read_from_buffer(const uint8_t*, uint32_t&, namelist*, bool);

    template <typename T>
    inline uint32_t _size_of(const T& value) {
        constexpr size_t fields_count = _count_fields<T>();
        auto tuple = _struct_to_tuple_converter<fields_count>::convert(value);

        uint32_t total = 4;
        std::apply([&](const auto&... fields) {
            ((total += _size_of(fields)), ...);
        }, tuple);
        return total;
    }

    template <typename T>
    void _write_in_buffer(uint8_t* buffer, uint32_t& offset, const T& value, bool skip_size) {
        constexpr size_t fields_count = _count_fields<T>();
        static_assert(fields_count > 0, "struct must have at least one field");
        static_assert(fields_count < 20, "struct must have at most 19 fields");

        if (!skip_size) {
            _write_in_buffer(buffer, offset, _size_of(value) - 4, false);
        }
        auto tuple = _struct_to_tuple_converter<fields_count>::convert(value);
        std::apply([&](const auto&... fields) {
            (_write_in_buffer(buffer, offset, fields, false), ...);
        }, tuple);
    }

    template <typename T>
    void _read_from_buffer(const uint8_t* buffer, uint32_t& offset, T* value, bool skip_size) {
        if (!skip_size) {
            uint32_t size;
            _read_from_buffer(buffer, offset, &size, false);
        }
        constexpr size_t fields_count = _count_fields<T>();
        *value = _make_with_initializer_impl<T>(buffer, offset, std::make_index_sequence<fields_count>{});
    }

    template<typename T, typename S>
    S _bit_convertion(const T& value) {
        uint8_t* buffer = new uint8_t[_size_of(value)];
        _write_in_buffer_no_offset(buffer, value);
        S result;
        _read_from_buffer_no_offset(buffer, &result);
        return result;
    }
}

#endif
