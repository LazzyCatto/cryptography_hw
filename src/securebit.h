#ifndef SECUREBIT
#define SECUREBIT

#include <cstdint>
#include <span>
#include <string.h>

#ifdef __has_builtin
    #if __has_builtin(__builtin_ia32_addcarryx_u64) || defined(_MSC_VER)
        #define MINISSH_HAS_ADDCARRY_INTRINSIC 1
    #endif

    #if __has_builtin(__builtin_ia32_sbb_u64) || defined(_MSC_VER)
        #define MINISSH_HAS_SUBBORROW_INTRINSIC 1
    #endif
#endif

#if defined(MINISSH_HAS_ADDCARRY_INTRINSIC) || defined(MINISSH_HAS_SUBBORROW_INTRINSIC)
    #ifdef _MSC_VER
        #include <intrin.h>
    #else
        #include <x86intrin.h>
    #endif
#endif

inline uint8_t addcarry_u64(uint8_t carry_in, uint64_t a, uint64_t b, uint64_t* out) {
#ifdef MINISSH_HAS_ADDCARRY_INTRINSIC
    return _addcarry_u64(carry_in, a, b, reinterpret_cast<unsigned long long*>(out));
#else
    __uint128_t sum = static_cast<__uint128_t>(a) + b + carry_in;
    *out = static_cast<uint64_t>(sum);
    return static_cast<unsigned char>(sum >> 64);
#endif
}

inline uint8_t subborrow_u64(uint8_t borrow_in, uint64_t a, uint64_t b, uint64_t* out) {
#ifdef MINISSH_HAS_SUBBORROW_INTRINSIC
    return _subborrow_u64(borrow_in, a, b, reinterpret_cast<unsigned long long*>(out));
#else
    uint64_t diff = a - b - borrow_in;
    *out = diff;
    return (a < b + borrow_in) || (borrow_in && a == b);
#endif
}

inline void secure_erase(void* ptr, size_t len) {
#if defined(_WIN32)
    SecureZeroMemory(ptr, len);
#elif defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
    explicit_bzero(ptr, len);
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
    explicit_bzero(ptr, len);
#elif defined(__NetBSD__)
    explicit_memset(ptr, 0, len);
#elif defined(__APPLE__)
    memset_s(ptr, len, 0, len);
#else
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len--) *p++ = 0;
#endif
}

namespace minissh {
    struct secure_buffer {
      public:
        secure_buffer() : _len{0}, _buffer{nullptr} {}
        secure_buffer(size_t len) : _len{len}, _buffer{_alloc(len)} {}
        secure_buffer(const uint8_t*, size_t);

        ~secure_buffer() { _free(_buffer, _len); }

        secure_buffer(const secure_buffer& other) {
            _len = other._len;
            _buffer = _alloc(_len);
            if (_buffer) {
                memcpy(_buffer, other._buffer, _len);
            }
        }
        secure_buffer(secure_buffer&& other) : secure_buffer{} {
            swap(*this, other);
        }
        secure_buffer& operator=(secure_buffer other) {
            swap(*this, other);
            return *this;
        }

        constexpr uint8_t operator[](size_t index) const noexcept { return _buffer[index]; }
        constexpr uint8_t& operator[](size_t index) { return _buffer[index]; }

        constexpr const uint8_t* data() const noexcept { return _buffer; }
        constexpr uint8_t* data() { return _buffer; }

        constexpr size_t length() const noexcept{ return _len; }

        operator bool() const { return _buffer; }

        friend bool operator==(const secure_buffer&, const secure_buffer&);
        
        friend void swap(secure_buffer& lhs, secure_buffer& rhs) noexcept {
            std::swap(lhs._buffer, rhs._buffer);
            std::swap(lhs._len, rhs._len);
        }

        static secure_buffer cat(std::initializer_list<secure_buffer> values) {
            return cat(std::span<const secure_buffer>(values.begin(), values.size()));
        }
        static secure_buffer cat(std::span<const secure_buffer>); 
      private:
        size_t _len;
        uint8_t* _buffer;

        void _free(uint8_t* ptr, size_t len) {
            if (ptr) {
                secure_erase(ptr, len);
                delete[] ptr;
            }
        }

        uint8_t* _alloc(size_t len) {
            if (len > 0) {
                return new uint8_t[len];
            }
            return nullptr;
        }
    };

    template<typename T>
    secure_buffer get_secure_buffer_from_object(const T& value) {
        secure_buffer result = secure_buffer{_size_of(value)};
        _write_in_buffer_no_offset(result.data(), value);
        return result;
    }
}

#endif
