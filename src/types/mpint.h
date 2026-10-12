#ifndef MPINT
#define MPINT

#include <cstdint>
#include <iostream>
#include <string.h>
#include <utility>

#include "src/securebit.h"

namespace minissh {
    struct mpint_view;
    struct mpint;

    static constexpr uint32_t MPINT_SCHOOLBOOK_THRESHOLD = 20;

    bool operator==(mpint_view, mpint_view) noexcept;
    bool operator!=(mpint_view, mpint_view) noexcept;
    bool operator< (mpint_view, mpint_view) noexcept;
    bool operator> (mpint_view, mpint_view) noexcept;
    bool operator<=(mpint_view, mpint_view) noexcept;
    bool operator>=(mpint_view, mpint_view) noexcept;

    struct mpint_view {
        friend mpint;
      public:
        constexpr mpint_view() noexcept : _size{0}, _data{nullptr}, _sign{false} {}
        constexpr mpint_view(uint32_t size, const uint64_t* data, bool sign) noexcept : _size{size}, _data{data}, _sign{sign} {}
        mpint_view(const mpint& mpint) noexcept;
        mpint_view(std::initializer_list<uint64_t> data) noexcept : _size{static_cast<uint32_t>(data.size())}, _data{data.begin()}, _sign{false} {}

        constexpr uint32_t size() const noexcept { return _size * sizeof(uint64_t); }
        constexpr const uint64_t* data() const noexcept { return _data; }
        constexpr bool sign() const noexcept { return _sign; }
        constexpr bool is_zero() const noexcept { return _size == 0; }

        friend bool operator==(mpint_view    , mpint_view    ) noexcept;
        friend bool operator!=(mpint_view lhs, mpint_view rhs) noexcept { return !(lhs == rhs); }
        friend bool operator< (mpint_view    , mpint_view    ) noexcept;
        friend bool operator> (mpint_view lhs, mpint_view rhs) noexcept { return rhs < lhs; }
        friend bool operator<=(mpint_view lhs, mpint_view rhs) noexcept { return !(rhs < lhs); }
        friend bool operator>=(mpint_view lhs, mpint_view rhs) noexcept { return !(lhs < rhs); }
      private:
        uint32_t _size;
        const uint64_t* _data;
        bool _sign;
    };

    struct mpint {
        friend mpint_view;
      public:
        constexpr mpint() noexcept :
            _size(0),
            _capasity(0),
            _data(nullptr),
            _sign(false) {}
        mpint(int64_t);
        mpint(mpint_view);
        
        mpint(const uint8_t*, uint32_t);
        static mpint from_wire(const uint8_t* buf, uint32_t size) { return mpint{buf, size}; }

        mpint(const secure_buffer&);
        static mpint from_buffer(const secure_buffer& buf) { return mpint{buf}; }

        void to_wire(uint8_t*, uint32_t*) const noexcept;
        uint8_t operator[](uint32_t i) const noexcept;

        ~mpint() { _free(_data, _capasity); }

        mpint(const mpint&);
        mpint(mpint&& other) noexcept : mpint{} { swap(*this, other); }

        mpint& operator=(const mpint&);
        mpint& operator=(mpint&& other) noexcept {
            mpint temp{std::move(other)};
            swap(*this, temp);
            return *this;
        }

        friend void swap(mpint& lhs, mpint& rhs) noexcept {
            std::swap(lhs._size, rhs._size);
            std::swap(lhs._capasity, rhs._capasity);
            std::swap(lhs._data, rhs._data);
            std::swap(lhs._sign, rhs._sign);
        }

        uint32_t wire_size() const;
        constexpr uint32_t size() const noexcept { return _size * sizeof(uint64_t); }
        constexpr uint32_t capasity() const noexcept { return _capasity * sizeof(uint64_t); }
        constexpr const uint64_t* data() const noexcept { return _data; }
        constexpr bool sign() const noexcept { return _sign; }
        constexpr bool is_zero() const noexcept { return _size == 0; }

        void reserve(uint32_t);
        void resize(uint32_t);

        static void divmod(mpint_view, mpint_view, mpint&, mpint&);
        static mpint pow_mod(mpint, mpint_view, mpint_view);
        static mpint gcd(mpint_view, mpint_view, mpint&, mpint&);
        static mpint mod_inv(mpint_view, mpint_view);

        mpint& operator<<=(uint32_t);
        mpint& operator>>=(uint32_t);

        mpint& operator+=(mpint_view);
        mpint& operator-=(mpint_view);
        mpint& operator*=(mpint_view);
        mpint& operator/=(mpint_view);
        mpint& operator%=(mpint_view);

      private:
        uint32_t _size;
        uint32_t _capasity;
        uint64_t* _data;
        bool _sign;

        uint64_t* _alloc(uint32_t len) {
            return new uint64_t[len];
        }
        void _free(uint64_t* ptr, uint32_t len) {
            if (ptr) {
                delete[] ptr;
            }
        }

        void _trim();
        mpint& _shift_left(uint32_t);
        mpint& _shift_right(uint32_t);

        mpint _schoolbook_mult(mpint_view, mpint_view);
        mpint _karatsuba_mult(const mpint_view&, const mpint_view&);
        static mpint _div_by_limb(mpint_view, uint64_t, uint64_t&);
    };

    inline mpint operator<<(mpint lhs, uint32_t bits) { return lhs <<= bits; }
    inline mpint operator>>(mpint lhs, uint32_t bits) { return lhs >>= bits; }

    inline mpint operator+(mpint_view lhs, mpint_view rhs) { return mpint{lhs} += rhs; }
    inline mpint operator-(mpint_view lhs, mpint_view rhs) { return mpint{lhs} -= rhs; }
    inline mpint operator*(mpint_view lhs, mpint_view rhs) { return mpint{lhs} *= rhs; }
    inline mpint operator/(mpint_view lhs, mpint_view rhs) { return mpint{lhs} /= rhs; }
    inline mpint operator%(mpint_view lhs, mpint_view rhs) { return mpint{lhs} %= rhs; }

    std::ostream& operator<<(std::ostream&, mpint_view);
    inline std::ostream& operator<<(std::ostream& out, mpint rhs) { return out << mpint_view{rhs}; }

    template<size_t N>
    struct mpint_literal {
        uint64_t words[N];
        constexpr operator mpint_view() const noexcept {
            return mpint_view{static_cast<uint32_t>(N), words, false};
        }
    };

    inline const mpint_literal<12> FIRST_OAKLEY_GROUP_PRIME{{
        0xFFFFFFFFFFFFFFFFULL, 0xF44C42E9A63A3620ULL, 0xE485B576625E7EC6ULL,
        0x4FE1356D6D51C245ULL, 0x302B0A6DF25F1437ULL, 0xEF9519B3CD3A431BULL,
        0x514A08798E3404DDULL, 0x020BBEA63B139B22ULL, 0x29024E088A67CC74ULL,
        0xC4C6628B80DC1CD1ULL, 0xC90FDAA22168C234ULL, 0xFFFFFFFFFFFFFFFFULL
    }};

    inline const mpint_literal<16> SECOND_OAKLEY_GROUP_PRIME{{
        0xFFFFFFFFFFFFFFFFULL, 0x49286651ECE65381ULL, 0xAE9F24117C4B1FE6ULL,
        0xEE386BFB5A899FA5ULL, 0x0BFF5CB6F406B7EDULL, 0xF44C42E9A637ED6BULL,
        0xE485B576625E7EC6ULL, 0x4FE1356D6D51C245ULL, 0x302B0A6DF25F1437ULL,
        0xEF9519B3CD3A431BULL, 0x514A08798E3404DDULL, 0x020BBEA63B139B22ULL,
        0x29024E088A67CC74ULL, 0xC4C6628B80DC1CD1ULL, 0xC90FDAA22168C234ULL,
        0xFFFFFFFFFFFFFFFFULL
    }};

    inline const mpint_literal<24> MODP_1563_BIT_PRIME{{
        0xFFFFFFFFFFFFFFFFULL, 0xF1746C08CA237327ULL, 0x670C354E4ABC9804ULL,
        0x9ED529077096966DULL, 0x1C62F356208552BBULL, 0x83655D23DCA3AD96ULL,
        0x69163FA8FD24CF5FULL, 0x98DA48361C55D39AULL, 0xC2007CB8A163BF05ULL,
        0x49286651ECE45B3DULL, 0xAE9F24117C4B1FE6ULL, 0xEE386BFB5A899FA5ULL,
        0x0BFF5CB6F406B7EDULL, 0xF44C42E9A637ED6BULL, 0xE485B576625E7EC6ULL,
        0x4FE1356D6D51C245ULL, 0x302B0A6DF25F1437ULL, 0xEF9519B3CD3A431BULL,
        0x514A08798E3404DDULL, 0x020BBEA63B139B22ULL, 0x29024E088A67CC74ULL,
        0xC4C6628B80DC1CD1ULL, 0xC90FDAA22168C234ULL, 0xFFFFFFFFFFFFFFFFULL
    }};

    inline const mpint_literal<32> MODP_2048_BIT_PRIME{{
        0xFFFFFFFFFFFFFFFFULL, 0x15728E5A8AACAA68ULL, 0x15D2261898FA0510ULL,
        0x3995497CEA956AE5ULL, 0xDE2BCBF695581718ULL, 0xB5C55DF06F4C52C9ULL,
        0x9B2783A2EC07A28FULL, 0xE39E772C180E8603ULL, 0x32905E462E36CE3BULL,
        0xF1746C08CA18217CULL, 0x670C354E4ABC9804ULL, 0x9ED529077096966DULL,
        0x1C62F356208552BBULL, 0x83655D23DCA3AD96ULL, 0x69163FA8FD24CF5FULL,
        0x98DA48361C55D39AULL, 0xC2007CB8A163BF05ULL, 0x49286651ECE45B3DULL,
        0xAE9F24117C4B1FE6ULL, 0xEE386BFB5A899FA5ULL, 0x0BFF5CB6F406B7EDULL,
        0xF44C42E9A637ED6BULL, 0xE485B576625E7EC6ULL, 0x4FE1356D6D51C245ULL,
        0x302B0A6DF25F1437ULL, 0xEF9519B3CD3A431BULL, 0x514A08798E3404DDULL,
        0x020BBEA63B139B22ULL, 0x29024E088A67CC74ULL, 0xC4C6628B80DC1CD1ULL,
        0xC90FDAA22168C234ULL, 0xFFFFFFFFFFFFFFFFULL
    }};

    inline const mpint_literal<32> MODY_2048_BIT_RABIN{{
        0x9B2E9DDEFB646E35ULL, 0x38307721FD1023D3ULL, 0x971A1E2CD6CD52F8ULL,
        0x16FBDB39FCCB30E5ULL, 0xAADB3F4660B3208CULL, 0x3DBD9ABC062B193FULL,
        0x44265D61B49118F0ULL, 0xF9D9292119E3E756ULL, 0xA716EC3FB1B2C9E0ULL,
        0x901BF2227EF9FB26ULL, 0x79AB459FDBDFA265ULL, 0xA5C46CD6A3B7F9A2ULL,
        0x8C8FE7BF66B8BF97ULL, 0x1939B01602D61B55ULL, 0xCC427025977877BDULL,
        0x4A1B1A180811A346ULL, 0xC58F49CEFEF973F3ULL, 0x48F825D0B354309CULL,
        0x52FF802D59FC3A9AULL, 0xB6F049521E3466F0ULL, 0x5ABA7DDAE3141E99ULL,
        0xF2106CC1D74BF57EULL, 0x942E8565DE62AAF1ULL, 0x2DDBA131D5183437ULL,
        0xB623E47077F3D9D8ULL, 0x9F28247B2577946CULL, 0x61310D1CBE90CC4CULL,
        0xAF7922C15C2A50D2ULL, 0x2ACA5F16DFCA91A9ULL, 0x9B959835320C125DULL,
        0x5FBCBDE9E6FA836BULL, 0x98A6A17D710C2212ULL
    }};
}

#endif
