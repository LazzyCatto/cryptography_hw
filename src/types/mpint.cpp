#include "src/types/mpint.h"

#include <stdexcept>
#include <vector>

namespace minissh {
    mpint_view::mpint_view(const mpint& mpint) noexcept : _size{mpint._size}, _data{mpint._data}, _sign{mpint._sign} {}

    mpint::mpint(int64_t value) : mpint{} {
        if (value == 0) {
            return;
        }
        _size = 1;
        _capasity = 1;
        _sign = value < 0;
        _data = _alloc(1);
        _data[0] = value < 0 ? ~static_cast<uint64_t>(value) + 1 : static_cast<uint64_t>(value);
    }

    mpint::mpint(const mpint& other) : mpint{} {
        if (other.is_zero()) {
            return;
        }

        _data = _alloc(other._size);
        memcpy(_data, other._data, other._size * sizeof(uint64_t));
        _size = other._size;
        _capasity = other._size;
        _sign = other._sign;
    }

    mpint::mpint(const uint8_t* buf, uint32_t size) : mpint{} {
        if (size == 0) {
            return;
        }
        _size = (size * sizeof(uint8_t) + sizeof(u_int64_t) - 1) / sizeof(u_int64_t);
        _data = _alloc(_size);
        _capasity = _size;
        _sign = buf[0] & 0x80;

        const uint32_t conv = sizeof(uint64_t) / sizeof(uint8_t);
        uint8_t carry = 1;
        for (uint32_t i = 0, j = 0; i < _size; ++i, j += conv) {
            uint64_t bytes = 0;
            for (uint32_t k = 0; k < conv; ++k) {
                bytes |= (j + k  < size ? static_cast<uint64_t>(buf[size - 1 - j - k]) : 0) << (k * conv);
            }
            if (_sign) {
                carry = addcarry_u64(carry, ~bytes, 0, &bytes);
            }
            _data[i] = bytes;
        }

        _trim();
    }

    mpint::mpint(const secure_buffer& buf) {
        if (buf.length() == 0) {
            return;
        }
        _size = (buf.length() * sizeof(uint8_t) + sizeof(u_int64_t) - 1) / sizeof(u_int64_t);
        _data = _alloc(_size);
        _capasity = _size;
        _sign = false;

        const uint32_t conv = sizeof(uint64_t) / sizeof(uint8_t);
        for (uint32_t i = 0, j = 0; i < _size; ++i, j += conv) {
            uint64_t bytes = 0;
            for (uint32_t k = 0; k < conv; ++k) {
                bytes |= (j + k  < buf.length() ? static_cast<uint64_t>(buf[buf.length() - 1 - j - k]) : 0) << (k * conv);
            }
            _data[i] = bytes;
        }

        _trim();
    }

    mpint::mpint(mpint_view view) : mpint{} {
        if (view.is_zero()) {
            return;
        }
        _data = _alloc(view._size);
        memcpy(_data, view._data, view._size * sizeof(uint64_t));
        _size = view._size;
        _capasity = view._size;
        _sign = view._sign;
        _trim();
    }

    void mpint::to_wire(uint8_t* buf, uint32_t* size) const noexcept {
        if (is_zero()) {
            *size = 0;
            return;
        }
        const uint32_t conv = sizeof(uint64_t) / sizeof(uint8_t);
        uint32_t start = conv - 1;
        while (((_data[_size - 1] >> (start * 8)) & 0xFF) == 0) {
            --start;
        }
        bool first_bit_flag = (_data[_size - 1] >> (start * 8)) & 0x80;
        *size = (_size - 1) * conv + start + 1 + static_cast<uint32_t>(first_bit_flag);
        
        uint8_t carry = 1;
        for (uint32_t i = 0, j = 0; j < *size; ++j) {
            uint64_t buff_data = (_data[i] >> ((j % conv) * 8)) & 0xFF;
            if (_sign) {
                buff_data = (~buff_data & 0xFF) + carry;
                carry = buff_data >> 8;
                buff_data &= 0xFF;
            }
            buf[*size - 1 - j] = static_cast<uint8_t>(buff_data);
            if (j % conv == conv - 1) {
                ++i;
            }
        }
    }

    uint32_t mpint::wire_size() const {
        const uint32_t conv = sizeof(uint64_t) / sizeof(uint8_t);
        uint32_t start = conv - 1;
        while (((_data[_size - 1] >> (start * 8)) & 0xFF) == 0) {
            --start;
        }
        bool first_bit_flag = (_data[_size - 1] >> (start * 8)) & 0x80;
        return (_size - 1) * conv + start + 1 + static_cast<uint32_t>(first_bit_flag);
    }

    mpint& mpint::operator=(const mpint& other) {
        if (other.is_zero()) {
            _free(_data, _capasity);
            _data = nullptr;
            _size = 0;
            _capasity = 0;
            _sign = false;
            return *this;
        }

        reserve(other._size);
        memcpy(_data, other._data, other._size * sizeof(uint64_t));
        _size = other._size;
        _sign = other._sign;
        return *this;
    }

    void mpint::reserve(uint32_t capasity) {
        if (_capasity >= capasity) {
            return;
        }

        uint64_t* new_data = _alloc(capasity);
        if (_data) {
            memcpy(new_data, _data, _size * sizeof(uint64_t));
            _free(_data, _capasity);
        }
        _data = new_data;
        _capasity = capasity;
    }

    void mpint::resize(uint32_t size) {
        if (_capasity < size) {
            reserve(size);
        }
        if (_size < size) {
            secure_erase(_data + _size, (size - _size) * sizeof(uint64_t));
        }
        _size = size;
    }

    bool operator==(mpint_view lhs, mpint_view rhs) noexcept {
        if (lhs._sign != rhs._sign) {
            return false;
        }
        if (lhs._size != rhs._size) {
            return false;
        }
        for (uint32_t i = 0; i < lhs._size; ++i) {
            if (lhs._data[i] != rhs._data[i]) {
                return false;
            }
        }
        return true;
    }

    bool operator<(mpint_view lhs, mpint_view rhs) noexcept {
        if (lhs._sign != rhs._sign) {
            return lhs._sign && !rhs._sign;
        }
        if (lhs._size != rhs._size) {
            return (lhs._size < rhs._size) != lhs._sign;
        }
        for (uint32_t i = 0; i < lhs._size; ++i) {
            if (lhs._data[lhs._size - i - 1] != rhs._data[lhs._size - i - 1]) {
                return (lhs._data[lhs._size - i - 1] < rhs._data[lhs._size - i - 1]) != lhs._sign;
            }
        }
        return false;
    }

    void mpint::_trim() {
        if (!_data) {
            _size = 0;
            return;
        }
        while (_size > 0 && _data[_size - 1] == 0) {
            --_size;
        }
        if (_size == 0) {
            _free(_data, _capasity);
            _data = nullptr;
            _capasity = 0;
            _sign = false;
        }
    }

    mpint& mpint::operator<<=(uint32_t bits) {
        if (is_zero() || bits == 0) {
            return *this;
        }
        const uint32_t limb_shift = bits / 64;
        const uint32_t bit_shift  = bits % 64;
        const uint32_t extra      = (bit_shift != 0) ? 1 : 0;
        const uint32_t new_size   = _size + limb_shift + extra;

        uint64_t* new_data = _alloc(new_size);

        if (limb_shift > 0) {
            memset(new_data, 0, limb_shift * sizeof(uint64_t));
        }

        if (bit_shift == 0) {
            memcpy(new_data + limb_shift, _data, _size * sizeof(uint64_t));
        } else {
            uint64_t carry = 0;
            for (uint32_t i = 0; i < _size; ++i) {
                uint64_t val = _data[i];
                new_data[limb_shift + i] = (val << bit_shift) | carry;
                carry = val >> (64 - bit_shift);
            }
            new_data[limb_shift + _size] = carry;
        }

        _free(_data, _capasity);
        _data = new_data;
        _size = new_size;
        _capasity = new_size;
        _trim();
        return *this;
    }

    mpint& mpint::operator>>=(uint32_t bits) {
        if (is_zero() || bits == 0) {
            return *this;
        }
        const uint32_t limb_shift = bits / 64;
        const uint32_t bit_shift  = bits % 64;

        if (limb_shift >= _size) {
            _free(_data, _capasity);
            _data = nullptr;
            _size = 0;
            _capasity = 0;
            _sign = false;
            return *this;
        }

        const uint32_t new_size = _size - limb_shift;
        uint64_t* new_data = _alloc(new_size);

        if (bit_shift == 0) {
            memcpy(new_data, _data + limb_shift, new_size * sizeof(uint64_t));
        } else {
            for (uint32_t i = 0; i < new_size; ++i) {
                uint64_t lo = _data[limb_shift + i] >> bit_shift;
                uint64_t hi = (limb_shift + i + 1 < _size)
                            ? (_data[limb_shift + i + 1] << (64 - bit_shift))
                            : 0;
                new_data[i] = lo | hi;
            }
        }

        _free(_data, _capasity);
        _data = new_data;
        _size = new_size;
        _capasity = new_size;
        _trim();
        return *this;
    }

    mpint& mpint::operator+=(mpint_view other) {
        reserve(_size < other._size ? other._size + 1 : _size + 1);

        if (_sign == other._sign) {
            uint8_t carry = 0;
            for (uint32_t i = 0;; ++i) {
                if (carry == 0 && other._size <= i && _size <= i) {
                    _size = i;
                    _trim();
                    break;
                }
                uint64_t lhs = i < _size ? _data[i] : 0;
                uint64_t rhs = i < other._size ? other._data[i] : 0;
                carry = addcarry_u64(carry, lhs, rhs, _data + i);
            }
            return *this;
        }
        bool keep_sign = (*this > other) != _sign;
        uint8_t borrow = 0;
        for (uint32_t i = 0;; ++i) {
            if (borrow == 0 && other._size <= i && _size <= i) {
                _size = i;
                _trim();
                break;
            }
            uint64_t lhs = i < _size ? _data[i] : 0;
            uint64_t rhs = i < other._size ? other._data[i] : 0;
            if (!keep_sign) {
                std::swap(lhs, rhs);
            }
            borrow = subborrow_u64(borrow, lhs, rhs, _data + i);
        }
        if (!keep_sign) {
            _sign = !_sign;
        }
        return *this;
    }

    mpint& mpint::operator-=(mpint_view other) {
        reserve(_size < other._size ? other._size + 1 : _size + 1);

        if (_sign == !other._sign) {
            uint8_t carry = 0;
            for (uint32_t i = 0;; ++i) {
                if (carry == 0 && other._size <= i && _size <= i) {
                    _size = i;
                    _trim();
                    break;
                }
                uint64_t lhs = i < _size ? _data[i] : 0;
                uint64_t rhs = i < other._size ? other._data[i] : 0;
                carry = addcarry_u64(carry, lhs, rhs, _data + i);
            }
            return *this;
        }
        bool keep_sign = (*this > other) != _sign;
        uint8_t borrow = 0;
        for (uint32_t i = 0;; ++i) {
            if (borrow == 0 && other._size <= i && _size <= i) {
                _size = i;
                _trim();
                break;
            }
            uint64_t lhs = i < _size ? _data[i] : 0;
            uint64_t rhs = i < other._size ? other._data[i] : 0;
            if (!keep_sign) {
                std::swap(lhs, rhs);
            }
            borrow = subborrow_u64(borrow, lhs, rhs, _data + i);
        }
        if (!keep_sign) {
            _sign = !_sign;
        }
        return *this;
    }

    mpint& mpint::operator*=(mpint_view other) {
        return *this = _karatsuba_mult(*this, other);
    }

    mpint& mpint::operator/=(mpint_view other) {
        mpint q, r;
        divmod(*this, other, q, r);
        *this = std::move(q);
        return *this;
    }

    mpint& mpint::operator%=(mpint_view other) {
        mpint q, r;
        divmod(*this, other, q, r);
        *this = std::move(r);
        return *this;
    }

    mpint& mpint::_shift_left(uint32_t shift) {
        if (is_zero()) {
            return *this;
        }
        uint64_t* new_data = _alloc(_size + shift);
        memset(new_data, 0, shift * sizeof(uint64_t));
        memcpy(new_data + shift, _data, _size * sizeof(uint64_t));
        _free(_data, _capasity);
        _data = new_data;
        _size += shift;
        _capasity = _size;
        return *this;
    }

    mpint& mpint::_shift_right(uint32_t shift) {
        if (is_zero()) {
            return *this;
        }
        if (_size <= shift) {
            _free(_data, _capasity);
            _data = nullptr;
            _size = 0;
            _capasity = 0;
            _sign = false;
            return *this;
        }
        uint64_t* new_data = _alloc(_size - shift);
        memcpy(new_data, _data + shift, (_size - shift) * sizeof(uint64_t));
        _free(_data, _capasity);
        _data = new_data;
        _size -= shift;
        _capasity = _size;
        return *this;
    }

    mpint mpint::_karatsuba_mult(const mpint_view& lhs, const mpint_view& rhs) {
        uint32_t size = lhs._size < rhs._size ? rhs._size : lhs._size;
        if (size <= 1) {
            if (lhs.is_zero() || rhs.is_zero()) {
                return mpint{};
            }
            __uint128_t x = static_cast<__uint128_t>(lhs._data[0]);
            __uint128_t y = static_cast<__uint128_t>(rhs._data[0]);
            __uint128_t prod = x * y;

            mpint result{};
            result._data = result._alloc(2);
            result._data[0] = static_cast<uint64_t>(        prod & 0xffffffffffffffff);
            result._data[1] = static_cast<uint64_t>((prod >> 64) & 0xffffffffffffffff);
            result._size = 2;
            result._capasity = 2;
            result._sign = (lhs._sign != rhs._sign);
            result._trim();
            return result;
        }

        uint32_t half = (size + 1) / 2;

        mpint_view x0{
            half < lhs._size ? half : lhs._size,
            lhs._size > 0 ? lhs._data : nullptr,
            false
        };
        mpint_view x1{
            half < lhs._size ? lhs._size - half : 0,
            lhs._size > half ? lhs._data + half : nullptr,
            false
        };
        mpint_view y0{
            half < rhs._size ? half : rhs._size,
            rhs._size > 0 ? rhs._data : nullptr,
            false
        };
        mpint_view y1{
            half < rhs._size ? rhs._size - half : 0,
            rhs._size > half ? rhs._data + half : nullptr,
            false
        };

        mpint z0 =_karatsuba_mult(     x0,      y0);
        mpint z2 =_karatsuba_mult(     x1,      y1);
        mpint z3 =_karatsuba_mult(x0 + x1, y0 + y1);
        mpint z1 = z3 - z2 - z0;

        mpint result = z2._shift_left(2 * half) + z1._shift_left(half) + z0;
        result._trim();
        result._sign = (lhs._sign != rhs._sign);
        return result;
    }

    mpint mpint::pow_mod(mpint lhs, mpint_view rhs, mpint_view mod) {
        if (rhs.is_zero()) {
            return mpint{1};
        }
        if (rhs._sign) {
            lhs = mpint::mod_inv(lhs, mod);
        }

        mpint result{1};
        for (uint32_t i = 0; i < rhs._size; ++i) {
            for (uint32_t j = 0; j < 64; ++ j) {
                if ((rhs._data[i] >> j) & 1) {
                    result *= lhs;
                    result %= mod;
                }
                lhs *= lhs;
                lhs %= mod;
            }
        }

        return result;
    }

    mpint mpint::gcd(mpint_view lhs, mpint_view rhs, mpint& a, mpint& b) {
        if (rhs.is_zero()) {
            a = mpint{1};
            b = mpint{0};
            return lhs;
        }

        mpint a1, b1;
        mpint r, q;
        mpint::divmod(lhs, rhs, q, r);
        mpint result = mpint::gcd(rhs, r, a1, b1);

        a = b1;
        b = a1 - q * b1;
        return result;
    }

    mpint mpint::mod_inv(mpint_view x, mpint_view mod) {
        mpint a, b;
        mpint gcd = mpint::gcd(x, mod, a, b);
        if (gcd != mpint{1}) {
            throw std::logic_error("zero devision");
        }
        mpint inv = a % mod;
        return inv._sign ? mod + inv : inv;
    }

    void mpint::divmod(mpint_view lhs, mpint_view rhs, mpint& q, mpint& r) {
        if (rhs.is_zero()) {
            throw std::logic_error{"zero devision"};
        }

        if (lhs.is_zero()) {
            q = mpint{};
            r = mpint{};
            return;
        }

        bool abs_less = false;
        if (lhs._size < rhs._size) {
            abs_less = true;
        } else if (lhs._size == rhs._size) {
            abs_less = true;
            for (uint32_t i = lhs._size; i-- > 0; ) {
                if (lhs._data[i] < rhs._data[i]) { abs_less = true; break; }
                if (lhs._data[i] > rhs._data[i]) { abs_less = false; break; }
                if (i == 0) { abs_less = false; }   // равны
            }
        }
        if (abs_less) {
            q = mpint{};
            r = mpint{lhs}; r._sign = lhs._sign;
            return;
        }

        if (rhs._size == 1) {
            uint64_t rem_limb = 0;
            mpint q_out = _div_by_limb(lhs, rhs._data[0], rem_limb);

            q_out._sign = (lhs._sign != rhs._sign);
            q_out._trim();

            mpint r_out;
            if (rem_limb != 0) {
                r_out._data = r_out._alloc(1);
                r_out._data[0] = rem_limb;
                r_out._size = 1;
                r_out._capasity = 1;
                r_out._sign = lhs._sign;
            }
            q = std::move(q_out);
            r = std::move(r_out);
            return;
        }

        const uint32_t n = rhs._size;
        const uint32_t m = lhs._size - n;

        const uint32_t shift = static_cast<uint32_t>(__builtin_clzll(rhs._data[n - 1]));

        uint64_t* vn = new uint64_t[n];
        if (shift == 0) {
            memcpy(vn, rhs._data, n * sizeof(uint64_t));
        } else {
            uint64_t carry = 0;
            for (uint32_t i = 0; i < n; ++i) {
                uint64_t val = rhs._data[i];
                vn[i] = (val << shift) | carry;
                carry = val >> (64 - shift);
            }
        }

        uint64_t* un = new uint64_t[n + m + 1];
        if (shift == 0) {
            memcpy(un, lhs._data, lhs._size * sizeof(uint64_t));
            un[lhs._size] = 0;
        } else {
            uint64_t carry = 0;
            for (uint32_t i = 0; i < lhs._size; ++i) {
                uint64_t val = lhs._data[i];
                un[i] = (val << shift) | carry;
                carry = val >> (64 - shift);
            }
            un[lhs._size] = carry;
        }

        uint64_t* qn = new uint64_t[m + 1];
        memset(qn, 0, (m + 1) * sizeof(uint64_t));

        for (uint32_t j = m + 1; j-- > 0; ) {
            __uint128_t num = (static_cast<__uint128_t>(un[j + n]) << 64) | un[j + n - 1];
            __uint128_t qhat, rhat;

            if (un[j + n] >= vn[n - 1]) {
                qhat = 0xffffffffffffffff;
                rhat = num - qhat * vn[n - 1];
            } else {
                qhat = num / vn[n - 1];
                rhat = num % vn[n - 1];
            }

            while (rhat <= 0xffffffffffffffff &&
                qhat * vn[n - 2] > (rhat << 64) + un[j + n - 2]) {
                --qhat;
                rhat += vn[n - 1];
            }

            uint64_t borrow = 0;
            uint64_t carry  = 0;
            for (uint32_t i = 0; i < n; ++i) {
                __uint128_t prod = qhat * vn[i] + carry;
                carry = static_cast<uint64_t>(prod >> 64);
                uint64_t prod_lo = static_cast<uint64_t>(prod);

                uint64_t old = un[j + i];
                un[j + i] = old - prod_lo - borrow;
                if (old < prod_lo || old - prod_lo < borrow) {
                    borrow = 1;
                } else {
                    borrow = 0;
                }
            }
            uint64_t old_top = un[j + n];
            un[j + n] = old_top - carry - borrow;
            bool negative = (old_top < carry || old_top - carry < borrow);

            if (negative) {
                --qhat;
                uint64_t carry2 = 0;
                for (uint32_t i = 0; i < n; ++i) {
                    __uint128_t sum = static_cast<__uint128_t>(un[j + i]) + vn[i] + carry2;
                    un[j + i] = static_cast<uint64_t>(sum);
                    carry2 = static_cast<uint64_t>(sum >> 64);
                }
                un[j + n] += carry2;
            }
            qn[j] = static_cast<uint64_t>(qhat);
        }

        uint32_t r_size = n;
        while (r_size > 0 && un[r_size - 1] == 0) {
            --r_size;
        }

        mpint r_out;
        if (r_size > 0) {
            r_out._data = r_out._alloc(r_size);
            r_out._size = r_size;
            r_out._capasity = r_size;
            if (shift == 0) {
                memcpy(r_out._data, un, r_size * sizeof(uint64_t));
            } else {
                for (uint32_t i = 0; i < r_size; ++i) {
                    uint64_t lo = un[i];
                    uint64_t hi = (i + 1 < n) ? un[i + 1] : 0;
                    r_out._data[i] = (lo >> shift) | (hi << (64 - shift));
                }
            }
            r_out._trim();
        }
        r_out._sign = lhs._sign;

        uint32_t q_size = m + 1;
        while (q_size > 0 && qn[q_size - 1] == 0) {
            --q_size;
        }
        mpint q_out;
        if (q_size > 0) {
            q_out._data = q_out._alloc(q_size);
            memcpy(q_out._data, qn, q_size * sizeof(uint64_t));
            q_out._size = q_size;
            q_out._capasity = q_size;
        }
        q_out._sign = (lhs._sign != rhs._sign);
        q_out._trim();

        delete[] vn;
        delete[] un;
        delete[] qn;

        q = std::move(q_out);
        r = std::move(r_out);
    }

    mpint mpint::_div_by_limb(mpint_view lhs, uint64_t divisor, uint64_t& rem_out) {
        mpint q;
        q.resize(lhs._size);
        uint64_t r = 0;
        for (uint32_t i = lhs._size; i-- > 0; ) {
            __uint128_t cur = (static_cast<__uint128_t>(r) << 64) | lhs._data[i];
            q._data[i] = static_cast<uint64_t>(cur / divisor);
            r          = static_cast<uint64_t>(cur % divisor);
        }
        q._trim();
        rem_out = r;
        return q;
    }

    std::ostream& operator<<(std::ostream& out, mpint_view rhs) {
        if (rhs.is_zero()) {
            return out << '0';
        }
        if (rhs.sign()) {
            out << '-';
        }

        constexpr uint64_t BASE = 10000000000000000000ULL;

        const uint32_t limb_count = rhs.size() / sizeof(uint64_t);
        const uint64_t* src = rhs.data();

        std::vector<uint64_t> work(src, src + limb_count);
        std::vector<uint64_t> chunks;

        while (!work.empty()) {
            uint64_t rem = 0;
            for (size_t i = work.size(); i-- > 0; ) {
                __uint128_t cur = (static_cast<__uint128_t>(rem) << 64) | work[i];
                work[i] = static_cast<uint64_t>(cur / BASE);
                rem     = static_cast<uint64_t>(cur % BASE);
            }
            while (!work.empty() && work.back() == 0) {
                work.pop_back();
            }
            chunks.push_back(rem);
        }
        out << chunks.back();
        for (size_t i = chunks.size() - 1; i-- > 0; ) {
            char buf[20];
            std::snprintf(buf, sizeof(buf), "%019llu",
                        static_cast<unsigned long long>(chunks[i]));
            out << buf;
        }

        return out;
    }
}
