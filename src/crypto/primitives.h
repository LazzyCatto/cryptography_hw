#ifndef PRIMITIVES
#define PRIMITIVES

#include <cstdint>

#include "src/types/mpint.h"
#include "src/securebit.h"

namespace minissh {
#ifndef _rotr
    inline constexpr uint32_t _rotr(uint32_t x, uint32_t n)  { return ((x) >> (n)) | ((x) << (32 - (n))); }
#endif
#ifndef _rotl
    inline constexpr uint32_t _rotl(uint32_t x, uint32_t n)  { return ((x) << (n)) | ((x) >> (32 - (n))); }
#endif
#ifndef _shr
    inline constexpr uint32_t _shr(uint32_t x, uint32_t n)  { return (x) >> (n); }
#endif
#ifndef _ch
    inline constexpr uint32_t _ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ ((~x) & z); }
#endif
#ifndef _maj
    inline constexpr uint32_t _maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
#endif
#ifndef _bsig0
    inline constexpr uint32_t _bsig0(uint32_t x) { return _rotr(x,  2) ^ _rotr(x, 13) ^ _rotr(x, 22); }
#endif
#ifndef _bsig1
    inline constexpr uint32_t _bsig1(uint32_t x) { return _rotr(x,  6) ^ _rotr(x, 11) ^ _rotr(x, 25); }
#endif
#ifndef _ssig0
    inline constexpr uint32_t _ssig0(uint32_t x) { return _rotr(x,  7) ^ _rotr(x, 18) ^ _shr(x,  3); }
#endif
#ifndef _ssig1
    inline constexpr uint32_t _ssig1(uint32_t x) { return _rotr(x, 17) ^ _rotr(x, 19) ^ _shr(x,  10); }
#endif

    secure_buffer _i2osp(mpint, uint32_t);
    mpint _os2ip(secure_buffer);
}

#endif
