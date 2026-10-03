#include "src/crypto/hash.h"

#include "src/crypto/primitives.h"

namespace minissh {
    secure_buffer sha_1(const secure_buffer& input) {
        uint64_t l = static_cast<uint64_t>(input.length());
        uint64_t r = (64 - (l + 9) % 64) % 64;
        size_t desired_length = l + r + 9;

        secure_buffer pad_input{desired_length};
        {
            uint32_t offset = 0;
            if (l > 0) {
                memcpy(pad_input.data() + offset, input.data(), l);
            }
            offset += l;
            pad_input[offset++] = 0x80;
            if (r > 0) {
                memset(pad_input.data() + offset, 0, r);
            }
            offset += r;
            _write_in_buffer(pad_input.data(), offset, l * 8);
        }

        uint32_t k[80] {
            0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999,
            0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999,
            0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999,
            0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999,
            0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999,
            0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1,
            0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1,
            0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1,
            0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1,
            0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1,
            0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC,
            0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC,
            0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC,
            0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC,
            0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC,
            0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6,
            0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6,
            0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6,
            0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6,
            0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6
        };

        uint32_t h_i[5] {
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        };
        size_t n = desired_length / 64;
        for (size_t i = 0; i < n; ++i) {
            uint32_t m_i[16];
            {
                uint32_t offset = i * 64;
                for (int t = 0; t < 16; ++t) {
                    _read_from_buffer(pad_input.data(), offset, m_i + t);
                }
            }

            uint32_t w[80];
            for (int t = 0; t < 16; ++t) {
                w[t] = m_i[t];
            }
            for (int t = 16; t < 80; ++t) {
                w[t] = _rotl(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1);
            }

            uint32_t a = h_i[0];
            uint32_t b = h_i[1];
            uint32_t c = h_i[2];
            uint32_t d = h_i[3];
            uint32_t e = h_i[4];

            for (int t = 0; t < 80; ++t) {
                uint32_t temp = _rotl(a, 5) + _sha_1_f(t, b, c, d) + e + w[t] + k[t];
                e = d;
                d = c;
                c = _rotl(b, 30);
                b = a;
                a = temp;
            }

            h_i[0] += a;
            h_i[1] += b;
            h_i[2] += c;
            h_i[3] += d;
            h_i[4] += e;
        }

        secure_buffer result{20};
        {
            uint32_t offset = 0;
            for (int i = 0; i < 5; ++i) {
                _write_in_buffer(result.data(), offset, h_i[i]);
            }
        }
        return result;
    }

    uint32_t _sha_1_f(uint32_t t, uint32_t b, uint32_t c, uint32_t d) {
        if (t < 20) {
            return _ch(b, c, d);
        } else if (t < 40) {
            return b ^ c ^ d;
        } else if (t < 60) {
            return _maj(b, c, d);
        }
        return b ^ c ^ d;
    }

    secure_buffer sha_256(const secure_buffer& input) {
        uint64_t l = static_cast<uint64_t>(input.length());
        uint64_t r = (64 - (l + 9) % 64) % 64;
        size_t desired_length = l + r + 9;

        secure_buffer pad_input{desired_length};
        {
            uint32_t offset = 0;
            if (l > 0) {
                memcpy(pad_input.data() + offset, input.data(), l);
            }
            offset += l;
            pad_input[offset++] = 0x80;
            if (r > 0) {
                memset(pad_input.data() + offset, 0, r);
            }
            offset += r;
            _write_in_buffer(pad_input.data(), offset, l * 8);
        }

        uint32_t k[64] {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        uint32_t h_i[8] {
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19,
        };
        size_t n = desired_length / 64;
        for (size_t i = 0; i < n; ++i) {
            uint32_t m_i[16];
            {
                uint32_t offset = i * 64;
                for (int t = 0; t < 16; ++t) {
                    _read_from_buffer(pad_input.data(), offset, m_i + t);
                }
            }

            uint32_t w[64];
            for (int t = 0; t < 16; ++t) {
                w[t] = m_i[t];
            }
            for (int t = 16; t < 64; ++t) {
                w[t] = _ssig1(w[t-2]) + w[t-7] + _ssig0(w[t - 15]) + w[t - 16];
            }

            uint32_t a = h_i[0];
            uint32_t b = h_i[1];
            uint32_t c = h_i[2];
            uint32_t d = h_i[3];
            uint32_t e = h_i[4];
            uint32_t f = h_i[5];
            uint32_t g = h_i[6];
            uint32_t h = h_i[7];

            for (int t = 0; t < 64; ++t) {
                uint32_t t1 = h + _bsig1(e) + _ch(e, f, g) + k[t] + w[t];
                uint32_t t2 = _bsig0(a) + _maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            h_i[0] += a;
            h_i[1] += b;
            h_i[2] += c;
            h_i[3] += d;
            h_i[4] += e;
            h_i[5] += f;
            h_i[6] += g;
            h_i[7] += h;
        }

        secure_buffer result{32};
        {
            uint32_t offset = 0;
            for (int i = 0; i < 8; ++i) {
                _write_in_buffer(result.data(), offset, h_i[i]);
            }
        }
        return result;
    }
}
