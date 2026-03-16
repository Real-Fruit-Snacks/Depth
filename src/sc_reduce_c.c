#include <stdint.h>
#include <string.h>

static const uint64_t L[4] = {
    0x5812631a5cf5d3edULL, 0x14def9dea2f79cd6ULL,
    0x0000000000000000ULL, 0x1000000000000000ULL
};

void sc_reduce(unsigned char *s_bytes) {
    uint64_t x[8];
    memcpy(x, s_bytes, 64);
    int highest = -1;
    for (int i = 7; i >= 0; i--) {
        if (x[i]) {
            uint64_t v = x[i]; int bit = 63;
            while (!(v & (1ULL << bit))) bit--;
            highest = i * 64 + bit; break;
        }
    }
    if (highest < 0) { memset(s_bytes, 0, 32); return; }
    for (int shift = highest - 252; shift >= 0; shift--) {
        uint64_t shifted[8] = {0};
        int ws = shift / 64, bs = shift % 64;
        for (int i = 0; i < 4; i++) {
            int d = i + ws;
            if (d < 8) { shifted[d] |= L[i] << bs; if (bs && d+1 < 8) shifted[d+1] |= L[i] >> (64-bs); }
        }
        int ge = 0, det = 0;
        for (int i = 7; i >= 0; i--) {
            if (!det) { if (x[i] > shifted[i]) { ge=1; det=1; } else if (x[i] < shifted[i]) { ge=0; det=1; } }
        }
        if (!det) ge = 1;
        if (ge) {
            uint64_t borrow = 0;
            for (int i = 0; i < 8; i++) {
                unsigned __int128 diff = (unsigned __int128)x[i] - shifted[i] - borrow;
                x[i] = (uint64_t)diff; borrow = (diff >> 127) & 1;
            }
        }
    }
    memcpy(s_bytes, x, 32); memset(s_bytes+32, 0, 32);
}

void sc_muladd(unsigned char *s, const unsigned char *a, const unsigned char *b, const unsigned char *c_in) {
    uint64_t av[4], bv[4], cv[4]; 
    memcpy(av, a, 32); memcpy(bv, b, 32); memcpy(cv, c_in, 32);
    unsigned __int128 r[8] = {0};
    for (int i = 0; i < 4; i++) {
        unsigned __int128 carry = 0;
        for (int j = 0; j < 4; j++) {
            int k = i + j;
            unsigned __int128 prod = (unsigned __int128)av[i] * bv[j];
            r[k] += prod + carry; carry = r[k] >> 64; r[k] &= 0xFFFFFFFFFFFFFFFFULL;
        }
        if (i+4 < 8) r[i+4] += carry;
    }
    unsigned __int128 carry = 0;
    for (int i = 0; i < 4; i++) { r[i] += cv[i] + carry; carry = r[i] >> 64; r[i] &= 0xFFFFFFFFFFFFFFFFULL; }
    for (int i = 4; i < 8 && carry; i++) { r[i] += carry; carry = r[i] >> 64; r[i] &= 0xFFFFFFFFFFFFFFFFULL; }
    uint64_t x[8]; for (int i = 0; i < 8; i++) x[i] = (uint64_t)r[i];
    memcpy(s, x, 64); sc_reduce(s);
}
