#include "siphash.h"

/* Contract and source in siphash.h. Written from the paper's
 * description of SipRound (its Figure 2.1). */

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

static uint64_t rd64le(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

#define SIPROUND                                                     \
    do {                                                             \
        v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; v0 = ROTL(v0, 32);    \
        v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2;                       \
        v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0;                       \
        v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; v2 = ROTL(v2, 32);    \
    } while (0)

uint64_t siphash24(const uint8_t key[16], const void *msg, size_t len) {
    const uint8_t *m = msg;
    uint64_t k0 = rd64le(key), k1 = rd64le(key + 8);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;

    size_t whole = len - (len % 8);
    for (size_t i = 0; i < whole; i += 8) {
        uint64_t mi = rd64le(m + i);
        v3 ^= mi;
        SIPROUND; SIPROUND;
        v0 ^= mi;
    }
    uint64_t b = (uint64_t)(len & 0xff) << 56;
    for (size_t i = 0; i < len % 8; i++)
        b |= (uint64_t)m[whole + i] << (8 * i);
    v3 ^= b;
    SIPROUND; SIPROUND;
    v0 ^= b;
    v2 ^= 0xff;
    SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}
