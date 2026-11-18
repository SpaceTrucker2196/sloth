#ifndef VA_AES_H
#define VA_AES_H

#include <stddef.h>
#include <stdint.h>

/* AES-128, encryption direction only (FIPS-197), and CTR mode over it
 * (NIST SP 800-38A §6.5). CTR decrypts by encrypting the counter
 * blocks, so the inverse cipher is never needed. sloth-va's alone:
 * nothing in `sloth` or `slothweb` links it (tests/test_va.c), and
 * MISSION.md §2 rule 2 stays sloth's: sloth decrypts nothing.
 *
 * Victron Instant Readout uses it with the device's own advertisement
 * key, which the owner provisions (docs/wiki/victron.md). Verified
 * against FIPS-197 Appendix C.1, SP 800-38A F.5.1 and two Instant
 * Readout advertisements in tests/test_va.c. Not constant-time with
 * respect to the key (table S-box): fine for decoding a broadcast with
 * a key that never leaves the host, not for anything an attacker can
 * time. */

typedef struct {
    uint8_t rk[176];          /* 11 round keys */
} va_aes128_t;

void va_aes128_init(va_aes128_t *ctx, const uint8_t key[16]);
void va_aes128_encrypt_block(const va_aes128_t *ctx, const uint8_t in[16],
                             uint8_t out[16]);

/* XOR `len` bytes of `in` with the keystream starting at counter block
 * `ctr` into `out` (in == out allowed). The counter block is advanced
 * as a 128-bit big-endian integer per block (SP 800-38A B.1's standard
 * incrementing function); `ctr` is not modified. */
void va_aes128_ctr(const va_aes128_t *ctx, const uint8_t ctr[16],
                   const uint8_t *in, uint8_t *out, size_t len);

/* Overwrite key material so it does not linger. */
void va_wipe(void *p, size_t n);

#endif /* VA_AES_H */
