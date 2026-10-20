#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

/* Minimal SHA-256 (FIPS 180-4, RFC 6234) — matches the src/md5.c house
 * style; sloth links no crypto library. Used for JA4 fingerprint hashing
 * (roadmap #16 phase 2) and for the #92 evidence manifest's per-file
 * digests (src/evidence_manifest.h), which are an integrity record and
 * not a secret: no key, no signature. Verified against the FIPS 180-4 /
 * CAVP example vectors in tests/test_sha256.c. */

typedef struct {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t  buffer[64];
    size_t   buflen;
} sha256_ctx_t;

void sha256_init  (sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len);
void sha256_final (sha256_ctx_t *ctx, uint8_t digest[32]);

/* Convenience: compute lowercase-hex digest (64 chars + NUL). */
void sha256_hex(const uint8_t *data, size_t len, char out[65]);

#endif /* SHA256_H */
