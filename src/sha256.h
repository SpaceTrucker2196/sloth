#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

/* Minimal SHA-256 (RFC 6234) — matches the src/md5.c house style.
 * Used for JA4 fingerprint hashing (roadmap #16 phase 2). Not for any
 * security-sensitive purpose. */

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
