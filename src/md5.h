#ifndef MD5_H
#define MD5_H

#include <stddef.h>
#include <stdint.h>

/* Minimal MD5 (RFC 1321). Used for JA3 fingerprint hashing only —
 * not for any security-sensitive purpose. */

typedef struct {
    uint32_t state[4];
    uint32_t count[2];   /* number of bits, mod 2^64 */
    uint8_t  buffer[64];
} md5_ctx_t;

void md5_init  (md5_ctx_t *ctx);
void md5_update(md5_ctx_t *ctx, const uint8_t *data, size_t len);
void md5_final (md5_ctx_t *ctx, uint8_t digest[16]);

/* Convenience: compute hex digest (lowercase, 32 chars + NUL). */
void md5_hex(const uint8_t *data, size_t len, char out[33]);

#endif /* MD5_H */
