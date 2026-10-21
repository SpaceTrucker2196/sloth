/* SHA-256 (FIPS 180-4) and base64 (RFC 4648 §4), for the build-time page
 * embedder and for the test that recomputes the page's CSP hashes.
 * Never linked into slothweb itself: the server serves digests the build
 * computed, it does not compute any. */
#ifndef SLOTHWEB_SHA256_H
#define SLOTHWEB_SHA256_H

#include <stddef.h>
#include <stdint.h>

void   web_sha256(const void *data, size_t len, uint8_t out[32]);

/* Standard-alphabet base64 with padding, NUL-terminated. out must hold
 * 4 * ((len + 2) / 3) + 1 bytes. Returns the length written. */
size_t web_base64(const uint8_t *in, size_t len, char *out);

#endif
