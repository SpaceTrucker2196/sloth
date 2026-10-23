#ifndef SIPHASH_H
#define SIPHASH_H

#include <stddef.h>
#include <stdint.h>

/* SipHash-2-4 (Aumasson and Bernstein, "SipHash: a fast short-input
 * PRF", INDOCRYPT 2012): a keyed 64-bit PRF. Two compression rounds per
 * 8-byte block, four finalisation rounds, a 128-bit key read as two
 * little-endian words, the message length mod 256 in the top octet of
 * the last block. Checked against the paper's Appendix A vector and the
 * reference implementation's vectors (tests/test_ble_rotation.c).
 *
 * Used where a value must be comparable inside one run and nowhere else
 * (src/ble_rotation.c): under a per-run random key a digest means
 * nothing outside the process that made it. Not a MAC for anything on
 * the wire, and not a password hash. */
uint64_t siphash24(const uint8_t key[16], const void *msg, size_t len);

#endif /* SIPHASH_H */
