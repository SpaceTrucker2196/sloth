#ifndef QUIC_SNOOP_H
#define QUIC_SNOOP_H

#include <stdint.h>

/* Inspect a UDP payload for a QUIC Long Header Initial packet (RFC 9000 §17.2.2,
   RFC 9369 §3 for v2).  Detects by first-byte type bits and version field;
   does NOT decrypt (Initial payload uses HKDF-derived AES-128-GCM keys).
   Returns 1 if recognised; fills ver_out with a short version string ("v1",
   "v2", "draft").  Returns 0 for all other UDP payloads. */
int quic_detect(const uint8_t *data, int len, char *ver_out, int versz);

#endif /* QUIC_SNOOP_H */
