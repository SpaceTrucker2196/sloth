/* DNS wire-format names: the one reader (#131).
 *
 * RFC 1035 §3.1 / §4.1.4. A name is a run of length-prefixed labels
 * ended by a zero octet, or by a two-octet compression pointer (top two
 * bits 11) to an earlier name in the same message. The two remaining
 * label types (01, 10) are reserved and treated as malformed.
 *
 * Before this module the reader was copied verbatim into dns_snoop,
 * dns_log and mdns_snoop (the third one's comment said "Identical to
 * dns_snoop's"), and nbns_snoop carried a fourth, laxer walker that took
 * a reserved label type for a length. Every DNS-family parser now walks
 * names here.
 *
 * Both functions read only msg[0 .. msglen) and return the offset that
 * follows the name *where it was encountered* — after the first pointer
 * when the name is compressed, since the rest of that record continues
 * from there and not from wherever the pointer led — or -1 when the
 * name is malformed or runs past msglen. */
#ifndef SLOTH_DNS_WIRE_H
#define SLOTH_DNS_WIRE_H

#include <stdint.h>

/* Compression pointers followed before a name is rejected. RFC 1035
 * sets no limit; it says only that a pointer refers to a *prior*
 * occurrence, a rule this reader does not enforce (forward pointers
 * are seen in the wild from broken encoders). The bound is what stops
 * a loop — `C0 0C` at offset 12 pointing at itself — so it counts
 * pointers followed, not labels: 20 followed is accepted, the 21st is
 * refused. */
#define DNS_NAME_MAX_HOPS 20

/* Decode the name at msg[off] into buf[bufsz] as dotted text, always
 * NUL-terminated (bufsz must be >= 1), truncated when it does not fit.
 * Label octets are copied **raw**: the caller that stores a name in a
 * name-class field passes it through netstr_copy() there (#138), so
 * this reader stays usable for comparisons on the wire value. */
int dns_read_name(const uint8_t *msg, int msglen, int off,
                  char *buf, int bufsz);

/* Step over the name at msg[off] without decoding it. A pointer ends
 * the name in place (off + 2) and is not followed: a skip has no use
 * for the target, and not chasing it means a skip cannot loop. */
int dns_skip_name(const uint8_t *msg, int msglen, int off);

#endif /* SLOTH_DNS_WIRE_H */
