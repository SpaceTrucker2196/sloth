#ifndef IMAP_SNOOP_H
#define IMAP_SNOOP_H

#include <stdint.h>

/* Passive IMAP command-channel observer (RFC 3501).
 *
 * Watches TCP/143 payloads for the `LOGIN <user> <pass>` command,
 * with or without double-quoting around the arguments. Captures the
 * username; marks that a password was on the wire. The password
 * value is never stored.
 *
 * Returns 1 if the payload looked like an IMAP command line, 0
 * otherwise. */
int imap_snoop(const uint8_t *data, int len,
               const char *src, const char *dst, uint16_t dst_port);

#endif /* IMAP_SNOOP_H */
