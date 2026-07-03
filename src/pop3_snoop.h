#ifndef POP3_SNOOP_H
#define POP3_SNOOP_H

#include <stdint.h>

/* Passive POP3 command-channel observer (RFC 1939).
 *
 * Watches TCP/110 payloads for `USER <name>` and `PASS <value>`
 * commands. USER captures the username; PASS marks the flow's
 * most recent record as having had a password on the wire. The
 * password value is never stored.
 *
 * Returns 1 if the payload looked like a POP3 command (so the
 * capture layer can label the packet), 0 otherwise. */
int pop3_snoop(const uint8_t *data, int len,
               const char *src, const char *dst, uint16_t dst_port);

#endif /* POP3_SNOOP_H */
