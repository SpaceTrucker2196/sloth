#ifndef FTP_SNOOP_H
#define FTP_SNOOP_H

#include <stdint.h>

/* Passive FTP command-channel observer.
 *
 * Watches TCP/21 payloads for the `USER <name>` and `PASS ...`
 * commands (RFC 959). USER captures the username; PASS marks the
 * flow's most recent record as having had a password on the wire.
 * The password value is never stored.
 *
 * Returns 1 if the payload looked like an FTP command (so the
 * capture layer can label the packet), 0 otherwise. */
int ftp_snoop(const uint8_t *data, int len,
              const char *src, const char *dst, uint16_t dst_port);

#endif /* FTP_SNOOP_H */
