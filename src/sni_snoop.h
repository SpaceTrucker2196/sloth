#ifndef SNI_SNOOP_H
#define SNI_SNOOP_H

#include <stdint.h>

/* Parse a TLS ClientHello from the start of a TCP payload segment.
   Extracts the SNI hostname from the server_name extension (type 0x0000).
   Writes the hostname into host[hostsz] (always NUL-terminated on success).
   Returns 1 if a valid SNI was found, 0 otherwise (not TLS, not ClientHello,
   no SNI extension, truncated packet, etc.).
   Does not allocate; safe to call from the capture thread. */
int sni_snoop(const uint8_t *tcp_data, int len, char *host, int hostsz);

#endif /* SNI_SNOOP_H */
