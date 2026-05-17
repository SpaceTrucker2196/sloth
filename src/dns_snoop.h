#ifndef DNS_SNOOP_H
#define DNS_SNOOP_H

#include <stdint.h>

/* Parse a raw DNS message starting at the DNS header (after the UDP header).
   - Fills info[info_sz] with a human-readable description of the packet.
   - For responses (QR=1): calls dns_set_resolved() for each A/AAAA answer.
   Returns 1 if the buffer looks like a valid DNS message, 0 otherwise.
   Thread-safe: may be called from the capture thread. */
int dns_snoop(const uint8_t *msg, int len, char *info, int info_sz);

#endif /* DNS_SNOOP_H */
