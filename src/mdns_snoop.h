#ifndef MDNS_SNOOP_H
#define MDNS_SNOOP_H

#include <stdint.h>
#include "sloth.h"

/* Parse one mDNS UDP payload (buf[0..len-1], starting after the UDP header).
   Updates the internal service table and injects hostnames into the DNS cache.
   Returns the number of services created or updated, 0 on invalid/empty input. */
int mdns_snoop(const uint8_t *msg, int len);

/* Copy the current service table into s->mdns_services / s->mdns_count. */
void mdns_snapshot(sloth_state_t *s);

/* Reset all internal state (for testing). */
void mdns_clear(void);

#endif /* MDNS_SNOOP_H */
