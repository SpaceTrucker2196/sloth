#ifndef MDNS_SNOOP_H
#define MDNS_SNOOP_H

#include <stdint.h>
#include <time.h>
#include "sloth.h"

/* Parse one mDNS UDP payload (buf[0..len-1], starting after the UDP header).
   Updates the internal service table and injects hostnames into the DNS cache.
   Returns the number of services created or updated, 0 on invalid/empty input. */
int mdns_snoop(const uint8_t *msg, int len);

/* Same, with the clock supplied. The service table reclaims a row only
   once it has gone 3600 s unseen (#110), so tests drive aging through
   this entry point rather than waiting on time(NULL). */
int mdns_snoop_at(const uint8_t *msg, int len, time_t now);

/* Copy the current service table into s->mdns_services / s->mdns_count. */
void mdns_snapshot(sloth_state_t *s);

/* Reset all internal state (for testing). */
void mdns_clear(void);

#endif /* MDNS_SNOOP_H */
