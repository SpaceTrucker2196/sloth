#ifndef NBNS_SNOOP_H
#define NBNS_SNOOP_H

#include <stdint.h>
#include "sloth.h"

/* Parse a NetBIOS Name Service datagram (UDP/137 payload).
   Decodes NAME_QUERY and NAME_REGISTRATION records, updates the internal
   name table, and calls dns_set_resolved() for NB responses with IPs.
   Fills info/infosz with a human-readable description (like dns_snoop).
   Returns 1 if the packet was recognised and info was filled, 0 otherwise. */
int  nbns_snoop(const uint8_t *msg, int len, char *info, int infosz);

/* Copy the current name table into state under lock. */
void nbns_snapshot(sloth_state_t *s);

/* Clear the name table. */
void nbns_clear(void);

#endif /* NBNS_SNOOP_H */
