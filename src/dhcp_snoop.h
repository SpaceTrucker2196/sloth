#ifndef DHCP_SNOOP_H
#define DHCP_SNOOP_H

#include <stdint.h>
#include "sloth.h"

/* Parse a DHCP datagram (raw UDP payload, port 67 or 68).
   Updates the internal live-event table and calls dns_set_resolved()
   on ACK packets where hostname and IP are both known.
   Fills info/infosz with a human-readable description.
   Returns 1 if the packet was a recognised DHCP message, 0 otherwise. */
int  dhcp_snoop(const uint8_t *data, int len, char *info, int infosz);

/* Copy the current event table into state under lock. */
void dhcp_snoop_snapshot(sloth_state_t *s);

/* Clear the event table. */
void dhcp_snoop_clear(void);

#endif /* DHCP_SNOOP_H */
