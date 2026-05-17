#ifndef DEVICES_H
#define DEVICES_H

#include "sloth.h"

/* Synthesize the device table from existing per-source state (ARP, DHCP,
 * beacons, probes, WiFi stations) and fill s->devices.
 * Deduplicates by MAC. Pulls hostname from DHCP via ARP-resolved IP,
 * vendor from the embedded OUI table. Safe to call once per poll. */
void devices_update(sloth_state_t *s);

#endif /* DEVICES_H */
