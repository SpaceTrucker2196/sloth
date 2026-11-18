#ifndef SLOTH_MON_RADIO_H
#define SLOTH_MON_RADIO_H

#include <stddef.h>

/* The sensor radios beside radio 0 (src/mon_radios.h): one capture
 * handle and one reader thread each, feeding probe.c's 802.11 path.
 * Receive-only, like radio 0. Their state, counts and share of the hop
 * list are in mon_radios.c, where the suite can reach them; this file
 * is the libpcap part and stubs itself without it.
 *
 * A radio that leaves the bus ends its own thread and reads `lost`;
 * nothing else stops. It is not opened again: by then the run has
 * given up the capability an open needs (#140). */

/* Open `iface` (registered with mon_radios_add(), which gave it
 * `radio`) as a monitor capture. 1, or 0 with why in err: absent, not
 * in monitor mode (type 803), a raw HCI device, not radiotap. Before
 * the privilege drop, after probe_open(). */
int  mon_radio_open(int radio, const char *iface, char *err, size_t errsz);

/* Start / stop one reader thread per opened radio. Stop before
 * probe_stop() and evidence_ring_shutdown(): these threads write the
 * ring too. */
void mon_radio_run(void);
void mon_radio_stop(void);

#endif
