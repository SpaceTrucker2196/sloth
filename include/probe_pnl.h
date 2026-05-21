#ifndef SLOTH_PROBE_PNL_H
#define SLOTH_PROBE_PNL_H

#include <stdint.h>
#include "sloth.h"

/* Per-MAC Preferred Network List aggregation.
 *
 * Each directed probe request observed by the capture thread feeds
 * probe_pnl_observe(mac, ssid). The module dedupes SSIDs per MAC and
 * keeps a per-client probe counter + first/last seen timestamps.
 * Snapshot copies into sloth_state_t for the view.
 *
 * Wildcard probes (empty SSID) are dropped — they leak no PNL info. */

void probe_pnl_observe(const uint8_t mac[6], const char *ssid);
void probe_pnl_snapshot(sloth_state_t *s);
void probe_pnl_clear(void);

/* Direct accessors for tests. */
int  probe_pnl_count(void);
int  probe_pnl_ssid_count(const uint8_t mac[6]);

#endif /* SLOTH_PROBE_PNL_H */
