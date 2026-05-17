#ifndef DEAUTH_SNOOP_H
#define DEAUTH_SNOOP_H

#include <stdint.h>
#include "sloth.h"

/* Parse a raw 802.11 management frame for deauth (subtype 12) or
   disassoc (subtype 10).  Returns 1 on success, 0 otherwise. */
int deauth_parse(const uint8_t *dot11, int len, int8_t signal,
                 uint8_t src_out[6], uint8_t dst_out[6], uint8_t bssid_out[6],
                 uint16_t *reason_out, uint8_t *subtype_out);

/* Record a deauth/disassoc event in the internal table (thread-safe).
   Increments count for existing (src,dst) pairs; detects bursts. */
void deauth_record(const uint8_t *src, const uint8_t *dst,
                   const uint8_t *bssid, uint16_t reason, uint8_t subtype);

/* Copy current table into s->deauth_events[], aging out stale entries.
   Sets s->deauth_flood_active if any entry is currently flooding. */
void deauth_snapshot(sloth_state_t *s);

/* Clear the internal event table. */
void deauth_clear(void);

#endif /* DEAUTH_SNOOP_H */
