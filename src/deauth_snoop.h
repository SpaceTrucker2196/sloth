#ifndef DEAUTH_SNOOP_H
#define DEAUTH_SNOOP_H

#include <stdint.h>
#include "sloth.h"

/* One parsed deauth (subtype 12) or disassoc (subtype 10) frame.
 * Everything a frame *says* is kept apart from what can be concluded
 * from it: flags, truncation, retransmission and reason validity are
 * separate fields rather than folded into one "reason" value. */
typedef struct {
    uint8_t  src[6];        /* Address 2, transmitter — as claimed, spoofable */
    uint8_t  dst[6];        /* Address 1, receiver */
    uint8_t  bssid[6];      /* Address 3 */
    uint8_t  subtype;       /* 10 disassoc, 12 deauth */
    uint8_t  fc_flags;      /* Frame Control byte 1, verbatim */
    uint8_t  retry;         /* FC Retry bit */
    uint8_t  protected_;    /* FC Protected Frame bit: body is encrypted (PMF) */
    uint8_t  truncated;     /* body shorter than the 2-byte Reason Code field */
    uint8_t  reason_valid;  /* 1 = reason decoded from a cleartext body */
    uint16_t reason;        /* 0 unless reason_valid */
    uint16_t seq;           /* Sequence Number (12 bits) */
    uint8_t  frag;          /* Fragment Number (4 bits) */
} deauth_frame_t;

/* Parse a raw 802.11 frame. Returns 1 for a management deauth/disassoc
 * with a complete 24-byte header (28 with +HTC), 0 otherwise. A frame
 * with a header but no reason is accepted with truncated = 1 and
 * reason_valid = 0 — it was on the air, its reason is unknown. */
int deauth_parse(const uint8_t *dot11, int len, deauth_frame_t *out);

/* Record one parsed frame (thread-safe). Clock comes from
 * flood_mono_ms() / flood_wall(). */
void deauth_record(const deauth_frame_t *f);

/* Copy the tables into s->deauth_events[] / s->deauth_victims[], ageing
 * out idle rows and recomputing flood status against the current
 * monotonic time. Sets s->deauth_flood_active if any victim aggregate
 * is flooded now. */
void deauth_snapshot(sloth_state_t *s);

/* Clear both internal tables. */
void deauth_clear(void);

#endif /* DEAUTH_SNOOP_H */
