#ifndef SLOTH_CUE_LIVE_H
#define SLOTH_CUE_LIVE_H

#include <stdint.h>

#include "sloth.h"
#include "wifi_chanhop.h"

/* sloth-wifi's side of passive cueing (#248): the policy is
 * src/chancue.h; this finds the findings, their channels and the
 * schedulers, writes the `cue` records and publishes the counters.
 *
 * Runs in the hop stage (src/poll.c st_chanhop, PH_POST), after
 * alerts_update(), before the schedulers tick, so a finding raised this
 * poll lengthens the dwell from this poll on. Off unless --cue (with
 * --hop; src/main.c refuses it under --strict and ignores it without
 * --hop). */

void cue_live_enable(int on);
int  cue_live_enabled(void);
/* Forget the cues, the counters and the incidents seen (tests). */
void cue_live_reset(void);

/* The channel a finding was heard on: the radiotap frequency of the
 * first frame it cites in the evidence ring with one (for EVIL_TWIN the
 * accused half comes first). 0 when it cites none, the ring no longer
 * holds them, or none carries a frequency; such a finding does not cue
 * (refused `no_channel`). */
int  cue_live_finding_mhz(const alert_t *a);

/* One poll. Each incident in s->alerts not seen before, open and of a
 * cueing kind, is a request; then the cue table is applied to radio 0's
 * scheduler h0 and every other sensor radio's share
 * (mon_hop_sched_rw()); then the events are written as `cue` records
 * and s->cue is filled. Nothing when cueing is off. Touches no
 * platform op: the retune that follows is chanhop_service()'s. */
void cue_live_step(sloth_state_t *s, chanhop_t *h0, uint64_t now_ms);

/* Fill s->cue from the cue table without stepping it: main.c's
 * chanhop_drive() calls it before its probe_iface guard, so under --cue
 * sensor_health carries the cue_* members (zeros) while no monitor
 * interface runs the scheduler too. cue_live_step() ends with it. */
void cue_live_publish(sloth_state_t *s);

#endif
