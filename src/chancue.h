#ifndef SLOTH_CHANCUE_H
#define SLOTH_CHANCUE_H

#include <stdint.h>

#include "sloth.h"
#include "wifi_chanhop.h"

/* Passive cueing, scheduler dwell only (#248; owner rulings of
 * 2026-11-23, docs/wiki/passive-cueing.md).
 *
 * Under --cue, a new incident of one of six fixed 802.11 kinds asks the
 * hop scheduler to stay longer on the channel the finding was heard on:
 * that channel's dwell becomes CHANHOP_CUE_MULT (4) times its normal
 * plan for CUE_DURATION_MS (120 s), then returns. FM 2-0 (2004) 8-14:
 * SIGINT "is often used to cue, and be cued by," other sensors; this is
 * the narrowest form, a sensor cueing its own receiver.
 *
 * Receive-only. A cue changes only how long sloth's own monitor radio
 * stays on a channel already in its --hop rotation: no channel is
 * added, nothing is transmitted, no other receiver is started (ruling
 * 5: sloth-rf records nothing) and no cue leaves the site (ruling 6,
 * deferred to sloth-mesh#19). MISSION.md section 2 carries the ruling
 * that this is inside the #22 carve-out.
 *
 * Limits (ruling 3). A cue over any of them is refused and counted, and
 * the limit refusals feed SENSOR_SUPPRESSED (`suppressed:cue`), because
 * an attacker can make false triggers to hold the radio on one channel:
 *
 *   share   on the radio that holds the channel, the cued channels'
 *           planned dwells together may not exceed the uncued channels'
 *           (src/wifi_chanhop.h, "Cued dwell"): cues take at most 50 %
 *           of that radio's time, and every other channel keeps at
 *           least half of its normal share - never zero.
 *   active  at most CUE_MAX_ACTIVE cues at once, over all radios.
 *   rate    at most CUE_RATE_MAX cues started in any CUE_RATE_WINDOW_MS.
 *
 * Two refusals are not limits and do not feed SENSOR_SUPPRESSED: the
 * finding names no channel (its evidence carries no radiotap frequency,
 * or the ring no longer holds it), or its channel is in no radio's
 * rotation. A finding on a channel already cued is absorbed: no new
 * cue, no record, the running cue's end unchanged.
 *
 * Pure: no platform call, no clock, no I/O. The caller passes the
 * schedulers (radio 0's first, then each other sensor radio's share,
 * NULL for a radio with none) and the monotonic time;
 * src/cue_live.c is the caller. */

#define CUE_MAX_ACTIVE         4
#define CUE_DURATION_MS        120000u
#define CUE_RATE_MAX           8
#define CUE_RATE_WINDOW_MS     600000u
/* A refused record is written once per kind, channel and reason in
 * this long; every refusal is counted. */
#define CUE_REFUSED_QUIET_MS   60000u
#define CUE_SCHED_MAX          4
#define CUE_EVENTS_MAX         32

typedef enum {
    CUE_STARTED = 0,         /* a cue began */
    CUE_NOT_CUEING,          /* not one of the six kinds: nothing done */
    CUE_ABSORBED,            /* its channel is cued already */
    CUE_REFUSE_NO_CHANNEL,   /* refused: the finding names no channel */
    CUE_REFUSE_NOT_HOPPED,   /* refused: no radio's rotation holds it */
    CUE_REFUSE_ACTIVE,       /* refused, limit: CUE_MAX_ACTIVE running */
    CUE_REFUSE_RATE,         /* refused, limit: CUE_RATE_MAX in the window */
    CUE_REFUSE_SHARE         /* refused, limit: past the radio's 50 % */
} cue_result_t;

/* The refusal word of the `cue` record: "no_channel", "not_hopped",
 * "active_cap", "rate_cap", "share_cap"; "" for anything else. */
const char *chancue_reason_name(cue_result_t r);
/* 1 for the three limit refusals, the ones SENSOR_SUPPRESSED counts. */
int chancue_is_limit(cue_result_t r);

/* 1 for the six kinds that may cue (ruling 4): EVIL_TWIN, KARMA_AP,
 * KARMA_PROBE_FORGE, DEAUTH_FLOOD, PMKID_HARVEST, HANDSHAKE_HARVEST. */
int chancue_kind_cues(alert_type_t t);

typedef enum { CUE_EV_STARTED = 0, CUE_EV_ENDED, CUE_EV_REFUSED } cue_ev_state_t;

typedef struct {
    cue_ev_state_t state;
    alert_type_t   ty;
    int            freq_mhz;      /* 0: not known (no_channel) */
    int            channel;       /* 0: not known */
    int            radio;         /* holding radio; -1 for a refusal */
    uint32_t       duration_s;    /* started: planned; ended: held */
    cue_result_t   reason;        /* refused only */
    char           incident_id[ALERT_INCIDENT_ID_LEN];
} cue_event_t;

typedef struct {
    int          used;
    alert_type_t ty;
    int          freq_mhz;
    int          channel;
    int          radio;
    uint64_t     start_ms, until_ms;
    char         incident_id[ALERT_INCIDENT_ID_LEN];
} cue_t;

typedef struct {
    cue_t       cue[CUE_MAX_ACTIVE];
    uint64_t    starts[CUE_RATE_MAX];   /* start times, ring */
    int         start_head;
    uint64_t    started, ended, refused, refused_limit;
    struct {
        alert_type_t ty;
        int          freq_mhz;
        cue_result_t reason;
        uint64_t     at_ms;
        int          used;
    }           quiet[16];              /* refused records written lately */
    int         quiet_head;
    cue_event_t ev[CUE_EVENTS_MAX];
    int         nev;
    uint64_t    ev_dropped;             /* events with no room (not counts) */
} chancue_t;

void chancue_init(chancue_t *c);

/* A new incident of kind ty heard on freq_mhz (0: unknown). Starts a
 * cue, marking the channel on its scheduler at once, or says why not;
 * a refusal is counted and queued as an event (subject to
 * CUE_REFUSED_QUIET_MS). sched[k] is radio k's scheduler or NULL. */
cue_result_t chancue_request(chancue_t *c, chanhop_t *const *sched, int nsched,
                             alert_type_t ty, int freq_mhz,
                             const char *incident_id, uint64_t now_ms);

/* Once a poll, before the schedulers tick: end the cues whose time is
 * up (an `ended` event each), then mark every scheduler's slots from
 * the running cues - set where a cue holds the slot's frequency, clear
 * elsewhere - so a share re-dealt after a radio was lost is cued again
 * wherever its channel now sits. */
void chancue_tick(chancue_t *c, chanhop_t *const *sched, int nsched, uint64_t now_ms);

int  chancue_active(const chancue_t *c);

/* Move up to max queued events to out, oldest first; the count. */
int  chancue_drain(chancue_t *c, cue_event_t *out, int max);

#endif
