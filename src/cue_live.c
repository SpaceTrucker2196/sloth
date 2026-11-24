/* Passive cueing, sloth-wifi's side (#248). See cue_live.h. */
#include "cue_live.h"

#include <string.h>

#include "chancue.h"
#include "cov_interval.h"
#include "evidence_ring.h"
#include "jsonl.h"
#include "mon_radios.h"
#include "rule_coverage_live.h"
#include "sloth_clock.h"

/* The open cueing incidents already offered: an incident asks once, as
 * it opens. Rebuilt every step from the incidents s->alerts still holds
 * open, so an id leaves only when its incident has resolved or been
 * evicted - and an incident id is never reused (a reopen is a new id) -
 * and the set never holds more than s->alerts can (#248 review: a
 * 128-entry ring let an incident still open be offered again once 128
 * newer ones had passed through). */
static struct {
    int       on;
    chancue_t c;
    char      seen[MAX_ALERTS][ALERT_INCIDENT_ID_LEN];
    int       nseen;
} g;

void cue_live_enable(int on) { g.on = on ? 1 : 0; }
int  cue_live_enabled(void)  { return g.on; }

void cue_live_reset(void) {
    memset(&g, 0, sizeof(g));
    chancue_init(&g.c);
}

int cue_live_finding_mhz(const alert_t *a) {
    if (!a) return 0;
    for (int i = 0; i < a->evidence_id_count && i < ALERT_EVIDENCE_IDS; i++) {
        evidence_rec_t r;
        if (evidence_ring_get(a->evidence_ids[i], &r, NULL, 0) < 0) continue;
        if (r.freq_mhz) return r.freq_mhz;
    }
    return 0;
}

static int was_seen(const char *id) {
    for (int i = 0; i < g.nseen; i++)
        if (!strcmp(g.seen[i], id)) return 1;
    return 0;
}

/* The `cue` record (JSONL 2.13.0): no address, no SSID - the alert
 * carries those, and incident_id joins the two. Each record is a change
 * of one cue's state; a burst of identical refusals is one record a
 * minute (CUE_REFUSED_QUIET_MS), counted in sensor_health either way. */
static void emit(const cue_event_t *e) {
    static const char *const st[] = { "started", "ended", "refused" };
    const char *kind = cov_kind_name(e->ty);
    const char *state = st[e->state];
    const char *band = cov_ivb_name(cov_ivb_of_mhz(e->freq_mhz));
    const char *reason = chancue_reason_name(e->reason);
    jsonl_field_t f[10];
    int n = 0;
    f[n++] = (jsonl_field_t){ "ty",          JSONL_F_INT, NULL, e->ty, 0.0, 0 };
    f[n++] = (jsonl_field_t){ "kind",        JSONL_F_STR, kind, 0, 0.0, 0 };
    f[n++] = (jsonl_field_t){ "state",       JSONL_F_STR, state, 0, 0.0, 0 };
    f[n++] = (jsonl_field_t){ "channel",     JSONL_F_INT, NULL, e->channel, 0.0, 0 };
    f[n++] = (jsonl_field_t){ "freq_mhz",    JSONL_F_INT, NULL, e->freq_mhz, 0.0, 0 };
    f[n++] = (jsonl_field_t){ "band",        JSONL_F_STR, band, 0, 0.0, 0 };
    f[n++] = (jsonl_field_t){ "duration_s",  JSONL_F_INT, NULL, e->duration_s, 0.0, 0 };
    if (e->state == CUE_EV_REFUSED)
        f[n++] = (jsonl_field_t){ "reason",  JSONL_F_STR, reason, 0, 0.0, 0 };
    else
        f[n++] = (jsonl_field_t){ "radio",   JSONL_F_INT, NULL, e->radio, 0.0, 0 };
    f[n++] = (jsonl_field_t){ "incident_id", JSONL_F_STR, e->incident_id, 0, 0.0, 0 };
    jsonl_emit_fields("cue", sloth_wall(), f, n);
}

static void flush(void) {
    cue_event_t ev[CUE_EVENTS_MAX];
    int n = chancue_drain(&g.c, ev, CUE_EVENTS_MAX);
    for (int i = 0; i < n; i++) emit(&ev[i]);
}

/* The next seen set, built while the current one is read. */
static char g_keep[MAX_ALERTS][ALERT_INCIDENT_ID_LEN];

void cue_live_step(sloth_state_t *s, chanhop_t *h0, uint64_t now_ms) {
    if (!s) return;
    s->cue.on = g.on;
    if (!g.on) return;

    chanhop_t *sched[CUE_SCHED_MAX];
    sched[0] = h0;
    for (int k = 1; k < CUE_SCHED_MAX; k++)
        sched[k] = k < MON_RADIO_MAX ? mon_hop_sched_rw(k) : NULL;

    /* End what is due first, so a cue that ran out frees its place for
     * a finding of this same poll. The events are written as they are
     * made, after the tick and after each request: one request makes at
     * most one event and a tick at most CUE_MAX_ACTIVE, so the queue of
     * CUE_EVENTS_MAX never fills however many incidents open in one
     * poll (#248 review: a burst after a monitor outage used to push a
     * `started` past the queue, leaving its `ended` unmatched). */
    chancue_tick(&g.c, sched, CUE_SCHED_MAX, now_ms);
    flush();

    int nkeep = 0;
    for (int i = 0; i < s->alert_count && i < MAX_ALERTS; i++) {
        const alert_t *a = &s->alerts[i];
        if (a->resolved || !a->incident_id[0] || !chancue_kind_cues(a->type))
            continue;
        int seen = was_seen(a->incident_id);
        memcpy(g_keep[nkeep], a->incident_id, ALERT_INCIDENT_ID_LEN);
        g_keep[nkeep][ALERT_INCIDENT_ID_LEN - 1] = '\0';
        nkeep++;
        if (seen) continue;
        (void)chancue_request(&g.c, sched, CUE_SCHED_MAX, a->type,
                              cue_live_finding_mhz(a), a->incident_id, now_ms);
        flush();
    }
    memcpy(g.seen, g_keep, (size_t)nkeep * sizeof(g.seen[0]));
    g.nseen = nkeep;

    s->cue.cued_ms = h0 ? h0->cued_total_ms : 0;
    cue_live_publish(s);
}

void cue_live_publish(sloth_state_t *s) {
    if (!s) return;
    s->cue.on = g.on;
    if (!g.on) return;
    s->cue.active        = chancue_active(&g.c);
    s->cue.started       = g.c.started;
    s->cue.refused       = g.c.refused;
    s->cue.refused_limit = g.c.refused_limit;
}
