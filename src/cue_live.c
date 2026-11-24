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

/* Incidents already considered: an incident asks once, as it opens. */
#define CUE_SEEN_MAX 128

static struct {
    int       on;
    chancue_t c;
    char      seen[CUE_SEEN_MAX][ALERT_INCIDENT_ID_LEN];
    int       seen_head;
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

/* 1 the first time an incident is offered, 0 after. */
static int first_sight(const char *id) {
    if (!id[0]) return 0;
    for (int i = 0; i < CUE_SEEN_MAX; i++)
        if (!strcmp(g.seen[i], id)) return 0;
    memcpy(g.seen[g.seen_head], id, ALERT_INCIDENT_ID_LEN);
    g.seen[g.seen_head][ALERT_INCIDENT_ID_LEN - 1] = '\0';
    g.seen_head = (g.seen_head + 1) % CUE_SEEN_MAX;
    return 1;
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

void cue_live_step(sloth_state_t *s, chanhop_t *h0, uint64_t now_ms) {
    if (!s) return;
    s->cue.on = g.on;
    if (!g.on) return;

    chanhop_t *sched[CUE_SCHED_MAX];
    sched[0] = h0;
    for (int k = 1; k < CUE_SCHED_MAX; k++)
        sched[k] = k < MON_RADIO_MAX ? mon_hop_sched_rw(k) : NULL;

    /* End what is due first, so a cue that ran out frees its place for
     * a finding of this same poll. */
    chancue_tick(&g.c, sched, CUE_SCHED_MAX, now_ms);
    for (int i = 0; i < s->alert_count; i++) {
        const alert_t *a = &s->alerts[i];
        if (a->resolved || !chancue_kind_cues(a->type)) continue;
        if (!first_sight(a->incident_id)) continue;
        (void)chancue_request(&g.c, sched, CUE_SCHED_MAX, a->type,
                              cue_live_finding_mhz(a), a->incident_id, now_ms);
    }

    cue_event_t ev[CUE_EVENTS_MAX];
    int n = chancue_drain(&g.c, ev, CUE_EVENTS_MAX);
    for (int i = 0; i < n; i++) emit(&ev[i]);

    s->cue.active        = chancue_active(&g.c);
    s->cue.started       = g.c.started;
    s->cue.refused       = g.c.refused;
    s->cue.refused_limit = g.c.refused_limit;
    s->cue.cued_ms       = h0 ? h0->cued_total_ms : 0;
}
