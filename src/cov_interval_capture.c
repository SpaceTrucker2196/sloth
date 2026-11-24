#include <string.h>
#include "cov_interval_capture.h"
#include "mon_radios.h"
#include "capture/probe.h"
#include "cov_timeline.h"
#include "sloth_clock.h"

/* The capture side of the per-interval coverage record (#242 item 2).
 * Contract: cov_interval_capture.h. Main thread only. */

int cov_frame_class(const dot11_frame_t *fr, int bad_fcs) {
    if (bad_fcs) return COV_FC_FCS_BAD;
    if (!fr || fr->proto != 0) return COV_FC_OTHER;
    switch (fr->type) {
    case 0:   /* management, IEEE 802.11-2020 Table 9-1 */
        switch (fr->subtype) {
        case 8: case 5:          return COV_FC_BEACON;   /* beacon, probe response */
        case 4:                  return COV_FC_PROBE;
        case 11:                 return COV_FC_AUTH;
        case 0: case 1: case 2: case 3:
                                 return COV_FC_ASSOC;    /* (re)assoc req / resp */
        case 10: case 12:        return COV_FC_DEAUTH;   /* disassoc, deauth */
        case 13: case 14:        return COV_FC_ACTION;   /* action, action no ack */
        default:                 return COV_FC_OTHER;
        }
    case 1:
        return COV_FC_CTRL;
    case 2: {
        uint16_t et = 0;
        if (dot11_frame_payload(fr, NULL, &et) == DOT11_DATA_OK && et == 0x888E)
            return COV_FC_EAPOL;
        return COV_FC_DATA;
    }
    default:  /* extension (type 3) */
        return COV_FC_OTHER;
    }
}

/* Per radio, the scheduler's slots as last read (a hopping radio), or
 * its delivered count (a fixed one). A slot is keyed by its frequency:
 * after a re-deal (chanhop_split() resets the scheduler) the list and
 * the totals start again, and a slot whose frequency moved or whose
 * total fell is differenced from zero. */
typedef struct {
    int      n;
    int      freq[CHANHOP_MAX];
    uint64_t ms[CHANHOP_MAX];
    uint64_t fr[CHANHOP_MAX];
    int      have_fixed;
    uint64_t fixed_frames;
} radio_base_t;

static struct {
    const chanhop_t *h0;
    int          started;
    uint64_t     last_ms;
    radio_base_t base[MON_RADIO_MAX];
    uint64_t     cls[COV_FC_N];
    int          cap_ok, mon_ok;
    uint64_t     cap_drop, cap_ifdrop, mon_drop, mon_ifdrop;
} g;

void cov_iv_capture_set_hop0(const chanhop_t *h0) { g.h0 = h0; }

void cov_iv_capture_reset(void) {
    const chanhop_t *h0 = g.h0;
    memset(&g, 0, sizeof(g));
    g.h0 = h0;
    cov_iv_reset();
}

/* main.c names every replayed stream's interface "replay" (#119). */
static int is_replay(const char *iface) { return strcmp(iface, "replay") == 0; }

static void sample_hop(int radio, const chanhop_t *h, uint64_t now_ms,
                       int alive, int add) {
    radio_base_t *b = &g.base[radio];
    int n = h->count < CHANHOP_MAX ? h->count : CHANHOP_MAX;
    for (int i = 0; i < n; i++) {
        const chanhop_slot_t *sl = &h->slots[i];
        uint64_t ms = chanhop_slot_time_ms(h, i, now_ms);
        uint64_t fr = sl->frames;
        uint64_t pms = 0, pfr = 0;
        if (i < b->n && b->freq[i] == sl->freq_mhz && ms >= b->ms[i] && fr >= b->fr[i]) {
            pms = b->ms[i];
            pfr = b->fr[i];
        }
        if (add && alive) cov_iv_add(radio, sl->freq_mhz, sl->channel, ms - pms, fr - pfr);
        b->freq[i] = sl->freq_mhz;
        b->ms[i]   = ms;
        b->fr[i]   = fr;
    }
    b->n = n;
    b->have_fixed = 0;
}

static void sample_fixed(int radio, int freq, uint64_t frames, uint64_t dt,
                         int alive, int add) {
    radio_base_t *b = &g.base[radio];
    uint64_t d = b->have_fixed && frames >= b->fixed_frames ? frames - b->fixed_frames : 0;
    if (add && alive)
        cov_iv_add(radio, freq, freq > 0 ? wifi_freq_channel(freq, NULL) : 0, dt, d);
    b->have_fixed   = 1;
    b->fixed_frames = frames;
    b->n = 0;
}

static void sample_radios(const sloth_state_t *s, uint64_t now_ms, uint64_t dt,
                          int add) {
    if (!s->probe_iface[0]) return;
    int multi = mon_radios_active();
    int alive0 = s->mon_health.running;
    if (g.h0 && g.h0->count > 0) {
        sample_hop(0, g.h0, now_ms, alive0, add);
    } else {
        mon_radio_t r0;
        uint64_t f = multi && mon_radios_get(0, &r0) ? r0.frames : mon_frame_total();
        sample_fixed(0, mon_radio0_freq_mhz(), f, dt, alive0, add);
    }
    if (!multi) return;
    int n = mon_radios_count();
    for (int k = 1; k < n && k < MON_RADIO_MAX; k++) {
        mon_radio_t r;
        if (!mon_radios_get(k, &r)) continue;
        int alive = mon_radio_alive(r.state);
        const chanhop_t *h = mon_hop_sched(k);
        if (h) sample_hop(k, h, now_ms, alive, add);
        else   sample_fixed(k, r.freq_mhz, r.frames, dt, alive, add);
    }
}

static int stats_ok(const capture_health_t *h) { return h->open && h->stats_valid; }

static void take_baselines(const sloth_state_t *s) {
    mon_frame_class_totals(g.cls);
    g.cap_ok     = stats_ok(&s->cap_health);
    g.cap_drop   = s->cap_health.ps_drop;
    g.cap_ifdrop = s->cap_health.ps_ifdrop;
    g.mon_ok     = stats_ok(&s->mon_health);
    g.mon_drop   = s->mon_health.ps_drop;
    g.mon_ifdrop = s->mon_health.ps_ifdrop;
}

static uint64_t diff(uint64_t now, uint64_t then) { return now >= then ? now - then : 0; }

void cov_iv_capture_poll(const sloth_state_t *s, time_t wall, uint64_t mono_ms) {
    if (!s) return;
    if (is_replay(s->pkt_iface) || is_replay(s->probe_iface) || is_replay(s->bt_iface)) {
        cov_iv_abandon();
        g.started = 0;
        return;
    }
    /* The monitor handle's drop total each tick (#246): a finding whose
     * cited frames span a tick in which it rose was not seen whole
     * (src/cov_timeline.h). Only while pcap_stats() is answering. */
    if (stats_ok(&s->mon_health))
        cov_tl_drops_note(sloth_wall_ms(), s->mon_health.ps_drop + s->mon_health.ps_ifdrop);
    if (!g.started) {
        sample_radios(s, mono_ms, 0, 0);
        take_baselines(s);
        cov_iv_open(wall, mono_ms);
        g.started = 1;
        g.last_ms = mono_ms;
        return;
    }
    uint64_t dt = diff(mono_ms, g.last_ms);
    g.last_ms = mono_ms;
    sample_radios(s, mono_ms, dt, 1);
    if (!cov_iv_due(mono_ms)) return;

    uint64_t now[COV_FC_N], d[COV_FC_N];
    mon_frame_class_totals(now);
    for (int k = 0; k < COV_FC_N; k++) d[k] = diff(now[k], g.cls[k]);
    int cap = g.cap_ok && stats_ok(&s->cap_health);
    int mon = g.mon_ok && stats_ok(&s->mon_health);
    cov_iv_close(wall, mono_ms, d,
                 cap, diff(s->cap_health.ps_drop, g.cap_drop),
                      diff(s->cap_health.ps_ifdrop, g.cap_ifdrop),
                 mon, diff(s->mon_health.ps_drop, g.mon_drop),
                      diff(s->mon_health.ps_ifdrop, g.mon_ifdrop));
    take_baselines(s);
}
