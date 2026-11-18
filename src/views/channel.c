#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "sloth_clock.h"
#include "tui.h"
#include "views/channel.h"
#include "rf_quality.h"
#include "tui_glyph.h"

/* Per-channel activity summary. Answers the operator's "where should
 * I park my monitor adapter?" question by aggregating APs + associated
 * clients we've already observed per channel. The current sniff
 * channel sees the most data; this view is the coverage map of every
 * channel we've ever heard a beacon or a 4-way completion on. */

static channel_summary_t *find_or_alloc(channel_summary_t *tbl, int *n,
                                          int ch) {
    for (int i = 0; i < *n; i++)
        if (tbl[i].channel == ch) return &tbl[i];
    if (*n >= MAX_CHAN_ENTRIES) return NULL;
    channel_summary_t *e = &tbl[(*n)++];
    memset(e, 0, sizeof(*e));
    e->channel     = ch;
    e->best_signal = -127;
    return e;
}

void channel_summary_update(sloth_state_t *s) {
    if (!s) return;
    channel_summary_t tbl[MAX_CHAN_ENTRIES];
    int n = 0;
    memset(tbl, 0, sizeof(tbl));

    /* Beacons: ap_count + best signal + top SSID per channel. */
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        if (a->channel <= 0) continue;
        channel_summary_t *e = find_or_alloc(tbl, &n, a->channel);
        if (!e) continue;
        e->ap_count++;
        /* Promote-only: once this channel number's row has seen a 6 GHz
         * source, a later AP on the same number with no source (or a
         * different one) must not erase it — so the HE_6GHZ arm is
         * skipped once set, not merely overwritten in both directions.
         * Otherwise carry the AP's own source through; a non-6-GHz
         * value has no effect on ap_band_label() but keeping it is no
         * less honest than zeroing it. See channel_summary_t's
         * channel_source contract. */
        if (e->channel_source != CH_SRC_HE_6GHZ) e->channel_source = a->channel_source;
        if (a->signal_dbm > e->best_signal) {
            e->best_signal = a->signal_dbm;
            if (a->ssid[0])
                snprintf(e->top_ssid, sizeof(e->top_ssid), "%s", a->ssid);
            else
                snprintf(e->top_ssid, sizeof(e->top_ssid), "(hidden)");
        }
        if (a->last_seen > e->last_seen) e->last_seen = a->last_seen;
    }

    /* Associations: bump client count where we have a channel for the
     * STA's BSSID. */
    for (int i = 0; i < s->assoc_count; i++) {
        const assoc_t *as = &s->assocs[i];
        if (as->channel <= 0) continue;
        channel_summary_t *e = find_or_alloc(tbl, &n, as->channel);
        if (!e) continue;
        e->assoc_count++;
        if (as->last_seen > e->last_seen) e->last_seen = as->last_seen;
    }

    /* Sort by total activity (APs + clients) descending. */
    for (int i = 0; i < n - 1; i++) {
        int best = i;
        for (int j = i + 1; j < n; j++) {
            int aj = tbl[j].ap_count + tbl[j].assoc_count;
            int ab = tbl[best].ap_count + tbl[best].assoc_count;
            if (aj > ab) best = j;
        }
        if (best != i) {
            channel_summary_t t = tbl[i]; tbl[i] = tbl[best]; tbl[best] = t;
        }
    }

    memcpy(s->channels, tbl, sizeof(tbl));
    s->channel_count = n;
    if (s->channel_sel >= n && n > 0) s->channel_sel = n - 1;
}

/* ── G3 history (#195) ─────────────────────────────────────
 * Poll thread only, as channel_summary_update() is. cells[] is oldest
 * first and its last cell is the minute `minute`. */
typedef struct {
    int      channel;
    long     minute;
    uint32_t last_total;
    uint32_t max;
    uint32_t cells[CHAN_HZ_CELLS];
} chan_hz_t;

static chan_hz_t g_hz[MAX_CHAN_ENTRIES];
static int       g_hz_n;

static chan_hz_t *hz_find(int ch, int make, long minute) {
    for (int i = 0; i < g_hz_n; i++)
        if (g_hz[i].channel == ch) return &g_hz[i];
    if (!make) return NULL;
    int slot;
    if (g_hz_n < MAX_CHAN_ENTRIES) {
        slot = g_hz_n++;
    } else {                                   /* full: the stalest */
        slot = 0;
        for (int i = 1; i < g_hz_n; i++)
            if (g_hz[i].minute < g_hz[slot].minute) slot = i;
    }
    chan_hz_t *e = &g_hz[slot];
    memset(e, 0, sizeof(*e));
    e->channel = ch;
    e->minute  = minute;
    for (int i = 0; i < CHAN_HZ_CELLS; i++) e->cells[i] = TG_HZ_UNSEEN;
    e->cells[CHAN_HZ_CELLS - 1] = 0;
    return e;
}

void channel_hz_update(const sloth_state_t *s, time_t now) {
    if (!s || now <= 0) return;
    long minute = (long)(now / CHAN_HZ_CELL_S);
    for (int i = 0; i < s->channel_count; i++) {
        const channel_summary_t *c = &s->channels[i];
        chan_hz_t *e = hz_find(c->channel, 0, minute);
        if (!e) {
            /* The first sighting sets the baseline only: the total so
             * far was counted before this history began. */
            e = hz_find(c->channel, 1, minute);
            e->last_total = c->ctrl_total;
            continue;
        }
        long step = minute - e->minute;
        if (step >= CHAN_HZ_CELLS) {
            for (int k = 0; k < CHAN_HZ_CELLS; k++) e->cells[k] = 0;
        } else if (step > 0) {
            memmove(e->cells, e->cells + step,
                    sizeof(uint32_t) * (size_t)(CHAN_HZ_CELLS - step));
            for (long k = CHAN_HZ_CELLS - step; k < CHAN_HZ_CELLS; k++)
                e->cells[k] = 0;
        }
        if (step > 0) e->minute = minute;
        /* ctrl_frames.c evicts its stalest channel when full; the
         * total then restarts from zero and is all new. */
        uint32_t d = c->ctrl_total >= e->last_total
                   ? c->ctrl_total - e->last_total : c->ctrl_total;
        e->last_total = c->ctrl_total;
        uint32_t *cur = &e->cells[CHAN_HZ_CELLS - 1];
        if (*cur == TG_HZ_UNSEEN) *cur = 0;
        *cur = UINT32_MAX - 1 - *cur < d ? UINT32_MAX - 1 : *cur + d;
        if (*cur > e->max) e->max = *cur;
    }
}

int channel_hz_cells(int channel, uint32_t out[CHAN_HZ_CELLS],
                     uint32_t *max) {
    const chan_hz_t *e = hz_find(channel, 0, 0);
    *max = 0;
    if (!e) {
        for (int i = 0; i < CHAN_HZ_CELLS; i++) out[i] = TG_HZ_UNSEEN;
        return 0;
    }
    memcpy(out, e->cells, sizeof(e->cells));
    *max = e->max;
    return 1;
}

void channel_hz_clear(void) {
    memset(g_hz, 0, sizeof(g_hz));
    g_hz_n = 0;
}

void view_channel_draw(const sloth_state_t *s) {
    int total_aps = 0, total_clients = 0;
    int active = 0;
    for (int i = 0; i < s->channel_count; i++) {
        total_aps     += s->channels[i].ap_count;
        total_clients += s->channels[i].assoc_count;
        if (s->channels[i].ap_count + s->channels[i].assoc_count > 0) active++;
    }

    tui_normal(); TPRINT(" Channel activity: ");
    tui_bright(); TPRINT("%d channels", active);
    tui_dim();    TPRINT(" (");
    tui_normal(); TPRINT("%d APs", total_aps);
    tui_dim();    TPRINT(" / ");
    tui_normal(); TPRINT("%d clients", total_clients);
    tui_dim();    TPRINT(")");
    if (s->probe_iface[0]) {
        tui_dim();    TPRINT("  iface: ");
        tui_bright(); TPRINT("%s", s->probe_iface);
    }
    TPRINT("\n");

    /* The table is cut at the edge rather than wrapped (#150), so an
     * 80-column screen loses the strip, not every row below it. */
    tui_clip_rows(1);
    tui_dim();
    TPRINT(" %-5s  %-7s  %4s  %4s  %4s  %-20s  %6s  %6s  %4s  %s\n",
           "Ch", "Band", "APs", "STAs", "Best", "Top SSID", "retry",
           "ctrl", "age", "ctrl/min, last 24 min");
    TPRINT(" %-5s  %-7s  %4s  %4s  %4s  %-20s  %6s  %6s  %4s  %s\n",
           "-----", "-------", "----", "----", "----",
           "--------------------", "------", "------", "----", "------------------------");
    tui_normal();

    if (s->channel_count == 0) {
        tui_clip_rows(0);    /* the advice below wraps on purpose */
        tui_dim();
        TPRINT("  (no channel activity observed yet)\n");
        if (s->probe_iface[0])
            TPRINT("  widen coverage by hopping channels: restart with "
                   "'--hop' (sloth retunes %s itself), or set them manually "
                   "with 'iw dev %s set channel N'.\n",
                   s->probe_iface, s->probe_iface);
        tui_normal();
        return;
    }

    time_t now = sloth_wall();
    for (int i = 0; i < s->channel_count; i++) {
        const channel_summary_t *c = &s->channels[i];
        long age = (long)(now - c->last_seen);
        if (age < 0)     age = 0;
        if (age > 99999) age = 99999;
        char age_buf[8];
        if      (age <   60) snprintf(age_buf, sizeof(age_buf), "%lds", age);
        else if (age < 3600) snprintf(age_buf, sizeof(age_buf), "%ldm", age / 60);
        else                 snprintf(age_buf, sizeof(age_buf), "%ldh", age / 3600);

        if (i == s->channel_sel) tui_sel(); else tui_normal();
        TPRINT(" %-5d", c->channel);
        tui_dim();    TPRINT("  %-7s", ap_band_label(c->channel, c->channel_source));
        if (i == s->channel_sel) tui_sel(); else tui_bright();
        TPRINT("  %4d", c->ap_count);
        if (i == s->channel_sel) tui_sel(); else tui_normal();
        TPRINT("  %4d", c->assoc_count);

        /* Best signal — heat colour. */
        double frac = (c->best_signal + 90.0) / 60.0;
        if (frac < 0) frac = 0;
        if (frac > 1) frac = 1;
        if (c->best_signal > -127) tui_heat(frac);
        else                        tui_dim();
        TPRINT("  %4d", c->best_signal);

        /* Top SSID — coloured by hash. */
        if (c->top_ssid[0]) {
#ifdef WITH_NCURSES
            char buf[24];
            snprintf(buf, sizeof(buf), "  %-20.20s", c->top_ssid);
            if (i != s->channel_sel) tui_ssid_addstr(buf, 0);
            else { tui_sel(); tui_printf("%s", buf); }
#else
            if (i == s->channel_sel) tui_sel(); else tui_bright();
            TPRINT("  %-20.20s", c->top_ssid);
#endif
        } else {
            tui_dim(); TPRINT("  %-20s", "-");
        }

        /* Retry ratio (roadmap B3) — the passive signature of a channel
         * in trouble. "-" is "not enough frames to say", which is not
         * the same as 0%: a quiet channel is not a clean one. */
        if (c->retry_pct < 0) {
            tui_dim(); TPRINT("  %6s", "-");
        } else {
            if      (c->retry_pct >= RF_RETRY_DEGRADED_PCT) tui_heat(0.9);
            else if (c->retry_pct >= RF_RETRY_DEGRADED_PCT / 2) tui_heat(0.5);
            else tui_normal();
            char rbuf[12];
            snprintf(rbuf, sizeof(rbuf), "%d%%", c->retry_pct);
            TPRINT("  %6s", rbuf);
        }

        /* Observed control-frame volume (#64). RTS/CTS/ACK dominate a
         * channel's real airtime, so this is the measured half of the
         * occupancy picture the QBSS Load IE only self-reports. "-" is
         * "none counted", which on a channel with APs on it usually
         * means the sweep has not dwelt here long. */
        if (c->ctrl_total == 0) {
            tui_dim(); TPRINT("  %6s", "-");
        } else {
            char cbuf[12];
            snprintf(cbuf, sizeof(cbuf), "%u", (unsigned)c->ctrl_total);
            /* Heat on the RTS share rather than the raw count: a busy
             * channel has plenty of ACKs and that is normal, while a
             * channel that is mostly RTS is one being reserved. */
            unsigned rts_share = c->ctrl_total
                               ? (c->ctrl_rts * 100u) / c->ctrl_total : 0u;
            if      (rts_share >= 50) tui_heat(0.9);
            else if (rts_share >= 25) tui_heat(0.5);
            else                      tui_normal();
            TPRINT("  %6s", cbuf);
        }

        tui_dim(); TPRINT("  %4s  ", age_buf);

        /* G3, the horizon strip (#195): control frames a minute over the
         * last CHAN_HZ_CELLS minutes on the channel's own scale, 0 to
         * its busiest minute so far, which is printed. It replaced the
         * activity bar, which drew APs + STAs against the busiest row:
         * the two numbers are in their own columns, and "when" is what
         * no column said. */
        uint32_t hz[CHAN_HZ_CELLS], hz_max = 0;
        channel_hz_cells(c->channel, hz, &hz_max);
        for (int b = 0; b < CHAN_HZ_CELLS; b++) {
            tg_cell_t cell = tg_hz_cell(hz[b], hz_max);
            if (cell.tone == TG_NONE) tui_normal(); else tg_tone_apply(cell.tone);
            TPRINT("%s", cell.glyph);
        }
        tui_dim();
        if (hz_max) TPRINT(" %u", (unsigned)hz_max);
        tui_normal();
        TPRINT("\n");
    }
    tui_clip_rows(0);
    /* R9's caption line: source, window, scale. */
    tui_dim();
    TPRINT(" ctrl: control frames a minute, last %d min, each row 0 to its"
           " busiest minute (the number); \xe2\x96\x84 to half, \xe2\x96\x88"
           " above, _ none counted (also: tuned elsewhere), blank before"
           " this run watched\n", CHAN_HZ_CELLS);
    tui_normal();
}

void view_channel_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->channel_sel > 0) s->channel_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->channel_count > 0 && s->channel_sel < s->channel_count - 1)
            s->channel_sel++;
        break;
    default:
        break;
    }
}
