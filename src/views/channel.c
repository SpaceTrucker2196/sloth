#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/channel.h"

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

static const char *band_for(int ch) {
    if (ch >= 1   && ch <= 14)  return "2.4 GHz";
    if (ch >= 32  && ch <= 177) return "5 GHz";
    if (ch >= 181 && ch <= 233) return "6 GHz";
    return "?";
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

    tui_dim();
    TPRINT(" %-5s  %-7s  %4s  %4s  %4s  %-20s  %4s  %s\n",
           "Ch", "Band", "APs", "STAs", "Best", "Top SSID", "age", "activity");
    TPRINT(" %-5s  %-7s  %4s  %4s  %4s  %-20s  %4s  %s\n",
           "-----", "-------", "----", "----", "----",
           "--------------------", "----", "--------");
    tui_normal();

    if (s->channel_count == 0) {
        tui_dim();
        TPRINT("  (no channel activity observed yet)\n");
        if (s->probe_iface[0])
            TPRINT("  hop the adapter to other channels with "
                   "'iw dev %s set channel N' to widen coverage.\n",
                   s->probe_iface);
        tui_normal();
        return;
    }

    /* Find max activity for the bar scaling. */
    int max_a = 1;
    for (int i = 0; i < s->channel_count; i++) {
        int a = s->channels[i].ap_count + s->channels[i].assoc_count;
        if (a > max_a) max_a = a;
    }

    time_t now = time(NULL);
    for (int i = 0; i < s->channel_count; i++) {
        const channel_summary_t *c = &s->channels[i];
        int activity = c->ap_count + c->assoc_count;
        long age = (long)(now - c->last_seen);
        if (age < 0)     age = 0;
        if (age > 99999) age = 99999;
        char age_buf[8];
        if      (age <   60) snprintf(age_buf, sizeof(age_buf), "%lds", age);
        else if (age < 3600) snprintf(age_buf, sizeof(age_buf), "%ldm", age / 60);
        else                 snprintf(age_buf, sizeof(age_buf), "%ldh", age / 3600);

        if (i == s->channel_sel) tui_sel(); else tui_normal();
        TPRINT(" %-5d", c->channel);
        tui_dim();    TPRINT("  %-7s", band_for(c->channel));
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
            else { tui_sel(); printw("%s", buf); }
#else
            if (i == s->channel_sel) tui_sel(); else tui_bright();
            TPRINT("  %-20.20s", c->top_ssid);
#endif
        } else {
            tui_dim(); TPRINT("  %-20s", "-");
        }

        tui_dim(); TPRINT("  %4s  ", age_buf);

        /* Activity bar. */
        int bar = (int)((double)activity / (double)max_a * 24.0 + 0.5);
        if (bar > 24) bar = 24;
        if (bar < 0)  bar = 0;
        tui_bright();
        for (int b = 0; b < bar;     b++) TPRINT("\xe2\x96\x88");  /* █ */
        tui_dim();
        for (int b = bar; b < 24;    b++) TPRINT("\xe2\x96\x91");  /* ░ */
        tui_normal();
        TPRINT("\n");
    }
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
