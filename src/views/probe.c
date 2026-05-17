#include <stdio.h>
#include <string.h>
#include <time.h>
#include "ntop.h"
#include "tui.h"
#include "oui.h"
#include "capture/probe.h"
#include "views/probe.h"

#define PROBE_PAGE 30

/* ── Helpers ─────────────────────────────────────────────── */

static void fmt_mac(const uint8_t *mac, char *buf, int sz) {
    snprintf(buf, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void fmt_age(time_t last_seen, char *buf, int sz) {
    time_t age = time(NULL) - last_seen;
    if      (age <   60) snprintf(buf, sz, "%llds", (long long)age);
    else if (age < 3600) snprintf(buf, sz, "%lldm", (long long)(age / 60));
    else                 snprintf(buf, sz, "%lldh", (long long)(age / 3600));
}

/* Age bucket: < 5s = bright, < 30s = normal, older = dim. */
static void phos_age(time_t last_seen) {
    time_t age = time(NULL) - last_seen;
    if      (age <  5) tui_bright();
    else if (age < 30) tui_normal();
    else               tui_dim();
}

/* 6-char phosphor signal bar; left third dim, mid normal, right bright. */
static void probe_signal_bar(int8_t dbm) {
    double pct    = (dbm < -90) ? 0.0 : (dbm > -30) ? 1.0 : (dbm + 90.0) / 60.0;
    int    filled = (int)(pct * 6);
    for (int i = 0; i < 6; i++) {
        if (i < filled) {
            double pos = (double)i / 6.0;
            if      (pos < 0.33) tui_dim();
            else if (pos < 0.66) tui_normal();
            else                 tui_bright();
            TPRINT("#");
        } else {
            tui_dim(); TPRINT(".");
        }
    }
}

/* Pre-build a 6-char bar string (no color) for selected-row use. */
static void sigbar_str(int8_t dbm, char *out) {
    double pct    = (dbm < -90) ? 0.0 : (dbm > -30) ? 1.0 : (dbm + 90.0) / 60.0;
    int    filled = (int)(pct * 6);
    for (int i = 0; i < 6; i++) out[i] = (i < filled) ? '#' : '.';
    out[6] = '\0';
}

/* ── Draw ────────────────────────────────────────────────── */

void view_probe_draw(const ntop_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = PROBE_PAGE;
#endif

    /* count devices seen in last 5 seconds */
    time_t now = time(NULL);
    int active = 0;
    for (int i = 0; i < s->probe_count; i++)
        if (now - s->probe_clients[i].last_seen < 5) active++;

    /* status bar */
    tui_normal(); TPRINT(" Probe clients: ");
    tui_bright();  TPRINT("%d", s->probe_count);
    if (active > 0) {
        tui_dim();    TPRINT("  (");
        tui_bright(); TPRINT("%d active", active);
        tui_dim();    TPRINT(")");
    }
    if (s->probe_iface[0]) {
        tui_dim();    TPRINT("  iface: ");
        tui_bright(); TPRINT("%s", s->probe_iface);
    } else {
        tui_dim(); TPRINT("  (no monitor interface)");
    }
#ifndef WITH_NCURSES
    tui_dim(); TPRINT("  [up/dn] navigate  [c] clear");
#endif
    TPRINT("\n");

    /* column headers */
    tui_dim();
    TPRINT(" %-17s  %-12s  %6s  %3s  %5s  %5s  %s\n",
           "MAC", "Vendor", "Signal", "Ch", "Seen", "Pkts", "Probing");
    TPRINT(" %-17s  %-12s  %6s  %3s  %5s  %5s  %s\n",
           "-----------------", "------------", "------", "---",
           "-----", "-----", "-------");
    tui_normal();

    if (s->probe_count == 0) {
        tui_dim();
        if (s->probe_iface[0])
            TPRINT("  (listening — no probe requests seen yet)\n");
        else
            TPRINT("  (no monitor-mode interface found — try: iw dev wlan1 set type monitor)\n");
        tui_normal();
        return;
    }

    int page_top = s->probe_sel - page / 2;
    if (page_top + page > s->probe_count) page_top = s->probe_count - page;
    if (page_top < 0) page_top = 0;
    int page_end = page_top + page;
    if (page_end > s->probe_count) page_end = s->probe_count;

    for (int row = page_top; row < page_end; row++) {
        const probe_client_t *c = &s->probe_clients[row];

        char mac[18], age[8];
        fmt_mac(c->mac, mac, sizeof(mac));
        fmt_age(c->last_seen, age, sizeof(age));
        const char *ssid   = c->ssid[0] ? c->ssid : "(wildcard)";
        const char *vendor = oui_lookup(c->mac);
        const char *vstr   = vendor ? vendor : "";

        if (row == s->probe_sel) {
            char bar[7];
            sigbar_str(c->signal_dbm, bar);
            tui_sel();
            TPRINT(" %-17s  %-12.12s  %6s  %3d  %5s  %5d  %.32s\n",
                   mac, vstr, bar, c->channel, age, c->frame_count, ssid);
            tui_reset();
        } else {
            /* MAC: intensity by age */
            phos_age(c->last_seen);
            TPRINT(" %s", mac);

            /* Vendor: secondary, always dim */
            tui_dim(); TPRINT("  %-12.12s  ", vstr);

            /* Signal: 6-char phosphor bar */
            probe_signal_bar(c->signal_dbm);

            /* Channel: dim */
            tui_dim(); TPRINT("  %3d", c->channel);

            /* Age: colored by recency */
            phos_age(c->last_seen);
            TPRINT("  %5s", age);

            /* Frame count: heat gradient (50 frames = max heat) */
            double frac = (c->frame_count > 0)
                ? (c->frame_count < 50 ? c->frame_count / 50.0 : 1.0)
                : 0.0;
            tui_heat(frac);
            TPRINT("  %5d", c->frame_count);

            /* SSID: bright for named targets, dim for wildcards */
            if (c->ssid[0]) tui_bright(); else tui_dim();
            TPRINT("  %.32s\n", ssid);

            tui_normal();
        }
    }
    tui_normal();
}

/* ── Key handler ─────────────────────────────────────────── */

void view_probe_key(ntop_state_t *s, int key) {
    switch (key) {
    case NTOP_KEY_UP:
        if (s->probe_sel > 0) s->probe_sel--;
        break;
    case NTOP_KEY_DOWN:
        if (s->probe_count > 0 && s->probe_sel < s->probe_count - 1)
            s->probe_sel++;
        break;
    case 'c': case 'C':
        probe_clear();
        s->probe_count = 0;
        s->probe_sel   = 0;
        break;
    default:
        break;
    }
}
