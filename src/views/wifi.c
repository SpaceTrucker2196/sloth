#include <stdio.h>
#include <string.h>
#include "sloth.h"
#include "tui.h"
#include "oui.h"
#include "util.h"
#include "views/wifi.h"

#define WIFI_PAGE 20

/* Phosphor intensity based on signal strength. */
static void phos_signal(int dbm) {
    if      (dbm > -50) tui_bright();
    else if (dbm > -70) tui_normal();
    else                tui_dim();
}

/* Print a signal bar with left→right phosphor gradient.
   Filled portion grades dim→normal→bright; empty dots are dim. */
static void print_signal_bar_phosphor(int dbm, int width) {
    double pct    = (dbm < -90) ? 0.0 : (dbm > -30) ? 1.0 : (dbm + 90.0) / 60.0;
    int    filled = (int)(pct * width);
    for (int i = 0; i < width; i++) {
        if (i < filled) {
            double pos = (double)i / width;
            if      (pos < 0.33) tui_dim();
            else if (pos < 0.66) tui_normal();
            else                 tui_bright();
            TPRINT("\xe2\x96\x88");   /* █ */
        } else {
            tui_dim(); TPRINT("\xe2\x96\x91");  /* ░ */
        }
    }
}

/* Format link rate (kbps) → human-readable string. */
static void fmt_link_rate(uint32_t kbps, char *buf, int len) {
    if (kbps == 0)         snprintf(buf, (size_t)len, "--");
    else if (kbps >= 1000) snprintf(buf, (size_t)len, "%.1f Mbps", kbps / 1000.0);
    else                   snprintf(buf, (size_t)len, "%u kbps", kbps);
}

/* Format connected time in seconds → "Xh Ym" / "Xm Ys" / "Xs". */
static void fmt_connected(uint32_t secs, char *buf, int len) {
    int h = (int)(secs / 3600);
    int m = (int)((secs % 3600) / 60);
    int s = (int)(secs % 60);
    if (h > 0)      snprintf(buf, (size_t)len, "%dh %02dm", h, m);
    else if (m > 0) snprintf(buf, (size_t)len, "%dm %02ds", m, s);
    else            snprintf(buf, (size_t)len, "%ds", s);
}

/* Find the first station whose MAC matches ap->bssid. */
static const wifi_sta_t *find_sta(const sloth_state_t *s, const wifi_ap_t *ap) {
    for (int i = 0; i < s->wifi_sta_count; i++) {
        if (strcmp(s->wifi_stas[i].mac, ap->bssid) == 0)
            return &s->wifi_stas[i];
    }
    return NULL;
}

/* ── Detail panel ───────────────────────────────────────── */

static void draw_wifi_detail(const sloth_state_t *s) {
    if (s->ap_count == 0 || s->wifi_sel >= s->ap_count) {
        tui_dim(); TPRINT("  (no AP selected)\n"); tui_normal(); return;
    }

    const wifi_ap_t *ap = &s->aps[s->wifi_sel];

    /* header bar */
    tui_bright();
    TPRINT(" \xe2\x94\x80\xe2\x94\x80 %s  [Esc] back \xe2\x94\x80\xe2\x94\x80\n\n",
           ap->ssid[0] ? ap->ssid : "<hidden>");

    /* AP identity */
    tui_dim();   TPRINT("  SSID:    ");
    tui_bright(); TPRINT("%-32.32s", ap->ssid[0] ? ap->ssid : "<hidden>");
    tui_dim();   TPRINT("  BSSID: ");
    tui_normal(); TPRINT("%s\n", ap->bssid);

    tui_dim();   TPRINT("  Channel: ");
    tui_bright(); TPRINT("%-6d", ap->channel);
    tui_dim();   TPRINT("  Enc: ");
    if (strncmp(ap->enc, "Open", 4) == 0) tui_dim(); else tui_bright();
    TPRINT("%-8s", ap->enc);
    tui_dim();   TPRINT("  Signal: ");
    phos_signal(ap->signal_dbm);
    TPRINT("%d dBm\n", ap->signal_dbm);

    /* signal bar */
    tui_dim(); TPRINT("  [");
    print_signal_bar_phosphor(ap->signal_dbm, 20);
    tui_dim(); TPRINT("]\n\n");

    /* station / link info */
    const wifi_sta_t *st = find_sta(s, ap);
    if (st) {
        char tx_r[20], rx_r[20], con[20], tx_b[20], rx_b[20];
        fmt_link_rate(st->tx_rate_kbps, tx_r, (int)sizeof(tx_r));
        fmt_link_rate(st->rx_rate_kbps, rx_r, (int)sizeof(rx_r));
        fmt_connected(st->connected_secs, con, (int)sizeof(con));
        fmt_bytes(st->tx_bytes, tx_b, (int)sizeof(tx_b));
        fmt_bytes(st->rx_bytes, rx_b, (int)sizeof(rx_b));

        tui_bright(); TPRINT("  Link\n");
        tui_dim();
        TPRINT("  \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
               "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
               "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
               "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
               "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
               "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
               "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
               "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
               "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
               "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\n");

        tui_dim();    TPRINT("  TX rate: ");
        tui_bright(); TPRINT("%-18s", tx_r);
        tui_dim();    TPRINT("  RX rate: ");
        tui_bright(); TPRINT("%s\n", rx_r);

        tui_dim();    TPRINT("  Signal:  ");
        phos_signal(st->signal_dbm);
        TPRINT("%-18d", (int)st->signal_dbm);
        tui_dim();    TPRINT("  dBm\n");

        tui_dim();    TPRINT("  Connected: ");
        tui_bright(); TPRINT("%-16s", con);
        tui_dim();    TPRINT("  Inactive: ");
        tui_bright(); TPRINT("%u ms\n", st->inactive_ms);

        tui_dim();    TPRINT("  TX total: ");
        tui_bright(); TPRINT("%-17s", tx_b);
        tui_dim();    TPRINT("  RX total: ");
        tui_bright(); TPRINT("%s\n", rx_b);
    } else {
        tui_dim(); TPRINT("  (not associated — no station data)\n");
    }

    tui_normal();
}

/* ── Draw ───────────────────────────────────────────────── */

void view_wifi_draw(const sloth_state_t *s) {
#ifndef WITH_WIFI
    (void)s;
    tui_dim(); TPRINT("  WiFi scanning disabled (build with WITH_WIFI=1)\n");
    tui_normal();
    return;
#else
    if (s->wifi_detail) { draw_wifi_detail(s); return; }

#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = WIFI_PAGE;
#endif

    /* status bar */
    tui_normal(); TPRINT(" WiFi: ");
    tui_bright();  TPRINT("%d AP%s", s->ap_count, s->ap_count == 1 ? "" : "s");
#ifndef WITH_NCURSES
    if (s->ap_count > 0) { tui_dim(); TPRINT("  [up/dn] navigate  [enter] detail"); }
#endif
    TPRINT("\n");

    /* column headers */
    tui_dim();
    TPRINT(" %-32s  %-17s  %-12s  %3s  %-14s  %s\n",
           "SSID", "BSSID", "Vendor", "Ch", "Signal", "Enc");
    TPRINT(" %-32s  %-17s  %-12s  %3s  %-14s  %s\n",
           "--------------------------------", "-----------------",
           "------------", "---", "--------------", "---");
    tui_normal();

    if (s->ap_count == 0) {
        tui_dim(); TPRINT("  (scanning... may require root or CAP_NET_ADMIN)\n");
        tui_normal(); return;
    }

    int top = s->wifi_sel - page / 2;
    if (top + page > s->ap_count) top = s->ap_count - page;
    if (top < 0) top = 0;
    int end = top + page;
    if (end > s->ap_count) end = s->ap_count;

    for (int row = top; row < end; row++) {
        const wifi_ap_t *ap = &s->aps[row];

        const char *vendor = oui_lookup_str(ap->bssid);
        const char *vstr   = vendor ? vendor : "";
        /* associated marker: * for associated, space for others */
        char assoc = (ap->status == WIFI_STATUS_ASSOC) ? '*' : ' ';

        if (row == s->wifi_sel) {
            /* selected: uniform bright reverse */
            double pct    = (ap->signal_dbm < -90) ? 0.0
                          : (ap->signal_dbm > -30) ? 1.0
                          : (ap->signal_dbm + 90.0) / 60.0;
            int    filled = (int)(pct * 10);
            tui_sel();
            TPRINT("%c%-32.32s  %-17s  %-12.12s  %3d  [",
                   assoc, ap->ssid, ap->bssid, vstr, ap->channel);
            for (int i = 0; i < 10; i++)
                TPRINT(i < filled ? "\xe2\x96\x88" : "\xe2\x96\x91");
            TPRINT("]%4d  %-4s\n", ap->signal_dbm, ap->enc);
            tui_reset();
        } else {
            /* associated marker */
            if (assoc == '*') tui_bright(); else tui_dim();
            TPRINT("%c", assoc);
            /* SSID: bright — the primary field */
            tui_bright(); TPRINT("%-32.32s", ap->ssid);
            /* BSSID: dim — secondary identifier */
            tui_dim();    TPRINT("  %-17s", ap->bssid);
            /* Vendor: dim */
            tui_dim();    TPRINT("  %-12.12s", vstr);
            /* Channel: normal */
            tui_normal(); TPRINT("  %3d  [", ap->channel);
            /* Signal bar: gradient */
            print_signal_bar_phosphor(ap->signal_dbm, 10);
            /* dBm value: intensity matches signal strength */
            phos_signal(ap->signal_dbm);
            TPRINT("]%4d", ap->signal_dbm);
            /* Encryption */
            if (strncmp(ap->enc, "Open", 4) == 0) tui_dim();
            else tui_bright();
            TPRINT("  %-4s\n", ap->enc);
            tui_normal();
        }
    }
#endif /* WITH_WIFI */
}

/* ── Key handler ────────────────────────────────────────── */

void view_wifi_key(sloth_state_t *s, int key) {
    if (s->wifi_detail) {
        if (key == '\033') s->wifi_detail = 0;
        return;
    }

    switch (key) {
    case '\r': case '\n':
        if (s->ap_count > 0) s->wifi_detail = 1;
        break;
    case SLOTH_KEY_UP:
        if (s->wifi_sel > 0) s->wifi_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->ap_count > 0 && s->wifi_sel < s->ap_count - 1)
            s->wifi_sel++;
        break;
    default:
        break;
    }
}
