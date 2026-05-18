#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/dashboard.h"
#include "bandwidth.h"

/* Compact byte-count formatter — kept local so we don't share helpers
 * across view files. */
static void fmt_bytes(uint64_t b, char *buf, int sz) {
    if      (b >= (uint64_t)1 << 30)
        snprintf(buf, sz, "%.1fGB", (double)b / (double)((uint64_t)1 << 30));
    else if (b >= (uint64_t)1 << 20)
        snprintf(buf, sz, "%.1fMB", (double)b / (double)((uint64_t)1 << 20));
    else if (b >= (uint64_t)1 << 10)
        snprintf(buf, sz, "%.1fKB", (double)b / (double)((uint64_t)1 << 10));
    else
        snprintf(buf, sz, "%lluB",  (unsigned long long)b);
}

static const char *proto_short(int p) {
    if (p == PROTO_TCP) return "TCP";
    if (p == PROTO_UDP) return "UDP";
    return "?";
}

#ifdef WITH_NCURSES

#define DASH_TOP_Y     2        /* below tabbar + hline */
#define IFACE_BAND_H   7        /* title + header + 4 ifaces + spacer */
#define BOTTOM_BAND_H 10        /* title + header + 7 rows + spacer */
#define MIN_BOTTOM_H   6

/* Position then print a single line clipped + padded to `w` chars.
 * Cursor attributes (color) must be set before the call. */
static void clipline(int y, int x, int w, const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    int n = (int)strlen(buf);
    if (n > w) n = w;
    move(y, x);
    addnstr(buf, n);
    for (int i = n; i < w; i++) addch(' ');
}

static void panel_title(int y, int x, int w, const char *name) {
    attrset(COLOR_PAIR(CP_DIM));
    move(y, x);
    int len = (int)strlen(name);
    /* leading "── " (3) + " name " + trailing dashes filling width */
    int leading = 3;
    int label   = 2 + len;        /* "name " (no leading space inside) */
    int filled  = 0;
    for (int i = 0; i < leading && filled < w; i++, filled++) addch('-');
    if (filled < w) { addch(' '); filled++; }
    for (int i = 0; i < len && filled < w; i++, filled++) addch(name[i]);
    if (filled < w) { addch(' '); filled++; }
    for (; filled < w; filled++) addch('-');
    (void)label;
}

/* ── Interfaces row ──────────────────────────────────────── */

static void draw_iface_band(const sloth_state_t *s, int y0, int h, int w) {
    panel_title(y0, 0, w, "Interfaces");

    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, 0, w, "  %-12s  %12s  %12s  %14s  %14s",
             "iface", "rx/s", "tx/s", "rx total", "tx total");

    int rows = h - 2;
    int n    = s->iface_count < rows ? s->iface_count : rows;
    for (int i = 0; i < n; i++) {
        const iface_stat_t *I = &s->ifaces[i];
        char rxr[16], txr[16], rxt[16], txt[16];
        bw_fmt_rate(I->rx_rate, rxr, sizeof(rxr));
        bw_fmt_rate(I->tx_rate, txr, sizeof(txr));
        fmt_bytes(I->rx_bytes, rxt, sizeof(rxt));
        fmt_bytes(I->tx_bytes, txt, sizeof(txt));

        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, 0, w,
                 "  %-12.12s  %12s  %12s  %14s  %14s",
                 I->name, rxr, txr, rxt, txt);
    }
}

/* ── Connections (scrollable) ────────────────────────────── */

static void draw_conn_band(const sloth_state_t *s, int y0, int h, int w) {
    panel_title(y0, 0, w, "Connections");

    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, 0, w, "  %-21s -> %-25s %-5s %5s %5s  %s",
             "Local", "Remote", "Proto", "St", "PID", "Process");

    int rows = h - 2;
    if (rows < 1) return;

    int n = s->conn_count;
    int top = s->conn_sel - rows / 2;
    if (top + rows > n) top = n - rows;
    if (top < 0)        top = 0;
    int end = top + rows;
    if (end > n)        end = n;

    for (int i = top; i < end; i++) {
        const conn_t *c = &s->conns[i];
        char local[64], remote[64];
        snprintf(local,  sizeof(local),  "%s:%u",
                 c->local_addr,  (unsigned)c->local_port);
        snprintf(remote, sizeof(remote), "%s:%u",
                 c->remote_addr, (unsigned)c->remote_port);

        if (i == s->conn_sel)
            attrset(A_REVERSE | COLOR_PAIR(CP_BRIGHT));
        else
            attrset(COLOR_PAIR(CP_NORMAL));

        clipline(y0 + 2 + (i - top), 0, w,
                 "  %-21.21s -> %-25.25s %-5s %5d %5d  %.16s",
                 local, remote, proto_short(c->proto),
                 c->state, c->pid, c->proc);
    }
}

/* ── Bottom 3 panels ─────────────────────────────────────── */

static void draw_wifi_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "WiFi APs");
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, x, w, "  %-18s %4s %3s", "SSID", "sig", "ch");

    int rows = h - 2;
    int n = s->ap_count < rows ? s->ap_count : rows;
    for (int i = 0; i < n; i++) {
        const wifi_ap_t *a = &s->aps[i];
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w,
                 "  %-18.18s %4d %3d",
                 a->ssid[0] ? a->ssid : "(hidden)",
                 a->signal_dbm, a->channel);
    }
    /* clear unused rows so the next redraw doesn't show stale content */
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}

static void draw_probe_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "Probe clients");
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, x, w, "  %-17s %-12s %4s",
             "MAC", "SSID", "sig");

    int rows = h - 2;
    int n = s->probe_count < rows ? s->probe_count : rows;
    for (int i = 0; i < n; i++) {
        const probe_client_t *p = &s->probe_clients[i];
        char mac[20];
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 p->mac[0], p->mac[1], p->mac[2],
                 p->mac[3], p->mac[4], p->mac[5]);
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w,
                 "  %-17s %-12.12s %4d",
                 mac, p->ssid[0] ? p->ssid : "(any)",
                 p->signal_dbm);
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}

static void draw_beacon_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "Beacons");
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, x, w, "  %-18s %4s %3s",
             "SSID", "sig", "ch");

    int rows = h - 2;
    int n = s->beacon_count < rows ? s->beacon_count : rows;
    for (int i = 0; i < n; i++) {
        const beacon_ap_t *b = &s->beacon_aps[i];
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w,
                 "  %-18.18s %4d %3d",
                 b->ssid[0] ? b->ssid : "(hidden)",
                 b->signal_dbm, b->channel);
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}

#endif /* WITH_NCURSES */

/* ── Public draw / key ───────────────────────────────────── */

void view_dashboard_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int lines = LINES;
    int cols  = COLS;
    if (lines < DASH_TOP_Y + IFACE_BAND_H + MIN_BOTTOM_H + 2 || cols < 80) {
        tui_dim();
        TPRINT(" Dashboard: terminal too small (need >=80 cols, >=24 rows)\n");
        tui_normal();
        return;
    }

    int iface_y = DASH_TOP_Y;
    int iface_h = IFACE_BAND_H;

    /* Reserve a bottom band, shrinking if the terminal is short. */
    int bottom_h = BOTTOM_BAND_H;
    int avail = lines - iface_y - iface_h;
    if (avail < bottom_h + 3) bottom_h = avail - 3;
    if (bottom_h < MIN_BOTTOM_H) bottom_h = MIN_BOTTOM_H;
    int bottom_y = lines - bottom_h;

    int conn_y = iface_y + iface_h;
    int conn_h = bottom_y - conn_y;

    draw_iface_band(s, iface_y, iface_h, cols);
    draw_conn_band (s, conn_y,  conn_h,  cols);

    int pw = cols / 3;
    draw_wifi_panel  (s, bottom_y, bottom_h, 0,          pw);
    draw_probe_panel (s, bottom_y, bottom_h, pw,         pw);
    draw_beacon_panel(s, bottom_y, bottom_h, pw * 2,     cols - pw * 2);

    attrset(COLOR_PAIR(CP_NORMAL));
#else
    /* ANSI fallback: stacked sections, no tiling. */
    tui_normal(); TPRINT(" Dashboard ");
    tui_dim();    TPRINT("(stacked layout - ncurses build tiles into 3 rows)\n\n");

    tui_dim();    TPRINT(" -- Interfaces --\n");
    tui_normal();
    for (int i = 0; i < s->iface_count && i < 4; i++) {
        const iface_stat_t *I = &s->ifaces[i];
        char rxr[16], txr[16], rxt[16], txt[16];
        bw_fmt_rate(I->rx_rate, rxr, sizeof(rxr));
        bw_fmt_rate(I->tx_rate, txr, sizeof(txr));
        fmt_bytes(I->rx_bytes, rxt, sizeof(rxt));
        fmt_bytes(I->tx_bytes, txt, sizeof(txt));
        TPRINT("  %-12s  rx/s=%-10s  tx/s=%-10s  rx=%-10s  tx=%s\n",
               I->name, rxr, txr, rxt, txt);
    }

    tui_dim();    TPRINT("\n -- Connections --\n");
    tui_normal();
    int cn = s->conn_count < 8 ? s->conn_count : 8;
    for (int i = 0; i < cn; i++) {
        const conn_t *c = &s->conns[i];
        TPRINT("  %s:%u -> %s:%u  %s pid=%d %s\n",
               c->local_addr,  (unsigned)c->local_port,
               c->remote_addr, (unsigned)c->remote_port,
               proto_short(c->proto), c->pid, c->proc);
    }

    tui_dim();    TPRINT("\n -- WiFi APs --\n");
    tui_normal();
    for (int i = 0; i < s->ap_count && i < 4; i++) {
        const wifi_ap_t *a = &s->aps[i];
        TPRINT("  %-20s sig=%d ch=%d\n",
               a->ssid[0] ? a->ssid : "(hidden)", a->signal_dbm, a->channel);
    }

    tui_dim();    TPRINT("\n -- Probe clients --\n");
    tui_normal();
    for (int i = 0; i < s->probe_count && i < 4; i++) {
        const probe_client_t *p = &s->probe_clients[i];
        TPRINT("  %02x:%02x:%02x:%02x:%02x:%02x  %s  sig=%d\n",
               p->mac[0], p->mac[1], p->mac[2],
               p->mac[3], p->mac[4], p->mac[5],
               p->ssid[0] ? p->ssid : "(any)", p->signal_dbm);
    }

    tui_dim();    TPRINT("\n -- Beacons --\n");
    tui_normal();
    for (int i = 0; i < s->beacon_count && i < 4; i++) {
        const beacon_ap_t *b = &s->beacon_aps[i];
        TPRINT("  %-20s sig=%d ch=%d\n",
               b->ssid[0] ? b->ssid : "(hidden)", b->signal_dbm, b->channel);
    }
#endif
}

void view_dashboard_key(sloth_state_t *s, int key) {
    /* Up/Down scroll the connections panel. */
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->conn_sel > 0) s->conn_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->conn_count > 0 && s->conn_sel < s->conn_count - 1)
            s->conn_sel++;
        break;
    default:
        break;
    }
}
