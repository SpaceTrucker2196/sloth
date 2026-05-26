/* Dashboard primitives: format helpers used by both ncurses and ANSI
 * builds, plus the ncurses drawing primitives (sparklines, clipline,
 * panel_title) used by every per-panel renderer. */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "sloth.h"
#include "tui.h"
#include "views/dashboard.h"
#include "views/dashboard_internal.h"

void fmt_bytes(uint64_t b, char *buf, int sz) {
    if      (b >= (uint64_t)1 << 30)
        snprintf(buf, sz, "%.1fGB", (double)b / (double)((uint64_t)1 << 30));
    else if (b >= (uint64_t)1 << 20)
        snprintf(buf, sz, "%.1fMB", (double)b / (double)((uint64_t)1 << 20));
    else if (b >= (uint64_t)1 << 10)
        snprintf(buf, sz, "%.1fKB", (double)b / (double)((uint64_t)1 << 10));
    else
        snprintf(buf, sz, "%lluB",  (unsigned long long)b);
}

const char *proto_short(int p) {
    if (p == PROTO_TCP) return "TCP";
    if (p == PROTO_UDP) return "UDP";
    return "?";
}

/* DHCP message-type name (RFC 2132 §9.6). */
const char *dhcp_msg_name(uint8_t t) {
    switch (t) {
    case 1: return "DISCOVER";
    case 2: return "OFFER";
    case 3: return "REQUEST";
    case 4: return "DECLINE";
    case 5: return "ACK";
    case 6: return "NAK";
    case 7: return "RELEASE";
    case 8: return "INFORM";
    default: return "?";
    }
}

/* Find the rate-history record for an iface by name. */
const iface_hist_t *hist_lookup(const sloth_state_t *s, const char *name) {
    for (int i = 0; i < MAX_IFACES; i++) {
        if (s->iface_hist[i].name[0] &&
            strcmp(s->iface_hist[i].name, name) == 0)
            return &s->iface_hist[i];
    }
    return NULL;
}

#ifdef WITH_NCURSES

/* Internal: panel title with optional right-edge "P" marker for panels
 * whose data is gathered by passive RF sniffing. Kept static — only
 * panel_title / panel_title_passive (below) call it. */
static void panel_title_ex(int y, int x, int w, const char *name,
                            int panel_id, int passive);

void draw_sparkline_at(int y, int x, int width,
                              const double *vals, int head, int n) {
    double max = 0.0;
    for (int i = 0; i < n && i < HIST_LEN; i++)
        if (vals[i] > max) max = vals[i];

    static const char *glyph[9] = {
        "_",
        "\xe2\x96\x81", "\xe2\x96\x82", "\xe2\x96\x83",
        "\xe2\x96\x84", "\xe2\x96\x85", "\xe2\x96\x86",
        "\xe2\x96\x87", "\xe2\x96\x88",
    };

    move(y, x);
    for (int i = 0; i < width; i++) {
        int lvl = 0;
        if (n > 0) {
            /* Stretch n samples across width screen columns. */
            int age;
            if (width <= 1) age = 0;
            else            age = ((width - 1 - i) * (n - 1)) / (width - 1);
            if (age < 0)   age = 0;
            if (age >= n)  age = n - 1;
            int slot = (head - 1 - age + HIST_LEN) % HIST_LEN;
            double v = vals[slot];
            if (v > 0.0 && max > 0.0) {
                lvl = (int)((v / max) * 8.0 + 0.5);
                if (lvl < 1) lvl = 1;
                if (lvl > 8) lvl = 8;
            }
        }
        if      (lvl == 0)  attrset(COLOR_PAIR(CP_DIM));
        else if (lvl <= 2)  attrset(COLOR_PAIR(CP_NORMAL));
        else if (lvl <= 4)  attrset(COLOR_PAIR(CP_HEAT_MID));
        else if (lvl <= 6)  attrset(COLOR_PAIR(CP_HEAT_HI));
        else                attrset(COLOR_PAIR(CP_HEAT_PEAK));
        addstr(glyph[lvl]);
    }
}

/* Solid-colour sparkline for per-connection bw history. Single colour for
 * every non-zero glyph; zero / missing samples render as a dim '_'.
 * Operates on float arrays (the conn_bw_t hist) instead of doubles. */
void draw_sparkline_solid_at(int y, int x, int width,
                                     const float *vals, int head, int n,
                                     int color_pair) {
    double max = 0.0;
    for (int i = 0; i < n && i < CONN_BW_HIST; i++)
        if ((double)vals[i] > max) max = (double)vals[i];

    static const char *glyph[9] = {
        "_",
        "\xe2\x96\x81", "\xe2\x96\x82", "\xe2\x96\x83",
        "\xe2\x96\x84", "\xe2\x96\x85", "\xe2\x96\x86",
        "\xe2\x96\x87", "\xe2\x96\x88",
    };
    move(y, x);
    for (int i = 0; i < width; i++) {
        int lvl = 0;
        if (n > 0) {
            int age;
            if (width <= 1) age = 0;
            else            age = ((width - 1 - i) * (n - 1)) / (width - 1);
            if (age < 0)   age = 0;
            if (age >= n)  age = n - 1;
            int slot = (head - 1 - age + CONN_BW_HIST) % CONN_BW_HIST;
            double v = (double)vals[slot];
            if (v > 0.0 && max > 0.0) {
                lvl = (int)((v / max) * 8.0 + 0.5);
                if (lvl < 1) lvl = 1;
                if (lvl > 8) lvl = 8;
            }
        }
        if (lvl == 0) attrset(COLOR_PAIR(CP_DIM));
        else          attrset(COLOR_PAIR(color_pair));
        addstr(glyph[lvl]);
    }
}

/* Position then print one line, padded to `w` chars. ASCII / single-byte. */
void clipline(int y, int x, int w, const char *fmt, ...) {
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

/* Internal: panel title with optional right-edge "P" marker for panels
 * whose data is gathered by passive RF sniffing (monitor-mode probes,
 * beacons, deauth). The marker is a small dim "P" before the trailing
 * horizontals so the eye reads it as a chip on the frame. */
static void panel_title_ex(int y, int x, int w, const char *name,
                            int panel_id, int passive) {
    int focused = (panel_id == g_dash_focus);
    /* Reserve "─ P ─" (5 cols) at the right edge when passive. */
    int reserve = passive ? 5 : 0;
    attrset(COLOR_PAIR(CP_DIM));
    move(y, x);
    int filled = 0;
    int len = (int)strlen(name);
    if (filled + 2 <= w) { addstr(G_HORIZ); addstr(G_HORIZ); filled += 2; }
    if (filled     <  w) { addch(' '); filled++; }
    /* Title text — bright + bold for extra pop; inverted if focused. */
    attr_t name_attr = COLOR_PAIR(CP_BRIGHT) | A_BOLD;
    if (focused) name_attr |= A_REVERSE;
    attrset(name_attr);
    for (int i = 0; i < len && filled < w - reserve; i++, filled++)
        addch((chtype)(unsigned char)name[i]);
    attrset(COLOR_PAIR(CP_DIM));
    if (filled < w - reserve) { addch(' '); filled++; }
    while (filled < w - reserve) { addstr(G_HORIZ); filled++; }
    if (passive && filled + reserve <= w) {
        /* "─ P ─" at the right edge, P in dim. */
        addstr(G_HORIZ); filled++;
        addch(' ');      filled++;
        addch('P');      filled++;
        addch(' ');      filled++;
        addstr(G_HORIZ); filled++;
    }
}

void panel_title(int y, int x, int w, const char *name, int panel_id) {
    panel_title_ex(y, x, w, name, panel_id, 0);
}

void panel_title_passive(int y, int x, int w, const char *name, int panel_id) {
    panel_title_ex(y, x, w, name, panel_id, 1);
}

#endif /* WITH_NCURSES */
