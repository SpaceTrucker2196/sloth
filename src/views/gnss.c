#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "sloth_clock.h"
#include "tui.h"
#include "views/view_page.h"
#include "gps.h"
#include "views/gnss.h"

/* [#] GNSS — 2026-11-02 (docs/wiki/gnss.md, docs/views/gnss.md).
 *
 * The receiver's sky as gpsd's SKY reports it, one row per satellite in
 * view, sorted by C/N0 so the strongest signals lead; the header is the
 * newest TPV (fix mode, DOPs, accuracy, speed) and the receiver's clock
 * against the host's. Observation only: no row here is a finding, and
 * the detectors that will read this sky (spoofing, jamming, time and
 * position jumps) are a following slice. Read-only on the receiver:
 * sloth sends gpsd one ?WATCH line and writes nothing to a serial
 * device (MISSION §2). The key is '#' because every letter and digit
 * already selects a view or does something global, and '*' is BLE. */

static int gnss_cols(void) {
#ifdef WITH_NCURSES
    return COLS > 0 ? COLS : 100;
#else
    return 100;
#endif
}

#define GNSS_PAGE 30
#define GNSS_LEGEND_ROWS 1

static const char *mode_name(int mode) {
    switch (mode) {
    case 1:  return "no fix";
    case 2:  return "2D";
    case 3:  return "3D";
    default: return "unknown";
    }
}

/* gpsd TPV status (gpsd_json.html). */
static const char *status_name(int st) {
    switch (st) {
    case 1: return "normal";
    case 2: return "DGPS";
    case 3: return "RTK fix";
    case 4: return "RTK float";
    case 5: return "DR";
    case 6: return "GNSS+DR";
    case 7: return "time-surveyed";
    case 8: return "simulated";
    case 9: return "P(Y)";
    default: return "-";
    }
}

static const char *health_name(int h) {
    switch (h) {
    case 1:  return "ok";
    case 2:  return "BAD";
    default: return "?";
    }
}

static void fx(char *out, size_t n, double v, int dp) {
    gps_fmt_fixed(out, n, v, dp);
}

/* The heat of a DOP: fine under 2, warm to 5, hot past it. */
static double dop_heat(double v) {
    if (v <= 0) return 0.0;
    return v < 2 ? 0.1 : v < 5 ? 0.5 : 1.0;
}

static double off_heat(long long ms) {
    long long a = ms < 0 ? -ms : ms;
    return a < 500 ? 0.1 : a < 2000 ? 0.5 : 1.0;
}

static double jam_heat(int jam) {
    return jam <= 0 ? 0.0 : jam < 64 ? 0.3 : jam < 128 ? 0.6 : 1.0;
}

/* Rows sorted by C/N0 descending, unknown last, then by PRN so a tie
 * is stable across passes. */
static int by_cn0(const void *a, const void *b) {
    const gnss_sat_t *x = *(const gnss_sat_t *const *)a;
    const gnss_sat_t *y = *(const gnss_sat_t *const *)b;
    int cx = x->has_cn0 ? x->cn0_x10 : -1, cy = y->has_cn0 ? y->cn0_x10 : -1;
    if (cx != cy) return cy - cx;
    if (x->gnssid != y->gnssid) return x->gnssid - y->gnssid;
    return x->prn - y->prn;
}

static int sorted(const gnss_sky_t *k, const gnss_sat_t **idx) {
    int n = 0;
    for (int i = 0; i < k->n && i < GNSS_MAX_SATS; i++) idx[n++] = &k->sats[i];
    if (n > 1) qsort(idx, (size_t)n, sizeof(idx[0]), by_cn0);
    return n;
}

static void kv(const char *key, const char *v) {
    tui_dim();    TPRINT("  %-16s ", key);
    tui_normal(); TPRINT("%s\n", v);
}

static void draw_detail(const sloth_state_t *s) {
    const gnss_sky_t *k = &s->gnss_sky;
    const gnss_sat_t *idx[GNSS_MAX_SATS];
    int n = sorted(k, idx);
    tui_dim(); TPRINT(" ── GNSS satellite ── "); tui_normal();
    tui_dim(); TPRINT("[Enter/Esc] back\n"); tui_normal();
    int sel = s->gnss_sel;
    if (sel < 0 || sel >= n) {
        tui_dim();
        TPRINT("  (the row has left the sky: the satellite set, or the pass "
               "that listed it is gone)\n");
        tui_normal();
        return;
    }
    const gnss_sat_t *a = idx[sel];
    char v[96], t[32];
    snprintf(v, sizeof(v), "%s (gnssid %d)", a->gnssid >= 0 ? gnss_name(a->gnssid) : "-",
             a->gnssid);
    kv("constellation", v);
    snprintf(v, sizeof(v), "%d", a->svid);           kv("svid", v);
    snprintf(v, sizeof(v), "%d", a->prn);            kv("PRN", v);
    if (a->sigid >= 0) { snprintf(v, sizeof(v), "%d", a->sigid); kv("signal id", v); }
    if (a->el >= 0) { snprintf(v, sizeof(v), "%d deg", a->el); kv("elevation", v); }
    if (a->az >= 0) { snprintf(v, sizeof(v), "%d deg true", a->az); kv("azimuth", v); }
    if (a->has_cn0) {
        fx(t, sizeof(t), a->cn0_x10 / 10.0, 1);
        snprintf(v, sizeof(v), "%s dB-Hz", t);
        kv("C/N0", v);
    } else {
        kv("C/N0", "- (not tracked)");
    }
    kv("used in solution", a->used ? "yes" : "no");
    kv("health", health_name(a->health));
    snprintf(v, sizeof(v), "%lld", (long long)k->ts);  kv("pass (unix)", v);
}

static void header(const sloth_state_t *s, time_t now) {
    const gnss_fix_t *f = &s->gnss_fix;
    const gnss_sky_t *k = &s->gnss_sky;
    char t[32], u[32];
    tui_normal(); TPRINT(" GNSS: fix ");
    if (f->valid && f->mode >= 2) tui_bright(); else tui_heat(0.5);
    TPRINT("%s", f->valid ? mode_name(f->mode) : "none");
    tui_normal(); TPRINT("  sats ");
    tui_bright(); TPRINT("%d/%d", k->usat > 0 ? k->usat : 0, k->nsat > 0 ? k->nsat : 0);
    tui_normal(); TPRINT("  HDOP ");
    fx(t, sizeof(t), k->hdop, 1);
    tui_heat(dop_heat(k->hdop)); TPRINT("%s", k->hdop > 0 ? t : "-");
    tui_normal(); TPRINT(" PDOP ");
    fx(t, sizeof(t), k->pdop, 1);
    tui_heat(dop_heat(k->pdop)); TPRINT("%s", k->pdop > 0 ? t : "-");
    tui_normal();
    if (f->valid && f->has_eph) {
        fx(t, sizeof(t), f->eph, 0);
        TPRINT("  acc ±%s m", t);
    }
    if (f->valid && f->has_speed) {
        fx(t, sizeof(t), f->speed, 1);
        TPRINT("  speed %s m/s", t);
    }
    TPRINT("  clock off ");
    if (f->valid && f->has_time_off) {
        tui_heat(off_heat(f->time_off_ms));
        TPRINT("%+lld ms", f->time_off_ms);
        tui_normal();
    } else {
        tui_dim(); TPRINT("-"); tui_normal();
    }
    tui_dim();
    TPRINT("  src %s  age %lds\n", s->gps.src,
           k->valid ? (long)(now - k->ts < 0 ? 0 : now - k->ts) : 0L);
    /* Second line: the receiver's own words about the fix. */
    TPRINT(" status %s", f->valid ? status_name(f->status) : "-");
    if (f->valid && f->leap >= 0) TPRINT("  leap %d", f->leap);
    TPRINT("  jam ");
    tui_normal();
    if (f->valid && f->jam >= 0) {
        tui_heat(jam_heat(f->jam)); TPRINT("%d", f->jam); tui_dim();
    } else {
        tui_dim(); TPRINT("-");
    }
    fx(t, sizeof(t), k->cn0_mean, 1);
    fx(u, sizeof(u), k->cn0_max, 1);
    TPRINT("  C/N0 mean %s max %s", k->cn0_n ? t : "-", k->cn0_n ? u : "-");
    if (f->valid && f->has_gst) {
        fx(t, sizeof(t), f->gst_rms, 1);
        TPRINT("  GST rms %s m", t);
    }
    TPRINT("  [up/dn] [Enter] detail\n");
    tui_normal();
}

void view_gnss_draw(const sloth_state_t *s) {
    if (!s->gps.has_gps) {
        tui_normal(); TPRINT(" GNSS: "); tui_dim();
        TPRINT("no receiver\n"
               "  (start with --gps gpsd:// or --gps /dev/ttyXXX; see docs/wiki/gnss.md.\n"
               "   Receive-only: sloth sends gpsd one ?WATCH line and writes nothing\n"
               "   to a serial device. --location alone is a setting, not a receiver.)\n");
        tui_normal();
        return;
    }
    if (s->gnss_detail) { draw_detail(s); return; }
    time_t now = sloth_wall();
    header(s, now);
    const gnss_sky_t *k = &s->gnss_sky;
    if (!k->valid || k->n == 0) {
        tui_dim();
        TPRINT("  (waiting for the receiver's first satellite list - gpsd's SKY,\n"
               "   which a serial NMEA source does not carry yet; err %s)\n",
               s->gps.err[0] ? s->gps.err : "none");
        tui_normal();
        return;
    }
    const gnss_sat_t *idx[GNSS_MAX_SATS];
    int n = sorted(k, idx);

    /* Fixed cells, then the bar flexes to the width. */
    int cols = gnss_cols();
    int fixed = 1 + 8 + 2 + 4 + 2 + 4 + 2 + 3 + 2 + 3 + 2 + 5 + 2 + 4 + 2 + 4 + 2;
    int bar = cols - 1 - fixed;
    if (bar < 10) bar = 10;
    if (bar > 50) bar = 50;

    tui_clip_rows(1);
    tui_dim();
    TPRINT(" %-8s  %4s  %4s  %3s  %3s  %5s  %4s  %4s  %s\n",
           "GNSS", "SV", "PRN", "EL", "AZ", "C/N0", "USED", "HLTH", "SIGNAL");
    tui_normal();

    int page = view_page_budget(GNSS_LEGEND_ROWS, GNSS_PAGE);
    int sel = s->gnss_sel;
    if (sel >= n) sel = n - 1;
    if (sel < 0) sel = 0;
    int top = sel - page / 2;
    if (top + page > n) top = n - page;
    if (top < 0) top = 0;
    int end = top + page;
    if (end > n) end = n;

    for (int i = top; i < end; i++) {
        const gnss_sat_t *a = idx[i];
        char cn[16], el[8], az[8], sv[8], g[12];
        if (a->has_cn0) fx(cn, sizeof(cn), a->cn0_x10 / 10.0, 1);
        else            snprintf(cn, sizeof(cn), "-");
        if (a->el >= 0) snprintf(el, sizeof(el), "%d", a->el); else snprintf(el, sizeof(el), "-");
        if (a->az >= 0) snprintf(az, sizeof(az), "%d", a->az); else snprintf(az, sizeof(az), "-");
        if (a->svid >= 0) snprintf(sv, sizeof(sv), "%d", a->svid); else snprintf(sv, sizeof(sv), "-");
        snprintf(g, sizeof(g), "%s", a->gnssid >= 0 ? gnss_name(a->gnssid) : "-");
        g[8] = '\0';
        if (i == sel) tui_sel();
        else if (a->health == 2) tui_dim();
        else if (a->used) tui_bright();
        else tui_normal();
        TPRINT("%c%-8s  %4s  %4d  %3s  %3s  %5s  %4s  %4s  ",
               i == sel ? '>' : ' ', g, sv, a->prn, el, az, cn,
               a->used ? "yes" : "-", health_name(a->health));
        /* The bar: C/N0 over a 50 dB-Hz span, heat-graded as the
         * sparklines are (tui_heat: cool phosphor to peak red). */
        int len = a->has_cn0 ? (a->cn0_x10 * bar) / 500 : 0;
        if (len > bar) len = bar;
        if (i != sel) tui_heat(a->has_cn0 ? a->cn0_x10 / 500.0 : 0.0);
        for (int j = 0; j < len; j++) TPRINT("|");
        tui_normal();
        TPRINT("\n");
    }
    tui_dim();
    TPRINT(" bright: used in the solution  dim: unhealthy  SIGNAL: C/N0 over 50 dB-Hz"
           "%s\n", k->overflow ? "  (more satellites than the table holds)" : "");
    tui_normal();
}

void view_gnss_key(sloth_state_t *s, int key) {
    if (s->gnss_detail) {
        if (key == '\r' || key == '\n' || key == 27) s->gnss_detail = 0;
        return;
    }
    int n = s->gnss_sky.valid ? s->gnss_sky.n : 0;
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->gnss_sel > 0) s->gnss_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (n > 0 && s->gnss_sel < n - 1) s->gnss_sel++;
        break;
    case '\r': case '\n':
        if (n > 0 && s->gnss_sel >= 0 && s->gnss_sel < n) s->gnss_detail = 1;
        break;
    default:
        break;
    }
}
