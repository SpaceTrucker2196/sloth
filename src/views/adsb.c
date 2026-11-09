#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "sloth_clock.h"
#include "tui.h"
#include "views/view_page.h"
#include "../adsb.h"
#include "gps.h"
#include "views/adsb.h"

/* [^] ADS-B — 2026-11-07 (docs/views/adsb.md, docs/wiki/adsb.md).
 *
 * The aircraft a local, already-running decoder (readsb, dump1090-fa)
 * lists in its aircraft.json, which --adsb tails: one row per address,
 * freshest first. Observation only — sloth never opens, tunes or talks
 * to the SDR, and this source uses no network (MISSION §2). The
 * emergency-squawk detector that will read this table is a following
 * slice; nothing here is a finding.
 *
 * Distance and bearing are the sensor's own, so they exist only when
 * the sensor knows where it is: gps_location_current() returning a
 * stamp (a --gps fix, or a fixed --location). Without one the two
 * columns are absent rather than drawn empty — a column of dashes
 * spends width to say nothing, and the legend says why instead. */

static int adsb_cols(void) {
#ifdef WITH_NCURSES
    return COLS > 0 ? COLS : 100;
#else
    return 100;
#endif
}

#define ADSB_PAGE 30
#define ADSB_LEGEND_ROWS 1

/* A row the decoder still lists but has not heard from for this long is
 * dim: half of ADSB_EXPIRE_S, so the operator sees a contact fading out
 * of the table before it is retired. */
#define ADSB_DIM_S 30

/* The RSSI span the signal bar covers, dBFS. readsb reports a negative
 * figure; a strong aircraft overhead is around -3 and the weakest the
 * decoder will accept around -30. */
#define ADSB_RSSI_FLOOR (-30.0)

/* The aircraft's identity as one non-zero int, so s->adsb_sel_key 0 is
 * "none": the 24-bit address with the non-ICAO flag above it (the two
 * key spaces are separate, per src/adsb.h). */
static int adsb_row_key(const adsb_aircraft_t *a) {
    unsigned k = (a->icao & 0xffffffu) | (a->non_icao ? 0x1000000u : 0u);
    return (int)k + 1;
}

/* Freshest first, by the decoder's own last-heard time; ties by address
 * so the order is stable across passes. Deliberately NOT by distance:
 * the row order then changed the moment a sensor position arrived, and
 * the only thing a fix should change is which columns are drawn. */
static int by_recent(const void *a, const void *b) {
    const adsb_aircraft_t *x = *(const adsb_aircraft_t *const *)a;
    const adsb_aircraft_t *y = *(const adsb_aircraft_t *const *)b;
    if (x->last_seen != y->last_seen)
        return x->last_seen < y->last_seen ? 1 : -1;
    if (x->non_icao != y->non_icao) return (int)x->non_icao - (int)y->non_icao;
    return x->icao < y->icao ? -1 : x->icao > y->icao ? 1 : 0;
}

static int sorted(const sloth_state_t *s, const adsb_aircraft_t **idx) {
    int n = 0;
    if (!s->adsb_rows) return 0;
    for (int i = 0; i < s->adsb_count && i < ADSB_MAX_AIRCRAFT; i++)
        idx[n++] = &s->adsb_rows[i];
    if (n > 1) qsort(idx, (size_t)n, sizeof(idx[0]), by_recent);
    return n;
}

/* The cursor's row: the selected aircraft's, wherever this pass's sort
 * put it (the table is re-sorted every poll, and an aircraft heard again
 * jumps to the top); the index only when that aircraft has left the
 * table. -1 for an empty table. */
static int cursor_row(const sloth_state_t *s, const adsb_aircraft_t **idx, int n) {
    if (n <= 0) return -1;
    if (s->adsb_sel_key)
        for (int i = 0; i < n; i++)
            if (adsb_row_key(idx[i]) == s->adsb_sel_key) return i;
    int sel = s->adsb_sel;
    return sel >= n ? n - 1 : sel < 0 ? 0 : sel;
}

static long row_age(const adsb_aircraft_t *a, time_t now) {
    long age = (long)(now - a->last_seen);
    if (age < 0) age = 0;
    if (age > 999) age = 999;
    return age;
}

/* feet, or "ground"; barometric where the aircraft sends it, geometric
 * where it sends only that (the doc's column note says so). */
static void fmt_alt(const adsb_aircraft_t *a, char *out, size_t n) {
    if (a->on_ground)         snprintf(out, n, "ground");
    else if (a->has_alt_baro) snprintf(out, n, "%d", (int)a->alt_baro);
    else if (a->has_alt_geom) snprintf(out, n, "%d", (int)a->alt_geom);
    else                      snprintf(out, n, "-");
}

static void header(const sloth_state_t *s, const loc_stamp_t *loc, int have_loc,
                   int emerg) {
    const adsb_health_t *h = &s->adsb;
    tui_normal(); TPRINT(" ADS-B: ");
    if (h->state == ADSB_LIVE) tui_bright(); else tui_heat(0.5);
    TPRINT("%s", adsb_state_name(h->state));
    tui_normal();
    TPRINT("  aircraft ");
    tui_bright(); TPRINT("%d", h->aircraft);
    tui_normal();
    if (emerg > 0) {
        /* The decoder's own emergency/priority field, counted rather
         * than graded: the rule that judges it is a later slice. */
        TPRINT("  emerg ");
        tui_heat(1.0); TPRINT("%d", emerg); tui_normal();
    }
    TPRINT("  msgs %llu", (unsigned long long)h->messages);
    TPRINT("  age ");
    if (h->age_s >= 0) TPRINT("%ds", h->age_s);
    else               TPRINT("-");
    tui_dim();
    TPRINT("  src %s  [up/dn]\n", h->src);
    /* An sbs:// source counts MSG lines, a beast:// one Mode S frames
     * taken into the table, not documents. */
    TPRINT(" %s %llu  read err %llu  parse err %llu  overflow %llu"
           "  bad %llu  expired %llu\n",
           strncmp(h->src, "sbs:", 4) == 0 ? "lines" :
           strncmp(h->src, "beast:", 6) == 0 ? "frames" : "docs",
           (unsigned long long)h->reads, (unsigned long long)h->read_errors,
           (unsigned long long)h->parse_errors, (unsigned long long)h->overflow,
           (unsigned long long)h->bad_entries, (unsigned long long)h->expired);
    if (h->err[0]) TPRINT(" err %.80s\n", h->err);
    if (have_loc) {
        char la[32], lo[32];
        gps_fmt_fixed(la, sizeof(la), loc->lat, 5);
        gps_fmt_fixed(lo, sizeof(lo), loc->lon, 5);
        TPRINT(" sensor at %s, %s (%s)\n", la, lo, gps_loc_src_name(loc->src));
    }
    tui_normal();
}

void view_adsb_draw(const sloth_state_t *s) {
    if (!s->adsb.configured) {
        tui_normal(); TPRINT(" ADS-B: "); tui_dim();
        TPRINT("no decoder\n"
               "  (start with --adsb /run/readsb/aircraft.json or\n"
               "   --adsb sbs://127.0.0.1:30003 or beast://127.0.0.1:30005;\n"
               "   see docs/wiki/adsb.md.\n"
               "   sloth never opens or tunes the SDR: a local readsb or\n"
               "   dump1090-fa does, and sloth only reads the aircraft.json\n"
               "   it already writes, or its SBS or Beast output.)\n");
        tui_normal();
        return;
    }
    time_t now = sloth_wall();
    loc_stamp_t loc;
    int have_loc = gps_location_current(&loc, now) != LOC_SRC_NONE;

    const adsb_aircraft_t *idx[ADSB_MAX_AIRCRAFT];
    int n = sorted(s, idx);
    int emerg = 0;
    for (int i = 0; i < n; i++)
        if (idx[i]->emergency > ADSB_EMERG_NONE) emerg++;

    header(s, &loc, have_loc, emerg);

    if (n == 0) {
        tui_dim();
        int sbs = strncmp(s->adsb.src, "sbs:", 4) == 0;
        int beast = strncmp(s->adsb.src, "beast:", 6) == 0;
        if (s->adsb.state == ADSB_WAITING && beast)
            TPRINT("  (waiting for the decoder's first Beast frame - connected\n"
                   "   or connecting; an empty sky sends only a heartbeat)\n");
        else if (s->adsb.state == ADSB_STALE && beast)
            TPRINT("  (the decoder has sent no frame, not even its heartbeat,\n"
                   "   for over %d s: connected, but nothing is arriving)\n",
                   ADSB_SBS_STALE_S);
        else if (s->adsb.state == ADSB_WAITING && sbs)
            TPRINT("  (waiting for the decoder's first SBS line - connected\n"
                   "   or connecting; an empty sky sends only a heartbeat)\n");
        else if (s->adsb.state == ADSB_WAITING)
            TPRINT("  (waiting for the decoder's first document - it writes\n"
                   "   aircraft.json about once a second once it is running)\n");
        else if (s->adsb.state == ADSB_STALE && sbs)
            TPRINT("  (the decoder has sent no line, not even its heartbeat,\n"
                   "   for over %d s: connected, but nothing is arriving)\n",
                   ADSB_SBS_STALE_S);
        else if (s->adsb.state == ADSB_ERROR)
            TPRINT("  (the last read failed, so the table stands as it was:\n"
                   "   nothing yet. A decoder starting after sloth is normal.)\n");
        else if (s->adsb.state == ADSB_STALE)
            TPRINT("  (the decoder's clock has stopped advancing: the file is\n"
                   "   readable but nothing is writing it, so no row is taken)\n");
        else
            TPRINT("  (the decoder lists no aircraft: nothing in range)\n");
        tui_normal();
        return;
    }

    /* Fixed cells, then the bar flexes to the width. Every data column
     * is bounded by its field (6 hex digits, an 8-character callsign,
     * 4 octal squawk digits), so the bar is what width is spent on. */
    int cols = adsb_cols();
    int fixed = 1 + 7 + 2 + 8 + 2 + 4 + 2 + 6 + 2 + 5 + 2 + 4 + 2
                  + 6 + 2 + 4 + 2;
    if (have_loc) fixed += 7 + 2 + 3 + 2;
    int bar = cols - 1 - fixed;
    if (bar < 10) bar = 10;
    if (bar > 40) bar = 40;

    tui_clip_rows(1);
    tui_dim();
    TPRINT(" %-7s  %-8s  %4s  %6s  %5s  %4s  %s%6s  %4s  %s\n",
           "ICAO", "FLIGHT", "SQWK", "ALT", "GS", "TRK",
           have_loc ? "   DIST  BRG  " : "", "RSSI", "AGE", "SIGNAL");
    tui_normal();

    int page = view_page_budget(ADSB_LEGEND_ROWS, ADSB_PAGE);
    int sel = cursor_row(s, idx, n);
    int top = sel - page / 2;
    if (top + page > n) top = n - page;
    if (top < 0) top = 0;
    int end = top + page;
    if (end > n) end = n;

    for (int i = top; i < end; i++) {
        const adsb_aircraft_t *a = idx[i];
        char hex[12], alt[12], gs[12], trk[12], rssi[12], age[12], db[48] = "";
        snprintf(hex, sizeof(hex), "%s%06x", a->non_icao ? "~" : "",
                 (unsigned)(a->icao & 0xffffffu));
        fmt_alt(a, alt, sizeof(alt));
        if (a->has_gs)    snprintf(gs, sizeof(gs), "%d", (int)(a->gs + 0.5));
        else              snprintf(gs, sizeof(gs), "-");
        if (a->has_track) snprintf(trk, sizeof(trk), "%d", (int)(a->track + 0.5));
        else              snprintf(trk, sizeof(trk), "-");
        if (a->has_rssi)  gps_fmt_fixed(rssi, sizeof(rssi), a->rssi, 1);
        else              snprintf(rssi, sizeof(rssi), "-");
        snprintf(age, sizeof(age), "%lds", row_age(a, now));
        if (have_loc) {
            /* The row's own position is what may be missing here: the
             * columns exist because the SENSOR's position is known. */
            char d[24], br[16];
            if (a->has_pos) {
                gps_fmt_fixed(d, sizeof(d),
                              gps_distance_m(loc.lat, loc.lon, a->lat, a->lon)
                              / 1000.0, 1);
                int bi = (int)(gps_bearing_deg(loc.lat, loc.lon,
                                               a->lat, a->lon) + 0.5);
                if (bi >= 360) bi = 0;
                snprintf(br, sizeof(br), "%03d", bi);
            } else {
                snprintf(d, sizeof(d), "-");
                snprintf(br, sizeof(br), "-");
            }
            snprintf(db, sizeof(db), "%7s  %3s  ", d, br);
        }
        long age_s = row_age(a, now);
        if (i == sel)              tui_sel();
        else if (age_s >= ADSB_DIM_S) tui_dim();
        else                       tui_normal();
        TPRINT("%c%-7s  %-8s  %4s  %6s  %5s  %4s  %s%6s  %4s  ",
               i == sel ? '>' : ' ', hex,
               a->flight[0] ? a->flight : "-",
               a->squawk[0] ? a->squawk : "-",
               alt, gs, trk, db, rssi, age);
        /* The bar: RSSI over the -30..0 dBFS span, heat-graded as the
         * sparklines are (tui_heat: cool phosphor to peak red). */
        double frac = a->has_rssi
                      ? (a->rssi - ADSB_RSSI_FLOOR) / -ADSB_RSSI_FLOOR : 0.0;
        if (frac < 0) frac = 0;
        if (frac > 1) frac = 1;
        int len = (int)(frac * bar);
        if (i != sel) tui_heat(a->has_rssi ? frac : 0.0);
        for (int j = 0; j < len; j++) TPRINT("|");
        tui_normal();
        TPRINT("\n");
    }
    tui_dim();
    TPRINT(" dim: not heard for %ds or more  SIGNAL: RSSI over %d..0 dBFS"
           "  ALT ft  GS kt  TRK deg%s%s\n",
           ADSB_DIM_S, (int)ADSB_RSSI_FLOOR,
           have_loc ? "  DIST km BRG deg true from the sensor"
                    : "  (no sensor position: --location or --gps adds "
                      "range and direction)",
           s->adsb.overflow ? "  (more aircraft than the table holds)" : "");
    tui_normal();
}

void view_adsb_key(sloth_state_t *s, int key) {
    const adsb_aircraft_t *idx[ADSB_MAX_AIRCRAFT];
    int n = sorted(s, idx);
    /* Move from where the cursor is drawn (the selected aircraft's row
     * after this pass's sort), and remember the aircraft landed on. */
    int sel = cursor_row(s, idx, n);
    switch (key) {
    case SLOTH_KEY_UP:
        if (sel > 0) sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (n > 0 && sel < n - 1) sel++;
        break;
    default:
        return;
    }
    if (sel >= 0 && sel < n) {
        s->adsb_sel = sel;
        s->adsb_sel_key = adsb_row_key(idx[sel]);
    } else if (n == 0) {
        s->adsb_sel = 0;
    }
}
