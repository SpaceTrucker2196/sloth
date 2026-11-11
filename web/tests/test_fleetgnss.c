/* GNSS across the owner's fleet (#192 I6, web_fleetgnss.h): the
 * classification on hand-built two- and three-site data (regional,
 * local, undetermined; the window's edges; a stale peer; a peer outside
 * the region; a class that does not match; an alert's class needing the
 * incidents offered, interference taking the receiver alone when it
 * lasted a sample's gap), coverage's edges, the samples' spans and
 * reference thinning, and the saved state's round trip and refusals. The
 * export, the pull and the route over a store and a sloth.db are
 * test_fleet.c's (test_gnss_*), beside the pull they read. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_fleetgnss.h"
#include "wtest.h"

/* W9FJC and beta-site, 16.8 m apart; gamma 60 km north. */
#define LAT_A 33.32922
#define LON_A (-111.87006)
#define LAT_B 33.32910
#define LON_B (-111.86995)
#define LAT_G 33.86922

static long long rs_a[1] = { 0 }, re_a[1] = { 5000 };
static long long rs_b[1] = { 0 }, re_b[1] = { 5000 };

static void cov_at(web_fg_cov_t *c, double lat, double lon, const long long *s,
                   const long long *e, int n, int ev) {
    memset(c, 0, sizeof(*c));
    c->has_pos = 1;
    c->lat = lat;
    c->lon = lon;
    c->nrx = n;
    c->rx_s = s;
    c->rx_e = e;
    if (ev) {
        c->nev = n;
        c->ev_s = s;
        c->ev_e = e;
    }
}

static web_fg_event_t evt(int site, const char *type, long long a, long long b) {
    web_fg_event_t e;
    memset(&e, 0, sizeof(e));
    e.site = site;
    e.cls = web_fg_class_of(type);
    snprintf(e.type, sizeof(e.type), "%s", type);
    e.a = a;
    e.b = b;
    return e;
}

#define W   WEB_FG_WINDOW_S
#define GAP 150
#define REG 50000.0
#define NOW 10000

/* The same class at both within the window: regional, each naming the
 * other. The window's edge: the peer's start exactly window after the
 * end still pairs; one second later it does not, and the covered,
 * silent peer makes it local. Seen red with the window term dropped from
 * the overlap test (the edge pair then local). */
static void test_regional_and_window_edges(void) {
    web_fg_cov_t c[2];
    cov_at(&c[0], LAT_A, LON_A, rs_a, re_a, 1, 1);
    cov_at(&c[1], LAT_B, LON_B, rs_b, re_b, 1, 1);
    web_fg_event_t ev[2] = { evt(0, "GNSS_JAMMING", 1000, 1100),
                             evt(1, "GNSS_JAMMING", 1150, 1300) };
    web_fg_classify(ev, 2, c, 2, W, GAP, REG, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_REGIONAL);
    WT_EQ(ev[1].verdict, WEB_FG_REGIONAL);
    WT_EQ(ev[0].with, 2u);
    WT_EQ(ev[1].with, 1u);
    WT_EQ(ev[0].quiet | ev[0].stale | ev[0].far, 0u);
    /* Edge: the peer's event starts at b + W. */
    ev[1] = evt(1, "GNSS_JAMMING", 1100 + W, 1100 + W + 30);
    web_fg_classify(ev, 2, c, 2, W, GAP, REG, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_REGIONAL);
    /* One second past it: two local events, each site quiet for the
     * other. */
    ev[1] = evt(1, "GNSS_JAMMING", 1100 + W + 1, 1100 + W + 30);
    web_fg_classify(ev, 2, c, 2, W, GAP, REG, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_LOCAL);
    WT_EQ(ev[0].quiet, 2u);
    WT_EQ(ev[0].with, 0u);
    /* And before: the peer's event ending at a - W pairs, a - W - 1 not. */
    ev[1] = evt(1, "GNSS_JAMMING", 700, 1000 - W);
    web_fg_classify(ev, 2, c, 2, W, GAP, REG, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_REGIONAL);
    ev[1] = evt(1, "GNSS_JAMMING", 700, 1000 - W - 1);
    web_fg_classify(ev, 2, c, 2, W, GAP, REG, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_LOCAL);
}

/* A peer seen observing all of the window and showing nothing: local.
 * A class that differs is no match (a time step at the peer during a
 * jam here). Seen red with the class test dropped from the match (the
 * jam then regional on the peer's time step). */
static void test_local_and_class(void) {
    web_fg_cov_t c[2];
    cov_at(&c[0], LAT_A, LON_A, rs_a, re_a, 1, 1);
    cov_at(&c[1], LAT_B, LON_B, rs_b, re_b, 1, 1);
    web_fg_event_t ev[2] = { evt(0, "GNSS_JAMMING", 1000, 1100),
                             evt(1, "GNSS_TIME_JUMP", 1000, 1000) };
    web_fg_classify(ev, 2, c, 2, W, GAP, REG, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_LOCAL);
    WT_EQ(ev[0].quiet, 2u);
    WT_EQ(ev[1].verdict, WEB_FG_LOCAL);
    /* A sample's interference matches an incident's: one class. */
    ev[1] = evt(1, "CN0_DROP", 1050, 1050);
    web_fg_classify(ev, 2, c, 2, W, GAP, REG, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_REGIONAL);
    WT_EQ(web_fg_class_of("JAM_IND"), WEB_FG_INTERFERENCE);
    WT_EQ(web_fg_class_of("GNSS_SPOOF_SUSPECT"), WEB_FG_SPOOF);
    WT_EQ(web_fg_class_of("GNSS_POSITION_JUMP"), WEB_FG_POSITION);
    WT_EQ(web_fg_class_of("DEAUTH_FLOOD"), -1);
    WT_EQ(web_fg_is_alert("CN0_DROP"), 0);
    WT_EQ(web_fg_is_alert("GNSS_TIME_JUMP"), 1);
}

/* A peer not seen over the whole window: undetermined, never local.
 * Its coverage ending at hi - gap still holds (the newest sample stands
 * for the gap after it); one second earlier it does not. An event still
 * running is judged only up to now. Seen red with web_fg_covered()
 * answering 1 always (the stale peer then "quiet" and the event local). */
static void test_stale_peer_is_undetermined(void) {
    web_fg_cov_t c[2];
    long long s1[1] = { 0 }, e1[1] = { 1100 + W - GAP };
    cov_at(&c[0], LAT_A, LON_A, rs_a, re_a, 1, 1);
    cov_at(&c[1], LAT_B, LON_B, s1, e1, 1, 1);
    web_fg_event_t ev[1] = { evt(0, "GNSS_SPOOF_SUSPECT", 1000, 1100) };
    web_fg_classify(ev, 1, c, 2, W, GAP, REG, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_LOCAL);
    e1[0] = 1100 + W - GAP - 1;
    web_fg_classify(ev, 1, c, 2, W, GAP, REG, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_UNDETERMINED);
    WT_EQ(ev[0].stale, 2u);
    WT_EQ(ev[0].quiet, 0u);
    /* The coverage must start by a - W. */
    s1[0] = 1000 - W + 1;
    e1[0] = 5000;
    web_fg_classify(ev, 1, c, 2, W, GAP, REG, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_UNDETERMINED);
    s1[0] = 1000 - W;
    web_fg_classify(ev, 1, c, 2, W, GAP, REG, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_LOCAL);
    /* Running now: the window's end is now, which the peer's newest
     * sample (now - gap) covers. */
    e1[0] = NOW - GAP;
    ev[0] = evt(0, "GNSS_SPOOF_SUSPECT", 9000, NOW);
    web_fg_classify(ev, 1, c, 2, W, GAP, REG, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_LOCAL);
    /* No coverage at all (unreachable, or never pulled). */
    c[1].nrx = c[1].nev = 0;
    web_fg_classify(ev, 1, c, 2, W, GAP, REG, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_UNDETERMINED);
}

/* An alert's class is quiet only where the peer offered its incidents
 * (ev); interference takes the receiver alone (rx) when the event lasted
 * at least the gap, so a peer sample fell inside it. Seen red with the
 * duration test dropped (the 60 s jam then local on rx alone). */
static void test_alert_class_needs_incidents(void) {
    web_fg_cov_t c[2];
    cov_at(&c[0], LAT_A, LON_A, rs_a, re_a, 1, 1);
    cov_at(&c[1], LAT_B, LON_B, rs_b, re_b, 1, 0);      /* rx only: an I5 export */
    web_fg_event_t ev[1] = { evt(0, "GNSS_TIME_JUMP", 1000, 1000) };
    web_fg_classify(ev, 1, c, 2, W, GAP, REG, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_UNDETERMINED);
    ev[0] = evt(0, "GNSS_JAMMING", 1000, 1000 + GAP);
    web_fg_classify(ev, 1, c, 2, W, GAP, REG, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_LOCAL);
    ev[0] = evt(0, "GNSS_JAMMING", 1000, 1060);
    web_fg_classify(ev, 1, c, 2, W, GAP, REG, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_UNDETERMINED);
    /* ev_none (this site's sloth.db unreadable) is no incidents. */
    cov_at(&c[1], LAT_B, LON_B, rs_b, re_b, 1, 1);
    c[1].ev_none = 1;
    ev[0] = evt(0, "GNSS_TIME_JUMP", 1000, 1000);
    web_fg_classify(ev, 1, c, 2, W, GAP, REG, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_UNDETERMINED);
}

/* The region: a peer 60 km off (default 50 km) is outside, so an event
 * there in the window makes nothing regional and its silence nothing
 * local; with a 100 km region it counts. A site with no position is
 * outside too. Seen red with the distance test inverted. */
static void test_region(void) {
    web_fg_cov_t c[3];
    cov_at(&c[0], LAT_A, LON_A, rs_a, re_a, 1, 1);
    cov_at(&c[1], LAT_G, LON_A, rs_b, re_b, 1, 1);
    web_fg_event_t ev[2] = { evt(0, "GNSS_JAMMING", 1000, 1100),
                             evt(1, "GNSS_JAMMING", 1000, 1100) };
    web_fg_classify(ev, 2, c, 2, W, GAP, REG, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_UNDETERMINED);
    WT_EQ(ev[0].far, 2u);
    web_fg_classify(ev, 2, c, 2, W, GAP, 100000.0, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_REGIONAL);
    c[1].has_pos = 0;
    web_fg_classify(ev, 2, c, 2, W, GAP, 100000.0, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_UNDETERMINED);
    WT_EQ(ev[0].far, 2u);
    /* Three sites: one near and quiet, one far with the same event:
     * local, the far one listed apart. */
    cov_at(&c[1], LAT_B, LON_B, rs_b, re_b, 1, 1);
    cov_at(&c[2], LAT_G, LON_A, rs_b, re_b, 1, 1);
    ev[1] = evt(2, "GNSS_JAMMING", 1000, 1100);
    web_fg_classify(ev, 2, c, 3, W, GAP, REG, NOW);
    WT_EQ(ev[0].verdict, WEB_FG_LOCAL);
    WT_EQ(ev[0].quiet, 2u);
    WT_EQ(ev[0].far, 4u);
}

/* Coverage edges, the spans a sample run makes (a gap past the limit
 * opens a new span; a clock back inside the newest changes nothing),
 * the reference thinned to one fix a WEB_FG_REF_EVERY_S, and the saved
 * state's round trip; a parse refuses a malformed value and leaves the
 * site as it was. */
static void test_samples_and_state(void) {
    long long s[2] = { 100, 1000 }, e[2] = { 500, 2000 };
    WT_EQ(web_fg_covered(s, e, 2, 100, 500, 0), 1);
    WT_EQ(web_fg_covered(s, e, 2, 99, 500, 0), 0);
    WT_EQ(web_fg_covered(s, e, 2, 100, 510, 10), 1);
    WT_EQ(web_fg_covered(s, e, 2, 100, 511, 10), 0);
    WT_EQ(web_fg_covered(s, e, 2, 400, 1200, 0), 0);      /* across a hole */
    web_fg_t *g = web_fg_new();
    WT_ASSERT(g != NULL);
    if (!g) return;
    WT_EQ(web_fg_slot(g, "self"), 0);
    int b = web_fg_slot(g, "beta");
    WT_EQ(b, 1);
    WT_EQ(web_fg_slot(g, "beta"), 1);
    WT_EQ(web_fg_slot(g, ""), -1);
    web_fg_sample_t sm;
    memset(&sm, 0, sizeof(sm));
    sm.fresh = sm.evok = sm.has_trk = 1;
    sm.has_fix = 1;
    sm.mode = 3;
    sm.has_eph = 1;
    sm.eph = 4.5;
    sm.lat = LAT_B;
    sm.lon = LON_B;
    for (long long t = 1000; t <= 1000 + 60 * 30; t += 60) {
        sm.t = t;
        web_fg_add(g, b, &sm, GAP);
    }
    web_fg_site_t *st = &g->site[b];
    WT_EQ(st->n, 31);
    WT_EQ(st->nrx, 1);
    WT_EQ(st->rx_s[0], 1000);
    WT_EQ(st->rx_e[0], 2800);
    WT_EQ(st->nref, 4);                    /* 1000, 1600, 2200, 2800 */
    /* A gap past GAP: a second span; a stale sample: no span. */
    sm.t = 2800 + GAP + 1;
    web_fg_add(g, b, &sm, GAP);
    WT_EQ(st->nrx, 2);
    sm.fresh = sm.evok = 0;
    sm.t += 60;
    web_fg_add(g, b, &sm, GAP);
    WT_EQ(st->nrx, 2);
    WT_EQ(st->rx_e[1], 2800 + GAP + 1);
    char *txt = malloc(1 << 16);
    WT_ASSERT(txt != NULL);
    if (!txt) { web_fg_free(g); return; }
    WT_ASSERT(web_fg_state_text(st, txt, 1 << 16) > 0);
    WT_HAS(txt, "1 rx 2 1000 2800 2951 2951 ev 2 ");
    web_fg_site_t *back = calloc(1, sizeof(*back));
    WT_ASSERT(back != NULL);
    if (back) {
        WT_EQ(web_fg_state_parse(back, txt), 0);
        WT_EQ(back->nrx, 2);
        WT_EQ(back->nref, st->nref);
        WT_EQ(back->last_ref, st->last_ref);
        WT_ASSERT(back->ref_lat[0] > 33.3290 && back->ref_lat[0] < 33.3292);
        /* Refusals: each leaves the site as it was. */
        static const char *const bad[] = {
            "", "2 rx 0 ev 0 ref 0 0", "1 rx 1 5 4 ev 0 ref 0 0",
            "1 rx 0 ev 0 ref 1 0 100 95.0 0.0", "1 rx 0 ev 0 ref 0 0 extra",
            "1 rx 65 ev 0 ref 0 0", "1 rx 2 1 9 5 10 ev 0 ref 0 0",
            "1 rx 0 ev 0 ref 1 0 100 nan 0.0",
        };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            if (web_fg_state_parse(back, bad[i]) != -1) fprintf(stderr, "    took: %s\n", bad[i]);
            WT_EQ(web_fg_state_parse(back, bad[i]), -1);
        }
        WT_EQ(back->nrx, 2);
        free(back);
    }
    free(txt);
    web_fg_free(g);
}

void run_fleetgnss_tests(void) {
    WT_RUN(test_regional_and_window_edges);
    WT_RUN(test_local_and_class);
    WT_RUN(test_stale_peer_is_undetermined);
    WT_RUN(test_alert_class_needs_incidents);
    WT_RUN(test_region);
    WT_RUN(test_samples_and_state);
}
