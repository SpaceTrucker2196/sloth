/* GNSS across the owner's fleet (#192 I6; docs/wiki/fleet.md "GNSS:
 * regional or local"): each site's receiver as its export reports it,
 * compared site against site. slothweb fleet findings, not sloth alerts:
 * nothing here is written to sloth.db.
 *
 * The samples. After each good pull of a peer, and once a pull round for
 * this site, one sample of the receiver's summary (fresh or stale, the
 * state, satellites, mean and tracked-median C/N0, the jamming indicator,
 * the clock offset, the newest fix with its eph and hdop, the peer's
 * clock skew) goes into the site's ring (WEB_FG_RING, memory only), and:
 *
 *   coverage  the spans of this site's clock over which the site was
 *             seen observing: `rx` while its receiver summary was fresh
 *             (at most WEB_FG_FRESH_S old: two of the emitter's 300 s
 *             heartbeats and a margin, WEB_GNSS_SAT_TTL_S), listed a sky
 *             and carried the tracked median with the hour of history the
 *             CN0_DROP test needs (so a C/N0 drop there would show), `ev`
 *             while its export offered the whole of its GNSS incidents
 *             (gnss=1, sloth.db open, read complete). Samples further
 *             apart than the gap (two pull intervals and 30 s) start a new
 *             span, and so does any sample that was not observing: a
 *             span is never bridged across a sample that said "not".
 *   sample events  JAM_IND and CN0_DROP (below), flagged as each sample
 *             is added and kept as runs for the week (WEB_FG_SEV), so a
 *             restart or the ring's eight hours do not drop a peer's
 *             event while its coverage stays.
 *   reference at most one fix a WEB_FG_REF_EVERY_S, the last WEB_FG_REF
 *             of them (a week): the site's reference position is their
 *             coordinate-wise median, used from WEB_FG_REF_MIN on.
 *
 * All three are kept in slothweb.db's meta table ("fleet.gnss.<site>"), so
 * a restart keeps them; no schema step. The ring is not: the C/N0 and
 * clock references rebuild within WEB_FG_HIST_S, and until then no
 * sample is `rx` coverage.
 *
 * The events, each in this site's clock (a peer's less its skew):
 *   - sloth's own GNSS incidents (alert_incidents, v11), this site's read
 *     from sloth.db, a peer's from its gnss_event lines;
 *   - from the samples: JAM_IND, the jamming indicator at or above
 *     WEB_FG_JAM_IND, and CN0_DROP, the tracked median at least
 *     WEB_FG_CN0_DROP_DB under the site's own median of the hour before
 *     (WEB_FG_HIST_S, at least WEB_FG_HIST_MIN samples), runs of samples
 *     merged.
 * Each is of a class: interference (GNSS_JAMMING, JAM_IND, CN0_DROP),
 * spoof (GNSS_SPOOF_SUSPECT), time (GNSS_TIME_JUMP) or position
 * (GNSS_POSITION_JUMP).
 *
 * The classification (web_fg_classify()), of an event [a, b] at site S,
 * over the sites within the region (--peer-gnss-region-km) of S:
 *   regional      one of them has an event of the same class whose span
 *                 comes within the window (WEB_FG_WINDOW_S) of [a, b];
 *   local         none has, and at least one was covered over
 *                 [a - window, b + window];
 *   undetermined  none of them was covered (stale, unreachable, an older
 *                 export with no incidents, an event still within the
 *                 window of its end or not yet pulled past it, or no site
 *                 within the region).
 * Covered: one span holds the interval, its last sample at or after
 * b + window, so the answer that sample came from already held anything
 * the site saw in the window; nothing stands for the time after a
 * sample. An incident (an alert class) is quiet on `ev` coverage, or for
 * interference on `rx` coverage when it lasted at least the gap, so a
 * peer sample fell inside it; a sample event (JAM_IND, CN0_DROP) only on
 * the latter: a peer's sloth not firing its rule says nothing of a drop
 * under the rule's test.
 *
 * The baseline (two or more static sites): each site's displacement from
 * its reference against k x eph (WEB_FG_K, the GNSS_POSITION_JUMP rule's
 * own default multiplier), and for each pair the distance now against the
 * distance between the references, bounded by k x (eph_a + eph_b): "for a
 * fixed sensor, zero, so the bound collapses to the two error estimates"
 * (research/gnss/time-and-position-integrity.md). A site past its own
 * bound is named; no eph (or an eph of 0, which no receiver means), no
 * bound, no claim. Time: each site's clock
 * offset against its median of the hour before, a step at or above
 * WEB_FG_TIME_STEP_MS (the GNSS_TIME_JUMP rule's default, from the gpsd
 * HOWTO's 200 ms floor and "anything below roughly a second is noise"),
 * with the peer's skew against its own median beside it. */
#ifndef SLOTHWEB_FLEETGNSS_H
#define SLOTHWEB_FLEETGNSS_H

#include "web_fleet.h"
#include "web_json.h"

#define WEB_FG_SITES         (WEB_FLEET_PEERS + 1)    /* [0] is this site */
#define WEB_FG_RING          480        /* 8 h at the default pull */
#define WEB_FG_SPANS         64
#define WEB_FG_SEV           256        /* sample events kept, the week's newest */
#define WEB_FG_REF           1008       /* a week at one per 600 s */
#define WEB_FG_REF_EVERY_S   600
#define WEB_FG_REF_MIN       6
#define WEB_FG_FRESH_S       660
#define WEB_FG_WINDOW_S      120
#define WEB_FG_K             3
#define WEB_FG_TIME_STEP_MS  1000
#define WEB_FG_CN0_DROP_DB   10
#define WEB_FG_JAM_IND       128
#define WEB_FG_HIST_S        3600
#define WEB_FG_HIST_MIN      10
#define WEB_FG_SKEW_STEP_S   2
#define WEB_FG_EVENTS_S      (7LL * 86400)
#define WEB_FG_EV_MAX        512
#define WEB_FG_REGION_KM_DEF 50
#define WEB_FG_REGION_KM_MAX 20000
#define WEB_FG_LIMIT_DEF     50
#define WEB_FG_LIMIT_MAX     200

enum { WEB_FG_INTERFERENCE = 0, WEB_FG_SPOOF, WEB_FG_TIME, WEB_FG_POSITION,
       WEB_FG_NCLASS };
enum { WEB_FG_UNDETERMINED = 0, WEB_FG_LOCAL, WEB_FG_REGIONAL };

const char *web_fg_class_word(int cls);
const char *web_fg_verdict_word(int v);
/* The class of a GNSS alert type's name or a sample event's word
 * (JAM_IND, CN0_DROP); -1 for anything else. */
int  web_fg_class_of(const char *type);
/* 1 for an event that is sloth's incident (an alert type), 0 a sample's. */
int  web_fg_is_alert(const char *type);

typedef struct {
    long long t;                     /* this site's clock at the read */
    long long gts;                   /* the summary's ts, the site's clock */
    long long skew;                  /* the site's clock less this one's (0 here) */
    int       fresh;                 /* summary at most WEB_FG_FRESH_S old */
    int       evok;                  /* sloth.db open and incidents offered */
    char      state[16];
    int       sats_used, sats_view;  /* -1 absent */
    int       has_trk;               /* the export sent tracked (#192 I6) */
    int       has_cn0;  double cn0_mean;
    int       tracked;  double cn0_med;    /* tracked 0: no median */
    int       jam;                   /* -1 absent */
    int       has_off;  long long off_ms;
    int       has_fix, mode;
    double    lat, lon;
    int       has_eph;  double eph;
    int       has_hdop; double hdop;
    long long fix_ts;
    unsigned char flag;              /* set by web_fg_add(): 1 JAM_IND, 2 CN0_DROP */
} web_fg_sample_t;

typedef struct {
    int       used;
    char      name[WEB_FLEET_NAME_MAX + 1];
    int       n, head;
    web_fg_sample_t ring[WEB_FG_RING];
    int       nrx, nev;
    long long rx_s[WEB_FG_SPANS], rx_e[WEB_FG_SPANS];
    long long ev_s[WEB_FG_SPANS], ev_e[WEB_FG_SPANS];
    int       nref, rhead;
    long long ref_ts[WEB_FG_REF];
    double    ref_lat[WEB_FG_REF], ref_lon[WEB_FG_REF];
    long long last_ref, saved_at;
    /* The sample events, oldest first: [a, b] and the word (0 JAM_IND,
     * 1 CN0_DROP); se_open the run each word's next flagged sample may
     * extend (-1 none). */
    int       nse;
    long long se_a[WEB_FG_SEV], se_b[WEB_FG_SEV];
    unsigned char se_w[WEB_FG_SEV];
    int       se_open[2];
    /* Whether the newest span may be extended: cleared by a sample that
     * was not observing, and at a load. */
    int       rx_open, ev_open;
    int       dirty;
} web_fg_site_t;

typedef struct web_fg {
    web_fg_site_t site[WEB_FG_SITES];
} web_fg_t;

web_fg_t *web_fg_new(void);
void      web_fg_free(web_fg_t *g);
/* The slot of a site by name ("self" is [0]), made when absent; -1 when
 * full or the name is not one. */
int  web_fg_slot(web_fg_t *g, const char *name);
/* One sample into a site: the ring, its sample events, the coverage
 * (gap_s apart at most within a span), the reference. */
void web_fg_add(web_fg_t *g, int slot, const web_fg_sample_t *s, long long gap_s);
/* "1 rx N s e .. ev N s e .. ref N last ts lat lon .. se N a b w .." and
 * back; the parse refuses anything but its own spelling (0, -1 left as
 * it was). */
int  web_fg_state_text(const web_fg_site_t *s, char *out, size_t cap);
int  web_fg_state_parse(web_fg_site_t *s, const char *text);

/* An event to classify. a, b and the coverage are this site's clock. */
typedef struct {
    int       site, cls;
    char      type[24];
    long long a, b, count;
    int       sev;
    /* Out: the verdict, and per site (bit i: site i) the sites with the
     * same class in the window, the covered sites without, the sites not
     * covered, and the sites outside the region or with no position. */
    int       verdict;
    unsigned  with, quiet, stale, far;
} web_fg_event_t;

typedef struct {
    int             has_pos;
    double          lat, lon;
    int             nrx, nev;
    const long long *rx_s, *rx_e, *ev_s, *ev_e;
    int             ev_none;         /* no incidents from this site at all */
} web_fg_cov_t;

/* 1 when one span of s[], e[] holds [a, b]: it starts by a and its last
 * sample is at or after b. */
int  web_fg_covered(const long long *s, const long long *e, int n, long long a, long long b);
void web_fg_classify(web_fg_event_t *ev, int n, const web_fg_cov_t *sites, int nsites,
                     long long window_s, long long gap_s, double region_m);

/* Read each site's coverage, reference and sample events back from meta over the pull
 * thread's connection (web_fleet_load()'s step). */
void web_fg_meta_load(web_fleet_t *f);

/* GET /api/fleet/gnss?limit=N (50, 1..200): each site's receiver, the
 * baseline and time checks, and the classified events of the last week,
 * newest first. A heap body; 0 with *status, -1 out of memory. */
int  web_fleet_gnss_route(web_fleet_t *f, const web_fleet_src_t *src, const char *query,
                          long long now_s, char **body, size_t *len, int *status);
/* /api/fleet/overview's "gnss": the position and time verdicts and the
 * last day's events by verdict. */
void web_fg_overview_json(web_fleet_t *f, const web_fleet_src_t *src, long long now_s,
                          web_jw_t *w);

#endif
