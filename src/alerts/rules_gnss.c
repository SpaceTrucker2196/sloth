/* GNSS rules (2026-11-03): what the --gps receiver's sky and fixes say
 * about the receiver's own inputs. Bases in research/gnss/; the inputs
 * and their caveats in docs/wiki/gnss.md.
 *
 * Every rule reads the snapshot gps_health_poll() copied onto the state
 * (s->gnss_sky, s->gnss_fix, s->gnss_hist), never src/gps.c, and every
 * window runs on the host's monotonic clock the history carries: a
 * host wall-clock step is exactly what GNSS_TIME_JUMP must not be fooled
 * by, so no rule here may measure a duration in wall time.
 *
 * What none of them can do, from the research and stated once here:
 * tell interference from jamming (DHS 2017: "the only difference is the
 * intent"), see a spoofer that was already there when sloth started
 * (u-blox M8 §16.2 says the same of its own detector), or catch a
 * patient drag-off within the receiver's own physics (Psiaki & Humphreys
 * 2016 §II-D). A u-blox 7 behind gpsd 3.27 exports no AGC, no
 * jammingState and no spoofDetState; these rules are built from what
 * it does export: SKY ss / used, TPV mode / time / eph / speed / eps /
 * leapseconds / jam. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "gps.h"
#include "sloth_clock.h"
#include "tune.h"
#include "alert_key.h"
#include "rules.h"
#include "engine_internal.h"

/* A receiver whose newest series point or sky is older than this is
 * not being heard, and nothing it said last is evidence about now. */
#define GNSS_LIVE_MS          5000
/* GNSS_JAMMING's trailing baseline: the 60 s before the window. Long
 * enough that a satellite setting or one passing obstruction moves the
 * mean little, short enough that the slow fall of a sky over minutes
 * is inside it rather than measured against it. A judgement: no read
 * source gives a baseline length. */
#define GNSS_JAM_BASELINE_MS  60000
/* Points the baseline must hold before a drop is measured against it:
 * half of one a second, so the first minute of a run cannot fire. */
#define GNSS_JAM_BASELINE_MIN 30
/* uSat flaps by one every few seconds on a moving or urban receiver
 * (docs/wiki/gnss.md), so a fall of one is not a fall. */
#define GNSS_JAM_USAT_FALL    2
/* The list itself moves by one as a satellite rises or sets; a fall of
 * two or more inside the window is satellites leaving the sky, which a
 * noise-floor rise does not do ("while nSat is unchanged"). */
#define GNSS_JAM_NSAT_FALL    2
/* A gap between two one-second points longer than this breaks a held
 * jamInd run: gpsd stopped sending, and the hold is not known. */
#define GNSS_JAM_GAP_MS       3000
/* A whole-second step is a leap second's when within this of a whole
 * second: the gpsd time HOWTO's 200 ms in-band jump, plus margin. */
#define GNSS_LEAP_TOL_MS      250
/* 1024 GPS weeks, the week-number rollover period (GPS.gov). */
#define GNSS_ROLLOVER_MS      (1024LL * 7 * 86400 * 1000)
#define GNSS_ROLLOVER_TOL_MS  60000
/* A fix whose next one is more than this further on in the receiver's
 * time than in the host's was read from a queue: the reader stalled
 * (the TUI stopped with Ctrl-Z, a loaded host) and is draining what
 * gpsd buffered, so its receipt time is not its epoch's. Over the
 * HOWTO's 200 ms latency jump, so ordinary jitter is not a queue. */
#define GNSS_BACKLOG_MS       250
/* The furthest the receiver's time between two fixes may run past the
 * host's elapsed time and still be taken as their epoch spacing: a
 * reader seconds behind, not a receiver clock stepped by minutes. */
#define GNSS_BACKLOG_MAX_MS   30000
/* How long a read lateness may stand before the rule takes it as the
 * reader's new normal and re-anchors on it (#182): without this a
 * reader late by a steady 300 ms forever would leave GNSS_TIME_JUMP
 * never judging again. The GNSS_BACKLOG_MAX_MS figure, a reader
 * seconds behind; a judgement, no source gives one. */
#define GNSS_LATE_REBASE_MS   30000

/* What the rules remember between ticks. Fix pairs are judged once:
 * each rule keeps the TPV count of the newest fix it has judged. A fix
 * received before alerts_clear() is never judged after it, so pressing
 * 'c' cannot replay a minute-old jump as a new finding. */
static struct {
    uint64_t forget_mono;
    uint64_t time_seq, pos_seq, spoof_seq;
    /* GNSS_TIME_JUMP's reference: the newest fix whose time was
     * accepted. A fix that stepped and did not hold, or was read from a
     * queue, never becomes it, so a run of them is each measured from
     * the last good fix and never from one another. A copy, because the
     * ring may have moved past it. */
    int           has_anchor;
    gnss_fix_pt_t anchor;
    /* Host monotonic ms of the first fix of the current run read late
     * against the anchor (read_lateness()), 0 when none is running. */
    uint64_t      late_mono;
    /* GNSS_JAMMING: the baseline a collapse was measured against, held
     * while the mean stays down so a standing jam does not resolve the
     * moment its own collapse ages into the baseline. */
    int      jam_active;
    int      jam_base_x10, jam_base_usat, jam_base_trk, jam_base_nsat;
    /* GNSS_SPOOF_SUSPECT: when each heuristic was last seen (mono ms, 0
     * never) and the figures it was seen with, for the detail. */
    uint64_t h_mono[3];
    int      h1_n, h1_max_x10;
    int      h2_n, h2_mean_x10, h2_sd_x10;
    double   h3_dist_m;
    long long h3_step_ms;
} g_gnss;

void rules_gnss_forget(void) {
    memset(&g_gnss, 0, sizeof(g_gnss));
    g_gnss.forget_mono = sloth_mono_ms();
}

/* What a rule reads before the first poll has pointed s->gnss_hist. */
static const gnss_hist_t g_empty;

static const gnss_fix_pt_t *fix_at(const gnss_hist_t *h, int i) {
    return &h->fixes[(h->fix_head - h->fix_n + i + 2 * GNSS_FIX_HIST) % GNSS_FIX_HIST];
}

static const gnss_sec_pt_t *sec_at(const gnss_hist_t *h, int i) {
    return &h->secs[(h->sec_head - h->sec_n + i + 2 * GNSS_SERIES_S) % GNSS_SERIES_S];
}

static long long llabs_(long long v) { return v < 0 ? -v : v; }

/* The receiver's time against the host's monotonic clock: constant
 * while both run, whatever the host's wall clock does. */
static long long rx_vs_mono(const gnss_fix_pt_t *p) {
    return p->rx_time_ms - (long long)p->mono_ms;
}

/* Both fixes carry the figures the time test needs. */
static int time_pair_ok(const gnss_fix_pt_t *a, const gnss_fix_pt_t *b) {
    return a->has_rx_time && b->has_rx_time && a->mono_ms && b->mono_ms &&
           b->mono_ms >= a->mono_ms;
}

/* The receiver's step between two fixes, ms, net of the elapsed
 * monotonic time. */
static long long rx_step(const gnss_fix_pt_t *a, const gnss_fix_pt_t *b) {
    return rx_vs_mono(b) - rx_vs_mono(a);
}

/* The host's wall clock against its monotonic one across the pair: a
 * step here moved the clock offset without the receiver moving. */
static long long host_step(const gnss_fix_pt_t *a, const gnss_fix_pt_t *b) {
    return (b->wall_ms - (long long)b->mono_ms) - (a->wall_ms - (long long)a->mono_ms);
}

/* The documented non-attack shapes of a time step
 * (research/gnss/time-and-position-integrity.md, "Edge cases that are
 * not attacks"). 1 leap second, 2 week rollover, 0 neither.
 *
 *   leap second  "a whole-second step coinciding with a change in"
 *                TPV leapseconds: the step is -Δleap whole seconds (UTC
 *                = GPS - leap, so one more leap second moves UTC back
 *                one), or, when the receiver had no leap count and now
 *                has one (the cold-boot case the HOWTO names), up to
 *                that many seconds; or a one-second step within two
 *                seconds of a UTC midnight, where a leap second is
 *                inserted, in case leapseconds changes on a later TPV.
 *   rollover     a date error of a whole multiple of 1024 weeks: "a
 *                fault, not an attack". */
static int time_step_benign(const gnss_fix_pt_t *a, const gnss_fix_pt_t *b,
                            long long step) {
    long long whole = (step >= 0 ? step + 500 : step - 500) / 1000;
    long long frac = llabs_(step - whole * 1000);
    if (whole != 0 && frac <= GNSS_LEAP_TOL_MS) {
        if (a->leap >= 0 && b->leap >= 0 && a->leap != b->leap &&
            whole == -(long long)(b->leap - a->leap))
            return 1;
        if (a->leap < 0 && b->leap >= 0 && llabs_(whole) <= b->leap)
            return 1;
        long long tod = b->rx_time_ms % 86400000LL;
        if (tod < 0) tod += 86400000LL;
        if (llabs_(whole) == 1 && (tod <= 2000 || tod >= 86400000LL - 2000))
            return 1;
    }
    for (int k = -2; k <= 2; k++) {
        if (k == 0) continue;
        if (llabs_(step - k * GNSS_ROLLOVER_MS) <= GNSS_ROLLOVER_TOL_MS)
            return 2;
    }
    return 0;
}

/* Elapsed seconds between the host's receipt of two fixes on the
 * monotonic clock, the wall stamps only when a point predates the mono
 * field (never in practice). */
static double mono_dt_s(const gnss_fix_pt_t *a, const gnss_fix_pt_t *b) {
    if (a->mono_ms && b->mono_ms && b->mono_ms >= a->mono_ms)
        return (double)(b->mono_ms - a->mono_ms) / 1000.0;
    return b->ts >= a->ts ? (double)(b->ts - a->ts) : 0.0;
}

/* Seconds between two fixes' epochs: the receiver's own time
 * difference, which is the Δt of the research's bound. Receipt time is
 * not it: a reader that stalls and drains gpsd's queue reads fixes a
 * second apart a millisecond apart, and the bound shrank to the two
 * error estimates for a car doing 30 m/s. The receiver's difference is
 * taken when it is positive and no more than GNSS_BACKLOG_MAX_MS past
 * the host's elapsed time (the larger of its monotonic and wall
 * clocks', so a suspend, which stops only the first, still counts);
 * otherwise the receiver's clock stepped, GNSS_TIME_JUMP's business,
 * and stretching dt with it would let a spoofer moving time and
 * position together widen the bound over its own jump. */
static double fix_dt_s(const gnss_fix_pt_t *a, const gnss_fix_pt_t *b) {
    double md = mono_dt_s(a, b);
    if (!a->has_rx_time || !b->has_rx_time) return md;
    long long rx = b->rx_time_ms - a->rx_time_ms;
    long long host = (long long)(md * 1000.0);
    long long wd = b->wall_ms - a->wall_ms;
    if (wd > host) host = wd;
    if (rx > 0 && rx <= host + GNSS_BACKLOG_MAX_MS) return (double)rx / 1000.0;
    return md;
}

/* b was read from a queue: the next fix c is further on in the
 * receiver's time than in the host's by more than GNSS_BACKLOG_MS, so b
 * waited before it was read and its receipt time is late by at least
 * that. */
static int read_from_queue(const gnss_fix_pt_t *b, const gnss_fix_pt_t *c) {
    long long rx = c->rx_time_ms - b->rx_time_ms;
    long long md = (long long)(c->mono_ms - b->mono_ms);
    return md + GNSS_BACKLOG_MS < rx;
}

/* The receiver's fix interval, ms: the median of its own time between
 * consecutive fixes in the ring, 0 with fewer than two pairs. The
 * receiver's epochs are what sloth's reads cannot move, so this is the
 * cadence a read's gap is held against; the median, because a step or
 * a dropped epoch is one pair. */
static long long fix_interval_ms(const gnss_hist_t *h) {
    long long v[GNSS_FIX_HIST];
    int n = 0;
    for (int i = 1; i < h->fix_n; i++) {
        const gnss_fix_pt_t *p = fix_at(h, i - 1), *x = fix_at(h, i);
        if (!p->has_rx_time || !x->has_rx_time) continue;
        long long rd = x->rx_time_ms - p->rx_time_ms;
        if (rd <= 0) continue;
        int j = n++;
        while (j > 0 && v[j - 1] > rd) { v[j] = v[j - 1]; j--; }
        v[j] = rd;
    }
    return n >= 2 ? v[n / 2] : 0;
}

/* How late b was read against the anchor a, ms (#182), into *late: over
 * each pair of consecutive reads from a to b on which the receiver kept
 * its fix interval iv (within tol), the host's gap past the receiver's.
 * There the receiver says one epoch passed and any difference is the
 * reader's: a starved reader late by 1.5 s shows it once, on the read
 * where it fell behind, and every read after it is as late until a
 * short gap catches it up. A pair off the interval is the receiver's
 * own spacing moving - a step, GNSS_TIME_JUMP's business - and adds
 * nothing, which is what keeps a real step at the ordinary cadence
 * judged: its host gap is the interval. tol is half the threshold, so
 * a step of at least the threshold always moves its pair off the
 * interval. Negative when the reads ran short of the receiver's, which
 * is the anchor having been the late one. 0 returned when a is no
 * longer in the ring, so there is nothing to sum.
 *
 * A pair adds only what the host's gap says on its own: the lesser of
 * its gap past the receiver's and past the interval, and nothing when
 * the two disagree in sign. A late read moves the host's gap off both
 * alike. A receiver whose own gap is nudged inside tol while its fixes
 * are read on time moves only the first, and the first draft summed
 * that: one 300 ms nudge from a spoofer read as lateness, left the rule
 * blind, and a step after it was re-anchored on unjudged 30 s later.
 * A receiver that re-times its output with the nudge moves both gaps
 * together and leaves the difference at 0.
 *
 * Not caught: a reader that falls behind on the very pair where the
 * receiver also dropped an epoch. That pair is off the interval, and
 * must be, since at 1 Hz a dropped epoch and a whole-second forward
 * step have the same receiver gap. */
static int read_lateness(const gnss_hist_t *h, int bi, const gnss_fix_pt_t *a,
                         long long iv, long long tol, long long *late) {
    int j = bi;
    while (j > 0 && fix_at(h, j - 1)->seq > a->seq) j--;
    if (j == 0 || fix_at(h, j - 1)->seq != a->seq) return 0;
    long long sum = 0;
    const gnss_fix_pt_t *p = a;
    for (; j <= bi; j++) {
        const gnss_fix_pt_t *x = fix_at(h, j);
        if (iv > 0 && time_pair_ok(p, x)) {
            long long rd = x->rx_time_ms - p->rx_time_ms;
            long long md = (long long)(x->mono_ms - p->mono_ms);
            long long by_rx = md - rd, by_iv = md - iv;
            if (llabs_(rd - iv) <= tol && by_rx && by_iv &&
                (by_rx > 0) == (by_iv > 0))
                sum += llabs_(by_rx) < llabs_(by_iv) ? by_rx : by_iv;
        }
        p = x;
    }
    *late = sum;
    return 1;
}

/* The host suspended between a and b: the receiver's clock and the
 * host's wall clock moved past the monotonic one by the same amount (to
 * half the threshold), at least the threshold, forward. CLOCK_MONOTONIC
 * stops across a suspend and neither independent clock does. A
 * receiver stepped by a spoofer moves alone; a chrony refclock stepping
 * the host onto it needs its filter's worth of samples first, not the
 * one TPV between two fixes. */
static int host_suspended(const gnss_fix_pt_t *a, const gnss_fix_pt_t *b,
                          long long step, long long thr) {
    long long hs = host_step(a, b);
    return hs >= thr && llabs_(step - hs) < thr / 2;
}

/* The farthest two fixes may honestly be apart:
 * (v + eps) x dt + k x (eph_a + eph_b), the research's
 * |Δpos| <= (v_max + eps)·Δt + eph₁ + eph₂ with v the larger reported
 * speed (gpsd's own, in place of a platform limit sloth does not know)
 * and k on the error estimates because gpsd says they are "guessed to
 * be 95% confidence, may also be 50%, one sigma, or two sigma". -1 when
 * either fix has no eph: no error estimate, no bound, no claim. */
static double pos_bound_m(const gnss_fix_pt_t *a, const gnss_fix_pt_t *b,
                          double dt, long k, double *v_out, double *e_out) {
    if (!a->has_eph || !b->has_eph) return -1.0;
    double v = 0.0, e = 0.0;
    if (a->has_speed && a->speed > v) v = a->speed;
    if (b->has_speed && b->speed > v) v = b->speed;
    if (a->has_eps && a->eps > e) e = a->eps;
    if (b->has_eps && b->eps > e) e = b->eps;
    if (v_out) *v_out = v;
    if (e_out) *e_out = e;
    return (v + e) * dt + (double)k * (a->eph + b->eph);
}

/* ── GNSS_JAMMING ────────────────────────────────────────────────────
 *
 * Two paths, either fires:
 *
 * (a) A simultaneous collapse. The newest one-second point's median
 *     C/N0 over the TRACKED satellites (ss > 0) is at least
 *     gnss.jam_cn0_drop_db under the mean of that median over the
 *     GNSS_JAM_BASELINE_MS before the window (gnss.jam_window_s); the
 *     sky still lists satellites and the list has not fallen by
 *     GNSS_JAM_NSAT_FALL; and the used set fell by GNSS_JAM_USAT_FALL or
 *     the fix is gone. The research's signature is "every tracked
 *     satellite's ss falling within one or two epochs ... while nSat is
 *     unchanged, ending in loss of fix with satellites still listed"
 *     (research/gnss/jamming-detection.md), and DHS 2017 Development
 *     Strategy 7 names "changes in effective C/N0". Tracked, because
 *     gpsd lists untracked satellites at ss 0 and "Attenuation by an
 *     obstruction is direction-dependent": the first draft averaged the
 *     ss-0 rows in, and four of ten satellites lost behind a building
 *     read as a 12 dB collapse while the other six never moved. The median,
 *     because it moves only when most of the tracked set falls; losing
 *     lock on a subset leaves it where the rest are. Every satellite
 *     lost from tracking at once, the sky still listed, is the
 *     signature's end state and counts as a level of 0 (a tunnel looks
 *     the same: Kriezis et al., "Physical obstructions ... can produce
 *     signatures similar to those of jamming"). The window is what
 *     separates it from a slow decline: a sky falling 10 dB over five
 *     minutes moves the window-to-baseline level by little more than a
 *     decibel. An empty sky is not this: it is the antenna gone
 *     (docs/wiki/gnss.md), so a point listing nothing never fires.
 *
 *     Default 10 dB: "No read source puts a number on 'simultaneous' or
 *     on the drop; any value is a judgement." 10 dB is the distance from
 *     the bottom of the nominal "~ 37 to 45dB-Hz" band (Inside GNSS
 *     2010) to the 27 dB-Hz Kriezis et al. define as signal loss: a
 *     typical sky pushed to the edge of tracking. Both ends are figures
 *     for tracked signals, which is what the median is taken over. 10 s: the research's
 *     "one or two epochs" stretched to cover gpsd's SKY cadence.
 *
 * (b) The receiver's own CW indicator: TPV jam (u-blox 7 MON-HW jamInd,
 *     "0 = no CW jamming, 255 = strong CW jamming") at or above
 *     gnss.jam_ind on every one-second point for gnss.jam_hold_s. The
 *     vendor says it "can be used as an indicator for continuous wave
 *     (narrowband) jammers/interference only" and that "It is necessary
 *     to run the receiver in the application and then calibrate the
 *     'not jammed' case": there is no published level. Default 128, the
 *     top half of the scale and the top band the [#] view grades, so an
 *     uncalibrated install errs quiet; 30 s because gpsd attaches jam
 *     about one TPV in four (MON-HW "every 4" epochs), so a single
 *     report cannot fire.
 *
 * WARN; CRIT when the fix is lost (mode 1; mode 0 is gpsd's "unknown",
 * a TPV that said nothing about the fix, and is not a loss), which is the research's
 * end state of a jam and the point at which every position stamp sloth
 * writes is gone. Never a claim of intent: the detail says so. */
void rule_gnss_jamming(const sloth_state_t *s, time_t now) {
    const gnss_hist_t *h = s->gnss_hist ? s->gnss_hist : &g_empty;
    if (h->sec_n == 0) { g_gnss.jam_active = 0; return; }
    const gnss_sec_pt_t *cur = sec_at(h, h->sec_n - 1);
    uint64_t now_m = sloth_mono_ms();
    if (!cur->mono_ms || now_m > cur->mono_ms + GNSS_LIVE_MS) {
        g_gnss.jam_active = 0;
        return;
    }
    const long drop_x10 = tune_val(TUNE_GNSS_JAM_CN0_DROP_DB) * 10;
    const uint64_t win_ms = (uint64_t)tune_val(TUNE_GNSS_JAM_WINDOW_S) * 1000;
    const int fix_lost = cur->mode == 1;

    /* (a) the collapse */
    int base_x10 = 0, base_usat = 0, base_trk = 0, base_nsat = 0, have_base = 0;
    if (g_gnss.jam_active) {
        base_x10 = g_gnss.jam_base_x10;
        base_usat = g_gnss.jam_base_usat;
        base_trk = g_gnss.jam_base_trk;
        base_nsat = g_gnss.jam_base_nsat;
        have_base = 1;
    } else if (cur->mono_ms > win_ms + GNSS_JAM_BASELINE_MS) {
        uint64_t hi = cur->mono_ms - win_ms, lo = hi - GNSS_JAM_BASELINE_MS;
        long sum = 0, usum = 0, tsum = 0, nsum = 0;
        int n = 0;
        for (int i = 0; i < h->sec_n; i++) {
            const gnss_sec_pt_t *p = sec_at(h, i);
            if (p->mono_ms < lo || p->mono_ms >= hi) continue;
            if (p->nsat == 0 || p->trk == 0 || p->cn0_med_x10 <= 0) continue;
            sum += p->cn0_med_x10;
            usum += p->usat;
            tsum += p->trk;
            nsum += p->nsat;
            n++;
        }
        if (n >= GNSS_JAM_BASELINE_MIN) {
            base_x10 = (int)(sum / n);
            base_usat = (int)((usum + n / 2) / n);
            base_trk = (int)((tsum + n / 2) / n);
            base_nsat = (int)((nsum + n / 2) / n);
            have_base = 1;
        }
    }
    /* No satellite tracked, the sky still listed: every one fell out. */
    const int level = cur->trk > 0 ? cur->cn0_med_x10 : 0;
    int collapse = 0;
    if (have_base && cur->nsat > 0) {
        int fell = base_x10 - level;
        int usat_fell = (int)cur->usat + GNSS_JAM_USAT_FALL <= base_usat;
        int nsat_held = (int)cur->nsat + GNSS_JAM_NSAT_FALL > base_nsat;
        if (fell >= drop_x10 && (nsat_held || g_gnss.jam_active) &&
            (usat_fell || fix_lost || g_gnss.jam_active))
            collapse = 1;
    }
    if (collapse && !g_gnss.jam_active) {
        g_gnss.jam_active = 1;
        g_gnss.jam_base_x10 = base_x10;
        g_gnss.jam_base_usat = base_usat;
        g_gnss.jam_base_trk = base_trk;
        g_gnss.jam_base_nsat = base_nsat;
    } else if (!collapse) {
        g_gnss.jam_active = 0;
    }

    /* (b) the indicator, held */
    const int jthr = (int)tune_val(TUNE_GNSS_JAM_IND);
    const uint64_t hold_ms = (uint64_t)tune_val(TUNE_GNSS_JAM_HOLD_S) * 1000;
    uint64_t run_from = 0;
    int jam_min = 255;
    for (int i = h->sec_n - 1; i >= 0; i--) {
        const gnss_sec_pt_t *p = sec_at(h, i);
        if (p->jam < jthr) break;
        if (run_from && run_from > p->mono_ms + GNSS_JAM_GAP_MS) break;
        run_from = p->mono_ms;
        if (p->jam < jam_min) jam_min = p->jam;
    }
    /* Each one-second point stands for its second, so a run of N
     * points spans N seconds. */
    int held = run_from && cur->mono_ms - run_from + 1000 >= hold_ms;

    if (!collapse && !held) return;

    char key[32];
    akey_t ak;
    akey_begin(&ak, key, sizeof(key), "gnssjam");
    if (!akey_end(&ak)[0]) return;

    char what[192] = "";
    if (collapse)
        snprintf(what, sizeof(what),
                 "tracked median C/N0 %d.%d -> %d.%d dB-Hz (-%d.%d dB, window "
                 "%ld s), tracked %d -> %d, used %d -> %d, %d still listed",
                 base_x10 / 10, base_x10 % 10, level / 10, abs(level % 10),
                 (base_x10 - level) / 10, abs((base_x10 - level) % 10),
                 tune_val(TUNE_GNSS_JAM_WINDOW_S),
                 base_trk, (int)cur->trk,
                 base_usat, (int)cur->usat, (int)cur->nsat);
    char ind[64] = "";
    if (held)
        snprintf(ind, sizeof(ind), "%su-blox jamInd >= %d for %lu s",
                 collapse ? "; " : "", jam_min,
                 (unsigned long)((cur->mono_ms - run_from + 1000) / 1000));
    /* The figures run to ~230 bytes with both paths, inside
     * ALERT_DETAIL_LEN; sized for the format's worst case, as
     * GNSS_SPOOF_SUSPECT's is, and the engine bounds what it keeps. */
    char detail[512];
    snprintf(detail, sizeof(detail),
             "%s%s%s - interference or jamming: the receiver cannot tell "
             "which (DHS 2017), nor locate the source",
             what, ind, fix_lost ? "; fix lost" : "");
    fire(ALERT_TYPE_GNSS_JAMMING, fix_lost ? ALERT_SEV_CRIT : ALERT_SEV_WARN,
         "GNSS_JAMMING", detail, key, NULL, 0, now);
}

/* ── GNSS_TIME_JUMP ──────────────────────────────────────────────────
 *
 * The receiver's time steps by at least gnss.time_jump_ms between the
 * last accepted fix (the anchor) and a positioned fix, measured against
 * the host's MONOTONIC clock: (rx_b - rx_a) - (mono_b - mono_a). That is
 * the clock offset's step with the host's own wall-clock step taken
 * out, so an NTP step or an operator's `date -s` on the host moves
 * time_off_ms and never fires this; the detail reports both.
 *
 * mono_b is when sloth read the TPV, not when the receiver produced it,
 * so read latency enters the step. Latency only ever makes a fix look
 * late, and the rule meets each way it does:
 *   - the step must hold on the next fix (within half the threshold): a
 *     single late or wild TPV is followed by one back on time, a moved
 *     clock stays moved;
 *   - a fix read from a queue (read_from_queue(): the next fix is
 *     further on in receiver time than in host time by GNSS_BACKLOG_MS)
 *     is not judged: after a stall the reader drains a second of epochs
 *     per millisecond, each late by what is left of the stall, and at a
 *     raised threshold their 1 s steps back are under the hold's half;
 *   - a fix read late (read_lateness(), #182: on the reads since the
 *     anchor where the receiver kept its fix interval, the host's gaps
 *     ran more than GNSS_BACKLOG_MS past the receiver's) is not judged.
 *     This is the queued read's mirror, and it is needed because a
 *     reader late by a steady amount on every fix passes the queue test
 *     (each next fix is no further on in receiver time than in host
 *     time) and the hold then confirms the lag instead of rejecting it:
 *     a starved reader 1.5 s behind read as a held -1500 ms step, and
 *     its recovery as a held +1500 ms one. The lateness is summed from
 *     the anchor, not taken from the last pair, because only the read
 *     where the reader fell behind shows a long gap; the reads after it
 *     are as late and a second apart. A real step at the ordinary
 *     cadence is untouched: its host gap is the interval and its
 *     receiver gap is off it by at least the threshold, past the half
 *     threshold the sum allows. So the hold now only ever sees a fix
 *     read on time against an anchor read on time. A lateness that
 *     stands GNSS_LATE_REBASE_MS is re-anchored on, unjudged, so a
 *     reader permanently slower does not blind the rule; a real step
 *     inside such a run is absorbed with it;
 *   - none of these becomes the anchor, so each fix after a run of
 *     them is measured from the last good one. The first draft measured
 *     the pair after an outlier from the fix before it, itself an
 *     outlier in a drained queue, and fired on a four-second Ctrl-Z.
 * A host suspend stops CLOCK_MONOTONIC and neither the receiver's clock
 * nor the host's wall clock: both move past it together
 * (host_suspended()), and that fix is a reacquisition, not a jump.
 *
 * Default 1000 ms, floor 200 ms. Humphreys et al. 2008's "flag jumps of
 * more than, say, 100 ns" is a receiver-internal figure; through gpsd
 * on USB with no PPS the HOWTO says the delay "may be stable to 10 mSec
 * for hours and then jump by 200mSec", so 200 ms is the cited lower
 * bound and "anything below roughly a second is noise on its own
 * terms" (research/gnss/time-and-position-integrity.md).
 *
 * Not judged: the first fix after a start, a no-fix TPV, a lost source
 * or a suspend (a cold start "must search the full time and frequency
 * space"; "compare only fix to fix"), a leap second and a week-rollover
 * signature (time_step_benign()). Why it matters: a receiver steering
 * the host clock through a `trust`ed chrony refclock outvotes every NTP
 * server; this catches the impatient step, not a patient pull. WARN. */
static void set_anchor(const gnss_fix_pt_t *p) {
    g_gnss.anchor = *p;
    g_gnss.has_anchor = 1;
    g_gnss.late_mono = 0;
}

void rule_gnss_time_jump(const sloth_state_t *s, time_t now) {
    const gnss_hist_t *h = s->gnss_hist ? s->gnss_hist : &g_empty;
    const long long thr = (long long)tune_val(TUNE_GNSS_TIME_JUMP_MS);
    const long long iv = fix_interval_ms(h);
    for (int i = 0; i < h->fix_n; i++) {
        const gnss_fix_pt_t *b = fix_at(h, i);
        if (b->seq <= g_gnss.time_seq) continue;
        const gnss_fix_pt_t *a = g_gnss.has_anchor ? &g_gnss.anchor : NULL;
        /* Nothing to step from: b is the new reference. A fix from
         * before alerts_clear() is a reference and never a finding. */
        if (b->mono_ms <= g_gnss.forget_mono || b->reacq || !a ||
            !time_pair_ok(a, b)) {
            set_anchor(b);
            g_gnss.time_seq = b->seq;
            continue;
        }
        /* A late read (#182): neither judged nor the anchor, like a
         * queued one. A lateness standing GNSS_LATE_REBASE_MS, or one
         * whose anchor has left the ring, is the reader's new normal:
         * re-anchor on it unjudged rather than go blind. */
        long long late = 0;
        int have_late = read_lateness(h, i, a, iv, thr / 2, &late);
        if (!have_late && g_gnss.late_mono) late = GNSS_BACKLOG_MS + 1;
        if (llabs_(late) > GNSS_BACKLOG_MS) {
            g_gnss.time_seq = b->seq;
            if (!g_gnss.late_mono) g_gnss.late_mono = b->mono_ms;
            if (!have_late || b->mono_ms >= g_gnss.late_mono + GNSS_LATE_REBASE_MS)
                set_anchor(b);
            continue;
        }
        g_gnss.late_mono = 0;
        long long step = rx_step(a, b);
        if (llabs_(step) < thr || time_step_benign(a, b, step) ||
            host_suspended(a, b, step, thr)) {
            set_anchor(b);
            g_gnss.time_seq = b->seq;
            continue;
        }
        /* Confirm on the next fix; without one yet, judge b next tick. */
        if (i + 1 >= h->fix_n) break;
        const gnss_fix_pt_t *c = fix_at(h, i + 1);
        g_gnss.time_seq = b->seq;
        if (c->reacq || !time_pair_ok(b, c)) continue;
        if (read_from_queue(b, c)) continue;
        if (llabs_(rx_step(b, c)) >= thr / 2) continue;

        char key[32];
        akey_t ak;
        akey_begin(&ak, key, sizeof(key), "gnsstime");
        if (!akey_end(&ak)[0]) return;
        long long hs = host_step(a, b);
        long long read_gap = (long long)(b->mono_ms - a->mono_ms);
        long long rx_gap = b->rx_time_ms - a->rx_time_ms;
        char detail[ALERT_DETAIL_LEN];
        snprintf(detail, sizeof(detail),
                 "receiver time stepped %+lld ms against the host's monotonic "
                 "clock, held on the next fix; reads %lld ms apart, receiver "
                 "times %lld ms apart, fix interval %lld ms; "
                 "clock offset %+lld -> %+lld ms, host clock step %+lld ms; "
                 "leap %d -> %d, not a leap second or week rollover",
                 step, read_gap, rx_gap, iv,
                 a->has_time_off ? a->time_off_ms : 0,
                 b->has_time_off ? b->time_off_ms : 0, hs, a->leap, b->leap);
        set_anchor(b);
        fire(ALERT_TYPE_GNSS_TIME_JUMP, ALERT_SEV_WARN, "GNSS_TIME_JUMP",
             detail, key, NULL, 0, now);
    }
}

/* ── GNSS_POSITION_JUMP ──────────────────────────────────────────────
 *
 * Two consecutive positioned fixes (mode >= 2 both: the ring holds no
 * other) farther apart than pos_bound_m(). Psiaki & Humphreys §III-C:
 * "the known maxima of its velocity, acceleration, and turn rate could
 * be used to check for excessive drift"; §II-D's spoof was caught by
 * speeds "above 900 kts" for a vessel that "could not cruise above 16
 * kts". For a fixed sensor reporting speed 0 the bound collapses to the
 * two error estimates, as the research says it must.
 *
 * k = gnss.pos_jump_k, default 3: "Because the confidence level of
 * eph is unknown, a multiplier on it is a judgement, not a cited
 * value." Three covers eph read as one sigma (the least conservative of
 * gpsd's four readings) to three sigma per fix. Spens et al.'s 100 m is
 * a phone's network-location check and is not used.
 *
 * Not judged: a reacquisition (the first fix after a start, a no-fix
 * TPV or a lost source: "The first fix after mode 1 has no prior to jump
 * from"), and a pair either of whose fixes has no eph. Multipath at a
 * fixed site can still exceed the bound; the error estimate "may not
 * cover it" (the research's own false positive). WARN. */
void rule_gnss_position_jump(const sloth_state_t *s, time_t now) {
    const gnss_hist_t *h = s->gnss_hist ? s->gnss_hist : &g_empty;
    const long k = tune_val(TUNE_GNSS_POS_JUMP_K);
    for (int i = 1; i < h->fix_n; i++) {
        const gnss_fix_pt_t *a = fix_at(h, i - 1), *b = fix_at(h, i);
        if (b->seq <= g_gnss.pos_seq) continue;
        g_gnss.pos_seq = b->seq;
        if (b->mono_ms <= g_gnss.forget_mono || b->reacq) continue;
        if (a->mode < 2 || b->mode < 2) continue;
        double dt = fix_dt_s(a, b), v = 0, e = 0;
        double bound = pos_bound_m(a, b, dt, k, &v, &e);
        if (bound < 0) continue;
        double d = gps_distance_m(a->lat, a->lon, b->lat, b->lon);
        if (!(d > bound)) continue;

        char key[32];
        akey_t ak;
        akey_begin(&ak, key, sizeof(key), "gnsspos");
        if (!akey_end(&ak)[0]) return;
        char detail[ALERT_DETAIL_LEN];
        snprintf(detail, sizeof(detail),
                 "fix moved %.0f m in %.1f s, past the %.0f m bound: speed "
                 "%.1f m/s + eps %.1f m/s, eph %.1f + %.1f m x %ld; a spoofed "
                 "position, multipath or a receiver fault look alike here",
                 d, dt, bound, v, e, a->eph, b->eph, k);
        fire(ALERT_TYPE_GNSS_POSITION_JUMP, ALERT_SEV_WARN,
             "GNSS_POSITION_JUMP", detail, key, NULL, 0, now);
    }
}

/* ── GNSS_SPOOF_SUSPECT ──────────────────────────────────────────────
 *
 * Fires only when at least two of three heuristics were each seen
 * within gnss.spoof_window_s, and says which. The research is explicit
 * that each is weak alone and that "nothing short of cryptographic
 * authentication can guard against a sophisticated spoofing attack"
 * (Humphreys et al. 2008 §VII), so this is a suspicion: LOW on two,
 * WARN on all three, never CRIT.
 *
 * H1, absolute C/N0 too high: at least gnss.spoof_high_sats used
 *     satellites at or above gnss.spoof_cn0_high_db. Basis: Received
 *     Power Monitoring (Psiaki & Humphreys §III-A), its per-signal half,
 *     the only half gpsd exports. Default 53 dB-Hz is Kriezis et al.'s
 *     spoofing threshold for a u-blox F9P with an ANN-MB antenna, 8 dB
 *     above the top of the nominal "~ 37 to 45dB-Hz" (Inside GNSS);
 *     "Neither number transfers to a u-blox 7 with an unknown antenna",
 *     so it is the conservative choice, not a calibrated one. Four
 *     satellites because four is what a spoofer must supply to steer a
 *     fix. False positives: a high-gain or amplified antenna, a GPS
 *     repeater.
 * H2, C/N0 uniform and high: over at least gnss.spoof_min_sats used
 *     satellites with a C/N0, the spread under gnss.spoof_cn0_sd_db and
 *     the mean at or above gnss.spoof_cn0_mean_db. Basis weak by the
 *     research's own account: one transmitter erases the elevation
 *     dependence authentic signals show (Inside GNSS), and "No
 *     peer-reviewed source read for this document states a uniformity
 *     (low-spread) threshold". Default 1 dB, below what a sky across
 *     elevations shows, and six satellites so the spread means
 *     something; the mean gate (45, the nominal band's top) keeps out
 *     the indoor case, where every signal arrives equally attenuated.
 * H3, reacquisition with a jump: the first fix after a no-fix TPV or a
 *     lost source lies outside the position bound from the last fix
 *     before it, or its time stepped by gnss.time_jump_ms against the
 *     monotonic clock (leap and rollover excluded). Psiaki & Humphreys
 *     §II-B: jam "to disrupt normal tracking and induce re-acquisition",
 *     then the receiver "will lock with high probability onto the false
 *     signals"; Humphreys et al. 2008 §II: "Such a forced re-acquisition
 *     would raise suspicion". False positives: cold or warm start, USB
 *     re-enumeration, a moving receiver passing under cover.
 *
 * Not observable here, and so not used: elevation/azimuth checks and
 * DOP consistency (no read source gives a test or a tolerance), and
 * clock drift (no oscillator class for the u-blox 7 was found). */
void rule_gnss_spoof_suspect(const sloth_state_t *s, time_t now) {
    const gnss_sky_t *k = &s->gnss_sky;
    const gnss_hist_t *h = s->gnss_hist ? s->gnss_hist : &g_empty;
    uint64_t now_m = sloth_mono_ms();

    if (k->valid && k->mono_ms && now_m <= k->mono_ms + GNSS_LIVE_MS) {
        const int hi_x10 = (int)tune_val(TUNE_GNSS_SPOOF_CN0_HIGH_DB) * 10;
        int n_hi = 0, mx = 0, n = 0;
        double sum = 0, sq = 0;
        for (int i = 0; i < k->n && i < GNSS_MAX_SATS; i++) {
            const gnss_sat_t *a = &k->sats[i];
            if (!a->used || !a->has_cn0 || a->cn0_x10 <= 0) continue;
            if (a->cn0_x10 >= hi_x10) n_hi++;
            if (a->cn0_x10 > mx) mx = a->cn0_x10;
            double c = a->cn0_x10 / 10.0;
            sum += c;
            sq += c * c;
            n++;
        }
        if (n_hi >= tune_val(TUNE_GNSS_SPOOF_HIGH_SATS)) {
            g_gnss.h_mono[0] = now_m;
            g_gnss.h1_n = n_hi;
            g_gnss.h1_max_x10 = mx;
        }
        if (n >= tune_val(TUNE_GNSS_SPOOF_MIN_SATS)) {
            double mean = sum / n, var = sq / n - mean * mean;
            double sd = var > 0 ? sqrt(var) : 0.0;
            if (mean >= (double)tune_val(TUNE_GNSS_SPOOF_CN0_MEAN_DB) &&
                sd < (double)tune_val(TUNE_GNSS_SPOOF_CN0_SD_DB)) {
                g_gnss.h_mono[1] = now_m;
                g_gnss.h2_n = n;
                g_gnss.h2_mean_x10 = (int)(mean * 10.0 + 0.5);
                g_gnss.h2_sd_x10 = (int)(sd * 10.0 + 0.5);
            }
        }
    }

    const long kk = tune_val(TUNE_GNSS_POS_JUMP_K);
    const long long thr = (long long)tune_val(TUNE_GNSS_TIME_JUMP_MS);
    for (int i = 1; i < h->fix_n; i++) {
        const gnss_fix_pt_t *a = fix_at(h, i - 1), *b = fix_at(h, i);
        if (b->seq <= g_gnss.spoof_seq) continue;
        g_gnss.spoof_seq = b->seq;
        if (b->mono_ms <= g_gnss.forget_mono || !b->reacq) continue;
        double dt = fix_dt_s(a, b);
        double bound = pos_bound_m(a, b, dt, kk, NULL, NULL);
        double d = gps_distance_m(a->lat, a->lon, b->lat, b->lon);
        long long step = time_pair_ok(a, b) ? rx_step(a, b) : 0;
        int moved = bound >= 0 && d > bound;
        int stepped = llabs_(step) >= thr && !time_step_benign(a, b, step) &&
                      !host_suspended(a, b, step, thr);
        if (!moved && !stepped) continue;
        g_gnss.h_mono[2] = b->mono_ms;
        g_gnss.h3_dist_m = moved ? d : 0.0;
        g_gnss.h3_step_ms = stepped ? step : 0;
    }

    const uint64_t win = (uint64_t)tune_val(TUNE_GNSS_SPOOF_WINDOW_S) * 1000;
    int seen[3], nseen = 0;
    for (int i = 0; i < 3; i++) {
        seen[i] = g_gnss.h_mono[i] && g_gnss.h_mono[i] > g_gnss.forget_mono &&
                  now_m <= g_gnss.h_mono[i] + win;
        nseen += seen[i];
    }
    if (nseen < 2) return;

    char key[32];
    akey_t ak;
    akey_begin(&ak, key, sizeof(key), "gnssspoof");
    if (!akey_end(&ak)[0]) return;
    char p1[64] = "", p2[80] = "", p3[96] = "";
    if (seen[0])
        snprintf(p1, sizeof(p1), "[1] %d used >= %ld dB-Hz (max %d.%d); ",
                 g_gnss.h1_n, tune_val(TUNE_GNSS_SPOOF_CN0_HIGH_DB),
                 g_gnss.h1_max_x10 / 10, g_gnss.h1_max_x10 % 10);
    if (seen[1])
        snprintf(p2, sizeof(p2), "[2] %d used, mean %d.%d sd %d.%d dB-Hz; ",
                 g_gnss.h2_n, g_gnss.h2_mean_x10 / 10, g_gnss.h2_mean_x10 % 10,
                 g_gnss.h2_sd_x10 / 10, g_gnss.h2_sd_x10 % 10);
    if (seen[2])
        snprintf(p3, sizeof(p3), "[3] reacquired %.0f m away, time %+lld ms; ",
                 g_gnss.h3_dist_m, g_gnss.h3_step_ms);
    /* All three parts with their figures run to ~250 bytes, inside
     * ALERT_DETAIL_LEN; the buffer is sized for the format's worst case
     * so nothing is cut here, and the engine bounds what it keeps. */
    char detail[512];
    snprintf(detail, sizeof(detail),
             "%d of 3 spoofing heuristics within %ld s: %s%s%s"
             "each is weak alone - a repeater, an amplified antenna or a "
             "cold start can explain one",
             nseen, tune_val(TUNE_GNSS_SPOOF_WINDOW_S), p1, p2, p3);
    fire(ALERT_TYPE_GNSS_SPOOF_SUSPECT, nseen >= 3 ? ALERT_SEV_WARN : ALERT_SEV_LOW,
         "GNSS_SPOOF_SUSPECT", detail, key, NULL, 0, now);
}
