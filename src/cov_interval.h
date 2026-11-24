#ifndef SLOTH_COV_INTERVAL_H
#define SLOTH_COV_INTERVAL_H

#include <stdint.h>
#include <time.h>

/* ── The per-interval coverage record (#242 item 2) ───────────────────
 *
 * rule_status says which rules CAN fire. This says what the sensor
 * actually did in the last minute: where its monitor radios were and
 * for how long, what they heard by frame class, what the capture
 * handles dropped, and which sources were up at the end. A quiet
 * minute with 50 s on 2.4 GHz and none on 5 GHz is not a quiet 5 GHz.
 *
 * A measurement on a fixed cadence, not a change feed: one record every
 * COV_IV_MS, whatever it holds. Written to the stream as
 * `coverage_interval` and to sloth.db as a `coverage_intervals` row.
 *
 * Two halves, as rule_coverage_live.h. This file holds the interval
 * being built, the last COV_IV_RING closed ones, and the writers; it
 * names no capture module, so db.c can read it and it links into
 * sloth-rf, which feeds it nothing. The figures come from a sampler
 * on the capture side (src/cov_interval_capture.c), which runs from
 * sloth-wifi's poll table after the hop stage.
 *
 * Receive-only: every figure is a counter sloth already keeps. */

/* One record a minute (#242's proposal). Not a tunable: a record's
 * shares and counts are compared across sensors and across time, and
 * that needs one length. A partial interval at shutdown is not
 * written. */
#define COV_IV_MS       60000

/* The channels one record holds: the most a --hop list has
 * (CHANHOP_MAX). Under --hop the radios' shares are disjoint, so this
 * is every channel; a re-deal after a radio is lost can put one channel
 * on two radios in one interval, and an entry beyond the bound is
 * counted in chan_overflow rather than written. */
#define COV_IV_CHAN_MAX 32

/* Closed intervals kept for the database, whose write tick can be
 * longer than one interval (--db-interval-secs). */
#define COV_IV_RING     8

/* Frame classes. The first nine are the COV_F_* bits of rule_coverage.h
 * in bit order (class i is bit 1u << i); then a frame whose FCS was
 * good and that is in none of them (an extension frame, a management
 * subtype no rule reads), then a frame radiotap marked FCS-failed,
 * whose type is not trusted. Every frame the monitor path records is
 * in exactly one, so the classes sum to the frames received. */
enum {
    COV_FC_BEACON = 0, COV_FC_PROBE, COV_FC_AUTH, COV_FC_ASSOC,
    COV_FC_DEAUTH, COV_FC_ACTION, COV_FC_CTRL, COV_FC_DATA, COV_FC_EAPOL,
    COV_FC_OTHER, COV_FC_FCS_BAD,
    COV_FC_N
};
/* "beacon", "probe", ..., "eapol", "other", "fcs_bad". */
const char *cov_fc_name(int fc);

/* Bands of the interval's radio time: the COV_B_* bits in order, then
 * a channel whose frequency is not known (a fixed radio that has heard
 * no frame yet). */
enum { COV_IVB_24 = 0, COV_IVB_5, COV_IVB_5DFS, COV_IVB_6, COV_IVB_UNKNOWN,
       COV_IVB_N };
/* "2.4", "5", "5dfs", "6", "unknown". */
const char *cov_ivb_name(int b);
/* The band a frequency is in; COV_IVB_UNKNOWN for 0 or no band. */
int cov_ivb_of_mhz(int mhz);

typedef struct {
    int      radio;      /* 0 is the --monitor-iface radio, 1.. the others */
    int      freq_mhz;   /* 0: not known */
    int      channel;
    uint64_t ms;         /* time the radio was on it in the interval */
    uint64_t frames;     /* frames it delivered there */
} cov_iv_chan_t;

/* The sources at the interval's end: name and state word, rows that are
 * not configured left out. Pointers to static strings. */
#define COV_IV_SRC_MAX  12
typedef struct {
    const char *name;
    const char *state;
} cov_iv_src_t;

typedef struct {
    uint32_t seq;            /* 1 for the first closed interval */
    time_t   start, end;     /* wall clock */
    uint64_t dur_ms;         /* measured on the monotonic clock */
    int      nchan, chan_overflow;
    cov_iv_chan_t chan[COV_IV_CHAN_MAX];
    uint64_t band_ms[COV_IVB_N];
    uint64_t radio_ms;       /* the sum of band_ms */
    uint64_t frames[COV_FC_N];
    /* Drops in the interval; has_* 0 when the handle was not open with
     * a pcap_stats() sample at both ends, and the figure is then not
     * written (NULL in sloth.db), never 0 for "not measured". */
    int      has_cap, has_mon;
    uint64_t cap_drop, cap_ifdrop, mon_drop, mon_ifdrop;
    int      nsrc;
    cov_iv_src_t src[COV_IV_SRC_MAX];
} cov_iv_t;

/* ── Building (the sampler's side) ── */

/* Add time and frames on (radio, freq) to the open interval; merged
 * with an entry of the same radio and frequency. */
void cov_iv_add(int radio, int freq_mhz, int channel, uint64_t ms,
                uint64_t frames);

/* The open interval's begin, when there is none: wall, monotonic ms. 1
 * when it opened one. */
int  cov_iv_open(time_t wall, uint64_t mono_ms);
int  cov_iv_is_open(void);
/* Whether the open interval is COV_IV_MS old at mono_ms. */
int  cov_iv_due(uint64_t mono_ms);
/* Close the open interval with the class counts, the drops and the
 * sources given (any may be NULL: none), publish it as the newest
 * closed one, and open the next at (wall, mono_ms). `frames` has
 * COV_FC_N entries. */
void cov_iv_close(time_t wall, uint64_t mono_ms, const uint64_t *frames,
                  int has_cap, uint64_t cap_drop, uint64_t cap_ifdrop,
                  int has_mon, uint64_t mon_drop, uint64_t mon_ifdrop);
/* Drop the open interval without publishing it (a run that stops being
 * assessable, a --replay). */
void cov_iv_abandon(void);

/* ── Reading ── */

/* The newest closed interval's seq, 0 none yet. */
uint32_t cov_iv_seq(void);
/* The closed interval `seq`, if it is still in the ring. 1 and *out. */
int  cov_iv_get(uint32_t seq, cov_iv_t *out);

/* The JSONL hook: a `coverage_interval` line for each interval closed
 * since the last call that is still in the ring. */
void cov_iv_emit(void);

/* The chans and sources members as JSON arrays, exactly as the record
 * writes them, for the database's two text columns. Length written. */
int  cov_iv_chans_json(const cov_iv_t *iv, char *out, int sz);
int  cov_iv_srcs_json(const cov_iv_t *iv, char *out, int sz);

void cov_iv_reset(void);

#endif /* SLOTH_COV_INTERVAL_H */
