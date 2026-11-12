#ifndef PROBE_LATENCY_H
#define PROBE_LATENCY_H

#include <stdint.h>
#include <time.h>
#include "dot11_frame.h"

/* ── Probe-response latency, per BSSID (#187 S3) ─────────────────────
 *
 * The time from a station's Probe Request to the Probe Response a BSSID
 * addresses back to that station, measured from the monitor capture.
 *
 * OBSERVATION ONLY. No cited threshold, not used in any verdict: no
 * alert rule, no KARMA score and no confidence reads it. The hypothesis
 * that a lure (hostapd-mana, airbase-ng, a PineAP radio) answers with a
 * measurably different latency from a real AP has no primary source
 * giving a direction or a magnitude — see
 * research/papers/probe-response-latency.md for what was read and why
 * the tools' own source code does not supply one either (they answer
 * through the same userspace path stock hostapd uses on any driver
 * without probe-response offload). The figure is measured so that a
 * source, or sloth's own captures of a known lure, can decide later.
 *
 * Clock. Both ends of a pair are stamped from one clock:
 *   PLAT_SRC_TSFT — radiotap TSFT on both frames: the receiver's own
 *                   802.11 TSF at the first bit of each MPDU, 1 µs
 *                   resolution, one hardware counter, no host jitter.
 *   PLAT_SRC_PCAP — otherwise, the pcap header timestamp on both: the
 *                   host's receive time, nominally 1 µs but carrying
 *                   driver, interrupt and USB batching delay.
 * The two are never mixed in one pair, nor in one BSSID's distribution
 * (a TSFT sample replaces a PCAP-only history; a PCAP sample is refused
 * by a TSFT row). TSFT measures start-of-request to start-of-response,
 * so the request's own airtime is inside the figure.
 *
 * Validity. A pair is formed only when:
 *   - both frames were heard in ONE dwell: the module numbers dwells
 *     from the radiotap frequency of every frame it is shown, so a
 *     --hop retune between request and response voids the pair (and a
 *     frame with no frequency cannot be placed in a dwell at all);
 *   - the request is the only live, unambiguous candidate: a request
 *     heard twice under one sequence number (a retransmission — which
 *     copy the AP answered is unknowable) is voided, and two distinct
 *     live requests that the same response could answer void the pair;
 *   - the response is a first transmission (Retry clear), and is the
 *     first answer this BSSID gave that request (hostapd-mana answers a
 *     wildcard probe with one response per remembered SSID, airbase-ng
 *     sends a broadcast-probe answer three times; only the first is a
 *     latency);
 *   - the response names the requested SSID (or the request was a
 *     wildcard), and a request addressed to one BSSID is answered by it;
 *   - 0 <= latency <= PLAT_PAIR_MAX_US.
 * Every refusal is counted (probe_latency_counters()).
 *
 * Window. Each BSSID keeps its last PLAT_SAMPLES pairs per kind
 * (directed, wildcard); the statistics are over those.
 *
 * Bounds. PLAT_PENDING requests and PLAT_MAX_BSS rows, both evicting the
 * oldest and tallying it. The tally is module-local for now: an
 * SH_EVICT_* kind would add an `evict_*` member to the sensor_health
 * JSONL record, and that change waits for the JSONL 1.6.0 bump.
 *
 * Thread model: probe_latency_observe() runs on the monitor capture
 * thread; every reader runs on the poll / UI thread. One mutex. */

#define PLAT_PENDING     64
#define PLAT_MAX_BSS     128
#define PLAT_SAMPLES     32
/* Engineering bound, not a threshold: the longest probe-wait any of the
 * three NICs in Mishra, Shin & Arbaugh (2003) §5.2 spent on a channel
 * was ~73 ms, and every probe response they saw arrived within 15 ms
 * (§5.3). A response 200 ms after the request is not one the station
 * was waiting on. */
#define PLAT_PAIR_MAX_US 200000u

enum { PLAT_SRC_NONE = 0, PLAT_SRC_PCAP = 1, PLAT_SRC_TSFT = 2 };
enum { PLAT_KIND_DIRECTED = 0, PLAT_KIND_WILDCARD = 1, PLAT_KIND_COUNT = 2 };

/* What the capture said about a frame's timing and channel. */
typedef struct {
    int      freq_mhz;   /* radiotap channel frequency, 0 when absent */
    int      has_tsft;
    uint64_t tsft_us;
    long     ts_sec;     /* pcap header timestamp */
    long     ts_usec;
} plat_clock_t;

/* Nearest-rank percentiles over the window (p50 is the lower median). */
typedef struct {
    uint32_t n;
    uint32_t min_us, p10_us, med_us, p90_us;
} plat_stats_t;

typedef struct {
    uint8_t      bssid[6];
    int          src;              /* PLAT_SRC_*: the clock of every sample */
    uint64_t     pairs_total;      /* lifetime pairs, both kinds */
    time_t       last_seen;        /* pcap seconds of the last pair */
    plat_stats_t kind[PLAT_KIND_COUNT];
} probe_latency_row_t;

typedef struct {
    uint64_t pairs;            /* samples recorded */
    uint64_t no_freq;          /* frames with no radiotap frequency */
    uint64_t dwells;           /* dwell boundaries seen (frequency changes) */
    uint64_t req_dup;          /* request heard again under one seq: voided */
    uint64_t resp_retry;       /* response with Retry set: ignored */
    uint64_t resp_extra;       /* 2nd+ answer by one BSSID to one request */
    uint64_t resp_ambiguous;   /* >1 live request could be the one answered */
    uint64_t resp_unpaired;    /* no live request in this dwell matched */
    uint64_t clock_backwards;  /* response stamped before its request */
    uint64_t src_mismatch;     /* PCAP sample refused by a TSFT row */
    uint64_t src_switch;       /* PCAP history dropped for TSFT */
    uint64_t evict_pending;    /* live request overwritten unanswered */
    uint64_t evict_bss;        /* BSSID row evicted (oldest) */
} plat_counters_t;

/* Shown every decoded monitor frame (it numbers dwells from all of
 * them); pairs only plaintext Probe Request / Probe Response with a
 * readable header and a good FCS. Thread-safe. */
void probe_latency_observe(const dot11_frame_t *f, const plat_clock_t *clk);

/* One BSSID's statistics. Returns 1 when the BSSID has a row. */
int probe_latency_get(const uint8_t bssid[6], probe_latency_row_t *out);

/* Up to `max` rows, unordered. Returns the number written. */
int probe_latency_snapshot(probe_latency_row_t *out, int max);

void probe_latency_counters(plat_counters_t *out);

/* Tests only: empty every table and counter. */
void probe_latency_reset(void);

#endif /* PROBE_LATENCY_H */
