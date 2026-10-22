/* slothweb metric derivation (#160, M2): records in, samples out.
 *
 * The ingest thread hands every decoded record here after the live
 * state has seen it. Each one becomes zero or more samples on the
 * rollup (web_rollup.h), keyed by a canonical form of a value the
 * record carries: a MAC is lower-case xx:xx:xx:xx:xx:xx, an IP is what
 * inet_ntop() writes back for what inet_pton() accepted, an interface
 * name is 1..15 bytes of [A-Za-z0-9_.:@-], a channel is its number (a
 * 6 GHz one prefixed "6g", since 5 and 6 GHz share numbers), an alert
 * type is ty as a decimal. A record whose key does not pass is not
 * counted, so nothing a peer wrote ever becomes a key verbatim.
 *
 * Counters that sloth reports as running totals (frame_count, count,
 * banner_count, ctrl_total, ...) are turned into deltas against the
 * last value seen for the same row, floored at zero: a row sloth
 * evicted and made again restarts its total, and that must not read as
 * a negative burst (§5.1). The first sight of a row on a connection is
 * a baseline (no delta) unless the row's own first_seen is no earlier
 * than the first record of the connection, i.e. it was born while we
 * were listening. So a reconnect, which re-sends every row at its full
 * total, is not counted as one huge burst. Rows without first_seen
 * (seqnum_client, channel_summary) are always a baseline on first
 * sight. High-water rows are held in a bounded table, least recently
 * used out first; evictions are counted.
 *
 * wifi.probe_clients and conns.total are rows per snapshot pass. A pass
 * runs from one batch start (the first `iface` record after another
 * poll-thread record, as web_live.c counts devices) to the next;
 * `connections` is written just before the `iface` records of its own
 * tick, so the window that closes at a batch start holds exactly that
 * tick's connections and the previous tick's probe clients. A window
 * that a socket_gap or an undecodable line may have cut is not
 * sampled, nor is the partial one a connection starts in.
 *
 * Bucketing uses the clock passed at init, never a record's ts. */
#ifndef SLOTHWEB_METRICS_H
#define SLOTHWEB_METRICS_H

#include <stddef.h>

#include "web_jsonl.h"
#include "web_rollup.h"

#define WEB_HW_ROWS   4096
#define WEB_HW_ID_MAX 159

typedef struct {
    char               id[WEB_HW_ID_MAX + 1];
    int                used, next;
    long long          v;
    unsigned long long touched;
} web_hw_t;

typedef long long (*web_clock_fn)(void *ctx);

typedef struct web_metrics {
    web_rollup_t *ru;
    web_clock_fn  clock;
    void         *clock_ctx;

    web_hw_t     *hw;
    int          *hw_head;
    int           hw_n, hw_cap, hw_nhead;
    unsigned long long touch;

    int       have_first_ts;
    long long first_ts;
    int       in_iface, batch_open, taint;
    long      probe_n, conns_n;
} web_metrics_t;

/* clock returns unix seconds; NULL means time(). 0, or -1 (memory). */
int  web_metrics_init(web_metrics_t *m, web_rollup_t *ru, web_clock_fn clock,
                      void *clock_ctx);
void web_metrics_destroy(web_metrics_t *m);

/* A new connection: a new stream, so every high-water mark and pass in
 * progress is forgotten. */
void web_metrics_stream(web_metrics_t *m);
/* A line was lost (undecodable, overlong): the pass in progress is not
 * sampled. */
void web_metrics_taint(web_metrics_t *m);
void web_metrics_record(web_metrics_t *m, const web_jrec_t *r);

/* Key canonicalisers; out holds WEB_KEY_MAX + 1. 0, or -1 when s is not
 * one. Also what /api/series checks its key parameter with. */
int  web_key_mac(const char *s, char *out);
int  web_key_ip(const char *s, char *out);
int  web_key_iface(const char *s, char *out);
/* channel 1..233; band is the record's band word ("6 GHz" gives 6g). */
int  web_key_channel(long long ch, const char *band, char *out);
/* A channel key as /api/series takes it: "N" or "6gN". */
int  web_key_channel_text(const char *s, char *out);
int  web_key_alert_type(long long ty, char *out);
/* The canonical key for metric from the text s, by its key kind; "" for
 * a global metric (s must then be empty). */
int  web_key_canon(int metric, const char *s, char *out);

#endif
