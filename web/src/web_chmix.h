/* slothweb's channel mix: who is transmitting on each channel.
 *
 * The WiFi view's channel x time grid says how busy a channel was; the
 * mix says who made it busy. Per channel and per bucket it keeps the
 * WEB_CHMIX_TOP transmitters that sent the most frames and one "other"
 * count for everyone else, so a cell can be drawn as a stacked bar of
 * five named bands and a grey one.
 *
 * Its samples are the frame counts of the stream records that carry
 * both a channel and one transmitter (src/jsonl.c): `beacon` (the AP,
 * by its bssid; frame_count is the beacons heard from it) and
 * `probe_client` (the station, by its mac; its probe requests). A
 * probe_client record carries no band and only the channel its latest
 * probe was heard on (src/capture/probe.c record_probe() overwrites it
 * per frame), so a station's whole delta since the last snapshot is
 * credited to that one channel, read in the 2.4 or 5 GHz band its
 * number is in: a station probing on 6 GHz is keyed as the 2.4 or
 * 5 GHz channel of the same number. `assoc` is not in the mix: its
 * frame_count (src/assoc_track.c) counts frames of both ends together,
 * the AP's (re)association responses and EAPOL M1/M3 with the
 * station's M2/M4, so no one transmitter sent them. The rest of
 * sloth's 802.11 records either carry no channel (deauth, eapol,
 * wifi_assoc_req) or no per-transmitter count (channel_summary's
 * control frames carry no transmitter address at all, RTS aside).
 * sloth emits no record for data frames, so data traffic is not in the
 * mix. Each count is a running total that web_metrics.c turns into a
 * delta the same way as for the time series, so a reconnect is not a
 * burst. A beacon's band is 6 GHz when its channel_source says the
 * channel came from an HE 6 GHz Operation element (sloth's
 * CH_SRC_HE_6GHZ, 3), and is otherwise the band its number is in, as
 * sloth's ap_band_label() decides.
 *
 * Buckets are the rollup's tiers (10 s, 1 min, 1 h) on slothweb's own
 * clock. Each channel holds one open bucket per tier, tracking at most
 * WEB_CHMIX_TRACK transmitters by name. A further one's frames go to
 * "other" and are also counted against it in a candidate table of
 * WEB_CHMIX_TRACK more; once what a candidate has sent in the bucket
 * outweighs the quietest tracked transmitter, the two change places,
 * each moving its own frames out of "other" or into it. So a heavy
 * transmitter first heard late in an hour enters on everything it sent
 * that hour, every named count is exact, and a scan of a thousand
 * one-frame MACs churns only the candidates' one-frame entries (a full
 * candidate table drops its quietest, whose frames stay in "other")
 * and cannot push the busy ones out. At close the tracked transmitters
 * are cut to the top WEB_CHMIX_TOP by frames (then by MAC) and the rest
 * join "other": nothing is dropped from a cell's total.
 *
 * Bounded everywhere: WEB_CHMIX_CHANNELS channels (sloth itself keeps
 * at most MAX_CHAN_ENTRIES, 64), the least recently heard one evicted
 * when a new one arrives, after its open buckets are closed; closed
 * 10 s buckets in a ring of WEB_CHMIX_RING rows in memory (about 4 MB;
 * the oldest are overwritten and counted, which bounds how far back the
 * fine tier reaches when many channels are busy); closed minute and
 * hour buckets in a queue of WEB_CHMIX_QUEUE rows for the store thread,
 * the oldest dropped and counted when it is full. Without a store the
 * minute and hour tiers are not kept at all (the grid serves the fine
 * tier only then). The AP names (the SSID each bssid's beacons named,
 * whole, as the stream carried it) are a table of WEB_CHMIX_NAMES,
 * least recently heard out first; they are never written to
 * slothweb.db. A name slot holds WEB_CHMIX_SSID_MAX bytes: an SSID is
 * 32 octets, and the stream's form can be three times that, since
 * sloth's json_escape() turns each octet that is not UTF-8 into U+FFFD
 * (three bytes). A longer name cannot have come from sloth and is not
 * kept at all, rather than cut: the page shows and colours an SSID's
 * whole octets or none of them.
 *
 * One mutex guards everything: the ingest thread adds, the store thread
 * closes and takes, the HTTP thread reads. */
#ifndef SLOTHWEB_CHMIX_H
#define SLOTHWEB_CHMIX_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "web_rollup.h"

#define WEB_CHMIX_TOP      5
#define WEB_CHMIX_TRACK    32
#define WEB_CHMIX_CHANNELS WEB_CHANNEL_KEYS
#define WEB_CHMIX_RING     49152
#define WEB_CHMIX_QUEUE    8192
#define WEB_CHMIX_NAMES    512
/* 32 octets, each possibly U+FFFD on the stream. */
#define WEB_CHMIX_SSID_MAX (32 * 3)
/* "6g233" and its NUL. */
#define WEB_CHMIX_KEY_MAX  7

enum { WEB_TX_OTHER = 0, WEB_TX_AP = 1, WEB_TX_CLIENT = 2 };
/* include/sloth.h CH_SRC_HE_6GHZ: a beacon's channel_source when its
 * channel came from the HE 6 GHz Operation element (test_wifi.c holds
 * the two equal). */
#define WEB_CH_SRC_HE_6GHZ 3

typedef struct {
    uint8_t  mac[6];
    uint8_t  kind;                 /* WEB_TX_AP or WEB_TX_CLIENT */
    uint32_t frames;
} web_mix_tx_t;

/* One closed bucket: its top transmitters, frames-first, and the rest. */
typedef struct {
    char         chan[WEB_CHMIX_KEY_MAX + 1];
    int          tier;
    long long    t;
    uint32_t     other;
    int          n;
    web_mix_tx_t tx[WEB_CHMIX_TOP];
} web_mix_row_t;

typedef struct {
    long long    t;                /* bucket start; -1 none */
    uint32_t     other;
    int          n, nc;
    web_mix_tx_t tx[WEB_CHMIX_TRACK];
    /* Transmitters past tx's bound, with the frames of "other" that are
     * theirs (exact; a candidate pushed out takes its count with it). */
    web_mix_tx_t cand[WEB_CHMIX_TRACK];
} web_mix_acc_t;

typedef struct {
    char          key[WEB_CHMIX_KEY_MAX + 1];
    int           used;
    long long     last_seen;
    web_mix_acc_t open[WEB_TIER_COUNT];
} web_mix_chan_t;

typedef struct {
    uint8_t   mac[6];
    int       used;
    long long seen;
    char      ssid[WEB_CHMIX_SSID_MAX + 1];
} web_mix_name_t;

typedef struct {
    unsigned long long samples;
    unsigned long channel_evictions, ring_overwritten, queue_dropped;
    unsigned long folded;          /* a transmitter's frames into "other"
                                      because its bucket was tracking
                                      WEB_CHMIX_TRACK already */
    unsigned long rows_closed[WEB_TIER_COUNT];
    size_t        ring_rows, queue_rows;
    long long     ring_oldest;     /* t of the oldest fine row; -1 none */
    int           channels;
} web_chmix_stats_t;

typedef struct web_chmix {
    pthread_mutex_t mu;
    int             store_on;
    web_mix_chan_t  ch[WEB_CHMIX_CHANNELS];
    web_mix_row_t  *ring;
    size_t          ring_head, ring_n;
    web_mix_row_t  *queue;
    size_t          q_head, q_n;
    web_mix_name_t  names[WEB_CHMIX_NAMES];
    web_chmix_stats_t st;
} web_chmix_t;

/* store_on: whether minute and hour buckets are kept for a store. 0, or
 * -1 (memory). */
int  web_chmix_init(web_chmix_t *c, int store_on);
void web_chmix_destroy(web_chmix_t *c);

/* frames frames from mac (a WEB_TX_* kind) on the channel key chan (a
 * canonical web_key_channel() key) at now_s. A non-positive or
 * non-finite count is ignored; one past 2^32 - 1 is clamped. */
void web_chmix_add(web_chmix_t *c, const char *chan, const uint8_t mac[6],
                   int kind, double frames, long long now_s);
/* The SSID an AP's beacon named (as the stream carried it); one
 * longer than WEB_CHMIX_SSID_MAX bytes is ignored. */
void web_chmix_name(web_chmix_t *c, const uint8_t mac[6], const char *ssid,
                    long long now_s);
/* 1 and the name into out (WEB_CHMIX_SSID_MAX + 1) when known. */
int  web_chmix_ssid(web_chmix_t *c, const uint8_t mac[6], char *out);

/* Close every open bucket whose interval ended at or before now_s. */
void web_chmix_close_due(web_chmix_t *c, long long now_s);
/* Close every open bucket (shutdown); the store merges a partial bucket
 * with the rest of it later. */
void web_chmix_close_all(web_chmix_t *c);

/* Move up to max queued minute and hour rows into out, oldest first. */
size_t web_chmix_take(web_chmix_t *c, web_mix_row_t *out, size_t max);

/* Each closed fine row with from <= t < to, in the order they closed,
 * to fn (nonzero stops), under the mix's lock: fn must not call back
 * into the mix. Rows given. */
typedef int (*web_mix_row_fn)(void *ctx, const web_mix_row_t *r);
int  web_chmix_each_fine(web_chmix_t *c, long long from, long long to,
                         web_mix_row_fn fn, void *ctx);

void web_chmix_stats(web_chmix_t *c, web_chmix_stats_t *out);

/* "aa:bb:cc:dd:ee:ff" for mac into out (18 bytes). */
void web_mix_mac_text(const uint8_t mac[6], char *out);
/* A canonical MAC's bytes: 0, or -1. */
int  web_mix_mac_bytes(const char *s, uint8_t mac[6]);

#endif
