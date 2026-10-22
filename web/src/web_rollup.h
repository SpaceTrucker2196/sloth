/* slothweb rollups (#160, M2): the metric catalogue of
 * docs/web-ui-spec.md §5.1 and the three tiers of §5.2.
 *
 * A sample is (metric, key, value) at a wall-clock second. Every
 * series keeps one open bucket per tier: 10 s, 1 min and 1 h. Each
 * bucket holds sum, count, min and max; a gauge's value is sum/count,
 * a counter's is sum, a presence metric's is max. A bucket is closed
 * when a sample lands in a later one, or by web_rollup_close_due() once
 * its interval has passed, whichever comes first. A closed fine bucket
 * goes to an in-memory ring that /api/series reads; every closed bucket
 * also goes to the store's queue when a store is attached.
 *
 * Cardinality is bounded the way sloth bounds it (§5.2): keys are held
 * per class (device MACs, host IPs, interfaces, channels, alert types),
 * each class has a cap, and a new key in a full class evicts the one
 * seen least recently, after flushing its open buckets. Evictions are
 * counted per class and shown on /api/health. Global metrics have one
 * key, "", and are never evicted.
 *
 * Only the device and host classes can be churned by a peer: a MAC or
 * an IP is whatever a frame or a packet claims. Their keys are judged
 * on their whole life, not their sample count. Until a key's samples
 * span WEB_MINUTE_S (last_seen - first_seen >= 60 s) it is not
 * established: its fine buckets close and are written as usual, but
 * its minute and hour buckets are held in memory, not queued. When it
 * becomes established they are released to the queue. When it is
 * evicted first (only a full class evicts) they are dropped and counted
 * (churn_dropped on /api/health), however many samples it took. A key
 * that is neither established nor evicted has them written at shutdown.
 * A key's life outlasts its stays in the class: an evicted key's
 * first_seen, and whether it was established, are kept in a small
 * per-class table (the ghosts, four per key slot) and given back when it
 * returns, so a host that recurs under LRU pressure, evicted between
 * every two of its samples, still becomes established a minute after it
 * was first seen and keeps its minute and hour rows from then on. The
 * table is bounded and prefers established keys: an unestablished
 * ghost never displaces an established one, so a scan can push out the
 * ghosts of other keys still in their first minute, never those of keys
 * that already had one. So what key churn
 * can put in the 30-day and 400-day tiers is the rows of keys seen over
 * a minute or more, at most one per metric per bucket each; a scan
 * whose targets are each seen for under a minute writes fine rows only.
 *
 * Interfaces, channels and alert types come from catalogues sloth
 * itself bounds (MAX_IFACES 32, MAX_CHAN_ENTRIES 64 at a time out of
 * 466 channel numbers, one alert kind per ALERT_TYPE_*), each has its
 * own class sized from those bounds, and their keys are established
 * from their first sample, as the global series are: an alert type that
 * fires twice in ten seconds gets its minute row when the minute ends,
 * and an evicted channel's rows are flushed, not dropped.
 *
 * The store queue is sized from the class caps: WEB_QROWS_PER_SERIES
 * rows for every series the classes can hold (see web_rollup_init()),
 * so an hour boundary, which closes a fine, a minute and an hour bucket
 * of every series in one pass, and the shutdown close_all() both fit at
 * --web-max-keys 8192. Only eviction churn can outrun it. When it is
 * full a fine row is dropped before a minute or an hour row: a minute
 * or hour row arriving at a full queue takes the place of the newest
 * queued fine row. Every drop is counted (queue_dropped).
 *
 * Keys arrive already validated and canonical (web_metrics.c); the
 * rollup trusts them only as far as WEB_KEY_MAX bytes. Bucketing uses
 * slothweb's own clock, never a record's ts: a hostile ts could
 * otherwise write anywhere in history.
 *
 * One mutex guards everything here. The ingest thread adds samples, the
 * store thread closes buckets and takes the queue, the HTTP thread
 * reads; nothing hands out a pointer into the state. */
#ifndef SLOTHWEB_ROLLUP_H
#define SLOTHWEB_ROLLUP_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#define WEB_FINE_S       10
#define WEB_MINUTE_S     60
#define WEB_HOUR_S       3600
/* Retention per tier (§5.2): fine 24 h, minute --web-retain-days (30 by
 * default), hour 400 days. */
#define WEB_FINE_KEEP_S  86400LL
#define WEB_HOUR_KEEP_S  (400LL * 86400)
#define WEB_DEFAULT_RETAIN_DAYS 30
#define WEB_RETAIN_DAYS_MAX     400

/* --web-max-keys N: N device keys and N/2 host keys (512 and 256 by
 * default, §5.2). Interfaces, channels and alert types have fixed caps
 * taken from sloth's own bounds: MAX_IFACES, MAX_CHAN_ENTRIES, and the
 * 90 ALERT_TYPE_* kinds with room for more. */
#define WEB_DEFAULT_MAX_KEYS 512
#define WEB_MAX_KEYS_MIN     16
#define WEB_MAX_KEYS_MAX     8192
#define WEB_IFACE_KEYS       32
#define WEB_CHANNEL_KEYS     64
#define WEB_ALERT_KEYS       128
/* The longest canonical key: an IPv6 address is at most 45 bytes. */
#define WEB_KEY_MAX          47

/* Closed fine buckets kept in memory, across every series. 40 bytes
 * each: about 5 MB. With no store this is all /api/series has. */
#define WEB_RING_ROWS        131072
/* Closed buckets waiting for the store thread: WEB_QROWS_PER_SERIES
 * for every series the key classes can hold, and never fewer than
 * WEB_QUEUE_ROWS. Per series, between two drains, the queue gets at
 * most two fine rows (a drain is due every 10 s), one minute, one hour
 * and the two held rows a key releases when it becomes established;
 * close_all() after a drain adds three open and two held. 96 bytes a
 * row: about 3 MB at the default --web-max-keys, 41 MB at 8192, and
 * calloc()ed, so the pages are only resident once used. */
#define WEB_QUEUE_ROWS       32768
#define WEB_QROWS_PER_SERIES 6
/* A value beyond this is clamped: nothing sloth reports is near it,
 * and it keeps every sum finite. */
#define WEB_VALUE_MAX        1e15

enum { WEB_TIER_FINE = 0, WEB_TIER_MINUTE, WEB_TIER_HOUR, WEB_TIER_COUNT };
enum { WEB_KC_GLOBAL = 0, WEB_KC_DEV, WEB_KC_HOST, WEB_KC_IFACE, WEB_KC_CHANNEL,
       WEB_KC_ALERT, WEB_KC_COUNT };
enum { WEB_MK_GAUGE = 0, WEB_MK_COUNTER, WEB_MK_PRESENCE };

/* §5.1, the metrics whose source records sloth emits today
 * (src/jsonl.c). web_rollup.c holds the table: name, kind, key class,
 * key kind and source. */
enum {
    WM_IFACE_RX = 0, WM_IFACE_TX,
    WM_HOST_RX, WM_HOST_TX, WM_HOST_CONNS,
    WM_DEV_FRAMES, WM_DEV_PRESENT,
    WM_DNS_QUERIES, WM_DNS_NXDOMAIN,
    WM_TLS_HANDSHAKES, WM_HTTP_REQUESTS,
    WM_ALERTS_FIRED,
    WM_WIFI_AP_COUNT, WM_WIFI_CTRL_TOTAL, WM_WIFI_DEAUTH, WM_WIFI_PROBE_CLIENTS,
    WM_CONNS_TOTAL,
    WM_FLOW_SSH, WM_FLOW_RDP, WM_FLOW_SMB, WM_FLOW_SNMP, WM_FLOW_MQTT,
    WM_COUNT
};

typedef struct {
    const char *name;      /* "iface.rx_rate" */
    int         kind;      /* WEB_MK_* */
    int         kclass;    /* WEB_KC_* */
    const char *keykind;   /* "iface", "ip", "mac", "channel", "alert_type", "" */
    const char *source;    /* the record type(s) and member it comes from */
    const char *unit;
} web_metric_t;

extern const web_metric_t web_metric_defs[WM_COUNT];

int         web_metric_find(const char *name);       /* id, or -1 */
int         web_tier_find(const char *name);         /* "fine"/"minute"/"hour", or -1 */
const char *web_tier_name(int tier);
int         web_tier_step(int tier);                 /* 10, 60, 3600 */
const char *web_kclass_name(int kc);

typedef struct {
    long long     t;       /* bucket start, unix seconds; -1 when none */
    double        sum, min, max;
    unsigned long n;
} web_agg_t;

typedef struct {
    uint32_t  sid;         /* the series instance it belongs to */
    uint32_t  n;
    long long t;
    double    sum, min, max;
} web_ring_row_t;

/* One closed bucket for the store. */
typedef struct {
    int           tier, metric;
    char          key[WEB_KEY_MAX + 1];
    long long     t;
    double        sum, min, max;
    unsigned long n;
} web_qrow_t;

typedef struct {
    char      key[WEB_KEY_MAX + 1];
    int       used;
    int       next;                       /* hash chain, -1 ends it */
    long long first_seen, last_seen;      /* slothweb's clock */
    int       est;                        /* samples span a minute: its
                                             minute and hour rows go out */
    uint32_t  sid[WM_COUNT];              /* 0: no series for that metric */
    web_agg_t open[WM_COUNT][WEB_TIER_COUNT];
    /* An unestablished key's closed minute and hour buckets ([0] minute,
     * [1] hour). Its samples lie within one minute, so they touch at
     * most two buckets of each tier: the one open and the one held.
     * 1.7 KB a key. */
    web_agg_t held[WM_COUNT][WEB_TIER_COUNT - 1];
} web_rkey_t;

/* An evicted key of a churnable class: what its life was so far. */
typedef struct {
    char      key[WEB_KEY_MAX + 1];
    long long first_seen;
    long long gone;                       /* when it was evicted */
    int       used, est;
} web_ghost_t;

#define WEB_GHOST_WAYS 4

typedef struct {
    int           cap, n;
    web_rkey_t   *k;
    int          *head;
    int           nhead;                  /* a power of two */
    unsigned long evictions;
    int           churnable;              /* device and host keys */
    web_ghost_t  *ghost;                  /* nghost sets of WEB_GHOST_WAYS */
    int           nghost;                 /* a power of two; 0 when none */
    unsigned long ghost_hits;             /* returning keys given their life */
} web_kclass_t;

typedef struct {
    pthread_mutex_t mu;
    web_kclass_t    cls[WEB_KC_COUNT];
    uint32_t        next_sid;
    web_ring_row_t *ring;
    size_t          ring_cap, ring_head, ring_n;
    int             store_on;
    web_qrow_t     *queue;
    size_t          q_cap, q_n;
    size_t          q_head;               /* the oldest row; a ring */
    size_t          q_scan;               /* logical; rows above not fine */
    unsigned long   q_dropped;
    unsigned long   churn_dropped;        /* see key_flush() */
    unsigned long long samples;
    unsigned long   clamped;
    unsigned long   hw_evictions;         /* web_metrics.c's high-water rows */
    unsigned long   rows_closed[WEB_TIER_COUNT];
} web_rollup_t;

typedef struct {
    int           keys[WEB_KC_COUNT], caps[WEB_KC_COUNT];
    unsigned long evictions[WEB_KC_COUNT];
    unsigned long ghost_hits[WEB_KC_COUNT];
    unsigned long series;
    size_t        ring_rows, queue_rows, queue_cap;
    unsigned long q_dropped, churn_dropped, clamped, hw_evictions;
    unsigned long long samples;
    unsigned long rows_closed[WEB_TIER_COUNT];
} web_rollup_stats_t;

/* A bucket handed to /api/series. */
typedef web_agg_t web_point_t;

typedef struct {
    char      key[WEB_KEY_MAX + 1];
    long long last_seen;
} web_keyinfo_t;

/* max_keys is --web-max-keys (device keys; hosts get half). store_on
 * says whether closed buckets are queued for a store. 0, or -1 with err
 * (memory). */
int  web_rollup_init(web_rollup_t *ru, int max_keys, int store_on,
                     char *err, size_t errsz);
void web_rollup_destroy(web_rollup_t *ru);

/* One sample. key is canonical ("" for a global metric). A NaN or
 * infinite v is ignored; a larger one is clamped to WEB_VALUE_MAX. */
void web_rollup_add(web_rollup_t *ru, int metric, const char *key, double v,
                    long long now_s);

/* Close every open bucket whose interval ended at or before now_s;
 * an unestablished key's minute and hour buckets stay open. */
void web_rollup_close_due(web_rollup_t *ru, long long now_s);
/* Close every open bucket, finished or not, and release every held one
 * (shutdown). The store merges a partial bucket with the rest of it on
 * the next run. */
void web_rollup_close_all(web_rollup_t *ru);

/* Move up to max queued rows into out, oldest first (a minute or hour
 * row that took a dropped fine row's place is where that row was).
 * Returns how many. */
size_t web_rollup_take(web_rollup_t *ru, web_qrow_t *out, size_t max);

/* The fine buckets of (metric, key) with from <= t < to that are in
 * memory, newest first, at most max; with_open adds the bucket still
 * filling. Only the key's current series instance is read: a key that
 * was evicted and came back has a new one, and the ring rows of its
 * earlier life are not returned (with a store they are on disk under
 * the same (metric, key), and /api/series reads them there; without
 * one that history is gone from the answer). Two ring rows of the
 * current instance for one bucket (a close_all() and then more samples
 * in the same bucket, or the clock stepping back) are merged. Returns
 * how many; *more is set when max cut it short. */
int  web_rollup_fine(web_rollup_t *ru, int metric, const char *key,
                     long long from, long long to, int with_open,
                     web_point_t *out, int max, int *more);

/* The keys holding a series of metric, most recently seen first, at
 * most max. *total gets how many there are. */
int  web_rollup_keys(web_rollup_t *ru, int metric, web_keyinfo_t *out,
                     int max, int *total);

void web_rollup_stats(web_rollup_t *ru, web_rollup_stats_t *st);
/* Rows waiting in the store queue. */
size_t web_rollup_queued(web_rollup_t *ru);
void web_rollup_note_hw_eviction(web_rollup_t *ru);

/* The value a bucket stands for: sum/n for a gauge, sum for a counter,
 * max for presence. */
double web_point_value(int metric, const web_point_t *p);

#endif
