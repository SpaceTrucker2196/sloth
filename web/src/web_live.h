/* slothweb live state (#159, M1): what the data-socket stream has said
 * lately, kept in fixed-size tables behind one mutex.
 *
 * The ingest thread writes it (web_live_apply() and the web_live_sock_*
 * calls); the HTTP thread reads it (the summaries and the JSON
 * renderers). Every call takes the lock itself; nothing hands out a
 * pointer into the state.
 *
 * Every string kept here came off the socket and is treated as
 * hostile: the decoder has already refused anything that is not valid
 * UTF-8, each copy is cut to a fixed size on a code-point boundary, and
 * nothing leaves except through web_jw_str(). Record-type names are
 * kept only when they look like one ([a-z0-9_.], 1..32 bytes).
 *
 * The device count is the number of `device` records in sloth's latest
 * snapshot pass, which is exactly the TUI's device_count: sloth's poll
 * thread emits one `device` record per row of s->devices every poll
 * (src/jsonl.c jsonl_emit_devices()). The pass is contiguous only among
 * the poll thread's own records: the capture thread's dns, tls, quic,
 * http, ntp, icmp and cleartext_cred records can land inside it, since
 * no lock spans the pass. So only the poll thread's record types
 * (POLL_TYPES in web_live.c) steer the count; every other type is
 * passed over, and a pass ends at the first poll-thread record of
 * another type. A pass that a `socket_gap` or an undecodable line may
 * have cut short is not published; the previous count stands. A
 * snapshot batch with no `device` record at all (batches start with
 * the `iface` records, jsonl_emit_state_snapshots()) publishes 0. */
#ifndef SLOTHWEB_LIVE_H
#define SLOTHWEB_LIVE_H

#include <pthread.h>
#include <stddef.h>

#include "web_json.h"
#include "web_jsonl.h"

#define WEB_LIVE_TYPES      48   /* distinct record types counted by name */
#define WEB_LIVE_TYPE_MAX   32
#define WEB_LIVE_RING       50   /* recent records: the ticker (spec §8.4) */
#define WEB_LIVE_TEXT_MAX   80
#define WEB_LIVE_ALERTS     8    /* latest alert lifecycle records */
#define WEB_LIVE_TITLE_MAX  48
#define WEB_LIVE_DETAIL_MAX 128
#define WEB_LIVE_ID_MAX     32
/* Open incidents tracked; sloth's engine holds MAX_ALERTS (128). */
#define WEB_LIVE_INCIDENTS  256
#define WEB_LIVE_SH_STR     32
/* sensor_health is change-only with a 300 s heartbeat
 * (JSONL_HEARTBEAT_SECS), so silence up to that long is normal. */
#define WEB_LIVE_SH_STALE_MS 330000
#define WEB_LIVE_ERR_MAX    160
#define WEB_LIVE_SPEC_MAX   128

enum {
    WEB_SOCK_NONE = 0,      /* no ingest configured */
    WEB_SOCK_CONNECTING,
    WEB_SOCK_CONNECTED,
    WEB_SOCK_RETRYING       /* waiting out a back-off */
};

typedef struct {
    unsigned long long seq;
    long long ts;
    char      type[WEB_LIVE_TYPE_MAX + 1];
    char      text[WEB_LIVE_TEXT_MAX + 1];
} web_live_rec_t;

typedef struct {
    long long ts;
    int       sev;
    char      type[WEB_LIVE_TYPE_MAX + 1];
    char      title[WEB_LIVE_TITLE_MAX + 1];
    char      detail[WEB_LIVE_DETAIL_MAX + 1];
    char      incident[WEB_LIVE_ID_MAX + 1];
} web_live_alert_t;

typedef struct {
    char               name[WEB_LIVE_TYPE_MAX + 1];
    unsigned long long n;
} web_live_type_t;

typedef struct {
    char id[WEB_LIVE_ID_MAX + 1];
    int  sev;
} web_live_inc_t;

typedef struct {
    pthread_mutex_t mu;

    /* the socket */
    char          spec[WEB_LIVE_SPEC_MAX + 1];
    int           sock_state;
    unsigned long attempts, connects, failures, closes;
    char          last_error[WEB_LIVE_ERR_MAX + 1];
    long long     last_error_ms;          /* -1 never */
    int           retry_ms;               /* the back-off now in force */
    long long     connected_ms;
    unsigned long conn_gen;               /* bumps on every connect */
    unsigned long long bytes, lines, records;
    unsigned long decode_errors;
    unsigned long dec_by[WEB_JL_ECOUNT];
    unsigned long truncated;              /* a line cut off by EOF */
    unsigned long gaps;
    unsigned long long gap_dropped;
    long long     last_record_ms;         /* -1 never */

    /* records by type */
    int                ntypes;
    web_live_type_t    types[WEB_LIVE_TYPES];
    unsigned long long types_other;       /* table full */
    unsigned long long types_invalid;     /* not a plausible type name */

    /* records per second, by second of the monotonic clock */
    long long rate_sec[8];
    unsigned  rate_n[8];

    /* devices */
    int           dev_known;
    long          dev_count;
    long long     dev_ts;                 /* the pass's own ts */
    unsigned long dev_gen;                /* conn_gen it was published on */
    unsigned long dev_rounds, dev_rounds_tainted;
    int           in_round, round_taint, pending_taint;
    long          round_n;
    long long     round_ts;
    int           batch_open, batch_saw_dev, batch_taint, last_iface;

    /* alerts */
    int              ninc;
    web_live_inc_t   inc[WEB_LIVE_INCIDENTS];
    int              inc_overflow;
    web_live_alert_t alerts[WEB_LIVE_ALERTS];
    int              alert_next, alert_n;

    /* sensor_health */
    int       sh_seen;
    long long sh_ms, sh_ts;
    int       cap_open, cap_running, mon_open, mon_running, scope_ne;
    char      cap_iface[WEB_LIVE_SH_STR + 1], mon_iface[WEB_LIVE_SH_STR + 1];
    char      cap_exit[WEB_LIVE_SH_STR + 1], mon_exit[WEB_LIVE_SH_STR + 1];
    char      scope[WEB_LIVE_SH_STR + 1];

    /* recent records */
    web_live_rec_t     ring[WEB_LIVE_RING];
    unsigned long long seq;               /* of the newest; 0 none yet */
} web_live_t;

/* The small view the tick event and /api/health carry. */
typedef struct {
    int                sock_state;
    int                dev_known, dev_stale;
    long               devices;
    unsigned long      alerts[3];         /* open incidents: LOW, WARN, CRIT */
    int                alerts_overflow;
    long               rate10;            /* records/s, times ten */
    unsigned long long records;
    const char        *sensor;            /* a fixed word, see below */
    long long          last_record_age_ms;  /* -1 never */
} web_live_sum_t;

/* spec is the operator's --socket text, kept for display. */
void web_live_init(web_live_t *l, const char *spec);
void web_live_destroy(web_live_t *l);

/* The ingest thread's account of the socket. err strings are our own
 * (strerror and a word of context), never anything the peer sent. */
void web_live_sock_attempt(web_live_t *l, long long now_ms);
void web_live_sock_connected(web_live_t *l, long long now_ms);
void web_live_sock_failed(web_live_t *l, const char *err, int retry_ms,
                          long long now_ms);
void web_live_sock_bytes(web_live_t *l, size_t n);

/* One decoded record, or one line that would not decode. */
void web_live_apply(web_live_t *l, const web_jrec_t *r, long long now_ms);
void web_live_decode_error(web_live_t *l, int err, long long now_ms);
/* The connection ended inside a line. */
void web_live_truncated(web_live_t *l);

void web_live_summary(web_live_t *l, web_live_sum_t *s, long long now_ms);

/* Copy up to max records newer than after, oldest first, into out; the
 * newest seq goes to *latest. When more than max are newer, the newest
 * max are copied. Returns how many. */
int  web_live_recent_after(web_live_t *l, unsigned long long after,
                           web_live_rec_t *out, int max,
                           unsigned long long *latest);

/* The /api/live document. Returns its length, 0 if it did not fit. */
size_t web_live_json(web_live_t *l, char *out, size_t cap, long long now_ms);

/* The socket members of /api/health, each preceded by a comma. */
void web_live_health_members(web_live_t *l, web_jw_t *w, long long now_ms);

const char *web_live_sock_word(int state);

/* "ok", "degraded", "not_observing", "stale" or "unknown": the
 * sensor_health liveness, from the latest record and its age. */
const char *web_live_sensor_word(web_live_t *l, long long now_ms);

#endif
