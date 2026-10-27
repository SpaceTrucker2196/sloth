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
#include "web_scope.h"

#define WEB_LIVE_TYPES      48   /* distinct record types counted by name */
#define WEB_LIVE_TYPE_MAX   32
#define WEB_LIVE_RING       50   /* recent records: the ticker (spec §8.4) */
#define WEB_LIVE_TEXT_MAX   80
#define WEB_LIVE_ALERTS     8    /* latest alert lifecycle records */
#define WEB_LIVE_TITLE_MAX  48
#define WEB_LIVE_DETAIL_MAX 128
#define WEB_LIVE_ID_MAX     32
/* The handle slothweb names an incident by on the wire, in place of
 * sloth's incident_id (see web_live_inc_t): 8 hex digits of a
 * per-process nonce and up to 16 of a counter. */
#define WEB_LIVE_HID_MAX    24
/* An alert's match_ip: INET6_ADDRSTRLEN - 1, address characters only. */
#define WEB_LIVE_IP_MAX     45
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
    int       sc;     /* its capture-scope tag, resolved when it came:
                         WEB_SC_M, WEB_SC_L, both, or 0 (web_scope.h) */
} web_live_rec_t;

typedef struct {
    long long ts;
    int       sev;
    int       ty;                      /* the record's ty, -1 none */
    char      type[WEB_LIVE_TYPE_MAX + 1];
    char      title[WEB_LIVE_TITLE_MAX + 1];
    char      detail[WEB_LIVE_DETAIL_MAX + 1];
    char      hid[WEB_LIVE_HID_MAX + 1];   /* the incident's handle, "" none */
    char      match_ip[WEB_LIVE_IP_MAX + 1];
} web_live_alert_t;

/* A per-second count over the last eight seconds of the monotonic
 * clock, as the records/s figure is kept. */
typedef struct {
    long long sec[8];
    unsigned  n[8];
} web_live_rate_t;

typedef struct {
    char               name[WEB_LIVE_TYPE_MAX + 1];
    unsigned long long n;
    web_live_rate_t    rate;
} web_live_type_t;

/* One incident as the lifecycle records have told it (alert.create,
 * .update, .escalate, .resolve). key is sloth's dedup key, kept so the
 * alert routes can bind it as a predicate against sloth.db's alerts.key
 * (web_alertdb.h); like alerts.key it can carry a remote string (for a
 * cleartext credential, the username), so it is never rendered, by any
 * route. detail is kept only for a type web_alert_detail_ok() admits.
 *
 * id, sloth's incident_id, is never rendered either. sloth derives it
 * by FNV-1a64 over the key, then the creation time, then a small
 * counter (src/alerts/engine.c incident_id_make()), and every FNV step
 * inverts: strip the time (first_seen) and the counter (a few thousand
 * guesses) and what is left is the key's unsalted hash, which a
 * dictionary of usernames turns back into CLEARTEXT_CRED's username.
 * The routes name an incident by hid instead: a nonce drawn at startup
 * and a counter of the incidents this process has seen, which says
 * nothing about the key. */
#define WEB_LIVE_KEY_MAX    191
#define WEB_LIVE_SEVH       8
#define WEB_LIVE_CLOSED     64
#define WEB_LIVE_REASON_MAX 15
#define WEB_LIVE_TECH_MAX   15
typedef struct {
    long long ts;
    int       sev;
    char      ev;                      /* 'c' create 'u' update 'e' escalate 'r' resolve */
} web_live_sevh_t;

typedef struct {
    char      id[WEB_LIVE_ID_MAX + 1];
    char      hid[WEB_LIVE_HID_MAX + 1];
    char      key[WEB_LIVE_KEY_MAX + 1];
    int       sev;
    int       type;                    /* the record's ty, -1 none */
    char      title[WEB_LIVE_TITLE_MAX + 1];
    char      detail[WEB_LIVE_DETAIL_MAX + 1];
    char      technique[WEB_LIVE_TECH_MAX + 1];
    char      match_ip[WEB_LIVE_IP_MAX + 1];
    int       match_port;
    long long first_ts, last_ts, closed_ts;   /* closed_ts -1 open */
    long long count, observations, reopen;
    int       pcap;                    /* sloth wrote a pcap of it */
    char      reason[WEB_LIVE_REASON_MAX + 1];
    int       nsev;                    /* changes seen, all of them */
    web_live_sevh_t sevh[WEB_LIVE_SEVH];  /* the latest WEB_LIVE_SEVH, oldest first */
    unsigned long long seq;            /* when it last changed: newest first */
} web_live_inc_t;

/* The devices of sloth's latest published pass, by MAC, for the
 * Devices view's pass:latest filter (the Overview's devices tile). A
 * row is the MAC's 17 characters, its NUL, and the device's scope tag
 * after it: the sort and the search compare the string only. */
#define WEB_LIVE_PASS_MAX   2048
#define WEB_LIVE_PASS_ROW   19

typedef struct web_live_s {
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

    /* records per second, by second of the monotonic clock: all of
     * them, and the ones counted as types_other and types_invalid */
    long long rate_sec[8];
    unsigned  rate_n[8];
    web_live_rate_t rate_other, rate_invalid;

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
    web_live_inc_t   closed[WEB_LIVE_CLOSED];   /* a ring, newest at closed_next - 1 */
    int              closed_next, closed_n;
    unsigned long long inc_seq;
    unsigned           hid_nonce;           /* drawn at init */
    unsigned long long hid_seq;             /* handles given out */
    web_live_alert_t alerts[WEB_LIVE_ALERTS];
    int              alert_next, alert_n;

    /* the latest pass's MACs: round_* while one is read, pass_* published */
    char             round_macs[WEB_LIVE_PASS_MAX][WEB_LIVE_PASS_ROW];
    int              round_nmac, round_mac_more;
    char             pass_macs[WEB_LIVE_PASS_MAX][WEB_LIVE_PASS_ROW];   /* sorted */
    int              pass_nmac, pass_mac_more;
    /* The pass's devices by capture scope (web_scope_device()): the
     * round's while it is read, and the published pass's. */
    long             round_n_m, round_n_l, dev_count_m, dev_count_l;

    /* The capture scope's facts (web_scope.h): the monitor radios named
     * so far, whether the IP capture is one, and sloth's own words for
     * it (sensor_health capture_linktype, -1 absent; monitor_only). */
    web_scope_ctx_t  sc;
    long long        cap_linktype;
    int              monitor_only;
    /* records/s by scope: [0] Monitor, [1] Local */
    web_live_rate_t  rate_scope[2];

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
    /* While connected: how long since the later of the last record and
     * the connection itself, so that a connection that never sends
     * counts from its start and a fresh one is not charged with the
     * silence of the last; -1 when not connected. */
    long long          silence_ms;
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
/* The same for one capture scope (web_scope.h): the device count is the
 * pass's devices of that scope, the open alerts and the alert list
 * those of its types, records/s and the ticker's backlog its records.
 * Hybrid is web_live_json() byte for byte. */
size_t web_live_json_scoped(web_live_t *l, const web_scope_ctx_t *sc,
                            char *out, size_t cap, long long now_ms);
/* The stream's scope facts for a request: the monitor radios named so
 * far and whether the IP capture is one; scope and given are left as
 * the caller set them. */
void   web_live_scope_ctx(web_live_t *l, web_scope_ctx_t *sc);
/* The scope tag of mac in the latest pass, or -1 when it is not in it. */
int    web_live_pass_tag(web_live_t *l, const char *mac);
/* The latest pass's MACs whose tag has a bit of want (WEB_SC_M, _L). */
int    web_live_pass_count(web_live_t *l, int want);
/* An incident's tag (its alert type's, the radio of now applied). */
int    web_live_inc_tag(const web_scope_ctx_t *sc, const web_live_inc_t *e);

/* The socket members of /api/health, each preceded by a comma. */
void web_live_health_members(web_live_t *l, web_jw_t *w, long long now_ms);

const char *web_live_sock_word(int state);

/* Is t one of the poll thread's record types (sloth's snapshot batch,
 * src/jsonl.c jsonl_emit_state_snapshots())? The capture thread's types
 * can land anywhere inside a batch; these cannot. */
int  web_live_is_poll_type(const char *t);

/* "ok", "degraded", "not_observing", "stale" or "unknown": the
 * sensor_health liveness, from the latest record and its age. */
const char *web_live_sensor_word(web_live_t *l, long long now_ms);

/* The incidents, for the alert routes: the open ones first (the
 * Overview's open-alerts count, exactly), then the recently closed,
 * each group newest change first; at most max into out. Their count;
 * *nopen of them open. */
int web_live_incidents(web_live_t *l, web_live_inc_t *out, int max, int *nopen);
/* One incident by its handle (web_live_inc_t.hid), open or recently
 * closed: 1 found. */
int web_live_incident(web_live_t *l, const char *hid, web_live_inc_t *out);
/* Is mac (canonical, lower case) in the latest published device pass? */
int web_live_pass_has(web_live_t *l, const char *mac);
/* The latest pass's MAC count, and whether more were in it than kept. */
int web_live_pass_size(web_live_t *l, int *more);
/* A records/s figure, times ten, of one rate ring (the same five whole
 * seconds the summary's records_s uses). */
long web_live_rate10(const web_live_rate_t *r, long long now_ms);

#endif
