/* slothweb's alert triage and the FRRS emitter record
 * (docs/web-frrs-spec.md, owner request 2026-10-27): the operator's
 * judgement on each finding, and for every emitter sloth hears what the
 * Joint Spectrum Center's five databases would hold about it, built only
 * from what sloth already recorded.
 *
 *   Triage   append-only rows in slothweb.db (v6, web_store.h): one per
 *            decision on one finding, false / noise / incident / known /
 *            untriaged (a clear), each with who, from where, when, an
 *            optional note, and for "follow recommended" the words of
 *            the research assessment that recommended it. The current
 *            state is the newest row of the finding; every change is
 *            reversible by another row. Never a change to sloth: triage
 *            feeds nothing back to the sensor.
 *   Report   /api/frrs/report: BEI (the RF environment around the
 *            emitter), SCS (certification and compliance posture), EC/S
 *            (the observed parametrics), TACDB (the operator's filing)
 *            and the COMINT report (identity, signal, function, timing,
 *            technical characteristics, protection posture, peers),
 *            every field with its sloth source named and "not observed"
 *            (v null) when absent. Two fixed sentences travel with it:
 *            a single passive sensor has no location axis, and sloth
 *            decrypts nothing (MISSION §2).
 *   TACDB    the operator's platforms (by nomenclature), each one's
 *            equipment complement (the emitters it owns, each linking to
 *            its EC/S), and the units that own platforms, a tree four
 *            deep; suggested from sloth's own correlations (sequence
 *            counter trails, MLD affiliation, BSSID families, a station
 *            the card and the air both heard) and confirmed by the
 *            operator; exported and imported as JSON Lines, so another
 *            sensor shares it.
 *   Anomalies  (owner request 2026-11-11) slothweb's own findings
 *            (web_anomaly.h) are triaged by the same rows, routes and
 *            states: an anomaly is named "a" and sixteen hex digits
 *            (web_anomaly_tid(): its rule, metric and key), which like
 *            an alert's subject names the finding, every episode of it,
 *            so a decision outlives the episode it was made on as an
 *            alert's outlives the incident. Each row records the
 *            episode it was written on (its first_seen), and the
 *            answer says "carried" when the state shown was decided on
 *            an earlier episode than the one held now, so it never
 *            attaches to a later episode unsaid. No assessment judges
 *            an anomaly rule, so nothing is ever recommended.
 *   Links    (web_relate.c) the operator's own links from an anomaly
 *            to an alert, another anomaly or a device, read from both
 *            ends, removable; and candidates slothweb offers and never
 *            stores: findings on the same MAC or IP whose times overlap
 *            or lie within WEB_REL_WINDOW_S, worded as what they are
 *            ("same device, within 10 minutes": a passive sensor
 *            corroborates, it does not confirm).
 *
 * The write surface is slothweb's first (every other route is GET or
 * HEAD) and is deliberately narrow: POST only, to the eight paths
 * web_http_post_path() names, which answer nothing else (a GET there is
 * 405 Allow: POST); JSON bodies of at most WEB_POST_MAX bytes
 * (WEB_IMPORT_MAX for the import); Content-Type checked; the Origin
 * header required and equal to the request's Host (slothweb sets no
 * cookie, so this is the whole of its cross-site defence: a browser
 * sends Origin on every cross-site POST and lets no page forge it); a
 * token bucket per peer; every member validated to its bound (an
 * over-long value is refused, never cut); every stored string an
 * address, slothweb's own words, or operator text that never came off
 * the stream. web_frrs_gate() runs the header checks before a body byte
 * is read. --web-read-only removes the surface whole: every POST is 405
 * Allow: GET, HEAD, as before this module existed. The allow list
 * (web_acl.h) stays the trust boundary: there is no login, and "by" is
 * the peer's address plus whatever name the operator typed.
 *
 * Writes go over a connection to slothweb.db of the HTTP thread's own
 * (web_store_open_aux(); web_store.h says why that is the one exception
 * to "the store thread writes"), one short transaction per request;
 * reads of sloth.db go through the M4 reader and its column allow-list
 * (web_slothdb.h), so no credential column is reachable from here
 * either. The ledger, the one place a stream string lives in this
 * module, is memory: the latest beacon, regulatory, MLD,
 * association-request, sequence-number, BLE, TLS and channel facts per
 * emitter, bounded, written by the ingest thread and read by the HTTP
 * thread under one mutex, lost at exit and refilled by the stream's
 * re-broadcast on connect. */
#ifndef SLOTHWEB_FRRS_H
#define SLOTHWEB_FRRS_H

#include <pthread.h>
#include <stddef.h>

#include "web_devices.h"
#include "web_http.h"
#include "web_json.h"
#include "web_jsonl.h"
#include "web_live.h"
#include "web_slothdb.h"
#include "web_store.h"

/* The bounds (docs/web-frrs-spec.md §3). Operator state is never
 * dropped by --web-max-mb. Triage is never refused for room: one
 * alert's history beyond WEB_FRRS_HIST_PER folds (its first row and the
 * newest kept, the count of the folded rows recorded on the first), and
 * at WEB_FRRS_TRIAGE_CAP the oldest superseded rows fold, imported ones
 * first (§3.1). A TACDB write at its cap is refused, 507. */
#define WEB_FRRS_TRIAGE_CAP   20000
#define WEB_FRRS_HIST_PER     64
/* Imported rows of one alert: at most this many, the oldest folded, so
 * a file can never fill an alert's history before its operator does. */
#define WEB_FRRS_IMPORT_PER   8
/* At the table's cap: rows folded at once, the cap over this (the
 * retention's scan runs once per batch, not per write), and how old an
 * alert's newest row is before its superseded rows are taken ahead of a
 * live alert's. */
#define WEB_FRRS_FOLD_DIV     100
#define WEB_FRRS_AGED_S       (7LL * 86400)
/* A clear is never refused: with nothing superseded left to fold, one
 * may go past the cap by at most the cap over this (each one leaves a
 * superseded row behind, so the next write folds it). */
#define WEB_FRRS_CLEAR_DIV    50
/* /api/frrs/summary and the page warn from this share of the cap. */
#define WEB_FRRS_WARN_PCT     90
/* An imported row's ts may run ahead of this clock by this much at most. */
#define WEB_FRRS_TS_AHEAD_S   300
#define WEB_FRRS_UNITS        512
#define WEB_FRRS_PLATFORMS    2048
#define WEB_FRRS_EMITTERS     8192
#define WEB_FRRS_DISMISS      4096
#define WEB_FRRS_UNIT_DEPTH   4
#define WEB_FRRS_ADDR_MAX     45
#define WEB_FRRS_NOTE_MAX     240
#define WEB_FRRS_BY_MAX       32
#define WEB_FRRS_BASIS_MAX    96
#define WEB_FRRS_NAME_MAX     64
#define WEB_FRRS_LABEL_MAX    32
/* The write path's token bucket per peer: a burst of ten, thirty a
 * minute after; WEB_FRRS_PEERS peers tracked, the least recent evicted.
 * The import route costs WEB_FRRS_IMPORT_COST of them. */
#define WEB_FRRS_RATE_BURST   10
#define WEB_FRRS_RATE_PER_MIN 30
#define WEB_FRRS_PEERS        64
#define WEB_FRRS_IMPORT_COST  5
/* The ledger (§3.3): the latest of each record per emitter. */
#define WEB_FRRS_LEDGER_BSSID 512
#define WEB_FRRS_LEDGER_STA   1024
#define WEB_FRRS_LEDGER_BLE   512
#define WEB_FRRS_LEDGER_IP    256
#define WEB_FRRS_LEDGER_CHAN  64
#define WEB_FRRS_SNI          8
#define WEB_FRRS_SNI_MAX      64
#define WEB_FRRS_SEQ_PARTNERS 4
#define WEB_FRRS_MLD_LINKS    4
/* /api/frrs/states takes at most this many ids (the query bound,
 * WEB_QUERY_ROUTE_MAX, holds sixteen of the longest). */
#define WEB_FRRS_IDS_MAX      16
/* The lists a record shows. */
#define WEB_FRRS_LIST         8
/* Suggestions listed at most, in evidence order. */
#define WEB_FRRS_SUGGEST_MAX  200
/* The assessment file read for "follow recommended": read until its
 * front matter closes, at most this much (the longest real front
 * matter is under 5 KiB; a whole file is under 30 KiB). */
#define WEB_FRRS_ASSESS_MAX   32768
/* An import's triage lines: at most WEB_FRRS_IMPORT_TRIAGE in one file
 * (more is refused whole, 413, before a line is merged: one import runs
 * on the HTTP thread, and this bounds how long it holds it), and
 * imported rows at most WEB_FRRS_IMPORTED_CAP of the table. */
#define WEB_FRRS_IMPORT_TRIAGE 1000
#define WEB_FRRS_IMPORTED_CAP  (WEB_FRRS_TRIAGE_CAP / 2)
/* The export, one JSON Lines file, and so also what one import takes. */
#define WEB_FRRS_EXPORT_MAX   WEB_IMPORT_MAX
/* Anomaly triage and the links (web_relate.c). The subjects slothweb
 * remembers the descriptor of, the links in all and those naming one
 * finding (a write past either is refused, 507: a link is the
 * operator's, never folded), a link's label, how many candidates one
 * answer offers and how many of sloth.db's alerts it reads for them. */
#define WEB_FRRS_ANOM_SUBJECTS 8192
#define WEB_REL_CAP           8192
#define WEB_REL_PER           32
#define WEB_REL_LABEL_MAX     96
#define WEB_REL_SUGGEST       8
#define WEB_REL_ALERT_SCAN    32
/* Two findings on one subject are offered as possibly related when
 * their [first_seen, last_seen] spans overlap or lie within this of
 * each other. Ten minutes is the longest any anomaly rule looks back
 * before it can fire (A7's window, WEB_ANOM_A7_WINDOW_S; A8's is the
 * same ten minutes of DNS, A1 needs three), so an episode's first_seen
 * can trail what caused it by that much and no more. */
#define WEB_REL_WINDOW_S      600

/* known (4): known good, expected traffic from a friendly or neutral
 * emitter (the FRRS/EW affiliation sense: friend, or neutral per
 * MIL-STD-2525's green). Triaged out like false and noise, never an
 * incident. Appended, so 0..3 keep their stored values. */
enum { WEB_TRI_UNTRIAGED = 0, WEB_TRI_FALSE, WEB_TRI_NOISE, WEB_TRI_INCIDENT,
       WEB_TRI_KNOWN, WEB_TRI_COUNT };
/* How a row was written. agent (3): through slothweb-mcp, with the
 * run's agent secret (web_agent.h); never from a request's own say-so.
 * Appended, so 0..2 keep their stored values; notes and links record
 * the same numbers (0 or 3). */
enum { WEB_TRI_VIA_MANUAL = 0, WEB_TRI_VIA_RECOMMENDED, WEB_TRI_VIA_IMPORT,
       WEB_TRI_VIA_AGENT, WEB_TRI_VIA_COUNT };
/* The triage= filter of /api/alerts (§5.4): the five states, and three
 * groups: any (every row, each carrying its triage), triaged (the four
 * decided states) and out (false, noise or known: what the tile counts
 * as triaged out). */
enum { WEB_TRI_F_ANY = -1, WEB_TRI_F_TRIAGED = -2, WEB_TRI_F_OUT = -3 };
#define WEB_TRI_F_BAD (-100)

/* The current triage of one finding. */
typedef struct {
    int       state;                 /* WEB_TRI_* */
    int       prev_state, via;
    long long ts, finding;           /* finding 0: not resolved */
    int       history_n;
    long long folded;                /* rows of its history folded away */
    char      note[WEB_FRRS_NOTE_MAX + 1];
    char      by[WEB_FRRS_BY_MAX + 1];
    char      basis[WEB_FRRS_BASIS_MAX + 1];
    char      peer[WEB_PEER_MAX];
    /* An imported row: who and where the file said (claims, not facts;
     * peer is the importer's). */
    char      claim_by[WEB_FRRS_BY_MAX + 1];
    char      claim_peer[WEB_PEER_MAX];
    /* An anomaly's (anom 1): the first_seen of the episode the row was
     * written on (0: none was held), and whether that is another
     * episode than the one held now. */
    int       anom, carried;
    long long episode;
} web_tri_t;

/* What names one alert to the triage join: its id as the alert routes
 * give it ("s<handle>" or "d<rowid>"), the stream incident's key (a
 * predicate only, never stored) or the sloth.db row, and the
 * descriptor that survives a rebuild of sloth.db. */
typedef struct {
    const char *id;
    const char *key;                 /* NULL: not a stream incident */
    long long   rid;                 /* 0: not a sloth.db row */
    int         type, port;
    const char *ip;
    long long   first;
} web_tri_q_t;

typedef struct {
    char      peer[WEB_PEER_MAX];
    double    tokens;
    long long last_ms;
} web_frrs_bucket_t;

typedef struct {
    unsigned long writes, write_errors, rate_limited;
    unsigned long refused_origin, refused_ctype, refused_body, refused_size;
    unsigned long triage_folded, triage_unchanged, ledger_evictions;
    unsigned long imports, exports;
    unsigned long links_made, links_removed;
    unsigned long notes_added, notes_retracted, notes_folded;
    unsigned long refused_agent, agent_writes;
} web_frrs_stats_t;

struct web_frrs_led;
struct sqlite3;

typedef struct web_frrs {
    struct sqlite3      *wr;          /* the HTTP thread's writer; NULL none */
    char                 assess_dir[4096];   /* --web-assessments, "" unset */
    int                  writes;      /* 0 under --web-read-only */
    long long            triage_cap;  /* WEB_FRRS_TRIAGE_CAP; the tests lower it */
    long long            note_cap;    /* WEB_NOTE_CAP; the tests lower it */
    int                  note_per;    /* WEB_NOTE_PER; the tests lower it */
    /* The run's agent secret (web_agent.h), "" none: no agent path. */
    char                 agent_secret[65];
    unsigned             nonce;       /* the suggestion tokens' */
    web_frrs_bucket_t    bucket[WEB_FRRS_PEERS];
    pthread_mutex_t      lmu;         /* the ledger's and the stats' */
    int                  lmu_init;
    struct web_frrs_led *led;
    web_frrs_stats_t     st;
    char                 err[WEB_STORE_ERR_MAX];
} web_frrs_t;

/* Open on the store (store NULL or not open: the record still answers
 * from the ledger and sloth.db, every triage and TACDB route 503
 * no_store). assess_dir is --web-assessments or NULL. writes 0 is
 * --web-read-only. 0, or -1 with err (the writer could not open: the
 * store opened first, so this is a locked or vanished file). Call
 * web_frrs_destroy() either way. */
int  web_frrs_init(web_frrs_t *f, web_store_t *store, const char *assess_dir,
                   int writes, char *err, size_t errsz);
void web_frrs_destroy(web_frrs_t *f);

/* The ingest thread: every decoded record, for the ledger. */
void web_frrs_record(web_frrs_t *f, const web_jrec_t *r);

/* What the ledger holds of one Wi-Fi emitter's signal, for G2
 * (docs/web-visual-spec.md, slice V2): sloth's own distance band and
 * trend (src/rf_distance.h) from the latest beacon (bssid 1) or
 * probe_client (bssid 0) record of mac, and for a BSSID the beacon's
 * rssi_min_60s..rssi_max_60s. The page draws these words, so the glyph
 * says what sloth's estimate says and never a trend of its own. band
 * and trend are "" unless they are one of sloth's words (rf_band_name,
 * rf_trend_name); the range is set only when both ends are a reading
 * (-127..-1) in order. channel is that record's (0 when it names
 * none) and six whether a beacon's channel_source says 6 GHz, for the
 * S-meter's band row (web_rf.h "radio"). 1 when the ledger holds the
 * record, else 0. */
typedef struct {
    char      band[12], trend[14];
    int       have_range, rmin, rmax;
    int       channel, six;
    long long ts;                     /* the record's ts */
} web_frrs_rf_t;
int  web_frrs_rf(web_frrs_t *f, int bssid, const char *mac, web_frrs_rf_t *out);

/* The Wi-Fi band census for /api/radar (web_radar.h, 2026-11-06): every
 * BSSID with a beacon (kind "ap": its SSID) and every station with a
 * probe_client (kind "sta") the ledger holds, each with the record's
 * signal_dbm (has_rssi 0 when the record carried none: the ledger keeps
 * 0 for absent) and sloth's distance band word from its est members
 * ("" when there is no estimate or the word is not one of sloth's), as
 * web_frrs_rf() reads them; with the band, the estimate's metres (has_m
 * 0 unless finite and in 0..100000) and trend word ("" unless one of
 * sloth's four). cb is called once per row under the
 * ledger's lock, so it must not call back into this module; the strings
 * are the ledger's and valid for the call only. */
typedef struct {
    const char *kind;                /* "ap" or "sta" */
    const char *mac;
    const char *ssid;                /* "" for a station */
    int         has_rssi, rssi;
    const char *band;
    int         has_m;
    double      m;
    const char *trend;
    long long   ts;
} web_frrs_rf_row_t;
void web_frrs_rf_census(web_frrs_t *f, void (*cb)(const web_frrs_rf_row_t *, void *),
                        void *ctx);

/* Is this a path of the module (GET or POST)? */
int  web_frrs_path(const char *path);

/* The routes, GET and POST (docs/web-frrs-spec.md §5): the body into
 * body (cap bytes), *status set; *extra gets extra header lines
 * ("Retry-After: 2\r\n", a Content-Disposition) or "". An answer too
 * large for body (only the export) is put in *big, malloc'd, with
 * *biglen; the caller sends and frees it. 0, or -1 when not even an
 * error fit. */
int  web_frrs_route(const web_m4_t *m, web_live_t *live, const web_req_t *rq,
                    long long now_s, long long now_ms, char *body, size_t cap,
                    size_t *len, int *status, char *extra, size_t extracap,
                    char **big, size_t *biglen);

/* The write path's header checks (§5.3 steps 4-6), before a body byte
 * is read: whose write it is (web_agent.h: the browser's, held to
 * Origin and Sec-Fetch-Site, or the agent's, held to the run's secret),
 * the peer's token bucket (an agent's its own), the Content-Type. 0 to go on, else the status with the reason word in why
 * (and "Retry-After: N\r\n" in extra for a 429). f may be NULL (no
 * module: 503 no_store). Counted. */
int  web_frrs_gate(web_frrs_t *f, const web_req_t *rq, long long now_ms,
                   const char **why, char *extra, size_t extracap);
/* A refusal's JSON answer, headers and all, into out. Its length. */
size_t web_frrs_refusal(int status, const char *why, const char *extra,
                        char *out, size_t outsz);

/* The run's agent secret, from --web-agent-secret (web_agent.h); NULL
 * or "" for none. Before the server runs. */
void web_frrs_set_agent(web_frrs_t *f, const char *secret);

/* The triage of one alert for the alert routes' triage= join. c is an
 * open sloth.db connection or NULL. 1 with *out filled, 0 untriaged
 * (*out zeroed), -1 on a store error. */
int  web_frrs_triage_find(web_frrs_t *f, web_sdb_conn_t *c, const web_tri_q_t *q,
                          web_tri_t *out);
/* Whether any triage row exists: the join's shortcut. */
int  web_frrs_triage_any(web_frrs_t *f);
/* The current state of each triaged subject decided at or after since,
 * newest first (ts, then the row id), at most max, each to fn (nonzero
 * stops): the fleet export's verdicts (web_fleet.h). The descriptor and
 * the state only. after_ts >= 0: only those after (after_ts, after_id)
 * in that order, the export's keyset page. Rows given, 0 without a
 * store, -1 on an error. */
typedef struct {
    int       type, port, state;
    char      addr[WEB_FRRS_ADDR_MAX + 1];
    long long first_seen, ts, id;
} web_frrs_verdict_t;
int  web_frrs_verdicts(web_frrs_t *f, long long since, long long after_ts,
                       long long after_id, int max,
                       int (*fn)(void *ctx, const web_frrs_verdict_t *v), void *ctx);
/* For each of addrs (n, sorted by strcmp, canonical IPs or MACs) the
 * newest current state of a triaged subject whose descriptor's address
 * it is, else -1: the Fleet tab's verdicts (web_fleet.h), one pass over
 * triage for all of them. The state only. Addresses found, -1 on an
 * error. */
int  web_frrs_addr_states(web_frrs_t *f, const char *const *addrs, int n, int *state);
/* "any", "untriaged", "false", "noise", "incident", "known", "triaged", "out"
 * -> the WEB_TRI_* value or WEB_TRI_F_*; WEB_TRI_F_BAD for anything
 * else. */
int  web_frrs_filter_find(const char *word);
/* Does a triage state pass a triage= filter? */
int  web_frrs_filter_pass(int filter, int state);
/* Is a triage state triaged out (false, noise or known)? */
int  web_frrs_state_out(int state);
const char *web_frrs_state_word(int state);
const char *web_frrs_via_word(int via);

/* The research assessment's recommendation for an alert type (§3.1):
 * the WEB_TRI_* state, or WEB_TRI_UNTRIAGED for "no recommendation
 * yet"; basis gets the front-matter line that decided it ("" none), fm
 * the three keys' raw values (each "" when absent, printable ASCII,
 * cut). Reads <assess_dir>/<TYPE>.md with TYPE from the alert table,
 * never from a request. */
typedef struct {
    int  found;                      /* the file was there and had front matter */
    char fpr[48], noise[48], sev[48];
} web_frrs_fm_t;
int  web_frrs_recommend(const web_frrs_t *f, int type, char *basis, size_t basiscap,
                        web_frrs_fm_t *fm);

/* The "frrs" member of /api/health, preceded by a comma. */
void web_frrs_health(web_frrs_t *f, web_jw_t *w);
void web_frrs_stats(web_frrs_t *f, web_frrs_stats_t *out);

/* The write path's checks, each on its own for the tests: the Origin
 * rule (1 ok), the Content-Type rule (1 ok), the token bucket (1
 * admitted; cost tokens taken). */
int  web_frrs_origin_ok(const web_req_t *rq);
int  web_frrs_ctype_ok(const web_req_t *rq);
int  web_frrs_rate_admit(web_frrs_t *f, const char *peer, long long now_ms, int cost);

#endif
