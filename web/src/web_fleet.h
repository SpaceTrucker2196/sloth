/* The owner's own fleet (#192 F1; docs/wiki/adr/0008-own-fleet.md,
 * docs/wiki/fleet.md): each slothweb serves what its sensor has seen
 * to the peers its allow list admits, and pulls the same from the peers
 * it is told to, into its own slothweb.db. The sensor and sloth.db are
 * untouched; slothweb still never writes sloth.db.
 *
 * The export. GET /api/fleet/export?since=EPOCH, read-only, on the
 * existing listener, so only to the addresses --web-allow already
 * admits. JSON Lines, one flat object per line, so the puller reads it
 * with the stream's own strict decoder (web_jsonl.h) and nothing new:
 *
 *   {"type":"fleet_export",...}  the version, the site (label, the
 *                                sensor's position and its age), the
 *                                build, the window
 *   {"type":"gnss",...}          the receiver's summary
 *   {"type":"wifi"|"ble"|"ap"|"probe"|"alert"|"verdict",...}
 *                                the rows changed since `since`, newest
 *                                first, each kind at most its cap
 *   {"type":"fleet_end",...}     the count of each kind, a truncated_<kind>
 *                                flag for each, and "complete":true
 *
 * Every member of every line is named in web_fleet_members[] and in no
 * other place: the writer emits those names only, the reader refuses a
 * line holding any other, and the suite holds each name to
 * web_sdb_is_secret() (web_secret.h). The sloth.db rows come through
 * the M4 reader and its column allow-list (web_slothdb.h), so no
 * credential column, no alert key, no alert detail and no EAPOL table
 * can be read, whatever a later edit to this file says; an alert travels
 * as its type, title, severity, count, times and a fingerprint of its
 * type and title. Every line is held to the importer's own checks before
 * it is sent: a row the importer would refuse (a value a sensor stored
 * outside its ranges) is left out and its kind marked truncated, since
 * one such line refuses the whole answer at every pull.
 *
 * The pull. --peer NAME=URL (at most WEB_FLEET_PEERS), every
 * --peer-interval-secs (default 60), on a thread of its own: a plain
 * HTTP/1.1 GET over TCP to http://A.B.C.D[:PORT] (literal IPv4 only,
 * nothing is resolved), a connect deadline and one read deadline for the
 * whole answer, no transfer coding, the response held
 * to WEB_FLEET_RESP_MAX and refused whole past it. The address must be
 * in 100.64.0.0/10 (the tailnet: WireGuard binds it to a node key)
 * unless --peer-allow-outside-tailnet is given, which is announced.
 * Incremental: `since` is the peer's own clock at its last good answer
 * less WEB_FLEET_OVERLAP_S. A response is checked whole (every line
 * decoded, every member known, every value in range, the end line's
 * counts matching) before one row is written; a refused response writes
 * no sighting.
 *
 * The backfill (F2). `since` advances, so rows a kind's cap cut from an
 * answer would never be asked for again. The pull asks with next=1, and
 * the end line then carries next_<kind>, a cursor after the last row
 * sent, for each pageable kind (wifi, ap, alert, verdict) that was cut.
 * The puller keeps (the cut answer's since, the cursor) per kind
 * (web_fleet_bf_t, in slothweb.db's meta table in the same transaction
 * as the rows) and after each good pull asks for up to
 * WEB_FLEET_PAGES_PER_PULL pages, GET
 * /api/fleet/export?since=FLOOR&kind=K&after=CURSOR, each the next cap's
 * worth in the reader's own order (keyset on last_seen and the key, so a
 * row updated meanwhile moves out of the range to the incremental pull
 * and none is skipped), until a page is not cut. A probe list rides its
 * client's wifi row; the BLE table never holds more than its cap.
 *
 * The store (slothweb.db v8, web_store.h): peer_sites, one row per
 * peer, and peer_sightings, one row per (peer, kind, key), first_seen
 * and last_seen widened by every pull. The pull thread writes over a
 * connection of its own (web_store_open_aux()); the HTTP thread reads
 * over the store's read-only one. Bounded: at most WEB_FLEET_ROWS_PER_PEER
 * sightings a peer, the least recently seen dropped first, and none
 * older than WEB_FLEET_KEEP_S by the peer's clock. */
#ifndef SLOTHWEB_FLEET_H
#define SLOTHWEB_FLEET_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "web_json.h"
#include "web_store.h"

#define WEB_FLEET_EXPORT_VERSION 1
#define WEB_FLEET_PEERS          8
#define WEB_FLEET_NAME_MAX       32
#define WEB_FLEET_URL_MAX        64
#define WEB_FLEET_INTERVAL_DEF   60
#define WEB_FLEET_INTERVAL_MIN   10
#define WEB_FLEET_INTERVAL_MAX   3600
#define WEB_FLEET_OVERLAP_S      120
#define WEB_FLEET_ERR_MAX        159

/* Per-kind row caps of one export. */
#define WEB_FLEET_CAP_WIFI       2000
#define WEB_FLEET_CAP_BLE        1024
#define WEB_FLEET_CAP_AP         1000
#define WEB_FLEET_CAP_PROBE      4000
#define WEB_FLEET_CAP_ALERT      1000
#define WEB_FLEET_CAP_VERDICT    1000
/* A page cursor (web_fleet_cursor_ok()): "<last_seen>~<tok>", tok the
 * last row's key in its reader's order (a MAC or BSSID as sloth.db holds
 * it, an alert's rowid, a triage row's id), at most these bytes. */
#define WEB_FLEET_TOK_MAX        24
#define WEB_FLEET_CUR_MAX        40
/* SSIDs a client's probe list contributes at most. */
#define WEB_FLEET_PNL_PER        32
/* The export's own bound (a row that would pass it is not written and
 * its kind is marked truncated), and the puller's, a little wider: a
 * well-formed export never reaches it, so a response that does is not
 * one, and is refused rather than cut. */
#define WEB_FLEET_EXPORT_MAX     (8u << 20)
#define WEB_FLEET_RESP_MAX       (10u << 20)
#define WEB_FLEET_HDR_MAX        16384
/* A decoded string member of an imported row, at most (bytes). */
#define WEB_FLEET_STR_MAX        255
#define WEB_FLEET_CONNECT_MS     5000
#define WEB_FLEET_READ_MS        30000
#define WEB_FLEET_BUSY_MS        5000
#define WEB_FLEET_ROWS_PER_PEER  20000
/* Backfill pages of one kind a pull at most (web_fleet_bf_t). */
#define WEB_FLEET_PAGES_PER_PULL 4
/* A peer whose export refused next=1 (an F1 build) is pulled without it
 * for this long before it is asked with it again. */
#define WEB_FLEET_NONEXT_S       3600
#define WEB_FLEET_KEEP_S         (90LL * 86400)

enum { WEB_FK_WIFI = 0, WEB_FK_BLE, WEB_FK_AP, WEB_FK_PROBE, WEB_FK_ALERT,
       WEB_FK_VERDICT, WEB_FK_COUNT };

/* The kind's word ("wifi", ...), the line type and peer_sightings.kind. */
const char *web_fleet_kind_word(int k);
/* 1 for a kind the export pages (wifi, ap, alert, verdict): a cut there
 * carries a next_<kind> cursor. A probe list rides its client's wifi
 * row; the BLE table is never larger than its cap. */
int  web_fleet_kind_pages(int k);
/* Is s a cursor: 1..12 digits, '~', 0..WEB_FLEET_TOK_MAX of
 * [0-9A-Za-z:]? */
int  web_fleet_cursor_ok(const char *s);

/* The members each line type may carry, NULL-ended per type, the type
 * name first in each row. web_fleet_members_of() answers NULL for a
 * type that is not one. */
extern const char *const *const web_fleet_members[];
extern const size_t web_fleet_members_n;
const char *const *web_fleet_members_of(const char *type);

typedef struct {
    char      name[WEB_FLEET_NAME_MAX + 1];
    char      url[WEB_FLEET_URL_MAX + 1];
    uint8_t   addr[4];
    uint16_t  port;
} web_fleet_peer_cfg_t;

/* "NAME=http://A.B.C.D[:PORT][/]". NAME is 1..32 of [A-Za-z0-9._-];
 * the address a literal IPv4 (no name is ever resolved), the port
 * 1..65535 (80 when absent, as for any http URL). Syntax only: the
 * tailnet rule is web_fleet_check_peer(). 0, or -1 with err. */
int  web_fleet_parse_peer(const char *spec, web_fleet_peer_cfg_t *out,
                          char *err, size_t errsz);
/* 1 when a is in 100.64.0.0/10. */
int  web_fleet_in_tailnet(const uint8_t a[4]);
/* The tailnet rule: 0, or -1 with err when the address is outside it
 * and allow_outside is 0. */
int  web_fleet_check_peer(const web_fleet_peer_cfg_t *p, int allow_outside,
                          char *err, size_t errsz);

/* A kind's backfill (F2): the rows a cut answer left behind, from
 * floor (the cut answer's since) to the cursor, fetched a page a pull
 * until a page is not cut. Kept in slothweb.db's meta table while it
 * runs, so a restart resumes it. */
typedef struct {
    int       active;
    long long floor;
    char      cur[WEB_FLEET_CUR_MAX + 1];
} web_fleet_bf_t;

typedef struct {
    web_fleet_peer_cfg_t cfg;
    long long last_attempt, last_ok;       /* unix s, 0 never */
    long long remote_ts;                   /* the peer's clock at its last
                                              good answer, 0 none */
    long long rows_last;
    unsigned long pulls, failures;
    unsigned long pages, page_failures;    /* backfill pages fetched, refused */
    long long no_next_until;               /* an F1 peer: plain pulls until then */
    web_fleet_bf_t bf[WEB_FK_COUNT];
    char      last_error[WEB_FLEET_ERR_MAX + 1];
} web_fleet_peer_t;


struct sqlite3;

typedef struct web_fleet {
    pthread_mutex_t   mu;                  /* guards peer[] and the counts */
    pthread_cond_t    cv;
    pthread_t         th;
    int               started, stop;
    web_fleet_peer_t  peer[WEB_FLEET_PEERS];
    int               npeer;
    int               interval_s;
    int               allow_outside;
    web_store_t *store;               /* NULL: no store, nothing pulled */
    struct sqlite3   *wr;                  /* the pull thread's own */
    /* Test seams, the defaults otherwise. */
    int               connect_ms, read_ms;
    size_t            resp_max;
    int               pages_per_pull;
} web_fleet_t;

/* Set up (no thread, no connection). peers may be NULL with n 0. */
void web_fleet_init(web_fleet_t *f, const web_fleet_peer_cfg_t *peers, int n,
                    int interval_s, int allow_outside, web_store_t *store);
/* Open the pull thread's connection and read back each peer's last
 * good pull from peer_sites; then start the thread when there is a
 * peer. 0, or -1 with err. */
int  web_fleet_start(web_fleet_t *f, char *err, size_t errsz);
void web_fleet_stop(web_fleet_t *f);
/* Read back each peer's last good pull from peer_sites and each kind's
 * backfill from meta, over the pull thread's connection (f->wr):
 * web_fleet_start()'s first step, and the tests' restart. */
void web_fleet_load(web_fleet_t *f);
void web_fleet_destroy(web_fleet_t *f);

/* One pull of peer i, now (the thread's step; the tests call it
 * directly). 0 stored, -1 refused or failed (the reason in the peer's
 * last_error). */
int  web_fleet_pull_one(web_fleet_t *f, int i, long long now_s);

/* Validate a whole export body and, when write is set and it passes,
 * store it as peer i's answer in one transaction. 0, or -1 with err.
 * *rows gets the data lines, *remote_ts the header's generated. */
int  web_fleet_ingest(web_fleet_t *f, int i, const char *body, size_t len,
                      long long now_s, int write, long long *rows,
                      long long *remote_ts, char *err, size_t errsz);

/* /api/health's "fleet" member. */
void web_fleet_health_json(web_fleet_t *f, web_jw_t *w, long long now_s);

/* /api/fleet/peers: peer_sites and each peer's sightings by kind, into
 * body. 0 with *len, *status set; -1 when it did not fit. */
int  web_fleet_peers_route(web_fleet_t *f, const char *query, long long now_s,
                           char *body, size_t cap, size_t *len, int *status);

struct web_slothdb;
struct web_ble;
struct web_gnss;
struct web_frrs;

/* What the export reads; any may be NULL (its lines are then absent,
 * and the header says why for sloth.db). */
typedef struct {
    struct web_slothdb *sdb;
    struct web_ble     *ble;
    struct web_gnss    *gnss;
    struct web_frrs    *frrs;
} web_fleet_src_t;

/* /api/fleet/export: a heap body the caller frees, in *body. 0 with
 * *status (200, 400 or 503), -1 out of memory. */
int  web_fleet_export_route(const web_fleet_src_t *src, const char *query,
                            long long now_s, char **body, size_t *len,
                            int *status);

/* ── the Fleet tab (F2) ── */

/* The shared list's rows: the default and the most a request may ask
 * for; the peer rows it scans for keys, newest first; its body's bound. */
#define WEB_FLEET_SHARED_DEF   50
#define WEB_FLEET_SHARED_MAX   200
#define WEB_FLEET_SHARED_SCAN  5000
#define WEB_FLEET_SHARED_BODY  (1u << 20)

/* The great-circle distance between two positions, metres (haversine on
 * the IUGG mean radius, 6,371,008.8 m). */
double web_fleet_dist_m(double lat1, double lon1, double lat2, double lon2);

/* GET /api/fleet/overview: this site (its label, the position the export
 * sends, sloth.db's state) and each peer from peer_sites and its live
 * state (position; last good pull and attempt, last refusal; clock skew,
 * the peer's clock at its last good answer less this one's then; the
 * rows by kind; each kind's backfill), and the distance between every
 * pair of sites with a position. Into body; 0 with *len and *status, -1
 * when it did not fit. A site is the whole sensor, whatever the scope. */
int  web_fleet_overview_route(web_fleet_t *f, const web_fleet_src_t *src, const char *query,
                              long long now_s, char *body, size_t cap, size_t *len,
                              int *status);
/* GET /api/fleet/shared?kind=wifi|ble|ap|probe&limit=N: the keys of the
 * kind a peer sent that this site holds too (sloth.db through the M4
 * reader, read-only; a BLE address from slothweb's own table), each
 * site's first and last seen and signal, the newest activity at any
 * site first, at most limit (50, 1..200). The newest
 * WEB_FLEET_SHARED_SCAN peer rows are looked at, the local reads within
 * the overview budget; "partial" says either stopped short. A heap body
 * the caller frees; 0 with *status, -1 out of memory. */
int  web_fleet_shared_route(web_fleet_t *f, const web_fleet_src_t *src, const char *query,
                            long long now_s, char **body, size_t *len, int *status);

#endif
