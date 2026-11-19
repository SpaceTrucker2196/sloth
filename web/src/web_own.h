/* slothweb: the operator's designated networks, as sloth reports them
 * (owner ruling 2026-11-11: "export your designated networks from the
 * sensor"; docs/wiki/jsonl-schema.md `ownership`).
 *
 * sloth's --my-ssid and --my-bssid rosters are its own configuration
 * and in neither sloth.db nor any other record, so until sloth writes
 * an `ownership` record slothweb cannot say which networks are the
 * operator's. This keeps the newest such record in memory, replaced
 * whole by the next (the roster is a set, not a log), and answers three
 * questions for the routes that mark a network "yours": is this SSID
 * designated, is this BSSID designated, and has sloth said at all.
 *
 * "Not known" is its own answer, never "no": a slothweb that has not
 * received the record (an older sloth, a copied sloth.db with no live
 * stream, or the first heartbeat not yet arrived) says so rather than
 * marking nothing and letting that read as "none of these are yours".
 *
 * The SSIDs arrive as the stream writes every string (RFC 8259 escapes,
 * valid UTF-8; docs/wiki/jsonl-schema.md *Common envelope*) and are
 * compared octet for octet with sloth.db's text, as sloth compares them
 * (ownership_is_my_ssid(): exact, case-sensitive). The known-device
 * roster travels as a count only.
 *
 * sloth's own configuration, so every scope's. Bounded like sloth's
 * tables (MAX_MY_SSIDS, MAX_MY_BSSIDS); a record past the bounds, or
 * with a malformed member, is refused whole and the last good one kept. */
#ifndef SLOTHWEB_OWN_H
#define SLOTHWEB_OWN_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "web_json.h"
#include "web_jsonl.h"
#include "web_scope.h"

#define WEB_OWN_SSIDS  16       /* sloth: MAX_MY_SSIDS */
#define WEB_OWN_BSSIDS 16       /* sloth: MAX_MY_BSSIDS */
#define WEB_OWN_KNOWN_MAX 512   /* sloth: MAX_KNOWN_MACS */

/* The managed card's joined network (#234). Monitor hides it from the
 * inventory: its APs, the clients associated to them, the probes for it
 * and their device rows; Hybrid shows it. Learned from the stream, never
 * configured, so it follows the card to another network:
 *   - wifi_sta, the managed card's station dump: on a managed interface
 *     its one station is the AP, so the newest wifi_sta's mac is the
 *     joined BSSID (Local provenance, read to filter and never shown);
 *   - wifi_ap (the card's scan) and beacon: BSSID to SSID, so the joined
 *     SSID and every BSSID that advertises it;
 *   - assoc, eapol, wifi_assoc_req, btm_request: station to BSSID, so the
 *     clients of those BSSIDs.
 * A wifi_sta older than WEB_OWN_JOIN_STALE_MS is no longer a joined
 * network: sloth's records are change-only with a five-minute heartbeat.
 * Alerts are not filtered (owner ruling 2026-11-19 on #234): an attack
 * on the own network is the reason to watch it. */
#define WEB_OWN_JOIN_NETS     256
#define WEB_OWN_JOIN_CLIENTS  256
#define WEB_OWN_JOIN_BSSIDS   32
#define WEB_OWN_JOIN_STALE_MS 360000LL

typedef struct {
    uint8_t   b[6];
    size_t    n;                          /* SSID octets */
    char      ssid[33];
    long long ms;
} web_own_net_t;

typedef struct {
    uint8_t   sta[6], ap[6];
    long long ms;
} web_own_cli_t;

/* One request's view of the joined network: taken once, then read with
 * no lock. */
typedef struct web_own_join_s {
    int     have;                         /* a joined network is known */
    size_t  ssid_len;                     /* 0: its SSID not heard yet */
    char    ssid[33];
    int     nb;
    uint8_t b[WEB_OWN_JOIN_BSSIDS][6];
    int     nc;
    uint8_t c[WEB_OWN_JOIN_CLIENTS][6];
    unsigned long hidden;                 /* rows a route passed over */
} web_own_join_t;

typedef struct web_own {
    pthread_mutex_t mu;
    int       seen;                       /* an ownership record was kept */
    long long ts, rx_ms;
    int       nssid;
    char      ssid[WEB_OWN_SSIDS][33];
    size_t    ssid_len[WEB_OWN_SSIDS];
    int       nbssid;
    uint8_t   bssid[WEB_OWN_BSSIDS][6];
    long long known_macs;
    unsigned long records, rejected;
    /* The joined network (#234). */
    int       join_have;
    uint8_t   join_bssid[6];
    long long join_ms;
    int       nnet, ncli;
    web_own_net_t net[WEB_OWN_JOIN_NETS];
    web_own_cli_t cli[WEB_OWN_JOIN_CLIENTS];
} web_own_t;

int  web_own_init(web_own_t *o);
void web_own_destroy(web_own_t *o);

/* Every decoded record; `ownership` applies, the rest return. */
void web_own_record(web_own_t *o, const web_jrec_t *r, long long now_ms);

/* The instance the routes consult (main.c binds the live one; a test
 * binds its own). NULL: none, every answer "not known". */
void web_own_bind(web_own_t *o);

/* -1 not known (no record), 0 not designated, 1 designated. ssid is n
 * octets; an empty SSID is never designated (sloth refuses one). */
int  web_own_ssid(const char *ssid, size_t n);
/* bssid as "aa:bb:cc:dd:ee:ff", either case. -1 / 0 / 1 as above; a
 * string that is not a MAC is 0 once a record is known. */
int  web_own_bssid(const char *bssid);
/* How many SSIDs are designated, -1 not known. */
int  web_own_ssid_count(void);

/* The joined network as of now_ms (monotonic, the clock records are
 * stamped with) into j: 1 when one is known, else 0 with j->have 0. */
int  web_own_join_at(web_own_join_t *j, long long now_ms);
/* The same, for a request under scope sc: only Monitor hides the joined
 * network, so under any other scope (or sc NULL) j->have is 0. */
int  web_own_join_for(const web_scope_ctx_t *sc, web_own_join_t *j);
/* Is mac ("aa:bb:..", either case) one of j's BSSIDs or clients? */
int  web_own_join_mac(const web_own_join_t *j, const char *mac);
/* The same for six address bytes. */
int  web_own_join_macb(const web_own_join_t *j, const uint8_t m[6]);
/* Is ssid (n octets) j's SSID? */
int  web_own_join_ssid(const web_own_join_t *j, const char *ssid, size_t n);
/* Does a decoded record name the joined network: a bssid, sta_mac, mac,
 * src or dst of it, or its ssid? */
int  web_own_join_rec(const web_own_join_t *j, const web_jrec_t *r);
/* "own_hidden": how many rows j's route passed over, as a member after
 * a comma, only when j->have. */
void web_own_join_jw(web_jw_t *w, const web_own_join_t *j);

/* Writes null, true or false: the "designated" member of a route. */
void web_own_jw(web_jw_t *w, int answer);

#endif /* SLOTHWEB_OWN_H */
