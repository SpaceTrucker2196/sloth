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

#define WEB_OWN_SSIDS  16       /* sloth: MAX_MY_SSIDS */
#define WEB_OWN_BSSIDS 16       /* sloth: MAX_MY_BSSIDS */
#define WEB_OWN_KNOWN_MAX 512   /* sloth: MAX_KNOWN_MACS */

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

/* Writes null, true or false: the "designated" member of a route. */
void web_own_jw(web_jw_t *w, int answer);

#endif /* SLOTHWEB_OWN_H */
