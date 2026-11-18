/* slothweb: plain notes on the things the page lists that are not
 * findings (owner request 2026-11-11: "an openclaw agent will need to
 * read the data thru an mcp and add notes to anomalies, devices, and
 * other observations and devices").
 *
 * An alert's or an anomaly's note is its triage row (web_frrs.h) and
 * stays there: this module holds none, so there is one place a
 * finding's note lives. A note here is text, who, from where, when and
 * how (the page, or an agent through slothweb-mcp), on one subject:
 *
 *   device    a MAC, canonical (web_dev_canon_mac())
 *   ble       a BLE advertiser as the links name one, its address and
 *             address type ("aa:bb:cc:dd:ee:ff/1"); the anonymous
 *             address (type 255) names no one advertiser and is refused
 *   ssid      an SSID's octets as /api/wifi/ssid's parameter spells
 *             them (web_ssid_param(): base64url, canonical, 1..32
 *             octets). Never the display form: two SSIDs can share one.
 *             The empty SSID ("-") is every hidden network and is
 *             refused
 *   gnss      a satellite, "gnssid.prn" in decimal (0..127, 0..32767),
 *             the key of web_gnss.c's table and of /api/gnss/sat
 *   aircraft  an ICAO 24-bit address as sloth writes one, six lower-case
 *             hex digits, '~' before a non-ICAO one (web_adsb.c)
 *   aprs      an AX.25 callsign with its optional -SSID
 *             (web_aprs_call_ok())
 *
 * The id is validated to that format whole, and a note is added only
 * to a subject slothweb holds now (a device sloth.db, the stream or the
 * ledger has; an advertiser in the ledger; an SSID in sloth.db's beacon
 * or probe tables; a satellite, aircraft or station in its panel's
 * table): a note on nothing is never written. Reading and retracting
 * need no holder, so a note outlives what it was written on and says
 * "held": false.
 *
 * Append-only. Taking a note back is another row naming it (a
 * retraction, with who and an optional reason), as a triage clear is a
 * row: the note stays listed, struck, until it folds. Bounds: a subject
 * holds WEB_NOTE_PER rows and the table WEB_NOTE_CAP; at either, the
 * oldest retracted notes fold with their retractions (the count kept on
 * the subject's oldest row), and with nothing retracted left to fold a
 * new note is refused, 507 "notes_full". A note that was not taken back
 * is never dropped. A retraction is never refused for room: it folds
 * its own pair when it lands past a cap.
 *
 *   GET  /api/frrs/notes?kind=&id=[&before=N]
 *        the subject's notes, newest first, each with its retraction if
 *        it has one; "more" and "next" when the body's room stopped the
 *        list (before= continues it)
 *   GET  /api/frrs/notes/marks?kind=&ids=a,b,c
 *        which of up to WEB_NOTE_MARK_IDS ids hold a note not taken
 *        back: the count, how many of those an agent wrote, the newest
 *        ts. One read for a table's page of rows
 *   POST /api/frrs/note   {"op":"add","kind":..,"id":..,"text":..,"by":..}
 *                         {"op":"retract","kind":..,"id":..,"note":N,
 *                          "text":<reason>,"by":..}
 *        through web_frrs.c's write path and gate, like every write
 *
 * Every stored string is an id validated here, slothweb's own words or
 * text from the validated POST body (frrs_text(): UTF-8, no control or
 * bidirectional-control character, over-long refused and never cut);
 * nothing from the stream. Every statement binds its values. */
#ifndef SLOTHWEB_NOTES_H
#define SLOTHWEB_NOTES_H

#include <stddef.h>

#include "web_frrs.h"

/* note.kind: appended only, the stored values stand. */
enum { WEB_NOTE_DEVICE = 0, WEB_NOTE_BLE, WEB_NOTE_SSID, WEB_NOTE_GNSS,
       WEB_NOTE_AIRCRAFT, WEB_NOTE_APRS, WEB_NOTE_KINDS };

#define WEB_NOTE_CAP       20000
#define WEB_NOTE_PER       64
/* Folded at once when the table is at its cap: the cap over this. */
#define WEB_NOTE_FOLD_DIV  100
/* The longest id: an SSID's 32 octets in base64url. */
#define WEB_NOTE_ID_MAX    43
#define WEB_NOTE_MARK_IDS  24
/* One listed note at its worst: the text and a reason at their bound,
 * every byte a six-byte escape, and the fixed members. */
#define WEB_NOTE_ROW_MAX   (2 * WEB_FRRS_NOTE_MAX * 6 + 4 * WEB_FRRS_BY_MAX * 6 + 512)

const char *web_note_kind_word(int kind);
int  web_note_kind_find(const char *word);
/* in as a request names a subject of kind, canonical into out
 * (WEB_NOTE_ID_MAX + 1). 0, or -1: not that kind's format. */
int  web_note_canon(int kind, const char *in, char *out);

/* The routes (dispatched by web_frrs_route()): the body into body,
 * *status set; 0, or -1 when not even an error fit. via is how the
 * write arrived, WEB_TRI_VIA_MANUAL or WEB_TRI_VIA_AGENT, decided by
 * the gate and never by the body. */
int  web_notes_get(const web_m4_t *m, web_live_t *live, const char *query, long long now_s,
                   char *body, size_t cap, size_t *len, int *status);
int  web_notes_marks(const web_m4_t *m, const char *query, char *body, size_t cap,
                     size_t *len, int *status);
int  web_notes_post(const web_m4_t *m, web_live_t *live, const web_jrec_t *r,
                    const char *peer, int via, long long now_s, char *body, size_t cap,
                    size_t *len, int *status);

/* The table's row count for /api/health, or -1 without a store. */
long long web_notes_rows(web_frrs_t *f);

#endif
