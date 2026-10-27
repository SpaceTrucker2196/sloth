/* slothweb Devices and Lookup routes (#162, M4): docs/web-ui-spec.md
 * §7's /api/devices, /api/device/{mac} and /api/lookup, §8.6, §8.11,
 * §9.1-9.3 as the rulings header amends them (no active lookup, ever).
 *
 *   /api/devices?q=&sort=&limit=&offset=
 *       the devices of sloth.db that the query (web_query.h) matches,
 *       sorted (last, first, mac, risk), limit 1..WEB_DEV_LIMIT_MAX
 *       (default WEB_DEV_LIMIT) from offset 0..WEB_DEV_OFFSET_MAX. Each
 *       row has the §8.6 columns that have a source, the vendor from
 *       the OUI table (sloth's own label when the table has none), the
 *       best passive name with its source glyph, the |z| now and the
 *       anomaly count from the engine, and the 24 h presence strip
 *       (144 cells of 10 minutes, as 36 hex digits, cell 0 the oldest)
 *       from slothweb.db's minute tier and the in-memory fine ring.
 *       "more" and "next_offset" page on; a page stops early, with
 *       "more", rather than not fit its buffer.
 *   /api/device/{mac}
 *       one device: the allow-listed sloth.db record, PNL SSIDs,
 *       associations, ARP bindings, every passive name with its source
 *       and time, the presence strip and the 168 hour-of-week cells of
 *       dev.present from the baseline, its anomaly episodes, and the
 *       alerts sloth.db has that name it. Each list is capped, and says
 *       so when cut.
 *   /api/lookup?q=MAC-or-IP
 *       the card of §8.11: for a MAC its OUI block, registry, vendor,
 *       local and multicast bits and the table it came from; for an IP
 *       its ARP MACs; for both every passive name seen (sloth.db, the
 *       stream, the passive PTR cache), and the device record if
 *       sloth.db has one.
 *
 * Parameters are validated whole before anything is read, as
 * /api/series's are, and a refusal is a 400 with a reason word of
 * slothweb's own. Without --sloth-db (or in a build without SQLite)
 * /api/devices is a 503 "no_sloth_db" and the other two answer from the
 * stream and the OUI table alone, saying "db" is not open. */
#ifndef SLOTHWEB_DEVICES_H
#define SLOTHWEB_DEVICES_H

#include <stddef.h>

#include "web_anomaly.h"
#include "web_ident.h"
#include "web_json.h"
#include "web_oui.h"
#include "web_ptr.h"
#include "web_scope.h"
#include "web_slothdb.h"
#include "web_tsdb.h"

#define WEB_DEV_LIMIT       100
#define WEB_DEV_LIMIT_MAX   200
#define WEB_DEV_OFFSET_MAX  100000
#define WEB_DEV_CELLS       144
#define WEB_DEV_CELL_S      600
/* The largest one device row renders to: every text member at its cut
 * length, each byte escaped six-fold, and the fixed members. */
#define WEB_DEV_ROW_MAX     2600

typedef struct {
    web_slothdb_t       *sdb;      /* NULL: no --sloth-db */
    const web_oui_tab_t *oui;
    web_ptr_t           *ptr;
    web_ident_t         *ident;
    web_anomaly_t       *anomaly;
    web_tsdb_t          *tsdb;
    /* The request's capture scope (web_scope.h); NULL is Hybrid. Set by
     * the router on its own copy, never on the shared one. */
    const web_scope_ctx_t *sc;
} web_m4_t;

/* The routes. Each renders its JSON body into body (cap bytes) and sets
 * *status; 0, or -1 when even an error did not fit. */
int web_devices_route(const web_m4_t *m, const char *query, long long now_s,
                      char *body, size_t cap, size_t *len, int *status);
int web_device_route(const web_m4_t *m, const char *path_mac,
                     const char *query, long long now_s, char *body,
                     size_t cap, size_t *len, int *status);
int web_lookup_route(const web_m4_t *m, const char *query, long long now_s,
                     char *body, size_t cap, size_t *len, int *status);

/* The M4 members of /api/health: the sloth.db reader, the vendor table,
 * the passive PTR cache, A4's state. */
void web_m4_health(const web_m4_t *m, long long now_s, web_jw_t *w);

/* The age in seconds of the sloth.db data the last health check read
 * (#168): 1 with *age_s set (never negative: an mtime ahead of the clock
 * reads as 0), or 0 when there is no --sloth-db or it is not open. */
int  web_m4_db_age(const web_m4_t *m, long long now_s, long long *age_s);

/* The presence strip of mac: 144 cells of 10 minutes ending with the
 * cell now_s is in, as 36 lower-case hex digits (cell 0 the oldest,
 * its bit the high bit of the first digit) into out[37]. For the
 * tests and the two routes. */
void web_dev_presence_hex(const unsigned char bits[WEB_DEV_CELLS / 8],
                          char out[WEB_DEV_CELLS / 4 + 1]);

#endif
