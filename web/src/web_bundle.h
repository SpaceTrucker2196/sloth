/* /api/bundle (owner request 2026-10-27): one JSON document holding
 * everything a detail view shows, for the page's "copy JSON" button,
 * so an operator can paste a device, an alert or a Lookup result into
 * Claude for analysis.
 *
 *   /api/bundle?kind=device|alert|lookup|ble|platform&id=...
 *       kind=device   id a MAC, folded as /api/device/{mac} folds it
 *       kind=alert    id s<handle> or d<rowid>, as /api/alert takes it
 *       kind=lookup   id a MAC or an IP, as /api/lookup?q= takes it
 *       kind=ble      id a BLE address, as /api/ble/{addr} takes it
 *                     (every sensor's row of it; the out-of-scope note
 *                     under Local, as the router answers)
 *       kind=platform id a TACDB platform's, as /api/frrs/tacdb/view
 *                     takes it
 *
 * The bundle does not re-render anything. Every detail route renders
 * straight into a buffer through web_jw_t and keeps no struct, and its
 * withholding (the detail gate, the predicate-only key, the opaque
 * ids, the lists a capture scope empties) lives in that rendering; so
 * the bundle calls the route functions themselves and splices their
 * bodies in verbatim as members ("device.drawer", "alert.page",
 * "lookup.card", "ble.drawer", "platform.view", and the nested
 * "alert.device" / "lookup.device"). Sections whose data a route
 * already answers are that route's bytes too: the FRRS record and the
 * alert's triage history are web_frrs_route()'s answers to the GETs the
 * page's panels make (/api/frrs/report, /api/frrs/report/alert,
 * /api/frrs/history), and vendor_research, assessment and evidence are
 * members of the primary answer lifted out whole (jmember()). A
 * bundle can carry nothing the page would not show, by construction:
 * web/tests/test_bundle.c compares the spliced bytes to the routes'
 * and reruns the alert routes' credential and incident-id tests
 * against every kind.
 *
 * Around the splices: an envelope (schema, when, the server, the
 * sensor as sensor_health told it, sloth.db's state, the scope in
 * effect and what it excludes, a "withheld" list naming what was left
 * out and why), the optional sections of the registry below, and three
 * analysis aids: a glossary of every field and unit, a suggested
 * prompt, and the limits applied.
 *
 * Optional sections and the registry. Each kind's sections past its
 * primary splice are rows of web_bundle_sections[]: a name, a fill
 * function and a cap. A row with no fill is written as
 * {"available":false,"reason":<its reason>} ("not_built" for a feature
 * no build has yet, "not_kept" for a stream field slothweb does not
 * retain); a fill that returns 0 as "no_data"; one that overflows its
 * cap, or the bundle's, is rolled back to "too_large"; a nested
 * sub-read that failed says why in its own route's words
 * (web_bundle_nested_reason(); "no_store" when an FRRS route needs
 * slothweb.db and it is not open). The reason words are fixed
 * (WEB_BUNDLE_REASONS) so the prompt can tell "slothweb cannot know"
 * from "this build has not got it yet". A slice that lands after this
 * one adds its row and function; one that lands before changes
 * nothing until this lands, then adds the same row. The page's hook
 * (web/ui/bundle.js) already passes the kind word.
 *
 * Bounds: the body is a heap buffer of at most web_bundle_max bytes
 * (WEB_BUNDLE_MAX, 512 KB; a test may lower it). The envelope, the
 * primary splice, the glossary, the prompt and the limits are
 * required and written first; the optional sections follow in table
 * order and are the ones rolled back; "limits.truncated_sections"
 * names them. Every list is a route's own capped list, or the 50
 * records of the ticker ring. Each sloth.db read keeps WEB_SDB_HTTP_MS
 * on its own connection, as the page's parallel requests do; a bundle
 * is at most four serial reads (an alert's: the page, its device or
 * address, its FRRS record, its triage), and "limits.reads" reports
 * each.
 *
 * GET only: a HEAD is a 405, as /api/alert's (nothing to describe
 * without reading sloth.db). The body is owned (web_resp_t.body_owned)
 * because it can outgrow the connection's buffer. */
#ifndef SLOTHWEB_BUNDLE_H
#define SLOTHWEB_BUNDLE_H

#include <stddef.h>

#include "web_json.h"
#include "web_routes.h"

#define WEB_BUNDLE_SCHEMA  "1.0.0"
#define WEB_BUNDLE_MAX     (512 * 1024)
/* The room held back for "limits" (its most, with every list named)
 * when the optional sections are measured against the cap. */
#define WEB_BUNDLE_LIMITS_MAX 4096
/* The longest unavailable marker an optional row can roll back to (the
 * too_large one, its cap at 20 digits): held back for every row of the
 * kind, beside its member name, since markers are written past the
 * fills' budget. */
#define WEB_BUNDLE_MARKER_MAX \
    (sizeof("{\"available\":false,\"reason\":\"too_large\",\"cap_bytes\":}") + 20)
/* The ticker ring: the most records_recent / records_around can hold. */
#define WEB_BUNDLE_RECORDS 50
/* The cap each spliced route renders into: what a route gets behind
 * its header in the connection's buffer (web_server.h, web_routes.h),
 * so a spliced body is cut exactly where the page's would be. */
#define WEB_BUNDLE_SCRATCH (65536 - WEB_LIVE_HDR_RESERVE)

/* The hard cap in force: WEB_BUNDLE_MAX, lowered only by a test. */
extern size_t web_bundle_max;
/* The scratch the stream summary renders into for records_by_type_global:
 * WEB_BUNDLE_SCRATCH, lowered only by a test. */
extern size_t web_bundle_scratch;

struct web_bundle_ctx;
typedef struct web_bundle_ctx web_bundle_ctx_t;

/* Writes the member's value into w. Returns the bytes it wrote, 0 to
 * say "no_data" (the writer is rolled back either way on 0). */
typedef size_t (*web_bundle_fill_fn)(const web_bundle_ctx_t *, web_jw_t *);

typedef struct {
    const char        *kind;      /* "device", "alert", "lookup", ... */
    const char        *name;      /* the member's name under the kind */
    web_bundle_fill_fn fill;      /* NULL: written as unavailable */
    const char        *reason;    /* for a NULL fill: "not_built" or "not_kept" */
    size_t             cap_bytes;
} web_bundle_sec_t;

extern const web_bundle_sec_t web_bundle_sections[];
extern const size_t           web_bundle_sections_n;

/* The fixed reason words an unavailable section may carry. */
extern const char *const web_bundle_reasons[];
extern const size_t      web_bundle_reasons_n;

/* The reason word for a nested sub-read (an alert's or a Lookup card's
 * device drawer, an alert's Lookup card, an FRRS route's answer) that
 * did not answer 200: status is the route's, or a negative when it
 * could not render (-1 its body overflowed its cap, -2 memory), body
 * its answer or NULL. 400 / 404 are "no_data", a sloth.db timeout
 * "budget", no sloth.db "no_sloth_db", no slothweb.db "no_store", an
 * overflow (or the FRRS record_too_large) "too_large", anything else
 * "read_error". */
const char *web_bundle_nested_reason(int status, const char *body);

/* The route. query is the request's (scope already taken out by the
 * router). On 0 *body is a malloc'd JSON body of *len bytes (the
 * caller frees it) and *status its status: 200, or 400/404/413/503
 * with {"error":...}. -1 when memory ran out. */
int web_bundle_route(const web_health_t *h, const char *query,
                     char **body, size_t *len, int *status);

#endif
