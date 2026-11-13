/* slothweb's Spectrum tab (2026-11-13, docs/wiki/sdr-sweep.md): the
 * latest sweep sloth-sdrsweep wrote, and the one write that asks for
 * another.
 *
 * slothweb never drives the radio. sloth-sdrsweep (src/sdrsweep/), run
 * by sloth-sdrsweep.service under its own account, does; it writes
 * latest.json (the sweep), prev.json (the one before) and status.json
 * (running, done, the next allowed start) into its state directory,
 * WEB_SPECTRUM_DIR by default (--spectrum-dir), world-readable.
 *
 *   GET /api/spectrum            the status, and the latest sweep under
 *                                "sweep" (null when there is none)
 *   GET /api/spectrum?status=1   the status alone, for polling a run
 *   POST /api/spectrum/run       ask for a run: creates the request
 *                                file (--spectrum-request), which
 *                                sloth-sdrsweep.path watches. 202, or
 *                                409 running/queued, 429 with
 *                                Retry-After inside the cooldown, 503
 *                                not installed.
 *
 * The request carries nothing. Its body is not read: there is no
 * parameter a browser can set, and the helper reads its settings from
 * /etc/default/sloth-sdrsweep alone. The POST passes the write surface's
 * gate first (Origin equal to Host, Sec-Fetch-Site, the peer's bucket,
 * Content-Type; web_frrs.h) and is refused to the agent header: the
 * radio is the operator's. --web-read-only makes it 405 like every
 * POST. A GET never creates, removes or writes anything.
 *
 * Everything read is another account's output and treated as untrusted:
 * latest.json is read only when it is a regular file of at most
 * WEB_SPECTRUM_MAX_BYTES (else "sweep_error":"too_large"), parsed by a
 * strict reader and written out again through web_jw_str() and a
 * number check, never spliced (web_json.h); one that does not parse is
 * "sweep_error":"invalid". status.json is one flat object
 * (web_jl_parse()). A "running" status not updated for
 * WEB_SPECTRUM_STALE_S is reported as stale, not running: the helper
 * writes it at least once a second while it sweeps. */
#ifndef SLOTHWEB_SPECTRUM_H
#define SLOTHWEB_SPECTRUM_H

#include <stddef.h>

#include "web_json.h"

#define WEB_SPECTRUM_DIR        "/var/lib/sloth-sdrsweep"
#define WEB_SPECTRUM_REQUEST    "/run/slothweb/sdrsweep.request"
#define WEB_SPECTRUM_MAX_BYTES  (4L << 20)
#define WEB_SPECTRUM_STALE_S    30
#define WEB_SPECTRUM_DEPTH      8

typedef struct web_spectrum {
    char dir[1024];
    char request[1024];
} web_spectrum_t;

void web_spectrum_init(web_spectrum_t *sp, const char *dir, const char *request);

/* GET. *body is malloc'd (the caller frees it), *status 200 or 400 (an
 * unknown query). out_of_scope (the Local scope: a sweep is radio, not
 * what the host's own interfaces carried) answers the status alone and
 * says so, as the APRS and ADS-B routes do. 0, or -1 when out of
 * memory. */
int  web_spectrum_get(const web_spectrum_t *sp, const char *query, long long now_s,
                      int out_of_scope, char **body, size_t *len, int *status);

/* POST /api/spectrum/run, after the gate. The answer into body; a
 * Retry-After line into extra on a 429. 0, or -1 when nothing fit. */
int  web_spectrum_run(const web_spectrum_t *sp, long long now_s, char *body, size_t cap,
                      size_t *len, int *status, char *extra, size_t extracap);

/* Re-serialise the JSON value in in[0..n) into w: strings decoded and
 * written again by web_jw_strn(), numbers checked against RFC 8259's
 * grammar, nesting at most WEB_SPECTRUM_DEPTH, nothing after the value
 * but whitespace. 0, or -1 on anything else (w is then unspecified). */
int  web_spectrum_copy_json(web_jw_t *w, const char *in, size_t n);

#endif
