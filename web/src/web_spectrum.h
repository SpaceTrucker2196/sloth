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
 *   GET /api/spectrum?range=R    R one of last3, 1h, 5h, 12h, 24h: the
 *                                status, "range", "runs", "skipped", and
 *                                under "sweep" a document of the same
 *                                shape as a sweep's, "mode":"history",
 *                                with one row per run from the helper's
 *                                history directory (the last 3 runs, or
 *                                the runs that started in the last R),
 *                                oldest first; null when none could be
 *                                read. 400 "unknown_range" for another R.
 *   GET /api/spectrum?marks=1    the operator's marks for the amateur
 *                                band charts: "configured" (a file was
 *                                named with --spectrum-marks), "marks"
 *                                [{"f_hz","label"}], "skipped" (lines
 *                                refused), and "error" ("absent",
 *                                "too_large", "unreadable") when the
 *                                file could not be read. Every scope's:
 *                                the file is the operator's, not a
 *                                capture.
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
 * writes it at least once a second while it sweeps.
 *
 * The ranges read <dir>/history/<digits>.json (the helper's history
 * records, docs/wiki/sdr-sweep.md "History"), each a regular file of at most WEB_SPECTRUM_HIST_MAX_BYTES
 * opened without following a link, parsed whole by the same strict
 * reader (a member twice, a bad number, base64 that is not exactly the
 * grid's bins: the record is skipped and counted, never fatal). The
 * newest good record sets the grid; a record on another grid (the span
 * was changed) is skipped. Long windows are max-pooled: k neighbouring
 * bins become one (web_spectrum_pool()), so rows x bins stays under
 * WEB_SPECTRUM_HIST_CELLS, about 2 MB of base64, whatever the window.
 * Every number and string in the answer is written by this file (the
 * peaks of the newest record through web_spectrum_copy_json()).
 *
 * The Run button cannot start a run within WEB_SPECTRUM_MIN_GAP_S of
 * the last one's end, whatever cooldown the helper's status names: the
 * 5-minute timer (sloth-sdrsweep-auto.timer) needs the helper's own
 * cooldown short, and this keeps a browser from holding a shared
 * receiver anyway. */
#ifndef SLOTHWEB_SPECTRUM_H
#define SLOTHWEB_SPECTRUM_H

#include <stddef.h>
#include <stdint.h>

#include "web_json.h"

#define WEB_SPECTRUM_DIR        "/var/lib/sloth-sdrsweep"
#define WEB_SPECTRUM_REQUEST    "/run/slothweb/sdrsweep.request"
#define WEB_SPECTRUM_MAX_BYTES  (4L << 20)
#define WEB_SPECTRUM_STALE_S    30
#define WEB_SPECTRUM_DEPTH      8
#define WEB_SPECTRUM_MIN_GAP_S  120
#define WEB_SPECTRUM_HIST_DIR   "history"
#define WEB_SPECTRUM_HIST_MAX_BYTES (512L << 10)
/* Records read for one answer: 288 a day at one per 5 minutes, and the
 * helper keeps at most 400. */
#define WEB_SPECTRUM_HIST_MAX_RUNS 600
/* Rows x bins of an answer before base64 (4/3 of it on the wire). */
#define WEB_SPECTRUM_HIST_CELLS 1500000LL
#define WEB_SPECTRUM_BINS_MAX   200000

/* The operator's marks file (--spectrum-marks): at most this many
 * bytes and marks, a name of at most WEB_SPECTRUM_MARK_NAME bytes. */
#define WEB_SPECTRUM_MARKS_MAX_BYTES (64L << 10)
#define WEB_SPECTRUM_MARKS_MAX  512
#define WEB_SPECTRUM_MARK_NAME  48

typedef struct web_spectrum {
    char dir[1024];
    char request[1024];
    char marks[1024];      /* --spectrum-marks; "" when none was given */
} web_spectrum_t;

void web_spectrum_init(web_spectrum_t *sp, const char *dir, const char *request);
/* The operator's own frequency marks for the amateur band charts (the
 * local repeaters): a text file, one "MHz,name" line each, '#' a
 * comment. NULL or "": none. */
void web_spectrum_set_marks(web_spectrum_t *sp, const char *path);

/* One line of the marks file, without its newline: 1 and *hz, name[]
 * for a mark, 0 for a blank or comment line, -1 for anything else (a
 * frequency that is not a plain decimal from 0.001 to 30000 MHz, a
 * missing, empty or over-long name, a byte that is not printable
 * ASCII). */
int  web_spectrum_mark_line(const char *line, size_t n, long long *hz, char *name, size_t cap);

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

/* A range's name to its length in seconds (0 for last3): 0, or -1 when
 * it is not one. */
int  web_spectrum_range(const char *name, long long *secs);
/* How many neighbouring bins one answer bin max-pools so rows x bins
 * stays within WEB_SPECTRUM_HIST_CELLS: 1 or more. */
int  web_spectrum_pool(long long rows, long long bins);
/* Strict RFC 4648 base64 of exactly want bytes (padding required, no
 * whitespace): 0, or -1. */
int  web_spectrum_b64_decode(const char *s, size_t n, uint8_t *out, size_t want);

/* Re-serialise the JSON value in in[0..n) into w: strings decoded and
 * written again by web_jw_strn(), numbers checked against RFC 8259's
 * grammar, nesting at most WEB_SPECTRUM_DEPTH, nothing after the value
 * but whitespace. 0, or -1 on anything else (w is then unspecified). */
int  web_spectrum_copy_json(web_jw_t *w, const char *in, size_t n);

#endif
