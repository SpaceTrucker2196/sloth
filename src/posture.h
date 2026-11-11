#ifndef POSTURE_H
#define POSTURE_H

#include <stdio.h>
#include <stdint.h>
#include "sloth.h"
#include "secure_file.h"

/* Posture report export — roadmap #16 phase 5.
 *
 * Rolls up the current sloth_state_t into a human-readable Markdown
 * report or a structured JSON companion. Called once at shutdown from
 * main.c so an operator (or a CI job) can get a signed-off summary
 * of what sloth observed during the session. Since #190 the same
 * rollup can also be written while the session runs (posture_live_*
 * below), to a separate "live" file that says it is not signed off.
 *
 * Both writers take a session_start timestamp so they can report
 * "session ran from X to Y" — main.c captures this at startup. */

/* `research` may be NULL — the References block is then omitted, which
 * is the report sloth produced before #73 existed. Passed rather than
 * reached for as a global: posture.c is in the test build and main.c is
 * not, so a global owned there would be untestable by construction. */
struct rq_handle;
int posture_render_md  (FILE *out, const sloth_state_t *s, time_t session_start,
                        struct rq_handle *research);
int posture_render_json(FILE *out, const sloth_state_t *s, time_t session_start);

/* ── Reports while the session runs, and one record per session (#190) ──
 *
 * The shutdown write above is the signed-off record and is unchanged.
 * On a long-running service it is also almost always stale, and every
 * restart truncates it. Three additions, all plain file I/O beside the
 * operator's --report / --report-json path:
 *
 *   report.md                    the shutdown write, as before
 *   report.live.md               this session so far; "Session end:
 *                                (running)". Replaced whole by rename,
 *                                removed once the session signs off
 *   report.<start>.md            one per finished session (opt-in),
 *                                created O_EXCL: never overwritten
 *   report.<mtime>.unclean.md    a live file found by a later session
 *                                (at its first live write, or at its
 *                                shutdown if it wrote none), i.e. the
 *                                last word of a session that never
 *                                signed off (OOM kill, power loss)
 *
 * <start> and <mtime> are UTC, YYYYMMDDTHHMMSSZ; a name already taken
 * gets _2 .. _99 rather than being replaced. Every file is 0600 through
 * secure_file. Paths longer than POSTURE_PATH_MAX are refused, never
 * clamped. */

#define POSTURE_PATH_MAX 1024

typedef struct {
    const char       *md_path;      /* --report      or NULL */
    const char       *json_path;    /* --report-json or NULL */
    unsigned          interval_s;   /* 0: only on request (force) */
    time_t            session_start;
    struct rq_handle *research;
    uint64_t          last_ms;      /* monotonic stamp of the last attempt */
    int               md_adopted;   /* an earlier session's live file has */
    int               json_adopted; /*   been set aside (or there was none) */
    sfile_fail_t      fail;         /* counted; the first is printed once */
} posture_live_t;

/* The names derived from an operator path. 0, or -1 when `path` has no
 * file name or the result does not fit `n`. */
int posture_live_path(const char *path, char *out, size_t n);
int posture_session_path(const char *path, time_t session_start,
                         char *out, size_t n);

void posture_live_init(posture_live_t *L, const char *md_path,
                       const char *json_path, unsigned interval_s,
                       time_t session_start, struct rq_handle *research);

/* Called once per poll tick. Writes the live report(s) when the
 * interval has elapsed on the monotonic clock, or at once when `force`
 * is set (SIGUSR1). Each file is rendered to a hidden temporary beside
 * it and renamed over the live name, so a reader sees the previous
 * complete report or the new one and never a partial. Returns the
 * number of files written, 0 when nothing was due, -1 when a write
 * failed: the previous live file is then left as it was, no temporary
 * remains, and the next interval tries again. Never fatal. */
int posture_live_tick(posture_live_t *L, const sloth_state_t *s, int force);

/* After the shutdown write of the Markdown (`json` 0) or JSON (1)
 * report succeeded: the live file is superseded by a signed-off record
 * and is removed, so a file that says "(running)" does not outlive its
 * session. A live file this session never wrote is not its own to
 * remove: it is an earlier, killed session's, and is set aside as
 * .unclean first (left in place if that fails). */
void posture_live_retire(posture_live_t *L, int json);

/* Write this session's own record beside `path` (`json` picks the
 * renderer). The name written is returned in name_out. 0, or -1 with
 * `err` filled; a record that failed part-way is removed. */
int posture_session_record(const char *path, int json,
                           const sloth_state_t *s, time_t session_start,
                           struct rq_handle *research,
                           char *name_out, size_t name_sz,
                           char *err, size_t errsz);

#endif /* POSTURE_H */
