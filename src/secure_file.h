#ifndef SECURE_FILE_H
#define SECURE_FILE_H

#include <stdio.h>
#include <stddef.h>

/* Private creation of on-disk artifacts (#87).
 *
 * Every file sloth writes that can hold captured traffic — handshake
 * exports, JSONL, the SQLite DB and its WAL, alert pcaps, reports — is
 * crackable or personal material. Its permissions must not depend on
 * the process umask or on whatever already sits at the path:
 *
 *   - directories are created 0700, files 0600, by descriptor
 *     (O_NOFOLLOW, O_CLOEXEC), never by a path re-resolved later;
 *   - an existing path is validated, never repaired: it must be the
 *     right type, owned by the effective uid, carry no group/other
 *     permission bits, and (files) have exactly one link. Anything else
 *     is refused with a reason. sloth never chmods an operator path;
 *   - a symlink as the final component is refused.
 *
 * Errors are written into a caller buffer so each call site can report
 * them in its own words. SFILE_ERR_MAX is enough for a path plus
 * reason. */

#define SFILE_ERR_MAX 320

/* How a file is opened. Each caller picks one deliberately:
 *   APPEND : log that accumulates across runs (eapol.22000, -o JSONL).
 *            Created if absent; an existing file is validated, then
 *            appended to.
 *   EXCL   : a fresh artifact that must not already exist (temp files,
 *            timestamped pcaps). Fails with EEXIST if present.
 *   TRUNC  : a whole-file rewrite at an operator path (--report).
 *            Validated BEFORE truncation, so a refused file is left
 *            intact. */
typedef enum { SFILE_APPEND, SFILE_EXCL, SFILE_TRUNC } sfile_mode_t;

/* Ensure `path` is a private directory. Created 0700 when absent;
 * otherwise validated as above. Returns an O_DIRECTORY descriptor
 * (caller closes) or -1 with `err` filled. Holding the descriptor
 * pins the validated directory: later openat()s cannot be redirected
 * by a rename or symlink swap of `path`. */
int   sfile_private_dir(const char *path, char *err, size_t errsz);

/* Open `name` relative to `dirfd` (AT_FDCWD for an operator path).
 * Write-only, 0600 on create. Returns an fd or -1 with `err` filled
 * (errno preserved for EXCL's EEXIST). */
int   sfile_open(int dirfd, const char *name, sfile_mode_t mode,
                 char *err, size_t errsz);
FILE *sfile_fopen(int dirfd, const char *name, sfile_mode_t mode,
                  char *err, size_t errsz);

/* EXCL-create `<stem><ext>`, then `<stem>_2<ext>` .. `<stem>_99<ext>`
 * — two artifacts named for the same second must not overwrite each
 * other. The name used is written to name_out. */
FILE *sfile_fopen_unique(int dirfd, const char *stem, const char *ext,
                         char *name_out, size_t name_sz,
                         char *err, size_t errsz);

/* Validate a path that sloth does not create itself but will write
 * through (SQLite's -wal / -shm / -journal). Absent is fine (returns
 * 0); present must pass the file checks. -1 with `err` otherwise. */
int   sfile_check_existing(const char *path, char *err, size_t errsz);

/* fclose that reports: any buffered-write error, flush failure or
 * close failure returns -1 with `err` naming `what`. The FILE is
 * closed either way. */
int   sfile_fclose(FILE *f, const char *what, char *err, size_t errsz);

/* Runtime export-failure bookkeeping. The first failure is printed to
 * stderr (one line — the journal in --headless); every failure is
 * counted and the latest reason kept for the UI and the tests. Export
 * keeps retrying: a full disk may drain, and capture is never stopped
 * for an export problem. */
typedef struct {
    int  failures;
    int  reported;
    char last[SFILE_ERR_MAX];
} sfile_fail_t;

void  sfile_fail(sfile_fail_t *f, const char *who, const char *msg);
void  sfile_fail_reset(sfile_fail_t *f);

#endif /* SECURE_FILE_H */
