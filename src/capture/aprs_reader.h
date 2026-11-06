#ifndef CAPTURE_APRS_READER_H
#define CAPTURE_APRS_READER_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* The --aprs reader (2026-11-05). The I/O half of src/aprs.h.
 *
 * Dire Wolf opens its -L log with fopen(..., "a") once and appends one
 * line per decoded packet, flushed; logrotate's copytruncate empties
 * the same inode in place, a rename-style rotation puts a new file at
 * the path. So every APRS_POLL_MS the reader opens the path afresh
 * (O_RDONLY | O_NONBLOCK, a regular file only), fstat()s it and keeps
 * (dev, ino, offset):
 *   - the very first open sees a file Dire Wolf already wrote: the
 *     offset starts at its END - the history in it is not replayed
 *     (sloth.db already holds what an earlier run read);
 *   - a file that appears after a poll found none is new: read from 0;
 *   - a different inode is a rotation: read the new file from 0;
 *   - a size below the offset is a truncation: from 0;
 *   - otherwise the bytes past the offset, at most APRS_POLL_BYTES a
 *     poll, cut into lines; a partial last line waits for the next
 *     poll, and a line over APRS_MAX_LINE is one bad line, skipped to
 *     its newline.
 * A missing file is a waiting state (Dire Wolf creates it with its
 * first packet); an unreadable one, or not a regular file, is counted
 * and reported in sensor_health and the sensor registry; neither stops
 * the worker. sloth writes nothing and dials nothing. Started after the
 * privilege drop: Dire Wolf's log is world-readable as it creates it. */

/* Parse SPEC and record the source with aprs_set_source(). 0, or -1
 * with err. Opens nothing. */
int  aprs_reader_configure(const char *spec, char *err, size_t errsz);

int  aprs_reader_configured(void);

/* One poll at host `wall` / `mono_ms`: what the worker runs every
 * APRS_POLL_MS, and the tests' seam. Returns the bytes consumed (0 for
 * nothing new), or -1 for a failure or a missing file (already noted). */
long aprs_reader_poll_once(time_t wall, uint64_t mono_ms);

void aprs_reader_run(void);    /* start the worker; no-op unless configured */
void aprs_reader_stop(void);   /* stop and join it */

#endif /* CAPTURE_APRS_READER_H */
