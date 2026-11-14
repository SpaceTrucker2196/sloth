#ifndef CAPTURE_RTL433_READER_H
#define CAPTURE_RTL433_READER_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* The --rtl433 reader (#208, 2026-11-14). The I/O half of src/rtl433.h,
 * and the same tail as src/capture/aprs_reader.h describes, against the
 * same two rotation shapes.
 *
 * rtl_433 `-F json:FILE` opens the path once and appends one object per
 * decode, flushed per record (its src/output_file.c); a shell redirect
 * of `-F json` to a file behaves the same. logrotate's copytruncate
 * empties that inode in place, a rename-style rotation puts a new file
 * at the path. So every RTL433_POLL_MS the reader opens the path afresh
 * (O_RDONLY | O_NONBLOCK, a regular file only), fstat()s it and keeps
 * (dev, ino, offset):
 *   - the very first open sees a file rtl_433 already wrote: the offset
 *     starts at its END - the history in it is not replayed;
 *   - a file that appears after a poll found none is new: read from 0;
 *   - a different inode is a rotation: read the new file from 0;
 *   - a size below the offset is a truncation: from 0;
 *   - otherwise the bytes past the offset, at most RTL433_POLL_BYTES a
 *     poll, cut into lines; a partial last line waits for the next
 *     poll, and a line over RTL433_MAX_LINE is one bad line, skipped to
 *     its newline.
 * A missing file is a waiting state (rtl_433 creates it with its first
 * decode); an unreadable one, or not a regular file, is counted and
 * reported in sensor_health and the sensor registry; neither stops the
 * worker. sloth writes nothing, opens no SDR and dials nothing. Started
 * after the privilege drop. */

/* Parse SPEC and record the source with rtl433_set_source(). 0, or -1
 * with err. Opens nothing. */
int  rtl433_reader_configure(const char *spec, char *err, size_t errsz);

int  rtl433_reader_configured(void);

/* One poll at host `wall`: what the worker runs every RTL433_POLL_MS,
 * and the tests' seam. Returns the bytes consumed (0 for nothing new),
 * or -1 for a failure or a missing file (already noted). */
long rtl433_reader_poll_once(time_t wall);

void rtl433_reader_run(void);    /* start the worker; no-op unless configured */
void rtl433_reader_stop(void);   /* stop and join it */

#endif /* CAPTURE_RTL433_READER_H */
