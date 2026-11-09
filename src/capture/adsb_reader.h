#ifndef CAPTURE_ADSB_READER_H
#define CAPTURE_ADSB_READER_H

#include <stdint.h>
#include <time.h>

/* The --adsb reader (#26 slice 1, 2026-11-05). The I/O half of
 * src/adsb.h.
 *
 * The decoder rewrites aircraft.json about once a second by writing a
 * temporary file and renaming it over the old one, so the reader opens
 * the path afresh on every poll (ADSB_POLL_MS) - a descriptor held
 * across polls would keep reading the unlinked old inode - fstat()s it,
 * refuses anything but a regular file of at most ADSB_MAX_DOC bytes,
 * reads it whole and parses it. A file whose inode, size and mtime are
 * unchanged since the last good read is not re-parsed: the decoder has
 * not written, and its clock not advancing is what turns the source
 * stale. A missing, unreadable, oversize or malformed file is counted
 * and reported in sensor_health and the sensor registry; it never stops
 * the worker. The open is O_RDONLY: sloth writes nothing to the
 * decoder's directory, and dials nothing. Started after the privilege
 * drop: the decoder's file is world-readable as readsb ships it.
 *
 * sbs:// (2026-11-09): the worker instead connects to the decoder's SBS
 * output on loopback (bounded non-blocking connect), reads CRLF lines
 * through adsb_sbs_lines_feed() and never writes a byte to the socket.
 * A refused or failed connect is a read error and is retried after
 * 2, 4, ... 30 s; a session the decoder closes, or a read error, is a
 * read error and is retried after 2 s. Lines are framed with a hard
 * cap (ADSB_SBS_MAX_LINE) across reads. The main thread never touches
 * the socket. */

/* Parse SPEC and record the source with adsb_set_source() (or
 * adsb_set_source_sbs()). 0, or -1 with err. Opens and dials nothing: a
 * decoder that starts after sloth is the normal case, not an error. */
int  adsb_reader_configure(const char *spec, char *err, size_t errsz);

int  adsb_reader_configured(void);

/* One poll of a file source (-1 for an sbs:// one): open, check, read,
 * parse, feed, at host `wall` / `mono_ms`.
 * What the worker runs every ADSB_POLL_MS, and the tests' seam. Returns
 * 1 for a document fed, 0 for an unchanged file, -1 for a failure
 * (already counted). */
int  adsb_reader_poll_once(time_t wall, uint64_t mono_ms);

void adsb_reader_run(void);    /* start the worker; no-op unless configured */
void adsb_reader_stop(void);   /* stop and join it */

#endif /* CAPTURE_ADSB_READER_H */
