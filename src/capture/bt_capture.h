#ifndef CAPTURE_BT_CAPTURE_H
#define CAPTURE_BT_CAPTURE_H

#include <stddef.h>
#include <stdio.h>
#include "sloth.h"

/* The Ubertooth capture reader (#144 slice 3, --bt-capture PATH).
 *
 * Reads a classic pcap file or FIFO that the OPERATOR fills with
 * ubertooth-btle or ubertooth-rx (docs/wiki/ubertooth.md). sloth does
 * not drive the dongle in any way: no libubertooth, no USB, no child
 * process. It reads bytes from a path, and src/bt_stream.c frames and
 * decodes them.
 *
 * ONE open, on the worker, never on the main thread:
 *   - a FIFO's open blocks until a writer appears, so the open is made
 *     with O_NONBLOCK on the worker, and startup never waits on it;
 *   - opening, closing and reopening a FIFO loses whatever the writer
 *     sent in between and can make the writer see EPIPE, so the
 *     descriptor opened once is the one read until the end;
 *   - reads wait in poll() with a short timeout and re-check the run
 *     flag, so stop always returns, even with a writer that has gone
 *     quiet holding the FIFO open.
 * The worker starts after the privilege drop, so the path is opened as
 * the account sloth runs as and must be readable by it.
 *
 * End of file (a regular file read to its end, or the FIFO's writer
 * closing it) ends the stream: state `eof` in sensor_health. */

#ifdef WITH_PCAP

/* Validate `path` with stat() — no open — and remember it. Refuses a
 * path that does not exist or is neither a regular file nor a FIFO
 * (a device node, a socket, a directory). 0 on success; -1 with `err`
 * filled otherwise. */
int  bt_capture_configure(const char *path, char *err, size_t errsz);

/* Start the worker; no-op unless configured. */
void bt_capture_run(void);

/* Stop and join the worker. */
void bt_capture_stop(void);

#else

static inline int bt_capture_configure(const char *path, char *err, size_t errsz)
    { (void)path; if (err && errsz) snprintf(err, errsz, "built without libpcap"); return -1; }
static inline void bt_capture_run(void)  {}
static inline void bt_capture_stop(void) {}

#endif /* WITH_PCAP */

#endif /* CAPTURE_BT_CAPTURE_H */
