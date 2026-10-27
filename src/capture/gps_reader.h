#ifndef CAPTURE_GPS_READER_H
#define CAPTURE_GPS_READER_H

#include <stddef.h>

/* The --gps reader (2026-10-27). The I/O half of src/gps.h.
 *
 * Serial NMEA (`--gps /dev/ttyXXX`): the device is opened in
 * gps_reader_configure(), BEFORE the privilege drop, because the drop
 * clears supplementary groups (src/privdrop.c) and a serial device is
 * usually group `dialout`. The descriptor is O_RDONLY: sloth never
 * writes a byte to the receiver, so it cannot reconfigure it. The
 * worker started by gps_reader_run() after the drop reads it in poll()
 * with a short timeout (the bt_capture shape). A lost device (unplug,
 * EOF) is reopened with backoff; after the drop that reopen may be
 * refused, and the refusal is published as gps_err.
 *
 * gpsd (`--gps gpsd://HOST:PORT`): the TCP connect happens on the worker,
 * after the drop, since it needs no privilege. sloth sends exactly one
 * line, `?WATCH={"enable":true,"json":true}`, and then only reads.
 * Lost connections are retried with backoff. */

/* Parse SPEC, refuse a remote gpsd unless allow_remote, and for a
 * serial device open and configure it (raw, `baud`, read only). Records
 * the label with gps_location_set_gps(). 0, or -1 with err. */
int  gps_reader_configure(const char *spec, int allow_remote, int baud,
                          char *err, size_t errsz);

/* 1 once configure succeeded. */
int  gps_reader_configured(void);

/* Start the worker; no-op unless configured. */
void gps_reader_run(void);

/* Stop and join the worker, close the descriptor. */
void gps_reader_stop(void);

/* 1 when `baud` is one gps_reader_configure() accepts. */
int  gps_reader_baud_ok(int baud);

#endif /* CAPTURE_GPS_READER_H */
