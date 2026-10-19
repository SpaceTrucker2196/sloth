#ifndef SLOTH_LIBVER_H
#define SLOTH_LIBVER_H

#include <stddef.h>

/* Versions of the libraries that parse untrusted bytes for sloth (#142).
 *
 * Two jobs. First, the RUNTIME sqlite floor: src/db.c and
 * research/query.c already refuse to compile against headers older than
 * 3.31.0 (#134), but the library loaded at run time is whatever the
 * dynamic linker finds, and a binary built on one host and copied to an
 * older one gets the older libsqlite3.so without a word. The flags the
 * floor exists for — SQLITE_OPEN_NOFOLLOW, SQLITE_DBCONFIG_TRUSTED_SCHEMA
 * — are unknown to that library, so the guard the compile check
 * promised would not be there.
 *
 * Second, observability: `--version` and sensor_health's `libs` field
 * say which libpcap and sqlite are actually loaded, so an operator can
 * match a sensor against a CVE without shelling in. libpcap gets no
 * hard floor: capture.c already degrades deliberately on an older
 * libpcap, and refusing to run would trade a degraded sensor for a
 * blind one. */

#define LIBVER_SQLITE_FLOOR_NUM 3031000
#define LIBVER_SQLITE_FLOOR_STR "3.31.0"

/* pcap_lib_version() verbatim, or "none" in a build without WITH_PCAP. */
const char *libver_pcap(void);

/* sqlite3_libversion() of the LOADED library, or "none" in a build
 * without WITH_SQLITE. */
const char *libver_sqlite(void);

/* "pcap: <libver_pcap()>; sqlite: <libver_sqlite()>". Truncates cleanly
 * at n; returns what snprintf returned. */
int libver_format(char *buf, size_t n);

/* 1 when a sqlite3_libversion_number() value meets the floor. */
int libver_sqlite_floor_ok(int version_number);

/* The loaded sqlite's version number, or 0 without WITH_SQLITE. */
int libver_sqlite_loaded(void);

/* 0 when the loaded sqlite meets the floor. Otherwise -1, with a
 * one-line reason naming the compared version and the floor written to
 * err. The one check db_open() and rq_open() both make. */
int libver_sqlite_refuse(char *err, size_t n);

/* Test seam: makes libver_sqlite_loaded() report v instead of the
 * loaded library, so the refusal path in db_open()/rq_open() can be
 * driven on a host whose real sqlite is new. 0 restores the real
 * value. Nothing outside tests/ calls it. */
void libver_sqlite_override_for_test(int v);

#endif
