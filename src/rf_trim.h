#ifndef SLOTH_RF_TRIM_H
#define SLOTH_RF_TRIM_H

#include <stdio.h>
#include <time.h>
#include "rf_flags.h"

/* sloth-rf trims itself to the receivers attached at startup (owner,
 * 2026-11-18): "have sloth-rf trim itself depending on what sensors are
 * installed at startup".
 *
 * One /etc/default/sloth-rf travels between hosts, and a host with no
 * SDR (W9FJC: Wi-Fi, GPS and BLE only) would otherwise start readers
 * for decoder files nothing will ever write, each reported stale and
 * then SENSOR_SOURCE_DOWN forever. So, once, before anything is
 * configured: if no USB device sys_usb_table[] calls an SDR is listed
 * under /sys/bus/usb/devices, the inputs that need a local SDR are not
 * started, each is named on stderr with the reason, and its source row
 * reads not_installed instead of stale or down.
 *
 * Trimmed when no SDR is attached:
 *   --adsb PATH (a file; readsb's aircraft.json)
 *   --aprs PATH, with --aprs-freq and --aprs-silent-hours
 *   --rtl433 PATH
 * Never trimmed:
 *   --adsb sbs:// and beast://: a socket, and whatever feeds it may
 *                       take its samples from an SDR on another machine
 *   --gps, --location, --victron: not an SDR's
 *
 * Read-only and least privilege: the detection is the idVendor and
 * idProduct text of each USB device in sysfs, through the receiver
 * inventory's seam and path guard (sys_usb_has_kind(), src/sys_status.h);
 * no libusb, no device node opened (MISSION.md section 2). The table of
 * SDR IDs is sys_usb_table[]'s, whose rows cite usb.ids and systemd's
 * software-radio hwdb.
 *
 * Fails toward reading: a sysfs that cannot be listed, a list longer
 * than is read, or a device whose ID cannot be read (with no SDR
 * found) is "cannot tell" and trims nothing; a SPEC that
 * does not parse is left for rf_flags_check() to refuse with its usual
 * words. --no-sdr-trim turns the trim off for a host where the
 * detection is wrong (an SDR whose ID is not in the table).
 *
 * Kept although no SDR is found (owner, 2026-11-18): a decoder whose
 * input file was modified recently. Something other than a local USB
 * SDR can feed it - Dire Wolf on a sound-card TNC, readsb net-only
 * writing aircraft.json from a remote receiver, rtl_433 reading
 * rtl_tcp or SoapyRemote - and the USB list cannot see that; a fresh
 * mtime can. So, fail open: stat() the file (read-only, nothing
 * opened) and keep the input when it was written within its window,
 * or when its mtime is ahead of the clock (skew is not proof the feed
 * stopped). A missing file (ENOENT, ENOTDIR) is trimmed as before;
 * one stat() cannot check for any other reason (EACCES under the
 * unit's sandbox or the file's modes) is kept, since the file may be
 * fed and its reader then reports the real cause, where a trim would
 * call it "no SDR". The trim runs before the privilege drop, so a run
 * started as root sees through modes the dropped account cannot; the
 * kept reader then reports the open failure, the same outcome. The
 * windows follow
 * each writer's cadence:
 *   --adsb    RF_TRIM_FRESH_ADSB_S, 10 min. readsb rewrites
 *             aircraft.json about once a second while it runs, empty
 *             sky or not, so a file ten minutes old has no writer; the
 *             margin covers a feeder restarted just before sloth-rf.
 *   --aprs, --rtl433   RF_TRIM_FRESH_EVENTS_S, 24 h. Dire Wolf and
 *             rtl_433 append only on a decode, and a quiet 144.39 MHz
 *             or 433 MHz channel can be silent for hours overnight; a
 *             short window would trim a working feed on a quiet night.
 *             A day is four times APRS_SILENT_S_DEFAULT (6 h, the span
 *             after which a running APRS decoder is already called
 *             silent), so a file older than that has no live feed.
 * The cost of failing open: a host whose SDR was unplugged within the
 * window keeps that input once, and its row goes stale as it would
 * have before the trim existed.
 *
 * Startup only: an SDR plugged in later needs a restart of sloth-rf. */

/* The fail-open windows above, in seconds. */
#define RF_TRIM_FRESH_ADSB_S   (10L * 60L)
#define RF_TRIM_FRESH_EVENTS_S (24L * 3600L)

enum { RF_SDR_UNKNOWN = -1, RF_SDR_ABSENT = 0, RF_SDR_PRESENT = 1 };

/* RF_SDR_*, and the first SDR's name into desc when present. */
int rf_trim_detect(char *desc, int cap);

/* rf_trim_apply()'s return. */
enum { RF_TRIM_GO = 0, RF_TRIM_NOTHING_LEFT = 1 };

/* Trim `f` in place by `sdr` (RF_SDR_*), unless `no_trim`. Writes one
 * line to `log` per trimmed input, or one saying why nothing was
 * trimmed when sysfs could not tell. `have_gps` is --gps given: with it
 * a run whose decoders were all trimmed still has a receiver to read.
 * RF_TRIM_NOTHING_LEFT when the trim removed at least one input and
 * none is left (no decoder, no --victron, no --gps); the caller says
 * so and runs on, idle, so its socket serves the not_installed rows
 * (an exit would leave slothweb's rf socket retrying and the rows
 * unread). Records what was trimmed for rf_trim_trimmed(). */
int rf_trim_apply(rf_flags_t *f, int have_gps, int no_trim, int sdr,
                  const char *sdr_desc, FILE *log);

/* For the source rows (src/sys_status_rf.c): 1 when sys_src_id_t `id`
 * was trimmed, with the SPEC as given into spec. */
int rf_trim_trimmed(int id, char *spec, int cap);

void rf_trim_reset(void);

/* Tests: the mtime lookup the fail-open guard uses (0 with *mtime set,
 * else the errno: ENOENT / ENOTDIR for a file that is not there, any
 * other for one that could not be checked); NULL restores stat(). The
 * age is taken against sloth_wall(), so a test pins both. */
void rf_trim_test_set_mtime(int (*fn)(const char *path, time_t *mtime));

#endif /* SLOTH_RF_TRIM_H */
