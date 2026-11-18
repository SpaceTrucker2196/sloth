#ifndef SLOTH_RF_TRIM_H
#define SLOTH_RF_TRIM_H

#include <stdio.h>
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
 * Startup only: an SDR plugged in later needs a restart of sloth-rf. */

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

#endif /* SLOTH_RF_TRIM_H */
