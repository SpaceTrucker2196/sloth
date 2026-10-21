#ifndef CAMERA_JOIN_H
#define CAMERA_JOIN_H

#include <stddef.h>
#include <time.h>
#include "sloth.h"

/* Camera identity on the device record (#106 round 2).
 *
 * The six camera rules each read one table sloth already keeps; this
 * folds the same rows, through the same predicates, onto the device
 * table devices_update() builds, so the Devices view, the JSONL device
 * record and the --db devices row can say "this one is a camera, and
 * here is what said so".
 *
 * Joined only on a key sloth observes. The LAN-side signals —
 * WS-Discovery, mDNS, SSDP, RTSP — carry a source IP and join on IP.
 * The beacon-side ones — setup SSID, camera-vendor OUI — carry a BSSID
 * and join on MAC. Nothing on the air ties a setup SoftAP's BSSID to
 * the LAN address the same camera has once it is provisioned, so the
 * two stay two records; joining them would be a guess written down as
 * a fact.
 *
 * A camera heard announcing itself (a class-bearing LAN signal) with no
 * device record holding its IP — the usual case on a mirror port, where
 * the sensor's own neighbour table never learns it — gets a record of
 * its own with an all-zero MAC and DEV_SRC_CAMERA: the IP is its only
 * key. RTSP and an mDNS _rtsp service never create one, because neither
 * says the host is a camera. */

/* Fold the camera rows in `s` onto dev[0..*n), appending IP-only camera
 * records (counted as SH_EVICT_DEVICE when the table is full). Called
 * by devices_update() after the per-source merges and before the sort. */
void camera_join(const sloth_state_t *s, device_t *dev, int *n);

/* "camera", "camera-vendor", or "" for DEV_CLASS_UNKNOWN. */
const char *device_class_label(device_class_t c);

/* The rule each CAM_SIG_* bit index (0..CAM_SIG_COUNT-1) mirrors. */
alert_type_t cam_signal_alert(int idx);

/* Value of the first onvif://www.onvif.org/<kind>/<value> scope in a
 * space-separated Scopes list (ONVIF Core Specification, discovery
 * scopes: "name", "hardware",
 * "location", "type", ...). Percent-decoded, and filtered to printable
 * ASCII because every byte is the camera's choice. Returns 1 when such
 * a scope was present, even if nothing printable survived. */
int cam_onvif_scope(const char *scopes, const char *kind, char *out, size_t n);

/* One line of a device's signal trail: which rule's input was seen,
 * when (that source row's last_seen), and what it said. */
typedef struct {
    int    sig;            /* CAM_SIG_* bit */
    time_t when;
    char   what[192];
} cam_trail_row_t;

/* Rebuild `d`'s trail from the same tables and keys camera_join() used,
 * newest first. Returns the number of rows written (at most `max`); a
 * device with more source rows than that is cut, never reordered. */
int camera_trail(const sloth_state_t *s, const device_t *d,
                 cam_trail_row_t *rows, int max);

/* Does LAN-side row `ip` belong to `d`? IP equality, nothing else. */
int cam_row_is_device_ip(const device_t *d, const char *ip);

#endif /* CAMERA_JOIN_H */
