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
 * Joined only on a key sloth observes. The LAN-side signals join on
 * IP: WS-Discovery and SSDP on the packet source, RTSP on the
 * responder's address, mDNS on the address an A/AAAA answer advertises
 * for the SRV target — the network's claim, sent by whoever answered
 * (docs/wiki/camera-detection.md says why the source is not required
 * to match).
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
 * says the host is a camera.
 *
 * An IP is a key only while the address has not changed hands, and a
 * passive sensor cannot see a lease move. So a LAN row joins only when
 * its last_seen is within camera.join_fresh_secs (--tune; default
 * CAM_JOIN_FRESH_SECS) of now, and only when exactly one record holds
 * the IP: two records on one address (two LANs on the same subnet, a
 * stale neighbour entry beside a fresh one) is a key that names no one.
 * The source tables only evict when full, never by age, so a stale row
 * stays readable on the trail as history, marked as not joined.
 *
 * ONVIF and SSDP rows are keyed by their own identity (EndpointReference,
 * USN) and keep one source address per family. The IPv4 address joins
 * first; when it joined (or created) a record the IPv6 one only
 * attaches, so a dual-stack camera is one record, not one per family. */

/* A LAN row older than this is history, not a join key. One hour: an
 * SSDP advertisement lives max-age >= 1800 s and is re-sent before it
 * expires (UDA 1.0 §1.1.2), mDNS service records are refreshed at 80 %
 * of a 4500 s TTL (RFC 6762 §10, §5.2), and a DHCP lease turning over
 * inside an hour is the exception. A WS-Discovery Hello is sent once on
 * joining the network (WS-Discovery 1.1 §4.1), so a camera nobody
 * probes drops back to unclassified after the window: the operator
 * trades that against the reuse risk with the knob. */
#define CAM_JOIN_FRESH_SECS 3600

/* Fold the camera rows in `s` onto dev[0..*n), appending IP-only camera
 * records (counted as SH_EVICT_DEVICE when the table is full). Called
 * by devices_update() after the per-source merges and before the sort. */
void camera_join(const sloth_state_t *s, device_t *dev, int *n, time_t now);

/* Why a LAN row at a record's IP did or did not join it. */
typedef enum {
    CAM_JOIN_OK = 0,
    CAM_JOIN_STALE,       /* older than camera.join_fresh_secs */
    CAM_JOIN_AMBIGUOUS,   /* more than one record holds the IP */
} cam_join_state_t;

/* The rule camera_join() applies to one LAN address seen at `when`,
 * against records[0..n). */
cam_join_state_t cam_lan_state(const device_t *records, int n,
                               const char *ip, time_t when, time_t now);

/* Is one of the row's per-family addresses `d`'s IP? Sets *when to that
 * address's own last-seen time. */
int cam_onvif_addr_of(const onvif_device_t *o, const device_t *d,
                      time_t *when);
int cam_ssdp_addr_of(const ssdp_device_t *e, const device_t *d,
                     time_t *when);

/* "camera", "camera-vendor", "not-camera", or "" for DEV_CLASS_UNKNOWN. */
const char *device_class_label(device_class_t c);

/* CAMERA or CAMERA_VENDOR: a class that says "camera". NOT_CAMERA is a
 * verdict against and UNKNOWN none, so neither counts. */
int device_class_is_camera(device_class_t c);

/* ── #155: telling a camera from a router on a mixed-vendor OUI ──
 *
 * After the join, every record is scored from behavioural evidence
 * (CAM_EV_*) and checked for router-role vetoes (CAM_VETO_*), each read
 * from a table sloth already fills from traffic it did not solicit.
 * The rule, from the issue's verified design:
 *
 *   - a self-declaration (ONVIF NVT, UPnP DigitalSecurityCamera:1, a
 *     camera mDNS type, a camera setup SSID) still decides: CAMERA;
 *   - a mixed-vendor OUI reads CAMERA_VENDOR only when the score is at
 *     least CAM_CLASS_MIN_SCORE and RTSP_SDP is part of it;
 *   - a veto on a mixed-vendor record with no camera evidence reads
 *     NOT_CAMERA;
 *   - camera evidence meeting a veto sets cam_conflict and is never
 *     resolved silently: a scored-only record stays UNKNOWN.
 *
 * Every IP-keyed row is held to the join's own key rule (cam_lan_state:
 * fresh, unambiguous); an RA carrying an SLLA option is keyed on the
 * MAC instead. */
#define CAM_CLASS_MIN_SCORE 3

/* One evidence or veto line for a record: which CAM_EV_* / CAM_VETO_*
 * bit (`veto` says which set), the source row's time (0 for the OUI,
 * which has none) and what it said. */
typedef struct {
    int    bit;
    int    veto;
    time_t when;
    char   what[200];
} cam_reason_t;

/* The classifier's inputs for `d`, judged against records[0..nrec) for
 * the IP key rule. camera_join() uses exactly this; the Devices detail
 * calls it on s->devices so it lists what the class rests on. Returns
 * the rows written, at most `max`. */
int camera_reasons(const sloth_state_t *s, const device_t *records,
                   int nrec, const device_t *d, time_t now,
                   cam_reason_t *rows, int max);

/* Short stable names ("rtsp_sdp", "dhcp_server"), the JSONL contract;
 * the descriptions are for the detail view. Unknown bits give "". */
const char *cam_evidence_slug(int bit);
const char *cam_evidence_desc(int bit);
int         cam_evidence_weight(int bit);
const char *cam_veto_slug(int bit);
const char *cam_veto_desc(int bit);

/* Comma-joined slugs of a mask, in bit order ("" for 0). */
void cam_evidence_list(int mask, char *out, size_t n);
void cam_veto_list(int mask, char *out, size_t n);

/* Does CAM_SETUP_OUI count this beacon? A camera-vendor block always; a
 * mixed-vendor block only beside a camera setup SSID on the same BSSID.
 * The rule, the join and the trail all ask this, so they agree. Out
 * pointers as cam_vendor_oui(), any may be NULL. */
int cam_setup_oui_counts(const beacon_ap_t *a, const char **vendor,
                         const char **org, int *local, int *mixed);

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
    cam_join_state_t state; /* CAM_JOIN_OK: counted on the record */
    char   what[192];
} cam_trail_row_t;

/* Rebuild `d`'s trail from the same tables, predicates and keys
 * camera_join() used, newest first. A LAN row at `d`'s IP that the join
 * refused (stale, ambiguous) is listed with that state and says so in
 * `what`; a row the rule itself would not count is never listed.
 * Returns the number of rows written (at most `max`); a device with
 * more source rows than that is cut, never reordered. */
int camera_trail(const sloth_state_t *s, const device_t *d, time_t now,
                 cam_trail_row_t *rows, int max);

/* Does LAN-side row `ip` belong to `d`? IP equality, nothing else. */
int cam_row_is_device_ip(const device_t *d, const char *ip);

#endif /* CAMERA_JOIN_H */
