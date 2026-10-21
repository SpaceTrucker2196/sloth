#ifndef CAMERA_VENDOR_H
#define CAMERA_VENDOR_H

/* Camera-vendor identity tables (#106 slice A).
 *
 * Three questions, one module, because they share one vendor list:
 *
 *   cam_vendor_oui     is this transmitter address assigned to a camera
 *                      vendor? (CAM_SETUP_OUI)
 *   cam_vendor_server  does this UPnP SERVER header's product token
 *                      name a camera vendor? (CAM_SSDP_DEVICE, Basic:1)
 *   cam_mdns_service   is this DNS-SD service type a camera service?
 *                      (CAM_MDNS_SERVICE)
 *
 * Embedded, not loaded (#145 ruling 8), for the reason vendor_watchlist.c
 * gives: detection behaviour reproducible from the commit. Every row has
 * a primary source — the IEEE Registration Authority's MA-L listing for
 * an OUI, the IANA Service Name registry for a service type — and the
 * vendor set itself is the one research/papers/camera-vendor-identity.md
 * sources. No row is guessed; what was considered and left out is listed
 * there with the reason.
 *
 * A match corroborates, it never confirms (#145 ruling 2): an OUI says
 * who the IEEE assigned the address block to, not what the box is, and
 * a SERVER string is whatever the firmware chose to print. Returned
 * strings are static and owned by the table. */

#include <stdint.h>

/* Compares the first three octets with the locally-administered bit
 * (bit 1 of octet 0, IEEE 802-2014 §8.2) masked off, because setup APs
 * are observed to set it on an otherwise registered prefix (#106: a
 * UniFi setup AP beaconing B6:FB:E4 for registered B4:FB:E4). The I/G
 * bit is not masked: a group address is never a transmitter.
 *
 * Returns 1 on a match and sets *vendor (short brand), *org (the
 * registry's assignee string, verbatim), *local (1 when the observed
 * address had the U/L bit set — "randomized-local") and *mixed. Any out
 * pointer may be NULL.
 *
 * *mixed is 1 for a mixed-vendor row (#155: Ubiquiti, TP-Link, Wyze —
 * vendors whose blocks carry routers, APs and plugs beside cameras).
 * Such a match names the vendor and is a +1 prior, nothing more: a
 * caller must not set a device class or fire CAM_SETUP_OUI on it alone.
 * A mixed row never matches a locally administered address — the U/L
 * mask above is for camera-vendor rows only. */
int cam_vendor_oui(const uint8_t mac[6], const char **vendor,
                   const char **org, int *local, int *mixed);

/* UPnP Device Architecture 1.0 §1.1.2: SERVER is "OS name/OS version
 * UPnP/1.0 product name/product version". Matches a camera vendor's
 * brand as a whole product-name token (case-insensitive, optionally
 * followed by '-' or '_'), never as a bare substring — "Axis" inside
 * some other word is not Axis. Returns 1 and sets *vendor. */
int cam_vendor_server(const char *server, const char **vendor);

/* DNS-SD service type as mdns_snoop.c stores it ("_axis-video._tcp").
 * The transport label is not compared: IANA registers the service
 * name, not a transport, for these rows. Returns 1 and sets *label (a
 * human description from the registry) and *camera_specific (0 for a
 * protocol cameras commonly advertise but that is not itself a camera
 * claim — RTSP). */
int cam_mdns_service(const char *service, const char **label,
                     int *camera_specific);

/* Camera vendors' documented setup-SoftAP SSID prefixes
 * (CAM_SETUP_SSID, #106 slice 2; moved here in round 2 so the Devices
 * join reads the same rows the rule fires on). ASCII case-insensitive
 * prefix match. Sets *label (rendered into the alert detail, e.g.
 * "Hikvision camera") and *brand (short vendor name for the device
 * record). The open-hotspot guardrail is the caller's: it runs before
 * this, in both callers. Sources: research/papers/camera-setup-softap.md. */
int cam_setup_ssid(const char *ssid, const char **label, const char **brand);

/* CAM_SSDP_DEVICE's row test, shared with the Devices join: a NOTIFY
 * (not an M-SEARCH, whose ST is what the asker wants) for UPnP
 * DigitalSecurityCamera:1 (*dsc = 1), or Basic:1 whose SERVER names a
 * camera vendor (*vendor set). For a DSC row *vendor is set too when
 * SERVER happens to name one, and NULL otherwise. */
int cam_ssdp_row(const char *type, const char *nts, const char *server,
                 int *dsc, const char **vendor);

/* Table sizes, for the provenance tests. */
int cam_vendor_oui_count(void);
void cam_vendor_oui_at(int i, uint8_t oui[3], const char **vendor,
                       const char **org);
int cam_vendor_oui_mixed_at(int i);

#endif /* CAMERA_VENDOR_H */
