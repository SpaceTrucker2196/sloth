/* Camera-identity rules over tables sloth already keeps (#106 slice A):
 * mDNS service rows, SSDP NOTIFY rows and beaconing BSSIDs, each read
 * against src/camera_vendor.c. No new capture surface — every input was
 * put on the air by the device itself, and sloth sends nothing to get
 * it (no M-SEARCH, no mDNS query, no probe).
 *
 * The three findings are the device's own exposure, not an adversary's
 * step, so they sit on the empty-technique list with OPEN_SETUP_AP,
 * CAM_WS_DISCOVERY and CAM_SETUP_SSID: T1046 would claim an
 * enumeration sloth did not perform. Each WARNs on first sighting and
 * keeps one alert per device with a rising count (#145: the INFO ->
 * WARN -> CRIT join across signals is unobservable, so it is not
 * attempted).
 *
 * Sources: research/papers/camera-vendor-identity.md. Kept in a file
 * of its own so the camera slices merge without touching each other's
 * rules. */
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include "camera_vendor.h"
#include "alert_key.h"
#include "rules.h"
#include "engine_internal.h"

/* ── CAM_MDNS_SERVICE ───────────────────────────────────────
 *
 * A DNS-SD service type IANA registers for camera video (axis-video,
 * cctv), or RTSP, which cameras advertise and which is reported as
 * what it is rather than as a camera. One alert per instance name:
 * that is the DNS-SD identity (RFC 6763 §4.1) and it survives a
 * DHCP lease change; the IP is in the detail and the pcap match. */
void rule_cam_mdns_service(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->mdns_count; i++) {
        const mdns_service_t *e = &s->mdns_services[i];
        const char *label = NULL;
        int specific = 0;
        if (!e->instance[0]) continue;
        if (!cam_mdns_service(e->service, &label, &specific)) continue;

        char key[ALERT_KEY_LEN];
        akey_t k;
        akey_begin(&k, key, sizeof(key), "cammdns");
        akey_remote(&k, e->instance, 40);
        if (!akey_end(&k)[0]) continue;

        char where[64];
        if (e->ip[0] && e->port)
            snprintf(where, sizeof(where), " at %.46s:%u", e->ip,
                     (unsigned)e->port);
        else if (e->ip[0])
            snprintf(where, sizeof(where), " at %.46s", e->ip);
        else
            snprintf(where, sizeof(where), "%s", " (address not yet seen)");

        char detail[ALERT_DETAIL_LEN];
        snprintf(detail, sizeof(detail),
                 "mDNS instance %.48s advertises %.31s, %.48s%.63s%s%.40s%s",
                 e->instance, e->service, label, where,
                 e->host[0] ? ", host " : "", e->host,
                 /* RTSP is a protocol, not a device class: said so in
                  * the row itself rather than left to the doc. */
                 specific ? "" : "; RTSP corroborates, not a device class");
        fire(ALERT_TYPE_CAM_MDNS_SERVICE, ALERT_SEV_WARN,
             "CAM_MDNS_SERVICE", detail, key,
             e->ip[0] ? e->ip : NULL, e->port, now);
    }
}

/* ── CAM_SSDP_DEVICE ────────────────────────────────────────
 *
 * Two shapes, both from a NOTIFY the device multicast:
 *
 *   DigitalSecurityCamera:1  the UPnP Forum's standardized camera
 *                            device type (DCP, 2005) — the device
 *                            calling itself a camera in the one field
 *                            that exists for that.
 *   Basic:1 + vendor SERVER  Basic:1 is the type for a product with no
 *                            standard type, so on its own it says
 *                            nothing; it counts only when the SERVER
 *                            header's product token names a camera
 *                            vendor (#145 ruling).
 *
 * An M-SEARCH row ("search") is skipped: its ST is what the *asker*
 * wants, so a control point searching for cameras is not one. */
#define UPNP_DSC1   "urn:schemas-upnp-org:device:DigitalSecurityCamera:1"
#define UPNP_BASIC1 "urn:schemas-upnp-org:device:Basic:1"

/* UDA 1.0 §1.1.4: USN is "uuid:device-UUID" optionally followed by
 * "::" and the type. The UUID part is the device; the rest varies per
 * NOTIFY, so keying on the whole USN would split one camera's
 * DigitalSecurityCamera and rootdevice announcements apart. */
static void usn_device(const char *usn, char *out, size_t n) {
    const char *sep = strstr(usn, "::");
    size_t len = sep ? (size_t)(sep - usn) : strlen(usn);
    if (len >= n) len = n - 1;
    memcpy(out, usn, len);
    out[len] = '\0';
}

void rule_cam_ssdp_device(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->ssdp_count; i++) {
        const ssdp_device_t *d = &s->ssdp_devices[i];
        if (strcmp(d->nts, "search") == 0) continue;

        const char *vendor = NULL;
        int dsc = strcasecmp(d->type, UPNP_DSC1) == 0;
        if (!dsc) {
            if (strcasecmp(d->type, UPNP_BASIC1) != 0) continue;
            if (!cam_vendor_server(d->server, &vendor)) continue;
        }

        char dev[96];
        usn_device(d->usn, dev, sizeof(dev));

        char key[ALERT_KEY_LEN];
        akey_t k;
        akey_begin(&k, key, sizeof(key), "camssdp");
        if (dev[0]) {
            akey_tok(&k, "usn");
            akey_remote(&k, dev, 48);
        } else {
            akey_tok(&k, "ip");
            akey_ip(&k, d->ip);
        }
        if (!akey_end(&k)[0]) continue;

        char detail[ALERT_DETAIL_LEN];
        if (dsc)
            snprintf(detail, sizeof(detail),
                     "UPnP DigitalSecurityCamera:1 device at %.46s announced"
                     " itself over SSDP (NOTIFY %.15s)%s%.80s",
                     d->ip, d->nts,
                     d->server[0] ? ", SERVER " : "", d->server);
        else
            snprintf(detail, sizeof(detail),
                     "UPnP Basic:1 device at %.46s names camera vendor %s"
                     " in its SERVER header (%.80s, NOTIFY %.15s) - the"
                     " device's own claim, not a registry check",
                     d->ip, vendor, d->server, d->nts);
        fire(ALERT_TYPE_CAM_SSDP_DEVICE, ALERT_SEV_WARN,
             "CAM_SSDP_DEVICE", detail, key, d->ip, 0, now);
    }
}

/* ── CAM_SETUP_OUI ──────────────────────────────────────────
 *
 * A beaconing BSSID inside an IEEE MA-L block assigned to a camera
 * vendor. A camera that beacons is acting as an AP — its setup SoftAP,
 * or a base station for its own cameras — which is the exposure #80 and
 * CAM_SETUP_SSID report from the SSID; this reports it from the
 * address, so a setup AP with a renamed or hidden SSID still shows.
 *
 * Compared with the U/L bit masked (camera_vendor.h says why) and the
 * fact reported as "randomized-local": a locally administered address
 * is by definition not a registry assignment, so that match rests on
 * the remaining 22 free bits coinciding, and the operator is told so. */
void rule_cam_setup_oui(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        const char *vendor = NULL, *org = NULL;
        int local = 0;
        if (!cam_vendor_oui(a->bssid, &vendor, &org, &local)) continue;

        char bssid_str[20];
        fmt_bssid(bssid_str, a->bssid);

        char key[ALERT_KEY_LEN];
        akey_t k;
        akey_begin(&k, key, sizeof(key), "camoui");
        akey_mac(&k, a->bssid);
        if (!akey_end(&k)[0]) continue;

        char detail[ALERT_DETAIL_LEN];
        snprintf(detail, sizeof(detail),
                 "BSSID %s ch %d SSID %.32s, enc %.9s: OUI %02X:%02X:%02X"
                 " is IEEE MA-L \"%.48s\" (%s, camera vendor; device class"
                 " not observed)%s",
                 bssid_str, a->channel,
                 a->ssid[0] ? a->ssid : "<hidden>",
                 a->enc[0] ? a->enc : "unknown",
                 (unsigned)(a->bssid[0] & ~0x02u), (unsigned)a->bssid[1],
                 (unsigned)a->bssid[2], org, vendor,
                 local ? "; randomized-local: U/L bit set, matched with it"
                         " masked - not itself a registry assignment"
                       : "");
        fire(ALERT_TYPE_CAM_SETUP_OUI, ALERT_SEV_WARN,
             "CAM_SETUP_OUI", detail, key, NULL, 0, now);
    }
}
