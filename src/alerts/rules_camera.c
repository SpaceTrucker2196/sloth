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
 * keeps one alert per identity with a rising count — the DNS-SD
 * service instance, the SSDP device UUID, the BSSID (#145: the INFO ->
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

/* Does this row qualify, and as which shape? *vendor is set for a
 * Basic:1 row (the SERVER match) and left NULL for a DSC row. */
static int ssdp_cam_row(const ssdp_device_t *d, int *dsc,
                        const char **vendor) {
    *vendor = NULL;
    *dsc = 0;
    if (strcmp(d->nts, "search") == 0) return 0;
    if (strcasecmp(d->type, UPNP_DSC1) == 0) { *dsc = 1; return 1; }
    if (strcasecmp(d->type, UPNP_BASIC1) != 0) return 0;
    return cam_vendor_server(d->server, vendor);
}

/* Same device: the same USN UUID, or with no UUID the same address. */
static int ssdp_same_dev(const char *da, const ssdp_device_t *a,
                         const char *db, const ssdp_device_t *b) {
    if (da[0] || db[0]) return strcmp(da, db) == 0;
    return strcmp(a->ip, b->ip) == 0;
}

/* A total order over one device's rows that does not depend on where
 * they sit in the table: the DSC row first (it is the stronger claim),
 * then by address, SERVER, USN and NTS. */
static int ssdp_row_before(const ssdp_device_t *a, int adsc, int ai,
                           const ssdp_device_t *b, int bdsc, int bi) {
    int c;
    if (adsc != bdsc) return adsc > bdsc;
    if ((c = strcmp(a->ip, b->ip)) != 0)         return c < 0;
    if ((c = strcmp(a->server, b->server)) != 0) return c < 0;
    if ((c = strcmp(a->usn, b->usn)) != 0)       return c < 0;
    if ((c = strcmp(a->nts, b->nts)) != 0)       return c < 0;
    return ai < bi;
}

/* One fire() per device per tick. The table is keyed per USN, so one
 * camera announcing DSC:1 and Basic:1 under one UUID, or from two
 * addresses, is several rows of one incident. Firing each with its own
 * detail alternated the detail signature every tick, so observations
 * and alert.update events climbed with time while nothing changed — the
 * change-only churn agents/AGENTS.md warns about. Here the first row in
 * ssdp_row_before() order speaks for the device and the rest are folded
 * into one deterministic detail. */
void rule_cam_ssdp_device(const sloth_state_t *s, time_t now) {
    char devs[MAX_SSDP_DEVICES][96];
    int  ok[MAX_SSDP_DEVICES], dscv[MAX_SSDP_DEVICES];
    const char *vend[MAX_SSDP_DEVICES];
    int n = s->ssdp_count;
    if (n > MAX_SSDP_DEVICES) n = MAX_SSDP_DEVICES;
    for (int i = 0; i < n; i++) {
        ok[i] = ssdp_cam_row(&s->ssdp_devices[i], &dscv[i], &vend[i]);
        usn_device(s->ssdp_devices[i].usn, devs[i], sizeof(devs[i]));
    }

    for (int i = 0; i < n; i++) {
        if (!ok[i]) continue;
        const ssdp_device_t *d = &s->ssdp_devices[i];

        int lead = 1, more = 0;
        const char *other_vendor = NULL;
        for (int j = 0; j < n && lead; j++) {
            if (j == i || !ok[j]) continue;
            const ssdp_device_t *o = &s->ssdp_devices[j];
            if (!ssdp_same_dev(devs[i], d, devs[j], o)) continue;
            if (ssdp_row_before(o, dscv[j], j, d, dscv[i], i)) lead = 0;
            more++;
            if (vend[j] && (!other_vendor || strcmp(vend[j], other_vendor) < 0))
                other_vendor = vend[j];
        }
        if (!lead) continue;

        char key[ALERT_KEY_LEN];
        akey_t k;
        akey_begin(&k, key, sizeof(key), "camssdp");
        if (devs[i][0]) {
            akey_tok(&k, "usn");
            akey_remote(&k, devs[i], 48);
        } else {
            akey_tok(&k, "ip");
            akey_ip(&k, d->ip);
        }
        if (!akey_end(&k)[0]) continue;

        char also[64] = "";
        if (dscv[i] && other_vendor)
            snprintf(also, sizeof(also),
                     "; Basic:1 SERVER names vendor %.24s",
                     other_vendor);
        char rows[48] = "";
        if (more)
            snprintf(rows, sizeof(rows), "; %d more row%s for this device",
                     more, more == 1 ? "" : "s");

        char detail[ALERT_DETAIL_LEN];
        if (dscv[i])
            snprintf(detail, sizeof(detail),
                     "UPnP DigitalSecurityCamera:1 device at %.46s announced"
                     " itself over SSDP (NOTIFY %.15s)%s%.64s%.54s%.47s",
                     d->ip, d->nts,
                     d->server[0] ? ", SERVER " : "", d->server, also, rows);
        else
            snprintf(detail, sizeof(detail),
                     "UPnP Basic:1 device at %.46s names camera vendor %s"
                     " in its SERVER header (%.80s, NOTIFY %.15s) - the"
                     " device's own claim, not a registry check%.47s",
                     d->ip, vend[i], d->server, d->nts, rows);
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
