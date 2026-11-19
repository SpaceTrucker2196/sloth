/* Camera-vendor identity tables (#106 slice A). Contracts are in
 * camera_vendor.h; sources in research/papers/camera-vendor-identity.md.
 * The rows are the intel pack's camera-vendor files (#231), generated
 * into build/intel/ by tools/intel_gen and #included below. */
#include <stddef.h>
#include <string.h>
#include <strings.h>

#include "camera_vendor.h"

/* ── OUI table ─────────────────────────────────────────────
 *
 * Every row is one MA-L (24-bit) assignment from the IEEE Registration
 * Authority public listing, oui.csv, as distributed by Debian's
 * ieee-data package (.lastupdate 2024-07-22). The second string is the
 * registry's "Organization Name" column verbatim, so a row is its own
 * citation: look the assignment up at
 * https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries
 * and the assignee must read exactly as written here.
 * tests/test_camera_vendor.c holds the table to that file when the
 * host has it, and everywhere to a digest of the registry's names for
 * these assignments, so CI without ieee-data still catches an edit.
 *
 * Two kinds of row. A camera-vendor row (mixed 0) is an assignee whose
 * own published material describes it as a camera maker. That is a
 * vendor test, not a product test: a Hikvision block is on an NVR as
 * readily as on a camera, which is why the alert says "camera vendor",
 * not "camera". A mixed-vendor row (mixed 1, #155) is Ubiquiti, TP-Link
 * or Wyze: they sell cameras, but most of what their blocks put on the
 * wire is an AP, a router, a plug or a bulb — every UniFi AP in a
 * building would match — so such a match names the vendor and is a +1
 * prior in camera_join.c's score, never a class and never CAM_SETUP_OUI
 * on its own (camera_vendor.h). MA-M / MA-S blocks are not here: they
 * are 28- and 36-bit prefixes and this compares 24. */
typedef struct {
    uint8_t     oui[3];
    const char *vendor;
    const char *org;
    int         mixed;
} cam_oui_row_t;

static const cam_oui_row_t g_cam_oui[] = {
    /* intel/camera-vendor/camera_vendors.csv (#231), in its order: per
     * assignee, as the IEEE snapshot lists them. */
#include "camera_oui.inc"
};

#define CAM_OUI_N ((int)(sizeof(g_cam_oui) / sizeof(g_cam_oui[0])))

/* IEEE 802-2014 §8.2: bit 1 of octet 0 is U/L (1 = locally
 * administered), bit 0 is I/G (1 = group). */
#define MAC_UL_BIT 0x02

int cam_vendor_oui(const uint8_t mac[6], const char **vendor,
                   const char **org, int *local, int *mixed) {
    if (!mac) return 0;
    /* No I/G test needed: every row has it clear (MA-L, pinned by
     * test_oui_table_rows_are_registry_shaped) and it is not masked,
     * so a group address cannot compare equal. */
    int ul = (mac[0] & MAC_UL_BIT) ? 1 : 0;
    uint8_t o0 = (uint8_t)(mac[0] & ~MAC_UL_BIT);
    for (int i = 0; i < CAM_OUI_N; i++) {
        const cam_oui_row_t *r = &g_cam_oui[i];
        if (r->oui[0] != o0 || r->oui[1] != mac[1] || r->oui[2] != mac[2])
            continue;
        /* A mixed-vendor prior is already weak; one resting on the 22
         * free bits of a local address coinciding is no prior at all. */
        if (r->mixed && ul) return 0;
        if (vendor) *vendor = r->vendor;
        if (org)    *org    = r->org;
        if (local)  *local  = ul;
        if (mixed)  *mixed  = r->mixed;
        return 1;
    }
    return 0;
}

int cam_vendor_oui_count(void) { return CAM_OUI_N; }

int cam_vendor_oui_mixed_at(int i) {
    if (i < 0 || i >= CAM_OUI_N) return 0;
    return g_cam_oui[i].mixed;
}

void cam_vendor_oui_at(int i, uint8_t oui[3], const char **vendor,
                       const char **org) {
    if (i < 0 || i >= CAM_OUI_N) return;
    memcpy(oui, g_cam_oui[i].oui, 3);
    if (vendor) *vendor = g_cam_oui[i].vendor;
    if (org)    *org    = g_cam_oui[i].org;
}

/* ── SERVER product token ──────────────────────────────────
 *
 * The same vendor set as the OUI table, by brand — a firmware that
 * names its maker in SERVER names the brand, not the registry's legal
 * name. Not a list of observed SERVER strings: nobody publishes those,
 * and a row for one would be a guess. What is matched is the vendor
 * naming itself in the field UDA 1.0 §1.1.2 reserves for the product
 * name, which is the device's own claim and is reported as such. */
static const char *const g_cam_server_brands[] = {
#include "camera_server_brands.inc"    /* camera_server_brands.csv */
};

int cam_server_brand_count(void) {
    return (int)(sizeof(g_cam_server_brands) / sizeof(g_cam_server_brands[0]));
}

static int is_tok_sep(char c) {
    return c == ' ' || c == '\t' || c == ',' || c == '\0';
}

int cam_vendor_server(const char *server, const char **vendor) {
    if (!server) return 0;
    const char *p = server;
    while (*p) {
        while (*p && is_tok_sep(*p)) p++;
        if (!*p) break;
        const char *tok = p;
        while (*p && !is_tok_sep(*p)) p++;
        /* product name is the part of the token before '/' */
        size_t tlen = (size_t)(p - tok);
        const char *slash = memchr(tok, '/', tlen);
        size_t nlen = slash ? (size_t)(slash - tok) : tlen;
        for (size_t b = 0; b < sizeof(g_cam_server_brands) /
                               sizeof(g_cam_server_brands[0]); b++) {
            const char *brand = g_cam_server_brands[b];
            size_t blen = strlen(brand);
            if (nlen < blen || strncasecmp(tok, brand, blen) != 0) continue;
            if (nlen == blen || tok[blen] == '-' || tok[blen] == '_') {
                if (vendor) *vendor = brand;
                return 1;
            }
        }
    }
    return 0;
}

/* ── DNS-SD service types ──────────────────────────────────
 *
 * Each row is a Service Name in the IANA "Service Name and Transport
 * Protocol Port Number Registry" (RFC 6335), Description column quoted.
 * Vendor-specific names the issue proposed (_hikvision, _dahua,
 * _reolink, _wyze, _arlo, _nest-cam, _ubnt) are not registered and no
 * vendor document naming them was found, so they are not here. ONVIF
 * discovery is WS-Discovery, which CAM_WS_DISCOVERY already reads;
 * "onvif" is not a registered service name either. */
typedef struct {
    const char *name;            /* service label, leading '_' */
    const char *label;
    int         camera_specific;
} cam_svc_row_t;

static const cam_svc_row_t g_cam_svcs[] = {
    /* camera_services.csv (#231). axis-video ("Axis Video Cameras")
     * names the device class itself; cctv is "IP and Closed-Circuit
     * Television for Securitiy applications" (registry spelling); rtsp
     * (port 554) is a streaming protocol, not a device class - cameras
     * advertise it, so do some media servers - so it carries
     * camera_specific 0 and the alert says so instead of calling the
     * host a camera. */
#include "camera_services.inc"
};

int cam_mdns_service_count(void) {
    return (int)(sizeof(g_cam_svcs) / sizeof(g_cam_svcs[0]));
}

int cam_mdns_service(const char *service, const char **label,
                     int *camera_specific) {
    if (!service || service[0] != '_') return 0;
    const char *dot = strchr(service, '.');
    size_t n = dot ? (size_t)(dot - service) : strlen(service);
    for (size_t i = 0; i < sizeof(g_cam_svcs) / sizeof(g_cam_svcs[0]); i++) {
        const cam_svc_row_t *r = &g_cam_svcs[i];
        if (strlen(r->name) != n || strncasecmp(service, r->name, n) != 0)
            continue;
        if (label)           *label = r->label;
        if (camera_specific) *camera_specific = r->camera_specific;
        return 1;
    }
    return 0;
}

/* ── Setup-SoftAP SSID prefixes (CAM_SETUP_SSID) ───────────
 *
 * Moved from src/alerts/rules_twin.c unchanged (#106 round 2). Every
 * row cites the vendor's own onboarding documentation — see
 * research/papers/camera-setup-softap.md. Rows whose SSID shape could
 * not be sourced to a vendor document were left out rather than
 * guessed; see that document's "considered and not shipped" section. */
typedef struct {
    const char *prefix;
    const char *label;     /* rendered into the alert detail */
    const char *brand;     /* device record's camera_vendor   */
} cam_setup_ssid_pat_t;

static const cam_setup_ssid_pat_t g_camera_setup_ssid_pats[] = {
    /* camera_setup_ssids.csv (#231): HAP_ (Hikvision Access Point,
     * + the label's verification code), DAP- (Dahua, and Amcrest as its
     * OEM - hence the label names the OEM), EZVIZ_ (Hikvision's consumer
     * brand, + a 9-digit serial), Tapo_Cam_ (+ the MAC's last 4; the
     * trailing underscore keeps Tapo plugs and bulbs out). */
#include "camera_setup_ssids.inc"
};

int cam_setup_ssid_count(void) {
    return (int)(sizeof(g_camera_setup_ssid_pats) /
                 sizeof(g_camera_setup_ssid_pats[0]));
}

/* SSIDs are bytes, not text: fold ASCII only, never by locale. */
static int ssid_ascii_iprefix(const char *hay, const char *prefix) {
    for (int i = 0; prefix[i]; i++) {
        unsigned char h = (unsigned char)hay[i], p = (unsigned char)prefix[i];
        if (h >= 'A' && h <= 'Z') h = (unsigned char)(h - 'A' + 'a');
        if (p >= 'A' && p <= 'Z') p = (unsigned char)(p - 'A' + 'a');
        if (h != p) return 0;   /* also stops at hay's NUL */
    }
    return 1;
}

int cam_setup_ssid(const char *ssid, const char **label, const char **brand) {
    if (!ssid || !ssid[0]) return 0;
    for (size_t i = 0; i < sizeof(g_camera_setup_ssid_pats) /
                           sizeof(g_camera_setup_ssid_pats[0]); i++) {
        const cam_setup_ssid_pat_t *r = &g_camera_setup_ssid_pats[i];
        if (!ssid_ascii_iprefix(ssid, r->prefix)) continue;
        if (label) *label = r->label;
        if (brand) *brand = r->brand;
        return 1;
    }
    return 0;
}

/* ── SSDP camera row (CAM_SSDP_DEVICE) ─────────────────────── */

#define UPNP_DSC1   "urn:schemas-upnp-org:device:DigitalSecurityCamera:1"
#define UPNP_BASIC1 "urn:schemas-upnp-org:device:Basic:1"

int cam_ssdp_row(const char *type, const char *nts, const char *server,
                 int *dsc, const char **vendor) {
    const char *v = NULL;
    int d = 0, ok = 0;
    if (type && nts && strcmp(nts, "search") != 0) {
        int named = server ? cam_vendor_server(server, &v) : 0;
        if (strcasecmp(type, UPNP_DSC1) == 0)        { d = 1; ok = 1; }
        else if (strcasecmp(type, UPNP_BASIC1) == 0) ok = named;
        if (!named) v = NULL;
    }
    if (dsc)    *dsc    = ok ? d : 0;
    if (vendor) *vendor = ok ? v : NULL;
    return ok;
}
