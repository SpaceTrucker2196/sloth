/* Camera-vendor identity tables (#106 slice A). Contracts are in
 * camera_vendor.h; sources in research/papers/camera-vendor-identity.md. */
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
 * host has it.
 *
 * Only assignees whose own published material describes them as a
 * camera maker are here. That is a vendor test, not a product test:
 * a Hikvision block is on an NVR as readily as on a camera, which is
 * why the alert says "camera vendor", not "camera". Ubiquiti, TP-Link
 * and Wyze are not here although they sell cameras, because most of
 * what they put on the air is not one — every UniFi AP in a building
 * would match. MA-M / MA-S blocks are not here: they are 28- and
 * 36-bit prefixes and this compares 24. */
typedef struct {
    uint8_t     oui[3];
    const char *vendor;
    const char *org;
} cam_oui_row_t;

static const cam_oui_row_t g_cam_oui[] = {
    /* IEEE RA MA-L, assignee "Amcrest Technologies" */
    { {0x00,0x65,0x1E}, "Amcrest", "Amcrest Technologies" },
    { {0x9C,0x8E,0xCD}, "Amcrest", "Amcrest Technologies" },
    { {0xA0,0x60,0x32}, "Amcrest", "Amcrest Technologies" },
    /* IEEE RA MA-L, assignee "Arlo Technology" */
    { {0x48,0x62,0x64}, "Arlo", "Arlo Technology" },
    { {0xA4,0x11,0x62}, "Arlo", "Arlo Technology" },
    { {0xFC,0x9C,0x98}, "Arlo", "Arlo Technology" },
    /* IEEE RA MA-L, assignee "Axis Communications AB" */
    { {0x00,0x40,0x8C}, "Axis", "Axis Communications AB" },
    { {0xAC,0xCC,0x8E}, "Axis", "Axis Communications AB" },
    { {0xB8,0xA4,0x4F}, "Axis", "Axis Communications AB" },
    { {0xE8,0x27,0x25}, "Axis", "Axis Communications AB" },
    /* IEEE RA MA-L, assignee "ZHEJIANG DAHUA TECHNOLOGYCO.,LTD" */
    { {0x30,0xDD,0xAA}, "Dahua", "ZHEJIANG DAHUA TECHNOLOGYCO.,LTD" },
    { {0x40,0x7A,0xA4}, "Dahua", "ZHEJIANG DAHUA TECHNOLOGYCO.,LTD" },
    { {0x4C,0x99,0xE8}, "Dahua", "ZHEJIANG DAHUA TECHNOLOGYCO.,LTD" },
    { {0xF8,0xCE,0x07}, "Dahua", "ZHEJIANG DAHUA TECHNOLOGYCO.,LTD" },
    /* IEEE RA MA-L, assignee "Zhejiang Dahua Technology Co., Ltd." */
    { {0x08,0xED,0xED}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0x14,0xA7,0x8B}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0x24,0x52,0x6A}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0x38,0xAF,0x29}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0x3C,0xE3,0x6B}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0x3C,0xEF,0x8C}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0x4C,0x11,0xBF}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0x5C,0xF5,0x1A}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0x64,0xFD,0x29}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0x6C,0x1C,0x71}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0x74,0xC9,0x29}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0x8C,0xE9,0xB4}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0x90,0x02,0xA9}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0x98,0xF9,0xCC}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0x9C,0x14,0x63}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0xA0,0xBD,0x1D}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0xB4,0x4C,0x3B}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0xBC,0x32,0x5F}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0xC0,0x39,0x5A}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0xC4,0xAA,0xC4}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0xD4,0x43,0x0E}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0xE0,0x2E,0xFE}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0xE0,0x50,0x8B}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0xE4,0x24,0x6C}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0xF4,0xB1,0xC2}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0xFC,0x5F,0x49}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    { {0xFC,0xB6,0x9D}, "Dahua", "Zhejiang Dahua Technology Co., Ltd." },
    /* IEEE RA MA-L, assignee "Hangzhou Ezviz Software Co.,Ltd." */
    { {0x0C,0xA6,0x4C}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd." },
    { {0x20,0xBB,0xBC}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd." },
    { {0x34,0xC6,0xDD}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd." },
    { {0x54,0xD6,0x0D}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd." },
    { {0x58,0x8F,0xCF}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd." },
    { {0x64,0x24,0x4D}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd." },
    { {0x64,0xF2,0xFB}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd." },
    { {0x78,0xA6,0xA0}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd." },
    { {0x78,0xC1,0xAE}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd." },
    { {0x94,0xEC,0x13}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd." },
    { {0xAC,0x1C,0x26}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd." },
    { {0xEC,0x97,0xE0}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd." },
    { {0xF4,0x70,0x18}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd." },
    { {0xFC,0x24,0x22}, "EZVIZ", "Hangzhou Ezviz Software Co.,Ltd." },
    /* IEEE RA MA-L, assignee "Hangzhou Hikvision Digital Technology Co.,Ltd." */
    { {0x00,0xBC,0x99}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x04,0x03,0x12}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x04,0xEE,0xCD}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x08,0x3B,0xC1}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x08,0x54,0x11}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x08,0xA1,0x89}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x08,0xCC,0x81}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x0C,0x75,0xD2}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x10,0x12,0xFB}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x18,0x68,0xCB}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x18,0x80,0x25}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x24,0x0F,0x9B}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x24,0x28,0xFD}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x24,0x32,0xAE}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x24,0x48,0x45}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x28,0x57,0xBE}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x2C,0xA5,0x9C}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x34,0x09,0x62}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x3C,0x1B,0xF8}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x40,0xAC,0xBF}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x40,0xB5,0x70}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x44,0x19,0xB6}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x44,0x47,0xCC}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x44,0xA6,0x42}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x48,0x78,0x5B}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x4C,0x1F,0x86}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x4C,0x62,0xDF}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x4C,0xBD,0x8F}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x4C,0xF5,0xDC}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x50,0xE5,0x38}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x54,0x8C,0x81}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x54,0xC4,0x15}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x58,0x03,0xFB}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x58,0x50,0xED}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x5C,0x34,0x5B}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x64,0xDB,0x8B}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x68,0x6D,0xBC}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x74,0x3F,0xC2}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x80,0x48,0x9F}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x80,0x7C,0x62}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x80,0xBE,0xAF}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x80,0xF5,0xAE}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x84,0x94,0x59}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x84,0x9A,0x40}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x88,0xDE,0x39}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x8C,0x22,0xD2}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x8C,0xE7,0x48}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x94,0xE1,0xAC}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x98,0x8B,0x0A}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x98,0x9D,0xE5}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x98,0xDF,0x82}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0x98,0xF1,0x12}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xA0,0xFF,0x0C}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xA4,0x14,0x37}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xA4,0x29,0x02}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xA4,0x4B,0xD9}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xA4,0xA4,0x59}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xA4,0xD5,0xC2}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xAC,0xB9,0x2F}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xAC,0xCB,0x51}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xB4,0xA3,0x82}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xBC,0x5E,0x33}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xBC,0x9B,0x5E}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xBC,0xAD,0x28}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xBC,0xBA,0xC2}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xC0,0x51,0x7E}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xC0,0x56,0xE3}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xC0,0x6D,0xED}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xC4,0x2F,0x90}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xC8,0xA7,0x02}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xCC,0x13,0xF3}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xD4,0xE8,0x53}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xDC,0x07,0xF8}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xDC,0xD2,0x6A}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xE0,0xBA,0xAD}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xE0,0xCA,0x3C}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xE0,0xDF,0x13}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xE4,0xD5,0x8B}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xE8,0xA0,0xED}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xEC,0xA9,0x71}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xEC,0xC8,0x9C}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xF8,0x4D,0xFC}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    { {0xFC,0x9F,0xFD}, "Hikvision", "Hangzhou Hikvision Digital Technology Co.,Ltd." },
    /* IEEE RA MA-L, assignee "Lorex Technology Inc." */
    { {0x00,0x1F,0x54}, "Lorex", "Lorex Technology Inc." },
    /* IEEE RA MA-L, assignee "Mobotix AG" */
    { {0x00,0x03,0xC5}, "Mobotix", "Mobotix AG" },
    /* IEEE RA MA-L, assignee "Reolink Innovation Limited" */
    { {0xEC,0x71,0xDB}, "Reolink", "Reolink Innovation Limited" },
};

#define CAM_OUI_N ((int)(sizeof(g_cam_oui) / sizeof(g_cam_oui[0])))

/* IEEE 802-2014 §8.2: bit 1 of octet 0 is U/L (1 = locally
 * administered), bit 0 is I/G (1 = group). */
#define MAC_UL_BIT 0x02

int cam_vendor_oui(const uint8_t mac[6], const char **vendor,
                   const char **org, int *local) {
    if (!mac) return 0;
    /* No I/G test needed: every row has it clear (MA-L, pinned by
     * test_oui_table_rows_are_registry_shaped) and it is not masked,
     * so a group address cannot compare equal. */
    uint8_t o0 = (uint8_t)(mac[0] & ~MAC_UL_BIT);
    for (int i = 0; i < CAM_OUI_N; i++) {
        const cam_oui_row_t *r = &g_cam_oui[i];
        if (r->oui[0] != o0 || r->oui[1] != mac[1] || r->oui[2] != mac[2])
            continue;
        if (vendor) *vendor = r->vendor;
        if (org)    *org    = r->org;
        if (local)  *local  = (mac[0] & MAC_UL_BIT) ? 1 : 0;
        return 1;
    }
    return 0;
}

int cam_vendor_oui_count(void) { return CAM_OUI_N; }

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
    "Hikvision", "EZVIZ", "Dahua", "Amcrest", "Axis",
    "Reolink", "Mobotix", "Lorex", "Arlo",
};

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
    /* IANA: axis-video, "Axis Video Cameras" — the registry entry
     * names the device class itself, which is why it is a row. */
    { "_axis-video", "Axis video camera service (IANA axis-video)", 1 },
    /* IANA: cctv, "IP and Closed-Circuit Television for Securitiy
     * applications" (registry spelling). */
    { "_cctv",       "IP/CCTV security video service (IANA cctv)", 1 },
    /* IANA: rtsp, port 554, "Real Time Streaming Protocol (RTSP)".
     * A streaming protocol, not a device class: cameras advertise it,
     * so do some media servers. Carried with camera_specific 0 so the
     * alert says so instead of calling the host a camera. */
    { "_rtsp",       "RTSP stream service (IANA rtsp)", 0 },
};

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
