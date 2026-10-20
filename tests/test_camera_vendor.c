/* Camera identity over mDNS, SSDP and the transmitter OUI (#106 slice A).
 *
 * Frames are hand-built per their clause, no pcap (agents/AGENTS.md):
 * the mDNS answer per RFC 1035 §3.1/§4.1.3 and RFC 6762 §10.2 (cache-
 * flush class bit), the SSDP NOTIFY per UPnP Device Architecture 1.0
 * §1.1.2/§1.1.3. The rules are then driven through the real parsers
 * and snapshots, so the path a capture would take is the path tested.
 *
 * Both clocks are pinned (sloth_clock_test_set): ssdp_snoop() and
 * alerts_update() stamp through the seam, and a test of "one alert, a
 * rising count" must not depend on which second it ran in. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "runner.h"
#include "sloth.h"
#include "alerts.h"
#include "camera_vendor.h"
#include "mdns_snoop.h"
#include "ssdp_snoop.h"
#include "sloth_clock.h"

/* ── Clock pin ─────────────────────────────────────────────── */

static time_t   cv_wall(void) { return (time_t)1760000000; }
static uint64_t cv_mono(void) { return 5000000ull; }
static void pin_clock(void) { sloth_clock_test_set(cv_mono, cv_wall); }

TEST_STATE(g_s);

static sloth_state_t *fresh(void) {
    pin_clock();
    alerts_clear();
    memset(&g_s, 0, sizeof(g_s));
    return &g_s;
}

static int find_alert(const sloth_state_t *s, alert_type_t type) {
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == type) return i;
    return -1;
}

static int count_alerts(const sloth_state_t *s, alert_type_t type) {
    int n = 0;
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == type) n++;
    return n;
}

/* ── camera_vendor.c: the OUI table ───────────────────────── */

static void test_oui_table_rows_are_registry_shaped(void) {
    /* An MA-L assignment is a universally administered individual
     * address block: U/L and I/G both clear (IEEE 802-2014 §8.2). A row
     * with either set could not have come from the registry, and a
     * duplicate means a transcription went wrong somewhere. */
    int n = cam_vendor_oui_count();
    ASSERT_GT(n, 0);
    int bad_bits = 0, dups = 0, no_org = 0;
    for (int i = 0; i < n; i++) {
        uint8_t a[3]; const char *v = NULL, *o = NULL;
        cam_vendor_oui_at(i, a, &v, &o);
        if (a[0] & 0x03) bad_bits++;
        if (!v || !v[0] || !o || !o[0]) no_org++;
        for (int j = i + 1; j < n; j++) {
            uint8_t b[3];
            cam_vendor_oui_at(j, b, NULL, NULL);
            if (memcmp(a, b, 3) == 0) dups++;
        }
    }
    ASSERT_EQ(bad_bits, 0);
    ASSERT_EQ(dups, 0);
    ASSERT_EQ(no_org, 0);
}

/* "MA-L,0012AB,Org Name,Address" — the org is quoted when it holds a
 * comma, with "" for a literal quote. Enough CSV for this file. */
static int csv_field(const char **pp, char *out, size_t n) {
    const char *p = *pp;
    size_t k = 0;
    if (*p == '"') {
        p++;
        while (*p) {
            if (p[0] == '"' && p[1] == '"') { if (k + 1 < n) out[k++] = '"'; p += 2; continue; }
            if (*p == '"') { p++; break; }
            if (k + 1 < n) out[k++] = *p;
            p++;
        }
    } else {
        while (*p && *p != ',' && *p != '\n' && *p != '\r') {
            if (k + 1 < n) out[k++] = *p;
            p++;
        }
    }
    out[k] = '\0';
    if (*p == ',') p++;
    *pp = p;
    return 1;
}

static void test_oui_table_matches_the_ieee_registry(void) {
    /* Every row claims to be one registry entry, verbatim. Hold it to
     * the registry where the host carries a copy (Debian's ieee-data);
     * where it does not, say so rather than pass silently. */
    FILE *f = fopen("/usr/share/ieee-data/oui.csv", "r");
    if (!f) {
        printf("    note: /usr/share/ieee-data/oui.csv absent, registry"
               " cross-check skipped\n");
        ASSERT_GT(cam_vendor_oui_count(), 0);
        return;
    }
    int n = cam_vendor_oui_count();
    int *ok = calloc((size_t)n, sizeof(int));
    ASSERT(ok != NULL);
    if (!ok) { fclose(f); return; }
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        const char *p = line;
        char reg[16], asg[16], org[256];
        csv_field(&p, reg, sizeof(reg));
        csv_field(&p, asg, sizeof(asg));
        csv_field(&p, org, sizeof(org));
        if (strcmp(reg, "MA-L") != 0 || strlen(asg) != 6) continue;
        unsigned v = (unsigned)strtoul(asg, NULL, 16);
        uint8_t a[3] = { (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
        for (int i = 0; i < n; i++) {
            uint8_t b[3]; const char *o = NULL;
            cam_vendor_oui_at(i, b, NULL, &o);
            if (memcmp(a, b, 3) == 0 && o && strcmp(o, org) == 0) ok[i] = 1;
        }
    }
    fclose(f);
    int missing = 0;
    for (int i = 0; i < n; i++) {
        if (ok[i]) continue;
        uint8_t b[3]; const char *o = NULL;
        cam_vendor_oui_at(i, b, NULL, &o);
        printf("    not in registry as written: %02X%02X%02X \"%s\"\n",
               b[0], b[1], b[2], o ? o : "");
        missing++;
    }
    free(ok);
    ASSERT_EQ(missing, 0);
}

static void test_oui_exact_match_is_not_local(void) {
    /* 44:19:B6 — IEEE MA-L, Hangzhou Hikvision Digital Technology. */
    const uint8_t mac[6] = {0x44,0x19,0xB6,0x12,0x34,0x56};
    const char *v = NULL, *o = NULL; int local = -1;
    ASSERT_EQ(cam_vendor_oui(mac, &v, &o, &local), 1);
    ASSERT(v && strcmp(v, "Hikvision") == 0);
    ASSERT(o && strcmp(o, "Hangzhou Hikvision Digital Technology Co.,Ltd.") == 0);
    ASSERT_EQ(local, 0);
}

static void test_oui_ul_bit_is_masked_and_reported(void) {
    /* #106 Case B's mechanism on a camera-vendor block: 0x44 | 0x02 =
     * 0x46. Without the mask this is no match at all. */
    const uint8_t mac[6] = {0x46,0x19,0xB6,0x12,0x34,0x56};
    const char *v = NULL; int local = -1;
    ASSERT_EQ(cam_vendor_oui(mac, &v, NULL, &local), 1);
    ASSERT(v && strcmp(v, "Hikvision") == 0);
    ASSERT_EQ(local, 1);
}

static void test_oui_group_bit_and_other_bits_are_not_masked(void) {
    /* Only U/L is masked. I/G set is a group address, never a
     * transmitter; any other bit is a different OUI. */
    const uint8_t grp[6] = {0x45,0x19,0xB6,0x12,0x34,0x56};
    const uint8_t oth[6] = {0x4C,0x19,0xB6,0x12,0x34,0x56};
    ASSERT_EQ(cam_vendor_oui(grp, NULL, NULL, NULL), 0);
    ASSERT_EQ(cam_vendor_oui(oth, NULL, NULL, NULL), 0);
    ASSERT_EQ(cam_vendor_oui(NULL, NULL, NULL, NULL), 0);
}

static void test_oui_ubiquiti_is_deliberately_absent(void) {
    /* #106's own field example. Ubiquiti's blocks are on every UniFi AP,
     * so they are not a camera signal; the exclusion is the design, and
     * this pins it so a later "complete the table" does not undo it. */
    const uint8_t reg[6] = {0xB4,0xFB,0xE4,0x01,0x02,0x03};
    const uint8_t loc[6] = {0xB6,0xFB,0xE4,0x01,0x02,0x03};
    ASSERT_EQ(cam_vendor_oui(reg, NULL, NULL, NULL), 0);
    ASSERT_EQ(cam_vendor_oui(loc, NULL, NULL, NULL), 0);
}

/* ── camera_vendor.c: SERVER product token ───────────────── */

static void test_server_token_matches_vendor_product(void) {
    const char *v = NULL;
    /* #106 Case E's header, UDA 1.0 §1.1.2 shape. */
    ASSERT_EQ(cam_vendor_server("Linux/3.x UPnP/1.0 Dahua/1.0", &v), 1);
    ASSERT(v && strcmp(v, "Dahua") == 0);
    v = NULL;
    ASSERT_EQ(cam_vendor_server("Linux UPnP/1.0 Hikvision-Webs", &v), 1);
    ASSERT(v && strcmp(v, "Hikvision") == 0);
    v = NULL;
    ASSERT_EQ(cam_vendor_server("Linux/4.9, UPnP/1.0, AXIS/10.12", &v), 1);
    ASSERT(v && strcmp(v, "Axis") == 0);
}

static void test_server_token_rejects_substrings_and_generic(void) {
    /* A brand inside a longer word is not the brand. The libupnp
     * string is what a great many non-cameras send. */
    ASSERT_EQ(cam_vendor_server("Linux/3.x UPnP/1.0 Taxis/1.0", NULL), 0);
    ASSERT_EQ(cam_vendor_server("Linux/3.x UPnP/1.0 Axisx/1.0", NULL), 0);
    ASSERT_EQ(cam_vendor_server("Linux/3.10, UPnP/1.0, Portable SDK for"
                                " UPnP devices/1.6.6", NULL), 0);
    ASSERT_EQ(cam_vendor_server("", NULL), 0);
    ASSERT_EQ(cam_vendor_server(NULL, NULL), 0);
}

/* ── camera_vendor.c: DNS-SD service types ───────────────── */

static void test_mdns_service_table(void) {
    const char *label = NULL; int spec = -1;
    ASSERT_EQ(cam_mdns_service("_axis-video._tcp", &label, &spec), 1);
    ASSERT_EQ(spec, 1);
    ASSERT(label && strstr(label, "axis-video") != NULL);
    ASSERT_EQ(cam_mdns_service("_cctv._tcp", NULL, &spec), 1);
    ASSERT_EQ(spec, 1);
    ASSERT_EQ(cam_mdns_service("_rtsp._tcp", NULL, &spec), 1);
    ASSERT_EQ(spec, 0);
    /* Transport is not compared; the label is, whole. */
    ASSERT_EQ(cam_mdns_service("_axis-video._udp", NULL, NULL), 1);
    ASSERT_EQ(cam_mdns_service("_rtsp-alt._tcp", NULL, NULL), 0);
    ASSERT_EQ(cam_mdns_service("_rts._tcp", NULL, NULL), 0);
    ASSERT_EQ(cam_mdns_service("_ipp._tcp", NULL, NULL), 0);
    ASSERT_EQ(cam_mdns_service("", NULL, NULL), 0);
}

/* ── Hand-built mDNS response (RFC 1035 §4.1, RFC 6762) ────── */

static int put_name(uint8_t *b, int off, const char *name) {
    /* RFC 1035 §3.1: length-prefixed labels, zero root, uncompressed. */
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        int len = dot ? (int)(dot - p) : (int)strlen(p);
        b[off++] = (uint8_t)len;
        memcpy(b + off, p, (size_t)len);
        off += len;
        p += len;
        if (*p == '.') p++;
    }
    b[off++] = 0;
    return off;
}

static int put_rr_hdr(uint8_t *b, int off, uint16_t type, uint16_t cls,
                      uint32_t ttl, uint16_t rdlen) {
    b[off++] = (uint8_t)(type >> 8);  b[off++] = (uint8_t)type;
    b[off++] = (uint8_t)(cls >> 8);   b[off++] = (uint8_t)cls;
    b[off++] = (uint8_t)(ttl >> 24);  b[off++] = (uint8_t)(ttl >> 16);
    b[off++] = (uint8_t)(ttl >> 8);   b[off++] = (uint8_t)ttl;
    b[off++] = (uint8_t)(rdlen >> 8); b[off++] = (uint8_t)rdlen;
    return off;
}

/* An unsolicited announcement: QR=1 AA=1 (0x8400), three answers —
 * PTR service->instance, SRV instance->host:port (cache-flush class
 * 0x8001), A host->addr. Returns the length. */
static int build_mdns_announce(uint8_t *b, int cap, const char *svc,
                               const char *inst, const char *host,
                               uint16_t port, const uint8_t ip[4]) {
    memset(b, 0, (size_t)cap);
    int off = 0;
    b[2] = 0x84; b[3] = 0x00;            /* flags */
    b[7] = 3;                            /* ANCOUNT */
    off = 12;
    /* PTR */
    off = put_name(b, off, svc);
    int rd_at = off + 8;
    off = put_rr_hdr(b, off, 12, 0x0001, 4500, 0);
    int rd0 = off;
    off = put_name(b, off, inst);
    b[rd_at] = (uint8_t)((off - rd0) >> 8); b[rd_at + 1] = (uint8_t)(off - rd0);
    /* SRV */
    off = put_name(b, off, inst);
    rd_at = off + 8;
    off = put_rr_hdr(b, off, 33, 0x8001, 120, 0);
    rd0 = off;
    b[off++] = 0; b[off++] = 0;          /* priority */
    b[off++] = 0; b[off++] = 0;          /* weight   */
    b[off++] = (uint8_t)(port >> 8); b[off++] = (uint8_t)port;
    off = put_name(b, off, host);
    b[rd_at] = (uint8_t)((off - rd0) >> 8); b[rd_at + 1] = (uint8_t)(off - rd0);
    /* A */
    off = put_name(b, off, host);
    off = put_rr_hdr(b, off, 1, 0x8001, 120, 4);
    memcpy(b + off, ip, 4);
    off += 4;
    return off;
}

static void mdns_feed(sloth_state_t *s, const char *svc, const char *inst,
                      const char *host, uint16_t port, uint8_t last_octet) {
    uint8_t pkt[512];
    const uint8_t ip[4] = {192, 168, 1, last_octet};
    int n = build_mdns_announce(pkt, (int)sizeof(pkt), svc, inst, host,
                                port, ip);
    ASSERT_GT(mdns_snoop_at(pkt, n, cv_wall()), 0);
    mdns_snapshot(s);
}

static void test_cam_mdns_rtsp_case_d(void) {
    /* #106 Case D: _rtsp._tcp PTR + SRV for a Reolink instance. */
    sloth_state_t *s = fresh();
    mdns_feed(s, "_rtsp._tcp.local", "Reolink-RLC-810A._rtsp._tcp.local",
              "reolink-810a.local", 554, 77);
    alerts_update(s);
    int i = find_alert(s, ALERT_TYPE_CAM_MDNS_SERVICE);
    ASSERT(i >= 0);
    if (i < 0) return;
    ASSERT_EQ((int)s->alerts[i].sev, (int)ALERT_SEV_WARN);
    ASSERT_EQ((int)s->alerts[i].technique[0], 0);
    ASSERT(strncmp(s->alerts[i].key, "cammdns:", 8) == 0);
    ASSERT(strstr(s->alerts[i].detail, "Reolink-RLC-810A") != NULL);
    ASSERT(strstr(s->alerts[i].detail, "192.168.1.77:554") != NULL);
    /* RTSP is reported as the protocol it is, not as a camera. */
    ASSERT(strstr(s->alerts[i].detail, "not a device class") != NULL);
    ASSERT(strcmp(s->alerts[i].match_ip, "192.168.1.77") == 0);
    ASSERT_EQ((int)s->alerts[i].match_port, 554);
}

static void test_cam_mdns_axis_video_is_camera_specific(void) {
    sloth_state_t *s = fresh();
    mdns_feed(s, "_axis-video._tcp.local",
              "AXIS M3106-L - ACCC8E012345._axis-video._tcp.local",
              "axis-accc8e012345.local", 80, 31);
    alerts_update(s);
    int i = find_alert(s, ALERT_TYPE_CAM_MDNS_SERVICE);
    ASSERT(i >= 0);
    if (i < 0) return;
    ASSERT(strstr(s->alerts[i].detail, "Axis video camera") != NULL);
    ASSERT(strstr(s->alerts[i].detail, "not a device class") == NULL);
}

static void test_cam_mdns_quiet_on_printer(void) {
    /* #106 Case I's printer. Seen red by deleting the
     * cam_mdns_service() gate in rule_cam_mdns_service. */
    sloth_state_t *s = fresh();
    mdns_feed(s, "_ipp._tcp.local", "Office Printer._ipp._tcp.local",
              "printer.local", 631, 20);
    ASSERT_EQ(s->mdns_count, 1);
    alerts_update(s);
    ASSERT_EQ(find_alert(s, ALERT_TYPE_CAM_MDNS_SERVICE), -1);
}

static void test_cam_mdns_one_alert_rising_count(void) {
    sloth_state_t *s = fresh();
    mdns_feed(s, "_axis-video._tcp.local", "cam1._axis-video._tcp.local",
              "cam1.local", 80, 40);
    alerts_update(s);
    alerts_update(s);
    ASSERT_EQ(count_alerts(s, ALERT_TYPE_CAM_MDNS_SERVICE), 1);
    int i = find_alert(s, ALERT_TYPE_CAM_MDNS_SERVICE);
    if (i >= 0) ASSERT_EQ(s->alerts[i].count, 2);
}

/* ── Hand-built SSDP NOTIFY (UDA 1.0 §1.1.2 / §1.1.3) ──────── */

static int ssdp_feed(const char *src, const char *msg) {
    return ssdp_snoop(src, (const uint8_t *)msg, (int)strlen(msg), NULL, 0);
}

static const char *k_dsc_alive =
    "NOTIFY * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "CACHE-CONTROL: max-age=1800\r\n"
    "LOCATION: http://192.168.1.64:49152/desc.xml\r\n"
    "NT: urn:schemas-upnp-org:device:DigitalSecurityCamera:1\r\n"
    "NTS: ssdp:alive\r\n"
    "SERVER: Linux/4.9 UPnP/1.0 IPCam/1.0\r\n"
    "USN: uuid:cam-0001::urn:schemas-upnp-org:device:DigitalSecurityCamera:1\r\n"
    "\r\n";

static const char *k_basic_dahua =
    "NOTIFY * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "CACHE-CONTROL: max-age=1800\r\n"
    "LOCATION: http://192.168.1.108:49152/desc.xml\r\n"
    "NT: urn:schemas-upnp-org:device:Basic:1\r\n"
    "NTS: ssdp:alive\r\n"
    "SERVER: Linux/3.x UPnP/1.0 Dahua/1.0\r\n"
    "USN: uuid:dahua-0108::urn:schemas-upnp-org:device:Basic:1\r\n"
    "\r\n";

static const char *k_basic_generic =
    "NOTIFY * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "NT: urn:schemas-upnp-org:device:Basic:1\r\n"
    "NTS: ssdp:alive\r\n"
    "SERVER: Linux/3.10, UPnP/1.0, Portable SDK for UPnP devices/1.6.6\r\n"
    "USN: uuid:nas-0001::urn:schemas-upnp-org:device:Basic:1\r\n"
    "\r\n";

static void test_ssdp_server_is_parsed(void) {
    sloth_state_t *s = fresh();
    ASSERT_EQ(ssdp_feed("192.168.1.108", k_basic_dahua), 1);
    ssdp_snapshot(s);
    ASSERT_EQ(s->ssdp_count, 1);
    ASSERT(strcmp(s->ssdp_devices[0].server,
                  "Linux/3.x UPnP/1.0 Dahua/1.0") == 0);
}

static void test_ssdp_byebye_keeps_server(void) {
    /* §1.1.3: ssdp:byebye carries no SERVER. It must not erase the one
     * the alive gave, or a camera leaving would stop being a camera.
     * Seen red by making the copy in ssdp_snoop() unconditional. */
    sloth_state_t *s = fresh();
    ASSERT_EQ(ssdp_feed("192.168.1.108", k_basic_dahua), 1);
    ASSERT_EQ(ssdp_feed("192.168.1.108",
        "NOTIFY * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "NT: urn:schemas-upnp-org:device:Basic:1\r\n"
        "NTS: ssdp:byebye\r\n"
        "USN: uuid:dahua-0108::urn:schemas-upnp-org:device:Basic:1\r\n"
        "\r\n"), 1);
    ssdp_snapshot(s);
    ASSERT_EQ(s->ssdp_count, 1);
    ASSERT(strcmp(s->ssdp_devices[0].nts, "byebye") == 0);
    ASSERT(strcmp(s->ssdp_devices[0].server,
                  "Linux/3.x UPnP/1.0 Dahua/1.0") == 0);
}

static void test_cam_ssdp_dsc_fires(void) {
    sloth_state_t *s = fresh();
    ssdp_feed("192.168.1.64", k_dsc_alive);
    ssdp_snapshot(s);
    alerts_update(s);
    int i = find_alert(s, ALERT_TYPE_CAM_SSDP_DEVICE);
    ASSERT(i >= 0);
    if (i < 0) return;
    ASSERT_EQ((int)s->alerts[i].sev, (int)ALERT_SEV_WARN);
    ASSERT_EQ((int)s->alerts[i].technique[0], 0);
    ASSERT(strncmp(s->alerts[i].key, "camssdp:usn:uuid_cam-0001", 25) == 0);
    ASSERT(strstr(s->alerts[i].detail, "DigitalSecurityCamera:1") != NULL);
    ASSERT(strstr(s->alerts[i].detail, "192.168.1.64") != NULL);
    ASSERT(strcmp(s->alerts[i].match_ip, "192.168.1.64") == 0);
}

static void test_cam_ssdp_basic_with_vendor_server_case_e(void) {
    /* #106 Case E. */
    sloth_state_t *s = fresh();
    ssdp_feed("192.168.1.108", k_basic_dahua);
    ssdp_snapshot(s);
    alerts_update(s);
    int i = find_alert(s, ALERT_TYPE_CAM_SSDP_DEVICE);
    ASSERT(i >= 0);
    if (i < 0) return;
    ASSERT(strstr(s->alerts[i].detail, "camera vendor Dahua") != NULL);
    ASSERT(strstr(s->alerts[i].detail, "own claim") != NULL);
}

static void test_cam_ssdp_basic_without_vendor_is_quiet(void) {
    /* Basic:1 alone says nothing about a device class (UPnP Basic:1.0
     * §1). Seen red by removing the cam_vendor_server() gate. */
    sloth_state_t *s = fresh();
    ssdp_feed("192.168.1.20", k_basic_generic);
    ssdp_snapshot(s);
    ASSERT_EQ(s->ssdp_count, 1);
    alerts_update(s);
    ASSERT_EQ(find_alert(s, ALERT_TYPE_CAM_SSDP_DEVICE), -1);
}

static void test_cam_ssdp_media_renderer_is_quiet(void) {
    /* #106 Case I: the smart TV's MediaRenderer, even from a server
     * string naming a camera brand, is not a camera type. Seen red by
     * accepting any NT when the SERVER token matched. */
    sloth_state_t *s = fresh();
    ssdp_feed("192.168.1.30",
        "NOTIFY * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "NT: urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
        "NTS: ssdp:alive\r\n"
        "SERVER: Linux/4.4 UPnP/1.0 Hikvision/1.0\r\n"
        "USN: uuid:tv-0001::urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
        "\r\n");
    ssdp_snapshot(s);
    ASSERT_EQ(s->ssdp_count, 1);
    alerts_update(s);
    ASSERT_EQ(find_alert(s, ALERT_TYPE_CAM_SSDP_DEVICE), -1);
}

static void test_cam_ssdp_msearch_for_cameras_is_quiet(void) {
    /* A control point searching for cameras is not a camera: the ST of
     * an M-SEARCH is the asker's want. Seen red by deleting the
     * "search" skip. */
    sloth_state_t *s = fresh();
    ssdp_feed("192.168.1.5",
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: urn:schemas-upnp-org:device:DigitalSecurityCamera:1\r\n"
        "\r\n");
    ssdp_snapshot(s);
    ASSERT_EQ(s->ssdp_count, 1);
    alerts_update(s);
    ASSERT_EQ(find_alert(s, ALERT_TYPE_CAM_SSDP_DEVICE), -1);
}

static void test_cam_ssdp_one_device_one_alert(void) {
    /* One camera announcing DigitalSecurityCamera:1 and Basic:1 under
     * the same device UUID (UDA §1.1.4) is one finding, counted. */
    sloth_state_t *s = fresh();
    ssdp_feed("192.168.1.64", k_dsc_alive);
    ssdp_feed("192.168.1.64",
        "NOTIFY * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "NT: urn:schemas-upnp-org:device:Basic:1\r\n"
        "NTS: ssdp:alive\r\n"
        "SERVER: Linux/4.9 UPnP/1.0 Axis/10.12\r\n"
        "USN: uuid:cam-0001::urn:schemas-upnp-org:device:Basic:1\r\n"
        "\r\n");
    ssdp_snapshot(s);
    ASSERT_EQ(s->ssdp_count, 2);
    alerts_update(s);
    ASSERT_EQ(count_alerts(s, ALERT_TYPE_CAM_SSDP_DEVICE), 1);
    alerts_update(s);
    ASSERT_EQ(count_alerts(s, ALERT_TYPE_CAM_SSDP_DEVICE), 1);
    int i = find_alert(s, ALERT_TYPE_CAM_SSDP_DEVICE);
    if (i >= 0) ASSERT_EQ(s->alerts[i].count, 4);
}

/* ── CAM_SETUP_OUI over beacon rows ───────────────────────── */

static void add_ap(sloth_state_t *s, const char *ssid, const uint8_t b[6],
                   const char *enc) {
    beacon_ap_t *a = &s->beacon_aps[s->beacon_count++];
    memset(a, 0, sizeof(*a));
    snprintf(a->ssid, sizeof(a->ssid), "%s", ssid);
    memcpy(a->bssid, b, 6);
    snprintf(a->enc, sizeof(a->enc), "%s", enc);
    a->channel   = 6;
    a->last_seen = cv_wall();
}

static void test_cam_setup_oui_fires_registered(void) {
    sloth_state_t *s = fresh();
    const uint8_t b[6] = {0x44,0x19,0xB6,0x0a,0x0b,0x0c};
    add_ap(s, "Cam-Setup", b, "WPA2");
    alerts_update(s);
    int i = find_alert(s, ALERT_TYPE_CAM_SETUP_OUI);
    ASSERT(i >= 0);
    if (i < 0) return;
    ASSERT_EQ((int)s->alerts[i].sev, (int)ALERT_SEV_WARN);
    ASSERT_EQ((int)s->alerts[i].technique[0], 0);
    ASSERT(strcmp(s->alerts[i].key, "camoui:44:19:b6:0a:0b:0c") == 0);
    ASSERT(strstr(s->alerts[i].detail,
                  "Hangzhou Hikvision Digital Technology Co.,Ltd.") != NULL);
    ASSERT(strstr(s->alerts[i].detail, "device class not observed") != NULL);
    ASSERT(strstr(s->alerts[i].detail, "randomized-local") == NULL);
}

static void test_cam_setup_oui_randomized_local_case_b(void) {
    /* #106 Case B, on a camera-vendor block. Seen red by dropping the
     * U/L mask in cam_vendor_oui() (no alert at all), and the flag
     * text by forcing local to 0. */
    sloth_state_t *s = fresh();
    const uint8_t b[6] = {0x46,0x19,0xB6,0x0a,0x0b,0x0c};
    add_ap(s, "", b, "OPEN");
    alerts_update(s);
    int i = find_alert(s, ALERT_TYPE_CAM_SETUP_OUI);
    ASSERT(i >= 0);
    if (i < 0) return;
    ASSERT(strstr(s->alerts[i].detail, "randomized-local") != NULL);
    /* The registered prefix, not the observed octet, is what's named. */
    ASSERT(strstr(s->alerts[i].detail, "OUI 44:19:B6") != NULL);
    ASSERT(strstr(s->alerts[i].detail, "<hidden>") != NULL);
}

static void test_cam_setup_oui_quiet_on_non_camera_vendor(void) {
    /* Ubiquiti's block, both as registered and with U/L set. Seen red
     * by adding a B4:FB:E4 row to the table. */
    sloth_state_t *s = fresh();
    const uint8_t a[6] = {0xB4,0xFB,0xE4,0x01,0x02,0x03};
    const uint8_t b[6] = {0xB6,0xFB,0xE4,0x01,0x02,0x03};
    add_ap(s, "UniFi", a, "WPA2");
    add_ap(s, "UniFi-setup", b, "OPEN");
    alerts_update(s);
    ASSERT_EQ(find_alert(s, ALERT_TYPE_CAM_SETUP_OUI), -1);
}

static void test_cam_setup_oui_once_per_bssid(void) {
    sloth_state_t *s = fresh();
    const uint8_t b[6] = {0x00,0x40,0x8C,0x11,0x22,0x33};   /* Axis */
    add_ap(s, "AXIS-setup", b, "OPEN");
    alerts_update(s);
    alerts_update(s);
    ASSERT_EQ(count_alerts(s, ALERT_TYPE_CAM_SETUP_OUI), 1);
    int i = find_alert(s, ALERT_TYPE_CAM_SETUP_OUI);
    if (i >= 0) ASSERT_EQ(s->alerts[i].count, 2);
}

void run_camera_vendor_tests(void) {
    TEST_SUITE("camera identity: mDNS / SSDP / OUI (#106 slice A)");
    RUN_TEST(test_oui_table_rows_are_registry_shaped);
    RUN_TEST(test_oui_table_matches_the_ieee_registry);
    RUN_TEST(test_oui_exact_match_is_not_local);
    RUN_TEST(test_oui_ul_bit_is_masked_and_reported);
    RUN_TEST(test_oui_group_bit_and_other_bits_are_not_masked);
    RUN_TEST(test_oui_ubiquiti_is_deliberately_absent);
    RUN_TEST(test_server_token_matches_vendor_product);
    RUN_TEST(test_server_token_rejects_substrings_and_generic);
    RUN_TEST(test_mdns_service_table);
    RUN_TEST(test_cam_mdns_rtsp_case_d);
    RUN_TEST(test_cam_mdns_axis_video_is_camera_specific);
    RUN_TEST(test_cam_mdns_quiet_on_printer);
    RUN_TEST(test_cam_mdns_one_alert_rising_count);
    RUN_TEST(test_ssdp_server_is_parsed);
    RUN_TEST(test_ssdp_byebye_keeps_server);
    RUN_TEST(test_cam_ssdp_dsc_fires);
    RUN_TEST(test_cam_ssdp_basic_with_vendor_server_case_e);
    RUN_TEST(test_cam_ssdp_basic_without_vendor_is_quiet);
    RUN_TEST(test_cam_ssdp_media_renderer_is_quiet);
    RUN_TEST(test_cam_ssdp_msearch_for_cameras_is_quiet);
    RUN_TEST(test_cam_ssdp_one_device_one_alert);
    RUN_TEST(test_cam_setup_oui_fires_registered);
    RUN_TEST(test_cam_setup_oui_randomized_local_case_b);
    RUN_TEST(test_cam_setup_oui_quiet_on_non_camera_vendor);
    RUN_TEST(test_cam_setup_oui_once_per_bssid);
}
