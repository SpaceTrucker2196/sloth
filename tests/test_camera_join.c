/* Camera identity on the device record and its Devices-view surface
 * (#106 round 2): src/camera_join.c, the CAMERA row and the Enter
 * detail in src/views/devices.c.
 *
 * Inputs are the snapshot tables the camera rules read, seeded field by
 * field; the parsers that fill them have their own byte-level tests
 * (test_onvif_discovery.c, test_rtsp_snoop.c, test_ssdp_*.c). The wall
 * clock is pinned for every test that renders an age or runs
 * devices_update(). */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "runner.h"
#include "sloth.h"
#include "tui.h"
#include "devices.h"
#include "camera_join.h"
#include "sloth_clock.h"
#include "tune.h"
#include "onvif_discovery.h"
#include "views/devices.h"

#define T0 ((time_t)1760000000)

static time_t g_wall;
static time_t k_wall(void) { return g_wall; }
static void pin(void) { g_wall = T0; sloth_clock_test_set(NULL, k_wall); }

TEST_STATE(g_s);

static sloth_state_t *fresh(void) {
    memset(&g_s, 0, sizeof(g_s));
    pin();
    return &g_s;
}

static void add_arp_on(sloth_state_t *s, const char *ip,
                       const uint8_t mac[6], const char *iface) {
    arp_entry_t *e = &s->arp_entries[s->arp_count++];
    snprintf(e->ip, sizeof(e->ip), "%s", ip);
    memcpy(e->mac, mac, 6);
    snprintf(e->iface, sizeof(e->iface), "%s", iface);
}

static void add_arp(sloth_state_t *s, const char *ip, const uint8_t mac[6]) {
    add_arp_on(s, ip, mac, "eth0");
}

static onvif_device_t *add_onvif(sloth_state_t *s, const char *ip,
                                 int is_camera, const char *scopes,
                                 time_t seen) {
    onvif_device_t *o = &s->onvif_devices[s->onvif_count++];
    snprintf(o->ip, sizeof(o->ip), "%s", ip);
    snprintf(o->uuid, sizeof(o->uuid), "urn:uuid:cam-%d", s->onvif_count);
    snprintf(o->types, sizeof(o->types), "%s",
             is_camera ? "dn:NetworkVideoTransmitter" : "tds:Device");
    snprintf(o->scopes, sizeof(o->scopes), "%s", scopes);
    snprintf(o->xaddrs, sizeof(o->xaddrs), "http://%s/onvif/device_service", ip);
    snprintf(o->kind, sizeof(o->kind), "Hello");
    o->is_camera = is_camera;
    o->last_seen = seen;
    return o;
}

static void add_mdns(sloth_state_t *s, const char *ip, const char *inst,
                     const char *svc, time_t seen) {
    mdns_service_t *e = &s->mdns_services[s->mdns_count++];
    snprintf(e->instance, sizeof(e->instance), "%s", inst);
    snprintf(e->service, sizeof(e->service), "%s", svc);
    snprintf(e->host, sizeof(e->host), "cam.local");
    snprintf(e->ip, sizeof(e->ip), "%s", ip);
    e->port = 554;
    e->last_seen = seen;
}

static void add_ssdp(sloth_state_t *s, const char *ip, const char *type,
                     const char *nts, const char *server, time_t seen) {
    ssdp_device_t *d = &s->ssdp_devices[s->ssdp_count++];
    snprintf(d->ip, sizeof(d->ip), "%s", ip);
    snprintf(d->type, sizeof(d->type), "%s", type);
    snprintf(d->usn, sizeof(d->usn), "uuid:dev-%d::%s", s->ssdp_count, type);
    snprintf(d->nts, sizeof(d->nts), "%s", nts);
    snprintf(d->server, sizeof(d->server), "%s", server);
    d->last_seen = seen;
}

static void add_rtsp(sloth_state_t *s, const char *ip, uint16_t port,
                     const char *path, uint32_t anon, uint32_t chal,
                     time_t seen) {
    rtsp_stream_t *r = &s->rtsp_streams[s->rtsp_stream_count++];
    snprintf(r->server, sizeof(r->server), "%s", ip);
    r->port = port;
    snprintf(r->path, sizeof(r->path), "%s", path);
    r->anon_ok = anon;
    r->challenged = chal;
    if (chal) snprintf(r->auth_scheme, sizeof(r->auth_scheme), "Digest");
    r->first_seen = seen - 10;
    r->last_seen = seen;
}

static void add_beacon(sloth_state_t *s, const uint8_t bssid[6],
                       const char *ssid, const char *enc, time_t seen) {
    beacon_ap_t *b = &s->beacon_aps[s->beacon_count++];
    memcpy(b->bssid, bssid, 6);
    snprintf(b->ssid, sizeof(b->ssid), "%s", ssid);
    snprintf(b->enc, sizeof(b->enc), "%s", enc);
    b->channel = 6;
    b->signal_dbm = -55;
    b->last_seen = seen;
}

static const device_t *by_mac(const sloth_state_t *s, const uint8_t m[6]) {
    for (int i = 0; i < s->device_count; i++)
        if (memcmp(s->devices[i].mac, m, 6) == 0) return &s->devices[i];
    return NULL;
}

static const device_t *by_ip(const sloth_state_t *s, const char *ip) {
    for (int i = 0; i < s->device_count; i++)
        if (strcmp(s->devices[i].ip, ip) == 0) return &s->devices[i];
    return NULL;
}

static int count_ip(const sloth_state_t *s, const char *ip) {
    int n = 0;
    for (int i = 0; i < s->device_count; i++)
        if (strcmp(s->devices[i].ip, ip) == 0) n++;
    return n;
}

static const uint8_t LAN_MAC[6] = { 0x3c, 0x22, 0xfb, 0x10, 0x20, 0x30 };
static const uint8_t HAP_BSSID[6] = { 0x9e, 0x11, 0x22, 0x33, 0x44, 0x55 };
static const uint8_t AXIS_BSSID[6] = { 0x00, 0x40, 0x8c, 0x01, 0x02, 0x03 };

#define SCOPES_HIK \
    "onvif://www.onvif.org/type/video_encoder " \
    "onvif://www.onvif.org/name/HIKVISION " \
    "onvif://www.onvif.org/hardware/DS-2CD2042WD-I " \
    "onvif://www.onvif.org/location/city/hangzhou"

/* ── ONVIF scope parser ──────────────────────────────────── */

static void test_scope_name_and_hardware(void) {
    char v[64];
    ASSERT_EQ(cam_onvif_scope(SCOPES_HIK, "name", v, sizeof(v)), 1);
    ASSERT_STR(v, "HIKVISION");
    ASSERT_EQ(cam_onvif_scope(SCOPES_HIK, "hardware", v, sizeof(v)), 1);
    ASSERT_STR(v, "DS-2CD2042WD-I");
    ASSERT_EQ(cam_onvif_scope(SCOPES_HIK, "model", v, sizeof(v)), 0);
    ASSERT_STR(v, "");
}

/* Percent-decoded (RFC 3986 §2.1), scheme/host case-folded, and every
 * decoded byte outside printable ASCII dropped — %0A would otherwise
 * put a newline into a device record. */
static void test_scope_decoding_and_filtering(void) {
    char v[64];
    ASSERT_EQ(cam_onvif_scope("ONVIF://WWW.ONVIF.ORG/name/AXIS%20P1435-LE%0A%1b",
                              "name", v, sizeof(v)), 1);
    ASSERT_STR(v, "AXIS P1435-LE");
    /* The kind is a whole path segment: "namex" is not "name". */
    ASSERT_EQ(cam_onvif_scope("onvif://www.onvif.org/namex/foo",
                              "name", v, sizeof(v)), 0);
    /* Another host is not the ONVIF scope namespace. */
    ASSERT_EQ(cam_onvif_scope("onvif://evil.example/name/foo",
                              "name", v, sizeof(v)), 0);
    /* Cut to the buffer, never past it. */
    char small[5];
    ASSERT_EQ(cam_onvif_scope("onvif://www.onvif.org/name/ABCDEFGH",
                              "name", small, sizeof(small)), 1);
    ASSERT_STR(small, "ABCD");
}

/* ── LAN-side join: same IP ──────────────────────────────── */

/* An ONVIF camera whose IP ARP already holds joins that record: one
 * device, the MAC kept, class camera, model from the scopes. Seen to
 * fail with camera_join() moved ahead of merge_arp() in devices_update
 * (an IP-only twin appears: two records for 10.0.0.64). */
static void test_wsd_joins_arp_record_by_ip(void) {
    sloth_state_t *s = fresh();
    add_arp(s, "10.0.0.64", LAN_MAC);
    add_onvif(s, "10.0.0.64", 1, SCOPES_HIK, T0 - 5);
    devices_update(s);
    ASSERT_EQ(s->device_count, 1);
    ASSERT_EQ(count_ip(s, "10.0.0.64"), 1);
    const device_t *d = by_mac(s, LAN_MAC);
    ASSERT(d != NULL);
    if (!d) return;
    ASSERT_EQ((int)d->device_class, (int)DEV_CLASS_CAMERA);
    ASSERT_EQ(d->cam_signal_mask, CAM_SIG_WS_DISCOVERY);
    ASSERT_STR(d->camera_model, "HIKVISION DS-2CD2042WD-I");
    ASSERT((d->sources & DEV_SRC_ARP) && (d->sources & DEV_SRC_CAMERA));
    ASSERT_EQ((long long)d->cam_seen[0], (long long)(T0 - 5));
    ASSERT_EQ(d->setup_mode, 0);
}

/* No record holds the IP — the mirror-port case — so the camera gets
 * one of its own, keyed by IP alone. */
static void test_wsd_without_arp_creates_ip_only_record(void) {
    sloth_state_t *s = fresh();
    add_onvif(s, "10.0.0.65", 1, SCOPES_HIK, T0 - 2);
    devices_update(s);
    ASSERT_EQ(s->device_count, 1);
    const device_t *d = by_ip(s, "10.0.0.65");
    ASSERT(d != NULL);
    if (!d) return;
    static const uint8_t z[6] = {0};
    ASSERT_EQ(memcmp(d->mac, z, 6), 0);
    ASSERT_EQ(d->sources, DEV_SRC_CAMERA);
    ASSERT_EQ((int)d->device_class, (int)DEV_CLASS_CAMERA);
    ASSERT_EQ((long long)d->last_seen, (long long)(T0 - 2));
}

/* A WS-Discovery device that is not a NetworkVideoTransmitter is not a
 * camera signal. Seen to fail with the is_camera test removed from the
 * ONVIF loop in camera_join() (a record appears). */
static void test_wsd_non_camera_is_ignored(void) {
    sloth_state_t *s = fresh();
    add_onvif(s, "10.0.0.66", 0, "", T0);
    devices_update(s);
    ASSERT_EQ(s->device_count, 0);
}

/* The camera service types create and classify; _rtsp only attaches,
 * and never names a class. Both halves seen to fail: _rtsp passed
 * create=1 (a record appears for 10.0.0.71), and its class passed as
 * DEV_CLASS_CAMERA (10.0.0.72 reads camera). */
static void test_mdns_camera_service_vs_rtsp(void) {
    sloth_state_t *s = fresh();
    uint8_t m[6] = { 0x02, 0, 0, 0, 0, 0x72 };
    add_mdns(s, "10.0.0.70", "AXIS M3045._axis-video._tcp.local",
             "_axis-video._tcp", T0 - 1);
    add_mdns(s, "10.0.0.71", "nas._rtsp._tcp.local", "_rtsp._tcp", T0);
    add_arp(s, "10.0.0.72", m);
    add_mdns(s, "10.0.0.72", "media._rtsp._tcp.local", "_rtsp._tcp", T0);
    devices_update(s);
    const device_t *a = by_ip(s, "10.0.0.70");
    ASSERT(a != NULL);
    if (a) {
        ASSERT_EQ((int)a->device_class, (int)DEV_CLASS_CAMERA);
        ASSERT_EQ(a->cam_signal_mask, CAM_SIG_MDNS_SERVICE);
    }
    ASSERT(by_ip(s, "10.0.0.71") == NULL);
    const device_t *c = by_ip(s, "10.0.0.72");
    ASSERT(c != NULL);
    if (c) {
        ASSERT_EQ((int)c->device_class, (int)DEV_CLASS_UNKNOWN);
        ASSERT_EQ(c->cam_signal_mask, CAM_SIG_MDNS_SERVICE);
    }
    ASSERT_EQ(s->device_count, 2);
}

/* _rtsp on a camera's IP attaches to the IP-only record a camera
 * service type created, whatever the table order: the _rtsp row sits
 * first and is the newer, so its time reaching cam_seen[] is what shows
 * it attached. Seen to fail with the two mDNS passes swapped (_rtsp
 * runs before any record exists and its time is lost). */
static void test_mdns_rtsp_attaches_after_creating_signals(void) {
    sloth_state_t *s = fresh();
    add_mdns(s, "10.0.0.73", "cam._rtsp._tcp.local", "_rtsp._tcp", T0);
    add_mdns(s, "10.0.0.73", "Cam._axis-video._tcp.local",
             "_axis-video._tcp", T0 - 30);
    devices_update(s);
    const device_t *d = by_ip(s, "10.0.0.73");
    ASSERT(d != NULL);
    if (!d) return;
    ASSERT_EQ(d->cam_signal_mask, CAM_SIG_MDNS_SERVICE);
    ASSERT_EQ((long long)d->cam_seen[2], (long long)T0);
}

/* SSDP: DSC:1 is a camera; Basic:1 is one only with a camera vendor in
 * SERVER, and then only camera-vendor; an M-SEARCH and a bare Basic:1
 * are nothing. */
static void test_ssdp_shapes(void) {
    sloth_state_t *s = fresh();
    add_ssdp(s, "10.0.0.80",
             "urn:schemas-upnp-org:device:DigitalSecurityCamera:1",
             "alive", "", T0);
    add_ssdp(s, "10.0.0.81", "urn:schemas-upnp-org:device:Basic:1",
             "alive", "Linux/3.0 UPnP/1.0 Hikvision-Webs/1.0", T0);
    add_ssdp(s, "10.0.0.82", "urn:schemas-upnp-org:device:Basic:1",
             "alive", "Linux/3.0 UPnP/1.0 miniupnpd/2.0", T0);
    add_ssdp(s, "10.0.0.83",
             "urn:schemas-upnp-org:device:DigitalSecurityCamera:1",
             "search", "", T0);
    devices_update(s);
    const device_t *a = by_ip(s, "10.0.0.80");
    const device_t *b = by_ip(s, "10.0.0.81");
    ASSERT(a && b);
    if (a) ASSERT_EQ((int)a->device_class, (int)DEV_CLASS_CAMERA);
    if (b) {
        ASSERT_EQ((int)b->device_class, (int)DEV_CLASS_CAMERA_VENDOR);
        ASSERT_STR(b->camera_vendor, "Hikvision");
    }
    ASSERT(by_ip(s, "10.0.0.82") == NULL);
    ASSERT(by_ip(s, "10.0.0.83") == NULL);
    ASSERT_EQ(s->device_count, 2);
}

/* RTSP: an anonymous answer marks a known host and sets no class; it
 * never creates a record, and an authenticated-only server is no
 * signal. Seen to fail with the RTSP lan() call passed create=1 (a
 * record appears for 10.0.0.91), and with the anon_ok test removed
 * (10.0.0.92 gains the bit). */
static void test_rtsp_attaches_only(void) {
    sloth_state_t *s = fresh();
    uint8_t m1[6] = { 0x02, 0, 0, 0, 0, 0x90 };
    uint8_t m2[6] = { 0x02, 0, 0, 0, 0, 0x92 };
    add_arp(s, "10.0.0.90", m1);
    add_arp(s, "10.0.0.92", m2);
    add_rtsp(s, "10.0.0.90", 554, "/Streaming/Channels/101", 3, 0, T0);
    add_rtsp(s, "10.0.0.91", 554, "/live", 1, 0, T0);
    add_rtsp(s, "10.0.0.92", 8554, "/stream", 0, 2, T0);
    devices_update(s);
    const device_t *a = by_ip(s, "10.0.0.90");
    const device_t *c = by_ip(s, "10.0.0.92");
    ASSERT(a && c);
    if (a) {
        ASSERT_EQ(a->cam_signal_mask, CAM_SIG_RTSP_UNAUTH);
        ASSERT_EQ((int)a->device_class, (int)DEV_CLASS_UNKNOWN);
    }
    if (c) ASSERT_EQ(c->cam_signal_mask, 0);
    ASSERT(by_ip(s, "10.0.0.91") == NULL);
    ASSERT_EQ(s->device_count, 2);
}

/* ── Join keys: recency, ambiguity, address family ───────── */

static const uint8_t LAPTOP_MAC[6] = { 0xa4, 0x83, 0xe7, 0x01, 0x02, 0x03 };

/* The DHCP-reuse case: a camera's ONVIF row from three days ago, and a
 * laptop holding that lease now. The tables never age a row out, so
 * only the recency rule stands between the row and the laptop. Seen to
 * fail with cam_lan_state()'s is_fresh() test removed (the laptop reads
 * class 2, mask 1, model "HIKVISION DS-2CD2042WD-I"). */
static void test_stale_lan_row_does_not_join(void) {
    sloth_state_t *s = fresh();
    add_arp(s, "10.0.0.64", LAPTOP_MAC);
    add_onvif(s, "10.0.0.64", 1, SCOPES_HIK, T0 - 3 * 86400);
    add_mdns(s, "10.0.0.64", "Cam._axis-video._tcp.local",
             "_axis-video._tcp", T0 - 2 * 86400);
    add_ssdp(s, "10.0.0.64",
             "urn:schemas-upnp-org:device:DigitalSecurityCamera:1",
             "alive", "", T0 - 86400);
    add_rtsp(s, "10.0.0.64", 554, "/live", 1, 0, T0 - 86400);
    devices_update(s);
    ASSERT_EQ(s->device_count, 1);
    const device_t *d = by_mac(s, LAPTOP_MAC);
    ASSERT(d != NULL);
    if (!d) return;
    ASSERT_EQ((int)d->device_class, (int)DEV_CLASS_UNKNOWN);
    ASSERT_EQ(d->cam_signal_mask, 0);
    ASSERT_STR(d->camera_model, "");
    ASSERT_EQ(d->sources & DEV_SRC_CAMERA, 0);

    /* Still readable, as history: every row is listed, none counted. */
    cam_trail_row_t t[8];
    int n = camera_trail(s, d, T0, t, 8);
    ASSERT_EQ(n, 4);
    for (int i = 0; i < n; i++) {
        ASSERT_EQ((int)t[i].state, (int)CAM_JOIN_STALE);
        ASSERT(strncmp(t[i].what, "history, not joined", 19) == 0);
    }

    /* The detail lists the rows as history on the trail and shows none
     * of their scopes, SERVER or streams as this host's. Seen to fail
     * with the view's joined() returning 1 (ONVIF SCOPES appears). */
    s->active_view = VIEW_DEVICES;
    s->device_sel = 0;
    view_devices_key(s, '\r');
    ASSERT_EQ(tui_init_offscreen(40, 160), 0);
    tui_test_erase();
    view_devices_draw(s);
    ASSERT_SCREEN_HAS("SIGNAL TRAIL");
    ASSERT_SCREEN_HAS("history, not joined");
    ASSERT_SCREEN_LACKS("ONVIF SCOPES");
    ASSERT_SCREEN_LACKS("RTSP EXPOSURE");
    ASSERT_SCREEN_LACKS("\xe2\x94\x80 mDNS \xe2\x94\x80");
    ASSERT_SCREEN_LACKS("_axis-video._tcp   host");
    s->device_detail = 0;

    /* A stale camera with no record holding its IP makes none. */
    s = fresh();
    add_onvif(s, "10.0.0.65", 1, SCOPES_HIK, T0 - 3 * 86400);
    devices_update(s);
    ASSERT_EQ(s->device_count, 0);
}

/* The window edge, and the knob that moves it. Seen to fail with
 * is_fresh()'s `<=` written `<` (the row exactly at the edge is
 * refused). */
static void test_join_window_edge_and_knob(void) {
    sloth_state_t *s = fresh();
    tune_reset();
    add_onvif(s, "10.0.0.66", 1, "", T0 - CAM_JOIN_FRESH_SECS);
    add_onvif(s, "10.0.0.67", 1, "", T0 - CAM_JOIN_FRESH_SECS - 1);
    devices_update(s);
    ASSERT(by_ip(s, "10.0.0.66") != NULL);
    ASSERT(by_ip(s, "10.0.0.67") == NULL);
    char err[128];
    ASSERT_EQ(tune_set("camera.join_fresh_secs=7200", err, sizeof(err)), 0);
    devices_update(s);
    ASSERT(by_ip(s, "10.0.0.67") != NULL);
    ASSERT_EQ(tune_set("camera.join_fresh_secs=60", err, sizeof(err)), -1);
    tune_reset();
}

/* Two LANs on the same subnet: one address, two records. The row's
 * interface is not observed, so neither record is marked and no
 * IP-only record is made. Seen to fail with cam_lan_state()'s `k > 1`
 * check removed (both records read camera). */
static void test_ip_on_two_records_joins_neither(void) {
    sloth_state_t *s = fresh();
    static const uint8_t other[6] = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 };
    add_arp_on(s, "192.168.1.10", LAN_MAC, "eth0");
    add_arp_on(s, "192.168.1.10", other, "wlan0");
    add_onvif(s, "192.168.1.10", 1, SCOPES_HIK, T0);
    devices_update(s);
    ASSERT_EQ(s->device_count, 2);
    int cams = 0;
    for (int i = 0; i < s->device_count; i++)
        if (s->devices[i].device_class != DEV_CLASS_UNKNOWN ||
            s->devices[i].cam_signal_mask)
            cams++;
    ASSERT_EQ(cams, 0);
    const device_t *d = by_mac(s, LAN_MAC);
    ASSERT(d != NULL);
    if (!d) return;
    cam_trail_row_t t[4];
    ASSERT_EQ(camera_trail(s, d, T0, t, 4), 1);
    ASSERT_EQ((int)t[0].state, (int)CAM_JOIN_AMBIGUOUS);
    ASSERT(strstr(t[0].what, "more than one device record") != NULL);
}

/* WS-Discovery 1.1 §4.1 Hello, as a dual-stack camera sends it on both
 * 239.255.255.250 and ff02::c. Hand-built, one EndpointReference. */
static const char k_hello_ds[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\""
    " xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\""
    " xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">"
    "<e:Header>"
    "<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello</w:Action>"
    "</e:Header>"
    "<e:Body><d:Hello>"
    "<w:EndpointReference><w:Address>urn:uuid:0a0b0c0d-0000-1111-2222-3c22fb102030</w:Address></w:EndpointReference>"
    "<d:Types>dn:NetworkVideoTransmitter</d:Types>"
    "<d:Scopes>onvif://www.onvif.org/name/HIKVISION</d:Scopes>"
    "<d:XAddrs>http://10.0.0.64/onvif/device_service</d:XAddrs>"
    "</d:Hello></e:Body></e:Envelope>";

static void hello_from(const char *src) {
    ASSERT_EQ(onvif_ws_discovery_snoop(src, (const uint8_t *)k_hello_ds,
                                       (int)strlen(k_hello_ds), NULL, 0), 1);
}

/* The last Hello came over IPv6: the row's ip[] is the link-local
 * address, but it keeps its IPv4 source too, so the ARP record stays
 * the camera and no IPv6 twin appears; the next IPv4 Hello changes
 * nothing. Seen to fail with lan_dual() passing `create` unchanged to
 * the IPv6 address (device_count 2: an IP-only fe80:: twin), and with
 * the join reading ip[] alone (the ARP record reads class 0). */
static void test_dual_stack_onvif_is_one_record(void) {
    sloth_state_t *s = fresh();
    onvif_clear();
    hello_from("10.0.0.64");
    g_wall = T0 + 5;
    hello_from("fe80::3e22:fbff:fe10:2030");
    onvif_snapshot(s);
    ASSERT_EQ(s->onvif_count, 1);
    ASSERT_STR(s->onvif_devices[0].ip, "fe80::3e22:fbff:fe10:2030");
    ASSERT_STR(s->onvif_devices[0].ip4, "10.0.0.64");
    ASSERT_EQ((long long)s->onvif_devices[0].ip4_seen, (long long)T0);
    ASSERT_EQ((long long)s->onvif_devices[0].ip6_seen, (long long)(T0 + 5));
    add_arp(s, "10.0.0.64", LAN_MAC);
    devices_update(s);
    ASSERT_EQ(s->device_count, 1);
    const device_t *d = by_mac(s, LAN_MAC);
    ASSERT(d != NULL);
    if (d) {
        ASSERT_EQ((int)d->device_class, (int)DEV_CLASS_CAMERA);
        ASSERT_EQ((long long)d->cam_seen[0], (long long)T0);
    }

    g_wall = T0 + 10;
    hello_from("10.0.0.64");
    onvif_snapshot(s);
    devices_update(s);
    ASSERT_EQ(s->device_count, 1);
    d = by_mac(s, LAN_MAC);
    ASSERT(d && d->device_class == DEV_CLASS_CAMERA);
    onvif_clear();
}

/* An IPv6-only camera still gets its record: the attach-only rule is
 * for the second family, not for IPv6 as such. SSDP keeps per-family
 * addresses by the same rule. */
static void test_v6_only_creates_and_ssdp_dual_stack(void) {
    sloth_state_t *s = fresh();
    add_onvif(s, "fe80::1", 1, "", T0);
    ssdp_device_t *e = &s->ssdp_devices[s->ssdp_count++];
    snprintf(e->ip, sizeof(e->ip), "fe80::64");
    snprintf(e->ip4, sizeof(e->ip4), "10.0.0.64");
    snprintf(e->ip6, sizeof(e->ip6), "fe80::64");
    e->ip4_seen = T0 - 4;
    e->ip6_seen = T0;
    e->last_seen = T0;
    snprintf(e->type, sizeof(e->type),
             "urn:schemas-upnp-org:device:DigitalSecurityCamera:1");
    snprintf(e->nts, sizeof(e->nts), "alive");
    add_arp(s, "10.0.0.64", LAN_MAC);
    devices_update(s);
    ASSERT_EQ(s->device_count, 2);
    ASSERT(by_ip(s, "fe80::1") != NULL);
    ASSERT(by_ip(s, "fe80::64") == NULL);
    const device_t *d = by_mac(s, LAN_MAC);
    ASSERT(d && d->cam_signal_mask == CAM_SIG_SSDP_DEVICE);
    if (d) ASSERT_EQ((long long)d->cam_seen[3], (long long)(T0 - 4));
}

/* ── Beacon-side join: same MAC ──────────────────────────── */

/* The setup SoftAP's BSSID record carries the setup signals; the LAN
 * camera record carries the LAN ones; neither gets the other's,
 * because nothing observed ties a BSSID to a LAN IP. Seen to fail with
 * the beacon loop's memcmp(dev[i].mac, a->bssid) check removed (every
 * record gains CAM_SETUP_SSID, the LAN camera included). */
static void test_setup_softap_never_joins_lan_ip(void) {
    sloth_state_t *s = fresh();
    add_arp(s, "10.0.0.64", LAN_MAC);
    add_onvif(s, "10.0.0.64", 1, SCOPES_HIK, T0);
    add_beacon(s, HAP_BSSID, "HAP_ABCDEFGH", "WPA2", T0 - 3);
    devices_update(s);
    ASSERT_EQ(s->device_count, 2);
    const device_t *ap  = by_mac(s, HAP_BSSID);
    const device_t *lan = by_mac(s, LAN_MAC);
    ASSERT(ap && lan);
    if (!ap || !lan) return;
    ASSERT_EQ(ap->cam_signal_mask, CAM_SIG_SETUP_SSID);
    ASSERT_EQ(ap->setup_mode, 1);
    ASSERT_STR(ap->ip, "");
    ASSERT_STR(ap->camera_vendor, "Hikvision");
    ASSERT_EQ((int)ap->device_class, (int)DEV_CLASS_CAMERA);
    ASSERT_EQ((long long)ap->cam_seen[1], (long long)(T0 - 3));
    ASSERT_EQ(lan->cam_signal_mask, CAM_SIG_WS_DISCOVERY);
    ASSERT_EQ(lan->setup_mode, 0);
}

/* The hotspot guardrail CAM_SETUP_SSID checks first applies here too:
 * a setup prefix containing "guest" marks nothing, as the rule fires
 * nothing. Seen to fail with ssid_is_public_hotspot() dropped from the
 * join's beacon test. */
static void test_setup_ssid_respects_hotspot_guardrail(void) {
    sloth_state_t *s = fresh();
    add_beacon(s, HAP_BSSID, "HAP_guest1234", "OPEN", T0);
    devices_update(s);
    const device_t *ap = by_mac(s, HAP_BSSID);
    ASSERT(ap != NULL);
    if (ap) {
        ASSERT_EQ(ap->cam_signal_mask, 0);
        ASSERT_EQ(ap->setup_mode, 0);
    }
}

/* A beaconing BSSID in a camera vendor's block: camera-vendor, never
 * camera — the rule's own detail says the class was not observed. The
 * U/L-bit form matches the same row. */
static void test_setup_oui_is_vendor_only(void) {
    sloth_state_t *s = fresh();
    uint8_t local[6] = { 0x02, 0x40, 0x8c, 0x09, 0x09, 0x09 };
    add_beacon(s, AXIS_BSSID, "corp", "WPA2", T0);
    add_beacon(s, local, "", "WPA2", T0);
    devices_update(s);
    const device_t *a = by_mac(s, AXIS_BSSID);
    const device_t *b = by_mac(s, local);
    ASSERT(a && b);
    if (a) {
        ASSERT_EQ(a->cam_signal_mask, CAM_SIG_SETUP_OUI);
        ASSERT_EQ((int)a->device_class, (int)DEV_CLASS_CAMERA_VENDOR);
        ASSERT_STR(a->camera_vendor, "Axis");
    }
    if (b) ASSERT_EQ(b->cam_signal_mask, CAM_SIG_SETUP_OUI);
}

/* Vendor precedence is by source, not table order: a setup SSID's
 * brand outranks the BSSID's registry assignee. Seen to fail with
 * VP_SSID and VP_OUI swapped (the record reads "Axis"). */
static void test_vendor_precedence(void) {
    sloth_state_t *s = fresh();
    add_beacon(s, AXIS_BSSID, "HAP_X1", "WPA2", T0);
    devices_update(s);
    const device_t *a = by_mac(s, AXIS_BSSID);
    ASSERT(a != NULL);
    if (!a) return;
    ASSERT_EQ(a->cam_signal_mask, CAM_SIG_SETUP_SSID | CAM_SIG_SETUP_OUI);
    ASSERT_STR(a->camera_vendor, "Hikvision");
    ASSERT_EQ((int)a->device_class, (int)DEV_CLASS_CAMERA);
}

/* A full table refuses the IP-only record, counted, never written past
 * MAX_DEVICES (ASan would see the overrun). */
static void test_full_table_refuses_ip_only_record(void) {
    sloth_state_t *s = fresh();
    for (int i = 0; i < MAX_DEVICES && i < MAX_ARP_ENTRIES; i++) {
        uint8_t m[6] = { 0x02, 0, 0, 0, (uint8_t)(i >> 8), (uint8_t)i };
        char ip[32];
        snprintf(ip, sizeof(ip), "10.1.%d.%d", i / 250, i % 250 + 1);
        add_arp(s, ip, m);
    }
    int before = s->arp_count;
    add_onvif(s, "10.9.9.9", 1, "", T0);
    devices_update(s);
    ASSERT(s->device_count <= MAX_DEVICES);
    if (before >= MAX_DEVICES) ASSERT(by_ip(s, "10.9.9.9") == NULL);
    else                       ASSERT(by_ip(s, "10.9.9.9") != NULL);
}

/* ── Trail ───────────────────────────────────────────────── */

static void test_trail_names_each_source_newest_first(void) {
    sloth_state_t *s = fresh();
    add_arp(s, "10.0.0.64", LAN_MAC);
    add_onvif(s, "10.0.0.64", 1, SCOPES_HIK, T0 - 30);
    add_mdns(s, "10.0.0.64", "Cam._axis-video._tcp.local",
             "_axis-video._tcp", T0 - 10);
    add_rtsp(s, "10.0.0.64", 554, "/live", 1, 0, T0 - 20);
    devices_update(s);
    const device_t *d = by_mac(s, LAN_MAC);
    ASSERT(d != NULL);
    if (!d) return;
    cam_trail_row_t t[8];
    int n = camera_trail(s, d, T0, t, 8);
    ASSERT_EQ(n, 3);
    if (n != 3) return;
    ASSERT_EQ(t[0].sig, CAM_SIG_MDNS_SERVICE);
    ASSERT_EQ(t[1].sig, CAM_SIG_RTSP_UNAUTH);
    ASSERT_EQ(t[2].sig, CAM_SIG_WS_DISCOVERY);
    ASSERT(strstr(t[2].what, "ONVIF Hello") != NULL);
    ASSERT(strstr(t[1].what, "/live") != NULL);
    /* Cut at max, not overrun. */
    ASSERT_EQ(camera_trail(s, d, T0, t, 2), 2);
    ASSERT_STR(alert_type_name(cam_signal_alert(0)), "ALERT_TYPE_CAM_WS_DISCOVERY");
    ASSERT_STR(device_class_label(DEV_CLASS_CAMERA_VENDOR), "camera-vendor");
}

/* The trail lists what the join counted and nothing the rules would
 * not: an authenticated-only RTSP stream, a non-NVT ONVIF device, a
 * miniupnpd Basic:1, a printer's mDNS service and a hotspot-guarded
 * setup SSID all sit on the same IP or BSSID as the one qualifying
 * row. Seen to fail, one at a time, with each of camera_trail()'s
 * predicates removed: RTSP `!r->anon_ok ||`, ONVIF `!o->is_camera ||`,
 * the cam_ssdp_row() result ignored, the cam_mdns_service() result
 * ignored, and `!ssid_is_public_hotspot()` (each makes n 2, or the AP's
 * trail 1). */
static void test_trail_excludes_rows_the_rules_ignore(void) {
    sloth_state_t *s = fresh();
    add_arp(s, "10.0.0.64", LAN_MAC);
    add_onvif(s, "10.0.0.64", 1, SCOPES_HIK, T0 - 30);
    add_onvif(s, "10.0.0.64", 0, "", T0 - 1);
    add_rtsp(s, "10.0.0.64", 8554, "/auth-only", 0, 3, T0 - 2);
    add_ssdp(s, "10.0.0.64", "urn:schemas-upnp-org:device:Basic:1",
             "alive", "Linux/3.0 UPnP/1.0 miniupnpd/2.0", T0 - 3);
    add_mdns(s, "10.0.0.64", "Printer._ipp._tcp.local", "_ipp._tcp", T0 - 4);
    add_beacon(s, HAP_BSSID, "HAP_guest1234", "OPEN", T0 - 5);
    devices_update(s);
    const device_t *d = by_mac(s, LAN_MAC);
    ASSERT(d != NULL);
    if (!d) return;
    ASSERT_EQ(d->cam_signal_mask, CAM_SIG_WS_DISCOVERY);
    cam_trail_row_t t[8];
    int n = camera_trail(s, d, T0, t, 8);
    ASSERT_EQ(n, 1);
    if (n >= 1) {
        ASSERT_EQ(t[0].sig, CAM_SIG_WS_DISCOVERY);
        ASSERT(strstr(t[0].what, "NetworkVideoTransmitter") != NULL);
        ASSERT_EQ((int)t[0].state, (int)CAM_JOIN_OK);
    }
    for (int i = 0; i < n; i++) {
        ASSERT(strstr(t[i].what, "/auth-only") == NULL);
        ASSERT(strstr(t[i].what, "tds:Device") == NULL);
        ASSERT(strstr(t[i].what, "Basic:1") == NULL);
        ASSERT(strstr(t[i].what, "_ipp") == NULL);
    }
    const device_t *ap = by_mac(s, HAP_BSSID);
    ASSERT(ap != NULL);
    if (ap) ASSERT_EQ(camera_trail(s, ap, T0, t, 8), 0);
}

/* ── View: list ──────────────────────────────────────────── */

static int widest_row(int rows) {
    char line[4096];
    int worst = 0;
    for (int y = 0; y < rows; y++) {
        if (tui_test_line(y, line, sizeof(line)) < 0) break;
        if (strncmp(line, "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80", 9) == 0)
            continue;   /* tui_draw()'s full-width rule under the tab bar */
        int cells = 0;
        for (const char *p = line; *p; p++)
            if (((unsigned char)*p & 0xC0) != 0x80) cells++;
        if (cells > worst) worst = cells;
    }
    return worst;
}

static void seed_camera(sloth_state_t *s) {
    add_arp(s, "10.0.0.64", LAN_MAC);
    add_onvif(s, "10.0.0.64", 1, SCOPES_HIK, T0 - 30);
    add_mdns(s, "10.0.0.64", "Garage Cam._axis-video._tcp.local",
             "_axis-video._tcp", T0 - 10);
    add_ssdp(s, "10.0.0.64", "urn:schemas-upnp-org:device:Basic:1",
             "alive", "Linux/3.0 UPnP/1.0 Hikvision-Webs/1.0", T0 - 15);
    add_rtsp(s, "10.0.0.64", 554, "/Streaming/Channels/101", 4, 0, T0 - 20);
    add_rtsp(s, "10.0.0.64", 8554, "/sub", 0, 1, T0 - 25);
}

/* 100x33, through tui_draw(): the CAMERA row is drawn whole on one
 * line and no row reaches the last column. tui_test_line() trims
 * trailing blanks, so a row exactly 100 cells wide measures the same
 * as one at 99 — but on the screen it fills the last column, the
 * cursor wraps, and its '\n' leaves a blank line under it. So the rows
 * are checked for adjacency: header, then every device row on the very
 * next lines. Seen to fail with plan_cols()'s `- 1` alone removed (a
 * blank line under the header and under each row), and with the Hits
 * cell printed as %-5d (the 123456-probe row is 100 wide and the line
 * after it is blank). */
static void test_list_camera_row_fits_100_columns(void) {
    sloth_state_t *s = fresh();
    seed_camera(s);
    uint8_t m[6] = { 0xb8, 0x27, 0xeb, 0x11, 0x22, 0x33 };
    add_arp(s, "10.0.0.5", m);
    probe_client_t *p = &s->probe_clients[s->probe_count++];
    static const uint8_t pm[6] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 };
    memcpy(p->mac, pm, 6);
    p->frame_count = 123456;
    p->signal_dbm = -70;
    p->last_seen = T0 - 100;
    static const uint8_t qm[6] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x02 };
    p = &s->probe_clients[s->probe_count++];
    memcpy(p->mac, qm, 6);
    p->frame_count = 7;
    p->signal_dbm = -71;
    p->last_seen = T0 - 200;
    devices_update(s);
    s->active_view = VIEW_DEVICES;
    s->device_sel = 3;   /* the selected row is drawn by its own printf */
    ASSERT_EQ(tui_init_offscreen(33, 100), 0);
    tui_test_erase();
    tui_draw(s);
    int h = runner_screen_find("Hostname / SSID");
    ASSERT(h >= 0);
    int ycam = runner_screen_find("10.0.0.64");
    int yarp = runner_screen_find("10.0.0.5 ");
    int yprb = runner_screen_find("de:ad:be:ef:00:01");
    int ylast = runner_screen_find("de:ad:be:ef:00:02");
    ASSERT_EQ((ycam == h + 1 && yarp == h + 2) ||
              (ycam == h + 2 && yarp == h + 1), 1);
    ASSERT_EQ(yprb, h + 3);
    ASSERT_EQ(ylast, h + 4);
    if (yprb != h + 3 || ylast != h + 4) tui_test_dump(stderr);
    if (yprb >= 0) ASSERT_LINE_HAS(yprb, "  123k");
    int y = ycam;
    if (y >= 0) {
        ASSERT_LINE_HAS(y, "CAMERA");
        /* SERVER says Hikvision and the model already starts with it:
         * the name cell does not spend its 15 cells saying it twice. */
        ASSERT_LINE_HAS(y, "  HIKVISION DS-2C");
        char line[512];
        tui_test_line(y, line, sizeof(line));
        size_t n = strlen(line);
        ASSERT(strstr(line, "A-----C") != NULL);
        ASSERT(n >= 2 && strcmp(line + n - 2, " 0") == 0);
        if (!(n >= 2 && strcmp(line + n - 2, " 0") == 0)) tui_test_dump(stderr);
    }
    ASSERT_SCREEN_HAS("cameras: 1");
    int w = widest_row(33);
    if (w >= 100) tui_test_dump(stderr);
    ASSERT(w < 100);
    /* The non-camera row says so. */
    y = runner_screen_find("10.0.0.5 ");
    ASSERT(y >= 0);
    if (y >= 0) {
        char line[512];
        tui_test_line(y, line, sizeof(line));
        ASSERT(strstr(line, "CAMERA") == NULL);
    }
}

/* The name column flexes: a 40-character hostname is cut at 100
 * columns and whole at 220. Seen to fail with plan_cols() returning
 * its 100-column plan whatever the width (the wide screen cuts too). */
static void test_list_name_column_flexes(void) {
    sloth_state_t *s = fresh();
    uint8_t m[6] = { 0xb8, 0x27, 0xeb, 0x11, 0x22, 0x44 };
    add_arp(s, "10.0.0.9", m);
    dhcp_lease_t *L = &s->dhcp_leases[s->dhcp_count++];
    snprintf(L->ip, sizeof(L->ip), "10.0.0.9");
    snprintf(L->hostname, sizeof(L->hostname),
             "a-very-long-hostname-for-the-flex-test40");
    devices_update(s);
    ASSERT_EQ(tui_init_offscreen(33, 100), 0);
    tui_test_erase();
    view_devices_draw(s);
    ASSERT_SCREEN_LACKS("a-very-long-hostname-for-the-flex-test40");
    ASSERT_SCREEN_HAS("a-very-long-ho");
    ASSERT_EQ(tui_init_offscreen(33, 220), 0);
    tui_test_erase();
    view_devices_draw(s);
    ASSERT_SCREEN_HAS("a-very-long-hostname-for-the-flex-test40");
}

/* An IP-only record shows "-" for its MAC, never a zero address. */
static void test_list_ip_only_row(void) {
    sloth_state_t *s = fresh();
    add_onvif(s, "10.0.0.65", 1, SCOPES_HIK, T0);
    devices_update(s);
    tui_test_erase();
    view_devices_draw(s);
    ASSERT_SCREEN_LACKS("00:00:00:00:00:00");
    int y = runner_screen_find("10.0.0.65");
    ASSERT(y >= 0);
    if (y >= 0) {
        ASSERT_LINE_HAS(y, " -  ");
        ASSERT_LINE_HAS(y, "------C");
        ASSERT_LINE_HAS(y, "HIKVISION DS-2CD2042WD-I");
    }
}

/* ── View: detail ────────────────────────────────────────── */

static void open_detail_on(sloth_state_t *s, const char *ip) {
    for (int i = 0; i < s->device_count; i++)
        if (strcmp(s->devices[i].ip, ip) == 0) s->device_sel = i;
    view_devices_key(s, '\r');
}

static void test_detail_shows_trail_and_sources(void) {
    sloth_state_t *s = fresh();
    seed_camera(s);
    devices_update(s);
    s->active_view = VIEW_DEVICES;
    open_detail_on(s, "10.0.0.64");
    ASSERT_EQ(s->device_detail, 1);
    ASSERT_EQ(tui_init_offscreen(60, 160), 0);
    tui_test_erase();
    tui_draw(s);
    ASSERT_SCREEN_HAS("DEVICE DETAIL");
    ASSERT_SCREEN_HAS("Class    camera - the device named its own class");
    ASSERT_SCREEN_HAS("model HIKVISION DS-2CD2042WD-I");
    ASSERT_SCREEN_HAS("Signals  WSD - MDNS SSDP - RTSP");
    ASSERT_SCREEN_HAS("SIGNAL TRAIL");
    ASSERT_SCREEN_HAS("CAM_WS_DISCOVERY  30s ago");
    ASSERT_SCREEN_HAS("CAM_MDNS_SERVICE  10s ago");
    ASSERT_SCREEN_HAS("CAM_SSDP_DEVICE   15s ago");
    ASSERT_SCREEN_HAS("CAM_RTSP_UNAUTH   20s ago");
    ASSERT_SCREEN_HAS("ONVIF SCOPES");
    ASSERT_SCREEN_HAS("onvif://www.onvif.org/hardware/DS-2CD2042WD-I");
    ASSERT_SCREEN_HAS("instance Garage Cam._axis-video._tcp.local");
    ASSERT_SCREEN_HAS("SERVER Linux/3.0 UPnP/1.0 Hikvision-Webs/1.0");
    ASSERT_SCREEN_HAS("RTSP EXPOSURE");
    ASSERT_SCREEN_HAS("/Streaming/Channels/101");
    ASSERT_SCREEN_HAS("Digest");
    /* Struck by owner ruling (#145): nothing credential-shaped. */
    ASSERT_SCREEN_LACKS("default cred");
    ASSERT_SCREEN_LACKS("password");
    /* Esc returns to the list. */
    view_devices_key(s, 27);
    ASSERT_EQ(s->device_detail, 0);
}

/* The detail holds its device across a re-sort. Seen to fail with
 * detail_device() returning &s->devices[s->device_sel] (the newer
 * device sorts to row 0 and the detail follows the row). */
static void test_detail_follows_identity_not_row(void) {
    sloth_state_t *s = fresh();
    add_onvif(s, "10.0.0.65", 1, SCOPES_HIK, T0 - 50);
    devices_update(s);
    s->device_sel = 0;
    view_devices_key(s, '\n');
    add_onvif(s, "10.0.0.99", 1, "onvif://www.onvif.org/name/OTHER", T0);
    devices_update(s);
    ASSERT_STR(s->devices[0].ip, "10.0.0.99");
    ASSERT_EQ(tui_init_offscreen(40, 140), 0);
    tui_test_erase();
    view_devices_draw(s);
    ASSERT_SCREEN_HAS("IP 10.0.0.65");
    ASSERT_SCREEN_LACKS("IP 10.0.0.99");
}

static void test_detail_device_gone(void) {
    sloth_state_t *s = fresh();
    add_onvif(s, "10.0.0.65", 1, "", T0);
    devices_update(s);
    view_devices_key(s, '\r');
    s->onvif_count = 0;
    devices_update(s);
    tui_test_erase();
    view_devices_draw(s);
    ASSERT_SCREEN_HAS("device no longer in the table");
}

/* At 100x33 a detail longer than the screen is cut with a count, and
 * nothing reaches the last row or the last column. Seen to fail with
 * dl()'s room check removed (lines run past row 32 and the count is
 * never drawn). */
static void test_detail_fits_100x33(void) {
    sloth_state_t *s = fresh();
    seed_camera(s);
    for (int i = 0; i < 20; i++) {
        char p[32]; snprintf(p, sizeof(p), "/path/%02d", i);
        add_rtsp(s, "10.0.0.64", 554, p, 1, 0, T0 - 40 - i);
    }
    devices_update(s);
    s->active_view = VIEW_DEVICES;
    open_detail_on(s, "10.0.0.64");
    ASSERT_EQ(tui_init_offscreen(33, 100), 0);
    tui_test_erase();
    tui_draw(s);
    ASSERT_SCREEN_HAS("more lines (screen full)");
    char last[512];
    ASSERT_EQ(tui_test_line(32, last, sizeof(last)), 0);
    int w = widest_row(33);
    if (w >= 100) tui_test_dump(stderr);
    ASSERT(w < 100);
}


void run_camera_join_tests(void) {
    TEST_SUITE("camera join: ONVIF scopes");
    RUN_TEST(test_scope_name_and_hardware);
    RUN_TEST(test_scope_decoding_and_filtering);

    TEST_SUITE("camera join: LAN side, by IP");
    RUN_TEST(test_wsd_joins_arp_record_by_ip);
    RUN_TEST(test_wsd_without_arp_creates_ip_only_record);
    RUN_TEST(test_wsd_non_camera_is_ignored);
    RUN_TEST(test_mdns_camera_service_vs_rtsp);
    RUN_TEST(test_mdns_rtsp_attaches_after_creating_signals);
    RUN_TEST(test_ssdp_shapes);
    RUN_TEST(test_rtsp_attaches_only);

    TEST_SUITE("camera join: recency, ambiguity, address family");
    RUN_TEST(test_stale_lan_row_does_not_join);
    RUN_TEST(test_join_window_edge_and_knob);
    RUN_TEST(test_ip_on_two_records_joins_neither);
    RUN_TEST(test_dual_stack_onvif_is_one_record);
    RUN_TEST(test_v6_only_creates_and_ssdp_dual_stack);

    TEST_SUITE("camera join: beacon side, by MAC");
    RUN_TEST(test_setup_softap_never_joins_lan_ip);
    RUN_TEST(test_setup_ssid_respects_hotspot_guardrail);
    RUN_TEST(test_setup_oui_is_vendor_only);
    RUN_TEST(test_vendor_precedence);
    RUN_TEST(test_full_table_refuses_ip_only_record);

    TEST_SUITE("camera join: trail");
    RUN_TEST(test_trail_names_each_source_newest_first);
    RUN_TEST(test_trail_excludes_rows_the_rules_ignore);

    TEST_SUITE("devices view: CAMERA row and detail");
    RUN_TEST(test_list_camera_row_fits_100_columns);
    RUN_TEST(test_list_name_column_flexes);
    RUN_TEST(test_list_ip_only_row);
    RUN_TEST(test_detail_shows_trail_and_sources);
    RUN_TEST(test_detail_follows_identity_not_row);
    RUN_TEST(test_detail_device_gone);
    RUN_TEST(test_detail_fits_100x33);
}
