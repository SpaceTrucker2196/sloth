/* Telling a camera from a router on a mixed-vendor OUI (#155):
 * src/lan_role.c, the DHCP plumbing in src/dhcp_snoop.c, and the
 * classifier at the end of src/camera_join.c, then its surfaces on the
 * Devices detail.
 *
 * Wire inputs are hand-built per their clause, no pcap (agents/AGENTS.md):
 * DHCP per RFC 2131 §2 / RFC 2132 §9.6-§9.13, DNS headers per RFC 1035
 * §4.1.1. The classifier's inputs are the snapshot tables it reads,
 * seeded field by field; their own parsers have their own byte tests
 * (test_rtsp_snoop.c, test_ndp_snoop.c, test_dhcp_snoop.c). The wall
 * clock is pinned for every test: lan_role and devices_update() stamp
 * and age through the seam.
 *
 * MACs are real IEEE MA-L blocks, so a row edit in camera_vendor.c that
 * drops one shows here: 50:C7:BF and F4:F2:6D are "TP-LINK TECHNOLOGIES
 * CO.,LTD." (the UNSW IoT list's TP-Link smart plug and camera),
 * B4:FB:E4 is "Ubiquiti Inc", D0:3F:27 "Wyze Labs Inc". */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "runner.h"
#include "sloth.h"
#include "tui.h"
#include "devices.h"
#include "camera_join.h"
#include "camera_vendor.h"
#include "dhcp_snoop.h"
#include "lan_role.h"
#include "sloth_clock.h"
#include "sensor_health.h"
#include "views/devices.h"
#ifdef WITH_PCAP
#include <pcap.h>            /* DLT_EN10MB */
#include "capture/capture.h"
#include "frame_build.h"
#endif

#define T0 ((time_t)1760000000)

static time_t g_wall;
static time_t k_wall(void) { return g_wall; }
static void pin(void) { g_wall = T0; sloth_clock_test_set(NULL, k_wall); }

TEST_STATE(g_s);

static sloth_state_t *fresh(void) {
    memset(&g_s, 0, sizeof(g_s));
    pin();
    lan_role_clear();
    dhcp_snoop_clear();
    return &g_s;
}

static const uint8_t TPL_PLUG[6] = { 0x50, 0xc7, 0xbf, 0x00, 0x56, 0x39 };
static const uint8_t TPL_CAM[6]  = { 0xf4, 0xf2, 0x6d, 0x93, 0x51, 0xf1 };
static const uint8_t UBNT[6]     = { 0xb4, 0xfb, 0xe4, 0x01, 0x02, 0x03 };
static const uint8_t WYZE[6]     = { 0xd0, 0x3f, 0x27, 0x0a, 0x0b, 0x0c };
/* 02:… is locally administered: no MA-L row of any kind. */
static const uint8_t PLAIN[6]    = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };

static void add_arp(sloth_state_t *s, const char *ip, const uint8_t mac[6]) {
    arp_entry_t *e = &s->arp_entries[s->arp_count++];
    snprintf(e->ip, sizeof(e->ip), "%s", ip);
    memcpy(e->mac, mac, 6);
    snprintf(e->iface, sizeof(e->iface), "eth0");
}

static rtsp_stream_t *add_rtsp(sloth_state_t *s, const char *ip, int sdp,
                               uint32_t anon, uint32_t chal, time_t seen) {
    rtsp_stream_t *r = &s->rtsp_streams[s->rtsp_stream_count++];
    snprintf(r->server, sizeof(r->server), "%s", ip);
    r->port = 554;
    snprintf(r->path, sizeof(r->path), "/stream1");
    r->anon_ok = anon;
    r->challenged = chal;
    r->sdp = (uint8_t)sdp;
    r->first_seen = seen - 10;
    r->last_seen = seen;
    return r;
}

static void add_mdns(sloth_state_t *s, const char *ip, const char *svc,
                     time_t seen) {
    mdns_service_t *e = &s->mdns_services[s->mdns_count++];
    snprintf(e->instance, sizeof(e->instance), "dev.%s.local", svc);
    snprintf(e->service, sizeof(e->service), "%s", svc);
    snprintf(e->ip, sizeof(e->ip), "%s", ip);
    e->port = 554;
    e->last_seen = seen;
}

static void add_onvif(sloth_state_t *s, const char *ip, time_t seen) {
    onvif_device_t *o = &s->onvif_devices[s->onvif_count++];
    snprintf(o->ip, sizeof(o->ip), "%s", ip);
    snprintf(o->uuid, sizeof(o->uuid), "urn:uuid:cam-%d", s->onvif_count);
    snprintf(o->types, sizeof(o->types), "dn:NetworkVideoTransmitter");
    snprintf(o->kind, sizeof(o->kind), "Hello");
    o->is_camera = 1;
    o->last_seen = seen;
}

static lan_role_t *add_role(sloth_state_t *s, const char *ip, int roles,
                            int dns_clients, time_t seen) {
    lan_role_t *r = &s->lan_roles[s->lan_role_count++];
    memset(r, 0, sizeof(*r));
    snprintf(r->ip, sizeof(r->ip), "%s", ip);
    r->roles = roles;
    r->dns_clients = dns_clients;
    if (roles & (LAN_ROLE_DHCP_REPLY | LAN_ROLE_DHCP_SID)) r->dhcp_seen = seen;
    if (roles & LAN_ROLE_DNS) r->dns_seen = seen;
    r->first_seen = seen;
    r->last_seen = seen;
    return r;
}

static ndp_ra_event_t *add_ra(sloth_state_t *s, const char *ip,
                              const uint8_t *slla, uint16_t lifetime,
                              time_t seen) {
    ndp_ra_event_t *e = &s->ndp_ras[s->ndp_ra_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->src_ip, sizeof(e->src_ip), "%s", ip);
    if (slla) { memcpy(e->src_mac, slla, 6); e->has_src_mac = 1; }
    e->router_lifetime = lifetime;
    e->first_seen = seen;
    e->last_seen = seen;
    e->count = 1;
    return e;
}

static const device_t *by_mac(const sloth_state_t *s, const uint8_t m[6]) {
    for (int i = 0; i < s->device_count; i++)
        if (memcmp(s->devices[i].mac, m, 6) == 0) return &s->devices[i];
    return NULL;
}

/* ── lan_role.c: address scope ───────────────────────────── */

static void test_lan_addr_scope(void) {
    ASSERT_EQ(lan_addr_is_local("10.1.2.3"), 1);
    ASSERT_EQ(lan_addr_is_local("172.16.0.1"), 1);
    ASSERT_EQ(lan_addr_is_local("172.31.255.254"), 1);
    ASSERT_EQ(lan_addr_is_local("172.32.0.1"), 0);
    ASSERT_EQ(lan_addr_is_local("192.168.1.1"), 1);
    ASSERT_EQ(lan_addr_is_local("100.64.0.1"), 1);      /* RFC 6598 */
    ASSERT_EQ(lan_addr_is_local("100.128.0.1"), 0);
    ASSERT_EQ(lan_addr_is_local("169.254.7.7"), 1);     /* RFC 3927 */
    ASSERT_EQ(lan_addr_is_local("8.8.8.8"), 0);
    ASSERT_EQ(lan_addr_is_local("127.0.0.1"), 0);
    ASSERT_EQ(lan_addr_is_local("fe80::1"), 1);
    ASSERT_EQ(lan_addr_is_local("fd00::53"), 1);
    ASSERT_EQ(lan_addr_is_local("2001:db8::1"), 0);
    ASSERT_EQ(lan_addr_is_local(""), 0);
    ASSERT_EQ(lan_addr_is_local(NULL), 0);
    ASSERT_EQ(lan_addr_is_local("192.168.1"), 0);
}

/* ── lan_role.c: DNS responder ───────────────────────────── */

/* RFC 1035 §4.1.1 header: ID, flags, QD/AN/NS/AR counts. Only the
 * header is read; a question follows so the bytes are a real message. */
static int dns_msg(uint8_t *m, int qr) {
    static const uint8_t q[] = {
        1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0,   /* a.example */
        0x00, 0x01, 0x00, 0x01,                             /* A, IN */
    };
    memset(m, 0, 12);
    m[0] = 0x12; m[1] = 0x34;
    m[2] = qr ? 0x81 : 0x01;    /* QR, opcode 0, RD */
    m[3] = qr ? 0x80 : 0x00;    /* RA */
    m[5] = 1;                   /* QDCOUNT */
    memcpy(m + 12, q, sizeof(q));
    return 12 + (int)sizeof(q);
}

static const lan_role_t *role_of(const sloth_state_t *s, const char *ip) {
    for (int i = 0; i < s->lan_role_count; i++)
        if (strcmp(s->lan_roles[i].ip, ip) == 0) return &s->lan_roles[i];
    return NULL;
}

static void test_dns_responder_counts_distinct_lan_clients(void) {
    sloth_state_t *s = fresh();
    uint8_t m[40];
    int n = dns_msg(m, 1);
    ASSERT_EQ(lan_role_dns_observe("192.168.1.1", 53, "192.168.1.20", m, n), 1);
    ASSERT_EQ(lan_role_dns_observe("192.168.1.1", 53, "192.168.1.20", m, n), 1);
    lan_role_snapshot(s);
    const lan_role_t *r = role_of(s, "192.168.1.1");
    ASSERT(r != NULL);
    if (!r) return;
    ASSERT_EQ(r->roles, LAN_ROLE_DNS);
    ASSERT_EQ(r->dns_clients, 1);     /* the same client twice is one */
    ASSERT_EQ((long long)r->dns_seen, (long long)T0);

    for (int i = 21; i < 30; i++) {
        char dst[32];
        snprintf(dst, sizeof(dst), "192.168.1.%d", i);
        lan_role_dns_observe("192.168.1.1", 53, dst, m, n);
    }
    lan_role_snapshot(s);
    r = role_of(s, "192.168.1.1");
    ASSERT(r != NULL);
    if (r) ASSERT_EQ(r->dns_clients, LAN_ROLE_DNS_CLIENTS);   /* saturates */
}

/* What is not a LAN host answering LAN hosts. Each refusal was seen to
 * fail on its own: the QR test removed (the query records), the src
 * port test removed (a reply from 5353 records), either scope test
 * removed (the public peer records), the self test removed. */
static void test_dns_responder_refusals(void) {
    sloth_state_t *s = fresh();
    uint8_t m[40];
    int nq = dns_msg(m, 0);
    ASSERT_EQ(lan_role_dns_observe("192.168.1.1", 53, "192.168.1.20", m, nq), 0);
    int n = dns_msg(m, 1);
    ASSERT_EQ(lan_role_dns_observe("192.168.1.1", 5353, "192.168.1.20", m, n), 0);
    ASSERT_EQ(lan_role_dns_observe("8.8.8.8", 53, "192.168.1.20", m, n), 0);
    ASSERT_EQ(lan_role_dns_observe("192.168.1.1", 53, "8.8.8.8", m, n), 0);
    ASSERT_EQ(lan_role_dns_observe("192.168.1.1", 53, "192.168.1.1", m, n), 0);
    ASSERT_EQ(lan_role_dns_observe("192.168.1.1", 53, "192.168.1.20", m, 11), 0);
    ASSERT_EQ(lan_role_dns_observe("192.168.1.1", 53, "192.168.1.20", NULL, n), 0);
    lan_role_snapshot(s);
    ASSERT_EQ(s->lan_role_count, 0);
}

/* STAB_OLDEST, counted under "lan_role". */
static void test_lan_role_table_evicts_and_counts(void) {
    sloth_state_t *s = fresh();
    sh_evict_reset();
    for (int i = 0; i < MAX_LAN_ROLES + 1; i++) {
        char ip[32];
        snprintf(ip, sizeof(ip), "10.0.%d.1", i);
        g_wall = T0 + i;
        lan_role_note_dhcp(ip, LAN_ROLE_DHCP_REPLY);
    }
    lan_role_snapshot(s);
    ASSERT_EQ(s->lan_role_count, MAX_LAN_ROLES);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_LAN_ROLE), 1);
    ASSERT(role_of(s, "10.0.0.1") == NULL);         /* the oldest went */
    ASSERT(role_of(s, "10.0.32.1") != NULL);
    ASSERT_STR(sh_evict_name(SH_EVICT_LAN_ROLE), "lan_role");
    /* A non-LAN address and a role that is not a DHCP one never land. */
    lan_role_clear();
    lan_role_note_dhcp("203.0.113.1", LAN_ROLE_DHCP_REPLY);
    lan_role_note_dhcp("10.9.9.9", LAN_ROLE_DNS);
    lan_role_snapshot(s);
    ASSERT_EQ(s->lan_role_count, 0);
}

/* ── dhcp_snoop.c: the packet source and options 55 / 60 ─── */

/* RFC 2131 §2 fixed header (236 octets) + magic cookie, then options. */
typedef struct {
    uint8_t     op;
    uint8_t     msg_type;           /* option 53 */
    const uint8_t *sid;             /* option 54, 4 octets, or NULL */
    const uint8_t *prl; int prl_n;  /* option 55 */
    const char *vci;                /* option 60 */
} dhcp_b_t;

static int build(const dhcp_b_t *a, uint8_t *buf, int cap) {
    int need = 240 + 3 + 6 + (a->prl ? 2 + a->prl_n : 0) +
               (a->vci ? 2 + (int)strlen(a->vci) : 0) + 1;
    if (need > cap) return 0;
    memset(buf, 0, (size_t)need);
    buf[0] = a->op;
    buf[1] = 1;                     /* htype Ethernet */
    buf[2] = 6;                     /* hlen */
    memcpy(buf + 28, TPL_PLUG, 6);  /* chaddr */
    buf[236] = 0x63; buf[237] = 0x82; buf[238] = 0x53; buf[239] = 0x63;
    int o = 240;
    buf[o++] = 53; buf[o++] = 1; buf[o++] = a->msg_type;
    if (a->sid) { buf[o++] = 54; buf[o++] = 4; memcpy(buf + o, a->sid, 4); o += 4; }
    if (a->prl) {
        buf[o++] = 55; buf[o++] = (uint8_t)a->prl_n;
        memcpy(buf + o, a->prl, (size_t)a->prl_n); o += a->prl_n;
    }
    if (a->vci) {
        int vn = (int)strlen(a->vci);
        buf[o++] = 60; buf[o++] = (uint8_t)vn;
        memcpy(buf + o, a->vci, (size_t)vn); o += vn;
    }
    buf[o++] = 255;
    return o;
}

static const uint8_t SID_1[4] = { 192, 168, 1, 1 };

/* A BOOTREPLY from UDP 67 makes its source a DHCP server (RFC 2131
 * §4.1). Seen to fail with dhcp_snoop()'s `src_port ==
 * DHCP_SERVER_PORT` test inverted (no role recorded). */
static void test_bootreply_from_67_marks_server(void) {
    sloth_state_t *s = fresh();
    dhcp_b_t a = { .op = 2, .msg_type = 2 };
    uint8_t buf[320];
    int n = build(&a, buf, sizeof(buf));
    ASSERT_EQ(dhcp_snoop("192.168.1.1", 67, buf, n, NULL, 0), 1);
    lan_role_snapshot(s);
    const lan_role_t *r = role_of(s, "192.168.1.1");
    ASSERT(r != NULL);
    if (r) ASSERT_EQ(r->roles, LAN_ROLE_DHCP_REPLY);
}

/* Not a server: a BOOTREQUEST from 67 (a relay forwarding, or noise),
 * a BOOTREPLY from 68, and a reply with no packet source. Seen to fail
 * with the `op == 2` test removed (the request marks 192.168.1.30) and
 * with the port test removed (the reply from 68 marks .31). */
static void test_dhcp_server_role_needs_reply_and_port(void) {
    sloth_state_t *s = fresh();
    uint8_t buf[320];
    dhcp_b_t req = { .op = 1, .msg_type = 3 };
    dhcp_b_t rep = { .op = 2, .msg_type = 5 };
    int nq = build(&req, buf, sizeof(buf));
    ASSERT_EQ(dhcp_snoop("192.168.1.30", 67, buf, nq, NULL, 0), 1);
    int nr = build(&rep, buf, sizeof(buf));
    ASSERT_EQ(dhcp_snoop("192.168.1.31", 68, buf, nr, NULL, 0), 1);
    ASSERT_EQ(dhcp_snoop(NULL, 67, buf, nr, NULL, 0), 1);
    lan_role_snapshot(s);
    ASSERT_EQ(s->lan_role_count, 0);
}

/* Option 54 names a server whichever side wrote it (RFC 2132 §9.7): a
 * client REQUEST naming the server that offered is, on a switched
 * port, often all sloth sees of that server. */
static void test_option_54_in_request_marks_named_server(void) {
    sloth_state_t *s = fresh();
    dhcp_b_t a = { .op = 1, .msg_type = 3, .sid = SID_1 };
    uint8_t buf[320];
    int n = build(&a, buf, sizeof(buf));
    ASSERT_EQ(dhcp_snoop("0.0.0.0", 68, buf, n, NULL, 0), 1);
    lan_role_snapshot(s);
    const lan_role_t *r = role_of(s, "192.168.1.1");
    ASSERT(r != NULL);
    if (r) ASSERT_EQ(r->roles, LAN_ROLE_DHCP_SID);
    ASSERT(role_of(s, "0.0.0.0") == NULL);
}

/* Options 55 and 60 are the client's: kept from a BOOTREQUEST, codes
 * in wire order, the class string filtered (#138). A server's reply
 * carrying them does not overwrite. Seen to fail with the `op == 1`
 * guard dropped from the PRL store (the reply's "1,3" replaces it). */
static void test_prl_and_vci_from_client_only(void) {
    sloth_state_t *s = fresh();
    static const uint8_t prl[] = { 1, 3, 6, 15, 119, 252 };
    static const uint8_t prl2[] = { 1, 3 };
    dhcp_b_t a = { .op = 1, .msg_type = 1, .prl = prl, .prl_n = 6,
                   .vci = "udhcp 1.31.1\x01" };
    uint8_t buf[320];
    int n = build(&a, buf, sizeof(buf));
    ASSERT_EQ(dhcp_snoop("0.0.0.0", 68, buf, n, NULL, 0), 1);
    dhcp_b_t r = { .op = 2, .msg_type = 2, .prl = prl2, .prl_n = 2,
                   .vci = "server" };
    n = build(&r, buf, sizeof(buf));
    ASSERT_EQ(dhcp_snoop("192.168.1.1", 67, buf, n, NULL, 0), 1);
    dhcp_snoop_snapshot(s);
    ASSERT_EQ(s->dhcp_event_count, 1);
    ASSERT_STR(s->dhcp_events[0].prl, "1,3,6,15,119,252");
    ASSERT_STR(s->dhcp_events[0].vci, "udhcp 1.31.1?");
}

/* A 255-code PRL is cut at a whole code inside the field. */
static void test_prl_cut_at_whole_code(void) {
    sloth_state_t *s = fresh();
    uint8_t codes[200];
    for (int i = 0; i < 200; i++) codes[i] = 200;
    dhcp_b_t a = { .op = 1, .msg_type = 1, .prl = codes, .prl_n = 200 };
    uint8_t buf[480];
    int n = build(&a, buf, sizeof(buf));
    ASSERT_GT(n, 0);
    ASSERT_EQ(dhcp_snoop("0.0.0.0", 68, buf, n, NULL, 0), 1);
    dhcp_snoop_snapshot(s);
    const char *p = s->dhcp_events[0].prl;
    size_t len = strlen(p);
    ASSERT_GT((int)len, 0);
    ASSERT_LT((int)len, (int)sizeof(s->dhcp_events[0].prl));
    ASSERT(p[len - 1] == '0');            /* ends "...,200" */
    ASSERT(len % 4 == 3);                 /* "200" + n x ",200" */
}

/* ── camera_join.c: the classifier ───────────────────────── */

/* A mixed-vendor block alone is a +1 prior and a vendor name, never a
 * class: the UNSW TP-Link plug and camera read the same. */
static void test_mixed_oui_alone_is_prior_not_class(void) {
    sloth_state_t *s = fresh();
    add_arp(s, "192.168.1.40", TPL_PLUG);
    add_arp(s, "192.168.1.41", TPL_CAM);
    add_arp(s, "192.168.1.42", UBNT);
    add_arp(s, "192.168.1.43", WYZE);
    devices_update(s);
    const uint8_t *m[4] = { TPL_PLUG, TPL_CAM, UBNT, WYZE };
    const char *v[4] = { "TP-Link", "TP-Link", "Ubiquiti", "Wyze" };
    for (int i = 0; i < 4; i++) {
        const device_t *d = by_mac(s, m[i]);
        ASSERT(d != NULL);
        if (!d) continue;
        ASSERT_EQ((int)d->device_class, (int)DEV_CLASS_UNKNOWN);
        ASSERT_EQ(d->cam_evidence, CAM_EV_MIXED_OUI);
        ASSERT_EQ(d->cam_score, 1);
        ASSERT_EQ(d->cam_vetoes, 0);
        ASSERT_EQ(d->cam_conflict, 0);
        ASSERT_STR(d->camera_vendor, v[i]);
    }
}

/* A locally administered address is no prior, even when its other
 * 22 bits are a mixed block's (52:C7:BF for 50:C7:BF). */
static void test_local_mac_is_no_prior(void) {
    sloth_state_t *s = fresh();
    const uint8_t loc[6] = { 0x52, 0xc7, 0xbf, 0x00, 0x56, 0x39 };
    add_arp(s, "192.168.1.44", loc);
    add_rtsp(s, "192.168.1.44", 1, 1, 0, T0);
    devices_update(s);
    const device_t *d = by_mac(s, loc);
    ASSERT(d != NULL);
    if (!d) return;
    ASSERT_EQ(d->cam_evidence & CAM_EV_MIXED_OUI, 0);
    ASSERT_EQ((int)d->device_class, (int)DEV_CLASS_UNKNOWN);
    ASSERT_STR(d->camera_vendor, "");
}

/* Mixed OUI + RTSP_SDP = 3: camera-vendor (RFC 2326 §10.2). */
static void test_mixed_plus_rtsp_sdp_is_camera_vendor(void) {
    sloth_state_t *s = fresh();
    add_arp(s, "192.168.1.41", TPL_CAM);
    add_rtsp(s, "192.168.1.41", 1, 0, 1, T0 - 5);   /* auth'd, then SDP */
    devices_update(s);
    const device_t *d = by_mac(s, TPL_CAM);
    ASSERT(d != NULL);
    if (!d) return;
    ASSERT_EQ((int)d->device_class, (int)DEV_CLASS_CAMERA_VENDOR);
    ASSERT_EQ(d->cam_evidence, CAM_EV_MIXED_OUI | CAM_EV_RTSP_SDP);
    ASSERT_EQ(d->cam_score, 3);
    ASSERT_EQ(d->cam_conflict, 0);
}

/* Score 3 from weaker signals is not a class: RTSP_SDP must be part of
 * it. Seen to fail with `(ev & CAM_EV_RTSP_SDP)` dropped from the
 * classifier's `scored` test (the record reads camera-vendor). */
static void test_weaker_signals_never_decide(void) {
    sloth_state_t *s = fresh();
    add_arp(s, "192.168.1.40", TPL_PLUG);
    add_rtsp(s, "192.168.1.40", 0, 1, 0, T0);       /* answered, no SDP */
    add_mdns(s, "192.168.1.40", "_rtsp._tcp", T0);
    devices_update(s);
    const device_t *d = by_mac(s, TPL_PLUG);
    ASSERT(d != NULL);
    if (!d) return;
    ASSERT_EQ(d->cam_evidence,
              CAM_EV_MIXED_OUI | CAM_EV_RTSP_SERVER | CAM_EV_MDNS_RTSP);
    ASSERT_EQ(d->cam_score, 3);
    ASSERT_EQ((int)d->device_class, (int)DEV_CLASS_UNKNOWN);
}

/* RTSP_SDP without a mixed OUI sets no class: the behaviour rule is
 * for the mixed-vendor question only. */
static void test_sdp_without_mixed_oui_sets_no_class(void) {
    sloth_state_t *s = fresh();
    add_arp(s, "192.168.1.50", PLAIN);
    add_rtsp(s, "192.168.1.50", 1, 1, 0, T0);
    devices_update(s);
    const device_t *d = by_mac(s, PLAIN);
    ASSERT(d != NULL);
    if (!d) return;
    ASSERT_EQ(d->cam_evidence, CAM_EV_RTSP_SDP);
    ASSERT_EQ(d->cam_score, 2);
    ASSERT_EQ((int)d->device_class, (int)DEV_CLASS_UNKNOWN);
}

/* Each router role, alone, makes a mixed-vendor record not-camera. */
static void test_each_veto_makes_mixed_not_camera(void) {
    sloth_state_t *s = fresh();
    add_arp(s, "192.168.1.1", TPL_PLUG);
    add_role(s, "192.168.1.1", LAN_ROLE_DHCP_REPLY, 0, T0);
    add_arp(s, "192.168.1.2", UBNT);
    add_ra(s, "fe80::b6fb:e4ff:fe01:203", UBNT, 1800, T0);
    add_arp(s, "192.168.1.3", WYZE);
    add_role(s, "192.168.1.3", LAN_ROLE_DNS, 2, T0);
    devices_update(s);
    const device_t *a = by_mac(s, TPL_PLUG);
    const device_t *b = by_mac(s, UBNT);
    const device_t *c = by_mac(s, WYZE);
    ASSERT(a && b && c);
    if (!a || !b || !c) return;
    ASSERT_EQ((int)a->device_class, (int)DEV_CLASS_NOT_CAMERA);
    ASSERT_EQ(a->cam_vetoes, CAM_VETO_DHCP_SERVER);
    ASSERT_EQ((int)b->device_class, (int)DEV_CLASS_NOT_CAMERA);
    ASSERT_EQ(b->cam_vetoes, CAM_VETO_SENDS_RA);
    ASSERT_EQ((int)c->device_class, (int)DEV_CLASS_NOT_CAMERA);
    ASSERT_EQ(c->cam_vetoes, CAM_VETO_DNS_RESPONDER);
    for (int i = 0; i < 3; i++) {
        const device_t *d = i == 0 ? a : i == 1 ? b : c;
        ASSERT_EQ(d->cam_conflict, 0);
        ASSERT_STR(device_class_label(d->device_class), "not-camera");
        ASSERT_EQ(device_class_is_camera(d->device_class), 0);
    }
}

/* Not vetoes. RFC 4861 §4.2: lifetime 0 says "not a default router".
 * One DNS client is not "a responder to >= 2". Each was seen to fail on
 * its own mutation: the `router_lifetime == 0` skip removed
 * (sends_ra), `dns_clients >= 2` written `>= 1` (dns_responder). That
 * the DNS-only row is not also a DHCP server is asserted but not
 * isolated: the role-mask test and the dhcp_seen window both guard it
 * (lan_role.c sets dhcp_seen only with a DHCP role), so removing
 * either one alone stays green. */
static void test_non_vetoes(void) {
    sloth_state_t *s = fresh();
    add_arp(s, "192.168.1.2", UBNT);
    add_ra(s, "fe80::b6fb:e4ff:fe01:203", UBNT, 0, T0);
    add_arp(s, "192.168.1.3", WYZE);
    add_role(s, "192.168.1.3", LAN_ROLE_DNS, 1, T0);
    devices_update(s);
    const device_t *b = by_mac(s, UBNT);
    const device_t *c = by_mac(s, WYZE);
    ASSERT(b && c);
    if (!b || !c) return;
    ASSERT_EQ(b->cam_vetoes, 0);
    ASSERT_EQ((int)b->device_class, (int)DEV_CLASS_UNKNOWN);
    ASSERT_EQ(c->cam_vetoes, 0);
    ASSERT_EQ((int)c->device_class, (int)DEV_CLASS_UNKNOWN);
}

/* An RA with no SLLA option joins by source address; and a veto row
 * older than camera.join_fresh_secs is history, not a veto. The stale
 * RA carries the record's own MAC as SLLA, so only the RA freshness
 * test stands between it and a veto: seen to fail with that test
 * removed (the stale RA vetoes m5). The stale role row is refused by
 * cam_lan_state()'s window, the join's own key rule. */
static void test_ra_by_ip_and_stale_vetoes(void) {
    sloth_state_t *s = fresh();
    uint8_t m4[6]; memcpy(m4, TPL_PLUG, 6); m4[5] = 0x01;
    uint8_t m5[6]; memcpy(m5, TPL_PLUG, 6); m5[5] = 0x02;
    uint8_t m6[6]; memcpy(m6, TPL_PLUG, 6); m6[5] = 0x03;
    add_arp(s, "fd00::4", m4);
    add_ra(s, "fd00::4", NULL, 600, T0);
    add_arp(s, "fd00::5", m5);
    add_ra(s, "fd00::5", m5, 600, T0 - CAM_JOIN_FRESH_SECS - 1);
    add_arp(s, "192.168.1.6", m6);
    add_role(s, "192.168.1.6", LAN_ROLE_DHCP_SID | LAN_ROLE_DNS, 3,
             T0 - CAM_JOIN_FRESH_SECS - 1);
    devices_update(s);
    const device_t *d4 = by_mac(s, m4), *d5 = by_mac(s, m5), *d6 = by_mac(s, m6);
    ASSERT(d4 && d5 && d6);
    if (!d4 || !d5 || !d6) return;
    ASSERT_EQ(d4->cam_vetoes, CAM_VETO_SENDS_RA);
    ASSERT_EQ(d5->cam_vetoes, 0);
    ASSERT_EQ(d6->cam_vetoes, 0);
}

/* A camera-vendor block is not a mixed one: a Hikvision NVR that also
 * hands out leases gets no mixed_oui prior, so the DHCP-server veto is
 * shown and decides nothing (only a mixed block opens the question).
 * Seen to fail with `&& mx` dropped from camera_reasons()'s OUI test
 * (the record gains mixed_oui and reads not-camera). */
static void test_camera_vendor_block_is_not_mixed(void) {
    sloth_state_t *s = fresh();
    static const uint8_t HIK[6] = { 0x44, 0x19, 0xb6, 0x10, 0x20, 0x30 };
    add_arp(s, "192.168.1.64", HIK);
    add_role(s, "192.168.1.64", LAN_ROLE_DHCP_REPLY, 0, T0);
    devices_update(s);
    const device_t *d = by_mac(s, HIK);
    ASSERT(d != NULL);
    if (!d) return;
    ASSERT_EQ(d->cam_evidence & CAM_EV_MIXED_OUI, 0);
    ASSERT_EQ(d->cam_vetoes, CAM_VETO_DHCP_SERVER);
    ASSERT(d->device_class != DEV_CLASS_NOT_CAMERA);
    ASSERT_EQ(d->cam_conflict, 0);
}

/* RTSP SDP rows are IP-keyed and held to cam_lan_state(): a row older
 * than camera.join_fresh_secs, or at an IP two records hold, is no
 * rtsp_sdp evidence and no camera-vendor class. Both seen to fail with
 * the cam_lan_state() term removed from camera_reasons()'s RTSP loop
 * (each record gains rtsp_sdp and reads camera-vendor). The rows are
 * challenged-only (no anon_ok), so the join's RTSP_UNAUTH fold never
 * touches them and only the classifier's key rule is under test. */
static void test_rtsp_sdp_held_to_key_rule(void) {
    sloth_state_t *s = fresh();
    uint8_t m1[6]; memcpy(m1, TPL_CAM, 6); m1[5] = 0x11;
    uint8_t m2[6]; memcpy(m2, TPL_CAM, 6); m2[5] = 0x12;
    uint8_t m3[6]; memcpy(m3, TPL_CAM, 6); m3[5] = 0x13;
    add_arp(s, "192.168.1.70", m1);
    add_rtsp(s, "192.168.1.70", 1, 0, 1, T0 - CAM_JOIN_FRESH_SECS - 1);
    add_arp(s, "192.168.1.71", m2);          /* the lease's old holder */
    add_arp(s, "192.168.1.71", m3);          /* and its new one */
    add_rtsp(s, "192.168.1.71", 1, 0, 1, T0);
    devices_update(s);
    const uint8_t *m[3] = { m1, m2, m3 };
    for (int i = 0; i < 3; i++) {
        const device_t *d = by_mac(s, m[i]);
        ASSERT(d != NULL);
        if (!d) continue;
        ASSERT_EQ(d->cam_evidence, CAM_EV_MIXED_OUI);
        ASSERT_EQ(d->cam_score, 1);
        ASSERT_EQ((int)d->device_class, (int)DEV_CLASS_UNKNOWN);
    }
}

/* An RA with no SLLA option is keyed on its source address, so it is
 * held to cam_lan_state() too. Ambiguous: two records on fd00::7 and
 * neither is vetoed; seen to fail with the cam_lan_state() term removed
 * from the RA by-IP test (both read not-camera with sends_ra). Stale:
 * asserted but not isolated - the RA loop's own is_fresh() skip runs
 * first on the same last_seen, so removing either guard alone stays
 * green. */
static void test_ra_by_ip_held_to_key_rule(void) {
    sloth_state_t *s = fresh();
    uint8_t m7[6]; memcpy(m7, UBNT, 6); m7[5] = 0x07;
    uint8_t m8[6]; memcpy(m8, UBNT, 6); m8[5] = 0x08;
    uint8_t m9[6]; memcpy(m9, UBNT, 6); m9[5] = 0x09;
    add_arp(s, "fd00::7", m7);
    add_arp(s, "fd00::7", m8);
    add_ra(s, "fd00::7", NULL, 1800, T0);
    add_arp(s, "fd00::9", m9);
    add_ra(s, "fd00::9", NULL, 1800, T0 - CAM_JOIN_FRESH_SECS - 1);
    devices_update(s);
    const uint8_t *m[3] = { m7, m8, m9 };
    for (int i = 0; i < 3; i++) {
        const device_t *d = by_mac(s, m[i]);
        ASSERT(d != NULL);
        if (!d) continue;
        ASSERT_EQ(d->cam_vetoes, 0);
        ASSERT_EQ((int)d->device_class, (int)DEV_CLASS_UNKNOWN);
    }
}

/* A veto on a record with no mixed OUI is shown and decides nothing:
 * only the mixed block made the class an open question. Seen to fail
 * with `(ev & CAM_EV_MIXED_OUI)` dropped from the not-camera branch
 * (the plain router reads not-camera). */
static void test_veto_without_mixed_oui_decides_nothing(void) {
    sloth_state_t *s = fresh();
    add_arp(s, "192.168.1.1", PLAIN);
    add_role(s, "192.168.1.1", LAN_ROLE_DHCP_REPLY | LAN_ROLE_DNS, 4, T0);
    devices_update(s);
    const device_t *d = by_mac(s, PLAIN);
    ASSERT(d != NULL);
    if (!d) return;
    ASSERT_EQ(d->cam_vetoes, CAM_VETO_DHCP_SERVER | CAM_VETO_DNS_RESPONDER);
    ASSERT_EQ((int)d->device_class, (int)DEV_CLASS_UNKNOWN);
    ASSERT_EQ(d->cam_conflict, 0);
}

/* The camera score meets a veto: a conflict, shown, and the class is
 * neither verdict. Seen to fail with the conflict branch removed (the
 * record reads camera-vendor and cam_conflict 0). */
static void test_scored_camera_with_veto_is_conflict(void) {
    sloth_state_t *s = fresh();
    add_arp(s, "192.168.1.41", TPL_CAM);
    add_rtsp(s, "192.168.1.41", 1, 1, 0, T0);
    add_role(s, "192.168.1.41", LAN_ROLE_DHCP_REPLY, 0, T0);
    devices_update(s);
    const device_t *d = by_mac(s, TPL_CAM);
    ASSERT(d != NULL);
    if (!d) return;
    ASSERT_EQ(d->cam_conflict, 1);
    ASSERT_EQ(d->cam_score, 3);
    ASSERT_EQ(d->cam_vetoes, CAM_VETO_DHCP_SERVER);
    ASSERT_EQ((int)d->device_class, (int)DEV_CLASS_UNKNOWN);
}

/* A self-declaration still decides (camera), and the veto beside it is
 * a conflict, not silence. */
static void test_self_declared_camera_with_veto_keeps_class(void) {
    sloth_state_t *s = fresh();
    add_arp(s, "192.168.1.41", TPL_CAM);
    add_onvif(s, "192.168.1.41", T0);
    add_role(s, "192.168.1.41", LAN_ROLE_DNS, 2, T0);
    devices_update(s);
    const device_t *d = by_mac(s, TPL_CAM);
    ASSERT(d != NULL);
    if (!d) return;
    ASSERT_EQ((int)d->device_class, (int)DEV_CLASS_CAMERA);
    ASSERT_EQ(d->cam_conflict, 1);
    ASSERT_EQ(d->cam_vetoes, CAM_VETO_DNS_RESPONDER);
}

/* Beacon side: a mixed-vendor BSSID alone sets no CAM_SETUP_OUI bit
 * and no class; beside Tapo's camera setup SSID it is a camera with
 * both bits. Seen to fail with the beacon loop back on
 * cam_vendor_oui() (the lone UniFi BSSID gets the OUI bit and
 * camera-vendor). */
static void test_mixed_bssid_needs_setup_ssid(void) {
    sloth_state_t *s = fresh();
    beacon_ap_t *a = &s->beacon_aps[s->beacon_count++];
    memcpy(a->bssid, UBNT, 6);
    snprintf(a->ssid, sizeof(a->ssid), "UniFi");
    snprintf(a->enc, sizeof(a->enc), "WPA2");
    a->last_seen = T0;
    beacon_ap_t *b = &s->beacon_aps[s->beacon_count++];
    memcpy(b->bssid, TPL_CAM, 6);
    snprintf(b->ssid, sizeof(b->ssid), "Tapo_Cam_51F1");
    snprintf(b->enc, sizeof(b->enc), "OPEN");
    b->last_seen = T0;
    devices_update(s);
    const device_t *u = by_mac(s, UBNT);
    const device_t *t = by_mac(s, TPL_CAM);
    ASSERT(u && t);
    if (!u || !t) return;
    ASSERT_EQ(u->cam_signal_mask, 0);
    ASSERT_EQ((int)u->device_class, (int)DEV_CLASS_UNKNOWN);
    ASSERT_EQ(u->cam_evidence, CAM_EV_MIXED_OUI);
    ASSERT_EQ(t->cam_signal_mask, CAM_SIG_SETUP_SSID | CAM_SIG_SETUP_OUI);
    ASSERT_EQ((int)t->device_class, (int)DEV_CLASS_CAMERA);
    /* The trail lists only what the rule counts. */
    cam_trail_row_t tr[8];
    ASSERT_EQ(camera_trail(s, u, T0, tr, 8), 0);
    ASSERT_EQ(camera_trail(s, t, T0, tr, 8), 2);
}

/* DHCP options 55 / 60 reach the record by chaddr, unscored. */
static void test_dhcp_options_on_record_unscored(void) {
    sloth_state_t *s = fresh();
    add_arp(s, "192.168.1.40", TPL_PLUG);
    dhcp_event_t *e = &s->dhcp_events[s->dhcp_event_count++];
    snprintf(e->mac, sizeof(e->mac), "50:c7:bf:00:56:39");
    snprintf(e->prl, sizeof(e->prl), "1,3,6,12,15,28,42");
    snprintf(e->vci, sizeof(e->vci), "udhcp 1.31.1");
    e->last_seen = T0;
    devices_update(s);
    const device_t *d = by_mac(s, TPL_PLUG);
    ASSERT(d != NULL);
    if (!d) return;
    ASSERT_STR(d->dhcp_prl, "1,3,6,12,15,28,42");
    ASSERT_STR(d->dhcp_vci, "udhcp 1.31.1");
    ASSERT_EQ(d->cam_score, 1);           /* the OUI's prior, nothing else */
}

/* Options are matched to the record by chaddr: another client's PRL
 * and VCI never land on a neighbour. Seen to fail with the chaddr
 * strcmp removed (the camera shows the plug's options). */
static void test_dhcp_options_only_on_their_client(void) {
    sloth_state_t *s = fresh();
    add_arp(s, "192.168.1.40", TPL_PLUG);
    add_arp(s, "192.168.1.41", TPL_CAM);
    dhcp_event_t *e = &s->dhcp_events[s->dhcp_event_count++];
    snprintf(e->mac, sizeof(e->mac), "50:c7:bf:00:56:39");
    snprintf(e->prl, sizeof(e->prl), "1,3,6");
    snprintf(e->vci, sizeof(e->vci), "udhcp 1.31.1");
    e->last_seen = T0;
    devices_update(s);
    const device_t *p = by_mac(s, TPL_PLUG);
    const device_t *c = by_mac(s, TPL_CAM);
    ASSERT(p && c);
    if (!p || !c) return;
    ASSERT_STR(p->dhcp_prl, "1,3,6");
    ASSERT_STR(c->dhcp_prl, "");
    ASSERT_STR(c->dhcp_vci, "");
}

static void test_slug_lists(void) {
    char b[128];
    cam_evidence_list(CAM_EV_MIXED_OUI | CAM_EV_RTSP_SDP, b, sizeof(b));
    ASSERT_STR(b, "mixed_oui,rtsp_sdp");
    cam_veto_list(CAM_VETO_DHCP_SERVER | CAM_VETO_SENDS_RA |
                  CAM_VETO_DNS_RESPONDER, b, sizeof(b));
    ASSERT_STR(b, "dhcp_server,sends_ra,dns_responder");
    cam_evidence_list(0, b, sizeof(b));
    ASSERT_STR(b, "");
    char small[12];
    cam_veto_list(CAM_VETO_DHCP_SERVER | CAM_VETO_SENDS_RA, small,
                  sizeof(small));
    ASSERT_STR(small, "dhcp_server");    /* cut at a whole slug */
    ASSERT_EQ(cam_evidence_weight(CAM_EV_RTSP_SDP), 2);
    ASSERT_EQ(cam_evidence_weight(CAM_EV_MIXED_OUI), 1);
    ASSERT_EQ(cam_evidence_weight(1 << 9), 0);
    ASSERT_STR(cam_veto_slug(1 << 9), "");
}

/* ── Devices view ────────────────────────────────────────── */

static int row_of(const sloth_state_t *s, const uint8_t m[6]) {
    for (int i = 0; i < s->device_count; i++)
        if (memcmp(s->devices[i].mac, m, 6) == 0) return i;
    return -1;
}

static void detail(sloth_state_t *s, const uint8_t m[6]) {
    s->active_view = VIEW_DEVICES;
    s->device_sel = row_of(s, m);
    view_devices_key(s, '\r');
    ASSERT_EQ(tui_init_offscreen(40, 160), 0);
    tui_test_erase();
    view_devices_draw(s);
}

static void test_view_list_cells(void) {
    sloth_state_t *s = fresh();
    add_arp(s, "192.168.1.1", TPL_PLUG);
    add_role(s, "192.168.1.1", LAN_ROLE_DHCP_REPLY, 0, T0);
    add_arp(s, "192.168.1.41", TPL_CAM);
    add_rtsp(s, "192.168.1.41", 1, 1, 0, T0);
    add_role(s, "192.168.1.41", LAN_ROLE_DNS, 2, T0);
    devices_update(s);
    ASSERT_EQ(tui_init_offscreen(33, 140), 0);
    tui_test_erase();
    view_devices_draw(s);
    ASSERT_SCREEN_HAS("NOTCAM");
    ASSERT_SCREEN_HAS("CONFL!");
    /* Neither counts as a camera in the header. */
    ASSERT_SCREEN_HAS("cameras: 0");
}

static void test_view_detail_lists_evidence_vetoes_and_conflict(void) {
    sloth_state_t *s = fresh();
    add_arp(s, "192.168.1.41", TPL_CAM);
    add_rtsp(s, "192.168.1.41", 1, 1, 0, T0 - 30);
    add_role(s, "192.168.1.41", LAN_ROLE_DHCP_REPLY | LAN_ROLE_DHCP_SID,
             0, T0 - 10);
    add_ra(s, "fe80::1", TPL_CAM, 1800, T0);
    dhcp_event_t *e = &s->dhcp_events[s->dhcp_event_count++];
    snprintf(e->mac, sizeof(e->mac), "f4:f2:6d:93:51:f1");
    snprintf(e->prl, sizeof(e->prl), "1,3,6,15");
    snprintf(e->vci, sizeof(e->vci), "MSFT 5.0");
    devices_update(s);
    detail(s, TPL_CAM);
    ASSERT_SCREEN_HAS("CONFLICT");
    ASSERT_SCREEN_HAS("EVIDENCE / VETOES");
    ASSERT_SCREEN_HAS("mixed_oui");
    ASSERT_SCREEN_HAS("TP-LINK TECHNOLOGIES CO.,LTD.");
    ASSERT_SCREEN_HAS("rtsp_sdp");
    ASSERT_SCREEN_HAS("application/sdp");
    ASSERT_SCREEN_HAS("dhcp_server");
    ASSERT_SCREEN_HAS("BOOTREPLY from UDP 67; named in option 54");
    ASSERT_SCREEN_HAS("sends RAs");
    ASSERT_SCREEN_HAS("Score    3");
    ASSERT_SCREEN_HAS("55 PRL  1,3,6,15");
    ASSERT_SCREEN_HAS("60 VCI  MSFT 5.0");
    s->device_detail = 0;
}

/* A mixed-vendor block names the maker, not a camera: the detail of an
 * unclassified TP-Link plug says so, and a scored camera-vendor record
 * keeps the camera line. Seen to fail with the mixed-vendor branch in
 * draw_device_detail() removed (the plug reads "Camera   vendor"). */
static void test_view_detail_mixed_vendor_is_not_camera_claim(void) {
    sloth_state_t *s = fresh();
    add_arp(s, "192.168.1.40", TPL_PLUG);
    add_arp(s, "192.168.1.41", TPL_CAM);
    add_rtsp(s, "192.168.1.41", 1, 1, 0, T0);
    devices_update(s);
    detail(s, TPL_PLUG);
    ASSERT_SCREEN_HAS("Vendor   TP-Link (mixed-vendor block; not a camera claim)");
    ASSERT_SCREEN_LACKS("Camera   vendor");
    s->device_detail = 0;
    detail(s, TPL_CAM);
    ASSERT_SCREEN_HAS("Camera   vendor TP-Link");
    ASSERT_SCREEN_LACKS("not a camera claim");
    s->device_detail = 0;
}

static void test_view_detail_not_camera(void) {
    sloth_state_t *s = fresh();
    add_arp(s, "192.168.1.2", UBNT);
    add_ra(s, "fe80::b6fb:e4ff:fe01:203", UBNT, 1800, T0);
    devices_update(s);
    detail(s, UBNT);
    ASSERT_SCREEN_HAS("not-camera - mixed-vendor block seen in a router role");
    ASSERT_SCREEN_HAS("SLLA is this MAC");
    ASSERT_SCREEN_HAS("Vendor   Ubiquiti (mixed-vendor block; not a camera claim)");
    ASSERT_SCREEN_LACKS("Camera   vendor");
    ASSERT_SCREEN_LACKS("CONFLICT");
    ASSERT_SCREEN_LACKS("DHCP OPTIONS");
    s->device_detail = 0;
}

/* ── The capture wiring: packet source reaches both roles ── */

#ifdef WITH_PCAP
/* Ethernet + IPv4 + UDP frames through the real decode seam: a DHCP
 * OFFER from the server port and a DNS answer from port 53, each from
 * 192.168.1.1. Seen to fail with capture.c's dhcp_snoop() call passing
 * NULL for the source (no DHCP_REPLY role) and with its
 * lan_role_dns_observe() call removed (no DNS role). */
static void test_capture_path_records_both_roles(void) {
    sloth_state_t *s = fresh();
    static const uint8_t gw_mac[6] = { 0x50, 0xc7, 0xbf, 0x00, 0x00, 0x01 };
    static const uint8_t bc[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    static const uint8_t cl_mac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x14 };
    static const uint8_t gw[4] = { 192, 168, 1, 1 };
    static const uint8_t bcast[4] = { 255, 255, 255, 255 };
    static const uint8_t c20[4] = { 192, 168, 1, 20 };
    static const uint8_t c21[4] = { 192, 168, 1, 21 };
    uint8_t dhcp[320];
    dhcp_b_t offer = { .op = 2, .msg_type = 2, .sid = SID_1 };
    int dn = build(&offer, dhcp, sizeof(dhcp));
    uint8_t f[400];
    fb_t b; fb_init(&b, f, sizeof f);
    fb_eth_ipv4_udp(&b, bc, gw_mac, gw, bcast, 67, 68, dhcp, dn, 1);
    ASSERT(fb_ok(&b));
    packet_info_t pkt;
    ASSERT_EQ(capture_test_decode_frame(f, b.len, b.len, DLT_EN10MB, &pkt), 1);

    uint8_t m[40];
    int mn = dns_msg(m, 1);
    for (int i = 0; i < 2; i++) {
        fb_init(&b, f, sizeof f);
        fb_eth_ipv4_udp(&b, cl_mac, gw_mac, gw, i ? c21 : c20, 53, 40000,
                        m, mn, (uint16_t)(2 + i));
        ASSERT(fb_ok(&b));
        ASSERT_EQ(capture_test_decode_frame(f, b.len, b.len, DLT_EN10MB,
                                            &pkt), 1);
    }
    lan_role_snapshot(s);
    const lan_role_t *r = role_of(s, "192.168.1.1");
    ASSERT(r != NULL);
    if (!r) return;
    ASSERT_EQ(r->roles, LAN_ROLE_DHCP_REPLY | LAN_ROLE_DHCP_SID | LAN_ROLE_DNS);
    ASSERT_EQ(r->dns_clients, 2);
}
#endif

void run_camera_class_tests(void) {
    TEST_SUITE("camera class: mixed-vendor OUI, behaviour, router vetoes (#155)");
    RUN_TEST(test_lan_addr_scope);
    RUN_TEST(test_dns_responder_counts_distinct_lan_clients);
    RUN_TEST(test_dns_responder_refusals);
    RUN_TEST(test_lan_role_table_evicts_and_counts);
    RUN_TEST(test_bootreply_from_67_marks_server);
    RUN_TEST(test_dhcp_server_role_needs_reply_and_port);
    RUN_TEST(test_option_54_in_request_marks_named_server);
    RUN_TEST(test_prl_and_vci_from_client_only);
    RUN_TEST(test_prl_cut_at_whole_code);
    RUN_TEST(test_mixed_oui_alone_is_prior_not_class);
    RUN_TEST(test_local_mac_is_no_prior);
    RUN_TEST(test_mixed_plus_rtsp_sdp_is_camera_vendor);
    RUN_TEST(test_weaker_signals_never_decide);
    RUN_TEST(test_sdp_without_mixed_oui_sets_no_class);
    RUN_TEST(test_each_veto_makes_mixed_not_camera);
    RUN_TEST(test_non_vetoes);
    RUN_TEST(test_ra_by_ip_and_stale_vetoes);
    RUN_TEST(test_camera_vendor_block_is_not_mixed);
    RUN_TEST(test_rtsp_sdp_held_to_key_rule);
    RUN_TEST(test_ra_by_ip_held_to_key_rule);
    RUN_TEST(test_veto_without_mixed_oui_decides_nothing);
    RUN_TEST(test_scored_camera_with_veto_is_conflict);
    RUN_TEST(test_self_declared_camera_with_veto_keeps_class);
    RUN_TEST(test_mixed_bssid_needs_setup_ssid);
    RUN_TEST(test_dhcp_options_on_record_unscored);
    RUN_TEST(test_dhcp_options_only_on_their_client);
    RUN_TEST(test_slug_lists);
    RUN_TEST(test_view_list_cells);
    RUN_TEST(test_view_detail_lists_evidence_vetoes_and_conflict);
    RUN_TEST(test_view_detail_mixed_vendor_is_not_camera_claim);
    RUN_TEST(test_view_detail_not_camera);
#ifdef WITH_PCAP
    RUN_TEST(test_capture_path_records_both_roles);
#endif
}
