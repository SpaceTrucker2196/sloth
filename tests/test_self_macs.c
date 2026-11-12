/* The host's own addresses beyond the iface rows (#183): the rtnetlink
 * link dump, the Wi-Fi phys' sysfs address pools, the nl80211
 * interface dump, and the PLATFORM stage that rosters them.
 *
 * Netlink messages are built from the kernel ABI, not captured, the
 * same way tests/test_parse.c builds its neighbour messages; sysfs is
 * tests/fake_platform.c's text table. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "runner.h"
#include "sloth.h"
#include "fake_platform.h"
#include "ownership.h"
#include "poll.h"
#include "alerts.h"

#ifdef PLATFORM_LINUX
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_arp.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include "platform/linux_self.h"
#include "platform/linux_wifi.h"

/* The reference host's managed card (issue #183), the address
 * NetworkManager's per-connection randomisation gave it, the monitor
 * radio, and wpa_supplicant's P2P device: the permanent address with
 * the locally administered bit set, which is how it derives one. */
static const uint8_t CARD_PERM[6] = {0x24,0x41,0x8c,0x30,0x97,0xa1};
static const uint8_t CARD_RAND[6] = {0x5a,0x10,0x7e,0x33,0x02,0x9c};
static const uint8_t MON[6]       = {0x00,0xc0,0xca,0xbb,0x51,0x82};
static const uint8_t P2P_DEV[6]   = {0x26,0x41,0x8c,0x30,0x97,0xa1};
static const uint8_t ZERO6[6]     = {0};
static const uint8_t BCAST[6]     = {0xff,0xff,0xff,0xff,0xff,0xff};

/* struct nlmsghdr is len u32, type u16, flags u16, seq u32, pid u32;
 * struct rtattr / nlattr is len u16, type u16, then the payload, every
 * length padded to 4. Host byte order, which netlink speaks. */
static size_t put16(uint8_t *b, size_t o, uint16_t v) { memcpy(b + o, &v, 2); return o + 2; }
static size_t put32(uint8_t *b, size_t o, uint32_t v) { memcpy(b + o, &v, 4); return o + 4; }
static size_t al4(size_t o) { return (o + 3u) & ~(size_t)3u; }

static size_t attr(uint8_t *b, size_t o, uint16_t type, const void *p, size_t n) {
    o = put16(b, o, (uint16_t)(4 + n));
    o = put16(b, o, type);
    memcpy(b + o, p, n);
    memset(b + o + n, 0, al4(n) - n);
    return o + al4(n);
}

static void hdr(uint8_t *b, size_t start, size_t end, uint16_t type) {
    put32(b, start, (uint32_t)(end - start));
    put16(b, start + 4, type);
    put16(b, start + 6, NLM_F_MULTI);
    put32(b, start + 8, 1);
    put32(b, start + 12, 0);
}

static size_t done_msg(uint8_t *b, size_t o) {
    put32(b, o, 20);
    put16(b, o + 4, NLMSG_DONE);
    put16(b, o + 6, NLM_F_MULTI);
    put32(b, o + 8, 1);
    put32(b, o + 12, 0);
    put32(b, o + 16, 0);
    return o + 20;
}

/* One RTM_NEWLINK: struct ifinfomsg is family u8, pad u8, type u16,
 * index s32, flags u32, change u32 (16 bytes). alen/plen 0 leave that
 * attribute out; the broadcast address is always present, as the
 * kernel sends it, and must never be read as one of the host's. */
static size_t link_msg(uint8_t *b, size_t o, uint16_t arphrd, int ifindex,
                       const uint8_t *addr, size_t alen,
                       const uint8_t *perm, size_t plen) {
    size_t start = o;
    o += 16;
    memset(b + o, 0, 16);
    b[o] = AF_UNSPEC;
    put16(b, o + 2, arphrd);
    put32(b, o + 4, (uint32_t)ifindex);
    o += 16;
    const char name[] = "wlan0";
    o = attr(b, o, IFLA_IFNAME, name, sizeof(name));
    if (alen) o = attr(b, o, IFLA_ADDRESS, addr, alen);
    o = attr(b, o, IFLA_BROADCAST, BCAST, 6);
    if (plen) o = attr(b, o, IFLA_PERM_ADDRESS, perm, plen);
    hdr(b, start, o, RTM_NEWLINK);
    return o;
}

static int has(uint8_t (*out)[6], int n, const uint8_t m[6]) {
    for (int i = 0; i < n; i++)
        if (memcmp(out[i], m, 6) == 0) return 1;
    return 0;
}

/* A card on a randomised address still names its own: both rostered,
 * because the card goes back to the permanent one when the connection
 * setting changes, and the monitor radio hears whichever is in use. */
static void test_links_address_and_permanent_address(void) {
    uint8_t b[512];
    size_t o = link_msg(b, 0, ARPHRD_ETHER, 3, CARD_RAND, 6, CARD_PERM, 6);
    o = link_msg(b, o, ARPHRD_IEEE80211_RADIOTAP, 4, MON, 6, MON, 6);
    uint8_t out[8][6];
    int done = 0;
    int n = linux_self_parse_links(b, o, out, 8, 0, &done);
    ASSERT_EQ(n, 3);
    ASSERT_EQ(done, 0);
    ASSERT(has(out, n, CARD_RAND));
    ASSERT(has(out, n, CARD_PERM));
    ASSERT(has(out, n, MON));          /* a monitor vif, by its own row */
    ASSERT(!has(out, n, BCAST));       /* IFLA_BROADCAST is not an address */
}

/* Loopback's all-zero address, a tunnel's four-byte one and an
 * InfiniBand twenty-byte one are not 802 addresses. A message of the
 * wrong type is skipped, and NLMSG_DONE ends the walk even with bytes
 * after it. */
static void test_links_skip_non_addresses_and_stop_at_done(void) {
    uint8_t b[1024];
    const uint8_t v4[4] = {192,0,2,1};
    uint8_t ib[20];
    memset(ib, 0x42, sizeof(ib));
    size_t o = link_msg(b, 0, ARPHRD_LOOPBACK, 1, ZERO6, 6, NULL, 0);
    o = link_msg(b, o, ARPHRD_TUNNEL, 5, v4, 4, NULL, 0);
    o = link_msg(b, o, ARPHRD_INFINIBAND, 6, ib, 20, ib, 20);
    size_t del = o;
    o = link_msg(b, o, ARPHRD_ETHER, 7, CARD_PERM, 6, NULL, 0);
    hdr(b, del, o, RTM_DELLINK);
    o = done_msg(b, o);
    o = link_msg(b, o, ARPHRD_ETHER, 8, MON, 6, NULL, 0);
    uint8_t out[8][6];
    int done = 0;
    int n = linux_self_parse_links(b, o, out, 8, 0, &done);
    ASSERT_EQ(n, 0);
    ASSERT_EQ(done, 1);
}

/* An address on two rows (a bridge and its first port) takes one slot;
 * the bound holds; n carries across recv() pages. */
static void test_links_dedupe_bound_and_append(void) {
    uint8_t b[512];
    size_t o = link_msg(b, 0, ARPHRD_ETHER, 3, CARD_PERM, 6, CARD_PERM, 6);
    o = link_msg(b, o, ARPHRD_ETHER, 9, CARD_PERM, 6, NULL, 0);
    uint8_t out[2][6];
    int n = linux_self_parse_links(b, o, out, 2, 0, NULL);
    ASSERT_EQ(n, 1);
    o = link_msg(b, 0, ARPHRD_ETHER, 4, CARD_RAND, 6, MON, 6);
    n = linux_self_parse_links(b, o, out, 2, n, NULL);
    ASSERT_EQ(n, 2);                   /* MON did not fit */
    ASSERT(has(out, n, CARD_PERM));
    ASSERT(has(out, n, CARD_RAND));
    ASSERT(!has(out, n, MON));
    ASSERT_EQ(linux_self_parse_links(NULL, 64, out, 2, 0, NULL), 0);
}

/* A message whose length runs past the buffer is not read. */
static void test_links_truncated_message(void) {
    uint8_t b[256];
    size_t o = link_msg(b, 0, ARPHRD_ETHER, 3, CARD_PERM, 6, NULL, 0);
    uint8_t out[4][6];
    ASSERT_EQ(linux_self_parse_links(b, o - 4, out, 4, 0, NULL), 0);
    ASSERT_EQ(linux_self_parse_links(b, o, out, 4, 0, NULL), 1);
}

static void test_parse_mac_token(void) {
    uint8_t m[6];
    ASSERT_EQ(linux_self_parse_mac("24:41:8c:30:97:a1\n", m), 0);
    ASSERT(memcmp(m, CARD_PERM, 6) == 0);
    ASSERT_EQ(linux_self_parse_mac("24:41:8C:30:97:A1", m), 0);
    ASSERT_EQ(linux_self_parse_mac("24:41:8c:30:97", m), -1);
    ASSERT_EQ(linux_self_parse_mac("24:41:8c:30:97:a1:00", m), -1);
    ASSERT_EQ(linux_self_parse_mac("24:41:8c:30:97:a10", m), -1);
    ASSERT_EQ(linux_self_parse_mac("", m), -1);
    ASSERT_EQ(linux_self_parse_mac(NULL, m), -1);
}

/* ── the phys' address pools, from a fake sysfs ─────────── */

/* The monitor radio's phy and the managed card's phy. The card lists a
 * pool of four (iwlwifi-style): the address a monitor vif or a second
 * station created later will take is in it. A bad line is skipped,
 * not guessed at. */
static void test_phy_macaddress_and_pool(void) {
    fake_net_reset();
    fake_sys_put("/sys/class/ieee80211/phy0/macaddress", "24:41:8c:30:97:a1\n");
    fake_sys_put("/sys/class/ieee80211/phy0/addresses",
                 "24:41:8c:30:97:a1\n24:41:8c:30:97:a2\n"
                 "not-an-address\n24:41:8c:30:97:a3\n24:41:8c:30:97:a4\n");
    fake_sys_put("/sys/class/ieee80211/phy1/macaddress", "00:c0:ca:bb:51:82\n");
    uint8_t out[16][6];
    int n = linux_self_phy_macs(g_platform.sys_read, g_platform.sys_list,
                                out, 16, 0);
    ASSERT_EQ(n, 5);
    const uint8_t a4[6] = {0x24,0x41,0x8c,0x30,0x97,0xa4};
    ASSERT(has(out, n, CARD_PERM));
    ASSERT(has(out, n, a4));
    ASSERT(has(out, n, MON));
    ASSERT_EQ(g_fake_net.sys_outside_calls, 0);
    fake_net_reset();
}

/* No phys (a wired-only host), or no sysfs reader at all (a platform
 * without the tree): nothing, and nothing outside /sys is asked for. */
static void test_phy_absent_and_null_readers(void) {
    fake_net_reset();
    uint8_t out[4][6];
    ASSERT_EQ(linux_self_phy_macs(g_platform.sys_read, g_platform.sys_list,
                                  out, 4, 0), 0);
    fake_sys_put("/sys/class/ieee80211/phy0/macaddress", "24:41:8c:30:97:a1\n");
    ASSERT_EQ(linux_self_phy_macs(NULL, g_platform.sys_list, out, 4, 0), 0);
    ASSERT_EQ(linux_self_phy_macs(g_platform.sys_read, NULL, out, 4, 0), 0);
    ASSERT_EQ(linux_self_phy_macs(g_platform.sys_read, g_platform.sys_list,
                                  out, 4, 0), 1);
    ASSERT_EQ(g_fake_net.sys_outside_calls, 0);
    fake_net_reset();
}

/* ── wireless devices with no netdev, over nl80211 ──────── */

#define FAKE_NL80211 0x1c

/* One genetlink message: nlmsghdr, genlmsghdr (cmd u8, version u8,
 * reserved u16), then attributes. */
static size_t wdev_msg(uint8_t *b, size_t o, uint16_t family, uint8_t cmd,
                       uint32_t iftype, const uint8_t *mac, size_t mlen) {
    size_t start = o;
    o += 16;
    b[o] = cmd; b[o + 1] = 1; put16(b, o + 2, 0);
    o += 4;
    uint64_t wdev = 0x100000002ull;
    o = attr(b, o, NL80211_ATTR_WDEV, &wdev, 8);
    o = attr(b, o, NL80211_ATTR_IFTYPE, &iftype, 4);
    if (mlen) o = attr(b, o, NL80211_ATTR_MAC, mac, mlen);
    hdr(b, start, o, family);
    return o;
}

/* wpa_supplicant's P2P device has no netdev, so neither rtnetlink nor
 * /sys/class/net names it; its P2P discovery probes leave the card from
 * this locally administered address. */
static void test_wdev_p2p_device_and_station(void) {
    uint8_t b[512];
    size_t o = wdev_msg(b, 0, FAKE_NL80211, NL80211_CMD_NEW_INTERFACE,
                        NL80211_IFTYPE_P2P_DEVICE, P2P_DEV, 6);
    o = wdev_msg(b, o, FAKE_NL80211, NL80211_CMD_NEW_INTERFACE,
                 NL80211_IFTYPE_STATION, CARD_RAND, 6);
    o = done_msg(b, o);
    uint8_t out[8][6];
    int done = 0;
    int n = linux_wifi_parse_wdev_macs(b, o, FAKE_NL80211, out, 8, 0, &done);
    ASSERT_EQ(n, 2);
    ASSERT_EQ(done, 1);
    ASSERT(has(out, n, P2P_DEV));
    ASSERT(has(out, n, CARD_RAND));
}

/* Another family's message, another command, and a MAC attribute of
 * the wrong length are not interface addresses. */
static void test_wdev_wrong_family_cmd_or_length(void) {
    uint8_t b[512];
    size_t o = wdev_msg(b, 0, FAKE_NL80211 + 1, NL80211_CMD_NEW_INTERFACE,
                        NL80211_IFTYPE_STATION, CARD_PERM, 6);
    o = wdev_msg(b, o, FAKE_NL80211, NL80211_CMD_NEW_STATION,
                 NL80211_IFTYPE_STATION, CARD_PERM, 6);
    o = wdev_msg(b, o, FAKE_NL80211, NL80211_CMD_NEW_INTERFACE,
                 NL80211_IFTYPE_STATION, CARD_PERM, 5);
    o = wdev_msg(b, o, FAKE_NL80211, NL80211_CMD_NEW_INTERFACE,
                 NL80211_IFTYPE_MONITOR, ZERO6, 6);
    uint8_t out[8][6];
    ASSERT_EQ(linux_wifi_parse_wdev_macs(b, o, FAKE_NL80211, out, 8, 0, NULL), 0);
    ASSERT_EQ(linux_wifi_parse_wdev_macs(NULL, 32, FAKE_NL80211, out, 8, 0, NULL), 0);
}
#endif /* PLATFORM_LINUX */

/* ── the roster's bound and the stage's throttle ────────── */

/* Per-connection randomisation hands the card a new address on every
 * association. Past the bound the newest address is the one in use,
 * so the stalest entry gives way, never the newcomer. An address
 * confirmed again is not the stalest. */
static void test_roster_full_evicts_the_stalest(void) {
    ownership_clear();
    uint8_t first[6] = {0x02,0,0,0,0,0};
    uint8_t second[6] = {0x02,0,0,0,0,1};
    ASSERT(ownership_self_add(first));
    ASSERT(ownership_self_add(second));
    for (int i = 2; i < MAX_SELF_MACS; i++) {
        uint8_t m[6] = {0x02,0,0,0,(uint8_t)(i >> 8),(uint8_t)i};
        ASSERT_EQ(ownership_self_add(m), 1);
    }
    ASSERT_EQ(ownership_self_count(), MAX_SELF_MACS);
    ASSERT(ownership_self_add(first));          /* confirmed again */
    uint8_t now[6] = {0x5a,0x10,0x7e,0x33,0x02,0x9c};
    ASSERT_EQ(ownership_self_add(now), 1);
    ASSERT_EQ(ownership_self_count(), MAX_SELF_MACS);
    ASSERT_EQ(ownership_is_self_mac(now), 1);
    ASSERT_EQ(ownership_is_self_mac(first), 1);
    ASSERT_EQ(ownership_is_self_mac(second), 0);
    ownership_clear();
}

static void test_add_list_rules_and_nulls(void) {
    ownership_clear();
    const uint8_t l[4][6] = {
        {0x24,0x41,0x8c,0x30,0x97,0xa1},
        {0},
        {0x01,0x00,0x5e,0x00,0x00,0x01},
        {0x26,0x41,0x8c,0x30,0x97,0xa1},
    };
    ASSERT_EQ(ownership_self_add_list(l, 4), 2);
    ASSERT_EQ(ownership_self_count(), 2);
    ASSERT_EQ(ownership_self_add_list(NULL, 4), 0);
    ASSERT_EQ(ownership_self_add_list(l, 0), 0);
    ownership_clear();
}

static void one_iface(iface_stat_t *f, const char *name, const uint8_t mac[6]) {
    memset(f, 0, sizeof(*f));
    snprintf(f->name, sizeof(f->name), "%s", name);
    memcpy(f->mac, mac, 6);
}

/* First call, a changed interface set (a monitor vif created, a card
 * re-addressed), and the timer say yes; a counter moving does not. */
static void test_scan_due_first_change_and_timer(void) {
    ownership_clear();
    const uint8_t a[6] = {0x24,0x41,0x8c,0x30,0x97,0xa1};
    const uint8_t r[6] = {0x5a,0x10,0x7e,0x33,0x02,0x9c};
    iface_stat_t f[2];
    one_iface(&f[0], "wlan0", a);
    ASSERT_EQ(ownership_self_scan_due(f, 1, 1000), 1);
    ASSERT_EQ(ownership_self_scan_due(f, 1, 2000), 0);
    f[0].rx_bytes = 123456;                            /* traffic only */
    ASSERT_EQ(ownership_self_scan_due(f, 1, 3000), 0);
    one_iface(&f[1], "wlan0mon", a);
    ASSERT_EQ(ownership_self_scan_due(f, 2, 4000), 1); /* a vif appeared */
    ASSERT_EQ(ownership_self_scan_due(f, 2, 5000), 0);
    memcpy(f[0].mac, r, 6);
    ASSERT_EQ(ownership_self_scan_due(f, 2, 6000), 1); /* re-addressed */
    ASSERT_EQ(ownership_self_scan_due(f, 2, 6000 + SELF_RESCAN_MS - 1), 0);
    ASSERT_EQ(ownership_self_scan_due(f, 2, 6000 + SELF_RESCAN_MS), 1);
    /* A clock that went backwards is not "not yet". */
    ASSERT_EQ(ownership_self_scan_due(f, 2, 10), 1);
    ownership_clear();
    ASSERT_EQ(ownership_self_scan_due(f, 2, 10), 1);   /* cleared */
    ownership_clear();
}

/* ── the PLATFORM stage ────────────────────────────────── */

/* The tick rosters what get_self_macs() names besides the iface rows,
 * asks once per interface-set change or timer, and an address only it
 * names (the P2P device) is "ours" to every exoneration. */
static void test_tick_rosters_platform_self_macs(void) {
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    fake_net_reset();
    ownership_clear();
    const uint8_t card[6] = {0x5a,0x10,0x7e,0x33,0x02,0x9c};
    const uint8_t perm[6] = {0x24,0x41,0x8c,0x30,0x97,0xa1};
    const uint8_t p2p[6]  = {0x26,0x41,0x8c,0x30,0x97,0xa1};
    one_iface(&g_fake_net.ifaces[0], "wlan0", card);
    g_fake_net.iface_count = 1;
    memcpy(g_fake_net.self_macs[0], perm, 6);
    memcpy(g_fake_net.self_macs[1], p2p, 6);
    memcpy(g_fake_net.self_macs[2], perm, 6);          /* duplicate */
    g_fake_net.self_mac_count = 3;

    poll_ctx_t ctx;
    poll_ctx_init(&ctx);
    poll_tick(&s, &ctx);
    ASSERT_EQ(g_fake_net.self_mac_calls, 1);
    ASSERT_EQ(ownership_is_self_mac(card), 1);
    ASSERT_EQ(ownership_is_self_mac(perm), 1);
    ASSERT_EQ(ownership_is_self_mac(p2p), 1);
    ASSERT_EQ(ownership_is_own_device(p2p), 1);
    ASSERT_EQ(ownership_self_count(), 3);

    /* Same interfaces, a second later: not asked again. */
    ctx.mono_ms += 1000;
    poll_tick(&s, &ctx);
    ASSERT_EQ(g_fake_net.self_mac_calls, 1);

    /* A monitor vif appears: asked at once, and a pool address the phy
     * gave it is rostered on that tick. */
    const uint8_t vif[6] = {0x24,0x41,0x8c,0x30,0x97,0xa2};
    one_iface(&g_fake_net.ifaces[1], "wlan0mon", vif);
    g_fake_net.iface_count = 2;
    memcpy(g_fake_net.self_macs[3], vif, 6);
    g_fake_net.self_mac_count = 4;
    ctx.mono_ms += 1000;
    poll_tick(&s, &ctx);
    ASSERT_EQ(g_fake_net.self_mac_calls, 2);

    /* Nothing in the interface set changes, but a P2P device came up:
     * the timer finds it. */
    const uint8_t nan[6] = {0x2a,0x41,0x8c,0x30,0x97,0xa1};
    memcpy(g_fake_net.self_macs[4], nan, 6);
    g_fake_net.self_mac_count = 5;
    ctx.mono_ms += SELF_RESCAN_MS;
    poll_tick(&s, &ctx);
    ASSERT_EQ(g_fake_net.self_mac_calls, 3);
    ASSERT_EQ(ownership_is_self_mac(nan), 1);

    /* A stranger stays one. */
    const uint8_t other[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
    ASSERT_EQ(ownership_is_self_mac(other), 0);
    ownership_clear();
    fake_net_reset();
}

/* The issue's first fixture, for an address no iface row names: 25
 * directed probes for the designated SSID over 700 s from the P2P
 * device's locally administered address. Rostered by the tick, it does
 * not fire; with g_platform.get_self_macs taken away (the platforms
 * that have none, and the state before this slice) the same probes
 * fire at WARN — the mutation, kept as the control. */
static void recon_from_p2p(sloth_state_t *s, const uint8_t p2p[6]) {
    alerts_clear();
    pnl_client_t *c = &s->pnl_clients[s->pnl_count++];
    memset(c, 0, sizeof(*c));
    memcpy(c->mac, p2p, 6);
    snprintf(c->ssids[0], 33, "%s", "CeilingCatHD");
    c->ssid_count  = 1;
    time_t now = time(NULL);
    c->first_seen  = now - 700;
    c->last_seen   = now;
    c->probe_count = 25;
    alerts_update(s);
}

static int recon_fired(const sloth_state_t *s) {
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == ALERT_TYPE_MY_NETWORK_RECON) return 1;
    return 0;
}

static void test_recon_from_p2p_device_exonerated(void) {
    static sloth_state_t s;
    const uint8_t card[6] = {0x24,0x41,0x8c,0x30,0x97,0xa1};
    const uint8_t p2p[6]  = {0x26,0x41,0x8c,0x30,0x97,0xa1};
    poll_ctx_t ctx;

    for (int with = 1; with >= 0; with--) {
        memset(&s, 0, sizeof(s));
        fake_net_reset();
        ownership_clear();
        alerts_clear();
        ownership_add_ssid("CeilingCatHD");
        one_iface(&g_fake_net.ifaces[0], "wlan0", card);
        g_fake_net.iface_count = 1;
        memcpy(g_fake_net.self_macs[0], p2p, 6);
        g_fake_net.self_mac_count = 1;
        int (*saved)(uint8_t (*)[6], int) = g_platform.get_self_macs;
        if (!with) g_platform.get_self_macs = NULL;
        poll_ctx_init(&ctx);
        poll_tick(&s, &ctx);
        g_platform.get_self_macs = saved;
        s.pnl_count = 0;
        recon_from_p2p(&s, p2p);
        ASSERT_EQ(recon_fired(&s), with ? 0 : 1);
    }
    alerts_clear();
    ownership_clear();
    fake_net_reset();
}

void run_self_macs_tests(void) {
    TEST_SUITE("the host's own addresses beyond the iface rows (#183)");
#ifdef PLATFORM_LINUX
    RUN_TEST(test_links_address_and_permanent_address);
    RUN_TEST(test_links_skip_non_addresses_and_stop_at_done);
    RUN_TEST(test_links_dedupe_bound_and_append);
    RUN_TEST(test_links_truncated_message);
    RUN_TEST(test_parse_mac_token);
    RUN_TEST(test_phy_macaddress_and_pool);
    RUN_TEST(test_phy_absent_and_null_readers);
    RUN_TEST(test_wdev_p2p_device_and_station);
    RUN_TEST(test_wdev_wrong_family_cmd_or_length);
#endif
    RUN_TEST(test_roster_full_evicts_the_stalest);
    RUN_TEST(test_add_list_rules_and_nulls);
    RUN_TEST(test_scan_due_first_change_and_timer);
    RUN_TEST(test_tick_rosters_platform_self_macs);
    RUN_TEST(test_recon_from_p2p_device_exonerated);
}
