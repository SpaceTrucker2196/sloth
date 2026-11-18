#include <stdio.h>
#include <string.h>

#include "runner.h"
#include "sloth.h"
#include "platform/linux_parse.h"

/* ── /proc/net/dev fixtures ─────────────────────────────── */

static const char *PROC_NET_DEV_BASIC =
    "Inter-|   Receive                                              |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
    "   lo: 188924    1234    0    0    0     0          0         0   188924    1234    0    0    0     0       0          0\n"
    " eth0: 1500000   15000    2    1    0     0          0         3   750000    7500    0    0    0     0       0          0\n"
    "wlan0:   64000     640    0    0    0     0          0         0    32000     320    0    0    0     0       0          0\n";

static const char *PROC_NET_DEV_EMPTY =
    "Inter-|   Receive                                              |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n";

static const char *PROC_NET_DEV_MALFORMED =
    "Inter-|header\n"
    " face |header\n"
    "  bad_line_no_colon\n"
    " eth0: not_numbers_here\n"
    "  lo: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16\n";

/* ── /proc/net/tcp fixture ──────────────────────────────── */
/*
 * 7F000001 = 127.0.0.1 (loopback, little-endian)
 * 0101007F = 127.0.1.1
 * state 0A = LISTEN, 01 = ESTABLISHED
 */
static const char *PROC_NET_TCP =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    "   0: 0101007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 12345 1 0000000000000000 100 0 0 10 0\n"
    "   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 23456 1 0000000000000000 100 0 0 10 0\n"
    "   2: 0A01A8C0:C738 08080808:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 34567 1 0000000000000000 100 0 0 10 0\n";

/* 0A01A8C0 little-endian = 192.168.1.10, C738 = 50992, 08080808 = 8.8.8.8, 01BB = 443 */

static const char *PROC_NET_UDP =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    "   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 99999 2 0000000000000000\n";

/* ── parse_hex_addr tests ───────────────────────────────── */

void test_hex_addr_loopback(void) {
    char addr[46];
    uint16_t port;
    parse_hex_addr("0100007F:0050", addr, &port);
    ASSERT_STR(addr, "127.0.0.1");
    ASSERT_EQ(port, 80);
}

void test_hex_addr_zero(void) {
    char addr[46];
    uint16_t port;
    parse_hex_addr("00000000:0000", addr, &port);
    ASSERT_STR(addr, "0.0.0.0");
    ASSERT_EQ(port, 0);
}

void test_hex_addr_dns_port(void) {
    char addr[46];
    uint16_t port;
    parse_hex_addr("0101007F:0035", addr, &port);
    ASSERT_STR(addr, "127.0.1.1");
    ASSERT_EQ(port, 53);
}

void test_hex_addr_established(void) {
    char addr[46];
    uint16_t port;
    /* 192.168.1.10 = C0 A8 01 0A → little-endian: 0A 01 A8 C0 → 0x0A01A8C0 */
    parse_hex_addr("0A01A8C0:C738", addr, &port);
    ASSERT_STR(addr, "192.168.1.10");
    ASSERT_EQ(port, 0xC738);
}

/* ── parse_proc_ifaces tests ────────────────────────────── */

void test_parse_ifaces_basic(void) {
    FILE *f = tmpfile();
    fputs(PROC_NET_DEV_BASIC, f);
    rewind(f);

    iface_stat_t stats[MAX_IFACES];
    int n = parse_proc_ifaces(f, stats, MAX_IFACES);
    fclose(f);

    ASSERT_EQ(n, 3);
    ASSERT_STR(stats[0].name, "lo");
    ASSERT_EQ((unsigned long long)stats[0].rx_bytes,   188924ULL);
    ASSERT_EQ((unsigned long long)stats[0].tx_bytes,   188924ULL);
    ASSERT_EQ((unsigned long long)stats[0].rx_packets,   1234ULL);
    ASSERT_EQ(stats[0].rx_rate, 0.0);   /* rates always zero from parser */

    ASSERT_STR(stats[1].name, "eth0");
    ASSERT_EQ((unsigned long long)stats[1].rx_bytes,  1500000ULL);
    ASSERT_EQ((unsigned long long)stats[1].tx_bytes,   750000ULL);
    ASSERT_EQ((unsigned long long)stats[1].rx_packets,  15000ULL);

    ASSERT_STR(stats[2].name, "wlan0");
    ASSERT_EQ((unsigned long long)stats[2].rx_bytes, 64000ULL);
}

void test_parse_ifaces_empty(void) {
    FILE *f = tmpfile();
    fputs(PROC_NET_DEV_EMPTY, f);
    rewind(f);

    iface_stat_t stats[MAX_IFACES];
    int n = parse_proc_ifaces(f, stats, MAX_IFACES);
    fclose(f);

    ASSERT_EQ(n, 0);
}

void test_parse_ifaces_max_limit(void) {
    FILE *f = tmpfile();
    fputs(PROC_NET_DEV_BASIC, f);
    rewind(f);

    iface_stat_t stats[2];
    int n = parse_proc_ifaces(f, stats, 2);   /* cap at 2 */
    fclose(f);

    ASSERT_EQ(n, 2);
    ASSERT_STR(stats[0].name, "lo");
    ASSERT_STR(stats[1].name, "eth0");
}

void test_parse_ifaces_malformed_skipped(void) {
    FILE *f = tmpfile();
    fputs(PROC_NET_DEV_MALFORMED, f);
    rewind(f);

    iface_stat_t stats[MAX_IFACES];
    int n = parse_proc_ifaces(f, stats, MAX_IFACES);
    fclose(f);

    /* only "lo:" line has enough valid columns to parse */
    ASSERT_EQ(n, 1);
    ASSERT_STR(stats[0].name, "lo");
}

void test_parse_ifaces_name_fits(void) {
    /* Interface name exactly 15 chars should not overflow */
    const char *data =
        "header1\n"
        "header2\n"
        "123456789012345: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16\n";
    FILE *f = tmpfile();
    fputs(data, f);
    rewind(f);

    iface_stat_t stats[MAX_IFACES];
    int n = parse_proc_ifaces(f, stats, MAX_IFACES);
    fclose(f);

    ASSERT_EQ(n, 1);
    ASSERT_EQ((int)strlen(stats[0].name), 15);
}

/* ── parse_proc_conns tests ─────────────────────────────── */

void test_parse_conns_tcp_basic(void) {
    FILE *f = tmpfile();
    fputs(PROC_NET_TCP, f);
    rewind(f);

    conn_t conns[MAX_CONNS];
    int n = 0;
    parse_proc_conns(f, PROTO_TCP, conns, MAX_CONNS, &n);
    fclose(f);

    ASSERT_EQ(n, 3);
    ASSERT_EQ(conns[0].proto, PROTO_TCP);
    ASSERT_EQ(conns[0].state, 0x0A);       /* LISTEN */
    ASSERT_STR(conns[0].local_addr, "127.0.1.1");
    ASSERT_EQ(conns[0].local_port, 53);

    ASSERT_EQ(conns[2].state, 0x01);       /* ESTABLISHED */
    ASSERT_STR(conns[2].local_addr, "192.168.1.10");
    ASSERT_EQ(conns[2].local_port, 0xC738);
    ASSERT_STR(conns[2].remote_addr, "8.8.8.8");
    ASSERT_EQ(conns[2].remote_port, 443);
}

void test_parse_conns_udp_basic(void) {
    FILE *f = tmpfile();
    fputs(PROC_NET_UDP, f);
    rewind(f);

    conn_t conns[MAX_CONNS];
    int n = 0;
    parse_proc_conns(f, PROTO_UDP, conns, MAX_CONNS, &n);
    fclose(f);

    ASSERT_EQ(n, 1);
    ASSERT_EQ(conns[0].proto, PROTO_UDP);
    ASSERT_EQ(conns[0].local_port, 53);
}

void test_parse_conns_appends(void) {
    /* Verify that parse_proc_conns appends to an existing array */
    FILE *f1 = tmpfile();
    FILE *f2 = tmpfile();
    fputs(PROC_NET_TCP, f1);
    fputs(PROC_NET_UDP, f2);
    rewind(f1);
    rewind(f2);

    conn_t conns[MAX_CONNS];
    int n = 0;
    parse_proc_conns(f1, PROTO_TCP, conns, MAX_CONNS, &n);
    parse_proc_conns(f2, PROTO_UDP, conns, MAX_CONNS, &n);
    fclose(f1);
    fclose(f2);

    ASSERT_EQ(n, 4);                     /* 3 TCP + 1 UDP */
    ASSERT_EQ(conns[3].proto, PROTO_UDP);
}

void test_parse_conns_max_limit(void) {
    FILE *f = tmpfile();
    fputs(PROC_NET_TCP, f);
    rewind(f);

    conn_t conns[1];
    int n = 0;
    parse_proc_conns(f, PROTO_TCP, conns, 1, &n);   /* cap at 1 */
    fclose(f);

    ASSERT_EQ(n, 1);
}

/* ── /proc/net/tcp6 fixture ─────────────────────────────── */
/*
 * ::1 local port 53 (LISTEN), remote ::  port 0
 * w[3] = 0x01000000 → b[12..15] = 00 00 00 01 → ::1
 */
static const char *PROC_NET_TCP6 =
    "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    "   0: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 55555\n";

/* ── parse_hex_addr6 tests ──────────────────────────────── */

void test_hex_addr6_loopback(void) {
    char addr[46];
    uint16_t port;
    /* ::1, port 80 */
    parse_hex_addr6("00000000000000000000000001000000:0050", addr, &port);
    ASSERT_STR(addr, "::1");
    ASSERT_EQ(port, 80);
}

void test_hex_addr6_all_zeros(void) {
    char addr[46];
    uint16_t port;
    parse_hex_addr6("00000000000000000000000000000000:0000", addr, &port);
    ASSERT_STR(addr, "::");
    ASSERT_EQ(port, 0);
}

void test_hex_addr6_ipv4_mapped(void) {
    char addr[46];
    uint16_t port;
    /* ::ffff:8.8.8.8 (port 443) */
    parse_hex_addr6("0000000000000000ffff000008080808:01BB", addr, &port);
    ASSERT_STR(addr, "::ffff:8.8.8.8");
    ASSERT_EQ(port, 443);
}

/* ── parse_proc_conns6 tests ────────────────────────────── */

void test_parse_conns6_listen(void) {
    FILE *f = tmpfile();
    fputs(PROC_NET_TCP6, f);
    rewind(f);

    conn_t conns[MAX_CONNS];
    int n = 0;
    parse_proc_conns6(f, PROTO_TCP, conns, MAX_CONNS, &n);
    fclose(f);

    ASSERT_EQ(n, 1);
    ASSERT_EQ(conns[0].proto, PROTO_TCP);
    ASSERT_EQ(conns[0].state, 0x0A);  /* LISTEN */
    ASSERT_STR(conns[0].local_addr, "::1");
    ASSERT_EQ(conns[0].local_port, 53);
    ASSERT_EQ(conns[0].inode, 55555UL);
}

void test_parse_conns6_appends(void) {
    /* Verify conns6 appends after existing IPv4 entries */
    FILE *f4 = tmpfile();
    FILE *f6 = tmpfile();
    fputs(PROC_NET_TCP, f4);
    fputs(PROC_NET_TCP6, f6);
    rewind(f4);
    rewind(f6);

    conn_t conns[MAX_CONNS];
    int n = 0;
    parse_proc_conns(f4,  PROTO_TCP, conns, MAX_CONNS, &n);
    parse_proc_conns6(f6, PROTO_TCP, conns, MAX_CONNS, &n);
    fclose(f4);
    fclose(f6);

    ASSERT_EQ(n, 4);  /* 3 IPv4 + 1 IPv6 */
    ASSERT_STR(conns[3].local_addr, "::1");
}

/* ── IPv6 neighbour cache over rtnetlink (#176) ──────────── */
#ifdef PLATFORM_LINUX
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include "platform/linux_neigh.h"

/* Messages built from the kernel ABI, not captured: struct nlmsghdr
 * (len u32, type u16, flags u16, seq u32, pid u32), struct ndmsg
 * (family u8, pad u8, pad u16, ifindex s32, state u16, flags u8,
 * type u8), then struct rtattr (len u16, type u16) + payload, every
 * length and payload padded to NLMSG_ALIGNTO (4). Host byte order,
 * which is what netlink speaks. */
static size_t nl_put16(uint8_t *b, size_t o, uint16_t v) { memcpy(b + o, &v, 2); return o + 2; }
static size_t nl_put32(uint8_t *b, size_t o, uint32_t v) { memcpy(b + o, &v, 4); return o + 4; }
static size_t nl_align(size_t o) { return (o + 3u) & ~(size_t)3u; }

static size_t nl_attr(uint8_t *b, size_t o, uint16_t type, const void *p, size_t n) {
    o = nl_put16(b, o, (uint16_t)(4 + n));
    o = nl_put16(b, o, type);
    memcpy(b + o, p, n);
    memset(b + o + n, 0, nl_align(n) - n);
    return o + nl_align(n);
}

/* One neighbour message at b+o. dstlen 0 / lllen 0 leaves that attribute
 * out. Returns the offset past it. */
static size_t nl_neigh(uint8_t *b, size_t o, uint16_t msgtype, uint8_t family,
                       int ifindex, uint16_t state, uint8_t flags,
                       const uint8_t *dst, size_t dstlen,
                       const uint8_t *ll, size_t lllen) {
    size_t start = o;
    o += 16;                                  /* nlmsghdr, filled below */
    b[o] = family; b[o + 1] = 0; nl_put16(b, o + 2, 0);
    nl_put32(b, o + 4, (uint32_t)ifindex);
    nl_put16(b, o + 8, state);
    b[o + 10] = flags; b[o + 11] = 0;
    o += 12;
    if (dstlen) o = nl_attr(b, o, NDA_DST, dst, dstlen);
    if (lllen)  o = nl_attr(b, o, NDA_LLADDR, ll, lllen);
    nl_put32(b, start, (uint32_t)(o - start));
    nl_put16(b, start + 4, msgtype);
    nl_put16(b, start + 6, NLM_F_MULTI);
    nl_put32(b, start + 8, 1);
    nl_put32(b, start + 12, 0);
    return o;
}

static size_t nl_done(uint8_t *b, size_t o) {
    nl_put32(b, o, 20);
    nl_put16(b, o + 4, NLMSG_DONE);
    nl_put16(b, o + 6, NLM_F_MULTI);
    nl_put32(b, o + 8, 1);
    nl_put32(b, o + 12, 0);
    nl_put32(b, o + 16, 0);                   /* the dump's error, 0 */
    return o + 20;
}

static int fake_ifname(int ifindex, char *out, size_t outsz) {
    if (ifindex == 3) { snprintf(out, outsz, "wlan1"); return 0; }
    return -1;
}

static const uint8_t V6_GLOBAL[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0x01 };
static const uint8_t V6_LINK[16]   = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                       0x02, 0x00, 0x5e, 0xff, 0xfe, 0x00, 0x53, 0x01 };
static const uint8_t LL_A[6]       = { 0x02, 0x00, 0x5e, 0x00, 0x53, 0x01 };
static const uint8_t LL_ZERO[6]    = { 0, 0, 0, 0, 0, 0 };

static void test_neigh_parse_reachable_row(void) {
    uint8_t b[256];
    size_t o = nl_neigh(b, 0, RTM_NEWNEIGH, AF_INET6, 3, NUD_REACHABLE, 0,
                        V6_GLOBAL, 16, LL_A, 6);
    arp_entry_t out[4];
    int done = 0;
    int n = linux_neigh_parse(b, o, out, 4, 0, &done, fake_ifname);
    ASSERT_EQ(n, 1);
    ASSERT_EQ(done, 0);
    ASSERT_STR(out[0].ip, "2001:db8::1");
    ASSERT(memcmp(out[0].mac, LL_A, 6) == 0);
    ASSERT_STR(out[0].iface, "wlan1");
}

/* STALE, DELAY, PROBE and PERMANENT carry an address the kernel still
 * uses; a link-local row is a neighbour like any other. */
static void test_neigh_parse_resolved_states_and_link_local(void) {
    uint8_t b[512];
    size_t o = 0;
    o = nl_neigh(b, o, RTM_NEWNEIGH, AF_INET6, 3, NUD_STALE, 0, V6_LINK, 16, LL_A, 6);
    o = nl_neigh(b, o, RTM_NEWNEIGH, AF_INET6, 3, NUD_DELAY, 0, V6_GLOBAL, 16, LL_A, 6);
    o = nl_neigh(b, o, RTM_NEWNEIGH, AF_INET6, 3, NUD_PROBE, 0, V6_GLOBAL, 16, LL_A, 6);
    o = nl_neigh(b, o, RTM_NEWNEIGH, AF_INET6, 3, NUD_PERMANENT, 0, V6_GLOBAL, 16, LL_A, 6);
    arp_entry_t out[8];
    int done = 0;
    int n = linux_neigh_parse(b, o, out, 8, 0, &done, fake_ifname);
    ASSERT_EQ(n, 4);
    ASSERT_STR(out[0].ip, "fe80::200:5eff:fe00:5301");
}

/* The rows /proc/net/arp shows with an all-zero MAC: INCOMPLETE and
 * FAILED have no address, NOARP is a non-resolving link, a proxy entry
 * is this host's own answer, and a zero lladdr is nothing. Seen red
 * with NEIGH_RESOLVED widened to every state. */
static void test_neigh_parse_unresolved_skipped(void) {
    uint8_t b[768];
    size_t o = 0;
    o = nl_neigh(b, o, RTM_NEWNEIGH, AF_INET6, 3, NUD_INCOMPLETE, 0, V6_GLOBAL, 16, LL_A, 6);
    o = nl_neigh(b, o, RTM_NEWNEIGH, AF_INET6, 3, NUD_FAILED, 0, V6_GLOBAL, 16, LL_A, 6);
    o = nl_neigh(b, o, RTM_NEWNEIGH, AF_INET6, 3, NUD_NOARP, 0, V6_GLOBAL, 16, LL_A, 6);
    o = nl_neigh(b, o, RTM_NEWNEIGH, AF_INET6, 3, NUD_NONE, 0, V6_GLOBAL, 16, LL_A, 6);
    o = nl_neigh(b, o, RTM_NEWNEIGH, AF_INET6, 3, NUD_REACHABLE, NTF_PROXY, V6_GLOBAL, 16, LL_A, 6);
    o = nl_neigh(b, o, RTM_NEWNEIGH, AF_INET6, 3, NUD_REACHABLE, 0, V6_GLOBAL, 16, LL_ZERO, 6);
    arp_entry_t out[8];
    int done = 0;
    int n = linux_neigh_parse(b, o, out, 8, 0, &done, fake_ifname);
    ASSERT_EQ(n, 0);
}

/* The dump is asked for AF_INET6, and the parser holds it to that: an
 * IPv4 ndmsg, a delete, and anything after NLMSG_DONE are not rows. */
static void test_neigh_parse_family_type_and_done(void) {
    static const uint8_t v4[4] = { 192, 0, 2, 1 };
    uint8_t b[512];
    size_t o = 0;
    o = nl_neigh(b, o, RTM_NEWNEIGH, AF_INET, 3, NUD_REACHABLE, 0, v4, 4, LL_A, 6);
    o = nl_neigh(b, o, RTM_DELNEIGH, AF_INET6, 3, NUD_REACHABLE, 0, V6_GLOBAL, 16, LL_A, 6);
    o = nl_neigh(b, o, RTM_NEWNEIGH, AF_INET6, 3, NUD_REACHABLE, 0, V6_GLOBAL, 16, LL_A, 6);
    o = nl_done(b, o);
    o = nl_neigh(b, o, RTM_NEWNEIGH, AF_INET6, 3, NUD_REACHABLE, 0, V6_LINK, 16, LL_A, 6);
    arp_entry_t out[8];
    int done = 0;
    int n = linux_neigh_parse(b, o, out, 8, 0, &done, fake_ifname);
    ASSERT_EQ(n, 1);
    ASSERT_EQ(done, 1);
    ASSERT_STR(out[0].ip, "2001:db8::1");
}

/* A row needs both attributes at their one valid size: an InfiniBand
 * link address is 20 bytes and is not a MAC; a 4-byte destination is
 * not an IPv6 address. */
static void test_neigh_parse_missing_or_odd_attrs_skipped(void) {
    static const uint8_t ib[20] = { 0x80, 0 };
    static const uint8_t v4[4] = { 192, 0, 2, 1 };
    uint8_t b[512];
    size_t o = 0;
    o = nl_neigh(b, o, RTM_NEWNEIGH, AF_INET6, 3, NUD_REACHABLE, 0, V6_GLOBAL, 16, NULL, 0);
    o = nl_neigh(b, o, RTM_NEWNEIGH, AF_INET6, 3, NUD_REACHABLE, 0, NULL, 0, LL_A, 6);
    o = nl_neigh(b, o, RTM_NEWNEIGH, AF_INET6, 3, NUD_REACHABLE, 0, V6_GLOBAL, 16, ib, 20);
    o = nl_neigh(b, o, RTM_NEWNEIGH, AF_INET6, 3, NUD_REACHABLE, 0, v4, 4, LL_A, 6);
    arp_entry_t out[8];
    int done = 0;
    int n = linux_neigh_parse(b, o, out, 8, 0, &done, fake_ifname);
    ASSERT_EQ(n, 0);
}

/* A header whose length runs past the buffer ends the walk before the
 * message is read; a message shorter than an ndmsg is skipped, and the
 * well-formed one after it is still a row. */
static void test_neigh_parse_truncated(void) {
    uint8_t b[512];
    size_t o = nl_neigh(b, 0, RTM_NEWNEIGH, AF_INET6, 3, NUD_REACHABLE, 0, V6_GLOBAL, 16, LL_A, 6);
    arp_entry_t out[4];
    int done = 0;
    /* Cut: the header promises o bytes, the buffer has o - 8. */
    ASSERT_EQ(linux_neigh_parse(b, o - 8, out, 4, 0, &done, fake_ifname), 0);
    /* Short: a 16-byte RTM_NEWNEIGH with no ndmsg, then a whole one. */
    size_t p = 0;
    nl_put32(b, p, 16); nl_put16(b, p + 4, RTM_NEWNEIGH); nl_put16(b, p + 6, 0);
    nl_put32(b, p + 8, 1); nl_put32(b, p + 12, 0);
    p = 16;
    p = nl_neigh(b, p, RTM_NEWNEIGH, AF_INET6, 3, NUD_REACHABLE, 0, V6_GLOBAL, 16, LL_A, 6);
    ASSERT_EQ(linux_neigh_parse(b, p, out, 4, 0, &done, fake_ifname), 1);
    ASSERT_STR(out[0].ip, "2001:db8::1");
}

/* The table's cap holds, counting from the rows already there; an
 * interface the callback cannot name leaves the row's iface empty. */
static void test_neigh_parse_cap_and_unnamed_iface(void) {
    uint8_t b[512];
    size_t o = 0;
    o = nl_neigh(b, o, RTM_NEWNEIGH, AF_INET6, 7, NUD_REACHABLE, 0, V6_GLOBAL, 16, LL_A, 6);
    o = nl_neigh(b, o, RTM_NEWNEIGH, AF_INET6, 3, NUD_REACHABLE, 0, V6_LINK, 16, LL_A, 6);
    arp_entry_t out[4];
    memset(out, 0, sizeof(out));
    snprintf(out[0].ip, sizeof(out[0].ip), "192.0.2.9");
    int done = 0;
    int n = linux_neigh_parse(b, o, out, 2, 1, &done, fake_ifname);
    ASSERT_EQ(n, 2);
    ASSERT_STR(out[0].ip, "192.0.2.9");
    ASSERT_STR(out[1].ip, "2001:db8::1");
    ASSERT_STR(out[1].iface, "");
    n = linux_neigh_parse(b, o, out, 4, 1, &done, NULL);
    ASSERT_EQ(n, 3);
    ASSERT_STR(out[2].iface, "");
}
#endif /* PLATFORM_LINUX */

void run_parse_tests(void) {
    TEST_SUITE("parse_hex_addr");
    RUN_TEST(test_hex_addr_loopback);
    RUN_TEST(test_hex_addr_zero);
    RUN_TEST(test_hex_addr_dns_port);
    RUN_TEST(test_hex_addr_established);

    TEST_SUITE("parse_proc_ifaces");
    RUN_TEST(test_parse_ifaces_basic);
    RUN_TEST(test_parse_ifaces_empty);
    RUN_TEST(test_parse_ifaces_max_limit);
    RUN_TEST(test_parse_ifaces_malformed_skipped);
    RUN_TEST(test_parse_ifaces_name_fits);

    TEST_SUITE("parse_proc_conns");
    RUN_TEST(test_parse_conns_tcp_basic);
    RUN_TEST(test_parse_conns_udp_basic);
    RUN_TEST(test_parse_conns_appends);
    RUN_TEST(test_parse_conns_max_limit);

    TEST_SUITE("parse_hex_addr6");
    RUN_TEST(test_hex_addr6_loopback);
    RUN_TEST(test_hex_addr6_all_zeros);
    RUN_TEST(test_hex_addr6_ipv4_mapped);

    TEST_SUITE("parse_proc_conns6");
    RUN_TEST(test_parse_conns6_listen);
    RUN_TEST(test_parse_conns6_appends);

#ifdef PLATFORM_LINUX
    TEST_SUITE("linux_neigh_parse");
    RUN_TEST(test_neigh_parse_reachable_row);
    RUN_TEST(test_neigh_parse_resolved_states_and_link_local);
    RUN_TEST(test_neigh_parse_unresolved_skipped);
    RUN_TEST(test_neigh_parse_family_type_and_done);
    RUN_TEST(test_neigh_parse_missing_or_odd_attrs_skipped);
    RUN_TEST(test_neigh_parse_truncated);
    RUN_TEST(test_neigh_parse_cap_and_unnamed_iface);
#endif
}
