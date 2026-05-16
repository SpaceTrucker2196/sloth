#include <stdio.h>
#include <string.h>

#include "runner.h"
#include "ntop.h"
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
}
