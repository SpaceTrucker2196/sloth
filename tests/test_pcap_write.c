#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "sloth.h"
#include "pcap_write.h"
#include "views/packets.h"

static uint32_t read_u32le(FILE *f) {
    uint8_t b[4];
    if (fread(b, 1, 4, f) != 4) return 0;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static void push_raw_pkt(sloth_state_t *s, uint32_t ts_sec,
                         uint8_t fill, uint16_t raw_len) {
    packet_info_t p;
    memset(&p, 0, sizeof(p));
    p.ts_sec  = ts_sec;
    p.len     = raw_len;
    p.raw_len = (raw_len > 64) ? 64 : raw_len;
    memset(p.raw, fill, p.raw_len);
    s->packets[s->pkt_head] = p;
    s->pkt_head = (s->pkt_head + 1) % MAX_PACKETS;
    if (s->pkt_count < MAX_PACKETS) s->pkt_count++;
}

/* ── Tests ───────────────────────────────────────────────── */

static void test_export_empty_ring(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    char path[128] = "";
    int n = pcap_export(&s, path, sizeof(path));
    ASSERT_EQ(n, 0);
    ASSERT(path[0] != '\0');
    FILE *f = fopen(path, "rb");
    ASSERT(f != NULL);
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fclose(f);
    remove(path);
    ASSERT_EQ((int)sz, 24);  /* global header only */
}

static void test_export_magic(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    char path[128] = "";
    pcap_export(&s, path, sizeof(path));
    FILE *f = fopen(path, "rb");
    ASSERT(f != NULL);
    uint32_t magic = read_u32le(f);
    fclose(f);
    remove(path);
    ASSERT_EQ((int)magic, (int)0xa1b2c3d4u);
}

static void test_export_default_dlt(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    /* pkt_linktype == 0 → must default to DLT_EN10MB (1) */
    char path[128] = "";
    pcap_export(&s, path, sizeof(path));
    FILE *f = fopen(path, "rb");
    ASSERT(f != NULL);
    fseek(f, 20, SEEK_SET);   /* DLT at byte offset 20 in global header */
    uint32_t dlt = read_u32le(f);
    fclose(f);
    remove(path);
    ASSERT_EQ((int)dlt, 1);
}

static void test_export_custom_dlt(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    s.pkt_linktype = 113;  /* DLT_LINUX_SLL */
    char path[128] = "";
    pcap_export(&s, path, sizeof(path));
    FILE *f = fopen(path, "rb");
    ASSERT(f != NULL);
    fseek(f, 20, SEEK_SET);
    uint32_t dlt = read_u32le(f);
    fclose(f);
    remove(path);
    ASSERT_EQ((int)dlt, 113);
}

static void test_export_skips_no_raw(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    /* raw_len==0 → push_raw_pkt leaves p.raw_len as 0 */
    for (int i = 0; i < 5; i++)
        push_raw_pkt(&s, (uint32_t)(1000 + i), 0, 0);
    char path[128] = "";
    int n = pcap_export(&s, path, sizeof(path));
    ASSERT_EQ(n, 0);
    FILE *f = fopen(path, "rb");
    ASSERT(f != NULL);
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fclose(f);
    remove(path);
    ASSERT_EQ((int)sz, 24);
}

static void test_export_counts_and_size(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_raw_pkt(&s, 1001, 0xAA, 20);
    push_raw_pkt(&s, 1002, 0xBB, 20);
    push_raw_pkt(&s, 1003, 0xCC, 20);
    char path[128] = "";
    int n = pcap_export(&s, path, sizeof(path));
    ASSERT_EQ(n, 3);
    /* 24 header + 3 * (16 rec_hdr + 20 data) = 132 */
    FILE *f = fopen(path, "rb");
    ASSERT(f != NULL);
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fclose(f);
    remove(path);
    ASSERT_EQ((int)sz, 132);
}

static void test_export_path_ends_with_pcap(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    char path[128] = "";
    pcap_export(&s, path, sizeof(path));
    int len = (int)strlen(path);
    ASSERT(len > 5);
    ASSERT_EQ(strcmp(path + len - 5, ".pcap"), 0);
    remove(path);
}

static void test_export_mixed_raw(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_raw_pkt(&s, 2001, 0x11, 14);   /* raw_len > 0 → counted */
    push_raw_pkt(&s, 2002, 0x00,  0);   /* raw_len == 0 → skipped */
    push_raw_pkt(&s, 2003, 0x22, 14);   /* raw_len > 0 → counted */
    char path[128] = "";
    int n = pcap_export(&s, path, sizeof(path));
    ASSERT_EQ(n, 2);
    /* 24 + 2 * (16 + 14) = 84 */
    FILE *f = fopen(path, "rb");
    ASSERT(f != NULL);
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fclose(f);
    remove(path);
    ASSERT_EQ((int)sz, 84);
}

/* ── Key handler integration ─────────────────────────────── */

static void test_w_key_sets_export_msg(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_raw_pkt(&s, 3001, 0xFF, 10);
    ASSERT_EQ(s.pkt_export_msg[0], '\0');
    view_packets_key(&s, 'w');
    ASSERT(s.pkt_export_msg[0] != '\0');
    /* extract filename from message ("saved N pkts -> FNAME") */
    const char *arrow = strstr(s.pkt_export_msg, "-> ");
    if (arrow) remove(arrow + 3);
}

void run_pcap_write_tests(void) {
    TEST_SUITE("pcap_export/header");
    RUN_TEST(test_export_empty_ring);
    RUN_TEST(test_export_magic);
    RUN_TEST(test_export_default_dlt);
    RUN_TEST(test_export_custom_dlt);

    TEST_SUITE("pcap_export/packets");
    RUN_TEST(test_export_skips_no_raw);
    RUN_TEST(test_export_counts_and_size);
    RUN_TEST(test_export_mixed_raw);

    TEST_SUITE("pcap_export/misc");
    RUN_TEST(test_export_path_ends_with_pcap);
    RUN_TEST(test_w_key_sets_export_msg);
}
