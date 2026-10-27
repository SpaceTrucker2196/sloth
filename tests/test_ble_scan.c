#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runner.h"
#include "ble_scan/ble_scan_cmd.h"

/*
 * sloth-ble-scan's pure half (src/ble_scan/ble_scan_cmd.c).
 *
 * The property: the helper can put exactly five command shapes (seven
 * with the extended pair) on its HCI socket, and none of them makes the
 * controller transmit. Expected bytes are written out here by hand from
 * the Core Specification v5.4, Vol 4 Part E — §5.4.1 for the packet
 * (opcode little-endian, OGF in the top six bits, then the parameter
 * length), §7.3.1/§7.3.2/§7.8.1/§7.8.10/§7.8.11/§7.8.64/§7.8.65 for
 * each command's parameters — never produced by the builder and fed
 * back to it.
 *
 * Absence assertions, each seen red under a named mutation and restored
 * byte-identical (docs/wiki/log.md, the 2026-10-26 sloth-ble-scan entry):
 *   - test_builder_never_produces_an_active_scan: BLES_SCAN_TYPE_PASSIVE
 *     set to 0x01 in the header;
 *   - test_gate_refuses_every_transmitting_command: the scan-type check
 *     dropped from the LE_SCAN_PARAMS case of bles_cmd_allowed(), and,
 *     separately, the per-PHY check from the extended case;
 *   - test_helper_is_not_linked_into_sloth: src/ble_scan/ble_scan_cmd.c
 *     appended to CORE_COMMON_SRCS in the Makefile.
 */

/* ── the builder, byte for byte ── */

static int built_is(int c, const uint8_t *want, size_t wn) {
    uint8_t b[BLES_CMD_MAX + 4];
    memset(b, 0xAA, sizeof(b));
    size_t n = bles_build(c, b, sizeof(b));
    if (n != wn || memcmp(b, want, wn) != 0) {
        fprintf(stderr, "    command %d: got", c);
        for (size_t i = 0; i < n; i++) fprintf(stderr, " %02x", b[i]);
        fprintf(stderr, "\n");
        return 0;
    }
    return 1;
}

static void test_builder_bytes_match_the_spec(void) {
    /* HCI_Reset, OGF 0x03 OCF 0x0003 → 0x0C03, no parameters (§7.3.2). */
    static const uint8_t reset[] = { 0x01, 0x03, 0x0C, 0x00 };
    /* Set Event Mask, 0x0C01, Event_Mask (8 octets, §7.3.1). The value
     * of the reference-host run: bit 61 LE Meta (octet 7, 0x20) set. */
    static const uint8_t evmask[] = { 0x01, 0x01, 0x0C, 0x08,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbf, 0x3d };
    /* LE Set Event Mask, OGF 0x08 OCF 0x0001 → 0x2001 (§7.8.1):
     * bit 1 LE Advertising Report, bit 12 LE Extended Advertising
     * Report (octet 1, 0x10). */
    static const uint8_t lemask[] = { 0x01, 0x01, 0x20, 0x08,
        0x02, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    /* LE Set Scan Parameters, 0x200B (§7.8.10): LE_Scan_Type 0x00
     * passive, LE_Scan_Interval 0x0060, LE_Scan_Window 0x0060,
     * Own_Address_Type 0x00, Scanning_Filter_Policy 0x00. */
    static const uint8_t params[] = { 0x01, 0x0B, 0x20, 0x07,
        0x00, 0x60, 0x00, 0x60, 0x00, 0x00, 0x00 };
    /* LE Set Scan Enable, 0x200C (§7.8.11): LE_Scan_Enable,
     * Filter_Duplicates 0x00. */
    static const uint8_t enable[]  = { 0x01, 0x0C, 0x20, 0x02, 0x01, 0x00 };
    static const uint8_t disable[] = { 0x01, 0x0C, 0x20, 0x02, 0x00, 0x00 };
    /* LE Set Extended Scan Parameters, 0x2041 (§7.8.64):
     * Own_Address_Type, Scanning_Filter_Policy, Scanning_PHYs 0x01 (1M),
     * then the one PHY's Scan_Type 0x00, Scan_Interval, Scan_Window. */
    static const uint8_t xparams[] = { 0x01, 0x41, 0x20, 0x08,
        0x00, 0x00, 0x01, 0x00, 0x60, 0x00, 0x60, 0x00 };
    /* LE Set Extended Scan Enable, 0x2042 (§7.8.65): Enable,
     * Filter_Duplicates, Duration 0x0000, Period 0x0000. */
    static const uint8_t xenable[]  = { 0x01, 0x42, 0x20, 0x06,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
    static const uint8_t xdisable[] = { 0x01, 0x42, 0x20, 0x06,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    ASSERT(built_is(BLES_CMD_RESET, reset, sizeof(reset)));
    ASSERT(built_is(BLES_CMD_SET_EVENT_MASK, evmask, sizeof(evmask)));
    ASSERT(built_is(BLES_CMD_LE_SET_EVENT_MASK, lemask, sizeof(lemask)));
    ASSERT(built_is(BLES_CMD_LE_SCAN_PARAMS, params, sizeof(params)));
    ASSERT(built_is(BLES_CMD_LE_SCAN_ENABLE, enable, sizeof(enable)));
    ASSERT(built_is(BLES_CMD_LE_SCAN_DISABLE, disable, sizeof(disable)));
    ASSERT(built_is(BLES_CMD_LE_EXT_SCAN_PARAMS, xparams, sizeof(xparams)));
    ASSERT(built_is(BLES_CMD_LE_EXT_SCAN_ENABLE, xenable, sizeof(xenable)));
    ASSERT(built_is(BLES_CMD_LE_EXT_SCAN_DISABLE, xdisable, sizeof(xdisable)));

    /* Opcodes by their OGF/OCF, not by the header's constants. */
    ASSERT_EQ(bles_opcode(BLES_CMD_RESET),              (0x03 << 10) | 0x0003);
    ASSERT_EQ(bles_opcode(BLES_CMD_LE_SCAN_PARAMS),     (0x08 << 10) | 0x000B);
    ASSERT_EQ(bles_opcode(BLES_CMD_LE_SCAN_ENABLE),     (0x08 << 10) | 0x000C);
    ASSERT_EQ(bles_opcode(BLES_CMD_LE_EXT_SCAN_PARAMS), (0x08 << 10) | 0x0041);
    ASSERT_EQ(bles_opcode(BLES_CMD_LE_EXT_SCAN_ENABLE), (0x08 << 10) | 0x0042);
}

static void test_builder_refuses_unknown_and_short(void) {
    uint8_t b[BLES_CMD_MAX];
    ASSERT_EQ(bles_build(-1, b, sizeof(b)), (size_t)0);
    ASSERT_EQ(bles_build(BLES_CMD_COUNT, b, sizeof(b)), (size_t)0);
    ASSERT_EQ(bles_build(0x7fffffff, b, sizeof(b)), (size_t)0);
    ASSERT_EQ(bles_opcode(BLES_CMD_COUNT), 0);
    /* A buffer one short of the packet: nothing, not a truncation. */
    ASSERT_EQ(bles_build(BLES_CMD_LE_SCAN_PARAMS, b, 10), (size_t)0);
    ASSERT_EQ(bles_build(BLES_CMD_RESET, b, 3), (size_t)0);
    ASSERT_EQ(bles_build(BLES_CMD_RESET, NULL, 8), (size_t)0);
    ASSERT_EQ(bles_build(BLES_CMD_SET_EVENT_MASK, b, BLES_CMD_MAX), (size_t)12);
}

/* Every value the builder accepts, and a margin either side: whatever
 * comes out passes the gate, and no scan-parameter packet carries a
 * scan type other than 0x00. The builder takes no scan-type argument,
 * so this is what "cannot produce type 1" means. */
static void test_builder_never_produces_an_active_scan(void) {
    int built = 0;
    for (int c = -4; c < BLES_CMD_COUNT + 4; c++) {
        uint8_t b[BLES_CMD_MAX];
        size_t n = bles_build(c, b, sizeof(b));
        if (n == 0) continue;
        built++;
        ASSERT(bles_cmd_allowed(b, n));
        uint16_t op = (uint16_t)(b[1] | (b[2] << 8));
        if (op == 0x200B) ASSERT_EQ(b[4], 0x00);
        if (op == 0x2041) {
            ASSERT_EQ(b[6], 0x01);   /* one PHY */
            ASSERT_EQ(b[7], 0x00);
        }
        /* Nothing outside the allow-listed opcodes. */
        ASSERT(op == 0x0C03 || op == 0x0C01 || op == 0x2001 || op == 0x200B ||
               op == 0x200C || op == 0x2041 || op == 0x2042);
    }
    ASSERT_EQ(built, BLES_CMD_COUNT);
}

/* ── the gate, against hand-built packets the builder cannot make ── */

static void test_gate_refuses_every_transmitting_command(void) {
    /* LE Set Scan Parameters with LE_Scan_Type 0x01 (active, §7.8.10):
     * sends SCAN_REQ. */
    static const uint8_t active[] = { 0x01, 0x0B, 0x20, 0x07,
        0x01, 0x60, 0x00, 0x60, 0x00, 0x00, 0x00 };
    ASSERT(!bles_cmd_allowed(active, sizeof(active)));
    /* Reserved scan types are not passive either. */
    static const uint8_t reserved[] = { 0x01, 0x0B, 0x20, 0x07,
        0x02, 0x60, 0x00, 0x60, 0x00, 0x00, 0x00 };
    ASSERT(!bles_cmd_allowed(reserved, sizeof(reserved)));
    /* Extended, one PHY, active. */
    static const uint8_t xactive[] = { 0x01, 0x41, 0x20, 0x08,
        0x00, 0x00, 0x01, 0x01, 0x60, 0x00, 0x60, 0x00 };
    ASSERT(!bles_cmd_allowed(xactive, sizeof(xactive)));
    /* Extended, 1M and Coded: passive on 1M, active on Coded. */
    static const uint8_t xmixed[] = { 0x01, 0x41, 0x20, 0x0D,
        0x00, 0x00, 0x05,
        0x00, 0x60, 0x00, 0x60, 0x00,
        0x01, 0x60, 0x00, 0x60, 0x00 };
    ASSERT(!bles_cmd_allowed(xmixed, sizeof(xmixed)));
    /* The same, both passive: admitted (the shape is legal, §7.8.64). */
    static const uint8_t xboth[] = { 0x01, 0x41, 0x20, 0x0D,
        0x00, 0x00, 0x05,
        0x00, 0x60, 0x00, 0x60, 0x00,
        0x00, 0x60, 0x00, 0x60, 0x00 };
    ASSERT(bles_cmd_allowed(xboth, sizeof(xboth)));
    /* Scanning_PHYs naming bit 1 (2M, which has no scan record) or no
     * PHY at all, and a record count that disagrees with the length. */
    static const uint8_t x2m[] = { 0x01, 0x41, 0x20, 0x08,
        0x00, 0x00, 0x02, 0x00, 0x60, 0x00, 0x60, 0x00 };
    ASSERT(!bles_cmd_allowed(x2m, sizeof(x2m)));
    static const uint8_t xnone[] = { 0x01, 0x41, 0x20, 0x03, 0x00, 0x00, 0x00 };
    ASSERT(!bles_cmd_allowed(xnone, sizeof(xnone)));
    static const uint8_t xshort[] = { 0x01, 0x41, 0x20, 0x08,
        0x00, 0x00, 0x05, 0x00, 0x60, 0x00, 0x60, 0x00 };
    ASSERT(!bles_cmd_allowed(xshort, sizeof(xshort)));

    /* Commands that transmit, each by its own opcode (Vol 4 Part E). */
    static const uint8_t adv_enable[]  = { 0x01, 0x0A, 0x20, 0x01, 0x01 };       /* §7.8.9  */
    static const uint8_t xadv_enable[] = { 0x01, 0x39, 0x20, 0x02, 0x00, 0x00 }; /* §7.8.56 */
    static const uint8_t create_conn[] = { 0x01, 0x0D, 0x20, 0x00 };             /* §7.8.12 */
    static const uint8_t inquiry[]     = { 0x01, 0x01, 0x04, 0x05,
        0x33, 0x8B, 0x9E, 0x08, 0x00 };                                           /* §7.1.1  */
    static const uint8_t page[]        = { 0x01, 0x05, 0x04, 0x00 };             /* §7.1.5  */
    static const uint8_t scan_enable[] = { 0x01, 0x1A, 0x0C, 0x01, 0x03 };       /* §7.3.18 */
    static const uint8_t vendor[]      = { 0x01, 0x01, 0xFC, 0x00 };             /* OGF 0x3F */
    ASSERT(!bles_cmd_allowed(adv_enable, sizeof(adv_enable)));
    ASSERT(!bles_cmd_allowed(xadv_enable, sizeof(xadv_enable)));
    ASSERT(!bles_cmd_allowed(create_conn, sizeof(create_conn)));
    ASSERT(!bles_cmd_allowed(inquiry, sizeof(inquiry)));
    ASSERT(!bles_cmd_allowed(page, sizeof(page)));
    ASSERT(!bles_cmd_allowed(scan_enable, sizeof(scan_enable)));
    ASSERT(!bles_cmd_allowed(vendor, sizeof(vendor)));

    /* Not a command packet, or a length that disagrees. */
    static const uint8_t acl[]     = { 0x02, 0x03, 0x0C, 0x00 };
    static const uint8_t trailing[] = { 0x01, 0x03, 0x0C, 0x00, 0x00 };
    static const uint8_t truncated[] = { 0x01, 0x0B, 0x20, 0x07, 0x00, 0x60 };
    static const uint8_t enable2[] = { 0x01, 0x0C, 0x20, 0x02, 0x02, 0x00 };
    static const uint8_t periodic[] = { 0x01, 0x42, 0x20, 0x06,
        0x01, 0x00, 0x00, 0x00, 0x10, 0x00 };
    ASSERT(!bles_cmd_allowed(acl, sizeof(acl)));
    ASSERT(!bles_cmd_allowed(trailing, sizeof(trailing)));
    ASSERT(!bles_cmd_allowed(truncated, sizeof(truncated)));
    ASSERT(!bles_cmd_allowed(enable2, sizeof(enable2)));
    ASSERT(!bles_cmd_allowed(periodic, sizeof(periodic)));
    ASSERT(!bles_cmd_allowed(NULL, 4));
    ASSERT(!bles_cmd_allowed(acl, 3));
}

/* ── events ── */

static void test_event_parser_command_complete_and_status(void) {
    bles_ev_t ev;
    /* Command Complete (§7.7.14) for HCI_Reset: Num_HCI_Command_Packets
     * 1, opcode 0x0C03, Status 0x00. */
    static const uint8_t cc_reset[] = { 0x04, 0x0E, 0x04, 0x01, 0x03, 0x0C, 0x00 };
    ASSERT_EQ(bles_parse_event(cc_reset, sizeof(cc_reset), &ev), BLES_EV_CMD_COMPLETE);
    ASSERT_EQ(ev.ncmd, 1);
    ASSERT_EQ(ev.opcode, 0x0C03);
    ASSERT_EQ(ev.has_status, 1);
    ASSERT_EQ(ev.status, 0x00);
    ASSERT(!bles_ev_lost_scan(&ev));
    /* LE Set Scan Parameters refused as Unknown HCI Command (0x01). */
    static const uint8_t cc_unknown[] = { 0x04, 0x0E, 0x04, 0x01, 0x0B, 0x20, 0x01 };
    ASSERT_EQ(bles_parse_event(cc_unknown, sizeof(cc_unknown), &ev), BLES_EV_CMD_COMPLETE);
    ASSERT_EQ(ev.opcode, 0x200B);
    ASSERT_EQ(ev.status, 0x01);
    ASSERT(bles_status_wants_extended(ev.status));
    ASSERT(bles_status_wants_extended(0x11));
    ASSERT(!bles_status_wants_extended(0x00));
    ASSERT(!bles_status_wants_extended(0x0C));   /* Command Disallowed */
    ASSERT(!bles_status_wants_extended(0x12));   /* Invalid Parameters */
    /* The unprompted NOP a controller sends when it (re)starts:
     * opcode 0x0000, no return parameters. */
    static const uint8_t nop[] = { 0x04, 0x0E, 0x03, 0x01, 0x00, 0x00 };
    ASSERT_EQ(bles_parse_event(nop, sizeof(nop), &ev), BLES_EV_CMD_COMPLETE);
    ASSERT_EQ(ev.opcode, 0x0000);
    ASSERT_EQ(ev.has_status, 0);
    ASSERT(bles_ev_lost_scan(&ev));
    /* Command Status (§7.7.15): Status 0x0C, Num 1, opcode 0x200C. */
    static const uint8_t cs[] = { 0x04, 0x0F, 0x04, 0x0C, 0x01, 0x0C, 0x20 };
    ASSERT_EQ(bles_parse_event(cs, sizeof(cs), &ev), BLES_EV_CMD_STATUS);
    ASSERT_EQ(ev.status, 0x0C);
    ASSERT_EQ(ev.ncmd, 1);
    ASSERT_EQ(ev.opcode, 0x200C);
    ASSERT(!bles_ev_lost_scan(&ev));
}

static void test_event_parser_hardware_error_and_reports(void) {
    bles_ev_t ev;
    /* Hardware Error (§7.7.16): Hardware_Code 0x42. */
    static const uint8_t hw[] = { 0x04, 0x10, 0x01, 0x42 };
    ASSERT_EQ(bles_parse_event(hw, sizeof(hw), &ev), BLES_EV_HW_ERROR);
    ASSERT_EQ(ev.hw_code, 0x42);
    ASSERT(bles_ev_lost_scan(&ev));
    /* LE Advertising Report (§7.7.65.2): one report, ADV_IND, public
     * address, 0 octets of data, RSSI -60. Classified, never opened. */
    static const uint8_t adv[] = { 0x04, 0x3E, 0x0C, 0x02, 0x01, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0xC4 };
    ASSERT_EQ(bles_parse_event(adv, sizeof(adv), &ev), BLES_EV_LE_META);
    ASSERT(!bles_ev_lost_scan(&ev));
    /* Number Of Completed Packets: some other event. */
    static const uint8_t other[] = { 0x04, 0x13, 0x01, 0x00 };
    ASSERT_EQ(bles_parse_event(other, sizeof(other), &ev), BLES_EV_OTHER);
    ASSERT(!bles_ev_lost_scan(&ev));
}

static void test_event_parser_rejects_bad_lengths(void) {
    bles_ev_t ev;
    static const uint8_t hw_long[]  = { 0x04, 0x10, 0x02, 0x42, 0x00 };
    static const uint8_t hw_trunc[] = { 0x04, 0x10, 0x01 };
    static const uint8_t cc_short[] = { 0x04, 0x0E, 0x02, 0x01, 0x03 };
    static const uint8_t cs_short[] = { 0x04, 0x0F, 0x03, 0x00, 0x01, 0x0C };
    static const uint8_t len_lies[] = { 0x04, 0x0E, 0x09, 0x01, 0x03, 0x0C, 0x00 };
    static const uint8_t acl[]      = { 0x02, 0x00, 0x20, 0x00 };
    static const uint8_t meta0[]    = { 0x04, 0x3E, 0x00 };
    ASSERT_EQ(bles_parse_event(hw_long, sizeof(hw_long), &ev), BLES_EV_MALFORMED);
    ASSERT(!bles_ev_lost_scan(&ev));
    ASSERT_EQ(bles_parse_event(hw_trunc, sizeof(hw_trunc), &ev), BLES_EV_MALFORMED);
    ASSERT_EQ(bles_parse_event(cc_short, sizeof(cc_short), &ev), BLES_EV_MALFORMED);
    ASSERT(!bles_ev_lost_scan(&ev));
    ASSERT_EQ(bles_parse_event(cs_short, sizeof(cs_short), &ev), BLES_EV_MALFORMED);
    ASSERT_EQ(bles_parse_event(len_lies, sizeof(len_lies), &ev), BLES_EV_MALFORMED);
    ASSERT_EQ(bles_parse_event(acl, sizeof(acl), &ev), BLES_EV_MALFORMED);
    ASSERT_EQ(bles_parse_event(meta0, sizeof(meta0), &ev), BLES_EV_MALFORMED);
    ASSERT_EQ(bles_parse_event(NULL, 7, &ev), BLES_EV_MALFORMED);
    ASSERT_EQ(bles_parse_event(hw_long, 0, NULL), BLES_EV_MALFORMED);
    ASSERT(!bles_ev_lost_scan(NULL));
}

static void test_rearm_budget(void) {
    bles_rearm_t b;
    memset(&b, 0, sizeof(b));
    uint64_t t = 1000000;
    for (int i = 0; i < BLES_REARM_MAX; i++) ASSERT(bles_rearm_take(&b, t + (uint64_t)i * 1000));
    /* The sixth inside the window is refused... */
    ASSERT(!bles_rearm_take(&b, t + 10000));
    /* ...and allowed once the first has aged out. */
    ASSERT(bles_rearm_take(&b, t + BLES_REARM_WINDOW_MS));
    ASSERT(!bles_rearm_take(&b, t + BLES_REARM_WINDOW_MS + 1));
    ASSERT(!bles_rearm_take(NULL, t));
}

/* ── the helper stays out of sloth ── */

static char *bs_slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    buf[fread(buf, 1, (size_t)n, f)] = '\0';
    fclose(f);
    return buf;
}

/* MISSION §2: sloth sends no HCI command, so the only code that can
 * build one is linked into the helper and the tests, never into any
 * list `sloth` is built from. A Makefile scan: every line that names
 * src/ble_scan/ must be the helper's own list or the tests'. */
static void test_helper_is_not_linked_into_sloth(void) {
    char *mk = bs_slurp("Makefile");
    ASSERT(mk != NULL);
    if (!mk) return;
    int named = 0, ok = 1;
    for (char *l = mk; l && *l; ) {
        char *nl = strchr(l, '\n');
        if (nl) *nl = '\0';
        if (strstr(l, "src/ble_scan/") && l[0] != '#') {
            named++;
            if (strncmp(l, "BLE_SCAN_SRCS", 13) != 0 &&
                strncmp(l, "BLE_SCAN_HDRS", 13) != 0 &&
                strncmp(l, "TEST_ONLY_SRCS", 14) != 0) {
                fprintf(stderr, "    Makefile links src/ble_scan/ elsewhere: %s\n", l);
                ok = 0;
            }
        }
        l = nl ? nl + 1 : NULL;
    }
    ASSERT(ok);
    ASSERT_GE(named, 2);
    free(mk);
    /* And nothing sloth compiles includes the builder. */
    static const char *const files[] = {
        "src/main.c", "src/capture/bt_monitor.c", "src/ble_hci.c", "src/poll.c"
    };
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        char *s = bs_slurp(files[i]);
        ASSERT(s != NULL);
        if (!s) continue;
        ASSERT(strstr(s, "ble_scan_cmd") == NULL);
        free(s);
    }
}

void run_ble_scan_tests(void) {
    TEST_SUITE("sloth-ble-scan: passive-only HCI command set");
    RUN_TEST(test_builder_bytes_match_the_spec);
    RUN_TEST(test_builder_refuses_unknown_and_short);
    RUN_TEST(test_builder_never_produces_an_active_scan);
    RUN_TEST(test_gate_refuses_every_transmitting_command);
    RUN_TEST(test_event_parser_command_complete_and_status);
    RUN_TEST(test_event_parser_hardware_error_and_reports);
    RUN_TEST(test_event_parser_rejects_bad_lengths);
    RUN_TEST(test_rearm_budget);
    RUN_TEST(test_helper_is_not_linked_into_sloth);
}
