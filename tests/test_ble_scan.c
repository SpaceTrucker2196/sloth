#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
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
 *     appended to CORE_COMMON_SRCS in the Makefile. That test reads
 *     Makefile text, which cannot see `CORE_COMMON_SRCS +=
 *     $(BLE_SCAN_SRCS)` or an include from any file it does not list, so
 *     it is the second line. The first is check_no_hci_builder in the
 *     `sloth` link recipe: no `bles_` symbol in the linked binary and no
 *     sloth source naming the builder, in every configuration. Seen red
 *     (2026-10-26, docs/wiki/log.md) with ble_scan_cmd.c added to
 *     CORE_COMMON_SRCS plus a bare bles_build reference in src/main.c,
 *     and separately with the header included from src/alerts/rules_ble.c;
 *   - test_nop_never_restarts_the_scan: the opcode-0x0000 clause put back
 *     in bles_ev_lost_scan();
 *   - the 0x03 / 0x07 Scanning_PHYs cases: `(phys & ~0x05u)` dropped
 *     from the gate;
 *   - test_establish_ignores_what_is_not_its_answer: a Command Status
 *     0x00 accepted as an answer;
 *   - test_args: the empty-device check removed from bles_parse_dev().
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
    /* x2m is also refused by the length check (2M counts no record, so
     * plen 8 disagrees). These two pass every check but the reserved-PHY
     * one: 0x03 is 1M plus the reserved bit 1 with exactly the one
     * passive record 1M implies, and 0x07 is 1M, bit 1 and Coded with
     * the two records 1M and Coded imply. */
    static const uint8_t x1m2m[] = { 0x01, 0x41, 0x20, 0x08,
        0x00, 0x00, 0x03, 0x00, 0x60, 0x00, 0x60, 0x00 };
    ASSERT(!bles_cmd_allowed(x1m2m, sizeof(x1m2m)));
    static const uint8_t xall[] = { 0x01, 0x41, 0x20, 0x0D,
        0x00, 0x00, 0x07,
        0x00, 0x60, 0x00, 0x60, 0x00,
        0x00, 0x60, 0x00, 0x60, 0x00 };
    ASSERT(!bles_cmd_allowed(xall, sizeof(xall)));
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
    /* A No-Op (§7.7.14): opcode 0x0000, no return parameters. Parsed
     * as a Command Complete; test_nop_never_restarts_the_scan says what
     * it does not mean. */
    static const uint8_t nop[] = { 0x04, 0x0E, 0x03, 0x01, 0x00, 0x00 };
    ASSERT_EQ(bles_parse_event(nop, sizeof(nop), &ev), BLES_EV_CMD_COMPLETE);
    ASSERT_EQ(ev.opcode, 0x0000);
    ASSERT_EQ(ev.has_status, 0);
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

/* ── the No-Op is flow control, not a restart ── */

/* Core Spec v5.4 Vol 4 Part E §7.7.14: a Command Complete with
 * Command_Opcode 0x0000 is a No-Op the controller may send at any time
 * to update Num_HCI_Command_Packets. In steady state it must not count
 * as a lost scan (that would Reset the controller out of its own scan
 * and spend the re-arm budget), and one arriving late inside a
 * sequence — some controllers send it after HCI_Reset completes — must
 * not answer the command in flight. */
static void test_nop_never_restarts_the_scan(void) {
    static const uint8_t nop1[] = { 0x04, 0x0E, 0x03, 0x01, 0x00, 0x00 };
    static const uint8_t nop5[] = { 0x04, 0x0E, 0x03, 0x05, 0x00, 0x00 };
    bles_ev_t ev;
    ASSERT_EQ(bles_parse_event(nop1, sizeof(nop1), &ev), BLES_EV_CMD_COMPLETE);
    ASSERT_EQ(ev.ncmd, 1);
    ASSERT(!bles_ev_lost_scan(&ev));
    ASSERT_EQ(bles_parse_event(nop5, sizeof(nop5), &ev), BLES_EV_CMD_COMPLETE);
    ASSERT(!bles_ev_lost_scan(&ev));

    bles_est_t est;
    bles_est_begin(&est);
    ASSERT_EQ(bles_est_feed(&est, &ev), BLES_STEP_WAIT);
    ASSERT_EQ(est.cmd, BLES_CMD_RESET);
}

/* ── the establish sequence, driven by hand-built events ── */

/* A Command Complete (§7.7.14), Num_HCI_Command_Packets 1, for `op`
 * with Status `st`, parsed as main.c would. */
static bles_ev_t cc(uint16_t op, uint8_t st) {
    uint8_t p[7] = { 0x04, 0x0E, 0x04, 0x01,
                     (uint8_t)(op & 0xff), (uint8_t)(op >> 8), st };
    bles_ev_t ev;
    (void)bles_parse_event(p, sizeof(p), &ev);
    return ev;
}

/* Command Status (§7.7.15): Status, Num 1, opcode. */
static bles_ev_t cs(uint16_t op, uint8_t st) {
    uint8_t p[7] = { 0x04, 0x0F, 0x04, st, 0x01,
                     (uint8_t)(op & 0xff), (uint8_t)(op >> 8) };
    bles_ev_t ev;
    (void)bles_parse_event(p, sizeof(p), &ev);
    return ev;
}

/* Feeds the answer `st` to the command in flight, asserting that
 * command's opcode first; returns the step. */
static bles_step_t answer(bles_est_t *est, uint16_t want_op, uint8_t st) {
    ASSERT_EQ(bles_opcode(est->cmd), want_op);
    bles_ev_t ev = cc(want_op, st);
    return bles_est_feed(est, &ev);
}

static void test_establish_legacy(void) {
    bles_est_t est;
    bles_est_begin(&est);
    ASSERT_EQ(answer(&est, 0x0C03, 0x00), BLES_STEP_SEND);   /* Reset */
    ASSERT_EQ(answer(&est, 0x0C01, 0x00), BLES_STEP_SEND);   /* Set Event Mask */
    ASSERT_EQ(answer(&est, 0x2001, 0x00), BLES_STEP_SEND);   /* LE Set Event Mask */
    ASSERT_EQ(answer(&est, 0x200B, 0x00), BLES_STEP_SEND);   /* LE Set Scan Parameters */
    ASSERT_EQ(answer(&est, 0x200C, 0x00), BLES_STEP_DONE);   /* LE Set Scan Enable */
    ASSERT_EQ(est.mode, BLES_MODE_LEGACY);
    /* The disable for that set: 0x200C, LE_Scan_Enable 0x00. */
    uint8_t b[BLES_CMD_MAX];
    size_t n = bles_build(bles_disable_cmd(est.mode), b, sizeof(b));
    static const uint8_t want[] = { 0x01, 0x0C, 0x20, 0x02, 0x00, 0x00 };
    ASSERT(n == sizeof(want) && memcmp(b, want, n) == 0);
}

/* Unknown HCI Command (0x01) and Unsupported Feature or Parameter
 * Value (0x11) on the legacy parameters move to the extended pair. */
static void test_establish_falls_back_to_extended(void) {
    static const uint8_t refusals[] = { 0x01, 0x11 };
    for (size_t i = 0; i < sizeof(refusals); i++) {
        bles_est_t est;
        bles_est_begin(&est);
        ASSERT_EQ(answer(&est, 0x0C03, 0x00), BLES_STEP_SEND);
        ASSERT_EQ(answer(&est, 0x0C01, 0x00), BLES_STEP_SEND);
        ASSERT_EQ(answer(&est, 0x2001, 0x00), BLES_STEP_SEND);
        ASSERT_EQ(answer(&est, 0x200B, refusals[i]), BLES_STEP_SEND);
        ASSERT_EQ(answer(&est, 0x2041, 0x00), BLES_STEP_SEND);   /* LE Set Ext Scan Params */
        ASSERT_EQ(answer(&est, 0x2042, 0x00), BLES_STEP_DONE);   /* LE Set Ext Scan Enable */
        ASSERT_EQ(est.mode, BLES_MODE_EXTENDED);
        /* Disabled with the extended command (§3.1.1: the legacy one is
         * Command Disallowed now), Enable 0x00, Duration/Period 0. */
        uint8_t b[BLES_CMD_MAX];
        size_t n = bles_build(bles_disable_cmd(est.mode), b, sizeof(b));
        static const uint8_t want[] = { 0x01, 0x42, 0x20, 0x06,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        ASSERT(n == sizeof(want) && memcmp(b, want, n) == 0);
    }
    /* A refusal of the legacy parameters by Command Status is the same
     * answer (§7.7.15 permits either for Unknown HCI Command). */
    bles_est_t est;
    bles_est_begin(&est);
    (void)answer(&est, 0x0C03, 0x00);
    (void)answer(&est, 0x0C01, 0x00);
    (void)answer(&est, 0x2001, 0x00);
    bles_ev_t ev = cs(0x200B, 0x01);
    ASSERT_EQ(bles_est_feed(&est, &ev), BLES_STEP_SEND);
    ASSERT_EQ(est.cmd, BLES_CMD_LE_EXT_SCAN_PARAMS);
}

static void test_establish_fails_on_any_other_refusal(void) {
    /* Command Disallowed (0x0C) on the legacy parameters is not "use the
     * extended commands": it fails, and nothing else is sent. */
    bles_est_t est;
    bles_est_begin(&est);
    (void)answer(&est, 0x0C03, 0x00);
    (void)answer(&est, 0x0C01, 0x00);
    (void)answer(&est, 0x2001, 0x00);
    ASSERT_EQ(answer(&est, 0x200B, 0x0C), BLES_STEP_FAIL);
    ASSERT_EQ(est.status, 0x0C);
    ASSERT_EQ(est.cmd, BLES_CMD_LE_SCAN_PARAMS);
    /* Invalid HCI Command Parameters (0x12) likewise. */
    bles_est_begin(&est);
    (void)answer(&est, 0x0C03, 0x00);
    (void)answer(&est, 0x0C01, 0x00);
    (void)answer(&est, 0x2001, 0x00);
    ASSERT_EQ(answer(&est, 0x200B, 0x12), BLES_STEP_FAIL);
    /* 0x01 on any other command is a failure, not a fallback. */
    bles_est_begin(&est);
    ASSERT_EQ(answer(&est, 0x0C03, 0x01), BLES_STEP_FAIL);
    bles_est_begin(&est);
    (void)answer(&est, 0x0C03, 0x00);
    (void)answer(&est, 0x0C01, 0x00);
    (void)answer(&est, 0x2001, 0x00);
    (void)answer(&est, 0x200B, 0x00);
    ASSERT_EQ(answer(&est, 0x200C, 0x01), BLES_STEP_FAIL);
    /* The extended pair refused: no third set to fall back to. */
    bles_est_begin(&est);
    (void)answer(&est, 0x0C03, 0x00);
    (void)answer(&est, 0x0C01, 0x00);
    (void)answer(&est, 0x2001, 0x00);
    (void)answer(&est, 0x200B, 0x11);
    ASSERT_EQ(answer(&est, 0x2041, 0x11), BLES_STEP_FAIL);
}

static void test_establish_ignores_what_is_not_its_answer(void) {
    bles_est_t est;
    bles_est_begin(&est);
    /* Another opcode's Command Complete, a pending Command Status, an
     * advertising report: none answers the Reset in flight. */
    bles_ev_t ev = cc(0x200B, 0x00);
    ASSERT_EQ(bles_est_feed(&est, &ev), BLES_STEP_WAIT);
    ev = cs(0x0C03, 0x00);
    ASSERT_EQ(bles_est_feed(&est, &ev), BLES_STEP_WAIT);
    static const uint8_t adv[] = { 0x04, 0x3E, 0x0C, 0x02, 0x01, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0xC4 };
    (void)bles_parse_event(adv, sizeof(adv), &ev);
    ASSERT_EQ(bles_est_feed(&est, &ev), BLES_STEP_WAIT);
    ASSERT_EQ(est.cmd, BLES_CMD_RESET);
    /* A Command Complete with no Status octet for the command in flight
     * is read as success (the shape of a parameterless return). */
    static const uint8_t bare[] = { 0x04, 0x0E, 0x03, 0x01, 0x03, 0x0C };
    (void)bles_parse_event(bare, sizeof(bare), &ev);
    ASSERT_EQ(bles_est_feed(&est, &ev), BLES_STEP_SEND);
    ASSERT_EQ(est.cmd, BLES_CMD_SET_EVENT_MASK);
    ASSERT_EQ(bles_est_feed(NULL, &ev), BLES_STEP_WAIT);
    ASSERT_EQ(bles_est_feed(&est, NULL), BLES_STEP_WAIT);
}

static void test_hardware_error_mid_sequence_retries_within_budget(void) {
    static const uint8_t hw[] = { 0x04, 0x10, 0x01, 0x03 };
    bles_ev_t ev;
    (void)bles_parse_event(hw, sizeof(hw), &ev);
    bles_est_t est;
    bles_est_begin(&est);
    (void)answer(&est, 0x0C03, 0x00);
    ASSERT_EQ(bles_est_feed(&est, &ev), BLES_STEP_HW_ERROR);
    ASSERT_EQ(est.status, 0x03);

    /* The decision after it: retry, from the budget, five times in the
     * window; then exit. The first run and a re-establish share it. */
    bles_rearm_t b;
    memset(&b, 0, sizeof(b));
    uint64_t t = 5000000;
    for (int i = 0; i < BLES_REARM_MAX; i++)
        ASSERT_EQ(bles_after_establish(BLES_STEP_HW_ERROR, &b, t + (uint64_t)i), BLES_NEXT_RETRY);
    ASSERT_EQ(bles_after_establish(BLES_STEP_HW_ERROR, &b, t + 10), BLES_NEXT_EXIT);
    /* Success holds whatever the budget; a refusal or a socket failure
     * exits and spends nothing. */
    ASSERT_EQ(bles_after_establish(BLES_STEP_DONE, &b, t + 11), BLES_NEXT_HOLD);
    bles_rearm_t fresh;
    memset(&fresh, 0, sizeof(fresh));
    ASSERT_EQ(bles_after_establish(BLES_STEP_FAIL, &fresh, t), BLES_NEXT_EXIT);
    ASSERT_EQ(bles_after_establish(BLES_STEP_IO_ERROR, &fresh, t), BLES_NEXT_EXIT);
    ASSERT_EQ(fresh.n, 0);
}

/* ── bind errors worth waiting out (boot ordering) ── */
static void test_bind_waits_only_for_a_controller_not_ready(void) {
    ASSERT(bles_bind_transient(ENODEV));
    ASSERT(bles_bind_transient(EBUSY));
    ASSERT(!bles_bind_transient(EUSERS));
    ASSERT(!bles_bind_transient(EPERM));
    ASSERT(!bles_bind_transient(ERFKILL));
    ASSERT(!bles_bind_transient(EAFNOSUPPORT));
    ASSERT(!bles_bind_transient(0));
}

/* ── argv ── */
static bles_args_rc_t args(bles_args_t *a, int argc, ...) {
    char *v[8] = { "sloth-ble-scan" };
    va_list ap;
    va_start(ap, argc);
    for (int i = 1; i < argc && i < 8; i++) v[i] = va_arg(ap, char *);
    va_end(ap);
    memset(a, 0x5A, sizeof(*a));
    return bles_parse_args(argc, v, a);
}

static void test_args(void) {
    bles_args_t a;
    ASSERT_EQ(args(&a, 1), BLES_ARGS_RUN);
    ASSERT_EQ(a.dev, 0); ASSERT_EQ(a.down, 0); ASSERT_EQ(a.delay, 0);
    /* --down with no device is hci0. */
    ASSERT_EQ(args(&a, 2, "--down"), BLES_ARGS_RUN);
    ASSERT_EQ(a.dev, 0); ASSERT_EQ(a.down, 1);
    ASSERT_EQ(args(&a, 3, "--down", "hci2"), BLES_ARGS_RUN);
    ASSERT_EQ(a.dev, 2); ASSERT_EQ(a.down, 1);
    ASSERT_EQ(args(&a, 4, "--delay", "3", "hci1"), BLES_ARGS_RUN);
    ASSERT_EQ(a.dev, 1); ASSERT_EQ(a.delay, 3); ASSERT_EQ(a.down, 0);
    ASSERT_EQ(args(&a, 3, "--delay", "0"), BLES_ARGS_RUN);
    ASSERT_EQ(a.delay, 0);
    ASSERT_EQ(args(&a, 3, "--delay", "60"), BLES_ARGS_RUN);
    ASSERT_EQ(a.delay, 60);
    ASSERT_EQ(args(&a, 2, "7"), BLES_ARGS_RUN);
    ASSERT_EQ(a.dev, 7);
    /* --delay bounds. */
    ASSERT_EQ(args(&a, 3, "--delay", "61"), BLES_ARGS_BAD_DELAY);
    ASSERT_EQ(args(&a, 3, "--delay", "-1"), BLES_ARGS_BAD_DELAY);
    ASSERT_EQ(args(&a, 3, "--delay", "3s"), BLES_ARGS_BAD_DELAY);
    ASSERT_EQ(args(&a, 3, "--delay", ""), BLES_ARGS_BAD_DELAY);
    ASSERT_EQ(args(&a, 3, "--delay", "99999999999999999999"), BLES_ARGS_BAD_DELAY);
    ASSERT_EQ(args(&a, 2, "--delay"), BLES_ARGS_USAGE);
    /* Devices: one, by number, below HCI_DEV_NONE (0xffff). The unit
     * passes ${SLOTH_BLE_HCI} as exactly one argument, so an empty
     * setting is "" — a usage error (exit 2, not restarted), not hci0. */
    ASSERT_EQ(args(&a, 2, ""), BLES_ARGS_USAGE);
    ASSERT_EQ(args(&a, 3, "--down", ""), BLES_ARGS_USAGE);
    ASSERT_EQ(args(&a, 2, "hci"), BLES_ARGS_USAGE);
    ASSERT_EQ(args(&a, 2, "hcix"), BLES_ARGS_USAGE);
    ASSERT_EQ(args(&a, 2, "hci-1"), BLES_ARGS_USAGE);
    ASSERT_EQ(args(&a, 2, "65535"), BLES_ARGS_USAGE);
    ASSERT_EQ(args(&a, 2, "65534"), BLES_ARGS_RUN);
    ASSERT_EQ(args(&a, 3, "hci0", "hci1"), BLES_ARGS_USAGE);
    ASSERT_EQ(args(&a, 2, "--passive"), BLES_ARGS_USAGE);
    ASSERT_EQ(args(&a, 2, "-h"), BLES_ARGS_HELP);
    ASSERT_EQ(args(&a, 3, "hci0", "--help"), BLES_ARGS_HELP);
    ASSERT_EQ(bles_parse_dev("hci12"), 12);
    ASSERT_EQ(bles_parse_dev(NULL), -1);
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
 * src/ble_scan/ must be the helper's own list or the tests'. Text only,
 * and so the second line behind the link-time check_no_hci_builder in
 * the Makefile (see the header of this file). */
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

/* ── every write passes the gate ──
 *
 * main.c's only route to the socket is bles_send() with a writer. These
 * drive bles_send() and bles_write_gated() with a writer that records
 * what it was handed, so a gate dropped from the path, or a byte changed
 * between the build and the write, shows up as bytes the controller
 * would have seen. */

typedef struct {
    int     calls;
    uint8_t got[BLES_CMD_MAX + 8];
    size_t  len;
    ssize_t ret;      /* what to report; -2 means "all of it" */
} bs_rec_t;

static ssize_t bs_rec_write(void *ctx, const uint8_t *pkt, size_t len) {
    bs_rec_t *r = ctx;
    r->calls++;
    r->len = len < sizeof(r->got) ? len : sizeof(r->got);
    memcpy(r->got, pkt, r->len);
    return r->ret == -2 ? (ssize_t)len : r->ret;
}

static void bs_rec_init(bs_rec_t *r) {
    memset(r, 0, sizeof(*r));
    r->ret = -2;
}

static void test_send_writes_exactly_the_built_packet(void) {
    for (int c = 0; c < BLES_CMD_COUNT; c++) {
        uint8_t want[BLES_CMD_MAX];
        size_t wn = bles_build(c, want, sizeof(want));
        ASSERT_GT(wn, 0);
        bs_rec_t r;
        bs_rec_init(&r);
        ASSERT_EQ(bles_send(c, bs_rec_write, &r), BLES_SEND_OK);
        ASSERT_EQ(r.calls, 1);
        ASSERT_EQ(r.len, wn);
        if (r.len != wn || memcmp(r.got, want, wn) != 0) {
            fprintf(stderr, "    bles_send(%d) wrote", c);
            for (size_t i = 0; i < r.len; i++) fprintf(stderr, " %02x", r.got[i]);
            fprintf(stderr, "\n");
        }
        ASSERT(r.len == wn && memcmp(r.got, want, wn) == 0);
        ASSERT(bles_cmd_allowed(r.got, r.len));
    }
    /* And the one that matters, from the spec rather than the builder:
     * LE Set Scan Parameters with LE_Scan_Type 0x00 (§7.8.10). */
    static const uint8_t passive[] = {
        0x01, 0x0B, 0x20, 0x07, 0x00, 0x60, 0x00, 0x60, 0x00, 0x00, 0x00
    };
    bs_rec_t r;
    bs_rec_init(&r);
    ASSERT_EQ(bles_send(BLES_CMD_LE_SCAN_PARAMS, bs_rec_write, &r), BLES_SEND_OK);
    ASSERT(r.len == sizeof(passive) && memcmp(r.got, passive, sizeof(passive)) == 0);
}

static void test_send_refuses_without_writing(void) {
    bs_rec_t r;
    /* Outside the vocabulary: nothing built, nothing written. */
    bs_rec_init(&r);
    ASSERT_EQ(bles_send(-1, bs_rec_write, &r), BLES_SEND_REFUSED);
    ASSERT_EQ(bles_send(BLES_CMD_COUNT, bs_rec_write, &r), BLES_SEND_REFUSED);
    ASSERT_EQ(r.calls, 0);

    /* Built elsewhere and handed to the write path: the gate, not the
     * builder, is what stops it. */
    static const uint8_t active[] = {          /* §7.8.10, LE_Scan_Type 0x01 */
        0x01, 0x0B, 0x20, 0x07, 0x01, 0x60, 0x00, 0x60, 0x00, 0x00, 0x00
    };
    static const uint8_t adv_on[] = {          /* §7.8.9 LE Set Advertising Enable */
        0x01, 0x0A, 0x20, 0x01, 0x01
    };
    static const uint8_t inquiry[] = {         /* §7.1.1 Inquiry */
        0x01, 0x01, 0x04, 0x05, 0x33, 0x8B, 0x9E, 0x08, 0x00
    };
    static const uint8_t ext_active[] = {      /* §7.8.64, 1M PHY active */
        0x01, 0x41, 0x20, 0x08, 0x00, 0x00, 0x01, 0x01, 0x60, 0x00, 0x60, 0x00
    };
    const struct { const uint8_t *p; size_t n; } bad[] = {
        { active, sizeof(active) }, { adv_on, sizeof(adv_on) },
        { inquiry, sizeof(inquiry) }, { ext_active, sizeof(ext_active) },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        bs_rec_init(&r);
        ASSERT_EQ(bles_write_gated(bad[i].p, bad[i].n, bs_rec_write, &r), BLES_SEND_REFUSED);
        if (r.calls) fprintf(stderr, "    bad[%zu] reached the writer\n", i);
        ASSERT_EQ(r.calls, 0);
    }

    /* An admitted packet goes through unchanged, once. */
    static const uint8_t passive[] = {
        0x01, 0x0B, 0x20, 0x07, 0x00, 0x60, 0x00, 0x60, 0x00, 0x00, 0x00
    };
    bs_rec_init(&r);
    ASSERT_EQ(bles_write_gated(passive, sizeof(passive), bs_rec_write, &r), BLES_SEND_OK);
    ASSERT_EQ(r.calls, 1);
    ASSERT(r.len == sizeof(passive) && memcmp(r.got, passive, sizeof(passive)) == 0);

    /* No writer is a refusal, not a crash. */
    ASSERT_EQ(bles_send(BLES_CMD_RESET, NULL, NULL), BLES_SEND_REFUSED);
}

static void test_send_reports_a_failed_or_short_write(void) {
    bs_rec_t r;
    bs_rec_init(&r);
    r.ret = -1;
    ASSERT_EQ(bles_send(BLES_CMD_RESET, bs_rec_write, &r), BLES_SEND_IO);
    ASSERT_EQ(r.calls, 1);
    bs_rec_init(&r);
    r.ret = 3;
    ASSERT_EQ(bles_send(BLES_CMD_LE_SCAN_PARAMS, bs_rec_write, &r), BLES_SEND_IO);
}

/* main.c, comments and literals blanked, so prose and messages that say
 * "send" or "write" do not count. */
static void bs_strip_c(char *s) {
    for (char *p = s; *p; ) {
        if (p[0] == '/' && p[1] == '*') {
            char *e = strstr(p + 2, "*/");
            char *end = e ? e + 2 : p + strlen(p);
            for (; p < end; p++) if (*p != '\n') *p = ' ';
        } else if (p[0] == '/' && p[1] == '/') {
            for (; *p && *p != '\n'; p++) *p = ' ';
        } else if (*p == '"' || *p == '\'') {
            char q = *p++;
            for (; *p && *p != q; p++) {
                if (*p == '\\' && p[1]) *p++ = ' ';
                if (*p != '\n') *p = ' ';
            }
            if (*p) p++;
        } else {
            p++;
        }
    }
}

static int bs_ident(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

/* Every call of `name` (an identifier followed by `(`), offsets into
 * out[]. */
static int bs_calls(const char *s, const char *name, size_t out[], int max) {
    size_t k = strlen(name);
    int n = 0;
    for (const char *p = s; (p = strstr(p, name)) != NULL; p += k) {
        if (p > s && bs_ident(p[-1])) continue;
        if (bs_ident(p[k])) continue;
        const char *q = p + k;
        while (*q == ' ' || *q == '\t' || *q == '\n') q++;
        if (*q != '(') continue;
        if (n < max) out[n] = (size_t)(p - s);
        n++;
    }
    return n;
}

/* The one send() in the helper sits inside the writer handed to
 * bles_send(), and nothing else in main.c writes to a descriptor. */
static void test_helper_writes_only_through_bles_send(void) {
    char *s = bs_slurp("src/ble_scan/main.c");
    ASSERT(s != NULL);
    if (!s) return;
    bs_strip_c(s);

    static const char *const other[] = {
        "write", "writev", "pwrite", "pwritev", "sendto", "sendmsg",
        "sendmmsg", "sendfile", "splice", "vmsplice", "ioctl"
    };
    for (size_t i = 0; i < sizeof(other) / sizeof(other[0]); i++) {
        size_t at[4];
        int c = bs_calls(s, other[i], at, 4);
        /* The one ioctl is HCIDEVDOWN in do_down(), which sends no
         * packet; it is counted so a second one cannot appear. */
        int allowed = strcmp(other[i], "ioctl") == 0 ? 1 : 0;
        if (c != allowed) fprintf(stderr, "    main.c: %d call(s) of %s()\n", c, other[i]);
        ASSERT_EQ(c, allowed);
    }

    size_t sends[4];
    int ns = bs_calls(s, "send", sends, 4);
    if (ns != 1) fprintf(stderr, "    main.c: %d send() calls, want 1\n", ns);
    ASSERT_EQ(ns, 1);

    /* The writer is bles_send()'s second argument, at its one call. */
    size_t bs[4];
    int nb = bs_calls(s, "bles_send", bs, 4);
    ASSERT_EQ(nb, 1);
    if (ns != 1 || nb != 1) { free(s); return; }
    const char *a = strchr(s + bs[0], '(');
    const char *comma = a ? strchr(a, ',') : NULL;
    ASSERT(comma != NULL);
    if (!comma) { free(s); return; }
    comma++;
    while (*comma == ' ' || *comma == '\t' || *comma == '\n') comma++;
    char wr[64];
    size_t wl = 0;
    while (bs_ident(comma[wl]) && wl + 1 < sizeof(wr)) { wr[wl] = comma[wl]; wl++; }
    wr[wl] = '\0';
    ASSERT_GT(wl, 0);

    /* Its definition: `name(` followed by a body `{ ... }`. */
    size_t defs[4];
    int nd = bs_calls(s, wr, defs, 4);
    const char *body = NULL, *end = NULL;
    for (int i = 0; i < nd && i < 4 && !body; i++) {
        const char *p = strchr(s + defs[i], ')');
        if (!p) continue;
        p++;
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        if (*p != '{') continue;
        int depth = 0;
        for (const char *q = p; *q; q++) {
            if (*q == '{') depth++;
            else if (*q == '}' && --depth == 0) { end = q; break; }
        }
        body = p;
    }
    ASSERT(body != NULL && end != NULL);
    const char *at = s + sends[0];
    if (!(body && end && at > body && at < end))
        fprintf(stderr, "    main.c: send() is not inside %s(), the writer bles_send() is given\n", wr);
    ASSERT(body && end && at > body && at < end);
    free(s);
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
    RUN_TEST(test_nop_never_restarts_the_scan);
    RUN_TEST(test_establish_legacy);
    RUN_TEST(test_establish_falls_back_to_extended);
    RUN_TEST(test_establish_fails_on_any_other_refusal);
    RUN_TEST(test_establish_ignores_what_is_not_its_answer);
    RUN_TEST(test_hardware_error_mid_sequence_retries_within_budget);
    RUN_TEST(test_bind_waits_only_for_a_controller_not_ready);
    RUN_TEST(test_args);
    RUN_TEST(test_helper_is_not_linked_into_sloth);
    RUN_TEST(test_send_writes_exactly_the_built_packet);
    RUN_TEST(test_send_refuses_without_writing);
    RUN_TEST(test_send_reports_a_failed_or_short_write);
    RUN_TEST(test_helper_writes_only_through_bles_send);
}
