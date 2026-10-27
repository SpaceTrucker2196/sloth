#include "ble_scan/ble_scan_cmd.h"

#include <errno.h>
#include <string.h>

/* Contract in ble_scan_cmd.h. Every multi-octet HCI parameter is
 * little-endian (Vol 4 Part E §5.2). */

/* Set Event Mask (§7.3.1): the value the reference-host run sent. Bit
 * 61 (LE Meta) has to be set or no advertising report reaches the host
 * — the post-Reset default 0x00001FFFFFFFFFFF clears it — and bit 15
 * keeps Hardware Error, which the re-establish path waits on. */
static const uint8_t k_event_mask[8] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbf, 0x3d
};

/* LE Set Event Mask (§7.8.1): bit 1 LE Advertising Report, bit 12 LE
 * Extended Advertising Report, nothing else. The connection subevents
 * the reference run also enabled (bits 0, 2-4) cannot occur, because
 * this helper never creates a connection; asking only for what is
 * wanted keeps the mask a statement of intent. */
static const uint8_t k_le_event_mask[8] = {
    0x02, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static size_t put_cmd(uint8_t *out, size_t cap, uint16_t op,
                      const uint8_t *par, uint8_t plen) {
    if (!out || cap < (size_t)4 + plen) return 0;
    out[0] = BLES_H4_CMD;
    out[1] = (uint8_t)(op & 0xff);
    out[2] = (uint8_t)(op >> 8);
    out[3] = plen;
    if (plen) memcpy(out + 4, par, plen);
    return (size_t)4 + plen;
}

size_t bles_build(int c, uint8_t *out, size_t cap) {
    uint8_t p[8];
    switch (c) {
    case BLES_CMD_RESET:
        return put_cmd(out, cap, BLES_OP_RESET, NULL, 0);
    case BLES_CMD_SET_EVENT_MASK:
        return put_cmd(out, cap, BLES_OP_SET_EVENT_MASK, k_event_mask, 8);
    case BLES_CMD_LE_SET_EVENT_MASK:
        return put_cmd(out, cap, BLES_OP_LE_SET_EVENT_MASK, k_le_event_mask, 8);
    case BLES_CMD_LE_SCAN_PARAMS:
        p[0] = BLES_SCAN_TYPE_PASSIVE;
        p[1] = (uint8_t)(BLES_SCAN_INTERVAL & 0xff);
        p[2] = (uint8_t)(BLES_SCAN_INTERVAL >> 8);
        p[3] = (uint8_t)(BLES_SCAN_WINDOW & 0xff);
        p[4] = (uint8_t)(BLES_SCAN_WINDOW >> 8);
        p[5] = 0x00;   /* Own_Address_Type public: a passive scan never sends it */
        p[6] = 0x00;   /* Scanning_Filter_Policy: every advertiser, not a list */
        return put_cmd(out, cap, BLES_OP_LE_SCAN_PARAMS, p, 7);
    case BLES_CMD_LE_SCAN_ENABLE:
    case BLES_CMD_LE_SCAN_DISABLE:
        p[0] = c == BLES_CMD_LE_SCAN_ENABLE ? 0x01 : 0x00;
        p[1] = 0x00;   /* Filter_Duplicates off: sloth wants every report */
        return put_cmd(out, cap, BLES_OP_LE_SCAN_ENABLE, p, 2);
    case BLES_CMD_LE_EXT_SCAN_PARAMS:
        p[0] = 0x00;   /* Own_Address_Type */
        p[1] = 0x00;   /* Scanning_Filter_Policy */
        p[2] = 0x01;   /* Scanning_PHYs: LE 1M only — one per-PHY record */
        p[3] = BLES_SCAN_TYPE_PASSIVE;
        p[4] = (uint8_t)(BLES_SCAN_INTERVAL & 0xff);
        p[5] = (uint8_t)(BLES_SCAN_INTERVAL >> 8);
        p[6] = (uint8_t)(BLES_SCAN_WINDOW & 0xff);
        p[7] = (uint8_t)(BLES_SCAN_WINDOW >> 8);
        return put_cmd(out, cap, BLES_OP_LE_EXT_SCAN_PARAMS, p, 8);
    case BLES_CMD_LE_EXT_SCAN_ENABLE:
    case BLES_CMD_LE_EXT_SCAN_DISABLE:
        p[0] = c == BLES_CMD_LE_EXT_SCAN_ENABLE ? 0x01 : 0x00;
        p[1] = 0x00;   /* Filter_Duplicates */
        p[2] = 0x00; p[3] = 0x00;   /* Duration 0: until disabled */
        p[4] = 0x00; p[5] = 0x00;   /* Period 0: not periodic */
        return put_cmd(out, cap, BLES_OP_LE_EXT_SCAN_ENABLE, p, 6);
    default:
        return 0;
    }
}

uint16_t bles_opcode(int c) {
    uint8_t b[BLES_CMD_MAX];
    if (bles_build(c, b, sizeof(b)) < 4) return 0;
    return (uint16_t)(b[1] | (b[2] << 8));
}

/* The gate's own spelling of passive (§7.8.10, §7.8.64), deliberately
 * not BLES_SCAN_TYPE_PASSIVE: an edit to the builder's constant must be
 * caught here, not carried through both halves at once. */
#define GATE_PASSIVE 0x00

/* An enable/disable octet: exactly 0x00 or 0x01 (0x02..0xFF reserved). */
static int is_bool(uint8_t v) { return v == 0x00 || v == 0x01; }

int bles_cmd_allowed(const uint8_t *pkt, size_t len) {
    if (!pkt || len < 4 || pkt[0] != BLES_H4_CMD) return 0;
    uint16_t op = (uint16_t)(pkt[1] | (pkt[2] << 8));
    size_t plen = pkt[3];
    if (len != 4 + plen) return 0;
    const uint8_t *p = pkt + 4;
    switch (op) {
    case BLES_OP_RESET:
        return plen == 0;
    case BLES_OP_SET_EVENT_MASK:
    case BLES_OP_LE_SET_EVENT_MASK:
        return plen == 8;
    case BLES_OP_LE_SCAN_PARAMS:
        return plen == 7 && p[0] == GATE_PASSIVE;
    case BLES_OP_LE_SCAN_ENABLE:
        return plen == 2 && is_bool(p[0]);
    case BLES_OP_LE_EXT_SCAN_PARAMS: {
        if (plen < 3) return 0;
        uint8_t phys = p[2];
        /* Bits 0 (1M) and 2 (Coded) only (§7.8.64); one five-octet
         * record per bit set, each passive. */
        if (phys == 0 || (phys & ~0x05u)) return 0;
        size_t nphy = (size_t)((phys & 1u) + ((phys >> 2) & 1u));
        if (plen != 3 + 5 * nphy) return 0;
        for (size_t i = 0; i < nphy; i++)
            if (p[3 + 5 * i] != GATE_PASSIVE) return 0;
        return 1;
    }
    case BLES_OP_LE_EXT_SCAN_ENABLE:
        /* Period non-zero is a periodic scan — still receive-only, but
         * not a shape this helper builds, so not one it admits. */
        return plen == 6 && is_bool(p[0]) && p[4] == 0 && p[5] == 0;
    default:
        return 0;
    }
}

bles_ev_kind_t bles_parse_event(const uint8_t *p, size_t n, bles_ev_t *ev) {
    bles_ev_t e;
    memset(&e, 0, sizeof(e));
    e.kind = BLES_EV_MALFORMED;
    if (p && n >= 3 && p[0] == BLES_H4_EVENT && n == (size_t)3 + p[2]) {
        const uint8_t *q = p + 3;
        size_t plen = p[2];
        e.code = p[1];
        switch (p[1]) {
        case 0x0E:   /* Command Complete: Num, Opcode, Return_Parameters */
            if (plen >= 3) {
                e.kind   = BLES_EV_CMD_COMPLETE;
                e.ncmd   = q[0];
                e.opcode = (uint16_t)(q[1] | (q[2] << 8));
                if (plen >= 4) { e.has_status = 1; e.status = q[3]; }
            }
            break;
        case 0x0F:   /* Command Status: Status, Num, Opcode */
            if (plen == 4) {
                e.kind   = BLES_EV_CMD_STATUS;
                e.status = q[0];
                e.ncmd   = q[1];
                e.opcode = (uint16_t)(q[2] | (q[3] << 8));
            }
            break;
        case 0x10:   /* Hardware Error: Hardware_Code */
            if (plen == 1) {
                e.kind    = BLES_EV_HW_ERROR;
                e.hw_code = q[0];
            }
            break;
        case 0x3E:   /* LE Meta: Subevent_Code, then content not read */
            if (plen >= 1) e.kind = BLES_EV_LE_META;
            break;
        default:
            e.kind = BLES_EV_OTHER;
            break;
        }
    }
    if (ev) *ev = e;
    return e.kind;
}

int bles_ev_lost_scan(const bles_ev_t *ev) {
    return ev && ev->kind == BLES_EV_HW_ERROR;
}

int bles_status_wants_extended(uint8_t status) {
    return status == 0x01 || status == 0x11;
}

void bles_est_begin(bles_est_t *est) {
    if (!est) return;
    est->cmd    = BLES_CMD_RESET;
    est->mode   = BLES_MODE_LEGACY;
    est->status = 0;
}

/* The command after `c` answered with status 0, or -1 when `c` ends the
 * sequence. */
static int est_next(int c) {
    switch (c) {
    case BLES_CMD_RESET:              return BLES_CMD_SET_EVENT_MASK;
    case BLES_CMD_SET_EVENT_MASK:     return BLES_CMD_LE_SET_EVENT_MASK;
    case BLES_CMD_LE_SET_EVENT_MASK:  return BLES_CMD_LE_SCAN_PARAMS;
    case BLES_CMD_LE_SCAN_PARAMS:     return BLES_CMD_LE_SCAN_ENABLE;
    case BLES_CMD_LE_EXT_SCAN_PARAMS: return BLES_CMD_LE_EXT_SCAN_ENABLE;
    default:                          return -1;
    }
}

bles_step_t bles_est_feed(bles_est_t *est, const bles_ev_t *ev) {
    if (!est || !ev) return BLES_STEP_WAIT;
    if (ev->kind == BLES_EV_HW_ERROR) {
        est->status = ev->hw_code;
        return BLES_STEP_HW_ERROR;
    }
    uint8_t st;
    if (ev->kind == BLES_EV_CMD_COMPLETE)
        st = ev->has_status ? ev->status : 0;
    else if (ev->kind == BLES_EV_CMD_STATUS && ev->status != 0)
        st = ev->status;
    else
        return BLES_STEP_WAIT;
    uint16_t op = bles_opcode(est->cmd);
    if (op == 0 || ev->opcode != op) return BLES_STEP_WAIT;

    est->status = st;
    if (st != 0) {
        if (est->cmd == BLES_CMD_LE_SCAN_PARAMS && bles_status_wants_extended(st)) {
            est->cmd = BLES_CMD_LE_EXT_SCAN_PARAMS;
            return BLES_STEP_SEND;
        }
        return BLES_STEP_FAIL;
    }
    if (est->cmd == BLES_CMD_LE_SCAN_ENABLE) {
        est->mode = BLES_MODE_LEGACY;
        return BLES_STEP_DONE;
    }
    if (est->cmd == BLES_CMD_LE_EXT_SCAN_ENABLE) {
        est->mode = BLES_MODE_EXTENDED;
        return BLES_STEP_DONE;
    }
    int next = est_next(est->cmd);
    if (next < 0) return BLES_STEP_FAIL;   /* a cmd the sequence never sends */
    est->cmd = next;
    return BLES_STEP_SEND;
}

int bles_disable_cmd(bles_mode_t mode) {
    return mode == BLES_MODE_EXTENDED ? BLES_CMD_LE_EXT_SCAN_DISABLE
                                      : BLES_CMD_LE_SCAN_DISABLE;
}

int bles_rearm_take(bles_rearm_t *b, uint64_t now_ms) {
    if (!b) return 0;
    int k = 0;
    for (int i = 0; i < b->n; i++)
        if (now_ms - b->at[i] < BLES_REARM_WINDOW_MS) b->at[k++] = b->at[i];
    b->n = k;
    if (b->n >= BLES_REARM_MAX) return 0;
    b->at[b->n++] = now_ms;
    return 1;
}

bles_next_t bles_after_establish(bles_step_t r, bles_rearm_t *b, uint64_t now_ms) {
    if (r == BLES_STEP_DONE) return BLES_NEXT_HOLD;
    if (r == BLES_STEP_HW_ERROR && bles_rearm_take(b, now_ms)) return BLES_NEXT_RETRY;
    return BLES_NEXT_EXIT;
}

int bles_bind_transient(int err) {
    return err == ENODEV || err == EBUSY;
}

int bles_parse_dev(const char *s) {
    if (!s) return -1;
    if (strncmp(s, "hci", 3) == 0) s += 3;
    if (!*s) return -1;
    long v = 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return -1;
        v = v * 10 + (*p - '0');
        if (v > 0xfffe) return -1;   /* HCI_DEV_NONE is 0xffff */
    }
    return (int)v;
}

bles_args_rc_t bles_parse_args(int argc, char *const argv[], bles_args_t *a) {
    bles_args_t r = { 0, 0, 0 };
    int have_dev = 0;
    for (int i = 1; i < argc; i++) {
        const char *s = argv[i];
        if (!strcmp(s, "--down")) {
            r.down = 1;
        } else if (!strcmp(s, "--delay")) {
            if (i + 1 >= argc) return BLES_ARGS_USAGE;
            const char *v = argv[++i];
            long d = 0;
            if (!*v) return BLES_ARGS_BAD_DELAY;
            for (const char *p = v; *p; p++) {
                if (*p < '0' || *p > '9') return BLES_ARGS_BAD_DELAY;
                d = d * 10 + (*p - '0');
                if (d > BLES_DELAY_MAX) return BLES_ARGS_BAD_DELAY;
            }
            r.delay = (int)d;
        } else if (!strcmp(s, "-h") || !strcmp(s, "--help")) {
            return BLES_ARGS_HELP;
        } else if (!have_dev && s[0] != '-' && bles_parse_dev(s) >= 0) {
            r.dev = bles_parse_dev(s);
            have_dev = 1;
        } else {
            return BLES_ARGS_USAGE;
        }
    }
    if (a) *a = r;
    return BLES_ARGS_RUN;
}
