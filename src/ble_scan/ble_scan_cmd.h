#ifndef BLE_SCAN_CMD_H
#define BLE_SCAN_CMD_H

/* sloth-ble-scan's pure half: the only HCI commands it can build, the
 * gate every packet passes before it is written, and the event parser.
 * No I/O here; src/ble_scan/main.c owns the socket. Linked into the
 * helper and the test binary only — never into `sloth`, which sends no
 * HCI command (MISSION.md §2; docs/wiki/ble.md).
 *
 * Clauses are Bluetooth Core Specification v5.4, Vol 4 Part E unless
 * noted: §5.4.1 (command packet), §5.4.4 (event packet), §7.3.1 Set
 * Event Mask, §7.3.2 Reset, §7.7.14 Command Complete, §7.7.15 Command
 * Status, §7.7.16 Hardware Error, §7.7.65 LE Meta, §7.8.1 LE Set Event
 * Mask, §7.8.10 LE Set Scan Parameters, §7.8.11 LE Set Scan Enable,
 * §7.8.64 LE Set Extended Scan Parameters, §7.8.65 LE Set Extended
 * Scan Enable, §3.1.1 (legacy and extended commands do not mix). The
 * H4 packet-type byte that leads every packet on the
 * Linux HCI user channel is Vol 4 Part A §2 (0x01 command, 0x04 event). */

#include <stddef.h>
#include <stdint.h>

#define BLES_H4_CMD   0x01
#define BLES_H4_EVENT 0x04

/* OGF << 10 | OCF (§5.4.1). */
#define BLES_OP_RESET                0x0C03  /* 0x03|0x0003 §7.3.2  */
#define BLES_OP_SET_EVENT_MASK       0x0C01  /* 0x03|0x0001 §7.3.1  */
#define BLES_OP_LE_SET_EVENT_MASK    0x2001  /* 0x08|0x0001 §7.8.1  */
#define BLES_OP_LE_SCAN_PARAMS       0x200B  /* 0x08|0x000B §7.8.10 */
#define BLES_OP_LE_SCAN_ENABLE       0x200C  /* 0x08|0x000C §7.8.11 */
#define BLES_OP_LE_EXT_SCAN_PARAMS   0x2041  /* 0x08|0x0041 §7.8.64 */
#define BLES_OP_LE_EXT_SCAN_ENABLE   0x2042  /* 0x08|0x0042 §7.8.65 */

/* LE_Scan_Type 0x00 (§7.8.10, §7.8.64): passive, "no scanning PDUs
 * shall be sent". The only value this module ever writes or admits. */
#define BLES_SCAN_TYPE_PASSIVE 0x00

/* 0x0060 × 0.625 ms = 60 ms, window = interval: the controller listens
 * continuously, as the reference-host measurement did. */
#define BLES_SCAN_INTERVAL 0x0060
#define BLES_SCAN_WINDOW   0x0060

/* The whole command vocabulary. There is no parameter for the scan
 * type, the address type or the filter policy: each is a constant of
 * the builder, so no caller can ask for an active scan. */
typedef enum {
    BLES_CMD_RESET = 0,
    BLES_CMD_SET_EVENT_MASK,
    BLES_CMD_LE_SET_EVENT_MASK,
    BLES_CMD_LE_SCAN_PARAMS,
    BLES_CMD_LE_SCAN_ENABLE,
    BLES_CMD_LE_SCAN_DISABLE,
    BLES_CMD_LE_EXT_SCAN_PARAMS,
    BLES_CMD_LE_EXT_SCAN_ENABLE,
    BLES_CMD_LE_EXT_SCAN_DISABLE,
    BLES_CMD_COUNT
} bles_cmd_t;

/* Longest packet built: 1 + 3 + 8 (the two event masks). */
#define BLES_CMD_MAX 12

/* Write command `c` as an H4 packet into out[0..cap). Returns its
 * length, or 0 for a value outside the enum or a buffer too short. */
size_t bles_build(int c, uint8_t *out, size_t cap);

/* Opcode of `c`, 0 outside the enum. */
uint16_t bles_opcode(int c);

/* The send gate, independent of the builder: 1 only for an H4 command
 * packet whose opcode is on the allow-list, whose length is that
 * command's, and whose scan type — legacy, or every PHY of an extended
 * one — is passive. Anything else, an active scan, advertising,
 * connection, inquiry or vendor (OGF 0x3F) command included, is 0. */
int bles_cmd_allowed(const uint8_t *pkt, size_t len);

typedef enum {
    BLES_EV_MALFORMED = 0,  /* not an H4 event, or lengths disagree */
    BLES_EV_CMD_COMPLETE,   /* §7.7.14 */
    BLES_EV_CMD_STATUS,     /* §7.7.15 */
    BLES_EV_HW_ERROR,       /* §7.7.16 */
    BLES_EV_LE_META,        /* §7.7.65 — advertising reports; discarded */
    BLES_EV_OTHER
} bles_ev_kind_t;

typedef struct {
    bles_ev_kind_t kind;
    uint8_t  code;        /* event code */
    uint16_t opcode;      /* CMD_COMPLETE / CMD_STATUS */
    uint8_t  ncmd;        /* Num_HCI_Command_Packets */
    uint8_t  has_status;  /* a Command Complete with return parameters */
    uint8_t  status;      /* CMD_STATUS, or CMD_COMPLETE when has_status */
    uint8_t  hw_code;     /* HW_ERROR */
} bles_ev_t;

/* Parse one H4 event packet as read from the user channel. Reads only
 * the header and, for the three events above, their fixed fields; an
 * advertising report's content is never looked at. */
bles_ev_kind_t bles_parse_event(const uint8_t *p, size_t n, bles_ev_t *ev);

/* 1 when the controller has lost the scan without the helper asking: a
 * Hardware Error (§7.7.16 — the host is expected to reset). Nothing
 * else counts. In particular a Command Complete for opcode 0x0000 does
 * not: §7.7.14 makes that a No-Op the controller may send at any time
 * to update Num_HCI_Command_Packets — the kernel treats HCI_OP_NOP as
 * flow control only — so reading it as a restart would let a chatty or
 * slow controller make the helper reset itself out of its own scan. */
int bles_ev_lost_scan(const bles_ev_t *ev);

/* A legacy LE Set Scan Parameters refused as Unknown HCI Command
 * (0x01) or Unsupported Feature or Parameter Value (0x11) — Vol 1
 * Part F §1.3 — means the controller wants the extended commands. */
int bles_status_wants_extended(uint8_t status);

/* ── establishing and ending the scan, as a pure step function ──
 *
 * main.c owns the socket and the clock; every decision is here so the
 * tests can drive it with hand-built events. The sequence: Reset → Set
 * Event Mask → LE Set Event Mask → LE Set Scan Parameters → LE Set Scan
 * Enable (legacy). Only a legacy parameters command refused with a
 * status bles_status_wants_extended() accepts moves to LE Set Extended
 * Scan Parameters → LE Set Extended Scan Enable; any other refusal
 * fails. Legacy first: after a Reset no extended command has been
 * issued, so a controller with both accepts them (it may not mix the
 * two sets between resets, Vol 4 Part E §3.1.1). */
typedef enum { BLES_MODE_LEGACY = 0, BLES_MODE_EXTENDED } bles_mode_t;

typedef enum {
    BLES_STEP_WAIT = 0,  /* not this command's answer: keep reading */
    BLES_STEP_SEND,      /* answered; send est->cmd next */
    BLES_STEP_DONE,      /* the scan is enabled; est->mode is the set in use */
    BLES_STEP_FAIL,      /* refused: est->status is the controller's */
    BLES_STEP_HW_ERROR,  /* Hardware Error: est->status is its code */
    BLES_STEP_IO_ERROR   /* main.c's: the socket failed or timed out */
} bles_step_t;

typedef struct {
    int         cmd;     /* the command in flight (a bles_cmd_t) */
    bles_mode_t mode;
    uint8_t     status;
} bles_est_t;

/* Starts a sequence: est->cmd is HCI_Reset. */
void bles_est_begin(bles_est_t *est);

/* Feeds one parsed event to the sequence. A Command Complete, or a
 * non-zero Command Status, for est->cmd's opcode is its answer; a
 * Command Status 0x00 is "pending" and keeps waiting (none of these
 * commands completes that way, §7.7.15). Everything else — reports,
 * No-Ops, answers to other opcodes — is WAIT. */
bles_step_t bles_est_feed(bles_est_t *est, const bles_ev_t *ev);

/* The disable for the command set the scan was enabled with: legacy LE
 * Set Scan Enable 0x00, or the extended one. Mixing the two is
 * Command Disallowed after an extended enable (§3.1.1), which would
 * leave the scan running and sloth never told it stopped. */
int bles_disable_cmd(bles_mode_t mode);

/* Re-establish budget: at most BLES_REARM_MAX in any
 * BLES_REARM_WINDOW_MS, so a controller that keeps failing ends the
 * process (systemd's restart limit takes over) instead of a hot loop. */
#define BLES_REARM_MAX       5
#define BLES_REARM_WINDOW_MS 60000u

typedef struct {
    uint64_t at[BLES_REARM_MAX];
    int      n;
} bles_rearm_t;

/* 1 and records `now_ms` when a re-establish is allowed; 0 when the
 * budget is spent. */
int bles_rearm_take(bles_rearm_t *b, uint64_t now_ms);

/* What to do once a sequence ends with `r`, first run or re-establish
 * alike. DONE holds the scan. A Hardware Error mid-sequence retries
 * from the Reset while the budget lasts — the usual shape is a second
 * Hardware Error while the host resets after the first, and exiting on
 * it would trade the in-process budget for systemd's restart, which
 * costs the RestartSec, the ExecStartPre and a StartLimitBurst slot.
 * A refusal or a socket failure exits without spending the budget. */
typedef enum { BLES_NEXT_HOLD = 0, BLES_NEXT_RETRY, BLES_NEXT_EXIT } bles_next_t;
bles_next_t bles_after_establish(bles_step_t r, bles_rearm_t *b, uint64_t now_ms);

/* 1 for a user-channel bind errno worth waiting out: ENODEV (hciN not
 * registered yet, at boot) and EBUSY (the kernel still in HCI_SETUP /
 * HCI_INIT on a USB controller). Anything else is final. main.c
 * retries these once a second for BLES_BIND_WAIT_S. */
int bles_bind_transient(int err);
#define BLES_BIND_WAIT_S 30

/* ── argv ── */
typedef struct {
    int dev;     /* hciN; 0 when none is named */
    int down;    /* --down */
    int delay;   /* --delay SECS, 0..BLES_DELAY_MAX */
} bles_args_t;

#define BLES_DELAY_MAX 60

typedef enum {
    BLES_ARGS_RUN = 0,
    BLES_ARGS_HELP,
    BLES_ARGS_USAGE,      /* exit 2 */
    BLES_ARGS_BAD_DELAY   /* exit 2 */
} bles_args_rc_t;

/* "hci3" or "3" → 3; -1 for anything else, an empty string included
 * (the unit's ${SLOTH_BLE_HCI} is always exactly one argument, so an
 * empty setting arrives as "" and is a usage error, not hci0). */
int bles_parse_dev(const char *s);

/* sloth-ble-scan [--down] [--delay SECS] [hciN] | -h | --help */
bles_args_rc_t bles_parse_args(int argc, char *const argv[], bles_args_t *a);

#endif /* BLE_SCAN_CMD_H */
