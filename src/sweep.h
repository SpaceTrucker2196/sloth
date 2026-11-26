#ifndef SLOTH_SWEEP_H
#define SLOTH_SWEEP_H

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include "sloth.h"

/* ── Sweep inventory (#249) ──────────────────────────────────────────
 *
 * What a sweep heard, kept for the whole sweep rather than read from
 * the state tables at its end: the beacon table ages an AP out after
 * BEACON_AGE_SECS and a probing client after PROBE_AGE_SECS, so a
 * sweep longer than that would forget what it heard on its first
 * channels. sweep_inv_observe() merges the state's tables in once a
 * poll; an emitter, once heard, stays in the inventory with its
 * strongest signal and the channel it was last heard on.
 *
 * Three kinds, each keyed by its address:
 *
 *   ap      the beacon table (monitor radio), keyed by BSSID
 *   client  probing clients and (re)association requests and responses
 *           (monitor radio), keyed by the station address
 *   ble     BLE advertisers (the HCI monitor channel or an Ubertooth),
 *           keyed by address and its kind
 *
 * Addresses that rotate are counts only and never an emitter (owner
 * ruling 2026-11-25 for BLE: public and static random addresses are
 * kept per label; resolvable and non-resolvable private addresses are
 * counted, never NEW or KNOWN). A Wi-Fi client address with the locally
 * administered bit set (IEEE 802-2014 §8.2, the randomised address of
 * every current phone) is held the same way: it changes per network and
 * per scan, so it would be NEW at every sweep. Both are counted as
 * distinct addresses heard, to SW_SET_CAP; past that the count says
 * "at least".
 *
 * The same inventory is what the site snapshot file holds since its
 * format v2 (src/wifi_snapshot.h): wifi_snapshot_write() builds one
 * from the state and writes it, and a sweep writes its own. Nothing
 * here transmits or touches a radio: it reads sloth_state_t. */

#define SW_MAX_AP      512
#define SW_MAX_CLIENT  512
#define SW_MAX_BLE     512
#define SW_MAX_EMIT    (SW_MAX_AP + SW_MAX_CLIENT + SW_MAX_BLE)
#define SW_SET_CAP     4096

typedef enum { SW_K_AP = 0, SW_K_CLIENT, SW_K_BLE, SW_K_N } sw_kind_t;

/* A kept BLE address's kind: Address_Type 0 (public) or a resolved
 * public identity (2); Address_Type 1 with the top two bits 11 (static
 * random, Core v5.4 Vol 6 Part B §1.3.2.1) or a resolved static
 * identity (3). */
typedef enum { SW_BLE_PUBLIC = 0, SW_BLE_STATIC = 1 } sw_ble_type_t;

/* The flags of the sweep report's own section (cameras, devices in
 * setup mode, hidden-name access points). */
#define SW_F_HIDDEN  0x01u   /* AP whose beacon carried no SSID */
#define SW_F_CAMERA  0x02u   /* a camera vendor's address block or setup SSID */
#define SW_F_SETUP   0x04u   /* a setup SoftAP (camera or OPEN_SETUP_AP) */

/* Compared with the label's baseline (sweep_compare()). */
typedef enum { SW_ST_NEW = 0, SW_ST_KNOWN, SW_ST_MISSING } sw_status_t;

typedef struct {
    uint8_t  kind;          /* sw_kind_t */
    uint8_t  addr[6];       /* display order */
    uint8_t  ble_type;      /* sw_ble_type_t, BLE only */
    uint8_t  flags;         /* SW_F_* */
    uint8_t  status;        /* sw_status_t, after sweep_compare() */
    uint8_t  has_dbm;       /* best_dbm was measured */
    int8_t   best_dbm;      /* strongest heard, dBm */
    int      channel;       /* 802.11 channel last heard on; BLE: LL
                             * channel index, -1 unknown */
    int      mfp;           /* AP: 0/1/2 */
    char     ssid[33];      /* AP: the octets heard, "" hidden */
    char     enc[16];       /* AP */
    char     akm[32];       /* AP */
    char     vendor[32];    /* AP: vendor IE guess; client: OUI vendor */
    char     name[33];      /* BLE: advertised local name */
    char     cat[16];       /* BLE: watch-list category, "" none */
    char     camera[24];    /* the camera vendor or setup label, "" */
    time_t   first_seen, last_seen;
    /* Baseline side of a KNOWN row whose AP fields moved (sweep.c):
     * the channel and encryption the baseline holds. */
    int      base_channel;
    char     base_enc[16];
} sw_emitter_t;

/* A set of distinct addresses, for the counts-only kinds. */
typedef struct {
    uint64_t key[SW_SET_CAP];
    int      n;
    int      full;          /* an address was not added: n is a floor */
} sw_set_t;

typedef struct {
    int          n;
    sw_emitter_t e[SW_MAX_EMIT];
    int          per_kind[SW_K_N];
    uint64_t     dropped[SW_K_N];   /* heard while the kind's cap was full */
    sw_set_t     ble_private;       /* RPA / NRPA / anonymous: counted */
    sw_set_t     client_random;     /* locally administered client addresses */
    /* Whether a file read back held the kind (a v1 snapshot holds APs
     * only), and its counts lines. Set by wifi_snapshot_read(). */
    int          has_kind[SW_K_N];
    int          file_ble_private, file_client_random;
} sw_inv_t;

/* Heap: the inventory is about 400 KiB. NULL on allocation failure. */
sw_inv_t *sweep_inv_new(void);
void      sweep_inv_free(sw_inv_t *inv);
void      sweep_inv_clear(sw_inv_t *inv);

/* Merge the state's AP, client and BLE tables in (main thread, after
 * poll_data(), or a test's state). Camera, setup-mode and hidden flags
 * are taken here, from the address's vendor block (camera_vendor.h),
 * the setup SSID tables and the open OPEN_SETUP_AP findings. */
void sweep_inv_observe(sw_inv_t *inv, const sloth_state_t *s);

/* Add one row as read from a file (wifi_snapshot_read()); the row's
 * kind and address are the key. 0, or -1 when the kind is full. */
int  sweep_inv_add(sw_inv_t *inv, const sw_emitter_t *e);

/* The row of `kind` at `addr` (and ble_type for BLE), or NULL. */
const sw_emitter_t *sweep_inv_find(const sw_inv_t *inv, int kind,
                                   const uint8_t addr[6], int ble_type);

/* Distinct addresses in a counts-only set. */
int  sweep_set_count(const sw_set_t *set);

/* A BLE row's kind under the owner ruling: SW_BLE_PUBLIC or
 * SW_BLE_STATIC when the address is kept, -1 when it is counted only
 * (private, anonymous or the reserved sub-type). Pure. */
int  sweep_ble_kept_type(uint8_t addr_type, const uint8_t addr[6]);

/* ── Compare with the label's baseline ──
 *
 * Every emitter heard is NEW (not in the baseline) or KNOWN; every row
 * of the baseline not heard is MISSING. A kind the baseline does not
 * hold (a v1 file holds APs only, and a first sweep has no baseline at
 * all) is compared against nothing: its rows are NEW and compared[kind]
 * is 0, so the report can say so rather than call a site's every phone
 * new. The rows are sorted: NEW first, then KNOWN, each strongest
 * signal first (an unknown strong emitter is probably in the room) and
 * a row with no measured signal last; MISSING last, by kind and
 * address. A KNOWN AP whose channel or encryption moved keeps the
 * baseline's in base_channel / base_enc. */
typedef struct {
    int           n;
    sw_emitter_t *row;                      /* heap, n rows */
    int           count[SW_K_N][3];         /* [kind][sw_status_t] */
    int           compared[SW_K_N];         /* the baseline holds the kind */
    int           have_base;
} sw_cmp_t;

/* 0, or -1 on allocation failure (out is then empty). `base` NULL: no
 * accepted baseline for the label. */
int  sweep_compare(const sw_inv_t *cur, const sw_inv_t *base, sw_cmp_t *out);
void sweep_cmp_free(sw_cmp_t *c);

/* "ap", "client", "ble"; "public", "static"; "new", "known", "missing". */
const char *sweep_kind_name(int kind);
const char *sweep_ble_type_name(int t);
const char *sweep_status_name(int st);

#endif /* SLOTH_SWEEP_H */
