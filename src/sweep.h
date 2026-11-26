#ifndef SLOTH_SWEEP_H
#define SLOTH_SWEEP_H

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include "sloth.h"
#include "wifi_chanhop.h"

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
 * Addresses that rotate are counts unless resolved (owner rulings
 * 2026-11-25). Public and static random BLE addresses and universal
 * Wi-Fi client addresses are kept per label. A resolvable or
 * non-resolvable private BLE address, and a Wi-Fi client address with
 * the locally administered bit (IEEE 802-2014 §8.2, the randomised
 * address of every current phone), are counted as distinct addresses
 * heard, to SW_SET_CAP (past that the count says "at least"), and are
 * kept and compared only once RESOLVED: the passive evidence says the
 * address itself is stable (below, and
 * research/papers/randomised-address-resolution.md). A resolved row's
 * identity is its own address and nothing else, so a device can be
 * KNOWN only when the very same address is in the baseline: no two
 * addresses are ever merged into one baseline identity, because a
 * wrong merge would hide a new device behind a known one. The rest
 * stay counted.
 *
 *   assoc       a randomised Wi-Fi client address in a (re)association
 *               exchange: the address a client joins with is per network
 *               and persistent (Android) or fixed or slowly rotating
 *               (Apple). Confidence SW_CONF_ASSOC.
 *   persistent  a randomised Wi-Fi client address, or a private BLE
 *               address, heard over at least SW_STABLE_SPAN_S within the
 *               sweep (BLE: past Core v5.4's recommended 15-min private
 *               address change; Wi-Fi: the same span as a judgement).
 *               Confidence SW_CONF_PERSIST.
 *   seqnum      a randomised probe address whose sequence numbers
 *               continue, strongly (seqnum_corr_is_strong()), into a
 *               universal client address: counted as LINKED to that
 *               device, never a row, and no row's status changes.
 *
 * IE fingerprints, probed SSID lists and the BLE rotation hints are not
 * used (the research note says why).
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
/* Randomised addresses followed for resolution, per sweep. A full table
 * follows no more: the rest stay counted (unresolved), never merged. */
#define SW_MAX_CAND    1024
/* "persistent": heard over this span within the sweep, seconds. */
#define SW_STABLE_SPAN_S 900
/* Confidence, 0..100, the seqnum_track axis: how likely the address
 * names one device at the next sweep. Ordinal judgements, not rates
 * (research/papers/randomised-address-resolution.md). */
#define SW_CONF_ASSOC    60
#define SW_CONF_PERSIST  40

typedef enum { SW_K_AP = 0, SW_K_CLIENT, SW_K_BLE, SW_K_N } sw_kind_t;

/* A kept BLE address's kind: Address_Type 0 (public) or a resolved
 * public identity (2); Address_Type 1 with the top two bits 11 (static
 * random, Core v5.4 Vol 6 Part B §1.3.2.1) or a resolved static
 * identity (3). */
typedef enum { SW_BLE_PUBLIC = 0, SW_BLE_STATIC = 1,
               SW_BLE_PRIVATE = 2 /* a resolved private address */ } sw_ble_type_t;

/* How a randomised address was resolved (above); NONE for an address
 * kept for what it is (universal, public, static). */
typedef enum { SW_RES_NONE = 0, SW_RES_ASSOC, SW_RES_PERSIST } sw_res_t;

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
    uint8_t  res;           /* sw_res_t: a resolved randomised address */
    uint8_t  res_conf;      /* its confidence, 0..100 */
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

/* A randomised address followed for resolution. */
typedef struct {
    uint8_t  kind;          /* SW_K_CLIENT or SW_K_BLE */
    uint8_t  addr[6];
    uint8_t  assoc;         /* seen in a (re)association exchange */
    uint8_t  resolved;      /* promoted to a row */
    time_t   first_seen, last_seen;
} sw_cand_t;

typedef struct {
    int          n;
    sw_emitter_t e[SW_MAX_EMIT];
    int          per_kind[SW_K_N];
    uint64_t     dropped[SW_K_N];   /* heard while the kind's cap was full */
    sw_set_t     ble_private;       /* RPA / NRPA / anonymous: counted */
    sw_set_t     client_random;     /* locally administered client addresses */
    sw_set_t     client_linked;     /* of those, linked by seqnum to a universal one */
    sw_cand_t    cand[SW_MAX_CAND];
    int          ncand;
    uint64_t     cand_dropped;      /* not followed: the table was full */
    /* Whether a file read back held the kind (a v1 snapshot holds APs
     * only), and its counts lines. Set by wifi_snapshot_read(). */
    int          has_kind[SW_K_N];
    int          file_ble_private, file_client_random;
    /* The file holds resolved randomised addresses as rows (its
     * "# resolved" line): a baseline written before resolution existed
     * holds none, and a resolved row is then not compared. */
    int          has_resolved;
} sw_inv_t;

/* The counts of the randomised addresses: distinct heard, resolved to a
 * row, linked by seqnum (and not resolved), and the rest, unresolved. */
typedef struct {
    int client_random, client_resolved, client_linked, client_unresolved;
    int ble_private, ble_resolved, ble_unresolved;
    int floor;              /* a set was full: the figures are floors */
} sw_rand_t;
void sweep_rand_counts(const sw_inv_t *inv, sw_rand_t *out);

/* "assoc", "persistent", "" */
const char *sweep_res_name(int res);

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
 * SW_BLE_STATIC when the address is kept, -1 when it is counted (and
 * may be resolved: private) or ignored (anonymous, the reserved
 * sub-type). Pure. */
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
 * baseline's in base_channel / base_enc. A resolved randomised row is
 * compared only against a baseline that holds such rows
 * (compared_resolved); against an older one it is NEW and the report
 * says the resolved rows were not compared. */
typedef struct {
    int           n;
    sw_emitter_t *row;                      /* heap, n rows */
    int           count[SW_K_N][3];         /* [kind][sw_status_t] */
    int           compared[SW_K_N];         /* the baseline holds the kind */
    int           compared_resolved;        /* ... and resolved rows */
    int           have_base;
} sw_cmp_t;

/* 0, or -1 on allocation failure (out is then empty). `base` NULL: no
 * accepted baseline for the label. */
int  sweep_compare(const sw_inv_t *cur, const sw_inv_t *base, sw_cmp_t *out);
void sweep_cmp_free(sw_cmp_t *c);

/* ── Coverage (src/sweep_cov.c) ──
 *
 * What the sweep's radios actually did, channel by channel: time on the
 * channel (the schedulers' own dwell accounting, chanhop_slot_time_ms(),
 * differenced each poll per radio, so a re-deal that resets a scheduler
 * loses nothing), frames attributed, visits, and retunes the driver
 * refused. A channel is swept when time was spent on it; one in the
 * plan with none is not swept, with its refusals if it had any. The
 * plan is the full list as chanhop_init_sweep() built it, before the
 * radios' deal. Pure over chanhop_t: a test drives it with a synthetic
 * clock through the fake platform. */
#define SW_COV_MAX CHANHOP_MAX

typedef struct {
    int      freq_mhz;
    int      channel;
    int      band;          /* wifi_band_t */
    uint64_t ms;            /* time on the channel, all radios */
    uint64_t frames;
    uint32_t visits;
    uint32_t refusals;
} sw_cov_ch_t;

#define SW_COV_RADIOS 8

typedef struct {
    int         n;
    sw_cov_ch_t ch[SW_COV_MAX];
    uint32_t    planned_dwell_ms;     /* the full list's equal dwell */
    uint64_t    sweep_ms;             /* the time given */
    uint64_t    start_ms, last_ms;    /* monotonic, first and last sample */
    int         radios;               /* radios that held a share */
    /* Per radio, the scheduler's slots as last read. */
    struct {
        int      n;
        int      freq[CHANHOP_MAX];
        uint64_t ms[CHANHOP_MAX];
        uint64_t fr[CHANHOP_MAX];
        uint32_t vis[CHANHOP_MAX];
        uint32_t ref[CHANHOP_MAX];
    } base[SW_COV_RADIOS];
} sw_cov_t;

/* Start from the plan (`full`, as chanhop_init_sweep() left it). */
void sweep_cov_init(sw_cov_t *c, const chanhop_t *full, uint64_t now_ms);
/* One radio's scheduler at now_ms (radio 0 is main.c's; k >= 1 the
 * further --monitor-iface radios). A slot whose frequency moved or
 * whose totals fell (a re-deal reset the scheduler) is differenced from
 * zero. */
void sweep_cov_sample(sw_cov_t *c, int radio, const chanhop_t *h, uint64_t now_ms);
/* Channels swept (time > 0) and not swept. */
int  sweep_cov_swept(const sw_cov_t *c);

/* ── The report (src/sweep_report.c) ──
 *
 * Markdown and JSON, from the comparison, the coverage and the facts of
 * the run, and one `sweep_report` JSONL record (counts, words and
 * channel numbers; no address, SSID or name). Each says what was not
 * swept and the fixed limits of a sweep. */
typedef enum {
    SW_END_TIME = 0,     /* the time given ran out */
    SW_END_PASS,         /* every radio finished its one pass */
    SW_END_STOPPED       /* stopped before either (a signal, q) */
} sw_end_t;

typedef struct {
    const char     *label;
    time_t          start, end;       /* wall */
    unsigned        minutes;
    int             end_why;          /* sw_end_t */
    const sw_cov_t *cov;
    const sw_cmp_t *cmp;
    const sw_inv_t *inv;              /* the counts-only sets, dropped rows */
    int             base_version;     /* 0 no baseline, 1, 2 */
    const char     *baseline_path;
    const char     *candidate_path;   /* this sweep's inventory, NULL if unwritten */
    int             mon_up;           /* the monitor radio's worker at the end */
    int             ble_configured;   /* --bt-monitor or --bt-capture */
    int             ble_up;
} sw_report_t;

/* The sweep's end word: "time", "pass", "stopped". */
const char *sweep_end_name(int end_why);
/* The bands the sweep did not cover, comma-separated ("6ghz,sub_ghz",
 * with "2.4ghz" / "5ghz" when no channel of it was swept). */
void sweep_bands_not_swept(const sw_cov_t *c, char *out, size_t sz);

void sweep_report_md(FILE *out, const sw_report_t *r);
void sweep_report_json(FILE *out, const sw_report_t *r);
/* The `sweep_report` record. A no-op with no JSONL sink open. */
void sweep_report_emit(const sw_report_t *r);

/* "ap", "client", "ble"; "public", "static", "private"; "new", "known",
 * "missing". */
const char *sweep_kind_name(int kind);
const char *sweep_ble_type_name(int t);
const char *sweep_status_name(int st);

#endif /* SLOTH_SWEEP_H */
