#ifndef BLE_ROTATION_H
#define BLE_ROTATION_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "sloth.h"
#include "ble_snoop.h"

/* BLE address-rotation hints (#156 item 2). INTERNAL USE ONLY, OFF BY
 * DEFAULT, enabled by --ble-rotation-hints (owner ruling 2026-10-23).
 * Design basis and grades: research/bluetooth/ble-address-rotation.md.
 *
 * ── What it is ──
 *
 * A hypothesis that one private BLE address was replaced by another on
 * the same sensor: "possible address rotation". It is an enrichment on
 * the advertiser rows (ble_identity_hint_t in sloth.h), not an alert
 * kind, because what it describes is an advertiser's own privacy
 * behaviour and no adversary is implied. It corroborates one advertiser
 * rotating its address; it does not confirm it, and it identifies no
 * device or person. These records alone are not grounds for personnel
 * action or physical identification.
 *
 * ── Who reads it ──
 *
 * Internal consumers only: the [*] view's de-duplicated advertiser
 * estimate, and BLE_HID_UNEXPECTED's rotation form (one keyboard
 * rotating its RPA is not N new HID addresses). No row shows a link, no
 * JSONL field names a link or a token, nothing goes to the database.
 * What leaves the process is four aggregate counters in sensor_health
 * (ble_rot_hints_payload, ble_rot_hints_timing, ble_rot_poisoned,
 * ble_rot_seam_evictions), which carry no address, and only while the
 * flag is on.
 *
 * ── Candidates ──
 *
 * Address_Type 1 (random, as received) whose top two bits of the
 * address (Core v5.4 Vol 6 Part B §1.3.2) are 01 (resolvable private)
 * or 00 (non-resolvable private). A static random address (11), a
 * public address, a resolved identity address (Address_Type 2 or 3:
 * the operator's controller resolved it with an IRK it holds), an
 * anonymous report (0xFF) and the reserved sub-type 10 never rotate in
 * the sense the spec's privacy feature defines and are never
 * candidates: they are not even stored. A link joins two addresses of
 * the same sub-type only.
 *
 * ── Grades (the research document's) ──
 *
 *   A  a documented identifying token carried across the seam, kept
 *      only as a SipHash-2-4 digest under a per-run random key:
 *        MS-CDP: company 0x0006, Scenario_Type 1, a whole 27-octet
 *          beacon; the token is Salt (4) + Device_Hash (19), the four
 *          fixed leading octets excluded ([MS-CDP] 2.2.2.2.3).
 *        Apple Handoff: company 0x004C, Continuity type 0x0C, length
 *          14; the token is the body after its first octet (the
 *          clipboard/version octet, a near-constant). UNVERIFIED: no
 *          vendor specification, the layout is the papers' (Martin et
 *          al. 2019 Fig. 2; Celosia and Cunche 2020 Fig. 9), and Jouans
 *          et al. 2021 saw carry-over associate nothing on iOS 13.
 *        Fast Pair account data: Service Data 0xFE2C in the
 *          non-discoverable form, an Account Key Filter of at least 4
 *          octets and a 2-octet Salt; the token is filter + salt, so it
 *          matches only when the salt did NOT change, which is the
 *          vendor ignoring the spec's "should be regenerated every time
 *          the RPA is updated".
 *   B  exclusivity plus a seam: the old address's last report precedes
 *      the new address's first in arrival order on one sensor, the gap
 *      is at most BLE_ROT_DSWAP_S, and the old one is not heard again
 *      (an interleaving revokes the link). Required for every link.
 *   C  shape agreement, corroborators only: Event_Type, payload family
 *      key (company ID and first octet, or Service Data UUID) and the
 *      AD structure list with lengths. B + C without A is a `timing`
 *      hint, used only for de-duplication, never shown as a link.
 *
 * The research's T_int corroborator (advertising interval in 10 ms
 * bins) is NOT implemented: device rows carry the frame clock at one
 * second, which cannot bin a 20 ms..10 s interval. Stated, not faked.
 *
 * ── Guards ──
 *
 *   - A token digest heard on two addresses whose reports interleave
 *     is poisoned for BLE_ROT_POISON_S on that sensor, and every link
 *     resting on it is revoked (replay and spam tools, Apple's
 *     concurrent addresses).
 *   - No link, and no candidacy, for an address heard while
 *     BLE_ADV_FLOOD's fresh-address gate is active on its payload key
 *     (ble_flood_fresh_active()): spam tools replay genuine Continuity
 *     payloads under fresh addresses.
 *   - Never across sensors or adapters: one seam table per (sensor
 *     kind, iface, HCI adapter).
 *   - Never a Fast Pair discoverable advertisement (Model ID form,
 *     where "the BLE address shall not be rotated"): an address that
 *     sent one is never a candidate, either side.
 *   - A chain is capped at BLE_ROT_MAX_HOPS links and BLE_ROT_RETAIN_S
 *     from its first address's first report; an entry unheard for
 *     BLE_ROT_RETAIN_S is dropped.
 *   - A timing link with a second arrival in the same seam is
 *     ambiguous and is not committed.
 *
 * A link is PENDING until BLE_ROT_DSWAP_S has passed since the new
 * address's first report with the old one silent, then COMMITTED and
 * counted. Only committed links reach the rows.
 *
 * ── Bounded state ──
 *
 * BLE_ROT_SENSORS seam tables of BLE_ROT_SEAM entries, allocated on the
 * first observation after the flag enabled them and never otherwise; a
 * full table drops its least recently heard entry (STAB_OLDEST
 * semantics), tallied as ble_rot_seam_evictions. That tally is not an
 * `evict_*` field: the evict_* breakout is emitted on every run, and a
 * run without the flag must write byte-identical output. Per entry:
 * the address, its sub-type, first/last arrival and frame time, the
 * shape tuple, and up to BLE_ROT_TOKENS digests. Token bytes are never
 * stored, the digest is never exported or persisted, and the key is
 * drawn from getrandom() per run, so no digest is comparable across
 * runs.
 *
 * Thread model: every function but the pure ones is called from
 * src/ble_hci.c with its module mutex held. */

#define BLE_ROT_SEAM        64
#define BLE_ROT_SENSORS     8
#define BLE_ROT_TOKENS      4
#define BLE_ROT_POISON_MAX  16
/* Jouans et al. bound the seam by d_swap = 10 x T_int. T_int is not
 * measurable at the one-second frame clock (above), so d_swap is ten
 * of those seconds: a judgement, stated as one. */
#define BLE_ROT_DSWAP_S     10
/* Core v5.4 Vol 3 Part C Appendix A: T_GAP(private_addr_int), the
 * recommended MAXIMUM interval between private address changes, is
 * 15 min. A poisoned token outlives every address the spec's
 * recommendation would put it on. */
#define BLE_ROT_POISON_S    900
#define BLE_ROT_MAX_HOPS    8
#define BLE_ROT_RETAIN_S    7200
/* Confidence ceilings, 0..100 (cf. corr_confidence() in
 * src/seqnum_track.c). Neither reaches the upper band: a hint is a
 * corroborator, never a finding. */
#define BLE_ROT_CONF_PAYLOAD_MAX 60
#define BLE_ROT_CONF_TIMING_MAX  25

typedef enum {
    BLE_TOK_NONE = 0,
    BLE_TOK_MS_CDP,          /* Salt + Device_Hash */
    BLE_TOK_APPLE_HANDOFF,   /* unverified */
    BLE_TOK_FAST_PAIR_ACCOUNT
} ble_token_kind_t;

/* One token found in a report: a view into the report's own bytes,
 * valid only while the report is. Never copied anywhere. */
typedef struct {
    uint8_t        kind;     /* ble_token_kind_t */
    const uint8_t *bytes;
    uint8_t        len;
} ble_token_t;

/* Tokens in `r`, at most `max`. *fp_discoverable (if non-NULL) is set
 * to 1 when `r` carries a Fast Pair discoverable advertisement (Model
 * ID form, plain or LE Audio Sharing). Pure. */
int ble_rot_tokens(const ble_adv_report_t *r, ble_token_t *out, int max,
                   int *fp_discoverable);

/* 1 when (Address_Type, address in display order) can be a candidate. */
int ble_rot_addr_candidate(uint8_t addr_type, const uint8_t addr[6]);

/* Turn the feature on or off. On draws a fresh key; off frees the
 * tables and zeroes the counters, so nothing survives. Called by
 * ble_hci_rotation_enable() under its mutex. Returns 0, or -1 when no
 * key could be drawn (the feature then stays off). */
int  ble_rot_set_enabled(int on);
int  ble_rot_enabled(void);

/* One observation from ble_hci.c. `addr` display order. `flooded` is
 * ble_flood_fresh_active() for this report. */
void ble_rot_observe(const ble_adv_report_t *r, uint8_t sensor_kind,
                     const char *iface, uint16_t adapter,
                     const uint8_t addr[6], time_t ts, int flooded);

/* Commit what is due and copy the committed hints onto the rows in
 * `s->ble_devices`, and the counters into `s->ble_rot`. With the
 * feature off it only zeroes `s->ble_rot` and touches no table. */
void ble_rot_snapshot(sloth_state_t *s);

/* Empty the tables (ble_clear()); counters, key and the on/off state
 * are kept. */
void ble_rot_drop_tables(void);

/* Back to the shipped state: off, no tables, no key, counters zero.
 * The test registry's reset (src/reset_all.h), so no test inherits the
 * flag from another. */
void ble_rot_reset(void);

/* De-duplicated count over the rows `keep` accepts (all rows when NULL):
 * rows sharing a committed chain count once. With no hints on the rows
 * this is the plain row count. */
int ble_rot_distinct(const sloth_state_t *s,
                     int (*keep)(const ble_device_t *d, void *ctx),
                     void *ctx);

/* Test seams. allocated: 1 once any seam table exists. digest: the
 * digest this run would hold for a token, so a test can search every
 * output for it. key_set: pin the key (tests only). */
int      ble_rot_test_allocated(void);
uint64_t ble_rot_test_digest(uint8_t kind, const uint8_t *bytes, size_t len);
void     ble_rot_test_set_key(const uint8_t key[16]);

#endif /* BLE_ROTATION_H */
