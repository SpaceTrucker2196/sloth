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
 * One internal consumer: the [*] view's de-duplicated advertiser
 * estimate over the recent window (payload and timing chains, see
 * ble_rot_distinct()). No detector reads a hint, and none may: a token
 * is whatever the advertiser chooses to send, so a link an attacker
 * can manufacture must never suppress a security finding.
 * BLE_HID_UNEXPECTED counts addresses with the flag on exactly as with
 * it off. ble_identity_hint_t.root_first is a documented hook for the
 * deferred "non-resident" definition (src/ble_detect.h) and has no
 * consumer. No row shows a link, no JSONL field names a link or a token, nothing goes to
 * the database. What leaves the process is three banded aggregates in
 * sensor_health (ble_rot_hints, ble_rot_poisoned,
 * ble_rot_seam_evictions: "0", "1-9", "10-99", "100-999", "1000+"),
 * which carry no address, do not split payload from timing, enter no
 * change-only signature, and appear only while the flag is on. Exact
 * counts and the split would let a consumer match an increment to the
 * one departure/arrival pair on a quiet sensor, ten seconds after the
 * newer address's first ble_device record, and learn the two carried
 * the same token; bands and no signature edge leave a coarser
 * residual: a band crossing, seen at the next heartbeat.
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
 *          non-discoverable form, an Account Key Filter of at least
 *          BLE_ROT_FP_FILTER_MIN octets and a 2-octet Salt; the token is
 *          filter + salt (the fixed 0x21 header between them left out),
 *          so it matches only when the salt did NOT change, which is the
 *          vendor ignoring the spec's "should be regenerated every time
 *          the RPA is updated". A 4-octet filter (one key) is the form
 *          but not a token: at most 8 bits set in 32 is <= 23.8 bits,
 *          39.8 with the salt, under the 40-bit bound; 5 octets (two
 *          keys) reach at most 53.1. Ceilings, not measured entropy, and
 *          in the very case the row exists for the salt may be constant.
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
 *   - A token digest heard on two addresses whose reports interleave,
 *     or on BLE_ROT_SPRAY_ADDRS addresses first heard inside one
 *     d_swap (a replay sprayed on fresh addresses one after another
 *     never interleaves), is poisoned for BLE_ROT_POISON_S on that
 *     sensor, and every link resting on it is revoked (replay and spam
 *     tools, Apple's concurrent addresses). A full poison list fails
 *     closed: no payload link on the sensor for the window the
 *     unrecorded poison would have had, never an early re-arm.
 *   - No link, and no candidacy, for an address heard while
 *     BLE_ADV_FLOOD's fresh-address gate is active on its payload key
 *     (ble_flood_fresh_active()): spam tools replay genuine Continuity
 *     payloads under fresh addresses. A report under the gate also
 *     excludes every entry on its key on that sensor, whatever the
 *     reporting address, so a link proposed before the gate tripped is
 *     refused at commit.
 *   - No link proposed, and none committed, on an HCI adapter whose
 *     LE Set (Extended) Scan Enable Filter_Duplicates (Vol 4 Part E
 *     §7.8.11, §7.8.65) is on or was never seen: a filtering
 *     controller reports an address once, so the re-report both the
 *     exclusivity guard and poisoning rest on never arrives. The
 *     Ubertooth stream is raw air and is not filtered.
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
 * Links are WINDOW-SCOPED: one exists only while both its entries are
 * in the seam table. Freeing an entry (evicted, or past retention)
 * revokes both its links, and a row whose address has no entry carries
 * no hint at the next snapshot. So no link outlives what could revoke
 * it, and the estimate covers the recent window only.
 *
 * ── Bounded state ──
 *
 * BLE_ROT_SENSORS seam tables of BLE_ROT_SEAM entries, allocated on the
 * first observation after the flag enabled them and never otherwise; a
 * full table drops its least recently heard entry (STAB_OLDEST
 * semantics), tallied as ble_rot_seam_evictions. That tally is not an
 * `evict_*` field: the evict_* breakout is emitted on every run, and a
 * run without the flag must write the same output. Per entry: the
 * address, its sub-type, first/last arrival and frame time, the shape
 * tuple, and up to BLE_ROT_TOKENS digests. Token bytes are never
 * stored, the digest is never exported or persisted, and the key is
 * drawn from getrandom() per run, so no digest is comparable across
 * runs.
 *
 * Expiry runs on the frame clock carried forward by monotonic time
 * since the sensor's last report (sensor_now()), so a quiet radio or an
 * ended capture file still expires. An entry no link rests on, silent
 * BLE_ROT_FORGET_S, loses its digests and shape (the research's
 * freshness rule: d_swap after the last report, plus the d_swap a
 * pending link waits). An entry a pending or committed link rests on,
 * either side, keeps them until the link is revoked or the entry is
 * freed: the older address heard again must still poison the token the
 * link rests on. Address and chain fields stay to BLE_ROT_RETAIN_S,
 * because the interleave guard needs to recognise the older address if
 * it speaks again. Expired poison slots are wiped. Turning the feature
 * on or off clears every row's hint.
 *
 * Thread model: every function but the pure ones is called from
 * src/ble_hci.c with its module mutex held. */

#define BLE_ROT_SEAM        64
#define BLE_ROT_SENSORS     8
#define BLE_ROT_TOKENS      4
#define BLE_ROT_POISON_MAX  16
/* Addresses first heard inside one d_swap carrying one token: two is
 * a rotation seen from both sides of a short seam, three is not one
 * advertiser. */
#define BLE_ROT_SPRAY_ADDRS 3
/* Fast Pair: the shortest Account Key Filter whose filter + salt can
 * clear the 40-bit bound (above). */
#define BLE_ROT_FP_FILTER_MIN 5
/* Jouans et al. bound the seam by d_swap = 10 x T_int. T_int is not
 * measurable at the one-second frame clock (above), so d_swap is ten
 * of those seconds: a judgement, stated as one. */
#define BLE_ROT_DSWAP_S     10
#define BLE_ROT_FORGET_S    (2 * BLE_ROT_DSWAP_S)
/* Sized to the token, not the address. The longest documented token
 * life in research/bluetooth/ble-address-rotation.md is about an hour:
 * MS-CDP's last 23 octets "static about 1 h" while the address changes
 * about every 960 s (Becker et al. 2019), Device_Hash about 60 min
 * against an address of about 16 min (Celosia and Cunche 2019). Core
 * v5.4 Vol 3 Part C Appendix A's 15-min T_GAP(private_addr_int) bounds
 * addresses only, so a 900 s window would re-arm a token still live. */
#define BLE_ROT_POISON_S    3600
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
    const uint8_t *bytes2;   /* a second run of the same token, or NULL */
    uint8_t        len2;
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
 * ble_flood_fresh_active() for this report. `blind` is 1 when the
 * stream's controller may be filtering duplicate reports (HCI adapter
 * with Filter_Duplicates on or never seen). */
void ble_rot_observe(const ble_adv_report_t *r, uint8_t sensor_kind,
                     const char *iface, uint16_t adapter,
                     const uint8_t addr[6], time_t ts, int flooded,
                     int blind);

/* Expire and commit what is due on every table, on each sensor's
 * carried-forward clock. No-op with the feature off. */
void ble_rot_tick_all(void);

/* Copy the committed hint onto one live advertiser row (ble_hci.c's
 * table, before its snapshot). A random-address row with no entry gets
 * a zero hint. No-op with the feature off. */
void ble_rot_update_row(ble_device_t *d);

/* The counters into `s->ble_rot`; with the feature off it only zeroes
 * them. */
void ble_rot_snapshot(sloth_state_t *s);

/* Empty the tables (ble_clear()); counters, key and the on/off state
 * are kept. */
void ble_rot_drop_tables(void);

/* Back to the shipped state: off, no tables, no key, counters zero.
 * The test registry's reset (src/reset_all.h), so no test inherits the
 * flag from another. */
void ble_rot_reset(void);

/* The [*] view's estimate: rows, with rows sharing a committed chain
 * (payload or timing) counted once. An estimate over the recent window,
 * never an input to a detector. With no hints on the rows this is the
 * plain row count. */
int ble_rot_distinct(const sloth_state_t *s);

/* Test seams. allocated: 1 once any seam table exists. held: entries,
 * digests, shapes, keys and poison slots still held. digests: digests
 * and link digests still held. digest: the digest this run would hold
 * for a token, so a test can search every output for it. key_set: pin
 * the key (tests only). */
int      ble_rot_test_allocated(void);
int      ble_rot_test_held(void);
int      ble_rot_test_digests(void);
uint64_t ble_rot_test_digest(uint8_t kind, const uint8_t *bytes, size_t len,
                             const uint8_t *bytes2, size_t len2);
void     ble_rot_test_set_key(const uint8_t key[16]);

#endif /* BLE_ROTATION_H */
