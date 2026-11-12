#ifndef ATTACK_HW_H
#define ATTACK_HW_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "sloth.h"
#include "tool_fingerprint.h"

/* Attack-hardware fingerprints (#151): the known-stack IE-order table,
 * the Pineapple setup-AP pairing, and the verdict layer over both plus
 * the tool-signature row and the OUI.
 *
 * Plan #145's evidence standard governs all three. A passive sensor
 * corroborates, it never confirms: the top tier is
 * `corroborated-<device>`, never `identified-` and never `CONFIRMED_`.
 * Nothing here raises an alert or moves a severity. It describes an
 * alert that already fired (KARMA_AP), in the detail and as two
 * additive JSONL fields.
 *
 * docs/wiki/attack-hardware-fingerprints.md has the provenance of
 * every input and the list of what is still missing. */

/* ── 1. Known-stack IE-order table ─────────────────────────
 *
 * `ie_order_hash` (beacon_snoop.c, #77) names the IE-emitting stack:
 * element identity in beacon order, bodies excluded, transient
 * elements (CSA, Quiet, ECSA, Channel Switch Wrapper, Quiet Channel)
 * excluded. A row maps one (hash, element count) to the stack that
 * emitted it.
 *
 * The table ships EMPTY. A row's values are the hash of a particular
 * firmware build's beacons; no specification or vendor document states
 * them, and #151 requires each row to carry the capture it came from
 * (named hardware, named firmware, band, the capture's SHA-256). No
 * such capture exists in this tree, so no row does. The mechanism, the
 * guard that refuses a row without a capture, and the matcher ship;
 * docs/wiki/attack-hardware-fingerprints.md lists the rows wanted. */
typedef struct {
    uint32_t ie_order_hash;     /* never 0: 0 means "not decoded"      */
    uint16_t ie_order_count;    /* pinned with the hash, never a wildcard */
    /* The attack device this stack is, or SLOTH_TOOL_UNKNOWN for a
     * production stack (Cisco, Aruba, ...). A production-stack hit is
     * evidence *against* attack hardware and caps the verdict. */
    sloth_tool_id_t tool;
    const char *stack;          /* "Cisco IOS-XE 17.9.4a, 5 GHz"       */
    const char *evidence;       /* rig, unit, firmware, band, capture file */
    const char *capture_sha256; /* 64 lowercase hex                    */
    const char *id;             /* stable, never reused (as #90's ids)  */
} hw_stack_row_t;

/* 1 when `row` meets #151's row standard: a non-zero hash, a non-zero
 * count, a stack label, an id, a non-empty evidence string that is not
 * UNVERIFIED (this table admits captures only, unlike TOOL_SIGNATURES),
 * and a 64-character lowercase-hex capture SHA-256. */
int hw_stack_row_valid(const hw_stack_row_t *row);

/* Rows compiled in, and row `i` (NULL out of range). */
int hw_stack_count(void);
const hw_stack_row_t *hw_stack_at(int i);

/* The row for (hash, count), or NULL. A hash of 0 never matches. When
 * more than one row matches — a hash collision across stacks, which
 * #151 says must arrive as its own row — the answer is NULL and
 * *ambiguous is set: a collision is reported, never resolved by row
 * order. `ambiguous` may be NULL. hw_stack_match() walks the shipped
 * table; _table() exists so the matcher is testable while that table
 * is empty (the same reason tool_fingerprint_match_table() exists). */
const hw_stack_row_t *hw_stack_match(uint32_t hash, uint16_t count,
                                     int *ambiguous);
const hw_stack_row_t *hw_stack_match_table(const hw_stack_row_t *rows,
                                           int n, uint32_t hash,
                                           uint16_t count, int *ambiguous);

/* ── 2. Pineapple setup-AP pairing ─────────────────────────
 *
 * Hak5's Mark VII documentation: during setup the device "serves an
 * Open AP ... The SSID of the AP is `Pineapple_XXXX`, where the 'XXXX'
 * is the last 4 characters of the devices MAC address", and that
 * network "will disappear after setup is complete"
 * (research/tools/wifi-pineapple-mk7.md).
 *
 * So the pairing is: a KARMA_AP BSSID, plus a *different* live BSSID
 * beaconing exactly `Pineapple_` + four hex digits. It is the one
 * two-BSSID relationship a public source states. What #151 also asks
 * about — adjacent MACs, a shared IE-order hash, the channel relation,
 * echo-to-traffic timing — no public source states, so none of it is
 * required or scored. Whether the suffix equals the low 16 bits of
 * either BSSID is recorded, not required: the docs say "the devices
 * MAC address", and which interface's MAC that is is not stated.
 *
 * The window is narrow by the docs' own account (setup only), so this
 * will rarely fire in the field. Enrichment only: it is called from
 * rule_karma_ap() on a BSSID that already fired. */
typedef struct {
    int     found;
    uint8_t bssid[6];          /* the setup-AP BSSID */
    char    ssid[33];          /* validated: "Pineapple_" + 4 hex */
    int     channel;
    /* 1 when XXXX equals the low 16 bits of the setup AP's own BSSID
     * or of the KARMA BSSID. Informational. */
    int     suffix_matches;
} hw_pine_pair_t;

/* 1 when `ssid` is exactly "Pineapple_" followed by four hex digits
 * (either case), with the parsed value in *suffix (may be NULL). */
int hw_pineapple_setup_ssid(const char *ssid, uint16_t *suffix);

/* Search the beacon table for a setup AP to pair with `karma`. Returns
 * 1 and fills *out on a pairing, else 0 with out->found = 0. An entry
 * is live while now - last_seen <= BEACON_AGE_SECS. The KARMA BSSID
 * itself never pairs with itself: one radio is not two. */
int hw_pineapple_pair(const sloth_state_t *s, const beacon_ap_t *karma,
                      time_t now, hw_pine_pair_t *out);

/* ── 3. Verdict layer ──────────────────────────────────────
 *
 * Combines what is known about one BSSID into a tier:
 *
 *   none                   no input names a device
 *   suspected-<device>     at least one input names it
 *   corroborated-<device>  two or more INDEPENDENT inputs name it, at
 *                          least one of them capture-backed, and no
 *                          input names a different device or a
 *                          production stack
 *
 * Inputs, each one signal class:
 *   tool   a TOOL_SIGNATURES row match. Capture-backed only when the
 *          row is not `unverified` (none is today).
 *   stack  a known-stack table hit (capture-backed by construction;
 *          the table is empty today).
 *   pair   the Pineapple setup-AP pairing (documentation-backed, no
 *          capture).
 *   oui    the BSSID's OUI is a Hak5 block -> Pineapple. An Espressif
 *          OUI names no device ("some ESP32") and is not an input.
 *          Not counted when the tool row itself requires an OUI flag:
 *          the Pineapple row is the Hak5 OUI restated, and counting it
 *          twice would corroborate a device from one observation.
 *
 * WPS/WSC vendor strings and TBTT jitter are not inputs. #151 lists
 * them, but no public source maps a string or a jitter figure to an
 * attack device; they stay measurements.
 *
 * With every shipped row unverified and the stack table empty,
 * `corroborated` is unreachable on live data today. That is the
 * intended reading of the standard, not a defect: suspected is the
 * honest ceiling until a capture backs an input. */
typedef enum {
    HW_TIER_NONE = 0,
    HW_TIER_SUSPECTED,
    HW_TIER_CORROBORATED,
} hw_tier_t;

#define HW_SIG_TOOL  0x01u
#define HW_SIG_STACK 0x02u
#define HW_SIG_PAIR  0x04u
#define HW_SIG_OUI   0x08u

typedef struct {
    const sloth_tool_sig_t *tool_row;   /* may be NULL */
    const hw_stack_row_t   *stack_row;  /* may be NULL */
    int                     pine_pair;  /* hw_pineapple_pair() found one */
    uint8_t                 oui[3];
} hw_inputs_t;

typedef struct {
    hw_tier_t       tier;
    sloth_tool_id_t device;     /* UNKNOWN when tier is none */
    uint8_t         signals;    /* HW_SIG_* naming `device` */
    uint8_t         backed;     /* HW_SIG_* of those that are capture-backed */
    uint8_t         conflict;   /* an input named another device or a production stack */
    char            label[40];  /* "suspected-pineapple-mk7", "" for none */
    char            names[32];  /* "oui+pair", "" for none */
} hw_verdict_t;

void hw_verdict_eval(const hw_inputs_t *in, hw_verdict_t *out);

/* The whole #151 enrichment for one KARMA_AP BSSID, in one call so
 * rule_karma_ap() carries a hook rather than the logic: looks the
 * BSSID's IE order up in the stack table, searches for a setup-AP
 * pairing, evaluates the verdict into *v, and writes the detail note
 * into `note` — " +setup-AP Pineapple_1a2b@<bssid> hw:<label>", either
 * half omitted when absent, "" when both are. `tool_row` is the row
 * karma_tool_match() returned (may be NULL). */
void hw_karma_context(const sloth_state_t *s, const beacon_ap_t *a,
                      const sloth_tool_sig_t *tool_row, time_t now,
                      hw_verdict_t *v, char *note, size_t n);

/* Render a (tier, device, signals) triple — the bytes alert_t keeps —
 * as the label ("suspected-pineapple-mk7") and the signal names
 * ("pair+oui"). Both "" for HW_TIER_NONE or an out-of-range value.
 * hw_verdict_eval() fills its own label/names through this, so the
 * detail and the JSONL fields cannot spell a verdict two ways. */
void hw_verdict_format(int tier, int device, int signals,
                       char *label, size_t label_n,
                       char *names, size_t names_n);

/* Lowercase slug for a device ("pineapple-mk7"); "" for UNKNOWN. */
const char *hw_device_slug(sloth_tool_id_t id);

#endif /* ATTACK_HW_H */
