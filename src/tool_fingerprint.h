#ifndef TOOL_FINGERPRINT_H
#define TOOL_FINGERPRINT_H

#include <stdint.h>
#include "sloth.h"

/* Attacker-tool identification from passive beacon characteristics —
 * issue #68.
 *
 * `ALERT_TYPE_KARMA_AP` already says "a suspicious AP echoed an SSID".
 * Naming the *tool* changes what an operator can do with that: "this is
 * hostapd-mana" is a response, "something odd happened" is a ticket. It
 * also lets one attacker be correlated across SSIDs, sites and times.
 *
 * ── Why this ships with no signatures ──
 *
 * A frame layout can be built from a specification. A tool's
 * fingerprint cannot: hostapd-mana's default beacon interval,
 * eaphammer's vendor-IE hash, an ESP32 Marauder's supported-rate set
 * are empirical facts about particular binaries. Inventing them
 * produces a table that passes every test and matches nothing on the
 * air — which is worse than an empty one, because it looks like
 * coverage.
 *
 * So the mechanism shipped and the data did not. The table is no
 * longer empty — see the note above TOOL_SIGNATURES for what its one
 * row is and, more importantly, what its provenance is not.
 * `tool_signature_count()` exists so the tests can assert the count
 * deliberately, and so a UI can say "no signature database loaded"
 * rather than "no tool detected".
 *
 * A contributor with a lab rig adds a tool by editing the table. They
 * do not need to understand the matcher, which is the whole point of
 * separating the two. */

typedef enum {
    SLOTH_TOOL_UNKNOWN = 0,
    SLOTH_TOOL_HOSTAPD_MANA,
    SLOTH_TOOL_EAPHAMMER,
    SLOTH_TOOL_HCXDUMPTOOL,
    SLOTH_TOOL_ESP32_MARAUDER,
    SLOTH_TOOL_WIFI_DUCK,
    SLOTH_TOOL_FLIPPER_ZERO,
    SLOTH_TOOL_PINEAPPLE_MK7,
    SLOTH_TOOL_COUNT,
} sloth_tool_id_t;

/* How much a match is worth saying out loud. A signature matching on a
 * wildcard-heavy row is a hint; one matching several independent
 * characteristics is a claim. */
typedef enum {
    TOOL_CONF_NONE = 0,
    TOOL_CONF_LOW,
    TOOL_CONF_MED,
    TOOL_CONF_HIGH,
} sloth_tool_conf_t;

/* One signature row. A zero field is a wildcard — it matches anything —
 * which is why `fields_used` is counted rather than assumed: a row of
 * all wildcards would otherwise match every AP with perfect
 * confidence. */
typedef struct {
    sloth_tool_id_t tool;
    uint32_t vendor_ie_hash;      /* 0 = wildcard */
    uint16_t beacon_interval_ms;  /* 0 = wildcard */
    uint32_t supported_rates;     /* 0 = wildcard, ASSOC_RATE_* bitmap */
    /* AP_FP_FLAG_* that must be set / must be clear. Both 0 = wildcard.
     *
     * Added for the first real signature (#74): half of what identifies
     * a cheap rogue is what its beacon *lacks* — no HT Capabilities, no
     * Country IE — and an all-positive schema cannot say "absent". A
     * forbid mask is not the same as omitting the field: omitting means
     * "do not care", forbidding means "and this must not be there",
     * which is a distinct and much stronger claim. */
    uint8_t  require_flags;
    uint8_t  forbid_flags;
    uint8_t  requires_karma_echo; /* only match when a KARMA event fired */
    uint8_t  requires_pmkid;      /* only match after a PMKID was seen  */
    /* No capture behind this row — its values came from research rather
     * than a rig (#74). Caps the reported confidence at MED however
     * many fields agree.
     *
     * The two are different axes and conflating them is the whole risk
     * of shipping unverified rows: field count measures how much of the
     * beacon was compared, provenance measures whether the values being
     * compared against are right. A row can pin three characteristics
     * perfectly and still be three guesses. */
    uint8_t  unverified;
    const char *human_label;
    /* Where the values came from. By convention this starts with
     * "UNVERIFIED - " exactly when `unverified` is set, and a test
     * enforces the agreement — the flag drives behaviour, the string is
     * what an operator reads, and they must not drift apart. */
    const char *evidence;
} sloth_tool_sig_t;

/* Observed characteristics of one AP, assembled by the caller. */
typedef struct {
    uint32_t vendor_ie_hash;
    uint16_t beacon_interval_ms;
    /* Beacons do not carry this today — supported_rates lives on
     * assoc_req_t, and nothing populates it on the beacon path. Left in
     * because a signature may legitimately pin it once an assoc-request
     * observation is wired in, and a caller that cannot fill it leaves
     * it 0, which every row treats as "not compared". */
    uint32_t supported_rates;
    uint8_t  fp_flags;            /* AP_FP_FLAG_* from ap_fingerprint_t */
    int      karma_echo;          /* this BSSID triggered a KARMA event */
    int      pmkid_seen;          /* a PMKID was harvested from it      */
} sloth_tool_obs_t;

/* Match `obs` against the signature table. Returns the tool, or
 * SLOTH_TOOL_UNKNOWN. *conf receives the confidence; *label a short
 * human name ("" when unknown). Either output may be NULL.
 *
 * Best match wins, measured by how many non-wildcard fields agreed —
 * a row that pins three characteristics beats one that pins one. */
sloth_tool_id_t tool_fingerprint_match(const sloth_tool_obs_t *obs,
                                       sloth_tool_conf_t *conf,
                                       const char **label);

/* The same matcher against a caller-supplied table.
 *
 * This exists because the built-in table is empty, and a matcher whose
 * only entry point walks an empty list cannot be tested at all — its
 * guards are unreachable, and a mutation to any of them survives. The
 * tests therefore drive *this* function with synthetic rows, which
 * means they exercise the shipped code rather than a copy of its logic
 * written alongside it.
 *
 * Not a test hook bolted on: tool_fingerprint_match() is a one-line
 * wrapper over it, so there is exactly one implementation. */
sloth_tool_id_t tool_fingerprint_match_table(const sloth_tool_sig_t *sigs,
                                             int n_sigs,
                                             const sloth_tool_obs_t *obs,
                                             sloth_tool_conf_t *conf,
                                             const char **label);

/* Rows currently compiled in. Callers should say "no signature
 * database" rather than "no tool detected" when this is 0. */
int tool_signature_count(void);

/* Row `i` of the compiled-in table, or NULL. Exists so a test can hold
 * every shipped row to the provenance rule — a signature whose evidence
 * string is empty cannot be re-checked when it stops matching, and that
 * is the form the mistake takes. Enforcement in the suite rather than
 * in review, for the same reason #73 argues detectors should cite their
 * sources at runtime. */
const sloth_tool_sig_t *tool_signature_at(int i);

/* Display name for a tool id; "" for SLOTH_TOOL_UNKNOWN. */
const char *tool_name(sloth_tool_id_t id);

/* Short confidence label — "low" / "med" / "high", "" for none. */
const char *tool_confidence_name(sloth_tool_conf_t c);

#endif /* TOOL_FINGERPRINT_H */
