#include <stddef.h>

#include "tool_fingerprint.h"

/* ── The signature table ───────────────────────────────────
 *
 * Empty, deliberately. See the note in tool_fingerprint.h: a tool's
 * fingerprint is an empirical fact about a binary, not something
 * derivable from a specification, and a table of invented rows would
 * pass every test while matching nothing on the air.
 *
 * To add a tool:
 *
 *   1. Capture its beacons on a rig you control.
 *   2. Read the vendor-IE hash sloth computes for it (the `beacon`
 *      JSONL record's `vendor_ies_hash`), the beacon interval, and the
 *      supported-rate set.
 *   3. Add one row here, with `evidence` naming the capture and the
 *      tool version — signatures drift as tools update, and a row with
 *      no provenance cannot be re-checked when it stops matching.
 *   4. Add a test asserting that observation matches that row and does
 *      not match any other.
 *
 * One row per commit. A signature that arrives without its capture is
 * a guess wearing a data structure. */
static const sloth_tool_sig_t TOOL_SIGNATURES[] = {
    /* Intentionally empty — see above. */
    { 0, 0, 0, 0, 0, 0, NULL, NULL }   /* terminator, never matched */
};

#define SIG_ROWS ((int)(sizeof(TOOL_SIGNATURES) / sizeof(TOOL_SIGNATURES[0])) - 1)

int tool_signature_count(void) { return SIG_ROWS; }

const char *tool_name(sloth_tool_id_t id) {
    switch (id) {
    case SLOTH_TOOL_HOSTAPD_MANA:   return "hostapd-mana";
    case SLOTH_TOOL_EAPHAMMER:      return "eaphammer";
    case SLOTH_TOOL_HCXDUMPTOOL:    return "hcxdumptool";
    case SLOTH_TOOL_ESP32_MARAUDER: return "ESP32 Marauder";
    case SLOTH_TOOL_WIFI_DUCK:      return "Wi-Fi Duck";
    case SLOTH_TOOL_FLIPPER_ZERO:   return "Flipper Zero";
    case SLOTH_TOOL_PINEAPPLE_MK7:  return "Pineapple MK7";
    case SLOTH_TOOL_UNKNOWN:
    case SLOTH_TOOL_COUNT:          break;
    }
    return "";
}

const char *tool_confidence_name(sloth_tool_conf_t c) {
    switch (c) {
    case TOOL_CONF_LOW:  return "low";
    case TOOL_CONF_MED:  return "med";
    case TOOL_CONF_HIGH: return "high";
    case TOOL_CONF_NONE: break;
    }
    return "";
}

sloth_tool_id_t tool_fingerprint_match(const sloth_tool_obs_t *obs,
                                       sloth_tool_conf_t *conf,
                                       const char **label) {
    return tool_fingerprint_match_table(TOOL_SIGNATURES, SIG_ROWS,
                                        obs, conf, label);
}

sloth_tool_id_t tool_fingerprint_match_table(const sloth_tool_sig_t *sigs,
                                             int n_sigs,
                                             const sloth_tool_obs_t *obs,
                                             sloth_tool_conf_t *conf,
                                             const char **label) {
    if (conf)  *conf  = TOOL_CONF_NONE;
    if (label) *label = "";
    if (!obs || !sigs) return SLOTH_TOOL_UNKNOWN;

    sloth_tool_id_t best      = SLOTH_TOOL_UNKNOWN;
    int             best_hits = 0;
    const char     *best_lbl  = "";

    for (int i = 0; i < n_sigs; i++) {
        const sloth_tool_sig_t *sig = &sigs[i];
        int hits = 0;

        /* A zero field is a wildcard. Counting only the non-wildcard
         * fields that agreed is what stops an all-wildcard row from
         * matching every AP with maximum confidence — which is the
         * failure mode a signature table falls into when someone adds
         * a row they were not sure about. */
        if (sig->vendor_ie_hash) {
            if (sig->vendor_ie_hash != obs->vendor_ie_hash) continue;
            hits++;
        }
        if (sig->beacon_interval_ms) {
            if (sig->beacon_interval_ms != obs->beacon_interval_ms) continue;
            hits++;
        }
        if (sig->supported_rates) {
            if (sig->supported_rates != obs->supported_rates) continue;
            hits++;
        }
        /* Preconditions, not characteristics: they gate the row without
         * adding to its confidence, because "a KARMA event happened" is
         * already why we are looking. */
        if (sig->requires_karma_echo && !obs->karma_echo) continue;
        if (sig->requires_pmkid      && !obs->pmkid_seen) continue;

        /* A row with no discriminating field matches everything and
         * means nothing, so it must never win — which the comparison
         * below already guarantees: best_hits starts at zero and the
         * test is strict, so a zero-hit row can never displace it.
         *
         * There was an explicit `if (hits == 0) continue;` here. It was
         * provably redundant and mutation testing proved it: removing
         * it failed nothing. Kept as a comment rather than as code,
         * because a malformed all-wildcard row being inert is a
         * property worth stating even where it is structural — and
         * relaxing the comparison to >= turns a test red, so the
         * property is covered where it actually lives. */
        if (hits > best_hits) {
            best_hits = hits;
            best      = sig->tool;
            best_lbl  = sig->human_label ? sig->human_label
                                         : tool_name(sig->tool);
        }
    }

    if (best == SLOTH_TOOL_UNKNOWN) return SLOTH_TOOL_UNKNOWN;
    if (conf)
        *conf = best_hits >= 3 ? TOOL_CONF_HIGH
              : best_hits == 2 ? TOOL_CONF_MED
                               : TOOL_CONF_LOW;
    if (label) *label = best_lbl;
    return best;
}
