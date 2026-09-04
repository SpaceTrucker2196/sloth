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
    /* ── UNVERIFIED ──────────────────────────────────────────────────
     *
     * Read this before trusting the row below or adding another like
     * it.
     *
     * The rule above says one row per commit, each landing with the
     * capture that corroborates it. This row does not have one. Its
     * values came from a research task (#74), not from a rig, and
     * nobody here has watched an ESP32 Marauder transmit. The owner's
     * call was to land it flagged rather than leave the table empty,
     * which is the right trade — but only because the flag is in the
     * `evidence` string, where an operator reading the alert sees it.
     *
     * A row is unverified until someone captures the tool and replaces
     * the evidence string with the capture and the version. Until then
     * it is a hypothesis sloth is willing to state out loud, and the
     * confidence model is what keeps it honest: two characteristics
     * gated behind a KARMA echo, not a standalone claim.
     *
     * ── What this row can and cannot say ──
     *
     * 100 TU is the 802.11 default and legacy-only rates are shared by
     * a decade of cheap hardware, so neither means anything alone. The
     * discriminating part is the *combination* with an Espressif OUI
     * and no HT Capabilities — a 2026 access point that negotiates no
     * HT is either very old or not really an access point.
     *
     * The rate set #74 gives (1/2/5.5/11) is not pinned: beacons do not
     * reach this matcher with supported_rates populated (see the note
     * on sloth_tool_obs_t). Claiming it while never comparing it would
     * inflate the confidence score for a field nothing fills. */
    {   SLOTH_TOOL_ESP32_MARAUDER,
        0,                              /* vendor-IE hash: unmeasured  */
        102,                            /* 100 TU -> 102 ms            */
        0,                              /* rates: not observable here  */
        AP_FP_FLAG_ESPRESSIF_OUI,       /* require                     */
        AP_FP_FLAG_HT_PRESENT,          /* forbid: no HT Capabilities  */
        1,                              /* only alongside a KARMA echo */
        0,
        1,                              /* unverified: caps conf at MED */
        "ESP32 Marauder",
        "UNVERIFIED - values from issue #74 research, 2026-09-04; "
        "no capture. Replace with a rig capture + firmware version." },

    /* Pineapple MK7. Also unverified, also from #74, and a much thinner
     * row than the one above — it pins exactly one characteristic.
     *
     * That is the honest shape of what #74 supplies. Its Pineapple data
     * is "the default OUI list and the default SSIDs": the OUIs were
     * already in kHak5Ouis, and there is no SSID field here to put the
     * rest in. So one field, LOW confidence, gated behind a KARMA echo.
     *
     * Thin is not worthless here, and the reason is the difference from
     * the Espressif row. 00:13:37 is a Hak5 vanity prefix and 00:c0:ca
     * is the Alfa radio they ship with it — neither turns up in an air
     * conditioner. An Espressif OUI on its own says "some ESP32", which
     * is why that row needs three fields to say anything; a Hak5 OUI on
     * an AP that just echoed three SSIDs says "Pineapple" at low
     * confidence all by itself.
     *
     * Not pinned, deliberately: AP_FP_FLAG_DEFAULT_HOSTAPD_CAPS. The
     * MK7 runs hostapd and the flag exists, but nothing in the tree
     * sets it. A require on a flag nobody populates never matches; a
     * forbid on one always passes and inflates the hit count for a
     * comparison that did not happen. */
    {   SLOTH_TOOL_PINEAPPLE_MK7,
        0,                              /* vendor-IE hash: unmeasured  */
        0,                              /* interval: #74 gives none    */
        0,                              /* rates: not observable here  */
        AP_FP_FLAG_HAK5_OUI,            /* require                     */
        0,
        1,                              /* only alongside a KARMA echo */
        0,
        1,                              /* unverified: caps conf at MED */
        "Pineapple MK7",
        "UNVERIFIED - OUI list from issue #74 research, 2026-09-04; "
        "no capture. Replace with a rig capture + firmware version." },

    { 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL } /* terminator, never matched */
};

#define SIG_ROWS ((int)(sizeof(TOOL_SIGNATURES) / sizeof(TOOL_SIGNATURES[0])) - 1)

int tool_signature_count(void) { return SIG_ROWS; }

const sloth_tool_sig_t *tool_signature_at(int i) {
    return (i >= 0 && i < SIG_ROWS) ? &TOOL_SIGNATURES[i] : NULL;
}

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
    int             best_unv  = 0;

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
        /* Presence and absence count as one characteristic each, not
         * one per bit: a row demanding two flags is pinning one aspect
         * of the beacon's shape, and letting it outscore a vendor-IE
         * hash match would rank a weak row above a strong one. */
        if (sig->require_flags) {
            if ((obs->fp_flags & sig->require_flags) != sig->require_flags)
                continue;
            hits++;
        }
        if (sig->forbid_flags) {
            if (obs->fp_flags & sig->forbid_flags) continue;
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
            best_unv  = sig->unverified;
            best_lbl  = sig->human_label ? sig->human_label
                                         : tool_name(sig->tool);
        }
    }

    if (best == SLOTH_TOOL_UNKNOWN) return SLOTH_TOOL_UNKNOWN;
    if (conf) {
        *conf = best_hits >= 3 ? TOOL_CONF_HIGH
              : best_hits == 2 ? TOOL_CONF_MED
                               : TOOL_CONF_LOW;
        /* A row with no capture behind it cannot be reported as high
         * confidence no matter how much of the beacon it compared. The
         * field count says how thorough the comparison was; it says
         * nothing about whether the values compared against are right,
         * and an operator reading "high" would reasonably assume both. */
        if (best_unv && *conf > TOOL_CONF_MED) *conf = TOOL_CONF_MED;
    }
    if (label) *label = best_lbl;
    return best;
}
