#include <stdio.h>
#include <string.h>

#include "attack_hw.h"
#include "wifi_oui_attacker.h"

/* ── The known-stack table ─────────────────────────────────
 *
 * Empty. See attack_hw.h: a row is the hash of one firmware build's
 * beacons, and #151 admits a row only with the capture it came from.
 *
 * To add one:
 *
 *   1. Capture the stack's beacons on a rig you control; note the unit,
 *      firmware version and band. Ideally a second unit, to show the
 *      hash is per-stack, not per-unit or per-configuration.
 *   2. Read `ie_order_hash` and `ie_order_count` from the `beacon` JSONL
 *      record (or the [b] detail's IE order line).
 *   3. Add one row: the pair, `tool` (SLOTH_TOOL_UNKNOWN for a
 *      production stack), the label, `evidence` naming rig, unit,
 *      firmware, band and capture file, `capture_sha256`, and a new
 *      `id`. The capture stays off-repo.
 *   4. Add a test that builds a `uint8_t` beacon with that element order
 *      and asserts it reaches this row. The capture is the integration
 *      check behind the test, never the fixture.
 *
 * A configuration that changes the order (WPA3 on, 11ax off) is a
 * second row with its own capture, never a wildcard. */
static const hw_stack_row_t HW_STACKS[] = {
    /* terminator, never matched */
    { 0, 0, SLOTH_TOOL_UNKNOWN, NULL, NULL, NULL, NULL }
};

#define HW_STACK_ROWS \
    ((int)(sizeof(HW_STACKS) / sizeof(HW_STACKS[0])) - 1)

static const hw_stack_row_t *g_stack_rows = HW_STACKS;
static int g_stack_n = HW_STACK_ROWS;

void hw_stack_test_table(const hw_stack_row_t *rows, int n) {
    g_stack_rows = rows ? rows : HW_STACKS;
    g_stack_n    = rows ? n : HW_STACK_ROWS;
}

int hw_stack_count(void) { return HW_STACK_ROWS; }

const hw_stack_row_t *hw_stack_at(int i) {
    return (i >= 0 && i < HW_STACK_ROWS) ? &HW_STACKS[i] : NULL;
}

static int is_hex(int c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static int hex_val(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return c - 'A' + 10;
}

int hw_stack_row_valid(const hw_stack_row_t *row) {
    if (!row || !row->ie_order_hash || !row->ie_order_count) return 0;
    if (!row->stack || !row->stack[0]) return 0;
    if (!row->id || !row->id[0]) return 0;
    if (!row->evidence || !row->evidence[0]) return 0;
    /* TOOL_SIGNATURES admits research rows flagged UNVERIFIED. This
     * table does not: #151's standard is a capture per row, and an
     * unverified stack row would be the "guess wearing a data
     * structure" tool_fingerprint.c warns about. */
    if (strncmp(row->evidence, "UNVERIFIED", 10) == 0) return 0;
    if (!row->capture_sha256 || strlen(row->capture_sha256) != 64) return 0;
    for (int i = 0; i < 64; i++) {
        char c = row->capture_sha256[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

const hw_stack_row_t *hw_stack_match_table(const hw_stack_row_t *rows,
                                           int n, uint32_t hash,
                                           uint16_t count, int *ambiguous) {
    if (ambiguous) *ambiguous = 0;
    if (!rows || !hash) return NULL;
    const hw_stack_row_t *hit = NULL;
    for (int i = 0; i < n; i++) {
        if (rows[i].ie_order_hash != hash ||
            rows[i].ie_order_count != count) continue;
        if (hit) {
            /* Two rows claim one order. Picking either would make the
             * answer depend on table order; say so instead. */
            if (ambiguous) *ambiguous = 1;
            return NULL;
        }
        hit = &rows[i];
    }
    return hit;
}

const hw_stack_row_t *hw_stack_match(uint32_t hash, uint16_t count,
                                     int *ambiguous) {
    return hw_stack_match_table(g_stack_rows, g_stack_n, hash, count,
                                ambiguous);
}

/* ── Pineapple setup-AP pairing ───────────────────────────── */

static const char PINE_PREFIX[] = "Pineapple_";
#define PINE_PREFIX_LEN (sizeof(PINE_PREFIX) - 1)

int hw_pineapple_setup_ssid(const char *ssid, uint16_t *suffix) {
    if (!ssid) return 0;
    if (strncmp(ssid, PINE_PREFIX, PINE_PREFIX_LEN) != 0) return 0;
    const char *x = ssid + PINE_PREFIX_LEN;
    uint16_t v = 0;
    for (int i = 0; i < 4; i++) {
        if (!is_hex((unsigned char)x[i])) return 0;
        v = (uint16_t)((v << 4) | (uint16_t)hex_val((unsigned char)x[i]));
    }
    /* Exactly four: "Pineapple_ABCDE" is someone's network name. */
    if (x[4] != '\0') return 0;
    if (suffix) *suffix = v;
    return 1;
}

static uint16_t low16(const uint8_t mac[6]) {
    return (uint16_t)(((uint16_t)mac[4] << 8) | mac[5]);
}

int hw_pineapple_pair(const sloth_state_t *s, const beacon_ap_t *karma,
                      time_t now, hw_pine_pair_t *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!s || !karma) return 0;
    int n = s->beacon_count < MAX_BEACON_APS ? s->beacon_count
                                             : MAX_BEACON_APS;
    for (int i = 0; i < n; i++) {
        const beacon_ap_t *b = &s->beacon_aps[i];
        if (memcmp(b->bssid, karma->bssid, 6) == 0) continue;
        if (now - b->last_seen > BEACON_AGE_SECS) continue;
        uint16_t sfx;
        if (!hw_pineapple_setup_ssid(b->ssid, &sfx)) continue;
        if (out) {
            out->found = 1;
            memcpy(out->bssid, b->bssid, 6);
            snprintf(out->ssid, sizeof(out->ssid), "%s", b->ssid);
            out->channel = b->channel;
            out->suffix_matches = sfx == low16(b->bssid) ||
                                  sfx == low16(karma->bssid);
        }
        return 1;
    }
    return 0;
}

/* ── Verdict ───────────────────────────────────────────── */

const char *hw_device_slug(sloth_tool_id_t id) {
    switch (id) {
    case SLOTH_TOOL_HOSTAPD_MANA:   return "hostapd-mana";
    case SLOTH_TOOL_EAPHAMMER:      return "eaphammer";
    case SLOTH_TOOL_HCXDUMPTOOL:    return "hcxdumptool";
    case SLOTH_TOOL_ESP32_MARAUDER: return "esp32-marauder";
    case SLOTH_TOOL_WIFI_DUCK:      return "wifi-duck";
    case SLOTH_TOOL_FLIPPER_ZERO:   return "flipper-zero";
    case SLOTH_TOOL_PINEAPPLE_MK7:  return "pineapple-mk7";
    case SLOTH_TOOL_UNKNOWN:
    case SLOTH_TOOL_COUNT:          break;
    }
    return "";
}

#define OUI_FLAGS (AP_FP_FLAG_HAK5_OUI | AP_FP_FLAG_ESPRESSIF_OUI)

void hw_verdict_eval(const hw_inputs_t *in, hw_verdict_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!in) return;

    /* Per device: which signal classes name it, and which of those are
     * capture-backed. */
    uint8_t sig[SLOTH_TOOL_COUNT];
    uint8_t bak[SLOTH_TOOL_COUNT];
    memset(sig, 0, sizeof(sig));
    memset(bak, 0, sizeof(bak));
    int against = 0;   /* a production stack was recognised */

    const sloth_tool_sig_t *t = in->tool_row;
    if (t && t->tool > SLOTH_TOOL_UNKNOWN && t->tool < SLOTH_TOOL_COUNT) {
        sig[t->tool] |= HW_SIG_TOOL;
        if (!t->unverified) bak[t->tool] |= HW_SIG_TOOL;
    }
    const hw_stack_row_t *st = in->stack_row;
    if (st) {
        if (st->tool > SLOTH_TOOL_UNKNOWN && st->tool < SLOTH_TOOL_COUNT) {
            sig[st->tool] |= HW_SIG_STACK;
            bak[st->tool] |= HW_SIG_STACK;
        } else {
            against = 1;
        }
    }
    if (in->pine_pair)
        sig[SLOTH_TOOL_PINEAPPLE_MK7] |= HW_SIG_PAIR;
    /* The tool row that requires an OUI flag already is the OUI
     * observation; counting both would be one fact twice. */
    int oui_in_row = t && (t->require_flags & OUI_FLAGS);
    if (!oui_in_row && oui_is_hak5(in->oui))
        sig[SLOTH_TOOL_PINEAPPLE_MK7] |= HW_SIG_OUI;

    int best = SLOTH_TOOL_UNKNOWN, best_n = 0, tie = 0, named = 0;
    for (int d = SLOTH_TOOL_UNKNOWN + 1; d < SLOTH_TOOL_COUNT; d++) {
        int c = 0;
        for (uint8_t m = sig[d]; m; m &= (uint8_t)(m - 1)) c++;
        if (!c) continue;
        named++;
        if (c > best_n)       { best = d; best_n = c; tie = 0; }
        else if (c == best_n) { tie = 1; }
    }
    out->conflict = (uint8_t)(named > 1 || against);
    /* A tie between devices is no answer: either name would be the
     * table's order speaking, not the evidence. */
    if (!best_n || tie) return;

    out->device  = (sloth_tool_id_t)best;
    out->signals = sig[best];
    out->backed  = bak[best];
    out->tier    = (best_n >= 2 && bak[best] && !out->conflict)
                 ? HW_TIER_CORROBORATED : HW_TIER_SUSPECTED;

    hw_verdict_format(out->tier, out->device, out->signals,
                      out->label, sizeof(out->label),
                      out->names, sizeof(out->names));
}

hw_tier_t hw_tier_of_tool_conf(sloth_tool_conf_t conf) {
    switch (conf) {
    case TOOL_CONF_LOW:
    case TOOL_CONF_MED:
    case TOOL_CONF_HIGH: return HW_TIER_SUSPECTED;
    case TOOL_CONF_NONE: break;
    }
    return HW_TIER_NONE;
}

void hw_verdict_format(int tier, int device, int signals,
                       char *label, size_t label_n,
                       char *names, size_t names_n) {
    if (label && label_n) label[0] = '\0';
    if (names && names_n) names[0] = '\0';
    if (tier != HW_TIER_SUSPECTED && tier != HW_TIER_CORROBORATED) return;
    if (device <= SLOTH_TOOL_UNKNOWN || device >= SLOTH_TOOL_COUNT) return;
    if (label && label_n)
        snprintf(label, label_n, "%s-%s",
                 tier == HW_TIER_CORROBORATED ? "corroborated" : "suspected",
                 hw_device_slug((sloth_tool_id_t)device));
    if (!names || !names_n) return;
    static const struct { unsigned bit; const char *name; } NM[] = {
        { HW_SIG_TOOL, "tool" }, { HW_SIG_STACK, "stack" },
        { HW_SIG_PAIR, "pair" }, { HW_SIG_OUI, "oui" },
    };
    size_t off = 0;
    for (size_t i = 0; i < sizeof(NM) / sizeof(NM[0]); i++) {
        if (!((unsigned)signals & NM[i].bit)) continue;
        int w = snprintf(names + off, names_n - off, "%s%s",
                         off ? "+" : "", NM[i].name);
        if (w < 0 || (size_t)w >= names_n - off) break;
        off += (size_t)w;
    }
}

void hw_karma_context(const sloth_state_t *s, const beacon_ap_t *a,
                      const sloth_tool_sig_t *tool_row, time_t now,
                      hw_verdict_t *v, char *note, size_t n) {
    hw_verdict_t local;
    if (!v) v = &local;
    memset(v, 0, sizeof(*v));
    if (note && n) note[0] = '\0';
    if (!a) return;

    hw_pine_pair_t pair;
    hw_pineapple_pair(s, a, now, &pair);

    hw_inputs_t in;
    memset(&in, 0, sizeof(in));
    in.tool_row  = tool_row;
    in.stack_row = hw_stack_match(a->fp.ie_order_hash,
                                  a->fp.ie_order_count, NULL);
    in.pine_pair = pair.found;
    memcpy(in.oui, a->bssid, 3);
    hw_verdict_eval(&in, v);

    if (!note || !n) return;
    char pnote[64] = "";
    /* pair.ssid passed hw_pineapple_setup_ssid(): "Pineapple_" and four
     * hex digits, so no transmitter-chosen byte reaches the detail. */
    if (pair.found)
        snprintf(pnote, sizeof(pnote),
                 " +setup-AP %s@%02x:%02x:%02x:%02x:%02x:%02x",
                 pair.ssid, pair.bssid[0], pair.bssid[1], pair.bssid[2],
                 pair.bssid[3], pair.bssid[4], pair.bssid[5]);
    snprintf(note, n, "%s%s%s", pnote, v->label[0] ? " hw:" : "",
             v->label);
}
