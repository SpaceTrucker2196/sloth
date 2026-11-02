/* What slothweb repeats of sloth's own tables (#163, M5), held to
 * sloth's: the AKM suite names (src/rsn_ie.c rsn_akm_name(), linked
 * into slothweb_test alone), the downgrade bits (include/sloth.h
 * WPA_DG_*) and DEAUTH_FLOOD's alert type (include/sloth_alerts.def).
 * slothweb compiles no src/ file; this suite is where the copies are
 * kept honest. Its own file, because it is the one place web/ includes
 * sloth.h. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sloth.h"
#include "web_ble.h"
#include "web_slothdb.h"
#include "web_wifi.h"
#include "wtest.h"

const char *rsn_akm_name(uint8_t t);

/* Seen red with web_akm_name(19) answering "?". */
static void test_akm_names_are_sloths(void) {
    for (int t = 0; t < 32; t++) {
        const char *a = web_akm_name(t), *b = rsn_akm_name((uint8_t)t);
        if (strcmp(a, b)) fprintf(stderr, "    AKM %d: %s, sloth %s\n", t, a, b);
        WT_ASSERT(!strcmp(a, b));
    }
}

static void test_downgrade_bits_are_sloths(void) {
    static const struct { int bit; const char *word; } D[] = {
        { WPA_DG_TRANSITION_SAE_PSK, "SAE/PSK" }, { WPA_DG_OWE_TRANSITION, "OWE" },
        { WPA_DG_MFP_OPTIONAL, "MFP" }, { WPA_DG_WPA1_ALONGSIDE, "WPA1" },
    };
    for (size_t i = 0; i < sizeof(D) / sizeof(D[0]); i++) {
        int b = 0;
        while (b < 8 && D[i].bit != (1 << b)) b++;
        WT_ASSERT(b < 8);
        const char *nm = web_downgrade_name(b);
        WT_ASSERT(nm && strstr(nm, D[i].word));
    }
    WT_ASSERT(web_downgrade_name(4) == NULL);
    WT_EQ(WEB_ALERT_DEAUTH_FLOOD, ALERT_TYPE_DEAUTH_FLOOD);
}

/* A source file as text (its own allocation: the test holds several). */
static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *buf = malloc(1 << 20);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (1 << 20) - 1, f);
    fclose(f);
    buf[n] = '\0';
    return buf;
}

/* A quoted string literal in a source file. */
static int has_lit(const char *src, const char *s) {
    char q[128];
    snprintf(q, sizeof(q), "\"%s\"", s);
    return src && strstr(src, q) != NULL;
}

/* The BLE view's vocabularies (web_ble.h) are sloth's own words: the
 * PDU names of src/ble_detect.c ble_adv_type_name(), the band, trend,
 * glyph and P_tx source names of src/rf_distance.c, the family names
 * of src/ble_flood.c, the finding kinds and sensor names of
 * src/jsonl.c, the alert names of include/sloth_alerts.def, and the
 * TUI's address-type letters (src/views/ble.c type_ch()). slothweb
 * compiles no src/ file, so the copies are read as text here. Seen red
 * with "bldg" changed to "bld" in web_ble.c. */
static void test_ble_vocabularies_are_sloths(void) {
    char *det = slurp("src/ble_detect.c");
    WT_ASSERT(det != NULL);
    for (int i = 0; i < WEB_BLE_PDU_COUNT; i++) WT_ASSERT(has_lit(det, web_ble_pdu_name(i)));
    char *rf = slurp("src/rf_distance.c");
    WT_ASSERT(rf != NULL);
    for (int b = WEB_BLE_BAND_IMMEDIATE; b < WEB_BLE_BAND_COUNT; b++) {
        WT_ASSERT(has_lit(rf, web_ble_band_name(b)));
        WT_ASSERT(has_lit(rf, web_ble_band_short(b)));
    }
    for (int t = 0; t < WEB_BLE_TREND_COUNT; t++) WT_ASSERT(has_lit(rf, web_ble_trend_name(t)));
    WT_ASSERT(rf && strstr(rf, "\"\\xe2\\x86\\x98\""));   /* ↘ approaching */
    WT_ASSERT(rf && strstr(rf, "\"\\xe2\\x86\\x92\""));   /* → steady */
    WT_ASSERT(rf && strstr(rf, "\"\\xe2\\x86\\x97\""));   /* ↗ leaving */
    for (int p = 0; p < WEB_BLE_PTX_COUNT; p++) {
        WT_ASSERT(has_lit(rf, web_ble_ptx_name(p)));
        WT_ASSERT(has_lit(rf, web_ble_ptx_short(p)));
    }
    /* rf_dist_cell()'s metres: "<1m", "%dm", ">1km"; the cell's "~". */
    WT_ASSERT(rf && strstr(rf, "\"<1m\"") && strstr(rf, "\"%dm\"") && strstr(rf, "\">1km\""));
    WT_ASSERT(rf && strstr(rf, "\"~%s %s%s%s\""));
    char *fl = slurp("src/ble_flood.c");
    WT_ASSERT(fl != NULL);
    WT_ASSERT(has_lit(fl, "mfr") && has_lit(fl, "svc_data"));
    char *jl = slurp("src/jsonl.c");
    WT_ASSERT(jl != NULL);
    for (int k = 0; k < WEB_BLE_FIND_OTHER; k++) WT_ASSERT(has_lit(jl, web_ble_kind_name(k)));
    WT_ASSERT(has_lit(jl, "previous") && has_lit(jl, "current"));
    char *def = slurp("include/sloth_alerts.def");
    WT_ASSERT(def != NULL);
    for (int a = 0; a < WEB_BLE_ALERT_OTHER; a++) {
        char x[64];
        snprintf(x, sizeof(x), "X(%s,", web_ble_alert_name(a));
        WT_ASSERT(def && strstr(def, x));
    }
    WT_EQ(WEB_BLE_IF_COUNT, 3);
    char *hci = slurp("src/ble_hci.h");
    char *bts = slurp("src/bt_stream.h");
    WT_ASSERT((hci && strstr(hci, "\"bluetooth-monitor\"")) || (bts && strstr(bts, "\"bluetooth-monitor\"")));
    char *tui = slurp("src/views/ble.c");
    WT_ASSERT(tui != NULL);
    static const struct { int t; char c; } TC[] = { { 0, 'P' }, { 1, 'R' }, { 2, 'p' }, { 3, 'r' } };
    for (size_t i = 0; i < sizeof(TC) / sizeof(TC[0]); i++) {
        char want[32];
        snprintf(want, sizeof(want), "case %d:  return '%c';", TC[i].t, TC[i].c);
        WT_ASSERT(tui && strstr(tui, want));
        WT_EQ(web_ble_type_ch(TC[i].t), TC[i].c);
    }
    WT_ASSERT(tui && strstr(tui, "default: return '?';"));
    WT_EQ(web_ble_type_ch(255), '?');
    /* The TUI's lines the page carries verbatim. */
    WT_ASSERT(tui && strstr(tui, "T: P public R random p/r resolved  H HID  W watchlist  ~ sample  DIST: signal-strength estimate"));
    WT_ASSERT(tui && strstr(tui, "corroborates, does not confirm, and identifies no device "));
    /* The record's own bounds: a name of BLE_DEV_NAME_MAX octets, the
     * stream's form up to three bytes each, the display form four. */
    WT_EQ(WEB_BLE_NAME_MAX, BLE_DEV_NAME_MAX * 4);
    WT_EQ(WEB_BLE_DEVICES, 4 * MAX_BLE_DEVICES);
    /* The alert-type numbers the BLE fixtures carry (web/tools/demo.c,
     * web/tests/test_ble.c, test_alerts.c): slothweb types a stream
     * incident by its "ty" (web_akb_get()), so a fixture one off names
     * the neighbouring rule. The parity map said 88..90; the .def says
     * 87..89, and this pin is what caught it. */
    WT_EQ(ALERT_TYPE_BLE_ADV_FLOOD, 87);
    WT_EQ(ALERT_TYPE_BLE_HID_UNEXPECTED, 88);
    WT_EQ(ALERT_TYPE_BLE_WATCHLIST, 89);
    free(det); free(rf); free(fl); free(jl); free(def); free(hci); free(bts); free(tui);
}

void run_parity_tests(void) {
    WT_RUN(test_akm_names_are_sloths);
    WT_RUN(test_downgrade_bits_are_sloths);
    WT_RUN(test_ble_vocabularies_are_sloths);
}
