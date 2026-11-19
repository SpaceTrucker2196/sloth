/* intel_parity: the generated tables against sloth's hand-kept rows
 * (#231, the parity proof #184 §3 Stage 2 asks for).
 *
 * Built once per section below (-DPARITY_<TABLE>, plus -DPARITY_MAIN
 * for main()), each section a translation unit that #includes one of
 * the six table sources as it stood before Stage 2 replaced its rows
 * (`make intel-parity` extracts them from git at PARITY_REF into a
 * directory searched first) next to an array built from the generated
 * initialiser file. Same struct type, compared element by element and
 * field by field, order included; strings by their bytes. So it holds
 * the generated rows to the rows the parent commit compiled, not to a
 * re-reading of the same CSV the generator read.
 *
 * Not part of `make test`: it needs git and the pre-Stage-2 tree. It is
 * the proof that the move changed no row, kept so it can be rerun (and
 * run against another generator's output, PARITY_INC=<dir>). */
#include <stdio.h>
#include <string.h>

/* Defined once, in the PARITY_MAIN unit. */
int cmp_str(const char *t, int row, const char *f, const char *a, const char *b);
int cmp_num(const char *t, int row, const char *f, long long a, long long b);
int cmp_count(const char *t, int old_n, int new_n);

#define N(a) ((int)(sizeof(a) / sizeof((a)[0])))

#if defined(PARITY_OUI)
#include "oui.c"
static const struct { uint32_t oui; const char *vendor; } gen_oui[] = {
#include "oui_builtin.inc"
};
int parity_oui(void);
int parity_oui(void) {
    int bad = cmp_count("g_oui", N(g_oui), N(gen_oui));
    for (int i = 0; i < N(g_oui) && i < N(gen_oui); i++) {
        bad += cmp_num("g_oui", i, "oui", g_oui[i].oui, gen_oui[i].oui);
        bad += cmp_str("g_oui", i, "vendor", g_oui[i].vendor, gen_oui[i].vendor);
    }
    return bad;
}

#elif defined(PARITY_ATTACKER)
#include "wifi_oui_attacker.c"
static const uint8_t gen_hak5[][3] = {
#include "attacker_hak5.inc"
};
static const uint8_t gen_esp[][3] = {
#include "attacker_espressif.inc"
};
static int cmp3(const char *t, const uint8_t (*o)[3], int on,
                const uint8_t (*g)[3], int gn) {
    int bad = cmp_count(t, on, gn);
    for (int i = 0; i < on && i < gn; i++)
        for (int k = 0; k < 3; k++) bad += cmp_num(t, i, "oui", o[i][k], g[i][k]);
    return bad;
}
int parity_attacker(void);
int parity_attacker(void) {
    return cmp3("kHak5Ouis", kHak5Ouis, N(kHak5Ouis), gen_hak5, N(gen_hak5)) +
           cmp3("kEspressifOuis", kEspressifOuis, N(kEspressifOuis), gen_esp, N(gen_esp));
}

#elif defined(PARITY_CAMERA)
#include "camera_vendor.c"
static const cam_oui_row_t gen_cam[] = {
#include "camera_oui.inc"
};
static const char *const gen_brands[] = {
#include "camera_server_brands.inc"
};
static const cam_svc_row_t gen_svcs[] = {
#include "camera_services.inc"
};
static const cam_setup_ssid_pat_t gen_ssids[] = {
#include "camera_setup_ssids.inc"
};
int parity_camera(void);
int parity_camera(void) {
    int bad = cmp_count("g_cam_oui", N(g_cam_oui), N(gen_cam));
    for (int i = 0; i < N(g_cam_oui) && i < N(gen_cam); i++) {
        for (int k = 0; k < 3; k++)
            bad += cmp_num("g_cam_oui", i, "oui", g_cam_oui[i].oui[k], gen_cam[i].oui[k]);
        bad += cmp_str("g_cam_oui", i, "vendor", g_cam_oui[i].vendor, gen_cam[i].vendor);
        bad += cmp_str("g_cam_oui", i, "org", g_cam_oui[i].org, gen_cam[i].org);
        bad += cmp_num("g_cam_oui", i, "mixed", g_cam_oui[i].mixed, gen_cam[i].mixed);
    }
    bad += cmp_count("g_cam_server_brands", N(g_cam_server_brands), N(gen_brands));
    for (int i = 0; i < N(g_cam_server_brands) && i < N(gen_brands); i++)
        bad += cmp_str("g_cam_server_brands", i, "brand", g_cam_server_brands[i], gen_brands[i]);
    bad += cmp_count("g_cam_svcs", N(g_cam_svcs), N(gen_svcs));
    for (int i = 0; i < N(g_cam_svcs) && i < N(gen_svcs); i++) {
        bad += cmp_str("g_cam_svcs", i, "name", g_cam_svcs[i].name, gen_svcs[i].name);
        bad += cmp_str("g_cam_svcs", i, "label", g_cam_svcs[i].label, gen_svcs[i].label);
        bad += cmp_num("g_cam_svcs", i, "camera_specific", g_cam_svcs[i].camera_specific,
                       gen_svcs[i].camera_specific);
    }
    bad += cmp_count("g_camera_setup_ssid_pats", N(g_camera_setup_ssid_pats), N(gen_ssids));
    for (int i = 0; i < N(g_camera_setup_ssid_pats) && i < N(gen_ssids); i++) {
        bad += cmp_str("g_camera_setup_ssid_pats", i, "prefix",
                       g_camera_setup_ssid_pats[i].prefix, gen_ssids[i].prefix);
        bad += cmp_str("g_camera_setup_ssid_pats", i, "label",
                       g_camera_setup_ssid_pats[i].label, gen_ssids[i].label);
        bad += cmp_str("g_camera_setup_ssid_pats", i, "brand",
                       g_camera_setup_ssid_pats[i].brand, gen_ssids[i].brand);
    }
    return bad;
}

#elif defined(PARITY_WATCHLIST)
#include "vendor_watchlist.c"
static const struct { const char *domain, *vendor, *family; } gen_ep[] = {
#include "surveillance_endpoints.inc"
};
int parity_watchlist(void);
int parity_watchlist(void) {
    int bad = cmp_count("kEndpoints", N(kEndpoints), N(gen_ep));
    for (int i = 0; i < N(kEndpoints) && i < N(gen_ep); i++) {
        bad += cmp_str("kEndpoints", i, "domain", kEndpoints[i].domain, gen_ep[i].domain);
        bad += cmp_str("kEndpoints", i, "vendor", kEndpoints[i].vendor, gen_ep[i].vendor);
        bad += cmp_str("kEndpoints", i, "family", kEndpoints[i].family, gen_ep[i].family);
    }
    return bad;
}

#elif defined(PARITY_TOOL)
#include "tool_fingerprint.c"
static const sloth_tool_sig_t gen_sig[] = {
#include "tool_signatures.inc"
};
int parity_tool(void);
int parity_tool(void) {
    int on = N(TOOL_SIGNATURES) - 1;     /* less the terminator */
    int bad = cmp_count("TOOL_SIGNATURES", on, N(gen_sig));
    for (int i = 0; i < on && i < N(gen_sig); i++) {
        const sloth_tool_sig_t *o = &TOOL_SIGNATURES[i], *g = &gen_sig[i];
        bad += cmp_num("TOOL_SIGNATURES", i, "tool", o->tool, g->tool);
        bad += cmp_num("TOOL_SIGNATURES", i, "vendor_ie_hash", o->vendor_ie_hash, g->vendor_ie_hash);
        bad += cmp_num("TOOL_SIGNATURES", i, "beacon_interval_ms", o->beacon_interval_ms, g->beacon_interval_ms);
        bad += cmp_num("TOOL_SIGNATURES", i, "supported_rates", o->supported_rates, g->supported_rates);
        bad += cmp_num("TOOL_SIGNATURES", i, "require_flags", o->require_flags, g->require_flags);
        bad += cmp_num("TOOL_SIGNATURES", i, "forbid_flags", o->forbid_flags, g->forbid_flags);
        bad += cmp_num("TOOL_SIGNATURES", i, "requires_karma_echo", o->requires_karma_echo, g->requires_karma_echo);
        bad += cmp_num("TOOL_SIGNATURES", i, "requires_pmkid", o->requires_pmkid, g->requires_pmkid);
        bad += cmp_num("TOOL_SIGNATURES", i, "unverified", o->unverified, g->unverified);
        bad += cmp_str("TOOL_SIGNATURES", i, "human_label", o->human_label, g->human_label);
        bad += cmp_str("TOOL_SIGNATURES", i, "evidence", o->evidence, g->evidence);
        bad += cmp_str("TOOL_SIGNATURES", i, "id", o->id, g->id);
        bad += cmp_str("TOOL_SIGNATURES", i, "version", o->version, g->version);
    }
    return bad;
}

#elif defined(PARITY_BLE)
#include "ble_watchlist.c"
static const ble_wl_row_t gen_ble[] = {
#include "ble_watchlist.inc"
    { NULL, 0, 0, 0, 0, 0, NULL }
};
int parity_ble(void);
int parity_ble(void) {
    /* The pre-Stage-2 table is no array at all: a NULL pointer and a
     * zero count. Its whole content is the count. */
    return cmp_count("ble watchlist rows", ble_watchlist_count(), N(gen_ble) - 1);
}

#elif defined(PARITY_MAIN)
int cmp_str(const char *t, int row, const char *f, const char *a, const char *b) {
    if ((a == NULL) != (b == NULL) || (a && strcmp(a, b) != 0)) {
        printf("  %s row %d %s: \"%s\" != \"%s\"\n", t, row, f, a ? a : "(null)", b ? b : "(null)");
        return 1;
    }
    return 0;
}

int cmp_num(const char *t, int row, const char *f, long long a, long long b) {
    if (a != b) {
        printf("  %s row %d %s: %lld != %lld\n", t, row, f, a, b);
        return 1;
    }
    return 0;
}

int cmp_count(const char *t, int old_n, int new_n) {
    printf("  %-28s old %4d rows, generated %4d rows\n", t, old_n, new_n);
    return old_n != new_n;
}

int parity_oui(void);
int parity_attacker(void);
int parity_camera(void);
int parity_watchlist(void);
int parity_tool(void);
int parity_ble(void);
int main(void) {
    int bad = parity_oui() + parity_attacker() + parity_camera() +
              parity_watchlist() + parity_tool() + parity_ble();
    if (bad) {
        printf("intel-parity: %d difference%s\n", bad, bad == 1 ? "" : "s");
        return 1;
    }
    printf("intel-parity: every row identical, field by field and in order\n");
    return 0;
}
#else
#error "build with -DPARITY_<TABLE> or -DPARITY_MAIN"
#endif
