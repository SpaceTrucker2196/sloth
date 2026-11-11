/* The BLE Devices view (web_bledev.h, 2026-11-02): the closed class
 * list and its first-match order, the proximity grade against sloth's
 * own distance model, the page's copies of both, the class mix fed from
 * ble_device records (the high-water ids, a reconnect, two sensors on
 * one address, a sampled row), the advertisers gauge, anonymous
 * advertising (one entry and one advertiser, always in Unknown, no
 * proximity row and no read slot), the two routes
 * over memory and (WITH_SQLITE) over slothweb.db, where the class mix
 * shares chmix with the WiFi mix and neither namespace reads the
 * other's rows. Every advertisement field is written as sloth's
 * jsonl_emit_ble_devices() writes it; every Appearance value is the
 * SIG's (web/data/btsig/appearance_values.csv). */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "web_assets.h"
#include "web_ble.h"
#include "web_bledev.h"
#include "web_chmix.h"
#include "web_jsonl.h"
#include "web_metrics.h"
#include "web_rollup.h"
#include "web_routes.h"
#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif
#include "web_store.h"
#include "web_tsdb.h"
#include "web_wifi.h"
#include "wtest.h"
#include "wt_tmp.h"

#define T 1793000000LL

static char g_out[131072];

static const char *body_of(const char *out) {
    const char *sep = strstr(out, "\r\n\r\n");
    return sep ? sep + 4 : "";
}

static int route(const web_health_t *h, const char *path, const char *query) {
    web_req_t rq;
    web_resp_t r;
    memset(&rq, 0, sizeof(rq));
    snprintf(rq.path, sizeof(rq.path), "%s", path);
    snprintf(rq.query, sizeof(rq.query), "%s", query);
    snprintf(rq.host, sizeof(rq.host), "127.0.0.1:8770");
    rq.host_count = 1;
    if (web_route(&rq, h, 1, g_out, sizeof(g_out), &r) != 0) return -1;
    g_out[r.out_len] = '\0';
    return r.status;
}

/* ── the classes ──────────────────────────────────────────────────── */

static web_ble_fields_t none(void) {
    web_ble_fields_t f = { -1, -1, -1, -1, -1, 0, 0 };
    return f;
}

static int cls_mfr(int id, int sub) {
    web_ble_fields_t f = none();
    f.mfr_id = id;
    f.mfr_subtype = sub;
    return web_ble_class_of(&f);
}

static int cls_app(int a) {
    web_ble_fields_t f = none();
    f.appearance = a;
    return web_ble_class_of(&f);
}

static int cls_uuid(int list, int svc) {
    web_ble_fields_t f = none();
    f.uuid16 = list;
    f.svc_data_uuid16 = svc;
    return web_ble_class_of(&f);
}

/* One field set per rule, and each thing the page says is left out
 * landing in Unknown. Seen red with the Tile UUIDs dropped from rule 1
 * (0xFEED reads Unknown) and with Eddystone matched on the service data
 * alone (a listed 0xFEAA reads Unknown). */
static void test_each_rule(void) {
    web_ble_fields_t f = none();
    f.watch = 1;
    WT_EQ(web_ble_class_of(&f), WEB_BC_TAG);
    WT_EQ(cls_app(0x0200), WEB_BC_TAG);            /* Tag */
    WT_EQ(cls_app(0x0240), WEB_BC_TAG);            /* Keyring */
    WT_EQ(cls_uuid(0xFEED, -1), WEB_BC_TAG);       /* Tile, listed */
    WT_EQ(cls_uuid(-1, 0xFEEC), WEB_BC_TAG);       /* Tile, service data */
    WT_EQ(cls_uuid(0xFD84, -1), WEB_BC_TAG);
    WT_EQ(cls_uuid(-1, 0xFE33), WEB_BC_TAG);       /* CHIPOLO */
    WT_EQ(cls_uuid(0xFE65, -1), WEB_BC_TAG);
    f = none();
    f.hid = 1;
    WT_EQ(web_ble_class_of(&f), WEB_BC_HID);
    f.hid = 2;
    WT_EQ(web_ble_class_of(&f), WEB_BC_HID);
    WT_EQ(cls_uuid(-1, 0xFEAA), WEB_BC_BCN);       /* Eddystone */
    WT_EQ(cls_uuid(0xFEAA, -1), WEB_BC_BCN);
    WT_EQ(cls_mfr(0x004C, 0x07), WEB_BC_WEAR);     /* Proximity Pairing */
    WT_EQ(cls_mfr(0x004C, 0x0B), WEB_BC_WEAR);     /* Magic Switch */
    WT_EQ(cls_uuid(-1, 0xFE2C), WEB_BC_WEAR);      /* Fast Pair provider */
    WT_EQ(cls_mfr(0x0075, 0x42), WEB_BC_WEAR);     /* buds */
    WT_EQ(cls_mfr(0x0075, 0x01), WEB_BC_WEAR);     /* watch */
    WT_EQ(cls_app(0x00C0), WEB_BC_WEAR);           /* Watch */
    WT_EQ(cls_app(0x0941), WEB_BC_WEAR);           /* Wearable Audio: Earbud */
    WT_EQ(cls_app(0x0A40), WEB_BC_WEAR);           /* Hearing aid */
    WT_EQ(cls_app(0x0341), WEB_BC_WEAR);           /* Heart Rate Belt */
    WT_EQ(cls_app(0x1440), WEB_BC_WEAR);           /* Outdoor Sports Activity */
    static const int PHONE_SUBS[] = { 0x05, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    for (size_t i = 0; i < sizeof(PHONE_SUBS) / sizeof(PHONE_SUBS[0]); i++)
        WT_EQ(cls_mfr(0x004C, PHONE_SUBS[i]), WEB_BC_PHONE);
    WT_EQ(cls_mfr(0x0006, 0x01), WEB_BC_PHONE);    /* MS-CDP */
    WT_EQ(cls_app(0x0040), WEB_BC_PHONE);          /* Phone */
    WT_EQ(cls_app(0x0083), WEB_BC_PHONE);          /* Computer / Laptop */
    WT_EQ(cls_mfr(0x004C, 0x06), WEB_BC_IOT);      /* HomeKit */
    WT_EQ(cls_app(0x0540), WEB_BC_IOT);            /* Sensor */
    WT_EQ(cls_app(0x08C1), WEB_BC_IOT);            /* Motorized Vehicle: Car */
    WT_EQ(cls_app(0x0100), WEB_BC_IOT);            /* Clock */
    /* Left out, and so Unknown. */
    f = none();
    WT_EQ(web_ble_class_of(&f), WEB_BC_UNK);
    WT_EQ(cls_mfr(0x004C, 0x02), WEB_BC_UNK);      /* iBeacon: no primary text read */
    WT_EQ(cls_mfr(0x004C, 0x12), WEB_BC_UNK);      /* Find My: unverified */
    WT_EQ(cls_mfr(0x004C, 0x09), WEB_BC_UNK);      /* AirPlay: sent by the source too */
    WT_EQ(cls_mfr(0x0006, 0x03), WEB_BC_UNK);      /* Swift Pair */
    WT_EQ(cls_uuid(-1, 0xFD59), WEB_BC_UNK);       /* SmartTag: unverified */
    WT_EQ(cls_uuid(-1, 0xFD5A), WEB_BC_UNK);
    WT_EQ(cls_uuid(0xFE2C, -1), WEB_BC_UNK);       /* listed only: no service data */
    WT_EQ(cls_app(0x0000), WEB_BC_UNK);
    WT_EQ(cls_app(0x03C1), WEB_BC_UNK);            /* HID category without sloth's bit */
}

/* A device whose fields hold two rules lands in the earlier; a
 * subtype of -1 (no first octet) is no subtype rule's, whatever the
 * company. The table's match numbers are the order the function tries. */
static void test_first_match_wins(void) {
    web_ble_fields_t f = none();
    f.watch = 1;
    f.hid = 1;
    WT_EQ(web_ble_class_of(&f), WEB_BC_TAG);
    f = none();
    f.hid = 1;
    f.mfr_id = 0x004C;
    f.mfr_subtype = 0x07;
    WT_EQ(web_ble_class_of(&f), WEB_BC_HID);
    f = none();
    f.svc_data_uuid16 = 0xFEAA;
    f.mfr_id = 0x004C;
    f.mfr_subtype = 0x10;
    WT_EQ(web_ble_class_of(&f), WEB_BC_BCN);
    f = none();                                    /* a Watch with Nearby Info */
    f.appearance = 0x00C1;
    f.mfr_id = 0x004C;
    f.mfr_subtype = 0x10;
    WT_EQ(web_ble_class_of(&f), WEB_BC_WEAR);
    f = none();
    f.appearance = 0x0540;
    f.mfr_id = 0x004C;
    f.mfr_subtype = 0x10;
    WT_EQ(web_ble_class_of(&f), WEB_BC_PHONE);
    f = none();
    f.appearance = 0x0200;
    f.uuid16 = 0xFEAA;
    WT_EQ(web_ble_class_of(&f), WEB_BC_TAG);
    WT_EQ(cls_mfr(0x004C, -1), WEB_BC_UNK);
    WT_EQ(cls_mfr(0x0075, -1), WEB_BC_UNK);
    WT_EQ(cls_mfr(0x0006, -1), WEB_BC_UNK);
    static const int ORDER[WEB_BC_COUNT] = { WEB_BC_TAG, WEB_BC_HID, WEB_BC_BCN, WEB_BC_WEAR,
                                             WEB_BC_PHONE, WEB_BC_IOT, WEB_BC_UNK };
    for (int i = 0; i < WEB_BC_COUNT; i++) WT_EQ(web_ble_classes[ORDER[i]].match, i + 1);
}

/* The slugs: short enough for a chmix key, unique, never a channel key
 * (web_key_channel_text() refuses each), and the only keys the
 * "bleclass" canonicaliser takes. */
static void test_slugs(void) {
    char out[WEB_KEY_MAX + 1];
    for (int c = 0; c < WEB_BC_COUNT; c++) {
        const char *s = web_ble_classes[c].slug;
        WT_ASSERT(strlen(s) <= WEB_CHMIX_KEY_MAX);
        WT_ASSERT(!strncmp(s, "b:", 2));
        WT_ASSERT(web_key_channel_text(s, out) != 0);
        WT_EQ(web_key_bleclass_text(s, out), 0);
        WT_ASSERT(!strcmp(out, s));
        WT_EQ(web_key_canon(WM_BLE_CLASS_ADV, s, out), 0);
        WT_EQ(web_ble_class_find(s), c);
        WT_EQ((int)strlen(web_ble_classes[c].glyph), 1);
        for (int k = 0; k < c; k++) WT_ASSERT(strcmp(web_ble_classes[k].slug, s));
    }
    WT_ASSERT(web_key_bleclass_text("b:", out) != 0);
    WT_ASSERT(web_key_bleclass_text("b:tags", out) != 0);
    WT_ASSERT(web_key_bleclass_text("B:TAG", out) != 0);
    WT_ASSERT(web_key_bleclass_text("6", out) != 0);
    WT_ASSERT(web_key_bleclass_text("", out) != 0);
    WT_ASSERT(web_key_canon(WM_BLE_CLASS_ADVERTISERS, "6", out) != 0);
    WT_ASSERT(!strcmp(web_metric_defs[WM_BLE_CLASS_ADVERTISERS].name, "ble.class.advertisers"));
    WT_ASSERT(!strcmp(web_metric_defs[WM_BLE_CLASS_ADV].name, "ble.class.adv"));
    WT_EQ(web_metric_defs[WM_BLE_CLASS_ADV].kind, WEB_MK_COUNTER);
    WT_EQ(web_metric_defs[WM_BLE_CLASS_ADVERTISERS].kind, WEB_MK_GAUGE);
    WT_EQ(web_metric_defs[WM_BLE_CLASS_ADV].kclass, WEB_KC_BLECLASS);
    WT_ASSERT(!strcmp(web_kclass_name(WEB_KC_BLECLASS), "bleclass"));
    WT_ASSERT(!strcmp(web_kclass_name(WEB_KC_BLE), "ble"));
    WT_EQ(web_scope_metric(WM_BLE_CLASS_ADV), WEB_SC_M);
}

/* A record's fields as the emitter writes them: absent numbers -1, a
 * subtype out of range ignored, a watch category any slug. */
static void test_class_of_record(void) {
    static web_jrec_t r;
    static const char *const L[] = {
        "{\"type\":\"ble_device\",\"mfr_id\":76,\"mfr_subtype\":12,\"uuid16\":-1,"
        "\"svc_data_uuid16\":-1,\"appearance\":-1,\"hid\":0,\"watch_category\":\"\"}",
        "{\"type\":\"ble_device\",\"mfr_id\":-1,\"mfr_subtype\":-1,\"uuid16\":-1,"
        "\"svc_data_uuid16\":-1,\"appearance\":-1,\"hid\":0,\"watch_category\":\"finder\"}",
        "{\"type\":\"ble_device\",\"mfr_id\":76,\"mfr_subtype\":300,\"appearance\":-1,\"hid\":0}",
        "{\"type\":\"ble_device\",\"appearance\":961,\"hid\":1}",
    };
    static const int WANT[] = { WEB_BC_PHONE, WEB_BC_TAG, WEB_BC_UNK, WEB_BC_HID };
    for (int i = 0; i < 4; i++) {
        WT_EQ(web_jl_parse(L[i], strlen(L[i]), &r), WEB_JL_OK);
        WT_EQ(web_ble_class_of_rec(&r), WANT[i]);
    }
}

/* ── the proximity grade ──────────────────────────────────────────── */

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    static char buf[1 << 17];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    return buf;
}

/* The edges are sloth's model's (src/rf_distance.h and .c, read here so
 * a change there fails this): P_tx 0 dBm assumed for BLE, 2440 MHz,
 * L(d0) = 20 log10(f) - 28, N 2.8, bands at 1, 3, 10, 30 m. A reading
 * exactly at an edge is the farther band, as rf_band_of()'s m < edge. */
static void test_proximity_edges(void) {
    WT_ASSERT(fabs(web_ble_prox_edge(1.0) - -39.748) < 0.005);
    WT_ASSERT(fabs(web_ble_prox_edge(3.0) - -53.108) < 0.005);
    WT_ASSERT(fabs(web_ble_prox_edge(10.0) - -67.748) < 0.005);
    WT_ASSERT(fabs(web_ble_prox_edge(30.0) - -81.108) < 0.005);
    WT_EQ(web_ble_prox_band(-30), WEB_BLE_BAND_IMMEDIATE);
    WT_EQ(web_ble_prox_band(-39.7), WEB_BLE_BAND_IMMEDIATE);
    WT_EQ(web_ble_prox_band(-39.8), WEB_BLE_BAND_NEAR);
    WT_EQ(web_ble_prox_band(-53.0), WEB_BLE_BAND_NEAR);
    WT_EQ(web_ble_prox_band(-53.2), WEB_BLE_BAND_ROOM);
    WT_EQ(web_ble_prox_band(-67.7), WEB_BLE_BAND_ROOM);
    WT_EQ(web_ble_prox_band(-67.8), WEB_BLE_BAND_BUILDING);
    WT_EQ(web_ble_prox_band(-81.1), WEB_BLE_BAND_BUILDING);
    WT_EQ(web_ble_prox_band(-81.2), WEB_BLE_BAND_FAR);
    WT_EQ(web_ble_prox_band(-127), WEB_BLE_BAND_FAR);
    WT_EQ(web_ble_prox_band(web_ble_prox_edge(3.0)), WEB_BLE_BAND_ROOM);
    const char *h = slurp("src/rf_distance.h");
    WT_ASSERT(h != NULL);
    if (h) {
        char want[64];
        WT_HAS(h, "#define RF_PTX_BLE_ASSUMED   0\n");
        snprintf(want, sizeof(want), "#define RF_N_2G_X10        %d\n", WEB_BLE_PROX_N_X10);
        WT_HAS(h, want);
        WT_HAS(h, "#define RF_BAND_IMMEDIATE_M  1.0\n");
        WT_HAS(h, "#define RF_BAND_NEAR_M       3.0\n");
        WT_HAS(h, "#define RF_BAND_ROOM_M      10.0\n");
        WT_HAS(h, "#define RF_BAND_BUILDING_M  30.0\n");
    }
    const char *c = slurp("src/rf_distance.c");
    WT_ASSERT(c != NULL);
    if (c) {
        WT_HAS(c, "    c->freq_mhz = 2440;\n");
        WT_HAS(c, "    return 20.0 * log10((double)freq_mhz) - 28.0;\n");
        WT_HAS(c, "    if (m < RF_BAND_IMMEDIATE_M) return RF_DIST_IMMEDIATE;\n");
    }
    WT_EQ(WEB_BLE_PROX_FREQ_MHZ, 2440);
    WT_EQ(WEB_BLE_PROX_PTX_DBM, 0);
}

/* ── the page ─────────────────────────────────────────────────────── */

/* bledev.js's class table is web_ble_classes[], row by row in display
 * order; its proximity grade is the same model; its panels are v-ble's
 * sections, so the scoped-out rule hides them under Local. Seen red
 * with a label changed on the C side only and with the JS N at 30. */
static void test_page_agrees(void) {
    const char *p = (const char *)web_page;
    const char *prev = strstr(p, "  var CLASSES = [\n");
    WT_ASSERT(prev != NULL);
    for (int c = 0; prev && c < WEB_BC_COUNT; c++) {
        char line[160];
        snprintf(line, sizeof(line), "    { slug: \"%s\", label: \"%s\", glyph: \"%s\" }%s\n",
                 web_ble_classes[c].slug, web_ble_classes[c].label, web_ble_classes[c].glyph,
                 c + 1 < WEB_BC_COUNT ? "," : "");
        const char *at = strstr(prev, line);
        if (!at) fprintf(stderr, "    bledev.js lacks, in order: %s", line);
        WT_ASSERT(at != NULL);
        if (at) prev = at;
    }
    WT_HAS(p, "  var PROX_L1 = 20 * Math.log10(2440) - 28, PROX_N_X10 = 28, PROX_PTX = 0;\n"
              "  function proxEdge(m) { return PROX_PTX - (PROX_L1 + PROX_N_X10 * Math.log10(m)); }\n"
              "  var PROX_EDGES = [proxEdge(1), proxEdge(3), proxEdge(10), proxEdge(30)];");
    WT_HAS(p, "    if (!E) E = PROX_EDGES;\n"
              "    return v > E[0] ? 1 : v > E[1] ? 2 : v > E[2] ? 3 : v > E[3] ? 4 : 5;");
    /* A row's own P_tx moves every edge by it, as web_ble_prox_edge_at(). */
    WT_HAS(p, "    return PROX_EDGES.map(function (e) { return e + ptx; });");
    WT_HAS(p, "    return b === 1 ? T.heat[3] : b === 2 ? T.heat[2] : b === 3 ? T.heat[1] : b === 4 ? T.heat[0] : T.faint;");
    WT_HAS(p, "A rotating random address is its own row: rotations are not linked.");
    WT_HAS(p, "so an empty row is not \"no trackers here\"");
    WT_HAS(p, "    add({ key: \"b:tag\" });");
    /* No BLE sensor is its own state, not a forced Trackers row; an
     * Ubertooth alone is said to be uncredited (2026-11-02 review). */
    WT_HAS(p, "    return !!(s && s.seen && !s.btmon_iface && !s.btcap_iface);");
    WT_HAS(p, "    return !!(s && s.seen && !s.btmon_iface && s.btcap_iface);");
    WT_HAS(p, "(no BLE sensor: no advertisements decoded - start with --bt-monitor or ");
    WT_HAS(p, "--bt-capture only: an Ubertooth's one-channel samples are not credited");
    /* A row is graded with its own P_tx; the label column opens the
     * drawer on a primary click only, never on pointerdown. */
    WT_HAS(p, "        g.fillStyle = proxColor(proxBand(v, rowEdges(r)));");
    WT_HAS(p, "    if (!geo || ev.button !== 0) return;");
    WT_HAS(p, "    pc.addEventListener(\"click\", function (ev) { labelClick(ev, pc, S.pgeo); });");
    WT_LACKS(p, "ev.type === \"pointerdown\"");
    /* The anonymous entry: neutral, labelled, never a button that
     * opens a drawer, counted apart from the named advertisers in the
     * mix note, said to be in Unknown in the note, the list and the
     * class panel; the proximity note says it was left out. Its kind
     * word is held to the C answer's in test_anonymous_routes. */
    WT_HAS(p, "    if (isAnon(t)) return H.theme().muted;");
    WT_HAS(p, "      var txs = S.mix.tx || [], named = txs.filter(function (t) { return !isAnon(t); }).length;\n"
              "      H.set(\"bledev-mix-note\", named + \" advertisers named\" +\n"
              "            (named < txs.length ? \" and anonymous advertising (no address: one neutral band, in Unknown)\" : \"\") +");
    WT_HAS(p, "\"  extended advertising with no address: every such advertiser a sensor heard, "
              "one row of fields between them, so Unknown\"");
    WT_HAS(p, "and anonymous advertising (an extended advertisement with no address) one neutral band "
              "labelled anonymous in Unknown, with no drawer to open: sloth holds every anonymous "
              "advertiser a sensor hears as one row, so its fields class none of them;");
    /* Under a cut the note's number is the candidates read, which
     * anonymous advertising takes no slot of (test_proximity_keeps_old_trackers). */
    WT_HAS(p, "(p.read_cut ? \"the \" + p.candidates + \" read (every tracker, then the newest; ");
    WT_HAS(p, "      var held = !anon && num(t.addr_type) && typeof t.iface === \"string\";");
    WT_HAS(p, "        nm.appendChild(H.el(\"span\", \"d-normal\", \"anonymous\"));");
    WT_HAS(p, "(p.anonymous_heard ? \"; anonymous advertising heard and not drawn: ");
    WT_HAS(p, "Anonymous advertising has no row: with no address there is no signal series to key");
    /* The class labels give way to glyphs past 30% of the canvas. */
    WT_HAS(p, "    if (padL + 6 * dpr > W * 0.3) {");
    /* The drawer's BLE lines are reset on every open, and redrawn on a
     * theme change. */
    WT_HAS(p, "    set(\"bdr-addr\", addr);\n    if (window.SlothBleDev) SlothBleDev.reset();\n");
    WT_HAS(p, "    if (!$(\"bdrawer\").hidden && B.sel) openBleDrawer(B.sel.addr, B.sel.type, B.sel.iface);");
    WT_HAS(p, "  window.SlothBleDev = { init: init, show: show, drawer: drawer, reset: reset };");
    /* The panels inside v-ble, each a section of it. */
    const char *vb = strstr(p, "<div id=\"v-ble\" hidden>");
    const char *vg = strstr(p, "<div id=\"v-gnss\" hidden>");
    const char *pc = strstr(p, "<canvas class=\"wfall bledev-classes\" id=\"bledev-classes\"");
    const char *pp = strstr(p, "<canvas class=\"wfall bledev-prox\" id=\"bledev-prox\"");
    WT_ASSERT(vb && vg && pc && pp && vb < pc && pc < pp && pp < vg);
    WT_HAS(p, "    <section class=\"panel\">\n      <div class=\"bleline\" id=\"bledev-now\"");
    WT_HAS(p, "<canvas class=\"spark bledev-rssi\" id=\"bledev-rssi\"");
    /* A colour by the name's hash or the address's, never through the
     * row's own d.addr (test_ble's pin on the table row). */
    WT_HAS(p, "    var nm = typeof name === \"string\" && name !== \"\" ? name : String(id);\n"
              "    return H.keyColor(nm);");
    /* No innerHTML anywhere in the module: every string is textContent
     * or fillText. */
    const char *m0 = strstr(p, "// slothweb: the BLE Devices view's waterfall");
    const char *m1 = m0 ? strstr(m0, "window.SlothBleDev = {") : NULL;
    WT_ASSERT(m0 && m1);
    if (m0 && m1) {
        size_t n = (size_t)(m1 - m0);
        char *mod = malloc(n + 1);
        if (mod) {
            memcpy(mod, m0, n);
            mod[n] = '\0';
            WT_LACKS(mod, "innerHTML");
            WT_LACKS(mod, "fetch(");
            free(mod);
        }
    }
}

/* ── the mix engine's BLE kind ────────────────────────────────────── */

static int g_nrows, g_frames;
static web_mix_row_t g_rows[64];

static int keep_row(void *ctx, const web_mix_row_t *r) {
    (void)ctx;
    if (g_nrows < 64) g_rows[g_nrows] = *r;
    g_nrows++;
    for (int i = 0; i < r->n; i++) g_frames += (int)r->tx[i].frames;
    g_frames += (int)r->other;
    return 0;
}

static void ring(web_chmix_t *c, long long from, long long to) {
    g_nrows = g_frames = 0;
    web_chmix_each_fine(c, from, to, keep_row, NULL);
}

/* Kinds 3 and 4 are taken (an advertiser, anonymous advertising),
 * kind 5 is not; a sized ring holds its rows and counts the
 * overwritten. Seen red with web_chmix_add() refusing WEB_TX_BLE as
 * before, and refusing WEB_TX_BLE_ANON (samples 1). */
static void test_chmix_ble_kind(void) {
    static web_chmix_t c;
    WT_EQ(web_chmix_init_sized(&c, 0, 4), 0);
    uint8_t mac[6] = { 0x02, 0xde, 0, 0, 0, 1 }, zero[6] = { 0, 0, 0, 0, 0, 0 };
    WT_EQ(WEB_TX_BLE_ANON, 4);
    web_chmix_add(&c, "b:unk", mac, WEB_TX_BLE, 5, T);
    web_chmix_add(&c, "b:unk", zero, WEB_TX_BLE_ANON, 5, T);
    web_chmix_add(&c, "b:unk", mac, 5, 5, T);
    web_chmix_stats_t st;
    web_chmix_stats(&c, &st);
    WT_EQ(st.samples, 2);
    /* The two share no key: the bucket at T holds both, apart. */
    web_chmix_close_all(&c);
    ring(&c, T, T + 10);
    WT_EQ(g_nrows, 1);
    WT_EQ(g_rows[0].n, 2);
    for (int i = 1; i <= 6; i++) web_chmix_add(&c, "b:wear", mac, WEB_TX_BLE, 1, T + i * 10);
    web_chmix_close_all(&c);
    web_chmix_stats(&c, &st);
    WT_EQ(st.ring_rows, 4);
    WT_EQ(st.ring_overwritten, 3);
    ring(&c, T, T + 100);
    WT_EQ(g_nrows, 4);
    WT_EQ(g_rows[0].tx[0].kind, WEB_TX_BLE);
    web_chmix_destroy(&c);
}

/* ── the records ──────────────────────────────────────────────────── */

static web_rollup_t  ru;
static web_metrics_t mx;
static web_chmix_t   bm;
static web_ble_t     bt;
static web_jrec_t    rec;
static long long     g_now;

static long long pinned(void *ctx) { (void)ctx; return g_now; }

static void line(const char *s) {
    int e = web_jl_parse(s, strlen(s), &rec);
    WT_EQ(e, WEB_JL_OK);
    if (e != WEB_JL_OK) return;
    web_metrics_record(&mx, &rec);
    web_ble_record(&bt, &rec, g_now * 1000);
}

/* A ble_device line as jsonl_emit_ble_devices() writes it, cut to what
 * slothweb reads. */
static void dev(const char *addr, const char *iface, int sampled, long long adv,
                long long first, long long last, int mfr, int sub, int rssi) {
    char l[768];
    snprintf(l, sizeof(l),
             "{\"type\":\"ble_device\",\"ts\":%lld,\"addr\":\"%s\",\"addr_type\":1,"
             "\"sensor\":\"ble\",\"iface\":\"%s\",\"adapter\":0,\"sampled\":%d,\"channel\":-1,"
             "\"last_pdu\":\"ADV_IND\",\"pdu_mask\":1,\"name\":\"\",\"name_complete\":0,"
             "\"uuid16\":-1,\"mfr_id\":%d,\"mfr_subtype\":%d,\"svc_data_uuid16\":-1,"
             "\"appearance\":-1,\"hid\":0,\"tx_power\":-128,\"flags\":-1,\"has_rssi\":1,"
             "\"rssi\":%d,\"rssi_best\":%d,\"adv_count\":%lld,\"watch_category\":\"\","
             "\"ext_adv\":0,\"primary_phy\":0,\"secondary_phy\":0,\"adv_sid\":-1,"
             "\"first_seen\":%lld,\"last_seen\":%lld}",
             g_now, addr, iface, sampled, mfr, sub, rssi, rssi, adv, first, last);
    line(l);
}

static int frames_of(const char *chan, int mac5) {
    int f = 0;
    for (int i = 0; i < g_nrows && i < 64; i++)
        if (!strcmp(g_rows[i].chan, chan))
            for (int k = 0; k < g_rows[i].n; k++)
                if (g_rows[i].tx[k].mac[5] == mac5) f += (int)g_rows[i].tx[k].frames;
    return f;
}

static void rec_up(void) {
    char err[64];
    WT_EQ(web_rollup_init(&ru, 64, 0, err, sizeof(err)), 0);
    WT_EQ(web_metrics_init(&mx, &ru, pinned, NULL), 0);
    WT_EQ(web_chmix_init_sized(&bm, 0, WEB_BLEDEV_RING), 0);
    WT_EQ(web_ble_init(&bt, 0), 0);
    web_metrics_set_blemix(&mx, &bm);
    web_metrics_set_ble(&mx, &bt);
}

static void rec_down(void) {
    web_ble_destroy(&bt);
    web_chmix_destroy(&bm);
    web_metrics_destroy(&mx);
    web_rollup_destroy(&ru);
}

/* adv_count is a running total per (addr, addr_type, sensor): a first
 * sight of a row older than the stream is a baseline, the next record
 * its delta, credited to the record's class in the mix and in
 * ble.class.adv; a reconnect is a baseline again; a row born while
 * listening counts its whole total; a one-channel sample counts
 * nothing; and the same address on two sensors keeps two totals. Seen
 * red with the iface left out of the high-water id: the two sensors'
 * totals interleaved into one, and the address's 27 reports read 232. */
static void test_records_feed_the_class_mix(void) {
    rec_up();
    g_now = T;
    const char *A = "c2:00:00:00:00:a1", *Y = "c2:00:00:00:00:a2", *S = "c2:00:00:00:00:a3";
    dev(A, "bluetooth-monitor", 0, 100, T - 1000, T, 0x004C, 0x10, -60);  /* baseline */
    dev(A, "ubertooth", 0, 3, T - 1000, T, 0x004C, 0x10, -70);           /* baseline */
    g_now = T + 10;
    dev(A, "bluetooth-monitor", 0, 115, T - 1000, T + 10, 0x004C, 0x10, -60);
    dev(A, "ubertooth", 0, 5, T - 1000, T + 10, 0x004C, 0x10, -70);
    dev(A, "bluetooth-monitor", 0, 125, T - 1000, T + 10, 0x004C, 0x10, -60);
    dev(Y, "bluetooth-monitor", 0, 7, T + 5, T + 10, 0x004C, 0x07, -50); /* born */
    dev(S, "ubertooth", 1, 40, T - 500, T + 10, -1, -1, -80);             /* sampled */
    g_now = T + 15;
    dev(S, "ubertooth", 1, 90, T - 500, T + 15, -1, -1, -80);
    web_chmix_close_all(&bm);
    ring(&bm, T - 100, T + 100);
    WT_EQ(frames_of("b:phone", 0xa1), 25 + 2);
    WT_EQ(frames_of("b:wear", 0xa2), 7);
    WT_EQ(frames_of("b:unk", 0xa3), 0);
    WT_EQ(g_frames, 34);
    WT_ASSERT(web_rollup_has(&ru, WM_BLE_CLASS_ADV, "b:phone"));
    WT_ASSERT(web_rollup_has(&ru, WM_BLE_CLASS_ADV, "b:wear"));
    WT_ASSERT(!web_rollup_has(&ru, WM_BLE_CLASS_ADV, "b:unk"));
    /* A reconnect: the next total is a baseline, then deltas again. */
    web_metrics_stream(&mx);
    g_now = T + 30;
    dev(A, "bluetooth-monitor", 0, 400, T - 1000, T + 30, 0x004C, 0x10, -60);
    g_now = T + 40;
    dev(A, "bluetooth-monitor", 0, 410, T - 1000, T + 40, 0x004C, 0x10, -60);
    web_chmix_close_all(&bm);
    ring(&bm, T + 20, T + 100);
    WT_EQ(frames_of("b:phone", 0xa1), 10);
    rec_down();
}

/* ble.class.advertisers: once a snapshot pass (the next iface record
 * after other records), the distinct addresses the BLE tables heard in
 * the last 20 s, per class; an address on two sensors once; a class
 * with none not sampled. Seen red with the address set removed from
 * web_ble_class_counts() (b:phone read 2). */
static void test_advertisers_gauge(void) {
    rec_up();
    g_now = T;
    char l[256];
    snprintf(l, sizeof(l), "{\"type\":\"iface\",\"ts\":%lld,\"name\":\"wlan0\"}", T);
    line(l);
    dev("c2:00:00:00:00:b1", "bluetooth-monitor", 0, 5, T - 100, T, 0x004C, 0x10, -60);
    dev("c2:00:00:00:00:b1", "ubertooth", 0, 5, T - 100, T, 0x004C, 0x10, -60);
    dev("c2:00:00:00:00:b2", "bluetooth-monitor", 0, 5, T - 100, T, 0x004C, 0x07, -60);
    dev("c2:00:00:00:00:b3", "bluetooth-monitor", 0, 5, T - 100, T - 60, 0x004C, 0x06, -60);
    line(l);
    web_point_t p[4];
    int more = 0;
    int n = web_rollup_fine(&ru, WM_BLE_CLASS_ADVERTISERS, "b:phone", T - 20, T + 20, 1, p, 4, &more);
    WT_EQ(n, 1);
    if (n == 1) WT_EQ((long long)(p[0].sum / p[0].n), 1);
    n = web_rollup_fine(&ru, WM_BLE_CLASS_ADVERTISERS, "b:wear", T - 20, T + 20, 1, p, 4, &more);
    WT_EQ(n, 1);
    WT_ASSERT(!web_rollup_has(&ru, WM_BLE_CLASS_ADVERTISERS, "b:iot"));   /* 60 s ago */
    WT_ASSERT(!web_rollup_has(&ru, WM_BLE_CLASS_ADVERTISERS, "b:tag"));
    rec_down();
}

/* An anonymous ble_device line (Address_Type 0xFF: an extended
 * advertisement with no AdvA), as sloth writes it: the address zeroed,
 * addr_type 255, one row per sensor for every anonymous advertiser it
 * hears. Only the host stream writes one: an Ubertooth row's addr_type
 * is the PDU's TxAdd, 0 or 1 (src/btle_ll.c), and sloth's HCI rows are
 * all iface bluetooth-monitor and sampled 0. The fields are the row's,
 * as src/ble_hci.c observe_locked() keeps them: the first mfr pair for
 * good, the Appearance its last, the HID bits OR-ed, so a caller passes
 * what the row has accumulated, never a changed mfr pair. */
static void anonym(long long adv, long long first, long long last, int mfr, int sub,
                   int app, int hid, int rssi) {
    char l[768];
    snprintf(l, sizeof(l),
             "{\"type\":\"ble_device\",\"ts\":%lld,\"addr\":\"00:00:00:00:00:00\",\"addr_type\":255,"
             "\"sensor\":\"ble\",\"iface\":\"bluetooth-monitor\",\"adapter\":0,\"sampled\":0,\"channel\":-1,"
             "\"last_pdu\":\"ADV_EXT_IND\",\"pdu_mask\":1,\"name\":\"\",\"name_complete\":0,"
             "\"uuid16\":-1,\"mfr_id\":%d,\"mfr_subtype\":%d,\"svc_data_uuid16\":-1,"
             "\"appearance\":%d,\"hid\":%d,\"tx_power\":-128,\"flags\":-1,\"has_rssi\":1,"
             "\"rssi\":%d,\"rssi_best\":%d,\"adv_count\":%lld,\"watch_category\":\"\","
             "\"ext_adv\":1,\"primary_phy\":1,\"secondary_phy\":1,\"adv_sid\":3,"
             "\"first_seen\":%lld,\"last_seen\":%lld}",
             g_now, mfr, sub, app, hid, rssi, rssi, adv, first, last);
    line(l);
}

/* The distinct transmitters and the frames of chan's rows in the last
 * ring() read, and of those the anonymous entry's. */
static int g_tx_n, g_tx_frames, g_anon_frames, g_anon_n;
static void mix_of(const char *chan) {
    uint8_t seen[64][7];
    g_tx_n = g_tx_frames = g_anon_frames = g_anon_n = 0;
    for (int i = 0; i < g_nrows && i < 64; i++) {
        if (strcmp(g_rows[i].chan, chan)) continue;
        g_tx_frames += (int)g_rows[i].other;
        for (int k = 0; k < g_rows[i].n; k++) {
            const web_mix_tx_t *x = &g_rows[i].tx[k];
            g_tx_frames += (int)x->frames;
            if (x->kind == WEB_TX_BLE_ANON) g_anon_frames += (int)x->frames;
            int dup = 0;
            for (int s = 0; s < g_tx_n && !dup; s++)
                dup = !memcmp(seen[s], x->mac, 6) && seen[s][6] == x->kind;
            if (dup || g_tx_n >= 64) continue;
            memcpy(seen[g_tx_n], x->mac, 6);
            seen[g_tx_n][6] = x->kind;
            g_tx_n++;
            if (x->kind == WEB_TX_BLE_ANON) g_anon_n++;
        }
    }
}

static double fine_sum(int metric, const char *key, long long from, long long to,
                       double *mean) {
    web_point_t p[8];
    int more = 0;
    int n = web_rollup_fine(&ru, metric, key, from, to, 1, p, 8, &more);
    double s = 0;
    unsigned long c = 0;
    for (int i = 0; i < n; i++) { s += p[i].sum; c += p[i].n; }
    if (mean) *mean = c ? s / (double)c : -1;
    return s;
}

/* Anonymous advertising is Unknown's, whatever its row's fields read
 * as (2026-11-03), and a class row's three numbers name one set:
 * ble.class.advertisers, the distinct transmitters drawn in its mix
 * cells, and ble.class.adv against the frames drawn. The one anonymous
 * row sloth can send (the host stream's) starts with Apple Nearby Info,
 * which alone is Phones, and then a report carrying a keyboard
 * Appearance ORs in sloth's HID bit, which alone is Input: the mfr pair
 * stays the first one, as src/ble_hci.c keeps it. Both reports go to
 * Unknown's one anonymous entry and its ble.class.adv, it is one
 * advertiser there, and neither Phones nor Input holds any of it. A
 * named advertiser heard by the Ubertooth too (sampled 1, addr_type 1,
 * as sloth writes every Ubertooth row) is one advertiser and its
 * samples are not credited. No signal series is keyed by the zero
 * address. Seen red four times: with the addr_type test removed from
 * web_ble_class_of_rec() (the anonymous 30 drawn in Phones and 5 in
 * Input, Unknown's advertiser not drawn: 1 against 0), with it removed
 * from web_ble_dev_class() (Unknown's advertisers absent, Input's 1
 * against nothing drawn), with web_chmix_add() refusing
 * WEB_TX_BLE_ANON (Unknown's 35 reports, 0 drawn) and with the
 * anonymous credit dropped from web_metrics.c (Unknown 1 advertiser,
 * no reports). */
/* Anonymous advertising and a real row whose AdvA is literally all
 * zeros (an Ubertooth copies AdvA as heard; a spoofer can send it) are
 * two advertisers in Unknown, whichever comes first. Seen red with the
 * anonymous row counted through the address set again (Unknown read 1). */
static void test_anonymous_and_zero_address_both_counted(void) {
    rec_up();
    g_now = T;
    dev("00:00:00:00:00:00", "ubertooth", 0, 4, T - 60, T, -1, -1, -70);
    anonym(10, T - 60, T, -1, -1, -1, 0, -50);
    int counts[WEB_BC_COUNT];
    int n = web_ble_class_counts(&bt, T - 100, counts);
    WT_EQ(n, 2);
    WT_EQ(counts[WEB_BC_UNK], 2);
    rec_down();
}

static void test_anonymous_counts_agree(void) {
    rec_up();
    g_now = T;
    char ifl[256];
    snprintf(ifl, sizeof(ifl), "{\"type\":\"iface\",\"ts\":%lld,\"name\":\"wlan0\"}", T);
    line(ifl);
    const char *A = "c2:00:00:00:00:61", *B = "c2:00:00:00:00:62";
    dev(A, "bluetooth-monitor", 0, 100, T - 900, T, 0x004C, 0x10, -60);   /* baselines */
    dev(A, "ubertooth", 1, 3, T - 900, T, 0x004C, 0x10, -72);
    dev(B, "bluetooth-monitor", 0, 50, T - 900, T, 0x004C, 0x07, -55);
    anonym(300, T - 900, T, 0x004C, 0x10, -1, 0, -50);
    g_now = T + 10;
    dev(A, "bluetooth-monitor", 0, 112, T - 900, T + 10, 0x004C, 0x10, -60);   /* +12 */
    dev(A, "ubertooth", 1, 9, T - 900, T + 10, 0x004C, 0x10, -72);            /* sampled */
    dev(B, "bluetooth-monitor", 0, 59, T - 900, T + 10, 0x004C, 0x07, -55);    /* +9 */
    anonym(330, T - 900, T + 10, 0x004C, 0x10, -1, 0, -50);                    /* +30 */
    /* A keyboard among the anonymous advertisers: Appearance 0x03C1 and
     * sloth's HID bit (BLE_HID_APPEARANCE), the first mfr pair kept. */
    anonym(335, T - 900, T + 10, 0x004C, 0x10, 0x03C1, 1, -48);                /* +5 */
    snprintf(ifl, sizeof(ifl), "{\"type\":\"iface\",\"ts\":%lld,\"name\":\"wlan0\"}", T + 10);
    line(ifl);
    web_chmix_close_all(&bm);
    ring(&bm, T - 100, T + 100);
    double adv_mean;
    /* Unknown: the anonymous entry alone, every anonymous report. */
    mix_of("b:unk");
    WT_EQ(g_tx_n, 1);
    WT_EQ(g_anon_n, 1);
    WT_EQ(g_anon_frames, 30 + 5);
    WT_EQ(g_tx_frames, 30 + 5);
    WT_EQ((long long)fine_sum(WM_BLE_CLASS_ADV, "b:unk", T - 100, T + 100, NULL), g_tx_frames);
    fine_sum(WM_BLE_CLASS_ADVERTISERS, "b:unk", T - 100, T + 100, &adv_mean);
    WT_EQ((long long)adv_mean, g_tx_n);
    /* Phones: A alone, once for its two sensors, its samples uncredited. */
    mix_of("b:phone");
    WT_EQ(g_tx_n, 1);
    WT_EQ(g_anon_n, 0);
    WT_EQ(g_tx_frames, 12);
    WT_EQ((long long)fine_sum(WM_BLE_CLASS_ADV, "b:phone", T - 100, T + 100, NULL), g_tx_frames);
    fine_sum(WM_BLE_CLASS_ADVERTISERS, "b:phone", T - 100, T + 100, &adv_mean);
    WT_EQ((long long)adv_mean, g_tx_n);
    /* Wearables: B alone. */
    mix_of("b:wear");
    WT_EQ(g_tx_n, 1);
    WT_EQ(g_anon_n, 0);
    WT_EQ(g_tx_frames, 9);
    WT_EQ((long long)fine_sum(WM_BLE_CLASS_ADV, "b:wear", T - 100, T + 100, NULL), g_tx_frames);
    fine_sum(WM_BLE_CLASS_ADVERTISERS, "b:wear", T - 100, T + 100, &adv_mean);
    WT_EQ((long long)adv_mean, g_tx_n);
    /* Input: nothing, though the anonymous row's fields now read as it. */
    mix_of("b:hid");
    WT_EQ(g_tx_n, 0);
    WT_ASSERT(!web_rollup_has(&ru, WM_BLE_CLASS_ADV, "b:hid"));
    WT_ASSERT(!web_rollup_has(&ru, WM_BLE_CLASS_ADVERTISERS, "b:hid"));
    /* No series under the zero address, which no key can be. */
    WT_ASSERT(!web_rollup_has(&ru, WM_RF_RSSI_BLE, "00:00:00:00:00:00"));
    WT_ASSERT(web_rollup_has(&ru, WM_RF_RSSI_BLE, A));
    rec_down();
}

/* The adv_count marks are a high-water table of their own: a flood of
 * fresh BLE addresses (one id each, as a spam tool rotating its address
 * makes) churns only BLE's marks. A Wi-Fi row filled into the shared
 * table, its next record after five thousand fresh advertisers, still
 * reads its true delta. Seen red with the BLE ids put back into the
 * shared table (the probe client's +3 read nothing: evicted, its next
 * total was a baseline). */
static void test_ble_flood_keeps_the_shared_marks(void) {
    rec_up();
    g_now = T - 100;
    char b[256];
    snprintf(b, sizeof(b), "{\"type\":\"probe_client\",\"ts\":%lld,\"mac\":"
             "\"02:00:00:ff:ff:ff\",\"first_seen\":%lld,\"last_seen\":%lld,"
             "\"frame_count\":5}", T, T, T);
    line(b);
    for (int i = 0; i < WEB_HW_ROWS - 1; i++) {
        snprintf(b, sizeof(b), "{\"type\":\"probe_client\",\"ts\":%lld,\"mac\":"
                 "\"02:00:00:%02x:%02x:%02x\",\"first_seen\":%lld,\"last_seen\":%lld,"
                 "\"frame_count\":1}", T, (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff,
                 T, T);
        if (web_jl_parse(b, strlen(b), &rec) == WEB_JL_OK) web_metrics_record(&mx, &rec);
    }
    WT_EQ(mx.hw.n, WEB_HW_ROWS);
    char a[32];
    for (int i = 0; i < 5000; i++) {
        snprintf(a, sizeof(a), "c2:00:00:%02x:%02x:%02x", (i >> 16) & 0xff,
                 (i >> 8) & 0xff, i & 0xff);
        dev(a, "bluetooth-monitor", 0, 3, T + 1, T + 1, 0x004C, 0x10, -60);
    }
    WT_EQ(mx.blehw.n, WEB_BLE_HW_ROWS);
    WT_EQ(mx.hw.n, WEB_HW_ROWS);
    g_now = T + 50;
    snprintf(b, sizeof(b), "{\"type\":\"probe_client\",\"ts\":%lld,\"mac\":"
             "\"02:00:00:ff:ff:ff\",\"first_seen\":%lld,\"last_seen\":%lld,"
             "\"frame_count\":8}", T + 50, T, T + 50);
    line(b);
    web_point_t p[4];
    int more = 0;
    long long b0 = g_now - g_now % WEB_FINE_S;
    int n = web_rollup_fine(&ru, WM_DEV_FRAMES, "02:00:00:ff:ff:ff", b0, b0 + WEB_FINE_S,
                            1, p, 4, &more);
    WT_EQ(n, 1);
    if (n == 1) WT_ASSERT(p[0].sum == 3);
    rec_down();
}

/* ── the routes ───────────────────────────────────────────────────── */

static web_tsdb_t   ts;
static web_m4_t     m4;
static web_health_t H;

static void route_up(int store_on) {
    rec_up();
    WT_EQ(web_tsdb_init(&ts, &ru, NULL, 30, 256, NULL, NULL), 0);
    (void)store_on;
    web_tsdb_set_blemix(&ts, &bm);
    memset(&m4, 0, sizeof(m4));
    m4.tsdb = &ts;
    memset(&H, 0, sizeof(H));
    H.wall_s = T;
    H.tsdb = &ts;
    H.m4 = &m4;
    H.ble = &bt;
}

static void route_down(void) {
    web_tsdb_destroy(&ts);
    rec_down();
}

static void named(const char *addr, const char *name, int app, const char *cat, int rssi,
                  long long last) {
    char l[768];
    snprintf(l, sizeof(l),
             "{\"type\":\"ble_device\",\"ts\":%lld,\"addr\":\"%s\",\"addr_type\":1,"
             "\"sensor\":\"ble\",\"iface\":\"bluetooth-monitor\",\"sampled\":0,\"channel\":-1,"
             "\"name\":\"%s\",\"uuid16\":-1,\"mfr_id\":-1,\"mfr_subtype\":-1,"
             "\"svc_data_uuid16\":-1,\"appearance\":%d,\"hid\":0,\"has_rssi\":1,\"rssi\":%d,"
             "\"rssi_best\":%d,\"adv_count\":10,\"watch_category\":\"%s\","
             "\"first_seen\":%lld,\"last_seen\":%lld}",
             g_now, addr, name, app, rssi, rssi, cat, last - 600, last);
    line(l);
}

/* The class mix at the fine tier, from the ring: /api/wifi/channels
 * ?mix=1's shape with "rows", in display order whatever the arrival, a
 * BLE advertiser per tx entry named from the BLE tables, an address
 * they no longer hold by its address alone, and the strip's facts.
 * Seen red with ble_mix_key() ranking every class 0 (wear before
 * phone by key). */
static void test_classes_mix_route(void) {
    route_up(0);
    g_now = T;
    named("c2:00:00:00:00:c1", "kettle", 0x0540, "", -70, T);
    named("c2:00:00:00:00:c2", "buds", 0x0941, "", -45, T);
    uint8_t m1[6] = { 0xc2, 0, 0, 0, 0, 0xc2 }, m2[6] = { 0xc2, 0, 0, 0, 0, 0xc1 };
    uint8_t m3[6] = { 0xc2, 0, 0, 0, 0, 0xc9 };
    web_chmix_add(&bm, "b:wear", m1, WEB_TX_BLE, 30, T - 600);
    web_chmix_add(&bm, "b:iot", m2, WEB_TX_BLE, 12, T - 600);
    web_chmix_add(&bm, "b:phone", m3, WEB_TX_BLE, 4, T - 600);
    web_chmix_close_all(&bm);
    char q[160];
    snprintf(q, sizeof(q), "mix=1&from=%lld&to=%lld&cols=12", T - 3600, T);
    WT_EQ(route(&H, "/api/ble/classes", q), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"metric\":\"ble.mix\",\"kind\":\"counter\",\"unit\":\"reports\",\"tier\":\"fine\",");
    WT_HAS(b, "\"source\":\"memory\",\"ring_from\":");
    WT_LACKS(b, "\"db\":");
    WT_HAS(b, "{\"id\":\"c2:00:00:00:00:c2\",\"kind\":\"ble\",\"name\":\"buds\",\"name_np\":false,"
              "\"class\":\"b:wear\",\"addr_type\":1,\"iface\":\"bluetooth-monitor\"}");
    WT_HAS(b, "{\"id\":\"c2:00:00:00:00:c9\",\"kind\":\"ble\",\"name\":null,\"name_np\":false,"
              "\"class\":null,\"addr_type\":null,\"iface\":null}");
    const char *ph = strstr(b, "{\"key\":\"b:phone\",\"label\":\"Phones \\u0026 computers\",\"glyph\":\"P\",\"total\":4,");
    const char *we = strstr(b, "{\"key\":\"b:wear\",\"label\":\"Wearables \\u0026 audio\",\"glyph\":\"W\",\"total\":30,");
    const char *io = strstr(b, "{\"key\":\"b:iot\",");
    if (!(ph && we && io && ph < we && we < io)) fprintf(stderr, "    body: %s\n", b);
    WT_ASSERT(ph && we && io && ph < we && we < io);
    WT_HAS(b, "\"rows\":[");
    WT_LACKS(b, "\"channels\":");
    WT_HAS(b, ",\"now\":{\"window_s\":60,\"advertisers\":2,\"advertisers_more\":false,"
              "\"trackers\":0,\"nearest\":{\"addr\":\"c2:00:00:00:00:c2\",");
    WT_HAS(b, "\"name\":\"buds\",\"name_np\":false,\"class\":\"b:wear\",\"rssi\":-45,\"band\":null,"
              "\"grade\":\"near\",\"ptx\":0,\"ptx_source\":\"assumed\"}");
    /* The answer's words, refused as the WiFi route refuses them. */
    WT_EQ(route(&H, "/api/ble/classes", "mix=2"), 400);
    WT_HAS(body_of(g_out), "bad_mix");
    WT_EQ(route(&H, "/api/ble/classes", "mix=1&metric=adv"), 400);
    WT_HAS(body_of(g_out), "mix_takes_no_metric");
    WT_EQ(route(&H, "/api/ble/classes", "metric=frames"), 400);
    WT_HAS(body_of(g_out), "unknown_metric");
    WT_EQ(route(&H, "/api/ble/classes", "cols=0"), 400);
    WT_EQ(route(&H, "/api/ble/classes", "bogus=1"), 400);
    route_down();
}

/* The series grid: each class with a series in the range in display
 * order, Trackers always (an empty row of nulls), a gauge's mean per
 * cell. Seen red with the always-Trackers branch removed. */
static void test_classes_series_route(void) {
    route_up(0);
    g_now = T;
    web_rollup_add(&ru, WM_BLE_CLASS_ADVERTISERS, "b:hid", 2, T - 300);
    web_rollup_add(&ru, WM_BLE_CLASS_ADVERTISERS, "b:hid", 4, T - 300);
    web_rollup_add(&ru, WM_BLE_CLASS_ADVERTISERS, "b:phone", 3, T - 300);
    web_rollup_add(&ru, WM_BLE_CLASS_ADV, "b:phone", 9, T - 300);
    web_rollup_close_due(&ru, T);
    char q[160];
    snprintf(q, sizeof(q), "from=%lld&to=%lld&cols=6", T - 600, T);
    WT_EQ(route(&H, "/api/ble/classes", q), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"metric\":\"ble.class.advertisers\",\"kind\":\"gauge\",\"unit\":\"advertisers\",");
    const char *ph = strstr(b, "{\"key\":\"b:phone\",\"label\":\"Phones \\u0026 computers\",\"glyph\":\"P\",\"cells\":[");
    const char *tg = strstr(b, "{\"key\":\"b:tag\",\"label\":\"Trackers\",\"glyph\":\"T\",\"cells\":[null,null,null,null,null,null]}");
    const char *hd = strstr(b, "{\"key\":\"b:hid\",\"label\":\"Input\",\"glyph\":\"H\",\"cells\":[null,null,null,3,null,null]}");
    if (!(ph && tg && hd && ph < tg && tg < hd)) fprintf(stderr, "    body: %s\n", b);
    WT_ASSERT(ph && tg && hd && ph < tg && tg < hd);
    WT_HAS(b, "\"total_keys\":3,");
    snprintf(q, sizeof(q), "metric=adv&from=%lld&to=%lld&cols=6", T - 600, T);
    WT_EQ(route(&H, "/api/ble/classes", q), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"metric\":\"ble.class.adv\",\"kind\":\"counter\",\"unit\":\"reports\",");
    WT_HAS(b, "{\"key\":\"b:phone\",\"label\":\"Phones \\u0026 computers\",\"glyph\":\"P\",\"cells\":[null,null,null,9,null,null]}");
    WT_LACKS(b, "b:hid");
    route_down();
}

/* The proximity rows: the advertisers heard in the window, trackers
 * first, then the strongest signal in it, then reports; each cell the
 * mean of its buckets; a row heard before the window absent; n's three
 * values only. Seen red with by_prox() ignoring the tracker term (the
 * tracker at -85 came last) and with the window's from ignored (the
 * old row listed). */
static void test_proximity_route(void) {
    route_up(0);
    g_now = T;
    named("c2:00:00:00:00:d1", "tag", 0x0200, "", -85, T - 30);
    named("c2:00:00:00:00:d2", "phone", 0x0040, "", -45, T - 30);
    named("c2:00:00:00:00:d3", "", -1, "", -70, T - 30);
    named("c2:00:00:00:00:d4", "gone", 0x0040, "", -40, T - 7200);
    web_rollup_add(&ru, WM_RF_RSSI_BLE, "c2:00:00:00:00:d2", -44, T - 300);
    web_rollup_add(&ru, WM_RF_RSSI_BLE, "c2:00:00:00:00:d2", -47, T - 300);
    web_rollup_add(&ru, WM_RF_RSSI_BLE, "c2:00:00:00:00:d1", -85, T - 100);
    web_rollup_add(&ru, WM_RF_RSSI_BLE, "c2:00:00:00:00:d3", -70, T - 100);
    web_rollup_close_due(&ru, T);
    char q[160];
    snprintf(q, sizeof(q), "from=%lld&to=%lld&cols=6&n=12", T - 600, T);
    WT_EQ(route(&H, "/api/ble/proximity", q), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"metric\":\"rf.rssi.ble\",\"unit\":\"dBm\",\"tier\":\"fine\",\"step\":10,");
    WT_HAS(b, "\"n\":12,\"candidates\":3,\"anonymous_heard\":false,\"edges\":[-39.75,-53.11,-67.75,-81.11],\"rows\":[");
    const char *r1 = strstr(b, "{\"addr\":\"c2:00:00:00:00:d1\",");
    const char *r2 = strstr(b, "{\"addr\":\"c2:00:00:00:00:d2\",");
    const char *r3 = strstr(b, "{\"addr\":\"c2:00:00:00:00:d3\",");
    WT_ASSERT(r1 && r2 && r3 && r1 < r2 && r2 < r3);
    WT_LACKS(b, "c2:00:00:00:00:d4");
    WT_HAS(b, "\"name\":\"phone\",\"name_np\":false,\"class\":\"b:phone\",\"best\":-44,\"samples\":2,");
    WT_HAS(b, "\"cells\":[null,null,null,-45.5,null,null]}");
    WT_HAS(b, "\"class\":\"b:tag\",\"best\":-85,");
    WT_HAS(b, "\"shown\":3,\"more\":false,\"read_cut\":false");
    WT_EQ(route(&H, "/api/ble/proximity", "n=13"), 400);
    WT_HAS(body_of(g_out), "bad_n");
    WT_EQ(route(&H, "/api/ble/proximity", "n=48"), 200);
    WT_EQ(route(&H, "/api/ble/proximity", "from=10&to=5"), 400);
    /* Matched before the address branch: neither path reads as one. */
    WT_EQ(route(&H, "/api/ble/proximity", ""), 200);
    WT_LACKS(body_of(g_out), "bad_mac");
    WT_EQ(route(&H, "/api/ble/classes", ""), 200);
    WT_LACKS(body_of(g_out), "bad_mac");
    route_down();
}

/* Anonymous advertising through both routes (2026-11-03): in the class
 * mix it is one tx entry in Unknown, a word for an id and no address,
 * class b:unk and nothing to open, and the page's kind test reads the
 * same word; in the proximity panel it is no row and no candidate
 * (there is no address to key a signal series by) and never the
 * strip's nearest, even at the strongest signal heard, the answer says
 * it was heard, and the strip counts it as one advertiser. Seen red
 * with ble_tx_json()'s anonymous branch removed (the entry was the zero
 * address, kind "ble"), with the kind word changed in bledev.js's
 * isAnon() alone, with web_ble_candidates()'s anonymous skip removed
 * (a row of 00:00:00:00:00:00, two candidates, "anonymous_heard"
 * false, nearest the anonymous row at -40) and with now_json() counting
 * the candidates alone (advertisers 1). */
static void test_anonymous_routes(void) {
    route_up(0);
    g_now = T;
    named("c2:00:00:00:00:71", "watch", 0x00C0, "", -60, T - 5);
    anonym(10, T - 600, T - 5, 0x004C, 0x10, -1, 0, -40);
    uint8_t z[6] = { 0, 0, 0, 0, 0, 0 }, w[6] = { 0xc2, 0, 0, 0, 0, 0x71 };
    web_chmix_add(&bm, "b:unk", z, WEB_TX_BLE_ANON, 9, T - 600);
    web_chmix_add(&bm, "b:wear", w, WEB_TX_BLE, 6, T - 600);
    web_chmix_close_all(&bm);
    char q[160];
    snprintf(q, sizeof(q), "mix=1&from=%lld&to=%lld&cols=12", T - 3600, T);
    WT_EQ(route(&H, "/api/ble/classes", q), 200);
    const char *b = body_of(g_out);
    const char *an = strstr(b, "{\"id\":\"anonymous\",\"kind\":\"anon\",\"name\":null,\"name_np\":false,"
                               "\"class\":\"b:unk\",\"addr_type\":255,\"iface\":null}");
    WT_ASSERT(an != NULL);
    if (an) WT_ASSERT(strstr(an + 8, "\"id\":\"anonymous\"") == NULL);   /* one entry */
    WT_LACKS(b, "\"id\":\"00:00:00:00:00:00\"");
    WT_HAS(b, "{\"key\":\"b:unk\",\"label\":\"Unknown\",\"glyph\":\"?\",\"total\":9,");
    WT_HAS(b, "{\"key\":\"b:wear\",\"label\":\"Wearables \\u0026 audio\",\"glyph\":\"W\",\"total\":6,");
    /* The page tells the entry apart by the word this answer serves. */
    const char *kw = an ? strstr(an, "\"kind\":\"") : NULL;
    WT_ASSERT(kw != NULL);
    if (kw) {
        kw += 8;
        const char *ke = strchr(kw, '"');
        WT_ASSERT(ke != NULL && ke - kw < 16);
        if (ke && ke - kw < 16) {
            char js[96];
            snprintf(js, sizeof(js), "  function isAnon(t) { return !!t && t.kind === \"%.*s\"; }",
                     (int)(ke - kw), kw);
            WT_HAS((const char *)web_page, js);
        }
    }
    web_rollup_add(&ru, WM_RF_RSSI_BLE, "c2:00:00:00:00:71", -60, T - 100);
    web_rollup_close_due(&ru, T);
    snprintf(q, sizeof(q), "from=%lld&to=%lld&cols=6&n=12", T - 600, T);
    WT_EQ(route(&H, "/api/ble/proximity", q), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"candidates\":1,\"anonymous_heard\":true,");
    WT_HAS(b, "\"rows\":[{\"addr\":\"c2:00:00:00:00:71\",");
    WT_LACKS(b, "{\"addr\":\"00:00:00:00:00:00\"");
    WT_HAS(b, "\"shown\":1,\"more\":false,");
    WT_HAS(b, "\"nearest\":{\"addr\":\"c2:00:00:00:00:71\",");
    /* The strip still counts it: one advertiser of the two heard. */
    WT_HAS(b, "\"now\":{\"window_s\":60,\"advertisers\":2,");
    route_down();
    /* Without it, the answer says none was left out. */
    route_up(0);
    g_now = T;
    named("c2:00:00:00:00:72", "watch", 0x00C0, "", -60, T - 5);
    WT_EQ(route(&H, "/api/ble/proximity", q), 200);
    WT_HAS(body_of(g_out), "\"candidates\":1,\"anonymous_heard\":false,");
    route_down();
}

/* The candidates are every tracker in the window first, whatever its
 * age, then the newest: three hundred newer addresses (rotated phones)
 * do not push a tracker heard 50 minutes ago out of the 256 read, and
 * the note's cut is said. Anonymous advertising, the newest row of all,
 * takes none of the 256: "candidates" is the 256 addresses read, the
 * number the note says, and the answer says it was heard. Seen red
 * with the tracker pass removed from web_ble_candidates() (the
 * Tile-class row was not a candidate), and with the anonymous skip
 * moved out of web_ble_candidates() to a filter after it, as this
 * view's first cut had it ("candidates":255). */
static void test_proximity_keeps_old_trackers(void) {
    route_up(0);
    g_now = T;
    named("c2:00:00:00:0f:01", "tile", 0x0200, "", -80, T - 3000);
    char a[32];
    for (int i = 0; i < 300; i++) {
        snprintf(a, sizeof(a), "c2:00:00:00:%02x:%02x", 0x10 + (i >> 8), i & 0xff);
        named(a, "", 0x0040, "", -60, T - 100 + i % 50);
    }
    anonym(40, T - 600, T - 1, 0x004C, 0x10, -1, 0, -50);
    char q[160];
    snprintf(q, sizeof(q), "from=%lld&to=%lld&cols=6&n=12", T - 3600, T);
    WT_EQ(route(&H, "/api/ble/proximity", q), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"candidates\":256,\"anonymous_heard\":true,");
    WT_LACKS(b, "{\"addr\":\"00:00:00:00:00:00\"");
    WT_HAS(b, "\"rows\":[{\"addr\":\"c2:00:00:00:0f:01\",");
    WT_HAS(b, "\"read_cut\":true");
    route_down();
}

/* A ble_device line with the two power fields. */
static void powered(const char *addr, int tx, int ext, int rssi, long long last) {
    char l[768];
    snprintf(l, sizeof(l),
             "{\"type\":\"ble_device\",\"ts\":%lld,\"addr\":\"%s\",\"addr_type\":1,"
             "\"sensor\":\"ble\",\"iface\":\"bluetooth-monitor\",\"sampled\":0,\"channel\":-1,"
             "\"name\":\"\",\"uuid16\":-1,\"mfr_id\":-1,\"mfr_subtype\":-1,"
             "\"svc_data_uuid16\":-1,\"appearance\":-1,\"hid\":0,\"tx_power\":%d,"
             "\"ext_tx_power\":%d,\"has_rssi\":1,\"rssi\":%d,\"rssi_best\":%d,"
             "\"adv_count\":10,\"watch_category\":\"\",\"first_seen\":%lld,\"last_seen\":%lld}",
             g_now, addr, tx, ext, rssi, rssi, last - 600, last);
    line(l);
}

/* An advertiser that announces its power is graded with it, in
 * rf_ctx_ble()'s order (extended header, else TX Power Level AD, else
 * 0 dBm), so the cell and the dist column name one band: TX Power
 * Level 10 dBm at -60 is about 12 m, building, not room. Its row
 * carries that P_tx and its edges; "nearest" ranks by the reading less
 * P_tx, so a 0 dBm advertiser at -65 is nearer than a 10 dBm one at
 * -60. Seen red with web_ble_dev_ptx() answering 0 dBm always (the row
 * said ptx 0 and edges -39.75.., and nearest was the 10 dBm one). */
static void test_grade_uses_announced_power(void) {
    route_up(0);
    g_now = T;
    powered("c2:00:00:00:00:f1", 10, -128, -60, T - 5);
    powered("c2:00:00:00:00:f2", -128, -128, -65, T - 5);
    powered("c2:00:00:00:00:f3", 4, 20, -70, T - 5);
    web_rollup_add(&ru, WM_RF_RSSI_BLE, "c2:00:00:00:00:f1", -60, T - 100);
    web_rollup_add(&ru, WM_RF_RSSI_BLE, "c2:00:00:00:00:f2", -65, T - 100);
    web_rollup_add(&ru, WM_RF_RSSI_BLE, "c2:00:00:00:00:f3", -70, T - 100);
    web_rollup_close_due(&ru, T);
    WT_EQ(web_ble_prox_band_at(-60, 10), WEB_BLE_BAND_BUILDING);
    WT_EQ(web_ble_prox_band(-60), WEB_BLE_BAND_ROOM);
    char q[160];
    snprintf(q, sizeof(q), "from=%lld&to=%lld&cols=6&n=12", T - 600, T);
    WT_EQ(route(&H, "/api/ble/proximity", q), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"edges\":[-39.75,-53.11,-67.75,-81.11],\"rows\":[");
    WT_HAS(b, "\"ptx\":10,\"ptx_source\":\"ble_ad_tx_power\",\"edges\":[-29.75,-43.11,-57.75,-71.11],");
    WT_HAS(b, "\"ptx\":0,\"ptx_source\":\"assumed\",\"edges\":[-39.75,-53.11,-67.75,-81.11],");
    WT_HAS(b, "\"ptx\":20,\"ptx_source\":\"ble_ext_tx_power\",\"edges\":[-19.75,-33.11,-47.75,-61.11],");
    /* Nearest by margin: f2 (-65 - 0) before f1 (-60 - 10) and f3. */
    const char *r1 = strstr(b, "{\"addr\":\"c2:00:00:00:00:f2\",");
    const char *r2 = strstr(b, "{\"addr\":\"c2:00:00:00:00:f1\",");
    const char *r3 = strstr(b, "{\"addr\":\"c2:00:00:00:00:f3\",");
    WT_ASSERT(r1 && r2 && r3 && r1 < r2 && r2 < r3);
    WT_HAS(b, "\"nearest\":{\"addr\":\"c2:00:00:00:00:f2\",");
    /* The drawer's row carries the same P_tx. */
    WT_EQ(route(&H, "/api/ble", ""), 200);
    WT_HAS(body_of(g_out), "\"ext_tx_power\":20,\"grade_ptx\":20,\"grade_ptx_source\":\"ble_ext_tx_power\"");
    WT_HAS(body_of(g_out), "\"ext_tx_power\":null,\"grade_ptx\":10,\"grade_ptx_source\":\"ble_ad_tx_power\"");
    route_down();
}

/* "now".sensor: which BLE receivers sloth's latest sensor_health
 * names, so the page can tell "no sensor" from a listening one that
 * heard nothing, and --bt-capture alone (whose one-channel samples the
 * class mix does not credit) from the host stream. Before any
 * sensor_health, seen false. Seen red with the sensor member removed
 * from now_json(). */
static void test_now_names_the_sensor(void) {
    route_up(0);
    g_now = T;
    WT_EQ(route(&H, "/api/ble/proximity", ""), 200);
    WT_HAS(body_of(g_out), "\"sensor\":{\"seen\":false,\"btmon_iface\":\"\",\"btcap_iface\":\"\"}}");
    char l[256];
    snprintf(l, sizeof(l), "{\"type\":\"sensor_health\",\"ts\":%lld,\"btmon_iface\":\"\","
             "\"btcap_iface\":\"\"}", T);
    line(l);
    WT_EQ(route(&H, "/api/ble/classes", ""), 200);
    WT_HAS(body_of(g_out), "\"sensor\":{\"seen\":true,\"btmon_iface\":\"\",\"btcap_iface\":\"\"}}");
    snprintf(l, sizeof(l), "{\"type\":\"sensor_health\",\"ts\":%lld,\"btmon_iface\":\"\","
             "\"btcap_iface\":\"ubertooth0\"}", T + 1);
    line(l);
    WT_EQ(route(&H, "/api/ble/classes", "mix=1"), 200);
    WT_HAS(body_of(g_out), "\"sensor\":{\"seen\":true,\"btmon_iface\":\"\",\"btcap_iface\":\"ubertooth0\"}}");
    route_down();
}

/* With no time series both routes answer 503 no_time_series, in either
 * scope: the grid's bounds need the tiers, so the check comes before
 * the Local answer (web/README.md says so). The class mix with no mix
 * wired is 503 no_ble_mix. */
static void test_routes_without_time_series(void) {
    route_up(0);
    g_now = T;
    const web_m4_t *keep = H.m4;
    web_m4_t bare;
    memset(&bare, 0, sizeof(bare));
    H.m4 = &bare;
    WT_EQ(route(&H, "/api/ble/classes", ""), 503);
    WT_HAS(body_of(g_out), "\"error\":\"no_time_series\"");
    WT_EQ(route(&H, "/api/ble/proximity", ""), 503);
    WT_HAS(body_of(g_out), "\"error\":\"no_time_series\"");
    WT_EQ(route(&H, "/api/ble/classes", "scope=local"), 503);
    WT_HAS(body_of(g_out), "\"error\":\"no_time_series\"");
    WT_EQ(route(&H, "/api/ble/proximity", "scope=local"), 503);
    WT_HAS(body_of(g_out), "\"error\":\"no_time_series\"");
    H.m4 = keep;
    web_tsdb_set_blemix(&ts, NULL);
    WT_EQ(route(&H, "/api/ble/classes", "mix=1"), 503);
    WT_HAS(body_of(g_out), "\"error\":\"no_ble_mix\"");
    route_down();
}

/* The router's Local answer for both: the query checked first (a 400
 * stays a 400), then out_of_scope with nothing of the tables. Seen red
 * with route_bledev()'s none_here forced 0 (each Local answer carried
 * the held name). */
static void test_routes_local(void) {
    route_up(0);
    g_now = T;
    named("c2:00:00:00:00:e1", "held-kettle", 0x0540, "", -60, T);
    WT_EQ(route(&H, "/api/ble/proximity", "scope=local"), 200);
    WT_HAS(body_of(g_out), "\"out_of_scope\":true");
    WT_LACKS(body_of(g_out), "held-kettle");
    WT_EQ(route(&H, "/api/ble/proximity", "scope=local&n=7"), 400);
    WT_EQ(route(&H, "/api/ble/classes", "scope=local&mix=1"), 200);
    WT_HAS(body_of(g_out), "\"out_of_scope\":true");
    WT_EQ(route(&H, "/api/ble/classes", "scope=monitor"), 200);
    WT_HAS(body_of(g_out), "held-kettle");
    /* A query past the router's bound is its 400, as every route's. */
    web_req_t rq;
    web_resp_t rr;
    memset(&rq, 0, sizeof(rq));
    snprintf(rq.path, sizeof(rq.path), "/api/ble/proximity");
    snprintf(rq.host, sizeof(rq.host), "127.0.0.1:8770");
    rq.host_count = 1;
    rq.query_long = 1;
    WT_EQ(web_route(&rq, &H, 1, g_out, sizeof(g_out), &rr), 0);
    g_out[rr.out_len] = '\0';
    WT_EQ(rr.status, 400);
    WT_HAS(body_of(g_out), "query_too_long");
    route_down();
}

#ifdef WITH_SQLITE

static char g_dir[TEST_TMP_MAX];

static long long raw_q(const char *path, const char *sql) {
    sqlite3 *h = NULL;
    long long v = -1;
    if (sqlite3_open(path, &h) == SQLITE_OK) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK &&
            sqlite3_step(st) == SQLITE_ROW)
            v = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    sqlite3_close(h);
    return v;
}

static int g_seen_wifi, g_seen_ble;

static int ns_seen(void *ctx, const char *chan, long long t, const char *tx, int kind,
                   long long frames) {
    (void)ctx; (void)t; (void)tx; (void)kind; (void)frames;
    if (!strncmp(chan, "b:", 2)) g_seen_ble++; else g_seen_wifi++;
    return 0;
}

/* The class mix and the WiFi mix in one chmix table at the same tier
 * and t, one MAC as both an AP and an advertiser: every row survives
 * with its frames (the primary key holds both), each namespace reads
 * only its own, each route draws only its own, and the file stays a v7
 * file that reopens as it was. The anonymous entry (kind 4, the zero
 * address, Unknown's) is a row of its own and is read back and drawn. Seen
 * red with the namespace filter dropped from web_store_mix_query_ns()
 * (the WiFi read saw both "b:" rows; the WiFi route did not draw them,
 * its key check did), and with the BLE route's kinds left at kind 3
 * alone (b:unk's total read 42, the anonymous 8 gone). */
static void test_store_shares_chmix(void) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-bledev-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    char p[160], err[512];
    snprintf(p, sizeof(p), "%s/slothweb.db", g_dir);
    static web_store_t st;
    WT_EQ(web_store_open(&st, p, err, sizeof(err)), 0);
    web_mix_row_t r[2];
    memset(r, 0, sizeof(r));
    const long long t0 = T - 2 * 86400 + 120;
    snprintf(r[0].chan, sizeof(r[0].chan), "6");
    r[0].tier = WEB_TIER_MINUTE;
    r[0].t = t0;
    r[0].n = 1;
    r[0].tx[0].mac[0] = 0x02; r[0].tx[0].mac[5] = 0x01;
    r[0].tx[0].kind = WEB_TX_AP;
    r[0].tx[0].frames = 70;
    r[0].other = 5;
    r[1] = r[0];
    snprintf(r[1].chan, sizeof(r[1].chan), "b:unk");
    r[1].tx[0].kind = WEB_TX_BLE;
    r[1].tx[0].frames = 40;
    /* Anonymous advertising: the zero address, kind 4, in Unknown. */
    r[1].n = 2;
    r[1].tx[1].kind = WEB_TX_BLE_ANON;
    r[1].tx[1].frames = 8;
    r[1].other = 2;
    WT_EQ(web_store_mix_write(&st, r, 2), 0);
    WT_EQ(web_store_mix_count(&st), 5);
    WT_EQ(raw_q(p, "SELECT SUM(frames) FROM chmix WHERE channel='6'"), 75);
    WT_EQ(raw_q(p, "SELECT SUM(frames) FROM chmix WHERE channel='b:unk'"), 50);
    WT_EQ(raw_q(p, "SELECT kind FROM chmix WHERE channel='b:unk' AND tx<>'' AND frames=40"),
          WEB_TX_BLE);
    WT_EQ(raw_q(p, "SELECT frames FROM chmix WHERE channel='b:unk' AND"
                   " tx='00:00:00:00:00:00' AND kind=4"), 8);
    int more = 0;
    g_seen_wifi = g_seen_ble = 0;
    WT_EQ(web_store_mix_query_ns(&st, WEB_MIX_NS_WIFI, WEB_TIER_MINUTE, t0 - 60, t0 + 60, 100,
                                 ns_seen, NULL, &more), 2);
    WT_EQ(g_seen_wifi, 2);
    WT_EQ(g_seen_ble, 0);
    g_seen_wifi = g_seen_ble = 0;
    WT_EQ(web_store_mix_query_ns(&st, WEB_MIX_NS_BLE, WEB_TIER_MINUTE, t0 - 60, t0 + 60, 100,
                                 ns_seen, NULL, &more), 3);
    WT_EQ(g_seen_wifi, 0);
    WT_EQ(g_seen_ble, 3);
    g_seen_wifi = g_seen_ble = 0;
    WT_EQ(web_store_mix_query(&st, WEB_TIER_MINUTE, t0 - 60, t0 + 60, 100, ns_seen, NULL,
                              &more), 2);
    WT_EQ(g_seen_ble, 0);
    WT_ASSERT(web_store_mix_query_ns(&st, 9, WEB_TIER_MINUTE, t0 - 60, t0 + 60, 100, ns_seen,
                                     NULL, &more) < 0);
    /* Through the routes, at the minute tier from the store. */
    route_up(1);
    static web_chmix_t wm;
    WT_EQ(web_chmix_init(&wm, 1), 0);
    web_tsdb_set_mix(&ts, &wm);
    ts.store = &st;
    char q[160];
    snprintf(q, sizeof(q), "mix=1&from=%lld&to=%lld&cols=24", T - 2 * 86400, T - 86400);
    WT_EQ(route(&H, "/api/wifi/channels", q), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"tier\":\"minute\",");
    WT_HAS(b, "{\"key\":\"6\",\"band\":\"2.4\",\"total\":75,");
    WT_LACKS(b, "b:unk");
    WT_EQ(route(&H, "/api/ble/classes", q), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"metric\":\"ble.mix\",");
    WT_HAS(b, "\"source\":\"store\",");
    WT_HAS(b, "{\"key\":\"b:unk\",\"label\":\"Unknown\",\"glyph\":\"?\",\"total\":50,");
    WT_HAS(b, "{\"id\":\"anonymous\",\"kind\":\"anon\",");
    WT_LACKS(b, "{\"key\":\"6\"");
    ts.store = NULL;
    web_chmix_destroy(&wm);
    route_down();
    web_store_close(&st);
    /* Still a current file (v8 since the fleet, #192 F1), and it opens
     * as one. */
    WT_EQ(raw_q(p, "SELECT value FROM meta WHERE name='schema_version'"), WEB_STORE_SCHEMA);
    WT_EQ(WEB_STORE_SCHEMA, 8);
    WT_EQ(web_store_open(&st, p, err, sizeof(err)), 0);
    WT_EQ(web_store_mix_count(&st), 5);
    web_store_close(&st);
    WT_EQ(raw_q(p, "SELECT value FROM meta WHERE name='schema_version'"), WEB_STORE_SCHEMA);
    const char *files[] = { "slothweb.db", "slothweb.db-wal", "slothweb.db-shm" };
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        snprintf(p, sizeof(p), "%s/%s", g_dir, files[i]);
        unlink(p);
    }
    rmdir(g_dir);
}

#endif

void run_bledev_tests(void) {
    WT_RUN(test_each_rule);
    WT_RUN(test_first_match_wins);
    WT_RUN(test_slugs);
    WT_RUN(test_class_of_record);
    WT_RUN(test_proximity_edges);
    WT_RUN(test_page_agrees);
    WT_RUN(test_chmix_ble_kind);
    WT_RUN(test_records_feed_the_class_mix);
    WT_RUN(test_advertisers_gauge);
    WT_RUN(test_anonymous_counts_agree);
    WT_RUN(test_anonymous_and_zero_address_both_counted);
    WT_RUN(test_ble_flood_keeps_the_shared_marks);
    WT_RUN(test_classes_mix_route);
    WT_RUN(test_classes_series_route);
    WT_RUN(test_proximity_route);
    WT_RUN(test_anonymous_routes);
    WT_RUN(test_proximity_keeps_old_trackers);
    WT_RUN(test_grade_uses_announced_power);
    WT_RUN(test_now_names_the_sensor);
    WT_RUN(test_routes_without_time_series);
    WT_RUN(test_routes_local);
#ifdef WITH_SQLITE
    WT_RUN(test_store_shares_chmix);
#endif
}
