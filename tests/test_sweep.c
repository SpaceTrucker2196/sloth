#include "runner.h"
#include "sloth.h"
#include "sweep.h"
#include "wifi_snapshot.h"
#include "camera_vendor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "tmp_dir.h"
#include "frame_build.h"
#include "beacon_snoop.h"
#include "ble_hci.h"
#include "reset_all.h"
#include "fake_platform.h"
#include "wifi_chanhop.h"
#include <errno.h>
#include "jsonl.h"
#include "sweep_run.h"

/* The sweep session (#249). Addresses are locally administered or
 * documentation-like values chosen here; a camera vendor's block is read
 * from the shipped table, never written out. */

TEST_STATE(g_s);
static char g_tmp[TEST_TMP_MAX];

static const char *tmpfile_path(void) {
    g_tmp[0] = '\0';
    int fd = mkstemp(test_tmp_tpl(g_tmp, sizeof(g_tmp), "sloth_sweep_XXXXXX"));
    if (fd >= 0) close(fd);
    return g_tmp;
}

static void seed_ap(sloth_state_t *s, const uint8_t b[6], const char *ssid,
                    const char *enc, int ch, int8_t dbm) {
    beacon_ap_t *a = &s->beacon_aps[s->beacon_count++];
    memset(a, 0, sizeof(*a));
    memcpy(a->bssid, b, 6);
    snprintf(a->ssid, sizeof(a->ssid), "%s", ssid);
    snprintf(a->enc, sizeof(a->enc), "%s", enc);
    a->channel = ch;
    a->signal_dbm = dbm;
    a->first_seen = 1000;
    a->last_seen = 1010;
}

static void seed_probe(sloth_state_t *s, const uint8_t m[6], int ch, int8_t dbm) {
    probe_client_t *p = &s->probe_clients[s->probe_count++];
    memset(p, 0, sizeof(*p));
    memcpy(p->mac, m, 6);
    p->channel = ch;
    p->signal_dbm = dbm;
    p->first_seen = 1000;
    p->last_seen = 1005;
}

static void seed_ble(sloth_state_t *s, const uint8_t a[6], uint8_t type,
                     const char *name, int8_t dbm) {
    ble_device_t *d = &s->ble_devices[s->ble_device_count++];
    memset(d, 0, sizeof(*d));
    memcpy(d->addr, a, 6);
    d->addr_type = type;
    if (name) {
        d->has_name = 1;
        snprintf(d->name, sizeof(d->name), "%s", name);
    }
    d->has_rssi = 1;
    d->rssi = d->rssi_best = dbm;
    d->channel = -1;
    d->first_seen = 1000;
    d->last_seen = 1002;
}

static const uint8_t AP1[6]  = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
static const uint8_t AP2[6]  = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
static const uint8_t CLI[6]  = { 0x00, 0x00, 0x5e, 0x00, 0x53, 0x10 };  /* universal */
static const uint8_t RND[6]  = { 0x52, 0x00, 0x00, 0x00, 0x00, 0x20 };  /* U/L set */
static const uint8_t BPUB[6] = { 0x00, 0x00, 0x5e, 0x00, 0x53, 0x30 };
static const uint8_t BSTA[6] = { 0xC1, 0x22, 0x33, 0x44, 0x55, 0x66 };  /* 11...... */
static const uint8_t BRPA[6] = { 0x41, 0x22, 0x33, 0x44, 0x55, 0x67 };  /* 01...... */
static const uint8_t BNRP[6] = { 0x01, 0x22, 0x33, 0x44, 0x55, 0x68 };  /* 00...... */

/* ── which addresses are kept (owner ruling 2026-11-25) ── */

static void test_ble_kept_types(void) {
    ASSERT_EQ(sweep_ble_kept_type(0, BPUB), SW_BLE_PUBLIC);
    ASSERT_EQ(sweep_ble_kept_type(2, BRPA), SW_BLE_PUBLIC);   /* resolved public identity */
    ASSERT_EQ(sweep_ble_kept_type(1, BSTA), SW_BLE_STATIC);
    ASSERT_EQ(sweep_ble_kept_type(3, BRPA), SW_BLE_STATIC);   /* resolved static identity */
    ASSERT_EQ(sweep_ble_kept_type(1, BRPA), -1);
    ASSERT_EQ(sweep_ble_kept_type(1, BNRP), -1);
    const uint8_t reserved[6] = { 0x81, 0, 0, 0, 0, 1 };      /* 10...... */
    ASSERT_EQ(sweep_ble_kept_type(1, reserved), -1);
    ASSERT_EQ(sweep_ble_kept_type(0xFF, BPUB), -1);           /* anonymous */
}

/* ── inventory ── */

static void test_inventory_kinds_and_counts(void) {
    memset(&g_s, 0, sizeof(g_s));
    seed_ap(&g_s, AP1, "Lobby", "WPA2", 6, -50);
    seed_ap(&g_s, AP2, "", "WPA2", 36, -70);
    seed_probe(&g_s, CLI, 6, -60);
    seed_probe(&g_s, RND, 6, -40);
    seed_ble(&g_s, BPUB, 0, "tag", -55);
    seed_ble(&g_s, BSTA, 1, NULL, -65);
    seed_ble(&g_s, BRPA, 1, "phone", -45);
    seed_ble(&g_s, BNRP, 1, NULL, -75);

    sw_inv_t *inv = sweep_inv_new();
    ASSERT(inv != NULL);
    if (!inv) return;
    sweep_inv_observe(inv, &g_s);
    ASSERT_EQ(inv->per_kind[SW_K_AP], 2);
    ASSERT_EQ(inv->per_kind[SW_K_CLIENT], 1);
    ASSERT_EQ(inv->per_kind[SW_K_BLE], 2);
    ASSERT_EQ(sweep_set_count(&inv->client_random), 1);
    ASSERT_EQ(sweep_set_count(&inv->ble_private), 2);
    ASSERT(sweep_inv_find(inv, SW_K_CLIENT, RND, 0) == NULL);
    ASSERT(sweep_inv_find(inv, SW_K_BLE, BRPA, SW_BLE_PUBLIC) == NULL);
    ASSERT(sweep_inv_find(inv, SW_K_BLE, BRPA, SW_BLE_STATIC) == NULL);
    const sw_emitter_t *e = sweep_inv_find(inv, SW_K_AP, AP2, 0);
    ASSERT(e && (e->flags & SW_F_HIDDEN));
    e = sweep_inv_find(inv, SW_K_AP, AP1, 0);
    ASSERT(e && !(e->flags & SW_F_HIDDEN) && e->best_dbm == -50 && e->channel == 6);
    e = sweep_inv_find(inv, SW_K_BLE, BSTA, SW_BLE_STATIC);
    ASSERT(e && e->best_dbm == -65);

    /* The same addresses again are not counted twice. */
    sweep_inv_observe(inv, &g_s);
    ASSERT_EQ(sweep_set_count(&inv->ble_private), 2);
    ASSERT_EQ(inv->per_kind[SW_K_AP], 2);
    sweep_inv_free(inv);
}

/* The state's tables age rows out; the sweep's inventory does not, and
 * keeps the strongest signal. */
static void test_inventory_outlives_the_tables(void) {
    memset(&g_s, 0, sizeof(g_s));
    seed_ap(&g_s, AP1, "Lobby", "WPA2", 6, -70);
    sw_inv_t *inv = sweep_inv_new();
    ASSERT(inv != NULL);
    if (!inv) return;
    sweep_inv_observe(inv, &g_s);
    g_s.beacon_aps[0].signal_dbm = -40;
    sweep_inv_observe(inv, &g_s);
    g_s.beacon_count = 0;                   /* aged out of the table */
    g_s.probe_count = 0;
    sweep_inv_observe(inv, &g_s);
    const sw_emitter_t *e = sweep_inv_find(inv, SW_K_AP, AP1, 0);
    ASSERT(e != NULL);
    if (e) ASSERT_EQ(e->best_dbm, -40);
    sweep_inv_free(inv);
}

/* A camera vendor's own block flags a client; the setup SSID flags an
 * AP as a camera in setup mode, and an open OPEN_SETUP_AP finding on a
 * BSSID flags it as setup mode. */
static void test_inventory_camera_and_setup_flags(void) {
    uint8_t cam[6] = { 0, 0, 0, 0x01, 0x02, 0x03 };
    int found = 0;
    for (int i = 0; i < cam_vendor_oui_count(); i++) {
        if (cam_vendor_oui_mixed_at(i)) continue;
        const char *v, *o;
        cam_vendor_oui_at(i, cam, &v, &o);
        found = 1;
        break;
    }
    ASSERT(found);
    memset(&g_s, 0, sizeof(g_s));
    seed_probe(&g_s, cam, 1, -30);
    seed_ap(&g_s, AP1, "HAP_ABCDEFGH", "WPA2", 1, -35);
    seed_ap(&g_s, AP2, "SETUP-1234", "OPEN", 11, -60);
    alert_t *a = &g_s.alerts[g_s.alert_count++];
    memset(a, 0, sizeof(*a));
    a->type = ALERT_TYPE_OPEN_SETUP_AP;
    snprintf(a->key, sizeof(a->key), "opensetup:02:00:00:00:00:02");

    sw_inv_t *inv = sweep_inv_new();
    ASSERT(inv != NULL);
    if (!inv) return;
    sweep_inv_observe(inv, &g_s);
    const sw_emitter_t *e = sweep_inv_find(inv, SW_K_CLIENT, cam, 0);
    ASSERT(e && (e->flags & SW_F_CAMERA) && e->camera[0]);
    e = sweep_inv_find(inv, SW_K_AP, AP1, 0);
    const char *label = NULL;
    if (cam_setup_ssid("HAP_ABCDEFGH", &label, NULL))
        ASSERT(e && (e->flags & (SW_F_CAMERA | SW_F_SETUP)) == (SW_F_CAMERA | SW_F_SETUP));
    else
        ASSERT(e && !(e->flags & SW_F_SETUP));
    e = sweep_inv_find(inv, SW_K_AP, AP2, 0);
    ASSERT(e && (e->flags & SW_F_SETUP) && !(e->flags & SW_F_CAMERA));
    sweep_inv_free(inv);
}

/* ── the snapshot file, format v2 ── */

static void test_snapshot_v2_round_trip(void) {
    memset(&g_s, 0, sizeof(g_s));
    seed_ap(&g_s, AP1, "Lob\tby", "WPA2", 6, -50);
    seed_probe(&g_s, CLI, 11, -60);
    seed_probe(&g_s, RND, 6, -40);
    seed_ble(&g_s, BPUB, 0, "a\tb\nc", -55);
    seed_ble(&g_s, BSTA, 1, NULL, -65);
    seed_ble(&g_s, BRPA, 1, NULL, -45);
    snprintf(g_s.ble_devices[1].watch_cat, sizeof(g_s.ble_devices[1].watch_cat),
             "tracker");
    const char *p = tmpfile_path();
    ASSERT_EQ(wifi_snapshot_write(&g_s, p, "room 4", 1234), 0);

    sw_inv_t *in = sweep_inv_new();
    ASSERT(in != NULL);
    if (!in) return;
    int ver = 0;
    ASSERT_EQ(wifi_snapshot_read(p, in, &ver), 0);
    ASSERT_EQ(ver, 2);
    ASSERT(in->has_kind[SW_K_AP] && in->has_kind[SW_K_CLIENT] && in->has_kind[SW_K_BLE]);
    ASSERT_EQ(in->per_kind[SW_K_AP], 1);
    ASSERT_EQ(in->per_kind[SW_K_CLIENT], 1);
    ASSERT_EQ(in->per_kind[SW_K_BLE], 2);
    ASSERT_EQ(in->file_client_random, 1);
    ASSERT_EQ(in->file_ble_private, 1);
    const sw_emitter_t *e = sweep_inv_find(in, SW_K_AP, AP1, 0);
    ASSERT(e && !strcmp(e->ssid, "Lob\tby") && e->channel == 6 && !strcmp(e->enc, "WPA2"));
    e = sweep_inv_find(in, SW_K_CLIENT, CLI, 0);
    ASSERT(e && e->channel == 11);
    e = sweep_inv_find(in, SW_K_BLE, BPUB, SW_BLE_PUBLIC);
    ASSERT(e && !strcmp(e->name, "a\tb\nc"));
    e = sweep_inv_find(in, SW_K_BLE, BSTA, SW_BLE_STATIC);
    ASSERT(e && !strcmp(e->cat, "tracker"));

    /* The v1 reader of every earlier sloth, wifi_snapshot_diff(), still
     * reads the APs and nothing else. */
    FILE *nul = fopen("/dev/null", "w");
    ASSERT_EQ(wifi_snapshot_diff(&g_s, p, nul), 0);
    if (nul) fclose(nul);
    sweep_inv_free(in);
    unlink(p);
}

static void write_raw(const char *p, const char *body) {
    FILE *f = fopen(p, "w");
    if (f) { fputs(body, f); fclose(f); }
}

/* A v1 file holds APs only: the reader says so, so a sweep does not
 * call every client and BLE advertiser new against it. */
static void test_snapshot_v1_holds_aps_only(void) {
    const char *p = tmpfile_path();
    write_raw(p, "# sloth-snapshot v1\n# label\t-\n# ts\t1\n# count\t1\n"
                 "02:00:00:00:00:01\tLobby\tWPA2\t6\t-\t2\t-\n");
    sw_inv_t *in = sweep_inv_new();
    ASSERT(in != NULL);
    if (!in) return;
    int ver = 0;
    ASSERT_EQ(wifi_snapshot_read(p, in, &ver), 0);
    ASSERT_EQ(ver, 1);
    ASSERT(in->has_kind[SW_K_AP]);
    ASSERT(!in->has_kind[SW_K_CLIENT]);
    ASSERT(!in->has_kind[SW_K_BLE]);
    ASSERT_EQ(in->per_kind[SW_K_AP], 1);
    ASSERT_EQ(wifi_snapshot_read("/no/such/snapshot", in, &ver), -1);
    sweep_inv_free(in);
    unlink(p);
}

/* Hand-edited rows: a private BLE address is never a row, and a client
 * row with an AP's field count is still not an AP to the diff reader. */
static void test_snapshot_v2_hostile_rows(void) {
    const char *p = tmpfile_path();
    write_raw(p, "# sloth-snapshot v2\n"
                 "ble\t41:22:33:44:55:67\tstatic\t-\t-\n"
                 "ble\tc1:22:33:44:55:66\tstatic\t-\t-\n"
                 "ble\tc1:22:33:44:55:69\trandom\t-\t-\n"
                 "client\t00:00:5e:00:53:10\t6junk\t-\n"
                 "client\t02:00:00:00:00:09\tWPA2\t6\t-\t2\t-\n");
    sw_inv_t *in = sweep_inv_new();
    ASSERT(in != NULL);
    if (!in) return;
    ASSERT_EQ(wifi_snapshot_read(p, in, NULL), 0);
    ASSERT_EQ(in->per_kind[SW_K_BLE], 1);
    ASSERT(sweep_inv_find(in, SW_K_BLE, BSTA, SW_BLE_STATIC) != NULL);
    ASSERT_EQ(in->per_kind[SW_K_CLIENT], 0);
    memset(&g_s, 0, sizeof(g_s));
    FILE *nul = fopen("/dev/null", "w");
    ASSERT_EQ(wifi_snapshot_diff(&g_s, p, nul), 0);
    if (nul) fclose(nul);
    sweep_inv_free(in);
    unlink(p);
}

/* ── compare ── */

static void test_compare_sorts_and_marks(void) {
    sw_inv_t *cur = sweep_inv_new(), *base = sweep_inv_new();
    ASSERT(cur && base);
    if (!cur || !base) { sweep_inv_free(cur); sweep_inv_free(base); return; }
    memset(&g_s, 0, sizeof(g_s));
    seed_ap(&g_s, AP1, "Lobby", "WPA2", 6, -70);
    seed_ble(&g_s, BSTA, 1, NULL, -65);
    sweep_inv_observe(base, &g_s);
    base->has_kind[SW_K_CLIENT] = 1;        /* as a v2 file read back */
    memset(&g_s, 0, sizeof(g_s));
    seed_ap(&g_s, AP1, "Lobby", "WPA3", 11, -40);
    seed_ap(&g_s, AP2, "Other", "WPA2", 1, -80);
    seed_probe(&g_s, CLI, 6, -30);
    sweep_inv_observe(cur, &g_s);

    sw_cmp_t c;
    ASSERT_EQ(sweep_compare(cur, base, &c), 0);
    ASSERT_EQ(c.n, 4);
    /* NEW by signal: the client at -30, then AP2 at -80; KNOWN AP1;
     * MISSING the static advertiser. */
    if (c.n == 4) {
        ASSERT(c.row[0].kind == SW_K_CLIENT && c.row[0].status == SW_ST_NEW);
        ASSERT(c.row[1].kind == SW_K_AP && !memcmp(c.row[1].addr, AP2, 6) &&
               c.row[1].status == SW_ST_NEW);
        ASSERT(c.row[2].status == SW_ST_KNOWN && c.row[2].base_channel == 6 &&
               !strcmp(c.row[2].base_enc, "WPA2") && c.row[2].channel == 11);
        ASSERT(c.row[3].kind == SW_K_BLE && c.row[3].status == SW_ST_MISSING);
    }
    ASSERT_EQ(c.count[SW_K_AP][SW_ST_NEW], 1);
    ASSERT_EQ(c.count[SW_K_AP][SW_ST_KNOWN], 1);
    ASSERT_EQ(c.count[SW_K_BLE][SW_ST_MISSING], 1);
    ASSERT(c.have_base && c.compared[SW_K_BLE]);
    sweep_cmp_free(&c);

    /* A baseline that holds no BLE (v1): nothing is MISSING there and
     * the kind is reported as not compared. */
    base->has_kind[SW_K_BLE] = 0;
    ASSERT_EQ(sweep_compare(cur, base, &c), 0);
    ASSERT_EQ(c.count[SW_K_BLE][SW_ST_MISSING], 0);
    ASSERT(!c.compared[SW_K_BLE]);
    sweep_cmp_free(&c);

    /* No baseline: everything heard is NEW, nothing compared. */
    ASSERT_EQ(sweep_compare(cur, NULL, &c), 0);
    ASSERT_EQ(c.n, 3);
    ASSERT(!c.have_base && !c.compared[SW_K_AP]);
    ASSERT_EQ(c.count[SW_K_AP][SW_ST_NEW], 2);
    sweep_cmp_free(&c);
    sweep_inv_free(cur);
    sweep_inv_free(base);
}

/* ── the acceptance test: two passes of one room ──
 *
 * Built by hand from the layouts the parsers read (no pcap fixture):
 * a beacon per IEEE 802.11-2020 §9.3.3.3 (fixed fields, SSID element,
 * DSSS Parameter Set element 3 for the channel, an RSNE), and an LE
 * Advertising Report per Core v5.4 Vol 4 Part E §7.7.65.2 in a Linux
 * HCI monitor record (opcode 3 EVENT, src/ble_hci.h). Each pass starts
 * from cleared module tables and an empty state. */

static void feed_beacon(const uint8_t bssid[6], const char *ssid, uint8_t ch,
                        int8_t dbm) {
    uint8_t f[128];
    fb_t b;
    fb_init(&b, f, sizeof(f));
    static const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    fb_mgmt(&b, 8, 0, bcast, bssid, bssid, 0, 0);
    fb_beacon_fixed(&b, 0, 100, 0x0011);         /* ESS, Privacy */
    fb_ssid(&b, ssid);
    fb_ie(&b, 3, &ch, 1);
    fb_rsn(&b, 4, 4, 2, 0);                       /* CCMP / CCMP / PSK */
    ASSERT(fb_ok(&b));
    char s_out[33], enc[10];
    uint8_t bss[6];
    int chan = 0;
    uint16_t bms = 0;
    beacon_rsn_t rsn;
    memset(&rsn, 0, sizeof(rsn));
    ASSERT_EQ(beacon_parse(f, b.len, dbm, s_out, bss, &chan, enc, &bms, &rsn), 1);
    ASSERT_EQ(chan, ch);
    beacon_record(bss, s_out, dbm, chan, enc, bms, &rsn);
}

/* `addr` in display order; the report carries it least significant
 * octet first. */
static void feed_adv(const uint8_t addr[6], uint8_t addr_type, int8_t rssi) {
    uint8_t r[64];
    int n = 0;
    r[n++] = 0; r[n++] = 0;                       /* adapter 0 */
    r[n++] = 0; r[n++] = BT_MON_EVENT_PKT;
    const uint8_t ad[3] = { 2, 0x01, 0x06 };      /* Flags */
    r[n++] = 0x3E;                                /* LE Meta */
    r[n++] = (uint8_t)(12 + sizeof(ad));
    r[n++] = 0x02;                                /* Advertising Report */
    r[n++] = 1;                                   /* Num_Reports */
    r[n++] = 0x00;                                /* ADV_IND */
    r[n++] = addr_type;
    for (int i = 0; i < 6; i++) r[n++] = addr[5 - i];
    r[n++] = (uint8_t)sizeof(ad);
    memcpy(r + n, ad, sizeof(ad)); n += (int)sizeof(ad);
    r[n++] = (uint8_t)rssi;
    ASSERT_EQ((int)ble_mon_ingest(r, (size_t)n, (size_t)n, 1700000000, 0),
              (int)BLE_REC_ADV);
}

static void pass_into(sw_inv_t *inv) {
    memset(&g_s, 0, sizeof(g_s));
    beacon_snapshot(&g_s);
    ble_snapshot(&g_s);
    sweep_inv_observe(inv, &g_s);
}

static void test_two_passes_of_one_room(void) {
    static const uint8_t ap_a[6]  = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x01 };
    static const uint8_t ap_b[6]  = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x02 };
    static const uint8_t rpa_a[6] = { 0x4A, 0x01, 0x02, 0x03, 0x04, 0x05 };
    static const uint8_t rpa_b[6] = { 0x5B, 0x06, 0x07, 0x08, 0x09, 0x0A };
    sw_inv_t *a = sweep_inv_new(), *b = sweep_inv_new(), *base = sweep_inv_new();
    ASSERT(a && b && base);
    if (!a || !b || !base) goto out;

    /* Pass A: one AP, one static-address advertiser, one phone on a
     * resolvable private address. */
    feed_beacon(ap_a, "Board", 6, -55);
    feed_adv(BSTA, 1, -60);
    feed_adv(rpa_a, 1, -50);
    pass_into(a);
    const char *p = tmpfile_path();
    ASSERT_EQ(wifi_snapshot_write_inv(a, p, "boardroom", 1000), 0);

    /* Pass B: the same, the phone's address rotated, plus one more AP
     * and one more (public-address) advertiser. */
    sloth_reset_all();
    feed_beacon(ap_a, "Board", 6, -57);
    feed_beacon(ap_b, "Planted", 11, -35);
    feed_adv(BSTA, 1, -61);
    feed_adv(rpa_b, 1, -48);
    feed_adv(BPUB, 0, -40);
    pass_into(b);

    ASSERT_EQ(wifi_snapshot_read(p, base, NULL), 0);
    sw_cmp_t c;
    ASSERT_EQ(sweep_compare(b, base, &c), 0);
    int news = 0, ap_b_new = 0, pub_new = 0;
    for (int i = 0; i < c.n; i++) {
        const sw_emitter_t *e = &c.row[i];
        ASSERT(e->status != SW_ST_MISSING);
        if (e->status != SW_ST_NEW) continue;
        news++;
        if (e->kind == SW_K_AP && !memcmp(e->addr, ap_b, 6)) ap_b_new = 1;
        if (e->kind == SW_K_BLE && !memcmp(e->addr, BPUB, 6)) pub_new = 1;
    }
    ASSERT_EQ(news, 2);
    ASSERT(ap_b_new && pub_new);
    /* The rotated address is a count in both passes, never a row. */
    ASSERT_EQ(c.count[SW_K_BLE][SW_ST_KNOWN], 1);
    ASSERT_EQ(sweep_set_count(&a->ble_private), 1);
    ASSERT_EQ(sweep_set_count(&b->ble_private), 1);
    ASSERT_EQ(base->file_ble_private, 1);
    /* The strongest NEW emitter comes first. */
    if (c.n > 0) ASSERT(c.row[0].kind == SW_K_AP && !memcmp(c.row[0].addr, ap_b, 6));
    sweep_cmp_free(&c);
    unlink(p);
out:
    sweep_inv_free(a);
    sweep_inv_free(b);
    sweep_inv_free(base);
}

/* ── the sweep plan and its coverage ── */

static void test_sweep_plan_is_equal_dwell(void) {
    chanhop_t h;
    ASSERT_EQ(chanhop_init_sweep(&h, 10, 0), 38);
    int n24 = 0, n5 = 0;
    for (int i = 0; i < h.count; i++) {
        n24 += h.slots[i].band == WIFI_BAND_2GHZ;
        n5  += h.slots[i].band == WIFI_BAND_5GHZ;
    }
    ASSERT_EQ(n24, 13);
    ASSERT_EQ(n5, 25);
    ASSERT_EQ(chanhop_sweep_dwell_ms(&h), 600000u / 38u);
    /* Activity, and a cue, move nothing. */
    h.slots[3].activity = 5000;
    chanhop_set_cue(&h, 4, 999999, 0);
    ASSERT_EQ(h.slots[4].cue_until_ms, 0);
    for (int i = 0; i < h.count; i++)
        ASSERT_EQ(chanhop_slot_plan_ms(&h, i), 600000u / 38u);
    /* Too little time for the channels: the floor. A whole minute over
     * 38 channels is above it, so the time is set by hand. */
    ASSERT_EQ(chanhop_init_sweep(&h, 1, 0), 38);
    h.sweep_ms = 10000;
    ASSERT_EQ(chanhop_sweep_dwell_ms(&h), CHANHOP_SWEEP_FLOOR_MS);
    /* Zero minutes is not a sweep. */
    chanhop_init_sweep(&h, 0, 0);
    ASSERT_EQ(chanhop_sweep_dwell_ms(&h), 0u);
    /* A radio's share spreads the whole time over its own channels. */
    chanhop_t full, part;
    chanhop_init_sweep(&full, 10, 0);
    ASSERT_EQ(chanhop_split(&part, &full, 2, 1), 19);
    ASSERT_EQ(chanhop_sweep_dwell_ms(&part), 600000u / 19u);
    /* Not a sweep: the #22 plan, unchanged. */
    chanhop_init_default(&h);
    ASSERT_EQ(chanhop_sweep_dwell_ms(&h), 0u);
}

/* Drive one radio through the fake platform on a synthetic clock, a
 * 50 ms poll, until `stop_ms` or the pass ends; sample the coverage
 * each poll. */
static uint64_t drive(chanhop_t *h, sw_cov_t *c, uint64_t stop_ms) {
    uint64_t t = 0;
    sweep_cov_init(c, h, 0);
    for (; t <= stop_ms && !h->sweep_done; t += 50) {
        int req = 0, err = 0;
        (void)chanhop_step(h, "mon0", t, 2, &req, &err);
        sweep_cov_sample(c, 0, h, t);
    }
    return t;
}

static const sw_cov_ch_t *cov_ch(const sw_cov_t *c, int mhz) {
    for (int i = 0; i < c->n; i++)
        if (c->ch[i].freq_mhz == mhz) return &c->ch[i];
    return NULL;
}

/* One minute over 38 channels: each visited once, an equal time, then
 * the pass ends; channel 6 refused is counted and is not swept. */
static void test_sweep_one_pass_and_a_refusal(void) {
    fake_net_reset();
    g_fake_net.refuse_freq_mhz = 2437;
    g_fake_net.refuse_rc = -EINVAL;
    chanhop_t h;
    chanhop_init_sweep(&h, 1, 0);
    static sw_cov_t c;
    uint64_t end = drive(&h, &c, 10 * 60000);
    ASSERT(h.sweep_done);
    ASSERT(end < 65000);
    uint32_t d = chanhop_sweep_dwell_ms(&h);
    ASSERT_EQ(d, 60000u / 38u);
    for (int i = 0; i < h.count; i++) {
        const sw_cov_ch_t *e = cov_ch(&c, h.slots[i].freq_mhz);
        ASSERT(e != NULL);
        if (!e) continue;
        if (h.slots[i].freq_mhz == 2437) {
            ASSERT_EQ(e->visits, 0u);
            ASSERT_EQ(e->refusals, 1u);
            ASSERT_EQ(e->ms, 0u);
            continue;
        }
        ASSERT_EQ(e->visits, 1u);
        ASSERT_EQ(e->refusals, 0u);
        /* Measured, start of dwell to start of next, on a 50 ms poll:
         * the plan rounded up to the poll, and the refused retune's
         * floor inside the dwell before it. */
        ASSERT(e->ms >= d && e->ms <= d + 50 + h.min_dwell_ms + 50);
    }
    ASSERT_EQ(sweep_cov_swept(&c), 37);
    ASSERT_EQ(c.n, 38);
}

/* Stopped at 40 % of the time: only the channels actually dwelt on are
 * swept, with their measured times, and the rest are listed as not
 * swept. */
static void test_sweep_stopped_early(void) {
    fake_net_reset();
    chanhop_t h;
    chanhop_init_sweep(&h, 10, 0);
    static sw_cov_t c;
    uint64_t stop = 600000u * 4 / 10;
    (void)drive(&h, &c, stop);
    ASSERT(!h.sweep_done);
    uint32_t d = chanhop_sweep_dwell_ms(&h);
    int swept = sweep_cov_swept(&c);
    /* 240 s at 15.789 s a channel: 15 closed dwells and the 16th open. */
    ASSERT_EQ(swept, 16);
    uint64_t total = 0;
    for (int i = 0; i < c.n; i++) {
        const sw_cov_ch_t *e = &c.ch[i];
        total += e->ms;
        if (i < 15) ASSERT(e->ms >= d && e->ms <= d + 50);
        else if (i == 15) ASSERT(e->ms > 0 && e->ms < d);
        else ASSERT(e->ms == 0 && e->visits == 0);
    }
    ASSERT_EQ(total, stop);
    ASSERT_EQ(c.n - swept, 22);
}

/* ── the report ── */

static char *slurp(const char *p) {
    FILE *f = fopen(p, "r");
    if (!f) return NULL;
    static char buf[1 << 17];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

/* A sweep stopped at 40 %: the report names the channels dwelt on with
 * their times and lists the rest as not swept, says which bands were
 * not swept, puts the strong unknown first, and keeps an on-air tab out
 * of the file raw. The JSONL record carries counts and channel numbers,
 * never an address or a name. */
static void test_report_of_a_stopped_sweep(void) {
    fake_net_reset();
    chanhop_t h;
    chanhop_init_sweep(&h, 10, 0);
    static sw_cov_t c;
    (void)drive(&h, &c, 600000u * 4 / 10);

    memset(&g_s, 0, sizeof(g_s));
    seed_ap(&g_s, AP1, "Lob|by\tX", "WPA2", 6, -30);
    seed_ap(&g_s, AP2, "", "WPA2", 36, -70);
    seed_ble(&g_s, BRPA, 1, NULL, -45);
    sw_inv_t *inv = sweep_inv_new();
    ASSERT(inv != NULL);
    if (!inv) return;
    sweep_inv_observe(inv, &g_s);
    sw_cmp_t cmp;
    ASSERT_EQ(sweep_compare(inv, NULL, &cmp), 0);
    sw_report_t r;
    memset(&r, 0, sizeof(r));
    r.label = "board-room";
    r.start = 1764000000;
    r.end = r.start + 240;
    r.minutes = 10;
    r.end_why = SW_END_STOPPED;
    r.cov = &c;
    r.cmp = &cmp;
    r.inv = inv;
    r.mon_up = 1;
    r.candidate_path = "/x/sweep-board-room.20251124T160000Z.tsv";

    const char *p = tmpfile_path();
    FILE *f = fopen(p, "w");
    ASSERT(f != NULL);
    if (f) { sweep_report_md(f, &r); fclose(f); }
    char *t = slurp(p);
    ASSERT(t != NULL);
    if (t) {
        ASSERT(strstr(t, "Channels in the plan: 38; swept: 16; not swept: 22.") != NULL);
        ASSERT(strstr(t, "| 2.4 GHz | 1 | 2412 | 15.8") != NULL);
        ASSERT(strstr(t, "| 5 GHz | 165 | 5825 | 0.000 | 0 | 0 | 0 | not swept: not reached |") != NULL);
        ASSERT(strstr(t, "6 GHz (no 6 GHz channel in the sweep plan") != NULL);
        ASSERT(strstr(t, "sub-GHz") != NULL);
        ASSERT(strstr(t, "Baseline: none accepted") != NULL);
        ASSERT(strstr(t, "stopped before") != NULL);
        ASSERT(strstr(t, "Lob\\|by\\tX") != NULL);
        ASSERT(strstr(t, "\tX") == NULL);
        ASSERT(strstr(t, "1 private BLE address, of which 0 resolved") != NULL);
        ASSERT(strstr(t, "uses a wire") != NULL);
        /* The strong unknown first in the New table. */
        const char *n1 = strstr(t, "02:00:00:00:00:01"), *n2 = strstr(t, "02:00:00:00:00:02");
        ASSERT(n1 && n2 && n1 < n2);
        ASSERT(strstr(t, "| (hidden) | hidden name | new |") != NULL);
        ASSERT(strstr(t, "radiation") == NULL);
    }
    f = fopen(p, "w");
    if (f) { sweep_report_json(f, &r); fclose(f); }
    t = slurp(p);
    ASSERT(t != NULL);
    if (t) {
        ASSERT(strstr(t, "\"end_why\":\"stopped\"") != NULL);
        ASSERT(strstr(t, "\"channels_planned\":38,\"channels_swept\":16") != NULL);
        ASSERT(strstr(t, "\"bands_not_swept\":\"6ghz,sub_ghz\"") != NULL);
        ASSERT(strstr(t, "\"ssid\":\"Lob|by\\u0009X\"") != NULL);
        ASSERT(strstr(t, "\"ap\":{\"compared\":false,\"new\":2") != NULL);
    }

    unlink(p);
    p = tmpfile_path();        /* mkstemp: 0600, as the JSONL sink wants */
    ASSERT(jsonl_open(p));
    sweep_report_emit(&r);
    jsonl_close();
    t = slurp(p);
    ASSERT(t != NULL);
    if (t) {
        ASSERT(strstr(t, "\"type\":\"sweep_report\"") != NULL);
        ASSERT(strstr(t, "\"channels_swept\":16") != NULL);
        ASSERT(strstr(t, "\"not_swept\":\"5:48,5:52,") != NULL);
        ASSERT(strstr(t, "\"ap_new\":2") != NULL);
        ASSERT(strstr(t, "\"ble_private\":1") != NULL);
        ASSERT(strstr(t, "02:00:00") == NULL);
        ASSERT(strstr(t, "Lob") == NULL);
    }
    sweep_cmp_free(&cmp);
    sweep_inv_free(inv);
    unlink(p);
}

/* ── the run: files, the end, and the baseline never written ── */

static void test_label_and_minutes(void) {
    ASSERT(sweep_label_ok("board-room_2.a"));
    ASSERT(!sweep_label_ok(""));
    ASSERT(!sweep_label_ok(".hidden"));
    ASSERT(!sweep_label_ok("-x"));
    ASSERT(!sweep_label_ok("a/b"));
    ASSERT(!sweep_label_ok("a b"));
    ASSERT(!sweep_label_ok("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));  /* 49 */
    unsigned m = 0;
    ASSERT_EQ(sweep_minutes_parse("15", &m), 0);
    ASSERT_EQ(m, 15u);
    ASSERT_EQ(sweep_minutes_parse("0", &m), -1);
    ASSERT_EQ(sweep_minutes_parse("1441", &m), -1);
    ASSERT_EQ(sweep_minutes_parse("5m", &m), -1);
}

static int file_eq(const char *a, const char *b) {
    FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb");
    int eq = fa && fb;
    while (eq) {
        int ca = fgetc(fa), cb = fgetc(fb);
        if (ca != cb) eq = 0;
        if (ca == EOF || cb == EOF) break;
    }
    if (fa) fclose(fa);
    if (fb) fclose(fb);
    return eq;
}

static int copy_file(const char *from, const char *to) {
    FILE *a = fopen(from, "rb"), *b = fopen(to, "wb");
    int ok = a && b;
    int c;
    while (ok && (c = fgetc(a)) != EOF) fputc(c, b);
    if (a) fclose(a);
    if (b) fclose(b);
    return ok;
}

static void test_run_writes_and_never_accepts(void) {
    char dir[TEST_TMP_MAX] = "";
    ASSERT(mkdtemp(test_tmp_tpl(dir, sizeof(dir), "sloth_sweepdir_XXXXXX")) != NULL);
    fake_net_reset();
    FILE *nul = fopen("/dev/null", "w");
    chanhop_t h;
    chanhop_init_sweep(&h, 1, 0);
    chanhop_sweep_quantum(&h, 50);        /* the loop below polls every 50 ms */
    ASSERT_EQ(chanhop_sweep_dwell_ms(&h), 1550u);
    static sweep_run_t r;
    char err[256];
    ASSERT_EQ(sweep_run_begin(&r, "room", 1, dir, NULL, &h, 0, 1764000000, err, sizeof(err)), 0);
    ASSERT(r.base == NULL);
    memset(&g_s, 0, sizeof(g_s));
    seed_ap(&g_s, AP1, "Lobby", "WPA2", 6, -50);
    g_s.mon_health.running = 1;
    /* The run ends when the time given runs out (one minute), or the
     * pass, whichever first; with the dwell rounded to the poll, the
     * pass, 38 x 1.55 s = 58.9 s. Unrounded (1578 ms) every dwell would
     * run to the next poll and the time would end first. */
    int done = 0;
    uint64_t t;
    for (t = 0; t <= 61000 && !done; t += 50) {
        (void)chanhop_step(&h, "mon0", t, 0, NULL, NULL);
        done = sweep_run_tick(&r, &g_s, &h, t);
    }
    ASSERT(done);
    ASSERT_EQ(r.end_why, SW_END_PASS);
    ASSERT_EQ(sweep_run_finish(&r, &g_s, 0, 0, 1764000060, nul), 0);

    char stem[SWEEP_PATH_MAX], path[SWEEP_PATH_MAX + 8], base[SWEEP_PATH_MAX];
    ASSERT_EQ(sweep_record_stem(dir, "room", 1764000000, stem, sizeof(stem)), 0);
    ASSERT_EQ(sweep_baseline_path(dir, "room", base, sizeof(base)), 0);
    snprintf(path, sizeof(path), "%s.md", stem);
    char *t1 = slurp(path);
    ASSERT(t1 && strstr(t1, "Ended: every channel visited once") &&
           strstr(t1, "Baseline: none accepted"));
    snprintf(path, sizeof(path), "%s.json", stem);
    ASSERT(slurp(path) != NULL);
    snprintf(path, sizeof(path), "%s.tsv", stem);
    struct stat st;
    ASSERT_EQ(stat(path, &st), 0);
    ASSERT_EQ((int)(st.st_mode & 0777), 0600);
    /* Nothing accepted it: no baseline was written. */
    ASSERT(stat(base, &st) != 0);

    /* The accept (slothweb's) copies the inventory to the baseline. A
     * second sweep reads it, and a third AP is the one new emitter; the
     * baseline is left byte for byte as it was. */
    ASSERT(copy_file(path, base));
    char keep[SWEEP_PATH_MAX + 8];
    snprintf(keep, sizeof(keep), "%s.keep", base);
    ASSERT(copy_file(base, keep));
    chanhop_init_sweep(&h, 1, 0);
    ASSERT_EQ(sweep_run_begin(&r, "room", 1, dir, NULL, &h, 0, 1764000600, err, sizeof(err)), 0);
    ASSERT(r.base != NULL);
    ASSERT_EQ(r.base_version, 2);
    seed_ap(&g_s, AP2, "Planted", "WPA2", 1, -30);
    (void)sweep_run_tick(&r, &g_s, &h, 50);
    /* Stopped (q) well before the pass. */
    ASSERT_EQ(sweep_run_finish(&r, &g_s, 1, 0, 1764000610, nul), 0);
    ASSERT(file_eq(base, keep));
    ASSERT_EQ(sweep_record_stem(dir, "room", 1764000600, stem, sizeof(stem)), 0);
    snprintf(path, sizeof(path), "%s.md", stem);
    t1 = slurp(path);
    ASSERT(t1 && strstr(t1, "| access points | 1 | 1 | 0 |") &&
           strstr(t1, "stopped before") && strstr(t1, "Planted"));

    /* One sweep never replaces another's record: the same second again
     * is refused, and the first record stays. */
    chanhop_init_sweep(&h, 1, 0);
    ASSERT_EQ(sweep_run_begin(&r, "room", 1, dir, NULL, &h, 0, 1764000600, err, sizeof(err)), 0);
    ASSERT_EQ(sweep_run_finish(&r, &g_s, 1, 0, 1764000620, nul), -1);
    t1 = slurp(path);
    ASSERT(t1 && strstr(t1, "Planted"));

    /* main.c's check before anything opens: present, absent, and (below)
     * there but not a file. */
    ASSERT_EQ(sweep_baseline_check(dir, "room", NULL, err, sizeof(err)), 1);
    ASSERT_EQ(sweep_baseline_check(dir, "other", NULL, err, sizeof(err)), 0);

    /* A baseline that is not a file is refused at the start. */
    unlink(base);
    ASSERT_EQ(mkdir(base, 0700), 0);
    ASSERT_EQ(sweep_baseline_check(dir, "room", NULL, err, sizeof(err)), -1);
    ASSERT(strstr(err, "cannot be read") != NULL);
    ASSERT_EQ(sweep_run_begin(&r, "room", 1, dir, NULL, &h, 0, 1764000900, err, sizeof(err)), -1);
    rmdir(base);
    if (nul) fclose(nul);
    test_rm_tree(dir);
}

/* --sweep-group (owner ruling 2026-11-25): the directory slothweb writes
 * the baseline into is the group's, 2770 or 0770; the outputs are 0640
 * in the group; the baseline slothweb wrote (0640, the group's) is read,
 * and one that is a symlink, has a bit for other, or is a directory is
 * refused. The process's own group stands in for the shared one. */
static void test_run_group_dir(void) {
    char dir[TEST_TMP_MAX] = "";
    ASSERT(mkdtemp(test_tmp_tpl(dir, sizeof(dir), "sloth_sweepgrp_XXXXXX")) != NULL);
    char gname[32];
    snprintf(gname, sizeof(gname), "%lu", (unsigned long)getegid());
    sweep_group_t g;
    char err[320];
    ASSERT_EQ(sweep_group_resolve(gname, &g, err, sizeof(err)), 0);
    ASSERT(g.on && g.gid == getegid());
    sweep_group_t bad;
    ASSERT_EQ(sweep_group_resolve("no-such-sloth-group-x", &bad, err, sizeof(err)), -1);
    ASSERT(strstr(err, "no such group") != NULL);
    ASSERT(!bad.on);

    /* The directory: mkdtemp's 0700 is refused under the group rule and
     * passes without it; 0770 and 2770 pass; 0775 and 2777 do not. */
    ASSERT_EQ(sweep_dir_check(dir, NULL, err, sizeof(err)), 0);
    ASSERT_EQ(sweep_dir_check(dir, &g, err, sizeof(err)), -1);
    ASSERT(strstr(err, "not 2770 or 0770") != NULL);
    ASSERT_EQ(chmod(dir, 0775), 0);
    ASSERT_EQ(sweep_dir_check(dir, &g, err, sizeof(err)), -1);
    ASSERT_EQ(chmod(dir, 02777), 0);
    ASSERT_EQ(sweep_dir_check(dir, &g, err, sizeof(err)), -1);
    ASSERT_EQ(chmod(dir, 0770), 0);
    ASSERT_EQ(sweep_dir_check(dir, &g, err, sizeof(err)), 0);
    ASSERT_EQ(chmod(dir, 02770), 0);
    ASSERT_EQ(sweep_dir_check(dir, &g, err, sizeof(err)), 0);
    /* Another group's directory is not this one. */
    sweep_group_t other = g;
    other.gid = g.gid + 1;
    ASSERT_EQ(sweep_dir_check(dir, &other, err, sizeof(err)), -1);
    ASSERT(strstr(err, "not --sweep-group") != NULL);
    /* A symlink to the right directory is refused, not followed. */
    char lnk[TEST_TMP_MAX + 8];
    snprintf(lnk, sizeof(lnk), "%s.ln", dir);
    ASSERT_EQ(symlink(dir, lnk), 0);
    ASSERT_EQ(sweep_dir_check(lnk, &g, err, sizeof(err)), -1);
    ASSERT(strstr(err, "a symlink") != NULL);
    unlink(lnk);

    /* A run in the group directory: 0640 outputs in the group. */
    fake_net_reset();
    FILE *nul = fopen("/dev/null", "w");
    chanhop_t h;
    chanhop_init_sweep(&h, 1, 0);
    static sweep_run_t r;
    mode_t um = umask(077);       /* the mode is set, not left to the umask */
    ASSERT_EQ(sweep_run_begin(&r, "room", 1, dir, &g, &h, 0, 1764000000, err,
                              sizeof(err)), 0);
    memset(&g_s, 0, sizeof(g_s));
    seed_ap(&g_s, AP1, "Lobby", "WPA2", 6, -50);
    (void)sweep_run_tick(&r, &g_s, &h, 50);
    ASSERT_EQ(sweep_run_finish(&r, &g_s, 1, 0, 1764000060, nul), 0);
    umask(um);
    char stem[SWEEP_PATH_MAX], path[SWEEP_PATH_MAX + 8], base[SWEEP_PATH_MAX];
    ASSERT_EQ(sweep_record_stem(dir, "room", 1764000000, stem, sizeof(stem)), 0);
    ASSERT_EQ(sweep_baseline_path(dir, "room", base, sizeof(base)), 0);
    static const char *const ext[3] = { "tsv", "md", "json" };
    for (int i = 0; i < 3; i++) {
        struct stat st;
        snprintf(path, sizeof(path), "%s.%s", stem, ext[i]);
        ASSERT_EQ(lstat(path, &st), 0);
        ASSERT_EQ((int)(st.st_mode & 07777), 0640);
        ASSERT(st.st_gid == g.gid);
    }

    /* slothweb's accept: the inventory as the baseline, 0640. */
    snprintf(path, sizeof(path), "%s.tsv", stem);
    ASSERT(copy_file(path, base));
    ASSERT_EQ(chmod(base, 0640), 0);
    ASSERT_EQ(sweep_baseline_check(dir, "room", &g, err, sizeof(err)), 1);
    chanhop_init_sweep(&h, 1, 0);
    ASSERT_EQ(sweep_run_begin(&r, "room", 1, dir, &g, &h, 0, 1764000600, err,
                              sizeof(err)), 0);
    ASSERT(r.base != NULL && r.base_version == 2);
    sweep_run_free(&r);
    /* A bit for other: refused. */
    ASSERT_EQ(chmod(base, 0644), 0);
    ASSERT_EQ(sweep_baseline_check(dir, "room", &g, err, sizeof(err)), -1);
    ASSERT(strstr(err, "by other") != NULL);
    /* A symlink to a good file: refused, not followed. */
    char real[SWEEP_PATH_MAX + 8];
    snprintf(real, sizeof(real), "%s.real", base);
    ASSERT_EQ(rename(base, real), 0);
    ASSERT_EQ(chmod(real, 0640), 0);
    ASSERT_EQ(symlink(real, base), 0);
    ASSERT_EQ(sweep_baseline_check(dir, "room", &g, err, sizeof(err)), -1);
    ASSERT(strstr(err, "a symlink") != NULL);
    ASSERT_EQ(sweep_run_begin(&r, "room", 1, dir, &g, &h, 0, 1764000900, err,
                              sizeof(err)), -1);
    /* Two links: refused. */
    unlink(base);
    ASSERT_EQ(link(real, base), 0);
    ASSERT_EQ(sweep_baseline_check(dir, "room", &g, err, sizeof(err)), -1);
    ASSERT(strstr(err, "more than one link") != NULL);
    unlink(base);
    unlink(real);
    /* The directory changed under the run: the outputs are refused at
     * the end, not written into a directory that broke the rule. */
    ASSERT_EQ(sweep_run_begin(&r, "late", 1, dir, &g, &h, 0, 1764001200, err,
                              sizeof(err)), 0);
    ASSERT_EQ(chmod(dir, 0777), 0);
    ASSERT_EQ(sweep_run_finish(&r, &g_s, 1, 0, 1764001260, nul), -1);
    ASSERT_EQ(chmod(dir, 02770), 0);
    ASSERT_EQ(sweep_record_stem(dir, "late", 1764001200, stem, sizeof(stem)), 0);
    snprintf(path, sizeof(path), "%s.tsv", stem);
    struct stat st;
    ASSERT(lstat(path, &st) != 0);
    if (nul) fclose(nul);
    test_rm_tree(dir);
}

/* ── resolving randomised addresses (owner ruling 2026-11-25) ── */

static const uint8_t PLANT[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };  /* fixed LA, associates */
static const uint8_t PL2[6]   = { 0x06, 0x11, 0x22, 0x33, 0x44, 0x56 };  /* fixed LA, probes 900 s */
static const uint8_t PL3[6]   = { 0x0a, 0x11, 0x22, 0x33, 0x44, 0x57 };  /* LA, probes 899 s */
static const uint8_t RND2[6]  = { 0x5a, 0x00, 0x00, 0x00, 0x00, 0x21 };  /* LA, seqnum-linked */
static const uint8_t RND3[6]  = { 0x5e, 0x00, 0x00, 0x00, 0x00, 0x22 };  /* LA, weak seam */

static void seed_assoc_req(sloth_state_t *s, const uint8_t sta[6], time_t ts) {
    assoc_req_t *r = &s->assoc_reqs[s->assoc_req_count++];
    memset(r, 0, sizeof(*r));
    memcpy(r->sta, sta, 6);
    memcpy(r->bssid, AP1, 6);
    r->ts = ts;
}

static void seed_corr(sloth_state_t *s, const uint8_t rnd[6], const uint8_t uni[6],
                      int conf) {
    seqnum_correlation_t *c = &s->seqnum_correlations[s->seqnum_correlation_count++];
    memset(c, 0, sizeof(*c));
    memcpy(c->mac_a, rnd, 6);
    memcpy(c->mac_b, uni, 6);
    c->mac_a_random = 1;
    c->confidence = conf;
}

/* The room of the ruling's test: a planted device on a fixed locally
 * administered address is reported (new), a phone's rotating probe
 * address is not a row, and the counts say which is which. */
static void seed_random_room(sloth_state_t *s) {
    memset(s, 0, sizeof(*s));
    seed_ap(s, AP1, "Lobby", "WPA2", 6, -50);
    seed_probe(s, CLI, 6, -60);                     /* universal */
    seed_probe(s, RND, 6, -40);                     /* rotating: 5 s */
    seed_probe(s, PL2, 6, -45);
    s->probe_clients[s->probe_count - 1].last_seen = 1000 + SW_STABLE_SPAN_S;
    seed_probe(s, PL3, 6, -47);
    s->probe_clients[s->probe_count - 1].last_seen = 1000 + SW_STABLE_SPAN_S - 1;
    seed_assoc_req(s, PLANT, 1001);
    seed_corr(s, RND2, CLI, 80);                    /* strong: linked */
    seed_corr(s, RND3, CLI, 50);                    /* weak: not */
    seed_ble(s, BRPA, 1, "tag", -55);
    s->ble_devices[s->ble_device_count - 1].last_seen = 1000 + SW_STABLE_SPAN_S;
    seed_ble(s, BNRP, 1, NULL, -75);                /* 2 s: rotating */
}

static void test_resolve_randomised(void) {
    seed_random_room(&g_s);
    sw_inv_t *inv = sweep_inv_new(), *base = sweep_inv_new(), *back = sweep_inv_new();
    ASSERT(inv && base && back);
    if (!inv || !base || !back) goto out;
    sweep_inv_observe(inv, &g_s);

    const sw_emitter_t *e = sweep_inv_find(inv, SW_K_CLIENT, PLANT, 0);
    ASSERT(e && e->res == SW_RES_ASSOC && e->res_conf == SW_CONF_ASSOC);
    e = sweep_inv_find(inv, SW_K_CLIENT, PL2, 0);
    ASSERT(e && e->res == SW_RES_PERSIST && e->res_conf == SW_CONF_PERSIST);
    /* Absent, each seen red under a mutation (commit message): a probe
     * address heard 5 s or 899 s is not resolved; a weak seam links
     * nothing; a 2 s private BLE address is not resolved. */
    ASSERT(sweep_inv_find(inv, SW_K_CLIENT, RND, 0) == NULL);
    ASSERT(sweep_inv_find(inv, SW_K_CLIENT, PL3, 0) == NULL);
    ASSERT(sweep_inv_find(inv, SW_K_CLIENT, RND2, 0) == NULL);
    e = sweep_inv_find(inv, SW_K_BLE, BRPA, SW_BLE_PRIVATE);
    ASSERT(e && e->res == SW_RES_PERSIST && !strcmp(e->name, "tag"));
    ASSERT(sweep_inv_find(inv, SW_K_BLE, BNRP, SW_BLE_PRIVATE) == NULL);
    sw_rand_t rc;
    sweep_rand_counts(inv, &rc);
    ASSERT_EQ(rc.client_random, 5);      /* RND PL2 PL3 PLANT RND2 (RND3 unheard) */
    ASSERT_EQ(rc.client_resolved, 2);
    ASSERT_EQ(rc.client_linked, 1);
    ASSERT_EQ(rc.client_unresolved, 2);  /* RND PL3 */
    ASSERT_EQ(rc.ble_private, 2);
    ASSERT_EQ(rc.ble_resolved, 1);
    ASSERT_EQ(rc.ble_unresolved, 1);

    /* Against an accepted v2 baseline that holds none of them: new. */
    seed_ap(&g_s, AP2, "x", "WPA2", 1, -80);         /* only to make a base */
    sw_emitter_t ap;
    memset(&ap, 0, sizeof(ap));
    ap.kind = SW_K_AP;
    memcpy(ap.addr, AP1, 6);
    ASSERT_EQ(sweep_inv_add(base, &ap), 0);
    for (int k = 0; k < SW_K_N; k++) base->has_kind[k] = 1;
    base->has_resolved = 1;
    sw_cmp_t c;
    ASSERT_EQ(sweep_compare(inv, base, &c), 0);
    ASSERT(c.compared_resolved);
    int plant_new = 0;
    for (int i = 0; i < c.n; i++)
        if (c.row[i].kind == SW_K_CLIENT && !memcmp(c.row[i].addr, PLANT, 6))
            plant_new = c.row[i].status == SW_ST_NEW;
    ASSERT(plant_new);
    ASSERT_EQ(c.count[SW_K_CLIENT][SW_ST_NEW], 3);   /* CLI PLANT PL2 */
    ASSERT_EQ(c.count[SW_K_BLE][SW_ST_NEW], 1);
    sweep_cmp_free(&c);

    /* The file: the resolved rows round-trip with method and confidence,
     * and the "# resolved" line says the file can hold them. */
    const char *path = tmpfile_path();
    ASSERT_EQ(wifi_snapshot_write_inv(inv, path, "room", 1764000000), 0);
    int ver = 0;
    ASSERT_EQ(wifi_snapshot_read(path, back, &ver), 0);
    ASSERT_EQ(ver, 2);
    ASSERT(back->has_resolved);
    e = sweep_inv_find(back, SW_K_CLIENT, PLANT, 0);
    ASSERT(e && e->res == SW_RES_ASSOC && e->res_conf == SW_CONF_ASSOC);
    e = sweep_inv_find(back, SW_K_BLE, BRPA, SW_BLE_PRIVATE);
    ASSERT(e && e->res == SW_RES_PERSIST);
    ASSERT(sweep_inv_find(back, SW_K_CLIENT, RND, 0) == NULL);
    char *t = slurp(path);
    ASSERT(t && strstr(t, "# resolved\t3\n") &&
           strstr(t, "client\t02:11:22:33:44:55\t0\t-\tassoc\t60\n") &&
           !strstr(t, "5e:00:00:00:00:22"));
    unlink(path);

    /* The next sweep against it: the planted device is known. */
    ASSERT_EQ(sweep_compare(inv, back, &c), 0);
    for (int i = 0; i < c.n; i++)
        if (!memcmp(c.row[i].addr, PLANT, 6)) ASSERT_EQ(c.row[i].status, SW_ST_KNOWN);
    ASSERT_EQ(c.count[SW_K_CLIENT][SW_ST_MISSING], 0);
    sweep_cmp_free(&c);

    /* Heard again only as a count (a short probe, not resolved this
     * time): it was heard, so not missing. Not heard at all: missing. */
    memset(&g_s, 0, sizeof(g_s));
    seed_probe(&g_s, PLANT, 6, -50);
    sw_inv_t *again = sweep_inv_new();
    ASSERT(again != NULL);
    if (again) {
        sweep_inv_observe(again, &g_s);
        ASSERT(sweep_inv_find(again, SW_K_CLIENT, PLANT, 0) == NULL);
        ASSERT_EQ(sweep_compare(again, back, &c), 0);
        int plant_missing = 0, pl2_missing = 0;
        for (int i = 0; i < c.n; i++) {
            if (c.row[i].status != SW_ST_MISSING) continue;
            if (!memcmp(c.row[i].addr, PLANT, 6)) plant_missing = 1;
            if (!memcmp(c.row[i].addr, PL2, 6)) pl2_missing = 1;
        }
        ASSERT(!plant_missing);
        ASSERT(pl2_missing);
        sweep_cmp_free(&c);
        sweep_inv_free(again);
    }

    /* A baseline from before resolution (no "# resolved" line) is not
     * compared for resolved rows: the planted device is new, even when
     * a hand-edited row of it is there. */
    back->has_resolved = 0;
    ASSERT_EQ(sweep_compare(inv, back, &c), 0);
    ASSERT(!c.compared_resolved);
    for (int i = 0; i < c.n; i++)
        if (!memcmp(c.row[i].addr, PLANT, 6) && c.row[i].status != SW_ST_MISSING)
            ASSERT_EQ(c.row[i].status, SW_ST_NEW);
    sweep_cmp_free(&c);
out:
    sweep_inv_free(inv);
    sweep_inv_free(base);
    sweep_inv_free(back);
}

/* Hand-edited rows: a randomised client address is a row only with a
 * method this writer produces; a universal one never carries one; a
 * private BLE address only as "persistent"; a static one never with a
 * method. Each refused row is absent (seen red with the reader's check
 * removed, commit message). */
static void test_resolved_rows_hand_edited(void) {
    const char *path = tmpfile_path();
    FILE *f = fopen(path, "w");
    ASSERT(f != NULL);
    if (!f) return;
    fputs("# sloth-snapshot v2\n# resolved\t0\n"
          "client\t02:00:00:00:00:01\t6\t-\n"                 /* LA, no method */
          "client\t02:00:00:00:00:02\t6\t-\tguess\t60\n"     /* unknown method */
          "client\t02:00:00:00:00:03\t6\t-\tassoc\t0\n"      /* confidence 0 */
          "client\t02:00:00:00:00:04\t6\t-\tassoc\t60\n"     /* kept */
          "client\t00:00:5e:00:53:05\t6\t-\tassoc\t60\n"     /* universal + method */
          "client\t03:00:00:00:00:06\t6\t-\tassoc\t60\n"     /* group */
          "ble\t41:22:33:44:55:01\tprivate\t-\t-\n"           /* no method */
          "ble\t41:22:33:44:55:02\tprivate\t-\t-\tassoc\t60\n"
          "ble\tc1:22:33:44:55:03\tprivate\t-\t-\tpersistent\t40\n" /* static bits */
          "ble\t41:22:33:44:55:04\tprivate\t-\t-\tpersistent\t40\n" /* kept */
          "ble\tc1:22:33:44:55:05\tstatic\t-\t-\tpersistent\t40\n", f);
    fclose(f);
    sw_inv_t *b = sweep_inv_new();
    ASSERT(b != NULL);
    if (!b) return;
    ASSERT_EQ(wifi_snapshot_read(path, b, NULL), 0);
    ASSERT(b->has_resolved);
    ASSERT_EQ(b->per_kind[SW_K_CLIENT], 1);
    ASSERT_EQ(b->per_kind[SW_K_BLE], 1);
    const uint8_t k1[6] = { 0x02, 0, 0, 0, 0, 0x04 }, k2[6] = { 0x41, 0x22, 0x33, 0x44, 0x55, 0x04 };
    ASSERT(sweep_inv_find(b, SW_K_CLIENT, k1, 0) != NULL);
    ASSERT(sweep_inv_find(b, SW_K_BLE, k2, SW_BLE_PRIVATE) != NULL);
    sweep_inv_free(b);
    unlink(path);
}

/* ── the 6 GHz plan (owner ruling 2026-11-25) ── */

static unsigned g_fake_bands;
static int      g_fake_bands_rc;
static int fake_bands(const char *iface, unsigned *mask) {
    (void)iface;
    *mask = g_fake_bands;
    return g_fake_bands_rc;
}

static void test_sweep_plan_6ghz(void) {
    chanhop_t h;
    ASSERT_EQ(chanhop_init_sweep(&h, 10, 1), 38 + CHANHOP_SWEEP_6GHZ_N);
    int n6 = 0;
    for (int i = 0; i < h.count; i++)
        if (h.slots[i].band == WIFI_BAND_6GHZ) {
            n6++;
            ASSERT_EQ(h.slots[i].freq_mhz, 5950 + 5 * h.slots[i].channel);
        }
    ASSERT_EQ(n6, 59);
    ASSERT_EQ(h.slots[38].channel, 1);
    ASSERT_EQ(h.slots[h.count - 1].channel, 233);
    ASSERT_EQ(chanhop_sweep_dwell_ms(&h), 600000u / 97u);

    /* Two radios, only radio 0 can tune 6 GHz: it is given every 6 GHz
     * channel beside its half of the rest; radio 1 none (seen red with
     * six_k ignored in chanhop_split_caps(), commit message). */
    chanhop_t r0, r1;
    ASSERT_EQ(chanhop_split_caps(&r0, &h, 2, 0, 1, 0), 19 + 59);
    ASSERT_EQ(chanhop_split_caps(&r1, &h, 2, 1, 1, -1), 19);
    for (int i = 0; i < r1.count; i++) ASSERT(r1.slots[i].band != WIFI_BAND_6GHZ);
    /* Neither can: no 6 GHz channel is dealt, so none is swept. */
    ASSERT_EQ(chanhop_split_caps(&r0, &h, 2, 0, 0, -1), 19);
    /* Both can: the 6 GHz channels are halved too, disjoint. */
    ASSERT_EQ(chanhop_split_caps(&r0, &h, 2, 0, 2, 0) +
              chanhop_split_caps(&r1, &h, 2, 1, 2, 1), 97);
    /* With no 6 GHz in the plan, the deal is chanhop_split()'s. */
    chanhop_t p38, a, b;
    chanhop_init_sweep(&p38, 10, 0);
    chanhop_split(&a, &p38, 3, 2);
    chanhop_split_caps(&b, &p38, 3, 2, 0, -1);
    ASSERT_EQ(a.count, b.count);
    for (int i = 0; i < a.count && i < b.count; i++)
        ASSERT_EQ(a.slots[i].freq_mhz, b.slots[i].freq_mhz);

    /* The capability, injected: bit 3 (NL80211_BAND_6GHZ) of the
     * wiphy's bands. Unreadable bands are not 6 GHz. */
    sweep_set_bands_probe(fake_bands);
    g_fake_bands = (1u << 0) | (1u << 1) | (1u << 3);
    g_fake_bands_rc = 1;
    ASSERT_EQ(sweep_iface_six("mon0"), 1);
    g_fake_bands = (1u << 0) | (1u << 1);
    ASSERT_EQ(sweep_iface_six("mon0"), 0);
    g_fake_bands = 1u << 3;
    g_fake_bands_rc = -EOPNOTSUPP;
    ASSERT_EQ(sweep_iface_six("mon0"), 0);
    ASSERT_EQ(sweep_iface_six(""), 0);
    sweep_set_bands_probe(NULL);

    /* Ten minutes over the 97: every channel, 6 GHz included, swept,
     * and the record's bands name only sub-GHz. */
    fake_net_reset();
    chanhop_init_sweep(&h, 10, 1);
    chanhop_sweep_quantum(&h, 50);            /* drive() polls every 50 ms */
    static sw_cov_t c;
    (void)drive(&h, &c, 10 * 60000);
    ASSERT(h.sweep_done);
    ASSERT_EQ(sweep_cov_swept(&c), 97);
    char bands[64];
    sweep_bands_not_swept(&c, bands, sizeof(bands));
    ASSERT(!strcmp(bands, "sub_ghz"));
    /* Without the band the plan is the 38 and 6 GHz is not swept. */
    chanhop_init_sweep(&h, 10, 0);
    (void)drive(&h, &c, 10 * 60000);
    sweep_bands_not_swept(&c, bands, sizeof(bands));
    ASSERT(!strcmp(bands, "6ghz,sub_ghz"));
}

void run_sweep_tests(void) {
    TEST_SUITE("sweep (#249): inventory");
    RUN_TEST(test_ble_kept_types);
    RUN_TEST(test_inventory_kinds_and_counts);
    RUN_TEST(test_inventory_outlives_the_tables);
    RUN_TEST(test_inventory_camera_and_setup_flags);
    TEST_SUITE("sweep (#249): snapshot format v2");
    RUN_TEST(test_snapshot_v2_round_trip);
    RUN_TEST(test_snapshot_v1_holds_aps_only);
    RUN_TEST(test_snapshot_v2_hostile_rows);
    TEST_SUITE("sweep (#249): compare with the baseline");
    RUN_TEST(test_compare_sorts_and_marks);
    RUN_TEST(test_two_passes_of_one_room);
    TEST_SUITE("sweep (#249): the plan and its coverage");
    RUN_TEST(test_sweep_plan_is_equal_dwell);
    RUN_TEST(test_sweep_one_pass_and_a_refusal);
    RUN_TEST(test_sweep_stopped_early);
    TEST_SUITE("sweep (#249): the report");
    RUN_TEST(test_report_of_a_stopped_sweep);
    TEST_SUITE("sweep (#249): the run");
    RUN_TEST(test_label_and_minutes);
    RUN_TEST(test_run_writes_and_never_accepts);
    RUN_TEST(test_run_group_dir);
    RUN_TEST(test_resolve_randomised);
    RUN_TEST(test_sweep_plan_6ghz);
    RUN_TEST(test_resolved_rows_hand_edited);
}
