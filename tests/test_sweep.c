#include "runner.h"
#include "sloth.h"
#include "sweep.h"
#include "wifi_snapshot.h"
#include "camera_vendor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "tmp_dir.h"

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
}
