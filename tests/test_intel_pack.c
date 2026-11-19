/* The intel-pack snapshot (#231, Stage 2 of #184): what intel/ holds,
 * what the build compiled from it, and what the reader refuses.
 *
 * Not circular. The snapshot hash is recomputed here from the files
 * with src/sha256.c, from its definition in docs/wiki/pack-schema.md,
 * without tools/intel_read.c; the row counts and sample rows are
 * constants written into this file from the 1.0.0 packs and read back
 * through each table's own lookup, so a regenerated table that dropped,
 * reordered or rewrote a row fails here whatever the generator thinks.
 * An update-intel that changes rows changes these constants in the same
 * commit, which is the point: the change is then visible in review.
 *
 * The reader's refusals are driven with packs built in a temporary
 * directory: a copy of intel/ with one file or one manifest changed. */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "runner.h"
#include "tmp_dir.h"
#include "sha256.h"
#include "intel_pack.h"
#include "oui.h"
#include "wifi_oui_attacker.h"
#include "camera_vendor.h"
#include "vendor_watchlist.h"
#include "tool_fingerprint.h"
#include "ble_watchlist.h"
#include "../tools/intel_read.h"
#include "alerts.h"
#include "alerts/rules.h"
#include "alerts/engine_internal.h"

#define INTEL "intel"

static const char *const k_packs[6] = {
    "attacker-ouis", "ble-watchlist", "camera-vendor",
    "oui-builtin", "surveillance-endpoints", "tool-fingerprints",
};

static char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 1 << 16, n = 0, r;
    char *b = malloc(cap + 1);
    while (b && (r = fread(b + n, 1, cap - n, f)) > 0) {
        n += r;
        if (n == cap) {
            char *nb = realloc(b, cap * 2 + 1);
            if (!nb) { free(b); b = NULL; break; }
            b = nb;
            cap *= 2;
        }
    }
    fclose(f);
    if (b) b[n] = '\0';
    if (len) *len = n;
    return b;
}

/* The value of "key: " in LOCK, or "". */
static void lock_get(const char *lock, const char *key, char *out, size_t n) {
    out[0] = '\0';
    char pat[40];
    snprintf(pat, sizeof(pat), "\n%s: ", key);
    const char *p = strstr(lock, pat);
    if (!p) return;
    p += strlen(pat);
    size_t k = strcspn(p, "\n");
    if (k >= n) k = n - 1;
    memcpy(out, p, k);
    out[k] = '\0';
}

/* intel/LOCK names the snapshot the packs hash to, and the binary
 * reports the same version and hash. The hash is rebuilt from its
 * definition: one line per pack in byte order of name, "<name> <sha256
 * of manifest.json>\n", hashed. Seen red with one manifest byte changed
 * in a copy (the check below on a temp tree) and with intel_gen's
 * snapshot order reversed. */
static void test_lock_names_the_snapshot_the_build_reports(void) {
    char *lock = slurp(INTEL "/LOCK", NULL);
    ASSERT(lock != NULL);
    if (!lock) return;
    char text[1024] = "";
    for (int i = 0; i < 6; i++) {
        char path[256], hex[65];
        snprintf(path, sizeof(path), INTEL "/%s/manifest.json", k_packs[i]);
        size_t n = 0;
        char *m = slurp(path, &n);
        ASSERT(m != NULL);
        if (!m) { free(lock); return; }
        sha256_hex((const uint8_t *)m, n, hex);
        free(m);
        size_t off = strlen(text);
        snprintf(text + off, sizeof(text) - off, "%s %s\n", k_packs[i], hex);
    }
    char want[65], got[65], ver[32];
    sha256_hex((const uint8_t *)text, strlen(text), want);
    lock_get(lock, "hash", got, sizeof(got));
    lock_get(lock, "pack_version", ver, sizeof(ver));
    ASSERT_STR(got, want);
    ASSERT_STR(intel_pack_hash(), want);
    ASSERT_EQ((int)strlen(intel_pack_hash()), INTEL_PACK_HASH_LEN);
    ASSERT_STR(intel_pack_version(), ver);
    ASSERT(ir_semver_ok(intel_pack_version()));
    char commit[64];
    lock_get(lock, "comint_commit", commit, sizeof(commit));
    ASSERT_EQ((int)strlen(commit), 40);
    free(lock);
}

/* The committed snapshot verifies whole, and it is exactly six packs:
 * nothing in intel/ that the build would not read. */
static void test_committed_snapshot_verifies(void) {
    ir_snapshot_t s;
    char err[IR_ERR] = "";
    int rc = ir_snapshot_load(INTEL, &s, err, sizeof(err));
    if (rc) fprintf(stderr, "    %s\n", err);
    ASSERT_EQ(rc, 0);
    if (rc) return;
    ASSERT_STR(s.hash, intel_pack_hash());
    ir_snapshot_free(&s);
    DIR *d = opendir(INTEL);
    ASSERT(d != NULL);
    if (!d) return;
    int entries = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        int known = !strcmp(de->d_name, "LOCK");
        for (int i = 0; i < 6; i++) if (!strcmp(de->d_name, k_packs[i])) known = 1;
        if (!known) fprintf(stderr, "    intel/%s is not a pack sloth reads\n", de->d_name);
        ASSERT(known);
        entries++;
    }
    closedir(d);
    ASSERT_EQ(entries, 7);
}

/* Every table's row count, pinned from pack 1.0.0. */
static void test_row_counts_are_pinned(void) {
    ASSERT_EQ(oui_builtin_count(), 118);
    ASSERT_EQ(oui_hak5_count(), 2);
    ASSERT_EQ(oui_espressif_count(), 11);
    ASSERT_EQ(cam_vendor_oui_count(), 455);
    ASSERT_EQ(cam_server_brand_count(), 9);
    ASSERT_EQ(cam_mdns_service_count(), 3);
    ASSERT_EQ(cam_setup_ssid_count(), 4);
    ASSERT_EQ(vendor_watchlist_count(), 4);
    ASSERT_EQ(tool_signature_count(), 2);
    ble_watchlist_reset();
    ASSERT_EQ(ble_watchlist_count(), 0);
}

/* Sample rows per table, first and last where the table has an order
 * a lookup can see, read back through the lookups the rules use. */
static void test_sample_rows_are_pinned(void) {
    const uint8_t first[6] = { 0x00, 0x03, 0x47, 1, 2, 3 };
    const uint8_t last[6]  = { 0xFC, 0xF5, 0xC4, 1, 2, 3 };
    const uint8_t alfa[6]  = { 0x00, 0xC0, 0xCA, 1, 2, 3 };
    const uint8_t none[6]  = { 0x00, 0x00, 0x01, 1, 2, 3 };
    const char *v = oui_lookup(first);
    ASSERT(v && !strcmp(v, "Intel"));
    v = oui_lookup(last);
    ASSERT(v && !strcmp(v, "Espressif"));
    v = oui_lookup(alfa);
    ASSERT(v && !strcmp(v, "Alfa Network"));
    ASSERT(oui_lookup(none) == NULL);

    const uint8_t h1[3] = { 0x00, 0x13, 0x37 }, h2[3] = { 0x00, 0xC0, 0xCA };
    const uint8_t e1[3] = { 0x24, 0x0A, 0xC4 }, e11[3] = { 0xAC, 0x0B, 0xFB };
    ASSERT_EQ(oui_is_hak5(h1), 1);
    ASSERT_EQ(oui_is_hak5(h2), 1);
    ASSERT_EQ(oui_is_espressif(e1), 1);
    ASSERT_EQ(oui_is_espressif(e11), 1);
    ASSERT_EQ(oui_is_hak5(e1), 0);
    ASSERT_EQ(oui_is_espressif(h1), 0);

    uint8_t o[3] = { 0, 0, 0 };
    const char *vendor = NULL, *org = NULL;
    cam_vendor_oui_at(0, o, &vendor, &org);
    ASSERT(o[0] == 0x00 && o[1] == 0x65 && o[2] == 0x1E);
    ASSERT(vendor && !strcmp(vendor, "Amcrest"));
    ASSERT(org && !strcmp(org, "Amcrest Technologies"));
    ASSERT_EQ(cam_vendor_oui_mixed_at(0), 0);
    cam_vendor_oui_at(454, o, &vendor, &org);
    ASSERT(o[0] == 0xF0 && o[1] == 0xC8 && o[2] == 0x8B);
    ASSERT(vendor && !strcmp(vendor, "Wyze"));
    ASSERT(org && !strcmp(org, "Wyze Labs Inc"));
    ASSERT_EQ(cam_vendor_oui_mixed_at(454), 1);
    /* A registry name with a comma inside it: the CSV quoting. */
    cam_vendor_oui_at(10, o, &vendor, &org);
    ASSERT(o[0] == 0x30 && o[1] == 0xDD && o[2] == 0xAA);
    ASSERT(org && !strcmp(org, "ZHEJIANG DAHUA TECHNOLOGYCO.,LTD"));

    const char *brand = NULL;
    ASSERT_EQ(cam_vendor_server("Linux/3.0 Arlo/1.0", &brand), 1);
    ASSERT(brand && !strcmp(brand, "Arlo"));
    const char *label = NULL;
    int specific = -1;
    ASSERT_EQ(cam_mdns_service("_rtsp._tcp.local", &label, &specific), 1);
    ASSERT(label && !strcmp(label, "RTSP stream service (IANA rtsp)"));
    ASSERT_EQ(specific, 0);
    ASSERT_EQ(cam_mdns_service("_axis-video._tcp.local", NULL, &specific), 1);
    ASSERT_EQ(specific, 1);
    brand = NULL;
    ASSERT_EQ(cam_setup_ssid("Tapo_Cam_1A2B", &label, &brand), 1);
    ASSERT(brand && !strcmp(brand, "TP-Link Tapo"));
    ASSERT_EQ(cam_setup_ssid("HAP_ABCDEF", &label, &brand), 1);
    ASSERT(label && !strcmp(label, "Hikvision camera"));

    const char *fam = NULL;
    vendor = NULL;
    ASSERT_EQ(vendor_watchlist_match_domain("api.control.verkada.com", &vendor, &fam), 1);
    ASSERT(vendor && !strcmp(vendor, "verkada"));
    ASSERT(fam && !strcmp(fam, "camera-cloud"));
    ASSERT_EQ(vendor_watchlist_match_domain("evidence.com", &vendor, &fam), 1);
    ASSERT(vendor && !strcmp(vendor, "axon"));
    ASSERT_EQ(vendor_watchlist_match_domain("verkada.com", NULL, NULL), 0);

    const sloth_tool_sig_t *t = tool_signature_at(0);
    ASSERT(t != NULL);
    if (t) {
        ASSERT_EQ(t->tool, SLOTH_TOOL_ESP32_MARAUDER);
        ASSERT_EQ(t->vendor_ie_hash, 0u);
        ASSERT_EQ(t->beacon_interval_ms, 102);
        ASSERT_EQ(t->supported_rates, 0u);
        ASSERT_EQ(t->require_flags, AP_FP_FLAG_ESPRESSIF_OUI);
        ASSERT_EQ(t->forbid_flags, AP_FP_FLAG_HT_PRESENT);
        ASSERT_EQ(t->requires_karma_echo, 1);
        ASSERT_EQ(t->requires_pmkid, 0);
        ASSERT_EQ(t->unverified, 1);
        ASSERT_STR(t->human_label, "ESP32 Marauder");
        ASSERT(!strncmp(t->evidence, "UNVERIFIED - values from issue #74 research", 43));
        ASSERT_STR(t->id, "esp32-marauder-01");
        ASSERT_STR(t->version, "research-2026-09-04");
    }
    t = tool_signature_at(1);
    ASSERT(t != NULL);
    if (t) {
        ASSERT_EQ(t->tool, SLOTH_TOOL_PINEAPPLE_MK7);
        ASSERT_EQ(t->beacon_interval_ms, 0);
        ASSERT_EQ(t->require_flags, AP_FP_FLAG_HAK5_OUI);
        ASSERT_EQ(t->forbid_flags, 0);
        ASSERT_STR(t->id, "pineapple-mk7-01");
    }
    ASSERT(tool_signature_at(2) == NULL);
}

/* ── The reader's refusals, on a copy of intel/ ───────────────────── */

static char g_dir[TEST_TMP_MAX];

static int write_file(const char *path, const char *data, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    int ok = fwrite(data, 1, n, f) == n;
    return (fclose(f) == 0 && ok) ? 0 : -1;
}

static void rm_tree(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    char path[512];
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        struct stat st;
        if (lstat(path, &st) == 0 && S_ISDIR(st.st_mode)) rm_tree(path);
        else unlink(path);
    }
    closedir(d);
    rmdir(dir);
}

/* A fresh copy of intel/ in g_dir: every pack's manifest and the files
 * it lists. 0 on success. */
static int copy_intel(void) {
    g_dir[0] = '\0';   /* test_tmp_tpl() fills an EMPTY buffer */
    if (!mkdtemp(test_tmp_tpl(g_dir, sizeof(g_dir), "sloth_intel_XXXXXX"))) return -1;
    for (int i = 0; i < 6; i++) {
        char src[256], dst[512];
        snprintf(dst, sizeof(dst), "%s/%s", g_dir, k_packs[i]);
        if (mkdir(dst, 0700) != 0) return -1;
        DIR *d;
        snprintf(src, sizeof(src), INTEL "/%s", k_packs[i]);
        if (!(d = opendir(src))) return -1;
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (de->d_name[0] == '.') continue;
            char sp[512];
            snprintf(sp, sizeof(sp), "%s/%s", src, de->d_name);
            snprintf(dst, sizeof(dst), "%s/%s/%s", g_dir, k_packs[i], de->d_name);
            size_t n;
            char *b = slurp(sp, &n);
            if (!b || write_file(dst, b, n) != 0) { free(b); closedir(d); return -1; }
            free(b);
        }
        closedir(d);
    }
    return 0;
}

/* Load the copy; 1 when it was refused with `want` in the reason. */
static int refused_with(const char *want) {
    ir_snapshot_t s;
    char err[IR_ERR] = "";
    int rc = ir_snapshot_load(g_dir, &s, err, sizeof(err));
    if (rc == 0) { ir_snapshot_free(&s); fprintf(stderr, "    accepted, wanted: %s\n", want); return 0; }
    if (!strstr(err, want)) { fprintf(stderr, "    refused for: %s\n    wanted: %s\n", err, want); return 0; }
    return 1;
}

/* Replace one data file of `pack` with `csv` and rewrite the pack's
 * manifest over every file in its directory with right hashes, lengths
 * and row counts, so that the only thing wrong is what the test put in
 * the CSV. */
static int put_csv(const char *pack, const char *file, const char *csv) {
    char path[512], dir[512], man[8192];
    /* Every path is checked rather than cut: a truncated one would write
     * somewhere the test does not mean (and -Wformat-truncation says so). */
    if (snprintf(dir, sizeof(dir), "%s/%s", g_dir, pack) >= (int)sizeof(dir) ||
        snprintf(path, sizeof(path), "%s/%s", dir, file) >= (int)sizeof(path))
        return -1;
    if (write_file(path, csv, strlen(csv)) != 0) return -1;
    int off = snprintf(man, sizeof(man),
        "{\"schema_version\":1,\"pack_name\":\"%s\",\"pack_version\":\"1.0.1\","
        "\"tier\":\"table\",\"country\":null,\"build_time\":\"2026-11-18T00:00:00Z\","
        "\"files\":[", pack);
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *de;
    int first = 1;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.' || !strcmp(de->d_name, "manifest.json")) continue;
        if (snprintf(path, sizeof(path), "%s/%s", dir, de->d_name) >= (int)sizeof(path)) {
            closedir(d);
            return -1;
        }
        size_t n = 0;
        char *b = slurp(path, &n);
        if (!b) { closedir(d); return -1; }
        char hex[65], rows[32] = "";
        sha256_hex((const uint8_t *)b, n, hex);
        int is_csv = strstr(de->d_name, ".csv") != NULL;
        if (is_csv) snprintf(rows, sizeof(rows), ",\"rows\":%ld", ir_csv_count(b, n));
        free(b);
        off += snprintf(man + off, sizeof(man) - (size_t)off,
            "%s{\"path\":\"%s\",\"sha256\":\"%s\",\"bytes\":%zu%s,"
            "\"source_url\":\"test\",\"retrieved\":\"2026-11-18\",\"licence\":\"test\","
            "\"format\":\"%s\"}",
            first ? "" : ",", de->d_name, hex, n, rows, is_csv ? "csv-rows" : "md-document");
        first = 0;
        if (off >= (int)sizeof(man) - 2) { closedir(d); return -1; }
    }
    closedir(d);
    snprintf(man + off, sizeof(man) - (size_t)off, "]}");
    if (snprintf(path, sizeof(path), "%s/manifest.json", dir) >= (int)sizeof(path)) return -1;
    return write_file(path, man, strlen(man));
}


/* The copy itself loads: every refusal below is the one change made. */
static void test_reader_accepts_the_copy_and_a_rewritten_manifest(void) {
    ASSERT_EQ(copy_intel(), 0);
    ir_snapshot_t s;
    char err[IR_ERR] = "";
    ASSERT_EQ(ir_snapshot_load(g_dir, &s, err, sizeof(err)), 0);
    if (!err[0]) ir_snapshot_free(&s);
    ASSERT_EQ(put_csv("surveillance-endpoints", "surveillance_endpoints.csv",
                      "domain,vendor,family\nexample.net,acme,test-cloud\n"), 0);
    err[0] = '\0';
    int rc = ir_snapshot_load(g_dir, &s, err, sizeof(err));
    if (rc) fprintf(stderr, "    %s\n", err);
    ASSERT_EQ(rc, 0);
    if (!rc) {
        ASSERT_EQ(s.n_ep, 1);
        ASSERT_STR(s.ep[0].domain, "example.net");
        ASSERT(strcmp(s.hash, intel_pack_hash()) != 0);
        ir_snapshot_free(&s);
    }
    rm_tree(g_dir);
}

/* Integrity: each refused, with the original untouched elsewhere. Seen
 * red, each alone, with the length, hash, row, stray-file and
 * schema_version checks in tools/intel_read.c turned off. */
static void test_reader_refuses_what_its_manifest_does_not_hold(void) {
    char path[512];

    ASSERT_EQ(copy_intel(), 0);
    snprintf(path, sizeof(path), "%s/oui-builtin/oui_builtin.csv", g_dir);
    size_t n;
    char *b = slurp(path, &n);
    ASSERT(b != NULL);
    if (b) {
        b[n - 3] = (char)(b[n - 3] ^ 0x20);          /* "Espressif" -> "EspressIf" */
        ASSERT_EQ(write_file(path, b, n), 0);
        ASSERT(refused_with("sha256"));
        ASSERT_EQ(write_file(path, b, n - 1), 0);   /* and one byte short */
        ASSERT(refused_with("bytes, the manifest says"));
        free(b);
    }
    rm_tree(g_dir);

    ASSERT_EQ(copy_intel(), 0);
    snprintf(path, sizeof(path), "%s/camera-vendor/notes.txt", g_dir);
    ASSERT_EQ(write_file(path, "x", 1), 0);
    ASSERT(refused_with("not in the pack's manifest"));
    rm_tree(g_dir);

    ASSERT_EQ(copy_intel(), 0);
    snprintf(path, sizeof(path), "%s/tool-fingerprints/manifest.json", g_dir);
    b = slurp(path, &n);
    ASSERT(b != NULL);
    if (b) {
        char *sv = strstr(b, "\"schema_version\": 1");
        ASSERT(sv != NULL);
        if (sv) {
            sv[18] = '2';
            ASSERT_EQ(write_file(path, b, n), 0);
            ASSERT(refused_with("unknown schema_version"));
        }
        char *rows = strstr(b, "\"rows\": 2");
        ASSERT(rows != NULL);
        if (sv && rows) {
            sv[18] = '1';
            rows[8] = '3';
            ASSERT_EQ(write_file(path, b, n), 0);
            ASSERT(refused_with("rows, the manifest says 3"));
        }
        free(b);
    }
    rm_tree(g_dir);
}

/* The manifest is read strictly: shapes v1 does not define are refused
 * before any file is opened. */
static void test_reader_refuses_a_malformed_manifest(void) {
    static const struct { const char *json, *why; } cases[] = {
        { "{\"schema_version\":1,\"schema_version\":1}", "duplicate member" },
        { "{\"schema_version\":1,\"pack_name\":\"ble-watchlist\",\"pack_version\":\"1.0.0\","
          "\"build_time\":\"2026-11-16T00:00:00Z\",\"extra\":1,\"files\":[]}",
          "a field v1 does not define" },
        { "{\"schema_version\":1.0}", "not an integer" },
        { "{\"schema_version\":1,\"pack_name\":\"ble-watchlist\",\"pack_version\":\"1.0\"}",
          "pack_version is not MAJOR.MINOR.PATCH" },
        { "{\"schema_version\":1,\"pack_name\":\"ble-watchlist\",\"pack_version\":\"1.0.0\","
          "\"build_time\":\"2026-11-16T00:00:00Z\",\"files\":[{\"path\":\"../LOCK\"}]}",
          "not a plain pack-relative name" },
        /* Flat names only: no directory, no absolute path, nothing
         * hidden, so a listed file can never be outside the pack and the
         * one-level stray scan sees all of it. */
        { "{\"schema_version\":1,\"pack_name\":\"ble-watchlist\",\"pack_version\":\"1.0.0\","
          "\"build_time\":\"2026-11-16T00:00:00Z\",\"files\":[{\"path\":\"sub/x.csv\"}]}",
          "not a plain pack-relative name" },
        { "{\"schema_version\":1,\"pack_name\":\"ble-watchlist\",\"pack_version\":\"1.0.0\","
          "\"build_time\":\"2026-11-16T00:00:00Z\",\"files\":[{\"path\":\"/etc/passwd\"}]}",
          "not a plain pack-relative name" },
        { "{\"schema_version\":1,\"pack_name\":\"ble-watchlist\",\"pack_version\":\"1.0.0\","
          "\"build_time\":\"2026-11-16T00:00:00Z\",\"files\":[{\"path\":\"..\"}]}",
          "not a plain pack-relative name" },
        { "{\"schema_version\":1,\"pack_name\":\"ble-watchlist\",\"pack_version\":\"1.0.0\","
          "\"build_time\":\"2026-11-16T00:00:00Z\",\"files\":[{\"path\":\".x.csv\"}]}",
          "not a plain pack-relative name" },
        { "{\"schema_version\":1,\"pack_name\":\"ble-watchlist\",\"pack_version\":\"1.0.0\","
          "\"build_time\":\"2026-11-16T00:00:00Z\",\"pii\":true,\"files\":[]}",
          "personal data" },
        { "{\"schema_version\":1,\"pack_name\":\"ble-watchlist\",\"pack_version\":\"1.0.0\","
          "\"build_time\":\"2026-11-16T00:00:00Z\",\"tier\":\"registry\",\"files\":[]}",
          "tier is not" },
        { "{\"schema_version\":1,\"pack_name\":\"ble-watchlist\",\"pack_version\":\"1.0.0\","
          "\"build_time\":\"2026-11-16T00:00:00Z\",\"files\":[]}", "files is empty" },
        { "{\"schema_version\":1,\"pack_name\":\"ble-watchlist\"} x", "trailing bytes" },
        { "{\"schema_version\":1,\"pack_name\":\"ble-watchlist\\ud800\"}", "unpaired surrogate" },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        ir_manifest_t m;
        char err[IR_ERR] = "";
        int rc = ir_manifest_parse(cases[i].json, strlen(cases[i].json), &m, err, sizeof(err));
        ASSERT_EQ(rc, -1);
        int named = strstr(err, cases[i].why) != NULL;
        if (!named) fprintf(stderr, "    case %zu: \"%s\", wanted \"%s\"\n", i, err, cases[i].why);
        ASSERT(named);
    }
    /* A pack whose manifest names another pack. */
    ASSERT_EQ(copy_intel(), 0);
    char path[512];
    snprintf(path, sizeof(path), "%s/oui-builtin/manifest.json", g_dir);
    char *b = slurp(path, NULL);
    ASSERT(b != NULL);
    if (b) {
        snprintf(path, sizeof(path), "%s/ble-watchlist/manifest.json", g_dir);
        ASSERT_EQ(write_file(path, b, strlen(b)), 0);
        ASSERT(refused_with("pack_name is \"oui-builtin\""));
        free(b);
    }
    rm_tree(g_dir);
}

/* Values against the C types they land in and the rules their tables'
 * code depends on. Each case is one CSV with a right manifest. Seen red
 * with the sort check, the U/L-bit check, the unverified/evidence check
 * and the category length check each removed. */
static void test_reader_refuses_values_the_tables_cannot_hold(void) {
    static const struct { const char *pack, *file, *csv, *why; } cases[] = {
        { "oui-builtin", "oui_builtin.csv", "oui,vendor\n000393,Apple\n000347,Intel\n",
          "not in ascending order" },
        { "oui-builtin", "oui_builtin.csv", "oui,vendor\n020393,Apple\n",
          "MA-L block" },
        { "oui-builtin", "oui_builtin.csv", "oui,vendor\n0003g3,Apple\n", "MA-L block" },
        { "oui-builtin", "oui_builtin.csv", "vendor,oui\nApple,000393\n", "header column 1" },
        { "oui-builtin", "oui_builtin.csv", "oui,vendor\n", "no rows" },
        { "oui-builtin", "oui_builtin.csv", "oui,vendor\n000393,Ap\"ple\n", "quote inside" },
        { "oui-builtin", "oui_builtin.csv", "oui,vendor\n000393,Apple,x\n", "3 fields" },
        { "oui-builtin", "oui_builtin.csv", "oui,vendor\n000393,\"Apple\n", "unterminated quote" },
        { "oui-builtin", "oui_builtin.csv", "oui,vendor\n000393,\x01pple\n", "not text" },
        { "attacker-ouis", "attacker_ouis.csv",
          "oui,family,note\n001337,hak5,x\n240AC4,flipper,y\n", "neither hak5 nor espressif" },
        { "attacker-ouis", "attacker_ouis.csv",
          "oui,family,note\n001337,hak5,x\n", "no espressif rows" },
        { "attacker-ouis", "attacker_ouis.csv",
          "oui,family,note\n001337,hak5,a */ b\n240AC4,espressif,y\n", "comment delimiter" },
        { "camera-vendor", "camera_vendors.csv", "oui,vendor,org,mixed\n00651E,Amcrest,A,2\n",
          "mixed is not 0 or 1" },
        { "surveillance-endpoints", "surveillance_endpoints.csv",
          "domain,vendor,family\nEvidence.com,axon,x\n", "lower-case LDH" },
        { "tool-fingerprints", "tool_fingerprints.csv",
          "tool,vendor_ie_hash,beacon_interval_ms,supported_rates,require_flags,forbid_flags,"
          "requires_karma_echo,requires_pmkid,unverified,human_label,evidence,id,version\n"
          "SLOTH_TOOL_PINEAPPLE_MK7,0,0,0,AP_FP_FLAG_HAK5_OUI,0,1,0,0,Pineapple,"
          "UNVERIFIED - no capture,p-01,v1\n", "unverified disagrees" },
        { "tool-fingerprints", "tool_fingerprints.csv",
          "tool,vendor_ie_hash,beacon_interval_ms,supported_rates,require_flags,forbid_flags,"
          "requires_karma_echo,requires_pmkid,unverified,human_label,evidence,id,version\n"
          "SLOTH_TOOL_NOPE,0,0,0,0,0,1,0,0,X,capture c1,p-01,v1\n", "SLOTH_TOOL_" },
        { "tool-fingerprints", "tool_fingerprints.csv",
          "tool,vendor_ie_hash,beacon_interval_ms,supported_rates,require_flags,forbid_flags,"
          "requires_karma_echo,requires_pmkid,unverified,human_label,evidence,id,version\n"
          "SLOTH_TOOL_EAPHAMMER,0,65536,0,0,0,1,0,0,X,capture c1,p-01,v1\n", "uint16_t" },
        { "tool-fingerprints", "tool_fingerprints.csv",
          "tool,vendor_ie_hash,beacon_interval_ms,supported_rates,require_flags,forbid_flags,"
          "requires_karma_echo,requires_pmkid,unverified,human_label,evidence,id,version\n"
          "SLOTH_TOOL_EAPHAMMER,0,0,0,AP_FP_FLAG_HT_PRESENT,AP_FP_FLAG_HT_PRESENT,1,0,0,X,"
          "capture c1,p-01,v1\n", "both required and forbidden" },
        { "tool-fingerprints", "tool_fingerprints.csv",
          "tool,vendor_ie_hash,beacon_interval_ms,supported_rates,require_flags,forbid_flags,"
          "requires_karma_echo,requires_pmkid,unverified,human_label,evidence,id,version\n"
          "SLOTH_TOOL_EAPHAMMER,0,0,0,0,0,1,0,0,X,capture c1,an-id-of-twenty-four-chr,v1\n",
          "too long for sig_id" },
        { "ble-watchlist", "ble_watchlist.csv",
          "category,match,id,subtype,min_len,max_len,source\n"
          "a-category-of-16,mfr,0x004C,-1,-1,-1,doc\n", "category is empty, too long" },
        { "ble-watchlist", "ble_watchlist.csv",
          "category,match,id,subtype,min_len,max_len,source\n"
          "finder,mfr,0x004C,-1,-1,-1,\n", "no source" },
        { "ble-watchlist", "ble_watchlist.csv",
          "category,match,id,subtype,min_len,max_len,source\n"
          "finder,beacon,0x004C,-1,-1,-1,doc\n", "match is not" },
        { "ble-watchlist", "ble_watchlist.csv",
          "category,match,id,subtype,min_len,max_len,source\n"
          "finder,mfr,0x1004C,-1,-1,-1,doc\n", "four hex digits" },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        ASSERT_EQ(copy_intel(), 0);
        ASSERT_EQ(put_csv(cases[i].pack, cases[i].file, cases[i].csv), 0);
        int ok = refused_with(cases[i].why);
        if (!ok) fprintf(stderr, "    case %zu (%s)\n", i, cases[i].file);
        ASSERT(ok);
        rm_tree(g_dir);
    }
    /* And one row the BLE table takes, to show the refusals above are
     * the values and not the table. */
    ASSERT_EQ(copy_intel(), 0);
    ASSERT_EQ(put_csv("ble-watchlist", "ble_watchlist.csv",
                      "category,match,id,subtype,min_len,max_len,source\n"
                      "finder,svc_data,0xFEAA,-1,2,20,\"doc, section 3\"\n"), 0);
    ir_snapshot_t s;
    char err[IR_ERR] = "";
    int rc = ir_snapshot_load(g_dir, &s, err, sizeof(err));
    if (rc) fprintf(stderr, "    %s\n", err);
    ASSERT_EQ(rc, 0);
    if (!rc) {
        ASSERT_EQ(s.n_ble, 1);
        ASSERT_EQ(s.ble[0].match, BLE_WL_SVC_DATA);
        ASSERT_EQ(s.ble[0].id, 0xFEAA);
        ASSERT_EQ(s.ble[0].min_len, 2);
        ASSERT_STR(s.ble[0].source, "doc, section 3");
        ir_snapshot_free(&s);
    }
    rm_tree(g_dir);
}

/* LOCK is read strictly too. */
static void test_lock_parse(void) {
    ir_lock_t l;
    char err[IR_ERR];
    const char *good = "# c\npack_version: 1.0.0\nhash: "
        "f27b877f623b8d32809b7b5b3f378921416e6e67e046887d955c76ee9c606286\n"
        "comint_commit: 88b1a0517eb59819c77b767b9a692387cc20097e\ndate: 2026-11-18\n"
        "packs: a b\n";
    ASSERT_EQ(ir_lock_parse(good, strlen(good), &l, err, sizeof(err)), 0);
    ASSERT_STR(l.pack_version, "1.0.0");
    const char *nodate = "pack_version: 1.0.0\nhash: "
        "f27b877f623b8d32809b7b5b3f378921416e6e67e046887d955c76ee9c606286\n"
        "comint_commit: 88b1a0517eb59819c77b767b9a692387cc20097e\n";
    ASSERT_EQ(ir_lock_parse(nodate, strlen(nodate), &l, err, sizeof(err)), -1);
    const char *short_sha = "pack_version: 1.0.0\nhash: "
        "f27b877f623b8d32809b7b5b3f378921416e6e67e046887d955c76ee9c606286\n"
        "comint_commit: 88b1a05\ndate: 2026-11-18\n";
    ASSERT_EQ(ir_lock_parse(short_sha, strlen(short_sha), &l, err, sizeof(err)), -1);
    ASSERT(strstr(err, "comint_commit") != NULL);
}

/* ── The engine's stage (alert_t.intel_pack) ───────────────────────────
 * fire_stage_intel() marks the NEXT fire only. These rules run under a
 * table of their own so each way a stage could outlive its fire is one
 * phase: a rule that staged and never fired (the per-rule clear in
 * alerts_update()), a fire dropped for an empty key, a second fire from
 * the rule that staged, a re-evaluation without a stage (refreshed, not
 * sticky), and a stage left when alerts_clear() runs. Seen red, one at
 * a time, with the per-rule clear, the empty-key clear and the clear in
 * alerts_clear() each removed from src/alerts/engine.c. */
static int g_phase;

static void r231_first(const sloth_state_t *s, time_t now) {
    (void)s;
    fire(ALERT_TYPE_ARP_SPOOF, ALERT_SEV_WARN, "ARP_SPOOF", "x", "t231:first", NULL, 0, now);
}

static void r231_stage_only(const sloth_state_t *s, time_t now) {
    (void)s; (void)now;
    if (g_phase == 1) fire_stage_intel();
}

static void r231_plain(const sloth_state_t *s, time_t now) {
    (void)s;
    fire(ALERT_TYPE_ARP_SPOOF, ALERT_SEV_WARN, "ARP_SPOOF", "x", "t231:plain", NULL, 0, now);
}

static void r231_staged(const sloth_state_t *s, time_t now) {
    (void)s;
    if (g_phase == 2) {
        fire_stage_intel();
        fire(ALERT_TYPE_SURV_DNS, ALERT_SEV_LOW, "SURV_DNS", "x", "", NULL, 0, now);
        fire(ALERT_TYPE_SURV_DNS, ALERT_SEV_LOW, "SURV_DNS", "x", "t231:after-drop", NULL, 0, now);
    } else if (g_phase == 3) {
        fire_stage_intel();
        fire(ALERT_TYPE_SURV_DNS, ALERT_SEV_LOW, "SURV_DNS", "x", "t231:staged", NULL, 0, now);
        fire(ALERT_TYPE_SURV_DNS, ALERT_SEV_LOW, "SURV_DNS", "x", "t231:second", NULL, 0, now);
    } else if (g_phase == 4) {
        fire(ALERT_TYPE_SURV_DNS, ALERT_SEV_LOW, "SURV_DNS", "x", "t231:staged", NULL, 0, now);
    }
}

static const alert_rule_t k_r231_rules[] = {
    { "r231_first",      r231_first },
    { "r231_stage_only", r231_stage_only },
    { "r231_plain",      r231_plain },
    { "r231_staged",     r231_staged },
};
static const alert_rule_table_t k_r231_table = {
    k_r231_rules, (int)(sizeof(k_r231_rules) / sizeof(k_r231_rules[0])), NULL, 0, NULL,
};

TEST_STATE(g_r231);

/* intel_pack of the open alert under key, or -1 when there is none. */
static int r231_intel(const char *key) {
    for (int i = 0; i < g_r231.alert_count; i++)
        if (!strcmp(g_r231.alerts[i].key, key) && !g_r231.alerts[i].resolved)
            return g_r231.alerts[i].intel_pack;
    return -1;
}

static void test_engine_stage_marks_the_next_fire_only(void) {
    const alert_rule_table_t *was = alerts_table();
    alerts_clear();
    memset(&g_r231, 0, sizeof(g_r231));
    alerts_set_table(&k_r231_table);

    g_phase = 1;   /* staged by one rule, fired by the next: not its own */
    alerts_update(&g_r231);
    ASSERT_EQ(r231_intel("t231:plain"), 0);

    g_phase = 2;   /* staged, then dropped for an empty key */
    alerts_update(&g_r231);
    ASSERT_EQ(r231_intel("t231:after-drop"), 0);

    g_phase = 3;   /* the staged fire carries it, the rule's next does not */
    alerts_update(&g_r231);
    ASSERT_EQ(r231_intel("t231:staged"), 1);
    ASSERT_EQ(r231_intel("t231:second"), 0);

    g_phase = 4;   /* the same incident re-evaluated without a stage */
    alerts_update(&g_r231);
    ASSERT_EQ(r231_intel("t231:staged"), 0);

    g_phase = 0;   /* a stage alerts_clear() must not leave behind */
    fire_stage_intel();
    alerts_clear();
    memset(&g_r231, 0, sizeof(g_r231));
    alerts_update(&g_r231);
    ASSERT_EQ(r231_intel("t231:first"), 0);   /* the table's first fire */

    alerts_set_table(was);
    alerts_clear();
}

void run_intel_pack_tests(void) {
    TEST_SUITE("intel pack snapshot (#231)");
    RUN_TEST(test_engine_stage_marks_the_next_fire_only);
    RUN_TEST(test_lock_names_the_snapshot_the_build_reports);
    RUN_TEST(test_committed_snapshot_verifies);
    RUN_TEST(test_row_counts_are_pinned);
    RUN_TEST(test_sample_rows_are_pinned);
    RUN_TEST(test_reader_accepts_the_copy_and_a_rewritten_manifest);
    RUN_TEST(test_reader_refuses_what_its_manifest_does_not_hold);
    RUN_TEST(test_reader_refuses_a_malformed_manifest);
    RUN_TEST(test_reader_refuses_values_the_tables_cannot_hold);
    RUN_TEST(test_lock_parse);
}
