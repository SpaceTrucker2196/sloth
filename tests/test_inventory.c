/* Approved-inventory loader — #89 slice 2.
 *
 * The file is operator-supplied DATA. These tests are written from the
 * hostile-input side first: every malformed, mistyped, oversized,
 * duplicated and absent case has to fail with a reason and leave
 * nothing loaded, because a half-loaded inventory is worse than none —
 * the operator believes their APs are approved while the dropped half
 * alerts as rogue. */

#include "runner.h"
#include "inventory.h"
#include "ownership.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char tmp[] = "/tmp/sloth_inv_XXXXXX";
static int  tmp_made;

static void write_tmp(const char *body) {
    if (!tmp_made) {
        int fd = mkstemp(tmp);
        if (fd >= 0) close(fd);
        tmp_made = 1;
    }
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    fwrite(body, 1, strlen(body), f);
    fclose(f);
}

/* Load `body` from the scratch file. Returns inventory_load's result. */
static int load_body(const char *body, char *err, size_t errsz) {
    inventory_clear();
    ownership_clear();
    write_tmp(body);
    return inventory_load(tmp, err, errsz);
}

static const char *VALID =
    "{ \"version\": \"2026-09-24.1\",\n"
    "  \"site\": \"hq-3f\",\n"
    "  \"networks\": [\n"
    "    { \"ssid\": \"CorpWiFi\",\n"
    "      \"security_profile\": \"wpa2-enterprise\",\n"
    "      \"bssids\": [\"aa:bb:cc:00:11:22\", \"aa:bb:cc:00:11:23\"] } ] }\n";

/* A rejected file must leave the module in the unconfigured state, not
 * in whatever half-built state the parser reached. */
static void assert_nothing_loaded(void) {
    ASSERT_EQ(inventory_loaded(), 0);
    ASSERT_EQ(inventory_network_count(), 0);
    ASSERT_EQ(inventory_bssid_count(), 0);
    ASSERT_STR(inventory_hash(), "");
    ASSERT_STR(inventory_version(), "");
}

/* ── the happy path ──────────────────────────────────────── */

static void test_valid_file_loads(void) {
    char err[INV_ERR_MAX] = "";
    ASSERT_EQ(load_body(VALID, err, sizeof(err)), 1);
    ASSERT_STR(err, "");
    ASSERT_EQ(inventory_loaded(), 1);
    ASSERT_EQ(inventory_network_count(), 1);
    ASSERT_EQ(inventory_bssid_count(), 2);
    ASSERT_STR(inventory_version(), "2026-09-24.1");
    ASSERT_STR(inventory_site(), "hq-3f");
    ASSERT_STR(inventory_profile_for_ssid("CorpWiFi"), "wpa2-enterprise");
    ASSERT_STR(inventory_profile_for_ssid("Nope"), "");
}

/* Optional fields absent is a valid file, and nothing is invented to
 * fill them — an unset site stays unset (see inventory.h). */
static void test_version_and_site_are_optional(void) {
    char err[INV_ERR_MAX] = "";
    ASSERT_EQ(load_body("{\"networks\":[{\"ssid\":\"A\","
                        "\"bssids\":[\"aa:bb:cc:dd:ee:01\"]}]}",
                        err, sizeof(err)), 1);
    ASSERT_STR(inventory_version(), "");
    ASSERT_STR(inventory_site(), "");
    ASSERT_STR(inventory_profile_for_ssid("A"), "");
    ASSERT_EQ(inventory_bssid_count(), 1);
}

/* An empty network list is well-formed and means "I have declared
 * nothing": loaded, with no approved BSSIDs, so no SSID can mismatch. */
static void test_empty_networks_is_valid_and_anchors_nothing(void) {
    char err[INV_ERR_MAX] = "";
    uint8_t any[6] = {0xde,0xad,0xbe,0xef,0x00,0x01};
    ASSERT_EQ(load_body("{\"networks\":[]}", err, sizeof(err)), 1);
    ASSERT_EQ(inventory_loaded(), 1);
    ASSERT_EQ(inventory_network_count(), 0);
    ASSERT_EQ((int)inventory_verdict("CorpWiFi", any), (int)INV_NO_INVENTORY);
}

/* Unknown keys are ignored rather than rejected — same forward-compat
 * rule src/updater.c applies to the release manifest. */
static void test_unknown_keys_ignored(void) {
    char err[INV_ERR_MAX] = "";
    ASSERT_EQ(load_body("{\"networks\":[{\"ssid\":\"A\","
                        "\"bssids\":[\"aa:bb:cc:dd:ee:01\"],"
                        "\"vlan\":42,\"notes\":{\"by\":\"ops\"}}],"
                        "\"generated_by\":\"controller-export\"}",
                        err, sizeof(err)), 1);
    ASSERT_EQ(inventory_network_count(), 1);
}

/* Whitespace-only differences still change the hash (it is over bytes),
 * but must not change what was parsed. */
static void test_whitespace_tolerated(void) {
    char err[INV_ERR_MAX] = "";
    ASSERT_EQ(load_body("\n\t {  \"networks\" : [ { \"ssid\" : \"A\" , "
                        "\"bssids\" : [ \"aa:bb:cc:dd:ee:01\" ] } ] }  \n",
                        err, sizeof(err)), 1);
    ASSERT_EQ(inventory_bssid_count(), 1);
}

/* ── absent / unreadable ─────────────────────────────────── */

static void test_missing_file_fails_cleanly(void) {
    char err[INV_ERR_MAX] = "";
    inventory_clear();
    ASSERT_EQ(inventory_load("/tmp/sloth-inventory-does-not-exist-89",
                             err, sizeof(err)), 0);
    ASSERT(err[0] != '\0');
    ASSERT(strstr(err, "/tmp/sloth-inventory-does-not-exist-89") != NULL);
    assert_nothing_loaded();
}

static void test_null_and_empty_path_fail(void) {
    char err[INV_ERR_MAX] = "";
    inventory_clear();
    ASSERT_EQ(inventory_load(NULL, err, sizeof(err)), 0);
    ASSERT_EQ(inventory_load("",   err, sizeof(err)), 0);
    assert_nothing_loaded();
}

/* err may be NULL — a caller that only wants the verdict must not
 * crash. */
static void test_null_err_buffer_is_safe(void) {
    inventory_clear();
    ASSERT_EQ(inventory_load("/tmp/sloth-inventory-does-not-exist-89",
                             NULL, 0), 0);
    assert_nothing_loaded();
}

static void test_empty_file_fails(void) {
    char err[INV_ERR_MAX] = "";
    ASSERT_EQ(load_body("", err, sizeof(err)), 0);
    ASSERT(err[0] != '\0');
    assert_nothing_loaded();
}

/* ── malformed JSON ──────────────────────────────────────── */

static void test_malformed_json_fails(void) {
    char err[INV_ERR_MAX];
    const char *bad[] = {
        "{",                                            /* truncated object */
        "{\"networks\":[",                              /* truncated array */
        "{\"networks\":[{\"ssid\":\"A\"",               /* truncated member */
        "{\"networks\":[]} trailing",                   /* trailing content */
        "{\"networks\":[]}{\"networks\":[]}",           /* two documents */
        "[{\"ssid\":\"A\"}]",                           /* top level not object */
        "\"just a string\"",
        "{\"networks\":[],}",                           /* trailing comma */
        "{,\"networks\":[]}",
        "{\"networks\" [] }",                           /* missing colon */
        "{networks:[]}",                                /* unquoted key */
        "{\"networks\":[{\"ssid\":\"unterminated}]}",   /* unterminated string */
        "{\"networks\":[{\"ssid\":\"A\",}]}",
        "{\"networks\":[,]}",
        "{\"networks\":[]",                             /* missing brace */
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        err[0] = '\0';
        ASSERT_EQ(load_body(bad[i], err, sizeof(err)), 0);
        ASSERT(err[0] != '\0');
        assert_nothing_loaded();
    }
}

/* An escape sloth does not implement is refused, not silently mangled.
 * \u would need UTF-8 transcoding for a field that carries opaque
 * 802.11 octets; half-implementing it would store the wrong SSID and
 * then fail to match the operator's own AP. */
static void test_unsupported_escape_rejected(void) {
    char err[INV_ERR_MAX] = "";
    ASSERT_EQ(load_body("{\"networks\":[{\"ssid\":\"A\\u0041\","
                        "\"bssids\":[\"aa:bb:cc:dd:ee:01\"]}]}",
                        err, sizeof(err)), 0);
    ASSERT(err[0] != '\0');
    assert_nothing_loaded();

    ASSERT_EQ(load_body("{\"networks\":[{\"ssid\":\"A\\q\","
                        "\"bssids\":[\"aa:bb:cc:dd:ee:01\"]}]}",
                        err, sizeof(err)), 0);
    assert_nothing_loaded();
}

/* The escapes that are implemented round-trip into the stored SSID. */
static void test_supported_escapes_decode(void) {
    char err[INV_ERR_MAX] = "";
    uint8_t m[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0x01};
    ASSERT_EQ(load_body("{\"networks\":[{\"ssid\":\"a\\\"b\\\\c\\/d\","
                        "\"bssids\":[\"aa:bb:cc:dd:ee:01\"]}]}",
                        err, sizeof(err)), 1);
    ASSERT_EQ((int)inventory_verdict("a\"b\\c/d", m), (int)INV_APPROVED);
}

/* A nesting bomb must hit a depth cap, not the C stack. */
static void test_deep_nesting_rejected(void) {
    char body[4096];
    char err[INV_ERR_MAX] = "";
    size_t off = 0;
    off += (size_t)snprintf(body + off, sizeof(body) - off, "{\"networks\":");
    for (int i = 0; i < 200; i++) body[off++] = '[';
    for (int i = 0; i < 200; i++) body[off++] = ']';
    body[off++] = '}';
    body[off]   = '\0';
    ASSERT_EQ(load_body(body, err, sizeof(err)), 0);
    ASSERT(err[0] != '\0');
    assert_nothing_loaded();
}

/* ── wrong types ─────────────────────────────────────────── */

static void test_wrong_types_fail(void) {
    char err[INV_ERR_MAX];
    const char *bad[] = {
        "{\"networks\":\"CorpWiFi\"}",                       /* not an array */
        "{\"networks\":{}}",
        "{\"networks\":42}",
        "{\"networks\":null}",
        "{\"networks\":[\"CorpWiFi\"]}",                     /* member not object */
        "{\"networks\":[[]]}",
        "{\"networks\":[{\"ssid\":42,\"bssids\":[\"aa:bb:cc:dd:ee:01\"]}]}",
        "{\"networks\":[{\"ssid\":null,\"bssids\":[\"aa:bb:cc:dd:ee:01\"]}]}",
        "{\"networks\":[{\"ssid\":\"A\",\"bssids\":\"aa:bb:cc:dd:ee:01\"}]}",
        "{\"networks\":[{\"ssid\":\"A\",\"bssids\":[42]}]}",
        "{\"networks\":[{\"ssid\":\"A\",\"bssids\":[[\"aa:bb:cc:dd:ee:01\"]]}]}",
        "{\"networks\":[{\"ssid\":\"A\",\"bssids\":{}}]}",
        "{\"networks\":[{\"ssid\":\"A\",\"bssids\":[\"aa:bb:cc:dd:ee:01\"],"
            "\"security_profile\":7}]}",
        "{\"version\":7,\"networks\":[]}",
        "{\"site\":[],\"networks\":[]}",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        err[0] = '\0';
        ASSERT_EQ(load_body(bad[i], err, sizeof(err)), 0);
        ASSERT(err[0] != '\0');
        assert_nothing_loaded();
    }
}

/* ── required fields ─────────────────────────────────────── */

static void test_missing_required_fields_fail(void) {
    char err[INV_ERR_MAX];
    const char *bad[] = {
        "{\"site\":\"hq\"}",                                  /* no networks */
        "{\"networks\":[{\"bssids\":[\"aa:bb:cc:dd:ee:01\"]}]}",  /* no ssid */
        "{\"networks\":[{\"ssid\":\"A\"}]}",                   /* no bssids */
        "{\"networks\":[{\"ssid\":\"\",\"bssids\":[\"aa:bb:cc:dd:ee:01\"]}]}",
        "{\"networks\":[{\"ssid\":\"A\",\"bssids\":[]}]}",     /* empty set */
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        err[0] = '\0';
        ASSERT_EQ(load_body(bad[i], err, sizeof(err)), 0);
        ASSERT(err[0] != '\0');
        assert_nothing_loaded();
    }
}

/* A duplicate key at one level is ambiguous — which site did the
 * operator mean? Refused rather than picking one. */
static void test_duplicate_keys_rejected(void) {
    char err[INV_ERR_MAX] = "";
    ASSERT_EQ(load_body("{\"site\":\"a\",\"site\":\"b\",\"networks\":[]}",
                        err, sizeof(err)), 0);
    assert_nothing_loaded();
    ASSERT_EQ(load_body("{\"networks\":[{\"ssid\":\"A\",\"ssid\":\"B\","
                        "\"bssids\":[\"aa:bb:cc:dd:ee:01\"]}]}",
                        err, sizeof(err)), 0);
    assert_nothing_loaded();
}

/* ── malformed / duplicate BSSIDs ────────────────────────── */

static void test_bad_bssid_rejected(void) {
    char err[INV_ERR_MAX];
    const char *bad[] = {
        "not-a-mac",
        "aa:bb:cc:dd:ee",
        "aa:bb:cc:dd:ee:ff:00",
        "aabbccddeeff",
        "gg:bb:cc:dd:ee:ff",
        "aa.bb.cc.dd.ee.ff",
        "",
    };
    char body[256];
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        snprintf(body, sizeof(body),
                 "{\"networks\":[{\"ssid\":\"A\",\"bssids\":[\"%s\"]}]}",
                 bad[i]);
        err[0] = '\0';
        ASSERT_EQ(load_body(body, err, sizeof(err)), 0);
        ASSERT(err[0] != '\0');
        assert_nothing_loaded();
    }
}

/* Upper case and '-' separators are the same address, and must not
 * sneak past the duplicate check by being spelled differently. */
static void test_bssid_case_and_separator_normalised(void) {
    char err[INV_ERR_MAX] = "";
    uint8_t m[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0x01};
    ASSERT_EQ(load_body("{\"networks\":[{\"ssid\":\"A\","
                        "\"bssids\":[\"AA-BB-CC-DD-EE-01\"]}]}",
                        err, sizeof(err)), 1);
    ASSERT_EQ((int)inventory_verdict("A", m), (int)INV_APPROVED);

    ASSERT_EQ(load_body("{\"networks\":[{\"ssid\":\"A\","
                        "\"bssids\":[\"aa:bb:cc:dd:ee:01\","
                        "\"AA-BB-CC-DD-EE-01\"]}]}",
                        err, sizeof(err)), 0);
    assert_nothing_loaded();
}

/* One BSSID may serve exactly one declared SSID. The same address
 * listed twice — in one entry or across two — is a contradiction in the
 * operator's own file, so it is refused rather than resolved. */
static void test_duplicate_bssid_rejected(void) {
    char err[INV_ERR_MAX] = "";
    ASSERT_EQ(load_body("{\"networks\":[{\"ssid\":\"A\","
                        "\"bssids\":[\"aa:bb:cc:dd:ee:01\","
                        "\"aa:bb:cc:dd:ee:01\"]}]}",
                        err, sizeof(err)), 0);
    ASSERT(err[0] != '\0');
    assert_nothing_loaded();

    ASSERT_EQ(load_body("{\"networks\":["
                        "{\"ssid\":\"A\",\"bssids\":[\"aa:bb:cc:dd:ee:01\"]},"
                        "{\"ssid\":\"B\",\"bssids\":[\"aa:bb:cc:dd:ee:01\"]}]}",
                        err, sizeof(err)), 0);
    assert_nothing_loaded();
}

static void test_duplicate_ssid_rejected(void) {
    char err[INV_ERR_MAX] = "";
    ASSERT_EQ(load_body("{\"networks\":["
                        "{\"ssid\":\"A\",\"bssids\":[\"aa:bb:cc:dd:ee:01\"]},"
                        "{\"ssid\":\"A\",\"bssids\":[\"aa:bb:cc:dd:ee:02\"]}]}",
                        err, sizeof(err)), 0);
    ASSERT(err[0] != '\0');
    assert_nothing_loaded();
}

/* ── absurd sizes ────────────────────────────────────────── */

static void test_oversized_file_rejected(void) {
    char err[INV_ERR_MAX] = "";
    size_t n = INV_FILE_MAX + 1024;
    char *body = malloc(n + 1);
    ASSERT(body != NULL);
    if (!body) return;
    memset(body, ' ', n);
    memcpy(body, "{\"networks\":[]}", 15);
    body[n] = '\0';
    ASSERT_EQ(load_body(body, err, sizeof(err)), 0);
    ASSERT(err[0] != '\0');
    assert_nothing_loaded();
    free(body);
}

static void test_too_many_networks_rejected(void) {
    char err[INV_ERR_MAX] = "";
    char *body = malloc(64 * 1024);
    ASSERT(body != NULL);
    if (!body) return;
    size_t off = 0;
    off += (size_t)snprintf(body + off, 64 * 1024 - off, "{\"networks\":[");
    for (int i = 0; i <= INV_MAX_NETWORKS; i++)
        off += (size_t)snprintf(body + off, 64 * 1024 - off,
                                "%s{\"ssid\":\"N%d\",\"bssids\":"
                                "[\"aa:bb:%02x:%02x:ee:01\"]}",
                                i ? "," : "", i, (i >> 8) & 0xff, i & 0xff);
    snprintf(body + off, 64 * 1024 - off, "]}");
    ASSERT_EQ(load_body(body, err, sizeof(err)), 0);
    ASSERT(err[0] != '\0');
    assert_nothing_loaded();
    free(body);
}

static void test_too_many_bssids_rejected(void) {
    char err[INV_ERR_MAX] = "";
    char *body = malloc(64 * 1024);
    ASSERT(body != NULL);
    if (!body) return;
    size_t off = 0;
    off += (size_t)snprintf(body + off, 64 * 1024 - off,
                            "{\"networks\":[{\"ssid\":\"A\",\"bssids\":[");
    for (int i = 0; i <= INV_MAX_BSSIDS; i++)
        off += (size_t)snprintf(body + off, 64 * 1024 - off,
                                "%s\"aa:bb:cc:%02x:%02x:01\"",
                                i ? "," : "", (i >> 8) & 0xff, i & 0xff);
    snprintf(body + off, 64 * 1024 - off, "]}]}");
    ASSERT_EQ(load_body(body, err, sizeof(err)), 0);
    ASSERT(err[0] != '\0');
    assert_nothing_loaded();
    free(body);
}

static void test_overlong_strings_rejected(void) {
    char err[INV_ERR_MAX];
    char body[512];
    char big[128];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';

    snprintf(body, sizeof(body), "{\"networks\":[{\"ssid\":\"%s\","
             "\"bssids\":[\"aa:bb:cc:dd:ee:01\"]}]}", big);   /* SSID > 32 */
    err[0] = '\0';
    ASSERT_EQ(load_body(body, err, sizeof(err)), 0);
    assert_nothing_loaded();

    snprintf(body, sizeof(body), "{\"site\":\"%s\",\"networks\":[]}", big);
    err[0] = '\0';
    ASSERT_EQ(load_body(body, err, sizeof(err)), 0);
    assert_nothing_loaded();

    snprintf(body, sizeof(body), "{\"version\":\"%s\",\"networks\":[]}", big);
    err[0] = '\0';
    ASSERT_EQ(load_body(body, err, sizeof(err)), 0);
    assert_nothing_loaded();

    snprintf(body, sizeof(body), "{\"networks\":[{\"ssid\":\"A\","
             "\"security_profile\":\"%s\","
             "\"bssids\":[\"aa:bb:cc:dd:ee:01\"]}]}", big);
    err[0] = '\0';
    ASSERT_EQ(load_body(body, err, sizeof(err)), 0);
    assert_nothing_loaded();
}

/* A NUL ends the document early for a C parser, so everything after it
 * would never be read — a silent partial load by another name. */
static void test_nul_byte_in_file_rejected(void) {
    char err[INV_ERR_MAX] = "";
    static const char body[] = "{\"networks\":[]}\0{\"networks\":[]}";
    inventory_clear();
    ownership_clear();
    if (!tmp_made) { int fd = mkstemp(tmp); if (fd >= 0) close(fd); tmp_made = 1; }
    FILE *f = fopen(tmp, "w");
    ASSERT(f != NULL);
    if (!f) return;
    fwrite(body, 1, sizeof(body) - 1, f);
    fclose(f);
    ASSERT_EQ(inventory_load(tmp, err, sizeof(err)), 0);
    ASSERT(err[0] != '\0');
    assert_nothing_loaded();
}

/* A control byte would corrupt the alert detail line and the JSONL
 * record it is copied into. Refused at the boundary. */
static void test_control_characters_rejected(void) {
    char err[INV_ERR_MAX] = "";
    ASSERT_EQ(load_body("{\"networks\":[{\"ssid\":\"A\\nB\","
                        "\"bssids\":[\"aa:bb:cc:dd:ee:01\"]}]}",
                        err, sizeof(err)), 0);
    assert_nothing_loaded();
    /* ...and raw, unescaped, which JSON forbids anyway. */
    ASSERT_EQ(load_body("{\"networks\":[{\"ssid\":\"A\nB\","
                        "\"bssids\":[\"aa:bb:cc:dd:ee:01\"]}]}",
                        err, sizeof(err)), 0);
    assert_nothing_loaded();
}

/* ':' separates fields in the canonical pair key, so a site carrying
 * one would make the key ambiguous. */
static void test_site_with_colon_rejected(void) {
    char err[INV_ERR_MAX] = "";
    ASSERT_EQ(load_body("{\"site\":\"hq:3f\",\"networks\":[]}",
                        err, sizeof(err)), 0);
    assert_nothing_loaded();
    inventory_clear();
    ASSERT_EQ(inventory_set_site("hq:3f"), 0);
    ASSERT_STR(inventory_site(), "");
}

/* ── all-or-nothing ──────────────────────────────────────── */

/* The defining property: a file whose first network is perfectly good
 * and whose second is broken loads NOTHING. Anything else leaves the
 * operator with an inventory they did not write. */
static void test_partial_file_loads_nothing(void) {
    char err[INV_ERR_MAX] = "";
    uint8_t good[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0x01};
    ASSERT_EQ(load_body("{\"networks\":["
                        "{\"ssid\":\"Good\",\"bssids\":[\"aa:bb:cc:dd:ee:01\"]},"
                        "{\"ssid\":\"Bad\",\"bssids\":[\"nonsense\"]}]}",
                        err, sizeof(err)), 0);
    assert_nothing_loaded();
    ASSERT_EQ((int)inventory_verdict("Good", good), (int)INV_NO_INVENTORY);
}

/* A failed load must not tear down an inventory that was already
 * valid — the previous anchor stays in force. */
static void test_failed_load_leaves_previous_inventory(void) {
    char err[INV_ERR_MAX] = "";
    uint8_t m[6] = {0xaa,0xbb,0xcc,0x00,0x11,0x22};
    ASSERT_EQ(load_body(VALID, err, sizeof(err)), 1);
    char first_hash[INV_HASH_LEN];
    snprintf(first_hash, sizeof(first_hash), "%s", inventory_hash());

    write_tmp("{\"networks\":[{\"ssid\":");     /* truncated */
    ASSERT_EQ(inventory_load(tmp, err, sizeof(err)), 0);
    ASSERT_EQ(inventory_loaded(), 1);
    ASSERT_EQ(inventory_network_count(), 1);
    ASSERT_STR(inventory_hash(), first_hash);
    ASSERT_EQ((int)inventory_verdict("CorpWiFi", m), (int)INV_APPROVED);
}

/* ── content hash ────────────────────────────────────────── */

static void test_hash_is_content_derived(void) {
    char err[INV_ERR_MAX] = "";
    char h1[INV_HASH_LEN], h2[INV_HASH_LEN];

    ASSERT_EQ(load_body(VALID, err, sizeof(err)), 1);
    snprintf(h1, sizeof(h1), "%s", inventory_hash());
    ASSERT_EQ((int)strlen(h1), INV_HASH_LEN - 1);
    for (int i = 0; h1[i]; i++)
        ASSERT((h1[i] >= '0' && h1[i] <= '9') ||
               (h1[i] >= 'a' && h1[i] <= 'f'));

    /* Same bytes → same hash. */
    ASSERT_EQ(load_body(VALID, err, sizeof(err)), 1);
    ASSERT_STR(inventory_hash(), h1);

    /* One changed BSSID octet → different hash, same `version` label.
     * That is the whole point of hashing the content: the label is what
     * a human typed, the hash is what sloth actually read. */
    ASSERT_EQ(load_body(
        "{ \"version\": \"2026-09-24.1\",\n"
        "  \"site\": \"hq-3f\",\n"
        "  \"networks\": [\n"
        "    { \"ssid\": \"CorpWiFi\",\n"
        "      \"security_profile\": \"wpa2-enterprise\",\n"
        "      \"bssids\": [\"aa:bb:cc:00:11:22\", \"aa:bb:cc:00:11:99\"] } ] }\n",
        err, sizeof(err)), 1);
    snprintf(h2, sizeof(h2), "%s", inventory_hash());
    ASSERT_STR(inventory_version(), "2026-09-24.1");
    ASSERT(strcmp(h1, h2) != 0);

    /* Byte-level: a whitespace-only edit is a different file. */
    ASSERT_EQ(load_body("{\"networks\":[]}",  err, sizeof(err)), 1);
    snprintf(h1, sizeof(h1), "%s", inventory_hash());
    ASSERT_EQ(load_body("{\"networks\":[]} ", err, sizeof(err)), 1);
    ASSERT(strcmp(h1, inventory_hash()) != 0);
}

/* ── site precedence ─────────────────────────────────────── */

/* --site beats the file's `site`, whichever order they are applied in:
 * the flag is the operator's most immediate statement, and argv order
 * against file reads must not change the canonical pair key. */
static void test_site_flag_overrides_file_either_order(void) {
    char err[INV_ERR_MAX] = "";
    ASSERT_EQ(load_body(VALID, err, sizeof(err)), 1);
    ASSERT_STR(inventory_site(), "hq-3f");
    ASSERT_EQ(inventory_set_site("dc-1"), 1);
    ASSERT_STR(inventory_site(), "dc-1");

    /* Flag first, then the file. */
    inventory_clear();
    ownership_clear();
    ASSERT_EQ(inventory_set_site("dc-1"), 1);
    write_tmp(VALID);
    ASSERT_EQ(inventory_load(tmp, err, sizeof(err)), 1);
    ASSERT_STR(inventory_site(), "dc-1");
}

static void test_site_flag_validation(void) {
    inventory_clear();
    ASSERT_EQ(inventory_set_site(NULL), 0);
    ASSERT_EQ(inventory_set_site(""),   0);
    char big[INV_SITE_LEN + 8];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    ASSERT_EQ(inventory_set_site(big), 0);
    ASSERT_STR(inventory_site(), "");
    ASSERT_EQ(inventory_set_site("hq-3f"), 1);
    ASSERT_STR(inventory_site(), "hq-3f");
    /* --site alone is a label, not an inventory. */
    ASSERT_EQ(inventory_loaded(), 0);
}

/* ── verdicts and the flag merge ─────────────────────────── */

static void test_verdicts(void) {
    char err[INV_ERR_MAX] = "";
    uint8_t approved[6] = {0xaa,0xbb,0xcc,0x00,0x11,0x22};
    uint8_t rogue[6]    = {0xaa,0xbb,0xcc,0x00,0x11,0x77};
    ASSERT_EQ(load_body(VALID, err, sizeof(err)), 1);

    ASSERT_EQ((int)inventory_verdict("CorpWiFi", approved), (int)INV_APPROVED);
    /* Same OUI, not in the approved set — a clone gets no credit for
     * copying three bytes. */
    ASSERT_EQ((int)inventory_verdict("CorpWiFi", rogue),    (int)INV_MISMATCH);
    /* Silence about an SSID is not approval of it. */
    ASSERT_EQ((int)inventory_verdict("Guest", approved), (int)INV_NO_INVENTORY);
    ASSERT_EQ((int)inventory_verdict(NULL, approved),    (int)INV_NO_INVENTORY);
    ASSERT_EQ((int)inventory_verdict("CorpWiFi", NULL),  (int)INV_NO_INVENTORY);
}

static void test_unconfigured_says_nothing(void) {
    uint8_t any[6] = {0xaa,0xbb,0xcc,0x00,0x11,0x22};
    inventory_clear();
    ASSERT_EQ(inventory_loaded(), 0);
    ASSERT_EQ((int)inventory_verdict("CorpWiFi", any), (int)INV_NO_INVENTORY);
    ASSERT_STR(inventory_hash(), "");
    ASSERT_STR(inventory_site(), "");
}

/* The documented merge: --my-bssid is unioned into the approved set,
 * never intersected with it. An operator adding a flag must not be able
 * to manufacture a rogue out of their own AP. */
static void test_my_bssid_flag_unions_with_file(void) {
    char err[INV_ERR_MAX] = "";
    uint8_t flagged[6]  = {0x11,0x22,0x33,0x44,0x55,0x66};
    uint8_t approved[6] = {0xaa,0xbb,0xcc,0x00,0x11,0x22};

    ASSERT_EQ(load_body(VALID, err, sizeof(err)), 1);
    /* Before the flag: not in the file, so it is a mismatch. */
    ASSERT_EQ((int)inventory_verdict("CorpWiFi", flagged), (int)INV_MISMATCH);
    ASSERT_EQ(ownership_add_bssid("11:22:33:44:55:66"), 1);
    ASSERT_EQ((int)inventory_verdict("CorpWiFi", flagged), (int)INV_APPROVED);
    /* ...and the file's own entries are untouched by the flag. */
    ASSERT_EQ((int)inventory_verdict("CorpWiFi", approved), (int)INV_APPROVED);
}

/* --my-ssid names a network as ours; it does not enumerate which radios
 * may serve it, so it cannot produce a mismatch on its own. */
static void test_my_ssid_flag_alone_is_no_anchor(void) {
    uint8_t any[6] = {0xde,0xad,0xbe,0xef,0x00,0x01};
    inventory_clear();
    ownership_clear();
    ASSERT_EQ(ownership_add_ssid("CorpWiFi"), 1);
    ASSERT_EQ((int)inventory_verdict("CorpWiFi", any), (int)INV_NO_INVENTORY);

    /* And with a file loaded that does not list it, still nothing. */
    char err[INV_ERR_MAX] = "";
    write_tmp("{\"networks\":[{\"ssid\":\"Other\","
              "\"bssids\":[\"aa:bb:cc:dd:ee:01\"]}]}");
    ASSERT_EQ(inventory_load(tmp, err, sizeof(err)), 1);
    ASSERT_EQ((int)inventory_verdict("CorpWiFi", any), (int)INV_NO_INVENTORY);
}

/* SSID comparison is exact and case-sensitive — 802.11 SSIDs are opaque
 * octet strings and two that differ in case are two networks. Same rule
 * ownership_is_my_ssid already follows. */
static void test_ssid_match_is_case_sensitive(void) {
    char err[INV_ERR_MAX] = "";
    uint8_t m[6] = {0xaa,0xbb,0xcc,0x00,0x11,0x22};
    ASSERT_EQ(load_body(VALID, err, sizeof(err)), 1);
    ASSERT_EQ((int)inventory_verdict("corpwifi", m), (int)INV_NO_INVENTORY);
    ASSERT_EQ((int)inventory_verdict("CORPWIFI", m), (int)INV_NO_INVENTORY);
}

static void test_clear_resets_everything(void) {
    char err[INV_ERR_MAX] = "";
    ASSERT_EQ(load_body(VALID, err, sizeof(err)), 1);
    ASSERT_EQ(inventory_set_site("dc-1"), 1);
    inventory_clear();
    assert_nothing_loaded();
    ASSERT_STR(inventory_site(), "");
}

void run_inventory_tests(void);
void run_inventory_tests(void) {
    TEST_SUITE("approved inventory (#89)");
    RUN_TEST(test_valid_file_loads);
    RUN_TEST(test_version_and_site_are_optional);
    RUN_TEST(test_empty_networks_is_valid_and_anchors_nothing);
    RUN_TEST(test_unknown_keys_ignored);
    RUN_TEST(test_whitespace_tolerated);
    RUN_TEST(test_missing_file_fails_cleanly);
    RUN_TEST(test_null_and_empty_path_fail);
    RUN_TEST(test_null_err_buffer_is_safe);
    RUN_TEST(test_empty_file_fails);
    RUN_TEST(test_malformed_json_fails);
    RUN_TEST(test_unsupported_escape_rejected);
    RUN_TEST(test_supported_escapes_decode);
    RUN_TEST(test_deep_nesting_rejected);
    RUN_TEST(test_wrong_types_fail);
    RUN_TEST(test_missing_required_fields_fail);
    RUN_TEST(test_duplicate_keys_rejected);
    RUN_TEST(test_bad_bssid_rejected);
    RUN_TEST(test_bssid_case_and_separator_normalised);
    RUN_TEST(test_duplicate_bssid_rejected);
    RUN_TEST(test_duplicate_ssid_rejected);
    RUN_TEST(test_oversized_file_rejected);
    RUN_TEST(test_too_many_networks_rejected);
    RUN_TEST(test_too_many_bssids_rejected);
    RUN_TEST(test_overlong_strings_rejected);
    RUN_TEST(test_nul_byte_in_file_rejected);
    RUN_TEST(test_control_characters_rejected);
    RUN_TEST(test_site_with_colon_rejected);
    RUN_TEST(test_partial_file_loads_nothing);
    RUN_TEST(test_failed_load_leaves_previous_inventory);
    RUN_TEST(test_hash_is_content_derived);
    RUN_TEST(test_site_flag_overrides_file_either_order);
    RUN_TEST(test_site_flag_validation);
    RUN_TEST(test_verdicts);
    RUN_TEST(test_unconfigured_says_nothing);
    RUN_TEST(test_my_bssid_flag_unions_with_file);
    RUN_TEST(test_my_ssid_flag_alone_is_no_anchor);
    RUN_TEST(test_ssid_match_is_case_sensitive);
    RUN_TEST(test_clear_resets_everything);
    inventory_clear();
    ownership_clear();
    unlink(tmp);
}
