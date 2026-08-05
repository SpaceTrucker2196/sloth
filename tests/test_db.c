/* Embedded SQLite sink (#42).
 *
 * These run against a real SQLite file in /tmp, not a mock — per the
 * repo rule about not mocking real-data interfaces. The sink's whole
 * value is that the rows are queryable afterwards, so the tests query
 * them back with SQL, which is also how the operator will. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>

#include "runner.h"
#include "sloth.h"
#include "db.h"
#include "presence.h"
#include "beacon_snoop.h"

static char db_path[] = "/tmp/sloth_db_XXXXXX";

static void fresh_db(void) {
    db_close();
    if (db_path[strlen(db_path) - 1] == 'X') {
        int fd = mkstemp(db_path);
        if (fd >= 0) close(fd);
    }
    unlink(db_path);
    ASSERT_EQ(db_open(db_path), 1);
}

/* Run a scalar integer query against the sink's file. -1 on any error,
 * which shows up as a failed assertion rather than a silent pass. */
static long long q_int(const char *sql) {
    sqlite3 *h = NULL;
    if (sqlite3_open(db_path, &h) != SQLITE_OK) { sqlite3_close(h); return -1; }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) != SQLITE_OK) {
        sqlite3_close(h);
        return -1;
    }
    long long v = -1;
    if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    sqlite3_close(h);
    return v;
}

static void q_text(const char *sql, char *out, size_t sz) {
    out[0] = '\0';
    sqlite3 *h = NULL;
    if (sqlite3_open(db_path, &h) != SQLITE_OK) { sqlite3_close(h); return; }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *t = sqlite3_column_text(st, 0);
        if (t) snprintf(out, sz, "%s", (const char *)t);
    }
    sqlite3_finalize(st);
    sqlite3_close(h);
}

/* Raw byte scan of the database file. Used by the MISSION §2 test to
 * assert a secret never reaches disk by any path, not merely that no
 * column is declared for it. */
static int file_contains(const char *path, const char *needle) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    static char buf[1 << 20];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    size_t nl = strlen(needle);
    if (nl == 0 || n < nl) return 0;
    for (size_t i = 0; i + nl <= n; i++)
        if (memcmp(buf + i, needle, nl) == 0) return 1;
    return 0;
}

/* ── MISSION §2 schema guardrails ────────────────────────── *
 *
 * These assert on the DDL text and need no SQLite at all. They are the
 * enforcement mechanism for the rules in #42: a future column addition
 * that violates one turns the suite red instead of relying on a
 * reviewer spotting it in a diff. */

/* The rule is not "the string never appears" — `has_pmkid` and
 * `pw_observed` are 0/1 flags recording that an exposure was observed,
 * which is the finding and belongs in the file. The rule is that no
 * column can *hold* the material: nothing named for a secret may be
 * TEXT or BLOB. Checked against the live schema so it covers every
 * table, including ones added later. */
static void test_no_column_can_hold_secret_material(void) {
    fresh_db();
    static const char *const forbidden[] = {
        "%pmkid%", "%nonce%", "%mic%", "%password%", "%passwd%",
        "%community%", "%secret%", "%key_material%",
    };
    for (unsigned i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++) {
        char sql[512];
        snprintf(sql, sizeof(sql),
            "SELECT COUNT(*) FROM sqlite_master m,"
            " pragma_table_info(m.name) c"
            " WHERE m.type='table' AND c.name LIKE '%s'"
            " AND UPPER(c.type) IN ('TEXT','BLOB')", forbidden[i]);
        ASSERT_EQ(q_int(sql), 0);
    }
    /* And the flags we *do* keep are integers, so the above is passing
     * because the types are right, not because the columns are absent. */
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM pragma_table_info('eapol_events')"
                    " WHERE name='has_pmkid' AND UPPER(type)='INTEGER'"), 1);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM pragma_table_info('cleartext_creds')"
                    " WHERE name='pw_observed' AND UPPER(type)='INTEGER'"), 1);
    db_close();
    unlink(db_path);
}

/* No column is named exactly for a secret either, whatever its type. */
static void test_schema_has_no_secret_named_columns(void) {
    const char *sql = db_schema_sql();
    ASSERT(sql != NULL);
    ASSERT(strstr(sql, "  password ") == NULL);
    ASSERT(strstr(sql, "  passwd ")   == NULL);
    ASSERT(strstr(sql, "  pmkid ")    == NULL);
    ASSERT(strstr(sql, "  anonce ")   == NULL);
    ASSERT(strstr(sql, "  snonce ")   == NULL);
    ASSERT(strstr(sql, "  mic ")      == NULL);
}

/* The strongest form of the claim: seed an EAPOL event carrying real
 * key material and assert none of it reaches the file. A schema
 * assertion cannot catch a leak through a future column, an index, or
 * a stray bind — scanning the bytes can. */
static void test_eapol_key_material_never_reaches_disk(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    eapol_event_t *e = &s.eapol_events[s.eapol_count++];
    memset(e, 0, sizeof(*e));
    e->bssid[0] = 0xaa; e->bssid[5] = 0x01;
    e->sta_mac[0] = 0x02; e->sta_mac[5] = 0x99;
    snprintf(e->ssid, sizeof(e->ssid), "CorpWiFi");
    e->ts        = 1700000000;
    e->msg_num   = 1;
    e->has_pmkid = 1;
    e->handshake_complete = 1;
    /* Recognisable ASCII in the key fields: if any of these buffers is
     * ever bound, the bytes show up in the file verbatim. */
    memcpy(e->pmkid,  "PMKIDLEAK1234567", 16);
    memcpy(e->anonce, "ANONCELEAK-0123456789abcdef01234", 32);
    memcpy(e->snonce, "SNONCELEAK-0123456789abcdef01234", 32);
    memcpy(e->mic,    "MICLEAK123456789", 16);
    db_tick(&s, 1700000000);

    /* The findings survive — that is the operational value. */
    ASSERT_EQ(q_int("SELECT has_pmkid FROM eapol_events"), 1);
    ASSERT_EQ(q_int("SELECT handshake_complete FROM eapol_events"), 1);
    db_close();

    ASSERT_EQ(file_contains(db_path, "PMKIDLEAK1234567"), 0);
    ASSERT_EQ(file_contains(db_path, "ANONCELEAK"), 0);
    ASSERT_EQ(file_contains(db_path, "SNONCELEAK"), 0);
    ASSERT_EQ(file_contains(db_path, "MICLEAK123456789"), 0);
    /* Control: the SSID we DO persist is found by the same scan. */
    ASSERT_EQ(file_contains(db_path, "CorpWiFi"), 1);
    unlink(db_path);
}

/* Every entity table carries the pair that makes the file a history
 * rather than a snapshot. Walks each CREATE TABLE body so a new table
 * that forgets them is caught, whatever its column formatting. */
static void test_schema_tables_have_seen_columns(void) {
    const char *sql = db_schema_sql();
    /* Tables that describe the file itself rather than something
     * observed. Named explicitly so adding an entity table without the
     * columns fails, while adding bookkeeping is a deliberate edit
     * here — a bare "tables - N" would silently absorb the mistake. */
    static const char *const exempt[] = { "meta (", "sessions (" };

    int tables = 0, entities = 0, with_both = 0;
    for (const char *p = strstr(sql, "CREATE TABLE"); p;
         p = strstr(p + 1, "CREATE TABLE")) {
        const char *end = strstr(p, ");");
        if (!end) break;
        tables++;

        int is_exempt = 0;
        for (unsigned e = 0; e < sizeof(exempt) / sizeof(exempt[0]); e++) {
            const char *hit = strstr(p, exempt[e]);
            if (hit && hit < end) { is_exempt = 1; break; }
        }
        if (is_exempt) continue;

        entities++;
        const char *f = strstr(p, "first_seen");
        const char *l = strstr(p, "last_seen");
        if (f && f < end && l && l < end) with_both++;
    }
    ASSERT(tables > 15);
    ASSERT(entities > 15);
    ASSERT_EQ(with_both, entities);
}

/* ── open / close / versioning ───────────────────────────── */

static void test_open_creates_and_stamps_version(void) {
    fresh_db();
    ASSERT_EQ(db_is_open(), 1);
    char v[32];
    q_text("SELECT value FROM meta WHERE key='schema_version'", v, sizeof(v));
    ASSERT_EQ(atoi(v), DB_SCHEMA_VERSION);
    db_close();
    ASSERT_EQ(db_is_open(), 0);
}

static void test_reopen_is_idempotent(void) {
    fresh_db();
    db_close();
    ASSERT_EQ(db_open(db_path), 1);   /* existing file, same version */
    ASSERT_EQ(db_is_open(), 1);
    db_close();
    unlink(db_path);
}

/* A file written by a newer sloth must be refused, not written into
 * with rows its readers would misinterpret. */
static void test_open_refuses_foreign_schema_version(void) {
    fresh_db();
    db_close();
    sqlite3 *h = NULL;
    ASSERT_EQ(sqlite3_open(db_path, &h), SQLITE_OK);
    sqlite3_exec(h, "UPDATE meta SET value='99' WHERE key='schema_version'",
                 NULL, NULL, NULL);
    sqlite3_close(h);
    ASSERT_EQ(db_open(db_path), 0);
    ASSERT_EQ(db_is_open(), 0);
    unlink(db_path);
}

static void test_open_bad_path_fails_cleanly(void) {
    db_close();
    ASSERT_EQ(db_open("/this/does/not/exist/nope/x.db"), 0);
    ASSERT_EQ(db_is_open(), 0);
    ASSERT_EQ(db_open(NULL), 0);
    ASSERT_EQ(db_open(""),   0);
}

/* Every entry point must tolerate never having been opened — the
 * fail-open contract starts here. */
static void test_calls_without_open_are_safe(void) {
    db_close();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    db_tick(&s, 1700000000);        /* must not crash */
    ASSERT_EQ(db_due(1700000000), 0);
    ASSERT_EQ(db_is_open(), 0);
    db_close();                     /* double close */
    ASSERT_EQ(db_is_open(), 0);
}

static void test_tick_null_state_is_safe(void) {
    fresh_db();
    db_tick(NULL, 1700000000);
    ASSERT_EQ(db_is_open(), 1);
    db_close();
    unlink(db_path);
}


/* ── assoc_reqs (#60) ────────────────────────────────────── */

static void seed_req(sloth_state_t *s, uint8_t last, int dg, uint32_t akm) {
    memset(s, 0, sizeof(*s));
    assoc_req_t *r = &s->assoc_reqs[0];
    memcpy(r->bssid, "\xaa\xbb\xcc\x11\x22\x33", 6);
    r->sta[0]=0x12; r->sta[1]=0x22; r->sta[2]=0x33;
    r->sta[3]=0x44; r->sta[4]=0x55; r->sta[5]=last;
    snprintf(r->requested_ssid, sizeof(r->requested_ssid), "home");
    r->akm_bits        = akm;
    r->requested_mfp   = 2;
    r->downgrade_flags = dg;
    r->ts              = 1700000000;
    s->assoc_req_count = 1;
}

static void test_assoc_reqs_written(void) {
    fresh_db();
    sloth_state_t s;
    seed_req(&s, 0x66, 0, RSN_AKM_SAE);
    db_tick(&s, 1700000000);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM assoc_reqs"), 1);
    ASSERT_EQ(q_int("SELECT requested_mfp FROM assoc_reqs"), 2);
    ASSERT_EQ(q_int("SELECT akm_bits FROM assoc_reqs"), (long long)RSN_AKM_SAE);
    db_close();
    unlink(db_path);
}

static void test_assoc_reqs_upsert_keeps_one_row(void) {
    fresh_db();
    sloth_state_t s;
    seed_req(&s, 0x66, 0, RSN_AKM_SAE);
    db_tick(&s, 1700000000);
    db_tick(&s, 1700000100);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM assoc_reqs"), 1);
    db_close();
    unlink(db_path);
}

static void test_assoc_reqs_downgrade_flag_is_sticky(void) {
    /* A downgrade already recorded must survive the client recovering.
     * Having been moved onto weaker parameters is the durable fact an
     * operator needs from history; a later clean request does not undo
     * that it happened. */
    fresh_db();
    sloth_state_t s;
    seed_req(&s, 0x66, ASSOC_DG_AKM | ASSOC_DG_MFP, RSN_AKM_PSK);
    db_tick(&s, 1700000000);
    ASSERT_EQ(q_int("SELECT downgrade_flags FROM assoc_reqs"),
              (long long)(ASSOC_DG_AKM | ASSOC_DG_MFP));

    seed_req(&s, 0x66, 0, RSN_AKM_SAE);      /* recovered, flags clear */
    db_tick(&s, 1700000100);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM assoc_reqs"), 1);
    ASSERT_EQ(q_int("SELECT downgrade_flags FROM assoc_reqs"),
              (long long)(ASSOC_DG_AKM | ASSOC_DG_MFP));
    /* The current ask is still updated — only the flags accumulate. */
    ASSERT_EQ(q_int("SELECT akm_bits FROM assoc_reqs"), (long long)RSN_AKM_SAE);
    db_close();
    unlink(db_path);
}

static void test_assoc_reqs_partial_index_exists(void) {
    /* The downgrade query is the one an operator actually runs; it gets
     * a partial index so it stays cheap as history grows. */
    fresh_db();
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM sqlite_master"
                    " WHERE type='index' AND name='idx_assoc_reqs_dg'"), 1);
    db_close();
    unlink(db_path);
}


/* Every table the schema creates must belong to exactly one retention
 * tier. A table with no tier is never aged out and grows without bound
 * — the failure mode #42's size ceiling exists to prevent, reintroduced
 * one table at a time. This is the check that would have caught it.
 *
 * Note what this does NOT check: that DB_SCHEMA_VERSION was bumped when
 * the table was added. Nothing can check that automatically — a fresh
 * file gets every table regardless of version, so the omission only
 * surfaces when an existing older database is opened. That is the
 * failure METRICS #56 records from #53. Bump it by hand. */
static void test_every_table_has_a_retention_tier(void) {
    fresh_db();
    /* meta and sessions are bookkeeping, not observation data, and are
     * deliberately never aged out. */
    long long untiered = q_int(
        "SELECT COUNT(*) FROM sqlite_master m"
        " WHERE m.type='table'"
        "   AND m.name NOT LIKE 'sqlite_%'"
        "   AND m.name NOT IN ('meta','sessions')"
        "   AND NOT EXISTS (SELECT 1 FROM pragma_table_info(m.name)"
        "                   WHERE name IN ('last_seen','bucket_ts','ts',"
        "                                  'run_ts','first_seen'))");
    ASSERT_EQ(untiered, 0);
    db_close();
    unlink(db_path);
}

/* ── write cadence ───────────────────────────────────────── */

static void test_due_respects_interval(void) {
    fresh_db();
    db_set_interval(10);
    ASSERT_EQ(db_interval(), 10);
    ASSERT_EQ(db_due(1700000000), 1);       /* first tick always */

    sloth_state_t s; memset(&s, 0, sizeof(s));
    db_tick(&s, 1700000000);
    ASSERT_EQ(db_due(1700000005), 0);       /* too soon */
    ASSERT_EQ(db_due(1700000010), 1);       /* exactly the interval */
    ASSERT_EQ(db_due(1700000099), 1);

    /* A clock stepped backwards (NTP correction on a sensor that booted
     * without RTC) must not wedge writes until the clock catches up. */
    ASSERT_EQ(db_due(1699999000), 1);

    db_set_interval(0);                     /* 0 restores the default */
    ASSERT_EQ(db_interval(), 1);
    db_close();
    unlink(db_path);
}

/* ── entity upserts ──────────────────────────────────────── */

static void seed_device(sloth_state_t *s, uint8_t last, const char *ip,
                        time_t seen) {
    device_t *d = &s->devices[s->device_count++];
    memset(d, 0, sizeof(*d));
    d->mac[0] = 0x02; d->mac[5] = last;
    snprintf(d->ip, sizeof(d->ip), "%s", ip);
    snprintf(d->vendor, sizeof(d->vendor), "TestCo");
    d->probe_count = 3;
    d->last_seen   = seen;
}

static void test_device_upsert_and_requery(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_device(&s, 0x11, "10.0.0.5", 1700000000);
    db_tick(&s, 1700000000);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM devices"), 1);
    char ip[64];
    q_text("SELECT ip FROM devices WHERE mac='02:00:00:00:00:11'",
           ip, sizeof(ip));
    ASSERT_STR(ip, "10.0.0.5");
    db_close();
    unlink(db_path);
}

/* The core claim of the design: repeated observation of one entity is
 * one row, not one row per tick. This is what turns 38 GB/day into
 * megabytes. */
static void test_repeated_ticks_do_not_grow_the_table(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_device(&s, 0x11, "10.0.0.5", 1700000000);
    for (int i = 0; i < 50; i++) db_tick(&s, 1700000000 + i);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM devices"), 1);
    db_close();
    unlink(db_path);
}

/* first_seen must pin the earliest observation and last_seen the
 * latest, regardless of the order ticks arrive in — the time range is
 * the whole point of the file. */
static void test_first_seen_never_moves_last_seen_never_rewinds(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_device(&s, 0x11, "10.0.0.5", 1700000500);
    db_tick(&s, 1700000500);

    s.devices[0].last_seen = 1700000900;      /* later */
    db_tick(&s, 1700000900);
    s.devices[0].last_seen = 1700000100;      /* out-of-order, earlier */
    db_tick(&s, 1700000100);

    ASSERT_EQ(q_int("SELECT first_seen FROM devices"), 1700000100);
    ASSERT_EQ(q_int("SELECT last_seen  FROM devices"), 1700000900);
    db_close();
    unlink(db_path);
}

static void test_distinct_entities_get_distinct_rows(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_device(&s, 0x11, "10.0.0.5", 1700000000);
    seed_device(&s, 0x22, "10.0.0.6", 1700000000);
    db_tick(&s, 1700000000);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM devices"), 2);
    db_close();
    unlink(db_path);
}

/* PNL is the 15%-of-volume type. Its SSID set must land in a joinable
 * table — "which devices remember network X" is the question the sink
 * exists to make answerable. */
static void test_pnl_client_and_ssids_split(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    pnl_client_t *p = &s.pnl_clients[s.pnl_count++];
    memset(p, 0, sizeof(*p));
    p->mac[0] = 0x02; p->mac[5] = 0x99;
    snprintf(p->ssids[0], 33, "HomeNet");
    snprintf(p->ssids[1], 33, "Cafe");
    p->ssid_count = 2;
    p->first_seen = 1700000000;
    p->last_seen  = 1700000060;
    db_tick(&s, 1700000060);

    ASSERT_EQ(q_int("SELECT COUNT(*) FROM pnl_clients"), 1);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM pnl_ssids"), 2);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM pnl_ssids WHERE ssid='HomeNet'"), 1);

    /* Re-observing the same PNL must not duplicate the SSID rows. */
    db_tick(&s, 1700000120);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM pnl_ssids"), 2);
    db_close();
    unlink(db_path);
}

/* An ssid_count larger than the array must not read past it. */
static void test_pnl_clamps_ssid_count(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    pnl_client_t *p = &s.pnl_clients[s.pnl_count++];
    memset(p, 0, sizeof(*p));
    p->mac[0] = 0x02;
    snprintf(p->ssids[0], 33, "OnlyOne");
    p->ssid_count = MAX_PNL_SSIDS_PER_CLI + 99;
    db_tick(&s, 1700000000);
    /* Empty slots are skipped, so exactly the one populated SSID lands. */
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM pnl_ssids"), 1);
    db_close();
    unlink(db_path);
}

/* Association evidence only ever strengthens: a later weaker
 * observation must not downgrade a confirmed EAPOL handshake. */
static void test_assoc_source_never_downgrades(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    assoc_t *a = &s.assocs[s.assoc_count++];
    memset(a, 0, sizeof(*a));
    a->bssid[0] = 0xaa; a->sta_mac[0] = 0x02;
    snprintf(a->ssid, sizeof(a->ssid), "Net");
    a->source     = ASSOC_SRC_EAPOL;
    a->first_seen = 1700000000;
    a->last_seen  = 1700000000;
    db_tick(&s, 1700000000);
    ASSERT_EQ(q_int("SELECT source FROM assocs"), ASSOC_SRC_EAPOL);

    s.assocs[0].source = ASSOC_SRC_ASSOC;   /* weaker evidence later */
    db_tick(&s, 1700000060);
    ASSERT_EQ(q_int("SELECT source FROM assocs"), ASSOC_SRC_EAPOL);

    /* UNKNOWN (0) is absence of evidence, not the strongest grade —
     * it must never displace a real observation even though it sorts
     * below every other value. */
    s.assocs[0].source = ASSOC_SRC_UNKNOWN;
    db_tick(&s, 1700000120);
    ASSERT_EQ(q_int("SELECT source FROM assocs"), ASSOC_SRC_EAPOL);
    db_close();
    unlink(db_path);
}

/* ...and the upgrade direction works: a weak first sighting is replaced
 * when the handshake later confirms it. Without this the rule above
 * could be satisfied by simply never updating the column. */
static void test_assoc_source_upgrades_to_stronger(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    assoc_t *a = &s.assocs[s.assoc_count++];
    memset(a, 0, sizeof(*a));
    a->bssid[0] = 0xaa; a->sta_mac[0] = 0x02;
    a->source     = ASSOC_SRC_REASSOC;      /* weakest real evidence */
    a->first_seen = 1700000000;
    a->last_seen  = 1700000000;
    db_tick(&s, 1700000000);
    ASSERT_EQ(q_int("SELECT source FROM assocs"), ASSOC_SRC_REASSOC);

    s.assocs[0].source = ASSOC_SRC_EAPOL;   /* handshake confirms it */
    db_tick(&s, 1700000060);
    ASSERT_EQ(q_int("SELECT source FROM assocs"), ASSOC_SRC_EAPOL);

    /* An UNKNOWN row that arrives first is upgraded by any real grade. */
    s.assoc_count = 0;
    assoc_t *b = &s.assocs[s.assoc_count++];
    memset(b, 0, sizeof(*b));
    b->bssid[0] = 0xbb; b->sta_mac[0] = 0x03;
    b->source = ASSOC_SRC_UNKNOWN;
    db_tick(&s, 1700000180);
    b->source = ASSOC_SRC_ASSOC;
    db_tick(&s, 1700000240);
    ASSERT_EQ(q_int("SELECT source FROM assocs WHERE bssid='bb:00:00:00:00:00'"),
              ASSOC_SRC_ASSOC);
    db_close();
    unlink(db_path);
}

/* Radio coverage accumulates — a radio that heard an entity once still
 * heard it, even when it is tuned elsewhere on a later tick. */
static void test_wifi_merged_sensor_mask_accumulates(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    wifi_merged_t *e = &s.wifi_merged.ents[s.wifi_merged.count++];
    memset(e, 0, sizeof(*e));
    e->key[0] = 0xaa;
    e->sensor_mask = 0x1;
    e->seen_by     = 1;
    e->best_rssi   = -70;
    e->first_seen  = 1700000000;
    e->last_seen   = 1700000000;
    db_tick(&s, 1700000000);
    ASSERT_EQ(q_int("SELECT sensor_mask FROM wifi_merged"), 1);

    s.wifi_merged.ents[0].sensor_mask = 0x2;   /* only radio 2 this tick */
    db_tick(&s, 1700000060);
    ASSERT_EQ(q_int("SELECT sensor_mask FROM wifi_merged"), 3);   /* union */
    db_close();
    unlink(db_path);
}

/* An empty state must produce an empty database, not an error and not
 * a phantom row. */
static void test_empty_state_writes_nothing(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    db_tick(&s, 1700000000);
    ASSERT_EQ(db_is_open(), 1);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM devices"), 0);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM pnl_clients"), 0);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM beacon_aps"), 0);
    db_close();
    unlink(db_path);
}

/* A run that persists survives a close/reopen — the point of the file. */
static void test_rows_survive_close_and_reopen(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_device(&s, 0x11, "10.0.0.5", 1700000000);
    db_tick(&s, 1700000000);
    db_close();

    ASSERT_EQ(db_open(db_path), 1);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM devices"), 1);
    /* And a second session extends the same row rather than adding one. */
    s.devices[0].last_seen = 1700009999;
    db_tick(&s, 1700009999);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM devices"), 1);
    ASSERT_EQ(q_int("SELECT last_seen FROM devices"), 1700009999);
    ASSERT_EQ(q_int("SELECT first_seen FROM devices"), 1700000000);
    db_close();
    unlink(db_path);
}


/* ── protocol-flow aggregates (#42 slice 1b) ─────────────── */

/* Counters keep a high-water mark, because the in-memory rings reset a
 * flow's counts when it is evicted and the durable row means "what has
 * this pair done", not "since the last eviction". Without this a busy
 * sensor would silently lose brute-force evidence to ring turnover. */
static void test_flow_counters_keep_high_water_mark(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    ssh_flow_t *f = &s.ssh_flows[s.ssh_flow_count++];
    memset(f, 0, sizeof(*f));
    snprintf(f->src_ip, sizeof(f->src_ip), "10.0.0.9");
    snprintf(f->dst_ip, sizeof(f->dst_ip), "10.0.0.1");
    f->banner_count = 400;
    snprintf(f->server_banner, sizeof(f->server_banner), "SSH-2.0-OpenSSH_9.6");
    db_tick(&s, 1700000000);
    ASSERT_EQ(q_int("SELECT banner_count FROM ssh_flows"), 400);

    s.ssh_flows[0].banner_count = 5;      /* ring evicted and restarted */
    db_tick(&s, 1700000060);
    ASSERT_EQ(q_int("SELECT banner_count FROM ssh_flows"), 400);

    s.ssh_flows[0].banner_count = 900;    /* genuinely more activity */
    db_tick(&s, 1700000120);
    ASSERT_EQ(q_int("SELECT banner_count FROM ssh_flows"), 900);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM ssh_flows"), 1);
    db_close();
    unlink(db_path);
}

/* SMB dialect is sticky to SMB1, mirroring the in-memory rule: once a
 * flow has spoken SMB1 that IS the finding, and a later SMB2
 * negotiation on the same pair must not erase it. */
static void test_smb_dialect_sticky_to_smb1(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    smb_session_t *f = &s.smb_sessions[s.smb_session_count++];
    memset(f, 0, sizeof(*f));
    snprintf(f->client_ip, sizeof(f->client_ip), "10.0.0.9");
    snprintf(f->server_ip, sizeof(f->server_ip), "10.0.0.1");
    f->server_port = 445;
    snprintf(f->dialect, sizeof(f->dialect), "SMB1");
    db_tick(&s, 1700000000);
    char d[16];
    q_text("SELECT dialect FROM smb_sessions", d, sizeof(d));
    ASSERT_STR(d, "SMB1");

    snprintf(s.smb_sessions[0].dialect, 8, "SMB2");
    db_tick(&s, 1700000060);
    q_text("SELECT dialect FROM smb_sessions", d, sizeof(d));
    ASSERT_STR(d, "SMB1");
    db_close();
    unlink(db_path);
}

/* ...and a flow that has only ever spoken SMB2 stays SMB2, so the
 * stickiness is not just "always report SMB1". */
static void test_smb_dialect_smb2_stays_smb2(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    smb_session_t *f = &s.smb_sessions[s.smb_session_count++];
    memset(f, 0, sizeof(*f));
    snprintf(f->client_ip, sizeof(f->client_ip), "10.0.0.9");
    snprintf(f->server_ip, sizeof(f->server_ip), "10.0.0.2");
    f->server_port = 445;
    snprintf(f->dialect, sizeof(f->dialect), "SMB2");
    db_tick(&s, 1700000000);
    db_tick(&s, 1700000060);
    char d[16];
    q_text("SELECT dialect FROM smb_sessions", d, sizeof(d));
    ASSERT_STR(d, "SMB2");
    db_close();
    unlink(db_path);
}

/* Requested-protocol bits accumulate: a client that once asked for
 * legacy RDP did ask for it, whatever it negotiates later. */
static void test_rdp_proto_mask_accumulates(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    rdp_flow_t *f = &s.rdp_flows[s.rdp_flow_count++];
    memset(f, 0, sizeof(*f));
    snprintf(f->src_ip, sizeof(f->src_ip), "10.0.0.9");
    snprintf(f->dst_ip, sizeof(f->dst_ip), "10.0.0.1");
    f->proto_mask = RDP_PROTO_RDP;
    snprintf(f->last_cookie, sizeof(f->last_cookie), "administrator");
    db_tick(&s, 1700000000);
    ASSERT_EQ(q_int("SELECT proto_mask FROM rdp_flows"), RDP_PROTO_RDP);

    s.rdp_flows[0].proto_mask = RDP_PROTO_HYBRID;
    db_tick(&s, 1700000060);
    ASSERT_EQ(q_int("SELECT proto_mask FROM rdp_flows"),
              RDP_PROTO_RDP | RDP_PROTO_HYBRID);

    /* The mstshash cookie is the username being guessed — an exposed
     * identifier, kept deliberately. */
    char c[64];
    q_text("SELECT last_cookie FROM rdp_flows", c, sizeof(c));
    ASSERT_STR(c, "administrator");
    db_close();
    unlink(db_path);
}

/* Endpoint pairs are distinct rows, and the same pair is one row. */
static void test_flows_keyed_by_endpoint_pair(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    for (int i = 0; i < 3; i++) {
        kerb_event_t *e = &s.kerb_events[s.kerb_event_count++];
        memset(e, 0, sizeof(*e));
        snprintf(e->src_ip, sizeof(e->src_ip), "10.0.0.%d", i + 1);
        e->preauth_failed_count = 10 + i;
    }
    db_tick(&s, 1700000000);
    db_tick(&s, 1700000060);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM kerb_events"), 3);
    ASSERT_EQ(q_int("SELECT preauth_failed_count FROM kerb_events"
                    " WHERE src_ip='10.0.0.3'"), 12);
    db_close();
    unlink(db_path);
}

/* Every flow table is reachable from a tick — a table added to the
 * schema but never written would be an invisible gap. */
static void test_all_flow_tables_writable(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));

    bgp_session_t *b = &s.bgp_sessions[s.bgp_session_count++];
    memset(b, 0, sizeof(*b));
    snprintf(b->peer_a, sizeof(b->peer_a), "10.0.0.1");
    snprintf(b->peer_b, sizeof(b->peer_b), "10.0.0.2");
    b->notification_count = 7;

    snmp_flow_t *sn = &s.snmp_flows[s.snmp_flow_count++];
    memset(sn, 0, sizeof(*sn));
    snprintf(sn->src_ip, sizeof(sn->src_ip), "10.0.0.3");
    snprintf(sn->dst_ip, sizeof(sn->dst_ip), "10.0.0.4");
    sn->community_count = 4;
    snprintf(sn->last_community, sizeof(sn->last_community), "s3cr3t-community");

    mqtt_flow_t *mq = &s.mqtt_flows[s.mqtt_flow_count++];
    memset(mq, 0, sizeof(*mq));
    snprintf(mq->src_ip, sizeof(mq->src_ip), "10.0.0.5");
    snprintf(mq->dst_ip, sizeof(mq->dst_ip), "10.0.0.6");
    snprintf(mq->last_username, sizeof(mq->last_username), "sensor01");

    ldap_event_t *ld = &s.ldap_events[s.ldap_event_count++];
    memset(ld, 0, sizeof(*ld));
    snprintf(ld->src_ip, sizeof(ld->src_ip), "10.0.0.7");
    ld->search_count = 500;

    db_tick(&s, 1700000000);
    ASSERT_EQ(q_int("SELECT notification_count FROM bgp_sessions"), 7);
    ASSERT_EQ(q_int("SELECT community_count FROM snmp_flows"), 4);
    ASSERT_EQ(q_int("SELECT search_count FROM ldap_events"), 500);
    char u[64];
    q_text("SELECT last_username FROM mqtt_flows", u, sizeof(u));
    ASSERT_STR(u, "sensor01");
    db_close();
    unlink(db_path);
}

/* MISSION §2, enforced at runtime rather than only in the DDL: an SNMP
 * community string is a shared secret in v1/v2c, so it must not reach
 * the file even though sloth holds it in memory to drive the
 * brute-force detector. This is the same blast-radius call the schema
 * makes for PMKIDs. */
static void test_snmp_community_string_never_persisted(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    snmp_flow_t *f = &s.snmp_flows[s.snmp_flow_count++];
    memset(f, 0, sizeof(*f));
    snprintf(f->src_ip, sizeof(f->src_ip), "10.0.0.3");
    snprintf(f->dst_ip, sizeof(f->dst_ip), "10.0.0.4");
    f->community_count = 2;
    snprintf(f->last_community, sizeof(f->last_community), "tot4lly-s3cret");
    snprintf(f->communities[0], SNMP_COMMUNITY_LEN, "tot4lly-s3cret");
    db_tick(&s, 1700000000);

    /* The count survives — that is the detection signal. */
    ASSERT_EQ(q_int("SELECT community_count FROM snmp_flows"), 2);
    /* No TEXT column on the table could hold one. */
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM pragma_table_info('snmp_flows')"
                    " WHERE name LIKE '%community%' AND type='TEXT'"), 0);
    db_close();

    /* And the strongest form of the claim: the secret is not in the
     * file at all. Scanning the bytes catches a leak through any path —
     * a stray column, an index, a future table — that a schema
     * assertion would miss. */
    ASSERT_EQ(file_contains(db_path, "tot4lly-s3cret"), 0);
    /* Control: a string we DO persist is found by the same scan, so a
     * pass above means "absent", not "the scan is broken". */
    ASSERT_EQ(file_contains(db_path, "10.0.0.3"), 1);
    unlink(db_path);
}

/* ── event episodes (#42 slice 2) ────────────────────────── */

/* An alert that persists is ONE row whose count and last_seen advance,
 * not one row per tick. At 1 Hz a single hour-long alert would
 * otherwise be 3600 rows — the exact firehose the sink exists to avoid. */
static void test_alert_episode_is_one_row(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    alert_t *a = &s.alerts[s.alert_count++];
    memset(a, 0, sizeof(*a));
    snprintf(a->key,    sizeof(a->key),    "portscan:10.0.0.9");
    snprintf(a->title,  sizeof(a->title),  "PORT_SCAN");
    snprintf(a->detail, sizeof(a->detail), "8 ports");
    snprintf(a->technique, sizeof(a->technique), "T1046");
    a->type = ALERT_TYPE_PORT_SCAN;
    a->sev  = ALERT_SEV_LOW;
    a->count = 1;
    a->first_seen = 1700000000;
    a->last_seen  = 1700000000;

    for (int i = 0; i < 30; i++) {
        s.alerts[0].last_seen = 1700000000 + i;
        s.alerts[0].count     = i + 1;
        db_tick(&s, 1700000000 + i);
    }
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM alerts"), 1);
    ASSERT_EQ(q_int("SELECT count FROM alerts"), 30);
    ASSERT_EQ(q_int("SELECT last_seen FROM alerts"), 1700000029);
    ASSERT_EQ(q_int("SELECT first_seen FROM alerts"), 1700000000);
    db_close();
    unlink(db_path);
}

/* A second episode under the same key — the alert cleared and fired
 * again later — is a distinct row, because first_seen is part of the
 * identity. Merging them would erase the gap, which is the interesting
 * part for an investigator. */
static void test_alert_second_episode_is_new_row(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    alert_t *a = &s.alerts[s.alert_count++];
    memset(a, 0, sizeof(*a));
    snprintf(a->key, sizeof(a->key), "portscan:10.0.0.9");
    a->type = ALERT_TYPE_PORT_SCAN;
    a->first_seen = 1700000000;
    a->last_seen  = 1700000010;
    db_tick(&s, 1700000010);

    s.alerts[0].first_seen = 1700009000;   /* fired again hours later */
    s.alerts[0].last_seen  = 1700009010;
    db_tick(&s, 1700009010);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM alerts"), 2);
    db_close();
    unlink(db_path);
}

/* Severity and detail track the live engine — the latest observation
 * wins, matching how fire() overwrites them. */
static void test_alert_severity_tracks_latest(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    alert_t *a = &s.alerts[s.alert_count++];
    memset(a, 0, sizeof(*a));
    snprintf(a->key, sizeof(a->key), "twin-fp:CorpWiFi");
    a->sev = ALERT_SEV_WARN;
    a->first_seen = 1700000000;
    a->last_seen  = 1700000000;
    db_tick(&s, 1700000000);
    ASSERT_EQ(q_int("SELECT sev FROM alerts"), ALERT_SEV_WARN);

    s.alerts[0].sev = ALERT_SEV_CRIT;      /* escalated */
    db_tick(&s, 1700000060);
    ASSERT_EQ(q_int("SELECT sev FROM alerts"), ALERT_SEV_CRIT);
    db_close();
    unlink(db_path);
}

/* Once a burst crossed the flood threshold, the episode was a flood —
 * a later poll below the rate must not un-flag it. */
static void test_deauth_flood_flag_latches(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    deauth_event_t *d = &s.deauth_events[s.deauth_count++];
    memset(d, 0, sizeof(*d));
    d->src[0] = 0xaa; d->dst[0] = 0xbb; d->bssid[0] = 0xcc;
    d->flood = 1;
    d->count = 40;
    d->first_seen = 1700000000;
    d->last_seen  = 1700000000;
    db_tick(&s, 1700000000);
    ASSERT_EQ(q_int("SELECT flood FROM deauth_events"), 1);

    s.deauth_events[0].flood = 0;
    s.deauth_events[0].count = 2;
    db_tick(&s, 1700000060);
    ASSERT_EQ(q_int("SELECT flood FROM deauth_events"), 1);
    ASSERT_EQ(q_int("SELECT obs_count FROM deauth_events"), 40);
    db_close();
    unlink(db_path);
}

/* Twin evidence flags latch for the same reason: a twin caught
 * mid-attack once was caught mid-attack. */
static void test_twin_evidence_flags_latch(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    twin_episode_t *t = &s.twin_episodes[s.twin_episode_count++];
    memset(t, 0, sizeof(*t));
    snprintf(t->ssid, sizeof(t->ssid), "CorpWiFi");
    t->real_bssid[0] = 0xaa; t->twin_bssid[0] = 0xbb;
    t->attack_in_progress = 1;
    t->attacker_oui       = 1;
    t->rssi_swing_dbm     = 25;
    t->last_seen = 1700000000;
    db_tick(&s, 1700000000);

    s.twin_episodes[0].attack_in_progress = 0;
    s.twin_episodes[0].attacker_oui       = 0;
    s.twin_episodes[0].rssi_swing_dbm     = 3;
    db_tick(&s, 1700000060);
    ASSERT_EQ(q_int("SELECT attack_in_progress FROM twin_episodes"), 1);
    ASSERT_EQ(q_int("SELECT attacker_oui FROM twin_episodes"), 1);
    ASSERT_EQ(q_int("SELECT rssi_swing_dbm FROM twin_episodes"), 25);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM twin_episodes"), 1);
    db_close();
    unlink(db_path);
}

/* Only flagged scan entries persist (#41). An unflagged entry is one
 * host touching a couple of ports — ordinary traffic — and persisting
 * it would put the CDN false positives #41 removed back into the
 * durable record. */
static void test_scan_entries_flagged_only(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    scan_entry_t *a = &s.scan_entries[s.scan_count++];
    memset(a, 0, sizeof(*a));
    snprintf(a->ip, sizeof(a->ip), "10.0.0.9");
    a->flagged = 1; a->port_count = 3;
    a->ports[0] = 22; a->ports[1] = 80; a->ports[2] = 443;
    a->first_seen = 1700000000; a->last_seen = 1700000000;

    scan_entry_t *b = &s.scan_entries[s.scan_count++];
    memset(b, 0, sizeof(*b));
    snprintf(b->ip, sizeof(b->ip), "10.0.0.10");
    b->flagged = 0; b->port_count = 2;       /* ordinary traffic */
    b->first_seen = 1700000000; b->last_seen = 1700000000;

    db_tick(&s, 1700000000);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM scan_entries"), 1);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM scan_entries WHERE ip='10.0.0.10'"), 0);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM scan_entry_ports"), 3);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM scan_entry_ports WHERE port=443"), 1);

    /* Re-ticking does not duplicate the port rows. */
    db_tick(&s, 1700000060);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM scan_entry_ports"), 3);
    db_close();
    unlink(db_path);
}

/* A port_count larger than the array must not read past it. */
static void test_scan_entry_clamps_port_count(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    scan_entry_t *a = &s.scan_entries[s.scan_count++];
    memset(a, 0, sizeof(*a));
    snprintf(a->ip, sizeof(a->ip), "10.0.0.9");
    a->flagged = 1;
    /* Distinct ports so the clamp is observable — a zero-filled array
     * would collapse to a single (ip, 0) row under the primary key and
     * the test would pass without proving anything. */
    for (int k = 0; k < MAX_SCAN_PORTS; k++)
        a->ports[k] = (uint16_t)(1000 + k);
    a->port_count = MAX_SCAN_PORTS + 500;
    db_tick(&s, 1700000000);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM scan_entry_ports"), MAX_SCAN_PORTS);
    /* Nothing was read past the end of the array. */
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM scan_entry_ports WHERE port=0"), 0);
    ASSERT_EQ(q_int("SELECT MAX(port) FROM scan_entry_ports"),
              1000 + MAX_SCAN_PORTS - 1);
    db_close();
    unlink(db_path);
}

/* Credential exposures keep the username (the exposure fact) and the
 * pw_observed flag — and there is no column the password could go in. */
static void test_cleartext_cred_keeps_username_not_secret(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_cred_t *c = &s.cleartext_creds[s.cleartext_cred_count++];
    memset(c, 0, sizeof(*c));
    snprintf(c->src, sizeof(c->src), "10.0.0.9");
    snprintf(c->dst, sizeof(c->dst), "10.0.0.1");
    c->dst_port = 80;
    snprintf(c->protocol, sizeof(c->protocol), "HTTP-Basic");
    snprintf(c->username, sizeof(c->username), "alice");
    c->password_observed = 1;
    c->ts = 1700000000;
    db_tick(&s, 1700000000);
    db_tick(&s, 1700000060);          /* same exposure, still one row */

    ASSERT_EQ(q_int("SELECT COUNT(*) FROM cleartext_creds"), 1);
    ASSERT_EQ(q_int("SELECT pw_observed FROM cleartext_creds"), 1);
    char u[64];
    q_text("SELECT username FROM cleartext_creds", u, sizeof(u));
    ASSERT_STR(u, "alice");
    db_close();
    unlink(db_path);
}

/* Seqnum correlations are the deanonymisation output and must survive
 * as a durable pair record. */
static void test_seqnum_correlation_persists(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_correlation_t *c =
        &s.seqnum_correlations[s.seqnum_correlation_count++];
    memset(c, 0, sizeof(*c));
    c->mac_a[0] = 0x02; c->mac_a[5] = 0x01;
    c->mac_b[0] = 0x06; c->mac_b[5] = 0x02;
    c->mac_a_random = 1; c->mac_b_random = 1;
    c->gap = 3; c->dt_ms = 120; c->a_count = 40; c->b_count = 38;
    db_tick(&s, 1700000000);
    db_tick(&s, 1700000060);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM seqnum_correlations"), 1);
    ASSERT_EQ(q_int("SELECT gap FROM seqnum_correlations"), 3);
    ASSERT_EQ(q_int("SELECT a_count FROM seqnum_correlations"), 40);
    db_close();
    unlink(db_path);
}

/* ── retention and the size ceiling (#42 slice 3) ────────── */

/* Insert a row directly at a chosen age, bypassing db_tick, so a test
 * can age data without waiting or faking a clock inside the sink. */
static void insert_at(const char *sql) {
    sqlite3 *h = NULL;
    if (sqlite3_open(db_path, &h) != SQLITE_OK) { sqlite3_close(h); return; }
    sqlite3_exec(h, sql, NULL, NULL, NULL);
    sqlite3_close(h);
}

#define DAY 86400LL
#define NOW 1900000000LL

/* Tiers age out at different rates, and the order is the point: an
 * observation goes first, the entity that produced it outlives it, and
 * the finding outlives both. A single retain window that dropped all
 * three together would lose the alert that made the file worth
 * keeping. */
static void test_retention_tiers_age_out_in_order(void) {
    fresh_db();
    db_set_retain_days(30);

    /* All three seeded at 45 days old: past 30 (observation), inside
     * 90 (entity) and inside 360 (finding). */
    long long old = NOW - 45 * DAY;
    char sql[1024];
    snprintf(sql, sizeof(sql),
        "INSERT INTO ssh_flows (src_ip,dst_ip,banner_count,first_seen,last_seen)"
        " VALUES ('10.0.0.1','10.0.0.2',5,%lld,%lld);"
        "INSERT INTO devices (mac,first_seen,last_seen)"
        " VALUES ('02:00:00:00:00:01',%lld,%lld);"
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,count)"
        " VALUES ('k1',%lld,%lld,0,2,1);",
        old, old, old, old, old, old);
    insert_at(sql);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM ssh_flows"), 1);

    db_maintain(NOW);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM ssh_flows"), 0);   /* > 30d  */
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM devices"),   1);   /* < 90d  */
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM alerts"),    1);   /* < 360d */
    db_close();
    unlink(db_path);
}

/* Past 3x, the entity goes but the finding still stands. */
static void test_entity_ages_out_before_finding(void) {
    fresh_db();
    db_set_retain_days(30);
    long long old = NOW - 100 * DAY;      /* > 90d, < 360d */
    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT INTO devices (mac,first_seen,last_seen)"
        " VALUES ('02:00:00:00:00:01',%lld,%lld);"
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,count)"
        " VALUES ('k1',%lld,%lld,0,2,1);", old, old, old, old);
    insert_at(sql);
    db_maintain(NOW);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM devices"), 0);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM alerts"),  1);
    db_close();
    unlink(db_path);
}

/* Everything eventually ages out — retention is not "keep findings
 * forever", it is "keep them twelve times longer". */
static void test_findings_age_out_eventually(void) {
    fresh_db();
    db_set_retain_days(30);
    long long ancient = NOW - 400 * DAY;   /* > 360d */
    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,count)"
        " VALUES ('k1',%lld,%lld,0,2,1);"
        "INSERT INTO cleartext_creds (ts,src,dst,dst_port,protocol,"
        "pw_observed,first_seen,last_seen)"
        " VALUES (%lld,'a','b',80,'HTTP-Basic',1,%lld,%lld);",
        ancient, ancient, ancient, ancient, ancient);
    insert_at(sql);
    db_maintain(NOW);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM alerts"), 0);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM cleartext_creds"), 0);
    db_close();
    unlink(db_path);
}

/* Fresh rows are never touched, whatever the tier. */
static void test_retention_keeps_recent_rows(void) {
    fresh_db();
    db_set_retain_days(30);
    long long recent = NOW - 2 * DAY;
    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT INTO ssh_flows (src_ip,dst_ip,banner_count,first_seen,last_seen)"
        " VALUES ('10.0.0.1','10.0.0.2',5,%lld,%lld);"
        "INSERT INTO devices (mac,first_seen,last_seen)"
        " VALUES ('02:00:00:00:00:01',%lld,%lld);",
        recent, recent, recent, recent);
    insert_at(sql);
    db_maintain(NOW);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM ssh_flows"), 1);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM devices"),   1);
    db_close();
    unlink(db_path);
}

/* Child tables carry their own last_seen and are pruned on the same
 * schedule as their parent tier — otherwise pnl_ssids would outlive
 * the pnl_clients row and accumulate forever. */
static void test_child_tables_are_pruned_too(void) {
    fresh_db();
    db_set_retain_days(30);
    long long old = NOW - 200 * DAY;      /* past the 90d entity tier */
    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT INTO pnl_clients (mac,first_seen,last_seen)"
        " VALUES ('02:00:00:00:00:01',%lld,%lld);"
        "INSERT INTO pnl_ssids (mac,ssid,first_seen,last_seen)"
        " VALUES ('02:00:00:00:00:01','HomeNet',%lld,%lld);",
        old, old, old, old);
    insert_at(sql);
    db_maintain(NOW);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM pnl_clients"), 0);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM pnl_ssids"),   0);
    db_close();
    unlink(db_path);
}

static void test_retain_days_setter_defaults(void) {
    fresh_db();
    db_set_retain_days(7);
    ASSERT_EQ(db_retain_days(), 7);
    db_set_retain_days(0);
    ASSERT_EQ(db_retain_days(), DB_DEFAULT_RETAIN_DAYS);
    db_set_retain_days(-5);
    ASSERT_EQ(db_retain_days(), DB_DEFAULT_RETAIN_DAYS);

    db_set_max_mb(64);
    ASSERT_EQ(db_max_mb(), 64);
    db_set_max_mb(0);                 /* 0 means unlimited, not default */
    ASSERT_EQ(db_max_mb(), 0);
    db_set_max_mb(-1);
    ASSERT_EQ(db_max_mb(), DB_DEFAULT_MAX_MB);
    db_set_max_mb(0);
    db_close();
    unlink(db_path);
}

/* The ceiling must never take a finding. This is the whole point of the
 * policy: a sensor that fills its disk loses telemetry, not the
 * evidence the disk was being kept for. */
static void test_ceiling_never_drops_findings(void) {
    fresh_db();
    db_set_retain_days(3650);          /* age-out must not confound this */
    /* One alert and one credential exposure, plus a pile of recent
     * observation rows. */
    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,count)"
        " VALUES ('keepme',%lld,%lld,0,2,1);"
        "INSERT INTO cleartext_creds (ts,src,dst,dst_port,protocol,username,"
        "pw_observed,first_seen,last_seen)"
        " VALUES (%lld,'a','b',80,'HTTP-Basic','alice',1,%lld,%lld);",
        NOW, NOW, NOW, NOW, NOW);
    insert_at(sql);

    sqlite3 *h = NULL;
    ASSERT_EQ(sqlite3_open(db_path, &h), SQLITE_OK);
    sqlite3_exec(h, "BEGIN", NULL, NULL, NULL);
    /* Enough bulk to clear 1 MiB — the smallest ceiling the flag can
     * express — so the guard actually has something to do. */
    char pad[600];
    memset(pad, 'x', sizeof(pad) - 1);
    pad[sizeof(pad) - 1] = '\0';
    for (int i = 0; i < 4000; i++) {
        char ins[1024];
        snprintf(ins, sizeof(ins),
            "INSERT INTO ssh_flows (src_ip,dst_ip,banner_count,server_banner,"
            "first_seen,last_seen) VALUES ('10.%d.%d.%d','10.0.0.1',1,"
            "'%s',%lld,%lld)",
            i / 65536, (i / 256) % 256, i % 256, pad, NOW, NOW + i);
        sqlite3_exec(h, ins, NULL, NULL, NULL);
    }
    sqlite3_exec(h, "COMMIT", NULL, NULL, NULL);
    sqlite3_close(h);

    long long before = q_int("SELECT COUNT(*) FROM ssh_flows");
    ASSERT(before > 3000);
    /* Precondition, asserted rather than assumed: if the fixture were
     * under the ceiling the test would "pass" without exercising the
     * guard at all. */
    ASSERT(db_size_bytes() > 1024 * 1024);

    db_set_max_mb(1);                  /* far below current size */
    db_maintain(NOW);

    /* Findings survive untouched... */
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM alerts"), 1);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM cleartext_creds"), 1);
    /* ...and the telemetry was the thing that gave way. */
    ASSERT(q_int("SELECT COUNT(*) FROM ssh_flows") < before);

    db_set_max_mb(DB_DEFAULT_MAX_MB);
    db_close();
    unlink(db_path);
}

/* A ceiling of 0 is unlimited and must not prune anything. */
static void test_ceiling_zero_is_unlimited(void) {
    fresh_db();
    db_set_retain_days(3650);
    db_set_max_mb(0);
    char sql[256];
    snprintf(sql, sizeof(sql),
        "INSERT INTO ssh_flows (src_ip,dst_ip,banner_count,first_seen,last_seen)"
        " VALUES ('10.0.0.1','10.0.0.2',5,%lld,%lld);", NOW, NOW);
    insert_at(sql);
    db_maintain(NOW);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM ssh_flows"), 1);
    db_set_max_mb(DB_DEFAULT_MAX_MB);
    db_close();
    unlink(db_path);
}

/* With nothing prunable left the pass must terminate rather than spin,
 * and must not start taking protected rows to reach the number. */
static void test_ceiling_terminates_when_nothing_prunable(void) {
    fresh_db();
    db_set_retain_days(3650);
    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,count)"
        " VALUES ('keepme',%lld,%lld,0,2,1);", NOW, NOW);
    insert_at(sql);
    db_set_max_mb(1);                  /* an empty-ish db still exceeds 1MiB? no —
                                          use a ceiling of 0 bytes via 1MiB and
                                          an already-small file: the loop must
                                          simply exit. */
    db_maintain(NOW);                  /* must return, not hang */
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM alerts"), 1);
    ASSERT_EQ(db_is_open(), 1);
    db_set_max_mb(DB_DEFAULT_MAX_MB);
    db_close();
    unlink(db_path);
}

static void test_maintain_without_open_is_safe(void) {
    db_close();
    db_maintain(NOW);                  /* must not crash */
    ASSERT_EQ(db_size_bytes(), -1);
    ASSERT_EQ(db_is_open(), 0);
}

static void test_size_bytes_reports_a_real_size(void) {
    fresh_db();
    long long sz = db_size_bytes();
    ASSERT(sz > 0);
    db_close();
    unlink(db_path);
}

/* ── detector evidence, #30 / #31 (#42 slice 4) ──────────── */

/* The hole this closes: the KARMA alert survives in `alerts`, but
 * before this the evidence behind it — SSID count, PNL overlap,
 * Jaccard, IE uniformity, the deauth chain — was TUI-only and gone on
 * exit. "sloth said this was a Pineapple" is not the same as being able
 * to show why. */
static void test_karma_evidence_persists(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    karma_ap_t *k = &s.karma_aps[s.karma_count++];
    memset(k, 0, sizeof(*k));
    k->bssid[0] = 0x00; k->bssid[1] = 0x13; k->bssid[2] = 0x37;
    k->ssid_count      = 12;
    k->pnl_overlap     = 5;
    k->pnl_jaccard_ppm = 412000;
    k->ie_uniform      = 1;
    k->deauth_chain    = 1;
    k->score           = 6;
    snprintf(k->top_ssid, sizeof(k->top_ssid), "Starbucks");
    k->last_seen = 1700000000;
    db_tick(&s, 1700000000);

    ASSERT_EQ(q_int("SELECT ssid_count FROM karma_candidates"), 12);
    ASSERT_EQ(q_int("SELECT pnl_jaccard_ppm FROM karma_candidates"), 412000);
    ASSERT_EQ(q_int("SELECT ie_uniform FROM karma_candidates"), 1);
    ASSERT_EQ(q_int("SELECT deauth_chain FROM karma_candidates"), 1);
    char ssid[64];
    q_text("SELECT top_ssid FROM karma_candidates", ssid, sizeof(ssid));
    ASSERT_STR(ssid, "Starbucks");
    db_close();
    unlink(db_path);
}

/* karma_update() rebuilds the table from scratch every poll, so a
 * briefly-quiet radio would otherwise erase the peak that justified the
 * alert. Evidence is high-water. */
static void test_karma_evidence_is_high_water(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    karma_ap_t *k = &s.karma_aps[s.karma_count++];
    memset(k, 0, sizeof(*k));
    k->bssid[0] = 0xaa;
    k->ssid_count   = 20;
    k->score        = 6;
    k->deauth_chain = 1;
    db_tick(&s, 1700000000);

    /* Next poll the radio is quiet: fewer SSIDs, no chain. */
    s.karma_aps[0].ssid_count   = 2;
    s.karma_aps[0].score        = 1;
    s.karma_aps[0].deauth_chain = 0;
    db_tick(&s, 1700000060);

    ASSERT_EQ(q_int("SELECT ssid_count FROM karma_candidates"), 20);
    ASSERT_EQ(q_int("SELECT score FROM karma_candidates"), 6);
    ASSERT_EQ(q_int("SELECT deauth_chain FROM karma_candidates"), 1);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM karma_candidates"), 1);
    db_close();
    unlink(db_path);
}

/* Offered EAP methods accumulate — an AP that once offered MD5 offered
 * it, whatever it advertises on the next handshake. */
static void test_rogue_radius_eap_types_accumulate(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    rogue_radius_ap_t *r = &s.rogue_radius[s.rogue_radius_count++];
    memset(r, 0, sizeof(*r));
    r->bssid[0] = 0xbb;
    r->eap_types_seen = (1u << 4);        /* MD5 */
    r->weak_method    = 1;
    r->identity_leaks = 3;
    snprintf(r->last_identity, sizeof(r->last_identity), "alice@corp.example");
    db_tick(&s, 1700000000);
    ASSERT_EQ(q_int("SELECT eap_types_seen FROM rogue_radius"), 1 << 4);

    s.rogue_radius[0].eap_types_seen = (1u << 25);   /* PEAP only now */
    s.rogue_radius[0].weak_method    = 0;
    s.rogue_radius[0].identity_leaks = 1;
    db_tick(&s, 1700000060);

    ASSERT_EQ(q_int("SELECT eap_types_seen FROM rogue_radius"),
              (1 << 4) | (1 << 25));
    ASSERT_EQ(q_int("SELECT weak_method FROM rogue_radius"), 1);
    ASSERT_EQ(q_int("SELECT identity_leaks FROM rogue_radius"), 3);

    /* A leaked EAP identity is a username — the exposure fact, kept
     * deliberately, exactly as cleartext_creds keeps one. */
    char id[80];
    q_text("SELECT last_identity FROM rogue_radius", id, sizeof(id));
    ASSERT_STR(id, "alice@corp.example");
    db_close();
    unlink(db_path);
}

/* Evidence must outlive nothing less than the alert it justifies. At
 * the entity tier it would expire at 3x while the CRIT it supports was
 * still retained at 12x — recreating the #30/#31 hole through
 * retention instead of through a missing emitter. */
static void test_detector_evidence_shares_the_finding_tier(void) {
    fresh_db();
    db_set_retain_days(30);
    long long old = NOW - 100 * DAY;      /* past 3x (90d), inside 12x */
    char sql[768];
    snprintf(sql, sizeof(sql),
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,count)"
        " VALUES ('karma:aa',%lld,%lld,0,2,1);"
        "INSERT INTO karma_candidates (bssid,score,first_seen,last_seen)"
        " VALUES ('aa:00:00:00:00:00',6,%lld,%lld);"
        "INSERT INTO rogue_radius (bssid,identity_leaks,first_seen,last_seen)"
        " VALUES ('bb:00:00:00:00:00',3,%lld,%lld);"
        "INSERT INTO devices (mac,first_seen,last_seen)"
        " VALUES ('02:00:00:00:00:01',%lld,%lld);",
        old, old, old, old, old, old, old, old);
    insert_at(sql);
    db_maintain(NOW);

    /* The entity is gone at 100 days... */
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM devices"), 0);
    /* ...but the alert and the evidence behind it both survive. */
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM alerts"), 1);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM karma_candidates"), 1);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM rogue_radius"), 1);
    db_close();
    unlink(db_path);
}

/* ...and the size ceiling must not take them either, for the same
 * reason it does not take alerts. */
static void test_ceiling_never_drops_detector_evidence(void) {
    fresh_db();
    db_set_retain_days(3650);
    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT INTO karma_candidates (bssid,score,first_seen,last_seen)"
        " VALUES ('aa:00:00:00:00:00',6,%lld,%lld);", NOW, NOW);
    insert_at(sql);

    sqlite3 *h = NULL;
    ASSERT_EQ(sqlite3_open(db_path, &h), SQLITE_OK);
    char pad[600];
    memset(pad, 'x', sizeof(pad) - 1); pad[sizeof(pad) - 1] = '\0';
    sqlite3_exec(h, "BEGIN", NULL, NULL, NULL);
    for (int i = 0; i < 4000; i++) {
        char ins[1024];
        snprintf(ins, sizeof(ins),
            "INSERT INTO ssh_flows (src_ip,dst_ip,banner_count,server_banner,"
            "first_seen,last_seen) VALUES ('10.%d.%d.%d','10.0.0.1',1,'%s',%lld,%lld)",
            i / 65536, (i / 256) % 256, i % 256, pad, NOW, NOW + i);
        sqlite3_exec(h, ins, NULL, NULL, NULL);
    }
    sqlite3_exec(h, "COMMIT", NULL, NULL, NULL);
    sqlite3_close(h);
    ASSERT(db_size_bytes() > 1024 * 1024);

    db_set_max_mb(1);
    db_maintain(NOW);
    ASSERT_EQ(q_int("SELECT COUNT(*) FROM karma_candidates"), 1);
    db_set_max_mb(DB_DEFAULT_MAX_MB);
    db_close();
    unlink(db_path);
}

/* Presence class is persisted at its strongest-ever verdict (#53). The
 * live RSSI ring only holds 60 s, so a device that demonstrably drove
 * past would otherwise revert to "unknown" the moment its trajectory
 * aged out — losing the single observation the operator was looking
 * for. */
static void test_presence_class_never_walks_back(void) {
    fresh_db();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    probe_client_t *p = &s.probe_clients[s.probe_count++];
    memset(p, 0, sizeof(*p));
    p->mac[0] = 0x02; p->mac[5] = 0x77;
    p->first_seen = 1700000000 - 30;
    p->last_seen  = 1700000000;
    /* A vehicle pass: rise, peak, recede inside the window. */
    const int pass[] = { -85, -72, -58, -45, -44, -60, -75, -88 };
    for (unsigned i = 0; i < sizeof(pass) / sizeof(pass[0]); i++) {
        p->rssi_ring.dbm[p->rssi_ring.head] = (int8_t)pass[i];
        p->rssi_ring.ts [p->rssi_ring.head] = 1700000000 - (7 - (int)i);
        p->rssi_ring.head = (p->rssi_ring.head + 1) % RSSI_WIN_SAMPLES;
        p->rssi_ring.count++;
    }
    db_tick(&s, 1700000000);
    ASSERT_EQ(q_int("SELECT presence FROM probe_clients"),
              (int)PRESENCE_TRANSIENT);

    /* Later the trajectory has aged out of the ring entirely. */
    memset(&s.probe_clients[0].rssi_ring, 0, sizeof(rssi_ring_t));
    s.probe_clients[0].last_seen = 1700000000 + 30;
    db_tick(&s, 1700000000 + 30);
    ASSERT_EQ(q_int("SELECT presence FROM probe_clients"),
              (int)PRESENCE_TRANSIENT);
    db_close();
    unlink(db_path);
}

/* ── survey sessions and "new since last visit" (#56) ────── */

/* The first visit has nothing to compare against, and must say so
 * rather than reporting the entire site as new. */
static void test_first_session_has_no_previous(void) {
    fresh_db();
    db_session_begin("Site A", 1700000000);
    ASSERT_EQ((long long)db_previous_session_end(), 0LL);
    db_session_end(1700003600);
    db_close();
    unlink(db_path);
}

/* A second visit compares against where the first one ended. */
static void test_second_session_sees_the_first(void) {
    fresh_db();
    db_session_begin("Site A", 1700000000);
    db_session_end(1700003600);
    db_close();

    ASSERT_EQ(db_open(db_path), 1);
    db_session_begin("Site A", 1700090000);
    ASSERT_EQ((long long)db_previous_session_end(), 1700003600LL);
    db_close();
    unlink(db_path);
}

/* A session that never recorded an end — a crash, a kill -9 — falls
 * back to its start rather than reading as "no previous visit" and
 * flooding the next report with everything. */
static void test_crashed_session_falls_back_to_its_start(void) {
    fresh_db();
    db_session_begin("Site A", 1700000000);
    /* no db_session_end */
    db_close();

    ASSERT_EQ(db_open(db_path), 1);
    db_session_begin("Site A", 1700090000);
    ASSERT_EQ((long long)db_previous_session_end(), 1700000000LL);
    db_close();
    unlink(db_path);
}

/* The heart of the feature: an entity carried over from a previous
 * visit keeps its original first_seen, so only genuinely new ones fall
 * inside the window. Without the MIN-ing upsert this would report the
 * whole site as new on every visit. */
static void test_new_since_excludes_carried_over_entities(void) {
    fresh_db();
    /* Visit one: two devices. */
    db_session_begin("Site A", 1700000000);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_device(&s, 0x11, "10.0.0.5", 1700000100);
    seed_device(&s, 0x22, "10.0.0.6", 1700000100);
    db_tick(&s, 1700000100);
    db_session_end(1700003600);
    db_close();

    /* Visit two: the same two return, plus one genuinely new. */
    ASSERT_EQ(db_open(db_path), 1);
    db_session_begin("Site A", 1700090000);
    time_t since = db_previous_session_end();
    s.devices[0].last_seen = 1700090100;
    s.devices[1].last_seen = 1700090100;
    seed_device(&s, 0x33, "10.0.0.7", 1700090100);
    db_tick(&s, 1700090100);

    ASSERT_EQ(db_count_new_since(DB_NEW_DEVICE, since), 1);
    db_new_entity_t rows[8];
    int n = db_new_since(DB_NEW_DEVICE, since, rows, 8);
    ASSERT_EQ(n, 1);
    ASSERT_STR(rows[0].ident, "02:00:00:00:00:33");
    db_close();
    unlink(db_path);
}

/* Nothing new is a real answer, distinct from "no history". */
static void test_new_since_reports_zero_when_nothing_new(void) {
    fresh_db();
    db_session_begin("Site A", 1700000000);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_device(&s, 0x11, "10.0.0.5", 1700000100);
    db_tick(&s, 1700000100);
    db_session_end(1700003600);
    db_close();

    ASSERT_EQ(db_open(db_path), 1);
    db_session_begin("Site A", 1700090000);
    time_t since = db_previous_session_end();
    s.devices[0].last_seen = 1700090100;
    db_tick(&s, 1700090100);
    ASSERT_EQ(db_count_new_since(DB_NEW_DEVICE, since), 0);
    db_close();
    unlink(db_path);
}

/* Each entity kind is queried independently — a new AP must not be
 * reported as a new device. */
static void test_new_since_kinds_are_independent(void) {
    fresh_db();
    db_session_begin("Site A", 1700000000);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    beacon_ap_t *b = &s.beacon_aps[s.beacon_count++];
    memset(b, 0, sizeof(*b));
    b->bssid[0] = 0xaa;
    snprintf(b->ssid, sizeof(b->ssid), "NewNet");
    b->last_seen = 1700000100;
    db_tick(&s, 1700000100);

    ASSERT_EQ(db_count_new_since(DB_NEW_BEACON_AP, 1699000000), 1);
    ASSERT_EQ(db_count_new_since(DB_NEW_DEVICE, 1699000000), 0);
    db_new_entity_t rows[4];
    ASSERT_EQ(db_new_since(DB_NEW_BEACON_AP, 1699000000, rows, 4), 1);
    ASSERT_STR(rows[0].label, "NewNet");
    db_close();
    unlink(db_path);
}

static void test_session_calls_without_open_are_safe(void) {
    db_close();
    db_session_begin("nowhere", 1700000000);   /* must not crash */
    db_session_end(1700000001);
    ASSERT_EQ((long long)db_previous_session_end(), 0LL);
    db_new_entity_t rows[2];
    ASSERT_EQ(db_new_since(DB_NEW_DEVICE, 0, rows, 2), 0);
    ASSERT_EQ(db_count_new_since(DB_NEW_DEVICE, 0), 0);
    ASSERT_EQ(db_new_since(DB_NEW_DEVICE, 0, NULL, 2), 0);
}

/* A v1 file predates the probe_clients.presence column added in #53.
 * CREATE TABLE IF NOT EXISTS cannot add a column to an existing table,
 * so it must be refused with the version message rather than failing on
 * whatever statement happens to hit the missing column first. */
static void test_stale_schema_version_refused_clearly(void) {
    db_close();
    unlink(db_path);
    sqlite3 *h = NULL;
    ASSERT_EQ(sqlite3_open(db_path, &h), SQLITE_OK);
    sqlite3_exec(h,
        "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
        "INSERT INTO meta VALUES('schema_version','1');"
        "CREATE TABLE probe_clients (mac TEXT PRIMARY KEY, ssid TEXT,"
        " signal_dbm INTEGER, channel INTEGER,"
        " frame_count INTEGER NOT NULL DEFAULT 0,"
        " first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL);",
        NULL, NULL, NULL);
    sqlite3_close(h);

    ASSERT_EQ(db_open(db_path), 0);
    ASSERT_EQ(db_is_open(), 0);
    unlink(db_path);
}

void run_db_tests(void) {
    TEST_SUITE("db: MISSION §2 schema guardrails");
    RUN_TEST(test_no_column_can_hold_secret_material);
    RUN_TEST(test_schema_has_no_secret_named_columns);
    RUN_TEST(test_eapol_key_material_never_reaches_disk);
    RUN_TEST(test_schema_tables_have_seen_columns);

    TEST_SUITE("db: open / close / versioning");
    RUN_TEST(test_open_creates_and_stamps_version);
    RUN_TEST(test_reopen_is_idempotent);
    RUN_TEST(test_open_refuses_foreign_schema_version);
    RUN_TEST(test_open_bad_path_fails_cleanly);
    RUN_TEST(test_calls_without_open_are_safe);
    RUN_TEST(test_tick_null_state_is_safe);

    TEST_SUITE("db: write cadence");
    RUN_TEST(test_every_table_has_a_retention_tier);
    RUN_TEST(test_assoc_reqs_written);
    RUN_TEST(test_assoc_reqs_upsert_keeps_one_row);
    RUN_TEST(test_assoc_reqs_downgrade_flag_is_sticky);
    RUN_TEST(test_assoc_reqs_partial_index_exists);
    RUN_TEST(test_due_respects_interval);

    TEST_SUITE("db: entity upserts");
    RUN_TEST(test_device_upsert_and_requery);
    RUN_TEST(test_repeated_ticks_do_not_grow_the_table);
    RUN_TEST(test_first_seen_never_moves_last_seen_never_rewinds);
    RUN_TEST(test_distinct_entities_get_distinct_rows);
    RUN_TEST(test_pnl_client_and_ssids_split);
    RUN_TEST(test_pnl_clamps_ssid_count);
    RUN_TEST(test_assoc_source_never_downgrades);
    RUN_TEST(test_assoc_source_upgrades_to_stronger);
    RUN_TEST(test_wifi_merged_sensor_mask_accumulates);
    RUN_TEST(test_empty_state_writes_nothing);
    RUN_TEST(test_rows_survive_close_and_reopen);

    TEST_SUITE("db: protocol-flow aggregates");
    RUN_TEST(test_flow_counters_keep_high_water_mark);
    RUN_TEST(test_smb_dialect_sticky_to_smb1);
    RUN_TEST(test_smb_dialect_smb2_stays_smb2);
    RUN_TEST(test_rdp_proto_mask_accumulates);
    RUN_TEST(test_flows_keyed_by_endpoint_pair);
    RUN_TEST(test_all_flow_tables_writable);
    RUN_TEST(test_snmp_community_string_never_persisted);

    TEST_SUITE("db: event episodes");
    RUN_TEST(test_alert_episode_is_one_row);
    RUN_TEST(test_alert_second_episode_is_new_row);
    RUN_TEST(test_alert_severity_tracks_latest);
    RUN_TEST(test_deauth_flood_flag_latches);
    RUN_TEST(test_twin_evidence_flags_latch);
    RUN_TEST(test_scan_entries_flagged_only);
    RUN_TEST(test_scan_entry_clamps_port_count);
    RUN_TEST(test_cleartext_cred_keeps_username_not_secret);
    RUN_TEST(test_seqnum_correlation_persists);

    TEST_SUITE("db: retention and size ceiling");
    RUN_TEST(test_retention_tiers_age_out_in_order);
    RUN_TEST(test_entity_ages_out_before_finding);
    RUN_TEST(test_findings_age_out_eventually);
    RUN_TEST(test_retention_keeps_recent_rows);
    RUN_TEST(test_child_tables_are_pruned_too);
    RUN_TEST(test_retain_days_setter_defaults);
    RUN_TEST(test_ceiling_never_drops_findings);
    RUN_TEST(test_ceiling_zero_is_unlimited);
    RUN_TEST(test_ceiling_terminates_when_nothing_prunable);
    RUN_TEST(test_maintain_without_open_is_safe);
    RUN_TEST(test_size_bytes_reports_a_real_size);

    TEST_SUITE("db: detector evidence (#30 / #31)");
    RUN_TEST(test_karma_evidence_persists);
    RUN_TEST(test_karma_evidence_is_high_water);
    RUN_TEST(test_rogue_radius_eap_types_accumulate);
    RUN_TEST(test_detector_evidence_shares_the_finding_tier);
    RUN_TEST(test_ceiling_never_drops_detector_evidence);
    RUN_TEST(test_presence_class_never_walks_back);

    TEST_SUITE("db: survey sessions (#56)");
    RUN_TEST(test_first_session_has_no_previous);
    RUN_TEST(test_second_session_sees_the_first);
    RUN_TEST(test_crashed_session_falls_back_to_its_start);
    RUN_TEST(test_new_since_excludes_carried_over_entities);
    RUN_TEST(test_new_since_reports_zero_when_nothing_new);
    RUN_TEST(test_new_since_kinds_are_independent);
    RUN_TEST(test_session_calls_without_open_are_safe);
    RUN_TEST(test_stale_schema_version_refused_clearly);
}
