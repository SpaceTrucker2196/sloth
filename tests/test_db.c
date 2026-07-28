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

static void test_schema_has_no_password_column(void) {
    const char *sql = db_schema_sql();
    ASSERT(sql != NULL);
    /* Credential exposures record that a username crossed the wire in
     * the clear. The password never enters sloth's memory and must
     * never gain a column here. */
    ASSERT(strstr(sql, "password") == NULL);
    ASSERT(strstr(sql, "passwd")   == NULL);
}

/* Crackable key material stays in the --eapol-dir file the operator
 * explicitly asked for. Concentrating it in a long-lived
 * general-purpose DB widens the blast radius of a stolen file for no
 * operational gain. */
static void test_schema_has_no_key_material(void) {
    const char *sql = db_schema_sql();
    ASSERT(strstr(sql, "pmkid")  == NULL);
    ASSERT(strstr(sql, "PMKID")  == NULL);
    ASSERT(strstr(sql, "anonce") == NULL);
    ASSERT(strstr(sql, "snonce") == NULL);
    ASSERT(strstr(sql, "nonce")  == NULL);
    ASSERT(strstr(sql, "_mic")   == NULL);
}

/* Every entity table carries the pair that makes the file a history
 * rather than a snapshot. Walks each CREATE TABLE body so a new table
 * that forgets them is caught, whatever its column formatting. */
static void test_schema_tables_have_seen_columns(void) {
    const char *sql = db_schema_sql();
    int tables = 0, with_both = 0;
    for (const char *p = strstr(sql, "CREATE TABLE"); p;
         p = strstr(p + 1, "CREATE TABLE")) {
        const char *end = strstr(p, ");");
        if (!end) break;
        tables++;
        /* meta is the one table that is not an entity record. */
        if (strstr(p, "meta (") && strstr(p, "meta (") < end) continue;
        const char *f = strstr(p, "first_seen");
        const char *l = strstr(p, "last_seen");
        if (f && f < end && l && l < end) with_both++;
    }
    ASSERT(tables > 15);
    ASSERT_EQ(with_both, tables - 1);
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

void run_db_tests(void) {
    TEST_SUITE("db: MISSION §2 schema guardrails");
    RUN_TEST(test_schema_has_no_password_column);
    RUN_TEST(test_schema_has_no_key_material);
    RUN_TEST(test_schema_tables_have_seen_columns);

    TEST_SUITE("db: open / close / versioning");
    RUN_TEST(test_open_creates_and_stamps_version);
    RUN_TEST(test_reopen_is_idempotent);
    RUN_TEST(test_open_refuses_foreign_schema_version);
    RUN_TEST(test_open_bad_path_fails_cleanly);
    RUN_TEST(test_calls_without_open_are_safe);
    RUN_TEST(test_tick_null_state_is_safe);

    TEST_SUITE("db: write cadence");
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
}
