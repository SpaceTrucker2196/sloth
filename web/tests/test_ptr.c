/* The passive PTR cache (#162, M4; docs/web-ui-spec.md §9.3 without
 * its cut active half) and the identity tables' M4 readers: hand-built
 * dns records through the decoder on a pinned clock, the reverse names
 * built per RFC 1035 §3.5 (in-addr.arpa) and RFC 3596 §2.5 (ip6.arpa).
 * slothweb never sends a query; every name here is one a record
 * carried. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

#include "web_anomaly.h"
#include "web_baseline.h"
#include "web_ident.h"
#include "web_jsonl.h"
#include "web_ptr.h"
#include "web_store.h"
#include "wtest.h"
#include "jsonl_ptr_fixture.h"

#define T0 1792627200LL

static void feed(web_ident_t *id, const char *line, long long now) {
    static web_jrec_t r;
    WT_EQ(web_jl_parse(line, strlen(line), &r), WEB_JL_OK);
    web_ident_record(id, &r, now);
}

static void test_reverse_names(void) {
    char ip[64];
    WT_EQ(web_ptr_qname_ip("5.1.0.10.in-addr.arpa", ip), 0);
    WT_ASSERT(!strcmp(ip, "10.0.1.5"));
    WT_EQ(web_ptr_qname_ip("5.1.0.10.IN-ADDR.ARPA.", ip), 0);
    WT_ASSERT(!strcmp(ip, "10.0.1.5"));
    /* 2001:db8::567:89ab, nibble by nibble, least significant first. */
    WT_EQ(web_ptr_qname_ip("b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0."
                           "8.b.d.0.1.0.0.2.ip6.arpa", ip), 0);
    WT_ASSERT(!strcmp(ip, "2001:db8::567:89ab"));
    static const char *const bad[] = {
        "1.0.10.in-addr.arpa", "1.1.1.0.10.in-addr.arpa", "a.1.0.10.in-addr.arpa",
        "1..0.10.in-addr.arpa", "1000.1.0.10.in-addr.arpa", "300.1.0.10.in-addr.arpa",
        "5.1.0.10.in-addr.arpa.example", "example.com", "", "in-addr.arpa",
        "b.a.9.8.ip6.arpa", "g.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0."
                            "8.b.d.0.1.0.0.2.ip6.arpa",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        WT_EQ(web_ptr_qname_ip(bad[i], ip), -1);
    WT_EQ(web_ptr_qname_ip(NULL, ip), -1);
}

/* What is recorded, and what is not: a PTR answer with a host name for
 * a reverse name; not a query, not another type, not an empty answer
 * (what a sloth older than #165 wrote for every PTR answer, counted), not NXDOMAIN,
 * an address or a name with markup. Seen red with name_ok()'s character
 * check removed. */
static void test_records(void) {
    web_ident_t id;
    web_ptr_t p;
    WT_EQ(web_ident_init(&id, 16, 16), 0);
    WT_EQ(web_ptr_init(&p, 4), 0);
    web_ident_set_ptr(&id, &p);
    feed(&id, "{\"type\":\"dns\",\"ts\":1,\"src\":\"10.0.0.53\",\"qname\":"
              "\"5.1.0.10.in-addr.arpa\",\"qtype\":\"PTR\",\"answer\":"
              "\"nas.lan.\",\"is_resp\":1}", T0);
    feed(&id, "{\"type\":\"dns\",\"ts\":1,\"src\":\"10.0.0.53\",\"qname\":"
              "\"6.1.0.10.in-addr.arpa\",\"qtype\":\"PTR\",\"answer\":"
              "\"\",\"is_resp\":1}", T0);
    feed(&id, "{\"type\":\"dns\",\"ts\":1,\"src\":\"10.0.1.7\",\"qname\":"
              "\"7.1.0.10.in-addr.arpa\",\"qtype\":\"PTR\",\"answer\":"
              "\"x.lan\",\"is_resp\":0}", T0);
    feed(&id, "{\"type\":\"dns\",\"ts\":1,\"src\":\"10.0.0.53\",\"qname\":"
              "\"8.1.0.10.in-addr.arpa\",\"qtype\":\"A\",\"answer\":"
              "\"10.0.1.8\",\"is_resp\":1}", T0);
    static const char *const refused[] = { "NXDOMAIN", "10.0.0.9",
        "<b>x</b>", "a b", "caf\\u00e9.lan" };
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
        char line[256];
        snprintf(line, sizeof(line), "{\"type\":\"dns\",\"ts\":1,\"src\":"
                 "\"10.0.0.53\",\"qname\":\"9.1.0.10.in-addr.arpa\",\"qtype\":"
                 "\"PTR\",\"answer\":\"%s\",\"is_resp\":1}", refused[i]);
        feed(&id, line, T0);
    }
    feed(&id, "{\"type\":\"dns\",\"ts\":1,\"src\":\"10.0.0.53\",\"qname\":"
              "\"example.com\",\"qtype\":\"PTR\",\"answer\":\"x.lan\","
              "\"is_resp\":1}", T0);
    web_ptr_stats_t st;
    web_ptr_stats(&p, &st);
    WT_EQ(st.seen, 1 + 1 + 5 + 1);
    WT_EQ(st.stored, 1);
    WT_EQ(st.empty, 1);
    WT_EQ(st.refused, 6);
    WT_EQ(st.n, 1);
    char name[WEB_PTR_NAME_MAX + 1];
    long long t;
    WT_EQ(web_ptr_get(&p, "10.0.1.5", name, &t), 1);
    WT_ASSERT(!strcmp(name, "nas.lan"));
    WT_EQ(t, T0);
    WT_EQ(web_ptr_get(&p, "10.0.1.9", name, &t), 0);
    WT_EQ(web_ptr_get(&p, "10.0.1.6", name, &t), 0);
    web_ptr_destroy(&p);
    web_ident_destroy(&id);
}

/* The table is bounded: full, the least recently seen address goes and
 * is counted; a renamed address starts its first_seen again; changed
 * rows come out once for the store and go back when a write fails.
 * Seen red with the eviction choosing the most recently seen. */
static void test_bound_and_dirty(void) {
    web_ptr_t p;
    WT_EQ(web_ptr_init(&p, 2), 0);
    web_ptr_record(&p, "PTR", 1, "1.0.0.10.in-addr.arpa", "a.lan", T0);
    web_ptr_record(&p, "PTR", 1, "2.0.0.10.in-addr.arpa", "b.lan", T0 + 1);
    web_ptr_record(&p, "PTR", 1, "1.0.0.10.in-addr.arpa", "a.lan", T0 + 2);
    web_ptr_record(&p, "PTR", 1, "3.0.0.10.in-addr.arpa", "c.lan", T0 + 3);
    web_ptr_stats_t st;
    web_ptr_stats(&p, &st);
    WT_EQ(st.evictions, 1);
    WT_EQ(st.n, 2);
    char name[WEB_PTR_NAME_MAX + 1];
    WT_EQ(web_ptr_get(&p, "10.0.0.2", name, NULL), 0);   /* the oldest */
    WT_EQ(web_ptr_get(&p, "10.0.0.1", name, NULL), 1);
    web_store_ptr_t out[4];
    WT_EQ(web_ptr_take_dirty(&p, out, 4), 2);
    WT_EQ(web_ptr_take_dirty(&p, out, 4), 0);
    web_ptr_redirty(&p, out, 2);
    WT_EQ(web_ptr_take_dirty(&p, out, 4), 2);
    web_ptr_record(&p, "PTR", 1, "1.0.0.10.in-addr.arpa", "renamed.lan", T0 + 9);
    WT_EQ(web_ptr_take_dirty(&p, out, 4), 1);
    WT_ASSERT(!strcmp(out[0].name, "renamed.lan"));
    WT_EQ(out[0].first_seen, T0 + 9);
    /* A row read back is checked like one off the wire. */
    web_store_ptr_t bad = { "10.0.0.7", "<script>", 1, 2 };
    web_ptr_load_row(&p, &bad);
    WT_EQ(web_ptr_get(&p, "10.0.0.7", name, NULL), 0);
    web_ptr_note_persist(&p, 0, 3);
    web_ptr_stats(&p, &st);
    WT_EQ(st.persist_errors, 1);
    WT_EQ(st.db_evictions, 3);
    web_ptr_destroy(&p);
}

/* The identity readers the Devices and Lookup routes use: an IP's
 * binding and current names, a MAC's binding, device hostname and
 * first_seen, each current only for its TTL. */
static void test_ident_readers(void) {
    web_ident_t id;
    WT_EQ(web_ident_init(&id, 16, 16), 0);
    feed(&id, "{\"type\":\"arp\",\"ts\":1,\"ip\":\"10.0.1.5\",\"mac\":"
              "\"00:11:22:33:44:55\"}", T0);
    feed(&id, "{\"type\":\"dhcp_lease\",\"ts\":1,\"ip\":\"10.0.1.5\","
              "\"hostname\":\"nas\"}", T0);
    feed(&id, "{\"type\":\"nbns_name\",\"ts\":1,\"ip\":\"10.0.1.5\","
              "\"name\":\"NAS\",\"suffix\":0}", T0);
    feed(&id, "{\"type\":\"probe_client\",\"ts\":1,\"mac\":"
              "\"00:11:22:33:44:55\",\"first_seen\":1792000000}", T0);
    char mac[WEB_KEY_MAX + 1], ip[WEB_KEY_MAX + 1];
    web_id_name_t nm[WEB_ID_SRC_COUNT], dh;
    long long fs;
    WT_EQ(web_ident_ip_info(&id, "10.0.1.5", T0, mac, nm), 1);
    WT_ASSERT(!strcmp(mac, "00:11:22:33:44:55"));
    WT_ASSERT(!strcmp(nm[WEB_ID_SRC_DHCP].name, "nas"));
    WT_ASSERT(!strcmp(nm[WEB_ID_SRC_NBNS].name, "NAS"));
    WT_EQ(nm[WEB_ID_SRC_MDNS].t, -1);
    WT_EQ(web_ident_ip_info(&id, "10.0.1.5", T0 + WEB_ID_TTL_S + 1, mac, nm), 1);
    WT_EQ(nm[WEB_ID_SRC_DHCP].t, -1);           /* stale */
    WT_EQ(web_ident_ip_info(&id, "10.0.1.6", T0, mac, nm), 0);
    WT_EQ(web_ident_mac_info(&id, "00:11:22:33:44:55", T0, ip, &dh, &fs), 1);
    WT_ASSERT(!strcmp(ip, "10.0.1.5"));
    WT_EQ(fs, 1792000000);
    WT_EQ(web_ident_mac_info(&id, "00:11:22:33:44:66", T0, ip, &dh, &fs), 0);
    WT_EQ(fs, -1);
    web_ident_destroy(&id);
}

/* #165: the dns record sloth writes for a PTR answer
 * (include/jsonl_ptr_fixture.h, which tests/test_jsonl.c ::
 * test_emit_dns_ptr_answer pins sloth's writer to), through the decoder
 * and the identity tables into the cache, then through the store
 * thread's persist (web_anomaly_step, which owns the writer) into
 * slothweb.db passive_ptr, and back at a restart. The persist half is
 * what this test alone covers: seen red (passive_ptr empty, the
 * restored cache missing the name) with web_anomaly.c's persist guard
 * `if (a->cfg.ptr)` made `if (0)`. */

#ifdef WITH_SQLITE
static int passive_ptr_int(const char *path, const char *sql) {
    sqlite3 *db = NULL;
    int v = -1;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
            sqlite3_step(st) == SQLITE_ROW)
            v = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
    sqlite3_close(db);
    return v;
}

/* The store thread's side: persist on a minute boundary, then a fresh
 * cache restored from the file. */
static void ptr_through_the_store(web_ptr_t *p) {
    char dir[64], path[128], err[512], s[160];
    snprintf(dir, sizeof(dir), "/tmp/slothweb-ptr-XXXXXX");
    WT_ASSERT(mkdtemp(dir) != NULL);
    snprintf(path, sizeof(path), "%s/w.db", dir);
    web_store_t st;
    WT_EQ(web_store_open(&st, path, err, sizeof(err)), 0);
    web_baseline_t bl;
    WT_EQ(web_baseline_init(&bl, 16), 0);
    web_anom_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.bl = &bl;
    cfg.store = &st;
    cfg.ptr = p;
    cfg.max_keys = 16;
    web_anomaly_t an;
    WT_EQ(web_anomaly_init(&an, 8, &cfg), 0);
    web_anomaly_step(&an, T0);
    web_anomaly_step(&an, T0 + 120);       /* minutes ran: persist */
    WT_EQ(passive_ptr_int(path, "SELECT COUNT(*) FROM passive_ptr"), 1);
    WT_EQ(passive_ptr_int(path, "SELECT COUNT(*) FROM passive_ptr WHERE"
                                " ip='203.0.113.25' AND name='" SLOTH_PTR_NAME "'"
                                " AND first_seen=1792627200"), 1);
    web_anomaly_destroy(&an);

    web_ptr_t back;
    WT_EQ(web_ptr_init(&back, 8), 0);
    cfg.ptr = &back;
    WT_EQ(web_anomaly_init(&an, 8, &cfg), 0);
    WT_EQ(web_anomaly_restore(&an, T0 + 180), 0);
    char name[WEB_PTR_NAME_MAX + 1];
    long long t = 0;
    WT_EQ(web_ptr_get(&back, "203.0.113.25", name, &t), 1);
    WT_ASSERT(!strcmp(name, SLOTH_PTR_NAME));
    WT_EQ(t, T0);
    web_anomaly_destroy(&an);
    web_ptr_destroy(&back);
    web_baseline_destroy(&bl);
    web_store_close(&st);
    unlink(path);
    snprintf(s, sizeof(s), "%s-wal", path); unlink(s);
    snprintf(s, sizeof(s), "%s-shm", path); unlink(s);
    rmdir(dir);
}
#endif

static void test_sloth_ptr_record_lands_in_passive_ptr(void) {
    web_ident_t id;
    web_ptr_t p;
    WT_EQ(web_ident_init(&id, 16, 16), 0);
    WT_EQ(web_ptr_init(&p, 8), 0);
    web_ident_set_ptr(&id, &p);
    feed(&id, SLOTH_PTR_LINE, T0);
    web_ptr_stats_t st;
    web_ptr_stats(&p, &st);
    WT_EQ(st.seen, 1);
    WT_EQ(st.stored, 1);
    WT_EQ(st.empty, 0);
    WT_EQ(st.refused, 0);
    char name[WEB_PTR_NAME_MAX + 1];
    long long t = 0;
    WT_EQ(web_ptr_get(&p, "203.0.113.25", name, &t), 1);
    WT_ASSERT(!strcmp(name, SLOTH_PTR_NAME));
    WT_EQ(t, T0);
#ifdef WITH_SQLITE
    if (web_store_available()) ptr_through_the_store(&p);
#endif
    web_ptr_destroy(&p);
    web_ident_destroy(&id);
}

void run_ptr_tests(void) {
    WT_RUN(test_reverse_names);
    WT_RUN(test_records);
    WT_RUN(test_bound_and_dirty);
    WT_RUN(test_sloth_ptr_record_lands_in_passive_ptr);
    WT_RUN(test_ident_readers);
}
