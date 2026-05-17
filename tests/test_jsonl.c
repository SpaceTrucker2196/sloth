#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "jsonl.h"
#include "tls_log.h"
#include "dns_log.h"
#include "ntp_log.h"
#include "icmp_log.h"

/* Each test opens a fresh temp file, exercises the emitter, then reads
 * the file back and asserts on the recorded line(s). */

static char tmp_path[] = "/tmp/sloth_jsonl_XXXXXX";

static void open_fresh(void) {
    /* Build a unique path; close immediately so jsonl_open can append. */
    int fd = mkstemp(tmp_path);
    if (fd >= 0) close(fd);
    jsonl_close();
    /* truncate any previous content */
    FILE *fp = fopen(tmp_path, "w"); if (fp) fclose(fp);
    ASSERT(jsonl_open(tmp_path));
}

static char *slurp(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    static char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    return buf;
}

static int contains(const char *hay, const char *needle) {
    return strstr(hay, needle) != NULL;
}

/* ── open / close ────────────────────────────────────────── */

static void test_open_close(void) {
    open_fresh();
    ASSERT(jsonl_is_open());
    jsonl_close();
    ASSERT(!jsonl_is_open());
}

static void test_emit_without_open_is_noop(void) {
    jsonl_close();
    dns_log_entry_t e; memset(&e, 0, sizeof(e));
    snprintf(e.src, sizeof(e.src), "1.2.3.4");
    snprintf(e.qname, sizeof(e.qname), "example.com");
    jsonl_emit_dns(&e);  /* must not crash */
    ASSERT(1);
}

static void test_open_invalid_path_fails(void) {
    jsonl_close();
    ASSERT(!jsonl_open("/this/should/not/exist/nopath/out.jsonl"));
    ASSERT(!jsonl_is_open());
}

/* ── per-type emit ───────────────────────────────────────── */

static void test_emit_dns_writes_fields(void) {
    open_fresh();
    dns_log_entry_t e; memset(&e, 0, sizeof(e));
    e.ts = 1700000000;
    snprintf(e.src,    sizeof(e.src),    "192.168.1.5");
    snprintf(e.qname,  sizeof(e.qname),  "example.com");
    snprintf(e.qtype,  sizeof(e.qtype),  "A");
    snprintf(e.answer, sizeof(e.answer), "93.184.216.34");
    e.is_resp = 1;
    jsonl_emit_dns(&e);
    jsonl_close();
    char *body = slurp(tmp_path);
    ASSERT(body != NULL);
    ASSERT(contains(body, "\"type\":\"dns\""));
    ASSERT(contains(body, "\"src\":\"192.168.1.5\""));
    ASSERT(contains(body, "\"qname\":\"example.com\""));
    ASSERT(contains(body, "\"qtype\":\"A\""));
    ASSERT(contains(body, "\"answer\":\"93.184.216.34\""));
    ASSERT(contains(body, "\"ts\":1700000000"));
    ASSERT(contains(body, "\"is_resp\":1"));
}

static void test_emit_tls_writes_ja3(void) {
    open_fresh();
    tls_log_entry_t e; memset(&e, 0, sizeof(e));
    e.ts = 1700000001;
    snprintf(e.src, sizeof(e.src), "10.0.0.5");
    snprintf(e.dst, sizeof(e.dst), "93.184.216.34");
    snprintf(e.host, sizeof(e.host), "example.com");
    snprintf(e.tls_ver, sizeof(e.tls_ver), "TLS 1.3");
    snprintf(e.ja3, sizeof(e.ja3), "deadbeefcafef00d00112233445566ff");
    jsonl_emit_tls(&e);
    jsonl_close();
    char *body = slurp(tmp_path);
    ASSERT(contains(body, "\"type\":\"tls\""));
    ASSERT(contains(body, "\"ja3\":\"deadbeefcafef00d00112233445566ff\""));
    ASSERT(contains(body, "\"host\":\"example.com\""));
    ASSERT(contains(body, "\"ver\":\"TLS 1.3\""));
}

static void test_emit_ntp_writes_numeric_fields(void) {
    open_fresh();
    ntp_log_entry_t e; memset(&e, 0, sizeof(e));
    e.ts = 1700000002;
    e.version = 4; e.stratum = 1;
    snprintf(e.src,  sizeof(e.src),  "10.0.0.1");
    snprintf(e.dst,  sizeof(e.dst),  "192.168.1.5");
    snprintf(e.mode, sizeof(e.mode), "server");
    snprintf(e.ref,  sizeof(e.ref),  "GPS");
    jsonl_emit_ntp(&e);
    jsonl_close();
    char *body = slurp(tmp_path);
    ASSERT(contains(body, "\"type\":\"ntp\""));
    ASSERT(contains(body, "\"version\":4"));
    ASSERT(contains(body, "\"stratum\":1"));
    ASSERT(contains(body, "\"mode\":\"server\""));
    ASSERT(contains(body, "\"ref\":\"GPS\""));
}

static void test_emit_icmp_writes_seq(void) {
    open_fresh();
    icmp_log_entry_t e; memset(&e, 0, sizeof(e));
    e.ts = 1700000003;
    e.type = 8; e.code = 0; e.seq = 42; e.is_v6 = 0;
    snprintf(e.src, sizeof(e.src), "192.168.1.5");
    snprintf(e.dst, sizeof(e.dst), "8.8.8.8");
    snprintf(e.desc, sizeof(e.desc), "Echo Req");
    jsonl_emit_icmp(&e);
    jsonl_close();
    char *body = slurp(tmp_path);
    ASSERT(contains(body, "\"type\":\"icmp\""));
    ASSERT(contains(body, "\"seq\":42"));
    ASSERT(contains(body, "\"desc\":\"Echo Req\""));
    ASSERT(contains(body, "\"v6\":0"));
}

static void test_emit_alert_writes_count(void) {
    open_fresh();
    alert_t a; memset(&a, 0, sizeof(a));
    a.last_seen = 1700000004;
    a.sev = ALERT_SEV_CRIT;
    a.type = ALERT_TYPE_THREAT_DOMAIN;
    a.count = 7;
    snprintf(a.title,  sizeof(a.title),  "THREAT_DOMAIN");
    snprintf(a.detail, sizeof(a.detail), "saw malware.testing.com");
    snprintf(a.key,    sizeof(a.key),    "threat-d:malware.testing.com");
    jsonl_emit_alert(&a);
    jsonl_close();
    char *body = slurp(tmp_path);
    ASSERT(contains(body, "\"type\":\"alert\""));
    ASSERT(contains(body, "\"title\":\"THREAT_DOMAIN\""));
    ASSERT(contains(body, "\"count\":7"));
    ASSERT(contains(body, "\"detail\":\"saw malware.testing.com\""));
}

/* ── escaping ────────────────────────────────────────────── */

static void test_json_escapes_quotes_and_backslash(void) {
    open_fresh();
    dns_log_entry_t e; memset(&e, 0, sizeof(e));
    e.ts = 1700000005;
    snprintf(e.qname, sizeof(e.qname), "weird \"\\\\name");
    jsonl_emit_dns(&e);
    jsonl_close();
    char *body = slurp(tmp_path);
    /* Resulting JSON should contain \" and \\ escapes. */
    ASSERT(contains(body, "\\\""));
    ASSERT(contains(body, "\\\\"));
}

static void test_json_escapes_newline_in_field(void) {
    open_fresh();
    dns_log_entry_t e; memset(&e, 0, sizeof(e));
    e.ts = 1700000006;
    snprintf(e.qname, sizeof(e.qname), "ab\ncd");
    jsonl_emit_dns(&e);
    jsonl_close();
    char *body = slurp(tmp_path);
    ASSERT(contains(body, "\\n"));
}

/* ── per-record() integration (a parallel write through the log API) ── */

static void test_dns_log_record_writes_jsonl(void) {
    open_fresh();
    dns_log_clear();

    dns_log_entry_t e; memset(&e, 0, sizeof(e));
    e.ts = 1700000007;
    snprintf(e.src,    sizeof(e.src),    "10.0.0.10");
    snprintf(e.qname,  sizeof(e.qname),  "tracker.example.com");
    snprintf(e.qtype,  sizeof(e.qtype),  "A");
    dns_log_record(&e);
    jsonl_close();
    char *body = slurp(tmp_path);
    ASSERT(contains(body, "\"qname\":\"tracker.example.com\""));
}

/* ── Suite ───────────────────────────────────────────────── */

void run_jsonl_tests(void) {
    TEST_SUITE("jsonl open/close");
    RUN_TEST(test_open_close);
    RUN_TEST(test_emit_without_open_is_noop);
    RUN_TEST(test_open_invalid_path_fails);

    TEST_SUITE("jsonl emit");
    RUN_TEST(test_emit_dns_writes_fields);
    RUN_TEST(test_emit_tls_writes_ja3);
    RUN_TEST(test_emit_ntp_writes_numeric_fields);
    RUN_TEST(test_emit_icmp_writes_seq);
    RUN_TEST(test_emit_alert_writes_count);

    TEST_SUITE("jsonl escaping");
    RUN_TEST(test_json_escapes_quotes_and_backslash);
    RUN_TEST(test_json_escapes_newline_in_field);

    TEST_SUITE("jsonl record-hook");
    RUN_TEST(test_dns_log_record_writes_jsonl);
}
