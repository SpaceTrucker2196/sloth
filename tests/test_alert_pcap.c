#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <sys/resource.h>
#include "evidence_manifest.h"
#include "runner.h"
#include "sloth.h"
#include "alerts.h"
#include "alert_pcap.h"
#include "beacon_detect.h"
#include "tune.h"
#include "sloth_clock.h"

/* ── Helpers ─────────────────────────────────────────────── */

static char tmp_dir[] = "/tmp/sloth_pcap_XXXXXX";

static void ensure_tmp_dir(void) {
    /* mkdtemp creates the directory and writes the final name back. */
    char *d = mkdtemp(tmp_dir);
    (void)d;
    alert_pcap_set_dir(tmp_dir);
}

static void seed_packet(sloth_state_t *s,
                         const char *src, const char *dst,
                         uint16_t sport, uint16_t dport,
                         uint32_t ts_sec) {
    if (s->pkt_count >= MAX_PACKETS) return;
    int slot = s->pkt_head;
    packet_info_t *p = &s->packets[slot];
    memset(p, 0, sizeof(*p));
    snprintf(p->src, sizeof(p->src), "%s", src);
    snprintf(p->dst, sizeof(p->dst), "%s", dst);
    p->src_port = sport;
    p->dst_port = dport;
    p->ts_sec   = ts_sec;
    p->ts_usec  = 0;
    p->len      = 64;
    p->raw_len  = 32;
    for (int i = 0; i < 32; i++) p->raw[i] = (uint8_t)(i + 1);
    s->pkt_head = (s->pkt_head + 1) % MAX_PACKETS;
    if (s->pkt_count < MAX_PACKETS) s->pkt_count++;
}

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static long file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (long)st.st_size;
}

/* ── Tests ───────────────────────────────────────────────── */

static void test_set_dir_enables_disables(void) {
    /* A private dir of our own — a shared one like /tmp is refused
     * (#87, test_set_dir_refuses_shared_tmp). */
    ensure_tmp_dir();
    ASSERT(alert_pcap_enabled());
    alert_pcap_set_dir(NULL);
    ASSERT(!alert_pcap_enabled());
    alert_pcap_set_dir("");
    ASSERT(!alert_pcap_enabled());
}

static void test_dump_writes_pcap_for_match(void) {
    ensure_tmp_dir();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_packet(&s, "192.168.1.5", "203.0.113.7", 33445, 443, 1700000000);
    seed_packet(&s, "203.0.113.7", "192.168.1.5", 443,   33445, 1700000001);
    seed_packet(&s, "192.168.1.5", "8.8.8.8",     54321, 53,    1700000002);

    alert_t a; memset(&a, 0, sizeof(a));
    snprintf(a.title,    sizeof(a.title),    "THREAT_IP");
    snprintf(a.match_ip, sizeof(a.match_ip), "203.0.113.7");
    a.match_port = 443;
    char path[512];
    int n = alert_pcap_dump(&s, &a, path, sizeof(path));
    ASSERT_EQ(n, 2);
    ASSERT(file_exists(path));
    /* pcap global header is 24 bytes; each per-packet header is 16 +
       raw_len(32). Two packets → 24 + 2*(16+32) = 120 bytes. */
    ASSERT_EQ(file_size(path), 120);
}

static void test_dump_skips_when_no_match(void) {
    ensure_tmp_dir();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_packet(&s, "192.168.1.5", "8.8.8.8", 54321, 53, 1700000000);

    alert_t a; memset(&a, 0, sizeof(a));
    snprintf(a.title,    sizeof(a.title),    "THREAT_IP");
    snprintf(a.match_ip, sizeof(a.match_ip), "203.0.113.7");
    a.match_port = 443;

    char path[512] = "untouched";
    int n = alert_pcap_dump(&s, &a, path, sizeof(path));
    ASSERT_EQ(n, 0);
    /* path should still be "untouched" because no file was written */
    ASSERT_STR(path, "untouched");
}

static void test_dump_port_zero_matches_any(void) {
    ensure_tmp_dir();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_packet(&s, "10.0.0.99", "192.168.1.5", 11111, 22222, 1700000000);
    seed_packet(&s, "10.0.0.99", "192.168.1.5", 33333, 22222, 1700000001);

    alert_t a; memset(&a, 0, sizeof(a));
    snprintf(a.title,    sizeof(a.title),    "PORT_SCAN");
    snprintf(a.match_ip, sizeof(a.match_ip), "10.0.0.99");
    a.match_port = 0;  /* any port */

    char path[512];
    int n = alert_pcap_dump(&s, &a, path, sizeof(path));
    ASSERT_EQ(n, 2);
}

static void test_dump_noop_when_dir_disabled(void) {
    alert_pcap_set_dir(NULL);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_packet(&s, "192.168.1.5", "203.0.113.7", 33445, 443, 1700000000);

    alert_t a; memset(&a, 0, sizeof(a));
    snprintf(a.match_ip, sizeof(a.match_ip), "203.0.113.7");
    ASSERT_EQ(alert_pcap_dump(&s, &a, NULL, 0), 0);
}

static void test_dump_skips_alert_without_match_ip(void) {
    ensure_tmp_dir();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_packet(&s, "1.2.3.4", "5.6.7.8", 1, 2, 1700000000);

    alert_t a; memset(&a, 0, sizeof(a));
    snprintf(a.title, sizeof(a.title), "DEAUTH_FLOOD");
    /* match_ip empty */
    ASSERT_EQ(alert_pcap_dump(&s, &a, NULL, 0), 0);
}

/* ── Export permissions, #87 ────────────────────────────── */

/* Per-alert pcaps hold raw packets — cleartext credentials among them
 * when a CLEARTEXT_CREDS flow matches. They get the same private-dir /
 * private-file guarantee as the handshake export. */

static char g_ap87[80];

static int ap87_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    return (int)(st.st_mode & 07777);
}

/* Evidence files only. The session manifest (#92 slice 3) sits in the
 * same directory and has its own assertions in test_evidence_manifest.c;
 * counting it here would make every "nothing partial was left" check
 * depend on whether an earlier export in the test created one. */
static int ap87_entries(void) {
    DIR *d = opendir(g_ap87);
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..") &&
            !evidence_manifest_is_name(e->d_name)) n++;
    closedir(d);
    return n;
}

static void ap87_cleanup(void) {
    alert_pcap_set_dir(NULL);
    DIR *d = opendir(g_ap87);
    if (d) {
        struct dirent *e;
        char p[400];
        while ((e = readdir(d)) != NULL) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            snprintf(p, sizeof(p), "%s/%s", g_ap87, e->d_name);
            unlink(p);
        }
        closedir(d);
    }
    unlink(g_ap87);
    rmdir(g_ap87);
}

static void ap87_setup(void) {
    snprintf(g_ap87, sizeof(g_ap87), "/tmp/sloth_test_ap87_%d", (int)getpid());
    ap87_cleanup();
}

static void ap87_alert(sloth_state_t *s, alert_t *a) {
    memset(s, 0, sizeof(*s));
    seed_packet(s, "192.168.1.5", "203.0.113.7", 33445, 443, 1700000000);
    memset(a, 0, sizeof(*a));
    snprintf(a->title,    sizeof(a->title),    "THREAT_IP");
    snprintf(a->match_ip, sizeof(a->match_ip), "203.0.113.7");
}

/* A world-writable shared directory is refused outright. */
static void test_set_dir_refuses_shared_tmp(void) {
    ASSERT_EQ(alert_pcap_set_dir("/tmp"), -1);
    ASSERT(!alert_pcap_enabled());
    ASSERT(alert_pcap_error()[0] != '\0');
}

static void test_set_dir_creates_private_under_permissive_umask(void) {
    ap87_setup();
    mode_t old = umask(022);
    ASSERT_EQ(alert_pcap_set_dir(g_ap87), 0);
    ASSERT_EQ(ap87_mode(g_ap87), 0700);
    sloth_state_t s; alert_t a;
    ap87_alert(&s, &a);
    char path[512];
    ASSERT_EQ(alert_pcap_dump(&s, &a, path, sizeof(path)), 1);
    ASSERT_EQ(ap87_mode(path), 0600);
    umask(old);
    ap87_cleanup();
}

static void test_set_dir_refuses_permissive_existing(void) {
    ap87_setup();
    mkdir(g_ap87, 0700);
    chmod(g_ap87, 0755);
    ASSERT_EQ(alert_pcap_set_dir(g_ap87), -1);
    ASSERT(!alert_pcap_enabled());
    ASSERT_EQ(ap87_mode(g_ap87), 0755);            /* not chmod'ed */
    ap87_cleanup();
}

static void test_set_dir_refuses_symlink(void) {
    ap87_setup();
    char target[120];
    snprintf(target, sizeof(target), "%s_target", g_ap87);
    rmdir(target);
    mkdir(target, 0700);
    ASSERT_EQ(symlink(target, g_ap87), 0);
    ASSERT_EQ(alert_pcap_set_dir(g_ap87), -1);
    ASSERT(!alert_pcap_enabled());
    rmdir(target);
    ap87_cleanup();
}

/* Two dumps for the same alert in the same second used to share a
 * name, the second overwriting the first. Exclusive create keeps both. */
static void test_dump_same_name_does_not_overwrite(void) {
    ap87_setup();
    ASSERT_EQ(alert_pcap_set_dir(g_ap87), 0);
    sloth_state_t s; alert_t a;
    ap87_alert(&s, &a);
    char p1[512], p2[512];
    ASSERT_EQ(alert_pcap_dump(&s, &a, p1, sizeof(p1)), 1);
    ASSERT_EQ(alert_pcap_dump(&s, &a, p2, sizeof(p2)), 1);
    ASSERT(strcmp(p1, p2) != 0);
    ASSERT_EQ(ap87_entries(), 2);
    ap87_cleanup();
}

/* A failed write is returned, counted, and leaves no partial pcap. */
static void test_dump_write_failure_visible(void) {
    ap87_setup();
    ASSERT_EQ(alert_pcap_set_dir(g_ap87), 0);
    ASSERT_EQ(alert_pcap_failures(), 0);
    sloth_state_t s; alert_t a;
    ap87_alert(&s, &a);

    struct rlimit old, lim;
    getrlimit(RLIMIT_FSIZE, &old);
    lim = old;
    lim.rlim_cur = 8;
    void (*prev)(int) = signal(SIGXFSZ, SIG_IGN);
    setrlimit(RLIMIT_FSIZE, &lim);
    int n = alert_pcap_dump(&s, &a, NULL, 0);
    setrlimit(RLIMIT_FSIZE, &old);
    signal(SIGXFSZ, prev);

    ASSERT_EQ(n, -1);
    ASSERT_EQ(alert_pcap_failures(), 1);
    ASSERT(strstr(alert_pcap_error(), "write failed") != NULL);
    ASSERT_EQ(ap87_entries(), 0);
    ap87_cleanup();
}

/* ── Integration: rule fires populate match_ip ──────────── */

static void test_threat_ip_rule_sets_match_fields(void) {
    alert_pcap_set_dir(NULL);   /* keep pcap disabled — just check fields */
    alerts_clear();

    sloth_state_t s; memset(&s, 0, sizeof(s));
    conn_t *c = &s.conns[s.conn_count++];
    snprintf(c->local_addr,  sizeof(c->local_addr),  "192.168.1.5");
    snprintf(c->remote_addr, sizeof(c->remote_addr), "192.0.2.66");
    c->local_port  = 33445;
    c->remote_port = 443;
    c->proto       = PROTO_TCP;

    alerts_update(&s);
    int found = -1;
    for (int i = 0; i < s.alert_count; i++) {
        if (s.alerts[i].type == ALERT_TYPE_THREAT_IP) { found = i; break; }
    }
    ASSERT(found >= 0);
    ASSERT_STR(s.alerts[found].match_ip, "192.0.2.66");
    ASSERT_EQ((int)s.alerts[found].match_port, 443);
}

/* ── Export policy: CRIT only, once per finding (#96) ─────
 *
 * The behaviour these pin was measured on a live sensor before it
 * existed: 16,131,622 files and 78 GB in --pcap-dir, 17.9 per second,
 * 98.6% of them one WARN-severity rule re-exported after every
 * alert-engine eviction. Across the whole corpus those 16.1M files held
 * about 191 distinct (destination, port) pairs.
 *
 * Both knobs open all the way up, so a full capture stays available —
 * the defaults just stop keeping the same evidence millions of times. */

static int find_threat_ip(const sloth_state_t *s);

static int ap_find(const sloth_state_t *s, alert_type_t t) {
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == t) return i;
    return -1;
}

/* A WARN alert that carries a match_ip. BEACONING is the real one from
 * the measurement; seeded directly rather than driven through
 * beacon_detect so the case is about the export policy and not about
 * periodicity maths. */
static void ap_seed_warn_with_match(sloth_state_t *s) {
    memset(s, 0, sizeof(*s));
    seed_packet(s, "192.168.1.5", "198.51.100.9", 33445, 443, 1700000000);
    bd_clear();
    for (int i = 0; i < 12; i++)
        bd_observe("198.51.100.9", 443, 1700000000 + i * 60);
}

static void test_warn_alerts_are_not_exported_by_default(void) {
    ap87_setup();
    ASSERT_EQ(alert_pcap_set_dir(g_ap87), 0);
    alerts_clear(); tune_reset();
    /* The default IS the documented contract: `--help` has always said
       "when a critical alert fires", and the export never checked. */
    ASSERT_EQ((long long)tune_val(TUNE_PCAP_MIN_SEVERITY), 2);

    sloth_state_t s; ap_seed_warn_with_match(&s);
    alerts_update(&s);
    int i = ap_find(&s, ALERT_TYPE_BEACONING);
    if (i >= 0) {
        /* If the detector fired, it is WARN and must not have exported. */
        ASSERT_EQ((int)s.alerts[i].sev, (int)ALERT_SEV_WARN);
        ASSERT_EQ(ap87_entries(), 0);
    }
    alerts_clear(); tune_reset(); ap87_cleanup();
}

static void test_min_severity_zero_restores_the_full_capture(void) {
    ap87_setup();
    ASSERT_EQ(alert_pcap_set_dir(g_ap87), 0);
    alerts_clear(); tune_reset();
    char err[256];
    ASSERT_EQ(tune_set("pcap.min_severity=0", err, sizeof(err)), 0);

    sloth_state_t s; ap_seed_warn_with_match(&s);
    alerts_update(&s);
    int i = ap_find(&s, ALERT_TYPE_BEACONING);
    if (i >= 0) {
        /* Same WARN alert, now exported — which is what "allow a full
           capture" has to mean, and the pre-#96 behaviour. */
        ASSERT_EQ((int)s.alerts[i].sev, (int)ALERT_SEV_WARN);
        ASSERT_EQ(ap87_entries(), 1);
    }
    alerts_clear(); tune_reset(); ap87_cleanup();
}

/* Seed the threat connection the engine turns into a CRIT THREAT_IP. */
static time_t   g_ap_wall = 1700000000;
static time_t   ap_wall(void)   { return g_ap_wall; }
static uint64_t ap_mono(void)   { return (uint64_t)g_ap_wall * 1000u; }

static void ap_seed_threat(sloth_state_t *s) {
    memset(s, 0, sizeof(*s));
    conn_t *c = &s->conns[s->conn_count++];
    snprintf(c->local_addr,  sizeof(c->local_addr),  "192.168.1.5");
    snprintf(c->remote_addr, sizeof(c->remote_addr), "192.0.2.66");
    c->local_port = 33445; c->remote_port = 443; c->proto = PROTO_TCP;
    seed_packet(s, "192.168.1.5", "192.0.2.66", 33445, 443, 1700000000);
}

/* Drive the THREAT_IP incident through resolve → re-fire, which is the
 * state the 16.1M duplicate pcaps came from: fire() only treats a key as
 * "already seen" while its entry is LIVE (`idx >= 0 && !resolved`), so a
 * resolved key falls through to the new-entry path, which memsets the
 * slot — clearing pcap_dumped — and mints a fresh incident id. What
 * survives is the key's side row in the engine (#112), which is what the
 * cooldown reads and what hands pcap_path back to the new incident.
 *
 * This used to flood the engine with PORT_SCAN until the THREAT_IP entry
 * was evicted. That stopped working when eviction learned per-type
 * fairness (#96): the flood's victim is now the flooding type's own
 * oldest entry, so a rule holding ONE slot is the last thing evicted and
 * a THREAT_IP incident survives any amount of PORT_SCAN. That is the
 * point of the fairness change, so the harness moved to the other route
 * to the same slot-reuse, rather than the policy bending to the test.
 * Expiry is also the more faithful route: it is what actually recycled
 * engine slots in the field, 300s at a time. */
static void ap_churn_engine(void) {
    sloth_state_t empty;
    memset(&empty, 0, sizeof(empty));
    g_ap_wall += ALERT_RESOLVE_AFTER_S + 1;
    /* No rule re-asserts the key against empty state, so expire_incidents
       resolves it; the next fire of the same key opens a new incident. */
    alerts_update(&empty);
}

static void test_a_refired_finding_does_not_export_twice(void) {
    /* The churn case, which is where the 78 GB came from. An evicted
       and re-fired alert looks brand new to the engine: fire_inv()
       memsets the slot, clearing pcap_dumped, and incident_id_make()
       hands it a FRESH incident id — so neither of those can be the
       dedupe key. The cooldown keys on the alert key instead. */
    sloth_clock_test_set(ap_mono, ap_wall);
    g_ap_wall = 1700000000;
    ap87_setup();
    ASSERT_EQ(alert_pcap_set_dir(g_ap87), 0);
    alerts_clear(); tune_reset();

    sloth_state_t s; ap_seed_threat(&s);
    alerts_update(&s);
    ASSERT_EQ(ap87_entries(), 1);           /* CRIT, exported once */
    char first_path[ALERT_PCAP_PATH_LEN] = "";
    int i = find_threat_ip(&s);
    ASSERT(i >= 0);
    if (i >= 0) snprintf(first_path, sizeof(first_path), "%s", s.alerts[i].pcap_path);
    ASSERT(first_path[0] != '\0');

    ap_churn_engine();                      /* resolve, so it re-fires fresh */
    ap_seed_threat(&s);
    alerts_update(&s);                      /* re-fires as a new entry */
    i = find_threat_ip(&s);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(s.alerts[i].pcap_dumped, 1);
        /* The new incident still names the file its finding's frames
           are in (#112). Before the side row, the memset left it empty,
           so the view and alert.create showed no evidence for an
           incident whose evidence was on disk. */
        ASSERT_STR(s.alerts[i].pcap_path, first_path);
        ASSERT_EQ((int)s.alerts[i].reopen_count, 1);
    }
    /* Still ONE file: the finding is the same even though the engine
       entry and the incident id are not. */
    ASSERT_EQ(ap87_entries(), 1);

    alerts_clear(); tune_reset(); ap87_cleanup();
    sloth_clock_test_set(NULL, NULL);
}

static void test_cooldown_zero_restores_the_full_capture(void) {
    sloth_clock_test_set(ap_mono, ap_wall);
    g_ap_wall = 1700000000;
    ap87_setup();
    ASSERT_EQ(alert_pcap_set_dir(g_ap87), 0);
    alerts_clear(); tune_reset();
    char err[256];
    ASSERT_EQ(tune_set("pcap.key_cooldown_secs=0", err, sizeof(err)), 0);

    sloth_state_t s; ap_seed_threat(&s);
    alerts_update(&s);
    ASSERT_EQ(ap87_entries(), 1);

    ap_churn_engine();
    ap_seed_threat(&s);
    alerts_update(&s);
    /* With the cooldown off, the re-fire exports again — the behaviour
       that produced the 78 GB, still reachable on request, which is the
       point of making it a parameter rather than a fix. */
    ASSERT_EQ(ap87_entries(), 2);

    alerts_clear(); tune_reset(); ap87_cleanup();
    sloth_clock_test_set(NULL, NULL);
}

/* ── #92: a failed export retries instead of being lost forever ── */

static int find_threat_ip(const sloth_state_t *s) {
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == ALERT_TYPE_THREAT_IP) return i;
    return -1;
}

/* Before #92, alerts_update()'s dump_new_alert_pcaps() set pcap_dumped
 * unconditionally, so a transient write failure (disk full, permission
 * lost) permanently lost that incident's evidence: pcap_dumped stayed 1
 * and the export was never attempted again. This drives the real engine
 * through alerts_update() (not alert_pcap_dump() directly) so the
 * regression is pinned at the call site that had the bug. */
static void test_dump_retries_after_transient_failure(void) {
    ap87_setup();
    ASSERT_EQ(alert_pcap_set_dir(g_ap87), 0);
    alerts_clear();

    sloth_state_t s; memset(&s, 0, sizeof(s));
    conn_t *c = &s.conns[s.conn_count++];
    snprintf(c->local_addr,  sizeof(c->local_addr),  "192.168.1.5");
    snprintf(c->remote_addr, sizeof(c->remote_addr), "192.0.2.66");
    c->local_port  = 33445;
    c->remote_port = 443;
    c->proto       = PROTO_TCP;
    seed_packet(&s, "192.168.1.5", "192.0.2.66", 33445, 443, 1700000000);

    struct rlimit old, lim;
    getrlimit(RLIMIT_FSIZE, &old);
    lim = old;
    lim.rlim_cur = 8;
    void (*prev)(int) = signal(SIGXFSZ, SIG_IGN);
    setrlimit(RLIMIT_FSIZE, &lim);
    alerts_update(&s);
    setrlimit(RLIMIT_FSIZE, &old);
    signal(SIGXFSZ, prev);

    int idx = find_threat_ip(&s);
    ASSERT(idx >= 0);
    ASSERT_EQ(s.alerts[idx].pcap_dumped, 0);
    ASSERT_EQ(s.alerts[idx].pcap_write_failures, 1);
    ASSERT_STR(s.alerts[idx].pcap_path, "");
    ASSERT_EQ(ap87_entries(), 0);   /* no partial pcap left behind */

    /* Next tick, with room to write: the same incident (same engine
     * slot — the dedup key hasn't changed) gets a real export. */
    alerts_update(&s);
    idx = find_threat_ip(&s);
    ASSERT(idx >= 0);
    ASSERT_EQ(s.alerts[idx].pcap_dumped, 1);
    ASSERT_EQ(s.alerts[idx].pcap_write_failures, 1);   /* not reset by success */
    ASSERT(s.alerts[idx].pcap_path[0] != '\0');
    ASSERT_EQ(ap87_entries(), 1);

    alerts_clear();
    ap87_cleanup();
}

/* pcap_write_failures belongs to the KEY, not the incident (#112):
 * jsonl-schema.md documents it as carried across incidents with
 * pcap_path, via the alert_side_t copy-back in fire_inv. Without this
 * test that copy-back could be deleted and nothing would notice - the
 * reviewer of #112 found exactly that gap. Fail one export, let the
 * incident resolve and re-fire as a NEW incident (fresh incident_id),
 * and the count must still be there. */
static void test_write_failures_survive_reopen(void) {
    sloth_clock_test_set(ap_mono, ap_wall);
    g_ap_wall = 1700000000;
    ap87_setup();
    ASSERT_EQ(alert_pcap_set_dir(g_ap87), 0);
    alerts_clear(); tune_reset();

    sloth_state_t s; ap_seed_threat(&s);
    struct rlimit old, lim;
    getrlimit(RLIMIT_FSIZE, &old);
    lim = old; lim.rlim_cur = 8;
    void (*prev)(int) = signal(SIGXFSZ, SIG_IGN);
    setrlimit(RLIMIT_FSIZE, &lim);
    alerts_update(&s);
    setrlimit(RLIMIT_FSIZE, &old);
    signal(SIGXFSZ, prev);

    int i = find_threat_ip(&s);
    ASSERT(i >= 0);
    char first_id[ALERT_INCIDENT_ID_LEN] = "";
    if (i >= 0) {
        ASSERT_EQ(s.alerts[i].pcap_write_failures, 1);
        snprintf(first_id, sizeof first_id, "%s", s.alerts[i].incident_id);
    }

    ap_churn_engine();                  /* resolve the incident */
    ap_seed_threat(&s);
    alerts_update(&s);                  /* same key, new incident */
    i = find_threat_ip(&s);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT(strcmp(s.alerts[i].incident_id, first_id) != 0);
        ASSERT_EQ(s.alerts[i].pcap_write_failures, 1);
    }

    alerts_clear(); tune_reset(); ap87_cleanup();
    sloth_clock_test_set(NULL, NULL);
}

/* A clean export on the first attempt records the path and never
 * retries — the write-failure count stays at 0. */
static void test_dump_records_path_on_success(void) {
    ap87_setup();
    ASSERT_EQ(alert_pcap_set_dir(g_ap87), 0);
    alerts_clear();

    sloth_state_t s; memset(&s, 0, sizeof(s));
    conn_t *c = &s.conns[s.conn_count++];
    snprintf(c->local_addr,  sizeof(c->local_addr),  "192.168.1.5");
    snprintf(c->remote_addr, sizeof(c->remote_addr), "192.0.2.66");
    c->local_port  = 33445;
    c->remote_port = 443;
    c->proto       = PROTO_TCP;
    seed_packet(&s, "192.168.1.5", "192.0.2.66", 33445, 443, 1700000000);

    alerts_update(&s);
    int idx = find_threat_ip(&s);
    ASSERT(idx >= 0);
    ASSERT_EQ(s.alerts[idx].pcap_dumped, 1);
    ASSERT_EQ(s.alerts[idx].pcap_write_failures, 0);
    ASSERT(s.alerts[idx].pcap_path[0] != '\0');
    ASSERT(strstr(s.alerts[idx].pcap_path, g_ap87) != NULL);
    ASSERT_EQ(ap87_entries(), 1);

    alerts_clear();
    ap87_cleanup();
}


/* ── Storage floors (#96) ─────────────────────────────────────────
 *
 * --pcap-dir is the only operator-named sink with no cap and no sweep,
 * and on the owner's monitor host it had grown to 15.9M files holding
 * ~93% of the filesystem's inodes while disk sat at 39% used. The
 * floors are the refusal; these are the cases that matter about them.
 *
 * The floors are set absurdly high rather than by filling a disk: the
 * real margin belongs to whatever host this runs on, and a test that
 * depended on it would pass or fail by accident. */

static void test_dump_refuses_below_the_inode_floor(void) {
    ensure_tmp_dir();
    tune_reset();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_packet(&s, "192.168.1.5", "203.0.113.7", 33445, 443, 1700000000);
    alert_t a; memset(&a, 0, sizeof(a));
    snprintf(a.title,    sizeof(a.title),    "THREAT_IP");
    snprintf(a.match_ip, sizeof(a.match_ip), "203.0.113.7");

    int before = alert_pcap_failures();
    /* A floor no filesystem can satisfy. The inode floor specifically,
       because it is the one the measured failure needed — a byte floor
       would have let that host write until the inodes ran out. */
    char terr[256];
    ASSERT_EQ(tune_set("storage.min_free_inodes=99000000", terr, sizeof(terr)), 0);
    char path[512];
    ASSERT_EQ(alert_pcap_dump(&s, &a, path, sizeof(path)), -1);
    /* Counted through the same sfile_fail path every other write
       failure uses, so the operator sees it in storage_failures and on
       the !persist badge with no new reporting path. */
    ASSERT_EQ(alert_pcap_failures(), before + 1);
    /* And the reason says inodes, not bytes — the whole point, since an
       operator reading `df -h` concludes the sensor is healthy. */
    ASSERT(strstr(alert_pcap_error(), "inode") != NULL);
    tune_reset();
}

static void test_dump_writes_when_the_floor_is_satisfiable(void) {
    ensure_tmp_dir();
    tune_reset();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_packet(&s, "192.168.1.5", "203.0.113.7", 33445, 443, 1700000000);
    alert_t a; memset(&a, 0, sizeof(a));
    snprintf(a.title,    sizeof(a.title),    "THREAT_IP");
    snprintf(a.match_ip, sizeof(a.match_ip), "203.0.113.7");

    /* Floors set, but to values any host running this suite meets. This
       is the assertion that the guard is a floor and not a switch — the
       refusal above would also pass if the guard refused everything. */
    char terr[256];
    ASSERT_EQ(tune_set("storage.min_free_mb=1", terr, sizeof(terr)), 0);
    ASSERT_EQ(tune_set("storage.min_free_inodes=1", terr, sizeof(terr)), 0);
    char path[512];
    ASSERT_EQ(alert_pcap_dump(&s, &a, path, sizeof(path)), 1);
    ASSERT(file_exists(path));
    tune_reset();
}

static void test_dump_succeeds_on_a_healthy_filesystem_by_default(void) {
    ensure_tmp_dir();
    tune_reset();
    /* The guard IS on by default now, via the relative floor — owner
       instruction 2026-10-13. The two ABSOLUTE floors stay 0, because a
       fixed inode or byte count cannot be right for two filesystems of
       different size; the percentage is what carries the default.
       
       (An earlier version of this comment said "both floors default to
       0, so an existing deployment inherits no behaviour change". That
       was true when the only floors were absolute and is not any more.
       An upgrade now DOES change behaviour on a filesystem already
       under 5% free, which is the point of the change rather than a
       side effect of it.)
       
       Asserted here rather than only in test_fs_capacity.c, because the
       default that matters is the one this call site reads. */
    ASSERT_EQ((long long)tune_val(TUNE_STORAGE_MIN_FREE_MB), 0);
    ASSERT_EQ((long long)tune_val(TUNE_STORAGE_MIN_FREE_INODES), 0);
    ASSERT_EQ((long long)tune_val(TUNE_STORAGE_MIN_FREE_PCT), 5);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_packet(&s, "192.168.1.5", "203.0.113.7", 33445, 443, 1700000000);
    alert_t a; memset(&a, 0, sizeof(a));
    snprintf(a.title,    sizeof(a.title),    "THREAT_IP");
    snprintf(a.match_ip, sizeof(a.match_ip), "203.0.113.7");
    char path[512];
    ASSERT_EQ(alert_pcap_dump(&s, &a, path, sizeof(path)), 1);
    ASSERT(file_exists(path));
}

/* ── Age sweep (#166) ────────────────────────────────────────────────
 *
 * Hand-built directory trees: empty files with names in the shape
 * alert_pcap_dump() writes, their mtimes set with utimensat() relative
 * to a wall clock pinned through the sloth_clock seam. The sweep reads
 * only the name, the type and the mtime, so no pcap bytes are needed. */

#define SW_DAY 86400
static time_t sw_now = 1800000000;          /* 2027-01-15, pinned */
static time_t sw_wall(void) { return sw_now; }

static char sw_dir[64];

/* A fresh private directory per test, so one test's leftovers cannot
 * be another's "kept" file. */
static void sw_setup(void) {
    tune_reset();
    sw_now = 1800000000;
    sloth_clock_test_set(NULL, sw_wall);
    snprintf(sw_dir, sizeof(sw_dir), "/tmp/sloth_sweep_XXXXXX");
    ASSERT(mkdtemp(sw_dir) != NULL);
    ASSERT_EQ(alert_pcap_set_dir(sw_dir), 0);
}

static void sw_path(const char *name, char *out, size_t n) {
    snprintf(out, n, "%s/%s", sw_dir, name);
}

/* A regular file `age_secs` old by mtime, against the pinned clock. */
static void sw_file(const char *name, long age_secs) {
    char p[256]; sw_path(name, p, sizeof(p));
    FILE *f = fopen(p, "w");
    ASSERT(f != NULL);
    if (!f) return;
    fputs("x", f);
    fclose(f);
    struct timespec ts[2];
    ts[0].tv_sec = ts[1].tv_sec = sw_now - age_secs;
    ts[0].tv_nsec = ts[1].tv_nsec = 0;
    ASSERT_EQ(utimensat(AT_FDCWD, p, ts, 0), 0);
}

static int sw_exists(const char *name) {
    char p[256]; sw_path(name, p, sizeof(p));
    struct stat st;
    return lstat(p, &st) == 0;
}

/* Run steps until the pass completes; bounded so a regression that
 * never finishes fails rather than hangs. Returns files removed. */
static int sw_run_pass(int budget) {
    int total = 0;
    for (int i = 0; i < 10000; i++) {
        int n = alert_pcap_sweep_step(budget);
        if (n > 0) total += n;
        if (!alert_pcap_sweep_in_progress()) break;
    }
    return total;
}

/* Remove everything left, including links and directories. */
static void sw_teardown(void) {
    alert_pcap_set_dir(NULL);
    sloth_clock_test_set(NULL, NULL);
    tune_reset();
    DIR *d = opendir(sw_dir);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            char p[256]; sw_path(e->d_name, p, sizeof(p));
            if (unlink(p) != 0) rmdir(p);
        }
        closedir(d);
    }
    chmod(sw_dir, 0700);
    rmdir(sw_dir);
}

static void test_sweep_name_shape(void) {
    /* What alert_pcap_dump() writes: the stem, an optional _N suffix
     * from sfile_fopen_unique(), an empty slug, and the manifest. */
    ASSERT(alert_pcap_is_name("alert_20261026_120000_THREAT_IP.pcap"));
    ASSERT(alert_pcap_is_name("alert_20261026_120000_THREAT_IP_2.pcap"));
    ASSERT(alert_pcap_is_name("alert_20261026_120000_.pcap"));
    ASSERT(alert_pcap_is_name("sloth-manifest-20261026T120000Z-1a2b.jsonl"));
    /* Everything else is the operator's. */
    ASSERT(!alert_pcap_is_name("capture.pcap"));
    ASSERT(!alert_pcap_is_name("alert_.pcap"));
    ASSERT(!alert_pcap_is_name("alert_2026102_120000_X.pcap"));
    ASSERT(!alert_pcap_is_name("alert_20261026-120000_X.pcap"));
    ASSERT(!alert_pcap_is_name("alert_20261026_120000_X.pcapng"));
    ASSERT(!alert_pcap_is_name("alert_20261026_120000_a.b.pcap"));
    ASSERT(!alert_pcap_is_name("alert_20261026_120000_X.pcap.tmp"));
    ASSERT(!alert_pcap_is_name(".alert_20261026_120000_X.pcap"));
    ASSERT(!alert_pcap_is_name("notes.txt"));
    ASSERT(!alert_pcap_is_name("."));
    ASSERT(!alert_pcap_is_name(".."));
    ASSERT(!alert_pcap_is_name(""));
    ASSERT(!alert_pcap_is_name(NULL));
}

static void test_sweep_default_is_the_ruling(void) {
    /* Owner ruling 2026-10-26: two weeks. */
    tune_reset();
    ASSERT_EQ(alert_pcap_retain_days(), 14);
    ASSERT_STR(tune_spec(TUNE_PCAP_RETAIN_DAYS)->name, "pcap.retain_days");
    char err[160];
    ASSERT_EQ(tune_set("pcap.retain_days=3650", err, sizeof(err)), 0);
    ASSERT(tune_set("pcap.retain_days=3651", err, sizeof(err)) != 0);
    ASSERT(tune_set("pcap.retain_days=-1", err, sizeof(err)) != 0);
    ASSERT_EQ(alert_pcap_retain_days(), 3650);       /* previous stands */
    tune_reset();
}

static void test_sweep_removes_old_keeps_young(void) {
    sw_setup();
    sw_file("alert_20261001_000000_OLD.pcap",   15 * SW_DAY);
    sw_file("alert_20261001_000001_OLD_2.pcap", 30 * SW_DAY);
    sw_file("sloth-manifest-20261001T000000Z-aa.jsonl", 15 * SW_DAY);
    /* One second inside the window, and one at day 13: both kept. */
    sw_file("alert_20261012_000000_EDGE.pcap", 14 * SW_DAY - 1);
    sw_file("alert_20261013_000000_YOUNG.pcap", 13 * SW_DAY);
    ASSERT_EQ(sw_run_pass(ALERT_PCAP_SWEEP_BUDGET), 3);
    ASSERT(!sw_exists("alert_20261001_000000_OLD.pcap"));
    ASSERT(!sw_exists("alert_20261001_000001_OLD_2.pcap"));
    ASSERT(!sw_exists("sloth-manifest-20261001T000000Z-aa.jsonl"));
    ASSERT(sw_exists("alert_20261012_000000_EDGE.pcap"));
    ASSERT(sw_exists("alert_20261013_000000_YOUNG.pcap"));
    ASSERT_EQ((long long)alert_pcap_swept(), 3);
    ASSERT_EQ(alert_pcap_sweep_errors(), 0);
    sw_teardown();
}

static void test_sweep_leaves_foreign_and_symlinked_files(void) {
    sw_setup();
    /* Old, but not names sloth writes. */
    sw_file("capture.pcap", 400 * SW_DAY);
    sw_file("notes.txt",    400 * SW_DAY);
    sw_file("alert_20261001_000000_x.pcapng", 400 * SW_DAY);
    /* A symlink at an artifact name, old by its own lstat mtime, to an
     * old regular file. A sweep that followed the link would see an old
     * regular file and unlink the name; one that did not check the type
     * would unlink the link. Both must leave both. */
    sw_file("target.bin", 400 * SW_DAY);
    char lnk[256];
    sw_path("alert_20260102_000000_LINK.pcap", lnk, sizeof(lnk));
    ASSERT_EQ(symlink("target.bin", lnk), 0);
    struct timespec ts[2];
    ts[0].tv_sec = ts[1].tv_sec = sw_now - 400 * SW_DAY;
    ts[0].tv_nsec = ts[1].tv_nsec = 0;
    ASSERT_EQ(utimensat(AT_FDCWD, lnk, ts, AT_SYMLINK_NOFOLLOW), 0);
    /* A directory at an artifact name. */
    char sub[256]; sw_path("alert_20260103_000000_DIR.pcap", sub, sizeof(sub));
    ASSERT_EQ(mkdir(sub, 0700), 0);

    ASSERT_EQ(sw_run_pass(ALERT_PCAP_SWEEP_BUDGET), 0);
    ASSERT(sw_exists("capture.pcap"));
    ASSERT(sw_exists("notes.txt"));
    ASSERT(sw_exists("alert_20261001_000000_x.pcapng"));
    ASSERT(sw_exists("alert_20260102_000000_LINK.pcap"));
    ASSERT(sw_exists("target.bin"));
    ASSERT(sw_exists("alert_20260103_000000_DIR.pcap"));
    /* Not silent: the link and the directory are each one error. */
    ASSERT_EQ(alert_pcap_sweep_errors(), 2);
    ASSERT(strstr(alert_pcap_sweep_error(), "not a regular file") != NULL);
    ASSERT_EQ((long long)alert_pcap_swept(), 0);
    sw_teardown();
}

static void test_sweep_pass_is_bounded_and_resumes(void) {
    sw_setup();
    char name[64];
    for (int i = 0; i < 10; i++) {
        snprintf(name, sizeof(name), "alert_20261001_0000%02d_B.pcap", i);
        sw_file(name, 20 * SW_DAY);
    }
    /* 12 entries with "." and "..": a budget of 3 cannot finish them in
     * one call, and must not remove more than 3 in any call. */
    int first = alert_pcap_sweep_step(3);
    ASSERT(first >= 0 && first <= 3);
    ASSERT(alert_pcap_sweep_in_progress());
    int calls = 1, total = first;
    while (alert_pcap_sweep_in_progress() && calls < 100) {
        int n = alert_pcap_sweep_step(3);
        ASSERT(n >= 0 && n <= 3);
        total += n;
        calls++;
    }
    ASSERT_EQ(total, 10);
    ASSERT(calls >= 4);                       /* ceil(12 / 3) */
    ASSERT_EQ((long long)alert_pcap_swept(), 10);

    /* The pass is over and the next is an hour away: a new old file
     * waits for it. */
    sw_file("alert_20261001_000100_LATE.pcap", 20 * SW_DAY);
    ASSERT_EQ(alert_pcap_sweep_step(ALERT_PCAP_SWEEP_BUDGET), 0);
    ASSERT(!alert_pcap_sweep_in_progress());
    sw_now += ALERT_PCAP_SWEEP_INTERVAL_S - 1;
    ASSERT_EQ(sw_run_pass(ALERT_PCAP_SWEEP_BUDGET), 0);
    ASSERT(sw_exists("alert_20261001_000100_LATE.pcap"));
    sw_now += 1;
    ASSERT_EQ(sw_run_pass(ALERT_PCAP_SWEEP_BUDGET), 1);
    ASSERT(!sw_exists("alert_20261001_000100_LATE.pcap"));
    sw_teardown();
}

static void test_sweep_zero_keeps_forever(void) {
    sw_setup();
    char err[160];
    ASSERT_EQ(tune_set("pcap.retain_days=0", err, sizeof(err)), 0);
    sw_file("alert_20200101_000000_ANCIENT.pcap", 3000 * SW_DAY);
    ASSERT_EQ(alert_pcap_maintain(), 0);
    ASSERT(!alert_pcap_sweep_in_progress());
    ASSERT(sw_exists("alert_20200101_000000_ANCIENT.pcap"));
    ASSERT_EQ((long long)alert_pcap_swept(), 0);
    sw_teardown();

    /* A pass already open when the window closes stops deleting. Fifty
     * old artifacts, so the one entry the opening step examines can
     * remove at most one of them whatever readdir's order. */
    sw_setup();
    char name[64];
    for (int i = 0; i < 50; i++) {
        snprintf(name, sizeof(name), "alert_20200101_0000%02d_OPEN.pcap", i);
        sw_file(name, 3000 * SW_DAY);
    }
    int first = alert_pcap_sweep_step(1);
    ASSERT(first == 0 || first == 1);
    ASSERT(alert_pcap_sweep_in_progress());
    ASSERT_EQ(tune_set("pcap.retain_days=0", err, sizeof(err)), 0);
    ASSERT_EQ(alert_pcap_sweep_step(ALERT_PCAP_SWEEP_BUDGET), 0);
    ASSERT(!alert_pcap_sweep_in_progress());
    ASSERT_EQ((long long)alert_pcap_swept(), first);
    sw_teardown();
}

static void test_sweep_window_follows_the_knob(void) {
    sw_setup();
    char err[160];
    ASSERT_EQ(tune_set("pcap.retain_days=1", err, sizeof(err)), 0);
    sw_file("alert_20261001_000000_TWO.pcap", 2 * SW_DAY);
    sw_file("alert_20261001_000000_HALF.pcap", SW_DAY / 2);
    ASSERT_EQ(sw_run_pass(ALERT_PCAP_SWEEP_BUDGET), 1);
    ASSERT(!sw_exists("alert_20261001_000000_TWO.pcap"));
    ASSERT(sw_exists("alert_20261001_000000_HALF.pcap"));
    sw_teardown();
}

static void test_sweep_counts_a_failed_delete(void) {
    /* Root ignores directory write permission, so the refusal this
     * relies on cannot be produced there. */
    if (geteuid() == 0) return;
    sw_setup();
    sw_file("alert_20261001_000000_STUCK.pcap", 20 * SW_DAY);
    ASSERT_EQ(chmod(sw_dir, 0500), 0);
    ASSERT_EQ(sw_run_pass(ALERT_PCAP_SWEEP_BUDGET), 0);
    ASSERT_EQ(chmod(sw_dir, 0700), 0);
    ASSERT(sw_exists("alert_20261001_000000_STUCK.pcap"));
    ASSERT_EQ(alert_pcap_sweep_errors(), 1);
    ASSERT(strstr(alert_pcap_sweep_error(), "could not delete") != NULL);
    ASSERT_EQ((long long)alert_pcap_swept(), 0);
    /* A sweep error is not a lost write: storage_pcap_failures stays. */
    ASSERT_EQ(alert_pcap_failures(), 0);
    sw_teardown();
}

static void test_sweep_noop_without_a_directory(void) {
    alert_pcap_set_dir(NULL);
    ASSERT_EQ(alert_pcap_maintain(), 0);
    ASSERT(!alert_pcap_sweep_in_progress());
    ASSERT_EQ(alert_pcap_sweep_errors(), 0);
}

void run_alert_pcap_tests(void) {
    TEST_SUITE("alert_pcap dir gating");
    RUN_TEST(test_set_dir_enables_disables);

    TEST_SUITE("alert_pcap dump");
    RUN_TEST(test_dump_writes_pcap_for_match);
    RUN_TEST(test_dump_skips_when_no_match);
    RUN_TEST(test_dump_port_zero_matches_any);
    RUN_TEST(test_dump_noop_when_dir_disabled);
    RUN_TEST(test_dump_skips_alert_without_match_ip);

    TEST_SUITE("alert_pcap export permissions (#87)");
    RUN_TEST(test_set_dir_refuses_shared_tmp);
    RUN_TEST(test_set_dir_creates_private_under_permissive_umask);
    RUN_TEST(test_set_dir_refuses_permissive_existing);
    RUN_TEST(test_set_dir_refuses_symlink);
    RUN_TEST(test_dump_same_name_does_not_overwrite);
    RUN_TEST(test_dump_write_failure_visible);

    TEST_SUITE("alert_pcap match-criteria integration");
    RUN_TEST(test_threat_ip_rule_sets_match_fields);

    TEST_SUITE("alert_pcap storage floors (#96)");
    RUN_TEST(test_dump_refuses_below_the_inode_floor);
    RUN_TEST(test_dump_writes_when_the_floor_is_satisfiable);
    RUN_TEST(test_dump_succeeds_on_a_healthy_filesystem_by_default);

    TEST_SUITE("alert_pcap export outcome recorded on the alert (#92)");
    RUN_TEST(test_warn_alerts_are_not_exported_by_default);
    RUN_TEST(test_min_severity_zero_restores_the_full_capture);
    RUN_TEST(test_a_refired_finding_does_not_export_twice);
    RUN_TEST(test_cooldown_zero_restores_the_full_capture);
    RUN_TEST(test_dump_retries_after_transient_failure);
    RUN_TEST(test_write_failures_survive_reopen);
    RUN_TEST(test_dump_records_path_on_success);

    TEST_SUITE("alert_pcap age sweep (#166)");
    RUN_TEST(test_sweep_name_shape);
    RUN_TEST(test_sweep_default_is_the_ruling);
    RUN_TEST(test_sweep_removes_old_keeps_young);
    RUN_TEST(test_sweep_leaves_foreign_and_symlinked_files);
    RUN_TEST(test_sweep_pass_is_bounded_and_resumes);
    RUN_TEST(test_sweep_zero_keeps_forever);
    RUN_TEST(test_sweep_window_follows_the_knob);
    RUN_TEST(test_sweep_counts_a_failed_delete);
    RUN_TEST(test_sweep_noop_without_a_directory);
}
