#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>

#include "runner.h"
#include "sloth.h"
#include "alert_pcap.h"
#include "evidence_export.h"
#include "evidence_manifest.h"
#include "evidence_ring.h"
#include "eapol_log.h"
#include "pcap_format.h"
#include "tune.h"
#include "sloth_clock.h"
#include "secure_file.h"
#include "manifest_check.h"

/* ── The per-session hashed manifest (#92 slice 3) ──────────────────
 *
 * Every file sloth commits under --pcap-dir and --eapol-dir gets one
 * JSON Lines entry in that directory's session manifest. This file
 * covers the two alert sinks (IP alert pcap, evidence pcap) and the
 * manifest's own contract: the crash shape, session naming, a shared
 * directory, the retention sweep, and failure accounting. The two
 * handshake sinks are covered in test_eapol_log.c beside the frame
 * builders that drive them, and the engine's incident/rule wiring in
 * test_evidence_alert.c.
 *
 * Also here: the per-alert pcap header's snaplen (#145 owner default) —
 * the wired ring keeps 64 bytes per packet and the file now says so.
 *
 * Every test works in its own mkdtemp() directory, removed at the end,
 * with the wall clock pinned through sloth_clock_test_set(). Packets
 * and frames are hand-built byte arrays; nothing is read from a
 * capture. */

static char   g_dir[64];
static time_t g_wall = 1700000000;           /* 2023-11-14T22:13:20Z */
static time_t   em_wall(void) { return g_wall; }
static uint64_t em_mono(void) { return (uint64_t)g_wall * 1000u; }

static void rm_dir(const char *dir) {
    DIR *d = opendir(dir);
    if (d) {
        struct dirent *e;
        char p[400];
        while ((e = readdir(d)) != NULL) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
            unlink(p);
        }
        closedir(d);
    }
    rmdir(dir);
}

static void setup(void) {
    snprintf(g_dir, sizeof(g_dir), "/tmp/sloth_manifest_XXXXXX");
    ASSERT(mkdtemp(g_dir) != NULL);
    g_wall = 1700000000;
    sloth_clock_test_set(em_mono, em_wall);
    tune_reset();
    evidence_manifest_reset();
    eapol_set_output_dir(NULL);
    eapol_set_collect_enabled(0);
    ASSERT_EQ(alert_pcap_set_dir(g_dir), 0);
    evidence_export_test_fault(EVX_FAULT_NONE, 0);
}

static void teardown(void) {
    evidence_export_test_fault(EVX_FAULT_NONE, 0);
    alert_pcap_set_dir(NULL);
    eapol_set_output_dir(NULL);
    eapol_set_collect_enabled(0);
    evidence_ring_reset();
    evidence_manifest_reset();
    tune_reset();
    rm_dir(g_dir);
    sloth_clock_test_set(NULL, NULL);
}

/* Ethernet II + IPv4 + TCP, built per IEEE 802.3 / RFC 791 / RFC 9293:
 * 02:00:5e:00:53:02 → 02:00:5e:00:53:01, 192.0.2.5:33445 → 203.0.113.7:443,
 * SYN, then `payload` bytes of 0xa5. Returns the frame length — the
 * wire length sloth would see as origlen. */
static int build_tcp(uint8_t *f, size_t cap, int payload) {
    const int len = 14 + 20 + 20 + payload;
    if (payload < 0 || (size_t)len > cap) return -1;
    memset(f, 0, (size_t)len);
    static const uint8_t dst[6] = {0x02,0x00,0x5e,0x00,0x53,0x01};
    static const uint8_t src[6] = {0x02,0x00,0x5e,0x00,0x53,0x02};
    memcpy(f, dst, 6);
    memcpy(f + 6, src, 6);
    f[12] = 0x08; f[13] = 0x00;                 /* EtherType IPv4 */
    uint8_t *ip = f + 14;
    ip[0] = 0x45;                               /* v4, IHL 5 */
    int tot = 20 + 20 + payload;
    ip[2] = (uint8_t)(tot >> 8); ip[3] = (uint8_t)tot;
    ip[8] = 64;                                 /* TTL */
    ip[9] = 6;                                  /* TCP */
    ip[12] = 192; ip[13] = 0;   ip[14] = 2;   ip[15] = 5;
    ip[16] = 203; ip[17] = 0;   ip[18] = 113; ip[19] = 7;
    uint8_t *tcp = ip + 20;
    tcp[0] = 0x82; tcp[1] = 0xa5;               /* 33445 */
    tcp[2] = 0x01; tcp[3] = 0xbb;               /* 443 */
    tcp[12] = 0x50;                             /* data offset 5 */
    tcp[13] = 0x02;                             /* SYN */
    for (int i = 0; i < payload; i++) tcp[20 + i] = 0xa5;
    return len;
}

/* Put a hand-built frame in the wired ring the way capture.c does:
 * the first min(caplen, 64) bytes, with the wire length beside it. */
static void ring_push(sloth_state_t *s, const uint8_t *f, int wire_len,
                      uint32_t ts) {
    packet_info_t *p = &s->packets[s->pkt_head];
    memset(p, 0, sizeof(*p));
    snprintf(p->src, sizeof(p->src), "192.0.2.5");
    snprintf(p->dst, sizeof(p->dst), "203.0.113.7");
    p->src_port = 33445;
    p->dst_port = 443;
    p->ts_sec   = ts;
    p->len      = (uint32_t)wire_len;
    int rl = wire_len < 64 ? wire_len : 64;
    memcpy(p->raw, f, (size_t)rl);
    p->raw_len = (uint16_t)rl;
    s->pkt_head = (s->pkt_head + 1) % MAX_PACKETS;
    if (s->pkt_count < MAX_PACKETS) s->pkt_count++;
}

static void ip_alert(alert_t *a, const char *title) {
    memset(a, 0, sizeof(*a));
    a->type = ALERT_TYPE_THREAT_IP;
    a->sev  = ALERT_SEV_CRIT;
    snprintf(a->title, sizeof(a->title), "%s", title);
    snprintf(a->match_ip, sizeof(a->match_ip), "203.0.113.7");
    snprintf(a->incident_id, sizeof(a->incident_id), "0123456789abcdef");
}

/* A ring with one short and one truncated packet, dumped once. */
static int dump_one(const char *title, char *path, size_t pathsz) {
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    uint8_t f[1600];
    int n1 = build_tcp(f, sizeof(f), 0);        /* 54 bytes: all kept */
    ring_push(&s, f, n1, 1700000000);
    int n2 = build_tcp(f, sizeof(f), 1460);     /* 1514: 64 kept */
    ring_push(&s, f, n2, 1700000001);
    alert_t a;
    ip_alert(&a, title);
    return alert_pcap_dump(&s, &a, path, (int)pathsz);
}

static const char *base(const char *p) {
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

static uint32_t le32(const uint8_t *b) {
    return (uint32_t)b[0] | (uint32_t)b[1] << 8 |
           (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}

/* ── Part 2: the IP alert pcap declares what it holds ───────────── */

static void test_alert_pcap_snaplen_is_the_ring_depth(void) {
    setup();
    char path[512];
    ASSERT_EQ(dump_one("THREAT_IP", path, sizeof(path)), 2);
    FILE *fp = fopen(path, "rb");
    ASSERT(fp != NULL);
    if (!fp) { teardown(); return; }
    uint8_t b[512];
    size_t n = fread(b, 1, sizeof(b), fp);
    fclose(fp);
    /* 24 + (16 + 54) + (16 + 64): nothing beyond the 64 stored bytes. */
    ASSERT_EQ((long)n, 24L + 16 + 54 + 16 + 64);
    ASSERT_EQ((long long)le32(b + 16), 64LL);       /* snaplen */
    /* Record 1: a 54-byte frame, all of it. */
    ASSERT_EQ((long long)le32(b + 24 + 8), 54LL);   /* incl_len */
    ASSERT_EQ((long long)le32(b + 24 + 12), 54LL);  /* orig_len */
    /* Record 2: 1514 on the wire, 64 stored, and the header says both. */
    const uint8_t *r2 = b + 24 + 16 + 54;
    ASSERT_EQ((long long)le32(r2 + 8), 64LL);
    ASSERT_EQ((long long)le32(r2 + 12), 1514LL);
    /* The stored bytes are the frame's first 64: Ethernet, IPv4, TCP,
     * then payload. */
    uint8_t want[1600];
    build_tcp(want, sizeof(want), 1460);
    ASSERT(memcmp(r2 + 16, want, 64) == 0);
    /* No record claims more than the header's snaplen. */
    ASSERT(le32(b + 24 + 8) <= le32(b + 16));
    ASSERT(le32(r2 + 8) <= le32(b + 16));
    teardown();
}

/* ── One line per committed file, and it is true ────────────────── */

static void check_line_is_the_file(const mf_line_t *l, const char *path) {
    char hex[65];
    long long size = -1;
    ASSERT_EQ(mf_hash_path(path, hex, &size), 0);
    ASSERT_STR(l->sha256, hex);
    ASSERT_EQ(l->size, size);
    struct stat st;
    ASSERT_EQ(stat(path, &st), 0);
    ASSERT_EQ(l->size, (long long)st.st_size);
    char sys[65];
    if (mf_sha256sum(path, sys)) {
        ASSERT_STR(l->sha256, sys);
    } else {
        printf("    (sha256sum not available: cross-check skipped)\n");
    }
}

static void test_alert_pcap_gets_a_true_line(void) {
    setup();
    char path[512];
    ASSERT_EQ(dump_one("THREAT_IP", path, sizeof(path)), 2);

    char mname[200];
    ASSERT_EQ(mf_count(g_dir, mname, sizeof(mname)), 1);
    ASSERT(strncmp(mname, EVM_PREFIX "20231114T221320Z-", 32) == 0);
    char mpath[400];
    snprintf(mpath, sizeof(mpath), "%s/%s", g_dir, mname);
    struct stat st;
    ASSERT_EQ(lstat(mpath, &st), 0);
    ASSERT_EQ((int)(st.st_mode & 07777), 0600);

    static mf_line_t l[8];
    int bad = -1;
    ASSERT_EQ(mf_read_dir(g_dir, l, 8, &bad), 1);
    ASSERT_EQ(bad, 0);
    ASSERT_STR(l[0].file, base(path));
    check_line_is_the_file(&l[0], path);
    ASSERT_STR(l[0].sink, "alert_pcap");
    ASSERT_STR(l[0].incident_id, "0123456789abcdef");
    ASSERT_STR(l[0].rule, "THREAT_IP");
    ASSERT_EQ(l[0].reconstructed, 0);
    ASSERT_STR(l[0].written_at, "2023-11-14T22:13:20Z");
    ASSERT_EQ(l[0].written_at_epoch, 1700000000LL);
    ASSERT_EQ(l[0].seq, 1LL);
    ASSERT(strncmp(l[0].session, "20231114T221320Z-", 17) == 0);
    ASSERT_EQ((int)strlen(l[0].session), 17 + 16);
    teardown();
}

/* A dump that writes nothing, and one that fails, list nothing. The
 * first absence was seen red by recording above the empty-file unlink.
 * The second is not mutation-isolated: a refused dump never creates a
 * file, so a record() call there has nothing to hash and refuses on its
 * own — the assertion pins the contract, not a guard. */
static void test_alert_pcap_no_file_no_line(void) {
    setup();
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    alert_t a;
    ip_alert(&a, "THREAT_IP");
    /* Matches nothing: the empty pcap is unlinked, so nothing is listed. */
    ASSERT_EQ(alert_pcap_dump(&s, &a, NULL, 0), 0);
    ASSERT_EQ(mf_count(g_dir, NULL, 0), 0);

    /* Refused by a free-space floor no filesystem meets. */
    ASSERT(tune_set_id(TUNE_STORAGE_MIN_FREE_MB, 4194304));   /* 4 TiB */
    char path[512];
    int before = alert_pcap_failures();
    ASSERT_EQ(dump_one("THREAT_IP", path, sizeof(path)), -1);
    ASSERT_EQ(alert_pcap_failures(), before + 1);
    ASSERT_EQ(mf_count(g_dir, NULL, 0), 0);
    teardown();
}

/* A manifest write that fails is counted on the sink's own counter —
 * the one behind the !persist badge and storage_pcap_failures — and
 * the pcap it would have described is still written and returned. The
 * half line it left is cut back off, so the next line parses. */
static void test_manifest_failure_is_counted_not_blocking(void) {
    setup();
    char p1[512], p2[512], p3[512];
    ASSERT_EQ(dump_one("ONE", p1, sizeof(p1)), 2);
    int before = alert_pcap_failures();

    evidence_manifest_test_fail_next();
    ASSERT_EQ(dump_one("TWO", p2, sizeof(p2)), 2);   /* evidence kept */
    struct stat st;
    ASSERT_EQ(stat(p2, &st), 0);
    ASSERT_EQ(alert_pcap_failures(), before + 1);
    ASSERT(strstr(alert_pcap_error(), "manifest") != NULL);

    char mname[200], mpath[400];
    ASSERT_EQ(mf_count(g_dir, mname, sizeof(mname)), 1);
    snprintf(mpath, sizeof(mpath), "%s/%s", g_dir, mname);
    static mf_line_t l[8];
    int bad = -1, tail = -1;
    ASSERT_EQ(mf_read_path(mpath, l, 8, &bad, &tail), 1);
    ASSERT_EQ(bad, 0);
    ASSERT_EQ(tail, 0);                 /* no half line left behind */

    ASSERT_EQ(dump_one("THREE", p3, sizeof(p3)), 2);
    ASSERT_EQ(mf_read_path(mpath, l, 8, &bad, &tail), 2);
    ASSERT_EQ(bad, 0);
    ASSERT_STR(l[1].file, base(p3));
    ASSERT_EQ(l[1].seq, 2LL);
    ASSERT(mf_find(l, 2, base(p2)) == NULL);
    teardown();
}

/* What a crash mid-append leaves is a prefix of the file. Every prefix,
 * at every byte, must parse as complete lines plus at most one
 * fragment — never a complete line that is not JSON. */
static void test_every_crash_prefix_parses(void) {
    setup();
    char p[512];
    ASSERT_EQ(dump_one("ONE", p, sizeof(p)), 2);
    ASSERT_EQ(dump_one("TWO", p, sizeof(p)), 2);
    ASSERT_EQ(dump_one("THREE", p, sizeof(p)), 2);

    char mname[200], mpath[400];
    ASSERT_EQ(mf_count(g_dir, mname, sizeof(mname)), 1);
    snprintf(mpath, sizeof(mpath), "%s/%s", g_dir, mname);
    static char whole[8192];
    FILE *fp = fopen(mpath, "rb");
    ASSERT(fp != NULL);
    if (!fp) { teardown(); return; }
    size_t n = fread(whole, 1, sizeof(whole), fp);
    fclose(fp);
    ASSERT(n > 0 && whole[n - 1] == '\n');

    char cut[400];
    snprintf(cut, sizeof(cut), "%s/prefix.jsonl", g_dir);
    int bad_total = 0, wrong_count = 0;
    static mf_line_t l[8];
    for (size_t k = 0; k <= n; k++) {
        FILE *o = fopen(cut, "wb");
        if (!o) { wrong_count++; break; }
        fwrite(whole, 1, k, o);
        fclose(o);
        int nl = 0;
        for (size_t i = 0; i < k; i++) nl += whole[i] == '\n';
        int bad = 0, tail = 0;
        int got = mf_read_path(cut, l, 8, &bad, &tail);
        bad_total += bad;
        if (got != nl) wrong_count++;
    }
    ASSERT_EQ(bad_total, 0);
    ASSERT_EQ(wrong_count, 0);
    /* And the whole file is three lines, in commit order. */
    int bad = -1;
    ASSERT_EQ(mf_read_path(mpath, l, 8, &bad, NULL), 3);
    ASSERT_EQ(l[0].seq, 1LL);
    ASSERT_EQ(l[2].seq, 3LL);
    teardown();
}

/* ── Sessions ───────────────────────────────────────────────────── */

/* Two runs that start in the same wall second — a restarting RTC-less
 * sensor — get different manifests. With the random suffix they differ
 * by name; with the suffix forced equal, O_EXCL moves the second run to
 * "-2" instead of appending to the first run's record. */
static void test_two_sessions_never_share_a_manifest(void) {
    setup();
    char p[512], m1[200], m2[200];
    ASSERT_EQ(dump_one("ONE", p, sizeof(p)), 2);
    ASSERT_EQ(mf_count(g_dir, m1, sizeof(m1)), 1);
    char s1[EVM_SESSION_MAX], s2[EVM_SESSION_MAX];
    evidence_manifest_session(s1, sizeof(s1));

    evidence_manifest_reset();                 /* a new process */
    ASSERT_EQ(dump_one("TWO", p, sizeof(p)), 2);
    evidence_manifest_session(s2, sizeof(s2));
    ASSERT_EQ(mf_count(g_dir, NULL, 0), 2);
    ASSERT(strcmp(s1, s2) != 0);
    ASSERT_EQ(strncmp(s1, s2, 17), 0);         /* same start second */
    ASSERT_EQ(evidence_manifest_name(-1, m2, sizeof(m2)), -1);
    teardown();

    /* Forced collision. */
    setup();
    evidence_manifest_test_force_suffix(1, 0x1234);
    ASSERT_EQ(dump_one("ONE", p, sizeof(p)), 2);
    ASSERT_EQ(mf_count(g_dir, m1, sizeof(m1)), 1);
    ASSERT_STR(m1, EVM_PREFIX "20231114T221320Z-0000000000001234" EVM_EXT);
    evidence_manifest_reset();
    evidence_manifest_test_force_suffix(1, 0x1234);
    ASSERT_EQ(dump_one("TWO", p, sizeof(p)), 2);
    ASSERT_EQ(mf_count(g_dir, NULL, 0), 2);
    char want[200], path1[400];
    snprintf(want, sizeof(want),
             "%s/" EVM_PREFIX "20231114T221320Z-0000000000001234-2" EVM_EXT,
             g_dir);
    struct stat st;
    ASSERT_EQ(stat(want, &st), 0);
    /* The first run's manifest is untouched: still its one line. */
    snprintf(path1, sizeof(path1), "%s/%s", g_dir, m1);
    static mf_line_t l[4];
    ASSERT_EQ(mf_read_path(path1, l, 4, NULL, NULL), 1);
    ASSERT_EQ(mf_read_path(want, l, 4, NULL, NULL), 1);
    ASSERT_STR(l[0].file, base(p));
    teardown();
}

/* The session is named for when the run began, not for its first file. */
static void test_session_is_named_for_its_start(void) {
    setup();
    evidence_manifest_session_begin(1700000000 - 3600);
    char p[512], m[200];
    ASSERT_EQ(dump_one("ONE", p, sizeof(p)), 2);
    ASSERT_EQ(mf_count(g_dir, m, sizeof(m)), 1);
    ASSERT(strncmp(m, EVM_PREFIX "20231114T211320Z-", 32) == 0);
    static mf_line_t l[2];
    ASSERT_EQ(mf_read_dir(g_dir, l, 2, NULL), 1);
    ASSERT_STR(l[0].written_at, "2023-11-14T22:13:20Z");   /* the write */
    teardown();
}

/* ── The evidence sink ──────────────────────────────────────────── */

static int deauth_frame(uint8_t *f, size_t cap, uint8_t seq) {
    /* Radiotap (8 bytes, no fields) + deauthentication, FC 0xc0,
     * IEEE 802.11-2020 9.3.3.12, reason 7. */
    const int len = 8 + 24 + 2;
    if (cap < (size_t)len) return -1;
    memset(f, 0, (size_t)len);
    f[2] = 8;
    f[8] = 0xc0;
    static const uint8_t sta[6] = {0x12,0x34,0x56,0x78,0x9a,0xbc};
    static const uint8_t ap[6]  = {0x02,0x00,0x5e,0x00,0x53,0x01};
    memcpy(f + 12, sta, 6);
    memcpy(f + 18, ap, 6);
    memcpy(f + 24, ap, 6);
    f[30] = (uint8_t)(seq << 4);
    f[32] = 7;
    return len;
}

static void seed_ring(uint64_t *ids, int n) {
    evidence_ring_reset();
    ASSERT_EQ(evidence_ring_init(64 * 1024), 0);
    uint8_t f[64];
    for (int i = 0; i < n; i++) {
        int len = deauth_frame(f, sizeof(f), (uint8_t)i);
        ids[i] = evidence_ring_note(f, (uint32_t)len, (uint32_t)len,
                                    g_wall - 3 + i, (uint32_t)i, 2412, -40);
        ASSERT(ids[i] != 0);
    }
}

static void open_eapol(const char *dir) {
    eapol_set_collect_enabled(1);
    ASSERT_EQ(eapol_set_output_dir(dir), 0);
}

static void test_evidence_pcap_gets_a_true_line(void) {
    setup();
    alert_pcap_set_dir(NULL);
    open_eapol(g_dir);
    uint64_t ids[3];
    seed_ring(ids, 3);
    char used[160], err[SFILE_ERR_MAX];
    ASSERT_EQ(evidence_export_pcap_unique("fedcba9876543210-1-DEAUTH_FLOOD.pcap",
                                          ids, 3, NULL,
                                          "fedcba9876543210", "DEAUTH_FLOOD",
                                          used, sizeof(used),
                                          err, sizeof(err)), 3);
    static mf_line_t l[4];
    int bad = -1;
    ASSERT_EQ(mf_read_dir(g_dir, l, 4, &bad), 1);
    ASSERT_EQ(bad, 0);
    ASSERT_STR(l[0].file, used);
    char path[400];
    snprintf(path, sizeof(path), "%s/%s", g_dir, used);
    check_line_is_the_file(&l[0], path);
    ASSERT_STR(l[0].sink, "evidence_pcap");
    ASSERT_STR(l[0].incident_id, "fedcba9876543210");
    ASSERT_STR(l[0].rule, "DEAUTH_FLOOD");
    ASSERT_EQ(l[0].reconstructed, 0);

    /* The plain writer has no alert to name: the keys are absent, not
     * empty strings a consumer would have to special-case. */
    ASSERT_EQ(evidence_export_pcap("plain.pcap", ids, 1, NULL,
                                   err, sizeof(err)), 1);
    ASSERT_EQ(mf_read_dir(g_dir, l, 4, &bad), 2);
    ASSERT_STR(l[1].file, "plain.pcap");
    ASSERT_EQ(l[1].has_incident, 0);
    ASSERT_EQ(l[1].has_rule, 0);
    teardown();
}

/* A failed evidence export lists nothing: a mid-file write failure
 * never reaches the commit, and a commit refused because the name is
 * taken lists nothing either — the line for that name is the earlier,
 * real file's. The second absence was seen red by recording in the
 * EAPOL_COMMIT_EXISTS branch. */
static void test_failed_evidence_export_lists_nothing(void) {
    setup();
    alert_pcap_set_dir(NULL);
    open_eapol(g_dir);
    uint64_t ids[2];
    seed_ring(ids, 2);
    char err[SFILE_ERR_MAX];
    evidence_export_test_fault(EVX_FAULT_WRITE, 2);
    ASSERT_EQ(evidence_export_pcap("a.pcap", ids, 2, NULL, err, sizeof(err)), -1);
    ASSERT_EQ(mf_count(g_dir, NULL, 0), 0);
    evidence_export_test_fault(EVX_FAULT_FSYNC, 1);
    ASSERT_EQ(evidence_export_pcap("a.pcap", ids, 2, NULL, err, sizeof(err)), -1);
    ASSERT_EQ(mf_count(g_dir, NULL, 0), 0);

    ASSERT_EQ(evidence_export_pcap("a.pcap", ids, 2, NULL, err, sizeof(err)), 2);
    ASSERT_EQ(evidence_export_pcap("a.pcap", ids, 1, NULL, err, sizeof(err)), -1);
    static mf_line_t l[4];
    ASSERT_EQ(mf_read_dir(g_dir, l, 4, NULL), 1);
    char path[400];
    snprintf(path, sizeof(path), "%s/a.pcap", g_dir);
    check_line_is_the_file(&l[0], path);       /* the first, 2-frame file */
    teardown();
}

/* --pcap-dir and --eapol-dir pointed at one directory: one manifest
 * there, listing both sinks. Seen red with the directory match removed
 * (two manifests, the second at "-2"). */
static void test_one_directory_one_manifest(void) {
    setup();
    open_eapol(g_dir);                 /* alert_pcap already on g_dir */
    char p[512], used[160], err[SFILE_ERR_MAX];
    ASSERT_EQ(dump_one("THREAT_IP", p, sizeof(p)), 2);
    uint64_t ids[1];
    seed_ring(ids, 1);
    ASSERT_EQ(evidence_export_pcap_unique("e.pcap", ids, 1, NULL, NULL, NULL,
                                          used, sizeof(used),
                                          err, sizeof(err)), 1);
    ASSERT_EQ(mf_count(g_dir, NULL, 0), 1);
    static mf_line_t l[4];
    ASSERT_EQ(mf_read_dir(g_dir, l, 4, NULL), 2);
    ASSERT_STR(l[0].sink, "alert_pcap");
    ASSERT_STR(l[1].sink, "evidence_pcap");
    ASSERT_EQ(l[1].seq, 2LL);
    teardown();
}

/* Two directories, two manifests, each naming only its own files. */
static void test_each_directory_lists_its_own_files(void) {
    setup();
    char edir[64];
    snprintf(edir, sizeof(edir), "/tmp/sloth_manifest_e_XXXXXX");
    ASSERT(mkdtemp(edir) != NULL);
    open_eapol(edir);
    char p[512], used[160], err[SFILE_ERR_MAX];
    ASSERT_EQ(dump_one("THREAT_IP", p, sizeof(p)), 2);
    uint64_t ids[1];
    seed_ring(ids, 1);
    ASSERT_EQ(evidence_export_pcap_unique("e.pcap", ids, 1, NULL, NULL, NULL,
                                          used, sizeof(used),
                                          err, sizeof(err)), 1);
    static mf_line_t l[4];
    ASSERT_EQ(mf_read_dir(g_dir, l, 4, NULL), 1);
    ASSERT_STR(l[0].sink, "alert_pcap");
    ASSERT_EQ(mf_read_dir(edir, l, 4, NULL), 1);
    ASSERT_STR(l[0].sink, "evidence_pcap");
    ASSERT_STR(l[0].file, "e.pcap");
    eapol_set_output_dir(NULL);
    rm_dir(edir);
    teardown();
}

/* The --eapol-dir retention sweep expires a manifest with the files it
 * lists, and a later file starts a fresh one rather than appending to
 * the unlinked inode. Both seen red: the sweep without the manifest
 * shape (the manifest survives), and the slot without its link-count
 * check (no manifest after the next export). */
static void test_sweep_expires_the_manifest_and_a_new_one_starts(void) {
    setup();
    alert_pcap_set_dir(NULL);
    open_eapol(g_dir);
    uint64_t ids[1];
    seed_ring(ids, 1);
    char err[SFILE_ERR_MAX];
    ASSERT_EQ(evidence_export_pcap("old.pcap", ids, 1, NULL, err, sizeof(err)), 1);
    ASSERT_EQ(mf_count(g_dir, NULL, 0), 1);

    /* File mtimes are the real clock; sweep as of a month past it. */
    ASSERT(eapol_sweep(time(NULL) + 30 * 86400) >= 2);
    ASSERT_EQ(mf_count(g_dir, NULL, 0), 0);

    ASSERT_EQ(evidence_export_pcap("new.pcap", ids, 1, NULL, err, sizeof(err)), 1);
    static mf_line_t l[4];
    int bad = -1;
    ASSERT_EQ(mf_read_dir(g_dir, l, 4, &bad), 1);
    ASSERT_EQ(bad, 0);
    ASSERT_STR(l[0].file, "new.pcap");
    ASSERT_EQ(l[0].seq, 1LL);
    teardown();
}

/* The manifest refuses to hash what is not a regular file in the pinned
 * directory, and refuses a name with a path in it. */
static void test_record_refuses_non_files(void) {
    setup();
    char err[SFILE_ERR_MAX];
    evm_meta_t m = { EVM_SINK_ALERT_PCAP, NULL, NULL };
    ASSERT_EQ(evidence_manifest_record(-1, "x", &m, err, sizeof(err)), -1);
    char sub[200];
    snprintf(sub, sizeof(sub), "%s/sub", g_dir);
    ASSERT_EQ(mkdir(sub, 0700), 0);
    char lnk[200];
    snprintf(lnk, sizeof(lnk), "%s/link", g_dir);
    ASSERT_EQ(symlink("/etc/hostname", lnk), 0);
    /* Through a real pinned dirfd: alert_pcap's own is private, so
     * open one here the same way. */
    int dfd = sfile_private_dir(g_dir, err, sizeof(err));
    ASSERT(dfd >= 0);
    ASSERT_EQ(evidence_manifest_record(dfd, "sub", &m, err, sizeof(err)), -1);
    ASSERT_EQ(evidence_manifest_record(dfd, "link", &m, err, sizeof(err)), -1);
    /* A FIFO opens without blocking and reads as empty: without the
     * regular-file check it would be listed with the empty-string hash.
     * (A directory is refused by read() anyway, so it alone could not
     * show that check matters; this one was seen red without it.) */
    char fifo[200];
    snprintf(fifo, sizeof(fifo), "%s/fifo", g_dir);
    ASSERT_EQ(mkfifo(fifo, 0600), 0);
    ASSERT_EQ(evidence_manifest_record(dfd, "fifo", &m, err, sizeof(err)), -1);
    ASSERT_EQ(evidence_manifest_record(dfd, "../x", &m, err, sizeof(err)), -1);
    ASSERT_EQ(evidence_manifest_record(dfd, "absent", &m, err, sizeof(err)), -1);
    ASSERT_EQ(mf_count(g_dir, NULL, 0), 0);
    if (dfd >= 0) close(dfd);
    rmdir(sub);
    teardown();
}

static void test_sink_names_and_reconstructed(void) {
    ASSERT_STR(evidence_manifest_sink_name(EVM_SINK_ALERT_PCAP), "alert_pcap");
    ASSERT_STR(evidence_manifest_sink_name(EVM_SINK_EVIDENCE_PCAP), "evidence_pcap");
    ASSERT_STR(evidence_manifest_sink_name(EVM_SINK_HANDSHAKE_PCAP), "handshake_pcap");
    ASSERT_STR(evidence_manifest_sink_name(EVM_SINK_HASHCAT_22000), "hashcat_22000");
    ASSERT_STR(evidence_manifest_sink_name(EVM_SINK_COUNT), "unknown");
    ASSERT_EQ(evidence_manifest_reconstructed(EVM_SINK_ALERT_PCAP), 0);
    ASSERT_EQ(evidence_manifest_reconstructed(EVM_SINK_EVIDENCE_PCAP), 0);
    ASSERT_EQ(evidence_manifest_reconstructed(EVM_SINK_HANDSHAKE_PCAP), 1);
    ASSERT_EQ(evidence_manifest_reconstructed(EVM_SINK_HASHCAT_22000), 1);
    ASSERT(evidence_manifest_is_name("sloth-manifest-x.jsonl"));
    ASSERT(!evidence_manifest_is_name("sloth-manifest-.jsonl"));
    ASSERT(!evidence_manifest_is_name("sloth-manifest-x.json"));
    ASSERT(!evidence_manifest_is_name("x.jsonl"));
}

void run_evidence_manifest_tests(void) {
    TEST_SUITE("evidence manifest — hashed per-session record (#92 slice 3)");
    RUN_TEST(test_alert_pcap_snaplen_is_the_ring_depth);
    RUN_TEST(test_alert_pcap_gets_a_true_line);
    RUN_TEST(test_alert_pcap_no_file_no_line);
    RUN_TEST(test_manifest_failure_is_counted_not_blocking);
    RUN_TEST(test_every_crash_prefix_parses);
    RUN_TEST(test_two_sessions_never_share_a_manifest);
    RUN_TEST(test_session_is_named_for_its_start);
    RUN_TEST(test_evidence_pcap_gets_a_true_line);
    RUN_TEST(test_failed_evidence_export_lists_nothing);
    RUN_TEST(test_one_directory_one_manifest);
    RUN_TEST(test_each_directory_lists_its_own_files);
    RUN_TEST(test_sweep_expires_the_manifest_and_a_new_one_starts);
    RUN_TEST(test_record_refuses_non_files);
    RUN_TEST(test_sink_names_and_reconstructed);
}
