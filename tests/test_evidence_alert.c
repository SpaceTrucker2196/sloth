#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#include "evidence_manifest.h"
#include "manifest_check.h"
#include "runner.h"
#include "sloth.h"
#include "alerts.h"
#include "alert_pcap.h"
#include "evidence_export.h"
#include "evidence_ring.h"
#include "eapol_log.h"
#include "ownership.h"
#include "tune.h"
#include "sloth_clock.h"
#include "secure_file.h"

/* ── Alert → evidence export, and no partial files (#92 slices 1+2) ──
 *
 * Slice 1: an alert that cites evidence-ring frames writes them to disk.
 * Before it, dump_new_alert_pcaps() skipped every alert without a
 * match_ip, so a DEAUTH_FLOOD CRIT — IDs on the alert, every flag set —
 * wrote zero frames. Driven through the real rule_deauth_flood() and
 * alerts_update(), not by calling the exporter directly, because the
 * defect was the missing call, not the writer.
 *
 * Slice 2: every failure path of evidence_export_pcap() leaves nothing
 * under the final name, and no temp either. Each path is driven by the
 * exporter's fault seam rather than a full disk.
 *
 * Each test runs in its own mkdtemp() directory, removed at the end;
 * nothing is written under tests/. The wall and monotonic clocks are
 * pinned for the whole suite (sloth_clock_test_set), so neither the
 * cooldown nor incident expiry can straddle a real second boundary. */

static char   g_dir[64];
static time_t g_wall = 1700000000;
static time_t   ea_wall(void) { return g_wall; }
static uint64_t ea_mono(void) { return (uint64_t)g_wall * 1000u; }

static const uint8_t VICTIM[6] = {0x12,0x34,0x56,0x78,0x9a,0xbc};
static const uint8_t BSSID[6]  = {0x02,0x00,0x5e,0x00,0x53,0x01};
#define BSSID_STR "02:00:5e:00:53:01"

/* Evidence files only. The session manifest (#92 slice 3) sits in the
 * same directory and has its own assertions in test_evidence_manifest.c;
 * counting it here would make every "nothing partial was left" check
 * depend on whether an earlier export in the test created one. */
static int dir_entries(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..") &&
            !evidence_manifest_is_name(e->d_name)) n++;
    closedir(d);
    return n;
}

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

/* A fresh private directory, the gate open on it, a clean engine. */
static void setup(int collect, int with_dir) {
    snprintf(g_dir, sizeof(g_dir), "/tmp/sloth_evalert_XXXXXX");
    ASSERT(mkdtemp(g_dir) != NULL);
    g_wall = 1700000000;
    sloth_clock_test_set(ea_mono, ea_wall);
    alerts_clear();
    tune_reset();
    ownership_clear();
    alert_pcap_set_dir(NULL);
    eapol_set_collect_enabled(collect);
    if (collect && with_dir) ASSERT_EQ(eapol_set_output_dir(g_dir), 0);
    evidence_export_test_fault(EVX_FAULT_NONE, 0);
}

static void teardown(void) {
    evidence_export_test_fault(EVX_FAULT_NONE, 0);
    alerts_clear();
    tune_reset();
    ownership_clear();
    alert_pcap_set_dir(NULL);
    eapol_set_output_dir(NULL);
    eapol_set_collect_enabled(0);
    evidence_ring_reset();
    rm_dir(g_dir);
    sloth_clock_test_set(NULL, NULL);
}

/* Radiotap (8-byte header, no present fields) + a deauthentication
 * frame: FC 0xc0 (type 0 management, subtype 12, IEEE 802.11-2020
 * 9.3.3.12), addr1 victim, addr2/addr3 BSSID, reason 7. The bytes do not
 * matter to the exporter — it copies them — but they are a real frame so
 * the file is one a reader can open and believe. */
static int deauth_frame(uint8_t *f, size_t cap, uint8_t seq) {
    const int len = 8 + 24 + 2;
    if (cap < (size_t)len) return -1;
    memset(f, 0, (size_t)len);
    f[2] = 8;                         /* it_len */
    f[8] = 0xc0;                      /* deauth */
    memcpy(f + 8 + 4,  VICTIM, 6);
    memcpy(f + 8 + 10, BSSID,  6);
    memcpy(f + 8 + 16, BSSID,  6);
    f[8 + 22] = (uint8_t)(seq << 4);  /* sequence number, low nibble */
    f[8 + 24] = 7;                    /* reason code, LE */
    return len;
}

static void seed_ring(uint64_t *ids, int n) {
    evidence_ring_reset();
    ASSERT_EQ(evidence_ring_init(64 * 1024), 0);
    uint8_t f[64];
    for (int i = 0; i < n; i++) {
        int len = deauth_frame(f, sizeof(f), (uint8_t)i);
        ids[i] = evidence_ring_note(f, (uint32_t)len, (uint32_t)len,
                                    g_wall - 3 + i, (uint32_t)i * 1000u,
                                    2412, -40);
        ASSERT(ids[i] != 0);
    }
}

/* The (BSSID, victim) aggregate rule_deauth_flood() reads, flooded, and
 * citing `ids`. */
static void seed_flood(sloth_state_t *s, const uint64_t *ids, int n) {
    memset(s, 0, sizeof(*s));
    deauth_victim_t *v = &s->deauth_victims[s->deauth_victim_count++];
    memcpy(v->victim, VICTIM, 6);
    memcpy(v->bssid,  BSSID,  6);
    v->reason       = 7;
    v->reason_valid = 1;
    v->frames       = 25;
    v->peak_win     = 25;
    v->streams      = 1;
    v->flood        = 1;
    v->first_seen   = g_wall;
    v->last_seen    = g_wall;
    v->flood_last   = g_wall;
    for (int i = 0; i < n && i < DEAUTH_EVIDENCE_IDS; i++)
        v->evidence_ids[i] = ids[i];
    v->evidence_id_count = n;
}

static int find_deauth(const sloth_state_t *s) {
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == ALERT_TYPE_DEAUTH_FLOOD) return i;
    return -1;
}

/* Records in a classic pcap written little-endian (pcap_format.h), and
 * its linktype. -1 if it is not a whole file: every record header must
 * be followed by exactly caplen bytes. */
static int pcap_records(const char *path, uint32_t *dlt) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    uint8_t gh[24];
    if (fread(gh, 1, sizeof(gh), fp) != sizeof(gh)) { fclose(fp); return -1; }
    uint32_t magic = (uint32_t)gh[0] | (uint32_t)gh[1] << 8 |
                     (uint32_t)gh[2] << 16 | (uint32_t)gh[3] << 24;
    if (magic != 0xa1b2c3d4u) { fclose(fp); return -1; }
    if (dlt) *dlt = (uint32_t)gh[20] | (uint32_t)gh[21] << 8 |
                    (uint32_t)gh[22] << 16 | (uint32_t)gh[23] << 24;
    int n = 0;
    uint8_t rh[16], body[4096];
    size_t got;
    while ((got = fread(rh, 1, sizeof(rh), fp)) == sizeof(rh)) {
        uint32_t caplen = (uint32_t)rh[8] | (uint32_t)rh[9] << 8 |
                          (uint32_t)rh[10] << 16 | (uint32_t)rh[11] << 24;
        if (caplen > sizeof(body) ||
            fread(body, 1, caplen, fp) != caplen) { fclose(fp); return -1; }
        n++;
    }
    fclose(fp);
    return got == 0 ? n : -1;
}

/* ── Slice 1: the alert engine writes the cited frames ───────────── */

static void test_deauth_crit_writes_its_frames(void) {
    setup(1, 1);
    ASSERT(ownership_add_bssid(BSSID_STR));   /* YOUR network → CRIT */
    uint64_t ids[3];
    seed_ring(ids, 3);
    static sloth_state_t s;
    seed_flood(&s, ids, 3);
    alerts_update(&s);

    int i = find_deauth(&s);
    ASSERT(i >= 0);
    if (i < 0) { teardown(); return; }
    const alert_t *a = &s.alerts[i];
    ASSERT_EQ((int)a->sev, (int)ALERT_SEV_CRIT);
    ASSERT_EQ(a->match_ip[0], '\0');      /* the case that used to be skipped */
    ASSERT_EQ(a->pcap_dumped, 1);
    ASSERT_EQ(a->pcap_write_failures, 0);

    /* Name: <incident_id>-<first cited event ID>-<rule>.pcap, under
       --eapol-dir. Built here from its parts, not by calling the
       function under test. */
    char want[ALERT_PCAP_PATH_LEN];
    snprintf(want, sizeof(want), "%s/%s-%llu-DEAUTH_FLOOD.pcap",
             g_dir, a->incident_id, (unsigned long long)ids[0]);
    ASSERT_STR(a->pcap_path, want);
    ASSERT_EQ((int)strlen(a->incident_id), 16);

    uint32_t dlt = 0;
    ASSERT_EQ(pcap_records(a->pcap_path, &dlt), 3);
    ASSERT_EQ((long long)dlt, 127LL);     /* IEEE 802.11 + radiotap */
    /* The file and nothing else: no temp left beside it. */
    ASSERT_EQ(dir_entries(g_dir), 1);

    struct stat st;
    ASSERT_EQ(stat(a->pcap_path, &st), 0);
    ASSERT_EQ((int)(st.st_mode & 0777), 0600);

    /* #92 slice 3: the engine hands the exporter the incident and the
     * rule, and the manifest line carries both beside the file's hash.
     * Seen red with the engine passing NULL for either. */
    static mf_line_t l[4];
    int bad = -1;
    ASSERT_EQ(mf_read_dir(g_dir, l, 4, &bad), 1);
    ASSERT_EQ(bad, 0);
    const char *leaf = strrchr(a->pcap_path, '/');
    ASSERT_STR(l[0].file, leaf ? leaf + 1 : a->pcap_path);
    ASSERT_STR(l[0].incident_id, a->incident_id);
    ASSERT_STR(l[0].rule, "DEAUTH_FLOOD");
    ASSERT_STR(l[0].sink, "evidence_pcap");
    char hex[65];
    ASSERT_EQ(mf_hash_path(a->pcap_path, hex, NULL), 0);
    ASSERT_STR(l[0].sha256, hex);
    teardown();
}

static void test_cooldown_suppresses_a_second_write(void) {
    /* A key that resolves and re-fires is a new incident with a new
       incident_id — so a new name — and must still not write the same
       finding's frames twice inside pcap.key_cooldown_secs (#96). */
    setup(1, 1);
    ASSERT(ownership_add_bssid(BSSID_STR));
    uint64_t ids[2];
    seed_ring(ids, 2);
    static sloth_state_t s;
    seed_flood(&s, ids, 2);
    alerts_update(&s);
    int i = find_deauth(&s);
    ASSERT(i >= 0);
    if (i < 0) { teardown(); return; }
    char first_inc[ALERT_INCIDENT_ID_LEN], first_path[ALERT_PCAP_PATH_LEN];
    snprintf(first_inc,  sizeof(first_inc),  "%s", s.alerts[i].incident_id);
    snprintf(first_path, sizeof(first_path), "%s", s.alerts[i].pcap_path);
    ASSERT(first_path[0] != '\0');
    ASSERT_EQ(dir_entries(g_dir), 1);

    /* Quiet past the resolve period: no rule re-asserts the key against
       empty state, so expire_incidents() closes it. */
    static sloth_state_t empty;
    memset(&empty, 0, sizeof(empty));
    g_wall += ALERT_RESOLVE_AFTER_S + 1;
    alerts_update(&empty);

    seed_flood(&s, ids, 2);
    alerts_update(&s);
    i = find_deauth(&s);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT(strcmp(s.alerts[i].incident_id, first_inc) != 0);
        ASSERT_EQ(s.alerts[i].pcap_dumped, 1);
        ASSERT_EQ(s.alerts[i].pcap_write_failures, 0);
        ASSERT_STR(s.alerts[i].pcap_path, first_path);
    }
    ASSERT_EQ(dir_entries(g_dir), 1);     /* still one file */
    teardown();
}

static void test_no_write_with_the_gate_closed(void) {
    /* --collect-handshakes off: no --eapol-dir is even accepted, and
       --pcap-dir alone must not become a second route to raw 802.11
       (owner ruling 2026-10-08, option A rejected). The pcap dir is the
       same temp directory, so "nothing written" is one count. */
    setup(0, 0);
    ASSERT_EQ(alert_pcap_set_dir(g_dir), 0);
    ASSERT(ownership_add_bssid(BSSID_STR));
    uint64_t ids[2];
    seed_ring(ids, 2);
    static sloth_state_t s;
    seed_flood(&s, ids, 2);
    alerts_update(&s);
    alerts_update(&s);
    int i = find_deauth(&s);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_STR(s.alerts[i].pcap_path, "");
        /* Switched off is not a failure: no retry storm, no badge. */
        ASSERT_EQ(s.alerts[i].pcap_write_failures, 0);
    }
    ASSERT_EQ(eapol_export_failures(), 0);
    ASSERT_EQ(dir_entries(g_dir), 0);
    teardown();
}

static void test_no_write_with_the_gate_open_but_no_dir(void) {
    setup(1, 0);
    ASSERT(ownership_add_bssid(BSSID_STR));
    uint64_t ids[1];
    seed_ring(ids, 1);
    static sloth_state_t s;
    seed_flood(&s, ids, 1);
    alerts_update(&s);
    int i = find_deauth(&s);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_STR(s.alerts[i].pcap_path, "");
        ASSERT_EQ(s.alerts[i].pcap_write_failures, 0);
    }
    /* And called directly, past the engine's own enabled check: the
       refusal is reported in err but is not a failed write, so the
       EAPOL failure count (and the !persist badge) stays at 0. */
    char err[SFILE_ERR_MAX] = "";
    ASSERT_EQ(evidence_export_pcap("ev.pcap", ids, 1, NULL,
                                   err, sizeof(err)), -1);
    ASSERT(strstr(err, "--eapol-dir") != NULL);
    ASSERT_EQ(eapol_export_failures(), 0);
    ASSERT_EQ(dir_entries(g_dir), 0);
    teardown();
}

static void test_severity_floor_applies_to_evidence(void) {
    /* Not the operator's BSSID → WARN, under the default CRIT floor
       (pcap.min_severity = 2). Nothing written, and not marked done:
       an escalation to CRIT must still export. */
    setup(1, 1);
    uint64_t ids[2];
    seed_ring(ids, 2);
    static sloth_state_t s;
    seed_flood(&s, ids, 2);
    alerts_update(&s);
    int i = find_deauth(&s);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((int)s.alerts[i].sev, (int)ALERT_SEV_WARN);
        ASSERT_EQ(s.alerts[i].pcap_dumped, 0);
        ASSERT_STR(s.alerts[i].pcap_path, "");
    }
    ASSERT_EQ(dir_entries(g_dir), 0);

    ASSERT(ownership_add_bssid(BSSID_STR));   /* now CRIT: escalates */
    g_wall += 1;
    seed_flood(&s, ids, 2);
    alerts_update(&s);
    i = find_deauth(&s);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((int)s.alerts[i].sev, (int)ALERT_SEV_CRIT);
        ASSERT_EQ(s.alerts[i].pcap_dumped, 1);
    }
    ASSERT_EQ(dir_entries(g_dir), 1);
    teardown();
}

static void test_failed_export_counts_and_retries(void) {
    /* A write that fails mid-file is recorded on the alert (and so in
       JSONL), leaves nothing behind, and is retried next tick. */
    setup(1, 1);
    ASSERT(ownership_add_bssid(BSSID_STR));
    uint64_t ids[2];
    seed_ring(ids, 2);
    static sloth_state_t s;
    seed_flood(&s, ids, 2);
    evidence_export_test_fault(EVX_FAULT_WRITE, 3);   /* first record body */
    alerts_update(&s);
    int i = find_deauth(&s);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(s.alerts[i].pcap_write_failures, 1);
        ASSERT_EQ(s.alerts[i].pcap_dumped, 0);
        ASSERT_STR(s.alerts[i].pcap_path, "");
    }
    ASSERT_EQ(dir_entries(g_dir), 0);

    g_wall += 1;
    seed_flood(&s, ids, 2);
    alerts_update(&s);
    i = find_deauth(&s);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(s.alerts[i].pcap_dumped, 1);
        ASSERT(s.alerts[i].pcap_path[0] != '\0');
        ASSERT_EQ(pcap_records(s.alerts[i].pcap_path, NULL), 2);
    }
    ASSERT_EQ(dir_entries(g_dir), 1);
    teardown();
}

static void test_aged_out_frames_write_no_file(void) {
    /* Every cited ID evicted (here: never issued by this ring). Zero
       frames is terminal and not a failure, and a header-only pcap is
       not evidence, so no file at all. */
    setup(1, 1);
    ASSERT(ownership_add_bssid(BSSID_STR));
    uint64_t real[1];
    seed_ring(real, 1);
    uint64_t gone[2] = { real[0] + 1000, real[0] + 1001 };
    static sloth_state_t s;
    seed_flood(&s, gone, 2);
    alerts_update(&s);
    int i = find_deauth(&s);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(s.alerts[i].pcap_dumped, 1);
        ASSERT_EQ(s.alerts[i].pcap_write_failures, 0);
        ASSERT_STR(s.alerts[i].pcap_path, "");
    }
    ASSERT_EQ(dir_entries(g_dir), 0);
    teardown();
}

/* ── Slice 2: nothing partial under the final name ───────────────── */

static int exists_in_dir(const char *name) {
    char p[400];
    snprintf(p, sizeof(p), "%s/%s", g_dir, name);
    struct stat st;
    return lstat(p, &st) == 0;
}

/* Arm one fault, export three frames, and require: -1, a reason, no
   file under the final name, no temp, an empty directory. */
static void expect_clean_failure(evx_fault_t f, int nth, const char *why) {
    setup(1, 1);
    uint64_t ids[3];
    seed_ring(ids, 3);
    evidence_export_test_fault(f, nth);
    const int before = eapol_export_failures();
    char err[SFILE_ERR_MAX] = "";
    ASSERT_EQ(evidence_export_pcap("ev.pcap", ids, 3, NULL,
                                   err, sizeof(err)), -1);
    ASSERT(strstr(err, why) != NULL);
    /* Counted where the [e] view and !persist badge read it, not only
       handed back in err. */
    ASSERT_EQ(eapol_export_failures(), before + 1);
    ASSERT(!exists_in_dir("ev.pcap"));
    ASSERT(!exists_in_dir(".ev.pcap.tmp"));
    ASSERT_EQ(dir_entries(g_dir), 0);
    teardown();
}

static void test_header_write_failure_leaves_nothing(void) {
    expect_clean_failure(EVX_FAULT_WRITE, 1, "header");
}
static void test_alloc_failure_leaves_nothing(void) {
    expect_clean_failure(EVX_FAULT_ALLOC, 1, "out of memory");
}
static void test_record_header_failure_leaves_nothing(void) {
    expect_clean_failure(EVX_FAULT_WRITE, 2, "record");
}
static void test_mid_file_failure_leaves_nothing(void) {
    /* Write 5 is the second record's header: one whole record is
       already on disk, which is the truncated-file case exactly. */
    expect_clean_failure(EVX_FAULT_WRITE, 5, "record");
}
static void test_fsync_failure_leaves_nothing(void) {
    expect_clean_failure(EVX_FAULT_FSYNC, 1, "fsync");
}
static void test_commit_failure_leaves_nothing(void) {
    expect_clean_failure(EVX_FAULT_COMMIT, 1, "commit");
}

static void test_existing_name_is_kept_and_temp_removed(void) {
    /* The real commit refusal, no seam: a second export to a name
       already on disk keeps the first file byte for byte and removes
       its own temp. */
    setup(1, 1);
    uint64_t ids[2];
    seed_ring(ids, 2);
    ASSERT_EQ(evidence_export_pcap("ev.pcap", ids, 1, NULL, NULL, 0), 1);
    char p[400];
    snprintf(p, sizeof(p), "%s/ev.pcap", g_dir);
    struct stat a, b;
    ASSERT_EQ(stat(p, &a), 0);
    char err[SFILE_ERR_MAX] = "";
    ASSERT_EQ(evidence_export_pcap("ev.pcap", ids, 2, NULL,
                                   err, sizeof(err)), -1);
    ASSERT(strstr(err, "exists") != NULL);
    ASSERT_EQ(stat(p, &b), 0);
    ASSERT_EQ((long long)b.st_size, (long long)a.st_size);
    ASSERT_EQ((long long)b.st_ino,  (long long)a.st_ino);
    ASSERT(!exists_in_dir(".ev.pcap.tmp"));
    ASSERT_EQ(dir_entries(g_dir), 1);
    teardown();
}

static void test_stale_temp_from_a_crash_does_not_block(void) {
    /* A crash mid-write leaves .<name>.tmp. The next export of that
       name must not be refused by O_EXCL forever. */
    setup(1, 1);
    uint64_t ids[1];
    seed_ring(ids, 1);
    char p[400];
    snprintf(p, sizeof(p), "%s/.ev.pcap.tmp", g_dir);
    FILE *fp = fopen(p, "wb");
    ASSERT(fp != NULL);
    if (fp) { fputs("partial", fp); fclose(fp); }
    ASSERT_EQ(evidence_export_pcap("ev.pcap", ids, 1, NULL, NULL, 0), 1);
    ASSERT(exists_in_dir("ev.pcap"));
    ASSERT(!exists_in_dir(".ev.pcap.tmp"));
    teardown();
}

/* ── Review fixes (#92 review) ───────────────────────────────────── */

/* A file with known content at g_dir/<name>, standing in for one an
   earlier process wrote. */
static void plant(const char *name, const char *body) {
    char p[400];
    snprintf(p, sizeof(p), "%s/%s", g_dir, name);
    FILE *fp = fopen(p, "wb");
    ASSERT(fp != NULL);
    if (fp) { fputs(body, fp); fclose(fp); }
}

static long size_in_dir(const char *name) {
    char p[400];
    snprintf(p, sizeof(p), "%s/%s", g_dir, name);
    struct stat st;
    return stat(p, &st) == 0 ? (long)st.st_size : -1;
}

/* The incident's first tick fails (armed write fault), so the name is
   known before any export succeeds; the test then puts a file there,
   as an earlier run of the same sensor would have. */
static int fail_first_tick(sloth_state_t *s, const uint64_t *ids, int n,
                           char *stem, size_t stemsz) {
    seed_flood(s, ids, n);
    evidence_export_test_fault(EVX_FAULT_WRITE, 1);
    alerts_update(s);
    int i = find_deauth(s);
    ASSERT(i >= 0);
    if (i < 0) return -1;
    ASSERT_EQ(s->alerts[i].pcap_write_failures, 1);
    ASSERT_EQ(s->alerts[i].pcap_dumped, 0);
    snprintf(stem, stemsz, "%s-%llu-DEAUTH_FLOOD", s->alerts[i].incident_id,
             (unsigned long long)ids[0]);
    return i;
}

static void test_name_from_an_earlier_run_gets_a_suffix(void) {
    /* The alert name is unique within one process only: incident_id is
       FNV(key, wall second, a sequence that restarts at 0) and evidence
       IDs restart at 1, so a restart that re-fires the key in the same
       wall second rebuilds the same name while the earlier file is still
       inside the retention window. The commit used to refuse that name,
       the engine took the refusal as transient, and every tick then
       rewrote, fsynced and unlinked the temp and counted a failure,
       forever. Now: one file, under "-2", and no further failures. */
    setup(1, 1);
    ASSERT(ownership_add_bssid(BSSID_STR));
    uint64_t ids[2];
    seed_ring(ids, 2);
    static sloth_state_t s;
    char stem[96], taken[112], want[ALERT_PCAP_PATH_LEN];
    int i = fail_first_tick(&s, ids, 2, stem, sizeof(stem));
    if (i < 0) { teardown(); return; }
    snprintf(taken, sizeof(taken), "%s.pcap", stem);
    plant(taken, "earlier run");
    const int before = eapol_export_failures();

    for (int t = 0; t < 5; t++) {
        g_wall += 1;
        seed_flood(&s, ids, 2);
        alerts_update(&s);
    }
    i = find_deauth(&s);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(s.alerts[i].pcap_dumped, 1);
        ASSERT_EQ(s.alerts[i].pcap_write_failures, 1);  /* the armed one */
        snprintf(want, sizeof(want), "%s/%s-2.pcap", g_dir, stem);
        ASSERT_STR(s.alerts[i].pcap_path, want);
        ASSERT_EQ(pcap_records(s.alerts[i].pcap_path, NULL), 2);
    }
    ASSERT_EQ(eapol_export_failures(), before);
    /* The earlier run's file is left exactly as it was. */
    ASSERT_EQ(size_in_dir(taken), (long)strlen("earlier run"));
    ASSERT_EQ(dir_entries(g_dir), 2);
    teardown();
}

static void test_every_name_taken_is_counted_once(void) {
    /* Past EVX_UNIQUE_MAX candidates the refusal stands — and is then
       terminal: one failure on the alert and in the EAPOL count, the
       incident done, nothing retried on later ticks. */
    setup(1, 1);
    ASSERT(ownership_add_bssid(BSSID_STR));
    uint64_t ids[1];
    seed_ring(ids, 1);
    static sloth_state_t s;
    char stem[96], nm[112];
    int i = fail_first_tick(&s, ids, 1, stem, sizeof(stem));
    if (i < 0) { teardown(); return; }
    snprintf(nm, sizeof(nm), "%s.pcap", stem);
    plant(nm, "x");
    for (int k = 2; k <= EVX_UNIQUE_MAX; k++) {
        snprintf(nm, sizeof(nm), "%s-%d.pcap", stem, k);
        plant(nm, "x");
    }
    const int before = eapol_export_failures();

    for (int t = 0; t < 5; t++) {
        g_wall += 1;
        seed_flood(&s, ids, 1);
        alerts_update(&s);
    }
    i = find_deauth(&s);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(s.alerts[i].pcap_dumped, 1);
        ASSERT_EQ(s.alerts[i].pcap_write_failures, 2);  /* armed + refusal */
        ASSERT_STR(s.alerts[i].pcap_path, "");
    }
    ASSERT_EQ(eapol_export_failures(), before + 1);
    ASSERT_EQ(dir_entries(g_dir), EVX_UNIQUE_MAX);    /* no temp left */
    teardown();
}

/* A subdirectory of g_dir long enough that "<it>/<alert file name>"
   cannot fit in ALERT_PCAP_PATH_LEN, while the directory itself fits
   the 256-byte buffers both exporters keep it in. */
static void long_subdir(char *out, size_t outsz) {
    char leaf[201];
    memset(leaf, 'd', sizeof(leaf) - 1);
    leaf[sizeof(leaf) - 1] = '\0';
    snprintf(out, outsz, "%s/%s", g_dir, leaf);
    ASSERT(strlen(out) < 256);
    ASSERT(strlen(out) + 1 + 36 >= ALERT_PCAP_PATH_LEN);
    ASSERT_EQ(mkdir(out, 0700), 0);
}

static int exists_under(const char *dir, const char *name) {
    char p[600];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    struct stat st;
    return stat(p, &st) == 0;
}

static void test_evidence_path_too_long_records_the_bare_name(void) {
    /* pcap_path is the bare name, which is still true relative to
       --eapol-dir — never a truncated path naming nothing, and never
       empty while a file was written. */
    setup(1, 0);
    char ldir[300];
    long_subdir(ldir, sizeof(ldir));
    ASSERT_EQ(eapol_set_output_dir(ldir), 0);
    ASSERT(ownership_add_bssid(BSSID_STR));
    uint64_t ids[1];
    seed_ring(ids, 1);
    static sloth_state_t s;
    seed_flood(&s, ids, 1);
    alerts_update(&s);
    int i = find_deauth(&s);
    ASSERT(i >= 0);
    if (i >= 0) {
        char want[ALERT_PCAP_PATH_LEN];
        snprintf(want, sizeof(want), "%s-%llu-DEAUTH_FLOOD.pcap",
                 s.alerts[i].incident_id, (unsigned long long)ids[0]);
        ASSERT_EQ(s.alerts[i].pcap_dumped, 1);
        ASSERT_STR(s.alerts[i].pcap_path, want);
        ASSERT(exists_under(ldir, want));
    }
    eapol_set_output_dir(NULL);
    rm_dir(ldir);
    teardown();
}

static void seed_ip_packet(sloth_state_t *s, const char *src, const char *dst,
                           uint16_t sport, uint16_t dport) {
    packet_info_t *p = &s->packets[s->pkt_head];
    memset(p, 0, sizeof(*p));
    snprintf(p->src, sizeof(p->src), "%s", src);
    snprintf(p->dst, sizeof(p->dst), "%s", dst);
    p->src_port = sport;
    p->dst_port = dport;
    p->ts_sec   = (uint32_t)g_wall;
    p->len      = 64;
    p->raw_len  = 32;
    for (int i = 0; i < 32; i++) p->raw[i] = (uint8_t)(i + 1);
    s->pkt_head = (s->pkt_head + 1) % MAX_PACKETS;
    if (s->pkt_count < MAX_PACKETS) s->pkt_count++;
}

static void test_ip_path_too_long_records_the_bare_name(void) {
    /* The same rule in the --pcap-dir exporter. */
    setup(0, 0);
    char ldir[300];
    long_subdir(ldir, sizeof(ldir));
    ASSERT_EQ(alert_pcap_set_dir(ldir), 0);
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    seed_ip_packet(&s, "192.0.2.5", "203.0.113.7", 33445, 443);
    alert_t a;
    memset(&a, 0, sizeof(a));
    snprintf(a.title,    sizeof(a.title),    "THREAT_IP");
    snprintf(a.match_ip, sizeof(a.match_ip), "203.0.113.7");
    a.match_port = 443;
    char path[ALERT_PCAP_PATH_LEN] = "";
    ASSERT_EQ(alert_pcap_dump(&s, &a, path, (int)sizeof(path)), 1);
    ASSERT(path[0] != '\0');
    ASSERT(strchr(path, '/') == NULL);
    ASSERT(strncmp(path, "alert_", 6) == 0);
    ASSERT(exists_under(ldir, path));
    alert_pcap_set_dir(NULL);
    rm_dir(ldir);
    teardown();
}

static void test_aged_out_evidence_falls_back_to_the_ip_path(void) {
    /* An alert with a match_ip AND evidence IDs, the evidence gate open,
       every cited frame aged out: the evidence export has nothing, but
       --pcap-dir can still hold the packets. It used to mark the
       incident done after the empty evidence export and write nothing. */
    setup(1, 1);
    char pdir[64];
    snprintf(pdir, sizeof(pdir), "/tmp/sloth_evalert_ip_XXXXXX");
    ASSERT(mkdtemp(pdir) != NULL);
    ASSERT_EQ(alert_pcap_set_dir(pdir), 0);
    uint64_t real[1];
    seed_ring(real, 1);
    uint64_t gone[2] = { real[0] + 1000, real[0] + 1001 };
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    seed_ip_packet(&s, "192.0.2.5", "203.0.113.7", 33445, 443);
    alerts_fire_ev_for_test(ALERT_TYPE_THREAT_IP, ALERT_SEV_CRIT,
                            "test|both", "both", "203.0.113.7", 443,
                            gone, 2);
    alerts_update(&s);
    int i = -1;
    for (int k = 0; k < s.alert_count; k++)
        if (!strcmp(s.alerts[k].key, "test|both")) i = k;
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(s.alerts[i].pcap_dumped, 1);
        ASSERT_EQ(s.alerts[i].pcap_write_failures, 0);
        ASSERT(strncmp(s.alerts[i].pcap_path, pdir, strlen(pdir)) == 0);
        ASSERT_EQ(pcap_records(s.alerts[i].pcap_path, NULL), 1);
    }
    ASSERT_EQ(dir_entries(pdir), 1);
    ASSERT_EQ(dir_entries(g_dir), 0);      /* no evidence file */
    alert_pcap_set_dir(NULL);
    rm_dir(pdir);
    teardown();
}

static void test_alert_name_format(void) {
    char out[128];
    ASSERT_EQ(evidence_export_alert_name("00ff00ff00ff00ff", 42,
                                         "DEAUTH_FLOOD", out, sizeof(out)), 0);
    ASSERT_STR(out, "00ff00ff00ff00ff-42-DEAUTH_FLOOD.pcap");
    /* Inputs that would make a misleading or unsafe name. */
    ASSERT_EQ(evidence_export_alert_name("", 42, "X", out, sizeof(out)), -1);
    ASSERT_STR(out, "");
    ASSERT_EQ(evidence_export_alert_name("00ff", 0, "X", out, sizeof(out)), -1);
    ASSERT_EQ(evidence_export_alert_name("../x", 1, "X", out, sizeof(out)), -1);
    ASSERT_EQ(evidence_export_alert_name("00FF", 1, "X", out, sizeof(out)), -1);
    ASSERT_EQ(evidence_export_alert_name("00ff", 1, "A/B", out, sizeof(out)), 0);
    ASSERT_STR(out, "00ff-1-A_B.pcap");
    ASSERT_EQ(evidence_export_alert_name("00ff", 1, "X", out, 8), -1);
    ASSERT_STR(out, "");
}

void run_evidence_alert_tests(void) {
    TEST_SUITE("evidence export: alert engine wiring, no partial files (#92)");
    RUN_TEST(test_deauth_crit_writes_its_frames);
    RUN_TEST(test_cooldown_suppresses_a_second_write);
    RUN_TEST(test_no_write_with_the_gate_closed);
    RUN_TEST(test_no_write_with_the_gate_open_but_no_dir);
    RUN_TEST(test_severity_floor_applies_to_evidence);
    RUN_TEST(test_failed_export_counts_and_retries);
    RUN_TEST(test_aged_out_frames_write_no_file);
    RUN_TEST(test_header_write_failure_leaves_nothing);
    RUN_TEST(test_alloc_failure_leaves_nothing);
    RUN_TEST(test_record_header_failure_leaves_nothing);
    RUN_TEST(test_mid_file_failure_leaves_nothing);
    RUN_TEST(test_fsync_failure_leaves_nothing);
    RUN_TEST(test_commit_failure_leaves_nothing);
    RUN_TEST(test_existing_name_is_kept_and_temp_removed);
    RUN_TEST(test_stale_temp_from_a_crash_does_not_block);
    RUN_TEST(test_name_from_an_earlier_run_gets_a_suffix);
    RUN_TEST(test_every_name_taken_is_counted_once);
    RUN_TEST(test_evidence_path_too_long_records_the_bare_name);
    RUN_TEST(test_ip_path_too_long_records_the_bare_name);
    RUN_TEST(test_aged_out_evidence_falls_back_to_the_ip_path);
    RUN_TEST(test_alert_name_format);
}
