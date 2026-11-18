#include "runner.h"
#include "sloth.h"
#include "wifi_snapshot.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include "tmp_dir.h"

static char tmp[TEST_TMP_MAX];

static void mktmp(void) { int fd = mkstemp(test_tmp_tpl(tmp, sizeof(tmp), "sloth_snap_XXXXXX")); if (fd >= 0) close(fd); }

static void seed_ap(sloth_state_t *s, int i, const uint8_t *bssid,
                    const char *ssid, const char *enc, int ch, int mfp) {
    beacon_ap_t *a = &s->beacon_aps[i];
    memcpy(a->bssid, bssid, 6);
    snprintf(a->ssid, sizeof(a->ssid), "%s", ssid);
    snprintf(a->enc,  sizeof(a->enc),  "%s", enc);
    a->channel = ch;
    a->mfp     = mfp;
}

/* Writing then diffing the same state must report zero drift. */
static void test_roundtrip_no_diff(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t b0[6] = { 0xaa, 0, 0, 0, 0, 1 }, b1[6] = { 0xaa, 0, 0, 0, 0, 2 };
    seed_ap(&s, 0, b0, "Home",  "WPA2", 6,  2);
    seed_ap(&s, 1, b1, "Guest", "WPA3", 36, 2);
    s.beacon_count = 2;
    mktmp();
    ASSERT_EQ(wifi_snapshot_write(&s, tmp, "site-a", 1000), 0);
    FILE *nul = fopen("/dev/null", "w");
    ASSERT_EQ(wifi_snapshot_diff(&s, tmp, nul), 0);
    fclose(nul);
}

/* A changed cipher, a disappeared AP, and a new AP = three differences. */
static void test_diff_detects_changes(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t b0[6] = { 0xaa, 0, 0, 0, 0, 1 }, b1[6] = { 0xaa, 0, 0, 0, 0, 2 };
    seed_ap(&s, 0, b0, "Home",  "WPA2", 6,  2);
    seed_ap(&s, 1, b1, "Guest", "WPA3", 36, 2);
    s.beacon_count = 2;
    mktmp();
    wifi_snapshot_write(&s, tmp, NULL, 1000);

    uint8_t b2[6] = { 0xaa, 0, 0, 0, 0, 3 };
    snprintf(s.beacon_aps[0].enc, sizeof(s.beacon_aps[0].enc), "OPEN"); /* CHANGED */
    seed_ap(&s, 1, b2, "New", "WPA2", 11, 2);   /* b1 GONE + b2 NEW */

    FILE *nul = fopen("/dev/null", "w");
    int d = wifi_snapshot_diff(&s, tmp, nul);
    fclose(nul);
    ASSERT_EQ(d, 3);
}

static void test_missing_baseline(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    FILE *nul = fopen("/dev/null", "w");
    ASSERT_EQ(wifi_snapshot_diff(&s, "/no/such/baseline/file", nul), -1);
    fclose(nul);
}

/* ── file permissions, #87 ───────────────────────────────── */

/* A site snapshot names every AP in range with its security posture —
 * an assessor's target list. Created private whatever the umask; an
 * existing file that is not private, or a symlink, is refused and left
 * byte-for-byte as it was. Overwriting the operator's own earlier
 * snapshot stays the normal case (repeat site survey). */

static void s87_path(char *out, size_t sz) {
    snprintf(out, sz, "%s/sloth_test_snap87_%d.txt", test_tmpdir(), (int)getpid());
}

static int s87_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    return (int)(st.st_mode & 07777);
}

static long s87_size(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    return (long)st.st_size;
}

/* Two APs, enough body to exceed a tiny RLIMIT_FSIZE. */
static void s87_seed(sloth_state_t *s) {
    uint8_t b0[6] = { 0xaa, 0, 0, 0, 0, 1 }, b1[6] = { 0xaa, 0, 0, 0, 0, 2 };
    memset(s, 0, sizeof(*s));
    seed_ap(s, 0, b0, "Home",  "WPA2", 6,  2);
    seed_ap(s, 1, b1, "Guest", "WPA3", 36, 2);
    s->beacon_count = 2;
}

static void test_write_creates_private_under_permissive_umask(void) {
    char p[96]; s87_path(p, sizeof(p));
    sloth_state_t s; s87_seed(&s);
    unlink(p);
    mode_t old = umask(022);
    ASSERT_EQ(wifi_snapshot_write(&s, p, "site-a", 1000), 0);
    umask(old);
    ASSERT_EQ(s87_mode(p), 0600);
    unlink(p);
}

static void test_write_refuses_permissive_existing_file(void) {
    char p[96]; s87_path(p, sizeof(p));
    sloth_state_t s; s87_seed(&s);
    unlink(p);
    FILE *f = fopen(p, "w");
    if (f) { fputs("prior\n", f); fclose(f); }
    chmod(p, 0644);
    ASSERT_EQ(wifi_snapshot_write(&s, p, "site-a", 1000), -1);
    ASSERT(strstr(wifi_snapshot_error(), "0644") != NULL);
    ASSERT_EQ(s87_mode(p), 0644);   /* validated, never repaired */
    ASSERT_EQ(s87_size(p), 6);      /* validate runs before ftruncate */
    unlink(p);
}

static void test_write_refuses_symlink(void) {
    char p[96], victim[112];
    s87_path(p, sizeof(p));
    snprintf(victim, sizeof(victim), "%s.victim", p);
    sloth_state_t s; s87_seed(&s);
    unlink(p);
    int fd = open(victim, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) close(fd);
    ASSERT_EQ(symlink(victim, p), 0);
    ASSERT_EQ(wifi_snapshot_write(&s, p, "site-a", 1000), -1);
    ASSERT(strstr(wifi_snapshot_error(), "symbolic link") != NULL);
    ASSERT_EQ(s87_size(victim), 0);   /* nothing written through the link */
    unlink(p);
    unlink(victim);
}

/* A write that fails after the open must not be announced as written —
 * RLIMIT_FSIZE stands in for a full disk. */
static void test_write_reports_failure_after_open(void) {
    char p[96]; s87_path(p, sizeof(p));
    sloth_state_t s; s87_seed(&s);
    unlink(p);

    struct rlimit old, lim;
    getrlimit(RLIMIT_FSIZE, &old);
    lim = old;
    lim.rlim_cur = 8;
    void (*prev)(int) = signal(SIGXFSZ, SIG_IGN);
    setrlimit(RLIMIT_FSIZE, &lim);
    int rc = wifi_snapshot_write(&s, p, "site-a", 1000);
    setrlimit(RLIMIT_FSIZE, &old);
    signal(SIGXFSZ, prev);

    ASSERT_EQ(rc, -1);
    ASSERT(wifi_snapshot_error()[0] != '\0');
    unlink(p);
}

/* The repeat-survey workflow: re-pointing --snapshot-out at your own
 * previous snapshot overwrites it. */
static void test_write_succeeds_over_private_existing_file(void) {
    char prev_path[TEST_TMP_MAX];
    test_tmp_path(prev_path, sizeof(prev_path), "sloth_snap87_prev_XXXXXX");
    int fd = mkstemp(prev_path);
    ASSERT_GE(fd, 0);
    if (fd >= 0) { (void)!write(fd, "stale snapshot\n", 15); close(fd); }

    sloth_state_t s; s87_seed(&s);
    ASSERT_EQ(wifi_snapshot_write(&s, prev_path, "site-a", 1000), 0);
    ASSERT_EQ(s87_mode(prev_path), 0600);

    FILE *f = fopen(prev_path, "r");
    ASSERT(f != NULL);
    char line[64] = { 0 };
    if (f) { ASSERT(fgets(line, sizeof(line), f) != NULL); fclose(f); }
    ASSERT_STR(line, "# sloth-snapshot v1\n");
    unlink(prev_path);
}

/* ── hostile SSIDs, #137 ─────────────────────────────────── */

/* The SSID is whatever the transmitter put on the air. Written raw into
 * a tab-separated file, a tab or newline in it adds fields or whole rows
 * to the baseline the next run reads back. */

static void e_path(char *out, size_t sz) {
    snprintf(out, sz, "%s/sloth_test_snap137_%d.txt", test_tmpdir(), (int)getpid());
}

static int data_lines(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int n = 0, at_bol = 1, c;
    while ((c = fgetc(f)) != EOF) {
        if (at_bol && c != '#') n++;
        at_bol = (c == '\n');
    }
    fclose(f);
    return n;
}

/* Diff report into buf; returns the diff count. */
static int diff_into(const sloth_state_t *s, const char *path,
                     char *buf, size_t cap) {
    FILE *t = tmpfile();
    if (!t) { buf[0] = '\0'; return -2; }
    int d = wifi_snapshot_diff(s, path, t);
    rewind(t);
    size_t n = fread(buf, 1, cap - 1, t);
    buf[n] = '\0';
    fclose(t);
    return d;
}

static void test_ssid_with_tab_newline_round_trips(void) {
    char p[96]; e_path(p, sizeof(p));
    unlink(p);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t b0[6] = { 0xaa, 0, 0, 0, 0, 1 }, b1[6] = { 0xaa, 0, 0, 0, 0, 2 };
    seed_ap(&s, 0, b0, "a\tb\nc", "WPA2", 6, 2);
    /* A second AP whose SSID is a forged row: if the newline got through,
     * this line would become a baseline AP of its own. */
    seed_ap(&s, 1, b1, "x\naa:00:00:00:00:09\tF\tOPEN\t1", "WPA3", 36, 2);
    s.beacon_count = 2;
    ASSERT_EQ(wifi_snapshot_write(&s, p, "site-a", 1000), 0);

    ASSERT_EQ(data_lines(p), s.beacon_count);
    char rep[2048];
    ASSERT_EQ(diff_into(&s, p, rep, sizeof(rep)), 0);
    ASSERT(strstr(rep, "(no changes)") != NULL);

    /* And the parsed columns are the right ones: against an empty scene
     * both APs are GONE with their own enc and channel — not with an SSID
     * fragment in the enc column. The SSID is shown escaped. */
    sloth_state_t empty; memset(&empty, 0, sizeof(empty));
    ASSERT_EQ(diff_into(&empty, p, rep, sizeof(rep)), 2);
    ASSERT(strstr(rep, "GONE     aa:00:00:00:00:01  a\\tb\\nc  WPA2 ch6\n")
           != NULL);
    ASSERT(strstr(rep, "GONE     aa:00:00:00:00:02  "
                       "x\\naa:00:00:00:00:09\\tF\\tOPEN\\t1  WPA3 ch36\n")
           != NULL);
    ASSERT(strstr(rep, "aa:00:00:00:00:09  ") == NULL);
    unlink(p);
}

static void test_ssid_backslash_control_and_dash_round_trip(void) {
    /* Backslash must be escaped too, or "a\tb" spelled with a real
     * backslash-t would read back as a tab. "-" is the column's hidden
     * marker, so a real SSID "-" is not the same AP as a hidden one. */
    char p[96]; e_path(p, sizeof(p));
    unlink(p);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t b0[6] = { 0xaa, 0, 0, 0, 0, 1 }, b1[6] = { 0xaa, 0, 0, 0, 0, 2 },
            b2[6] = { 0xaa, 0, 0, 0, 0, 3 }, b3[6] = { 0xaa, 0, 0, 0, 0, 4 };
    seed_ap(&s, 0, b0, "C:\\temp\\t", "WPA2", 1, 0);
    seed_ap(&s, 1, b1, "\x1b[31mred\x7f", "WPA2", 11, 1);
    seed_ap(&s, 2, b2, "-", "OPEN", 6, 0);
    seed_ap(&s, 3, b3, "",  "WPA3", 6, 2);
    s.beacon_count = 4;
    ASSERT_EQ(wifi_snapshot_write(&s, p, NULL, 1000), 0);
    ASSERT_EQ(data_lines(p), 4);

    char rep[2048];
    ASSERT_EQ(diff_into(&s, p, rep, sizeof(rep)), 0);
    sloth_state_t empty; memset(&empty, 0, sizeof(empty));
    ASSERT_EQ(diff_into(&empty, p, rep, sizeof(rep)), 4);
    ASSERT(strstr(rep, "aa:00:00:00:00:01  C:\\\\temp\\\\t  WPA2") != NULL);
    ASSERT(strstr(rep, "aa:00:00:00:00:02  \\x1b[31mred\\x7f  WPA2") != NULL);
    /* The report is for a terminal: no raw ESC or DEL reaches it. */
    ASSERT(strchr(rep, 0x1b) == NULL);
    ASSERT(strchr(rep, 0x7f) == NULL);
    /* Real "-" displays as itself; hidden displays as the marker. */
    ASSERT(strstr(rep, "aa:00:00:00:00:03  -  OPEN") != NULL);
    ASSERT(strstr(rep, "aa:00:00:00:00:04  -  WPA3") != NULL);

    /* ...and in the file they are spelled differently. */
    FILE *f = fopen(p, "r");
    char body[2048] = { 0 };
    if (f) { size_t n = fread(body, 1, sizeof(body) - 1, f); body[n] = 0;
             fclose(f); }
    ASSERT(strstr(body, "aa:00:00:00:00:03\t\\x2d\tOPEN") != NULL);
    ASSERT(strstr(body, "aa:00:00:00:00:04\t-\tWPA3") != NULL);
    unlink(p);
}

static void test_label_newline_adds_no_row(void) {
    char p[96]; e_path(p, sizeof(p));
    unlink(p);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t b0[6] = { 0xaa, 0, 0, 0, 0, 1 };
    seed_ap(&s, 0, b0, "Home", "WPA2", 6, 2);
    s.beacon_count = 1;
    ASSERT_EQ(wifi_snapshot_write(&s, p,
              "site\naa:00:00:00:00:07\tX\tOPEN\t1\t-\t0\t-", 1000), 0);
    ASSERT_EQ(data_lines(p), 1);
    char rep[1024];
    ASSERT_EQ(diff_into(&s, p, rep, sizeof(rep)), 0);
    unlink(p);
}

static void write_raw(const char *path, const char *body) {
    FILE *f = fopen(path, "w");
    if (f) { fputs(body, f); fclose(f); }
}

static void test_pre_escape_v1_file_parses_as_before(void) {
    /* A v1 file written before #137 has no backslashes. The format line
     * did not change, so it must still diff clean. */
    char p[96]; e_path(p, sizeof(p));
    write_raw(p,
        "# sloth-snapshot v1\n# label\tsite-a\n# ts\t1000\n# count\t2\n"
        "# bssid\tssid\tenc\tchannel\takm\tmfp\tvendor\n"
        "aa:00:00:00:00:01\tHome\tWPA2\t6\t-\t2\t-\n"
        "aa:00:00:00:00:02\t-\tWPA3\t36\tSAE\t2\tAcme\n");
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t b0[6] = { 0xaa, 0, 0, 0, 0, 1 }, b1[6] = { 0xaa, 0, 0, 0, 0, 2 };
    seed_ap(&s, 0, b0, "Home", "WPA2", 6,  2);
    seed_ap(&s, 1, b1, "",     "WPA3", 36, 2);
    s.beacon_count = 2;
    char rep[1024];
    ASSERT_EQ(diff_into(&s, p, rep, sizeof(rep)), 0);
    unlink(p);
}

static void test_out_of_range_numbers_reject_the_row(void) {
    /* atoi() read "6junk" as 6 and "x" as 0. Each malformed row is now
     * dropped; only the one good row is a baseline AP. */
    char p[96]; e_path(p, sizeof(p));
    write_raw(p,
        "# sloth-snapshot v1\n"
        "aa:00:00:00:00:01\tok\tWPA2\t6\t-\t2\t-\n"
        "aa:00:00:00:00:02\tjunk\tWPA2\t6junk\t-\t2\t-\n"
        "aa:00:00:00:00:03\tbig\tWPA2\t999\t-\t2\t-\n"
        "aa:00:00:00:00:04\tneg\tWPA2\t-1\t-\t2\t-\n"
        "aa:00:00:00:00:05\tmfp\tWPA2\t6\t-\t3\t-\n"
        "aa:00:00:00:00:06\tnan\tWPA2\tx\t-\t2\t-\n"
        "aa:00:00:00:00:07\twide\tWPA2\t99999999999999999999\t-\t2\t-\n");
    sloth_state_t empty; memset(&empty, 0, sizeof(empty));
    char rep[2048];
    ASSERT_EQ(diff_into(&empty, p, rep, sizeof(rep)), 1);
    ASSERT(strstr(rep, "GONE     aa:00:00:00:00:01  ok  WPA2 ch6\n") != NULL);
    /* Upper bounds are inclusive: 255 and mfp 2 are still rows. */
    write_raw(p,
        "aa:00:00:00:00:01\tok\tWPA2\t255\t-\t2\t-\n"
        "aa:00:00:00:00:02\tok\tWPA2\t0\t-\t0\t-\n");
    ASSERT_EQ(diff_into(&empty, p, rep, sizeof(rep)), 2);
    unlink(p);
}

void run_wifi_snapshot_tests(void) {
    TEST_SUITE("wifi site snapshot");
    RUN_TEST(test_roundtrip_no_diff);
    RUN_TEST(test_diff_detects_changes);
    RUN_TEST(test_missing_baseline);

    TEST_SUITE("wifi site snapshot: file permissions (#87)");
    RUN_TEST(test_write_creates_private_under_permissive_umask);
    RUN_TEST(test_write_refuses_permissive_existing_file);
    RUN_TEST(test_write_refuses_symlink);
    RUN_TEST(test_write_reports_failure_after_open);
    RUN_TEST(test_write_succeeds_over_private_existing_file);

    TEST_SUITE("wifi site snapshot: on-air SSID is untrusted (#137)");
    RUN_TEST(test_ssid_with_tab_newline_round_trips);
    RUN_TEST(test_ssid_backslash_control_and_dash_round_trip);
    RUN_TEST(test_label_newline_adds_no_row);
    RUN_TEST(test_pre_escape_v1_file_parses_as_before);
    RUN_TEST(test_out_of_range_numbers_reject_the_row);

    unlink(tmp);
}
