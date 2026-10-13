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

static char tmp[] = "/tmp/sloth_snap_XXXXXX";

static void mktmp(void) { int fd = mkstemp(tmp); if (fd >= 0) close(fd); }

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
    snprintf(out, sz, "/tmp/sloth_test_snap87_%d.txt", (int)getpid());
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
    char prev_path[] = "/tmp/sloth_snap87_prev_XXXXXX";
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
}
