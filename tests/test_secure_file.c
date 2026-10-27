#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "runner.h"
#include "secure_file.h"
#include "evidence_export.h"
#include "eapol_log.h"
#include "tmp_dir.h"

/* ── secure_file (#87) hardening (#134) ─────────────────────────────
 *
 * Two bypasses closed here, each pinned by a test that was watched go
 * red under the mutation the issue names before its comment was
 * written:
 *
 *   - sfile_open() with a real dirfd refuses a name carrying a path
 *     component. Mutation: delete the guard → "../escape" is created
 *     in the PARENT of the pinned directory → red.
 *   - sfile_system_dir() refuses a group/other-writable directory.
 *     Mutation: drop the `& 022` test → /tmp and a chmod 0777 dir are
 *     accepted → red.
 *
 * Every directory is a fresh mkdtemp (0700, euid-owned) so the tests
 * neither depend on nor disturb anything already under $TMPDIR. */

static char g_parent[TEST_TMP_MAX];   /* mkdtemp root */
static char g_child[TEST_TMP_MAX + 8];    /* g_parent/d — the directory we pin */

static void fresh_dirs(void) {
    snprintf(g_parent, sizeof(g_parent), "%s/sloth_sfile_XXXXXX", test_tmpdir());
    ASSERT(mkdtemp(g_parent) != NULL);
    snprintf(g_child, sizeof(g_child), "%s/d", g_parent);
    ASSERT_EQ(mkdir(g_child, 0700), 0);
}

static void remove_dirs(void) {
    const char *names[] = { "d/ok.bin", "d/x", "d/sub", "escape", "x",
                            "op.txt", "d", NULL };
    char p[160];
    for (int i = 0; names[i]; i++) {
        snprintf(p, sizeof(p), "%s/%s", g_parent, names[i]);
        unlink(p); rmdir(p);
    }
    rmdir(g_parent);
}

static int exists(const char *dir, const char *name) {
    char p[160];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    struct stat st;
    return lstat(p, &st) == 0;
}

/* ── dirfd-relative names must be bare ─────────────────────────── */

static void test_dirfd_relative_rejects_path_components(void) {
    fresh_dirs();
    char err[SFILE_ERR_MAX];
    int dfd = sfile_private_dir(g_child, err, sizeof(err));
    ASSERT(dfd >= 0);

    /* The one that matters: a name walking out of the pinned directory.
     * Without the guard openat(dfd, "../escape", O_CREAT|O_EXCL) happily
     * creates g_parent/escape — the parent is ours and 0700, so every
     * post-open check would pass too. */
    errno = 0;
    ASSERT_EQ(sfile_open(dfd, "../escape", SFILE_EXCL, err, sizeof(err)), -1);
    ASSERT_EQ(errno, EINVAL);
    ASSERT(!exists(g_parent, "escape"));
    ASSERT(strstr(err, "bare file name") != NULL);

    /* A subdirectory component is the same class even when it stays
     * inside: the pin is on the directory, not its subtree. */
    char sub[160];
    snprintf(sub, sizeof(sub), "%s/sub", g_child);
    ASSERT_EQ(mkdir(sub, 0700), 0);
    errno = 0;
    ASSERT_EQ(sfile_open(dfd, "sub/x", SFILE_EXCL, err, sizeof(err)), -1);
    ASSERT_EQ(errno, EINVAL);
    ASSERT(!exists(sub, "x"));

    /* The degenerate names. */
    errno = 0;
    ASSERT_EQ(sfile_open(dfd, "", SFILE_EXCL, err, sizeof(err)), -1);
    ASSERT_EQ(errno, EINVAL);
    errno = 0;
    ASSERT_EQ(sfile_open(dfd, ".", SFILE_EXCL, err, sizeof(err)), -1);
    ASSERT_EQ(errno, EINVAL);
    errno = 0;
    ASSERT_EQ(sfile_open(dfd, "..", SFILE_EXCL, err, sizeof(err)), -1);
    ASSERT_EQ(errno, EINVAL);
    errno = 0;
    ASSERT_EQ(sfile_open(dfd, NULL, SFILE_EXCL, err, sizeof(err)), -1);
    ASSERT_EQ(errno, EINVAL);

    /* The FILE* wrapper and the unique-name helper route through the
     * same guard. */
    ASSERT(sfile_fopen(dfd, "../escape", SFILE_APPEND, err, sizeof(err)) == NULL);
    ASSERT(!exists(g_parent, "escape"));
    char used[64];
    ASSERT(sfile_fopen_unique(dfd, "../escape", ".bin", used, sizeof(used),
                              err, sizeof(err)) == NULL);
    ASSERT(!exists(g_parent, "escape.bin"));

    /* And a bare name still works, 0600, inside the pin — so the
     * refusals above are the guard and not a broken descriptor. */
    int fd = sfile_open(dfd, "ok.bin", SFILE_EXCL, err, sizeof(err));
    ASSERT(fd >= 0);
    struct stat st;
    ASSERT_EQ(fstat(fd, &st), 0);
    ASSERT_EQ((int)(st.st_mode & 07777), 0600);
    close(fd);
    ASSERT(exists(g_child, "ok.bin"));

    close(dfd);
    rmdir(sub);
    remove_dirs();
}

/* AT_FDCWD callers are operator paths and carry slashes by nature;
 * the guard must not reach them. */
static void test_at_fdcwd_still_takes_a_path(void) {
    fresh_dirs();
    char err[SFILE_ERR_MAX], p[160];
    snprintf(p, sizeof(p), "%s/op.txt", g_parent);
    int fd = sfile_open(AT_FDCWD, p, SFILE_TRUNC, err, sizeof(err));
    ASSERT(fd >= 0);
    close(fd);
    ASSERT(exists(g_parent, "op.txt"));
    remove_dirs();
}

/* The caller the issue names: evidence export takes a file NAME from
 * whoever asks for the export. Today that is only the test suite; the
 * day it is a TUI prompt or the data socket, "../" must stop here. */
static void test_evidence_export_cannot_escape_its_directory(void) {
    fresh_dirs();
    eapol_set_collect_enabled(1);
    ASSERT_EQ(eapol_set_output_dir(g_child), 0);

    /* The name is refused before any ring lookup, so the IDs never
     * matter; one never-issued ID keeps the arguments valid. */
    uint64_t ids[1] = { 1 };
    char err[128] = "";
    ASSERT_EQ(evidence_export_pcap("../x", ids, 1, NULL, err, sizeof(err)), -1);
    ASSERT(!exists(g_parent, "x"));
    ASSERT(!exists(g_child, "x"));
    ASSERT(strstr(err, "bare file name") != NULL);

    /* Leave the gate shut, as test_evidence_export.c does: a later suite
     * assuming the shipped default must not inherit an open gate. */
    eapol_set_collect_enabled(0);
    remove_dirs();
}

/* ── sfile_system_dir ──────────────────────────────────────────── */

static void test_system_dir_accepts_root_owned_0755(void) {
    /* "/" is root:root 0755 on every Linux; the production target
     * (/etc/avahi/services) is the same shape and may not exist here. */
    char err[SFILE_ERR_MAX];
    int fd = sfile_system_dir("/", err, sizeof(err));
    ASSERT(fd >= 0);
    struct stat st;
    ASSERT_EQ(fstat(fd, &st), 0);
    ASSERT(S_ISDIR(st.st_mode));
    close(fd);
}

static void test_system_dir_accepts_euid_owned_0755(void) {
    fresh_dirs();
    ASSERT_EQ(chmod(g_child, 0755), 0);
    char err[SFILE_ERR_MAX];
    int fd = sfile_system_dir(g_child, err, sizeof(err));
    ASSERT(fd >= 0);
    close(fd);
    /* A private 0700 directory is a fortiori acceptable. */
    ASSERT_EQ(chmod(g_child, 0700), 0);
    fd = sfile_system_dir(g_child, err, sizeof(err));
    ASSERT(fd >= 0);
    close(fd);
    remove_dirs();
}

static void test_system_dir_refuses_group_or_other_writable(void) {
    fresh_dirs();
    char err[SFILE_ERR_MAX];

    ASSERT_EQ(chmod(g_child, 0777), 0);
    err[0] = '\0';
    ASSERT_EQ(sfile_system_dir(g_child, err, sizeof(err)), -1);
    ASSERT(strstr(err, "writable") != NULL);

    ASSERT_EQ(chmod(g_child, 0775), 0);   /* group alone is enough */
    ASSERT_EQ(sfile_system_dir(g_child, err, sizeof(err)), -1);

    ASSERT_EQ(chmod(g_child, 0757), 0);   /* other alone is enough */
    ASSERT_EQ(sfile_system_dir(g_child, err, sizeof(err)), -1);

    /* The sticky bit does not rescue a shared directory: anyone can
     * still create the name we are about to rename onto. */
    ASSERT_EQ(sfile_system_dir("/tmp", err, sizeof(err)), -1);

    ASSERT_EQ(chmod(g_child, 0700), 0);
    remove_dirs();
}

static void test_system_dir_refuses_symlink_and_non_directory(void) {
    fresh_dirs();
    char err[SFILE_ERR_MAX], link[160], file[160];

    snprintf(link, sizeof(link), "%s/x", g_parent);
    ASSERT_EQ(symlink(g_child, link), 0);
    err[0] = '\0';
    ASSERT_EQ(sfile_system_dir(link, err, sizeof(err)), -1);
    ASSERT(strstr(err, "symbolic link") != NULL);
    unlink(link);

    snprintf(file, sizeof(file), "%s/x", g_parent);
    int fd = open(file, O_WRONLY | O_CREAT | O_EXCL, 0644);
    ASSERT(fd >= 0);
    close(fd);
    ASSERT_EQ(sfile_system_dir(file, err, sizeof(err)), -1);
    unlink(file);

    ASSERT_EQ(sfile_system_dir("", err, sizeof(err)), -1);
    ASSERT_EQ(sfile_system_dir(NULL, err, sizeof(err)), -1);
    remove_dirs();
}

/* Unlike sfile_private_dir(), an absent system directory is never
 * created: it belongs to the daemon that reads it, not to sloth. */
static void test_system_dir_never_creates(void) {
    fresh_dirs();
    char err[SFILE_ERR_MAX], p[160];
    snprintf(p, sizeof(p), "%s/x", g_parent);
    ASSERT_EQ(sfile_system_dir(p, err, sizeof(err)), -1);
    ASSERT(!exists(g_parent, "x"));
    remove_dirs();
}

void run_secure_file_tests(void) {
    TEST_SUITE("secure_file: dirfd bare names, system directories (#134)");
    RUN_TEST(test_dirfd_relative_rejects_path_components);
    RUN_TEST(test_at_fdcwd_still_takes_a_path);
    RUN_TEST(test_evidence_export_cannot_escape_its_directory);
    RUN_TEST(test_system_dir_accepts_root_owned_0755);
    RUN_TEST(test_system_dir_accepts_euid_owned_0755);
    RUN_TEST(test_system_dir_refuses_group_or_other_writable);
    RUN_TEST(test_system_dir_refuses_symlink_and_non_directory);
    RUN_TEST(test_system_dir_never_creates);
}
