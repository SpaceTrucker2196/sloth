/* The Camera tab's route (web_camera.h): GET /api/camera.jpg.
 *
 * Seen red under a mutation (2026-11-15), each then restored:
 *   - test_symlink_refused: O_NOFOLLOW dropped from web_camera_get()
 *     (the link's target was served 200);
 *   - test_partial_jpeg_refused: the EOI check removed (a file cut
 *     short was served 200);
 *   - test_post_refused: the is_post guard removed (the POST was
 *     answered with the image). */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "web_camera.h"
#include "web_routes.h"
#include "wt_tmp.h"
#include "wtest.h"

static char g_out[1 << 16];

typedef struct {
    char         dir[TEST_TMP_MAX];
    char         state[TEST_TMP_MAX + 16];
    web_camera_t cam;
    web_m4_t     m4;
    web_health_t h;
} env_t;

static env_t E;
static const long long NOW = 1763000000;

/* SOI, an APP0 marker's first bytes, a little filler, EOI. Enough for
 * the route's whole-JPEG check, which is all it makes. */
static const unsigned char JPG[] = { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F',
                                     0x00, 0x01, 0x02, 0x03, 0xFF, 0xD9 };

static int env_open(int with_state_dir) {
    memset(&E, 0, sizeof(E));
    snprintf(E.dir, sizeof(E.dir), "%s/slothweb-cam-XXXXXX", test_tmpdir());
    if (!mkdtemp(E.dir)) return -1;
    snprintf(E.state, sizeof(E.state), "%s/state", E.dir);
    if (with_state_dir && mkdir(E.state, 0755) != 0) return -1;
    web_camera_init(&E.cam, E.state);
    E.m4.camera = &E.cam;
    E.h.m4 = &E.m4;
    E.h.wall_s = NOW;
    E.h.now_ms = 1000000;
    return 0;
}

static void env_close(void) { test_rm_tree(E.dir); }

static void put_bytes(const char *path, const unsigned char *b, size_t n, long long mtime) {
    FILE *f = fopen(path, "wb");
    if (!f) return;
    fwrite(b, 1, n, f);
    fclose(f);
    struct timeval tv[2] = { { (time_t)mtime, 0 }, { (time_t)mtime, 0 } };
    utimes(path, tv);
}

static void put_jpg(const unsigned char *b, size_t n, long long mtime) {
    char p[TEST_TMP_MAX + 64];
    snprintf(p, sizeof(p), "%s/latest.jpg", E.state);
    put_bytes(p, b, n, mtime);
}

static int route(const char *path, int is_head, int is_post, size_t *body_len) {
    web_req_t rq;
    memset(&rq, 0, sizeof(rq));
    snprintf(rq.path, sizeof(rq.path), "%s", path);
    snprintf(rq.host, sizeof(rq.host), "127.0.0.1:8770");
    rq.host_count = 1;
    rq.content_length = -1;
    rq.is_head = is_head;
    rq.is_post = is_post;
    snprintf(rq.peer, sizeof(rq.peer), "127.0.0.1");
    web_resp_t r;
    memset(&r, 0, sizeof(r));
    if (web_route(&rq, &E.h, 1, g_out, sizeof(g_out), &r) != 0) return -1;
    size_t n = r.out_len < sizeof(g_out) - 1 ? r.out_len : sizeof(g_out) - 1;
    if (body_len) *body_len = r.body ? r.body_len : 0;
    if (r.body && r.body_len && n + r.body_len < sizeof(g_out) - 1) {
        memcpy(g_out + n, r.body, r.body_len);
        n += r.body_len;
    }
    g_out[n] = '\0';
    if (r.body_free) free((void *)r.body);
    free(r.body_owned);
    return r.status;
}

static void test_not_attached_and_missing(void) {
    WT_ASSERT(env_open(0) == 0);
    E.m4.camera = NULL;
    WT_EQ(route("/api/camera.jpg", 0, 0, NULL), 404);
    E.m4.camera = &E.cam;
    WT_EQ(route("/api/camera.jpg", 0, 0, NULL), 404);
    WT_HAS(g_out, "no_image");
    env_close();
}

static void test_serves_jpeg(void) {
    WT_ASSERT(env_open(1) == 0);
    put_jpg(JPG, sizeof(JPG), NOW - 7);
    size_t bl = 0;
    WT_EQ(route("/api/camera.jpg", 0, 0, &bl), 200);
    WT_HAS(g_out, "Content-Type: image/jpeg\r\n");
    WT_HAS(g_out, "X-Content-Type-Options: nosniff\r\n");
    WT_HAS(g_out, "Cache-Control: no-store\r\n");
    char want[64];
    snprintf(want, sizeof(want), "X-Sloth-Captured: %lld\r\n", NOW - 7);
    WT_HAS(g_out, want);
    WT_HAS(g_out, "X-Sloth-Age: 7\r\n");
    WT_EQ((long long)bl, (long long)sizeof(JPG));
    const char *b = strstr(g_out, "\r\n\r\n");
    WT_ASSERT(b && memcmp(b + 4, JPG, sizeof(JPG)) == 0);
    /* HEAD: the same header, no body. */
    WT_EQ(route("/api/camera.jpg", 1, 0, &bl), 200);
    WT_EQ((long long)bl, 0);
    env_close();
}

static void test_partial_jpeg_refused(void) {
    WT_ASSERT(env_open(1) == 0);
    put_jpg(JPG, sizeof(JPG) - 2, NOW);
    WT_EQ(route("/api/camera.jpg", 0, 0, NULL), 503);
    WT_HAS(g_out, "invalid");
    static const unsigned char html[] = "<html><script>x</script></html>";
    put_jpg(html, sizeof(html) - 1, NOW);
    WT_EQ(route("/api/camera.jpg", 0, 0, NULL), 503);
    WT_ASSERT(!strstr(g_out, "<script>"));
    env_close();
}

static void test_symlink_refused(void) {
    WT_ASSERT(env_open(1) == 0);
    char tgt[TEST_TMP_MAX + 64], lnk[TEST_TMP_MAX + 64];
    snprintf(tgt, sizeof(tgt), "%s/elsewhere.jpg", E.dir);
    snprintf(lnk, sizeof(lnk), "%s/latest.jpg", E.state);
    put_bytes(tgt, JPG, sizeof(JPG), NOW);
    WT_ASSERT(symlink(tgt, lnk) == 0);
    WT_EQ(route("/api/camera.jpg", 0, 0, NULL), 503);
    env_close();
}

static void test_directory_and_oversize_refused(void) {
    WT_ASSERT(env_open(1) == 0);
    char p[TEST_TMP_MAX + 64];
    snprintf(p, sizeof(p), "%s/latest.jpg", E.state);
    WT_ASSERT(mkdir(p, 0755) == 0);
    WT_EQ(route("/api/camera.jpg", 0, 0, NULL), 503);
    WT_ASSERT(rmdir(p) == 0);
    /* One byte over the cap: a sparse file, so nothing is written. */
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    WT_ASSERT(fd >= 0);
    WT_ASSERT(ftruncate(fd, WEB_CAMERA_MAX_BYTES + 1) == 0);
    close(fd);
    WT_EQ(route("/api/camera.jpg", 0, 0, NULL), 503);
    env_close();
}

static void test_post_refused(void) {
    WT_ASSERT(env_open(1) == 0);
    put_jpg(JPG, sizeof(JPG), NOW);
    size_t bl = 0;
    WT_EQ(route("/api/camera.jpg", 0, 1, &bl), 405);
    WT_HAS(g_out, "Allow: GET, HEAD\r\n");
    WT_ASSERT(!strstr(g_out, "image/jpeg"));
    env_close();
}

void run_camera_tests(void) {
    WT_RUN(test_not_attached_and_missing);
    WT_RUN(test_serves_jpeg);
    WT_RUN(test_partial_jpeg_refused);
    WT_RUN(test_symlink_refused);
    WT_RUN(test_directory_and_oversize_refused);
    WT_RUN(test_post_refused);
}
