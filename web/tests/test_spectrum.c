/* The Spectrum tab's routes (web_spectrum.h): GET /api/spectrum and
 * POST /api/spectrum/run, against a state directory written here by
 * hand in sloth-sdrsweep's format (docs/wiki/sdr-sweep.md "Output").
 *
 * Absence assertions, each seen red under the named mutation and then
 * restored (docs/wiki/log.md, the 2026-11-13 sdr-sweep entry):
 *   - test_get_never_writes: web_spectrum_get() given an
 *     open(sp->request, O_CREAT) (the request file appeared);
 *   - test_post_refusals_create_nothing: the decide() call skipped in
 *     web_spectrum_run() (409 and 429 became 202 and the file was
 *     made), and separately the gate's `agent && spectrum` line removed
 *     (a correctly presented agent secret passed the gate);
 *   - test_hostile_document_is_escaped: web_jw_strn() in jc_value()
 *     replaced by a raw copy (a "<script>" reached the answer);
 *   - test_oversize_and_links_refused: O_NOFOLLOW dropped from slurp()
 *     (the linked file's bytes were served);
 *   - test_acl_and_read_only_over_a_socket: the peer allow list emptied
 *     still admitted (web_acl_permits() made to return 1) - the request
 *     file was created by a peer the list refuses.
 *
 * The ranges (GET /api/spectrum?range=, history/), the same way (the
 * 2026-11-15 spectrum-ranges entry in docs/wiki/log.md):
 *   - test_range_skips_bad_records: hist_parse()'s `if (bit & h->seen)
 *     goto out;` dropped (the record with "started" twice was served,
 *     its -71.5 floor in the answer); the grid comparison in
 *     hist_window() made `else if (0)` (the 600 kHz-span record's -72.5
 *     served); O_NOFOLLOW dropped from slurp_at() (the linked record's
 *     -77.5 served); the base64 decode's result ignored (-73.5 and
 *     -75.5 served);
 *   - test_range_window: the record's own `started` check dropped (the
 *     record named inside the hour but started two hours ago, -81.5,
 *     served) and, separately, the name's window filter dropped (the
 *     record named outside the hour, -82.5, served);
 *   - test_run_floor: the WEB_SPECTRUM_MIN_GAP_S fold in read_state()
 *     made `if (0)` (a press 60 s after a run with cooldown 0 was 202).
 *   - test_range_never_writes: hist_window() given an
 *     open(sp->request, O_CREAT) (the request file appeared). */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "web_frrs.h"
#include "web_routes.h"
#include "web_server.h"
#include "web_spectrum.h"
#include "wt_tmp.h"
#include "web_assets.h"
#include "wtest.h"

static char g_out[1 << 20];

typedef struct {
    char           dir[TEST_TMP_MAX];
    char           state[TEST_TMP_MAX + 16];
    char           req[TEST_TMP_MAX + 16];
    web_spectrum_t sp;
    web_m4_t       m4;
    web_health_t   h;
} env_t;

static env_t E;
static const long long NOW = 1763000000;

static int env_open(int with_state_dir) {
    memset(&E, 0, sizeof(E));
    snprintf(E.dir, sizeof(E.dir), "%s/slothweb-spec-XXXXXX", test_tmpdir());
    if (!mkdtemp(E.dir)) return -1;
    snprintf(E.state, sizeof(E.state), "%s/state", E.dir);
    snprintf(E.req, sizeof(E.req), "%s/req", E.dir);
    if (with_state_dir && mkdir(E.state, 0755) != 0) return -1;
    web_spectrum_init(&E.sp, E.state, E.req);
    E.m4.spectrum = &E.sp;
    E.h.m4 = &E.m4;
    E.h.wall_s = NOW;
    E.h.now_ms = 1000000;
    return 0;
}

static void env_close(void) { test_rm_tree(E.dir); }

static void put_file(const char *name, const char *text) {
    char p[TEST_TMP_MAX + 64];
    snprintf(p, sizeof(p), "%s/%s", E.state, name);
    FILE *f = fopen(p, "w");
    if (!f) return;
    fputs(text, f);
    fclose(f);
}

static void put_status(const char *state, long long updated, long long next_allowed) {
    char b[512];
    snprintf(b, sizeof(b),
             "{\"version\":1,\"state\":\"%s\",\"mode\":\"sweep\",\"pid\":42,"
             "\"started\":%lld.250,\"updated\":%lld.5%s%lld%s,\"cooldown\":600,"
             "\"row\":2,\"step\":117,\"steps\":334,\"antenna\":\"Antenna A\"}\n",
             state, updated - 20, updated,
             next_allowed ? ",\"ended\":1,\"next_allowed\":" : ",\"x\":",
             next_allowed ? next_allowed : 0, "");
    put_file("status.json", b);
}

static int exists(const char *p) {
    struct stat st;
    return lstat(p, &st) == 0;
}

static int entries(const char *dir) {
    int n = 0;
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *e;
    while ((e = readdir(d))) if (e->d_name[0] != '.') n++;
    closedir(d);
    return n;
}

static void base_rq(web_req_t *rq, const char *path, const char *query) {
    memset(rq, 0, sizeof(*rq));
    snprintf(rq->path, sizeof(rq->path), "%s", path);
    snprintf(rq->query, sizeof(rq->query), "%s", query ? query : "");
    snprintf(rq->host, sizeof(rq->host), "127.0.0.1:8770");
    rq->host_count = 1;
    rq->content_length = -1;
    snprintf(rq->peer, sizeof(rq->peer), "127.0.0.1");
}

static int route(web_req_t *rq) {
    web_resp_t r;
    memset(&r, 0, sizeof(r));
    if (web_route(rq, &E.h, 1, g_out, sizeof(g_out), &r) != 0) return -1;
    size_t n = r.out_len < sizeof(g_out) - 1 ? r.out_len : sizeof(g_out) - 1;
    if (r.body && r.body_len && n + r.body_len < sizeof(g_out) - 1) {
        memcpy(g_out + n, r.body, r.body_len);
        n += r.body_len;
    }
    g_out[n] = '\0';
    if (r.body_free) free((void *)r.body);
    free(r.body_owned);
    return r.status;
}

static int get(const char *path, const char *query) {
    web_req_t rq;
    base_rq(&rq, path, query);
    return route(&rq);
}

static int head(const char *path) {
    web_req_t rq;
    base_rq(&rq, path, "");
    rq.is_head = 1;
    return route(&rq);
}

/* As the page sends it: Origin equal to Host, JSON, a "{}" body. */
static int post_with(const char *path, int origin, const char *ctype, int agent) {
    web_req_t rq;
    base_rq(&rq, path, "");
    rq.is_post = 1;
    if (origin) {
        snprintf(rq.origin, sizeof(rq.origin), "http://127.0.0.1:8770");
        rq.origin_count = 1;
    }
    if (agent) {
        snprintf(rq.agent, sizeof(rq.agent), "%064d", 0);
        rq.agent_count = 1;
    }
    snprintf(rq.ctype, sizeof(rq.ctype), "%s", ctype);
    rq.ctype_count = 1;
    rq.body = "{}";
    rq.body_len = 2;
    rq.content_length = 2;
    return route(&rq);
}

static int post(void) { return post_with("/api/spectrum/run", 1, "application/json", 0); }

/* ── the read path ── */

static void test_not_attached_and_not_installed(void) {
    WT_EQ(env_open(0), 0);
    /* No spectrum attached: the route does not exist. */
    E.m4.spectrum = NULL;
    WT_EQ(get("/api/spectrum", ""), 404);
    WT_EQ(post(), 404);
    E.m4.spectrum = &E.sp;
    /* Attached, no state directory: not installed, nothing to run. */
    WT_EQ(get("/api/spectrum", ""), 200);
    WT_HAS(g_out, "\"installed\":false");
    WT_HAS(g_out, "\"sweep\":null");
    WT_HAS(g_out, "\"can_run\":false");
    WT_HAS(g_out, "\"why_not\":\"not_installed\"");
    WT_EQ(post(), 503);
    WT_HAS(g_out, "{\"error\":\"not_installed\"}");
    WT_ASSERT(!exists(E.req));
    env_close();
}

static void test_idle_and_query(void) {
    WT_EQ(env_open(1), 0);
    WT_EQ(get("/api/spectrum", ""), 200);
    WT_HAS(g_out, "Content-Type: application/json\r\n");
    WT_HAS(g_out, "Cache-Control: no-store\r\n");
    WT_HAS(g_out, "\"installed\":true");
    WT_HAS(g_out, "\"state\":\"idle\"");
    WT_HAS(g_out, "\"can_run\":true");
    WT_HAS(g_out, "\"sweep\":null");
    WT_LACKS(g_out, "sweep_error");      /* absent is not an error */
    WT_EQ(get("/api/spectrum", "status=1"), 200);
    WT_LACKS(g_out, "\"sweep\"");
    WT_EQ(get("/api/spectrum", "status=2"), 400);
    WT_HAS(g_out, "unknown_parameter");
    WT_EQ(get("/api/spectrum", "f=1"), 400);
    WT_EQ(head("/api/spectrum"), 200);
    WT_LACKS(g_out, "\"installed\"");
    /* Under the Local scope the status answers, the sweep does not. */
    put_file("latest.json", "{\"version\":1,\"rows\":[]}\n");
    WT_EQ(get("/api/spectrum", "scope=local"), 200);
    WT_HAS(g_out, "\"out_of_scope\":true,\"sweep\":null");
    WT_LACKS(g_out, "\"version\"");
    WT_EQ(get("/api/spectrum", "scope=monitor"), 200);
    WT_HAS(g_out, "\"sweep\":{\"version\":1,\"rows\":[]}");
    env_close();
}

static void test_status_states(void) {
    WT_EQ(env_open(1), 0);
    put_status("running", NOW - 2, 0);
    WT_EQ(get("/api/spectrum", "status=1"), 200);
    WT_HAS(g_out, "\"state\":\"running\",\"running\":true");
    WT_HAS(g_out, "\"why_not\":\"running\"");
    WT_HAS(g_out, "\"antenna\":\"Antenna A\"");
    WT_HAS(g_out, "\"step\":117,\"steps\":334");
    WT_EQ(post(), 409);
    WT_HAS(g_out, "{\"error\":\"running\"}");
    WT_ASSERT(!exists(E.req));
    /* Not updated for longer than WEB_SPECTRUM_STALE_S: the helper is
     * gone, and a run may be asked for. */
    put_status("running", NOW - WEB_SPECTRUM_STALE_S - 5, 0);
    WT_EQ(get("/api/spectrum", "status=1"), 200);
    WT_HAS(g_out, "\"state\":\"stale\",\"running\":false");
    WT_EQ(post(), 202);
    WT_ASSERT(exists(E.req));
    env_close();
}

static void test_cooldown_429(void) {
    WT_EQ(env_open(1), 0);
    put_status("done", NOW - 30, NOW + 300);
    WT_EQ(get("/api/spectrum", "status=1"), 200);
    WT_HAS(g_out, "\"can_run\":false,\"why_not\":\"cooldown\",\"retry_after\":300");
    WT_HAS(g_out, "\"next_allowed\":1763000300");
    WT_EQ(post(), 429);
    WT_HAS(g_out, "Retry-After: 300\r\n");
    WT_HAS(g_out, "{\"error\":\"cooldown\",\"retry_after\":300}");
    WT_ASSERT(!exists(E.req));
    put_status("done", NOW - 700, NOW - 1);
    WT_EQ(post(), 202);
    WT_HAS(g_out, "HTTP/1.1 202 Accepted\r\n");
    WT_HAS(g_out, "{\"queued\":true,\"requested\":1763000000}");
    env_close();
}

static void test_queue_once(void) {
    WT_EQ(env_open(1), 0);
    WT_EQ(post(), 202);
    struct stat st;
    WT_EQ(lstat(E.req, &st), 0);
    WT_ASSERT(S_ISREG(st.st_mode) && st.st_size == 0);   /* carries nothing */
    WT_EQ(post(), 409);
    WT_HAS(g_out, "{\"error\":\"queued\"}");
    WT_EQ(get("/api/spectrum", "status=1"), 200);
    WT_HAS(g_out, "\"queued\":true,\"queued_since\":");
    WT_HAS(g_out, "\"why_not\":\"queued\"");
    /* A request directory that is not there (slothweb run by hand, no
     * /run/slothweb): 503, never a crash. */
    unlink(E.req);
    snprintf(E.sp.request, sizeof(E.sp.request), "%s/no/such/req", E.dir);
    WT_EQ(post(), 503);
    WT_HAS(g_out, "request_failed");
    env_close();
}

/* GET is read only: any number of reads, of either shape, in any state,
 * leave the directory and the request path as they were. */
static void test_get_never_writes(void) {
    WT_EQ(env_open(1), 0);
    put_status("done", NOW - 30, NOW + 300);
    put_file("latest.json", "{\"version\":1}\n");
    int before = entries(E.state);
    for (int i = 0; i < 3; i++) {
        WT_EQ(get("/api/spectrum", ""), 200);
        WT_EQ(get("/api/spectrum", "status=1"), 200);
        WT_EQ(head("/api/spectrum"), 200);
    }
    WT_ASSERT(!exists(E.req));
    WT_EQ(entries(E.state), before);
    WT_EQ(entries(E.dir), 1);
    env_close();
}

/* ── the write path's guards ── */

static void test_method_guards(void) {
    WT_EQ(env_open(1), 0);
    WT_EQ(get("/api/spectrum/run", ""), 405);
    WT_HAS(g_out, "Allow: POST\r\n");
    WT_EQ(head("/api/spectrum/run"), 405);
    WT_EQ(post_with("/api/spectrum", 1, "application/json", 0), 405);
    WT_HAS(g_out, "Allow: GET, HEAD\r\n");
    WT_ASSERT(!exists(E.req));
    /* The parser's half: a POST anywhere but a write path is not routed. */
    WT_ASSERT(web_http_post_path("/api/spectrum/run"));
    WT_ASSERT(!web_http_post_path("/api/spectrum"));
    env_close();
}

static void test_post_refusals_create_nothing(void) {
    WT_EQ(env_open(1), 0);
    WT_EQ(post_with("/api/spectrum/run", 0, "application/json", 0), 403);
    WT_HAS(g_out, "bad_origin");
    WT_EQ(post_with("/api/spectrum/run", 1, "text/plain", 0), 415);
    WT_HAS(g_out, "bad_content_type");
    /* An agent header: refused whatever the secret, and the radio is
     * never an agent's (no store here, so no secret either). */
    WT_EQ(post_with("/api/spectrum/run", 0, "application/json", 1), 403);
    WT_ASSERT(!exists(E.req));
    web_req_t rq;
    base_rq(&rq, "/api/spectrum/run", "");
    rq.agent_count = 1;
    snprintf(rq.agent, sizeof(rq.agent), "%064d", 0);
    const char *why = NULL;
    char extra[64];
    WT_EQ(web_frrs_gate(NULL, &rq, 0, &why, extra, sizeof(extra)), 403);
    /* With an agent secret configured and presented correctly, the
     * agent is still refused here: the radio is the operator's. */
    static web_frrs_t fa;
    memset(&fa, 0, sizeof(fa));
    snprintf(fa.agent_secret, sizeof(fa.agent_secret), "%064d", 0);
    base_rq(&rq, "/api/spectrum/run", "");
    snprintf(rq.peer, sizeof(rq.peer), "127.0.0.1");
    rq.agent_count = 1;
    snprintf(rq.agent, sizeof(rq.agent), "%064d", 0);
    snprintf(rq.ctype, sizeof(rq.ctype), "application/json");
    rq.ctype_count = 1;
    why = NULL;
    WT_EQ(web_frrs_gate(&fa, &rq, 0, &why, extra, sizeof(extra)), 403);
    WT_ASSERT(why && !strcmp(why, "agent_path"));
    /* Another write path still needs the store the gate is about. */
    base_rq(&rq, "/api/frrs/triage", "");
    WT_EQ(web_frrs_gate(NULL, &rq, 0, &why, extra, sizeof(extra)), 503);
    WT_ASSERT(why && !strcmp(why, "no_store"));
    /* Running and in cooldown: refused, nothing made. */
    put_status("running", NOW, 0);
    WT_EQ(post(), 409);
    put_status("done", NOW - 10, NOW + 590);
    WT_EQ(post(), 429);
    WT_ASSERT(!exists(E.req));
    env_close();
}

/* ── the document ── */

static void test_valid_document_round_trip(void) {
    WT_EQ(env_open(1), 0);
    put_file("latest.json",
             "{\"version\":1,\"mode\":\"sweep\",\"complete\":true,\"started\":1763000000.250,"
             "\"f_lo\":500000,\"bins\":3,\"quant\":{\"offset_db\":-130.0,\"step_db\":0.5},\n"
             "\"rows\":[\n{\"t\":1763000001.5,\"floor\":-98.5,\"data\":\"AAEC\"},\n"
             "{\"t\":1763000020,\"floor\":null,\"data\":\"/w+=\"}],\n"
             "\"peaks\":[\n{\"freq_hz\":144390000,\"width_hz\":12000,\"snr_avg\":9.5,"
             "\"snr_peak\":31.0,\"dbfs\":-61.5,\"rows\":3,\"note\":\"\"},\n"
             "{\"freq_hz\":1176000000,\"width_hz\":2000,\"snr_avg\":30.1,\"snr_peak\":31.2,"
             "\"dbfs\":-60.0,\"rows\":4,\"note\":\"clock harmonic?\"}]}\n");
    WT_EQ(get("/api/spectrum", ""), 200);
    WT_HAS(g_out, ",\"sweep\":{\"version\":1,\"mode\":\"sweep\",\"complete\":true,"
                  "\"started\":1763000000.250,\"f_lo\":500000,\"bins\":3,"
                  "\"quant\":{\"offset_db\":-130.0,\"step_db\":0.5},\"rows\":[{\"t\":1763000001.5,"
                  "\"floor\":-98.5,\"data\":\"AAEC\"},{\"t\":1763000020,\"floor\":null,"
                  "\"data\":\"/w+=\"}],\"peaks\":[{\"freq_hz\":144390000");
    WT_HAS(g_out, "\"note\":\"clock harmonic?\"}]}}\n");
    WT_LACKS(g_out, "sweep_error");
    env_close();
}

static void test_hostile_document_is_escaped(void) {
    WT_EQ(env_open(1), 0);
    put_file("latest.json", "{\"antenna\":\"<script>alert(1)</script>\",\"s\":\"a\\u0026b\\ud83d\\ude00\"}");
    WT_EQ(get("/api/spectrum", ""), 200);
    WT_LACKS(g_out, "<script>");
    WT_HAS(g_out, "\"antenna\":\"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e\"");
    WT_HAS(g_out, "\"s\":\"a\\u0026b\xf0\x9f\x98\x80\"");
    /* Each of these is refused whole: the sweep is null and says why. */
    static const char *const bad[] = {
        "{\"a\":1} x",                     /* trailing bytes */
        "{\"a\":\"\x01\"}",                /* a raw control byte */
        "{\"a\":\"\\ud800\"}",             /* a lone surrogate */
        "{\"a\":\"\\q\"}",                 /* an unknown escape */
        "{\"a\":01}",                      /* a leading zero */
        "{\"a\":1.}",                      /* a bare point */
        "{\"a\":NaN}",
        "{\"a\":[1,]}",
        "{a:1}",
        "{\"a\":1",                        /* truncated */
        "[[[[[[[[[1]]]]]]]]]",             /* nine deep, over WEB_SPECTRUM_DEPTH */
        "",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        put_file("latest.json", bad[i]);
        WT_EQ(get("/api/spectrum", ""), 200);
        WT_HAS(g_out, "\"sweep\":null,\"sweep_error\":\"invalid\"}");
    }
    put_file("latest.json", "[[[[[[[[1]]]]]]]]");   /* eight: allowed */
    WT_EQ(get("/api/spectrum", ""), 200);
    WT_HAS(g_out, "\"sweep\":[[[[[[[[1]]]]]]]]}");
    env_close();
}

static void test_oversize_and_links_refused(void) {
    WT_EQ(env_open(1), 0);
    char p[TEST_TMP_MAX + 64];
    snprintf(p, sizeof(p), "%s/latest.json", E.state);
    FILE *f = fopen(p, "w");
    WT_ASSERT(f != NULL);
    if (f) {
        fputs("{\"a\":\"", f);
        for (long i = 0; i < WEB_SPECTRUM_MAX_BYTES; i++) fputc('A', f);
        fputs("\"}", f);
        fclose(f);
    }
    WT_EQ(get("/api/spectrum", ""), 200);
    WT_HAS(g_out, "\"sweep\":null,\"sweep_error\":\"too_large\"}");
    WT_LACKS(g_out, "AAAAAAAA");
    /* A link is not followed: the directory is another account's. */
    unlink(p);
    char target[TEST_TMP_MAX + 64];
    snprintf(target, sizeof(target), "%s/elsewhere.json", E.dir);
    f = fopen(target, "w");
    if (f) { fputs("{\"secret\":1}", f); fclose(f); }
    WT_EQ(symlink(target, p), 0);
    WT_EQ(get("/api/spectrum", ""), 200);
    WT_LACKS(g_out, "secret");
    WT_HAS(g_out, "\"sweep_error\":\"unreadable\"");
    /* A directory where the file should be. */
    unlink(p);
    WT_EQ(mkdir(p, 0755), 0);
    WT_EQ(get("/api/spectrum", ""), 200);
    WT_HAS(g_out, "\"sweep_error\":\"unreadable\"");
    rmdir(p);
    /* A status that is not one object is no status. */
    put_file("status.json", "[1,2]");
    WT_EQ(get("/api/spectrum", "status=1"), 200);
    WT_HAS(g_out, "\"state\":\"idle\"");
    env_close();
}

static void test_copy_json_direct(void) {
    char buf[256];
    web_jw_t w;
    web_jw_init(&w, buf, sizeof(buf));
    WT_EQ(web_spectrum_copy_json(&w, " { \"a\" : [ 1 , -2.5e+3 , true , false , null ] } \n", 49), 0);
    WT_ASSERT(!strcmp(buf, "{\"a\":[1,-2.5e+3,true,false,null]}"));
    /* Too small an output is a refusal, not a cut answer. */
    char tiny[8];
    web_jw_init(&w, tiny, sizeof(tiny));
    WT_EQ(web_spectrum_copy_json(&w, "{\"abcdefgh\":1}", 14), -1);
}

/* ── over a socket: the allow list and --web-read-only ── */

typedef struct { web_server_t *s; pthread_t th; } running_t;

static void *server_main(void *arg) {
    running_t *r = arg;
    web_server_run(r->s);
    return NULL;
}

static int srv_start(running_t *r, int read_only, int empty_acl) {
    web_config_t c;
    web_config_defaults(&c);
    c.bind_port = 0;
    c.timeout_ms = 2000;
    c.linger_ms = 200;
    c.read_only = read_only;
    if (empty_acl) c.acl.n = 0;
    char err[256];
    r->s = calloc(1, sizeof(*r->s));
    if (!r->s || web_server_open(r->s, &c, err, sizeof(err)) != 0) {
        if (r->s) web_server_close(r->s);
        free(r->s);
        r->s = NULL;
        return -1;
    }
    web_server_set_m4(r->s, &E.m4);
    if (pthread_create(&r->th, NULL, server_main, r) != 0) return -1;
    return 0;
}

static void srv_stop(running_t *r) {
    web_server_stop(r->s);
    pthread_join(r->th, NULL);
    web_server_close(r->s);
    free(r->s);
    r->s = NULL;
}

static void exchange(uint16_t port, const char *req) {
    g_out[0] = '\0';
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;
    struct timeval tv = { 4, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
        send(fd, req, strlen(req), MSG_NOSIGNAL);
        size_t n = 0;
        while (n + 1 < sizeof(g_out)) {
            ssize_t r = recv(fd, g_out + n, sizeof(g_out) - 1 - n, 0);
            if (r <= 0) break;
            n += (size_t)r;
        }
        g_out[n] = '\0';
    }
    close(fd);
}

static void post_over(uint16_t port) {
    char req[512];
    snprintf(req, sizeof(req),
             "POST /api/spectrum/run HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
             "Origin: http://127.0.0.1:%u\r\nContent-Type: application/json\r\n"
             "Content-Length: 2\r\n\r\n{}", port, port);
    exchange(port, req);
}

static void test_acl_and_read_only_over_a_socket(void) {
    WT_EQ(env_open(1), 0);
    running_t r;
    /* A peer the allow list refuses is closed at accept(): no answer,
     * no request. */
    WT_EQ(srv_start(&r, 0, 1), 0);
    if (r.s) {
        uint16_t port = web_server_port(r.s);
        post_over(port);
        WT_LACKS(g_out, "HTTP/1.1 202");
        WT_ASSERT(!exists(E.req));
        srv_stop(&r);
    }
    /* --web-read-only: every POST is 405, this one too. */
    WT_EQ(srv_start(&r, 1, 0), 0);
    if (r.s) {
        uint16_t port = web_server_port(r.s);
        post_over(port);
        WT_HAS(g_out, "HTTP/1.1 405");
        WT_ASSERT(!exists(E.req));
        srv_stop(&r);
    }
    /* The page's POST, gated by the server with no store attached: 202,
     * then the GET shows it queued. */
    WT_EQ(srv_start(&r, 0, 0), 0);
    if (r.s) {
        uint16_t port = web_server_port(r.s);
        post_over(port);
        WT_HAS(g_out, "HTTP/1.1 202 Accepted\r\n");
        WT_ASSERT(exists(E.req));
        char req[256];
        snprintf(req, sizeof(req), "GET /api/spectrum?status=1 HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n\r\n",
                 port);
        exchange(port, req);
        WT_HAS(g_out, "\"queued\":true");
        /* No Origin: refused before the body, nothing more queued. */
        unlink(E.req);
        snprintf(req, sizeof(req),
                 "POST /api/spectrum/run HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
                 "Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}", port);
        exchange(port, req);
        WT_HAS(g_out, "HTTP/1.1 403");
        WT_ASSERT(!exists(E.req));
        srv_stop(&r);
    }
    env_close();
}

/* ── the ranges (history/) ── */

/* RFC 4648 base64, written here for the test's records (not the code
 * under test's encoder). */
static void b64(const uint8_t *in, size_t n, char *out) {
    static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        unsigned x = (unsigned)in[i] << 16 | (i + 1 < n ? (unsigned)in[i + 1] << 8 : 0) |
                     (i + 2 < n ? in[i + 2] : 0);
        out[o++] = A[x >> 18 & 63];
        out[o++] = A[x >> 12 & 63];
        out[o++] = i + 1 < n ? A[x >> 6 & 63] : '=';
        out[o++] = i + 2 < n ? A[x & 63] : '=';
    }
    out[o] = '\0';
}

static void hist_dir(void) {
    char p[TEST_TMP_MAX + 64];
    snprintf(p, sizeof(p), "%s/history", E.state);
    mkdir(p, 0755);
}

/* A record as the helper writes one (sdrs_write_hist()), named by its
 * start unless name is given; q is bins bytes; extra is spliced before
 * "peaks" so a test can add a member. */
static void put_hist_full(const char *name, double started, const char *flr, int bins,
                          double f_lo, const uint8_t *q, const char *extra, const char *peaks) {
    char *data = malloc(4 * ((size_t)bins / 3 + 1) + 1);
    size_t cap = (size_t)bins * 2 + 4096;
    char *doc = malloc(cap);
    if (!data || !doc) { free(data); free(doc); return; }
    b64(q, (size_t)bins, data);
    snprintf(doc, cap,
             "{\"version\":1,\"kind\":\"history\",\"mode\":\"sweep\",\"complete\":true,"
             "\"started\":%.3f,\"ended\":%.3f,\"t_first\":%.3f,\"t_last\":%.3f,"
             "\"antenna\":\"Antenna A\",\"rows\":3,\"floor\":%s,\"f_lo\":%.0f,"
             "\"f_hi\":%.0f,\"bin_hz\":100000,\"bins\":%d,"
             "\"quant\":{\"offset_db\":-130.0,\"step_db\":0.5},\n\"data\":\"%s\",\n%s"
             "\"peaks\":[%s]}\n",
             started, started + 50, started + 0.3, started + 32, flr, f_lo,
             f_lo + bins * 100000.0, bins, data, extra ? extra : "",
             peaks ? peaks : "\n{\"freq_hz\":144390000,\"width_hz\":12000,\"snr_avg\":9.5,"
                             "\"snr_peak\":31.0,\"dbfs\":-61.5,\"rows\":3,\"note\":\"\"}");
    char fn[64];
    if (name) snprintf(fn, sizeof(fn), "history/%s", name);
    else snprintf(fn, sizeof(fn), "history/%lld.json", (long long)started);
    put_file(fn, doc);
    free(data);
    free(doc);
}

static void put_hist(double started, const char *flr) {
    static const uint8_t q[6] = { 0, 10, 200, 3, 0, 220 };
    put_hist_full(NULL, started, flr, 6, 500000, q, NULL, NULL);
}

static void test_range_parse(void) {
    long long s = -1;
    WT_EQ(web_spectrum_range("last3", &s), 0); WT_EQ(s, 0);
    WT_EQ(web_spectrum_range("1h", &s), 0);    WT_EQ(s, 3600);
    WT_EQ(web_spectrum_range("5h", &s), 0);    WT_EQ(s, 18000);
    WT_EQ(web_spectrum_range("12h", &s), 0);   WT_EQ(s, 43200);
    WT_EQ(web_spectrum_range("24h", &s), 0);   WT_EQ(s, 86400);
    WT_EQ(web_spectrum_range("2h", &s), -1);
    WT_EQ(web_spectrum_range("", &s), -1);
    WT_EQ(web_spectrum_range("1H", &s), -1);
    WT_EQ(web_spectrum_range(NULL, &s), -1);
    WT_EQ(env_open(1), 0);
    WT_EQ(get("/api/spectrum", "range=2h"), 400);
    WT_HAS(g_out, "{\"error\":\"unknown_range\"}");
    WT_EQ(get("/api/spectrum", "range="), 400);
    WT_EQ(get("/api/spectrum", "range=1h&status=1"), 400);
    WT_EQ(get("/api/spectrum", "range=1h%00"), 400);
    /* No history directory yet: no rows, not an error. */
    WT_EQ(get("/api/spectrum", "range=1h"), 200);
    WT_HAS(g_out, "\"range\":\"1h\",\"runs\":0,\"skipped\":0,\"sweep\":null}\n");
    /* The status still leads, so the tab's poll reads either answer. */
    WT_HAS(g_out, "{\"installed\":true,");
    /* Local scope: the status alone, as without a range. */
    WT_EQ(get("/api/spectrum", "scope=local&range=1h"), 200);
    WT_HAS(g_out, "\"out_of_scope\":true,\"sweep\":null}");
    WT_LACKS(g_out, "\"range\"");
    env_close();
    WT_EQ(env_open(0), 0);
    WT_EQ(get("/api/spectrum", "range=24h"), 200);
    WT_HAS(g_out, "\"installed\":false");
    WT_HAS(g_out, "\"runs\":0,\"skipped\":0,\"sweep\":null}");
    env_close();
    /* The pooling factor: rows x bins over 1.5 M cells, rounded up. The
     * helper's 19,995 bins: 1 h (12 runs) and 5 h (60) unpooled, 12 h
     * (144) in pairs, 24 h (288) in fours, 400 runs in sixes. */
    WT_EQ(web_spectrum_pool(3, 19995), 1);
    WT_EQ(web_spectrum_pool(12, 19995), 1);
    WT_EQ(web_spectrum_pool(60, 19995), 1);
    WT_EQ(web_spectrum_pool(144, 19995), 2);
    WT_EQ(web_spectrum_pool(288, 19995), 4);
    WT_EQ(web_spectrum_pool(400, 19995), 6);
    WT_EQ(web_spectrum_pool(0, 19995), 1);
    WT_EQ(web_spectrum_pool(1, 0), 1);
    WT_EQ(web_spectrum_pool(1000000, 10), 7);
    WT_EQ(web_spectrum_pool(1000000000, 10), 10);   /* never past one bin */
}

/* Which runs each range answers with, oldest first, and that a record's
 * own "started" and its name must both be in the window. */
static void test_range_window(void) {
    WT_EQ(env_open(1), 0);
    hist_dir();
    put_hist(NOW - 100, "-90.5");
    put_hist(NOW - 3000, "-91.5");
    put_hist(NOW - 4000, "-92.5");
    put_hist(NOW - 17000, "-93.5");
    put_hist(NOW - 40000, "-94.5");
    put_hist(NOW - 80000, "-95.5");
    put_hist(NOW - 90000, "-96.5");          /* older than 24 h */
    /* Named inside the hour but started outside it, and the reverse. */
    static const uint8_t q[6] = { 1, 2, 3, 4, 5, 6 };
    char nm[32];
    snprintf(nm, sizeof(nm), "%lld.json", NOW - 50);
    put_hist_full(nm, NOW - 7200, "-81.5", 6, 500000, q, NULL, NULL);
    snprintf(nm, sizeof(nm), "%lld.json", NOW - 7300);
    put_hist_full(nm, NOW - 60, "-82.5", 6, 500000, q, NULL, NULL);
    WT_EQ(get("/api/spectrum", "range=1h"), 200);
    WT_HAS(g_out, "\"range\":\"1h\",\"runs\":2,\"skipped\":1,\"sweep\":{\"version\":1,"
                  "\"mode\":\"history\",\"range\":\"1h\",\"from\":1762996400,\"to\":1763000000,"
                  "\"runs\":2,\"skipped\":1,\"pool\":1,\"f_lo\":500000,\"f_hi\":1100000,"
                  "\"bin_hz\":100000,\"bins\":6,\"quant\":{\"offset_db\":-130.0,\"step_db\":0.50},"
                  "\"antenna\":\"Antenna A\",\"started\":1762997000.000,\"ended\":1762999950.000,"
                  "\"rows\":[\n{\"t\":1762997000.000,\"ended\":1762997050.000,\"floor\":-91.5,"
                  "\"rows\":3,\"complete\":true,\"data\":\"AArIAwDc\"},\n{\"t\":1762999900.000,");
    WT_HAS(g_out, "\"floor\":-90.5,");
    WT_HAS(g_out, "],\"peaks\":[{\"freq_hz\":144390000,\"width_hz\":12000,\"snr_avg\":9.5,"
                  "\"snr_peak\":31.0,\"dbfs\":-61.5,\"rows\":3,\"note\":\"\"}]}}\n");
    WT_LACKS(g_out, "-81.5");               /* named in, started out */
    WT_LACKS(g_out, "-82.5");               /* started in, named out */
    /* 5 h: both odd records are inside it by name and by start. */
    WT_EQ(get("/api/spectrum", "range=5h"), 200);
    WT_HAS(g_out, "\"runs\":6,");
    WT_HAS(g_out, "-93.5");
    WT_LACKS(g_out, "-94.5");
    WT_EQ(get("/api/spectrum", "range=12h"), 200);
    WT_HAS(g_out, "\"runs\":7,");
    WT_EQ(get("/api/spectrum", "range=24h"), 200);
    WT_HAS(g_out, "\"runs\":8,");
    WT_LACKS(g_out, "-96.5");
    /* last3: the three newest by name, whatever their age. */
    WT_EQ(get("/api/spectrum", "range=last3"), 200);
    WT_HAS(g_out, "\"runs\":3,");
    WT_HAS(g_out, "\"from\":1762997000,");
    WT_HAS(g_out, "-81.5");
    WT_HAS(g_out, "-90.5");
    WT_HAS(g_out, "-91.5");
    WT_LACKS(g_out, "-92.5");
    /* The no-range answer is what it was: latest.json, no "range". */
    WT_EQ(get("/api/spectrum", ""), 200);
    WT_LACKS(g_out, "\"range\"");
    WT_HAS(g_out, "\"sweep\":null}");
    env_close();
}

/* Every bad record is skipped and counted, never fatal, and nothing of
 * it reaches the answer. */
static void test_range_skips_bad_records(void) {
    WT_EQ(env_open(1), 0);
    hist_dir();
    put_hist(NOW - 100, "-90.5");
    static const uint8_t q[6] = { 0, 10, 200, 3, 0, 220 };
    char nm[32];
    /* A member twice (the second "started" in the window). */
    snprintf(nm, sizeof(nm), "%lld.json", NOW - 200);
    put_hist_full(nm, NOW - 99999, "-71.5", 6, 500000, q, "\"started\":1762999800,", NULL);
    /* Another grid: a different span. */
    put_hist_full(NULL, NOW - 300, "-72.5", 6, 600000, q, NULL, NULL);
    /* Base64 of 9 bytes under "bins":6. */
    put_file("history/1762999600.json",
             "{\"version\":1,\"started\":1762999600,\"ended\":1762999650,\"rows\":3,"
             "\"floor\":-73.5,\"f_lo\":500000,\"f_hi\":1100000,\"bin_hz\":100000,\"bins\":6,"
             "\"quant\":{\"offset_db\":-130.0,\"step_db\":0.5},\"data\":\"CQkJCQkJCQkJ\"}");
    /* Not JSON; a bad number; "=" inside the data; version 2. */
    put_file("history/1762999500.json", "{\"version\":1,");
    snprintf(nm, sizeof(nm), "%lld.json", NOW - 600);
    put_hist_full(nm, NOW - 600, "-74.", 6, 500000, q, NULL, NULL);
    put_file("history/1762999350.json",
             "{\"version\":1,\"started\":1762999300,\"ended\":1762999350,\"rows\":3,"
             "\"floor\":-75.5,\"f_lo\":500000,\"f_hi\":1100000,\"bin_hz\":100000,\"bins\":6,"
             "\"quant\":{\"offset_db\":-130.0,\"step_db\":0.5},\"data\":\"AA=IAwDc\"}");
    put_file("history/1762999250.json",
             "{\"version\":2,\"started\":1762999200,\"ended\":1762999250,\"rows\":3,"
             "\"floor\":-76.5,\"f_lo\":500000,\"f_hi\":1100000,\"bin_hz\":100000,\"bins\":6,"
             "\"quant\":{\"offset_db\":-130.0,\"step_db\":0.5},\"data\":\"AArIAwDc\"}");
    /* A link to a good record elsewhere, and a directory by a record's
     * name: neither is read. */
    char tgt[TEST_TMP_MAX + 64], lnk[TEST_TMP_MAX + 64];
    put_hist_full("../elsewhere.json", NOW - 700, "-77.5", 6, 500000, q, NULL, NULL);
    snprintf(tgt, sizeof(tgt), "%s/elsewhere.json", E.state);
    snprintf(lnk, sizeof(lnk), "%s/history/%lld.json", E.state, NOW - 700);
    WT_EQ(symlink(tgt, lnk), 0);
    snprintf(lnk, sizeof(lnk), "%s/history/%lld.json", E.state, NOW - 800);
    WT_EQ(mkdir(lnk, 0755), 0);
    /* Names that are not records: not counted at all. */
    put_file("history/.1762999950.json.tmp", "x");
    put_file("history/notes", "x");
    /* A hostile antenna and peak note on a good record. */
    put_file("history/1762999950.json",
             "{\"version\":1,\"antenna\":\"<b>x</b>\",\"started\":1762999950,"
             "\"ended\":1763000000,\"rows\":3,\"floor\":-60.5,\"f_lo\":500000,"
             "\"f_hi\":1100000,\"bin_hz\":100000,\"bins\":6,\"future\":{\"x\":[1,\"y\"]},"
             "\"quant\":{\"offset_db\":-130.0,\"step_db\":0.5},\"data\":\"AArIAwDc\","
             "\"peaks\":[{\"freq_hz\":1,\"note\":\"<script>\"}]}");
    WT_EQ(get("/api/spectrum", "range=1h"), 200);
    WT_HAS(g_out, "\"runs\":2,\"skipped\":9,");
    WT_HAS(g_out, "-90.5");
    WT_HAS(g_out, "-60.5");
    for (int m = 71; m <= 77; m++) {
        char mark[16];
        snprintf(mark, sizeof(mark), "-%d.", m);
        WT_LACKS(g_out, mark);
    }
    WT_LACKS(g_out, "<b>");
    WT_LACKS(g_out, "<script>");
    WT_HAS(g_out, "\"antenna\":\"\\u003cb\\u003ex\\u003c/b\\u003e\"");
    WT_HAS(g_out, "\"peaks\":[{\"freq_hz\":1,\"note\":\"\\u003cscript\\u003e\"}]");
    /* last3 reads on past the bad ones; two good is what there is. */
    WT_EQ(get("/api/spectrum", "range=last3"), 200);
    WT_HAS(g_out, "\"runs\":2,");
    env_close();
}

/* Max-pooling: a narrow spike in any of k bins survives in the one they
 * become; the answer stays inside the bound whatever the window. */
static void test_range_pooling(void) {
    WT_EQ(env_open(1), 0);
    hist_dir();
    enum { BINS = 19995, RUNS = 288 };
    uint8_t *q = calloc(BINS, 1);
    WT_ASSERT(q != NULL);
    if (!q) { env_close(); return; }
    q[1] = 77;            /* pooled bin 0 */
    q[BINS - 1] = 99;     /* pooled bin 4998, the last, 3 wide */
    for (int i = 0; i < RUNS; i++)
        put_hist_full(NULL, NOW - 60 - i * 300.0, "-90.5", BINS, 500000, q, NULL, NULL);
    free(q);
    char *body = NULL;
    size_t len = 0;
    int status = 0;
    WT_EQ(web_spectrum_get(&E.sp, "range=24h", NOW, 0, &body, &len, &status), 0);
    WT_EQ(status, 200);
    WT_ASSERT(body != NULL);
    if (body) {
        WT_HAS(body, "\"runs\":288,\"skipped\":0,\"pool\":4,");
        WT_HAS(body, "\"bin_hz\":400000,\"bins\":4999,");
        /* 4999 pooled bins: 77 first, 99 last. 77 0 0 = TQAA; 4999 is
         * 3 x 1666 + 1, so the last quantum is 99 alone: Yw== */
        WT_HAS(body, "\"data\":\"TQAA");
        WT_HAS(body, "AAAAYw==\"}");
        /* The bound: 288 x 4999 cells as base64 plus the rows' numbers. */
        WT_ASSERT(len < 2200000);
        WT_ASSERT(len > 288 * 4999 * 4 / 3);
        free(body);
    }
    body = NULL;
    WT_EQ(web_spectrum_get(&E.sp, "range=1h", NOW, 0, &body, &len, &status), 0);
    if (body) {
        WT_HAS(body, "\"runs\":12,\"skipped\":0,\"pool\":1,");
        WT_HAS(body, "\"bins\":19995,");
        free(body);
    }
    env_close();
}

static void test_b64_decode_strict(void) {
    uint8_t o[8];
    WT_EQ(web_spectrum_b64_decode("Zm9vYmFy", 8, o, 6), 0);
    WT_ASSERT(!memcmp(o, "foobar", 6));
    WT_EQ(web_spectrum_b64_decode("Zm9vYg==", 8, o, 4), 0);
    WT_ASSERT(!memcmp(o, "foob", 4));
    WT_EQ(web_spectrum_b64_decode("Zm9vYmE=", 8, o, 5), 0);
    WT_EQ(web_spectrum_b64_decode("Zm9vYg==", 8, o, 5), -1);   /* length */
    WT_EQ(web_spectrum_b64_decode("Zm9vYmFy", 8, o, 5), -1);
    WT_EQ(web_spectrum_b64_decode("Zm9vYg=", 7, o, 4), -1);
    WT_EQ(web_spectrum_b64_decode("Zm=vYmFy", 8, o, 6), -1);   /* "=" inside */
    WT_EQ(web_spectrum_b64_decode("Zm9vYg=x", 8, o, 4), -1);
    WT_EQ(web_spectrum_b64_decode("Zm9v Yg=", 8, o, 4), -1);
    WT_EQ(web_spectrum_b64_decode("Zm9-YmFy", 8, o, 6), -1);   /* base64url */
}

/* slothweb's floor under the helper's cooldown: a status naming no
 * cooldown left still refuses a press inside 120 s of the last end. */
static void test_run_floor(void) {
    WT_EQ(env_open(1), 0);
    put_file("status.json",
             "{\"version\":1,\"state\":\"done\",\"mode\":\"sweep\",\"started\":1762999900,"
             "\"updated\":1762999940,\"ended\":1762999940,\"next_allowed\":1762999940,"
             "\"cooldown\":0,\"row\":3,\"step\":334,\"steps\":334,\"antenna\":\"A\"}\n");
    WT_EQ(post(), 429);
    WT_HAS(g_out, "Retry-After: 60\r\n");
    WT_ASSERT(!exists(E.req));
    WT_EQ(get("/api/spectrum", "status=1"), 200);
    WT_HAS(g_out, "\"next_allowed\":1763000060");
    put_file("status.json",
             "{\"version\":1,\"state\":\"done\",\"mode\":\"sweep\",\"started\":1762999800,"
             "\"updated\":1762999879,\"ended\":1762999879,\"next_allowed\":1762999879,"
             "\"cooldown\":0,\"row\":3,\"step\":334,\"steps\":334,\"antenna\":\"A\"}\n");
    WT_EQ(post(), 202);
    env_close();
}

/* A range read writes nothing either. */
static void test_range_never_writes(void) {
    WT_EQ(env_open(1), 0);
    hist_dir();
    put_hist(NOW - 100, "-90.5");
    char p[TEST_TMP_MAX + 64];
    snprintf(p, sizeof(p), "%s/history", E.state);
    int before = entries(p), top = entries(E.state);
    WT_EQ(get("/api/spectrum", "range=last3"), 200);
    WT_EQ(get("/api/spectrum", "range=24h"), 200);
    WT_EQ(entries(p), before);
    WT_EQ(entries(E.state), top);
    WT_ASSERT(!exists(E.req));
    env_close();
}

/* ── the operator's marks (--spectrum-marks, ?marks=1) ── */

static void test_mark_line(void) {
    long long hz = 0;
    char name[WEB_SPECTRUM_MARK_NAME + 1];
#define LINE(t) web_spectrum_mark_line(t, strlen(t), &hz, name, sizeof(name))
    WT_EQ(LINE("146.940,W0ABC -0.6 PL 100"), 1);
    WT_ASSERT(hz == 146940000LL);
    WT_ASSERT(!strcmp(name, "W0ABC -0.6 PL 100"));
    /* No float rounds a channel: six decimals, to the hertz. */
    WT_EQ(LINE("  7.074001 , FT8 \r"), -1);         /* a space before the comma is not a digit */
    WT_EQ(LINE("7.074001, FT8 \r"), 1);
    WT_ASSERT(hz == 7074001LL);
    WT_ASSERT(!strcmp(name, "FT8"));
    WT_EQ(LINE("1296,23 cm"), 1);
    WT_ASSERT(hz == 1296000000LL);
    /* Blank and comment lines are not marks and not errors. */
    WT_EQ(LINE(""), 0);
    WT_EQ(LINE("   \t"), 0);
    WT_EQ(LINE("# 2 m repeaters"), 0);
    /* Refused: no name, no frequency, a sign, an exponent, two points,
     * seven decimals, out of range, a control byte, a name too long. */
    WT_EQ(LINE("146.94"), -1);
    WT_EQ(LINE("146.94,"), -1);
    WT_EQ(LINE(",name"), -1);
    WT_EQ(LINE("-146.94,x"), -1);
    WT_EQ(LINE("1e3,x"), -1);
    WT_EQ(LINE("1.2.3,x"), -1);
    WT_EQ(LINE("146.,x"), -1);
    WT_EQ(LINE("1.0000001,x"), -1);
    WT_EQ(LINE("0.0001,x"), -1);
    WT_EQ(LINE("30000.1,x"), -1);
    WT_EQ(LINE("146.94,a\x01" "b"), -1);
    WT_EQ(LINE("146.94,caf\xc3\xa9"), -1);
    WT_EQ(LINE("146.94,0123456789012345678901234567890123456789012345678"), -1);
    WT_EQ(LINE("146.94,012345678901234567890123456789012345678901234567"), 1);
#undef LINE
}

static void test_marks_route(void) {
    WT_EQ(env_open(1), 0);
    /* No file named: an empty list that says so; every scope's. */
    WT_EQ(get("/api/spectrum", "marks=1"), 200);
    WT_HAS(g_out, "{\"configured\":false,\"marks\":[],\"skipped\":0}");
    WT_EQ(get("/api/spectrum", "marks=2"), 400);
    char path[TEST_TMP_MAX + 64];
    snprintf(path, sizeof(path), "%s/marks.csv", E.state);
    web_spectrum_set_marks(&E.sp, path);
    /* Named and absent. */
    WT_EQ(get("/api/spectrum", "marks=1"), 200);
    WT_HAS(g_out, "\"configured\":true,\"marks\":[],\"skipped\":0,\"error\":\"absent\"");
    /* Marks, a comment, a blank line, and two refused lines; a name's
     * markup is written by the JSON writer, never spliced. */
    put_file("marks.csv", "# local\n146.940,W0ABC -0.6\n\n444.1,<b>\"x\"\nbad line\n9e9,x\n");
    WT_EQ(get("/api/spectrum", "marks=1"), 200);
    WT_HAS(g_out, "\"marks\":[{\"f_hz\":146940000,\"label\":\"W0ABC -0.6\"},{\"f_hz\":444100000,\"label\":\"");
    WT_HAS(g_out, "\"skipped\":2}");
    WT_LACKS(g_out, "<b>");
    WT_LACKS(g_out, "error");
    /* A link is not followed: the file is the operator's, the path may
     * not be. */
    char target[TEST_TMP_MAX + 64], link[TEST_TMP_MAX + 64];
    snprintf(target, sizeof(target), "%s/marks.csv", E.state);
    snprintf(link, sizeof(link), "%s/link.csv", E.state);
    WT_EQ(symlink(target, link), 0);
    web_spectrum_set_marks(&E.sp, link);
    WT_EQ(get("/api/spectrum", "marks=1"), 200);
    WT_HAS(g_out, "\"marks\":[],\"skipped\":0,\"error\":\"unreadable\"");
    /* Over the size limit: refused whole. */
    web_spectrum_set_marks(&E.sp, path);
    {
        FILE *f = fopen(path, "w");
        WT_ASSERT(f != NULL);
        if (f) {
            for (long k = 0; k < WEB_SPECTRUM_MARKS_MAX_BYTES / 10 + 2; k++) fputs("146.94,xx\n", f);
            fclose(f);
        }
    }
    WT_EQ(get("/api/spectrum", "marks=1"), 200);
    WT_HAS(g_out, "\"error\":\"too_large\"");
    /* At most WEB_SPECTRUM_MARKS_MAX marks; the rest counted. */
    {
        FILE *f = fopen(path, "w");
        WT_ASSERT(f != NULL);
        if (f) {
            for (int k = 0; k < WEB_SPECTRUM_MARKS_MAX + 3; k++) fputs("146.94,x\n", f);
            fclose(f);
        }
    }
    WT_EQ(get("/api/spectrum", "marks=1"), 200);
    WT_HAS(g_out, "\"skipped\":3}");
    env_close();
}

/* The page's half: the allocation chart's lanes and the amateur band
 * charts, their data shown as text only. */
static void test_ham_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "  var CATS = [[\"ham\", \"ham\", \"--br-9\"], [\"bc\", \"bcast\", \"--br-4\"], [\"air\", \"aero\", \"--br-0\"],");
    WT_HAS(p, "[144, 148, \"2 m amateur\", \"ham\"]");
    WT_HAS(p, "[902, 928, \"ISM 915\", \"ism\"], [902, 928, \"33 cm amateur\", \"ham\"]");
    WT_HAS(p, "    fetch(\"/api/spectrum?marks=1\", { credentials: \"same-origin\", cache: \"no-store\" })");
    WT_HAS(p, "        if (m[i] && num(m[i].f_hz) && typeof m[i].label === \"string\") out.push([m[i].f_hz / 1e6, m[i].label]);");
    WT_HAS(p, "    [\"2 m\", 144.0, 148.0,");
    WT_HAS(p, "[144.39, \"APRS\"]");
    WT_HAS(p, "[146.52, \"FM calling\"]");
    WT_HAS(p, "[14.074, \"FT8\"]");
    WT_HAS(p, "<div class=\"ham-grid\" id=\"ham-grid\"></div>");
    /* hambands.js before spectrum.js, which calls it. */
    const char *ham = strstr(p, "window.SlothHam = {"), *spec = strstr(p, "window.SlothSpectrum = {");
    WT_ASSERT(ham && spec && ham < spec);
}

void run_spectrum_tests(void) {
    WT_RUN(test_not_attached_and_not_installed);
    WT_RUN(test_idle_and_query);
    WT_RUN(test_status_states);
    WT_RUN(test_cooldown_429);
    WT_RUN(test_queue_once);
    WT_RUN(test_get_never_writes);
    WT_RUN(test_method_guards);
    WT_RUN(test_post_refusals_create_nothing);
    WT_RUN(test_valid_document_round_trip);
    WT_RUN(test_hostile_document_is_escaped);
    WT_RUN(test_oversize_and_links_refused);
    WT_RUN(test_copy_json_direct);
    WT_RUN(test_acl_and_read_only_over_a_socket);
    WT_RUN(test_range_parse);
    WT_RUN(test_range_window);
    WT_RUN(test_range_skips_bad_records);
    WT_RUN(test_range_pooling);
    WT_RUN(test_b64_decode_strict);
    WT_RUN(test_run_floor);
    WT_RUN(test_range_never_writes);
    WT_RUN(test_mark_line);
    WT_RUN(test_marks_route);
    WT_RUN(test_ham_page);
}
