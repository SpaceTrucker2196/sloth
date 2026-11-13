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
 *     file was created by a peer the list refuses. */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
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
}
