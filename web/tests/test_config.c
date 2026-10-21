/* Command line and the remote-exposure policy. Output goes to
 * open_memstream() buffers, so nothing here touches a host file. */
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_config.h"
#include "wtest.h"

typedef struct {
    web_config_t cfg;
    int          rc;
    char        *out, *err, *ann;    /* stdout, stderr, announcement */
} parsed_t;

static void parse(parsed_t *p, const char *const *args) {
    char *argv[2 * WEB_ACL_MAX + 8];
    int argc = 0;
    argv[argc++] = (char *)"slothweb";
    for (int i = 0; args && args[i] && argc < 2 * WEB_ACL_MAX + 7; i++)
        argv[argc++] = (char *)args[i];
    argv[argc] = NULL;

    size_t ol = 0, el = 0, al = 0;
    p->out = p->err = p->ann = NULL;
    FILE *o = open_memstream(&p->out, &ol);
    FILE *e = open_memstream(&p->err, &el);
    p->rc = web_config_parse(&p->cfg, argc, argv, o, e);
    fclose(o);
    fclose(e);
    FILE *a = open_memstream(&p->ann, &al);
    if (p->rc == 0) web_config_announce(&p->cfg, a);
    fclose(a);
}

static void done(parsed_t *p) {
    free(p->out);
    free(p->err);
    free(p->ann);
}

static void test_default_bind_is_loopback_8770(void) {
    parsed_t p;
    parse(&p, NULL);
    WT_EQ(p.rc, 0);
    WT_EQ(p.cfg.bind_family, AF_INET);
    WT_EQ(p.cfg.bind_addr[0], 127);
    WT_EQ(p.cfg.bind_addr[1], 0);
    WT_EQ(p.cfg.bind_addr[2], 0);
    WT_EQ(p.cfg.bind_addr[3], 1);
    WT_EQ(p.cfg.bind_port, 8770);
    WT_EQ(p.cfg.allow_remote, 0);
    WT_EQ(p.cfg.acl.n, 2);
    char where[64];
    web_format_bind(p.cfg.bind_family, p.cfg.bind_addr, p.cfg.bind_port,
                    where, sizeof(where));
    WT_HAS(where, WEB_DEFAULT_BIND);
    /* Absence: a loopback-only run announces nothing. Seen red with
     * web_config_announce() made unconditional. */
    WT_EQ(strlen(p.ann), 0);
    WT_EQ(strlen(p.err), 0);
    done(&p);
}

static void test_loopback_binds_need_no_flag(void) {
    static const char *const a1[] = { "--web-bind", "127.0.0.5:9000", NULL };
    static const char *const a2[] = { "--web-bind", "[::1]:8771", NULL };
    parsed_t p;
    parse(&p, a1);
    WT_EQ(p.rc, 0);
    WT_EQ(p.cfg.bind_port, 9000);
    WT_EQ(p.cfg.bind_addr[3], 5);
    WT_EQ(strlen(p.ann), 0);
    done(&p);
    parse(&p, a2);
    WT_EQ(p.rc, 0);
    WT_EQ(p.cfg.bind_family, AF_INET6);
    WT_EQ(p.cfg.bind_addr[15], 1);
    WT_EQ(strlen(p.ann), 0);
    done(&p);
}

static void test_remote_bind_refused_without_flag(void) {
    static const char *const binds[] = {
        "0.0.0.0:8770", "192.168.1.10:8770", "[::]:8770", "[2001:db8::1]:8770",
        "[::ffff:192.168.1.10]:8770",
    };
    for (size_t i = 0; i < sizeof(binds) / sizeof(binds[0]); i++) {
        const char *args[] = { "--web-bind", binds[i], NULL };
        parsed_t p;
        parse(&p, args);
        if (p.rc != -1) fprintf(stderr, "    accepted %s\n", binds[i]);
        WT_EQ(p.rc, -1);
        WT_HAS(p.err, "not a loopback address");
        WT_HAS(p.err, "--web-allow-remote");
        done(&p);
    }
}

static void test_remote_bind_with_flag_is_announced(void) {
    static const char *const a[] = {
        "--web-bind", "0.0.0.0:8770", "--web-allow-remote", NULL };
    parsed_t p;
    parse(&p, a);
    WT_EQ(p.rc, 0);
    WT_EQ(p.cfg.allow_remote, 1);
    WT_HAS(p.ann, "WARNING");
    WT_HAS(p.ann, "0.0.0.0:8770");
    WT_HAS(p.ann, "--web-allow-remote");
    /* The flag authorises the bind, not the peers: the list is still
     * loopback only until --web-allow says otherwise. */
    WT_EQ(p.cfg.acl.n, 2);
    done(&p);
}

static void test_remote_allow_needs_flag(void) {
    static const char *const no[]  = { "--web-allow", "192.168.1.0/24", NULL };
    static const char *const yes[] = {
        "--web-allow", "192.168.1.0/24", "--web-allow-remote", NULL };
    static const char *const lo[]  = { "--web-allow", "127.0.0.2", NULL };
    parsed_t p;
    parse(&p, no);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "192.168.1.0/24");
    WT_HAS(p.err, "--web-allow-remote");
    done(&p);

    parse(&p, yes);
    WT_EQ(p.rc, 0);
    WT_EQ(p.cfg.acl.n, 3);
    WT_HAS(p.ann, "admitting non-loopback peers in 192.168.1.0/24");
    /* Loopback bind, so the bind warning must not appear. Seen red with
     * the loopback test in web_config_announce() inverted. */
    WT_LACKS(p.ann, "listening on");
    done(&p);

    /* A loopback entry is not remote exposure. */
    parse(&p, lo);
    WT_EQ(p.rc, 0);
    WT_EQ(p.cfg.acl.n, 3);
    WT_EQ(strlen(p.ann), 0);
    done(&p);
}

static void test_strict_refuses_remote_even_with_flag(void) {
    static const char *const bind[] = {
        "--strict", "--web-bind", "0.0.0.0:8770", "--web-allow-remote", NULL };
    static const char *const allow[] = {
        "--web-allow-remote", "--web-allow", "10.0.0.0/8", "--strict", NULL };
    static const char *const ok[] = { "--strict", NULL };
    parsed_t p;
    parse(&p, bind);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "--strict refuses a non-loopback --web-bind");
    done(&p);
    parse(&p, allow);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "--strict refuses a non-loopback --web-allow");
    done(&p);
    parse(&p, ok);
    WT_EQ(p.rc, 0);
    WT_EQ(p.cfg.strict, 1);
    done(&p);
}

static void test_bind_parse_rejects(void) {
    static const char *const bad[] = {
        "localhost:8770", "127.0.0.1", "127.0.0.1:", "127.0.0.1:0",
        "127.0.0.1:65536", "127.0.0.1:80x", "::1:8770", "[::1]8770",
        "[::1]:", "[127.0.0.1]:8770", "[]:8770", ":8770", "127.0.0.1:-1",
        "127.0.0.1:+80", "127.0.0.1:123456",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        const char *args[] = { "--web-bind", bad[i], NULL };
        parsed_t p;
        parse(&p, args);
        if (p.rc != -1) fprintf(stderr, "    accepted %s\n", bad[i]);
        WT_EQ(p.rc, -1);
        WT_ASSERT(p.err && p.err[0]);
        done(&p);
    }
    /* Names are never resolved, and the message says so. */
    const char *args[] = { "--web-bind", "localhost:8770", NULL };
    parsed_t p;
    parse(&p, args);
    WT_HAS(p.err, "names are not resolved");
    done(&p);

    int fam;
    uint8_t addr[16];
    uint16_t port = 1;
    char err[128];
    WT_EQ(web_parse_bind("127.0.0.1:0", &fam, addr, &port, 1, err, sizeof(err)), 0);
    WT_EQ(port, 0);
}

static void test_usage_and_unknown(void) {
    static const char *const help[] = { "--help", NULL };
    static const char *const unk[]  = { "--web-token", "x", NULL };
    static const char *const miss[] = { "--web-bind", NULL };
    parsed_t p;
    parse(&p, help);
    WT_EQ(p.rc, 1);
    WT_HAS(p.out, "--web-allow-remote");
    WT_HAS(p.out, "every GET and HEAD is 404");
    done(&p);
    parse(&p, unk);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "unknown option --web-token");
    done(&p);
    parse(&p, miss);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "needs an argument");
    done(&p);
}

static void test_allow_list_capacity(void) {
    const char *args[2 * WEB_ACL_MAX + 2];
    int n = 0;
    for (int i = 0; i < WEB_ACL_MAX - 1; i++) {
        args[n++] = "--web-allow";
        args[n++] = "127.0.0.2";
    }
    args[n] = NULL;
    parsed_t p;
    parse(&p, args);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "too many --web-allow entries");
    done(&p);
}

void run_config_tests(void) {
    WT_RUN(test_default_bind_is_loopback_8770);
    WT_RUN(test_loopback_binds_need_no_flag);
    WT_RUN(test_remote_bind_refused_without_flag);
    WT_RUN(test_remote_bind_with_flag_is_announced);
    WT_RUN(test_remote_allow_needs_flag);
    WT_RUN(test_strict_refuses_remote_even_with_flag);
    WT_RUN(test_bind_parse_rejects);
    WT_RUN(test_usage_and_unknown);
    WT_RUN(test_allow_list_capacity);
}
