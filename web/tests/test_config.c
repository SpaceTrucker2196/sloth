/* Command line and the remote-exposure policy. Output goes to
 * open_memstream() buffers, so nothing here touches a host file. */
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_config.h"
#include "web_slothdb.h"
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
    WT_HAS(p.out, "/api/health");
    WT_HAS(p.out, "/events");
    WT_HAS(p.out, "405");
    WT_LACKS(p.out, "serves no routes");
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

/* --socket (#159): sloth's default path unless told otherwise, literal
 * addresses only, and a stream read from another host is announced or,
 * under --strict, refused. Seen red (rc 0, nothing on stderr) with the
 * --socket test removed from web_config_check(). */
static void test_socket_flag(void) {
    parsed_t p;
    parse(&p, NULL);
    WT_EQ(p.rc, 0);
    WT_EQ(p.cfg.sock.kind, WEB_SOCKSPEC_UNIX);
    WT_ASSERT(!strcmp(p.cfg.sock.path, "/run/sloth/sloth.sock"));
    done(&p);

    static const char *const loop[] = { "--socket", "tcp:127.0.0.1:8765", NULL };
    parse(&p, loop);
    WT_EQ(p.rc, 0);
    WT_EQ(p.cfg.sock.kind, WEB_SOCKSPEC_TCP);
    WT_EQ(p.cfg.sock.port, 8765);
    WT_ASSERT(p.ann && p.ann[0] == '\0');
    done(&p);

    static const char *const remote[] = { "--socket", "tcp:192.168.1.5:8765", NULL };
    parse(&p, remote);
    WT_EQ(p.rc, 0);
    WT_HAS(p.ann, "WARNING: reading the data stream from tcp:192.168.1.5:8765");
    done(&p);

    static const char *const strict[] = { "--strict", "--socket",
                                          "tcp:192.168.1.5:8765", NULL };
    parse(&p, strict);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "--strict refuses a non-loopback --socket (tcp:192.168.1.5:8765)");
    done(&p);

    static const char *const strict_ok[] = { "--strict", "--socket",
                                             "unix:/tmp/x.sock", NULL };
    parse(&p, strict_ok);
    WT_EQ(p.rc, 0);
    done(&p);

    static const char *const name[] = { "--socket", "tcp:localhost:8765", NULL };
    parse(&p, name);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "names are not resolved");
    done(&p);

    static const char *const bare[] = { "--socket", NULL };
    parse(&p, bare);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "--socket needs an argument");
    done(&p);

    static const char *const help[] = { "--help", NULL };
    parse(&p, help);
    WT_EQ(p.rc, 1);
    WT_HAS(p.out, "--socket SPEC");
    WT_HAS(p.out, "/api/live");
    done(&p);
}

/* --web-max-mb below what the analysis state and the history allowance
 * need is refused at start (main() exits 2 on it), naming the least
 * that would do; at the minimum it runs. The defaults clear it; the
 * largest --web-max-keys at the default ceiling does not. A memory-only
 * build has no file to bound and refuses nothing. Seen red (rc 0, no
 * message) with the size test removed from web_config_check(). */
static void test_ceiling_below_minimum_refused(void) {
    long long need = web_config_store_min_mb(WEB_DEFAULT_MAX_KEYS);
    fprintf(stderr, "  minimum %lld MB at the default keys, %lld MB at %d\n",
            need, web_config_store_min_mb(WEB_MAX_KEYS_MAX), WEB_MAX_KEYS_MAX);
    WT_ASSERT(need > 64 && need <= WEB_DEFAULT_MAX_MB);
    WT_ASSERT(web_config_store_min_mb(WEB_MAX_KEYS_MAX) > WEB_DEFAULT_MAX_MB);
    char at[24], under[24], want[64];
    snprintf(at, sizeof(at), "%lld", need);
    snprintf(under, sizeof(under), "%lld", need - 1);
    snprintf(want, sizeof(want), "Use --web-max-mb %lld or more", need);
    parsed_t p;
    const char *const low[] = { "--web-max-mb", under, NULL };
    parse(&p, low);
    if (web_store_available()) {
        WT_EQ(p.rc, -1);
        WT_HAS(p.err, "is below what --web-max-keys 512 needs");
        WT_HAS(p.err, want);
    } else {
        WT_EQ(p.rc, 0);
    }
    done(&p);
    const char *const ok[] = { "--web-max-mb", at, NULL };
    parse(&p, ok);
    WT_EQ(p.rc, 0);
    done(&p);
    parse(&p, NULL);
    WT_EQ(p.rc, 0);
    done(&p);
    static const char *const big[] = { "--web-max-keys", "8192", NULL };
    parse(&p, big);
    WT_EQ(p.rc, web_store_available() ? -1 : 0);
    done(&p);
}

/* --sloth-db: a path, never empty or past the buffer, never the store's
 * path, and only in a build that can read it. Each refusal seen red
 * with its condition in web_config.c replaced by 0 (the same-path and
 * length ones under the default build, the SQLite one under
 * WITH_SQLITE=0). */
static void test_sloth_db_flag(void) {
    parsed_t p;
    static const char *const ok[] = { "--sloth-db", "/var/lib/sloth/sloth.db", NULL };
    parse(&p, ok);
    if (web_slothdb_available()) {
        WT_EQ(p.rc, 0);
        WT_ASSERT(!strcmp(p.cfg.sloth_db, "/var/lib/sloth/sloth.db"));
    } else {
        WT_EQ(p.rc, -1);
        WT_HAS(p.err, "--sloth-db needs SQLite; this slothweb was built with "
                      "WITH_SQLITE=0");
        WT_EQ(p.cfg.sloth_db[0], '\0');
    }
    done(&p);

    static const char *const empty[] = { "--sloth-db", "", NULL };
    parse(&p, empty);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "--sloth-db: empty or too long a path");
    done(&p);
    static char longp[sizeof(((web_config_t *)0)->sloth_db)];
    memset(longp, 'a', sizeof(longp) - 16);
    longp[0] = '/';
    longp[sizeof(longp) - 16] = '\0';
    const char *const toolong[] = { "--sloth-db", longp, NULL };
    parse(&p, toolong);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "--sloth-db: empty or too long a path");
    done(&p);
    longp[sizeof(longp) - 17] = '\0';             /* one byte shorter fits */
    parse(&p, toolong);
    WT_EQ(p.rc, web_slothdb_available() ? 0 : -1);
    done(&p);

    if (web_slothdb_available() && web_store_available()) {
        static const char *const same[] = { "--sloth-db", "/tmp/x/one.db",
                                            "--store", "/tmp/x/one.db", NULL };
        parse(&p, same);
        WT_EQ(p.rc, -1);
        WT_HAS(p.err, "--sloth-db and --store name the same file (/tmp/x/one.db)");
        done(&p);
        static const char *const apart[] = { "--sloth-db", "/tmp/x/one.db",
                                             "--store", "/tmp/x/two.db", NULL };
        parse(&p, apart);
        WT_EQ(p.rc, 0);
        done(&p);
    }
}

void run_config_tests(void) {
    WT_RUN(test_ceiling_below_minimum_refused);
    WT_RUN(test_socket_flag);
    WT_RUN(test_sloth_db_flag);
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
