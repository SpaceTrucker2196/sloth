#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runner.h"

/*
 * Shipped-unit guard — issue #139.
 *
 * The property under test: the systemd unit this repo ships runs sloth
 * as an unprivileged account, from root-owned paths, under a sandbox
 * that lists exactly the two capabilities capture needs — and the
 * Makefile that installs it never widens that.
 *
 * The unit it replaces did none of this. It ran `User=root` with
 * `ExecStart=/home/<uid 1000>/Projects/sloth/sloth`, so `make clean`
 * took the sensor down (2026-10-14, ~1 h with no binary on disk) and any
 * process able to write that checkout could replace the binary root
 * executes — CWE-426 / CWE-732 / CWE-250. Nothing in-tree could notice,
 * because nothing in-tree described the unit.
 *
 * Why a text scan rather than `systemd-analyze`: this suite runs on
 * machines without systemd (CI's macOS leg, containers), and the
 * invariant is about what the *file in the repo* says, before any
 * install. The CI job that stages `make install DESTDIR=$TMP` and runs
 * `systemd-analyze verify` is the behavioural half. Pattern follows
 * tests/test_build_recipe.c (#95): collapse continuations, look at
 * logical lines, and keep the scanner's own cases hand-built so the
 * checks are known capable of failing.
 *
 * Every check that asserts an *absence* here (no /home/, no AF_INET on a
 * unix: profile, no --eapol-dir without --collect-handshakes, nothing
 * outside {NET_RAW, NET_ADMIN}, no useradd from make) was seen red under
 * a mutation before it was committed; the log entry for #139 names each
 * one and the test it reddened.
 */

#define UF_PATH_UNIT     "packaging/systemd/sloth-sensor.service"
#define UF_PATH_SYSUSERS "packaging/systemd/sloth.sysusers.conf"
#define UF_PATH_HELPER   "packaging/bin/sloth-monitor-up"
#define UF_PATH_DEFAULTS "packaging/default/sloth"
#define UF_PATH_WIKI     "docs/wiki/deployment.md"
#define UF_PATH_WEB_UNIT "packaging/systemd/slothweb.service"
#define UF_PATH_WEB_DEFAULTS "packaging/default/slothweb"
#define UF_PATH_BLE_UNIT "packaging/systemd/sloth-ble-scan.service"
#define UF_PATH_BT_DROPIN "packaging/systemd/sloth-sensor.service.d/bt-monitor.conf"
#define UF_MAX_LINES     512

static char *uf_slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    buf[got] = '\0';
    fclose(f);
    return buf;
}

/* Collapse backslash continuations (systemd and make share the rule) so
 * a directive wrapped over several source lines is examined as the one
 * value systemd sees. Rewrites in place; `out[i]` points into `buf`. */
static int uf_logical_lines(char *buf, char *out[], int max) {
    int n = 0;
    char *p = buf;
    while (*p && n < max) {
        out[n++] = p;
        for (;;) {
            char *nl = strchr(p, '\n');
            if (!nl) { p += strlen(p); break; }
            if (nl > buf && nl[-1] == '\\') {
                nl[-1] = ' ';
                *nl = ' ';
                p = nl + 1;
                continue;
            }
            *nl = '\0';
            p = nl + 1;
            break;
        }
    }
    return n;
}

/* A unit directive is `Key=value` outside a comment or section header. */
static int uf_is_directive(const char *line) {
    while (*line == ' ' || *line == '\t') line++;
    if (*line == '#' || *line == ';' || *line == '[' || *line == '\0') return 0;
    return strchr(line, '=') != NULL;
}

/* Value of the first `key=` directive, or NULL. Keys are exact: `User`
 * must not match `UserNS`, `ExecStart` must not match `ExecStartPre`. */
static const char *uf_value(char *lines[], int n, const char *key) {
    size_t k = strlen(key);
    for (int i = 0; i < n; i++) {
        const char *l = lines[i];
        while (*l == ' ' || *l == '\t') l++;
        if (!uf_is_directive(l)) continue;
        if (strncmp(l, key, k) == 0 && l[k] == '=') return l + k + 1;
    }
    return NULL;
}

/* uf_value() for a key the caller then compares: never NULL. A missing
 * key prints its name and yields a value no expected one equals, so
 * ASSERT_STR() and strncmp() fail an assertion naming the key instead
 * of handing strcmp() a NULL (which ended the whole suite with
 * SIGSEGV). */
#define UF_ABSENT "\x01(absent)"
static const char *uf_req(char *lines[], int n, const char *key) {
    const char *v = uf_value(lines, n, key);
    if (v) return v;
    fprintf(stderr, "    %s= absent\n", key);
    return UF_ABSENT;
}

/* Number of directives with this key — a key given twice is how
 * SystemCallFilter accumulates, and how User= could be overridden. */
static int uf_count(char *lines[], int n, const char *key) {
    size_t k = strlen(key);
    int c = 0;
    for (int i = 0; i < n; i++) {
        const char *l = lines[i];
        while (*l == ' ' || *l == '\t') l++;
        if (!uf_is_directive(l)) continue;
        if (strncmp(l, key, k) == 0 && l[k] == '=') c++;
    }
    return c;
}

/* Whitespace-separated token membership. `--db` must not match
 * `--db-interval-secs`, and `AF_INET` must not match `AF_INET6`. */
static int uf_has_token(const char *value, const char *tok) {
    if (!value) return 0;
    size_t k = strlen(tok);
    const char *p = value;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        const char *e = p;
        while (*e && *e != ' ' && *e != '\t') e++;
        if ((size_t)(e - p) == k && strncmp(p, tok, k) == 0) return 1;
        p = e;
    }
    return 0;
}

/* Every token of `value` is in the allow-list. Empty value → 0, so a
 * directive emptied out cannot pass as "trivially a subset". */
static int uf_tokens_within(const char *value, const char *const allow[],
                            int nallow) {
    if (!value) return 0;
    int seen = 0;
    const char *p = value;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        const char *e = p;
        while (*e && *e != ' ' && *e != '\t') e++;
        int ok = 0;
        for (int i = 0; i < nallow; i++)
            if ((size_t)(e - p) == strlen(allow[i]) &&
                strncmp(p, allow[i], (size_t)(e - p)) == 0) ok = 1;
        if (!ok) return 0;
        seen++;
        p = e;
    }
    return seen > 0;
}

/* A token of a path list (ReadWritePaths= and kin) at or under `dir`,
 * after the '-' and '+' prefixes systemd allows. `/var/lib/slothweb`
 * is not under `/var/lib/sloth`; `/var/lib/sloth/` and
 * `-/var/lib/sloth/x` are. */
static int uf_path_under(const char *value, const char *dir) {
    if (!value) return 0;
    size_t k = strlen(dir);
    const char *p = value;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        const char *e = p;
        while (*e && *e != ' ' && *e != '\t') e++;
        const char *t = p;
        while (t < e && (*t == '-' || *t == '+')) t++;
        if ((size_t)(e - t) >= k && strncmp(t, dir, k) == 0 &&
            (t + k == e || t[k] == '/')) return 1;
        p = e;
    }
    return 0;
}

/* A flag is "named" by a document when it appears followed by something
 * that cannot continue a flag name — so a page listing only
 * `--db-interval-secs` does not get credit for `--db`. */
static int uf_doc_names_flag(const char *doc, const char *flag) {
    size_t k = strlen(flag);
    const char *p = doc;
    while ((p = strstr(p, flag)) != NULL) {
        char c = p[k];
        if (!(isalnum((unsigned char)c) || c == '-' || c == '_')) return 1;
        p += k;
    }
    return 0;
}

/* ── scanner self-tests: hand-built strings, so the checks below are
 *    known to be capable of failing ── */

static void test_scanner_directive_lookup_is_exact(void) {
    char src[] = "[Service]\n"
                 "# User=root in a comment\n"
                 "UserNS=no\n"
                 "User=sloth\n"
                 "ExecStartPre=+/usr/local/sbin/helper x\n"
                 "ExecStart=/usr/local/bin/sloth \\\n"
                 "    --headless \\\n"
                 "    --db /var/lib/sloth/sloth.db\n"
                 "SystemCallFilter=@system-service\n"
                 "SystemCallFilter=~@privileged\n";
    char *lines[32];
    int n = uf_logical_lines(src, lines, 32);
    ASSERT_EQ(n, 8);
    ASSERT(!uf_is_directive("[Service]"));
    ASSERT(!uf_is_directive("# User=root in a comment"));
    ASSERT(uf_is_directive("User=sloth"));
    ASSERT_STR(uf_req(lines, n, "User"), "sloth");
    ASSERT_STR(uf_req(lines, n, "UserNS"), "no");
    ASSERT(uf_value(lines, n, "Group") == NULL);
    /* The continuation joined into the one ExecStart systemd sees. */
    ASSERT(strncmp(uf_req(lines, n, "ExecStart"), "/usr/local/bin/sloth", 20) == 0);
    ASSERT(uf_has_token(uf_value(lines, n, "ExecStart"), "--db"));
    ASSERT(uf_has_token(uf_value(lines, n, "ExecStart"), "--headless"));
    ASSERT(strncmp(uf_req(lines, n, "ExecStartPre"), "+/usr/local/sbin/", 17) == 0);
    ASSERT_EQ(uf_count(lines, n, "SystemCallFilter"), 2);
    ASSERT_EQ(uf_count(lines, n, "User"), 1);
}

static void test_scanner_tokens_are_whole_words(void) {
    ASSERT(uf_has_token("AF_UNIX AF_NETLINK AF_PACKET", "AF_NETLINK"));
    ASSERT(!uf_has_token("AF_UNIX AF_NETLINK AF_PACKET", "AF_INET"));
    ASSERT(uf_has_token("AF_UNIX AF_INET6", "AF_INET6"));
    ASSERT(!uf_has_token("AF_UNIX AF_INET6", "AF_INET"));
    ASSERT(!uf_has_token("--db-interval-secs 1", "--db"));
    ASSERT(uf_has_token("--db x --db-interval-secs 1", "--db"));
    ASSERT(!uf_has_token(NULL, "x"));

    static const char *const caps[] = { "CAP_NET_RAW", "CAP_NET_ADMIN" };
    ASSERT(uf_tokens_within("CAP_NET_RAW CAP_NET_ADMIN", caps, 2));
    ASSERT(uf_tokens_within("CAP_NET_RAW", caps, 2));
    ASSERT(!uf_tokens_within("CAP_NET_RAW CAP_SYS_ADMIN", caps, 2));
    ASSERT(!uf_tokens_within("CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE", caps, 2));
    /* Emptied-out directive is not a subset, it is a missing directive. */
    ASSERT(!uf_tokens_within("", caps, 2));
    ASSERT(!uf_tokens_within(NULL, caps, 2));

    ASSERT(uf_path_under("/var/lib/sloth", "/var/lib/sloth"));
    ASSERT(uf_path_under("/var/lib/sloth/", "/var/lib/sloth"));
    ASSERT(uf_path_under("/var/lib/sloth/x", "/var/lib/sloth"));
    ASSERT(uf_path_under("-/var/lib/sloth", "/var/lib/sloth"));
    ASSERT(uf_path_under("+/var/lib/sloth/x", "/var/lib/sloth"));
    ASSERT(uf_path_under("/var/lib/sloth /var/lib/slothweb", "/var/lib/sloth"));
    ASSERT(uf_path_under("/var/lib/slothweb /var/lib/sloth", "/var/lib/sloth"));
    ASSERT(!uf_path_under("/var/lib/slothweb", "/var/lib/sloth"));
    ASSERT(!uf_path_under("/var/lib/slothweb/x /tmp/var/lib/sloth", "/var/lib/sloth"));
    ASSERT(!uf_path_under("/var/lib/slot", "/var/lib/sloth"));
    ASSERT(!uf_path_under("", "/var/lib/sloth"));
    ASSERT(!uf_path_under(NULL, "/var/lib/sloth"));
}

static void test_scanner_doc_flag_match_needs_a_boundary(void) {
    ASSERT(uf_doc_names_flag("run with `--db FILE` and", "--db"));
    ASSERT(!uf_doc_names_flag("only `--db-interval-secs 1`", "--db"));
    ASSERT(uf_doc_names_flag("`--db-interval-secs 1` and `--db x`", "--db"));
    ASSERT(uf_doc_names_flag("--headless\n", "--headless"));
    ASSERT(!uf_doc_names_flag("", "--headless"));
}

/* ── the unit ── */

static void test_unit_runs_as_the_sloth_account(void) {
    char *buf = uf_slurp(UF_PATH_UNIT);
    ASSERT(buf != NULL);
    if (!buf) return;
    char *lines[UF_MAX_LINES];
    int n = uf_logical_lines(buf, lines, UF_MAX_LINES);
    ASSERT_GT(n, 0);
    ASSERT_LT(n, UF_MAX_LINES);

    /* The whole point of the slice. Given once, so a later User= cannot
     * quietly win. */
    ASSERT_EQ(uf_count(lines, n, "User"), 1);
    ASSERT_STR(uf_req(lines, n, "User"), "sloth");
    ASSERT_STR(uf_req(lines, n, "Group"), "sloth");
    ASSERT(uf_value(lines, n, "DynamicUser") == NULL);

    /* State lives where systemd creates it for that account, not in a
     * checkout. */
    ASSERT_STR(uf_req(lines, n, "StateDirectory"), "sloth");
    ASSERT_STR(uf_req(lines, n, "StateDirectoryMode"), "0700");
    ASSERT_STR(uf_req(lines, n, "RuntimeDirectory"), "sloth");
    ASSERT_STR(uf_req(lines, n, "WorkingDirectory"), "/var/lib/sloth");
    ASSERT_STR(uf_req(lines, n, "UMask"), "0077");
    free(buf);
}

static void test_unit_executes_installed_paths_only(void) {
    char *buf = uf_slurp(UF_PATH_UNIT);
    ASSERT(buf != NULL);
    if (!buf) return;

    /* No /home/ anywhere — directives, comments or Documentation=. The
     * old unit's Documentation=file:///home/... was the tell that it was
     * written for one checkout. Raw scan, before continuations are
     * collapsed, so a comment cannot hide one either. */
    ASSERT(strstr(buf, "/home/") == NULL);
    /* And no ConditionPathExists on a build artefact: the unit must not
     * go silent when the artefact is missing, it must fail loudly. */
    ASSERT(strstr(buf, "ConditionPathExists=") == NULL);

    char *lines[UF_MAX_LINES];
    int n = uf_logical_lines(buf, lines, UF_MAX_LINES);

    const char *start = uf_value(lines, n, "ExecStart");
    ASSERT(start != NULL);
    if (start) {
        /* No `-`/`@`/`+`/`!` prefix: sloth itself must run inside the
         * sandbox, and its failure must fail the unit. */
        ASSERT(strncmp(start, "/usr/local/bin/sloth ", 21) == 0 ||
               strcmp(start, "/usr/local/bin/sloth") == 0);
        ASSERT(uf_has_token(start, "--headless"));
    }
    ASSERT_EQ(uf_count(lines, n, "ExecStart"), 1);

    /* Monitor mode is set by the helper, as root (`+`), never by sloth:
     * MISSION.md §2. */
    const char *pre = uf_value(lines, n, "ExecStartPre");
    ASSERT(pre != NULL);
    if (pre) ASSERT(strncmp(pre, "+/usr/local/sbin/sloth-monitor-up ", 34) == 0);
    free(buf);
}

static void test_unit_capabilities_are_exactly_the_two(void) {
    char *buf = uf_slurp(UF_PATH_UNIT);
    ASSERT(buf != NULL);
    if (!buf) return;
    char *lines[UF_MAX_LINES];
    int n = uf_logical_lines(buf, lines, UF_MAX_LINES);

    static const char *const allow[] = { "CAP_NET_RAW", "CAP_NET_ADMIN" };
    const char *bound = uf_value(lines, n, "CapabilityBoundingSet");
    const char *amb   = uf_value(lines, n, "AmbientCapabilities");
    ASSERT(bound != NULL);
    ASSERT(amb != NULL);
    /* Bounding set ⊆ {NET_RAW, NET_ADMIN}; ambient ⊆ bounding. Each given
     * once, since a second CapabilityBoundingSet= line merges in. */
    if (!uf_tokens_within(bound, allow, 2))
        fprintf(stderr, "    unit: CapabilityBoundingSet=%s is wider than "
                "{CAP_NET_RAW, CAP_NET_ADMIN}\n", bound ? bound : "(absent)");
    ASSERT(uf_tokens_within(bound, allow, 2));
    if (!uf_tokens_within(amb, allow, 2))
        fprintf(stderr, "    unit: AmbientCapabilities=%s is wider than "
                "{CAP_NET_RAW, CAP_NET_ADMIN}\n", amb ? amb : "(absent)");
    ASSERT(uf_tokens_within(amb, allow, 2));
    ASSERT_EQ(uf_count(lines, n, "CapabilityBoundingSet"), 1);
    ASSERT_EQ(uf_count(lines, n, "AmbientCapabilities"), 1);
    /* Both are needed, not just permitted: capture without NET_RAW and
     * --hop without NET_ADMIN each fail at startup. */
    ASSERT(uf_has_token(amb, "CAP_NET_RAW"));
    ASSERT(uf_has_token(amb, "CAP_NET_ADMIN"));
    ASSERT(uf_has_token(bound, "CAP_NET_RAW"));
    ASSERT(uf_has_token(bound, "CAP_NET_ADMIN"));
    ASSERT_STR(uf_req(lines, n, "NoNewPrivileges"), "true");
    free(buf);
}

static void test_unit_sandbox_keys_present(void) {
    char *buf = uf_slurp(UF_PATH_UNIT);
    ASSERT(buf != NULL);
    if (!buf) return;
    char *lines[UF_MAX_LINES];
    int n = uf_logical_lines(buf, lines, UF_MAX_LINES);

    static const struct { const char *key, *val; } want[] = {
        { "ProtectSystem",            "strict"    },
        { "ProtectHome",              "true"      },
        { "PrivateTmp",               "true"      },
        { "PrivateDevices",           "true"      },
        { "ProtectKernelTunables",    "true"      },
        { "ProtectKernelModules",     "true"      },
        { "ProtectKernelLogs",        "true"      },
        { "ProtectControlGroups",     "true"      },
        { "ProtectClock",             "true"      },
        { "ProtectHostname",          "true"      },
        { "ProtectProc",              "invisible" },
        { "RestrictNamespaces",       "true"      },
        { "RestrictRealtime",         "true"      },
        { "RestrictSUIDSGID",         "true"      },
        { "LockPersonality",          "true"      },
        { "MemoryDenyWriteExecute",   "true"      },
        { "SystemCallArchitectures",  "native"    },
        { "SystemCallErrorNumber",    "EPERM"     },
        { "Restart",                  "always"    },
        { "KillSignal",               "SIGTERM"   },
    };
    for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
        const char *v = uf_value(lines, n, want[i].key);
        if (!v || strcmp(v, want[i].val) != 0)
            fprintf(stderr, "    unit: %s=%s wanted, got %s\n",
                    want[i].key, want[i].val, v ? v : "(absent)");
        ASSERT(v != NULL && strcmp(v, want[i].val) == 0);
    }

    /* The syscall filter is an allow-list plus a deny-list; both halves
     * have to be there for either to mean anything. */
    int allow_seen = 0, deny_seen = 0;
    for (int i = 0; i < n; i++) {
        const char *l = lines[i];
        while (*l == ' ' || *l == '\t') l++;
        if (strncmp(l, "SystemCallFilter=", 17) != 0) continue;
        if (uf_has_token(l + 17, "@system-service")) allow_seen = 1;
        if (uf_has_token(l + 17, "~@privileged")) deny_seen = 1;
    }
    ASSERT(allow_seen);
    ASSERT(deny_seen);

    /* #140: sloth sheds CAP_NET_RAW with capset after capture opens and
     * fails closed if it cannot. capset is in @privileged, so the unit
     * must re-allow it on a line AFTER the deny — an earlier allow line
     * is removed again by the deny that follows it. */
    int deny_at = -1, capset_at = -1;
    for (int i = 0; i < n; i++) {
        const char *l = lines[i];
        while (*l == ' ' || *l == '\t') l++;
        if (strncmp(l, "SystemCallFilter=", 17) != 0) continue;
        if (uf_has_token(l + 17, "~@privileged")) deny_at = i;
        if (l[17] != '~' && uf_has_token(l + 17, "capset")) capset_at = i;
    }
    ASSERT(capset_at >= 0);
    ASSERT(capset_at > deny_at);

    /* Memory ceiling until M0 closes; without one a leak is a host OOM. */
    ASSERT(uf_value(lines, n, "MemoryMax") != NULL);
    ASSERT(uf_value(lines, n, "TasksMax") != NULL);
    free(buf);
}

/* Conditional absences in ExecStart. Each reads as "if A then B" and so
 * passes vacuously when A is absent — the mutations that proved them add
 * A without B (see the #139 log entry). */
static void test_unit_flag_pairs_are_consistent(void) {
    char *buf = uf_slurp(UF_PATH_UNIT);
    ASSERT(buf != NULL);
    if (!buf) return;
    char *lines[UF_MAX_LINES];
    int n = uf_logical_lines(buf, lines, UF_MAX_LINES);
    const char *start = uf_value(lines, n, "ExecStart");
    ASSERT(start != NULL);
    if (!start) { free(buf); return; }

    /* #87: --eapol-dir without --collect-handshakes is a refused start,
     * and a unit that refuses to start restarts forever under
     * Restart=always. */
    if (uf_has_token(start, "--eapol-dir"))
        ASSERT(uf_has_token(start, "--collect-handshakes"));

    /* The address-family list must match the socket the unit asks for.
     * A unix: data socket with no --allow-active needs no AF_INET; a
     * tcp: one, or --allow-active, needs it or sloth fails at bind. */
    const char *fam = uf_value(lines, n, "RestrictAddressFamilies");
    ASSERT(fam != NULL);
    int tcp    = strstr(start, "--data-socket tcp:") != NULL;
    int active = uf_has_token(start, "--allow-active");
    if (!tcp && !active) {
        ASSERT(!uf_has_token(fam, "AF_INET"));
        ASSERT(!uf_has_token(fam, "AF_INET6"));
    } else {
        ASSERT(uf_has_token(fam, "AF_INET"));
    }
    /* And the three the db-only profile cannot run without. */
    ASSERT(uf_has_token(fam, "AF_UNIX"));
    ASSERT(uf_has_token(fam, "AF_NETLINK"));
    ASSERT(uf_has_token(fam, "AF_PACKET"));
    /* Not AF_BLUETOOTH. --bt-monitor needs it, but with the family
     * allowed a compromised sensor could bind a raw HCI socket or an
     * L2CAP one and make an up hciN transmit; it comes from the opt-in
     * drop-in (test_sensor_bt_monitor_dropin) instead. */
    ASSERT(!uf_has_token(fam, "AF_BLUETOOTH"));
    static const char *const fams[] = {
        "AF_UNIX", "AF_NETLINK", "AF_PACKET", "AF_INET", "AF_INET6"
    };
    ASSERT(uf_tokens_within(fam, fams, 5));

    /* The data socket is a unix: path under the RuntimeDirectory, so
     * SO_PEERCRED is the authentication and nothing listens on a port. */
    ASSERT(strstr(start, "--data-socket unix:/run/sloth/") != NULL);
    free(buf);
}

/* docs-consistency: the wiki page describes the unit that ships, flag
 * for flag. A reader following the page must not be following a
 * different ExecStart than the one installed. */
static void test_deployment_page_names_every_execstart_flag(void) {
    char *buf = uf_slurp(UF_PATH_UNIT);
    char *doc = uf_slurp(UF_PATH_WIKI);
    ASSERT(buf != NULL);
    ASSERT(doc != NULL);
    if (!buf || !doc) { free(buf); free(doc); return; }
    char *lines[UF_MAX_LINES];
    int n = uf_logical_lines(buf, lines, UF_MAX_LINES);
    const char *start = uf_value(lines, n, "ExecStart");
    ASSERT(start != NULL);
    if (!start) { free(buf); free(doc); return; }

    int flags = 0;
    const char *p = start;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        const char *e = p;
        while (*e && *e != ' ' && *e != '\t') e++;
        if (e - p > 2 && p[0] == '-' && p[1] == '-') {
            char flag[64];
            size_t k = (size_t)(e - p);
            if (k >= sizeof(flag)) k = sizeof(flag) - 1;
            memcpy(flag, p, k);
            flag[k] = '\0';
            flags++;
            if (!uf_doc_names_flag(doc, flag))
                fprintf(stderr, "    %s does not name ExecStart flag %s\n",
                        UF_PATH_WIKI, flag);
            ASSERT(uf_doc_names_flag(doc, flag));
        }
        p = e;
    }
    /* Twelve today. A floor keeps the loop from passing on an ExecStart
     * that has lost its flags. */
    ASSERT_GE(flags, 10);

    /* The page's migration recipe must name the account, the state dir
     * and the install targets it tells the operator to run. */
    ASSERT(strstr(doc, "install-service") != NULL);
    ASSERT(strstr(doc, "systemd-sysusers") != NULL);
    ASSERT(strstr(doc, "/var/lib/sloth") != NULL);
    ASSERT(strstr(doc, "chown -R sloth:sloth") != NULL);
    free(buf);
    free(doc);
}

/* ── the sysusers fragment ── */

static void test_sysusers_fragment_declares_a_system_account(void) {
    char *buf = uf_slurp(UF_PATH_SYSUSERS);
    ASSERT(buf != NULL);
    if (!buf) return;
    char *lines[64];
    int n = uf_logical_lines(buf, lines, 64);
    int found = 0;
    for (int i = 0; i < n; i++) {
        const char *l = lines[i];
        while (*l == ' ' || *l == '\t') l++;
        if (*l == '#' || *l == '\0') continue;
        found++;
        /* `u sloth - "..." /var/lib/sloth /usr/sbin/nologin`: a system
         * user with a kernel-assigned id, a home that is the state dir
         * and no shell. Field positions per sysusers.d(5). */
        ASSERT(strncmp(l, "u ", 2) == 0);
        ASSERT(uf_has_token(l, "sloth"));
        ASSERT(uf_has_token(l, "-"));
        ASSERT(uf_has_token(l, "/var/lib/sloth"));
        ASSERT(uf_has_token(l, "/usr/sbin/nologin"));
        ASSERT(strstr(l, "/bin/bash") == NULL);
        ASSERT(strstr(l, "/bin/sh") == NULL);
    }
    /* Exactly one record: one account, no groups or ranges smuggled in. */
    ASSERT_EQ(found, 1);
    free(buf);
}

/* ── the helper and the defaults file ── */

static void test_monitor_up_helper_is_idempotent_and_root_side(void) {
    char *buf = uf_slurp(UF_PATH_HELPER);
    ASSERT(buf != NULL);
    if (!buf) return;
    ASSERT(strncmp(buf, "#!/bin/sh", 9) == 0);
    /* The test for "already 803" has to come before the mode change, or
     * the helper is not idempotent and the unit flaps the radio on every
     * restart. */
    const char *check = strstr(buf, "= \"803\"");
    const char *set   = strstr(buf, "set type monitor");
    ASSERT(check != NULL);
    ASSERT(set != NULL);
    ASSERT(check != NULL && set != NULL && check < set);
    /* It prepares the radio; it never starts, stops or configures sloth. */
    ASSERT(strstr(buf, "/usr/local/bin/sloth") == NULL);
    ASSERT(strstr(buf, "systemctl") == NULL);
    free(buf);
}

static void test_defaults_file_is_an_environment_file(void) {
    char *buf = uf_slurp(UF_PATH_DEFAULTS);
    ASSERT(buf != NULL);
    if (!buf) return;
    char *lines[64];
    int n = uf_logical_lines(buf, lines, 64);
    int iface = 0, args = 0;
    for (int i = 0; i < n; i++) {
        const char *l = lines[i];
        if (*l == '#' || *l == '\0') continue;
        /* KEY=value only — systemd does not run a shell over this file,
         * so `export`, `$(...)` and backticks would be read literally. */
        ASSERT(strchr(l, '=') != NULL);
        ASSERT(strncmp(l, "export ", 7) != 0);
        ASSERT(strstr(l, "$(") == NULL);
        ASSERT(strchr(l, '`') == NULL);
        if (strncmp(l, "SLOTH_IFACE=", 12) == 0) iface++;
        if (strncmp(l, "SLOTH_ARGS=", 11) == 0) args++;
    }
    ASSERT_EQ(iface, 1);
    ASSERT_EQ(args, 1);
    /* Site identity is operator data, not repo content: the shipped
     * defaults must not carry a real --my-ssid / --my-bssid on any
     * non-comment line (the commented example is the operator's cue).
     * Asserted structurally rather than by naming any particular site. */
    {
        int leaked = 0;
        char *copy = strdup(buf);
        ASSERT(copy != NULL);
        if (copy) {
            for (char *l = strtok(copy, "\n"); l; l = strtok(NULL, "\n")) {
                while (*l == ' ' || *l == '\t') l++;
                if (*l == '#' || *l == '\0') continue;
                if (strstr(l, "--my-ssid") || strstr(l, "--my-bssid")) leaked++;
            }
            free(copy);
        }
        ASSERT_EQ(leaked, 0);
    }
    free(buf);
}

/* ── slothweb.service (#153) ──
 *
 * The web UI's unit: the same account as the sensor (it reads the
 * sensor's 0700 state dir and 0600 socket), but nothing the sensor
 * holds beyond that — no capability at all, no /home, no packet or
 * netlink socket, and the sensor's directory read-only. Each absence
 * below was seen red under a one-line mutation of the unit (the #153
 * log entry names them). */

static void test_web_unit_runs_as_sloth_with_no_capabilities(void) {
    char *buf = uf_slurp(UF_PATH_WEB_UNIT);
    ASSERT(buf != NULL);
    if (!buf) return;
    /* Raw scans, comments included, as for the sensor's unit, and
     * before uf_logical_lines(), which cuts buf in place: after it a
     * strstr() over buf stops at the first line. */
    ASSERT(strstr(buf, "/home/") == NULL);
    ASSERT(strstr(buf, "CAP_") == NULL);
    char *lines[UF_MAX_LINES];
    int n = uf_logical_lines(buf, lines, UF_MAX_LINES);
    ASSERT_GT(n, 0);
    ASSERT_LT(n, UF_MAX_LINES);

    ASSERT_EQ(uf_count(lines, n, "User"), 1);
    ASSERT_STR(uf_req(lines, n, "User"), "sloth");
    ASSERT_EQ(uf_count(lines, n, "Group"), 1);
    ASSERT_STR(uf_req(lines, n, "Group"), "sloth");
    ASSERT(uf_value(lines, n, "DynamicUser") == NULL);

    /* Present and empty: an absent CapabilityBoundingSet= is the full
     * set, not none. Given once, since a second line merges in. */
    const char *bound = uf_value(lines, n, "CapabilityBoundingSet");
    const char *amb   = uf_value(lines, n, "AmbientCapabilities");
    ASSERT(bound != NULL);
    ASSERT(amb != NULL);
    if (bound && bound[0])
        fprintf(stderr, "    slothweb unit: CapabilityBoundingSet=%s, want empty\n", bound);
    ASSERT(bound != NULL && bound[0] == '\0');
    ASSERT(amb != NULL && amb[0] == '\0');
    ASSERT_EQ(uf_count(lines, n, "CapabilityBoundingSet"), 1);
    ASSERT_EQ(uf_count(lines, n, "AmbientCapabilities"), 1);
    ASSERT_STR(uf_req(lines, n, "NoNewPrivileges"), "true");
    free(buf);
}

static void test_web_unit_sandbox(void) {
    char *buf = uf_slurp(UF_PATH_WEB_UNIT);
    ASSERT(buf != NULL);
    if (!buf) return;
    char *lines[UF_MAX_LINES];
    int n = uf_logical_lines(buf, lines, UF_MAX_LINES);

    static const struct { const char *key, *val; } want[] = {
        { "ProtectSystem",            "strict"    },
        { "ProtectHome",              "yes"       },
        { "PrivateTmp",               "true"      },
        { "PrivateDevices",           "true"      },
        { "ProtectKernelTunables",    "true"      },
        { "ProtectKernelModules",     "true"      },
        { "ProtectKernelLogs",        "true"      },
        { "ProtectControlGroups",     "true"      },
        { "RestrictNamespaces",       "true"      },
        { "RestrictSUIDSGID",         "true"      },
        { "MemoryDenyWriteExecute",   "true"      },
        { "SystemCallArchitectures",  "native"    },
        { "StateDirectory",           "slothweb"  },
        { "StateDirectoryMode",       "0700"      },
        { "WorkingDirectory",         "/var/lib/slothweb" },
        { "UMask",                    "0077"      },
        { "EnvironmentFile",          "-/etc/default/slothweb" },
        { "After",                    "sloth-sensor.service" },
        { "Wants",                    "sloth-sensor.service" },
    };
    for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
        const char *v = uf_value(lines, n, want[i].key);
        if (!v || strcmp(v, want[i].val) != 0)
            fprintf(stderr, "    slothweb unit: %s=%s wanted, got %s\n",
                    want[i].key, want[i].val, v ? v : "(absent)");
        ASSERT(v != NULL && strcmp(v, want[i].val) == 0);
    }
    ASSERT_EQ(uf_count(lines, n, "StateDirectory"), 1);

    /* It serves HTTP and reads a unix socket; nothing else. */
    static const char *const fams[] = { "AF_UNIX", "AF_INET", "AF_INET6" };
    const char *fam = uf_value(lines, n, "RestrictAddressFamilies");
    ASSERT(uf_tokens_within(fam, fams, 3));
    ASSERT(uf_has_token(fam, "AF_UNIX"));
    ASSERT(uf_has_token(fam, "AF_INET"));
    ASSERT(!uf_has_token(fam, "AF_PACKET"));
    ASSERT(!uf_has_token(fam, "AF_NETLINK"));
    ASSERT_EQ(uf_count(lines, n, "RestrictAddressFamilies"), 1);

    int allow_seen = 0;
    for (int i = 0; i < n; i++) {
        const char *l = lines[i];
        while (*l == ' ' || *l == '\t') l++;
        if (strncmp(l, "SystemCallFilter=", 17) == 0 &&
            uf_has_token(l + 17, "@system-service")) allow_seen = 1;
    }
    ASSERT(allow_seen);
    ASSERT(uf_value(lines, n, "MemoryMax") != NULL);

    /* No signal to another process: the same uid could otherwise stop or
     * kill the sensor. tgkill with the rest, since it reaches any
     * process (deployment.md §6). Each name on a deny ('~') line. */
    static const char *const sigs[] = {
        "kill", "tkill", "tgkill", "rt_sigqueueinfo", "rt_tgsigqueueinfo",
        "pidfd_send_signal",
    };
    for (size_t s = 0; s < sizeof(sigs) / sizeof(sigs[0]); s++) {
        int denied = 0;
        for (int i = 0; i < n; i++) {
            const char *l = lines[i];
            while (*l == ' ' || *l == '\t') l++;
            if (strncmp(l, "SystemCallFilter=~", 18) == 0 &&
                uf_has_token(l + 18, sigs[s])) denied = 1;
        }
        if (!denied)
            fprintf(stderr, "    slothweb unit: %s not denied\n", sigs[s]);
        ASSERT(denied);
    }

    /* The sensor's directory: read-only, and never this unit's state
     * directory, which systemd would chown and chmod on every start.
     * The '-' so a host whose sensor never started (no /var/lib/sloth)
     * still starts slothweb rather than failing 226/NAMESPACE. */
    ASSERT(uf_has_token(uf_value(lines, n, "ReadOnlyPaths"), "-/var/lib/sloth"));
    for (int i = 0; i < n; i++) {
        const char *l = lines[i];
        while (*l == ' ' || *l == '\t') l++;
        if (strncmp(l, "ReadWritePaths=", 15) == 0) {
            if (uf_path_under(l + 15, "/var/lib/sloth"))
                fprintf(stderr, "    slothweb unit: %s\n", l);
            ASSERT(!uf_path_under(l + 15, "/var/lib/sloth"));
        }
    }
    ASSERT(!uf_has_token(uf_value(lines, n, "StateDirectory"), "sloth"));
    free(buf);
}

static void test_web_unit_execstart(void) {
    char *buf = uf_slurp(UF_PATH_WEB_UNIT);
    char *doc = uf_slurp(UF_PATH_WIKI);
    ASSERT(buf != NULL);
    ASSERT(doc != NULL);
    if (!buf || !doc) { free(buf); free(doc); return; }
    char *lines[UF_MAX_LINES];
    int n = uf_logical_lines(buf, lines, UF_MAX_LINES);
    const char *start = uf_value(lines, n, "ExecStart");
    ASSERT(start != NULL);
    ASSERT_EQ(uf_count(lines, n, "ExecStart"), 1);
    if (start) {
        ASSERT(strncmp(start, "/usr/local/bin/slothweb ", 24) == 0);
        ASSERT(strstr(start, "--socket unix:/run/sloth/sloth.sock") != NULL);
        ASSERT(strstr(start, "--sloth-db /var/lib/sloth/sloth.db") != NULL);
        ASSERT(strstr(start, "--store /var/lib/slothweb/slothweb.db") != NULL);
        ASSERT(uf_has_token(start, "$SLOTHWEB_ARGS"));
        /* Loopback unless the site's file says otherwise: the unit
         * itself never widens the bind or the peer list. */
        ASSERT(!uf_has_token(start, "--web-bind"));
        ASSERT(!uf_has_token(start, "--web-allow-remote"));
        ASSERT(!uf_has_token(start, "--web-allow"));
        ASSERT(!uf_has_token(start, "--web-allow-sql"));
        /* The deployment page names every flag the unit runs with. */
        static const char *const flags[] = { "--socket", "--sloth-db", "--store" };
        for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
            if (!uf_doc_names_flag(doc, flags[i]))
                fprintf(stderr, "    %s does not name slothweb flag %s\n",
                        UF_PATH_WIKI, flags[i]);
            ASSERT(uf_doc_names_flag(doc, flags[i]));
        }
    }
    ASSERT(strstr(doc, "slothweb.service") != NULL);
    ASSERT(strstr(doc, "--data-socket-unix") != NULL);
    ASSERT(strstr(doc, "--with-slothweb") != NULL);
    free(buf);
    free(doc);
}

/* An IPv4 literal at p (four dotted octets, not inside a longer token):
 * its length, or 0. */
static size_t uf_ipv4_at(const char *p, unsigned char o[4]) {
    const char *q = p;
    for (int k = 0; k < 4; k++) {
        if (!isdigit((unsigned char)*q)) return 0;
        unsigned v = 0;
        int d = 0;
        while (isdigit((unsigned char)*q) && d < 4) { v = v * 10 + (unsigned)(*q - '0'); q++; d++; }
        if (v > 255 || d > 3) return 0;
        o[k] = (unsigned char)v;
        if (k < 3) { if (*q != '.') return 0; q++; }
    }
    if (isdigit((unsigned char)*q) || *q == '.') return 0;
    return (size_t)(q - p);
}

static void test_web_defaults_file(void) {
    char *buf = uf_slurp(UF_PATH_WEB_DEFAULTS);
    ASSERT(buf != NULL);
    if (!buf) return;
    char *copy = strdup(buf);
    ASSERT(copy != NULL);
    int args = 0, live_remote = 0, ex_remote = 0, ex_allow32 = 0;
    if (copy) {
        for (char *l = strtok(copy, "\n"); l; l = strtok(NULL, "\n")) {
            while (*l == ' ' || *l == '\t') l++;
            if (*l == '#') {
                if (strstr(l, "--web-allow-remote")) ex_remote++;
                if (strstr(l, "--web-allow ") && strstr(l, "/32")) ex_allow32++;
                continue;
            }
            if (*l == '\0') continue;
            ASSERT(strchr(l, '=') != NULL);
            ASSERT(strncmp(l, "export ", 7) != 0);
            ASSERT(strstr(l, "$(") == NULL);
            ASSERT(strchr(l, '`') == NULL);
            ASSERT(strchr(l, '"') == NULL);
            if (strncmp(l, "SLOTHWEB_ARGS=", 14) == 0) {
                args++;
                /* Shipped empty: loopback, 127.0.0.1:8770. */
                ASSERT_STR(l + 14, "");
            }
            if (strstr(l, "--web-allow-remote")) live_remote++;
        }
        free(copy);
    }
    ASSERT_EQ(args, 1);
    ASSERT_EQ(live_remote, 0);
    /* The Tailscale recipe is there, commented, with a single /32. */
    ASSERT_GT(ex_remote, 0);
    ASSERT_GT(ex_allow32, 0);
    /* No real host's address: every IPv4 literal is loopback or one of
     * the placeholders in 100.64.0.0/24. Structural, so the test does
     * not have to name the addresses it keeps out. */
    for (const char *p = buf; *p; p++) {
        if (p > buf && (isdigit((unsigned char)p[-1]) || p[-1] == '.')) continue;
        unsigned char o[4];
        size_t k = uf_ipv4_at(p, o);
        if (!k) continue;
        int ok = (o[0] == 127) ||
                 (o[0] == 100 && o[1] == 64 && o[2] == 0) ||
                 (o[0] == 0 && o[1] == 0 && o[2] == 0 && o[3] == 0);
        if (!ok)
            fprintf(stderr, "    %s: %u.%u.%u.%u is not a placeholder\n",
                    UF_PATH_WEB_DEFAULTS, o[0], o[1], o[2], o[3]);
        ASSERT(ok);
        p += k - 1;
    }
    free(buf);
}

static void test_scanner_ipv4_literal(void) {
    unsigned char o[4];
    ASSERT_EQ(uf_ipv4_at("100.64.0.10:8770", o), 11);
    ASSERT(o[0] == 100 && o[1] == 64 && o[2] == 0 && o[3] == 10);
    ASSERT_EQ(uf_ipv4_at("10.1.2", o), 0);
    ASSERT_EQ(uf_ipv4_at("1.2.3.4.5", o), 0);
    ASSERT_EQ(uf_ipv4_at("256.1.1.1", o), 0);
    ASSERT_EQ(uf_ipv4_at("v1.2.3.4", o), 0);
}

/* ── the Makefile side ── */

static int uf_is_recipe(const char *line) { return line[0] == '\t'; }

/* The Makefile is far longer than a unit file and grows with every
 * module; size its scan independently so this test cannot go red for a
 * reason unrelated to the install targets. */
#define UF_MAX_MAKE_LINES 4096

/* ── sloth-ble-scan.service ──
 *
 * The passive-scan holder for --bt-monitor. What has to stay true: it
 * holds CAP_NET_ADMIN and nothing else, reaches AF_BLUETOOTH and
 * nothing else, displaces bluetoothd rather than fighting it, runs
 * inside its sandbox including the step that brings hciN down, lives
 * and dies with the sensor without the sensor depending on it, and is
 * installed but never enabled by make. Each absence below was seen red
 * under a one-line mutation (docs/wiki/log.md, the 2026-10-26
 * sloth-ble-scan entry, names them). */

/* Any directive `key=` carrying `tok` — After= and kin may be given on
 * several lines, and uf_value() reads only the first. */
static int uf_any_has(char *lines[], int n, const char *key, const char *tok) {
    size_t k = strlen(key);
    for (int i = 0; i < n; i++) {
        const char *l = lines[i];
        while (*l == ' ' || *l == '\t') l++;
        if (!uf_is_directive(l)) continue;
        if (strncmp(l, key, k) == 0 && l[k] == '=' && uf_has_token(l + k + 1, tok))
            return 1;
    }
    return 0;
}

static void test_scanner_any_has_reads_every_line(void) {
    char src[] = "[Unit]\nAfter=a.service\nAfter=b.service c.service\n"
                 "# After=d.service\nAfterX=e.service\n";
    char *lines[16];
    int n = uf_logical_lines(src, lines, 16);
    ASSERT(uf_any_has(lines, n, "After", "a.service"));
    ASSERT(uf_any_has(lines, n, "After", "c.service"));
    ASSERT(!uf_any_has(lines, n, "After", "d.service"));
    ASSERT(!uf_any_has(lines, n, "After", "e.service"));
    ASSERT(!uf_any_has(lines, n, "Before", "a.service"));
}

static void test_ble_scan_unit_privilege(void) {
    char *buf = uf_slurp(UF_PATH_BLE_UNIT);
    ASSERT(buf != NULL);
    if (!buf) return;
    ASSERT(strstr(buf, "/home/") == NULL);
    ASSERT(strstr(buf, "ConditionPathExists=") == NULL);
    char *lines[UF_MAX_LINES];
    int n = uf_logical_lines(buf, lines, UF_MAX_LINES);
    ASSERT_GT(n, 0);
    ASSERT_LT(n, UF_MAX_LINES);

    /* A transient uid, not the sloth account that owns the sensor's
     * data. Given once; no User= that could name a real account. */
    ASSERT_STR(uf_req(lines, n, "DynamicUser"), "yes");
    ASSERT_EQ(uf_count(lines, n, "DynamicUser"), 1);
    ASSERT(uf_value(lines, n, "User") == NULL);

    /* Exactly CAP_NET_ADMIN: the kernel's check for HCI_CHANNEL_USER and
     * HCIDEVDOWN. Not CAP_NET_RAW — that is the monitor channel's, and
     * the monitor channel is sloth's. */
    static const char *const allow[] = { "CAP_NET_ADMIN" };
    const char *bound = uf_value(lines, n, "CapabilityBoundingSet");
    const char *amb   = uf_value(lines, n, "AmbientCapabilities");
    if (!uf_tokens_within(bound, allow, 1))
        fprintf(stderr, "    ble-scan unit: CapabilityBoundingSet=%s, want CAP_NET_ADMIN\n",
                bound ? bound : "(absent)");
    ASSERT(uf_tokens_within(bound, allow, 1));
    ASSERT(uf_tokens_within(amb, allow, 1));
    ASSERT(uf_has_token(bound, "CAP_NET_ADMIN"));
    ASSERT(uf_has_token(amb, "CAP_NET_ADMIN"));
    ASSERT_EQ(uf_count(lines, n, "CapabilityBoundingSet"), 1);
    ASSERT_EQ(uf_count(lines, n, "AmbientCapabilities"), 1);
    ASSERT_STR(uf_req(lines, n, "NoNewPrivileges"), "true");
    /* Single-value keys: systemd applies the last assignment, so a
     * second line would override the first one this reads. */
    ASSERT_EQ(uf_count(lines, n, "NoNewPrivileges"), 1);

    /* No account or group membership, and nothing writable: the
     * transient uid is the whole identity and the helper writes no
     * file. */
    static const char *const absent[] = {
        "Group", "SupplementaryGroups", "ReadWritePaths", "BindPaths",
        "StateDirectory", "RuntimeDirectory", "LogsDirectory",
        "CacheDirectory", "ConfigurationDirectory"
    };
    for (size_t i = 0; i < sizeof(absent) / sizeof(absent[0]); i++) {
        if (uf_count(lines, n, absent[i]) != 0)
            fprintf(stderr, "    ble-scan unit: %s= present\n", absent[i]);
        ASSERT_EQ(uf_count(lines, n, absent[i]), 0);
    }

    /* Only the two Exec lines below. Any other Exec key runs a command
     * too, and with a `+` or `!` prefix it runs outside the sandbox with
     * full privilege — what the prefix check on ExecStartPre exists to
     * stop. */
    static const char *const no_exec[] = {
        "ExecStartPost", "ExecStop", "ExecStopPost", "ExecReload",
        "ExecCondition"
    };
    for (size_t i = 0; i < sizeof(no_exec) / sizeof(no_exec[0]); i++) {
        if (uf_count(lines, n, no_exec[i]) != 0)
            fprintf(stderr, "    ble-scan unit: %s= present\n", no_exec[i]);
        ASSERT_EQ(uf_count(lines, n, no_exec[i]), 0);
    }

    /* The installed helper, inside the sandbox, both steps: no `+`,
     * `!` or `-` prefix on either. */
    const char *start = uf_value(lines, n, "ExecStart");
    const char *pre   = uf_value(lines, n, "ExecStartPre");
    ASSERT(start != NULL && strncmp(start, "/usr/local/sbin/sloth-ble-scan ", 31) == 0);
    ASSERT(pre != NULL && strncmp(pre, "/usr/local/sbin/sloth-ble-scan --down ", 38) == 0);
    ASSERT_EQ(uf_count(lines, n, "ExecStart"), 1);
    ASSERT_EQ(uf_count(lines, n, "ExecStartPre"), 1);
    free(buf);
}

static void test_ble_scan_unit_sandbox(void) {
    char *buf = uf_slurp(UF_PATH_BLE_UNIT);
    ASSERT(buf != NULL);
    if (!buf) return;
    char *lines[UF_MAX_LINES];
    int n = uf_logical_lines(buf, lines, UF_MAX_LINES);

    static const struct { const char *key, *val; } want[] = {
        { "ProtectSystem",            "strict"    },
        { "ProtectHome",              "true"      },
        { "PrivateTmp",               "true"      },
        { "PrivateDevices",           "true"      },
        { "ProtectKernelTunables",    "true"      },
        { "ProtectKernelModules",     "true"      },
        { "ProtectKernelLogs",        "true"      },
        { "ProtectControlGroups",     "true"      },
        { "ProtectClock",             "true"      },
        { "ProtectHostname",          "true"      },
        { "ProtectProc",              "invisible" },
        { "RestrictNamespaces",       "true"      },
        { "RestrictRealtime",         "true"      },
        { "RestrictSUIDSGID",         "true"      },
        { "LockPersonality",          "true"      },
        { "MemoryDenyWriteExecute",   "true"      },
        { "SystemCallArchitectures",  "native"    },
        { "SystemCallErrorNumber",    "EPERM"     },
        { "MemoryMax",                "16M"       },
        { "Restart",                  "on-failure" },
        { "KillSignal",               "SIGTERM"   },
    };
    for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
        const char *v = uf_value(lines, n, want[i].key);
        if (!v || strcmp(v, want[i].val) != 0)
            fprintf(stderr, "    ble-scan unit: %s=%s wanted, got %s\n",
                    want[i].key, want[i].val, v ? v : "(absent)");
        ASSERT(v != NULL && strcmp(v, want[i].val) == 0);
        /* Read once and given once: systemd applies the last of a
         * single-value key, so `ProtectSystem=false` appended below
         * would win over the line read above. */
        if (uf_count(lines, n, want[i].key) != 1)
            fprintf(stderr, "    ble-scan unit: %s= given %d times\n",
                    want[i].key, uf_count(lines, n, want[i].key));
        ASSERT_EQ(uf_count(lines, n, want[i].key), 1);
    }

    /* AF_BLUETOOTH and nothing else, given once. */
    static const char *const fams[] = { "AF_BLUETOOTH" };
    const char *fam = uf_value(lines, n, "RestrictAddressFamilies");
    if (!uf_tokens_within(fam, fams, 1))
        fprintf(stderr, "    ble-scan unit: RestrictAddressFamilies=%s, want AF_BLUETOOTH\n",
                fam ? fam : "(absent)");
    ASSERT(uf_tokens_within(fam, fams, 1));
    ASSERT_EQ(uf_count(lines, n, "RestrictAddressFamilies"), 1);

    /* Either would break it rather than harden it: AF_BLUETOOTH exists
     * only in the initial network namespace, and a capability held in a
     * private user namespace does not pass the kernel's check. */
    ASSERT(uf_value(lines, n, "PrivateNetwork") == NULL);
    ASSERT(uf_value(lines, n, "PrivateUsers") == NULL);

    /* The two filter lines and no others. An empty `SystemCallFilter=`
     * resets every line before it, so it is refused wherever it sits. */
    int allow_seen = 0, deny_seen = 0, empty = 0;
    for (int i = 0; i < n; i++) {
        const char *l = lines[i];
        while (*l == ' ' || *l == '\t') l++;
        if (strncmp(l, "SystemCallFilter=", 17) != 0) continue;
        const char *v = l + 17;
        while (*v == ' ' || *v == '\t') v++;
        if (!*v) empty = 1;
        if (uf_has_token(l + 17, "@system-service")) allow_seen = 1;
        if (uf_has_token(l + 17, "~@privileged")) deny_seen = 1;
    }
    ASSERT(allow_seen);
    ASSERT(deny_seen);
    ASSERT(!empty);
    ASSERT_EQ(uf_count(lines, n, "SystemCallFilter"), 2);
    free(buf);
}

/* [Service] is an allow-list, like [Install]: the checks above pin the
 * keys they know, and a key nobody thought to refuse — `DeviceAllow=
 * /dev/mem rw`, `LD_PRELOAD` through Environment=, a `BindPaths=` this
 * test does not list — would otherwise pass every one of them. A new
 * key is added here deliberately, with the reason it is safe. */
static void test_ble_scan_unit_service_keys_are_allow_listed(void) {
    char *buf = uf_slurp(UF_PATH_BLE_UNIT);
    ASSERT(buf != NULL);
    if (!buf) return;
    char *lines[UF_MAX_LINES];
    int n = uf_logical_lines(buf, lines, UF_MAX_LINES);
    static const char *const keys[] = {
        "Type", "DynamicUser", "Environment", "ExecStartPre", "ExecStart",
        "AmbientCapabilities", "CapabilityBoundingSet", "NoNewPrivileges",
        "ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateDevices",
        "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
        "ProtectControlGroups", "ProtectClock", "ProtectHostname",
        "ProtectProc", "ProcSubset", "UMask", "RestrictAddressFamilies",
        "IPAddressDeny", "RestrictNamespaces", "RestrictRealtime",
        "RestrictSUIDSGID", "LockPersonality", "MemoryDenyWriteExecute",
        "SystemCallArchitectures", "SystemCallFilter",
        "SystemCallErrorNumber", "MemoryMax", "TasksMax", "KillSignal",
        "TimeoutStopSec", "Restart", "RestartSec", "RestartPreventExitStatus"
    };
    int in_service = 0, seen = 0, unknown = 0, env = 0;
    for (int i = 0; i < n; i++) {
        const char *l = lines[i];
        while (*l == ' ' || *l == '\t') l++;
        if (*l == '[') { in_service = strncmp(l, "[Service]", 9) == 0; continue; }
        if (!in_service || !uf_is_directive(l)) continue;
        seen++;
        size_t k = (size_t)(strchr(l, '=') - l);
        int ok = 0;
        for (size_t j = 0; j < sizeof(keys) / sizeof(keys[0]); j++)
            if (strlen(keys[j]) == k && strncmp(l, keys[j], k) == 0) ok = 1;
        if (!ok) {
            fprintf(stderr, "    ble-scan unit: [Service] key not allowed: %s\n", l);
            unknown++;
        }
        /* The one variable is the controller's name. Anything else in
         * the helper's environment (LD_PRELOAD, LD_LIBRARY_PATH) runs
         * code inside the CAP_NET_ADMIN process before main(). */
        if (strncmp(l, "Environment=", 12) == 0) {
            env++;
            const char *v = l + 12;
            if (strncmp(v, "SLOTH_BLE_HCI=", 14) != 0 || strchr(v, ' ') || strchr(v, '\t')) {
                fprintf(stderr, "    ble-scan unit: %s\n", l);
                unknown++;
            }
        }
    }
    ASSERT_GT(seen, 0);
    ASSERT_EQ(unknown, 0);
    ASSERT_EQ(env, 1);
    free(buf);
}

static void test_ble_scan_unit_relationships(void) {
    char *buf = uf_slurp(UF_PATH_BLE_UNIT);
    ASSERT(buf != NULL);
    if (!buf) return;
    char *lines[UF_MAX_LINES];
    int n = uf_logical_lines(buf, lines, UF_MAX_LINES);

    /* bluetoothd holds the controller; the user channel is refused while
     * it does. */
    ASSERT(uf_any_has(lines, n, "Conflicts", "bluetooth.service"));
    /* After the sensor, so sloth sees the Reset and the parameters;
     * PartOf it, so it lives as long as the sensor; pulled in by the
     * sensor once enabled. */
    ASSERT(uf_any_has(lines, n, "After", "sloth-sensor.service"));
    ASSERT(uf_any_has(lines, n, "PartOf", "sloth-sensor.service"));
    ASSERT(uf_any_has(lines, n, "WantedBy", "sloth-sensor.service"));
    /* Not started on its own — at boot, or with bluetooth.target, or
     * by anything but the sensor — and never ordered before the sensor.
     * [Install] is an allow-list: every WantedBy= line names only the
     * sensor, and nothing else installs a link to the unit. */
    static const char *const by[] = { "sloth-sensor.service" };
    int wb = 0;
    for (int i = 0; i < n; i++) {
        const char *l = lines[i];
        while (*l == ' ' || *l == '\t') l++;
        if (!uf_is_directive(l) || strncmp(l, "WantedBy=", 9) != 0) continue;
        wb++;
        if (!uf_tokens_within(l + 9, by, 1))
            fprintf(stderr, "    ble-scan unit: %s\n", l);
        ASSERT(uf_tokens_within(l + 9, by, 1));
    }
    ASSERT_GE(wb, 1);
    static const char *const no_install[] = {
        "RequiredBy", "UpheldBy", "Alias", "Also", "DefaultInstance"
    };
    for (size_t i = 0; i < sizeof(no_install) / sizeof(no_install[0]); i++) {
        if (uf_count(lines, n, no_install[i]) != 0)
            fprintf(stderr, "    ble-scan unit: %s= present\n", no_install[i]);
        ASSERT_EQ(uf_count(lines, n, no_install[i]), 0);
    }
    ASSERT(!uf_any_has(lines, n, "Before", "sloth-sensor.service"));
    free(buf);

    /* The sensor must start without it: nothing in the sensor's unit
     * requires, binds to or waits on the scan. */
    char *sb = uf_slurp(UF_PATH_UNIT);
    ASSERT(sb != NULL);
    if (!sb) return;
    char *sl[UF_MAX_LINES];
    int sn = uf_logical_lines(sb, sl, UF_MAX_LINES);
    static const char *const deps[] = {
        "Requires", "Requisite", "BindsTo", "Wants", "After", "Upholds"
    };
    for (size_t i = 0; i < sizeof(deps) / sizeof(deps[0]); i++) {
        if (uf_any_has(sl, sn, deps[i], "sloth-ble-scan.service"))
            fprintf(stderr, "    sensor unit: %s=sloth-ble-scan.service\n", deps[i]);
        ASSERT(!uf_any_has(sl, sn, deps[i], "sloth-ble-scan.service"));
    }
    free(sb);
}

/* The opt-in drop-in that gives the sensor AF_BLUETOOTH for
 * --bt-monitor: one [Service] directive, the family and nothing else —
 * not a deny list (`~`), not a reset (empty), not any other key. */
static void test_sensor_bt_monitor_dropin(void) {
    char *buf = uf_slurp(UF_PATH_BT_DROPIN);
    ASSERT(buf != NULL);
    if (!buf) return;
    char *lines[UF_MAX_LINES];
    int n = uf_logical_lines(buf, lines, UF_MAX_LINES);
    int directives = 0, sections = 0, service = 0;
    for (int i = 0; i < n; i++) {
        const char *l = lines[i];
        while (*l == ' ' || *l == '\t') l++;
        if (*l == '[') {
            sections++;
            if (strcmp(l, "[Service]") == 0) service = 1;
        }
        if (uf_is_directive(l)) directives++;
    }
    ASSERT_EQ(sections, 1);
    ASSERT(service);
    ASSERT_EQ(directives, 1);
    const char *fam = uf_value(lines, n, "RestrictAddressFamilies");
    ASSERT(fam != NULL && strcmp(fam, "AF_BLUETOOTH") == 0);
    free(buf);
}

/* make installs the helper and the unit, and enables nothing: taking
 * the controller from bluetoothd is the operator's decision. Recipe
 * lines only; the closing @echo hints may name systemctl. */
static void test_makefile_installs_ble_scan_without_enabling(void) {
    char *buf = uf_slurp("Makefile");
    ASSERT(buf != NULL);
    if (!buf) return;
    static char *lines[UF_MAX_MAKE_LINES];
    int n = uf_logical_lines(buf, lines, UF_MAX_MAKE_LINES);
    int in_install = 0, in_service = 0, bin = 0, unit = 0, enables = 0;
    int dropin = 0, active_dropin = 0;
    for (int i = 0; i < n; i++) {
        const char *l = lines[i];
        if (!uf_is_recipe(l)) {
            in_install = strncmp(l, "install:", 8) == 0;
            in_service = strncmp(l, "install-service:", 16) == 0;
            if (in_install) ASSERT(strstr(l, "$(BLE_SCAN_BIN)") != NULL);
            continue;
        }
        if (in_install && strstr(l, "install -m 755 sloth-ble-scan ") &&
            strstr(l, "[ -z \"$(BLE_SCAN_BIN)\" ] ||") &&
            strstr(l, "$(DESTDIR)$(PREFIX)/sbin/sloth-ble-scan")) bin = 1;
        if (in_service && strstr(l, "packaging/systemd/sloth-ble-scan.service")) unit = 1;
        /* The sensor's AF_BLUETOOTH drop-in goes to share/sloth, inert;
         * placed in sloth-sensor.service.d/ it would give every sensor
         * the family. */
        if (in_service && strstr(l, "sloth-sensor.service.d/bt-monitor.conf") &&
            strstr(l, "$(DESTDIR)$(PREFIX)/share/sloth/sloth-sensor-bt-monitor.conf"))
            dropin = 1;
        if ((in_install || in_service) && strstr(l, ".service.d")) {
            const char *u = strstr(l, "$(UNITDIR)");
            if (u && strstr(u, ".service.d")) {
                fprintf(stderr, "    Makefile installs a drop-in into the unit dir: %s\n", l);
                active_dropin = 1;
            }
        }
        if ((in_install || in_service) && strncmp(l, "\t@echo", 6) != 0 &&
            strstr(l, "systemctl")) {
            fprintf(stderr, "    Makefile install recipe runs systemctl: %s\n", l);
            enables = 1;
        }
    }
    ASSERT(bin);
    ASSERT(unit);
    ASSERT(!enables);
    ASSERT(dropin);
    ASSERT(!active_dropin);
    free(buf);
}

static void test_makefile_install_targets(void) {
    char *buf = uf_slurp("Makefile");
    ASSERT(buf != NULL);
    if (!buf) return;
    static char *lines[UF_MAX_MAKE_LINES];
    int n = uf_logical_lines(buf, lines, UF_MAX_MAKE_LINES);
    ASSERT_LT(n, UF_MAX_MAKE_LINES);

    int in_install = 0, in_service = 0;
    int inst_bin = 0, inst_helper = 0, inst_db = 0, inst_web = 0;
    int inst_web_fresh = 0;
    int svc_unit = 0, svc_sysusers = 0, svc_defaults_nc = 0, svc_defaults_b = 0;
    int svc_web_unit = 0, svc_web_defaults_nc = 0, svc_web_defaults_b = 0;
    int recipes_seen = 0;
    for (int i = 0; i < n; i++) {
        const char *l = lines[i];
        if (!uf_is_recipe(l)) {
            in_install = strncmp(l, "install:", 8) == 0;
            in_service = strncmp(l, "install-service:", 16) == 0;
            continue;
        }
        if (!in_install && !in_service) continue;
        recipes_seen++;
        /* Nothing make installs may create an account. That is
         * systemd-sysusers' job, from the fragment, after install. */
        ASSERT(strstr(l, "useradd") == NULL);
        ASSERT(strstr(l, "adduser") == NULL);
        ASSERT(strstr(l, "groupadd") == NULL);
        /* Every `install` must honour DESTDIR so CI can stage into a
         * scratch root. Only the recipe lines that invoke install(1). */
        if (strncmp(l, "\tinstall ", 9) == 0)
            ASSERT(strstr(l, "$(DESTDIR)") != NULL);
        if (in_install) {
            if (strstr(l, "$(TARGET)") && strstr(l, "/bin/")) inst_bin = 1;
            if (strstr(l, "packaging/bin/sloth-monitor-up") && strstr(l, "/sbin/")) inst_helper = 1;
            if (strstr(l, "research.db") && strstr(l, "/share/sloth/")) inst_db = 1;
            if (strstr(l, "install -m 755 slothweb ") && strstr(l, "/bin/slothweb")) inst_web = 1;
            /* An old ./slothweb is refused, not installed beside a new
             * unit and UI: its sources and the Makefile are its inputs. */
            if (strstr(l, "find web/src web/ui ") && strstr(l, " -newer slothweb") &&
                strstr(l, "exit 1")) inst_web_fresh = 1;
        }
        if (in_service) {
            if (strstr(l, "sloth-sensor.service")) svc_unit = 1;
            if (strstr(l, "sloth.sysusers.conf")) svc_sysusers = 1;
            /* No-clobber, like slothweb's below: /etc/default/sloth is
             * the site's SLOTH_ARGS, and `install -b` replaced it with
             * the stock file (the edit survived only as sloth~). */
            if (strstr(l, "packaging/default/sloth ")) {
                if (strstr(l, "[ -e $(DESTDIR)$(DEFAULTDIR)/sloth ] ||"))
                    svc_defaults_nc = 1;
                if (strstr(l, "install -b")) svc_defaults_b = 1;
            }
            if (strstr(l, "packaging/systemd/slothweb.service")) svc_web_unit = 1;
            /* No-clobber: installed only behind a test that none is
             * there, and never with a backup that would let make
             * replace an operator's bind and peers. */
            if (strstr(l, "packaging/default/slothweb")) {
                if (strstr(l, "[ -e $(DESTDIR)$(DEFAULTDIR)/slothweb ] ||"))
                    svc_web_defaults_nc = 1;
                if (strstr(l, "install -b")) svc_web_defaults_b = 1;
            }
        }
    }
    ASSERT_GT(recipes_seen, 0);
    /* `install`: what the unit's ExecStart/ExecStartPre reference. */
    ASSERT(inst_bin);
    ASSERT(inst_helper);
    ASSERT(inst_db);
    ASSERT(inst_web);
    ASSERT(inst_web_fresh);
    /* `install-service`: the unit, the account declaration, and each
     * defaults file only where there is none, never over an edit. */
    ASSERT(svc_unit);
    ASSERT(svc_sysusers);
    ASSERT(svc_defaults_nc);
    ASSERT(!svc_defaults_b);
    ASSERT(svc_web_unit);
    ASSERT(svc_web_defaults_nc);
    ASSERT(!svc_web_defaults_b);
    free(buf);
}

void run_unit_file_tests(void) {
    TEST_SUITE("shipped systemd unit (#139)");
    RUN_TEST(test_scanner_directive_lookup_is_exact);
    RUN_TEST(test_scanner_tokens_are_whole_words);
    RUN_TEST(test_scanner_doc_flag_match_needs_a_boundary);
    RUN_TEST(test_scanner_ipv4_literal);
    RUN_TEST(test_unit_runs_as_the_sloth_account);
    RUN_TEST(test_unit_executes_installed_paths_only);
    RUN_TEST(test_unit_capabilities_are_exactly_the_two);
    RUN_TEST(test_unit_sandbox_keys_present);
    RUN_TEST(test_unit_flag_pairs_are_consistent);
    RUN_TEST(test_deployment_page_names_every_execstart_flag);
    RUN_TEST(test_sysusers_fragment_declares_a_system_account);
    RUN_TEST(test_monitor_up_helper_is_idempotent_and_root_side);
    RUN_TEST(test_defaults_file_is_an_environment_file);
    RUN_TEST(test_web_unit_runs_as_sloth_with_no_capabilities);
    RUN_TEST(test_web_unit_sandbox);
    RUN_TEST(test_web_unit_execstart);
    RUN_TEST(test_web_defaults_file);
    RUN_TEST(test_makefile_install_targets);
    RUN_TEST(test_scanner_any_has_reads_every_line);
    RUN_TEST(test_sensor_bt_monitor_dropin);
    RUN_TEST(test_ble_scan_unit_privilege);
    RUN_TEST(test_ble_scan_unit_sandbox);
    RUN_TEST(test_ble_scan_unit_service_keys_are_allow_listed);
    RUN_TEST(test_ble_scan_unit_relationships);
    RUN_TEST(test_makefile_installs_ble_scan_without_enabling);
}
