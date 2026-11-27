/* contract_parity: the facts a presentation repository's tests hold its
 * page to, written from this tree into the contract's parity/ directory
 * (docs/wiki/contract.md, "parity/"; #184 Stage 3, sloth#233). slothweb's
 * suite read them out of src/ and include/ while it lived here; in
 * sloth-mesh it may not reach into this tree, so the contract carries
 * them as data instead of as source.
 *
 *   contract_parity constants          parity/constants.tsv
 *   contract_parity akm                parity/akm-names.tsv
 *   contract_parity ipcolor            parity/ip-color.tsv
 *   contract_parity literals LIST      parity/literals.tsv
 *   contract_parity pins LIST          parity/pins.tsv
 *   contract_parity fires FILE...      parity/fire-sites.tsv
 *
 * Each writes to stdout. constants are the values of sloth.h's macros
 * and enumerators the page mirrors, compiled in, not parsed; akm is
 * rsn_akm_name() for all 256 suite types; ipcolor is ip_color_index()
 * over a fixed, generated set of keys (every single byte, the cases the
 * page's tests use, and pseudo-random strings), so a port of the hash is
 * held to the real one; literals are every C string literal of the files
 * LIST names (tests/contract/literals.txt), as written in the source; and
 * pins are tests/contract/pins.tsv after each text is found in the file
 * it names (a pin that no longer holds fails the build here, so a change
 * to the TUI's words reaches the page's tests as a contract change); and
 * fires are the fire*(ALERT_TYPE_<kind>, <severity>, ...) calls of the
 * rule files named, with the severity argument as written, which the
 * page's rule table is held to.
 *
 * TSV fields escape a backslash, a tab and a newline as \\, \t and \n;
 * nothing else. Build time only; it opens the files it is named. */
#include <glob.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sloth.h"
#include "ip_color.h"
#include "rsn_ie.h"
#include "probe_hist.h"
#include "db.h"

#define FILE_MAX (4 * 1024 * 1024)

static void tsv(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '\\') fputs("\\\\", stdout);
        else if (c == '\t') fputs("\\t", stdout);
        else if (c == '\n') fputs("\\n", stdout);
        else putchar(c);
    }
}

static size_t untsv(const char *s, char *out) {
    size_t k = 0;
    for (; *s; s++) {
        if (*s == '\\' && s[1]) {
            s++;
            out[k++] = *s == 't' ? '\t' : *s == 'n' ? '\n' : *s;
        } else {
            out[k++] = *s;
        }
    }
    out[k] = '\0';
    return k;
}

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "contract_parity: cannot open %s\n", path); return NULL; }
    char *b = malloc(FILE_MAX);
    size_t n = b ? fread(b, 1, FILE_MAX - 1, f) : 0;
    fclose(f);
    if (!b || n >= FILE_MAX - 1) {
        fprintf(stderr, "contract_parity: %s unreadable or too large\n", path);
        free(b);
        return NULL;
    }
    b[n] = '\0';
    return b;
}

/* ── constants ─────────────────────────────────────────────────────── */

static int constants(void) {
    puts("# sloth's constants the page mirrors, compiled from include/sloth.h,");
    puts("# src/ip_color.h, src/probe_hist.h and src/db.h by tools/contract_parity.c");
    puts("# (not parsed out of the text).");
    puts("name\tvalue");
#define C(x) printf("%s\t%lld\n", #x, (long long)(x))
    C(DEV_SRC_ARP); C(DEV_SRC_DHCP); C(DEV_SRC_MDNS); C(DEV_SRC_BEACON);
    C(DEV_SRC_PROBE); C(DEV_SRC_STA); C(DEV_SRC_CAMERA);
    C(DEV_RISK_RANDOM_MAC); C(DEV_RISK_UNKNOWN_VENDOR); C(DEV_RISK_NO_HOSTNAME);
    C(DEV_RISK_PROBE_ONLY); C(DEV_RISK_CLEARTEXT_CRED); C(DEV_RISK_ALERT_TAGGED);
    C(DEV_RISK_SELF);
    C(DEV_RISK_LOW); C(DEV_RISK_MED); C(DEV_RISK_HIGH); C(DEV_RISK_CRIT);
    C(CH_SRC_HE_6GHZ);
    C(WPA_DG_TRANSITION_SAE_PSK); C(WPA_DG_OWE_TRANSITION);
    C(WPA_DG_MFP_OPTIONAL); C(WPA_DG_WPA1_ALONGSIDE);
    C(MAX_BLE_DEVICES); C(BLE_DEV_NAME_MAX);
    C(IP_NUM_COLORS);
    C(IP_SRC_CONN); C(IP_SRC_PKT); C(IP_SRC_ARP); C(IP_SRC_DNS);
    C(IP_SRC_ICMP); C(IP_SRC_ALERT); C(IP_SRC_DEV);
    /* sloth.db's probe_history (schema v23): the bucket width a reader
     * steps by, the keys a bucket holds at most, and how stale the open
     * bucket's rows can be. */
    C(PROBE_HIST_BUCKET_S); C(PROBE_HIST_BUCKET_KEYS); C(DB_PROBE_HIST_FLUSH_S);
#undef C
    return ferror(stdout) ? 1 : 0;
}

/* ── akm ───────────────────────────────────────────────────────────── */

static int akm(void) {
    puts("# src/rsn_ie.c rsn_akm_name(t) for every suite type t, by tools/contract_parity.c.");
    puts("t\tname");
    for (int t = 0; t < 256; t++) {
        const char *n = rsn_akm_name((uint8_t)t);
        printf("%d\t", t);
        tsv(n ? n : "", n ? strlen(n) : 0);
        putchar('\n');
    }
    return ferror(stdout) ? 1 : 0;
}

/* ── ipcolor ───────────────────────────────────────────────────────── */

static void vec(const char *key) {
    tsv(key, strlen(key));
    printf("\t%d\n", ip_color_index(key));
}

static int ipcolor(void) {
    /* The page colours addresses, SSIDs and table keys by this hash; its
     * tests compare against it on their own cases, which are among these. */
    static const char *const CASES[] = {
        "10.0.0.1", "10.0.0.2", "192.168.1.1", "192.168.1.254", "172.16.0.10",
        "198.51.100.7", "203.0.113.42", "8.8.8.8", "1.1.1.1", "127.0.0.1",
        "0.0.0.0", "255.255.255.255", "2001:db8::1", "fe80::1c2b:3cff:fe4d:5e6f",
        "::1", "2001:db8:cafe::ab:1234", "::ffff:192.0.2.1", "100.64.0.9",
        "home-net", "CoffeeShop_Guest", "xfinitywifi", "eduroam", "DIRECT-ab-HP",
        "demo", "demo\xff", "demo\xff-x", "demo\xef\xbf\xbd", "02:00:00:00:00:12",
        "Caf\xc3\xa9 Wi-Fi", "\xe2\x98\x95 espresso", "\xf0\x9f\x93\xb6 signal",
    };
    puts("# src/ip_color.c ip_color_index(key) over a fixed set of keys, by");
    puts("# tools/contract_parity.c: the empty key, every single byte but NUL,");
    puts("# the page tests' own cases, and 512 pseudo-random byte strings.");
    puts("key\tindex");
    vec("");
    for (int b = 1; b < 256; b++) {
        char k[2] = { (char)b, 0 };
        vec(k);
    }
    for (size_t i = 0; i < sizeof(CASES) / sizeof(CASES[0]); i++) vec(CASES[i]);
    uint32_t x = 2463534242u;   /* xorshift32: the same keys on every host */
    for (int i = 0; i < 512; i++) {
        char k[48];
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        int len = 1 + (int)(x % 40);
        for (int j = 0; j < len; j++) {
            x ^= x << 13; x ^= x >> 17; x ^= x << 5;
            k[j] = (char)(1 + x % 255);
        }
        k[len] = '\0';
        vec(k);
    }
    return ferror(stdout) ? 1 : 0;
}

/* ── literals ──────────────────────────────────────────────────────── */

/* Every "..." literal of [p, e), comments and character constants
 * skipped, each written as its source text between the quotes. */
static void literals_of(const char *key, const char *p, const char *e) {
    while (p < e) {
        if (p[0] == '/' && p + 1 < e && p[1] == '*') {
            const char *c = strstr(p + 2, "*/");
            p = c ? c + 2 : e;
        } else if (p[0] == '/' && p + 1 < e && p[1] == '/') {
            const char *c = strchr(p, '\n');
            p = c ? c : e;
        } else if (*p == '\'') {
            for (p++; p < e && *p != '\''; p++)
                if (*p == '\\') p++;
            p++;
        } else if (*p == '"') {
            const char *s = ++p;
            for (; p < e && *p != '"'; p++)
                if (*p == '\\') p++;
            printf("%s\t", key);
            tsv(s, (size_t)(p - s));
            putchar('\n');
            p++;
        } else {
            p++;
        }
    }
}

/* LIST: one source per line, "PATH" for the whole file (a glob pattern
 * for every file it names, in glob order, under the pattern), or
 * "PATH<TAB>KEY<TAB>AFTER<TAB>FROM" for the literals from the first FROM
 * after the first AFTER up to the next "};", written under KEY. */
static int literals(const char *list) {
    char *l = slurp(list);
    if (!l) return 1;
    puts("# Every C string literal of the files tests/contract/literals.txt names,");
    puts("# as written between the quotes, by tools/contract_parity.c.");
    puts("path\tliteral");
    int rc = 0;
    char *save = NULL;
    for (char *line = strtok_r(l, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        if (*line == '#' || !*line) continue;
        char *f[4] = { line, NULL, NULL, NULL };
        int nf = 1;
        for (char *q = line; *q && nf < 4; q++)
            if (*q == '\t') { *q = '\0'; f[nf++] = q + 1; }
        if (nf == 1) {
            /* A whole file, or every file a pattern names, under the
             * line as written. */
            glob_t g;
            if (glob(f[0], 0, NULL, &g) != 0 || g.gl_pathc == 0) {
                fprintf(stderr, "contract_parity: %s names no file\n", f[0]);
                rc = 1;
                break;
            }
            for (size_t i = 0; i < g.gl_pathc && !rc; i++) {
                char *one = slurp(g.gl_pathv[i]);
                if (!one) { rc = 1; break; }
                literals_of(f[0], one, one + strlen(one));
                free(one);
            }
            globfree(&g);
            if (rc) break;
            continue;
        }
        char *src = slurp(f[0]);
        if (!src) { rc = 1; break; }
        if (nf == 4) {
            const char *a = strstr(src, f[2]);
            const char *b = a ? strstr(a, f[3]) : NULL;
            const char *e = b ? strstr(b, "};") : NULL;
            if (!e) {
                fprintf(stderr, "contract_parity: %s has no %s ... %s ... }; region\n", f[0], f[2], f[3]);
                free(src);
                rc = 1;
                break;
            }
            literals_of(f[1], b + strlen(f[3]), e);
        } else {
            fprintf(stderr, "contract_parity: %s: a line of %d fields\n", list, nf);
            free(src);
            rc = 1;
            break;
        }
        free(src);
    }
    free(l);
    return rc || ferror(stdout) ? 1 : 0;
}

/* ── pins ──────────────────────────────────────────────────────────── */

/* Each row's text must occur in the file PATH names; a PATH with a glob
 * character matches when any file it names holds the text. */
static int pins(const char *list) {
    char *l = slurp(list);
    if (!l) return 1;
    int rc = 0, rows = 0, head = 0;
    static char want[64 * 1024];
    char *save = NULL;
    for (char *line = strtok_r(l, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        if (*line == '#') { puts(line); continue; }
        if (!head) {
            if (strcmp(line, "path\ttext")) {
                fprintf(stderr, "contract_parity: %s: header is not path<TAB>text\n", list);
                rc = 1;
                break;
            }
            puts(line);
            head = 1;
            continue;
        }
        char *tab = strchr(line, '\t');
        if (!tab || strchr(tab + 1, '\t') || strlen(tab + 1) >= sizeof(want)) {
            fprintf(stderr, "contract_parity: %s: a row is not path<TAB>text\n", list);
            rc = 1;
            break;
        }
        *tab = '\0';
        untsv(tab + 1, want);
        glob_t g;
        int found = 0;
        if (glob(line, 0, NULL, &g) == 0) {
            for (size_t i = 0; i < g.gl_pathc && !found; i++) {
                char *src = slurp(g.gl_pathv[i]);
                found = src && strstr(src, want) != NULL;
                free(src);
            }
            globfree(&g);
        }
        if (!found) {
            fprintf(stderr, "contract_parity: pin no longer holds: %s does not contain \"%s\"\n",
                    line, tab + 1);
            rc = 1;
            continue;
        }
        printf("%s\t%s\n", line, tab + 1);
        rows++;
    }
    free(l);
    if (!rc && rows == 0) { fprintf(stderr, "contract_parity: %s pins nothing\n", list); rc = 1; }
    return rc || ferror(stdout) ? 1 : 0;
}

/* ── fires ─────────────────────────────────────────────────────────── */

/* Every fire*(ALERT_TYPE_<kind>, <arg> call: the word "fire" not after
 * a lower-case letter or '_', any lower-case suffix, then
 * "(ALERT_TYPE_"; <arg> runs to the next ',' or ')' at depth 0. The
 * reading slothweb's test_alertkb.c made of src/alerts/ when it lived
 * in this tree, unchanged. */
static int fires(int n, char **files) {
    puts("# The fire*() calls of src/alerts/, with the severity argument as");
    puts("# written, by tools/contract_parity.c.");
    puts("file\tkind\tsev");
    int rows = 0;
    for (int f = 0; f < n; f++) {
        char *src = slurp(files[f]);
        if (!src) return 1;
        for (char *p = src; (p = strstr(p, "fire")) != NULL; p++) {
            if (p > src && ((p[-1] >= 'a' && p[-1] <= 'z') || p[-1] == '_')) continue;
            char *q = p + 4;
            while ((*q >= 'a' && *q <= 'z') || *q == '_') q++;
            if (strncmp(q, "(ALERT_TYPE_", 12) != 0) continue;
            const char *a = q + 12, *e = a;
            while ((*e >= 'A' && *e <= 'Z') || (*e >= '0' && *e <= '9') || *e == '_') e++;
            if (*e != ',' || e - a >= 96) continue;
            const char *b = e + 1, *z = b;
            int depth = 0;
            for (; *z && !(depth == 0 && (*z == ',' || *z == ')')); z++) {
                if (*z == '(') depth++;
                if (*z == ')') depth--;
            }
            size_t al = (size_t)(z - b) < 255 ? (size_t)(z - b) : 255;
            printf("%s\t%.*s\t", files[f], (int)(e - a), a);
            tsv(b, al);
            putchar('\n');
            rows++;
        }
        free(src);
    }
    if (rows == 0) { fprintf(stderr, "contract_parity: no fire() site\n"); return 1; }
    return ferror(stdout) ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "constants")) return constants();
    if (argc == 2 && !strcmp(argv[1], "akm")) return akm();
    if (argc == 2 && !strcmp(argv[1], "ipcolor")) return ipcolor();
    if (argc == 3 && !strcmp(argv[1], "literals")) return literals(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "pins")) return pins(argv[2]);
    if (argc >= 3 && !strcmp(argv[1], "fires")) return fires(argc - 2, argv + 2);
    fprintf(stderr, "usage: contract_parity constants | akm | ipcolor | literals LIST | pins LIST | fires FILE...\n");
    return 2;
}
