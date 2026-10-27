/* The detail audit (web_alertfmt.h), held to sloth's own source on
 * every run: src/alerts/ is read as text, every fire(), fire_conf(),
 * fire_ev() and fire_inv() call is found with its type and its detail
 * argument, and each snprintf() into that detail inside the enclosing
 * function, before the call, is parsed: its format's conversions are
 * matched to their arguments, and every %s argument must be a string
 * literal, a ternary of them, or a variable named in
 * web_alert_fmt_names[] (or the row's own extra names), and never one
 * named for a username, credential, community, cookie or free text.
 * Every other appearance of the detail variable in that function fails
 * the type: the audit accepts only its declaration (char var[...];),
 * sizeof and strlen of it, the first argument of an snprintf() it then
 * checks, and the fire() argument itself. So a write through an alias
 * (char *w = detail;), a helper given the detail as any argument, an
 * assignment by index, a strcat or memcpy are all refused, rather than
 * read as harmless.
 *
 * A listed type that fails, or that has no fire() site at all, fails
 * the suite and names itself. The credential-bearing types are held off
 * the list, and the checker is seen to refuse them, so a checker that
 * passed everything would fail here. Runs from the top of the tree, as
 * the suite does. */
#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_alertfmt.h"
#include "web_alertkb.h"
#include "wtest.h"

#define SRC_MAX (1 << 20)
#define ARGS_MAX 16

typedef struct {
    char  path[300];
    char *text;              /* comments blanked, strings kept */
} srcf_t;

static srcf_t g_src[32];
static int    g_nsrc;

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *b = malloc(SRC_MAX + 1);
    size_t n = b ? fread(b, 1, SRC_MAX, f) : 0;
    fclose(f);
    if (!b) return NULL;
    b[n] = '\0';
    return b;
}

/* Comments to spaces (newlines kept), strings and chars left whole. */
static void blank_comments(char *s) {
    for (char *p = s; *p; p++) {
        if (*p == '"' || *p == '\'') {
            char q = *p;
            for (p++; *p && *p != q; p++)
                if (*p == '\\' && p[1]) p++;
            if (!*p) return;
        } else if (p[0] == '/' && p[1] == '*') {
            for (; *p && !(p[0] == '*' && p[1] == '/'); p++)
                if (*p != '\n') *p = ' ';
            if (!*p) return;
            p[0] = ' ';
            p[1] = ' ';
            p++;
        } else if (p[0] == '/' && p[1] == '/') {
            for (; *p && *p != '\n'; p++) *p = ' ';
            if (!*p) return;
        }
    }
}

static void load(void) {
    if (g_nsrc) return;
    DIR *d = opendir("src/alerts");
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && g_nsrc < 32) {
        size_t l = strlen(e->d_name);
        if (l < 3 || strcmp(e->d_name + l - 2, ".c")) continue;
        srcf_t *s = &g_src[g_nsrc];
        snprintf(s->path, sizeof(s->path), "src/alerts/%s", e->d_name);
        s->text = slurp(s->path);
        if (!s->text) continue;
        blank_comments(s->text);
        g_nsrc++;
    }
    closedir(d);
}

/* Past a string or char literal starting at p. */
static const char *skip_lit(const char *p) {
    char q = *p;
    for (p++; *p && *p != q; p++)
        if (*p == '\\' && p[1]) p++;
    return *p ? p + 1 : p;
}

/* The arguments of the call whose '(' is at open: up to ARGS_MAX
 * [start, end) spans at depth 1. Count, or -1. */
static int split_args(const char *open, const char *a[], const char *b[]) {
    int n = 0, depth = 0;
    const char *start = open + 1;
    for (const char *p = open; *p; ) {
        if (*p == '"' || *p == '\'') { p = skip_lit(p); continue; }
        if (*p == '(' || *p == '[' || *p == '{') depth++;
        else if (*p == ')' || *p == ']' || *p == '}') {
            if (--depth == 0) {
                if (n < ARGS_MAX) { a[n] = start; b[n] = p; n++; }
                return n;
            }
        } else if (*p == ',' && depth == 1) {
            if (n < ARGS_MAX) { a[n] = start; b[n] = p; n++; }
            start = p + 1;
        }
        p++;
    }
    return -1;
}

static void trim(const char **a, const char **b) {
    while (*a < *b && isspace((unsigned char)**a)) (*a)++;
    while (*b > *a && isspace((unsigned char)(*b)[-1])) (*b)--;
}

/* The start of the function body enclosing pos: the last '{' opened at
 * file depth 0 before it. */
static const char *body_start(const char *text, const char *pos) {
    int depth = 0;
    const char *last = text;
    for (const char *p = text; p < pos && *p; ) {
        if (*p == '"' || *p == '\'') { p = skip_lit(p); continue; }
        if (*p == '{') { if (depth == 0) last = p; depth++; }
        else if (*p == '}') depth--;
        p++;
    }
    return last;
}

/* Is [a, b) one string literal, or adjacent ones? */
static int is_literal(const char *a, const char *b) {
    trim(&a, &b);
    if (a >= b) return 0;
    while (a < b) {
        if (*a != '"') return 0;
        a = skip_lit(a);
        while (a < b && isspace((unsigned char)*a)) a++;
    }
    return 1;
}

static int word_in(const char *w, size_t n, const char *list) {
    for (const char *p = list; *p; ) {
        while (*p == ' ') p++;
        const char *e = p;
        while (*e && *e != ' ') e++;
        if ((size_t)(e - p) == n && !strncmp(p, w, n)) return 1;
        p = e;
    }
    return 0;
}

static int named_ok(const char *w, size_t n, const char *extra) {
    for (int i = 0; web_alert_fmt_names[i]; i++)
        if (strlen(web_alert_fmt_names[i]) == n && !strncmp(web_alert_fmt_names[i], w, n))
            return 1;
    return word_in(w, n, extra);
}

static int banned(const char *a, const char *b) {
    for (int i = 0; web_alert_fmt_banned[i]; i++) {
        size_t bl = strlen(web_alert_fmt_banned[i]);
        for (const char *p = a; p + bl <= b; p++) {
            size_t k = 0;
            while (k < bl && tolower((unsigned char)p[k]) == web_alert_fmt_banned[i][k]) k++;
            if (k == bl) return 1;
        }
    }
    return 0;
}

/* One %s argument: a literal, a ternary of acceptable branches, or a
 * variable path whose last member is approved. */
static int str_arg_ok(const char *a, const char *b, const char *extra,
                      char *why, size_t wsz) {
    trim(&a, &b);
    if (a >= b) { snprintf(why, wsz, "empty argument"); return 0; }
    if (is_literal(a, b)) return 1;
    /* A ternary at depth 0: cond ? x : y. */
    int depth = 0;
    const char *q = NULL, *c = NULL;
    for (const char *p = a; p < b; ) {
        if (*p == '"' || *p == '\'') { p = skip_lit(p); continue; }
        if (*p == '(' || *p == '[') depth++;
        else if (*p == ')' || *p == ']') depth--;
        else if (depth == 0 && *p == '?' && !q) q = p;
        else if (depth == 0 && *p == ':' && q && !c) c = p;
        p++;
    }
    if (q && c)
        return str_arg_ok(q + 1, c, extra, why, wsz) &&
               str_arg_ok(c + 1, b, extra, why, wsz);
    /* A path: idents joined by -> or ., its indices dropped (an index
     * selects an element; the element's name is the member after it). */
    char path[256];
    size_t pl = 0;
    int idx = 0;
    for (const char *p = a; p < b && pl + 1 < sizeof(path); p++) {
        if (*p == '[') { idx++; continue; }
        if (*p == ']') { idx--; continue; }
        if (!idx) path[pl++] = *p;
    }
    path[pl] = '\0';
    if (idx) { snprintf(why, wsz, "not a variable: %.*s", (int)(b - a), a); return 0; }
    for (const char *p = path; *p; p++)
        if (!(isalnum((unsigned char)*p) || *p == '_' || *p == '.' ||
              (*p == '-' && p[1] == '>') || (*p == '>' && p > path && p[-1] == '-'))) {
            snprintf(why, wsz, "not a variable: %.*s", (int)(b - a), a);
            return 0;
        }
    /* The field's own name: never one for a credential or free text,
     * whatever the approved list says. */
    if (banned(path, path + pl)) {
        snprintf(why, wsz, "a field named for free text or a credential: %.*s",
                 (int)(b - a), a);
        return 0;
    }
    const char *e = path + pl;
    const char *last = e;
    while (last > path && (isalnum((unsigned char)last[-1]) || last[-1] == '_')) last--;
    if (!named_ok(last, (size_t)(e - last), extra)) {
        snprintf(why, wsz, "a string field not audited: %.*s", (int)(b - a), a);
        return 0;
    }
    return 1;
}

/* The concatenated format literal of [a, b) into out; 0, or -1 when it
 * is not literals alone (a macro between them, say). */
static int format_of(const char *a, const char *b, char *out, size_t cap) {
    trim(&a, &b);
    if (!is_literal(a, b)) return -1;
    size_t o = 0;
    while (a < b) {
        const char *e = skip_lit(a);
        for (const char *p = a + 1; p < e - 1 && o + 2 < cap; p++) {
            if (*p == '\\' && p + 1 < e - 1) { out[o++] = p[0]; out[o++] = p[1]; p++; continue; }
            out[o++] = *p;
        }
        a = e;
        while (a < b && isspace((unsigned char)*a)) a++;
    }
    out[o] = '\0';
    return 0;
}

/* One snprintf(detail..., size, fmt, args...) whose '(' is at open. */
static int snprintf_ok(const char *open, const char *extra, char *why, size_t wsz) {
    const char *a[ARGS_MAX], *b[ARGS_MAX];
    int n = split_args(open, a, b);
    if (n < 3) { snprintf(why, wsz, "an snprintf too short to read"); return 0; }
    char fmt[2048];
    if (format_of(a[2], b[2], fmt, sizeof(fmt)) != 0) {
        snprintf(why, wsz, "a format that is not literals alone");
        return 0;
    }
    int arg = 3;
    for (const char *p = fmt; *p; p++) {
        if (*p != '%') continue;
        p++;
        if (*p == '%') continue;
        while (*p && strchr("-+ #0", *p)) p++;
        if (*p == '*') { arg++; p++; }
        while (isdigit((unsigned char)*p)) p++;
        if (*p == '.') {
            p++;
            if (*p == '*') { arg++; p++; }
            while (isdigit((unsigned char)*p)) p++;
        }
        while (*p && strchr("hlLqjzt", *p)) p++;
        if (!*p) break;
        if (*p == 'n') { snprintf(why, wsz, "%%n in a format"); return 0; }
        if (arg >= n) { snprintf(why, wsz, "fewer arguments than conversions"); return 0; }
        if (*p == 's' && !str_arg_ok(a[arg], b[arg], extra, why, wsz)) return 0;
        arg++;
    }
    return 1;
}

static const struct { const char *fn; int detail; } F[] = {
    { "fire", 3 }, { "fire_conf", 4 }, { "fire_ev", 5 }, { "fire_inv", 10 },
};

/* The call whose argument list holds s, between from and s: its name
 * [*ns, *ne) and which argument s is in. 0, or -1 when s is in none. */
static int enclosing_call(const char *from, const char *s, const char **ns,
                          const char **ne, int *argi) {
    int depth = 0, commas = 0;
    for (const char *p = s - 1; p >= from; p--) {
        if (*p == ')' || *p == ']' || *p == '}') depth++;
        else if (*p == '[' || *p == '{') { if (depth == 0) return -1; depth--; }
        else if (*p == '(') {
            if (depth == 0) {
                const char *e = p;
                while (e > from && isspace((unsigned char)e[-1])) e--;
                const char *b = e;
                while (b > from && (isalnum((unsigned char)b[-1]) || b[-1] == '_')) b--;
                *ns = b;
                *ne = e;
                *argi = commas;
                return b < e ? 0 : -1;
            }
            depth--;
        } else if (*p == ',' && depth == 0) commas++;
        else if ((*p == ';') && depth == 0) return -1;
    }
    return -1;
}

/* Is s, an appearance of var, the detail argument of a fire*() call
 * (another site in the same function, audited as its own)? */
static int fire_detail_arg(const char *from, const char *s, size_t vl) {
    const char *ns, *ne;
    int argi;
    if (enclosing_call(from, s, &ns, &ne, &argi) != 0) return 0;
    const char *r = s + vl;
    while (isspace((unsigned char)*r)) r++;
    if (*r != ',' && *r != ')') return 0;
    for (size_t k = 0; k < sizeof(F) / sizeof(F[0]); k++)
        if ((size_t)(ne - ns) == strlen(F[k].fn) && !strncmp(ns, F[k].fn, (size_t)(ne - ns)))
            return argi == F[k].detail;
    return 0;
}

/* Is s, an appearance of var, a declarator of a plain char-array
 * declaration with no initializer: "char a[N], var[M];"? */
static int char_declarator(const char *from, const char *s, size_t vl) {
    const char *st = s;
    while (st > from && st[-1] != ';' && st[-1] != '{' && st[-1] != '}') st--;
    while (isspace((unsigned char)*st)) st++;
    if (strncmp(st, "char", 4) || !isspace((unsigned char)st[4])) return 0;
    for (const char *p = st; p < s; p++)
        if (*p == '=' || *p == '(' || *p == '*') return 0;
    const char *r = s + vl;
    while (isspace((unsigned char)*r)) r++;
    if (*r != '[') return 0;
    const char *z = strchr(r, ']');
    if (!z) return 0;
    z++;
    while (isspace((unsigned char)*z)) z++;
    return *z == ';' || *z == ',';
}

/* Audit every fire site of type name. Sites found into *sites; 1 when
 * every one passes. why says the first failure. */
static int audit_type(const char *name, const char *extra, int *sites,
                      char *why, size_t wsz) {
    char want[96];
    snprintf(want, sizeof(want), "ALERT_TYPE_%s", name);
    *sites = 0;
    load();
    for (int f = 0; f < g_nsrc; f++) {
        const char *t = g_src[f].text;
        for (const char *p = t; (p = strstr(p, want)) != NULL; p += strlen(want)) {
            char after = p[strlen(want)];
            if (isalnum((unsigned char)after) || after == '_') continue;
            /* Back over white space and '(' to the call's name. */
            const char *q = p;
            while (q > t && isspace((unsigned char)q[-1])) q--;
            if (q == t || q[-1] != '(') continue;
            const char *open = q - 1;
            const char *ne = open;
            while (ne > t && isspace((unsigned char)ne[-1])) ne--;
            const char *ns = ne;
            while (ns > t && (isalnum((unsigned char)ns[-1]) || ns[-1] == '_')) ns--;
            int which = -1;
            for (size_t k = 0; k < sizeof(F) / sizeof(F[0]); k++)
                if ((size_t)(ne - ns) == strlen(F[k].fn) && !strncmp(ns, F[k].fn, strlen(F[k].fn)))
                    which = (int)k;
            if (which < 0) continue;
            (*sites)++;
            const char *a[ARGS_MAX], *b[ARGS_MAX];
            int n = split_args(open, a, b);
            if (n <= F[which].detail) {
                snprintf(why, wsz, "%s: a %s() call too short to read", g_src[f].path, F[which].fn);
                return 0;
            }
            const char *da = a[F[which].detail], *db = b[F[which].detail];
            trim(&da, &db);
            if (is_literal(da, db)) continue;
            char var[64];
            size_t vl = (size_t)(db - da);
            for (const char *x = da; x < db; x++)
                if (!(isalnum((unsigned char)*x) || *x == '_')) vl = 0;
            if (vl == 0 || vl >= sizeof(var)) {
                snprintf(why, wsz, "%s: a detail argument that is not one variable", g_src[f].path);
                return 0;
            }
            memcpy(var, da, vl);
            var[vl] = '\0';
            const char *body = body_start(t, ns);
            int writes = 0;
            for (const char *s = body; s < ns; s++) {
                if (*s == '"' || *s == '\'') { s = skip_lit(s) - 1; continue; }
                if (!(s == body || !(isalnum((unsigned char)s[-1]) || s[-1] == '_'))) continue;
                if (strncmp(s, var, vl) || isalnum((unsigned char)s[vl]) || s[vl] == '_') continue;
                /* What comes before it: a token, or the '(' of a call. */
                const char *c = s;
                while (c > body && isspace((unsigned char)c[-1])) c--;
                const char *ps = c;
                while (ps > body && (isalnum((unsigned char)ps[-1]) || ps[-1] == '_')) ps--;
                size_t pl = (size_t)(c - ps);
                const char *r = s + vl;
                while (isspace((unsigned char)*r)) r++;
                /* sizeof detail */
                if (pl == 6 && !strncmp(ps, "sizeof", 6)) continue;
                /* char detail[N]; (or char key[K], detail[N];) */
                if (char_declarator(body, s, vl)) continue;
                /* Another fire site's detail, audited as its own. */
                if (fire_detail_arg(body, s, vl)) continue;
                if (c == body || c[-1] != '(') {
                    snprintf(why, wsz, "%s: %s used where the audit cannot follow it "
                             "(an alias, a helper's argument, an assignment)", g_src[f].path, var);
                    return 0;
                }
                /* The first argument of a call: which one? */
                const char *ce = c - 1;
                while (ce > body && isspace((unsigned char)ce[-1])) ce--;
                const char *cs = ce;
                while (cs > body && (isalnum((unsigned char)cs[-1]) || cs[-1] == '_')) cs--;
                size_t cl = (size_t)(ce - cs);
                if ((cl == 6 && !strncmp(cs, "sizeof", 6)) ||
                    (cl == 6 && !strncmp(cs, "strlen", 6))) {
                    if (*r == ')') continue;
                    snprintf(why, wsz, "%s: %s inside an expression the audit cannot read",
                             g_src[f].path, var);
                    return 0;
                }
                if (cl == 8 && !strncmp(cs, "snprintf", 8)) {
                    writes++;
                    if (!snprintf_ok(c - 1, extra, why, wsz)) {
                        size_t wl = strlen(why);
                        snprintf(why + wl, wsz - wl, " (%s)", g_src[f].path);
                        return 0;
                    }
                    continue;
                }
                snprintf(why, wsz, "%s: %s passed to %.*s(), a write the audit cannot read",
                         g_src[f].path, var, (int)cl, cs);
                return 0;
            }
            if (!writes) {
                snprintf(why, wsz, "%s: no snprintf into %s before the call", g_src[f].path, var);
                return 0;
            }
        }
    }
    return *sites > 0;
}

/* Seen red with ", e->username" added as a %s field to PORT_SCAN's
 * format in src/alerts/rules_wired.c (the fire site found, the field
 * refused; the file restored by the inverse edit). */
static void test_every_listed_type_passes_the_audit(void) {
    for (size_t i = 0; i < web_alert_detail_audited_n; i++) {
        const web_adf_t *r = &web_alert_detail_audited[i];
        int sites = 0;
        char why[512] = "";
        int ok = audit_type(r->type, r->extra, &sites, why, sizeof(why));
        if (!ok)
            fprintf(stderr, "    %s: %s%s\n", r->type, sites ? "" : "no fire() site found; ",
                    why);
        WT_ASSERT(ok);
        WT_ASSERT(sites > 0);
        /* Every row names a real type, and its extra names say why. */
        WT_ASSERT(web_akb_find(r->type) >= 0);
        WT_ASSERT(!r->extra[0] || r->why[0]);
    }
}

/* The types whose detail carries a credential or a remote's free text:
 * off the list, and refused by the checker. */
static const char *const WITHHELD[] = {
    "CLEARTEXT_CRED", "SNMP_COMMUNITY_BRUTE", "RDP_BRUTE_FORCE",
    "MQTT_BROKER_BRUTE", "SSH_BRUTE_FORCE", "DGA_DOMAIN",
    "DNS_TUNNEL", "CAPTIVE_PORTAL", "ATTACK_PATH", "ATTACK_TOOL_UA",
    "WEAK_TLS", "THREAT_DOMAIN",
};

/* Off the list by choice although today's format would pass: the rule
 * reads 802.1X identities, so a field added to its detail later is
 * withheld until someone audits it, rather than shown until someone
 * notices. */
static const char *const KEPT_OFF[] = { "ROGUE_RADIUS" };

/* Seen red with "CLEARTEXT_CRED" added to web_alert_detail_audited[]
 * (the list check), and with str_arg_ok() answering 1 (the checker
 * accepted every withheld type's fields). */
static void test_credential_types_stay_withheld(void) {
    for (size_t i = 0; i < sizeof(WITHHELD) / sizeof(WITHHELD[0]); i++) {
        int t = web_akb_find(WITHHELD[i]);
        WT_ASSERT(t >= 0);
        if (web_alert_detail_ok(t)) fprintf(stderr, "    %s is shown\n", WITHHELD[i]);
        WT_ASSERT(!web_alert_detail_ok(t));
        /* The positive control: the checker refuses each one, for a
         * field in its format, not for want of a site. */
        int sites = 0;
        char why[512] = "";
        int ok = audit_type(WITHHELD[i], "", &sites, why, sizeof(why));
        if (ok) fprintf(stderr, "    the audit passed %s\n", WITHHELD[i]);
        WT_ASSERT(!ok);
        WT_ASSERT(sites > 0);
    }
    for (size_t i = 0; i < sizeof(KEPT_OFF) / sizeof(KEPT_OFF[0]); i++) {
        int t = web_akb_find(KEPT_OFF[i]);
        WT_ASSERT(t >= 0);
        WT_ASSERT(!web_alert_detail_ok(t));
    }
    WT_EQ(web_alert_detail_ok(-1), 0);
    WT_EQ(web_alert_detail_ok(web_akb_n), 0);
    WT_EQ(web_alert_detail_ok(web_akb_find("PORT_SCAN")), 1);
}

/* The checker's controls, on source written here in the shapes it must
 * refuse: the detail aliased by a pointer and written through it, the
 * detail given to a helper as a later argument, written by index, given
 * to strcat() as its first, and declared with a value; and the plain
 * shape it must accept, so a checker that refused everything would fail
 * too. Seen red with the strict branch in audit_type() turned back into
 * "continue" for an appearance not after a '(' (the parent's rule: the
 * alias and the later argument passed), and with the branch refusing an
 * unknown call made to continue (strcat passed), each restored by the
 * inverse edit. */
static void test_audit_refuses_aliases_and_helpers(void) {
    static const char CTL[] =
        "void rule_alias(void) {\n"
        "    char detail[ALERT_DETAIL_LEN];\n"
        "    snprintf(detail, sizeof(detail), \"%d ports\", n);\n"
        "    char *w = detail;\n"
        "    strcpy(w + 4, e->username);\n"
        "    fire(ALERT_TYPE_AUDITCTL_ALIAS, ALERT_SEV_WARN, \"T\", detail, key, NULL, 0, now);\n"
        "}\n"
        "void rule_helper(void) {\n"
        "    char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];\n"
        "    snprintf(detail, sizeof(detail), \"%d ports\", n);\n"
        "    put_user(e, sizeof(detail), detail);\n"
        "    fire(ALERT_TYPE_AUDITCTL_HELPER, ALERT_SEV_WARN, \"T\", detail, key, NULL, 0, now);\n"
        "}\n"
        "void rule_index(void) {\n"
        "    char detail[ALERT_DETAIL_LEN];\n"
        "    snprintf(detail, sizeof(detail), \"%d ports\", n);\n"
        "    detail[0] = e->username[0];\n"
        "    fire(ALERT_TYPE_AUDITCTL_INDEX, ALERT_SEV_WARN, \"T\", detail, key, NULL, 0, now);\n"
        "}\n"
        "void rule_strcat(void) {\n"
        "    char detail[ALERT_DETAIL_LEN];\n"
        "    snprintf(detail, sizeof(detail), \"%d ports\", n);\n"
        "    strcat(detail, e->username);\n"
        "    fire(ALERT_TYPE_AUDITCTL_STRCAT, ALERT_SEV_WARN, \"T\", detail, key, NULL, 0, now);\n"
        "}\n"
        "void rule_init(void) {\n"
        "    char detail[ALERT_DETAIL_LEN] = \"x\";\n"
        "    snprintf(detail, sizeof(detail), \"%d ports\", n);\n"
        "    fire(ALERT_TYPE_AUDITCTL_INIT, ALERT_SEV_WARN, \"T\", detail, key, NULL, 0, now);\n"
        "}\n"
        "void rule_ok(void) {\n"
        "    char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];\n"
        "    snprintf(detail, sizeof(detail), \"%d ports\", n);\n"
        "    if (strlen(detail) > 3) fire(ALERT_TYPE_AUDITCTL_OK, ALERT_SEV_LOW, \"T\", detail, key,\n"
        "                                 NULL, 0, now);\n"
        "    fire(ALERT_TYPE_AUDITCTL_OK, ALERT_SEV_WARN, \"T\", detail, key, NULL, 0, now);\n"
        "}\n";
    load();
    WT_ASSERT(g_nsrc < 32);
    if (g_nsrc >= 32) return;
    srcf_t *c = &g_src[g_nsrc];
    snprintf(c->path, sizeof(c->path), "(control)");
    c->text = malloc(sizeof(CTL));
    WT_ASSERT(c->text != NULL);
    if (!c->text) return;
    memcpy(c->text, CTL, sizeof(CTL));
    g_nsrc++;
    static const char *const refused[] = { "AUDITCTL_ALIAS", "AUDITCTL_HELPER",
                                           "AUDITCTL_INDEX", "AUDITCTL_STRCAT",
                                           "AUDITCTL_INIT" };
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
        int sites = 0;
        char why[512] = "";
        int ok = audit_type(refused[i], "", &sites, why, sizeof(why));
        if (ok) fprintf(stderr, "    the audit passed %s\n", refused[i]);
        WT_ASSERT(!ok);
        WT_EQ(sites, 1);
    }
    int sites = 0;
    char why[512] = "";
    int ok = audit_type("AUDITCTL_OK", "", &sites, why, sizeof(why));
    if (!ok) fprintf(stderr, "    the audit refused the plain shape: %s\n", why);
    WT_ASSERT(ok);
    WT_EQ(sites, 2);
}

void run_alertfmt_tests(void) {
    WT_RUN(test_every_listed_type_passes_the_audit);
    WT_RUN(test_credential_types_stay_withheld);
    WT_RUN(test_audit_refuses_aliases_and_helpers);
    for (int i = 0; i < g_nsrc; i++) free(g_src[i].text);
    g_nsrc = 0;
}
