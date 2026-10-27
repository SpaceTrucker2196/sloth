#include "web_query.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_json.h"
#include "web_scope.h"

/* In web_anomaly_kind_find()'s order: test_query.c holds the two lists
 * to each other. */
const char *const web_query_anomaly_kinds[] = {
    "rate", "new", "hours", "ident", "fanout", "dns", "proto", "sensor",
    "vendor", NULL
};

/* sloth's DEV_SRC_* bits (include/sloth.h), which devices.sources
 * holds; test_query.c holds these to that header. */
static const struct { const char *w; long long bit; } SRC[] = {
    { "arp", 1 << 0 }, { "dhcp", 1 << 1 }, { "mdns", 1 << 2 },
    { "beacon", 1 << 3 }, { "probe", 1 << 4 }, { "sta", 1 << 5 },
    { "camera", 1 << 6 }, { NULL, 0 }
};

static const char *const HAS[] = {
    "pnl", "alert", "anomaly", "name", "ip", "ssid", NULL
};

static const struct { const char *p; int kind; } PREFIX[] = {
    { "vendor", WEB_QT_VENDOR }, { "mac", WEB_QT_MAC }, { "ip", WEB_QT_IP },
    { "ssid", WEB_QT_SSID }, { "name", WEB_QT_NAME },
    { "random", WEB_QT_RANDOM }, { "seen", WEB_QT_SEEN },
    { "first", WEB_QT_FIRST }, { "risk", WEB_QT_RISK }, { "z", WEB_QT_Z },
    { "src", WEB_QT_SRC }, { "has", WEB_QT_HAS },
    { "anomaly", WEB_QT_ANOMALY }, { "pass", WEB_QT_PASS }, { NULL, 0 }
};

static int fail(char *err, size_t errsz, const char *why) {
    snprintf(err, errsz, "%s", why);
    return -1;
}

static int word_index(const char *const *list, const char *w) {
    for (int i = 0; list[i]; i++)
        if (!strcmp(list[i], w)) return i;
    return -1;
}

/* Text a person typed: well-formed UTF-8, no C0, DEL or C1 control. */
static int text_ok(const char *s) {
    const unsigned char *p = (const unsigned char *)s;
    size_t n = strlen(s);
    while (n) {
        unsigned cp;
        size_t l = web_utf8_seq(p, n, &cp);
        if (!l || cp < 0x20 || (cp >= 0x7f && cp <= 0x9f)) return 0;
        p += l;
        n -= l;
    }
    return 1;
}

static int is_hex(int c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static int lower(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

/* A MAC prefix as sloth stores MACs: lower-case hex, ':' between
 * octets; '-' is taken for ':'. */
static int mac_value(const char *v, char *out) {
    size_t n = strlen(v);
    if (n > 17 || !is_hex((unsigned char)v[0])) return -1;
    for (size_t i = 0; i < n; i++) {
        int c = (unsigned char)v[i];
        if (c == '-') c = ':';
        if (!is_hex(c) && c != ':') return -1;
        /* Where a full MAC has its separators, and nowhere else. */
        if ((c == ':') != (i % 3 == 2)) return -1;
        out[i] = (char)lower(c);
    }
    out[n] = '\0';
    return 0;
}

static int ip_value(const char *v, char *out) {
    size_t n = strlen(v);
    if (n > 45) return -1;
    for (size_t i = 0; i < n; i++) {
        int c = (unsigned char)v[i];
        if (!is_hex(c) && c != '.' && c != ':') return -1;
        out[i] = (char)lower(c);
    }
    out[n] = '\0';
    return 0;
}

/* Days since 1970-01-01 of a proleptic Gregorian date (Hinnant's
 * days_from_civil). */
static long long days_from_civil(long long y, int m, int d) {
    y -= m <= 2;
    long long era = (y >= 0 ? y : y - 399) / 400;
    long long yoe = y - era * 400;
    long long doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    long long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static int digits(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) if (s[i] < '0' || s[i] > '9') return 0;
    return 1;
}

/* YYYY-MM-DD, 1970..2999, a real day. */
static int date_value(const char *s, long long *out) {
    if (strlen(s) != 10 || s[4] != '-' || s[7] != '-' || !digits(s, 4) ||
        !digits(s + 5, 2) || !digits(s + 8, 2))
        return -1;
    int y = atoi(s), m = atoi(s + 5), d = atoi(s + 8);
    static const int mdays[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (y < 1970 || y > 2999 || m < 1 || m > 12 || d < 1) return -1;
    int leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    if (d > mdays[m - 1] + (m == 2 && leap)) return -1;
    *out = days_from_civil(y, m, d) * 86400;
    return 0;
}

/* seen: and first: values. */
static int time_value(const char *v, long long now_s, web_qterm_t *t) {
    int op = 0, eq = 0;                             /* 0 none, '<', '>' */
    if (v[0] == '<' || v[0] == '>') {
        op = v[0];
        v++;
        if (v[0] == '=') { eq = 1; v++; }
    }
    size_t n = strlen(v);
    if (n >= 2 && n <= 7 && digits(v, n - 1)) {
        long long mul;
        switch (v[n - 1]) {
        case 's': mul = 1; break;
        case 'm': mul = 60; break;
        case 'h': mul = 3600; break;
        case 'd': mul = 86400; break;
        case 'w': mul = 7 * 86400; break;
        default: return -1;
        }
        long long secs = atoll(v) * mul;
        t->num = now_s - secs;
        t->op = op == '>' ? WEB_QOP_LT : WEB_QOP_GT;
        return 0;
    }
    long long day;
    if (date_value(v, &day) != 0) return -1;
    t->num = day;
    /* A date names a whole UTC day: >DATE and >=DATE are from its start,
     * <DATE before it, <=DATE to its end (so including it). */
    if (op == '>') t->op = WEB_QOP_GE;
    else if (op == '<') { t->op = WEB_QOP_LT; if (eq) t->num = day + 86400; }
    else { t->op = WEB_QOP_EQ; t->num2 = day + 86400; }
    return 0;
}

static const char *cmp_op(const char *v, int *op, int dflt) {
    if (!strncmp(v, "<=", 2)) { *op = WEB_QOP_LE; return v + 2; }
    if (!strncmp(v, ">=", 2)) { *op = WEB_QOP_GE; return v + 2; }
    if (v[0] == '<') { *op = WEB_QOP_LT; return v + 1; }
    if (v[0] == '>') { *op = WEB_QOP_GT; return v + 1; }
    if (v[0] == '=') { *op = WEB_QOP_EQ; return v + 1; }
    *op = dflt;
    return v;
}

/* Up to four integer digits and two decimals. */
static int z_value(const char *v, double *out) {
    size_t n = strlen(v), i = 0;
    while (i < n && v[i] >= '0' && v[i] <= '9') i++;
    if (i == 0 || i > 4) return -1;
    if (i < n) {
        if (v[i] != '.' || n - i - 1 < 1 || n - i - 1 > 2 ||
            !digits(v + i + 1, n - i - 1))
            return -1;
    }
    *out = atof(v);
    return 0;
}

static int value(web_qterm_t *t, const char *v, long long now_s, char *err,
                 size_t errsz) {
    switch (t->kind) {
    case WEB_QT_FREE: case WEB_QT_VENDOR: case WEB_QT_SSID: case WEB_QT_NAME:
        if (!text_ok(v)) return fail(err, errsz, "bad_text");
        snprintf(t->text, sizeof(t->text), "%s", v);
        return 0;
    case WEB_QT_MAC:
        return mac_value(v, t->text) == 0 ? 0 : fail(err, errsz, "bad_mac");
    case WEB_QT_IP:
        return ip_value(v, t->text) == 0 ? 0 : fail(err, errsz, "bad_ip");
    case WEB_QT_RANDOM:
        if (!strcmp(v, "yes") || !strcmp(v, "true") || !strcmp(v, "1")) t->num = 1;
        else if (!strcmp(v, "no") || !strcmp(v, "false") || !strcmp(v, "0")) t->num = 0;
        else return fail(err, errsz, "bad_random");
        return 0;
    case WEB_QT_SEEN: case WEB_QT_FIRST:
        return time_value(v, now_s, t) == 0 ? 0 : fail(err, errsz, "bad_time");
    case WEB_QT_RISK: {
        const char *r = cmp_op(v, &t->op, WEB_QOP_EQ);
        if (strlen(r) != 1 || r[0] < '0' || r[0] > '3')
            return fail(err, errsz, "bad_risk");
        t->num = r[0] - '0';
        return 0;
    }
    case WEB_QT_Z: {
        const char *r = cmp_op(v, &t->op, WEB_QOP_GE);
        if (t->op == WEB_QOP_EQ || z_value(r, &t->z) != 0)
            return fail(err, errsz, "bad_z");
        return 0;
    }
    case WEB_QT_SRC:
        for (int i = 0; SRC[i].w; i++)
            if (!strcmp(SRC[i].w, v)) { t->num = SRC[i].bit; return 0; }
        return fail(err, errsz, "bad_src");
    case WEB_QT_HAS:
        t->num = word_index(HAS, v);
        return t->num >= 0 ? 0 : fail(err, errsz, "bad_has");
    case WEB_QT_ANOMALY:
        t->num = word_index(web_query_anomaly_kinds, v);
        return t->num >= 0 ? 0 : fail(err, errsz, "bad_anomaly");
    case WEB_QT_PASS:
        /* The one pass slothweb keeps: sloth's latest. */
        if (strcmp(v, "latest")) return fail(err, errsz, "bad_pass");
        t->num = 0;
        return 0;
    default:
        return fail(err, errsz, "bad_text");
    }
}

int web_query_parse(const char *q, long long now_s, web_query_t *out,
                    char *err, size_t errsz) {
    memset(out, 0, sizeof(*out));
    if (!q) return 0;
    size_t len = strlen(q);
    if (len > WEB_Q_LEN) return fail(err, errsz, "query_too_long");
    const char *p = q, *end = q + len;
    while (p < end) {
        while (p < end && *p == ' ') p++;
        if (p >= end) break;
        if (out->n >= WEB_Q_TERMS) return fail(err, errsz, "too_many_terms");
        web_qterm_t *t = &out->t[out->n];
        memset(t, 0, sizeof(*t));
        if (*p == '-') { t->neg = 1; p++; }
        /* The prefix: lower-case letters and a ':'. */
        const char *w = p;
        while (w < end && *w >= 'a' && *w <= 'z') w++;
        t->kind = WEB_QT_FREE;
        if (w < end && *w == ':' && w > p) {
            for (int i = 0; PREFIX[i].p; i++)
                if (strlen(PREFIX[i].p) == (size_t)(w - p) &&
                    !memcmp(PREFIX[i].p, p, (size_t)(w - p))) {
                    t->kind = PREFIX[i].kind;
                    p = w + 1;
                    break;
                }
        }
        char v[WEB_Q_TERM_LEN + 1];
        size_t o = 0;
        if (p < end && *p == '"') {
            const char *close = memchr(p + 1, '"', (size_t)(end - p - 1));
            if (!close || (close + 1 < end && close[1] != ' '))
                return fail(err, errsz, "bad_quote");
            if ((size_t)(close - p - 1) > WEB_Q_TERM_LEN)
                return fail(err, errsz, "term_too_long");
            o = (size_t)(close - p - 1);
            memcpy(v, p + 1, o);
            p = close + 1;
        } else {
            while (p < end && *p != ' ') {
                if (*p == '"') return fail(err, errsz, "bad_quote");
                if (o >= WEB_Q_TERM_LEN) return fail(err, errsz, "term_too_long");
                v[o++] = *p++;
            }
        }
        v[o] = '\0';
        if (!o) return fail(err, errsz, "empty_value");
        if (value(t, v, now_s, err, errsz) != 0) return -1;
        out->n++;
    }
    return 0;
}

int web_query_sort_find(const char *s) {
    static const char *const SORTS[] = { "last", "first", "mac", "risk",
        "vendor", "ip", "ssid", "signal", "sources", NULL };
    return s ? word_index(SORTS, s) : -1;
}

int web_sort_dir_find(const char *s) {
    if (s && !strcmp(s, "asc")) return WEB_SORT_ASC;
    if (s && !strcmp(s, "desc")) return WEB_SORT_DESC;
    return -1;
}

/* ── the statement ───────────────────────────────────────────────────── */

typedef struct {
    char  *buf;
    size_t cap, len;
    int    over;
} sb_t;

static void sb_put(sb_t *b, const char *s) {
    size_t n = strlen(s);
    if (b->over || b->len + n >= b->cap) { b->over = 1; return; }
    memcpy(b->buf + b->len, s, n + 1);
    b->len += n;
}

/* "?N": a parameter's number, which is ours, never the input's. */
static void param(sb_t *b, int n) {
    char t[16];
    snprintf(t, sizeof(t), "?%d", n);
    sb_put(b, t);
}

/* `expr LIKE ?n ESCAPE '\'` for a column expression. */
static void like(sb_t *b, const char *col, int n) {
    sb_put(b, col);
    sb_put(b, " LIKE ");
    param(b, n);
    sb_put(b, " ESCAPE '\\'");
}

static const char LA[] =
    "(substr(d.mac,2,1) IN ('2','3','6','7','a','b','e','f'))";

static int bind_like(web_qsql_t *o, const char *text, int prefix_only) {
    web_qbind_t *b = &o->b[o->nb];
    size_t k = 0;
    if (!prefix_only) b->s[k++] = '%';
    for (const char *p = text; *p && k + 3 < sizeof(b->s); p++) {
        if (*p == '\\' || *p == '%' || *p == '_') b->s[k++] = '\\';
        b->s[k++] = *p;
    }
    b->s[k++] = '%';
    b->s[k] = '\0';
    b->type = 0;
    return ++o->nb;
}

static int bind_int(web_qsql_t *o, long long v) {
    o->b[o->nb].type = 1;
    o->b[o->nb].i = v;
    return ++o->nb;
}

static int bind_real(web_qsql_t *o, double v) {
    o->b[o->nb].type = 2;
    o->b[o->nb].d = v;
    return ++o->nb;
}

static const char *op_text(int op) {
    switch (op) {
    case WEB_QOP_LT: return " < ";
    case WEB_QOP_GT: return " > ";
    case WEB_QOP_LE: return " <= ";
    case WEB_QOP_GE: return " >= ";
    default:         return " = ";
    }
}

/* ── the capture scope's columns (web_scope.h) ─────────────────────── *
 *
 * Under Hybrid every column is the devices row's own, and the statement
 * is exactly what it was before scopes. Under Monitor or Local a device
 * row is a member when the scope's own tables hold its MAC, or its
 * sources (the latest tick's only: sloth's upsert replaces them) have
 * the scope's bits; and each column is the scope's: the address, the
 * hostname and the names behind the address are Local's, the last SSID
 * and the AP bit Monitor's, the signal the scope's own table's
 * (probe_clients, then beacon_aps; wifi_stas), first and last seen over
 * the scope's tables (the row's own when they hold none), the sources
 * and risk signals masked to the scope's bits and the risk level summed
 * again from those with sloth's weights (web_scope_risk_level()). Each
 * fragment is constant text of this file's, chosen by the scope and by
 * which tables the file has. */

#define BIGT "9000000000000000000"

typedef struct {
    int  scope;
    char ip[64], host[64], ssid[64], is_ap[32], sources[48], rsig[48];
    char risk[1024], signal[512], first[1536], last[1536], member[1536];
    unsigned f;
} dcols_t;

static void cat(char *dst, size_t cap, const char *s) {
    size_t n = strlen(dst), k = strlen(s);
    if (n + k + 1 > cap) return;      /* sized for the longest; never cut */
    memcpy(dst + n, s, k + 1);
}

/* The risk level from masked signals S, with sloth's weights. */
static void risk_case(char *out, size_t cap, const char *s, long long mask) {
    static const int W[6] = { 1, 1, 1, 1, 3, 3 };
    char sum[640] = "(0";
    for (int b = 0; b < 6; b++) {
        if (!(mask & (1LL << b))) continue;
        char t[96];
        snprintf(t, sizeof(t), " + %d * ((%s & %d) <> 0)", W[b], s, 1 << b);
        cat(sum, sizeof(sum), t);
    }
    cat(sum, sizeof(sum), ")");
    snprintf(out, cap, "(CASE WHEN %s >= 5 THEN 3 WHEN %s >= 3 THEN 2"
             " WHEN %s >= 1 THEN 1 ELSE 0 END)", sum, sum, sum);
}

static void dcols(unsigned f, int scope, dcols_t *c) {
    memset(c, 0, sizeof(*c));
    c->scope = scope;
    c->f = f;
    if (scope == 1) {                    /* WEB_SCOPE_MONITOR */
        snprintf(c->ip, sizeof(c->ip), "NULL");
        snprintf(c->host, sizeof(c->host), "NULL");
        snprintf(c->ssid, sizeof(c->ssid), "d.last_ssid");
        snprintf(c->is_ap, sizeof(c->is_ap), "d.is_ap");
        snprintf(c->sources, sizeof(c->sources), "(d.sources & 88)");
        snprintf(c->rsig, sizeof(c->rsig), "(d.risk_signals & 11)");
        risk_case(c->risk, sizeof(c->risk), "d.risk_signals", 11);
        snprintf(c->signal, sizeof(c->signal), "COALESCE(%s, %s)",
                 (f & WEB_QF_PROBE)
                     ? "(SELECT p.signal_dbm FROM probe_clients p WHERE p.mac = d.mac)"
                     : "NULL",
                 (f & WEB_QF_BEACON)
                     ? "(SELECT b.signal_dbm FROM beacon_aps b WHERE b.bssid = d.mac)"
                     : "NULL");
        /* min()/max() of two or more arguments are the scalar ones. */
        static const char *const FS[4] = {
            "(SELECT p.first_seen FROM probe_clients p WHERE p.mac = d.mac)",
            "(SELECT b.first_seen FROM beacon_aps b WHERE b.bssid = d.mac)",
            "(SELECT min(s.first_seen) FROM assocs s WHERE s.sta_mac = d.mac"
            " OR s.bssid = d.mac)",
            "(SELECT c.first_seen FROM pnl_clients c WHERE c.mac = d.mac)",
        };
        static const char *const LS[4] = {
            "(SELECT p.last_seen FROM probe_clients p WHERE p.mac = d.mac)",
            "(SELECT b.last_seen FROM beacon_aps b WHERE b.bssid = d.mac)",
            "(SELECT max(s.last_seen) FROM assocs s WHERE s.sta_mac = d.mac"
            " OR s.bssid = d.mac)",
            "(SELECT c.last_seen FROM pnl_clients c WHERE c.mac = d.mac)",
        };
        static const char *const EX[4] = {
            "EXISTS (SELECT 1 FROM probe_clients p WHERE p.mac = d.mac)",
            "EXISTS (SELECT 1 FROM beacon_aps b WHERE b.bssid = d.mac)",
            "EXISTS (SELECT 1 FROM assocs s WHERE s.sta_mac = d.mac OR s.bssid = d.mac)",
            "EXISTS (SELECT 1 FROM pnl_clients c WHERE c.mac = d.mac)",
        };
        const unsigned FT[4] = { WEB_QF_PROBE, WEB_QF_BEACON, WEB_QF_ASSOC, WEB_QF_PNLC };
        cat(c->first, sizeof(c->first), "COALESCE(NULLIF(min(" BIGT ", " BIGT);
        cat(c->last, sizeof(c->last), "COALESCE(NULLIF(max(-1, -1");
        cat(c->member, sizeof(c->member), "((d.sources & 24) <> 0");
        for (int i = 0; i < 4; i++) {
            if (!(f & FT[i])) continue;
            cat(c->first, sizeof(c->first), ", COALESCE(");
            cat(c->first, sizeof(c->first), FS[i]);
            cat(c->first, sizeof(c->first), ", " BIGT ")");
            cat(c->last, sizeof(c->last), ", COALESCE(");
            cat(c->last, sizeof(c->last), LS[i]);
            cat(c->last, sizeof(c->last), ", -1)");
            cat(c->member, sizeof(c->member), " OR ");
            cat(c->member, sizeof(c->member), EX[i]);
        }
        if (f & WEB_QF_CAMSIG)
            cat(c->member, sizeof(c->member), " OR (d.cam_signals & 18) <> 0");
        cat(c->first, sizeof(c->first), "), " BIGT "), d.first_seen)");
        cat(c->last, sizeof(c->last), "), -1), d.last_seen)");
        cat(c->member, sizeof(c->member), ")");
    } else if (scope == 2) {             /* WEB_SCOPE_LOCAL */
        snprintf(c->ip, sizeof(c->ip), "d.ip");
        snprintf(c->host, sizeof(c->host), "d.hostname");
        snprintf(c->ssid, sizeof(c->ssid), "NULL");
        snprintf(c->is_ap, sizeof(c->is_ap), "0");
        snprintf(c->sources, sizeof(c->sources), "(d.sources & 103)");
        snprintf(c->rsig, sizeof(c->rsig), "(d.risk_signals & 55)");
        risk_case(c->risk, sizeof(c->risk), "d.risk_signals", 55);
        snprintf(c->signal, sizeof(c->signal), "%s",
                 (f & WEB_QF_STA)
                     ? "(SELECT w.signal_dbm FROM wifi_stas w WHERE w.mac = d.mac)"
                     : "NULL");
        static const char *const FS[3] = {
            "(SELECT min(a.first_seen) FROM arp a WHERE a.mac = d.mac)",
            "(SELECT w.first_seen FROM wifi_stas w WHERE w.mac = d.mac)",
            "(SELECT min(l.first_seen) FROM dhcp_leases l WHERE l.ip = d.ip)",
        };
        static const char *const LS[3] = {
            "(SELECT max(a.last_seen) FROM arp a WHERE a.mac = d.mac)",
            "(SELECT w.last_seen FROM wifi_stas w WHERE w.mac = d.mac)",
            "(SELECT max(l.last_seen) FROM dhcp_leases l WHERE l.ip = d.ip)",
        };
        static const char *const EX[3] = {
            "EXISTS (SELECT 1 FROM arp a WHERE a.mac = d.mac)",
            "EXISTS (SELECT 1 FROM wifi_stas w WHERE w.mac = d.mac)",
            NULL,
        };
        const unsigned FT[3] = { WEB_QF_ARP, WEB_QF_STA, WEB_QF_DHCP };
        cat(c->first, sizeof(c->first), "COALESCE(NULLIF(min(" BIGT ", " BIGT);
        cat(c->last, sizeof(c->last), "COALESCE(NULLIF(max(-1, -1");
        cat(c->member, sizeof(c->member),
            "((d.sources & 39) <> 0 OR COALESCE(d.ip,'') <> ''");
        for (int i = 0; i < 3; i++) {
            if (!(f & FT[i])) continue;
            cat(c->first, sizeof(c->first), ", COALESCE(");
            cat(c->first, sizeof(c->first), FS[i]);
            cat(c->first, sizeof(c->first), ", " BIGT ")");
            cat(c->last, sizeof(c->last), ", COALESCE(");
            cat(c->last, sizeof(c->last), LS[i]);
            cat(c->last, sizeof(c->last), ", -1)");
            if (EX[i]) {
                cat(c->member, sizeof(c->member), " OR ");
                cat(c->member, sizeof(c->member), EX[i]);
            }
        }
        if (f & WEB_QF_CAMSIG)
            cat(c->member, sizeof(c->member), " OR (d.cam_signals & 45) <> 0");
        cat(c->first, sizeof(c->first), "), " BIGT "), d.first_seen)");
        cat(c->last, sizeof(c->last), "), -1), d.last_seen)");
        cat(c->member, sizeof(c->member), ")");
    } else {
        snprintf(c->ip, sizeof(c->ip), "d.ip");
        snprintf(c->host, sizeof(c->host), "d.hostname");
        snprintf(c->ssid, sizeof(c->ssid), "d.last_ssid");
        snprintf(c->is_ap, sizeof(c->is_ap), "d.is_ap");
        snprintf(c->sources, sizeof(c->sources), "d.sources");
        snprintf(c->rsig, sizeof(c->rsig), "d.risk_signals");
        snprintf(c->risk, sizeof(c->risk), "d.risk_level");
        snprintf(c->signal, sizeof(c->signal), "d.signal_dbm");
        snprintf(c->first, sizeof(c->first), "d.first_seen");
        snprintf(c->last, sizeof(c->last), "d.last_seen");
    }
}

/* `COALESCE(<expr>,'')`, as the Hybrid text has it for a column. */
static void co(sb_t *b, const char *expr) {
    sb_put(b, "COALESCE(");
    sb_put(b, expr);
    sb_put(b, ",'')");
}

static void like_co(sb_t *b, const char *expr, int n) {
    char t[96];
    snprintf(t, sizeof(t), "COALESCE(%s,'')", expr);
    like(b, t, n);
}

/* The alert types a scope holds, as constant integers of our own table
 * (web_scope.h), for has:alert. Empty under Hybrid. */
static void alert_types_in(sb_t *b, const dcols_t *c, const char *col) {
    if (!c->scope) return;
    int ty[128];
    int n = web_scope_alert_types(c->scope, 0, ty, 128);
    sb_put(b, " AND ");
    sb_put(b, col);
    sb_put(b, " IN (-1");
    for (int i = 0; i < n; i++) {
        char t[16];
        snprintf(t, sizeof(t), ",%d", ty[i]);
        sb_put(b, t);
    }
    sb_put(b, ")");
}

/* Only an address can carry a name from these tables, and most of a
 * large sloth.db's devices have none: testing it first spares each such
 * row a scan of the unindexed name tables (0.43 s to 0.02 s on the
 * reference host's 32,000 devices). */
static void names_exist(sb_t *b, const dcols_t *c, int n) {
    unsigned f = c->f;
    /* The names behind the address are Local's. */
    if (c->scope == 1) {
        sb_put(b, " OR 0");
        return;
    }
    sb_put(b, " OR (COALESCE(d.ip,'') <> '' AND (0");
    if (f & WEB_QF_DHCP) {
        sb_put(b, " OR EXISTS (SELECT 1 FROM dhcp_leases l WHERE l.ip = NULLIF(d.ip, '') AND ");
        like(b, "COALESCE(l.hostname,'')", n);
        sb_put(b, ")");
    }
    if (f & WEB_QF_MDNS) {
        sb_put(b, " OR EXISTS (SELECT 1 FROM mdns_services m WHERE m.ip = NULLIF(d.ip, '') AND (");
        like(b, "COALESCE(m.host,'')", n);
        sb_put(b, " OR ");
        like(b, "COALESCE(m.instance,'')", n);
        sb_put(b, "))");
    }
    if (f & WEB_QF_NBNS) {
        /* The unique names (suffix 0 workstation, 32 server), as the
         * row shows: a group registration (WORKGROUP<1E>) names no host. */
        sb_put(b, " OR EXISTS (SELECT 1 FROM nbns_names b WHERE b.ip = NULLIF(d.ip, '') AND"
               " b.suffix IN (0, 32) AND ");
        like(b, "b.name", n);
        sb_put(b, ")");
    }
    sb_put(b, " OR ");
    like(b, "COALESCE(web_ptr(d.ip),'')", n);
    sb_put(b, "))");
}

static void term(sb_t *b, const web_qterm_t *t, const dcols_t *c, web_qsql_t *o) {
    int n;
    unsigned f = c->f;
    int mon = c->scope == 1, loc = c->scope == 2;
    switch (t->kind) {
    case WEB_QT_FREE:
        n = bind_like(o, t->text, 0);
        sb_put(b, "(");
        like(b, "d.mac", n);
        sb_put(b, " OR ");
        like_co(b, c->ip, n);
        sb_put(b, " OR ");
        like_co(b, c->host, n);
        sb_put(b, " OR ");
        like(b, "COALESCE(d.vendor,'')", n);
        sb_put(b, " OR ");
        like(b, "COALESCE(web_vendor(d.mac),'')", n);
        sb_put(b, " OR ");
        like_co(b, c->ssid, n);
        sb_put(b, ")");
        break;
    case WEB_QT_VENDOR:
        n = bind_like(o, t->text, 0);
        sb_put(b, "(");
        like(b, "COALESCE(d.vendor,'')", n);
        sb_put(b, " OR ");
        like(b, "COALESCE(web_vendor(d.mac),'')", n);
        sb_put(b, ")");
        break;
    case WEB_QT_MAC:
        n = bind_like(o, t->text, 1);
        sb_put(b, "(");
        like(b, "d.mac", n);
        sb_put(b, ")");
        break;
    case WEB_QT_IP:
        n = bind_like(o, t->text, 1);
        sb_put(b, "(");
        like_co(b, c->ip, n);
        if ((f & WEB_QF_ARP) && !mon) {
            sb_put(b, " OR EXISTS (SELECT 1 FROM arp a WHERE a.mac = d.mac AND ");
            like(b, "a.ip", n);
            sb_put(b, ")");
        }
        sb_put(b, ")");
        break;
    case WEB_QT_SSID:
        n = bind_like(o, t->text, 0);
        sb_put(b, "(");
        like_co(b, c->ssid, n);
        if ((f & WEB_QF_PNL) && !loc) {
            sb_put(b, " OR EXISTS (SELECT 1 FROM pnl_ssids s WHERE s.mac = d.mac AND ");
            like(b, "s.ssid", n);
            sb_put(b, ")");
        }
        sb_put(b, ")");
        break;
    case WEB_QT_NAME:
        n = bind_like(o, t->text, 0);
        sb_put(b, "(");
        like_co(b, c->host, n);
        names_exist(b, c, n);
        sb_put(b, ")");
        break;
    case WEB_QT_RANDOM:
        sb_put(b, t->num ? LA : "(NOT ");
        if (!t->num) { sb_put(b, LA); sb_put(b, ")"); }
        break;
    case WEB_QT_SEEN: case WEB_QT_FIRST: {
        const char *col = t->kind == WEB_QT_SEEN ? c->last : c->first;
        sb_put(b, "(");
        sb_put(b, col);
        if (t->op == WEB_QOP_EQ) {
            sb_put(b, " >= ");
            param(b, bind_int(o, t->num));
            sb_put(b, " AND ");
            sb_put(b, col);
            sb_put(b, " < ");
            param(b, bind_int(o, t->num2));
        } else {
            sb_put(b, op_text(t->op));
            param(b, bind_int(o, t->num));
        }
        sb_put(b, ")");
        break;
    }
    case WEB_QT_RISK:
        sb_put(b, "(");
        sb_put(b, c->risk);
        sb_put(b, op_text(t->op));
        param(b, bind_int(o, t->num));
        sb_put(b, ")");
        break;
    case WEB_QT_Z:
        sb_put(b, "(COALESCE(web_z(d.mac),0)");
        sb_put(b, op_text(t->op));
        param(b, bind_real(o, t->z));
        sb_put(b, ")");
        break;
    case WEB_QT_SRC:
        sb_put(b, "((");
        sb_put(b, c->sources);
        sb_put(b, " & ");
        param(b, bind_int(o, t->num));
        sb_put(b, ") <> 0)");
        break;
    case WEB_QT_HAS:
        switch (t->num) {
        case WEB_HAS_PNL:
            sb_put(b, (f & WEB_QF_PNL) && !loc
                   ? "EXISTS (SELECT 1 FROM pnl_ssids s WHERE s.mac = d.mac)"
                   : "(0)");
            break;
        case WEB_HAS_ALERT:
            if (!(f & WEB_QF_ALERTS)) { sb_put(b, "(0)"); break; }
            if (!c->scope) {
                sb_put(b, "EXISTS (SELECT 1 FROM alerts a WHERE (COALESCE(d.ip,'') <> ''"
                          " AND a.match_ip = d.ip) OR instr(a.key, d.mac) > 0)");
                break;
            }
            /* The scope's own alert types; an address is Local's. */
            sb_put(b, "EXISTS (SELECT 1 FROM alerts a WHERE (");
            if (!mon) sb_put(b, "(COALESCE(d.ip,'') <> '' AND a.match_ip = d.ip) OR ");
            sb_put(b, "instr(a.key, d.mac) > 0)");
            alert_types_in(b, c, "a.type");
            sb_put(b, ")");
            break;
        case WEB_HAS_ANOMALY:
            sb_put(b, "(web_anoms(d.mac,-1) > 0)");
            break;
        case WEB_HAS_NAME:
            sb_put(b, "(");
            co(b, c->host);
            sb_put(b, " <> ''");
            if (!mon) {
                /* The address first, as in names_exist(). */
                sb_put(b, " OR (COALESCE(d.ip,'') <> '' AND (0");
                if (f & WEB_QF_DHCP)
                    sb_put(b, " OR EXISTS (SELECT 1 FROM dhcp_leases l WHERE l.ip = NULLIF(d.ip, '')"
                           " AND COALESCE(l.hostname,'') <> '')");
                if (f & WEB_QF_MDNS)
                    sb_put(b, " OR EXISTS (SELECT 1 FROM mdns_services m WHERE m.ip = NULLIF(d.ip, '')"
                           " AND COALESCE(m.host,'') <> '')");
                if (f & WEB_QF_NBNS)
                    sb_put(b, " OR EXISTS (SELECT 1 FROM nbns_names b WHERE b.ip = NULLIF(d.ip, '')"
                           " AND b.suffix IN (0, 32))");
                sb_put(b, " OR web_ptr(d.ip) IS NOT NULL))");
            }
            sb_put(b, ")");
            break;
        case WEB_HAS_IP:
            sb_put(b, "(");
            co(b, c->ip);
            sb_put(b, " <> '')");
            break;
        default:
            sb_put(b, "(");
            co(b, c->ssid);
            sb_put(b, " <> ''");
            if ((f & WEB_QF_PNL) && !loc)
                sb_put(b, " OR EXISTS (SELECT 1 FROM pnl_ssids s WHERE s.mac = d.mac)");
            sb_put(b, ")");
            break;
        }
        break;
    case WEB_QT_ANOMALY:
        sb_put(b, "(web_anoms(d.mac,");
        param(b, bind_int(o, t->num));
        sb_put(b, ") > 0)");
        break;
    case WEB_QT_PASS:
        if (!c->scope) {
            sb_put(b, "(web_inpass(d.mac) = 1)");
        } else {
            /* In the pass, and a row of the scope's in it. */
            sb_put(b, mon ? "(web_inpass(d.mac, 1) = 1)" : "(web_inpass(d.mac, 2) = 1)");
        }
        break;
    default:
        sb_put(b, "(0)");
        break;
    }
}

static int row_select(const dcols_t *c, const char *extra, char *out, size_t cap) {
    sb_t b = { out, cap, 0, 0 };
    unsigned f = c->f;
    out[0] = '\0';
    if (!c->scope) {
        sb_put(&b, "SELECT d.mac, d.ip, d.hostname, d.vendor, d.last_ssid,"
                " d.signal_dbm, d.sources, d.risk_signals, d.risk_level,"
                " d.first_seen, d.last_seen, d.is_ap, ");
    } else {
        /* Named, so the ORDER BY says each once (SQLite resolves a
         * result column's alias inside an ORDER BY expression). */
        sb_put(&b, "SELECT d.mac, ");
        sb_put(&b, c->ip);
        sb_put(&b, " AS s_ip, ");
        sb_put(&b, c->host);
        sb_put(&b, " AS s_host, d.vendor, ");
        sb_put(&b, c->ssid);
        sb_put(&b, " AS s_ssid, ");
        sb_put(&b, c->signal);
        sb_put(&b, " AS s_signal, ");
        sb_put(&b, c->sources);
        sb_put(&b, " AS s_sources, ");
        sb_put(&b, c->rsig);
        sb_put(&b, " AS s_rsig, ");
        sb_put(&b, c->risk);
        sb_put(&b, " AS s_risk, ");
        sb_put(&b, c->first);
        sb_put(&b, " AS s_first, ");
        sb_put(&b, c->last);
        sb_put(&b, " AS s_last, ");
        sb_put(&b, c->is_ap);
        sb_put(&b, " AS s_is_ap, ");
    }
    /* The names behind the address are Local's: Monitor has none. */
    int names = c->scope != 1;
    sb_put(&b, (f & WEB_QF_DHCP) && names
            ? "(SELECT l.hostname FROM dhcp_leases l WHERE l.ip = NULLIF(d.ip, '') AND"
              " COALESCE(l.hostname,'') <> '' ORDER BY l.last_seen DESC LIMIT 1), "
            : "NULL, ");
    sb_put(&b, (f & WEB_QF_MDNS) && names
            ? "(SELECT m.host FROM mdns_services m WHERE m.ip = NULLIF(d.ip, '') AND"
              " COALESCE(m.host,'') <> '' ORDER BY m.last_seen DESC LIMIT 1), "
            : "NULL, ");
    sb_put(&b, (f & WEB_QF_NBNS) && names
            ? "(SELECT b.name FROM nbns_names b WHERE b.ip = NULLIF(d.ip, '') AND"
              " b.suffix IN (0, 32) ORDER BY b.last_seen DESC LIMIT 1)"
            : "NULL");
    if (extra) { sb_put(&b, ", "); sb_put(&b, extra); }
    sb_put(&b, " FROM devices d");
    return b.over ? -1 : 0;
}

int web_query_row_select(unsigned f, const char *extra, char *out,
                         size_t cap) {
    return web_query_row_select_scoped(f, 0, extra, out, cap);
}

int web_query_row_select_scoped(unsigned f, int scope, const char *extra,
                                char *out, size_t cap) {
    dcols_t *c = malloc(sizeof(*c));
    if (!c) return -1;
    dcols(f, scope, c);
    int rc = row_select(c, extra, out, cap);
    free(c);
    return rc;
}

int web_query_member(unsigned f, int scope, char *out, size_t cap) {
    out[0] = '\0';
    if (!scope) return 0;
    dcols_t *c = malloc(sizeof(*c));
    if (!c) return -1;
    dcols(f, scope, c);
    int rc = strlen(c->member) + 1 > cap ? -1 : 0;
    if (!rc) memcpy(out, c->member, strlen(c->member) + 1);
    free(c);
    return rc;
}

int web_query_compile(const web_query_t *q, unsigned feats, int sort,
                      long long limit, long long offset, web_qsql_t *out) {
    return web_query_compile_scoped(q, feats, 0, sort, limit, offset, out);
}

int web_query_compile_scoped(const web_query_t *q, unsigned feats, int scope,
                             int sort, long long limit, long long offset,
                             web_qsql_t *out) {
    static const char *const ORDER[WEB_QS_COUNT] = {
        " ORDER BY d.last_seen DESC, d.mac",
        " ORDER BY d.first_seen DESC, d.mac",
        " ORDER BY d.mac",
        " ORDER BY d.risk_level DESC, d.last_seen DESC, d.mac",
        " ORDER BY d.vendor IS NULL, d.vendor, d.mac",
        " ORDER BY web_ipkey(d.ip) IS NULL, web_ipkey(d.ip), d.ip, d.mac",
        " ORDER BY d.last_ssid IS NULL, d.last_ssid, d.mac",
        " ORDER BY d.signal_dbm IS NULL, d.signal_dbm DESC, d.mac",
        " ORDER BY d.sources DESC, d.last_seen DESC, d.mac",
    };
    /* With a direction: the sort's column, empty last, then the MAC.
     * An address sorts by its numeric key (web_slothdb.c fn_ipkey()),
     * as the page compares addresses, not as text. */
    static const char *const KEY[WEB_QS_COUNT] = {
        "d.last_seen", "d.first_seen", "d.mac", "d.risk_level", "d.vendor",
        "web_ipkey(d.ip)", "d.last_ssid", "d.signal_dbm", "d.sources",
    };
    int dir = WEB_SORT_DIR(sort);
    sort = WEB_SORT_KEY(sort);
    memset(out, 0, sizeof(*out));
    dcols_t *c = malloc(sizeof(*c));
    if (!c) return -1;
    dcols(feats, scope, c);
    if (row_select(c, NULL, out->sql, sizeof(out->sql)) != 0) { free(c); return -1; }
    sb_t b = { out->sql, sizeof(out->sql), strlen(out->sql), 0 };
    sb_put(&b, " WHERE 1");
    if (scope) {
        sb_put(&b, " AND ");
        sb_put(&b, c->member);
    }
    for (int i = 0; i < q->n && i < WEB_Q_TERMS; i++) {
        sb_put(&b, q->t[i].neg ? " AND NOT " : " AND ");
        term(&b, &q->t[i], c, out);
    }
    if (sort < 0 || sort >= WEB_QS_COUNT) sort = WEB_QS_LAST;
    if (scope) {
        /* The scope's columns by their aliases (the SELECT list above),
         * in the Hybrid orders' shapes. */
        static const char *const SORD[WEB_QS_COUNT] = {
            " ORDER BY s_last DESC, d.mac",
            " ORDER BY s_first DESC, d.mac",
            " ORDER BY d.mac",
            " ORDER BY s_risk DESC, s_last DESC, d.mac",
            " ORDER BY d.vendor IS NULL, d.vendor, d.mac",
            " ORDER BY web_ipkey(s_ip) IS NULL, web_ipkey(s_ip), s_ip, d.mac",
            " ORDER BY s_ssid IS NULL, s_ssid, d.mac",
            " ORDER BY s_signal IS NULL, s_signal DESC, d.mac",
            " ORDER BY s_sources DESC, s_last DESC, d.mac",
        };
        if (dir == WEB_SORT_ASC || dir == WEB_SORT_DESC) {
            static const char *const SKEY[WEB_QS_COUNT] = {
                "s_last", "s_first", "d.mac", "s_risk", "d.vendor",
                "web_ipkey(s_ip)", "s_ssid", "s_signal", "s_sources",
            };
            sb_put(&b, " ORDER BY ");
            sb_put(&b, SKEY[sort]);
            sb_put(&b, " IS NULL, ");
            sb_put(&b, SKEY[sort]);
            sb_put(&b, dir == WEB_SORT_ASC ? " ASC" : " DESC");
            if (sort != WEB_QS_MAC) sb_put(&b, ", d.mac");
        } else {
            sb_put(&b, SORD[sort]);
        }
    } else if (dir == WEB_SORT_ASC || dir == WEB_SORT_DESC) {
        sb_put(&b, " ORDER BY ");
        sb_put(&b, KEY[sort]);
        sb_put(&b, " IS NULL, ");
        sb_put(&b, KEY[sort]);
        sb_put(&b, dir == WEB_SORT_ASC ? " ASC" : " DESC");
        if (sort != WEB_QS_MAC) sb_put(&b, ", d.mac");
    } else {
        sb_put(&b, ORDER[sort]);
    }
    free(c);
    sb_put(&b, " LIMIT ");
    param(&b, bind_int(out, limit));
    sb_put(&b, " OFFSET ");
    param(&b, bind_int(out, offset));
    return b.over ? -1 : 0;
}
