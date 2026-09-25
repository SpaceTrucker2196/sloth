/* Approved-inventory trust anchor. Contract in inventory.h (#89 slice 2).
 *
 * The JSON reader is hand-rolled and deliberately so. The repo has no
 * JSON *parser* — src/jsonl.c and src/formatter.c only write, and
 * src/updater.c's scan_str_field is a flat key scanner that says of
 * itself that it is "not a general JSON parser". A substring scanner
 * cannot express `networks[].bssids[]`, and worse, it would happily
 * find `"ssid"` inside a string *value* and read the file the operator
 * did not write. Adding a library for ~300 lines would be the first
 * third-party dependency in a tree whose embedded build links nothing
 * but pthread and libm.
 *
 * So: recursive descent, RFC 8259 syntax, every bound checked, one
 * depth cap, and a hard refusal on anything it does not fully
 * understand. It parses the whole document — including the fields it
 * ignores — because "sloth did not read that key" is not a reason to
 * accept a file that is malformed inside it. */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "inventory.h"
#include "ownership.h"
#include "sha256.h"

typedef struct {
    char ssid[INV_SSID_LEN];
    char profile[INV_PROFILE_LEN];
    int  first;                 /* index of the first BSSID in `bssids` */
    int  count;
} inv_net_t;

typedef struct {
    inv_net_t nets[INV_MAX_NETWORKS];
    int       net_n;
    uint8_t   bssids[INV_MAX_BSSIDS][6];
    int       bssid_n;
    char      version[INV_VERSION_LEN];
    char      site[INV_SITE_LEN];
    char      hash[INV_HASH_LEN];
    int       loaded;
} inv_t;

/* `g_live` is what every lookup reads; `g_stage` is where a load
 * builds. The two are separate so a rejected file cannot leave a
 * half-built inventory behind — see the all-or-nothing note in the
 * header. The commit is a single struct copy at the end of a
 * fully-successful parse. */
static inv_t g_live;
static inv_t g_stage;

/* --site, kept apart from the file's `site` so precedence does not
 * depend on the order argv happens to be walked in. */
static char  g_site_flag[INV_SITE_LEN];

/* ── JSON reader ─────────────────────────────────────────── */

typedef struct {
    const char *base;
    const char *p;
    const char *end;
    int         depth;
    char        err[INV_ERR_MAX];
} jp_t;

/* First failure wins: it is the one closest to the operator's mistake,
 * and every caller above it unwinds without overwriting the reason. */
static int jp_fail(jp_t *j, const char *fmt, ...) {
    if (!j->err[0]) {
        /* Leaves room for the " at byte N" suffix appended below, so
         * the offset is never the part that gets truncated away. */
        char msg[INV_ERR_MAX - 32];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(msg, sizeof(msg), fmt, ap);
        va_end(ap);
        snprintf(j->err, sizeof(j->err), "%s at byte %ld",
                 msg, (long)(j->p - j->base));
    }
    return 0;
}

static void skip_ws(jp_t *j) {
    while (j->p < j->end && (*j->p == ' '  || *j->p == '\t' ||
                             *j->p == '\r' || *j->p == '\n'))
        j->p++;
}

static int peek(jp_t *j) { return j->p < j->end ? (unsigned char)*j->p : -1; }

static int expect(jp_t *j, char c) {
    skip_ws(j);
    if (peek(j) != (unsigned char)c)
        return jp_fail(j, "expected '%c'", c);
    j->p++;
    return 1;
}

/* A stored string may not carry a byte that would corrupt the alert
 * detail line or the JSONL record it is copied into. Bytes >= 0x80 pass
 * through so a UTF-8 SSID survives; sloth treats an SSID as opaque
 * octets either way. */
static int printable_octet(unsigned char c) { return c >= 0x20 && c != 0x7f; }

/* Parse one JSON string. `out` NULL consumes without storing — used for
 * the fields sloth ignores, which still have to be syntactically whole.
 *
 * \u is refused rather than half-implemented: decoding it correctly
 * means UTF-16 surrogate pairing into UTF-8 for a field that carries
 * opaque 802.11 octets, and a wrong decode stores an SSID that then
 * silently fails to match the operator's own AP. */
static int parse_string(jp_t *j, char *out, size_t outsz, const char *what) {
    skip_ws(j);
    if (peek(j) != '"') return jp_fail(j, "%s must be a string", what);
    j->p++;
    size_t n = 0;
    while (j->p < j->end) {
        unsigned char c = (unsigned char)*j->p++;
        if (c == '"') {
            if (out) out[n] = '\0';
            return 1;
        }
        if (c < 0x20)
            return jp_fail(j, "%s contains a raw control byte", what);
        if (c == '\\') {
            if (j->p >= j->end) break;
            unsigned char e = (unsigned char)*j->p++;
            switch (e) {
            case '"':  c = '"';  break;
            case '\\': c = '\\'; break;
            case '/':  c = '/';  break;
            case 'b':  c = 0x08; break;
            case 'f':  c = 0x0c; break;
            case 'n':  c = 0x0a; break;
            case 'r':  c = 0x0d; break;
            case 't':  c = 0x09; break;
            case 'u':
                return jp_fail(j, "%s uses \\u, which sloth does not decode",
                               what);
            default:
                return jp_fail(j, "%s has an unknown escape \\%c", what, e);
            }
        }
        if (!out) continue;
        if (!printable_octet(c))
            return jp_fail(j, "%s contains a non-printable byte", what);
        if (n + 1 >= outsz)
            return jp_fail(j, "%s exceeds %d bytes", what, (int)outsz - 1);
        out[n++] = (char)c;
    }
    return jp_fail(j, "%s is unterminated", what);
}

static int parse_value(jp_t *j);

static int parse_number(jp_t *j) {
    const char *start = j->p;
    if (peek(j) == '-') j->p++;
    while (j->p < j->end && ((*j->p >= '0' && *j->p <= '9') ||
                             *j->p == '.' || *j->p == 'e' || *j->p == 'E' ||
                             *j->p == '+' || *j->p == '-'))
        j->p++;
    if (j->p == start) return jp_fail(j, "not a value");
    return 1;
}

static int parse_literal(jp_t *j, const char *lit) {
    size_t n = strlen(lit);
    if ((size_t)(j->end - j->p) < n || memcmp(j->p, lit, n) != 0)
        return jp_fail(j, "not a value");
    j->p += n;
    return 1;
}

/* Consume any well-formed value, for the keys sloth does not read.
 * Depth-capped: a file of nothing but '[' must hit a limit, not the C
 * stack. */
static int parse_value(jp_t *j) {
    if (++j->depth > INV_MAX_DEPTH) {
        j->depth--;
        return jp_fail(j, "nested more than %d deep", INV_MAX_DEPTH);
    }
    int ok = 1;
    skip_ws(j);
    switch (peek(j)) {
    case '"':
        ok = parse_string(j, NULL, 0, "value");
        break;
    case '{':
        j->p++;
        skip_ws(j);
        if (peek(j) == '}') { j->p++; break; }
        for (;;) {
            if (!parse_string(j, NULL, 0, "key")) { ok = 0; break; }
            if (!expect(j, ':'))                  { ok = 0; break; }
            if (!parse_value(j))                  { ok = 0; break; }
            skip_ws(j);
            if (peek(j) == ',') { j->p++; continue; }
            if (!expect(j, '}')) ok = 0;
            break;
        }
        break;
    case '[':
        j->p++;
        skip_ws(j);
        if (peek(j) == ']') { j->p++; break; }
        for (;;) {
            if (!parse_value(j)) { ok = 0; break; }
            skip_ws(j);
            if (peek(j) == ',') { j->p++; continue; }
            if (!expect(j, ']')) ok = 0;
            break;
        }
        break;
    case 't': ok = parse_literal(j, "true");  break;
    case 'f': ok = parse_literal(j, "false"); break;
    case 'n': ok = parse_literal(j, "null");  break;
    default:  ok = parse_number(j);           break;
    }
    j->depth--;
    return ok;
}

/* ── staging helpers ─────────────────────────────────────── */

static int stage_add_bssid(jp_t *j, const char *text) {
    uint8_t mac[6];
    if (!ownership_parse_mac(text, mac))
        return jp_fail(j, "'%.24s' is not aa:bb:cc:dd:ee:ff", text);
    /* Spelling is not identity: aa:bb:… and AA-BB-… are one address,
     * and a duplicate must not slip past by being typed differently. */
    for (int i = 0; i < g_stage.bssid_n; i++)
        if (memcmp(g_stage.bssids[i], mac, 6) == 0)
            return jp_fail(j, "BSSID '%.24s' is listed twice", text);
    if (g_stage.bssid_n >= INV_MAX_BSSIDS)
        return jp_fail(j, "more than %d BSSIDs", INV_MAX_BSSIDS);
    memcpy(g_stage.bssids[g_stage.bssid_n++], mac, 6);
    return 1;
}

/* One `networks` entry. */
static int parse_network(jp_t *j) {
    if (g_stage.net_n >= INV_MAX_NETWORKS)
        return jp_fail(j, "more than %d networks", INV_MAX_NETWORKS);
    inv_net_t *net = &g_stage.nets[g_stage.net_n];
    memset(net, 0, sizeof(*net));
    net->first = g_stage.bssid_n;

    skip_ws(j);
    if (peek(j) != '{') return jp_fail(j, "each network must be an object");
    j->p++;

    int saw_ssid = 0, saw_bssids = 0, saw_profile = 0;
    skip_ws(j);
    if (peek(j) == '}') { j->p++; return jp_fail(j, "network has no 'ssid'"); }
    for (;;) {
        char key[40];
        if (!parse_string(j, key, sizeof(key), "network key")) return 0;
        if (!expect(j, ':')) return 0;

        if (strcmp(key, "ssid") == 0) {
            if (saw_ssid++) return jp_fail(j, "duplicate 'ssid'");
            if (!parse_string(j, net->ssid, sizeof(net->ssid), "ssid"))
                return 0;
            if (!net->ssid[0]) return jp_fail(j, "'ssid' is empty");
        } else if (strcmp(key, "security_profile") == 0) {
            if (saw_profile++) return jp_fail(j, "duplicate 'security_profile'");
            if (!parse_string(j, net->profile, sizeof(net->profile),
                              "security_profile"))
                return 0;
        } else if (strcmp(key, "bssids") == 0) {
            if (saw_bssids++) return jp_fail(j, "duplicate 'bssids'");
            skip_ws(j);
            if (peek(j) != '[') return jp_fail(j, "'bssids' must be an array");
            j->p++;
            skip_ws(j);
            if (peek(j) != ']') {
                for (;;) {
                    char mac[32];
                    if (!parse_string(j, mac, sizeof(mac), "bssid")) return 0;
                    if (!stage_add_bssid(j, mac)) return 0;
                    net->count++;
                    skip_ws(j);
                    if (peek(j) == ',') { j->p++; continue; }
                    break;
                }
            }
            if (!expect(j, ']')) return 0;
        } else {
            if (!parse_value(j)) return 0;   /* ignored, still validated */
        }

        skip_ws(j);
        if (peek(j) == ',') { j->p++; continue; }
        if (!expect(j, '}')) return 0;
        break;
    }

    if (!saw_ssid)   return jp_fail(j, "network has no 'ssid'");
    if (!saw_bssids) return jp_fail(j, "network '%.32s' has no 'bssids'",
                                    net->ssid);
    /* An entry with an empty set approves nothing while claiming to
     * describe the network — every one of the operator's own radios
     * would read as a mismatch. That is a typo, not a policy. */
    if (net->count == 0)
        return jp_fail(j, "network '%.32s' lists no BSSIDs", net->ssid);
    /* Two entries for one SSID leave "which security_profile is
     * authoritative" unanswerable, so the file is refused rather than
     * silently resolved one way. */
    for (int i = 0; i < g_stage.net_n; i++)
        if (strcmp(g_stage.nets[i].ssid, net->ssid) == 0)
            return jp_fail(j, "SSID '%.32s' is listed twice", net->ssid);

    g_stage.net_n++;
    return 1;
}

static int parse_networks(jp_t *j) {
    skip_ws(j);
    if (peek(j) != '[') return jp_fail(j, "'networks' must be an array");
    j->p++;
    skip_ws(j);
    if (peek(j) == ']') { j->p++; return 1; }   /* declared nothing */
    for (;;) {
        if (!parse_network(j)) return 0;
        skip_ws(j);
        if (peek(j) == ',') { j->p++; continue; }
        break;
    }
    return expect(j, ']');
}

static int parse_document(jp_t *j) {
    skip_ws(j);
    if (peek(j) != '{')
        return jp_fail(j, "the inventory must be a JSON object");
    j->p++;

    int saw_version = 0, saw_site = 0, saw_networks = 0;
    skip_ws(j);
    if (peek(j) == '}') { j->p++; return jp_fail(j, "no 'networks' array"); }
    for (;;) {
        char key[40];
        if (!parse_string(j, key, sizeof(key), "key")) return 0;
        if (!expect(j, ':')) return 0;

        if (strcmp(key, "version") == 0) {
            if (saw_version++) return jp_fail(j, "duplicate 'version'");
            if (!parse_string(j, g_stage.version, sizeof(g_stage.version),
                              "version"))
                return 0;
        } else if (strcmp(key, "site") == 0) {
            if (saw_site++) return jp_fail(j, "duplicate 'site'");
            if (!parse_string(j, g_stage.site, sizeof(g_stage.site), "site"))
                return 0;
            /* ':' separates the fields of the canonical pair key, so a
             * site carrying one would make the key ambiguous. */
            if (strchr(g_stage.site, ':'))
                return jp_fail(j, "'site' may not contain ':'");
        } else if (strcmp(key, "networks") == 0) {
            if (saw_networks++) return jp_fail(j, "duplicate 'networks'");
            if (!parse_networks(j)) return 0;
        } else {
            if (!parse_value(j)) return 0;   /* forward-compatible */
        }

        skip_ws(j);
        if (peek(j) == ',') { j->p++; continue; }
        if (!expect(j, '}')) return 0;
        break;
    }

    if (!saw_networks) return jp_fail(j, "no 'networks' array");
    /* Anything after the document is a second file glued onto the
     * first, or a truncated edit. Either way it is not what the
     * operator meant to load. */
    skip_ws(j);
    if (j->p != j->end) return jp_fail(j, "trailing content after the object");
    return 1;
}

/* ── public API ──────────────────────────────────────────── */

static void set_err(char *err, size_t errsz, const char *path,
                    const char *fmt, ...) {
    if (!err || !errsz) return;
    char msg[INV_ERR_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    snprintf(err, errsz, "%s: %s", path ? path : "(null)", msg);
}

int inventory_load(const char *path, char *err, size_t errsz) {
    if (err && errsz) err[0] = '\0';
    if (!path || !path[0]) {
        set_err(err, errsz, path, "no inventory path given");
        return 0;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        set_err(err, errsz, path, "cannot open (%s)", strerror(errno));
        return 0;
    }
    /* Read one byte past the cap so "exactly at the cap" and "over it"
     * are distinguishable without trusting a stat size. */
    size_t cap = INV_FILE_MAX + 1;
    char  *buf = malloc(cap + 1);
    if (!buf) {
        fclose(f);
        set_err(err, errsz, path, "out of memory");
        return 0;
    }
    size_t n = fread(buf, 1, cap, f);
    int    rd_err = ferror(f);
    fclose(f);

    if (rd_err) {
        free(buf);
        set_err(err, errsz, path, "read failed");
        return 0;
    }
    if (n > INV_FILE_MAX) {
        free(buf);
        set_err(err, errsz, path, "larger than %d bytes", INV_FILE_MAX);
        return 0;
    }
    if (n == 0) {
        free(buf);
        set_err(err, errsz, path, "is empty");
        return 0;
    }
    /* A NUL would end the document early for a C parser, so the bytes
     * after it would never be read at all — a silent partial load by
     * another name. */
    if (memchr(buf, '\0', n)) {
        free(buf);
        set_err(err, errsz, path, "contains a NUL byte");
        return 0;
    }
    buf[n] = '\0';

    memset(&g_stage, 0, sizeof(g_stage));
    jp_t j;
    memset(&j, 0, sizeof(j));
    j.base = buf;
    j.p    = buf;
    j.end  = buf + n;

    if (!parse_document(&j)) {
        set_err(err, errsz, path, "%s",
                j.err[0] ? j.err : "malformed JSON");
        memset(&g_stage, 0, sizeof(g_stage));
        free(buf);
        return 0;   /* g_live untouched — all or nothing */
    }

    /* Identity is the bytes, not the label: two files may both call
     * themselves "2026-09-24.1". Truncated to 16 hex characters — this
     * names a local file in an alert line, it is not a security
     * boundary, and 64 characters on every twin alert is noise. */
    char full[65];
    sha256_hex((const uint8_t *)buf, n, full);
    snprintf(g_stage.hash, sizeof(g_stage.hash), "%.*s", INV_HASH_LEN - 1,
             full);
    free(buf);

    g_stage.loaded = 1;
    g_live = g_stage;
    memset(&g_stage, 0, sizeof(g_stage));
    return 1;
}

void inventory_clear(void) {
    memset(&g_live,  0, sizeof(g_live));
    memset(&g_stage, 0, sizeof(g_stage));
    memset(g_site_flag, 0, sizeof(g_site_flag));
}

int inventory_loaded(void)        { return g_live.loaded; }
int inventory_network_count(void) { return g_live.net_n; }
int inventory_bssid_count(void)   { return g_live.bssid_n; }

const char *inventory_hash(void)    { return g_live.hash; }
const char *inventory_version(void) { return g_live.version; }

const char *inventory_site(void) {
    if (g_site_flag[0]) return g_site_flag;
    return g_live.site;
}

int inventory_set_site(const char *site) {
    if (!site || !site[0]) {
        fprintf(stderr, "sloth: --site needs a non-empty label\n");
        return 0;
    }
    if (strlen(site) >= INV_SITE_LEN) {
        fprintf(stderr, "sloth: --site '%s' exceeds %d bytes\n",
                site, INV_SITE_LEN - 1);
        return 0;
    }
    for (const char *p = site; *p; p++) {
        if (!printable_octet((unsigned char)*p)) {
            fprintf(stderr, "sloth: --site contains a non-printable byte\n");
            return 0;
        }
        if (*p == ':') {
            /* ':' separates the fields of the canonical pair key. */
            fprintf(stderr, "sloth: --site '%s' may not contain ':'\n", site);
            return 0;
        }
    }
    snprintf(g_site_flag, sizeof(g_site_flag), "%s", site);
    return 1;
}

static const inv_net_t *find_net(const char *ssid) {
    if (!ssid || !ssid[0]) return NULL;
    for (int i = 0; i < g_live.net_n; i++)
        if (strcmp(g_live.nets[i].ssid, ssid) == 0) return &g_live.nets[i];
    return NULL;
}

inv_verdict_t inventory_verdict(const char *ssid, const uint8_t bssid[6]) {
    if (!g_live.loaded || !bssid) return INV_NO_INVENTORY;
    const inv_net_t *net = find_net(ssid);
    if (!net) return INV_NO_INVENTORY;
    for (int i = 0; i < net->count; i++)
        if (memcmp(g_live.bssids[net->first + i], bssid, 6) == 0)
            return INV_APPROVED;
    /* The flag merge (#52): --my-bssid is unioned in, never intersected
     * out. Reasoning in inventory.h. */
    if (ownership_is_my_bssid(bssid)) return INV_APPROVED;
    return INV_MISMATCH;
}

const char *inventory_profile_for_ssid(const char *ssid) {
    const inv_net_t *net = find_net(ssid);
    return net ? net->profile : "";
}
