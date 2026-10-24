/* The page colours data as sloth's TUI does (owner ruling 2026-10-23).
 *
 * Each case runs the TUI itself, src/tui.c's ANSI backend linked into
 * this binary, captures the SGR it writes for an address, an SSID, a
 * host name or an info string, and compares the colour of every byte
 * with the colour the page gives that byte: the page's JS (pinned as
 * served) through a C port of it, its tables (SLOTH_PALETTE) and its
 * generated custom properties read out of the served page. A drift in
 * the TUI, in the generator (web/tools/palette.c) or in app.js is a
 * failure here.
 *
 * The C ports below follow the JS line for line. utf8() has no port: a
 * C string already is the bytes the TUI hashes, and the JS turns its
 * UTF-16 string back into those same bytes. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../src/ip_color.h"
#include "../../src/persist_health.h"
#include "sloth.h"
#include "../../src/sloth_clock.h"
#include "../../src/tui.h"
#include "../../src/tui_palette.h"
#include "web_assets.h"
#include "wtest.h"

/* ── what src/tui.c links against and this test never calls ─────── */

#define X(id, label, key, slug) \
    void view_##slug##_draw(const sloth_state_t *s); \
    void view_##slug##_draw(const sloth_state_t *s) { (void)s; }
#include "sloth_views.def"
#undef X

int persist_badge(const persist_health_t *p, char *buf, size_t sz) {
    (void)p; (void)buf; (void)sz;
    return 0;
}

/* tui_ip_addstr()'s alert-hot table is empty in every case here, so
 * the clock is never read for a decision. */
time_t sloth_wall(void) { return 0; }

static const char *page(void) { return (const char *)web_page; }

/* ── the TUI, captured ──────────────────────────────────────────── */

typedef struct { int fg[256]; int bold[256]; char text[256]; int n; } run_t;

/* Run fn(arg) with stdout in a temporary file, then decode its SGR:
 * every text byte gets the 256-colour foreground and the bold flag
 * live when it was written. */
static int capture(void (*fn)(const char *), const char *arg, run_t *out) {
    memset(out, 0, sizeof(*out));
    fflush(stdout);
    FILE *tmp = tmpfile();
    if (!tmp) return -1;
    int saved = dup(1);
    if (saved < 0 || dup2(fileno(tmp), 1) < 0) { fclose(tmp); return -1; }
    fn(arg);
    fflush(stdout);
    dup2(saved, 1);
    close(saved);
    char buf[4096];
    rewind(tmp);
    size_t n = fread(buf, 1, sizeof(buf) - 1, tmp);
    fclose(tmp);
    buf[n] = '\0';
    int fg = -1, bold = 0;
    for (size_t i = 0; i < n;) {
        if (buf[i] == '\033' && buf[i + 1] == '[') {
            size_t j = i + 2;
            int a = 0, b = 0, c = 0, k = sscanf(buf + j, "%d;%d;%dm", &a, &b, &c);
            if (k == 3 && a == 38 && b == 5) fg = c;
            else if (k >= 1 && a == 0) { bold = 0; fg = -1; }
            else if (k >= 1 && a == 1) bold = 1;
            while (j < n && buf[j] != 'm') j++;
            i = j + 1;
            continue;
        }
        if (out->n < 255) {
            out->fg[out->n] = fg;
            out->bold[out->n] = bold;
            out->text[out->n++] = buf[i];
        }
        i++;
    }
    return 0;
}

static void tui_ip(const char *s)   { tui_ip_addstr(s, 0); }
static void tui_ssid(const char *s) { tui_ssid_addstr(s, 0); }
static void tui_brand(const char *s) { tui_brand_addstr(s, 0); }
static void tui_info(const char *s) { tui_info_color(s); tui_addstr(s); }

/* ── the page's tables and properties ───────────────────────────── */

/* xterm-256 to hex, the standard formula. */
static void xterm_hex(int i, char out[8]) {
    static const unsigned char sys[16][3] = {
        { 0, 0, 0 },       { 128, 0, 0 },     { 0, 128, 0 },   { 128, 128, 0 },
        { 0, 0, 128 },     { 128, 0, 128 },   { 0, 128, 128 }, { 192, 192, 192 },
        { 128, 128, 128 }, { 255, 0, 0 },     { 0, 255, 0 },   { 255, 255, 0 },
        { 0, 0, 255 },     { 255, 0, 255 },   { 0, 255, 255 }, { 255, 255, 255 },
    };
    static const int lv[6] = { 0, 95, 135, 175, 215, 255 };
    int r = 0, g = 0, b = 0;
    if (i >= 0 && i < 16) { r = sys[i][0]; g = sys[i][1]; b = sys[i][2]; }
    else if (i >= 16 && i < 232) { int k = i - 16; r = lv[k / 36]; g = lv[k / 6 % 6]; b = lv[k % 6]; }
    else if (i >= 232 && i < 256) r = g = b = 8 + 10 * (i - 232);
    snprintf(out, 8, "#%02x%02x%02x", r, g, b);
}

/* The served value of a custom property in the dark block, which is
 * the first place the page names it (palette.css leads the <style>). */
static int prop(const char *name, char out[8]) {
    char key[40];
    snprintf(key, sizeof(key), "  %s: ", name);
    const char *t = strstr(page(), key);
    if (!t) return -1;
    t += strlen(key);
    if (t[0] != '#' || strlen(t) < 7) return -1;
    memcpy(out, t, 7);
    out[7] = '\0';
    return 0;
}

static struct {
    int ip, google, gseq[16], ngseq, nbr;
    int br[256];
    char sub[256][40];
    int src[8];
} P;

static const char *const SRC_NAME[7] = { "conn", "pkt", "arp", "dns", "icmp", "alert", "dev" };

static int read_palette(void) {
    memset(&P, 0, sizeof(P));
    const char *p = strstr(page(), "var SLOTH_PALETTE = {\n");
    if (!p || sscanf(p, "var SLOTH_PALETTE = {\n  ip: %d, info: 8, google: %d,", &P.ip,
                     &P.google) != 2)
        return -1;
    const char *g = strstr(p, "gseq: [");
    if (!g) return -1;
    g += 7;
    while (*g != ']' && P.ngseq < 16) {
        P.gseq[P.ngseq++] = (int)strtol(g, (char **)&g, 10);
        while (*g == ',' || *g == ' ') g++;
    }
    const char *b = strstr(p, "brands: [\n");
    const char *e = b ? strstr(b, "\n  ]\n};") : NULL;
    if (!e) return -1;
    for (const char *q = b + 10; q < e && P.nbr < 256;) {
        int v, used = 0;
        char s[40];
        if (sscanf(q, " [%d, \"%39[^\"]\"]%n", &v, s, &used) != 2 || used == 0) break;
        P.br[P.nbr] = v;
        snprintf(P.sub[P.nbr++], sizeof(P.sub[0]), "%s", s);
        q += used;
        while (*q == ',' || *q == '\n') q++;
    }
    const char *x = strstr(page(), "var IP_SRC = { ");
    if (!x) return -1;
    for (int i = 0; i < 7; i++) {
        char k[16];
        snprintf(k, sizeof(k), "%s: ", SRC_NAME[i]);
        const char *v = strstr(x, k);
        if (!v || v - x > 120) return -1;
        P.src[i] = atoi(v + strlen(k));
    }
    return 0;
}

/* ── C ports of the page's functions ────────────────────────────── */

/* ipColorIndex() */
static int js_ip_color_index(const char *s) {
    if (!s[0]) return 0;
    uint32_t h = 5381;
    for (const unsigned char *b = (const unsigned char *)s; *b; b++) h = ((h << 5) + h) + *b;
    return (int)(h % (uint32_t)P.ip);
}

static char lower_ascii(char c) { return c >= 'A' && c <= 'Z' ? (char)(c + 32) : c; }

/* indexOf() over the lower-cased string, from `at`. */
static int index_of(const char *low, const char *sub, int at) {
    const char *h = strstr(low + at, sub);
    return h ? (int)(h - low) : -1;
}

/* brandRuns(): per byte, the brand slot, or -1 for the base pair. */
static void js_brand_slots(const char *s, int *slot) {
    char low[256];
    int n = (int)strlen(s);
    for (int i = 0; i <= n; i++) low[i] = lower_ascii(s[i]);
    for (int i = 0; i < n; i++) slot[i] = -1;
    int at = 0;
    for (;;) {
        int best = -1, brand = 0, len = 0;
        for (int i = 0; i < P.nbr; i++) {
            int j = index_of(low, P.sub[i], at);
            if (j >= 0 && (best < 0 || j < best)) { best = j; brand = P.br[i]; len = (int)strlen(P.sub[i]); }
        }
        if (best < 0) return;
        for (int k = 0; k < len; k++)
            slot[best + k] = brand == P.google ? P.gseq[k % P.ngseq] : brand;
        at = best + len;
    }
}

/* ipNote()'s mask and crossPanel(). */
static int js_cross_panel(int m) { return (m & (m - 1)) != 0; }

/* ── the cases ──────────────────────────────────────────────────── */

static const char *const IPS[] = {
    "10.0.0.1", "10.0.0.2", "192.168.1.1", "192.168.1.254", "172.16.0.10",
    "198.51.100.7", "203.0.113.42", "8.8.8.8", "1.1.1.1", "127.0.0.1",
    "0.0.0.0", "255.255.255.255", "2001:db8::1", "fe80::1c2b:3cff:fe4d:5e6f",
    "::1", "2001:db8:cafe::ab:1234", "::ffff:192.0.2.1", "100.64.0.9",
};
static const char *const SSIDS[] = {
    "home-net", "CoffeeShop_Guest", "xfinitywifi", "eduroam", "DIRECT-ab-HP",
    "linksys", "NETGEAR42", "Caf\xc3\xa9 Wi-Fi", "\xe2\x98\x95 espresso",
    "a", "TP-Link_5G", "attwifi",
};
static const char *const HOSTS[] = {
    "www.google.com", "WWW.GOOGLE.COM", "mail.gmail.com", "i.ytimg.com",
    "lh3.googleusercontent.com", "youtu.be", "detectportal.firefox.com",
    "cloudflare-dns.com", "one.one.cloudflare.com", "example.org", "www.example.com",
    "api.github.com", "cdn.discordapp.com", "static.xx.fbcdn.net",
    "open.spotify.com", "www.twitch.tv", "s3.amazonaws.com", "www.linkedin.com",
    "ipv4-c001.nflxvideo.net", "old.reddit.com", "scontent.cdninstagram.com",
    "google-cloudflare.example.net", "printer.local", "nas", "api.anthropic.com",
    "claude.ai", "settings-win.data.microsoft.com", "googlegoogle",
};
static const char *const INFOS[] = {
    "", "SYN", "A? www.example.com", "TLSv1.3 ClientHello", "GET /index.html",
    "echo request id=1", "ACK seq=42", "NXDOMAIN",
};

static void same_ip_colour(const char *what, const char *s, int colour_class_index,
                           const run_t *r, const char *page_prop, int want_bold) {
    char want[8], got[8], name[24];
    snprintf(name, sizeof(name), "%s%d", page_prop, colour_class_index);
    int ok = prop(name, want) == 0 && r->n == (int)strlen(s);
    for (int i = 0; ok && i < r->n; i++) {
        xterm_hex(r->fg[i], got);
        if (strcmp(got, want) || r->bold[i] != want_bold) ok = 0;
    }
    if (!ok)
        fprintf(stderr, "    %s \"%s\": the TUI wrote xterm %d (bold %d), the page %s %s\n",
                what, s, r->n ? r->fg[0] : -1, r->n ? r->bold[0] : -1, name, want);
    WT_ASSERT(ok);
}

/* An address and an SSID: one colour for the whole string, the hash's,
 * and bold only for a cross-panel address. Half the addresses are seen
 * in two sources, in the TUI's index and in the page's mask alike. */
static void test_ips_and_ssids_colour_as_the_tui(void) {
    WT_HAS(page(), "  function ipColorIndex(s) {\n"
                   "    if (!s) return 0;\n"
                   "    var b = utf8(s), h = 5381;\n"
                   "    for (var i = 0; i < b.length; i++) h = (((h << 5) + h) + b[i]) >>> 0;\n"
                   "    return h % P.ip;\n"
                   "  }");
    WT_HAS(page(), "function crossPanel(m) { return (m & (m - 1)) !== 0; }");
    WT_HAS(page(), "sp.style.color = \"var(--k-\" + ipColorIndex(ip) + \")\";");
    WT_HAS(page(), "if (ssid !== \"\") sp.style.color = \"var(--k-\" + ipColorIndex(ssid) + \")\";");
    WT_EQ(read_palette(), 0);
    WT_EQ(P.ip, IP_NUM_COLORS);
    static const int bits[7] = { IP_SRC_CONN, IP_SRC_PKT, IP_SRC_ARP, IP_SRC_DNS,
                                 IP_SRC_ICMP, IP_SRC_ALERT, IP_SRC_DEV };
    for (int i = 0; i < 7; i++) WT_EQ(P.src[i], bits[i]);

    tui_set_color(1);
    tui_alert_hot_clear();
    tui_set_highlight_ips(NULL, NULL);
    ip_index_clear();
    int seen[8] = { 0 }, bolds = 0;
    for (size_t i = 0; i < sizeof(IPS) / sizeof(IPS[0]); i++) {
        int m = P.src[i % 7];
        ip_index_add(IPS[i], bits[i % 7]);
        if (i % 2) {
            ip_index_add(IPS[i], bits[(i + 3) % 7]);
            m |= P.src[(i + 3) % 7];
        }
        run_t r;
        WT_EQ(capture(tui_ip, IPS[i], &r), 0);
        int k = js_ip_color_index(IPS[i]);
        WT_EQ(k, ip_color_index(IPS[i]));
        seen[k] = 1;
        bolds += js_cross_panel(m);
        same_ip_colour("address", IPS[i], k, &r, "--k-", js_cross_panel(m));
    }
    int distinct = 0;
    for (int i = 0; i < 8; i++) distinct += seen[i];
    WT_ASSERT(distinct >= 6);           /* the cases reach most of the palette */
    WT_EQ(bolds, 9);
    ip_index_clear();
    for (size_t i = 0; i < sizeof(SSIDS) / sizeof(SSIDS[0]); i++) {
        run_t r;
        WT_EQ(capture(tui_ssid, SSIDS[i], &r), 0);
        int k = js_ip_color_index(SSIDS[i]);
        WT_EQ(k, ip_color_index(SSIDS[i]));
        same_ip_colour("ssid", SSIDS[i], k, &r, "--k-", 0);
    }
}

/* A host name: every byte in its brand's colour, Google's letters in
 * the logo's sequence, the rest in CP_NORMAL, which is what the page's
 * base classes resolve to where the TUI row would use its plain pair. */
static void test_host_names_colour_as_the_tui(void) {
    WT_HAS(page(), "      if (brand === P.google) {\n"
                   "        for (var k = 0; k < len; k++) out.push([best + k, best + k + 1, "
                   "P.gseq[k % P.gseq.length]]);");
    WT_HAS(page(), "        if (j >= 0 && (best < 0 || j < best)) { best = j; brand = "
                   "P.brands[i][0]; len = P.brands[i][1].length; }");
    WT_HAS(page(), "if (r[2] >= 0) sp.style.color = \"var(--br-\" + r[2] + \")\";");
    WT_EQ(read_palette(), 0);
    WT_ASSERT(P.nbr >= 60);
    WT_EQ(P.ngseq, 6);
    char normal[8];
    WT_EQ(prop("--tui-normal", normal), 0);
    int branded = 0, google = 0;
    for (size_t i = 0; i < sizeof(HOSTS) / sizeof(HOSTS[0]); i++) {
        run_t r;
        WT_EQ(capture(tui_brand, HOSTS[i], &r), 0);
        int slot[256];
        js_brand_slots(HOSTS[i], slot);
        int ok = r.n == (int)strlen(HOSTS[i]);
        for (int b = 0; ok && b < r.n; b++) {
            char want[8], got[8], name[16];
            if (slot[b] < 0) memcpy(want, normal, 8);
            else {
                snprintf(name, sizeof(name), "--br-%d", slot[b]);
                if (prop(name, want) != 0) { ok = 0; break; }
                branded++;
                google += slot[b] != slot[b > 0 ? b - 1 : b];
            }
            xterm_hex(r.fg[b], got);
            if (strcmp(got, want)) {
                fprintf(stderr, "    \"%s\" byte %d: the TUI xterm %d %s, the page %s\n",
                        HOSTS[i], b, r.fg[b], got, want);
                ok = 0;
            }
        }
        WT_ASSERT(ok);
    }
    WT_ASSERT(branded > 150);
    WT_ASSERT(google > 20);             /* the letter sequence was exercised */
}

/* An info string: an earth tone by its hash, CP_NORMAL when empty. */
static void test_info_strings_colour_as_the_tui(void) {
    WT_HAS(page(), "function infoClass(s) { return s ? \"info-\" + (ipColorIndex(s) & 7) : "
                   "\"d-normal\"; }");
    WT_HAS(page(), ".d-normal { color: var(--tui-normal); }");
    WT_HAS(page(), ".info-0 { color: var(--info-0); }");
    WT_EQ(read_palette(), 0);
    for (size_t i = 1; i < sizeof(INFOS) / sizeof(INFOS[0]); i++) {
        run_t r;
        WT_EQ(capture(tui_info, INFOS[i], &r), 0);
        same_ip_colour("info", INFOS[i], js_ip_color_index(INFOS[i]) & 7, &r, "--info-", 0);
    }
    short f, b;
    WT_ASSERT(tui_pair_colors(CP_NORMAL, &f, &b));
    char want[8], got[8];
    xterm_hex(f, want);
    WT_EQ(prop("--tui-normal", got), 0);
    WT_EQ(strcmp(got, want), 0);
}

/* The pairs the page names directly: the phosphor, the heat ramp (the
 * page's thresholds are tui_heat()'s), the monitor rows' ground. */
static void test_pairs_and_heat_as_the_tui(void) {
    static const struct { const char *prop; int pair; int bg; } pr[] = {
        { "--tui-bright", CP_BRIGHT, 0 }, { "--tui-normal", CP_NORMAL, 0 },
        { "--tui-dim", CP_DIM, 0 },       { "--heat-0", CP_HEAT_LO, 0 },
        { "--heat-1", CP_HEAT_MID, 0 },   { "--heat-2", CP_HEAT_HI, 0 },
        { "--heat-3", CP_HEAT_PEAK, 0 },  { "--mon-bg", CP_MON_ROW, 1 },
        { "--mon-fg", CP_MON_ROW, 0 },    { "--mon-dim", CP_MON_ROW_DIM, 0 },
    };
    for (size_t i = 0; i < sizeof(pr) / sizeof(pr[0]); i++) {
        short f, b;
        char want[8], got[8];
        WT_ASSERT(tui_pair_colors(pr[i].pair, &f, &b));
        xterm_hex(pr[i].bg ? b : f, want);
        WT_EQ(prop(pr[i].prop, got), 0);
        if (strcmp(got, want))
            fprintf(stderr, "    %s is %s, the TUI's pair %d %s\n", pr[i].prop, got,
                    pr[i].pair, want);
        WT_EQ(strcmp(got, want), 0);
    }
    char g236[8];
    xterm_hex(236, g236);
    WT_EQ(strcmp(g236, "#303030"), 0);  /* the formula's grey ramp, by hand */
    WT_HAS(page(), "function heatClass(f) { return f < 0.15 ? \"h0\" : f < 0.40 ? \"h1\" : "
                   "f < 0.70 ? \"h2\" : \"h3\"; }");
    WT_HAS(page(), ".h3 { color: var(--heat-3); }");
}

void run_tui_colors_tests(void) {
    WT_RUN(test_ips_and_ssids_colour_as_the_tui);
    WT_RUN(test_host_names_colour_as_the_tui);
    WT_RUN(test_info_strings_colour_as_the_tui);
    WT_RUN(test_pairs_and_heat_as_the_tui);
}
