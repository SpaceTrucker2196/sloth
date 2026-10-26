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
 * The C ports below follow the JS line for line, and the JS they port is
 * pinned verbatim, so a change to either side fails here. utf8() is
 * ported too: each case's text is decoded into the UTF-16 units a JS
 * string holds (what the browser makes of the JSON), and the port turns
 * those back into bytes for the hash, so a non-ASCII SSID goes through
 * the page's encoder, not through the C string's own bytes. */
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

/* tui_alert_hot_check()'s clock; the page's port reads the same one. */
static time_t g_now = 1800000000;
time_t sloth_wall(void) { return g_now; }

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

/* What a JS string holds for a UTF-8 C string: its UTF-16 units. The
 * cases are valid UTF-8; this is the browser's decode, not the page's. */
static int utf16_units(const char *s, uint16_t *u, int cap) {
    const unsigned char *p = (const unsigned char *)s;
    int n = 0;
    while (*p && n + 2 <= cap) {
        uint32_t c;
        if (p[0] < 0x80) { c = p[0]; p += 1; }
        else if (p[0] < 0xe0) { c = (uint32_t)(p[0] & 31) << 6 | (p[1] & 63); p += 2; }
        else if (p[0] < 0xf0) { c = (uint32_t)(p[0] & 15) << 12 | (uint32_t)(p[1] & 63) << 6 | (p[2] & 63); p += 3; }
        else { c = (uint32_t)(p[0] & 7) << 18 | (uint32_t)(p[1] & 63) << 12 | (uint32_t)(p[2] & 63) << 6 | (p[3] & 63); p += 4; }
        if (c >= 0x10000) {
            u[n++] = (uint16_t)(0xd800 + ((c - 0x10000) >> 10));
            u[n++] = (uint16_t)(0xdc00 + ((c - 0x10000) & 0x3ff));
        } else {
            u[n++] = (uint16_t)c;
        }
    }
    return n;
}

/* utf8() */
static int js_utf8(const uint16_t *s, int len, unsigned char *out) {
    int n = 0;
    for (int i = 0; i < len; i++) {
        uint32_t c = s[i];
        if (c >= 0xd800 && c < 0xdc00 && i + 1 < len) {
            uint32_t d = s[i + 1];
            if (d >= 0xdc00 && d < 0xe000) { c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00); i++; }
        }
        if (c < 0x80) out[n++] = (unsigned char)c;
        else if (c < 0x800) { out[n++] = (unsigned char)(0xc0 | c >> 6); out[n++] = (unsigned char)(0x80 | (c & 63)); }
        else if (c < 0x10000) {
            out[n++] = (unsigned char)(0xe0 | c >> 12);
            out[n++] = (unsigned char)(0x80 | (c >> 6 & 63));
            out[n++] = (unsigned char)(0x80 | (c & 63));
        } else {
            out[n++] = (unsigned char)(0xf0 | c >> 18);
            out[n++] = (unsigned char)(0x80 | (c >> 12 & 63));
            out[n++] = (unsigned char)(0x80 | (c >> 6 & 63));
            out[n++] = (unsigned char)(0x80 | (c & 63));
        }
    }
    return n;
}

/* ipColorIndex(), over utf8() of the string's UTF-16 units. */
static int js_ip_color_index(const char *s) {
    if (!s[0]) return 0;
    uint16_t u[256];
    unsigned char b[1024];
    int n = js_utf8(u, utf16_units(s, u, 256), b);
    uint32_t h = 5381;
    for (int i = 0; i < n; i++) h = ((h << 5) + h) + b[i];
    return (int)(h % (uint32_t)P.ip);
}

/* lowerAscii(), one character. */
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
    "a", "TP-Link_5G", "attwifi", "\xf0\x9f\x93\xb6 signal", "\xc3\x9c" "bung-\xe6\x97\xa5\xe6\x9c\xac",
    /* A lead byte with its low bit clear (U+041F: 0xd0), so a wrong
     * 2-byte lead cannot hide behind an OR. */
    "\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82",
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
    "DETECTPORTAL.FIREFOX.COM", "One.One.CloudFlare.com", "MAIL.GOOGLE.COM", "Old.Reddit.COM",
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
    WT_HAS(page(), "  function utf8(s) {\n"
                   "    var out = [];\n"
                   "    for (var i = 0; i < s.length; i++) {\n"
                   "      var c = s.charCodeAt(i);\n"
                   "      if (c >= 0xd800 && c < 0xdc00 && i + 1 < s.length) {\n"
                   "        var d = s.charCodeAt(i + 1);\n"
                   "        if (d >= 0xdc00 && d < 0xe000) { c = 0x10000 + ((c - 0xd800) << 10) + "
                   "(d - 0xdc00); i++; }\n"
                   "      }\n"
                   "      if (c < 0x80) out.push(c);\n"
                   "      else if (c < 0x800) out.push(0xc0 | c >> 6, 0x80 | c & 63);\n"
                   "      else if (c < 0x10000) out.push(0xe0 | c >> 12, 0x80 | c >> 6 & 63, "
                   "0x80 | c & 63);\n"
                   "      else out.push(0xf0 | c >> 18, 0x80 | c >> 12 & 63, 0x80 | c >> 6 & 63, "
                   "0x80 | c & 63);\n"
                   "    }\n"
                   "    return out;\n"
                   "  }");
    WT_HAS(page(), "  function ipColorIndex(s) {\n"
                   "    if (!s) return 0;\n"
                   "    var b = utf8(s), h = 5381;\n"
                   "    for (var i = 0; i < b.length; i++) h = (((h << 5) + h) + b[i]) >>> 0;\n"
                   "    return h % P.ip;\n"
                   "  }");
    WT_HAS(page(), "function crossPanel(m) { return (m & (m - 1)) !== 0; }");
    /* ip_index_build() adds an alert's match_ip under IP_SRC_ALERT and
     * nothing else of it: the other addresses in an alert's text, and
     * in an alert record on the ticker, count toward no source. */
    WT_HAS(page(), "\"t-alert\": 0, \"t-tls\": IP_SRC.pkt,");
    WT_HAS(page(), "      richText(tx, detail, 0, \"d-normal\");");
    WT_HAS(page(), "    hotSet(ip, t, sev);\n    ipNote(ip, IP_SRC.alert);");
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
    int wide = 0;
    for (size_t i = 0; i < sizeof(SSIDS) / sizeof(SSIDS[0]); i++) {
        run_t r;
        uint16_t u[256];
        int nu = utf16_units(SSIDS[i], u, 256);
        wide += nu != (int)strlen(SSIDS[i]);
        WT_EQ(capture(tui_ssid, SSIDS[i], &r), 0);
        int k = js_ip_color_index(SSIDS[i]);
        WT_EQ(k, ip_color_index(SSIDS[i]));
        same_ip_colour("ssid", SSIDS[i], k, &r, "--k-", 0);
    }
    WT_EQ(wide, 5);                     /* 2-, 3- and 4-byte sequences, a surrogate pair */
}

/* A host name: every byte in its brand's colour, Google's letters in
 * the logo's sequence, the rest in CP_NORMAL, which is what the page's
 * base classes resolve to where the TUI row would use its plain pair. */
static void test_host_names_colour_as_the_tui(void) {
    WT_HAS(page(), "  function lowerAscii(s) {\n"
                   "    return s.replace(/[A-Z]/g, function (c) { return "
                   "String.fromCharCode(c.charCodeAt(0) + 32); });\n"
                   "  }");
    WT_HAS(page(), "    var low = lowerAscii(s), out = [], at = 0;");
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
    int branded = 0, google = 0, upper = 0;
    for (size_t i = 0; i < sizeof(HOSTS) / sizeof(HOSTS[0]); i++) {
        run_t r;
        WT_EQ(capture(tui_brand, HOSTS[i], &r), 0);
        int slot[256];
        js_brand_slots(HOSTS[i], slot);
        for (const char *c = HOSTS[i]; *c; c++) upper += *c >= 'A' && *c <= 'Z' && slot[c - HOSTS[i]] >= 0;
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
    fprintf(stderr, "    %d branded bytes, %d of them upper-case in the host name\n", branded, upper);
    WT_ASSERT(branded > 150);
    WT_ASSERT(google > 20);             /* the letter sequence was exercised */
    WT_ASSERT(upper >= 20);             /* brands found through the lower-casing */
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
        { "--mon-fg", CP_MON_ROW, 0 },    { "--hot-0", CP_ALERT_HOT_LOW, 0 },
        { "--hot-1", CP_ALERT_HOT_WARN, 0 }, { "--hot-2", CP_ALERT_HOT_CRIT, 0 },
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

/* ── the alert-hot override ─────────────────────────────────────── */

/* hotSet() and hotCheck(): 256 slots, promotion only, the newest time
 * kept, the oldest slot replaced when full, cold past the TTL. */
static struct { char ip[64]; long t; int sev; } g_hot[512];
static int g_nhot;

static void js_hot_set(const char *ip, long t, int sev) {
    if (!ip[0]) return;
    if (sev < 0) sev = 0;
    if (sev > 2) sev = 2;
    for (int i = 0; i < g_nhot; i++)
        if (!strcmp(g_hot[i].ip, ip)) {
            if (t > g_hot[i].t) g_hot[i].t = t;
            if (sev > g_hot[i].sev) g_hot[i].sev = sev;
            return;
        }
    if (g_nhot >= 256) {
        int old = 0;
        for (int i = 1; i < g_nhot; i++) if (g_hot[i].t < g_hot[old].t) old = i;
        g_hot[old] = g_hot[--g_nhot];
    }
    snprintf(g_hot[g_nhot].ip, sizeof(g_hot[0].ip), "%s", ip);
    g_hot[g_nhot].t = t;
    g_hot[g_nhot++].sev = sev;
}

static int js_hot_check(const char *ip, int ttl) {
    for (int i = 0; i < g_nhot; i++)
        if (!strcmp(g_hot[i].ip, ip)) return (long)g_now - g_hot[i].t > ttl ? -1 : g_hot[i].sev;
    return -1;
}

static void both_hot(const char *ip, long t, int sev) {
    tui_alert_hot_set(ip, t, sev);
    js_hot_set(ip, t, sev);
}

/* An address an alert names is drawn in CP_ALERT_HOT_* by severity,
 * bold from WARN, over the hash colour and the cross-panel bold, until
 * ALERT_HOT_TTL_S after the alert was last seen. Seen red with the
 * page's bold threshold moved to CRIT and with the TTL made 3599. */
static void test_alert_hot_addresses_colour_as_the_tui(void) {
    WT_HAS(page(), "    var hot = hotCheck(ip);\n"
                   "    if (hot >= 0) {\n"
                   "      sp.style.color = \"var(--hot-\" + hot + \")\";\n"
                   "      if (hot >= 1) sp.classList.add(\"xb\");\n"
                   "      return sp;\n"
                   "    }\n"
                   "    sp.style.color = \"var(--k-\" + ipColorIndex(ip) + \")\";");
    WT_HAS(page(), "    if (e) {\n"
                   "      if (t > e.t) e.t = t;\n"
                   "      if (sev > e.sev) e.sev = sev;\n"
                   "      return;\n"
                   "    }\n"
                   "    if (HOT.size >= HOT_CAP) {");
    WT_HAS(page(), "    if (Math.floor(Date.now() / 1000) - e.t > HOT_TTL_S) return -1;\n"
                   "    return e.sev;");
    WT_HAS(page(), "noteAlertIp(list[h].match_ip, list[h].ts, list[h].sev);");
    int ttl = -1, cap = -1, tcap = -1;
    const char *p = strstr(page(), "var HOT_TTL_S = ");
    if (p) ttl = atoi(p + 16);
    p = strstr(page(), "var HOT_CAP = ");
    if (p) cap = atoi(p + 14);
    WT_EQ(ttl, ALERT_HOT_TTL_S);
    FILE *f = fopen("src/tui.c", "rb");
    WT_ASSERT(f != NULL);
    if (f) {
        static char src[1 << 20];
        size_t n = fread(src, 1, sizeof(src) - 1, f);
        fclose(f);
        src[n] = '\0';
        const char *d = strstr(src, "#define ALERT_HOT_CAP ");
        if (d) tcap = atoi(d + 22);
    }
    WT_EQ(cap, tcap);
    WT_EQ(read_palette(), 0);

    tui_set_color(1);
    tui_alert_hot_clear();
    tui_set_highlight_ips(NULL, NULL);
    ip_index_clear();
    g_nhot = 0;
    static const char *const HOT[] = {
        "192.0.2.20", "203.0.113.50", "198.51.100.7", "10.0.0.2", "2001:db8::1",
        "172.16.0.10", "8.8.8.8", "1.1.1.1",
    };
    long now = (long)g_now;
    both_hot(HOT[0], now - 10, 2);              /* CRIT */
    both_hot(HOT[1], now - 3600, 1);            /* WARN, at the edge of the TTL */
    both_hot(HOT[2], now - 5, 0);               /* LOW, never bold */
    both_hot(HOT[3], now - 20, 2);
    both_hot(HOT[3], now - 1, 0);               /* a later LOW keeps the CRIT */
    both_hot(HOT[4], now - 3601, 2);            /* gone cold */
    both_hot(HOT[5], now - 4000, 1);
    both_hot(HOT[5], now - 30, 0);              /* warmed again, still WARN */
    both_hot(HOT[6], now - 3601, 0);            /* cold: the hash colour */
    /* Cross-panel everywhere: the override wins over the bold too. */
    for (size_t i = 0; i < sizeof(HOT) / sizeof(HOT[0]); i++) {
        ip_index_add(HOT[i], IP_SRC_CONN);
        ip_index_add(HOT[i], IP_SRC_ALERT);
    }
    int hot = 0, cold = 0;
    for (size_t i = 0; i < sizeof(HOT) / sizeof(HOT[0]); i++) {
        run_t r;
        WT_EQ(capture(tui_ip, HOT[i], &r), 0);
        int h = js_hot_check(HOT[i], ttl);
        if (h >= 0) {
            hot++;
            same_ip_colour("alert-hot address", HOT[i], h, &r, "--hot-", h >= 1);
        } else {
            cold++;
            same_ip_colour("cold address", HOT[i], js_ip_color_index(HOT[i]), &r, "--k-", 1);
        }
    }
    WT_EQ(hot, 5);
    WT_EQ(cold, 3);

    /* Full: the oldest slot goes, in both. */
    tui_alert_hot_clear();
    g_nhot = 0;
    char ip[32];
    for (int i = 0; i < 257; i++) {
        snprintf(ip, sizeof(ip), "198.51.%d.%d", i / 200, i % 200);
        both_hot(ip, now - 300 + i, 1);
    }
    int agree = 1;
    for (int i = 0; i < 257; i++) {
        snprintf(ip, sizeof(ip), "198.51.%d.%d", i / 200, i % 200);
        if (tui_alert_hot_check(ip) != js_hot_check(ip, ttl)) agree = 0;
    }
    WT_ASSERT(agree);
    WT_EQ(js_hot_check("198.51.0.0", ttl), -1);  /* the oldest, replaced */
    tui_alert_hot_clear();
    ip_index_clear();
}

/* ── monitor rows ───────────────────────────────────────────────── */

/* The ticker's monitor rows are the records src/jsonl.c emits from the
 * monitor radio's state: the emitters jsonl_emit_state_snapshots() calls
 * from jsonl_emit_beacons() to jsonl_emit_eapol_events(), less
 * jsonl_emit_cp_events() (captive-portal detections come from the IP
 * capture). The page's MON_TYPES is exactly their record types, so an
 * emitter added to that run without a page entry fails here. Seen red
 * with "eapol" taken out of MON_TYPES. */
static void test_monitor_rows_are_jsonls_monitor_records(void) {
    WT_HAS(page(), "    var mon = isMon(r.type);");
    WT_HAS(page(), "function isMon(t) { return MON_TYPES.indexOf(t) >= 0; }");
    static char src[1 << 20];
    FILE *f = fopen("src/jsonl.c", "rb");
    WT_ASSERT(f != NULL);
    if (!f) return;
    size_t n = fread(src, 1, sizeof(src) - 1, f);
    fclose(f);
    src[n] = '\0';
    char want[32][40];
    int nw = 0, in = 0;
    const char *b = strstr(src, "void jsonl_emit_state_snapshots(");
    const char *e = b ? strstr(b, "\n}\n") : NULL;
    WT_ASSERT(b && e);
    if (!b || !e) return;
    for (const char *q = strstr(b, "    jsonl_emit_"); q && q < e; q = strstr(q + 1, "    jsonl_emit_")) {
        char fn[64];
        if (sscanf(q, " %63[a-z_]", fn) != 1) continue;
        if (!strcmp(fn, "jsonl_emit_beacons")) in = 1;
        if (in && strcmp(fn, "jsonl_emit_cp_events") && nw < 32) {
            char def[80];
            snprintf(def, sizeof(def), "void %s(", fn);
            const char *d = strstr(src, def);
            const char *so = d ? strstr(d, "start_obj(buf, LINEBUF, &off, \"") : NULL;
            WT_ASSERT(so != NULL);
            if (so && sscanf(so + 31, "%39[a-z0-9_]", want[nw]) == 1) nw++;
        }
        if (!strcmp(fn, "jsonl_emit_eapol_events")) break;
    }
    WT_EQ(nw, 15);
    const char *m = strstr(page(), "var MON_TYPES = [");
    const char *me = m ? strstr(m, "];") : NULL;
    WT_ASSERT(m && me);
    if (!m || !me) return;
    int got = 0, found = 0;
    for (const char *q = strchr(m, '"'); q && q < me; q = strchr(q + 1, '"')) {
        char t[40];
        if (sscanf(q + 1, "%39[a-z0-9_]", t) != 1) break;
        got++;
        int hit = 0;
        for (int i = 0; i < nw; i++) hit |= !strcmp(want[i], t);
        if (!hit) fprintf(stderr, "    MON_TYPES names %s, not a monitor record of jsonl.c\n", t);
        found += hit;
        q = strchr(q + 1, '"');
        if (!q) break;
    }
    WT_EQ(got, nw);
    WT_EQ(found, nw);
}

void run_tui_colors_tests(void) {
    WT_RUN(test_ips_and_ssids_colour_as_the_tui);
    WT_RUN(test_host_names_colour_as_the_tui);
    WT_RUN(test_info_strings_colour_as_the_tui);
    WT_RUN(test_pairs_and_heat_as_the_tui);
    WT_RUN(test_alert_hot_addresses_colour_as_the_tui);
    WT_RUN(test_monitor_rows_are_jsonls_monitor_records);
}
