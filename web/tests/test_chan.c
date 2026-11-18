/* The WiFi channel palette and the greenbar (owner 2026-11-18: "a
 * consistent color palette for wifi channels both 2.4 and 5ghz that's
 * used throughout the app when device or ssid is shown. use cool colors
 * for 2.4 ghz and warm colors for 5ghz ... like greenbar paper make an
 * alternating pattern in lists where the alternate bar color is the
 * background but 8% lighter"). The colours are written and checked in
 * web/tools/palette.c (CHAN[], chan_check(): the build fails on a fill
 * under 3:1 on --bg, --panel or either greenbar stripe, on the chip's
 * ink under 4.5:1, and on the CIEDE2000 floors, both themes), so this
 * suite holds the rest by the page's text, which is all it has: every
 * channel token written once per theme; web/ui/chan.js whole, the one
 * place a channel becomes a token, ahead of every user; each place a
 * channel is shown going through it; the greenbar's one rule set, last
 * of the stylesheets, and the virtualised table's index-marked rows.
 *
 * Since the owner's second request the same day ("use that palette
 * throughout the ui for all wifi devices and ssids and mac addresses
 * depending on the current or last read channel"), every Wi-Fi MAC and
 * SSID the page writes is in its channel's colour through
 * SlothChan.mark(), the channel what /api/wifi/lastch says it was last
 * heard on (test_scope.c holds the route): test_text_sites() pins each
 * place whole. palette.c holds the colours at 4.5:1 as text on every
 * list ground (CH_TEXT_MIN).
 *
 * The absence assertions, each seen red and restored: no token built
 * outside chan.js (a "--ch-" + ch string added to app.js); no second
 * var() of a channel token (a "var(--ch-" + n + ")" string added to
 * app.js); one reader of /api/wifi/lastch (a second getJSON of it added
 * to ssid.js). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_assets.h"
#include "wtest.h"

static const char *page(void) { return (const char *)web_page; }

static int count(const char *hay, const char *needle) {
    int n = 0;
    for (const char *q = strstr(hay, needle); q; q = strstr(q + 1, needle)) n++;
    return n;
}

static const char CHAN_JS[] =
        "  function bandOf(ch, band) {\n"
        "    if (typeof band === \"string\") band = band.replace(/ GHz$/, \"\");\n"
        "    if (band === \"2.4\" || band === \"5\" || band === \"6\") return band;\n"
        "    var s = String(ch);\n"
        "    if (/^6g\\d+$/.test(s)) return \"6\";\n"
        "    var n = parseInt(s, 10);\n"
        "    if (!(n > 0)) return \"\";\n"
        "    return n <= 14 ? \"2.4\" : n >= 32 && n <= 177 ? \"5\" : \"\";\n"
        "  }\n"
        "  function token(ch, band) {\n"
        "    var b = bandOf(ch, band), n = parseInt(String(ch).replace(/^6g/, \"\"), 10);\n"
        "    if (!b || !(n > 0)) return null;\n"
        "    if (b === \"6\") return n <= 233 && P[\"6\"] > 0 ? \"--ch6-\" + ((n - 1) >> 2) % P[\"6\"] : null;\n"
        "    return P[b].indexOf(n) >= 0 ? \"--ch-\" + n : null;\n"
        "  }\n"
        "  function color(ch, band) {\n"
        "    var t = token(ch, band);\n"
        "    return \"var(\" + (t || \"--muted\") + \")\";\n"
        "  }\n"
        "  function rgb(ch, band) {\n"
        "    var v = getComputedStyle(document.documentElement).getPropertyValue(token(ch, band) || \"--muted\");\n"
        "    return v && v.trim() ? v.trim() : \"#8a82a0\";\n"
        "  }\n"
        "  function chip(ch, band, text) {\n"
        "    var t = token(ch, band), s = document.createElement(\"span\");\n"
        "    s.className = t ? \"ch-chip\" : \"ch-chip unk\";\n"
        "    if (t) s.style.backgroundColor = color(ch, band);\n"
        "    s.textContent = String(text === undefined ? ch : text);\n"
        "    return s;\n"
        "  }";

/* Every channel palette.js lists has its --ch-N in both themes'
 * blocks, read from the list itself so a channel added to CHAN[] is
 * checked without touching this file; and the 6 GHz steps. */
static void test_tokens_both_themes(void) {
    const char *p = page();
    const char *c = strstr(p, "  chan: {");
    WT_ASSERT(c != NULL);
    if (!c) return;
    WT_HAS(c, "  chan: { \"2.4\": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14], "
              "\"5\": [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, "
              "132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177], \"6\": 4 },");
    int n = 0;
    static const char *const LISTS[2] = { "\"2.4\": [", "\"5\": [" };
    for (int l = 0; l < 2; l++) {
        const char *q = strstr(c, LISTS[l]);
        WT_ASSERT(q != NULL);
        if (!q) return;
        q += strlen(LISTS[l]);
        while (*q && *q != ']') {
            char *end;
            long ch = strtol(q, &end, 10);
            if (end == q) break;
            char want[24];
            snprintf(want, sizeof want, "  --ch-%ld: #", ch);
            if (count(p, want) != 2) fprintf(stderr, "    %s written %d times\n", want, count(p, want));
            WT_EQ(count(p, want), 2);
            n++;
            q = end;
            while (*q == ',' || *q == ' ') q++;
        }
    }
    WT_EQ(n, 42);
    for (int s = 0; s < 4; s++) {
        char want[24];
        snprintf(want, sizeof want, "  --ch6-%d: #", s);
        WT_EQ(count(p, want), 2);
    }
    WT_HAS(p, "  --ch-ink: var(--bg); /* a chip's number */");
    /* A stripe row's chrome text (greenbar.css): the token itself in the
     * dark theme, palette.c's stripe value in the light one. */
    static const char *const GB[] = { "ink", "muted", "brass", "phosphor-hi", "phosphor-mid", "hover" };
    for (int i = 0; i < 6; i++) {
        char d[48], l[48];
        snprintf(d, sizeof d, "  --gb-%s: var(--%s);", GB[i], GB[i]);
        snprintf(l, sizeof l, "  --gb-%s: #", GB[i]);
        WT_EQ(count(p, d), 1);
        WT_EQ(count(p, l), 1);
    }
    WT_HAS(p, "  --ch-ink: var(--panel);");
}

static void test_one_mapping(void) {
    const char *p = page();
    WT_HAS(p, CHAN_JS);
    WT_HAS(p, "  window.SlothChan = { token: token, color: color, rgb: rgb, chip: chip, band: bandOf,\n"
              "                       text: text, paint: paint, mark: mark, unmark: unmark, learn: learn, of: of };");
    /* The one place a token is built, and the one var() of one: chan.css's
     * chip ink. Text takes its colour from color(), as a chip does. */
    WT_EQ(count(p, "\"--ch-\""), 1);
    WT_EQ(count(p, "\"--ch6-\""), 1);
    WT_EQ(count(p, "var(--ch-"), 1);
    WT_HAS(p, "color: var(--ch-ink); }");
    /* palette.js, then chan.js, then every user of it. */
    const char *pal = strstr(p, "var SLOTH_PALETTE = {"), *ch = strstr(p, "// slothweb: the WiFi channel palette");
    WT_ASSERT(pal && ch && pal < ch);
    static const char *const users[] = {
        "// slothweb: one SSID's detail", "  window.SlothIso = {", "  function isoGrid() {",
    };
    for (size_t i = 0; i < sizeof(users) / sizeof(users[0]); i++) {
        const char *u = strstr(p, users[i]);
        WT_ASSERT(ch && u && ch < u);
    }
    WT_HAS(p, ".ch-chip { display: inline-block; min-width: 3ch; padding: 0 3px; border-radius: 2px; text-align: center;\n"
        "  font-variant-numeric: tabular-nums; font-weight: 600; line-height: 1.35; color: var(--ch-ink); }\n"
        ".ch-chip.unk { color: var(--muted); font-weight: 400; box-shadow: inset 0 0 0 1px var(--rule-hi); }");
}

/* Each place the page shows a WiFi channel beside a device, an AP, a
 * station or an SSID: the chip (or, on a canvas, the colour) through
 * SlothChan, the number still there. */
static void test_sites(void) {
    const char *p = page();
    static const char *const site[] = {
        /* the fleet's "also heard by" lines (fvDrawer(), test_text_sites()
         * pins it whole) */
                "      function chN() {\n"
        "        var sp = el(\"span\", \"\", \"ch \");\n"
        "        sp.appendChild(SlothChan.chip(x.channel));\n"
        "        return sp;\n"
        "      }",
        /* the device drawer's associations */
                "        sp.appendChild(el(\"span\", \"d-normal\", \"  ch \"));\n"
        "        sp.appendChild(num(x.channel) ? SlothChan.chip(x.channel) : el(\"span\", \"d-normal\", String(x.channel)));\n"
        "        sp.appendChild(el(\"span\", \"d-normal\", (num(x.signal) ? \"  \" + x.signal + \" dBm\" : \"\") + \"  source \" + x.source));",
        /* the waterfall's picked cell */
                "    var lab = box.appendChild(el(\"div\", \"label\", \"ch \"));\n"
        "    lab.appendChild(SlothChan.chip(r.key, r.band));\n"
        "    lab.appendChild(document.createTextNode(head));",
        /* the AP table, the card's scan */
                "    var cc = row.appendChild(el(\"span\", \"c-ch d-normal\", num(a.channel) ? undefined : \"-\"));\n"
        "    if (num(a.channel)) cc.appendChild(SlothChan.chip(a.channel, a.rf ? a.rf.radio : null));",
                "      var cc = row.appendChild(el(\"span\", \"n d-normal\", num(a.channel) ? undefined : String(a.channel)));\n"
        "      if (num(a.channel)) cc.appendChild(SlothChan.chip(a.channel));",
        /* the stacked grid's and G3's row keys */
                "      // The channel's colour (SlothChan) as a bar before its key.\n"
        "      g.fillStyle = SlothChan.rgb(r.key, r.band);\n"
        "      g.fillRect(0, y + dpr, 3 * dpr, rh - dpr);\n"
        "      g.fillStyle = T.muted;\n"
        "      g.fillText(r.key, 5 * dpr, y + rh / 2);",
                "      g.fillStyle = SlothChan.rgb(r.key, r.band);\n"
        "      g.fillRect(0, (j * ROW + 3) * dpr, 2 * dpr, (ROW - 4) * dpr);\n"
        "      g.fillStyle = H.tok(\"--muted\");\n"
        "      g.textAlign = \"left\";\n"
        "      g.fillText(r.key, 4 * dpr, ty);",
        /* the SSID drawer's access points and clients */
                "      var ch = li.appendChild(H.el(\"span\", \"d-normal\", \"ch \"));\n"
        "      ch.appendChild(num(b.channel) ? SlothChan.chip(b.channel) : H.el(\"span\", \"\", String(b.channel)));",
                "           on.appendChild(document.createTextNode(\", ch \"));\n"
        "           on.appendChild(num(a.channel) ? SlothChan.chip(a.channel) : H.el(\"span\", \"\", String(a.channel)));\n"
        "           if (num(a.signal)) on.appendChild(document.createTextNode(\", \" + a.signal + \" dBm\"));",
        /* the direction-finding card's emitters */
                "            r.channel > 0 ? SlothChan.chip(r.channel) : \"-\", r.quality,",
                "      for (var k = 0; k < c.length; k++) {\n"
        "        // a cell is text, or a node (the channel's chip, a MAC in its\n"
        "        // channel's colour: SlothChan)\n"
        "        var td = tr.appendChild(el(\"td\", null, c[k] instanceof Node ? null : c[k]));\n"
        "        if (c[k] instanceof Node) td.appendChild(c[k]);\n"
        "      }",
    };
    for (size_t i = 0; i < sizeof(site) / sizeof(site[0]); i++) WT_HAS(p, site[i]);
    /* The waterfall's floor, tops, key and client trace (test_iso.c
     * pins those functions whole); no list prints a bare channel. */
    WT_HAS(p, "    var rc = rows.map(function (r) { return SlothChan.rgb(r.key, r.band); }), gc = {};");
    WT_HAS(p, "          if (sc && sc.step === i) it.appendChild(SlothChan.chip(r.key, r.band, r.key.replace(/^6g/, \"\")));");
    WT_LACKS(p, "\"ch \" + b.channel");
    WT_LACKS(p, "\", ch \" + a.channel");
    WT_LACKS(p, "num(x.channel) ? \"ch \" + x.channel");
    WT_LACKS(p, "row.appendChild(el(\"span\", \"n d-normal\", String(a.channel)));");
    WT_LACKS(p, "\"c-ch d-normal\", num(a.channel) ? String(a.channel)");
    /* The AP table's row knows its band when sloth's rf names one ("6
     * GHz"): passed, so a 6 GHz 5 is not coloured as 2.4 GHz's 5. Seen
     * red with the band argument dropped from the AP table's chip. */
    WT_LACKS(p, "    if (num(a.channel)) cc.appendChild(SlothChan.chip(a.channel));\n"
                "    var sg = row.appendChild(el(\"span\", \"c-sig d-dim\"));");
}

static const char GREENBAR[] =
        ":root { --gb-toward: #ffffff; }\n"
        ":root[data-theme=\"light\"] { --gb-toward: #000000; }\n"
        "body { --gb-surface: var(--bg); }\n"
        ".panel, .drawer, dialog, .scope-legend, .radar-ov { --gb-surface: var(--panel); }\n"
        ".card, .cell, .filterbar, .scopebar { --gb-surface: var(--panel-2); }\n"
        "\n"
        ":where(.dt-row:nth-child(even of .dt-row:not(.dhead)):not(.vrows > *)),\n"
        ":where(.vrows > .gb-alt),\n"
        ":where(:is(.lst, .alerts, .ticker, .mixl, .radar-list, .vc-svc) > li:nth-child(even of :not(.sub, .dhead))),\n"
        ":where(table tr:nth-child(even of :has(> td))),\n"
        ":where(:is(.fv-line, .fleet-row, .fid-row, .inc-row, .ak-row):nth-child(even of :is(.fv-line, .fleet-row, .fid-row, .inc-row, .ak-row))) {\n"
        "  background-color: color-mix(in srgb, var(--gb-surface) 92%, var(--gb-toward));\n"
        "  --ink: var(--gb-ink); --muted: var(--gb-muted); --brass: var(--gb-brass);\n"
        "  --phosphor-hi: var(--gb-phosphor-hi); --phosphor-mid: var(--gb-phosphor-mid); --hover: var(--gb-hover);\n"
        "}\n"
        ":is(.ticker, .mixl) > li.mon:nth-child(even of :not(.sub, .dhead)) {\n"
        "  background-color: color-mix(in srgb, var(--mon-bg) 92%, var(--gb-toward));\n"
        "}";

static void test_greenbar(void) {
    const char *p = page();
    WT_HAS(p, GREENBAR);
    /* After every other stylesheet, so a later sheet does not undo it;
     * its stripe rules weigh nothing (:where), so a hover or a selected
     * row's background still wins. */
    const char *g = strstr(p, ":root { --gb-toward: #ffffff; }"), *st = strstr(p, "</style>");
    WT_ASSERT(g && st && g < st);
    WT_HAS(p,         "      if (r.k !== k) { fill(r, D.rows[k]); r.k = k; }\n"
        "      // greenbar.css: the pool's DOM order is not the data's, so the\n"
        "      // alternate row is marked by its index.\n"
        "      r.el.classList.toggle(\"gb-alt\", (k & 1) === 1);");
    WT_HAS(p, "    var r = { el: el(\"div\", \"drow dt-row\"), k: -1, mac: \"\" };");
}

static const char *const TEXT_SITES[] = {
    /* chan.js: text() to learn(), whole */
        "  function text(ch, band) {\n"
        "    var t = token(ch, band);\n"
        "    return t ? color(ch, band) : \"\";\n"
        "  }\n"
        "  function paint(node, ch, band) {\n"
        "    node.style.color = text(ch, band);\n"
        "    return node;\n"
        "  }\n"
        "\n"
        "  // What /api/wifi/lastch said, by name: the MACs (an AP's own channel\n"
        "  // first, then a station's) and the SSIDs.\n"
        "  var own = Object.prototype.hasOwnProperty, L = { aps: map(null), stas: map(null), ssids: map(null) };\n"
        "  function of(kind, key) {\n"
        "    if (typeof key !== \"string\" || key === \"\") return null;\n"
        "    if (kind === \"ssid\") return own.call(L.ssids, key) ? L.ssids[key] : null;\n"
        "    var k = key.replace(/^~/, \"\").toLowerCase();\n"
        "    return own.call(L.aps, k) ? L.aps[k] : own.call(L.stas, k) ? L.stas[k] : null;\n"
        "  }\n"
        "  function repaint(node) {\n"
        "    var d = node.dataset;\n"
        "    // The record's own channel first: it is the current one (the live\n"
        "    // row's, beside its chip), where sloth.db's is up to a minute old\n"
        "    // and carries no band. sloth.db's fills a name drawn without one.\n"
        "    if (d.chOwn !== undefined && token(d.chOwn, d.chBand)) paint(node, d.chOwn, d.chBand);\n"
        "    else paint(node, of(d.chKind, d.chKey));\n"
        "  }\n"
        "  function mark(node, kind, key, ch, band) {\n"
        "    node.dataset.chKind = kind;\n"
        "    node.dataset.chKey = String(key);\n"
        "    // a recycled node (the device table's pool) drops the last row's\n"
        "    if (ch !== undefined && ch !== null && ch !== \"\") node.dataset.chOwn = String(ch);\n"
        "    else delete node.dataset.chOwn;\n"
        "    if (typeof band === \"string\") node.dataset.chBand = band;\n"
        "    else delete node.dataset.chBand;\n"
        "    repaint(node);\n"
        "    return node;\n"
        "  }\n"
        "  function unmark(node) {\n"
        "    delete node.dataset.chKind;\n"
        "    delete node.dataset.chKey;\n"
        "    delete node.dataset.chOwn;\n"
        "    delete node.dataset.chBand;\n"
        "    node.style.color = \"\";\n"
        "    return node;\n"
        "  }\n"
        "  // names off the air, as keys: no prototype for one to land on\n"
        "  function map(o) {\n"
        "    var m = Object.create(null);\n"
        "    if (o && typeof o === \"object\")\n"
        "      for (var k in o) if (own.call(o, k) && typeof o[k] === \"number\") m[k] = o[k];\n"
        "    return m;\n"
        "  }\n"
        "  function learn(j) {\n"
        "    L = { aps: map(j && j.aps), stas: map(j && j.stas), ssids: map(j && j.ssids) };\n"
        "    var ns = document.querySelectorAll(\"[data-ch-kind]\");\n"
        "    for (var i = 0; i < ns.length; i++) repaint(ns[i]);",
    /* app.js ssidText(): an SSID's colour */
        "  function ssidText(ssid, k, np, ch, band) {\n"
        "    var sp = el(\"span\", \"\", ssid);\n"
        "    if (ssid !== \"\") SlothChan.mark(sp, \"ssid\", ssid, ch, band);\n"
        "    if (np !== true) return sp;\n"
        "    var w = el(\"span\", \"ssid-np\");\n"
        "    w.appendChild(sp);\n"
        "    w.appendChild(el(\"span\", \"npm\", \"non-printable\"));\n"
        "    w.title = \"bytes that are not printable UTF-8 are shown as \\\\xNN\";\n"
        "    return w;\n"
        "  }",
    /* app.js ssidSpan() */
        "  function ssidSpan(ssid, k, np, plain, ch, band) {\n"
        "    var n = ssidText(ssid, k, np, ch, band);\n"
        "    return plain || !window.SlothSsid ? n : SlothSsid.link(n, ssid);\n"
        "  }",
    /* app.js keySpan(): a series or episode key */
        "  function keySpan(k) {\n"
        "    if (isIP(k)) return ipSpan(k, 0);\n"
        "    if (MAC_RE.test(k)) return SlothChan.mark(el(\"span\", \"d-dim\", k), \"mac\", k);\n"
        "    return el(\"span\", \"d-normal\", k);\n"
        "  }",
    /* app.js macVal(): the drawer's, Lookup's, the alert's device */
        "  function macVal(v) {\n"
        "    return v === null || v === undefined ? null : SlothChan.mark(el(\"span\", \"d-dim\", String(v)), \"mac\", String(v));\n"
        "  }",
    /* app.js macCell(): the card's scan and station dump */
        "  function macCell(mac, ch) {\n"
        "    var c = el(\"span\", \"\");\n"
        "    var sw = el(\"span\", \"sw\");\n"
        "    sw.style.background = keyColor(String(mac));\n"
        "    c.appendChild(sw);\n"
        "    c.appendChild(SlothChan.mark(el(\"span\", \"d-dim\", String(mac)), \"mac\", String(mac), ch));\n"
        "    return c;\n"
        "  }",
    /* app.js chanLoad(): /api/wifi/lastch */
        "  var CHAN_POLL_MS = 60000, chanSeq = 0;\n"
        "  function chanLoad(fresh) {\n"
        "    var n = ++chanSeq;\n"
        "    getJSON(\"/api/wifi/lastch\").then(function (j) { if (n === chanSeq) SlothChan.learn(j); })\n"
        "      .catch(function () { if (n === chanSeq && fresh === true) SlothChan.learn(null); });\n"
        "  }\n"
        "  chanLoad(true);\n"
        "  setInterval(chanLoad, CHAN_POLL_MS);",
    /* app.js setScope(): the colours anew in the new scope */
        "    // the channel colours as this scope holds them\n"
        "    chanLoad(true);",
    /* app.js fvDrawer(): the fleet's also-heard-by lines, whole */
        "  function fvDrawer(box, f) {\n"
        "    if (!f) return;\n"
        "    var rows = (f.rows || []).concat(f.ap_rows || [], f.probe_rows || []);\n"
        "    if (!rows.length) return;\n"
        "    box.appendChild(el(\"div\", \"label\", f.remote ? \"other sloth hosts (\" + f.note + \")\"\n"
        "                                                : \"also heard by other sloth hosts\"));\n"
        "    rows.forEach(function (x) {\n"
        "      var line = el(\"div\", \"fv-line\");\n"
        "      line.appendChild(el(\"span\", \"fv-host\", fvCut(fvName(x))));\n"
        "      // Words, and the names as nodes: the SSID and the BSSID in their\n"
        "      // channel's colour (SlothChan.mark(), owner 2026-11-18), the\n"
        "      // channel as its chip, each between the words around it. A probe's\n"
        "      // channel is the station's, never its SSID's.\n"
        "      function ssidN(w) {\n"
        "        var sp = el(\"span\", \"\", w);\n"
        "        sp.appendChild(ssidText(String(x.ssid), x.ssid_k, x.ssid_np, x.kind === \"probe\" ? null : x.channel));\n"
        "        return sp;\n"
        "      }\n"
        "      function bssidN() {\n"
        "        var sp = el(\"span\", \"\", \"bssid \");\n"
        "        sp.appendChild(SlothChan.mark(el(\"span\", \"\", String(x.bssid)), \"mac\", x.bssid, x.channel));\n"
        "        return sp;\n"
        "      }\n"
        "      function chN() {\n"
        "        var sp = el(\"span\", \"\", \"ch \");\n"
        "        sp.appendChild(SlothChan.chip(x.channel));\n"
        "        return sp;\n"
        "      }\n"
        "      var t = [x.kind === \"ap\" ? \"as an AP\" : null,\n"
        "               x.kind === \"probe\" ? ssidN(\"probed for \") : x.ssid ? ssidN(\"ssid \") : null,\n"
        "               x.name ? \"name \" + x.name : null,\n"
        "               x.vendor ? \"vendor \" + x.vendor : null, x.class ? \"class \" + x.class : null,\n"
        "               num(x.signal) ? x.signal + \" dBm\" : num(x.rssi) ? x.rssi + \" dBm\" : null,\n"
        "               num(x.channel) ? chN() : null,\n"
        "               x.enc ? x.enc : null, x.bssid ? bssidN() : null,\n"
        "               \"first \" + stamp(x.first_seen), \"last \" + stamp(x.last_seen)];\n"
        "      var rest = line.appendChild(el(\"span\", \"d-dim\", \"  \"));\n"
        "      t.filter(function (s) { return s !== null; }).forEach(function (s, i) {\n"
        "        if (i) rest.appendChild(document.createTextNode(\", \"));\n"
        "        rest.appendChild(typeof s === \"string\" ? document.createTextNode(s) : s);\n"
        "      });\n"
        "      box.appendChild(line);\n"
        "    });\n"
        "  }",
    /* app.js fill(): the device table's MAC */
        "    r.macText.textContent = (d.random ? \"~\" : \"\") + r.mac;\n"
        "    SlothChan.mark(r.macText, \"mac\", r.mac);",
    /* app.js fillRemote(): another host's row stays grey */
        "    r.macText.textContent = (d.random ? \"~\" : \"\") + r.mac;\n"
        "    SlothChan.unmark(r.macText);",
    /* app.js openDrawer(): the drawer's title */
        "    // its channel's colour (SlothChan.mark()), as in the table\n"
        "    SlothChan.mark($(\"dr-mac\"), \"mac\", mac);",
    /* app.js the drawer's associations */
        "        sp.appendChild(SlothChan.mark(el(\"span\", \"d-dim\", String(x.bssid)), \"mac\", x.bssid, x.channel));\n"
        "        sp.appendChild(el(\"span\", \"d-dim\", \"  \"));\n"
        "        if (x.ssid !== null) sp.appendChild(ssidSpan(String(x.ssid), x.ssid_k, x.ssid_np, false, x.channel));",
    /* app.js apRow(): the BSSID */
        "    // the BSSID in its own channel's colour (SlothChan.mark()); another\n"
        "    // host's row stays grey\n"
        "    var bt = bs.appendChild(el(\"span\", \"d-dim\", a.bssid));\n"
        "    if (!rem) SlothChan.mark(bt, \"mac\", String(a.bssid), a.channel, a.rf ? a.rf.radio : null);",
    /* app.js apRow(): the SSID */
        "    // The SSID in its channel's colour (this row's, the AP's current\n"
        "    // one; /api/wifi/lastch's where it has none); the warning (KARMA,\n"
        "    // multi-VAP) is the squares after it, at the heat the TUI warns at.\n"
        "    var ss = el(\"span\", \"c-ssid\");\n"
        "    ss.appendChild(a.ssid === null ? ssidHidden(\"(hidden)\")\n"
        "                   : rem ? el(\"span\", \"\", String(a.ssid))\n"
        "                   : ssidSpan(String(a.ssid), a.ssid_k, a.ssid_np, false, a.channel, a.rf ? a.rf.radio : null));",
    /* app.js the WiFi clients panel */
        "      mc.appendChild(SlothChan.mark(el(\"span\", d.random ? \"rnd d-dim\" : \"d-dim\", (d.random ? \"~\" : \"\") + d.mac), \"mac\", String(d.mac)));",
    /* app.js cardScanDraw() */
        "      row.appendChild(macCell(a.bssid, a.channel));\n"
        "      var ss = el(\"span\", \"\");\n"
        "      ss.appendChild(a.ssid === null ? ssidHidden(\"(hidden)\") : ssidSpan(String(a.ssid), a.ssid_k, a.ssid_np, false, a.channel));",
    /* app.js History's new rows */
        "            // a device's host name (or vendor). The BSSID or MAC in its\n"
        "            // channel's colour (SlothChan.mark()).\n"
        "            li.appendChild(SlothChan.mark(el(\"span\", \"d-dim\", r.ident), \"mac\", String(r.ident)));",
    /* app.js History's who was here */
        "    mac.appendChild(SlothChan.mark(el(\"span\", d.random ? \"rnd d-dim\" : \"d-dim\", (d.random ? \"~\" : \"\") + d.mac), \"mac\", String(d.mac)));",
    /* probes.js macBtn(), whole */
        "  function macBtn(mac, random, title, go, ch) {\n"
        "    var b = H.el(\"button\", \"lk\");\n"
        "    b.type = \"button\";\n"
        "    var sw = H.el(\"span\", \"sw\");\n"
        "    sw.style.background = H.keyColor(String(mac));\n"
        "    b.appendChild(sw);\n"
        "    b.appendChild(SlothChan.mark(H.el(\"span\", random ? \"rnd d-dim\" : \"d-dim\", (random ? \"~\" : \"\") + mac),\n"
        "                                 \"mac\", String(mac), ch));\n"
        "    b.title = title;\n"
        "    b.addEventListener(\"click\", function (e) { e.stopPropagation(); go(String(mac)); });\n"
        "    return b;\n"
        "  }",
    /* probes.js clientsDraw(): a station's MAC */
        "      // the station in the channel it was last heard on (SlothChan.mark()):\n"
        "      // its latest probe's here, /api/wifi/lastch's where that has none\n"
        "      mc.appendChild(SlothChan.mark(H.el(\"span\", d.random ? \"rnd d-dim\" : \"d-dim\", (d.random ? \"~\" : \"\") + d.mac),\n"
        "                                    \"mac\", String(d.mac), d.channel));",
    /* ssid.js macGo(), whole */
        "  function macGo(mac, random, ch) {\n"
        "    var b = H.el(\"button\", \"lk\");\n"
        "    b.type = \"button\";\n"
        "    var sw = H.el(\"span\", \"sw\");\n"
        "    sw.style.background = H.keyColor(String(mac));\n"
        "    b.appendChild(sw);\n"
        "    b.appendChild(SlothChan.mark(H.el(\"span\", random ? \"rnd d-dim\" : \"d-dim\", (random ? \"~\" : \"\") + mac),\n"
        "                                 \"mac\", String(mac), ch));\n"
        "    b.title = \"the device drawer of \" + mac;\n"
        "    b.addEventListener(\"click\", function () { H.openDrawer(String(mac)); });\n"
        "    return b;\n"
        "  }",
    /* ssid.js lastCh(), whole */
        "  function lastCh(j) {\n"
        "    var best = null;\n"
        "    (j.bssids || []).forEach(function (b) {\n"
        "      if (num(b.channel) && b.channel > 0 && num(b.last_seen) && (!best || b.last_seen > best.last_seen)) best = b;\n"
        "    });\n"
        "    return best ? best.channel : null;\n"
        "  }",
    /* ssid.js render(): the name */
        "    var nm = clear(\"sdr-name\"), ch = lastCh(j);\n"
        "    nm.appendChild(j.ssid === null ? H.el(\"span\", \"d-dim\", \"(hidden)\") : H.ssidPlain(String(j.ssid), j.ssid_k, j.ssid_np, ch));",
    /* ssid.js the clients' lines */
        "           li.appendChild(macGo(a.mac, a.random, a.channel));\n"
        "           li.appendChild(H.el(\"span\", a.random ? \"d-dim\" : \"d-bright\", who(a)));\n"
        "           var on = li.appendChild(H.el(\"span\", \"d-dim\", \"on \"));\n"
        "           on.appendChild(SlothChan.mark(H.el(\"span\", \"\", String(a.bssid)), \"mac\", String(a.bssid), a.channel));\n"
        "           on.appendChild(document.createTextNode(\", ch \"));",
    /* df.js emCells(), whole */
        "  function emCells(r) {\n"
        "    return [SlothChan.mark(el(\"span\", null, String(r.mac)), \"mac\", String(r.mac), r.channel > 0 ? r.channel : null),\n"
        "            r.channel > 0 ? SlothChan.chip(r.channel) : \"-\", r.quality,\n"
        "            r.best_iface || (r.best_radio >= 0 ? \"radio \" + r.best_radio : \"-\"),\n"
        "            fixed(r.margin_db, 1, \" dB\"), bearingText(r), fixed(r.along_m, 2, \" m\"), r.heard_by,\n"
        "            stamp(r.last_seen)];\n"
        "  }",
    /* chain.js head(), whole */
        "  function head(bssid) {\n"
        "    var d = el(\"div\", \"chhead\");\n"
        "    d.appendChild(SlothChan.mark(el(\"span\", \"\", bssid), \"mac\", bssid));\n"
        "    return d;\n"
        "  }",
    /* lure.js wname(), whole */
        "  function wname(kind, v) {\n"
        "    return window.SlothChan ? SlothChan.mark(el(\"span\", null, String(v)), kind, String(v)) : String(v);\n"
        "  }",
    /* lure.js the three tables' cells */
        "  function karmaCells(r) {\n"
        "    return [r.bssid, r.top_ssid ? wname(\"ssid\", r.top_ssid) : \"\", r.ssids, r.ie_postures > 0 ? r.ie_postures : \"-\",\n"
        "            r.forged, r.forge_stations, r.pnl_best, r.lure_chain ? \"yes\" : \"\",\n"
        "            r.score, r.tool || \"\", stamp(r.last_seen)];\n"
        "  }\n"
        "  function staCells(r) {\n"
        "    return [wname(\"mac\", r.sta), r.asked, r.m1_bssids, r.unanswered, r.unanswered_kde, r.answered,\n"
        "            stamp(r.first_seen), stamp(r.last_seen)];",
    /* lure.js table(): a node cell */
        "        // a cell is text, or a node (a name in its channel's colour)\n"
        "        var nd = typeof Node !== \"undefined\" && c[k] instanceof Node;\n"
        "        var td = el(\"td\", null, k === 0 && first || nd ? null : c[k]);\n"
        "        if (k === 0 && first) td.appendChild(first(c[k]));\n"
        "        else if (nd) td.appendChild(c[k]);\n"
        "        tr.appendChild(td);",
    /* lure.js karmaFirst(), whole */
        "  function karmaFirst(v) {\n"
        "    return window.SlothKarma ? SlothKarma.button(String(v)) : wname(\"mac\", v);\n"
        "  }",
    /* karma.js button(), whole */
        "  function button(bssid) {\n"
        "    if (typeof bssid !== \"string\" || !MAC_RE.test(bssid)) return document.createTextNode(String(bssid));\n"
        "    var b = el(\"button\", \"lk\");\n"
        "    b.type = \"button\";\n"
        "    var sw = el(\"span\", \"sw\");\n"
        "    sw.style.background = H ? H.keyColor(bssid) : \"\";\n"
        "    b.appendChild(sw);\n"
        "    // the BSSID in its own channel's colour (SlothChan.mark())\n"
        "    b.appendChild(SlothChan.mark(el(\"span\", \"d-dim\", bssid), \"mac\", bssid));\n"
        "    b.title = \"the KARMA detail of \" + bssid;\n"
        "    b.addEventListener(\"click\", function () { open(bssid); });\n"
        "    return b;\n"
        "  }",
    /* karma.js open(): the title */
        "    $(\"kdr-bssid\").textContent = bssid;\n"
        "    SlothChan.mark($(\"kdr-bssid\"), \"mac\", bssid);",
    /* karma.js render(): the top SSID */
        "      // the SSID in its channel's colour (SlothChan.mark(): its most\n"
        "      // recently heard AP's)\n"
        "      [\"score\", String(c.score)],\n"
        "      [\"top ssid\", c.top_ssid ? SlothChan.mark(el(\"span\", null, c.top_ssid), \"ssid\", c.top_ssid) : \"-\"],\n"
        "      [\"tool\", c.tool || \"-\"],",
    /* fleet.js the shared rows' label */
        "        // an AP's or a probe's label is an SSID: its channel's colour\n"
        "        var lb = row.appendChild(H.el(\"span\", \"\"));\n"
        "        if (r.label && (kind === \"ap\" || kind === \"probe\"))\n"
        "          lb.appendChild(SlothChan.mark(H.el(\"span\", \"\", r.label), \"ssid\", r.label));\n"
        "        else if (r.label) lb.appendChild(document.createTextNode(r.label));\n"
        "        if (r.vendor) lb.appendChild(document.createTextNode(\" · \" + r.vendor));",
    /* air.js rug(): each BSSID's label */
        "    // each BSSID in its own channel's colour (SlothChan.of(): the AP's\n"
        "    // channel /api/wifi/lastch names), else dim, as a list writes it\n"
        "    rows.forEach(function (r, i) {\n"
        "      var ch = SlothChan.of(\"mac\", String(r.bssid));\n"
        "      g.fillStyle = ch !== null ? SlothChan.rgb(ch) : H.tok(\"--tui-dim\");\n"
        "      g.fillText(String(r.bssid), 2 * dpr, (i * (LANE + GAP) + LANE / 2) * dpr);\n"
        "    });",
    /* chan.css: a monitor row keeps its ink */
        ":is(.ticker, .mixl) > li.mon [data-ch-kind] { color: var(--mon-fg) !important; }",
};

/* Every Wi-Fi MAC and SSID the page writes, in its channel's colour
 * (owner 2026-11-18): each place, whole where it is a function of its
 * own, through SlothChan.mark() (or, on the deauth rug's canvas,
 * SlothChan.of()). The record's own channel where it carries one (the
 * current one, its chip's); else /api/wifi/lastch's: an AP's its own,
 * a station's the one it was last heard on, an SSID's its most recently
 * heard AP's; else the ink around it. */
static void test_text_sites(void) {
    const char *p = page();
    for (size_t i = 0; i < sizeof(TEXT_SITES) / sizeof(TEXT_SITES[0]); i++) WT_HAS(p, TEXT_SITES[i]);
    /* One reader of the route: app.js's, which hands it to learn(). */
    WT_EQ(count(p, "\"/api/wifi/lastch\""), 1);
    /* The AP table's chip beside its names keeps its row's band. */
    WT_HAS(p, "    if (num(a.channel)) cc.appendChild(SlothChan.chip(a.channel, a.rf ? a.rf.radio : null));");
}

void run_chan_tests(void) {
    WT_RUN(test_tokens_both_themes);
    WT_RUN(test_one_mapping);
    WT_RUN(test_sites);
    WT_RUN(test_text_sites);
    WT_RUN(test_greenbar);
}
