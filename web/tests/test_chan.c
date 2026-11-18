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
 * The absence assertion (no token built outside chan.js) was seen red
 * with a "--ch-" + ch string added to app.js, and restored. */
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
    WT_HAS(p, "  --ch-ink: var(--panel);");
}

static void test_one_mapping(void) {
    const char *p = page();
    WT_HAS(p, CHAN_JS);
    WT_HAS(p, "  window.SlothChan = { token: token, color: color, rgb: rgb, chip: chip, band: bandOf };");
    /* The one place a token is built. */
    WT_EQ(count(p, "\"--ch-\""), 1);
    WT_EQ(count(p, "\"--ch6-\""), 1);
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
        /* the fleet's "also heard by" lines */
                "      var u = [x.enc ? x.enc : null, x.bssid ? \"bssid \" + x.bssid : null,\n"
        "               \"first \" + stamp(x.first_seen), \"last \" + stamp(x.last_seen)];\n"
        "      function some(a) { return a.filter(function (s) { return s !== null; }).join(\", \"); }\n"
        "      // The channel as its chip (SlothChan, owner 2026-11-18), between\n"
        "      // the words before and after it.\n"
        "      line.appendChild(el(\"span\", \"d-dim\", \"  \" + some(t) + (num(x.channel) ? (some(t) ? \", \" : \"\") + \"ch \" : \"\")));\n"
        "      if (num(x.channel)) line.appendChild(SlothChan.chip(x.channel));\n"
        "      line.appendChild(el(\"span\", \"d-dim\", (some(t) || num(x.channel) ? \", \" : \"\") + some(u)));\n"
        "      box.appendChild(line);",
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
                "           var on = li.appendChild(H.el(\"span\", \"d-dim\", \"on \" + a.bssid + \", ch \"));\n"
        "           on.appendChild(num(a.channel) ? SlothChan.chip(a.channel) : H.el(\"span\", \"\", String(a.channel)));\n"
        "           if (num(a.signal)) on.appendChild(document.createTextNode(\", \" + a.signal + \" dBm\"));",
        /* the direction-finding card's emitters */
                "    return [r.mac, r.channel > 0 ? SlothChan.chip(r.channel) : \"-\", r.quality,",
                "      for (var k = 0; k < c.length; k++) {\n"
        "        // a cell is text, or a node (the channel's chip, SlothChan)\n"
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

void run_chan_tests(void) {
    WT_RUN(test_tokens_both_themes);
    WT_RUN(test_one_mapping);
    WT_RUN(test_sites);
    WT_RUN(test_greenbar);
}
