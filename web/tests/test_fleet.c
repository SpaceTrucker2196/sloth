/* The owner's fleet (#192 F1, web_fleet.h; ADR 0008): the peer URL
 * rule, the member allow-list held to web_secret.h, the export over a
 * sloth.db generated from sloth's own DDL with a credential, a
 * username, EAPOL rows and a RADIUS identity seeded and held out of it,
 * `since`, and the pull from a loopback server answering canned bytes:
 * a good answer stored and widened by a second, and every refused
 * answer (oversize, cut short, malformed, an unknown member, a wrong
 * count, no end line, a non-200) leaving every sighting as it was. The
 * v7 -> v8 migration and its failure are test_store.c's, beside the
 * other steps (make_v6() lives there). */
#include <arpa/inet.h>
#include <math.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "web_assets.h"
#include "web_config.h"
#include "web_adsb.h"
#include "web_alertkb.h"
#include "web_fleet.h"
#include "web_fleetadsb.h"
#include "web_fleetgnss.h"
#include "web_frrs.h"
#include "web_jsonl.h"
#include "web_gnss.h"
#include "web_locate.h"
#include "web_routes.h"
#include "web_secret.h"
#include "web_slothdb.h"
#include "web_store.h"
#include "wtest.h"
#include "wt_tmp.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#include "sdb_gen.h"
#endif

/* ── the peer list ──────────────────────────────────────────────────── */

/* Seen red with web_fleet_in_tailnet() testing the second octet against
 * 0x80 (100.128.0.0 then taken as the tailnet) and with the port's
 * range check dropped (":0" taken). */
static void test_peer_urls(void) {
    web_fleet_peer_cfg_t p;
    char err[200];
    WT_EQ(web_fleet_parse_peer("w9fjc=http://100.64.1.2:8770", &p, err, sizeof(err)), 0);
    WT_ASSERT(!strcmp(p.name, "w9fjc"));
    WT_ASSERT(!strcmp(p.url, "http://100.64.1.2:8770"));
    WT_EQ(p.port, 8770);
    WT_EQ(web_fleet_check_peer(&p, 0, err, sizeof(err)), 0);
    WT_EQ(web_fleet_parse_peer("beta-site=http://100.127.255.254/", &p, err, sizeof(err)), 0);
    WT_EQ(p.port, 80);
    WT_ASSERT(!strcmp(p.url, "http://100.127.255.254:80"));
    WT_EQ(web_fleet_check_peer(&p, 0, err, sizeof(err)), 0);
    /* Routable, and the edges of 100.64.0.0/10: refused unless forced. */
    static const char *const outside[] = {
        "x=http://8.8.8.8:8770", "x=http://100.63.255.255:8770",
        "x=http://100.128.0.1:8770", "x=http://127.0.0.1:8770",
        "x=http://192.168.1.10:8770",
    };
    for (size_t i = 0; i < sizeof(outside) / sizeof(outside[0]); i++) {
        WT_EQ(web_fleet_parse_peer(outside[i], &p, err, sizeof(err)), 0);
        WT_EQ(web_fleet_check_peer(&p, 0, err, sizeof(err)), -1);
        WT_HAS(err, "outside the tailnet");
        WT_EQ(web_fleet_check_peer(&p, 1, err, sizeof(err)), 0);
    }
    static const char *const bad[] = {
        "nourl", "=http://100.64.0.1", "bad name=http://100.64.0.1",
        "x=https://100.64.0.1", "x=http://host.example:80", "x=http://100.64.0.1:0",
        "x=http://100.64.0.1:70000", "x=http://100.64.0.1/api/fleet/export",
        "x=http://100.64.0.1:80x", "x=http://100.64.0.1:", "x=http://[::1]:80",
        "x=http://100.64.0.1.5:80", "x=", "x=http://",
        "a234567890123456789012345678901234=http://100.64.0.1",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        int rc = web_fleet_parse_peer(bad[i], &p, err, sizeof(err));
        if (rc != -1) fprintf(stderr, "    taken: %s\n", bad[i]);
        WT_EQ(rc, -1);
    }
}

typedef struct {
    web_config_t cfg;
    int          rc;
    char        *err, *ann;
} parsed_t;

static void parse(parsed_t *p, const char *const *args) {
    char *argv[24];
    int argc = 0;
    argv[argc++] = (char *)"slothweb";
    for (int i = 0; args[i] && argc < 23; i++) argv[argc++] = (char *)args[i];
    argv[argc] = NULL;
    char *out = NULL;
    size_t ol = 0, el = 0, al = 0;
    p->err = p->ann = NULL;
    FILE *o = open_memstream(&out, &ol);
    FILE *e = open_memstream(&p->err, &el);
    p->rc = web_config_parse(&p->cfg, argc, argv, o, e);
    fclose(o);
    fclose(e);
    free(out);
    FILE *a = open_memstream(&p->ann, &al);
    if (p->rc == 0) web_config_announce(&p->cfg, a);
    fclose(a);
}

static void done(parsed_t *p) {
    free(p->err);
    free(p->ann);
}

/* The flags. A tailnet peer is quiet; one outside is refused, and with
 * the flag announced; --strict refuses any. */
static void test_peer_flags(void) {
    parsed_t p;
#ifdef WITH_SQLITE
    static const char *const one[] = { "--peer", "lab=http://100.80.0.9:8770",
                                       "--peer-interval-secs", "30", NULL };
    parse(&p, one);
    WT_EQ(p.rc, 0);
    WT_EQ(p.cfg.npeer, 1);
    WT_EQ(p.cfg.peer_interval_s, 30);
    WT_LACKS(p.ann, "--peer");
    done(&p);
    static const char *const out[] = { "--peer", "x=http://192.0.2.7:8770", NULL };
    parse(&p, out);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "--peer x: http://192.0.2.7:8770 is outside the tailnet");
    done(&p);
    /* The flag after the peer: the rule is applied to the whole line. */
    static const char *const forced[] = { "--peer", "x=http://192.0.2.7:8770",
                                          "--peer-allow-outside-tailnet", NULL };
    parse(&p, forced);
    WT_EQ(p.rc, 0);
    WT_HAS(p.ann, "WARNING: --peer x at http://192.0.2.7:8770 is outside the tailnet");
    done(&p);
    static const char *const strict[] = { "--peer", "lab=http://100.80.0.9", "--strict", NULL };
    parse(&p, strict);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "--strict refuses --peer.");
    done(&p);
    static const char *const twice[] = { "--peer", "a=http://100.80.0.9", "--peer",
                                         "a=http://100.80.0.10", NULL };
    parse(&p, twice);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "given twice");
    done(&p);
    static const char *const many[] = {
        "--peer", "a=http://100.80.0.1", "--peer", "b=http://100.80.0.2",
        "--peer", "c=http://100.80.0.3", "--peer", "d=http://100.80.0.4",
        "--peer", "e=http://100.80.0.5", "--peer", "f=http://100.80.0.6",
        "--peer", "g=http://100.80.0.7", "--peer", "h=http://100.80.0.8",
        "--peer", "i=http://100.80.0.9", NULL };
    parse(&p, many);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "--peer: at most 8 peers");
    done(&p);
#else
    static const char *const one[] = { "--peer", "lab=http://100.80.0.9:8770", NULL };
    parse(&p, one);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "--peer needs SQLite");
    done(&p);
#endif
    static const char *const iv[] = { "--peer-interval-secs", "5", NULL };
    parse(&p, iv);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "want a whole number from 10 to 3600");
    done(&p);
    static const char *const none[] = { NULL };
    parse(&p, none);
    WT_EQ(p.rc, 0);
    WT_EQ(p.cfg.npeer, 0);
    WT_EQ(p.cfg.peer_interval_s, WEB_FLEET_INTERVAL_DEF);
    done(&p);
}

/* Every member a fleet line may carry is a name web_secret.h does not
 * withhold; the positive control is a name it does. Seen red with
 * "username" added to the wifi line's members. */
static void test_members_are_not_secret(void) {
    int names = 0;
    for (size_t i = 0; i < web_fleet_members_n; i++) {
        const char *const *m = web_fleet_members[i];
        WT_ASSERT(web_fleet_members_of(m[0]) == m);
        for (int k = 1; m[k]; k++) {
            names++;
            if (web_sdb_is_secret("fleet", m[k], "TEXT"))
                fprintf(stderr, "    %s.%s is a withheld name\n", m[0], m[k]);
            WT_ASSERT(!web_sdb_is_secret("fleet", m[k], "TEXT"));
        }
    }
    WT_ASSERT(names > 50);
    WT_ASSERT(web_sdb_is_secret("fleet", "username", "TEXT"));
    WT_ASSERT(web_sdb_is_secret("fleet", "pmkid", "TEXT"));
    WT_ASSERT(web_fleet_members_of("eapol") == NULL);
    WT_ASSERT(web_fleet_members_of("cleartext_creds") == NULL);
}

/* The haversine against values worked by hand: a degree of longitude on
 * the equator, and W9FJC to Chicago. */
static void test_distance(void) {
    double d = web_fleet_dist_m(0, 0, 0, 1);
    WT_ASSERT(d > 111195.0 && d < 111195.2);
    d = web_fleet_dist_m(33.32919, -111.87007, 41.8781136, -87.6297982);
    WT_ASSERT(d > 2326924.5 && d < 2326925.5);
    WT_ASSERT(web_fleet_dist_m(33.32919, -111.87007, 33.32919, -111.87007) == 0);
}


/* ── the Fleet tab's page (web/ui/fleet.js) ─────────────────────────── */

/* The module's own text: its header comment to its export line. */
static char *fleet_module(const char *p) {
    const char *s = strstr(p, "// slothweb: the Fleet view");
    const char *m = strstr(p, "window.SlothFleet = { init: init, show: show };");
    if (!s || !m || s >= m) return NULL;
    size_t n = (size_t)(m - s);
    char *mod = malloc(n + 1);
    if (!mod) return NULL;
    memcpy(mod, s, n);
    mod[n] = '\0';
    return mod;
}

static int count_of(const char *s, const char *needle) {
    int n = 0;
    if (!s) return 0;
    for (const char *q = strstr(s, needle); q; q = strstr(q + 1, needle)) n++;
    return n;
}

/* The tab after TACDB, its click, show()'s hook, the init line with the
 * helpers lent, the view and its ids; the map is the page's own <svg>
 * drawn with the elements' length properties (no attribute writes, no
 * namespace URL in the page); the module fetches nothing but the five
 * routes (#192 I6 added /api/fleet/gnss, I7 /api/fleet/aircraft). Pinned by whole functions
 * (#171 V1's review): the projection (fitted to the sites and the
 * located candidates' radii, #192 I5), the metre scale bar, the located
 * emitters' layer, a site's bar on the shared axis, the device link, the
 * SVG element maker, the poll, and the GNSS panel's gauge, event rows
 * and load (#192 I6), the coverage plot, the aircraft rows and their
 * load (#192 I7; the plot is drawn into an <svg> the module makes, so
 * the view's markup still holds one). The fetch census was seen red with a third getJSON
 * ("/api/fleet/peers") added to loadOverview(), and with a fetch("/x")
 * added to load(); the one-control census with a second <select
 * id="fleet-x"> added to v-fleet; the token-only colours with the
 * self mark's fill written as #ff8c26. */
static void test_fleet_page(void) {
    const char *p = (const char *)web_page;
    WT_HAS(p, "<li><button type=\"button\" class=\"go\" id=\"nav-tacdb\">TACDB</button></li>\n"
              "      <li><button type=\"button\" class=\"go\" id=\"nav-fleet\">Fleet</button></li>");
    WT_HAS(p, "  $(\"nav-fleet\").addEventListener(\"click\", function () { show(\"fleet\"); });");
    WT_HAS(p, "    if (v === \"fleet\" && window.SlothFleet) SlothFleet.show();");
    WT_HAS(p, "  if (window.SlothFleet) SlothFleet.init({ el: el, set: set, getJSON: getJSON, errText: errText,\n"
              "    stamp: stamp, openDrawer: openDrawer, openBleDrawer: openBleDrawer });");
    WT_HAS(p, "\"aprs\", \"radar\", \"fleet\"];");
    WT_HAS(p, "<div id=\"v-fleet\" hidden>");
    WT_HAS(p, "<svg id=\"fleet-map\" viewBox=\"0 0 600 300\" role=\"img\" aria-label=");
    WT_HAS(p, "<g id=\"fleet-map-g\"></g></svg>");
    static const char *const ids[] = {
        "fleet-head", "fleet-empty", "fleet-map", "fleet-map-g", "fleet-map-note",
        "fleet-cards", "fleet-shared-note", "fleet-kind", "fleet-shared-rows", "fleet-axis",
        "fleet-loc-note", "fleet-loc-rows", "fleet-gnss-note", "fleet-gnss-sites",
        "fleet-gnss-base", "fleet-gnss-rows", "fleet-ac-note", "fleet-ac-sites",
        "fleet-ac-rows",
    };
    char *mod = fleet_module(p);
    WT_ASSERT(mod != NULL);
    if (!mod) return;
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        char want[64];
        snprintf(want, sizeof(want), " id=\"%s\"", ids[i]);
        WT_HAS(p, want);
        snprintf(want, sizeof(want), "\"%s\"", ids[i]);
        WT_HAS(mod, want);
    }
    /* The GNSS card says when the reference re-anchored (#196). */
    WT_HAS(mod, "      if (num(s.reference_moved_at)) kv(dl, \"reference\", \"re-anchored \" + "
                "dist(s.reference_moved_m) +\n"
                "         \" on \" + H.stamp(s.reference_moved_at), true);\n");
    /* The whole functions. */
    WT_HAS(mod,
              "  function project(pts) {\n"
              "    var lat0 = 0, i;\n"
              "    for (i = 0; i < pts.length; i++) lat0 += pts[i].lat / pts.length;\n"
              "    var k = Math.cos(lat0 * Math.PI / 180);\n"
              "    var x0 = Infinity, x1 = -Infinity, y0 = Infinity, y1 = -Infinity;\n"
              "    for (i = 0; i < pts.length; i++) {\n"
              "      var x = pts[i].lon * k, y = -pts[i].lat, r = (pts[i].r || 0) / M_DEG;\n"
              "      x0 = Math.min(x0, x - r); x1 = Math.max(x1, x + r); y0 = Math.min(y0, y - r); y1 = Math.max(y1, y + r);\n"
              "    }\n"
              "    var sx = x1 - x0, sy = y1 - y0;\n"
              "    var sc = Math.min(sx > 0 ? (MAP_W - 2 * PAD) / sx : Infinity, sy > 0 ? (MAP_H - 2 * PAD) / sy : Infinity);\n"
              "    if (!isFinite(sc)) sc = 0;\n"
              "    var cx = (x0 + x1) / 2, cy = (y0 + y1) / 2;\n"
              "    var f = function (lat, lon) {\n"
              "      return [MAP_W / 2 + (lon * k - cx) * sc, MAP_H / 2 + (-lat - cy) * sc];\n"
              "    };\n"
              "    f.ppm = sc / M_DEG;\n"
              "    return f;\n"
              "  }");
    WT_HAS(mod,
              "  function scaleBar(g, ppm, sized) {\n"
              "    if (!(ppm > 0)) return;\n"
              "    var m = 1, steps = [1, 2, 5], best = 0;\n"
              "    for (var e = -1; e < 8; e++)\n"
              "      for (var j = 0; j < 3; j++) {\n"
              "        m = steps[j] * Math.pow(10, e);\n"
              "        if (m * ppm <= 120) best = m;\n"
              "      }\n"
              "    if (!best) return;\n"
              "    var w = best * ppm, x = 14, y = MAP_H - 14;\n"
              "    var ln = svgEl(\"line\", \"fleet-scale\");\n"
              "    ln.x1.baseVal.value = x; ln.y1.baseVal.value = y;\n"
              "    ln.x2.baseVal.value = x + w; ln.y2.baseVal.value = y;\n"
              "    g.appendChild(ln);\n"
              "    var t = sized(svgEl(\"text\", \"fleet-scale-t\"), 11);\n"
              "    t.x.baseVal.appendItem(svgLen(x));\n"
              "    t.y.baseVal.appendItem(svgLen(y - 5));\n"
              "    t.textContent = best >= 1000 ? best / 1000 + \" km\" : best + \" m\";\n"
              "    g.appendChild(t);\n"
              "  }");
    WT_HAS(mod,
              "  function drawLocated(g, P, at, sized) {\n"
              "    var L = S.loc;\n"
              "    if (!L || !L.rows) return;\n"
              "    L.rows.forEach(function (r) {\n"
              "      var picked = r.key === S.pick;\n"
              "      r.candidates.forEach(function (c) {\n"
              "        var p = P(c.lat, c.lon), e = svgEl(\"circle\", \"fleet-cand\");\n"
              "        if (picked) e.classList.add(\"picked\");\n"
              "        e.cx.baseVal.value = p[0]; e.cy.baseVal.value = p[1];\n"
              "        e.r.baseVal.value = Math.max(3, c.radius_m * P.ppm);\n"
              "        var ti = svgEl(\"title\");\n"
              "        ti.textContent = r.key + (r.label ? \" \" + r.label : \"\") + \": \" + r.method.replace(\"_\", \" \") +\n"
              "                         \", +/-\" + c.radius_m + \" m\" + (r.coarse ? \" (coarse)\" : \"\");\n"
              "        e.appendChild(ti);\n"
              "        e.addEventListener(\"click\", function () { pick(r.key); });\n"
              "        g.appendChild(e);\n"
              "      });\n"
              "      if (!picked) return;\n"
              "      r.sites.forEach(function (s) {\n"
              "        var a = at[s.site];\n"
              "        if (!a) return;\n"
              "        var e = svgEl(\"circle\", \"fleet-range\");\n"
              "        e.cx.baseVal.value = a[0]; e.cy.baseVal.value = a[1];\n"
              "        e.r.baseVal.value = s.range_m * P.ppm;\n"
              "        g.appendChild(e);\n"
              "      });\n"
              "    });\n"
              "  }");
    /* The located emitters' table, whole (#192 I5 review: "neither"
     * when the nearer site's difference is inside its sigma). */
    WT_HAS(mod,
              "  function locRows() {\n"
              "    var box = $(\"fleet-loc-rows\"), L = S.loc;\n"
              "    while (box.firstChild) box.removeChild(box.firstChild);\n"
              "    if (!L) return;\n"
              "    L.rows.forEach(function (r) {\n"
              "      var row = H.el(\"div\", \"fleet-loc\" + (r.key === S.pick ? \" picked\" : \"\"));\n"
              "      var b = H.el(\"button\", \"fleet-dev\", r.key);\n"
              "      b.type = \"button\";\n"
              "      b.title = \"show its range circles on the map\";\n"
              "      b.addEventListener(\"click\", function () { pick(r.key); });\n"
              "      row.appendChild(b);\n"
              "      row.appendChild(H.el(\"span\", \"\", r.sites.map(function (s) {\n"
              "        return (s.site === \"self\" ? \"here\" : s.site) + \" \" + s.range_m + \" m (\" + s.lo_m + \"-\" + s.hi_m +\n"
              "               \")\" + (s.calibrated ? \"\" : \"*\");\n"
              "      }).join(\", \")));\n"
              "      // A difference inside its own sigma names no side.\n"
              "      row.appendChild(H.el(\"span\", r.nearest.within_band ? \"warn\" : \"\", r.nearest.within_band\n"
              "        ? \"neither (\" + r.nearest.by_db + \" dB, inside +/-\" + r.nearest.sigma_db + \")\"\n"
              "        : siteName(r.nearest.site) + \" by \" + r.nearest.by_db + \" dB (+/-\" + r.nearest.sigma_db + \")\"));\n"
              "      row.appendChild(H.el(\"span\", r.coarse ? \"warn\" : \"\", r.method.replace(\"_\", \" \") +\n"
              "                           (r.candidates.length ? \", \" + r.candidates.length + \" candidate\" +\n"
              "                            (r.candidates.length === 1 ? \"\" : \"s\") : \", circles do not cross\") +\n"
              "                           (r.coarse ? \"; coarse: band +/-\" + r.band_m + \" m over a \" + r.baseline_m +\n"
              "                            \" m baseline\" : \"\")));\n"
              "      box.appendChild(row);\n"
              "    });\n"
              "  ");
    WT_HAS(mod,
              "  function lane(site, t0, t1) {\n"
              "    var ln = H.el(\"div\", \"fleet-lane\" + (site.site === \"self\" ? \" self\" : \"\"));\n"
              "    ln.appendChild(H.el(\"span\", \"fleet-who\", site.site === \"self\" ? \"here\" : site.site));\n"
              "    var tr = H.el(\"div\", \"fleet-track\"), b = H.el(\"div\", \"fleet-bar\");\n"
              "    var span = t1 > t0 ? t1 - t0 : 1;\n"
              "    var a = Math.max(0, (site.first_seen - t0) / span), z = Math.min(1, (site.last_seen - t0) / span);\n"
              "    b.style.left = (a * 100).toFixed(2) + \"%\";\n"
              "    b.style.width = (Math.max(0, z - a) * 100).toFixed(2) + \"%\";\n"
              "    b.title = H.stamp(site.first_seen) + \" to \" + H.stamp(site.last_seen) +\n"
              "              (num(site.rssi) ? \", \" + site.rssi + \" dBm\" : \"\");\n"
              "    tr.appendChild(b);\n"
              "    ln.appendChild(tr);\n"
              "    return ln;\n"
              "  }");
    WT_HAS(mod,
              "  function devLink(kind, r) {\n"
              "    var b = H.el(\"button\", \"fleet-dev\", r.key);\n"
              "    b.type = \"button\";\n"
              "    b.title = \"open \" + r.addr;\n"
              "    b.addEventListener(\"click\", function () {\n"
              "      if (kind === \"ble\") H.openBleDrawer(r.addr);\n"
              "      else H.openDrawer(r.addr);\n"
              "    });\n"
              "    return b;\n"
              "  }");
    WT_HAS(mod,
              "  function svgEl(tag, cls) {\n"
              "    var e = document.createElementNS($(\"fleet-map\").namespaceURI, tag);\n"
              "    if (cls) e.classList.add(cls);\n"
              "    return e;\n"
              "  }");
    WT_HAS(mod,
              "    function sized(t, px) { t.style.fontSize = (px * fk).toFixed(1) + \"px\"; return t; }");
    WT_HAS(mod,
              "      kv(dl, \"backfill\", p.pages_refused ? \"not offered: the peer's build has no paged export (F1); upgrade it\"\n"
              "                         : bf.length ? \"fetching the rest of \" + bf.join(\", \") + \" (\" + p.pages + \" pages, \" +\n"
              "                          p.page_failures + \" refused)\" : \"complete\" + (p.pages ? \" (\" + p.pages + \" pages)\" : \"\"),\n"
              "         p.page_failures > 0 || !!p.pages_refused);");
    WT_HAS(mod,
              "  function show() {\n"
              "    load();\n"
              "    if (!S.timer) S.timer = setInterval(function () { if (!$(\"v-fleet\").hidden) load(); }, POLL_MS);\n"
              "  }");
    /* GNSS across the sites (#192 I6): the gauge (the band +/- the bound
     * around the reference distance, the mark the distance now), the
     * classified events' rows, the load and its note. */
    WT_HAS(mod,
              "  function gauge(p) {\n"
              "    var row = H.el(\"div\", \"fleet-gauge\");\n"
              "    row.appendChild(H.el(\"span\", \"fleet-who\", siteName(p.a) + \" - \" + siteName(p.b)));\n"
              "    var tr = H.el(\"div\", \"fleet-gtrack\");\n"
              "    if (num(p.delta_m) && num(p.bound_m)) {\n"
              "      var span = Math.max(p.bound_m * 1.5, Math.abs(p.delta_m) * 1.2, 1);\n"
              "      var band = H.el(\"div\", \"fleet-gband\"), mark = H.el(\"div\", \"fleet-gmark\" + (p.verdict === \"outside\" ? \" out\" : \"\"));\n"
              "      band.style.left = (50 - 50 * p.bound_m / span).toFixed(2) + \"%\";\n"
              "      band.style.width = (100 * p.bound_m / span).toFixed(2) + \"%\";\n"
              "      mark.style.left = (50 + 50 * p.delta_m / span).toFixed(2) + \"%\";\n"
              "      tr.appendChild(band);\n"
              "      tr.appendChild(mark);\n"
              "    }\n"
              "    row.appendChild(tr);\n"
              "    row.appendChild(H.el(\"span\", p.verdict === \"outside\" ? \"warn\" : \"\", p.verdict === \"undetermined\"\n"
              "      ? \"undetermined (\" + (p.why || \"\").replace(/_/g, \" \") + \")\"\n"
              "      : p.ref_m + \" m then, \" + p.now_m + \" m now: \" + (p.delta_m > 0 ? \"+\" : \"\") + p.delta_m + \" m, bound +/-\" +\n"
              "        p.bound_m + \" m, \" + p.verdict + (p.moved.length ? \"; moved: \" + p.moved.map(siteName).join(\", \") : \"\")));\n"
              "    return row;\n"
              "  ");
    WT_HAS(mod,
              "  function gnssRows(j) {\n"
              "    var box = $(\"fleet-gnss-rows\");\n"
              "    while (box.firstChild) box.removeChild(box.firstChild);\n"
              "    j.events.forEach(function (e) {\n"
              "      var row = H.el(\"div\", \"fleet-gev\");\n"
              "      row.appendChild(H.el(\"span\", \"\", H.stamp(e.first_seen) + (e.last_seen > e.first_seen ? \" +\" +\n"
              "                           Math.round((e.last_seen - e.first_seen) / 60) + \" min\" : \"\")));\n"
              "      row.appendChild(H.el(\"span\", \"\", siteName(e.site)));\n"
              "      row.appendChild(H.el(\"span\", \"\", e.type + \" (\" + e.class + (e.source === \"sample\" ? \", from the summary\" : \"\") + \")\"));\n"
              "      row.appendChild(H.el(\"span\", \"fleet-v \" + e.verdict, e.verdict === \"local\" ? \"this site only, the others watching\" : e.verdict));\n"
              "      var who = [];\n"
              "      if (e.with.length) who.push(\"same at \" + e.with.map(siteName).join(\", \"));\n"
              "      if (e.quiet.length) who.push(\"quiet at \" + e.quiet.map(siteName).join(\", \"));\n"
              "      if (e.stale.length) who.push(\"not observed at \" + e.stale.map(siteName).join(\", \"));\n"
              "      if (e.far.length) who.push(\"outside the region: \" + e.far.map(siteName).join(\", \"));\n"
              "      var w = H.el(\"span\", \"\", who.join(\"; \") || \"no other site\");\n"
              "      w.title = j.basis[e.class] || \"\";\n"
              "      row.appendChild(w);\n"
              "      box.appendChild(row);\n"
              "    });\n"
              "  ");
    WT_HAS(mod,
              "  function loadGnss() {\n"
              "    var gen = ++S.ggen;\n"
              "    return H.getJSON(\"/api/fleet/gnss?limit=50\").then(function (j) {\n"
              "      if (gen !== S.ggen) return;\n"
              "      gnssCards(j);\n"
              "      var base = $(\"fleet-gnss-base\");\n"
              "      while (base.firstChild) base.removeChild(base.firstChild);\n"
              "      j.baseline.forEach(function (p) { base.appendChild(gauge(p)); });\n"
              "      gnssRows(j);\n"
              "      var c = j.counts;\n"
              "      H.set(\"fleet-gnss-note\", \"position \" + j.position.verdict.replace(\"_\", \" \") +\n"
              "            (j.position.site ? \" (\" + siteName(j.position.site) + \")\" : \"\") + \", time \" +\n"
              "            j.time.verdict.replace(\"_\", \" \") + (j.time.site ? \" (\" + siteName(j.time.site) + \")\" : \"\") +\n"
              "            \"; this week \" + c.regional + \" regional, \" + c.local + \" local, \" + c.undetermined +\n"
              "            \" undetermined; window \" + j.window_s + \" s, region \" + dist(j.region_m) +\n"
              "            (j.local === \"open\" ? \"\" : \"; this site's own incidents not read (sloth.db: \" + j.local.replace(/_/g, \" \") + \")\"));\n"
              "    }).catch(function (e) {\n"
              "      if (gen === S.ggen) H.set(\"fleet-gnss-note\", H.errText(e.message));\n"
              "    });\n"
              "  ");
    WT_HAS(mod,
              "  function polar(s) {\n"
              "    var svg = svgEl(\"svg\", \"fleet-polar\");\n"
              "    var c = POLAR / 2, max = num(s.range_max_m) && s.range_max_m > 0 ? s.range_max_m : 0;\n"
              "    [1, 2, 3].forEach(function (k) {\n"
              "      var r = svgEl(\"circle\", \"fleet-pring\");\n"
              "      r.cx.baseVal.value = c; r.cy.baseVal.value = c; r.r.baseVal.value = POLAR_R * k / 3;\n"
              "      svg.appendChild(r);\n"
              "    });\n"
              "    if (max) {\n"
              "      var poly = svgEl(\"polygon\", \"fleet-pcov\"), host = $(\"fleet-map\");\n"
              "      s.sectors.forEach(function (sec) {\n"
              "        var r = num(sec.max_m) ? POLAR_R * sec.max_m / max : 0;\n"
              "        [sec.from, sec.from + 30].forEach(function (deg) {\n"
              "          var p = host.createSVGPoint(), a = deg * Math.PI / 180;\n"
              "          p.x = c + r * Math.sin(a); p.y = c - r * Math.cos(a);\n"
              "          poly.points.appendItem(p);\n"
              "        });\n"
              "      });\n"
              "      svg.appendChild(poly);\n"
              "    }\n"
              "    var me = svgEl(\"circle\", \"fleet-pself\");\n"
              "    me.cx.baseVal.value = c; me.cy.baseVal.value = c; me.r.baseVal.value = 3;\n"
              "    svg.appendChild(me);\n"
              "    var n = svgEl(\"text\", \"fleet-pt\");\n"
              "    n.x.baseVal.appendItem(svgLen(c)); n.y.baseVal.appendItem(svgLen(10));\n"
              "    n.textContent = \"N\";\n"
              "    svg.appendChild(n);\n"
              "    var t = svgEl(\"text\", \"fleet-pt\");\n"
              "    t.x.baseVal.appendItem(svgLen(c)); t.y.baseVal.appendItem(svgLen(POLAR - 2));\n"
              "    t.textContent = max ? \"outer ring \" + dist(max) : \"no position decoded\";\n"
              "    svg.appendChild(t);\n"
              "    return svg;\n"
              "  }\n");
    WT_HAS(mod,
              "  function acCards(j) {\n"
              "    var box = $(\"fleet-ac-sites\");\n"
              "    while (box.firstChild) box.removeChild(box.firstChild);\n"
              "    j.sites.forEach(function (s) {\n"
              "      if (!s.receiver) return;\n"
              "      var c = H.el(\"div\", \"fleet-card\");\n"
              "      c.appendChild(H.el(\"div\", \"fleet-card-h\", siteName(s.site)));\n"
              "      var dl = H.el(\"dl\");\n"
              "      kv(dl, \"decoder\", s.state ? (s.source || \"-\") + \", \" + s.state + (num(s.summary_age_s) ? \", \" + age(s.summary_age_s) : \"\")\n"
              "         : \"no summary\", !s.fresh);\n"
              "      kv(dl, \"now\", num(s.aircraft_now) ? s.aircraft_now + \" aircraft\" + (num(s.msg_rate) ? \", \" + s.msg_rate + \" msg/s\" : \"\") : \"-\");\n"
              "      kv(dl, \"coverage\", s.positions + \" positions over \" + Math.round(j.cov_window_s / 3600) + \" h\" +\n"
              "         (num(s.range_max_m) ? \", farthest \" + dist(s.range_max_m) : \"\") + (s.cov_complete ? \"\" : \" (partial)\"));\n"
              "      kv(dl, \"data to\", num(s.through_age_s) ? age(s.through_age_s) : \"never\", !num(s.through_age_s) || s.through_age_s > 300);\n"
              "      c.appendChild(dl);\n"
              "      c.appendChild(polar(s));\n"
              "      box.appendChild(c);\n"
              "    });\n"
              "    if (!box.firstChild) box.appendChild(H.el(\"div\", \"sub\", \"no site has an ADS-B receiver (sloth --adsb)\"));\n"
              "  }\n");
    WT_HAS(mod,
              "  function acRows(j) {\n"
              "    var box = $(\"fleet-ac-rows\");\n"
              "    while (box.firstChild) box.removeChild(box.firstChild);\n"
              "    j.aircraft.forEach(function (a) {\n"
              "      var row = H.el(\"div\", \"fleet-ac\");\n"
              "      row.appendChild(H.el(\"span\", \"\", a.hex + (a.flight ? \" \" + a.flight : \"\") + (a.emergency ? \" (\" + a.emergency + \")\" : \"\")));\n"
              "      row.appendChild(H.el(\"span\", \"\", (num(a.alt) ? a.alt + \" ft\" : \"-\") + (num(a.pos_ts) ? \", \" + H.stamp(a.pos_ts) : \", no position\") +\n"
              "                           (a.ref ? \" by \" + siteName(a.ref) : \"\")));\n"
              "      row.appendChild(H.el(\"span\", \"\", a.seen.map(function (s) {\n"
              "        return siteName(s.site) + (num(s.range_m) ? \" \" + dist(s.range_m) : \"\") + \" to \" + H.stamp(s.last_seen);\n"
              "      }).join(\"; \")));\n"
              "      var v = H.el(\"span\", \"fleet-v \" + a.verdict, a.verdict.replace(/_/g, \" \") + (a.why ? \" (\" + a.why.replace(/_/g, \" \") + \")\" : \"\") +\n"
              "                   (a.inconsistent ? \"; positions \" + dist(a.separation_m) + \" apart, more than it could fly\" : \"\"));\n"
              "      v.title = a.inconsistent ? j.basis.inconsistent : a.verdict === \"unconfirmed\" ? j.basis.unconfirmed : j.basis.thresholds;\n"
              "      row.appendChild(v);\n"
              "      row.appendChild(H.el(\"span\", \"\", a.peers.map(function (p) {\n"
              "        return siteName(p.site) + \": \" + p.state.replace(/_/g, \" \") + (num(p.dist_m) ? \" at \" + dist(p.dist_m) +\n"
              "               (num(p.sector_max_m) ? \" (reaches \" + dist(p.sector_max_m) + \" there)\" : \"\") : \"\");\n"
              "      }).join(\"; \") || \"no other receiver\"));\n"
              "      box.appendChild(row);\n"
              "    });\n");
    WT_HAS(mod,
              "  function loadAircraft() {\n"
              "    var gen = ++S.agen;\n"
              "    return H.getJSON(\"/api/fleet/aircraft?limit=100\").then(function (j) {\n"
              "      if (gen !== S.agen) return;\n"
              "      acCards(j);\n"
              "      acRows(j);\n"
              "      var c = j.counts, rx = j.sites.filter(function (s) { return s.receiver; }).map(function (s) { return siteName(s.site); });\n"
              "      H.set(\"fleet-ac-note\", (j.single_receiver\n"
              "        ? (rx.length ? \"one receiver in the fleet (\" + rx.join(\", \") + \"): \" : \"no receiver: \") +\n"
              "          \"every aircraft is undetermined until a second site decodes ADS-B; \"\n"
              "        : j.receivers + \" receivers; \") + j.total + \" aircraft in \" + Math.round(j.list_s / 3600) + \" h: \" +\n"
              "        c.confirmed + \" confirmed, \" + c.unconfirmed + \" unconfirmed, \" + c.out_of_peer_coverage + \" out of coverage, \" +\n"
              "        c.undetermined + \" undetermined\" + (c.inconsistent ? \", \" + c.inconsistent + \" with inconsistent positions\" : \"\") +\n"
              "        (j.partial ? \"; partial\" : \"\"));\n"
              "    }).catch(function (e) {\n"
              "      if (gen === S.agen) H.set(\"fleet-ac-note\", H.errText(e.message));\n"
              "    });\n");
    WT_HAS(mod,
              "  function load() {\n"
              "    loadOverview().then(loadLocate).then(loadShared).then(loadGnss).then(loadAircraft);\n"
              "  }");
    /* The module's fetches: the five routes, through the page's getJSON,
     * and nothing else. */
    WT_EQ(count_of(mod, "getJSON("), 5);
    WT_HAS(mod, "H.getJSON(\"/api/fleet/aircraft?limit=100\")");
    WT_HAS(mod, "H.getJSON(\"/api/fleet/gnss?limit=50\")");
    WT_HAS(mod, "H.getJSON(\"/api/fleet/overview\")");
    WT_HAS(mod, "H.getJSON(\"/api/fleet/locate?kind=\" + kind + \"&limit=50\")");
    WT_HAS(mod, "H.getJSON(\"/api/fleet/shared?kind=\" + kind + \"&limit=100\")");
    WT_LACKS(mod, "fetch(");
    WT_LACKS(mod, "XMLHttpRequest");
    WT_LACKS(mod, "<canvas");
    /* The view: one control (kept, test_prefs.c), one SVG, no canvas. */
    const char *v = strstr(p, "<div id=\"v-fleet\" hidden>");
    const char *ve = v ? strstr(v, "<div id=\"v-tacdb\" hidden>") : NULL;
    WT_ASSERT(v && ve);
    if (v && ve) {
        size_t n = (size_t)(ve - v);
        char *view = malloc(n + 1);
        if (view) {
            memcpy(view, v, n);
            view[n] = '\0';
            WT_EQ(count_of(view, "<select"), 1);
            WT_EQ(count_of(view, "<svg"), 1);
            WT_EQ(count_of(view, "<canvas"), 0);
            WT_LACKS(view, "<input");
            free(view);
        }
    }
    /* The stylesheet after radar's, the script after radar.js. */
    const char *rcss = strstr(p, ".radar-stage { position: relative;"), *fcss = strstr(p, "#fleet-map { display: block;");
    WT_ASSERT(rcss && fcss && rcss < fcss);
    const char *rjs = strstr(p, "// slothweb: the Radar view"), *fjs = strstr(p, "// slothweb: the Fleet view");
    WT_ASSERT(rjs && fjs && rjs < fjs);
    /* Colours by token only, so the light theme follows: to the end of
     * the aircraft panel's rules (#192 I6, I7). */
    const char *c0 = fcss, *c1 = fcss ? strstr(fcss, ".fleet-v.out_of_peer_coverage {") : NULL;
    WT_ASSERT(c0 && c1);
    if (c0 && c1) {
        size_t n = (size_t)(c1 - c0);
        char *css = malloc(n + 1);
        if (css) {
            memcpy(css, c0, n);
            css[n] = '\0';
            WT_LACKS(css, ": #");
            WT_LACKS(css, "rgb(");
            WT_LACKS(css, "hsl(");
            free(css);
        }
    }
    free(mod);
}

#ifdef WITH_SQLITE

#define T SDB_NOW
#define HR 3600LL
#define DY 86400LL

static char g_dir[TEST_TMP_MAX];
static char g_db[TEST_TMP_MAX + 32], g_store[TEST_TMP_MAX + 32];
static web_store_t   S;
static web_slothdb_t SDB;
static web_frrs_t    FR;
/* This site's radios as the export names them for own=1 (#192 I5). */
static const char   *g_own_csv;

static void rm_dir(void) {
    static const char *const names[] = {
        "sloth.db", "sloth.db-wal", "sloth.db-shm", "sloth.db-journal",
        "slothweb.db", "slothweb.db-wal", "slothweb.db-shm", "slothweb.db-journal",
        "here.db", "here.db-wal", "here.db-shm", "here.db-journal",
        "here-web.db", "here-web.db-wal", "here-web.db-shm", "here-web.db-journal",
    };
    char p[TEST_TMP_MAX + 32];
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        snprintf(p, sizeof(p), "%s/%s", g_dir, names[i]);
        unlink(p);
    }
    rmdir(g_dir);
}

static int sql_on(const char *path, const char *sql) {
    sqlite3 *h = NULL;
    int rc = sqlite3_open(path, &h);
    if (rc == SQLITE_OK) rc = sqlite3_exec(h, sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) fprintf(stderr, "    sql: %s\n", sqlite3_errmsg(h));
    sqlite3_close(h);
    return rc == SQLITE_OK ? 0 : -1;
}

static long long q1(const char *path, const char *sql) {
    sqlite3 *h = NULL;
    long long v = -1;
    if (sqlite3_open_v2(path, &h, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK &&
            sqlite3_step(st) == SQLITE_ROW)
            v = sqlite3_column_int64(st, 0);
        else
            fprintf(stderr, "    q1: %s\n", sqlite3_errmsg(h));
        sqlite3_finalize(st);
    }
    sqlite3_close(h);
    return v;
}

/* A sloth.db with sdb_seed()'s scenario (its cleartext credential among
 * it: the username alice-secret-user in cleartext_creds, in an alert's
 * key and in its detail) and, in the tables no export statement may
 * read, the other things that must never travel: EAPOL rows, a RADIUS
 * identity, an MQTT username, an RDP cookie. slothweb.db with a triage
 * decision whose note and author must stay here. */
static void up(void) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-fleet-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    snprintf(g_db, sizeof(g_db), "%s/sloth.db", g_dir);
    snprintf(g_store, sizeof(g_store), "%s/slothweb.db", g_dir);
    WT_EQ(sdb_make(g_db, db_schema_version(), 0), 0);
    WT_EQ(sdb_seed(g_db), 0);
    char sql[2048];
    snprintf(sql, sizeof(sql),
        "INSERT INTO eapol_events (bssid,sta_mac,ts,msg_num,ssid,has_pmkid,"
        "handshake_complete,first_seen,last_seen) VALUES"
        " ('0e:ee:ee:ee:ee:01','02:ee:ee:ee:ee:02',%lld,2,'eapol-marker-ssid',1,1,%lld,%lld);"
        "INSERT INTO rogue_radius (bssid,identity_leaks,last_identity,first_seen,"
        "last_seen) VALUES ('0e:ee:ee:ee:ee:03',1,'radius-identity-marker',%lld,%lld);"
        "INSERT INTO mqtt_flows (src_ip,dst_ip,connect_count,last_username,first_seen,"
        "last_seen) VALUES ('10.0.4.1','10.0.4.2',1,'mqtt-user-marker',%lld,%lld);"
        "INSERT INTO rdp_flows (src_ip,dst_ip,connect_req_count,last_cookie,proto_mask,"
        "first_seen,last_seen) VALUES ('10.0.4.3','10.0.4.4',1,'mstshash=rdp-marker',1,"
        "%lld,%lld);"
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,technique,"
        "match_ip,match_port,count) VALUES ('pmkid:0e:ee:ee:ee:ee:01:deadbeefcafe',%lld,"
        "%lld,5,1,'PMKID exposed','pmkid=deadbeefcafe0123','T1557',NULL,NULL,1);",
        T - 50, T - 50, T - 50, T - 45, T - 44, T - 40, T - 30, T - 40, T - 30, T - 70,
        T - 60);
    WT_EQ(sdb_exec(g_db, sql), 0);
    web_slothdb_init(&SDB, g_db, NULL);
    char err[512];
    WT_EQ(web_store_open(&S, g_store, err, sizeof(err)), 0);
    snprintf(sql, sizeof(sql),
        "INSERT INTO triage (subject,finding,type,addr,port,first_seen,state,ts,note,"
        "who,peer) VALUES ('x12:%lld',NULL,12,'10.0.1.5',21,%lld,4,%lld,"
        "'triage-note-marker','op-marker','127.0.0.1'),"
        " ('x0:%lld',NULL,0,'10.0.0.7',0,%lld,1,%lld,'','','127.0.0.1');",
        T - 100, T - 100, T - 90, T - 30 * DY, T - 30 * DY, T - 20 * DY);
    WT_EQ(sql_on(g_store, sql), 0);
    WT_EQ(web_frrs_init(&FR, &S, NULL, 1, err, sizeof(err)), 0);
}

static void down(void) {
    web_frrs_destroy(&FR);
    web_slothdb_destroy(&SDB);
    web_store_close(&S);
    rm_dir();
}

static char *export(long long since_q, const char *query, int *status) {
    web_fleet_src_t src = { &SDB, NULL, NULL, &FR, g_own_csv, NULL, NULL, NULL };
    char q[64];
    if (!query) snprintf(q, sizeof(q), "since=%lld", since_q);
    char *body = NULL;
    size_t len = 0;
    WT_EQ(web_fleet_export_route(&src, query ? query : q, T, &body, &len, status), 0);
    if (!body) return NULL;
    char *t = realloc(body, len + 1);
    if (!t) { free(body); return NULL; }
    t[len] = '\0';
    return t;
}

/* The export over the seeded files: the device, its association and its
 * probe list, the AP, the alerts by type, title and fingerprint, the
 * verdict by descriptor and state; and nothing it must not carry. Every
 * line decodes, every member is listed, and the importer takes it.
 * The username's absence was seen red with web_sdb_alerts_between()'s
 * statement selecting alerts.detail in place of the title and
 * alerts.detail put on M4's allow-list (the reader's two guards changed
 * together: either alone still holds it out), "alice-detail" then in the
 * body; the note's with web_frrs_verdicts() reading note into addr. */
static void test_export_withholds_secrets(void) {
    up();
    int st = 0;
    char *b = export(0, NULL, &st);
    WT_EQ(st, 200);
    WT_ASSERT(b != NULL);
    if (!b) { down(); return; }
    WT_HAS(b, "{\"type\":\"fleet_export\",\"fleet_export_version\":1,\"generated\":");
    WT_HAS(b, ",\"sloth_db\":\"open\",\"lat\":null,");
    WT_HAS(b, "{\"type\":\"wifi\",\"mac\":\"da:a1:19:00:00:01\",\"vendor\":\"Apple\","
              "\"ssid\":\"HomeNet\",\"rssi\":-48,\"bssid\":\"aa:bb:cc:dd:ee:ff\","
              "\"is_ap\":false,");
    WT_HAS(b, "{\"type\":\"probe\",\"mac\":\"da:a1:19:00:00:01\",\"ssid\":\"HomeNet\",");
    WT_HAS(b, "{\"type\":\"probe\",\"mac\":\"da:a1:19:00:00:01\",\"ssid\":\"CafeFree\",");
    WT_HAS(b, "{\"type\":\"alert\",\"alert_type\":");
    WT_HAS(b, ",\"title\":\"FTP login in cleartext\",\"ip\":\"10.0.1.5\",\"sev\":2,\"count\":3,");
    WT_HAS(b, ",\"title\":\"PMKID exposed\",");
    WT_HAS(b, "{\"type\":\"verdict\",\"alert_type\":");
    WT_HAS(b, ",\"addr\":\"10.0.1.5\",\"port\":21,");
    WT_HAS(b, ",\"state\":\"known\",");
    WT_HAS(b, "\"complete\":true}\n");
    /* The things that must never travel. */
    static const char *const never[] = {
        "alice", "cred:", "user=", "eapol-marker", "02:ee:ee:ee:ee:02",
        "radius-identity", "mqtt-user", "mstshash", "rdp-marker", "deadbeef",
        "pmkid:", "triage-note-marker", "op-marker", "127.0.0.1",
    };
    for (size_t i = 0; i < sizeof(never) / sizeof(never[0]); i++) WT_LACKS(b, never[i]);
    /* Every line decodes and lists only its own members. */
    web_jrec_t *rec = malloc(sizeof(*rec));
    int lines = 0;
    for (char *p = b; rec && *p;) {
        char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        WT_EQ(web_jl_parse(p, n, rec), WEB_JL_OK);
        const char *const *m = web_fleet_members_of(web_jl_str(rec, "type"));
        WT_ASSERT(m != NULL);
        for (int i = 0; m && i < rec->n; i++) {
            int ok = !strcmp(rec->f[i].key, "type");
            for (int k = 1; m[k] && !ok; k++) ok = !strcmp(m[k], rec->f[i].key);
            WT_ASSERT(ok);
        }
        lines++;
        p = nl ? nl + 1 : p + n;
    }
    free(rec);
    WT_ASSERT(lines >= 15);
    /* The importer takes what the exporter writes. */
    web_fleet_t f;
    web_fleet_peer_cfg_t pc;
    char err[200];
    WT_EQ(web_fleet_parse_peer("self=http://100.64.0.1:8770", &pc, err, sizeof(err)), 0);
    web_fleet_init(&f, &pc, 1, 60, 0, &S);
    long long rows = 0, rts = 0;
    int rc = web_fleet_ingest(&f, 0, b, strlen(b), T, 0, &rows, &rts, err, sizeof(err));
    if (rc) fprintf(stderr, "    ingest: %s\n", err);
    WT_EQ(rc, 0);
    WT_EQ(rts, T);
    WT_ASSERT(rows >= 12);
    web_fleet_destroy(&f);
    free(b);
    down();
}

/* `since`: a row last seen before it is not sent; the parameter is
 * checked. Seen red with the export reading from 0 whatever since
 * says. */
static void test_export_since(void) {
    up();
    int st = 0;
    char *b = export(T - 2 * HR, NULL, &st);
    WT_EQ(st, 200);
    if (b) {
        WT_HAS(b, "\"mac\":\"da:a1:19:00:00:01\"");       /* seen 1 h ago */
        WT_HAS(b, "\"mac\":\"00:11:22:33:44:55\"");       /* 10 s ago */
        WT_LACKS(b, "\"mac\":\"da:a1:19:00:00:02\"");     /* 30 h ago */
        WT_LACKS(b, "\"mac\":\"f2:11:22:00:00:06\"");     /* 23 h ago */
        WT_LACKS(b, "\"mac\":\"da:a1:19:00:00:07\"");     /* 24 h ago */
        WT_LACKS(b, "\"state\":\"false\"");               /* decided 20 d ago */
        WT_HAS(b, "\"state\":\"known\"");
    }
    free(b);
    b = export(0, "since=12x", &st);
    WT_EQ(st, 400);
    if (b) WT_HAS(b, "bad_since");
    free(b);
    b = export(0, "since=1&limit=2", &st);
    WT_EQ(st, 400);
    if (b) WT_HAS(b, "unknown_parameter");
    free(b);
    b = export(0, "from=1", &st);
    WT_EQ(st, 400);
    free(b);
    b = export(0, "", &st);
    WT_EQ(st, 200);
    if (b) WT_HAS(b, "\"mac\":\"da:a1:19:00:00:02\"");
    free(b);
    /* Through the route table: JSON Lines, GET only. */
    web_m4_t m4;
    memset(&m4, 0, sizeof(m4));
    m4.sdb = &SDB;
    m4.frrs = &FR;
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.wall_s = T;
    h.m4 = &m4;
    static char out[65536];
    web_req_t rq;
    web_resp_t r;
    memset(&rq, 0, sizeof(rq));
    snprintf(rq.path, sizeof(rq.path), "/api/fleet/export");
    snprintf(rq.query, sizeof(rq.query), "since=%lld", T - 60);
    snprintf(rq.host, sizeof(rq.host), "100.64.0.1:8770");
    rq.host_count = 1;
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 200);
    out[r.out_len] = '\0';
    WT_HAS(out, "Content-Type: application/x-ndjson\r\n");
    WT_ASSERT(r.body_owned != NULL && r.body_len > 0);
    free(r.body_owned);
    rq.is_head = 1;
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 405);
    down();
}

/* A row the importer would refuse is not sent: one such row refuses the
 * peer's whole answer, at every pull, while it is in the window. A device
 * whose stored signal is +60 dBm (outside the importer's -150..30) and
 * one whose first seen is after its last seen are left out, the wifi
 * kind is marked truncated, and the answer is still taken. Seen red with
 * row_end()'s self-check removed (the importer then refused the answer:
 * "line N: a wifi line with a value out of range"). */
static void test_export_sends_only_what_the_importer_takes(void) {
    up();
    char sql[1024];
    snprintf(sql, sizeof(sql),
        "INSERT INTO devices (mac,vendor,is_ap,signal_dbm,first_seen,last_seen) VALUES"
        " ('02:0b:ad:00:00:60','Odd',0,60,%lld,%lld),"
        " ('02:0b:ad:00:00:61','Odd',0,-50,%lld,%lld),"
        " ('02:0b:ad:00:00:62','Arp',0,0,%lld,%lld),"
        " ('02:0b:ad:00:00:63','Old',0,0,%lld,%lld),"
        " ('02:0b:ad:00:00:64','Five',0,0,%lld,%lld);"
        "INSERT INTO probe_clients (mac,ssid,signal_dbm,channel,first_seen,last_seen)"
        " VALUES ('02:0b:ad:00:00:62','',-52,6,%lld,%lld),"
        " ('02:0b:ad:00:00:63','',-53,6,%lld,%lld),"
        " ('02:0b:ad:00:00:64','',-54,36,%lld,%lld);",
        T - 100, T - 20, T - 5, T - 30, T - 100, T - 20, T - 100, T - 20, T - 100, T - 20,
        T - 100, T - 40, T - 900, T - 20 - WEB_LOC_WINDOW_S - 1, T - 100, T - 20);
    WT_EQ(sdb_exec(g_db, sql), 0);
    int st = 0;
    char *b = export(0, NULL, &st);
    WT_EQ(st, 200);
    if (b) {
        /* +60 dBm is no reading (sloth's 0 and above, #192 I5): the
         * row travels with none; the inverted times still keep 61 out. */
        WT_HAS(b, "\"mac\":\"02:0b:ad:00:00:60\",\"vendor\":\"Odd\",\"ssid\":null,"
                  "\"rssi\":null,");
        WT_LACKS(b, "02:0b:ad:00:00:61");
        /* An ARP row's 0 travels as the probe's reading (#192 I5; seen
         * red with the export's fallback removed: "rssi":null). */
        WT_HAS(b, "\"mac\":\"02:0b:ad:00:00:62\",\"vendor\":\"Arp\",\"ssid\":null,"
                  "\"rssi\":-52,");
        /* Not a probe older than the window before the row's last_seen,
         * which the importer would pair as current, nor one on 5 GHz,
         * which it would model at 2.4 (#192 I5 review; seen red with
         * each condition removed: -53 and -54). */
        WT_HAS(b, "\"mac\":\"02:0b:ad:00:00:63\",\"vendor\":\"Old\",\"ssid\":null,"
                  "\"rssi\":null,");
        WT_HAS(b, "\"mac\":\"02:0b:ad:00:00:64\",\"vendor\":\"Five\",\"ssid\":null,"
                  "\"rssi\":null,");
        WT_HAS(b, "\"mac\":\"da:a1:19:00:00:01\"");
        WT_HAS(b, "\"truncated_wifi\":true");
        WT_HAS(b, "\"truncated_ap\":false");
        web_fleet_t f;
        web_fleet_peer_cfg_t pc;
        char err[200];
        WT_EQ(web_fleet_parse_peer("self=http://100.64.0.1:8770", &pc, err, sizeof(err)), 0);
        web_fleet_init(&f, &pc, 1, 60, 0, &S);
        long long rows = 0, rts = 0;
        int rc = web_fleet_ingest(&f, 0, b, strlen(b), T, 0, &rows, &rts, err, sizeof(err));
        if (rc) fprintf(stderr, "    ingest: %s\n", err);
        WT_EQ(rc, 0);
        web_fleet_destroy(&f);
    }
    free(b);
    down();
}

/* ── the pull, from a loopback server ───────────────────────────────── */

typedef struct {
    int         lfd;
    const char *resp;
    size_t      len;
    char        req[512];
} srv_t;

static void *serve_once(void *arg) {
    srv_t *s = arg;
    int fd = accept(s->lfd, NULL, NULL);
    if (fd < 0) return NULL;
    size_t n = 0;
    while (n + 1 < sizeof(s->req)) {
        ssize_t k = recv(fd, s->req + n, sizeof(s->req) - 1 - n, 0);
        if (k <= 0) break;
        n += (size_t)k;
        s->req[n] = '\0';
        if (strstr(s->req, "\r\n\r\n")) break;
    }
    for (size_t o = 0; o < s->len;) {
        ssize_t k = send(fd, s->resp + o, s->len - o, MSG_NOSIGNAL);
        if (k <= 0) break;
        o += (size_t)k;
    }
    close(fd);
    return NULL;
}

static web_fleet_t F;

/* One pull of peer 0 against a server answering resp (headers added
 * here unless raw). The pull's return. */
static int pull_with(const char *resp, int raw, char *req, size_t reqsz) {
    srv_t s;
    memset(&s, 0, sizeof(s));
    s.lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    WT_EQ(bind(s.lfd, (struct sockaddr *)&sa, sizeof(sa)), 0);
    WT_EQ(listen(s.lfd, 1), 0);
    socklen_t sl = sizeof(sa);
    getsockname(s.lfd, (struct sockaddr *)&sa, &sl);
    F.peer[0].cfg.port = ntohs(sa.sin_port);
    char *full = NULL;
    if (raw) {
        s.resp = resp;
        s.len = strlen(resp);
    } else {
        size_t bl = strlen(resp);
        full = malloc(bl + 256);
        int hl = snprintf(full, 256, "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\n"
                          "Content-Length: %zu\r\nConnection: close\r\n\r\n", bl);
        memcpy(full + hl, resp, bl + 1);
        s.resp = full;
        s.len = (size_t)hl + bl;
    }
    pthread_t th;
    pthread_create(&th, NULL, serve_once, &s);
    int rc = web_fleet_pull_one(&F, 0, T);
    pthread_join(th, NULL);
    close(s.lfd);
    free(full);
    if (req) snprintf(req, reqsz, "%s", s.req);
    return rc;
}

#define HDR(gen) "{\"type\":\"fleet_export\",\"fleet_export_version\":1,\"generated\":" #gen \
    ",\"since\":0,\"site_label\":\"beta-site\",\"slothweb_version\":\"1.8.6\"," \
    "\"sloth_version\":null,\"sloth_db\":\"open\",\"lat\":41.8781136,\"lon\":-87.6297982," \
    "\"alt_m\":181.0,\"pos_source\":\"fixed\",\"pos_ts\":" #gen ",\"pos_age_s\":0}\n"

static const char GOOD[] =
    HDR(1792627000)
    "{\"type\":\"gnss\",\"gps_state\":\"fixed\",\"sats_in_view\":12,\"sats_used\":9,"
    "\"cn0_mean\":38.5,\"time_offset_ms\":null,\"jam\":3,\"ts\":1792626990}\n"
    "{\"type\":\"wifi\",\"mac\":\"DA:A1:19:00:00:01\",\"vendor\":\"Apple\",\"ssid\":\"HomeNet\","
    "\"rssi\":-48,\"bssid\":\"aa:bb:cc:dd:ee:ff\",\"is_ap\":false,\"first_seen\":1792600000,"
    "\"last_seen\":1792626000}\n"
    "{\"type\":\"ble\",\"addr\":\"c0:ff:ee:00:00:01\",\"addr_type\":\"r\",\"name\":\"tag\","
    "\"class\":\"tag\",\"rssi\":-70,\"first_seen\":1792620000,\"last_seen\":1792626500}\n"
    "{\"type\":\"ap\",\"bssid\":\"aa:bb:cc:dd:ee:ff\",\"ssid\":\"HomeNet\",\"channel\":6,"
    "\"enc\":\"WPA2\",\"vendor\":null,\"rssi\":-40,\"first_seen\":1792500000,"
    "\"last_seen\":1792626900}\n"
    "{\"type\":\"probe\",\"mac\":\"da:a1:19:00:00:01\",\"ssid\":\"W9FJC-home\","
    "\"first_seen\":1792610000,\"last_seen\":1792626000}\n"
    "{\"type\":\"alert\",\"alert_type\":\"EVIL_TWIN\",\"ty\":18,\"fingerprint\":"
    "\"0123456789abcdef\",\"title\":\"Evil twin\",\"ip\":null,\"sev\":1,\"count\":4,"
    "\"first_seen\":1792620000,\"last_seen\":1792626000}\n"
    "{\"type\":\"verdict\",\"alert_type\":\"EVIL_TWIN\",\"addr\":\"aa:bb:cc:dd:ee:ff\","
    "\"port\":0,\"alert_first_seen\":1792620000,\"state\":\"known\",\"ts\":1792626100}\n"
    "{\"type\":\"wifi\",\"mac\":\"02:00:00:00:00:99\",\"vendor\":null,\"ssid\":null,"
    "\"rssi\":null,\"bssid\":null,\"is_ap\":false,\"first_seen\":1700000000,"
    "\"last_seen\":1700000000}\n"
    "{\"type\":\"fleet_end\",\"rows\":7,\"wifi\":2,\"ble\":1,\"ap\":1,\"probe\":1,\"alert\":1,"
    "\"verdict\":1,\"truncated_wifi\":false,\"truncated_ble\":false,\"truncated_ap\":false,"
    "\"truncated_probe\":false,\"truncated_alert\":false,\"truncated_verdict\":false,"
    "\"complete\":true}\n";

/* The second answer: the device again, heard earlier and later than the
 * first said, and nothing else. */
static const char GOOD2[] =
    HDR(1792627600)
    "{\"type\":\"wifi\",\"mac\":\"da:a1:19:00:00:01\",\"vendor\":\"Apple\",\"ssid\":\"CafeFree\","
    "\"rssi\":-60,\"bssid\":null,\"is_ap\":false,\"first_seen\":1792500000,"
    "\"last_seen\":1792627500}\n"
    "{\"type\":\"fleet_end\",\"rows\":1,\"wifi\":1,\"ble\":0,\"ap\":0,\"probe\":0,\"alert\":0,"
    "\"verdict\":0,\"truncated_wifi\":false,\"truncated_ble\":false,\"truncated_ap\":false,"
    "\"truncated_probe\":false,\"truncated_alert\":false,\"truncated_verdict\":false,"
    "\"complete\":true}\n";

static void pull_up(void) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-pull-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    snprintf(g_store, sizeof(g_store), "%s/slothweb.db", g_dir);
    char err[512];
    WT_EQ(web_store_open(&S, g_store, err, sizeof(err)), 0);
    web_fleet_peer_cfg_t pc;
    WT_EQ(web_fleet_parse_peer("beta=http://127.0.0.1:1", &pc, err, sizeof(err)), 0);
    web_fleet_init(&F, &pc, 1, 60, 1, &S);
    F.connect_ms = 2000;
    F.read_ms = 5000;
    /* The pull thread's connection, without the thread: the tests step
     * the pull themselves. */
    WT_EQ(web_store_open_aux(&S, &F.wr, err, sizeof(err)), 0);
}

static void pull_down(void) {
    web_fleet_destroy(&F);
    web_store_close(&S);
    rm_dir();
}

static long long sightings(void) {
    return q1(g_store, "SELECT COUNT(*) FROM peer_sightings");
}

/* A good answer is stored whole: the site and its position, each kind
 * keyed canonically (the upper-case MAC lower-cased), a row older than
 * WEB_FLEET_KEEP_S by the peer's own clock dropped by the bound; the
 * first request asks since=0. The second asks from the peer's clock
 * less the overlap, and widens the device's first and last seen while
 * taking its newest label. Seen red with the upsert's first_seen CASE
 * replaced by excluded.first_seen (and with the age bound's DELETE
 * removed: 02:..:99 kept). */
static void test_pull_good_and_upsert(void) {
    pull_up();
    char req[512];
    int rc = pull_with(GOOD, 0, req, sizeof(req));
    if (rc) fprintf(stderr, "    pull: %s\n", F.peer[0].last_error);
    WT_EQ(rc, 0);
    WT_HAS(req, "GET /api/fleet/export?since=0&next=1&own=1&gnss=1&adsb=1&ident=1 HTTP/1.1\r\n");
    WT_HAS(req, "Host: 127.0.0.1:");
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sites WHERE peer='beta' AND"
                      " label='beta-site' AND pos_source='fixed' AND lat>41.87 AND"
                      " lat<41.88 AND remote_ts=1792627000 AND rows_last=7 AND"
                      " last_error='' AND last_ok>0"), 1);
    WT_EQ(sightings(), 7);    /* 6 kinds and the receiver; 02:..:99 aged out */
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi' AND"
                      " key='da:a1:19:00:00:01' AND label='HomeNet' AND vendor='Apple'"
                      " AND rssi=-48 AND first_seen=1792600000 AND last_seen=1792626000"
                      " AND extra='{\"bssid\":\"aa:bb:cc:dd:ee:ff\",\"is_ap\":false}'"), 1);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE"
                      " key='02:00:00:00:00:99'"), 0);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='probe' AND"
                      " key='da:a1:19:00:00:01|W9FJC-home'"), 1);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='verdict' AND"
                      " key='EVIL_TWIN|aa:bb:cc:dd:ee:ff|0|1792620000' AND label='known'"), 1);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='gnss' AND"
                      " key='receiver' AND label='fixed'"), 1);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='alert' AND"
                      " key='0123456789abcdef' AND label='Evil twin'"), 1);

    rc = pull_with(GOOD2, 0, req, sizeof(req));
    WT_EQ(rc, 0);
    WT_HAS(req, "GET /api/fleet/export?since=1792626880&next=1&own=1&gnss=1&adsb=1&ident=1 HTTP/1.1\r\n");
    WT_EQ(sightings(), 7);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi' AND"
                      " key='da:a1:19:00:00:01' AND label='CafeFree' AND rssi=-60"
                      " AND first_seen=1792500000 AND last_seen=1792627500"), 1);
    /* An answer reporting less (an older last seen, a later first seen)
     * narrows nothing. */
    static const char OLD[] =
        HDR(1792627700)
        "{\"type\":\"wifi\",\"mac\":\"da:a1:19:00:00:01\",\"vendor\":\"Apple\",\"ssid\":\"x\","
        "\"rssi\":-61,\"bssid\":null,\"is_ap\":false,\"first_seen\":1792610000,"
        "\"last_seen\":1792611000}\n"
        "{\"type\":\"fleet_end\",\"rows\":1,\"wifi\":1,\"ble\":0,\"ap\":0,\"probe\":0,\"alert\":0,"
        "\"verdict\":0,\"truncated_wifi\":false,\"truncated_ble\":false,\"truncated_ap\":false,"
        "\"truncated_probe\":false,\"truncated_alert\":false,\"truncated_verdict\":false,"
        "\"complete\":true}\n";
    WT_EQ(pull_with(OLD, 0, NULL, 0), 0);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi' AND"
                      " key='da:a1:19:00:00:01' AND first_seen=1792500000 AND"
                      " last_seen=1792627500"), 1);
    /* /api/health and /api/fleet/peers. */
    web_m4_t m4;
    memset(&m4, 0, sizeof(m4));
    m4.fleet = &F;
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.wall_s = T + 30;
    h.m4 = &m4;
    static char out[65536];
    web_req_t rq;
    web_resp_t r;
    memset(&rq, 0, sizeof(rq));
    snprintf(rq.path, sizeof(rq.path), "/api/health");
    snprintf(rq.host, sizeof(rq.host), "127.0.0.1:8770");
    rq.host_count = 1;
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    out[r.out_len] = '\0';
    WT_EQ(r.status, 200);
    WT_HAS(out, ",\"fleet\":{\"export\":true,\"export_version\":1,\"interval_s\":60,"
                "\"outside_tailnet\":true,\"peers\":[{\"name\":\"beta\",\"url\":"
                "\"http://127.0.0.1:1\",\"last_ok_age_s\":30,\"last_attempt_age_s\":30,"
                "\"last_error\":null,\"rows\":1,\"pulls\":3,\"failures\":0}]}");
    snprintf(rq.path, sizeof(rq.path), "/api/fleet/peers");
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    out[r.out_len] = '\0';
    WT_EQ(r.status, 200);
    WT_HAS(out, "{\"export\":true,\"interval_s\":60,\"store\":true,\"peers\":[{\"name\":"
                "\"beta\",\"configured\":true,\"url\":\"http://127.0.0.1:1\",\"label\":"
                "\"beta-site\",");
    WT_HAS(out, ",\"lat\":41.8781136,\"lon\":-87.6297982,\"alt_m\":181.0,\"pos_source\":"
                "\"fixed\",");
    WT_HAS(out, ",\"counts\":{\"alert\":1,\"ap\":1,\"ble\":1,\"gnss\":1,\"probe\":1,"
                "\"verdict\":1,\"wifi\":1}}");
    snprintf(rq.query, sizeof(rq.query), "x=1");
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 400);
    pull_down();
}

/* Each refused answer leaves every sighting and the last good pull as
 * they were, and says why. Seen red with the response-size checks in
 * http_get() removed (the oversize answer stored), with the ingest's
 * "no end line" refusal removed (that answer stored) and with
 * members_ok() returning 1 (the username line taken). */
static void test_pull_refusals(void) {
    pull_up();
    WT_EQ(pull_with(GOOD, 0, NULL, 0), 0);
    long long before = sightings();
    WT_EQ(before, 7);
    static const char FP[] = "SELECT COUNT(*) FROM peer_sites WHERE remote_ts=1792627000"
                             " AND rows_last=7 AND last_ok=" "1792627200";
    WT_EQ(q1(g_store, FP), 1);
    char line[512];
    struct { const char *what, *resp; int raw; const char *why; } cases[] = {
        { "malformed", HDR(1792627900) "{\"type\":\"wifi\",\"mac\":\n", 0, "line 2" },
        { "username member", HDR(1792627900)
          "{\"type\":\"wifi\",\"mac\":\"02:00:00:00:00:01\",\"username\":\"u-marker\","
          "\"first_seen\":1,\"last_seen\":2}\n"
          "{\"type\":\"fleet_end\",\"rows\":1,\"wifi\":1,\"ble\":0,\"ap\":0,\"probe\":0,"
          "\"alert\":0,\"verdict\":0,\"complete\":true}\n", 0, "may not carry" },
        { "no end line", HDR(1792627900)
          "{\"type\":\"wifi\",\"mac\":\"02:00:00:00:00:01\",\"first_seen\":1,"
          "\"last_seen\":2}\n", 0, "no end line" },
        { "count", HDR(1792627900)
          "{\"type\":\"wifi\",\"mac\":\"02:00:00:00:00:01\",\"first_seen\":1,"
          "\"last_seen\":2}\n"
          "{\"type\":\"fleet_end\",\"rows\":1,\"wifi\":2,\"ble\":0,\"ap\":0,\"probe\":0,"
          "\"alert\":0,\"verdict\":0,\"complete\":true}\n", 0, "wifi count" },
        { "version", "{\"type\":\"fleet_export\",\"fleet_export_version\":2,"
          "\"generated\":1792627900}\n{\"type\":\"fleet_end\",\"rows\":0,\"wifi\":0,"
          "\"ble\":0,\"ap\":0,\"probe\":0,\"alert\":0,\"verdict\":0,\"complete\":true}\n",
          0, "no fleet_export header" },
        { "bad mac", HDR(1792627900)
          "{\"type\":\"wifi\",\"mac\":\"not-a-mac\",\"first_seen\":1,\"last_seen\":2}\n", 0,
          "out of range" },
        { "status", "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n", 1,
          "HTTP status 503" },
        { "cut short", "HTTP/1.1 200 OK\r\nContent-Length: 9999\r\n\r\n"
          HDR(1792627900), 1, "cut short" },
        { "chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
          "1f4\r\n" HDR(1792627900) "\r\n0\r\n\r\n", 1, "Transfer-Encoding" },
        { "two lengths", "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n"
          "Content-Length: 10\r\n\r\n0123456789", 1, "two Content-Length" },
        { "length not a number", "HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n", 1,
          "not a number" },
        { "not http", "SSH-2.0-OpenSSH_9.6\r\n", 1, "not an HTTP response" },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int rc = pull_with(cases[i].resp, cases[i].raw, NULL, 0);
        if (rc == 0) fprintf(stderr, "    taken: %s\n", cases[i].what);
        WT_EQ(rc, -1);
        snprintf(line, sizeof(line), "%s", F.peer[0].last_error);
        if (!strstr(line, cases[i].why))
            fprintf(stderr, "    %s: \"%s\"\n", cases[i].what, line);
        WT_HAS(line, cases[i].why);
        WT_EQ(sightings(), before);
        WT_EQ(q1(g_store, FP), 1);
        WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE"
                          " key LIKE '02:00:00:00:00:01%'"), 0);
    }
    /* The refusal is kept beside the last good pull. */
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sites WHERE last_error LIKE"
                      " '%not an HTTP response%'"), 1);
    /* Oversize: past resp_max, refused, never cut to fit. */
    /* A well-formed answer of 60 probe lines, some 7 KB: only its size
     * is wrong. */
    F.resp_max = 1024;
    char *huge = malloc(16384);
    size_t o = (size_t)snprintf(huge, 16384, "%s", HDR(1792627900));
    for (int i = 0; i < 60; i++)
        o += (size_t)snprintf(huge + o, 16384 - o, "{\"type\":\"probe\",\"mac\":"
                              "\"02:00:00:00:00:01\",\"ssid\":\"net-%02d\",\"first_seen\":1792620000,"
                              "\"last_seen\":1792626000}\n", i);
    snprintf(huge + o, 16384 - o, "{\"type\":\"fleet_end\",\"rows\":60,\"wifi\":0,"
             "\"ble\":0,\"ap\":0,\"probe\":60,\"alert\":0,\"verdict\":0,"
             "\"complete\":true}\n");
    WT_ASSERT(strlen(huge) > 4096);
    WT_EQ(pull_with(huge, 0, NULL, 0), -1);
    WT_HAS(F.peer[0].last_error, "over 1024 bytes");
    WT_EQ(sightings(), before);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE"
                      " key LIKE '02:00:00:00:00:01%'"), 0);
    free(huge);
    F.resp_max = WEB_FLEET_RESP_MAX;
    /* And a good one after them all is stored. */
    WT_EQ(pull_with(GOOD2, 0, NULL, 0), 0);
    WT_EQ(F.peer[0].last_error[0], '\0');
    WT_EQ(F.peer[0].failures, 13);
    pull_down();
}

/* A peer that answers a byte at a time and never finishes. */
typedef struct {
    int lfd;
} trickle_t;

static void *serve_trickle(void *arg) {
    trickle_t *t = arg;
    int fd = accept(t->lfd, NULL, NULL);
    if (fd < 0) return NULL;
    char rq[512];
    (void)recv(fd, rq, sizeof(rq), 0);
    static const char H[] = "HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n";
    if (send(fd, H, sizeof(H) - 1, MSG_NOSIGNAL) > 0) {
        /* A byte every 50 ms for up to 20 s, until the client hangs up. */
        for (int i = 0; i < 400; i++) {
            if (send(fd, "{", 1, MSG_NOSIGNAL) != 1) break;
            usleep(50000);
        }
    }
    close(fd);
    return NULL;
}

static long long ms_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* The read deadline is the whole answer's, not each read's: a peer that
 * keeps a trickle going is cut off at read_ms, not held for as long as
 * it likes. Seen red with http_get() renewing the deadline after each
 * read (the pull then ran the trickle's whole 20 s and failed for
 * another reason). */
static void test_pull_trickle_is_cut_off(void) {
    pull_up();
    trickle_t t;
    t.lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    WT_EQ(bind(t.lfd, (struct sockaddr *)&sa, sizeof(sa)), 0);
    WT_EQ(listen(t.lfd, 1), 0);
    socklen_t sl = sizeof(sa);
    getsockname(t.lfd, (struct sockaddr *)&sa, &sl);
    F.peer[0].cfg.port = ntohs(sa.sin_port);
    F.read_ms = 600;
    pthread_t th;
    pthread_create(&th, NULL, serve_trickle, &t);
    long long t0 = ms_now();
    WT_EQ(web_fleet_pull_one(&F, 0, T), -1);
    long long ms = ms_now() - t0;
    pthread_join(th, NULL);
    close(t.lfd);
    if (!strstr(F.peer[0].last_error, "timed out"))
        fprintf(stderr, "    trickle: \"%s\" after %lld ms\n", F.peer[0].last_error, ms);
    WT_HAS(F.peer[0].last_error, "read: timed out");
    WT_ASSERT(ms < 600 + 2000LL * web_sdb_test_budget_scale);
    WT_EQ(sightings(), 0);
    pull_down();
}

/* No peer reachable: a refused connection is an error in words, and the
 * thread's start and stop are clean with a peer configured (the pull
 * runs at once and fails, the stop is prompt). */
static void test_pull_unreachable_and_thread(void) {
    pull_up();
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(s, (struct sockaddr *)&sa, sizeof(sa));
    socklen_t sl = sizeof(sa);
    getsockname(s, (struct sockaddr *)&sa, &sl);
    close(s);                         /* nothing listens there now */
    F.peer[0].cfg.port = ntohs(sa.sin_port);
    WT_EQ(web_fleet_pull_one(&F, 0, T), -1);
    WT_HAS(F.peer[0].last_error, "connect: ");
    WT_EQ(sightings(), 0);
    web_fleet_destroy(&F);
    web_fleet_peer_cfg_t pc = F.peer[0].cfg;
    web_fleet_init(&F, &pc, 1, 3600, 1, &S);
    char err[256];
    WT_EQ(web_fleet_start(&F, err, sizeof(err)), 0);
    WT_EQ(F.started, 1);
    unsigned long pulls = 0;
    for (int i = 0; i < 500 && !pulls; i++) {
        pthread_mutex_lock(&F.mu);
        pulls = F.peer[0].pulls;
        pthread_mutex_unlock(&F.mu);
        if (!pulls) usleep(10000);
    }
    WT_ASSERT(pulls >= 1);
    web_fleet_stop(&F);
    WT_EQ(F.started, 0);
    pull_down();
}


/* ── F2: the backfill, against the real export ─────────────────────── */

/* A peer: a loopback server answering every request with
 * web_fleet_export_route() over the peer's own files (SDB, FR), until
 * stopped; each request's target kept. */
typedef struct {
    int       lfd, stop, n;
    int       f1;                     /* answer as an F1 export: a 400 for any '&' */
    int       f2;                     /* answer as an F2 export: a 400 for own= */
    int       i5;                     /* answer as an I5 export: a 400 for gnss= */
    int       i6;                     /* answer as an I6 export: a 400 for adsb= */
    int       i7;                     /* answer as an I7 export: a 400 for ident= */
    long long now;                    /* the export's clock (0: T), under mu */
    unsigned  delay_ms;               /* each answer held this long first */
    pthread_mutex_t mu;               /* guards stop, now */
    char      req[24][256];
    web_fleet_src_t src;
} peer_srv_t;

static int srv_stopped(peer_srv_t *s) {
    pthread_mutex_lock(&s->mu);
    int v = s->stop;
    pthread_mutex_unlock(&s->mu);
    return v;
}

static void *serve_export(void *arg) {
    peer_srv_t *s = arg;
    for (;;) {
        struct pollfd pf = { s->lfd, POLLIN, 0 };
        int r = poll(&pf, 1, 50);
        if (srv_stopped(s)) break;
        if (r <= 0) continue;
        int fd = accept(s->lfd, NULL, NULL);
        if (fd < 0) continue;
        char rq[1024];
        size_t n = 0;
        while (n + 1 < sizeof(rq)) {
            ssize_t k = recv(fd, rq + n, sizeof(rq) - 1 - n, 0);
            if (k <= 0) break;
            n += (size_t)k;
            rq[n] = '\0';
            if (strstr(rq, "\r\n\r\n")) break;
        }
        rq[n] = '\0';
        const char *q = strstr(rq, "/api/fleet/export?");
        const char *sp = q ? strchr(q, ' ') : NULL;
        char query[256] = "";
        if (q && sp && (size_t)(sp - q - 18) < sizeof(query)) {
            memcpy(query, q + 18, (size_t)(sp - q - 18));
            query[sp - q - 18] = '\0';
        }
        if (s->n < 24) snprintf(s->req[s->n++], sizeof(s->req[0]), "%s", query);
        char *body = NULL;
        size_t bl = 0;
        int st = 0;
        if ((s->f1 && strchr(query, '&')) || (s->f2 && strstr(query, "own=")) ||
            (s->i5 && strstr(query, "gnss=")) || (s->i6 && strstr(query, "adsb=")) ||
            (s->i7 && strstr(query, "ident="))) {
            /* F1's parse_since(): since= alone, else unknown_parameter. */
            body = malloc(64);
            if (body) bl = (size_t)snprintf(body, 64, "{\"error\":\"unknown_parameter\"}");
            st = 400;
        } else {
            pthread_mutex_lock(&s->mu);
            long long now = s->now ? s->now : T;
            unsigned dl = s->delay_ms;
            pthread_mutex_unlock(&s->mu);
            if (dl) {
                struct timespec ds = { (time_t)(dl / 1000), (long)(dl % 1000) * 1000000L };
                nanosleep(&ds, NULL);
            }
            web_fleet_export_route(&s->src, query, now, &body, &bl, &st);
        }
        char hdr[160];
        int hl = snprintf(hdr, sizeof(hdr), "HTTP/1.1 %d X\r\nContent-Length: %zu\r\n"
                          "Connection: close\r\n\r\n", st, bl);
        send(fd, hdr, (size_t)hl, MSG_NOSIGNAL);
        for (size_t o = 0; body && o < bl;) {
            ssize_t k = send(fd, body + o, bl - o, MSG_NOSIGNAL);
            if (k <= 0) break;
            o += (size_t)k;
        }
        free(body);
        close(fd);
    }
    return NULL;
}

static web_store_t S2;
static char g_here_db[TEST_TMP_MAX + 32], g_here_web[TEST_TMP_MAX + 32];

/* The peer is up()'s files; this site's store is here-web.db, F pulling
 * the peer at a loopback port. */
static void here_up(peer_srv_t *srv, pthread_t *th) {
    up();
    snprintf(g_here_web, sizeof(g_here_web), "%s/here-web.db", g_dir);
    snprintf(g_here_db, sizeof(g_here_db), "%s/here.db", g_dir);
    char err[512];
    WT_EQ(web_store_open(&S2, g_here_web, err, sizeof(err)), 0);
    web_fleet_peer_cfg_t pc;
    WT_EQ(web_fleet_parse_peer("beta=http://127.0.0.1:1", &pc, err, sizeof(err)), 0);
    web_fleet_init(&F, &pc, 1, 60, 1, &S2);
    F.connect_ms = 2000;
    F.read_ms = 10000;
    WT_EQ(web_store_open_aux(&S2, &F.wr, err, sizeof(err)), 0);
    memset(srv, 0, sizeof(*srv));
    pthread_mutex_init(&srv->mu, NULL);
    srv->src.sdb = &SDB;
    srv->src.frrs = &FR;
    srv->lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    WT_EQ(bind(srv->lfd, (struct sockaddr *)&sa, sizeof(sa)), 0);
    WT_EQ(listen(srv->lfd, 8), 0);
    socklen_t sl = sizeof(sa);
    getsockname(srv->lfd, (struct sockaddr *)&sa, &sl);
    F.peer[0].cfg.port = ntohs(sa.sin_port);
    pthread_create(th, NULL, serve_export, srv);
}

static void here_down(peer_srv_t *srv, pthread_t th) {
    pthread_mutex_lock(&srv->mu);
    srv->stop = 1;
    pthread_mutex_unlock(&srv->mu);
    pthread_join(th, NULL);
    pthread_mutex_destroy(&srv->mu);
    close(srv->lfd);
    web_fleet_destroy(&F);
    web_store_close(&S2);
    down();
}

static long long here_q(const char *sql) { return q1(g_here_web, sql); }

/* More of each pageable kind than one answer carries, most of them in
 * ties on last_seen across the cut, all of them older than the next
 * pull's window: the first pull takes the newest of each and one page
 * after it (pages_per_pull 1), a restart reads the backfill back from
 * meta, and the next pull's page finishes it. Every row arrives once,
 * the incremental pull never asks for them again, and the meta row is
 * gone when the kind is whole. Seen red with the page request's
 * &after= dropped (every page answered the top again: wifi stayed at
 * 2,000 of 4,509, ap, alert and verdict at 1,000, every backfill still
 * running), with the device reader's tie term (d.last_seen = ?5 AND
 * d.mac > ?6) removed (the rows of the cut's tie group after the cursor
 * never came: 4,004 of 4,509), and with bf_meta_write() not called (the
 * restart forgot the backfill: 4,000). */
static void test_backfill_after_a_cut(void) {
    peer_srv_t srv;
    pthread_t th;
    here_up(&srv, &th);
    char sql[4096];
    snprintf(sql, sizeof(sql),
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<4499)"
        " INSERT INTO devices (mac,vendor,is_ap,signal_dbm,first_seen,last_seen)"
        " SELECT printf('02:aa:00:00:%%02x:%%02x', i/256, i%%256),'Bulk',0,-60,%lld,"
        " %lld-(i%%4) FROM n;"
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<1299)"
        " INSERT INTO beacon_aps (bssid,ssid,channel,signal_dbm,first_seen,last_seen)"
        " SELECT printf('0a:bb:00:00:%%02x:%%02x', i/256, i%%256),'bulk-net',6,-70,%lld,"
        " %lld-(i%%3) FROM n;"
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<1099)"
        " INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,technique,count)"
        " SELECT 'bulk:'||i,%lld,%lld-(i%%5),3,1,'bulk alert '||i,'T1557',1 FROM n;",
        T - 5000, T - 1000, T - 5000, T - 2000, T - 4000, T - 3000);
    WT_EQ(sdb_exec(g_db, sql), 0);
    snprintf(sql, sizeof(sql),
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<1099)"
        " INSERT INTO triage (subject,finding,type,addr,port,first_seen,state,ts,note,who,peer)"
        " SELECT 'b'||i,NULL,12,printf('10.9.%%d.%%d', i/256, i%%256),0,%lld,4,%lld-(i%%5),"
        "'','','127.0.0.1' FROM n;", T - 4000, T - 3000);
    WT_EQ(sql_on(g_store, sql), 0);
    long long want_wifi = q1(g_db, "SELECT COUNT(*) FROM devices");
    long long want_ap = q1(g_db, "SELECT COUNT(*) FROM beacon_aps");
    long long want_alert = q1(g_db, "SELECT COUNT(DISTINCT type||'|'||title) FROM alerts");
    long long want_verdict = q1(g_store, "SELECT COUNT(DISTINCT subject) FROM triage");
    WT_ASSERT(want_wifi > 2 * WEB_FLEET_CAP_WIFI && want_ap > WEB_FLEET_CAP_AP &&
              want_alert > WEB_FLEET_CAP_ALERT && want_verdict > WEB_FLEET_CAP_VERDICT);

    F.pages_per_pull = 1;
    int rc = web_fleet_pull_one(&F, 0, T);
    if (rc) fprintf(stderr, "    pull 1: %s\n", F.peer[0].last_error);
    WT_EQ(rc, 0);
    WT_EQ(F.peer[0].page_failures, 0);
    if (F.peer[0].last_error[0]) fprintf(stderr, "    pull 1: %s\n", F.peer[0].last_error);
    /* The whole export, then one page of each cut kind from its floor. */
    WT_ASSERT(srv.n == 5);
    WT_ASSERT(!strcmp(srv.req[0], "since=0&next=1&own=1&gnss=1&adsb=1&ident=1"));
    WT_ASSERT(!strncmp(srv.req[1], "since=0&kind=wifi&after=", 24));
    WT_ASSERT(!strncmp(srv.req[2], "since=0&kind=ap&after=", 22));
    WT_ASSERT(!strncmp(srv.req[3], "since=0&kind=alert&after=", 25));
    WT_ASSERT(!strncmp(srv.req[4], "since=0&kind=verdict&after=", 27));
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi'"), 2 * WEB_FLEET_CAP_WIFI);
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='ap'"), want_ap);
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='alert'"), want_alert);
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='verdict'"), want_verdict);
    /* Only wifi is still running, and its state is in meta. */
    WT_EQ(F.peer[0].bf[WEB_FK_WIFI].active, 1);
    WT_EQ(F.peer[0].bf[WEB_FK_WIFI].floor, 0);
    WT_EQ(F.peer[0].bf[WEB_FK_AP].active + F.peer[0].bf[WEB_FK_ALERT].active +
          F.peer[0].bf[WEB_FK_VERDICT].active, 0);
    WT_EQ(here_q("SELECT COUNT(*) FROM meta WHERE name LIKE 'fleet.backfill.%'"), 1);
    WT_EQ(here_q("SELECT COUNT(*) FROM meta WHERE name='fleet.backfill.beta.wifi'"
                 " AND value LIKE '0 %~02:aa:00:00:%'"), 1);
    /* The rows of the overview's backfill state. */
    web_m4_t m4;
    memset(&m4, 0, sizeof(m4));
    m4.fleet = &F;
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.wall_s = T;
    h.m4 = &m4;
    static char out[65536];
    web_req_t rq;
    web_resp_t r;
    memset(&rq, 0, sizeof(rq));
    snprintf(rq.path, sizeof(rq.path), "/api/fleet/overview");
    snprintf(rq.host, sizeof(rq.host), "127.0.0.1:8770");
    rq.host_count = 1;
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    out[r.out_len] = '\0';
    WT_EQ(r.status, 200);
    WT_HAS(out, ",\"backfill\":{\"wifi\":{\"floor\":0,\"cursor\":\"");
    WT_HAS(out, ",\"pages\":4,\"page_failures\":0,");

    /* A restart: the pull state from peer_sites, the backfill from meta. */
    web_fleet_peer_cfg_t pc = F.peer[0].cfg;
    web_fleet_destroy(&F);
    web_fleet_init(&F, &pc, 1, 60, 1, &S2);
    F.connect_ms = 2000;
    F.read_ms = 10000;
    F.pages_per_pull = 1;
    char err[256];
    WT_EQ(web_store_open_aux(&S2, &F.wr, err, sizeof(err)), 0);
    web_fleet_load(&F);
    WT_EQ(F.peer[0].remote_ts, T);
    WT_EQ(F.peer[0].bf[WEB_FK_WIFI].active, 1);
    rc = web_fleet_pull_one(&F, 0, T + 5);
    WT_EQ(rc, 0);
    WT_ASSERT(srv.n == 7);
    /* The incremental pull asks only for what is new; the page goes on
     * from the cursor. */
    char want[64];
    snprintf(want, sizeof(want), "since=%lld&next=1&own=1&gnss=1&adsb=1&ident=1",
             T - WEB_FLEET_OVERLAP_S);
    WT_ASSERT(!strcmp(srv.req[5], want));
    WT_ASSERT(!strncmp(srv.req[6], "since=0&kind=wifi&after=", 24));
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi'"), want_wifi);
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi' AND"
                 " key LIKE '02:aa:%'"), 4500);
    WT_EQ(F.peer[0].bf[WEB_FK_WIFI].active, 0);
    WT_EQ(here_q("SELECT COUNT(*) FROM meta WHERE name LIKE 'fleet.backfill.%'"), 0);
    /* A third pull: nothing cut, so no page. */
    WT_EQ(web_fleet_pull_one(&F, 0, T + 65), 0);
    WT_ASSERT(srv.n == 8);
    here_down(&srv, th);
}

static void srv_set(peer_srv_t *s, long long now, unsigned delay_ms) {
    pthread_mutex_lock(&s->mu);
    s->now = now;
    s->delay_ms = delay_ms;
    pthread_mutex_unlock(&s->mu);
}

/* A peer cut at every pull (#196): 10,000 devices older than any later
 * window, then, before each later pull, 2,100 new ones inside that
 * pull's window only, so every incremental answer is cut at its 2,000
 * and leaves a gap of 100. Two pages a pull: the gap's page and one more.
 * The backfill pages the new gap first and then resumes the older
 * segment from its own cursor, so the old rows arrive at a page a pull
 * (all but up()'s few newer devices' share of the first answer after the
 * third pull) with every new row, and the fourth leaves nothing running. Seen red with bf_next() restarting the paged
 * segment from the new cut at the older floor (the old rule: every pull's
 * two pages re-read the 100 new rows and the newest 3,900 already held,
 * and the old devices stayed at 6,000 of 10,000). */
static void test_backfill_cut_every_pull(void) {
    peer_srv_t srv;
    pthread_t th;
    here_up(&srv, &th);
    char sql[1024];
    snprintf(sql, sizeof(sql),
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<9999)"
        " INSERT INTO devices (mac,vendor,is_ap,signal_dbm,first_seen,last_seen)"
        " SELECT printf('02:aa:00:00:%%02x:%%02x', i/256, i%%256),'Bulk',0,-60,%lld,"
        " %lld-(i%%7) FROM n;", T - 9000, T - 5000);
    WT_EQ(sdb_exec(g_db, sql), 0);
    /* up()'s own devices that the first answer carried, newer than these. */
    long long fx = 0;
    F.pages_per_pull = 2;
    for (int k = 0; k < 4; k++) {
        long long now = T + 600LL * k;
        if (k > 0) {
            snprintf(sql, sizeof(sql),
                "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<2099)"
                " INSERT INTO devices (mac,vendor,is_ap,signal_dbm,first_seen,last_seen)"
                " SELECT printf('02:b%d:00:00:%%02x:%%02x', i/256, i%%256),'New',0,-60,%lld,"
                " %lld-(i%%3) FROM n;", k, now - 300, now - 200);
            WT_EQ(sdb_exec(g_db, sql), 0);
        }
        srv_set(&srv, now, 0);
        int rc = web_fleet_pull_one(&F, 0, now);
        if (rc) fprintf(stderr, "    pull %d: %s\n", k, F.peer[0].last_error);
        WT_EQ(rc, 0);
        if (k == 0) {
            fx = here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi' AND"
                        " key NOT LIKE '02:aa:%'");
            WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi' AND"
                         " key LIKE '02:aa:%'"), 6000 - fx);
        }
        if (k == 1) {
            /* The new gap was paged first and ended; the older segment
             * resumed from its own cursor, not from the new cut. */
            WT_EQ(F.peer[0].bf[WEB_FK_WIFI].active, 1);
            WT_EQ(F.peer[0].bf[WEB_FK_WIFI].nold, 0);
            WT_EQ(F.peer[0].bf[WEB_FK_WIFI].floor, 0);
            WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi' AND"
                         " key LIKE '02:aa:%'"), 8000 - fx);
        }
        if (k == 2) {
            WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi' AND"
                         " key LIKE '02:aa:%'"), 10000 - fx);
            WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi' AND"
                         " key LIKE '02:b%'"), 2 * 2100);
        }
    }
    WT_EQ(F.peer[0].page_failures, 0);
    WT_EQ(F.peer[0].bf[WEB_FK_WIFI].active, 0);
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi'"),
          q1(g_db, "SELECT COUNT(*) FROM devices"));
    WT_EQ(here_q("SELECT COUNT(*) FROM meta WHERE name LIKE 'fleet.backfill.%'"), 0);
    here_down(&srv, th);
}

/* Past WEB_FLEET_BF_SEGS suspended segments (#196): a peer cut at six
 * pulls running with no page fetched between them (pages_per_pull 0)
 * holds the paged segment and four suspended, and the sixth cut is
 * merged into the paged one (the older floor, the new cursor). The five
 * segments survive a restart through meta (five pairs read back), and
 * once pages are fetched again every row arrives and nothing stays
 * running. Seen red with the merge taking the new gap's floor alone
 * (the fifth pull's 100-row gap was never fetched). */
static void test_backfill_merge_past_bound(void) {
    peer_srv_t srv;
    pthread_t th;
    here_up(&srv, &th);
    char sql[1024];
    snprintf(sql, sizeof(sql),
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<2999)"
        " INSERT INTO devices (mac,vendor,is_ap,signal_dbm,first_seen,last_seen)"
        " SELECT printf('02:aa:00:00:%%02x:%%02x', i/256, i%%256),'Bulk',0,-60,%lld,"
        " %lld-(i%%7) FROM n;", T - 9000, T - 5000);
    WT_EQ(sdb_exec(g_db, sql), 0);
    F.pages_per_pull = 0;
    web_fleet_bf_t *b = &F.peer[0].bf[WEB_FK_WIFI];
    for (int k = 0; k < 7; k++) {
        long long now = T + 600LL * k;
        if (k > 0 && k < 6) {
            snprintf(sql, sizeof(sql),
                "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<2099)"
                " INSERT INTO devices (mac,vendor,is_ap,signal_dbm,first_seen,last_seen)"
                " SELECT printf('02:b%d:00:00:%%02x:%%02x', i/256, i%%256),'New',0,-60,%lld,"
                " %lld-(i%%3) FROM n;", k, now - 300, now - 200);
            WT_EQ(sdb_exec(g_db, sql), 0);
        }
        if (k == 6) F.pages_per_pull = 64;
        srv_set(&srv, now, 0);
        int rc = web_fleet_pull_one(&F, 0, now);
        if (rc) fprintf(stderr, "    pull %d: %s\n", k, F.peer[0].last_error);
        WT_EQ(rc, 0);
        if (k < 5) WT_EQ(b->nold, k);
        if (k == 5) {
            WT_EQ(b->active, 1);
            WT_EQ(b->nold, WEB_FLEET_BF_SEGS);
            WT_EQ(b->floor, T + 600LL * 3 - WEB_FLEET_OVERLAP_S);
            memset(F.peer[0].bf, 0, sizeof(F.peer[0].bf));
            web_fleet_load(&F);
            WT_EQ(b->active, 1);
            WT_EQ(b->nold, WEB_FLEET_BF_SEGS);
            WT_EQ(b->old[0].floor, 0);
        }
    }
    WT_EQ(F.peer[0].page_failures, 0);
    WT_EQ(b->active, 0);
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi'"),
          q1(g_db, "SELECT COUNT(*) FROM devices"));
    WT_EQ(here_q("SELECT COUNT(*) FROM meta WHERE name LIKE 'fleet.backfill.%'"), 0);
    here_down(&srv, th);
}

/* The backfill's suspended segments survive a restart through meta, in
 * order, and a value an earlier build wrote (one pair) still reads; a
 * value with more pairs than kept, or a bad cursor anywhere, is not
 * taken. Seen red with bf_meta_write() writing the paged segment only
 * (the restart forgot the suspended one). */
static void test_backfill_segments_meta(void) {
    pull_up();
    F.pages_per_pull = 0;
    web_fleet_bf_t *b = &F.peer[0].bf[WEB_FK_WIFI];
    b->active = 1;
    b->floor = 500;
    snprintf(b->cur, sizeof(b->cur), "900~02:aa:00:00:00:01");
    b->nold = 2;
    b->old[0].floor = 0;
    snprintf(b->old[0].cur, sizeof(b->old[0].cur), "100~02:aa:00:00:00:09");
    b->old[1].floor = 200;
    snprintf(b->old[1].cur, sizeof(b->old[1].cur), "300~02:aa:00:00:00:05");
    /* A whole answer with nothing cut writes the state as it stands. */
    char req[512];
    WT_EQ(pull_with(GOOD, 0, req, sizeof(req)), 0);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM meta WHERE name='fleet.backfill.beta.wifi' AND"
             " value='500 900~02:aa:00:00:00:01 200 300~02:aa:00:00:00:05"
             " 0 100~02:aa:00:00:00:09'"), 1);
    memset(F.peer[0].bf, 0, sizeof(F.peer[0].bf));
    web_fleet_load(&F);
    WT_EQ(b->active, 1);
    WT_EQ(b->floor, 500);
    WT_EQ(b->nold, 2);
    WT_EQ(b->old[0].floor, 0);
    WT_ASSERT(!strcmp(b->old[0].cur, "100~02:aa:00:00:00:09"));
    WT_EQ(b->old[1].floor, 200);
    WT_ASSERT(!strcmp(b->old[1].cur, "300~02:aa:00:00:00:05"));
    /* An earlier build's one pair. */
    WT_EQ(sql_on(g_store, "UPDATE meta SET value='7 9~ab' WHERE name='fleet.backfill.beta.wifi'"), 0);
    web_fleet_load(&F);
    WT_EQ(b->active, 1);
    WT_EQ(b->floor, 7);
    WT_EQ(b->nold, 0);
    static const char *const BAD[] = {
        "1 2~a 1 2~a 1 2~a 1 2~a 1 2~a 1 2~a", "1 2~a 3", "1 2~a 3 x~a", "1 2~a ", "1  2~a",
    };
    for (size_t j = 0; j < sizeof(BAD) / sizeof(BAD[0]); j++) {
        char q[160];
        snprintf(q, sizeof(q), "UPDATE meta SET value='%s' WHERE name='fleet.backfill.beta.wifi'",
                 BAD[j]);
        WT_EQ(sql_on(g_store, q), 0);
        web_fleet_load(&F);
        WT_EQ(b->active, 0);
    }
    pull_down();
}

/* An alert key's incidents by the thousand fill the reader's
 * WEB_SDB_ALERT_SCAN window long before the cap, as they do on W9FJC
 * (364,191 incidents, the newest 20,000 of them 955 keys of 17,988):
 * three hot keys with 7,000 incidents each, newer than 1,500 keys with
 * one. The whole export sends the three uncut-looking keys, says the
 * kind was cut at the scan's oldest row, and the pages from there bring
 * every other key. Seen red with the scan-cap check removed from the
 * export (6 of 1,506 keys arrived, no page asked for) and with
 * web_sdb_alerts_upto()'s ceiling not applied (the page read the same
 * newest 20,000 rows, found nothing past its cursor and ended the
 * backfill: 6 of 1,506, no cold key). */
static void test_backfill_alerts_past_the_scan(void) {
    peer_srv_t srv;
    pthread_t th;
    here_up(&srv, &th);
    char sql[4096];
    snprintf(sql, sizeof(sql),
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<2)"
        " INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,technique,count)"
        " SELECT 'hot:'||i,%lld,%lld,3,1,'hot alert '||i,'T1557',7000 FROM n;"
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<20999)"
        " INSERT INTO alert_incidents (key,incident_id,type,first_seen,last_seen,sev,"
        "peak_sev,count,observations) SELECT 'hot:'||(i%%3),printf('%%016x',i),3,"
        "%lld-(i/3)-10,%lld-(i/3),1,1,1,1 FROM n;"
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<1499)"
        " INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,technique,count)"
        " SELECT 'cold:'||i,%lld-i-10,%lld-i,3,1,'cold alert '||i,'T1557',1 FROM n;"
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<1499)"
        " INSERT INTO alert_incidents (key,incident_id,type,first_seen,last_seen,sev,"
        "peak_sev,count,observations) SELECT 'cold:'||i,'0000000000000001',3,%lld-i-10,"
        "%lld-i,1,1,1,1 FROM n;",
        T - 8100, T - 1000, T - 1000, T - 1000, T - 9000, T - 9000, T - 9000, T - 9000);
    WT_EQ(sdb_exec(g_db, sql), 0);
    long long want = q1(g_db, "SELECT COUNT(DISTINCT type||'|'||title) FROM alerts");
    WT_ASSERT(want > 1500);
    F.pages_per_pull = 4;
    /* The peer is an F2 build (#192 I5 review): own=1 refused, asked
     * again with next=1, and the backfill runs from that answer's
     * cursor as from any other. Seen red with the own=1 retry made to
     * drop next=1 as well (no page asked for). */
    srv.f2 = 1;
    WT_EQ(web_fleet_pull_one(&F, 0, T), 0);
    /* The first answer was cut by the scan, not the cap: fewer keys than
     * the cap, and a backfill. */
    WT_ASSERT(srv.n >= 6);
    WT_ASSERT(!strcmp(srv.req[0], "since=0&next=1&own=1&gnss=1&adsb=1&ident=1"));
    WT_ASSERT(!strcmp(srv.req[1], "since=0&next=1&own=1&gnss=1&adsb=1"));
    WT_ASSERT(!strcmp(srv.req[2], "since=0&next=1&own=1&gnss=1"));
    WT_ASSERT(!strcmp(srv.req[3], "since=0&next=1&own=1"));
    WT_ASSERT(!strcmp(srv.req[4], "since=0&next=1"));
    WT_ASSERT(!strncmp(srv.req[5], "since=0&kind=alert&after=", 25));
    for (int i = 0; i < 6 && F.peer[0].bf[WEB_FK_ALERT].active; i++)
        WT_EQ(web_fleet_pull_one(&F, 0, T + 60 * (i + 1)), 0);
    WT_EQ(F.peer[0].bf[WEB_FK_ALERT].active, 0);
    WT_EQ(F.peer[0].page_failures, 0);
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='alert'"), want);
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='alert' AND"
                 " label LIKE 'cold alert %'"), 1500);
    /* A hot key given again from a page keeps its newest last_seen. */
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='alert' AND"
                 " label LIKE 'hot alert %' AND last_seen = (SELECT MAX(last_seen) FROM"
                 " peer_sightings WHERE kind='alert' AND label LIKE 'hot alert %')"), 3);
    here_down(&srv, th);
}

/* A fleet upgraded a host at a time: this F2 puller against an F1 peer,
 * whose export refuses next=1 as an unknown parameter. The pull asks
 * again without it and is stored; nothing is paged from that peer; the
 * next pull within WEB_FLEET_NONEXT_S asks plainly at once; the overview
 * says so. Seen red with the retry removed (the pull failed with HTTP
 * status 400 and no row was stored). */
static void test_pull_from_an_f1_peer(void) {
    peer_srv_t srv;
    pthread_t th;
    here_up(&srv, &th);
    srv.f1 = 1;
    int rc = web_fleet_pull_one(&F, 0, T);
    if (rc) fprintf(stderr, "    pull: %s\n", F.peer[0].last_error);
    WT_EQ(rc, 0);
    /* ident=1 refused, adsb=1 refused, gnss=1 refused, own=1 refused,
     * then next=1 refused, then plain (#192 I5 put own=1 in front, I6
     * gnss=1, I7 adsb=1, I4 ident=1). */
    WT_ASSERT(srv.n == 6);
    WT_ASSERT(!strcmp(srv.req[0], "since=0&next=1&own=1&gnss=1&adsb=1&ident=1"));
    WT_ASSERT(!strcmp(srv.req[1], "since=0&next=1&own=1&gnss=1&adsb=1"));
    WT_ASSERT(!strcmp(srv.req[2], "since=0&next=1&own=1&gnss=1"));
    WT_ASSERT(!strcmp(srv.req[3], "since=0&next=1&own=1"));
    WT_ASSERT(!strcmp(srv.req[4], "since=0&next=1"));
    WT_ASSERT(!strcmp(srv.req[5], "since=0"));
    WT_ASSERT(here_q("SELECT COUNT(*) FROM peer_sightings WHERE peer='beta'") > 0);
    WT_EQ(F.peer[0].failures, 0);
    WT_EQ(F.peer[0].last_error[0], '\0');
    WT_ASSERT(F.peer[0].no_next_until > T);
    /* Within the hour: plain at once, one request. */
    WT_EQ(web_fleet_pull_one(&F, 0, T + 60), 0);
    WT_ASSERT(srv.n == 7);
    char want[64];
    snprintf(want, sizeof(want), "since=%lld", T - WEB_FLEET_OVERLAP_S);
    WT_ASSERT(!strcmp(srv.req[6], want));
    web_m4_t m4;
    memset(&m4, 0, sizeof(m4));
    m4.fleet = &F;
    web_fleet_src_t src = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
    static char body[65536];
    size_t len = 0;
    int st = 0;
    WT_EQ(web_fleet_overview_route(&F, &src, "", T + 60, body, sizeof(body) - 1, &len, &st), 0);
    body[len] = '\0';
    WT_EQ(st, 200);
    WT_HAS(body, ",\"pages_refused\":true,");
    /* After it: asked with next=1 again (the peer may have been
     * upgraded meanwhile). */
    srv.f1 = 0;
    WT_EQ(web_fleet_pull_one(&F, 0, T + 60 + WEB_FLEET_NONEXT_S), 0);
    WT_ASSERT(srv.n == 8);
    WT_ASSERT(strstr(srv.req[7], "&next=1&own=1&gnss=1&adsb=1&ident=1") != NULL);
    here_down(&srv, th);
}

/* The export's paging, request by request: the parameters; an F1 pull
 * (no next=1) answered without a member an F1 importer would refuse; a
 * page of wifi after a cursor holding only that kind. Seen red with the
 * next_<kind> members written whatever the request (next_ in the plain
 * answer) and with the device reader's keyset made always true (the
 * cursor's own row and a newer one in the page). */
static void test_export_pages(void) {
    up();
    int st = 0;
    char *b = export(0, "since=0", &st);
    WT_EQ(st, 200);
    if (b) WT_LACKS(b, "next_");
    free(b);
    b = export(0, "since=0&next=1", &st);
    WT_EQ(st, 200);
    if (b) WT_LACKS(b, "own_macs");     /* only for own=1: an F2 importer refuses it */
    if (b) WT_HAS(b, ",\"next_wifi\":null,\"next_ap\":null,\"next_alert\":null,"
                     "\"next_verdict\":null,\"complete\":true}");
    free(b);
    /* A page: only its kind (and a client's probes), from the cursor. */
    b = export(0, "since=0&kind=wifi&after=1792623600~da:a1:19:00:00:01", &st);
    WT_EQ(st, 200);
    if (b) {
        WT_LACKS(b, "\"mac\":\"da:a1:19:00:00:01\"");   /* the cursor's own row */
        WT_LACKS(b, "\"mac\":\"00:11:22:33:44:55\"");   /* newer than it */
        WT_HAS(b, "\"mac\":\"da:a1:19:00:00:02\"");     /* older */
        WT_LACKS(b, "{\"type\":\"alert\"");
        WT_LACKS(b, "{\"type\":\"verdict\"");
        WT_LACKS(b, "{\"type\":\"gnss\"");
        WT_HAS(b, "\"next_wifi\":null");
    }
    free(b);
    /* own=1 (#192 I5): the header names this site's radios, or says
     * none. */
    g_own_csv = "02:00:5e:00:00:0a,02:00:5e:00:00:0b";
    b = export(0, "since=0&next=1&own=1", &st);
    WT_EQ(st, 200);
    if (b) WT_HAS(b, ",\"pos_age_s\":null,\"own_macs\":\"02:00:5e:00:00:0a,02:00:5e:00:00:0b\"}\n");
    free(b);
    g_own_csv = NULL;
    b = export(0, "since=0&own=1", &st);
    WT_EQ(st, 200);
    if (b) WT_HAS(b, ",\"own_macs\":null}\n");
    free(b);
    static const struct { const char *q, *why; } bad[] = {
        { "since=0&own=2", "bad_own" }, { "since=0&own=1&own=1", "unknown_parameter" },
        { "since=0&kind=probe", "bad_kind" }, { "since=0&kind=ble", "bad_kind" },
        { "since=0&after=1~x", "after_needs_kind" }, { "kind=wifi&after=x~1", "bad_after" },
        { "kind=wifi&after=1~a-b", "bad_after" }, { "kind=wifi&after=1", "bad_after" },
        { "since=0&next=2", "bad_next" }, { "since=0&since=1", "unknown_parameter" },
        { "since=0&limit=1", "unknown_parameter" }, { "since", "unknown_parameter" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        b = export(0, bad[i].q, &st);
        if (st != 400) fprintf(stderr, "    taken: %s\n", bad[i].q);
        WT_EQ(st, 400);
        if (b) WT_HAS(b, bad[i].why);
        free(b);
    }
    WT_EQ(web_fleet_cursor_ok("1792623600~da:a1:19:00:00:01"), 1);
    WT_EQ(web_fleet_cursor_ok("4102444800~"), 1);
    WT_EQ(web_fleet_cursor_ok("~x"), 0);
    WT_EQ(web_fleet_cursor_ok("1234567890123~x"), 0);
    WT_EQ(web_fleet_cursor_ok("1~0123456789012345678901234"), 0);
    down();
}

/* The overview and the shared list over a pulled peer and this site's
 * own sloth.db (here.db): the keys both hold, each site's times and
 * signal, this site's verdict; nothing only the peer holds. Seen red
 * with the shared walk taking a key the local read did not find (the
 * peer's da:a1:19:00:00:02 and 00:11:22:33:44:55 listed, the HomeNet
 * probe too) and with the overview's skew written as last_ok -
 * remote_ts. A key only this site holds (02:10:ca:10:ca:01, OnlyHere)
 * cannot be listed by construction (the walk starts from the peer's
 * rows), so its absence is a statement of that, not a guard seen red.
 * The verdicts: the peer's "incident" at a device this site has not
 * triaged, never the peer's "noise" where this site said "known" (seen
 * red with this site's triage pass skipped: "noise" from beta shown). */
static void test_overview_and_shared(void) {
    peer_srv_t srv;
    pthread_t th;
    here_up(&srv, &th);
    char sql[2048];
    /* The peer's verdicts at two of the devices: one this site has
     * triaged too (its own wins), one it has not (the peer's shown). */
    snprintf(sql, sizeof(sql),
        "INSERT INTO triage (subject,finding,type,addr,port,first_seen,state,ts,note,who,"
        "peer) VALUES ('p3a',NULL,3,'da:a1:19:00:00:01',0,%lld,2,%lld,'','',''),"
        " ('p3b',NULL,3,'da:a1:19:00:00:04',0,%lld,3,%lld,'','','');",
        T - 600, T - 590, T - 600, T - 580);
    WT_EQ(sql_on(g_store, sql), 0);
    WT_EQ(web_fleet_pull_one(&F, 0, T + 5), 0);
    WT_EQ(sdb_make(g_here_db, db_schema_version(), 0), 0);
    snprintf(sql, sizeof(sql),
        "INSERT INTO devices (mac,vendor,is_ap,signal_dbm,first_seen,last_seen) VALUES"
        " ('da:a1:19:00:00:01','Apple',0,-41,%lld,%lld),"
        " ('da:a1:19:00:00:04','Samsung',0,0,%lld,%lld),"
        " ('02:10:ca:10:ca:01','Here',0,-50,%lld,%lld);"
        /* :04's device row came from ARP (sloth's 0: never heard on the
         * air); the monitor heard it probe (#192 I5). */
        "INSERT INTO probe_clients (mac,ssid,signal_dbm,channel,first_seen,last_seen)"
        " VALUES ('da:a1:19:00:00:04','',-52,6,1792626000,1792626100);"
        "INSERT INTO pnl_clients (mac,mac_random,probe_count,first_seen,last_seen)"
        " VALUES ('da:a1:19:00:00:01',1,2,%lld,%lld);"
        "INSERT INTO pnl_ssids (mac,ssid,first_seen,last_seen) VALUES"
        " ('da:a1:19:00:00:01','CafeFree',%lld,%lld),"
        " ('da:a1:19:00:00:01','OnlyHere',%lld,%lld);",
        T - 900, T - 30, T - 90000, T - 80000, T - 900, T - 20,
        T - 900, T - 30, T - 800, T - 40, T - 800, T - 40);
    WT_EQ(sdb_exec(g_here_db, sql), 0);
    web_slothdb_t here;
    web_slothdb_init(&here, g_here_db, NULL);
    web_frrs_t fr2;
    char err[256];
    WT_EQ(web_frrs_init(&fr2, &S2, NULL, 1, err, sizeof(err)), 0);
    snprintf(sql, sizeof(sql),
        "INSERT INTO triage (subject,finding,type,addr,port,first_seen,state,ts,note,who,"
        "peer) VALUES ('x3:%lld',NULL,3,'da:a1:19:00:00:01',0,%lld,4,%lld,'','','');",
        T - 500, T - 500, T - 400);
    WT_EQ(sql_on(g_here_web, sql), 0);
    /* Two positions to measure between: beta's, and a peer no longer
     * named. */
    WT_EQ(sql_on(g_here_web, "UPDATE peer_sites SET lat=33.32919, lon=-111.87007,"
                             " pos_source='fixed' WHERE peer='beta';"
                             "INSERT INTO peer_sites (peer,url,lat,lon) VALUES"
                             " ('old','http://100.64.9.9:8770',41.8781136,-87.6297982);"), 0);

    web_m4_t m4;
    memset(&m4, 0, sizeof(m4));
    m4.fleet = &F;
    m4.sdb = &here;
    m4.frrs = &fr2;
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.wall_s = T + 65;
    h.m4 = &m4;
    static char out[65536];
    web_req_t rq;
    web_resp_t r;
    memset(&rq, 0, sizeof(rq));
    snprintf(rq.host, sizeof(rq.host), "127.0.0.1:8770");
    rq.host_count = 1;
    snprintf(rq.path, sizeof(rq.path), "/api/fleet/overview");
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    out[r.out_len] = '\0';
    WT_EQ(r.status, 200);
    WT_HAS(out, "{\"local\":{\"name\":\"self\",\"label\":null,\"sloth_db\":\"open\",\"lat\":null,");
    WT_HAS(out, ",\"store\":true,\"configured\":1,\"peers\":[{\"name\":\"beta\",\"configured\":true,");
    WT_HAS(out, ",\"last_ok_age_s\":60,\"last_attempt_age_s\":60,\"last_error\":null,"
                "\"skew_s\":-5,");
    WT_HAS(out, ",\"counts\":{\"wifi\":9,\"ble\":0,\"ap\":0,\"probe\":2,");
    WT_HAS(out, "{\"name\":\"old\",\"configured\":false,");
    WT_HAS(out, "\"distances\":[{\"a\":\"beta\",\"b\":\"old\",\"m\":2326925.0}]");
    snprintf(rq.query, sizeof(rq.query), "x=1");
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 400);

    snprintf(rq.path, sizeof(rq.path), "/api/fleet/shared");
    snprintf(rq.query, sizeof(rq.query), "kind=wifi");
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 200);
    char *body = (char *)r.body_owned;
    WT_ASSERT(body != NULL);
    if (body) {
        char *t = realloc(body, r.body_len + 1);
        if (t) { body = t; body[r.body_len] = '\0'; }
        WT_HAS(body, "{\"kind\":\"wifi\",\"limit\":50,\"store\":true,\"local\":\"open\",");
        WT_HAS(body, "\"partial\":false,");
        WT_HAS(body, "{\"key\":\"da:a1:19:00:00:01\",\"addr\":\"da:a1:19:00:00:01\","
                     "\"label\":\"HomeNet\",\"vendor\":\"Apple\",\"last\":");
        WT_HAS(body, "\"sites\":[{\"site\":\"self\",\"first_seen\":1792626300,"
                     "\"last_seen\":1792627170,\"rssi\":-41},{\"site\":\"beta\",");
        WT_HAS(body, "\"verdict\":{\"state\":\"known\",\"site\":\"self\"}");
        /* The ARP row's 0 is not 0 dBm: the probe's reading (#192 I5;
         * seen red with web_sdb_seen()'s fallback removed, the reading
         * then null, and with its "< 0" made "<= 0", the 0 kept). */
        const char *d4 = strstr(body, "{\"key\":\"da:a1:19:00:00:04\"");
        WT_ASSERT(d4 != NULL);
        if (d4) WT_HAS(d4, "\"sites\":[{\"site\":\"self\",\"first_seen\":");
        if (d4) {
            const char *e4 = strstr(d4, "],\"verdict\"");
            const char *r4 = strstr(d4, "\"rssi\":-52}");
            WT_ASSERT(r4 && e4 && r4 < e4);
        }
        WT_LACKS(body, "\"rssi\":0}");
        /* No verdict here: the peer's, named with its site; and the
         * peer's at the address this site has triaged is not shown. */
        WT_HAS(body, "\"verdict\":{\"state\":\"incident\",\"site\":\"beta\"}");
        WT_LACKS(body, "\"state\":\"noise\"");
        /* Held by one site only: not listed. */
        WT_LACKS(body, "02:10:ca:10:ca:01");
        WT_LACKS(body, "da:a1:19:00:00:02");
        WT_LACKS(body, "00:11:22:33:44:55");
        /* The newest cross-site activity first. */
        const char *a = strstr(body, "\"key\":\"da:a1:19:00:00:01\"");
        const char *c = strstr(body, "\"key\":\"da:a1:19:00:00:04\"");
        WT_ASSERT(a && c && a < c);
        free(body);
    }
    snprintf(rq.query, sizeof(rq.query), "kind=wifi&limit=1");
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    body = (char *)r.body_owned;
    if (body) {
        char *t = realloc(body, r.body_len + 1);
        if (t) { body = t; body[r.body_len] = '\0'; }
        WT_HAS(body, "da:a1:19:00:00:01");
        WT_LACKS(body, "da:a1:19:00:00:04");
        free(body);
    }
    snprintf(rq.query, sizeof(rq.query), "kind=probe");
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    body = (char *)r.body_owned;
    if (body) {
        char *t = realloc(body, r.body_len + 1);
        if (t) { body = t; body[r.body_len] = '\0'; }
        WT_HAS(body, "{\"key\":\"da:a1:19:00:00:01|CafeFree\",\"addr\":\"da:a1:19:00:00:01\",");
        WT_LACKS(body, "HomeNet");
        WT_LACKS(body, "OnlyHere");
        free(body);
    }
    static const char *const badq[] = { "kind=alert", "kind=wifi&limit=0", "limit=201",
                                        "kind=wifi&x=1", "limit=1x" };
    for (size_t i = 0; i < sizeof(badq) / sizeof(badq[0]); i++) {
        snprintf(rq.query, sizeof(rq.query), "%s", badq[i]);
        WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
        WT_EQ(r.status, 400);
        free(r.body_owned);
    }
    web_frrs_destroy(&fr2);
    web_slothdb_destroy(&here);
    here_down(&srv, th);
}

/* #192 I5: the pull asks with own=1 and keeps the radios the peer names;
 * an F2 peer, whose export refuses own=1, is asked again with next=1
 * alone (its backfill kept) and not asked with own=1 for the hour; a
 * peer that has not named its radios keeps what it named before. Seen
 * red with the own=1 retry removed (the F2 pull then fell through to the
 * plain request and set no_next_until; the F1 test's request sequence
 * went red with it). */
static void test_pull_own_radios(void) {
    peer_srv_t srv;
    pthread_t th;
    here_up(&srv, &th);
    srv.src.own_csv = "02:00:5e:00:00:0b";
    WT_EQ(web_fleet_pull_one(&F, 0, T), 0);
    WT_ASSERT(!strcmp(srv.req[0], "since=0&next=1&own=1&gnss=1&adsb=1&ident=1"));
    WT_EQ(F.peer[0].nown, 1);
    WT_ASSERT(!strcmp(F.peer[0].own[0], "02:00:5e:00:00:0b"));
    WT_EQ(F.peer[0].own_at, T);
    /* Now an F2 build: own=1 refused, next=1 kept. */
    srv.f2 = 1;
    int n0 = srv.n;
    WT_EQ(web_fleet_pull_one(&F, 0, T + 60), 0);
    WT_ASSERT(srv.n >= n0 + 5);
    char want[64];
    snprintf(want, sizeof(want), "since=%lld&next=1&own=1&gnss=1&adsb=1&ident=1",
             T - WEB_FLEET_OVERLAP_S);
    WT_ASSERT(!strcmp(srv.req[n0], want));
    snprintf(want, sizeof(want), "since=%lld&next=1&own=1&gnss=1&adsb=1", T - WEB_FLEET_OVERLAP_S);
    WT_ASSERT(!strcmp(srv.req[n0 + 1], want));
    snprintf(want, sizeof(want), "since=%lld&next=1&own=1&gnss=1", T - WEB_FLEET_OVERLAP_S);
    WT_ASSERT(!strcmp(srv.req[n0 + 2], want));
    snprintf(want, sizeof(want), "since=%lld&next=1&own=1", T - WEB_FLEET_OVERLAP_S);
    WT_ASSERT(!strcmp(srv.req[n0 + 3], want));
    snprintf(want, sizeof(want), "since=%lld&next=1", T - WEB_FLEET_OVERLAP_S);
    WT_ASSERT(!strcmp(srv.req[n0 + 4], want));
    WT_ASSERT(F.peer[0].no_own_until > T + 60);
    WT_EQ(F.peer[0].no_next_until, 0);
    WT_EQ(F.peer[0].failures, 0);
    /* Not named this time: the radios named before stay. */
    WT_EQ(F.peer[0].nown, 1);
    /* Within the hour, one request, without own=1. */
    n0 = srv.n;
    WT_EQ(web_fleet_pull_one(&F, 0, T + 120), 0);
    WT_ASSERT(srv.n >= n0 + 1);
    WT_LACKS(srv.req[n0], "own=");
    WT_HAS(srv.req[n0], "&next=1");
    here_down(&srv, th);
}

/* #192 I5's route over a store and a sloth.db built here: W9FJC ("self",
 * 33.32922,-111.87006) and beta-site (33.32910,-111.86995), 16.8 m
 * apart, beta's clock 100 s ahead; a third site, gamma, 21 m north.
 *
 * Calibration: beta heard self's radio (02:..:0a) at -52 dBm, an offset
 * of -7.1 dB at the haversine's 16.84 m, inside the bound: beta
 * calibrated. Self heard beta's radio (02:..:0b, named by beta's own=1)
 * through an ARP row and a probe at -88 dBm: 28.9 dB, refused, its
 * links listed.
 *
 * The emitters: :01 heard at both within the window (self -60 at T-10,
 * beta -52 at true T-20): two circles, 18 m and 17 m as quantised, two
 * candidates, nearer beta by 0.9 dB, coarse (bands far wider than
 * 16.8 m). :02 at beta at true T-200: outside the 120 s window,
 * unpaired (seen red with the skew correction dropped: beta's T-100 as
 * stored then paired it). :03 at both, a half hour ago: stale. :04 at
 * all three: least squares. 5 GHz :05 is not calibrated at beta (seen
 * red with the model's 5 GHz cal_ok = 0 removed). */
static void test_locate_route(void) {
    pull_up();
    snprintf(g_here_db, sizeof(g_here_db), "%s/here.db", g_dir);
    WT_EQ(sdb_make(g_here_db, db_schema_version(), 0), 0);
    char sql[4096];
    snprintf(sql, sizeof(sql),
        "INSERT INTO devices (mac,vendor,is_ap,signal_dbm,first_seen,last_seen) VALUES"
        " ('02:00:5e:00:00:0b','Beta card',0,0,%lld,%lld),"
        " ('02:aa:00:00:00:01',NULL,0,-60,%lld,%lld),"
        " ('02:aa:00:00:00:02',NULL,0,-60,%lld,%lld),"
        " ('02:aa:00:00:00:03',NULL,0,-60,%lld,%lld),"
        " ('02:aa:00:00:00:04',NULL,0,-58,%lld,%lld),"
        " ('02:aa:00:00:00:06',NULL,0,-60,%lld,%lld),"
        " ('02:00:5e:00:00:0c','Beta 5 GHz card',0,0,%lld,%lld),"
        " ('02:aa:00:00:00:07',NULL,0,0,%lld,%lld),"
        " ('02:aa:00:00:00:08',NULL,0,-40,%lld,%lld);"
        "INSERT INTO probe_clients (mac,ssid,signal_dbm,channel,first_seen,last_seen)"
        " VALUES ('02:00:5e:00:00:0b','',-88,1,%lld,%lld),"
        " ('02:00:5e:00:00:0c','',-60,36,%lld,%lld),"
        " ('02:aa:00:00:00:07','',-60,36,%lld,%lld);"
        "INSERT INTO beacon_aps (bssid,ssid,signal_dbm,channel,enc,first_seen,last_seen)"
        " VALUES ('02:bb:00:00:00:05','Five',-70,36,'WPA2',%lld,%lld);",
        T - 900, T - 5, T - 900, T - 10, T - 900, T - 10, T - 2000, T - 1800,
        T - 900, T - 5, T - 900, T - 10, T - 900, T - 5, T - 900, T - 5, T - 900, T - 10,
        T - 900, T - 60, T - 900, T - 60, T - 900, T - 10, T - 900, T - 10);
    WT_EQ(sdb_exec(g_here_db, sql), 0);
    snprintf(sql, sizeof(sql),
        "INSERT INTO peer_sites (peer,url,lat,lon,pos_source,remote_ts,last_ok) VALUES"
        " ('beta','http://127.0.0.1:1',33.32910,-111.86995,'fixed',%lld,%lld),"
        " ('gamma','http://100.64.0.9:8770',33.32941,-111.87000,'fixed',%lld,%lld),"
        " ('far','http://100.64.0.8:8770',41.8781136,-87.6297982,'fixed',%lld,%lld);"
        "INSERT INTO peer_sightings (peer,kind,key,rssi,first_seen,last_seen,extra) VALUES"
        " ('beta','wifi','02:00:5e:00:00:0a',-52,%lld,%lld,'{}'),"
        " ('beta','wifi','02:aa:00:00:00:01',-52,%lld,%lld,'{}'),"
        " ('beta','wifi','02:aa:00:00:00:02',-60,%lld,%lld,'{}'),"
        " ('beta','wifi','02:aa:00:00:00:03',-60,%lld,%lld,'{}'),"
        " ('beta','wifi','02:aa:00:00:00:04',-61,%lld,%lld,'{}'),"
        " ('gamma','wifi','02:aa:00:00:00:04',-63,%lld,%lld,'{}'),"
        " ('far','wifi','02:aa:00:00:00:01',-40,%lld,%lld,'{}'),"
        " ('beta','wifi','02:aa:00:00:00:06',0,%lld,%lld,'{}'),"
        " ('beta','wifi','02:aa:00:00:00:07',-55,%lld,%lld,'{}'),"
        " ('beta','wifi','02:aa:00:00:00:08',-75,%lld,%lld,'{}'),"
        " ('beta','ap','02:bb:00:00:00:05',-72,%lld,%lld,'{\"channel\":36,\"enc\":\"WPA2\"}');",
        T + 100, T, T, T, T, T,
        T, T + 100 - 30, T, T + 100 - 20, T, T + 100 - 200, T - 2000, T + 100 - 1790,
        T, T + 100 - 8, T, T - 6, T, T - 5, T, T + 100 - 5, T, T + 100 - 10, T, T + 100 - 10,
        T, T + 100 - 15);
    WT_EQ(sql_on(g_store, sql), 0);
    F.nown = 1;
    snprintf(F.own[0], sizeof(F.own[0]), "02:00:5e:00:00:0a");
    snprintf(F.own_csv, sizeof(F.own_csv), "02:00:5e:00:00:0a");
    F.peer[0].nown = 2;
    F.peer[0].own_at = T;
    snprintf(F.peer[0].own[0], sizeof(F.peer[0].own[0]), "02:00:5e:00:00:0b");
    snprintf(F.peer[0].own[1], sizeof(F.peer[0].own[1]), "02:00:5e:00:00:0c");
    web_slothdb_t here;
    web_slothdb_init(&here, g_here_db, NULL);
    web_gnss_t G;
    WT_EQ(web_gnss_init(&G), 0);
    G.loc.has = 1;
    G.loc.lat = 33.32922;
    G.loc.lon = -111.87006;
    G.loc.ts = T;
    snprintf(G.loc.src, sizeof(G.loc.src), "fixed");
    web_fleet_src_t src = { &here, NULL, &G, NULL, NULL, NULL, NULL, NULL };

    char *b = NULL;
    size_t bl = 0;
    int st = 0;
    WT_EQ(web_fleet_locate_route(&F, &src, "kind=wifi", T, &b, &bl, &st), 0);
    WT_EQ(st, 200);
    if (b) {
        b[bl - 1] = '\0';               /* the newline */
        WT_HAS(b, "{\"kind\":\"wifi\",\"limit\":50,\"window_s\":120,\"max_age_s\":900,\"origin\":{");
        /* Sites: far is alone (2,327 km from the rest). */
        WT_HAS(b, "{\"site\":\"far\",\"lat\":41.8781136,\"lon\":-87.6297982,\"e\":2252072.5,"
                  "\"n\":950592.3,\"too_far\":true,");
        /* beta calibrated by self's radio; self refused by beta's. */
        WT_HAS(b, "{\"site\":\"beta\",\"lat\":33.3291000,");
        WT_HAS(b, "\"calibration\":{\"state\":\"calibrated\",\"offset_db\":-7.1,\"exponent_x10\":28,"
                  "\"links\":[{\"from\":\"self\",\"mac\":\"02:00:5e:00:00:0a\",\"rssi\":-52,"
                  "\"dist_m\":16.8,\"offset_db\":-7.1,\"accepted\":true,\"age_s\":30}]}");
        /* Beta's second card, heard here only on 5 GHz, is no link for
         * a 2.4 GHz offset (#192 I5 review; seen red with the channel
         * test removed from calibrate_all(): its +1.0 dB link accepted,
         * self calibrated). */
        WT_HAS(b, "\"calibration\":{\"state\":\"refused\",\"offset_db\":28.9,\"exponent_x10\":28,"
                  "\"links\":[{\"from\":\"beta\",\"mac\":\"02:00:5e:00:00:0b\",\"rssi\":-88,"
                  "\"dist_m\":16.8,\"offset_db\":28.9,\"accepted\":false,\"age_s\":60}]}");
        WT_LACKS(b, "02:00:5e:00:00:0c");
        const char *r1 = strstr(b, "{\"key\":\"02:aa:00:00:00:01\"");
        WT_ASSERT(r1 != NULL);
        if (r1) {
            WT_HAS(r1, "\"age_s\":10,\"freq_mhz\":2437,\"ptx_dbm\":15,\"ptx\":\"assumed\","
                       "\"exponent_x10\":28,\"sites\":[{\"site\":\"self\",\"rssi\":-60,");
            WT_HAS(r1, "\"range_m\":18.0,");
            WT_HAS(r1, "\"sigma_db\":11.7,\"calibrated\":false},{\"site\":\"beta\",\"rssi\":-52,"
                       "\"seen\":");
            WT_HAS(r1, "\"range_m\":17.0,");
            /* 0.9 dB is inside the difference's sigma, sqrt(2 x 8^2 + 6^2)
             * with self uncalibrated: no side (#192 I5 review). */
            WT_HAS(r1, "\"sigma_db\":10.0,\"calibrated\":true}],\"nearest\":{\"site\":\"beta\","
                       "\"by_db\":0.9,\"than\":\"self\",\"sigma_db\":12.8,\"within_band\":true},"
                       "\"candidates\":[{\"lat\":");
            const char *e1 = strstr(r1, "\"method\":");
            WT_ASSERT(e1 && count_of(r1, "\"radius_m\"") >= 2);
            if (e1) WT_HAS(e1, "\"method\":\"two_circles\",\"residual_m\":null,"
                               "\"baseline_m\":16.8,");
            if (e1) WT_HAS(e1, "\"coarse\":true}");
        }
        WT_LACKS(b, "02:aa:00:00:00:02");
        WT_LACKS(b, "02:aa:00:00:00:03");
        /* beta's 0 for :06 is no reading, so :06 is heard here only
         * (seen red with the scan's rssi < 0 dropped). */
        WT_LACKS(b, "02:aa:00:00:00:06");
        WT_LACKS(b, "{\"site\":\"far\",\"rssi\"");
        /* :08, -40 here and -75 at calibrated beta: 42.1 dB, a side. */
        WT_HAS(b, "\"nearest\":{\"site\":\"self\",\"by_db\":42.1,\"than\":\"beta\","
                  "\"sigma_db\":12.8,\"within_band\":false}");
        /* :07's reading here is a probe on channel 36: the row is
         * modelled at 5 GHz, uncalibrated (#192 I5 review; seen red with
         * the local row's channel kept for APs only: 2437 MHz, N 2.8). */
        const char *r7 = strstr(b, "{\"key\":\"02:aa:00:00:00:07\"");
        WT_ASSERT(r7 != NULL);
        if (r7) {
            WT_HAS(r7, "\"freq_mhz\":5180,\"ptx_dbm\":15,\"ptx\":\"assumed\",\"exponent_x10\":30,");
            const char *e7 = strstr(r7, "\"method\":");
            const char *c7 = strstr(r7, "\"calibrated\":true");
            WT_ASSERT(e7 && (!c7 || c7 > e7));
        }
        const char *r4 = strstr(b, "{\"key\":\"02:aa:00:00:00:04\"");
        WT_ASSERT(r4 != NULL);
        if (r4) {
            WT_HAS(r4, "\"method\":\"least_squares\",\"residual_m\":");
            WT_HAS(r4, "{\"site\":\"gamma\",\"rssi\":-63,");
        }
        WT_HAS(b, "\"unpaired\":1,\"stale\":1,\"partial\":false}");
        free(b);
    }
    /* A 5 GHz AP: N 3.0, never the 2.4 GHz calibration. */
    WT_EQ(web_fleet_locate_route(&F, &src, "kind=ap&limit=5", T, &b, &bl, &st), 0);
    WT_EQ(st, 200);
    if (b) {
        b[bl - 1] = '\0';
        WT_HAS(b, "{\"key\":\"02:bb:00:00:00:05\",\"label\":null,");
        WT_HAS(b, "\"freq_mhz\":5180,\"ptx_dbm\":20,\"ptx\":\"assumed\",\"exponent_x10\":30,");
        WT_LACKS(b, "\"calibrated\":true");
        free(b);
    }
    /* The limit, and the bounds. */
    WT_EQ(web_fleet_locate_route(&F, &src, "kind=wifi&limit=1", T, &b, &bl, &st), 0);
    if (b) {
        b[bl - 1] = '\0';
        WT_EQ(count_of(b, "{\"key\":"), 1);
        free(b);
    }
    static const char *const badq[] = { "kind=probe", "kind=alert", "limit=0", "limit=201",
                                        "kind=wifi&x=1", "limit=1x", "kind=wifi&kind=ap",
                                        "kind" };
    for (size_t i = 0; i < sizeof(badq) / sizeof(badq[0]); i++) {
        WT_EQ(web_fleet_locate_route(&F, &src, badq[i], T, &b, &bl, &st), 0);
        if (st != 400) fprintf(stderr, "    taken: %s\n", badq[i]);
        WT_EQ(st, 400);
        free(b);
    }
    /* The overview carries the same calibration. */
    static char ob[65536];
    size_t ol = 0;
    WT_EQ(web_fleet_overview_route(&F, &src, "", T, ob, sizeof(ob) - 1, &ol, &st), 0);
    ob[ol] = '\0';
    WT_EQ(st, 200);
    WT_HAS(ob, "],\"calibration\":[{\"site\":\"self\",\"own_radios\":1,\"receiver\":{\"state\":"
               "\"refused\",");
    WT_HAS(ob, "{\"site\":\"beta\",\"own_radios\":2,\"receiver\":{\"state\":\"calibrated\","
               "\"offset_db\":-7.1,");
    WT_HAS(ob, ",\"distances\":[");
    /* An address two sites both name as their own has no known position
     * and is no link for anyone (#192 I5 review): with this site also
     * claiming beta's card, self has no link at all and beta keeps only
     * the link to self's other radio. Seen red with the check removed
     * (self "refused" by the -88 dBm link again). */
    F.nown = 2;
    snprintf(F.own[1], sizeof(F.own[1]), "02:00:5e:00:00:0b");
    WT_EQ(web_fleet_locate_route(&F, &src, "kind=wifi", T, &b, &bl, &st), 0);
    WT_EQ(st, 200);
    if (b) {
        b[bl - 1] = '\0';
        const char *me = strstr(b, "{\"site\":\"self\",\"lat\":");
        const char *mc = me ? strstr(me, "\"calibration\":") : NULL;
        WT_ASSERT(mc && !strncmp(mc, "\"calibration\":{\"state\":\"none\",\"offset_db\":null,"
                                     "\"exponent_x10\":28,\"links\":[]}", 76));
        WT_HAS(b, "\"calibration\":{\"state\":\"calibrated\",\"offset_db\":-7.1,\"exponent_x10\":28,"
                  "\"links\":[{\"from\":\"self\",\"mac\":\"02:00:5e:00:00:0a\",");
        WT_LACKS(b, "\"mac\":\"02:00:5e:00:00:0b\"");
        free(b);
    }
    F.nown = 1;
    /* Through the router: GET only. */
    web_m4_t m4;
    memset(&m4, 0, sizeof(m4));
    m4.fleet = &F;
    m4.sdb = &here;
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.wall_s = T;
    h.m4 = &m4;
    h.gnss = &G;
    static char out[65536];
    web_req_t rq;
    web_resp_t r;
    memset(&rq, 0, sizeof(rq));
    snprintf(rq.host, sizeof(rq.host), "127.0.0.1:8770");
    rq.host_count = 1;
    snprintf(rq.path, sizeof(rq.path), "/api/fleet/locate");
    snprintf(rq.query, sizeof(rq.query), "kind=wifi");
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 200);
    free(r.body_owned);
    rq.is_head = 1;
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 405);
    web_gnss_destroy(&G);
    web_slothdb_destroy(&here);
    pull_down();
}

/* The host's own radios from a sysfs tree built here: physical
 * interfaces only (a device link), sorted by name, all-zero and group
 * addresses refused. Seen red with the device test removed (the bridge's
 * address then listed). */
static void test_read_own(void) {
    char d[TEST_TMP_MAX], p[TEST_TMP_MAX + 96];
    snprintf(d, sizeof(d), "%s/slothweb-sysfs-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(d) != NULL);
    static const struct { const char *name, *addr; int phys; } ifs[] = {
        { "wlan1", "24:41:8c:30:97:a1\n", 1 }, { "alfa0", "00:c0:ca:bb:51:82\n", 1 },
        { "br0", "02:42:ac:11:00:01\n", 0 }, { "lo", "00:00:00:00:00:00\n", 1 },
        { "mc0", "01:00:5e:00:00:01\n", 1 },
    };
    snprintf(p, sizeof(p), "%s/class", d);
    mkdir(p, 0700);
    snprintf(p, sizeof(p), "%s/class/net", d);
    mkdir(p, 0700);
    for (size_t i = 0; i < sizeof(ifs) / sizeof(ifs[0]); i++) {
        snprintf(p, sizeof(p), "%s/class/net/%s", d, ifs[i].name);
        mkdir(p, 0700);
        snprintf(p, sizeof(p), "%s/class/net/%s/address", d, ifs[i].name);
        FILE *fp = fopen(p, "w");
        if (fp) { fputs(ifs[i].addr, fp); fclose(fp); }
        if (ifs[i].phys) {
            snprintf(p, sizeof(p), "%s/class/net/%s/device", d, ifs[i].name);
            mkdir(p, 0700);
        }
    }
    web_fleet_t f;
    web_fleet_init(&f, NULL, 0, 60, 0, NULL);
    WT_EQ(web_fleet_read_own(&f, d), 2);
    WT_ASSERT(!strcmp(f.own_csv, "00:c0:ca:bb:51:82,24:41:8c:30:97:a1"));
    web_fleet_destroy(&f);
    for (size_t i = 0; i < sizeof(ifs) / sizeof(ifs[0]); i++) {
        snprintf(p, sizeof(p), "%s/class/net/%s/address", d, ifs[i].name);
        unlink(p);
        snprintf(p, sizeof(p), "%s/class/net/%s/device", d, ifs[i].name);
        rmdir(p);
        snprintf(p, sizeof(p), "%s/class/net/%s", d, ifs[i].name);
        rmdir(p);
    }
    snprintf(p, sizeof(p), "%s/class/net", d);
    rmdir(p);
    snprintf(p, sizeof(p), "%s/class", d);
    rmdir(p);
    rmdir(d);
}

static void mk_if(const char *d, const char *name, const char *addr, int phys) {
    char p[TEST_TMP_MAX + 96];
    snprintf(p, sizeof(p), "%s/class/net/%s", d, name);
    mkdir(p, 0700);
    snprintf(p, sizeof(p), "%s/class/net/%s/address", d, name);
    FILE *fp = fopen(p, "w");
    if (fp) { fputs(addr, fp); fclose(fp); }
    if (phys) {
        snprintf(p, sizeof(p), "%s/class/net/%s/device", d, name);
        mkdir(p, 0700);
    }
}

static void rm_if(const char *d, const char *name) {
    char p[TEST_TMP_MAX + 96];
    snprintf(p, sizeof(p), "%s/class/net/%s/address", d, name);
    unlink(p);
    snprintf(p, sizeof(p), "%s/class/net/%s/device", d, name);
    rmdir(p);
    snprintf(p, sizeof(p), "%s/class/net/%s", d, name);
    rmdir(p);
}

/* A host with a thousand container veths beside its radios (#196): every
 * directory entry is looked at, so the two physical interfaces are named
 * wherever readdir() puts them; a radio plugged in later is named at the
 * next read due (WEB_FLEET_OWN_REREAD_S after the last), not before, and
 * the export carries the list as re-read. Seen red with the scan stopped
 * at 64 entries, as before (the radios missed in 5 of 5 runs on tmpfs),
 * and with the tick's re-read removed (wlan9 never named). */
static void test_read_own_many_and_again(void) {
    char d[TEST_TMP_MAX], p[TEST_TMP_MAX + 96];
    snprintf(d, sizeof(d), "%s/slothweb-sysfs-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(d) != NULL);
    snprintf(p, sizeof(p), "%s/class", d);
    mkdir(p, 0700);
    snprintf(p, sizeof(p), "%s/class/net", d);
    mkdir(p, 0700);
    /* The radios first: tmpfs lists the newest entries first, so they
     * then come after the veths there; elsewhere readdir()'s order is a
     * hash, 2 of 1,002. */
    mk_if(d, "wlan1", "24:41:8c:30:97:a1\n", 1);
    mk_if(d, "eth0", "00:c0:ca:bb:51:82\n", 1);
    char nm[32], ad[32];
    for (int i = 0; i < 1000; i++) {
        snprintf(nm, sizeof(nm), "veth%04x", i);
        snprintf(ad, sizeof(ad), "02:42:ac:11:%02x:%02x\n", i / 256, i % 256);
        mk_if(d, nm, ad, 0);
    }
    web_fleet_t f;
    web_fleet_init(&f, NULL, 0, 60, 0, NULL);
    WT_EQ(web_fleet_read_own(&f, d), 2);
    char own[WEB_FLEET_OWN_MAX][WEB_FLEET_MAC_SZ];
    WT_EQ(web_fleet_own_get(&f, own), 2);
    WT_ASSERT(!strcmp(own[0], "00:c0:ca:bb:51:82") && !strcmp(own[1], "24:41:8c:30:97:a1"));
    mk_if(d, "wlan9", "00:c0:ca:00:00:09\n", 1);
    web_fleet_own_tick(&f, T);                       /* notes now */
    web_fleet_own_tick(&f, T + WEB_FLEET_OWN_REREAD_S - 1);
    WT_EQ(web_fleet_own_get(&f, own), 2);
    web_fleet_own_tick(&f, T + WEB_FLEET_OWN_REREAD_S);
    WT_EQ(web_fleet_own_get(&f, own), 3);
    WT_ASSERT(!strcmp(own[2], "00:c0:ca:00:00:09"));
    /* The export names the list as it now stands. */
    web_fleet_src_t src;
    memset(&src, 0, sizeof(src));
    src.own_csv = f.own_csv;
    char *body = NULL;
    size_t len = 0;
    int st = 0;
    WT_EQ(web_fleet_export_route(&src, "since=0&next=1&own=1", T, &body, &len, &st), 0);
    WT_EQ(st, 200);
    char *b = body ? realloc(body, len + 1) : NULL;
    if (b) b[len] = '\0'; else free(body);
    WT_HAS(b, "\"own_macs\":\"00:c0:ca:bb:51:82,24:41:8c:30:97:a1,00:c0:ca:00:00:09\"");
    free(b);
    web_fleet_destroy(&f);
    for (int i = 0; i < 1000; i++) {
        snprintf(nm, sizeof(nm), "veth%04x", i);
        rm_if(d, nm);
    }
    rm_if(d, "wlan1");
    rm_if(d, "eth0");
    rm_if(d, "wlan9");
    snprintf(p, sizeof(p), "%s/class/net", d);
    rmdir(p);
    snprintf(p, sizeof(p), "%s/class", d);
    rmdir(p);
    rmdir(d);
}

/* ── #192 I6: GNSS across the sites ────────────────────────────────── */

/* This site's receiver as sloth writes it (test_gnss.c's records at T):
 * fixed at W9FJC, eph 4.5, offset -60 ms, three satellites tracked at
 * 41, 30.5 and 22.5 dB-Hz. */
static void gnss_feed(web_gnss_t *g, long long ts, double lat, double lon, long long off) {
    web_jrec_t *r = malloc(sizeof(*r));
    WT_ASSERT(r != NULL);
    if (!r) return;
    char line[1024];
    const char *const fmt[] = {
        "{\"type\":\"sensor_health\",\"ts\":%lld,\"capture_iface\":\"any\",\"gps_state\":\"fix\","
        "\"gnss_sats_in_view\":4,\"gnss_sats_used\":3,\"gnss_cn0_mean\":23.5,"
        "\"gnss_time_offset_ms\":%lld,\"gnss_jam\":12}",
        "{\"type\":\"gnss_fix\",\"ts\":%lld,\"src\":\"gpsd:127.0.0.1:2947\",\"fix_ts\":%lld,"
        "\"mode\":3,\"status\":2,\"nsat\":4,\"usat\":3,\"hdop\":0.9,\"lat\":%.7f,\"lon\":%.7f,"
        "\"eph\":4.5,\"time_off_ms\":%lld,\"jam\":12,\"tpv_count\":1}",
    };
    snprintf(line, sizeof(line), fmt[0], ts, off);
    WT_EQ(web_jl_parse(line, strlen(line), r), WEB_JL_OK);
    web_gnss_record(g, r, ts * 1000);
    snprintf(line, sizeof(line), fmt[1], ts, ts, lat, lon, off);
    WT_EQ(web_jl_parse(line, strlen(line), r), WEB_JL_OK);
    web_gnss_record(g, r, ts * 1000);
    static const struct { int prn; double cn0; } sat[] = { { 5, 41 }, { 7, 22.5 }, { 9, 30.5 },
                                                           { 11, 0 } };
    for (size_t i = 0; i < sizeof(sat) / sizeof(sat[0]); i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"gnss_sat\",\"ts\":%lld,\"gnss\":\"GPS\",\"gnssid\":0,\"svid\":%d,"
                 "\"prn\":%d,\"el\":40,\"az\":100,\"cn0\":%.1f,\"used\":1,\"health\":1,"
                 "\"sky_ts\":%lld}", ts, sat[i].prn, sat[i].prn, sat[i].cn0, ts);
        WT_EQ(web_jl_parse(line, strlen(line), r), WEB_JL_OK);
        web_gnss_record(g, r, ts * 1000);
    }
    free(r);
}

static void gnss_incidents(const char *db) {
    char sql[2048];
    int jam = web_akb_find("GNSS_JAMMING"), tj = web_akb_find("GNSS_TIME_JUMP");
    int pj = web_akb_find("GNSS_POSITION_JUMP"), sp = web_akb_find("GNSS_SPOOF_SUSPECT");
    WT_ASSERT(jam > 0 && tj > 0 && pj > 0 && sp > 0);
    snprintf(sql, sizeof(sql),
        "INSERT INTO alert_incidents (key,incident_id,type,first_seen,last_seen,sev,peak_sev,"
        "count,observations) VALUES"
        " ('gnssjam','j1',%d,%lld,%lld,1,2,7,7),"
        " ('gnsspos','p1',%d,%lld,%lld,1,1,1,1),"
        " ('gnssspoof','s1',%d,%lld,%lld,1,1,1,1),"
        /* Older than the week: not sent, not classified. */
        " ('gnsstime','t1',%d,%lld,%lld,1,1,1,1),"
        /* Another rule's incident with a GNSS type under its own key: the
         * keys are the filter, so it never travels. */
        " ('deauth:02:00:00:00:00:01','d1',%d,%lld,%lld,1,1,1,1);",
        jam, T - 3000, T - 2900, pj, T - 1500, T - 1500, sp, T - 9000, T - 9000,
        tj, T - 8 * DY, T - 8 * DY, tj, T - 100, T - 100);
    WT_EQ(sdb_exec(db, sql), 0);
}

/* The export with gnss=1: the gnss line gains the newest fix and the
 * tracked median (three satellites above 0 dB-Hz: 30.5), the week's GNSS
 * incidents travel as gnss_event lines (not the one a week old, not the
 * one under another key), the end line counts them, and the importer
 * takes every line. Without gnss=1 none of it is sent: an I5 importer
 * refuses a member it does not know. That absence was seen red with the
 * gnss_event read's `xq.gnss &&` dropped (the plain answer then held
 * gnss_event lines and an I5 importer refused it) and with the gnss
 * line's `if (xq.gnss)` dropped (fix_lat in the plain answer). */
static void test_gnss_export(void) {
    up();
    gnss_incidents(g_db);
    web_gnss_t *g = malloc(sizeof(*g));
    WT_ASSERT(g && web_gnss_init(g) == 0);
    gnss_feed(g, T - 5, 33.32922, -111.87006, -60);
    web_fleet_src_t src = { &SDB, NULL, g, &FR, NULL, NULL, NULL, NULL };
    char *body = NULL;
    size_t len = 0;
    int st = 0;
    WT_EQ(web_fleet_export_route(&src, "since=0&gnss=1", T, &body, &len, &st), 0);
    WT_EQ(st, 200);
    char *b = body ? realloc(body, len + 1) : NULL;
    if (b) b[len] = '\0';
    WT_HAS(b, "{\"type\":\"gnss\",\"gps_state\":\"fix\",\"sats_in_view\":4,\"sats_used\":3,"
              "\"cn0_mean\":23.5,\"time_offset_ms\":-60,\"jam\":12,\"ts\":1792627195,"
              "\"fix_ts\":1792627195,\"mode\":3,\"fix_lat\":33.3292200,\"fix_lon\":-111.8700600,"
              "\"eph\":4.5,\"hdop\":0.9,\"cn0_med\":30.5,\"tracked\":3}\n");
    char want[256];
    snprintf(want, sizeof(want), "{\"type\":\"gnss_event\",\"alert_type\":\"GNSS_JAMMING\","
             "\"ty\":%d,\"first_seen\":%lld,\"last_seen\":%lld,\"count\":7,\"sev\":2}\n",
             web_akb_find("GNSS_JAMMING"), T - 3000, T - 2900);
    WT_HAS(b, want);
    WT_HAS(b, "\"alert_type\":\"GNSS_POSITION_JUMP\"");
    WT_HAS(b, "\"alert_type\":\"GNSS_SPOOF_SUSPECT\"");
    /* Not the week-old time jump, not the deauth key's incident. */
    WT_EQ(count_of(b, "\"type\":\"gnss_event\""), 3);
    WT_EQ(count_of(b, "GNSS_TIME_JUMP"), 0);
    WT_HAS(b, ",\"gnss_event\":3,\"gnss_complete\":true,\"complete\":true}");
    /* The importer takes the whole answer. */
    web_fleet_peer_cfg_t pc;
    char err[256];
    WT_EQ(web_fleet_parse_peer("beta=http://127.0.0.1:1", &pc, err, sizeof(err)), 0);
    web_fleet_init(&F, &pc, 1, 60, 1, NULL);
    long long rows = 0, rts = 0;
    int rc = web_fleet_ingest(&F, 0, b, len, T, 0, &rows, &rts, err, sizeof(err));
    if (rc) fprintf(stderr, "    ingest: %s\n", err);
    WT_EQ(rc, 0);
    free(b);
    /* Without gnss=1: neither the fix nor an incident nor the count. */
    WT_EQ(web_fleet_export_route(&src, "since=0", T, &body, &len, &st), 0);
    b = body ? realloc(body, len + 1) : NULL;
    if (b) b[len] = '\0';
    WT_HAS(b, "{\"type\":\"gnss\",");
    WT_LACKS(b, "fix_lat");
    WT_LACKS(b, "gnss_event");
    WT_LACKS(b, "tracked");
    WT_EQ(web_fleet_export_route(&src, "since=0&gnss=2", T, &body, &len, &st), 0);
    WT_EQ(st, 400);
    free(body);
    free(b);
    /* More than the cap in the week: the newest 256 go, and the end line
     * says they are not all, so the importer takes no coverage from the
     * answer. Seen red with gev_all set regardless of the cut. */
    char sql[1024];
    snprintf(sql, sizeof(sql),
             "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<300)"
             " INSERT INTO alert_incidents (key,incident_id,type,first_seen,last_seen,sev,"
             "peak_sev,count,observations) SELECT 'gnssjam','m'||i,%d,%lld-i*60,%lld-i*60,"
             "1,1,1,1 FROM n;", web_akb_find("GNSS_JAMMING"), T - 4000, T - 4000);
    WT_EQ(sdb_exec(g_db, sql), 0);
    WT_EQ(web_fleet_export_route(&src, "since=0&gnss=1", T, &body, &len, &st), 0);
    b = body ? realloc(body, len + 1) : NULL;
    if (b) b[len] = '\0';
    WT_HAS(b, ",\"gnss_event\":256,\"gnss_complete\":false,\"complete\":true}");
    free(b);
    /* A sloth.db before v11 has no incident rows: no lines, and not
     * complete, never "none happened". Seen red with the reader's
     * WEB_SDB_GNSS_NONE returned as 0. */
    WT_EQ(sdb_exec(g_db, "DROP TABLE alert_incidents;"), 0);
    WT_EQ(web_fleet_export_route(&src, "since=0&gnss=1", T, &body, &len, &st), 0);
    b = body ? realloc(body, len + 1) : NULL;
    if (b) b[len] = '\0';
    WT_HAS(b, ",\"gnss_event\":0,\"gnss_complete\":false,\"complete\":true}");
    free(b);
    web_fleet_destroy(&F);
    web_gnss_destroy(g);
    free(g);
    down();
}

/* The importer's own checks of the new lines: a gnss_event of a type
 * that is not GNSS's, an end line whose count is not the lines sent or
 * that lacks it, a fix with a latitude and no longitude: each refuses
 * the whole answer. */
static void test_gnss_import_refusals(void) {
    web_fleet_peer_cfg_t pc;
    char err[256];
    WT_EQ(web_fleet_parse_peer("beta=http://127.0.0.1:1", &pc, err, sizeof(err)), 0);
    web_fleet_init(&F, &pc, 1, 60, 1, NULL);
#define GH "{\"type\":\"fleet_export\",\"fleet_export_version\":1,\"generated\":1792627000}\n"
#define GEND(n) "{\"type\":\"fleet_end\",\"rows\":0,\"wifi\":0,\"ble\":0,\"ap\":0,\"probe\":0," \
                "\"alert\":0,\"verdict\":0,\"complete\":true" n "}\n"
#define GEV(t) "{\"type\":\"gnss_event\",\"alert_type\":\"" t "\",\"ty\":90,\"first_seen\":5," \
               "\"last_seen\":9,\"count\":1,\"sev\":1}\n"
    static const struct { const char *body, *why; } bad[] = {
        { GH GEV("DEAUTH_FLOOD") GEND(",\"gnss_event\":1"), "gnss_event line with a value" },
        { GH GEV("GNSS_JAMMING") GEND(",\"gnss_event\":2"), "gnss_event count" },
        { GH GEV("GNSS_JAMMING") GEND(""), "gnss_event count" },
        { GH "{\"type\":\"gnss\",\"gps_state\":\"fix\",\"fix_lat\":33.3}\n" GEND(""),
          "gnss line with a value" },
        { GH GEV("GNSS_JAMMING") GEND(",\"gnss_event\":1,\"gnss_complete\":1"),
          "gnss_complete" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        long long rows, rts;
        err[0] = '\0';
        WT_EQ(web_fleet_ingest(&F, 0, bad[i].body, strlen(bad[i].body), 1792627000, 0, &rows,
                               &rts, err, sizeof(err)), -1);
        if (!strstr(err, bad[i].why)) fprintf(stderr, "    %zu: %s\n", i, err);
        WT_HAS(err, bad[i].why);
    }
    static const char good[] = GH GEV("GNSS_JAMMING") GEND(",\"gnss_event\":1,\"gnss_complete\":true");
    long long rows, rts;
    WT_EQ(web_fleet_ingest(&F, 0, good, strlen(good), 1792627000, 0, &rows, &rts, err,
                           sizeof(err)), 0);
#undef GH
#undef GEND
#undef GEV
    web_fleet_destroy(&F);
}

/* The pull: a current peer is asked with gnss=1, its incidents stored as
 * gnss_event sightings keyed type|first_seen and its receiver sampled
 * fresh with its incidents offered; an I5 peer refuses gnss=1, is asked
 * again with next=1&own=1 at once, its rows stored, its receiver sampled
 * without incidents (evok 0), and not asked with gnss=1 for the hour.
 * The I5 sample's evok 0 was seen red with evok taken without the end
 * line's gnss_event count (1 then: an I5 peer's silence read as quiet). */
static void test_gnss_pull_and_mixed_versions(void) {
    peer_srv_t srv;
    pthread_t th;
    here_up(&srv, &th);
    gnss_incidents(g_db);
    web_gnss_t *g = malloc(sizeof(*g));
    WT_ASSERT(g && web_gnss_init(g) == 0);
    gnss_feed(g, T - 5, 33.32910, -111.86995, 20);
    srv.src.gnss = g;
    WT_EQ(web_fleet_pull_one(&F, 0, T), 0);
    WT_ASSERT(!strcmp(srv.req[0], "since=0&next=1&own=1&gnss=1&adsb=1&ident=1"));
    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM peer_sightings WHERE kind='gnss_event'"
             " AND key='GNSS_JAMMING|%lld' AND last_seen=%lld AND extra LIKE '%%\"count\":7%%'",
             T - 3000, T - 2900);
    WT_EQ(here_q(sql), 1);
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='gnss_event'"), 3);
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='gnss' AND"
                 " extra LIKE '%\"fix_lat\":33.3291000%'"), 1);
    int sl = web_fg_slot(F.fg, "beta");
    WT_ASSERT(sl > 0);
    web_fg_site_t *fs = &F.fg->site[sl];
    WT_EQ(fs->n, 1);
    const web_fg_sample_t *smp = &fs->ring[0];
    WT_EQ(smp->fresh, 1);
    WT_EQ(smp->evok, 1);
    WT_EQ(smp->has_fix, 1);
    WT_EQ(smp->tracked, 3);
    WT_EQ(smp->off_ms, 20);
    WT_EQ(smp->skew, 0);
    WT_EQ(fs->nev, 1);
    /* Now an I5 build. */
    srv.i5 = 1;
    int n0 = srv.n;
    WT_EQ(web_fleet_pull_one(&F, 0, T + 60), 0);
    WT_ASSERT(srv.n >= n0 + 4);
    char want[96];
    snprintf(want, sizeof(want), "since=%lld&next=1&own=1&gnss=1&adsb=1&ident=1",
             T - WEB_FLEET_OVERLAP_S);
    WT_ASSERT(!strcmp(srv.req[n0], want));
    snprintf(want, sizeof(want), "since=%lld&next=1&own=1&gnss=1&adsb=1", T - WEB_FLEET_OVERLAP_S);
    WT_ASSERT(!strcmp(srv.req[n0 + 1], want));
    snprintf(want, sizeof(want), "since=%lld&next=1&own=1&gnss=1", T - WEB_FLEET_OVERLAP_S);
    WT_ASSERT(!strcmp(srv.req[n0 + 2], want));
    snprintf(want, sizeof(want), "since=%lld&next=1&own=1", T - WEB_FLEET_OVERLAP_S);
    WT_ASSERT(!strcmp(srv.req[n0 + 3], want));
    WT_ASSERT(F.peer[0].no_gnss_until > T + 60);
    WT_EQ(F.peer[0].no_own_until, 0);
    WT_EQ(F.peer[0].failures, 0);
    WT_EQ(fs->n, 2);
    WT_EQ(fs->ring[1].fresh, 1);
    WT_EQ(fs->ring[1].evok, 0);
    WT_EQ(fs->ring[1].has_trk, 0);
    WT_EQ(fs->ring[1].has_fix, 0);
    /* Within the hour: one request, without gnss=1. */
    n0 = srv.n;
    WT_EQ(web_fleet_pull_one(&F, 0, T + 120), 0);
    WT_LACKS(srv.req[n0], "gnss=");
    WT_HAS(srv.req[n0], "&own=1");
    /* Current again, with more incidents changed since the last pull
     * than the cap: the lines are stored and the receiver sampled fresh,
     * but not as offering its incidents, so the span is closed there.
     * Seen red with evok taken from the end line's count alone. */
    srv.i5 = 0;
    F.peer[0].no_gnss_until = 0;
    snprintf(sql, sizeof(sql),
             "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<300)"
             " INSERT INTO alert_incidents (key,incident_id,type,first_seen,last_seen,sev,"
             "peak_sev,count,observations) SELECT 'gnssjam','m'||i,%d,%lld+i,%lld+i,"
             "1,1,1,1 FROM n;", web_akb_find("GNSS_JAMMING"), T, T);
    WT_EQ(sdb_exec(g_db, sql), 0);
    WT_EQ(web_fleet_pull_one(&F, 0, T + 180), 0);
    WT_EQ(fs->n, 4);
    WT_EQ(fs->ring[3].fresh, 1);
    WT_EQ(fs->ring[3].evok, 0);
    WT_EQ(fs->ev_open, 0);
    here_down(&srv, th);
    web_gnss_destroy(g);
    free(g);
}

/* The skew against a slow peer (#196), on the real pull: ten quick pulls
 * of a peer whose clock is this one's, then one it holds 5 s before
 * answering, its generated 5 s on. The skew is measured at the
 * request's middle and judged against 2 s plus half the round trip, so
 * the slow pull's 3 s step (its generated less the middle) is not a
 * clock that moved; a quick pull 3 s ahead then is. Seen red with the
 * allowance dropped (the slow pull read as moved) and with the skew
 * taken from the request's start instead of its middle (the same). */
static char *gnss_get(const web_fleet_src_t *src, const char *q, long long now);

static void test_gnss_skew_slow_peer(void) {
    peer_srv_t srv;
    pthread_t th;
    here_up(&srv, &th);
    web_gnss_t *g = malloc(sizeof(*g));
    WT_ASSERT(g && web_gnss_init(g) == 0);
    srv.src.gnss = g;
    web_fleet_src_t none;
    memset(&none, 0, sizeof(none));
    int sl = -1;
    for (int k = 0; k < 12; k++) {
        long long now = T + 60LL * k;
        long long ahead = k == 10 ? 5 : k == 11 ? 3 : 0;
        gnss_feed(g, now + ahead - 5, 33.32910, -111.86995, 20);
        srv_set(&srv, now + ahead, k == 10 ? 5000 : 0);
        WT_EQ(web_fleet_pull_one(&F, 0, now), 0);
        sl = web_fg_slot(F.fg, "beta");
        WT_ASSERT(sl > 0);
        const web_fg_site_t *fs = &F.fg->site[sl];
        const web_fg_sample_t *r = &fs->ring[(fs->head + WEB_FG_RING - 1) % WEB_FG_RING];
        WT_EQ(r->has_ms, 1);
        WT_EQ(r->fresh, 1);
        if (k < 10) WT_ASSERT(r->rtt_ms >= 0 && r->rtt_ms < 1000);
        if (k < 10) WT_ASSERT(r->skew_ms > -500 && r->skew_ms <= 500);
        if (k == 10) {
            WT_ASSERT(r->rtt_ms >= 5000 && r->rtt_ms < 9000);
            /* 5,500 less the middle, about 2,500 in. */
            WT_ASSERT(r->skew_ms >= 1000 && r->skew_ms <= 3500);
            WT_EQ(r->skew, 5);
            WT_EQ(F.peer[0].rtt_ms, r->rtt_ms);
            char *b = gnss_get(&none, NULL, now);
            WT_HAS(b, "\"skew_moved\":false");
            WT_LACKS(b, "\"skew_moved\":true");
            WT_ASSERT(b && strstr(b, "\"rtt_ms\":5") != NULL);
            free(b);
        }
        if (k == 11) {
            char *b = gnss_get(&none, NULL, now);
            WT_HAS(b, "\"skew_moved\":true");
            free(b);
        }
    }
    here_down(&srv, th);
    web_gnss_destroy(g);
    free(g);
}

/* Samples every 60 s over two hours at both sites, both fixed: W9FJC
 * ("self") at 33.32922,-111.87006 and beta at 33.32910,-111.86995, 16.8 m
 * apart, eph 4.5 each, offsets -60 and 20 ms. beta's clock 100 s ahead. */
static void gnss_two_sites(web_fleet_t *f, long long from, long long to) {
    web_fg_sample_t s;
    for (int site = 0; site < 2; site++) {
        int sl = web_fg_slot(f->fg, site ? "beta" : "self");
        for (long long t = from; t <= to; t += 60) {
            memset(&s, 0, sizeof(s));
            s.t = t;
            s.fresh = s.evok = s.has_trk = 1;
            s.gts = t + (site ? 100 : 0);
            s.skew = site ? 100 : 0;
            snprintf(s.state, sizeof(s.state), "fix");
            s.sats_used = 9;
            s.sats_view = 16;
            s.has_cn0 = 1;
            s.cn0_mean = 25;
            s.tracked = 9;
            s.cn0_med = 38;
            s.jam = 10;
            s.has_off = 1;
            s.off_ms = site ? 20 : -60;
            s.has_fix = 1;
            s.mode = 3;
            s.lat = site ? 33.32910 : 33.32922;
            s.lon = site ? -111.86995 : -111.87006;
            s.has_eph = 1;
            s.eph = 4.5;
            s.has_hdop = 1;
            s.hdop = 1.2;
            web_fg_add(f->fg, sl, &s, 150);
        }
    }
}

static char *gnss_get(const web_fleet_src_t *src, const char *q, long long now) {
    char *body = NULL;
    size_t len = 0;
    int st = 0;
    WT_EQ(web_fleet_gnss_route(&F, src, q, now, &body, &len, &st), 0);
    WT_EQ(st, 200);
    char *b = body ? realloc(body, len + 1) : NULL;
    if (b) b[len] = '\0';
    else free(body);
    WT_LACKS(b, "nan");
    WT_LACKS(b, "inf");
    return b;
}

/* GET /api/fleet/gnss over a sloth.db (this site's incidents), a store
 * (beta's incidents, by beta's clock, 100 s ahead) and two hours of
 * samples at each site:
 *   - the jam here at T-3000..T-2900 and beta's at its T-2850..T-2750
 *     (ours T-2950..T-2850): regional, each naming the other;
 *   - the position jump here at T-1500, beta covered and silent: local;
 *   - the spoof suspect here at T-9000, before beta's coverage began:
 *     undetermined, beta stale;
 *   - beta's time jump at T-600 (its clock T-500): local to beta.
 * The baseline: 16.8 m now as at the references, bound 27 m: within, the
 * position consistent. Then beta's fix moves 50 m north (eph 4.5, its
 * own bound 13.5 m): outside, beta named, the pair "outside" with beta
 * moved. Time: beta's offset steps 2000 ms at the last sample, ours
 * does not: one_site beta. The overview carries the verdicts and the
 * day's counts. Seen red with the pair's `moved` taking a site whenever
 * the pair is outside (self then listed beside beta), with the region
 * test inverted (every verdict changed), with web_fg_covered() always 1
 * (the spoof suspect then local), with the skew left out of a peer's
 * incident times (beta's events printed 100 s late), and with the
 * no-sloth.db case's ev_none ignored (beta's time jump then local on a
 * site whose incidents were never read). */
static void test_gnss_route(void) {
    up();
    gnss_incidents(g_db);
    web_fleet_peer_cfg_t pc;
    char err[256];
    WT_EQ(web_fleet_parse_peer("beta=http://127.0.0.1:1", &pc, err, sizeof(err)), 0);
    web_fleet_init(&F, &pc, 1, 60, 1, &S);
    WT_EQ(web_store_open_aux(&S, &F.wr, err, sizeof(err)), 0);
    char sql[2048];
    snprintf(sql, sizeof(sql),
        "INSERT INTO peer_sites (peer,url,label,last_attempt,last_ok,last_error,lat,lon,"
        "remote_ts) VALUES ('beta','http://127.0.0.1:1','beta-site',%lld,%lld,'',33.3291,"
        "-111.86995,%lld);"
        "INSERT INTO peer_sightings (peer,kind,key,label,vendor,rssi,first_seen,last_seen,extra)"
        " VALUES ('beta','gnss_event','GNSS_JAMMING|%lld','GNSS_JAMMING','',NULL,%lld,%lld,"
        "'{\"count\":3,\"sev\":1}'),"
        " ('beta','gnss_event','GNSS_TIME_JUMP|%lld','GNSS_TIME_JUMP','',NULL,%lld,%lld,"
        "'{\"count\":1,\"sev\":1}');",
        T, T, T + 100, T - 2850, T - 2850, T - 2750, T - 500, T - 500, T - 500);
    WT_EQ(sql_on(g_store, sql), 0);
    gnss_two_sites(&F, T - 7200, T);
    web_fleet_src_t src = { &SDB, NULL, NULL, &FR, NULL, NULL, NULL, NULL };
    char *b = gnss_get(&src, "", T);
    WT_HAS(b, "\"local\":\"open\"");
    WT_HAS(b, "\"window_s\":120,\"gap_s\":150,\"region_m\":50000,");
    char want[512];
    snprintf(want, sizeof(want), "{\"site\":\"self\",\"type\":\"GNSS_JAMMING\",\"class\":"
             "\"interference\",\"source\":\"incident\",\"first_seen\":%lld,\"last_seen\":%lld,"
             "\"count\":7,\"sev\":2,\"verdict\":\"regional\",\"with\":[\"beta\"],\"quiet\":[],"
             "\"stale\":[],\"far\":[]}", T - 3000, T - 2900);
    WT_HAS(b, want);
    snprintf(want, sizeof(want), "{\"site\":\"beta\",\"type\":\"GNSS_JAMMING\",\"class\":"
             "\"interference\",\"source\":\"incident\",\"first_seen\":%lld,\"last_seen\":%lld,"
             "\"count\":3,\"sev\":1,\"verdict\":\"regional\",\"with\":[\"self\"]",
             T - 2950, T - 2850);
    WT_HAS(b, want);
    snprintf(want, sizeof(want), "\"type\":\"GNSS_POSITION_JUMP\",\"class\":\"position\","
             "\"source\":\"incident\",\"first_seen\":%lld,\"last_seen\":%lld,\"count\":1,"
             "\"sev\":1,\"verdict\":\"local\",\"with\":[],\"quiet\":[\"beta\"]", T - 1500, T - 1500);
    WT_HAS(b, want);
    snprintf(want, sizeof(want), "\"type\":\"GNSS_SPOOF_SUSPECT\",\"class\":\"spoof\","
             "\"source\":\"incident\",\"first_seen\":%lld,\"last_seen\":%lld,\"count\":1,"
             "\"sev\":1,\"verdict\":\"undetermined\",\"with\":[],\"quiet\":[],\"stale\":[\"beta\"]",
             T - 9000, T - 9000);
    WT_HAS(b, want);
    snprintf(want, sizeof(want), "{\"site\":\"beta\",\"type\":\"GNSS_TIME_JUMP\",\"class\":"
             "\"time\",\"source\":\"incident\",\"first_seen\":%lld,\"last_seen\":%lld,"
             "\"count\":1,\"sev\":1,\"verdict\":\"local\",\"with\":[],\"quiet\":[\"self\"]",
             T - 600, T - 600);
    WT_HAS(b, want);
    /* The deauth key's incident (a GNSS type) is not this site's. */
    snprintf(want, sizeof(want), "\"first_seen\":%lld", T - 100);
    WT_LACKS(b, want);
    WT_HAS(b, "\"counts\":{\"regional\":2,\"local\":2,\"undetermined\":1}");
    WT_HAS(b, "\"baseline\":[{\"a\":\"self\",\"b\":\"beta\",\"ref_m\":16.8,\"now_m\":16.8,"
              "\"delta_m\":0.0,\"bound_m\":27.0,\"verdict\":\"within\",\"why\":null,"
              "\"moved\":[]}]");
    WT_HAS(b, "\"position\":{\"verdict\":\"consistent\",\"site\":null,\"evaluated\":2}");
    WT_HAS(b, "\"time\":{\"verdict\":\"consistent\",\"site\":null,\"evaluated\":2}");
    WT_HAS(b, "\"reference\":{\"n\":13,\"lat\":33.3292200,\"lon\":-111.8700600,"
              "\"displacement_m\":0.0,\"bound_m\":13.5,\"outside\":false}");
    WT_HAS(b, "\"basis\":{\"interference\":\"Interference shows as C/N0 collapsing");
    free(b);
    /* beta moves 50 m north and its clock offset steps 2 s. */
    web_fg_sample_t s;
    int sl = web_fg_slot(F.fg, "beta");
    s = F.fg->site[sl].ring[(F.fg->site[sl].head + WEB_FG_RING - 1) % WEB_FG_RING];
    s.t = T + 60;
    s.gts = T + 160;
    s.lat += 50.0 / 111194.9;
    s.off_ms = 2020;
    web_fg_add(F.fg, sl, &s, 150);
    b = gnss_get(&src, "limit=1", T + 60);
    /* North, away from self: the distance grows 21.2 m, inside the
     * pair's 27 m, but beta is past its own 13.5 m and named. */
    WT_HAS(b, "\"ref_m\":16.8,\"now_m\":38.1,\"delta_m\":21.2,\"bound_m\":27.0,"
              "\"verdict\":\"within\",\"why\":null,\"moved\":[\"beta\"]");
    WT_HAS(b, "\"position\":{\"verdict\":\"one_site\",\"site\":\"beta\",\"evaluated\":2}");
    WT_HAS(b, "\"time\":{\"verdict\":\"one_site\",\"site\":\"beta\",\"evaluated\":2}");
    WT_HAS(b, "\"time\":{\"ref_ms\":20,\"now_ms\":2020,\"step_ms\":2000,\"stepped\":true,"
              "\"skew_ref_s\":100,\"skew_step_s\":0,\"skew_step_ms\":0,\"rtt_ms\":null,"
              "\"skew_moved\":false}");
    WT_HAS(b, "\"displacement_m\":50.0,\"bound_m\":13.5,\"outside\":true}");
    WT_EQ(count_of(b, "{\"site\":\"self\",\"type\""), 0);    /* limit=1: beta's newest */
    free(b);
    /* South instead, past self: the distance grows past the bound. */
    s.t = T + 120;
    s.gts = T + 220;
    s.lat -= 100.0 / 111194.9;
    web_fg_add(F.fg, sl, &s, 150);
    b = gnss_get(&src, "limit=1", T + 120);
    WT_HAS(b, "\"verdict\":\"outside\",\"why\":null,\"moved\":[\"beta\"]");
    WT_HAS(b, "\"position\":{\"verdict\":\"one_site\",\"site\":\"beta\",\"evaluated\":2}");
    free(b);
    /* The overview's compact verdicts. */
    static char ob[65536];
    size_t ol = 0;
    int st = 0;
    WT_EQ(web_fleet_overview_route(&F, &src, "", T + 60, ob, sizeof(ob) - 1, &ol, &st), 0);
    ob[ol] = '\0';
    WT_HAS(ob, ",\"gnss\":{\"position\":{\"verdict\":\"one_site\",\"site\":\"beta\",\"evaluated\":2},"
               "\"time\":{\"verdict\":\"one_site\",\"site\":\"beta\",\"evaluated\":2},"
               "\"events_24h\":{\"regional\":2,\"local\":2,\"undetermined\":1}}");
    /* Bad queries. */
    char *body = NULL;
    size_t len = 0;
    WT_EQ(web_fleet_gnss_route(&F, &src, "limit=0", T, &body, &len, &st), 0);
    WT_EQ(st, 400);
    free(body);
    WT_EQ(web_fleet_gnss_route(&F, &src, "x=1", T, &body, &len, &st), 0);
    WT_EQ(st, 400);
    free(body);
    /* No sloth.db here: this site's incidents unknown, so beta's time
     * jump, which this site was "quiet" for, becomes undetermined. */
    /* A sample no importer would take (a NaN latitude, an infinite eph),
     * put straight into the ring: still no nan or inf in the answer
     * (gnss_get()'s check). Seen red with jnum()'s isfinite() dropped. */
    s.t = T + 180;
    s.lat = NAN;
    s.eph = INFINITY;
    web_fg_add(F.fg, web_fg_slot(F.fg, "self"), &s, 150);
    b = gnss_get(&src, "", T + 180);
    WT_HAS(b, "\"fix\":{\"lat\":null,");
    free(b);
    /* An eph of 0 is no estimate: no 0 m bound, so no "moved" on any
     * metre of noise. Seen red with has_cur taking eph >= 0 (beta, 1 m
     * from its reference, then outside a 0 m bound and named). */
    s = F.fg->site[sl].ring[(F.fg->site[sl].head + WEB_FG_RING - 3) % WEB_FG_RING];
    s.t = T + 240;
    s.gts = T + 340;
    s.lat += 1.0 / 111194.9;
    s.eph = 0;
    web_fg_add(F.fg, sl, &s, 150);
    s.t = T + 240;
    s.lat = 33.32922;
    s.eph = 4.5;
    web_fg_add(F.fg, web_fg_slot(F.fg, "self"), &s, 150);
    b = gnss_get(&src, "", T + 240);
    WT_HAS(b, "\"displacement_m\":null,\"bound_m\":null,\"outside\":null}");
    WT_HAS(b, "\"why\":\"no_current_fix\"");
    WT_LACKS(b, "\"moved\":[\"beta\"]");
    free(b);
    web_fleet_src_t nos = { NULL, NULL, NULL, &FR, NULL, NULL, NULL, NULL };
    b = gnss_get(&nos, "", T + 60);
    WT_HAS(b, "\"local\":\"none\"");
    snprintf(want, sizeof(want), "{\"site\":\"beta\",\"type\":\"GNSS_TIME_JUMP\",\"class\":"
             "\"time\",\"source\":\"incident\",\"first_seen\":%lld,\"last_seen\":%lld,"
             "\"count\":1,\"sev\":1,\"verdict\":\"undetermined\",\"with\":[],\"quiet\":[],"
             "\"stale\":[\"self\"]", T - 600, T - 600);
    WT_HAS(b, want);
    free(b);
    web_fleet_destroy(&F);
    down();
}

/* The events the samples show, through the route with no store and no
 * sloth.db: the tracked median falling from 38 to 20 dB-Hz at both sites
 * over the same 40 minutes (an 18 dB drop, past 10 dB under each site's
 * own hour): a CN0_DROP each, regional; the jamming indicator at 200
 * here alone for three minutes to T, past the window from beta's drop:
 * undetermined at T (beta not yet pulled past its window), local at
 * T + 120 with beta seen all along; a 1 dB dip is no event. The
 * drop's own samples are kept out of the median it is measured against,
 * so a drop standing longer than half the hour stays one event to its
 * end: seen red with that exclusion removed (the median then reached
 * 20 dB-Hz after half an hour and the event ended at T-960, not
 * T-360). */
static void test_gnss_sample_events(void) {
    web_fleet_peer_cfg_t pc;
    char err[256];
    WT_EQ(web_fleet_parse_peer("beta=http://127.0.0.1:1", &pc, err, sizeof(err)), 0);
    web_fleet_init(&F, &pc, 1, 60, 1, NULL);
    gnss_two_sites(&F, T - 9000, T - 3000);
    int sl[2] = { web_fg_slot(F.fg, "self"), web_fg_slot(F.fg, "beta") };
    for (long long t = T - 2940; t <= T + 120; t += 60) {
        if (t == T + 60) {
            /* At T the indicator's window has not closed at beta's last
             * pull: no quiet peer yet. */
            char *b0 = gnss_get(&(web_fleet_src_t){ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }, "", T);
            char want0[512];
            snprintf(want0, sizeof(want0), "{\"site\":\"self\",\"type\":\"JAM_IND\",\"class\":"
                     "\"interference\",\"source\":\"sample\",\"first_seen\":%lld,"
                     "\"last_seen\":%lld,\"count\":0,\"sev\":1,\"verdict\":\"undetermined\","
                     "\"with\":[],\"quiet\":[],\"stale\":[\"beta\"]", T - 180, T);
            WT_HAS(b0, want0);
            free(b0);
        }
        for (int i = 0; i < 2; i++) {
            web_fg_site_t *fs = &F.fg->site[sl[i]];
            web_fg_sample_t s = fs->ring[(fs->head + WEB_FG_RING - 1) % WEB_FG_RING];
            s.t = t;
            s.gts = t + s.skew;
            s.cn0_med = t >= T - 2700 && t < T - 300 ? 20 : t == T - 120 ? 37 : 38;
            s.jam = i == 0 && t >= T - 180 && t <= T ? 200 : 10;
            web_fg_add(F.fg, sl[i], &s, 150);
        }
    }
    web_fleet_src_t src = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
    char *b = gnss_get(&src, "", T + 120);
    char want[512];
    snprintf(want, sizeof(want), "{\"site\":\"self\",\"type\":\"CN0_DROP\",\"class\":"
             "\"interference\",\"source\":\"sample\",\"first_seen\":%lld,\"last_seen\":%lld,"
             "\"count\":0,\"sev\":1,\"verdict\":\"regional\",\"with\":[\"beta\"]", T - 2700, T - 360);
    WT_HAS(b, want);
    snprintf(want, sizeof(want), "{\"site\":\"beta\",\"type\":\"CN0_DROP\",\"class\":"
             "\"interference\",\"source\":\"sample\",\"first_seen\":%lld,\"last_seen\":%lld,"
             "\"count\":0,\"sev\":1,\"verdict\":\"regional\",\"with\":[\"self\"]", T - 2700, T - 360);
    WT_HAS(b, want);
    snprintf(want, sizeof(want), "{\"site\":\"self\",\"type\":\"JAM_IND\",\"class\":"
             "\"interference\",\"source\":\"sample\",\"first_seen\":%lld,\"last_seen\":%lld,"
             "\"count\":0,\"sev\":1,\"verdict\":\"local\",\"with\":[],\"quiet\":[\"beta\"]",
             T - 180, T);
    WT_HAS(b, want);
    WT_EQ(count_of(b, "\"type\":\"CN0_DROP\""), 2);
    WT_EQ(count_of(b, "\"type\":\"JAM_IND\""), 1);
    WT_HAS(b, "\"local\":\"none\",\"store\":false");
    free(b);
    web_fleet_destroy(&F);
}

/* Each site's coverage and reference go to meta at the tick and come
 * back at a restart (web_fleet_load()); the ring does not. This site's
 * own sample with no receiver is stale: no span. */
static void test_gnss_state_survives_a_restart(void) {
    up();
    web_fleet_peer_cfg_t pc;
    char err[256];
    WT_EQ(web_fleet_parse_peer("beta=http://127.0.0.1:1", &pc, err, sizeof(err)), 0);
    web_fleet_init(&F, &pc, 1, 60, 1, &S);
    WT_EQ(web_store_open_aux(&S, &F.wr, err, sizeof(err)), 0);
    gnss_two_sites(&F, T - 7200, T);
    /* beta's indicator high at T + 30: a sample event, saved with the
     * rest. */
    int b0 = web_fg_slot(F.fg, "beta");
    web_fg_sample_t hi = F.fg->site[b0].ring[(F.fg->site[b0].head + WEB_FG_RING - 1) % WEB_FG_RING];
    hi.t = T + 30;
    hi.jam = 200;
    web_fg_add(F.fg, b0, &hi, 150);
    web_fleet_gnss_tick(&F, T + 30);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM meta WHERE name IN ('fleet.gnss.self',"
                      "'fleet.gnss.beta')"), 2);
    int sl = web_fg_slot(F.fg, "self");
    WT_EQ(F.fg->site[sl].nrx, 1);              /* the tick's stale sample added none */
    int nref = F.fg->site[web_fg_slot(F.fg, "beta")].nref;
    web_fleet_destroy(&F);
    web_fleet_init(&F, &pc, 1, 60, 1, &S);
    WT_EQ(web_store_open_aux(&S, &F.wr, err, sizeof(err)), 0);
    web_fleet_load(&F);
    int b = web_fg_slot(F.fg, "beta");
    WT_EQ(F.fg->site[b].nref, nref);
    WT_EQ(F.fg->site[b].nrx, 1);
    WT_EQ(F.fg->site[b].rx_s[0], T - 6600);      /* the drop test's ten before it */
    WT_EQ(F.fg->site[b].n, 0);
    /* The sample event came back with the coverage: a restart (or the
     * ring's eight hours) does not leave beta covered with its event
     * gone, which would read beta quiet. Seen red with the "se" part
     * left out of the saved state. */
    WT_EQ(F.fg->site[b].nse, 1);
    WT_EQ(F.fg->site[b].se_a[0], T + 30);
    /* With the references back, the baseline needs only a fresh fix. */
    gnss_two_sites(&F, T + 60, T + 60);
    web_fleet_src_t src = { &SDB, NULL, NULL, &FR, NULL, NULL, NULL, NULL };
    char *body = gnss_get(&src, "", T + 60);
    WT_HAS(body, "\"verdict\":\"within\"");
    free(body);
    web_fleet_destroy(&F);
    down();
}

/* A move held past half the week becomes the reference (#196): beta's
 * fixes at A ten times, a reference sample each 600 s, then at B 100 m
 * north. The reference median stays at A through nine fixes at B; at
 * ten of twenty it is the midpoint (the median of an even count), 50 m
 * on, and at eleven it is B. The move is announced once, at its whole
 * 100 m, when the median has settled on B (eleven and twelve), never as
 * the halfway 50 m. The route says when and how far, and the
 * record survives a restart through meta "fleet.gnssref.beta" (a build
 * before it reads "fleet.gnss.beta" unchanged). Seen red with ref_note()
 * not called (reference_moved_at stayed null while the reference sat on
 * B), with the move's test made always false (the same), and with the
 * settling dropped (50.0 at the midpoint, then 50.0 again). */
static void test_gnss_reference_moved(void) {
    up();
    web_fleet_peer_cfg_t pc;
    char err[256];
    WT_EQ(web_fleet_parse_peer("beta=http://127.0.0.1:1", &pc, err, sizeof(err)), 0);
    web_fleet_init(&F, &pc, 1, 60, 1, &S);
    WT_EQ(web_store_open_aux(&S, &F.wr, err, sizeof(err)), 0);
    int sl = web_fg_slot(F.fg, "beta");
    web_fg_sample_t s;
    memset(&s, 0, sizeof(s));
    s.fresh = s.has_fix = s.has_eph = 1;
    s.mode = 3;
    s.eph = 4.5;
    s.lon = -111.86995;
    web_fleet_src_t none;
    memset(&none, 0, sizeof(none));
    long long t = T - 22 * 600;
    for (int k = 0; k < 22; k++, t += 600) {
        s.t = s.gts = s.fix_ts = t;
        s.lat = 33.32910 + (k < 10 ? 0 : 100.0 / 111194.9);
        web_fg_add(F.fg, sl, &s, 1300);
        char *b = gnss_get(&none, "", t);
        if (k == 18) {
            WT_HAS(b, "\"reference_moved_at\":null,\"reference_moved_m\":null");
            WT_HAS(b, "\"reference\":{\"n\":19,\"lat\":33.3291000,");
        }
        if (k == 20) WT_HAS(b, "\"reference_moved_at\":null,\"reference_moved_m\":null");
        if (k >= 21) {
            char want[96];
            snprintf(want, sizeof(want), "\"reference_moved_at\":%lld,\"reference_moved_m\":100.0",
                     t);
            WT_HAS(b, want);
        }
        free(b);
    }
    long long at = F.fg->site[sl].moved_at;
    WT_EQ(at, t - 600);
    WT_ASSERT(fabs(F.fg->site[sl].anc_lat - (33.32910 + 100.0 / 111194.9)) < 1e-7);
    web_fleet_gnss_tick(&F, t);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM meta WHERE name='fleet.gnssref.beta'"), 1);
    web_fleet_destroy(&F);
    web_fleet_init(&F, &pc, 1, 60, 1, &S);
    WT_EQ(web_store_open_aux(&S, &F.wr, err, sizeof(err)), 0);
    web_fleet_load(&F);
    sl = web_fg_slot(F.fg, "beta");
    WT_EQ(F.fg->site[sl].moved_at, at);
    WT_ASSERT(fabs(F.fg->site[sl].moved_m - 100.0) < 0.1);
    WT_EQ(F.fg->site[sl].has_anc, 1);
    /* A value it did not write is not taken. */
    web_fg_site_t z;
    memset(&z, 0, sizeof(z));
    WT_EQ(web_fg_ref_parse(&z, "33.3 -111.8 5"), -1);
    WT_EQ(web_fg_ref_parse(&z, "91 -111.8 5 1.0"), -1);
    WT_EQ(web_fg_ref_parse(&z, "33.3 -111.8 5 1.0 x"), -1);
    WT_EQ(z.has_anc, 0);
    WT_EQ(web_fg_ref_parse(&z, "33.3 -111.8 5 1.0"), 0);
    WT_EQ(z.moved_at, 5);
    web_fleet_destroy(&F);
    down();
}

/* ── #192 I7: aircraft across the sites ────────────────────────────── */

#define AC_MDEG 111194.9              /* metres in a degree of latitude */
#define BETA_LAT 33.32910
#define BETA_LON (-111.86995)
#define SELF_LAT 33.32922
#define SELF_LON (-111.87006)

/* One adsb_aircraft row and its sightings as sloth writes them. */
static void ac_put(const char *db, const char *hex, long long first, long long vf,
                   long long last, const char *flight) {
    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT INTO adsb_aircraft (hex,non_icao,first_seen,last_seen,visit_first,visits,"
        "sightings,flight,squawk,category,source_type,messages,pos_seen) VALUES"
        " ('%s',%d,%lld,%lld,%lld,1,1,'%s','4175','A3','adsb_icao',307,1);",
        hex, hex[0] == '~', first, last, vf, flight);
    WT_EQ(sdb_exec(db, sql), 0);
}

/* A sighting north of (lat0, lon0) at north_m, or with no position
 * (north_m < 0). */
static void ac_sight(const char *db, const char *hex, long long ts, double lat0, double lon0,
                     double north_m, int alt, const char *gs, int ground) {
    char sql[640], pos[96] = "NULL,NULL";
    if (north_m >= 0)
        snprintf(pos, sizeof(pos), "%.7f,%.7f", lat0 + north_m / AC_MDEG, lon0);
    snprintf(sql, sizeof(sql),
        "INSERT INTO adsb_sightings (last_seen,hex,heard,flight,squawk,emergency,category,"
        "on_ground,alt_baro,alt_band,gs,track,lat,lon,rssi,messages,source_type) VALUES"
        " (%lld,'%s',%lld,'SWA4754','4175','none','A3',%d,%d,9,%s,136.0,%s,-20.1,300,"
        "'adsb_icao');", ts, hex, ts, ground, alt, gs, pos);
    WT_EQ(sdb_exec(db, sql), 0);
}

static void adsb_rx(web_adsb_t *a, long long ts, long long msgs) {
    pthread_mutex_lock(&a->mu);
    a->sh.seen = 1;
    a->sh.ts = ts;
    snprintf(a->sh.state, sizeof(a->sh.state), "live");
    snprintf(a->sh.src, sizeof(a->sh.src), "file:/run/readsb/aircraft.json");
    a->sh.aircraft = 13;
    a->sh.messages = msgs;
    pthread_mutex_unlock(&a->mu);
}

static void site_at(web_gnss_t *g, double lat, double lon) {
    WT_EQ(web_gnss_init(g), 0);
    g->loc.has = 1;
    g->loc.lat = lat;
    g->loc.lon = lon;
    g->loc.has_alt = 1;
    g->loc.alt_m = 364.6;
    g->loc.ts = T;
    snprintf(g->loc.src, sizeof(g->loc.src), "fixed");
}

/* The peer's sky in sloth.db: a00001 (this visit's newest position at
 * T-500, 20 km north, then a newer sighting with no position), a00002
 * (its only position from an earlier visit: none sent), a00004 (gs
 * stored as infinity: sent as null), a0000f (last seen 7 h ago: not
 * sent), and the coverage: ten positions 30 km north, one 60 km north
 * on the ground and one 2 days old (neither counted). */
static void peer_sky(const char *db) {
    ac_put(db, "a00001", T - 5000, T - 900, T - 100, "SWA4754");
    ac_sight(db, "a00001", T - 900, BETA_LAT, BETA_LON, 15000, 5000, "250.0", 0);
    ac_sight(db, "a00001", T - 500, BETA_LAT, BETA_LON, 20000, 8875, "279.4", 0);
    ac_sight(db, "a00001", T - 100, BETA_LAT, BETA_LON, -1, 9000, "280.0", 0);
    ac_put(db, "a00002", T - 4100, T - 300, T - 200, "SKW6344");
    ac_sight(db, "a00002", T - 4000, BETA_LAT, BETA_LON, 25000, 9000, "300.0", 0);
    ac_sight(db, "a00002", T - 250, BETA_LAT, BETA_LON, -1, 9000, "300.0", 0);
    ac_put(db, "a00004", T - 400, T - 400, T - 300, "ASI72");
    ac_sight(db, "a00004", T - 300, BETA_LAT, BETA_LON, 5000, 2000, "9e999", 0);
    ac_put(db, "a0000f", T - 30000, T - 30000, T - 7 * 3600, "OLD1");
    for (int i = 0; i < 10; i++)
        ac_sight(db, "a0000f", T - 7 * 3600 - 60 * i, BETA_LAT, BETA_LON, 30000, 30000, "400.0", 0);
    ac_sight(db, "a00004", T - 380, BETA_LAT, BETA_LON, 60000, 0, "10.0", 1);
    ac_sight(db, "a00004", T - 2 * DY, BETA_LAT, BETA_LON, 70000, 30000, "400.0", 0);
}

static char *export_q(const web_fleet_src_t *src, const char *q) {
    char *body = NULL;
    size_t len = 0;
    int st = 0;
    WT_EQ(web_fleet_export_route(src, q, T, &body, &len, &st), 0);
    WT_EQ(st, 200);
    if (!body) return NULL;
    char *t = realloc(body, len + 1);
    if (!t) { free(body); return NULL; }
    t[len] = '\0';
    return t;
}

static int ingest_ok(const char *b) {
    web_fleet_t f;
    web_fleet_peer_cfg_t pc;
    char err[160];
    WT_EQ(web_fleet_parse_peer("beta=http://100.64.0.2:8770", &pc, err, sizeof(err)), 0);
    web_fleet_init(&f, &pc, 1, 60, 0, NULL);
    long long rows = 0, rts = 0;
    int rc = web_fleet_ingest(&f, 0, b, strlen(b), T, 0, &rows, &rts, err, sizeof(err));
    if (rc) fprintf(stderr, "    ingest: %s\n", err);
    web_fleet_destroy(&f);
    return rc;
}

/* The export with adsb=1: the receiver's summary (its source's kind, not
 * its path; messages/s between two summaries 30 s apart) and its
 * coverage (fourteen airborne positions, the farthest 30 km north; one
 * on the ground and one two days old not counted), and the aircraft changed in the
 * last 6 h with the current visit's newest position, every figure range
 * checked, nothing not finite, counted on the end line; the importer
 * takes it whole. Without adsb=1 none of it is sent: an I6 importer
 * refuses a member it does not know (seen red with the aircraft read's
 * `xq.adsb &&` dropped). A row the importer would refuse (a squawk of
 * 8888) is left out and the kind marked truncated, the rest still sent
 * (seen red with opt_end()'s line_takes() made to pass: the 8888 row
 * sent and the whole answer refused). */
static void test_adsb_export(void) {
    up();
    peer_sky(g_db);
    web_gnss_t G;
    site_at(&G, BETA_LAT, BETA_LON);
    web_adsb_t A;
    WT_EQ(web_adsb_init(&A), 0);
    adsb_rx(&A, T - 30, 2247000);
    web_fleet_src_t src = { &SDB, NULL, &G, &FR, NULL, &A, NULL, NULL };
    char *b0 = export_q(&src, "since=0&adsb=1");
    free(b0);
    adsb_rx(&A, T, 2247900);
    char *b = export_q(&src, "since=0&adsb=1");
    WT_ASSERT(b != NULL);
    if (b) {
        WT_HAS(b, "{\"type\":\"adsb_rx\",\"source\":\"file\",\"state\":\"live\",\"ts\":");
        WT_HAS(b, ",\"aircraft\":13,\"messages\":2247900,\"msg_rate\":30.0,\"window_s\":86400,"
                  "\"positions\":14,\"cov_complete\":true,\"range_max_m\":30000,"
                  "\"r000\":25000,\"r030\":null,");
        WT_HAS(b, ",\"n000\":14,\"n030\":0,");
        WT_LACKS(b, "/run/readsb");
        char want[640];
        snprintf(want, sizeof(want),
            "{\"type\":\"aircraft\",\"hex\":\"a00001\",\"flight\":\"SWA4754\",\"squawk\":\"4175\","
            "\"category\":\"A3\",\"emergency\":\"none\",\"alt\":9000,\"on_ground\":false,"
            "\"gs\":280.0,\"track\":136.0,\"rssi\":-20.1,\"messages\":300,\"lat\":33.50896,"
            "\"lon\":-111.86995,\"pos_ts\":%lld,\"pos_prev\":%lld,\"pos_alt\":8875,"
            "\"first_seen\":%lld,\"visit_first\":%lld,\"last_seen\":%lld}\n",
            T - 500, T - 900, T - 5000, T - 900, T - 100);
        WT_HAS(b, want);
        WT_HAS(b, "{\"type\":\"aircraft\",\"hex\":\"a00002\",\"flight\":\"SKW6344\"");
        WT_HAS(b, "\"lat\":null,\"lon\":null,\"pos_ts\":null,\"pos_prev\":null,\"pos_alt\":null,");
        WT_HAS(b, "{\"type\":\"aircraft\",\"hex\":\"a00004\",\"flight\":\"ASI72\"");
        WT_HAS(b, "\"gs\":null");
        WT_LACKS(b, "a0000f");
        WT_LACKS(b, "inf");
        WT_LACKS(b, "nan");
        WT_HAS(b, ",\"aircraft\":3,\"truncated_aircraft\":false,\"complete\":true}\n");
        WT_EQ(ingest_ok(b), 0);
        free(b);
    }
    /* Without adsb=1: the I6 answer. */
    b = export_q(&src, "since=0&next=1&own=1&gnss=1");
    WT_ASSERT(b != NULL);
    if (b) {
        WT_LACKS(b, "adsb_rx");
        WT_LACKS(b, "\"type\":\"aircraft\"");
        WT_LACKS(b, "truncated_aircraft");
        free(b);
    }
    /* No receiver summary and no sloth.db: no adsb_rx line at all, and
     * the aircraft, not read, are cut - never an empty list the
     * comparison would take as "heard none" (seen red, false, with the
     * !ac_read clause removed from the export). */
    web_fleet_src_t none = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
    b = export_q(&none, "since=0&adsb=1");
    if (b) {
        WT_LACKS(b, "adsb_rx");
        WT_HAS(b, ",\"aircraft\":0,\"truncated_aircraft\":true,");
        free(b);
    }
    /* A row the importer would refuse. */
    char sql[256];
    snprintf(sql, sizeof(sql), "UPDATE adsb_aircraft SET squawk='8888' WHERE hex='a00002';"
             "UPDATE adsb_sightings SET squawk='8888' WHERE hex='a00002';");
    WT_EQ(sdb_exec(g_db, sql), 0);
    b = export_q(&src, "since=0&adsb=1");
    if (b) {
        WT_LACKS(b, "a00002");
        WT_HAS(b, "\"hex\":\"a00001\"");
        WT_HAS(b, ",\"aircraft\":2,\"truncated_aircraft\":true,");
        WT_EQ(ingest_ok(b), 0);
        free(b);
    }
    web_adsb_destroy(&A);
    web_gnss_destroy(&G);
    down();
}

static const char AC_LINE[] =
    "{\"type\":\"aircraft\",\"hex\":\"a00001\",\"flight\":\"SWA4754\",\"squawk\":\"4175\","
    "\"category\":\"A3\",\"emergency\":\"none\",\"alt\":9000,\"on_ground\":false,"
    "\"gs\":280.0,\"track\":136.0,\"rssi\":-20.1,\"messages\":300,\"lat\":33.50897,"
    "\"lon\":-111.86995,\"pos_ts\":1792626500,\"pos_prev\":1792626400,\"pos_alt\":8875,"
    "\"first_seen\":1792622000,"
    "\"visit_first\":1792626100,\"last_seen\":1792626900}\n";
#define END_AC(n, cut) "{\"type\":\"fleet_end\",\"rows\":0,\"wifi\":0,\"ble\":0,\"ap\":0," \
    "\"probe\":0,\"alert\":0,\"verdict\":0,\"truncated_wifi\":false,\"truncated_ble\":false," \
    "\"truncated_ap\":false,\"truncated_probe\":false,\"truncated_alert\":false," \
    "\"truncated_verdict\":false,\"aircraft\":" #n ",\"truncated_aircraft\":" #cut "," \
    "\"complete\":true}\n"

/* The importer's checks on the new lines, each refusing the whole
 * answer and writing nothing: an upper-case address, a squawk not four
 * octal digits, a position without its time or the time's lower bound,
 * a lower bound past the time, a position time past the row's last
 * seen, an altitude out of range,
 * an infinite RSSI, a member the type may not carry, a count that is not
 * the lines sent, aircraft lines with no count, a cut without a count,
 * a receiver line's sector out of range. Then the good answer is stored
 * as kind aircraft and kind adsb, and meta holds the answer's clock. */
static void test_adsb_import_refusals(void) {
    pull_up();
    static char body[4096];
    struct { const char *from, *to; const char *end; } bad[] = {
        { "\"hex\":\"a00001\"", "\"hex\":\"A00001\"", END_AC(1, false) },
        { "\"squawk\":\"4175\"", "\"squawk\":\"8888\"", END_AC(1, false) },
        { "\"pos_ts\":1792626500", "\"pos_ts\":null", END_AC(1, false) },
        { "\"pos_prev\":1792626400", "\"pos_prev\":null", END_AC(1, false) },
        { "\"pos_prev\":1792626400", "\"pos_prev\":1792626501", END_AC(1, false) },
        { "\"pos_ts\":1792626500", "\"pos_ts\":1792626901", END_AC(1, false) },
        { "\"alt\":9000", "\"alt\":200000", END_AC(1, false) },
        { "\"rssi\":-20.1", "\"rssi\":1e999", END_AC(1, false) },
        { "\"track\":136.0", "\"track\":136.0,\"x\":1", END_AC(1, false) },
        { "\"emergency\":\"none\"", "\"emergency\":\"panic\"", END_AC(1, false) },
        { NULL, NULL, END_AC(2, false) },
        { NULL, NULL, "{\"type\":\"fleet_end\",\"rows\":0,\"wifi\":0,\"ble\":0,\"ap\":0,"
          "\"probe\":0,\"alert\":0,\"verdict\":0,\"truncated_wifi\":false,"
          "\"truncated_ble\":false,\"truncated_ap\":false,\"truncated_probe\":false,"
          "\"truncated_alert\":false,\"truncated_verdict\":false,\"complete\":true}\n" },
        { NULL, NULL, "{\"type\":\"fleet_end\",\"rows\":0,\"wifi\":0,\"ble\":0,\"ap\":0,"
          "\"probe\":0,\"alert\":0,\"verdict\":0,\"truncated_wifi\":false,"
          "\"truncated_ble\":false,\"truncated_ap\":false,\"truncated_probe\":false,"
          "\"truncated_alert\":false,\"truncated_verdict\":false,\"aircraft\":1,"
          "\"complete\":true}\n" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char line[1024];
        snprintf(line, sizeof(line), "%s", AC_LINE);
        if (bad[i].from) {
            char *at = strstr(line, bad[i].from);
            WT_ASSERT(at != NULL);
            if (!at) continue;
            char tail[1024];
            snprintf(tail, sizeof(tail), "%s", at + strlen(bad[i].from));
            snprintf(at, sizeof(line) - (size_t)(at - line), "%s%s", bad[i].to, tail);
        }
        snprintf(body, sizeof(body), "%s%s%s", HDR(1792627000), line, bad[i].end);
        int rc = pull_with(body, 0, NULL, 0);
        if (rc == 0) fprintf(stderr, "    case %zu taken\n", i);
        WT_EQ(rc, -1);
        WT_EQ(sightings(), 0);
    }
    static const char RX_BAD[] =
        "{\"type\":\"adsb_rx\",\"source\":\"file\",\"state\":\"live\",\"ts\":1792626990,"
        "\"aircraft\":13,\"messages\":2247900,\"msg_rate\":30.0,\"window_s\":86400,"
        "\"positions\":12,\"cov_complete\":true,\"range_max_m\":30000,\"r000\":3000000,"
        "\"r030\":null,\"r060\":null,\"r090\":null,\"r120\":null,\"r150\":null,\"r180\":null,"
        "\"r210\":null,\"r240\":null,\"r270\":null,\"r300\":null,\"r330\":null,\"n000\":12,"
        "\"n030\":0,\"n060\":0,\"n090\":0,\"n120\":0,\"n150\":0,\"n180\":0,\"n210\":0,"
        "\"n240\":0,\"n270\":0,\"n300\":0,\"n330\":0}\n";
    snprintf(body, sizeof(body), "%s%s%s", HDR(1792627000), RX_BAD, END_AC(0, false));
    WT_EQ(pull_with(body, 0, NULL, 0), -1);
    WT_EQ(sightings(), 0);
    /* Good: the receiver and the aircraft, cut. */
    char rx[2048];
    snprintf(rx, sizeof(rx), "%s", RX_BAD);
    char *r0 = strstr(rx, "\"r000\":3000000");
    WT_ASSERT(r0 != NULL);
    if (r0) memcpy(r0, "\"r000\":  30000", 14);
    snprintf(body, sizeof(body), "%s%s%s%s", HDR(1792627000), rx, AC_LINE, END_AC(1, true));
    int rc = pull_with(body, 0, NULL, 0);
    if (rc) fprintf(stderr, "    pull: %s\n", F.peer[0].last_error);
    WT_EQ(rc, 0);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='aircraft' AND"
                      " key='a00001' AND label='SWA4754' AND vendor='A3' AND rssi=-20 AND"
                      " first_seen=1792622000 AND last_seen=1792626900 AND"
                      " extra LIKE '{\"visit_first\":1792626100,\"squawk\":\"4175\",%'"
                      " AND extra LIKE '%\"pos_ts\":1792626500,\"pos_prev\":1792626400,\"pos_alt\":8875}'"), 1);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='adsb' AND"
                      " key='receiver' AND label='live' AND vendor='file' AND"
                      " last_seen=1792626990 AND extra LIKE '%\"r000\":30000,\"n000\":12,%'"), 1);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM meta WHERE name='fleet.adsb.beta' AND"
                      " value='1792627000 1792627000'"), 1);
    /* Coverage with no decoder summary: kept as of the answer (seen red
     * with put_line()'s receiver clause removed: the age bound took the
     * row at once), the cut kept from the answer before. */
    static char rx2[2048];
    snprintf(rx2, sizeof(rx2), "%s", rx);
    char *s0 = strstr(rx2, "\"source\":\"file\",\"state\":\"live\",\"ts\":1792626990,");
    WT_ASSERT(s0 != NULL);
    if (s0) {
        const char *tail = s0 + strlen("\"source\":\"file\",\"state\":\"live\",\"ts\":1792626990,");
        char rest[2048];
        snprintf(rest, sizeof(rest), "%s", tail);
        snprintf(s0, sizeof(rx2) - (size_t)(s0 - rx2), "\"source\":null,\"state\":null,"
                 "\"ts\":null,%s", rest);
    }
    WT_EQ(sql_on(g_store, "DELETE FROM peer_sightings WHERE kind='adsb'"), 0);
    snprintf(body, sizeof(body), "%s%s%s", HDR(1792640000), rx2, END_AC(0, false));
    rc = pull_with(body, 0, NULL, 0);
    if (rc) fprintf(stderr, "    pull: %s\n", F.peer[0].last_error);
    WT_EQ(rc, 0);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='adsb' AND"
                      " label='' AND last_seen=1792640000"), 1);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM meta WHERE name='fleet.adsb.beta' AND"
                      " value='1792640000 1792627000'"), 1);
    pull_down();
}

/* The pull asks adsb=1 and stores the receiver and the aircraft, the
 * second answer widening the first; an I6 peer refuses adsb=1, is asked
 * again with gnss=1 (an I6-shaped answer, stored as before, the aircraft
 * kept) and not asked with adsb=1 for the hour; the meta clock moves
 * only with an answer that carried aircraft. The fallback was seen red
 * with the adsb level's retry removed (every pull against an older peer
 * failed, here and in each mixed-version test above). */
static void test_adsb_pull_and_mixed_versions(void) {
    peer_srv_t srv;
    pthread_t th;
    here_up(&srv, &th);
    peer_sky(g_db);
    web_gnss_t G;
    site_at(&G, BETA_LAT, BETA_LON);
    web_adsb_t A;
    WT_EQ(web_adsb_init(&A), 0);
    adsb_rx(&A, T - 10, 2247000);
    srv.src.gnss = &G;
    srv.src.adsb = &A;
    WT_EQ(web_fleet_pull_one(&F, 0, T), 0);
    WT_ASSERT(!strcmp(srv.req[0], "since=0&next=1&own=1&gnss=1&adsb=1&ident=1"));
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='aircraft'"), 3);
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='adsb' AND key='receiver'"
                 " AND label='live' AND extra LIKE '%\"positions\":14,%'"), 1);
    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM meta WHERE name='fleet.adsb.beta' AND"
             " value='%lld 0'", T);
    WT_EQ(here_q(sql), 1);
    /* Heard again: the row widens, its first seen kept. */
    snprintf(sql, sizeof(sql), "UPDATE adsb_aircraft SET last_seen=%lld,first_seen=%lld"
             " WHERE hex='a00001';", T + 30, T - 100);
    WT_EQ(sdb_exec(g_db, sql), 0);
    WT_EQ(web_fleet_pull_one(&F, 0, T + 60), 0);
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM peer_sightings WHERE kind='aircraft' AND"
             " key='a00001' AND first_seen=%lld AND last_seen=%lld", T - 5000, T + 30);
    WT_EQ(here_q(sql), 1);
    /* Now an I6 build. */
    srv.i6 = 1;
    int n0 = srv.n;
    WT_EQ(web_fleet_pull_one(&F, 0, T + 120), 0);
    WT_ASSERT(srv.n >= n0 + 3);
    char want[96];
    snprintf(want, sizeof(want), "since=%lld&next=1&own=1&gnss=1&adsb=1&ident=1",
             T - WEB_FLEET_OVERLAP_S);
    WT_ASSERT(!strcmp(srv.req[n0], want));
    snprintf(want, sizeof(want), "since=%lld&next=1&own=1&gnss=1&adsb=1", T - WEB_FLEET_OVERLAP_S);
    WT_ASSERT(!strcmp(srv.req[n0 + 1], want));
    snprintf(want, sizeof(want), "since=%lld&next=1&own=1&gnss=1", T - WEB_FLEET_OVERLAP_S);
    WT_ASSERT(!strcmp(srv.req[n0 + 2], want));
    WT_ASSERT(F.peer[0].no_adsb_until > T + 120);
    WT_EQ(F.peer[0].no_gnss_until, 0);
    WT_EQ(F.peer[0].failures, 0);
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='aircraft'"), 3);
    /* Within the hour: one request, without adsb=1. */
    n0 = srv.n;
    WT_EQ(web_fleet_pull_one(&F, 0, T + 180), 0);
    WT_EQ(srv.n, n0 + 1);
    WT_LACKS(srv.req[n0], "adsb=");
    WT_HAS(srv.req[n0], "&gnss=1");
    here_down(&srv, th);
    web_adsb_destroy(&A);
    web_gnss_destroy(&G);
}

/* This puller against an I7 peer (#192 I4), whose export refuses
 * ident=1: asked again at once without it and stored, and asked without
 * it for WEB_FLEET_NOIDENT_S, then with it again. The I7 answer carries
 * no own_net and no fingerprint member, which this importer takes as it
 * takes any older answer. Seen red with the ident retry's
 * `p->no_ident_until = until` removed (the next pull asked with ident=1
 * again, two requests). */
static void test_ident_pull_from_an_i7_peer(void) {
    peer_srv_t srv;
    pthread_t th;
    here_up(&srv, &th);
    srv.i7 = 1;
    WT_EQ(web_fleet_pull_one(&F, 0, T), 0);
    WT_EQ(srv.n, 2);
    WT_ASSERT(!strcmp(srv.req[0], "since=0&next=1&own=1&gnss=1&adsb=1&ident=1"));
    WT_ASSERT(!strcmp(srv.req[1], "since=0&next=1&own=1&gnss=1&adsb=1"));
    WT_ASSERT(F.peer[0].no_ident_until > T);
    WT_EQ(F.peer[0].no_adsb_until, 0);
    WT_EQ(F.peer[0].failures, 0);
    WT_ASSERT(here_q("SELECT COUNT(*) FROM peer_sightings WHERE peer='beta'") > 0);
    WT_EQ(here_q("SELECT COUNT(*) FROM peer_sightings WHERE kind='own_net'"), 0);
    WT_EQ(here_q("SELECT COUNT(*) FROM meta WHERE name='fleet.ident.beta'"), 0);
    /* Within the hour: one request, without ident=1. */
    int n0 = srv.n;
    WT_EQ(web_fleet_pull_one(&F, 0, T + 60), 0);
    WT_EQ(srv.n, n0 + 1);
    WT_LACKS(srv.req[n0], "ident=");
    WT_HAS(srv.req[n0], "&adsb=1");
    /* Upgraded meanwhile: after the hour, with ident=1, and the own
     * networks' meta row written (this peer names none). */
    srv.i7 = 0;
    n0 = srv.n;
    WT_EQ(web_fleet_pull_one(&F, 0, T + 60 + WEB_FLEET_NOIDENT_S), 0);
    WT_EQ(srv.n, n0 + 1);
    WT_HAS(srv.req[n0], "&adsb=1&ident=1");
    WT_EQ(here_q("SELECT COUNT(*) FROM meta WHERE name='fleet.ident.beta'"), 1);
    here_down(&srv, th);
}

static char *aircraft_get(const web_fleet_src_t *src, const char *q) {
    char *b = NULL;
    size_t bl = 0;
    int st = 0;
    WT_EQ(web_fleet_aircraft_route(&F, src, q, T, &b, &bl, &st), 0);
    WT_EQ(st, 200);
    if (b && bl) b[bl - 1] = '\0';
    return b;
}

/* The route over two receivers 16.8 m apart: beta, pulled, and this
 * site's sloth.db. Before this site has heard anything it is not a
 * receiver, and every aircraft reads undetermined, single_receiver, as
 * the live fleet does today. Then this site's sky: twelve aircraft over
 * the last hour (its activity), ten of them placed 30 to 50 km north
 * (its demonstrated north sector), and a00001 heard at the same time as
 * beta. a00001 is confirmed; a00002, 20 km north where this site hears
 * to 50 km while hearing others, unconfirmed; a00003, 45 km north,
 * beyond 0.8 of that, out of this site's coverage; a00004, positioned
 * 20 s ago, pending this site's next data. The overview carries the
 * counts. */
static void test_adsb_route(void) {
    peer_srv_t srv;
    pthread_t th;
    here_up(&srv, &th);
    WT_EQ(sdb_make(g_here_db, db_schema_version(), 0), 0);
    ac_put(g_db, "a00001", T - 900, T - 900, T - 100, "SWA4754");
    ac_sight(g_db, "a00001", T - 500, BETA_LAT, BETA_LON, 20000, 10000, "280.0", 0);
    ac_put(g_db, "a00002", T - 1500, T - 1500, T - 1100, "GHOST1");
    ac_sight(g_db, "a00002", T - 1200, BETA_LAT, BETA_LON, 20000, 10000, "280.0", 0);
    ac_put(g_db, "a00003", T - 1500, T - 1500, T - 1100, "FAR1");
    ac_sight(g_db, "a00003", T - 1200, BETA_LAT, BETA_LON, 45000, 10000, "280.0", 0);
    ac_put(g_db, "a00004", T - 60, T - 60, T - 20, "NEW1");
    ac_sight(g_db, "a00004", T - 20, BETA_LAT, BETA_LON, 20000, 10000, "280.0", 0);
    web_gnss_t GB, GS;
    site_at(&GB, BETA_LAT, BETA_LON);
    site_at(&GS, SELF_LAT, SELF_LON);
    web_adsb_t A;
    WT_EQ(web_adsb_init(&A), 0);
    adsb_rx(&A, T - 10, 2247000);
    srv.src.gnss = &GB;
    srv.src.adsb = &A;
    WT_EQ(web_fleet_pull_one(&F, 0, T), 0);
    web_slothdb_t here;
    web_slothdb_init(&here, g_here_db, NULL);
    web_fleet_src_t src = { &here, NULL, &GS, NULL, NULL, NULL, NULL, NULL };
    char *b = aircraft_get(&src, "");
    WT_ASSERT(b != NULL);
    if (b) {
        WT_HAS(b, ",\"receivers\":1,\"single_receiver\":true,");
        WT_HAS(b, "\"counts\":{\"undetermined\":4,\"confirmed\":0,\"unconfirmed\":0,"
                  "\"out_of_peer_coverage\":0,\"inconsistent\":0}");
        WT_HAS(b, "{\"hex\":\"a00002\",\"flight\":\"GHOST1\"");
        WT_HAS(b, "\"verdict\":\"undetermined\",\"why\":\"single_receiver\",\"ref\":\"beta\"");
        WT_LACKS(b, "\"verdict\":\"unconfirmed\"");
        WT_HAS(b, "{\"site\":\"beta\",\"label\":null,\"receiver\":true,\"source\":\"file\","
                  "\"state\":\"live\",\"summary_age_s\":10,\"fresh\":true,");
        free(b);
    }
    /* This site's sky. */
    for (int i = 0; i < 12; i++) {
        char hex[8];
        snprintf(hex, sizeof(hex), "c%05d", i);
        ac_put(g_here_db, hex, T - 3000, T - 3000, T - 100, "LOCAL");
        if (i < 10)
            ac_sight(g_here_db, hex, T - 2000 + i, SELF_LAT, SELF_LON, 30000 + 2000 * i,
                     20000, "300.0", 0);
    }
    ac_put(g_here_db, "a00001", T - 800, T - 800, T - 150, "SWA4754");
    ac_sight(g_here_db, "a00001", T - 450, SELF_LAT, SELF_LON, 20500, 10000, "280.0", 0);
    b = aircraft_get(&src, "limit=200");
    WT_ASSERT(b != NULL);
    if (b) {
        WT_HAS(b, ",\"receivers\":2,\"single_receiver\":false,");
        WT_HAS(b, "{\"site\":\"self\",\"label\":null,\"receiver\":true,");
        WT_HAS(b, ",\"positions\":11,\"cov_complete\":true,\"range_max_m\":48000,"
                  "\"sectors\":[{\"from\":0,\"max_m\":48000,\"n\":11},");
        /* The unconfirmed first. */
        WT_HAS(b, "\"aircraft\":[{\"hex\":\"a00002\",\"flight\":\"GHOST1\"");
        WT_HAS(b, "\"verdict\":\"unconfirmed\",\"why\":null,\"ref\":\"beta\"");
        WT_HAS(b, "\"peers\":[{\"site\":\"self\",\"state\":\"should_have_heard\",\"dist_m\":19986,"
                  "\"sector_max_m\":48000,\"horizon_m\":");
        static const struct { const char *hex, *verdict; } want[] = {
            { "a00001", "\"verdict\":\"confirmed\",\"why\":null,\"ref\":\"self\"" },
            { "a00002", "\"verdict\":\"unconfirmed\",\"why\":null,\"ref\":\"beta\"" },
            { "a00003", "\"verdict\":\"out_of_peer_coverage\",\"why\":null,\"ref\":\"beta\"" },
            { "a00004", "\"verdict\":\"undetermined\",\"why\":\"pending\",\"ref\":\"beta\"" },
        };
        for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
            char at[32];
            snprintf(at, sizeof(at), "{\"hex\":\"%s\"", want[i].hex);
            const char *o = strstr(b, at);
            WT_ASSERT(o != NULL);
            if (!o) continue;
            const char *nx = strstr(o + 1, "{\"hex\":");
            size_t n = nx ? (size_t)(nx - o) : strlen(o);
            char *one = malloc(n + 1);
            if (!one) continue;
            memcpy(one, o, n);
            one[n] = '\0';
            WT_HAS(one, want[i].verdict);
            free(one);
        }
        WT_LACKS(b, "nan");
        WT_LACKS(b, "inf");
        free(b);
    }
    static char ov[131072];
    size_t len = 0;
    int st = 0;
    WT_EQ(web_fleet_overview_route(&F, &src, "", T, ov, sizeof(ov) - 1, &len, &st), 0);
    ov[len] = '\0';
    WT_EQ(st, 200);
    WT_HAS(ov, ",\"aircraft\":{\"receivers\":2,\"single_receiver\":false,\"aircraft\":16,");
    WT_HAS(ov, "\"unconfirmed\":1,");
    /* A peer's read filled to its cap: its older rows may be left out,
     * so its silence reads as a cut answer, never as "did not hear"
     * (seen red, beta's cut_age_s null, with peer_rows()'s cap test
     * removed). */
    char ins[512];
    snprintf(ins, sizeof(ins), "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n"
             " WHERE i < %d) INSERT INTO peer_sightings (peer,kind,key,first_seen,last_seen)"
             " SELECT 'beta', 'aircraft', printf('b%%05x', i), %lld, %lld FROM n",
             WEB_FA_ROWS_PER_PEER, T + 100, T + 100);
    WT_EQ(sql_on(g_here_web, ins), 0);
    b = aircraft_get(&src, "limit=1");
    WT_ASSERT(b != NULL);
    if (b) {
        const char *bs = strstr(b, "{\"site\":\"beta\"");
        WT_ASSERT(bs != NULL);
        const char *ce = bs ? strstr(bs, "\"cut_age_s\":") : NULL;
        WT_ASSERT(ce != NULL && !strncmp(ce, "\"cut_age_s\":0,", 14));
        free(b);
    }
    /* The limit's bounds. */
    char *e = NULL;
    size_t el = 0;
    WT_EQ(web_fleet_aircraft_route(&F, &src, "limit=0", T, &e, &el, &st), 0);
    WT_EQ(st, 400);
    free(e);
    WT_EQ(web_fleet_aircraft_route(&F, &src, "x=1", T, &e, &el, &st), 0);
    WT_EQ(st, 400);
    free(e);
    web_slothdb_destroy(&here);
    here_down(&srv, th);
    web_adsb_destroy(&A);
    web_gnss_destroy(&GB);
    web_gnss_destroy(&GS);
}
#endif

void run_fleet_tests(void) {
    WT_RUN(test_peer_urls);
    WT_RUN(test_peer_flags);
    WT_RUN(test_members_are_not_secret);
#ifdef WITH_SQLITE
    WT_RUN(test_export_withholds_secrets);
    WT_RUN(test_export_since);
    WT_RUN(test_export_sends_only_what_the_importer_takes);
    WT_RUN(test_pull_good_and_upsert);
    WT_RUN(test_pull_refusals);
    WT_RUN(test_pull_trickle_is_cut_off);
    WT_RUN(test_pull_unreachable_and_thread);
    WT_RUN(test_export_pages);
    WT_RUN(test_backfill_after_a_cut);
    WT_RUN(test_backfill_alerts_past_the_scan);
    WT_RUN(test_backfill_cut_every_pull);
    WT_RUN(test_backfill_merge_past_bound);
    WT_RUN(test_backfill_segments_meta);
    WT_RUN(test_pull_from_an_f1_peer);
    WT_RUN(test_overview_and_shared);
    WT_RUN(test_pull_own_radios);
    WT_RUN(test_locate_route);
    WT_RUN(test_read_own);
    WT_RUN(test_read_own_many_and_again);
    WT_RUN(test_gnss_export);
    WT_RUN(test_gnss_import_refusals);
    WT_RUN(test_gnss_pull_and_mixed_versions);
    WT_RUN(test_gnss_skew_slow_peer);
    WT_RUN(test_gnss_route);
    WT_RUN(test_gnss_sample_events);
    WT_RUN(test_gnss_state_survives_a_restart);
    WT_RUN(test_gnss_reference_moved);
    WT_RUN(test_adsb_export);
    WT_RUN(test_adsb_import_refusals);
    WT_RUN(test_adsb_pull_and_mixed_versions);
    WT_RUN(test_adsb_route);
    WT_RUN(test_ident_pull_from_an_i7_peer);
#endif
    WT_RUN(test_distance);
    WT_RUN(test_fleet_page);
}
