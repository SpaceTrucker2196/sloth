// slothweb client. The Alerts page and an alert's page (/api/alerts,
// /api/alert), the record ticker by type and the sensor's health, and
// the Overview's tiles as links to the views of what they count
// (#alerts?state=open, #devices?q=pass:latest, ...), on top of the M6
// client: the Flows view (M6: /api/flows, /api/flows/graph,
// a chord diagram on Canvas 2D) and, before it, the M5 client: the Overview view (M1, with M3's baseline band,
// hour-of-week heatmap and top anomalies), the Activity view (M2, with
// M3's baseline band), the Anomalies view (M3), the Devices view,
// the device drawer and the Lookup view (M4: /api/devices,
// /api/device/MAC, /api/lookup; passive only, nothing is ever resolved
// or sent anywhere but this page's own server), and the WiFi and
// History views with the SQL box (M5: /api/wifi/*, /api/history/*,
// /api/sessions, /api/query only when the server says it is on). Overview: KPI tiles
// and the strip from the /events tick, the record ticker from /events
// record events, /api/live for the alert list, the sensor detail and the
// ticker's backlog. Charts: /api/metrics, /api/keys, /api/series and
// /api/baseline on Canvas 2D. Anomalies: /api/anomalies, refreshed on
// the /events anomaly event. Same-origin relative paths only; the page's
// CSP (connect-src 'self') refuses anything else.
//
// Every value that came from the stream is shown with textContent and
// nothing else: a hostname or SSID holding markup is shown as the
// characters it is. Stream values never become a class name, an
// attribute or a URL; record types and anomaly kinds map to fixed
// class tables.
//
// Every data value is coloured as sloth's TUI colours it (owner ruling
// 2026-10-23): the palette is generated from the TUI's sources into
// palette.css and palette.js (web/tools/palette.c), and the functions
// below port the TUI's choices (src/ip_color.c, src/tui.c); the chrome
// around the data is the Spacetrucker design system (theme.css).
(function () {
  "use strict";

  // The theme, before the first paint: the script sits in <head>, so
  // this runs before the body is parsed, and the rest waits for the DOM.
  // Dark is the default; only a stored "light" changes it, and a blocked
  // or absent store means dark.
  var THEME_KEY = "slothweb.theme";
  var root = document.documentElement;
  try {
    if (window.localStorage.getItem(THEME_KEY) === "light") root.dataset.theme = "light";
  } catch (e) { /* no storage: dark */ }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", main);
  else main();

  // main()'s body keeps the indentation it had as the module body:
  // the page tests pin its lines as served.
  function main() {
  var $ = function (id) { return document.getElementById(id); };
  var TICKER_MAX = 50;
  var NOSQL = false;
  // The records src/jsonl.c emits from the monitor radio's state: the
  // emitters jsonl_emit_state_snapshots() calls from beacons to EAPOL,
  // less the captive-portal events (body, DNS answer, TLS destination:
  // the IP capture). Each is a monitor row on the ticker, as packets.c
  // draws a monitor frame (web/tests/test_tui_colors.c pins the list
  // against jsonl.c).
  var MON_TYPES = [
    "beacon", "wifi_regulatory", "deauth", "probe_client", "pnl_client",
    "seqnum_client", "seqnum_correlation", "channel_summary", "assoc",
    "wifi_assoc_req", "btm_request", "wifi_csa_event", "rrm_beacon_request",
    "wifi_mld", "eapol"
  ];
  var TYPE_CLASS = {
    "dns": "t-dns", "tls": "t-tls", "http": "t-http", "quic": "t-quic",
    "icmp": "t-icmp", "arp": "t-arp",
    "wifi_ap": "t-wifi", "wifi_sta": "t-wifi",
    "alert": "t-alert", "alert.create": "t-alert", "alert.update": "t-alert",
    "alert.escalate": "t-alert", "alert.resolve": "t-alert"
  };
  MON_TYPES.forEach(function (t) { TYPE_CLASS[t] = "t-wifi"; });
  function isMon(t) { return MON_TYPES.indexOf(t) >= 0; }
  var SEV_WORD = ["low", "warn", "crit"];
  // §6's kinds, each with a glyph so a card reads in greyscale too.
  var KINDS = ["rate", "new", "hours", "ident", "fanout", "dns", "proto",
               "sensor", "vendor"];
  var KIND_GLYPH = {
    "rate": "~", "new": "+", "hours": "@", "ident": "=", "fanout": "<",
    "dns": "?", "proto": "^", "sensor": "!", "vendor": "#"
  };
  // A canonical MAC, as the server writes one: what may open a drawer.
  var MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;

  // ── the capture scope (web/src/web_scope.h) ───────────────────────
  // Monitor / Hybrid / Local in the top bar: which captured data every
  // view shows. The server does the filtering (every /api route takes
  // scope=, and counts, pages and tiles are its own); the page keeps the
  // scope's records on the ticker (each carries its tag, sc) and draws
  // the empty states. The choice is in the address (#devices?scope=
  // monitor; Hybrid left out) and kept in this browser for an address
  // that names none; a blocked or absent store means Hybrid.
  var SCOPE_KEY = "slothweb.scope";
  var SCOPES = ["monitor", "hybrid", "local"];
  var SCOPE_WANT = { "monitor": 1, "local": 2 };
  var SCOPE_WORD = { "monitor": "Monitor", "hybrid": "Hybrid", "local": "Local" };
  var SCOPE = "hybrid";
  try {
    var savedScope = window.localStorage.getItem(SCOPE_KEY);
    if (SCOPES.indexOf(savedScope) >= 0) SCOPE = savedScope;
  } catch (e) { /* no storage: Hybrid */ }
  // An address that names one wins, before the first fetch.
  var hashScope = /[?&]scope=(monitor|hybrid|local)(&|$)/.exec(String(location.hash || ""));
  if (hashScope) SCOPE = hashScope[1];
  // A same-origin API path with the scope added; Hybrid's is the path.
  function scoped(path) {
    if (SCOPE === "hybrid") return path;
    return path + (path.indexOf("?") >= 0 ? "&" : "?") + "scope=" + SCOPE;
  }
  // Does the scope keep a record tagged sc (1 Monitor, 2 Local, 3 both)?
  // A record with no tag is an answer from before the scope was picked:
  // Hybrid's alone.
  function scopeKeeps(sc) {
    if (SCOPE === "hybrid") return true;
    if (typeof sc !== "number") return false;
    return (sc & SCOPE_WANT[SCOPE]) !== 0;
  }
  // A ticker record's line in the scope shown: a device row's own
  // Monitor line under Monitor (no address, no hostname).
  function recText(r) {
    return SCOPE === "monitor" && typeof r.text_m === "string" ? r.text_m : r.text;
  }

  function set(id, text) { $(id).textContent = String(text); }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = String(text);
    return e;
  }

  function typeClass(t) {
    return Object.prototype.hasOwnProperty.call(TYPE_CLASS, t)
      ? TYPE_CLASS[t] : "t-other";
  }

  function kindGlyph(k) {
    return Object.prototype.hasOwnProperty.call(KIND_GLYPH, k) ? KIND_GLYPH[k] : "*";
  }

  function state(cls, word) {
    $("dot").className = "dot " + cls;
    set("conn", word);
  }

  function dur(s) {
    if (s < 60) return s + "s";
    if (s < 3600) return Math.floor(s / 60) + "m" + (s % 60) + "s";
    return Math.floor(s / 3600) + "h" + Math.floor((s % 3600) / 60) + "m";
  }

  function hhmmss(ts) {
    var d = new Date(ts * 1000);
    function two(n) { return (n < 10 ? "0" : "") + n; }
    return two(d.getHours()) + ":" + two(d.getMinutes()) + ":" + two(d.getSeconds());
  }

  function num(v) { return typeof v === "number" && isFinite(v); }

  // ── data colours, as the TUI ──────────────────────────────────────
  // Colours are CSS variables (palette.css), set as var() references,
  // so a theme switch recolours the DOM without a redraw. A value picks
  // a colour by its index only; it never becomes a class or attribute.
  var P = SLOTH_PALETTE;

  // A string's UTF-8 bytes: the TUI hashes bytes, not UTF-16 units.
  function utf8(s) {
    var out = [];
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if (c >= 0xd800 && c < 0xdc00 && i + 1 < s.length) {
        var d = s.charCodeAt(i + 1);
        if (d >= 0xdc00 && d < 0xe000) { c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00); i++; }
      }
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | c >> 6, 0x80 | c & 63);
      else if (c < 0x10000) out.push(0xe0 | c >> 12, 0x80 | c >> 6 & 63, 0x80 | c & 63);
      else out.push(0xf0 | c >> 18, 0x80 | c >> 12 & 63, 0x80 | c >> 6 & 63, 0x80 | c & 63);
    }
    return out;
  }

  // src/ip_color.c ip_color_index(): djb2 over the bytes, modulo
  // IP_NUM_COLORS; "" is 0. tui_ip_addstr() colours an IP by it,
  // tui_ssid_addstr() an SSID, tui_info_color() an info string.
  function ipColorIndex(s) {
    if (!s) return 0;
    var b = utf8(s), h = 5381;
    for (var i = 0; i < b.length; i++) h = (((h << 5) + h) + b[i]) >>> 0;
    return h % P.ip;
  }

  // src/tui.c find_brand() and tui_brand_addstr(): from each point the
  // earliest match of any table entry wins, ASCII case-insensitively, a
  // tie going to the entry listed first; Google's letters take the
  // logo's sequence in turn. [start, end, slot], slot -1 for plain text.
  function lowerAscii(s) {
    return s.replace(/[A-Z]/g, function (c) { return String.fromCharCode(c.charCodeAt(0) + 32); });
  }
  function brandRuns(s) {
    var low = lowerAscii(s), out = [], at = 0;
    for (;;) {
      var best = -1, brand = 0, len = 0;
      for (var i = 0; i < P.brands.length; i++) {
        var j = low.indexOf(P.brands[i][1], at);
        if (j >= 0 && (best < 0 || j < best)) { best = j; brand = P.brands[i][0]; len = P.brands[i][1].length; }
      }
      if (best < 0) { if (at < s.length) out.push([at, s.length, -1]); return out; }
      if (best > at) out.push([at, best, -1]);
      if (brand === P.google) {
        for (var k = 0; k < len; k++) out.push([best + k, best + k + 1, P.gseq[k % P.gseq.length]]);
      } else {
        out.push([best, best + len, brand]);
      }
      at = best + len;
    }
  }

  // src/ip_color.h's sources and ip_index_is_cross_panel(): an address
  // seen in more than one of them is drawn bold, as the dashboard does.
  // The TUI rebuilds its index every frame from what is on screen; the
  // page keeps one for its lifetime, at the TUI's 512 addresses.
  var IP_SRC = { conn: 1, pkt: 2, arp: 4, dns: 8, icmp: 16, alert: 32, dev: 64 };
  var IP_INDEX_CAP = 512;
  // The source a ticker record's addresses count toward.
  var RECORD_SRC = {
    "t-dns": IP_SRC.dns, "t-icmp": IP_SRC.icmp, "t-arp": IP_SRC.arp,
    "t-alert": 0, "t-tls": IP_SRC.pkt, "t-http": IP_SRC.pkt,
    "t-quic": IP_SRC.pkt, "t-other": IP_SRC.pkt
  };
  // ip_index_build() adds an alert's match_ip under IP_SRC_ALERT and
  // nothing else of it: the other addresses an alert's text names are
  // coloured but counted toward no source (alertText(), noteAlertIp()).
  function recordSrc(cls) {
    return Object.prototype.hasOwnProperty.call(RECORD_SRC, cls) ? RECORD_SRC[cls] : IP_SRC.pkt;
  }
  var IPX = new Map();
  function crossPanel(m) { return (m & (m - 1)) !== 0; }
  function ipNote(ip, bit) {
    var e = IPX.get(ip);
    if (!e) {
      if (!bit || IPX.size >= IP_INDEX_CAP) return null;
      e = { m: 0, els: [] };
      IPX.set(ip, e);
    }
    if (bit && !(e.m & bit)) {
      var was = crossPanel(e.m);
      e.m |= bit;
      // Turned cross-panel: what is already drawn turns bold too.
      if (!was && crossPanel(e.m)) {
        e.els.forEach(function (x) { x.classList.add("xb"); });
        e.els = [];
      }
    }
    return e;
  }

  // tui_alert_hot_set() / tui_alert_hot_check() (src/tui.c): an address
  // an alert names as its match_ip is drawn in CP_ALERT_HOT_* by the
  // alert's severity for ALERT_HOT_TTL_S after the alert was last seen,
  // over the hash colour and the cross-panel bold; promotion only, the
  // newest time kept, 256 slots with the oldest replaced.
  var HOT_TTL_S = 3600;
  var HOT_CAP = 256;
  var HOT = new Map();
  function hotSet(ip, t, sev) {
    if (!ip) return;
    if (sev < 0) sev = 0;
    if (sev > 2) sev = 2;
    var e = HOT.get(ip);
    if (e) {
      if (t > e.t) e.t = t;
      if (sev > e.sev) e.sev = sev;
      return;
    }
    if (HOT.size >= HOT_CAP) {
      var old = null;
      HOT.forEach(function (v, k) { if (old === null || v.t < HOT.get(old).t) old = k; });
      HOT.delete(old);
    }
    HOT.set(ip, { t: t, sev: sev });
  }
  function hotCheck(ip) {
    var e = HOT.get(ip);
    if (!e) return -1;
    if (Math.floor(Date.now() / 1000) - e.t > HOT_TTL_S) return -1;
    return e.sev;
  }
  // An alert's match_ip: hot by its severity, and its one IP_SRC_ALERT.
  function noteAlertIp(ip, t, sev) {
    if (!isIP(ip) || !num(t) || !num(sev)) return;
    hotSet(ip, t, sev);
    ipNote(ip, IP_SRC.alert);
  }

  var IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  function isIPv4(t) { return IPV4_RE.test(t); }
  function isIPv6(t) {
    if (!/^[0-9A-Fa-f:.]+$/.test(t)) return false;
    var parts = t.split("::");
    if (parts.length > 2) return false;
    var groups = [];
    for (var p = 0; p < parts.length; p++) if (parts[p] !== "") groups = groups.concat(parts[p].split(":"));
    var n = 0;
    for (var i = 0; i < groups.length; i++) {
      var g = groups[i];
      if (i === groups.length - 1 && isIPv4(g)) { n += 2; continue; }
      if (!/^[0-9A-Fa-f]{1,4}$/.test(g)) return false;
      n++;
    }
    return n >= 1 && (parts.length === 2 ? n <= 7 : n === 8);
  }
  function isIP(t) { return typeof t === "string" && (isIPv4(t) || isIPv6(t)); }

  // An address in the TUI's hash colour, bold once cross-panel; bit is
  // the source it was seen in (0: shown, not counted as a source).
  function ipSpan(ip, bit) {
    var sp = el("span", "", ip);
    var e = ipNote(ip, bit);
    var hot = hotCheck(ip);
    if (hot >= 0) {
      sp.style.color = "var(--hot-" + hot + ")";
      if (hot >= 1) sp.classList.add("xb");
      return sp;
    }
    sp.style.color = "var(--k-" + ipColorIndex(ip) + ")";
    if (e && crossPanel(e.m)) sp.classList.add("xb");
    else if (e) {
      if (e.els.length >= 64) e.els = e.els.filter(function (x) { return x.isConnected; });
      if (e.els.length < 64) e.els.push(sp);
    }
    return sp;
  }

  // tui_ssid_addstr(): the same palette, its own hash of the SSID. The
  // server sends every SSID in its display form (web/src/web_ssid.h:
  // printable UTF-8 as it is, any other octet as \xNN), never raw, with
  // the colour it hashed over the octets themselves (k, its *_k member),
  // which is the TUI's; the page's own hash is for an SSID that came
  // without one. One that needed escaping (np) carries a marker.
  function ssidSpan(ssid, k, np) {
    var sp = el("span", "", ssid);
    if (num(k) && k >= 0 && k < P.ip) sp.style.color = "var(--k-" + k + ")";
    else if (ssid !== "") sp.style.color = "var(--k-" + ipColorIndex(ssid) + ")";
    if (np !== true) return sp;
    var w = el("span", "ssid-np");
    w.appendChild(sp);
    w.appendChild(el("span", "npm", "non-printable"));
    w.title = "bytes that are not printable UTF-8 are shown as \\xNN";
    return w;
  }

  // tui_brand_addstr() into parent: brand runs in their colours, the
  // rest in base (a d-* class: the pair the TUI row would use).
  function brandText(parent, s, base) {
    var runs = brandRuns(s);
    for (var i = 0; i < runs.length; i++) {
      var r = runs[i], sp = el("span", r[2] < 0 ? base || "" : "", s.slice(r[0], r[1]));
      if (r[2] >= 0) sp.style.color = "var(--br-" + r[2] + ")";
      parent.appendChild(sp);
    }
    return parent;
  }
  function brandSpan(s, base) { return brandText(el("span", ""), s, base); }

  // Free text (a record's summary, an alert's detail): every address in
  // it as tui_ip_addstr() draws one, the rest through the brand rules.
  function ipTokens(s) {
    var out = [], re = /[0-9A-Fa-f:.]+/g, m;
    while ((m = re.exec(s)) !== null) {
      var t = m[0], at = m.index;
      if (at > 0 && /[0-9A-Za-z_]/.test(s.charAt(at - 1))) continue;
      if (/[0-9A-Za-z_]/.test(s.charAt(at + t.length))) continue;
      t = t.replace(/[.:]+$/, "");
      var lead = /^[.:]*/.exec(t)[0].length;
      if (lead && !(t.charAt(0) === ":" && t.charAt(1) === ":" && isIPv6(t))) {
        at += lead;
        t = t.slice(lead);
      }
      var port = /^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/.exec(t);
      if (port) t = port[1];
      if (isIP(t)) out.push([at, at + t.length]);
    }
    return out;
  }
  function richText(parent, s, bit, base) {
    s = String(s);
    var toks = ipTokens(s), at = 0;
    for (var i = 0; i < toks.length; i++) {
      if (toks[i][0] > at) brandText(parent, s.slice(at, toks[i][0]), base);
      parent.appendChild(ipSpan(s.slice(toks[i][0], toks[i][1]), bit));
      at = toks[i][1];
    }
    if (at < s.length) brandText(parent, s.slice(at), base);
    return parent;
  }

  // tui_info_color(): an earth tone by the string's hash, CP_NORMAL for
  // an empty one.
  function infoClass(s) { return s ? "info-" + (ipColorIndex(s) & 7) : "d-normal"; }

  // A series key or episode key: an address as an address, a MAC in
  // CP_DIM (the TUI's device and station tables), anything else (an
  // interface, a channel, an alert type) in CP_NORMAL.
  function keySpan(k) {
    if (isIP(k)) return ipSpan(k, 0);
    return el("span", MAC_RE.test(k) ? "d-dim" : "d-normal", k);
  }

  // The heat ramp's class, tui_heat()'s 0.15 / 0.40 / 0.70.
  function heatClass(f) { return f < 0.15 ? "h0" : f < 0.40 ? "h1" : f < 0.70 ? "h2" : "h3"; }

  // ── data tables (owner request 2026-10-26) ────────────────────────
  // Every table on the page is one of these, one implementation: a
  // header of columns over rows whose cells line up under them (each
  // row a CSS grid on the columns' tracks, or, for the SQL box, a
  // fixed-layout <table>). A sortable column's header is a button: a
  // click or Enter cycles ascending, descending and off, and the header
  // says which in aria-sort. Its right edge is a separator to drag (a
  // mouse, a pen or a finger), to move with the arrow keys once it has
  // the focus (Shift for bigger steps, Home for the minimum) or to
  // double-click (or Enter) to fit the column to its widest cell. A
  // column never goes below its minimum. The widths are kept per table
  // in this browser (localStorage; the page works the same without it);
  // "reset columns" forgets them and the sort.
  //
  // A table whose rows the page holds sorts them in place, stably, by
  // the column's type: an address numerically (IPv4 before IPv6, each
  // by its bytes), a MAC by its six octets, a time, a count, a dBm or a
  // severity by number, text by its UTF-8 bytes (no locale), an empty
  // value last in either direction. A table the server pages instead
  // asks its view to fetch again with the column's own sort word and a
  // direction, both checked by the server against its list; a column
  // with no word there is not sortable, and the page then orders the
  // rows it holds by the same comparator, so the server picks the rows
  // and the page the order of the bytes within them (an address read as
  // text by SQL, numerically here).
  var DT_STORE = "slothweb.cols.";
  var DT_GAP = 6;
  var CH_PX = 0;
  function chPx() {
    if (CH_PX) return CH_PX;
    var p = el("span", "", "0000000000");
    p.style.position = "absolute";
    p.style.visibility = "hidden";
    p.style.fontSize = "12px";
    p.style.fontFamily = "var(--font-mono)";
    document.body.appendChild(p);
    CH_PX = p.getBoundingClientRect().width / 10 || 7.2;
    document.body.removeChild(p);
    return CH_PX;
  }

  // Sort keys, one comparable array per value; null sorts last.
  function bytesKey(s) { return utf8(String(s)); }
  function ipKey(s) {
    s = String(s);
    if (isIPv4(s)) return [4].concat(s.split(".").map(Number));
    if (!isIPv6(s)) return null;
    var parts = s.split("::"), head = [], tail = [];
    function groups(t) {
      var out = [];
      if (t === "") return out;
      t.split(":").forEach(function (g) {
        if (isIPv4(g)) {
          var b = g.split(".").map(Number);
          out.push(b[0] * 256 + b[1], b[2] * 256 + b[3]);
        } else out.push(parseInt(g, 16));
      });
      return out;
    }
    head = groups(parts[0]);
    if (parts.length === 2) tail = groups(parts[1]);
    var fill = 8 - head.length - tail.length, k = [6];
    head.concat(new Array(Math.max(0, fill)).fill(0), tail).forEach(function (g) { k.push(g >> 8, g & 255); });
    return k;
  }
  function macKey(s) {
    var m = /([0-9a-f]{2}(?::[0-9a-f]{2}){5})/i.exec(String(s));
    return m ? m[1].split(":").map(function (h) { return parseInt(h, 16); }) : null;
  }
  function sortKey(type, v) {
    if (v === null || v === undefined || v === "") return null;
    if (type === "num" || type === "time" || type === "sev") {
      var n = Number(v);
      return isFinite(n) ? [n] : null;
    }
    if (type === "ip") return ipKey(v) || [99].concat(bytesKey(v));
    if (type === "mac") return macKey(v) || [999].concat(bytesKey(v));
    return bytesKey(v);
  }
  function cmpKey(a, b) {
    for (var i = 0; i < a.length && i < b.length; i++)
      if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
    return a.length - b.length;
  }

  function loadWidths(id) {
    try {
      var v = JSON.parse(window.localStorage.getItem(DT_STORE + id) || "null");
      return v && typeof v === "object" && !Array.isArray(v) ? v : {};
    } catch (e) { return {}; }
  }
  function saveWidths(id, w) {
    try {
      if (Object.keys(w).length) window.localStorage.setItem(DT_STORE + id, JSON.stringify(w));
      else window.localStorage.removeItem(DT_STORE + id);
    } catch (e) { /* no storage: the widths last until the page goes */ }
  }

  // o: { id, box, head, cols, table (a <table>: the SQL box), server
  //      (fetch again: server-paged), redraw (draw the rows again:
  //      held rows), reset (an element the "reset columns" button goes
  //      in) }. A column: { k, label, w (ch) or px, min (ch), flex,
  //      type (num, time, sev, ip, mac, text; none: not sortable),
  //      srv (its server sort word), val (row -> the value sorted by),
  //      num (right-aligned) }.
  function DataTable(o) {
    var t = { o: o, cols: o.cols, w: loadWidths(o.id), key: null, dir: 0, th: [], rs: [] };
    var own = Object.prototype.hasOwnProperty;
    t.col = function (k) {
      for (var i = 0; i < t.cols.length; i++) if (t.cols[i].k === k) return t.cols[i];
      return null;
    };
    // The narrowest a column goes: its min (ch), and never less than
    // its header's label, the sort triangle and the cell's right
    // padding (page.css .dt-th, .dt-lab: 10 px capitals, 0.1em apart;
    // the SQL box's 12 px as they are), so no label is cut to "…".
    t.labPx = function (c) {
      var n = String(c.label || "").length;
      if (!n) return 0;
      var per = o.table ? chPx() : chPx() * 10 / 12 + 1;
      return Math.ceil(n * per) + 8 + (t.sortable(c) ? 4 + 9 : 0);
    };
    t.min = function (c) {
      return Math.max(Math.round((num(c.min) ? c.min : 4) * chPx()), t.labPx(c));
    };
    // The width the user set, or null.
    t.set = function (c) {
      return own.call(t.w, c.k) && num(t.w[c.k]) && t.w[c.k] >= t.min(c) && t.w[c.k] <= 4000
        ? Math.round(t.w[c.k]) : null;
    };
    // The column's own width: the user's, or its default, at least its
    // minimum.
    t.base = function (c) {
      var v = t.set(c);
      if (v !== null) return v;
      return Math.max(t.min(c), num(c.px) ? c.px : Math.round((num(c.w) ? c.w : 10) * chPx()));
    };
    // The width drawn. A flex column the user has not set takes its
    // share of the row (minmax(base, 1fr)), so its drawn width is
    // measured: a drag or an arrow starts from what is on the screen.
    t.px = function (c) {
      var i = t.cols.indexOf(c), b = t.base(c);
      if (!c.flex || t.set(c) !== null || !t.th[i]) return b;
      var wd = Math.round(t.th[i].getBoundingClientRect().width);
      return wd > b ? wd : b;
    };
    t.sortable = function (c) {
      return !!c.type && c.type !== "none" && (!o.server || !!c.srv);
    };
    // A flex column keeps its share of the row until the user sets its
    // width; from then it is that many px, the edge under the pointer,
    // and any flex column still unset takes up the rest.
    t.apply = function () {
      var tracks = [], sum = 0;
      t.cols.forEach(function (c, i) {
        var px = t.base(c);
        sum += px;
        tracks.push(c.flex && t.set(c) === null ? "minmax(" + px + "px, 1fr)" : px + "px");
        if (o.table && t.th[i]) t.th[i].style.width = px + "px";
      });
      if (o.table) o.table.style.width = sum + "px";
      else {
        o.box.style.setProperty("--dt-cols", tracks.join(" "));
        o.box.style.setProperty("--dt-minw", (sum + DT_GAP * (t.cols.length - 1) + 12) + "px");
      }
      for (var i = 0; i < t.cols.length; i++) t.value(i);
    };
    // The separator's value: the width drawn, in px, within its range.
    t.value = function (i) {
      var rs = t.rs[i], c = t.cols[i];
      if (!rs) return;
      var px = Math.min(4000, t.px(c));
      rs.ariaValueMin = String(t.min(c));
      rs.ariaValueMax = "4000";
      rs.ariaValueNow = String(px);
      rs.ariaValueText = px + " px";
    };
    t.setWidth = function (c, px) {
      t.w[c.k] = Math.max(t.min(c), Math.min(4000, Math.round(px)));
      saveWidths(o.id, t.w);
      t.apply();
    };
    // The widest cell of column i among the rows drawn, and its header.
    t.fit = function (i) {
      var c = t.cols[i], best = 0;
      if (num(c.px)) return;
      var rows = o.box.querySelectorAll(".dt-row");
      for (var r = 0; r < rows.length; r++) {
        var cell = rows[r].children[i];
        if (!cell || cell.hidden) continue;
        var wd = cell.scrollWidth;
        if (rows[r] === o.head || rows[r].contains(t.th[i])) {
          var lab = t.th[i].querySelector(".dt-lab");
          wd = (lab ? lab.scrollWidth : wd) + 18;
        }
        if (wd > best) best = wd;
      }
      if (best > 0) t.setWidth(c, best + 4);
    };
    t.paint = function () {
      t.cols.forEach(function (c, i) {
        var th = t.th[i];
        if (!th) return;
        var on = t.key === c.k && t.dir !== 0;
        th.ariaSort = t.sortable(c) ? (on ? (t.dir > 0 ? "ascending" : "descending") : "none") : null;
        var ind = th.querySelector(".dt-ind");
        if (ind) ind.textContent = on ? (t.dir > 0 ? "▲" : "▼") : "";
      });
    };
    t.cycle = function (c) {
      if (t.key !== c.k) { t.key = c.k; t.dir = 1; }
      else if (t.dir === 1) t.dir = -1;
      else { t.key = null; t.dir = 0; }
      t.paint();
      if (o.server) o.server(); else if (o.redraw) o.redraw();
    };
    t.clear = function () { t.key = null; t.dir = 0; t.paint(); };
    // The server's sort word and direction, or null for its default.
    t.word = function () {
      var c = t.key ? t.col(t.key) : null;
      return c && c.srv && t.dir ? { sort: c.srv, dir: t.dir > 0 ? "asc" : "desc" } : null;
    };
    // rows in the order the header says: a stable sort of a copy. A
    // server-paged table's rows are already in the server's order; it
    // is applied again only when complete says every row is held, since
    // a prefix sorted again could lose the rows that belong first.
    t.sort = function (rows, complete) {
      var c = t.key ? t.col(t.key) : null;
      if (!c || !t.dir || !c.val || (o.server && !complete)) return rows.slice();
      var d = rows.map(function (r, i) { return { r: r, i: i, k: sortKey(c.type, c.val(r)) }; });
      d.sort(function (a, b) {
        if (a.k === null || b.k === null) {
          if (a.k === null && b.k === null) return a.i - b.i;
          return a.k === null ? 1 : -1;
        }
        var x = cmpKey(a.k, b.k) * t.dir;
        return x || a.i - b.i;
      });
      return d.map(function (e) { return e.r; });
    };
    t.label = function (k, text) {
      var i = t.cols.indexOf(t.col(k));
      if (i < 0 || !t.th[i]) return;
      t.cols[i].label = text;
      var lab = t.th[i].querySelector(".dt-lab");
      if (lab) lab.textContent = text;
    };
    t.reset = function () {
      t.w = {};
      saveWidths(o.id, t.w);
      t.key = null;
      t.dir = 0;
      t.apply();
      t.paint();
      if (o.server) o.server(); else if (o.redraw) o.redraw();
    };
    t.build = function () {
      var h = o.head;
      while (h.firstChild) h.removeChild(h.firstChild);
      if (!o.table) {
        h.classList.add("dt-row");
        h.role = "row";
        h.ariaHidden = null;
        o.box.classList.add("dt");
        o.box.role = "table";
        o.box.ariaLabel = o.label || o.id;
      }
      t.th = [];
      t.rs = [];
      t.cols.forEach(function (c, i) {
        var th = el(o.table ? "th" : "span", "dt-th" + (c.num ? " n" : ""));
        th.role = "columnheader";
        if (t.sortable(c)) {
          var b = el("button", "dt-sort");
          b.type = "button";
          b.appendChild(el("span", "dt-lab", c.label));
          b.appendChild(el("span", "dt-ind", ""));
          b.title = "sort by " + (c.label || c.k);
          b.addEventListener("click", function () { t.cycle(c); });
          th.appendChild(b);
        } else {
          th.appendChild(el("span", "dt-lab", c.label));
        }
        var rs = el("span", "dt-rs");
        rs.tabIndex = 0;
        rs.role = "separator";
        rs.ariaOrientation = "vertical";
        rs.ariaLabel = "width of " + (c.label || c.k) + ": arrows resize, Enter fits";
        rs.ariaValueMin = String(t.min(c));
        rs.ariaValueMax = "4000";
        rs.title = "drag to resize, double-click to fit";
        rs.addEventListener("focus", function () { t.value(i); });
        rs.addEventListener("pointerdown", function (e) {
          e.preventDefault();
          var x0 = e.clientX, w0 = t.px(c);
          rs.setPointerCapture(e.pointerId);
          rs.classList.add("on");
          function mv(ev) { t.setWidth(c, w0 + ev.clientX - x0); }
          function up() {
            rs.classList.remove("on");
            rs.removeEventListener("pointermove", mv);
            rs.removeEventListener("pointerup", up);
            rs.removeEventListener("pointercancel", up);
          }
          rs.addEventListener("pointermove", mv);
          rs.addEventListener("pointerup", up);
          rs.addEventListener("pointercancel", up);
        });
        rs.addEventListener("dblclick", function (e) { e.preventDefault(); t.fit(i); });
        rs.addEventListener("click", function (e) { e.stopPropagation(); });
        rs.addEventListener("keydown", function (e) {
          var step = e.shiftKey ? 40 : 8;
          if (e.key === "ArrowLeft") t.setWidth(c, t.px(c) - step);
          else if (e.key === "ArrowRight") t.setWidth(c, t.px(c) + step);
          else if (e.key === "Home") t.setWidth(c, t.min(c));
          else if (e.key === "Enter") t.fit(i);
          else return;
          e.preventDefault();
          e.stopPropagation();
        });
        th.appendChild(rs);
        t.th.push(th);
        t.rs.push(rs);
        h.appendChild(th);
      });
      t.apply();
      t.paint();
    };
    // ARIA's table: every row the builders put in the box a row of
    // cells, and what holds rows between the box and them a rowgroup,
    // so a screen reader reads the body and not a one-row table.
    t.aria = function (node) {
      if (o.table || !(node instanceof Element)) return;
      var rows = node.classList.contains("dt-row") ? [node] : node.querySelectorAll(".dt-row");
      for (var r = 0; r < rows.length; r++) {
        var row = rows[r];
        if (row !== o.head) {
          row.role = "row";
          for (var k = 0; k < row.children.length; k++)
            if (!row.children[k].role) row.children[k].role = "cell";
        }
        for (var p = row.parentNode; p && p !== o.box; p = p.parentNode)
          if (!p.role) p.role = "rowgroup";
      }
    };
    if (!o.table && typeof MutationObserver === "function") {
      new MutationObserver(function (ms) {
        ms.forEach(function (m) {
          for (var n = 0; n < m.addedNodes.length; n++) t.aria(m.addedNodes[n]);
        });
      }).observe(o.box, { childList: true, subtree: true });
    }
    if (o.reset) {
      var rb = el("button", "dt-reset", "reset columns");
      rb.type = "button";
      rb.title = "forget this table's column widths and sort";
      rb.addEventListener("click", t.reset);
      o.reset.appendChild(rb);
    }
    t.build();
    return t;
  }

  // A cell of a held-rows table: a span with its column's class.
  function dtCell(cls, node) {
    var s = el("span", cls || "");
    if (node instanceof Node) s.appendChild(node);
    else if (node !== undefined && node !== null) s.textContent = String(node);
    return s;
  }

  // ── sloth.db freshness (#168) ─────────────────────────────────────
  // Every DB-backed view says what its sloth.db is as of: a --sloth-db
  // snapshot is as old as the moment it was taken, and with the rest of
  // the page updating from the stream a frozen table otherwise looks
  // live. The server decides "stale" (/api/health sloth_db_stale: older
  // than sloth_db_stale_after_s while the stream is current); the page
  // only says so.
  var DB_VIEWS = ["devices", "wifi", "flows", "history", "lookup"];
  var DB_AGE_IDS = ["d-dbage", "w-dbage", "f-dbage", "h-dbage", "l-dbage"];
  // The date as well when it is not today's: a snapshot days old must not
  // read as this afternoon, and "stale" is said only while the stream is
  // current, so the time alone carries it when the stream is down.
  function dbWhen(ts) {
    var d = new Date(ts * 1000), now = new Date();
    function two(n) { return (n < 10 ? "0" : "") + n; }
    var t = two(d.getHours()) + ":" + two(d.getMinutes());
    if (d.toDateString() === now.toDateString()) return t;
    return d.getFullYear() + "-" + two(d.getMonth() + 1) + "-" + two(d.getDate()) + " " + t;
  }
  function dbAgeText(h) {
    if (!num(h.sloth_db_mtime)) return h.db && h.db !== "none" ? "database time unknown (sloth.db " + h.db + ")" : "";
    var t = "database as of " + dbWhen(h.sloth_db_mtime);
    if (h.sloth_db_stale === true)
      t += " - stale: " + dur(h.sloth_db_age_s) + " old while the live stream is current; these rows are as old as it is";
    return t;
  }
  function dbAge(h) {
    var t = dbAgeText(h);
    var stale = h.sloth_db_stale === true && num(h.sloth_db_mtime);
    for (var i = 0; i < DB_AGE_IDS.length; i++) {
      var e = $(DB_AGE_IDS[i]);
      e.textContent = t;
      e.className = stale ? "sub dbage stale" : "sub dbage";
    }
  }
  function dbFresh() {
    fetch("/api/health", { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(dbAge)
      .catch(function () {});
  }

  // ── sensitivity (§5.3: 1.5 to 4 sd, view only) ────────────────────
  // Kept in this browser only; a blocked or absent store just means the
  // default.
  var SENS_KEY = "slothweb.sensitivity";
  var sens = 2;
  try {
    var saved = Number(window.localStorage.getItem(SENS_KEY));
    if (saved >= 1.5 && saved <= 4) sens = saved;
  } catch (e) { /* no storage: the default */ }
  $("sens").value = String(sens);
  set("sens-v", sens.toFixed(1));

  // ── KPIs ──────────────────────────────────────────────────────────
  function kpis(t) {
    if (typeof t.socket === "string") { set("sock", t.socket); set("s-sock", t.socket); }
    // A tick's figures are Hybrid's: under a scope only /api/live's
    // (asked for with the scope) set the tiles, and a tick passes
    // without them.
    if (Object.prototype.hasOwnProperty.call(t, "devices")) {
      var devs = num(t.devices) ? String(t.devices) : "-";
      set("k-devs", devs);
      set("s-devs", devs);
      $("k-devs").className = "kpi" + (t.devices_stale ? " stale" : "");
      set("k-devs-sub", !num(t.devices) ? "waiting for a device pass"
                        : t.devices_stale ? "last known; stream not live"
                        : SCOPE === "monitor" ? "the monitor radio's, in sloth's latest pass"
                        : SCOPE === "local" ? "the host's interfaces', in sloth's latest pass"
                        : "in sloth's latest pass");
    }
    var a = t.alerts_open;
    if (a && num(a[0]) && num(a[1]) && num(a[2])) {
      set("k-low", a[0]); set("k-warn", a[1]); set("k-crit", a[2]);
      set("s-alerts", a[0] + a[1] + a[2]);
    }
    if (t.records_s !== undefined && t.records_s !== null) {
      set("k-rate", t.records_s);
      set("s-rate", t.records_s);
    }
    if (num(t.records)) set("k-rate-sub", t.records + " records since start");
    if (typeof t.sensor === "string") {
      set("k-sensor", t.sensor);
      $("k-sensor").className = "kpi health-" +
        (t.sensor === "ok" ? "ok" : t.sensor === "unknown" ? "unknown" : "bad");
    }
    if (num(t.anomalies_open)) {
      set("k-anoms", t.anomalies_open);
      set("s-anoms", t.anomalies_open);
    }
  }

  // ── the ticker ────────────────────────────────────────────────────
  var paused = false;
  var lastSeq = 0;
  var held = 0;

  // The ticker is a table: held rows, newest first unless a header says
  // otherwise; sorted, it is drawn again at most twice a second.
  var TK = { rows: [], timer: 0 };
  var DTT = DataTable({ id: "ticker", label: "records", box: $("ticker-box"), head: $("ticker-head"),
    reset: $("ticker-tools"), redraw: tickerDraw, cols: [
      { k: "ts", label: "time", w: 9, type: "time", val: function (r) { return r.ts; } },
      { k: "ty", label: "type", w: 14, type: "text", val: function (r) { return r.type; } },
      { k: "tx", label: "record", w: 30, flex: true, type: "text", val: function (r) { return r.text; } }
    ] });
  function tickerDraw() {
    var list = $("ticker");
    while (list.firstChild) list.removeChild(list.firstChild);
    DTT.sort(TK.rows).forEach(function (r) { list.appendChild(tickRow(r)); });
  }

  function addRecord(r) {
    if (!num(r.seq) || r.seq <= lastSeq) return;
    lastSeq = r.seq;
    // A record of another capture scope is passed over, its number
    // counted, so the backlog is not asked for again.
    if (!scopeKeeps(r.sc)) return;
    // Held and drawn as the scope's line; the rows start again with the
    // scope (setScope()).
    r = { seq: r.seq, type: r.type, ts: r.ts, text: recText(r), sc: r.sc };
    if (paused) { held++; set("tick-note", held + " held"); return; }
    TK.rows.unshift(r);
    if (TK.rows.length > TICKER_MAX) TK.rows.length = TICKER_MAX;
    if (DTT.key) {
      if (!TK.timer) TK.timer = setTimeout(function () { TK.timer = 0; tickerDraw(); }, 500);
      return;
    }
    var list = $("ticker");
    list.insertBefore(tickRow(r), list.firstChild);
    while (list.childNodes.length > TICKER_MAX) list.removeChild(list.lastChild);
  }

  function tickRow(r) {
    var cls = typeClass(r.type);
    // An 802.11 record interleaved with the IP capture's is a monitor
    // row, on CP_MON_ROW's ground in its phosphor (src/views/packets.c);
    // any other record is a packets-band row: its info text in the
    // earth tone of its hash, every address in it in its own colour.
    var mon = isMon(r.type);
    var li = el("li", cls + (mon ? " mon" : "") + " tkrow dt-row");
    li.appendChild(el("span", "ts", num(r.ts) ? hhmmss(r.ts) : "-"));
    li.appendChild(el("span", "ty", r.type));
    var tx = el("span", "tx");
    if (mon) tx.textContent = String(r.text);
    else richText(tx, r.text, recordSrc(cls), infoClass(String(r.text)));
    li.appendChild(tx);
    return li;
  }

  $("pause").addEventListener("click", function () {
    paused = !paused;
    set("pause", paused ? "resume" : "pause");
    if (!paused) { held = 0; set("tick-note", ""); }
  });

  // ── /api/live ─────────────────────────────────────────────────────
  var AL = { list: [] };
  var DTL = DataTable({ id: "alerts", label: "latest alerts", box: $("alerts-box"), head: $("alerts-head"),
    reset: $("alerts-tools"), redraw: function () { alerts(AL.list); }, cols: [
      { k: "ts", label: "time", w: 9, type: "time", val: function (a) { return a.ts; } },
      { k: "sev", label: "sev", w: 6, min: 3, type: "sev", val: function (a) { return a.sev; } },
      { k: "ty", label: "kind", w: 9, type: "text", val: function (a) { return String(a.type).replace("alert.", ""); } },
      { k: "tx", label: "alert", w: 24, flex: true, type: "text", val: function (a) { return a.title; } }
    ] });
  function alerts(list) {
    AL.list = list || [];
    var ol = $("alerts");
    while (ol.firstChild) ol.removeChild(ol.firstChild);
    if (!list || !list.length) { ol.appendChild(el("li", "sub", "none since connect")); return; }
    // Hot before any of them is drawn, as st_alert_hot() runs before
    // the frame.
    for (var h = 0; h < list.length; h++)
      noteAlertIp(list[h].match_ip, list[h].ts, list[h].sev);
    list = DTL.sort(list);
    for (var i = 0; i < list.length; i++) {
      var a = list[i];
      var sev = num(a.sev) && a.sev >= 0 && a.sev <= 2 ? a.sev : -1;
      var li = el("li", (sev >= 0 ? "sev" + sev : "") + " alrow dt-row");
      li.appendChild(el("span", "ts", num(a.ts) ? hhmmss(a.ts) : "-"));
      li.appendChild(el("span", "ty", sev >= 0 ? SEV_WORD[sev] : "?"));
      li.appendChild(el("span", "ty d-dim", String(a.type).replace("alert.", "")));
      li.appendChild(alertText(a.title, a.detail));
      // slothweb's handle for the incident, never sloth's incident_id
      // (web/src/web_live.h).
      if (typeof a.alert_id === "string") alertLink(li, a.alert_id);
      ol.appendChild(li);
    }
  }

  // src/views/alerts.c: the title in CP_BRIGHT, the detail in
  // CP_NORMAL, with its addresses in their colours.
  function alertText(title, detail) {
    var tx = el("span", "tx");
    tx.appendChild(el("span", "d-bright", String(title)));
    if (detail !== undefined && detail !== null && detail !== "") {
      tx.appendChild(document.createTextNode("  "));
      richText(tx, detail, 0, "d-normal");
    }
    return tx;
  }

  function sensor(s) {
    if (!s) return;
    var bits = [];
    if (num(s.age_s)) bits.push("report " + dur(s.age_s) + " ago");
    if (s.capture_iface) bits.push("capture " + s.capture_iface +
                                   (s.capture_running ? " running" : " stopped"));
    if (s.monitor_iface) bits.push("monitor " + s.monitor_iface +
                                   (s.monitor_running ? " running" : " stopped"));
    if (s.scope_not_enforced) bits.push("scope " + s.scope);
    set("k-sensor-sub", bits.length ? bits.join(", ") : "no sensor_health yet");
  }

  var first = true;
  // Each call is stamped with the scope it asked in; an answer that
  // lands after the viewer picked another (setScope() bumps liveGen) is
  // dropped, so a Hybrid answer never fills a scoped ticker or tiles.
  var liveGen = 0;
  function live() {
    var gen = liveGen, asked = SCOPE;
    fetch(scoped("/api/live"), { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (l) {
        if (gen !== liveGen || asked !== SCOPE ||
            (SCOPE !== "hybrid" && l.scope !== SCOPE)) return;
        kpis({ socket: l.socket, devices: l.devices,
               devices_stale: l.devices_stale, records: l.records,
               records_s: l.records_s,
               sensor: l.sensor ? l.sensor.state : undefined,
               alerts_open: l.alerts_open
                 ? [l.alerts_open.low, l.alerts_open.warn, l.alerts_open.crit]
                 : null });
        // The scope's own count of open episodes (the tick's is every
        // scope's).
        if (SCOPE !== "hybrid" && num(l.anomalies_open)) {
          set("k-anoms", l.anomalies_open);
          set("s-anoms", l.anomalies_open);
        }
        alerts(l.alerts);
        sensor(l.sensor);
        if (first && l.recent) {
          for (var i = 0; i < l.recent.length; i++) addRecord(l.recent[i]);
        }
        first = false;
        scopeFacts(l.scope_facts);
      })
      .catch(function () { set("sock", "?"); });
    lastLive = Date.now();
  }
  var lastLive = 0;

  // ── /events ───────────────────────────────────────────────────────
  var es = new EventSource("/events");
  state("wait", "connecting");
  es.onopen = function () { state("ok", "live"); };
  es.onerror = function () { state("down", "retrying"); };
  var lastTick = 0;
  es.addEventListener("tick", function (ev) {
    var t;
    try { t = JSON.parse(ev.data); } catch (e) { return; }
    // A tick counting from lower than before is a restarted server,
    // whose record numbers start again too.
    if (num(t.seq) && t.seq < lastTick) { lastSeq = 0; first = true; live(); }
    if (num(t.seq)) lastTick = t.seq;
    state("ok", "live");
    set("seq", t.seq);
    set("up", dur(t.uptime_s));
    set("clients", t.sse_clients);
    kpis(SCOPE === "hybrid" ? t : { socket: t.socket, sensor: t.sensor });
    // Under a scope the tiles are /api/live's: asked again every 2 s.
    if (SCOPE !== "hybrid" && Date.now() - lastLive >= 2000) live();
  });
  es.addEventListener("record", function (ev) {
    var r;
    try { r = JSON.parse(ev.data); } catch (e) { return; }
    addRecord(r);
  });
  // An episode opened, advanced or closed: the lists are re-read, at
  // most once a second however many arrive.
  var anomTimer = 0;
  es.addEventListener("anomaly", function () {
    if (anomTimer) return;
    anomTimer = setTimeout(function () { anomTimer = 0; anomalies(); }, 1000);
  });

  fetch("/api/health", { cache: "no-store" })
    .then(function (r) { return r.json(); })
    .then(function (h) {
      set("sock", h.socket);
      set("db", h.db);
      set("store", h.store);
      // A store of "memory" is a slothweb built without SQLite: it has
      // no --sloth-db to suggest.
      NOSQL = h.store === "memory";
      set("milestone", h.milestone);
      dbAge(h);
      // The SQL box exists only when the server was started with
      // --web-allow-sql; otherwise it is never drawn and never asked.
      Q.on = !!(h.sql && typeof h.sql === "object");
      $("h-sql").hidden = !Q.on;
      if (h.anomaly && h.anomaly.persisted === false)
        set("k-anoms-sub", "in memory only: lost at a restart");
      else if (typeof h.a4 === "string" && h.a4 !== "on")
        set("k-anoms-sub", "rules A1-A3, A5-A10; A4 off: " + h.a4);
      else if (h.a4 === "on")
        set("k-anoms-sub", "rules A1-A10");
    })
    .catch(function () { set("db", "?"); });

  live();
  setInterval(live, 5000);
  // A shown DB-backed view's freshness line, kept current.
  setInterval(function () { if (DB_VIEWS.indexOf(view) >= 0) dbFresh(); }, 30000);

  // ── views ─────────────────────────────────────────────────────────
  var VIEWS = ["overview", "activity", "devices", "anomalies", "wifi", "flows", "history",
               "lookup"];
  // The views with a tab, and the drill-downs: the Alerts page (6),
  // an alert's page, the record ticker by type, the sensor's health.
  var NAV = VIEWS.concat(["alerts"]);
  VIEWS = NAV.concat(["alert", "records", "health"]);
  // The tab lit for a view without one of its own.
  var NAV_OF = { "alert": "alerts", "records": "overview", "health": "overview" };
  // The parameters each view takes from the address, and nothing else:
  // what a drill-down link (an Overview tile) or a reload hands it.
  var PARAMS = { "alerts": ["state", "sev", "type", "q"], "alert": ["id"],
                 "devices": ["q"], "anomalies": ["state"], "activity": ["focus"] };
  var view = "overview", VP = {};
  function hashQuery(v, p) {
    var keys = PARAMS[v] || [], out = [];
    for (var i = 0; i < keys.length; i++)
      if (p && typeof p[keys[i]] === "string" && p[keys[i]] !== "")
        out.push(encodeURIComponent(keys[i]) + "=" + encodeURIComponent(p[keys[i]]));
    // The capture scope, every view's, outside PARAMS; Hybrid unsaid.
    if (SCOPE !== "hybrid") out.push("scope=" + SCOPE);
    return out.length ? "?" + out.join("&") : "";
  }
  function show(v, p) {
    view = v;
    VP = p || {};
    var lit = NAV_OF[v] || v;
    for (var i = 0; i < VIEWS.length; i++) $("v-" + VIEWS[i]).hidden = v !== VIEWS[i];
    for (i = 0; i < NAV.length; i++) {
      var nb = $("nav-" + NAV[i]);
      nb.className = lit === NAV[i] ? "on" : "go";
      // ARIA reflection, not an attribute write: the page has none.
      nb.ariaCurrent = lit === NAV[i] ? "page" : null;
    }
    if (v === "activity") activity();
    if (v === "anomalies") anomalies();
    if (v === "overview") overview();
    if (v === "devices") devices();
    if (v === "wifi") wifi();
    if (v === "flows") flows();
    if (v === "history") historyView();
    if (v === "lookup") $("l-q").focus();
    if (v === "alerts") alertsView();
    if (v === "alert") alertView();
    if (v === "records") recordsView();
    if (v === "health") healthView();
    if (DB_VIEWS.indexOf(v) >= 0) dbFresh();
    scopeView(v);
    // The view is in the address (#flows, #alerts?state=open), so a
    // reload or a link opens it again; replaceState, so Back leaves the
    // page as before. Only a sandboxed frame's refusal is expected;
    // anything else is a bug and is left to surface rather than be
    // swallowed here.
    var hq = hashQuery(v, VP);
    try {
      if (hq) window.history.replaceState(null, "", "#" + v + hq);
      else window.history.replaceState(null, "", "#" + v);
    } catch (e) { if (e.name !== "SecurityError") throw e; }
  }
  // The view named in the address, if it is one, and its parameters.
  function hashRoute() {
    var h = String(location.hash || "").replace(/^#/, "");
    var at = h.indexOf("?"), v = at < 0 ? h : h.slice(0, at), p = {};
    if (VIEWS.indexOf(v) < 0) return null;
    var sc = null;
    if (at >= 0) h.slice(at + 1).split("&").forEach(function (kv) {
      var eq = kv.indexOf("=");
      if (eq <= 0) return;
      try {
        var k = decodeURIComponent(kv.slice(0, eq));
        if ((PARAMS[v] || []).indexOf(k) >= 0) p[k] = decodeURIComponent(kv.slice(eq + 1));
        if (k === "scope" && SCOPES.indexOf(kv.slice(eq + 1)) >= 0) sc = kv.slice(eq + 1);
      } catch (e) { /* a malformed escape: the parameter is left out */ }
    });
    return { v: v, p: p, scope: sc };
  }
  function hashView() { var r = hashRoute(); return r ? r.v : ""; }
  // To a view with parameters, as a new entry in the history, so Back
  // returns to where the link was followed from.
  function go(v, p) {
    var h = "#" + v + hashQuery(v, p);
    if (location.hash === h) show(v, p);
    else location.hash = h;
  }
  window.addEventListener("hashchange", function () {
    var r = hashRoute();
    // An address without a scope keeps the one in force.
    if (r && r.scope) setScope(r.scope);
    if (r) show(r.v, r.p);
  });
  $("nav-overview").addEventListener("click", function () { show("overview"); });
  $("nav-activity").addEventListener("click", function () { show("activity"); });
  $("nav-anomalies").addEventListener("click", function () { show("anomalies"); });
  $("nav-devices").addEventListener("click", function () { show("devices"); });
  $("nav-wifi").addEventListener("click", function () { show("wifi"); });
  $("nav-flows").addEventListener("click", function () { show("flows"); });
  $("nav-history").addEventListener("click", function () { show("history"); });
  $("nav-lookup").addEventListener("click", function () { show("lookup"); });
  $("nav-alerts").addEventListener("click", function () { show("alerts"); });

  // ── the theme toggle ──────────────────────────────────────────────
  // Light or dark on :root's data-theme, the choice kept in this
  // browser only. The DOM's colours are var() references and follow by
  // themselves; canvases hold pixels, so the view is drawn again.
  function themeLabel() {
    var light = root.dataset.theme === "light";
    set("theme", light ? "dark theme" : "light theme");
    $("theme").title = "switch to the " + (light ? "dark" : "light") + " theme";
  }
  themeLabel();
  $("theme").addEventListener("click", function () {
    var light = root.dataset.theme !== "light";
    if (light) root.dataset.theme = "light";
    else delete root.dataset.theme;
    try { window.localStorage.setItem(THEME_KEY, light ? "light" : "dark"); } catch (e) { /* none */ }
    TH = null;
    themeLabel();
    // Redrawn with its parameters: an alert's page keeps its id, a
    // drill-down its filter.
    if (view !== "lookup") show(view, VP);
    if (!$("drawer").hidden && D.sel) openDrawer(D.sel);
  });

  // ── the capture-scope switch ──────────────────────────────────────
  // A radio group: a click or an arrow key picks one; the views, the
  // tiles, the ticker and an open drawer are drawn again for it.
  var SC = { facts: null };
  var SCOPE_SAYS = {
    "monitor": "Monitor: only what the passive monitor radio (and BLE) heard over the air; " +
               "nothing the connected Wi-Fi or Ethernet carried.",
    "local": "Local: only what the host's own Ethernet and Wi-Fi interfaces carried, " +
             "the managed card's own scan and link included (the WiFi view); never the monitor radio."
  };
  function scopeBar() {
    var bar = $("scopebar"), f = SC.facts || {};
    var radio = f.ip_on_radio === true;
    bar.hidden = SCOPE === "hybrid";
    bar.className = "scopebar sc-" + SCOPE.charAt(0) + (radio ? " radio" : "");
    set("scopebar-t", SCOPE === "hybrid" ? "" : SCOPE_SAYS[SCOPE] + (radio
      ? " sloth's IP capture is itself a monitor radio now, so the stream's IP records count as Monitor's."
      : ""));
  }
  function scopeFacts(f) {
    SC.facts = f && typeof f === "object" ? f : null;
    scopeBar();
  }
  // A tile's drill-down (#devices?q=pass:latest) names no scope, so it
  // opens in the scope in force, the one its count was taken in, and
  // show() writes that scope into the address. No link is rewritten:
  // the page writes no attribute (test_routes.c).
  // Each view's first line names the scope it shows: a line of its own
  // above the view's panels, made once per view.
  function scopeView(v) {
    var box = $("v-" + v);
    if (!box) return;
    var line = box.firstElementChild;
    if (!line || !line.classList.contains("scopeline")) {
      line = el("div", "scopeline");
      line.appendChild(el("span", "scopechip"));
      box.insertBefore(line, box.firstChild);
    }
    var chip = line.firstChild;
    // sloth's own state is every scope's.
    var all = v === "health";
    chip.className = "scopechip" + (SCOPE === "hybrid" || all ? "" : " sc-" + SCOPE.charAt(0));
    chip.textContent = all ? "every scope: sloth's own state" : "scope: " + SCOPE_WORD[SCOPE];
  }
  function scopeUI() {
    for (var i = 0; i < SCOPES.length; i++) {
      var b = $("sc-" + SCOPES[i]), on = SCOPES[i] === SCOPE;
      // ARIA reflection, not an attribute write: the page has none.
      b.ariaChecked = on ? "true" : "false";
      b.tabIndex = on ? 0 : -1;
    }
    set("s-scope", SCOPE);
    $("v-wifi").classList.toggle("scoped-out", SCOPE === "local");
    $("v-wifi").classList.toggle("card-out", SCOPE === "monitor");
    $("v-flows").classList.toggle("scoped-out", SCOPE === "monitor");
    scopeBar();
    scopeView(view);
  }
  // 1 when the scope changed.
  function setScope(s) {
    if (SCOPES.indexOf(s) < 0 || s === SCOPE) return 0;
    SCOPE = s;
    try { window.localStorage.setItem(SCOPE_KEY, s); } catch (e) { /* this load only */ }
    SC.facts = null;
    scopeUI();
    // The ticker and the tiles start again in the new scope; an answer
    // still in flight from the old one is dropped (live()).
    liveGen++;
    set("k-anoms", "-");
    set("s-anoms", "-");
    TK.rows = [];
    tickerDraw();
    lastSeq = 0;
    held = 0;
    set("tick-note", "");
    first = true;
    live();
    return 1;
  }
  function pickScope(s) {
    if (!setScope(s)) return;
    show(view, VP);
    if (view === "lookup") lookup();
    if (!$("drawer").hidden && D.sel) openDrawer(D.sel);
  }
  SCOPES.forEach(function (s, i) {
    var b = $("sc-" + s);
    b.addEventListener("click", function () { pickScope(s); });
    b.addEventListener("keydown", function (e) {
      var d = e.key === "ArrowRight" || e.key === "ArrowDown" ? 1
            : e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 0;
      if (!d) return;
      e.preventDefault();
      var n = SCOPES[(i + d + SCOPES.length) % SCOPES.length];
      pickScope(n);
      $("sc-" + n).focus();
    });
  });
  function scopeLegend(open) {
    $("scope-legend").hidden = !open;
    $("scope-info").ariaExpanded = open ? "true" : "false";
  }
  $("scope-info").addEventListener("click", function () { scopeLegend($("scope-legend").hidden); });
  $("scopebar-legend").addEventListener("click", function () { scopeLegend(true); });
  $("scope-legend-close").addEventListener("click", function () {
    scopeLegend(false);
    $("scope-info").focus();
  });
  scopeUI();

  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") { closeDrawer(); scopeLegend(false); return; }
    // A focused row or card opens as a click would.
    var t = e.target;
    if ((e.key === "Enter" || e.key === " ") && t && t.tabIndex === 0 && t.classList &&
        (t.classList.contains("drow") || t.classList.contains("hrow") ||
         t.classList.contains("frow") || t.classList.contains("card") ||
         t.classList.contains("anrow") || t.classList.contains("alprow") ||
         t.classList.contains("rcrow") || t.classList.contains("go"))) {
      e.preventDefault();
      t.click();
      return;
    }
    if (e.target !== document.body) return;
    if (e.key === "[") $("app").classList.toggle("collapsed");
    if (e.key === "1") show("overview");
    if (e.key === "2") show("activity");
    if (e.key === "3") show("devices");
    if (e.key === "4") show("anomalies");
    if (e.key === "5") show("wifi");
    if (e.key === "6") show("alerts");
    if (e.key === "7") show("flows");
    if (e.key === "8") show("history");
    if (e.key === "9") show("lookup");
    // §3: search with /.
    if (e.key === "/") { e.preventDefault(); show("devices"); $("d-q").focus(); }
  });

  // ── drawing ───────────────────────────────────────────────────────
  // Charts are Canvas 2D, coloured from the theme.css tokens read back
  // at run time, so colour still lives in one place. Keys came off the
  // stream but were canonicalised by the server (a MAC, an IP, an
  // interface name, a channel, an alert type); they are shown with
  // textContent or fillText, kept in arrays and referenced by index,
  // and only ever leave as an encodeURIComponent()'d parameter of a
  // same-origin fetch.
  function css(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }
  // Read once per theme: the toggle clears it and redraws.
  var TH = null;
  function theme() {
    if (TH) return TH;
    TH = { ink: css("--ink"), muted: css("--muted"), faint: css("--faint"),
           rule: css("--rule"), data: css("--data"), signal: css("--signal"),
           bg: css("--bg"), panel: css("--panel"), bright: css("--tui-bright"),
           normal: css("--tui-normal"), dim: css("--tui-dim"), mon: css("--mon-bg"),
           monfg: css("--mon-fg"), k: [], heat: [], hot: [] };
    for (var i = 0; i < 8; i++) TH.k.push(css("--k-" + i));
    for (i = 0; i < 4; i++) TH.heat.push(css("--heat-" + i));
    for (i = 0; i < 3; i++) TH.hot.push(css("--hot-" + i));
    return TH;
  }
  // A key's colour from the TUI's hash, for a canvas or a swatch.
  function keyColor(k) {
    return theme().k[ipColorIndex(k)];
  }
  // draw_sparkline_at() (src/views/dashboard_primitives.c): a sample's
  // level is round(v / max x 8), at least 1 above zero; level 0 is
  // CP_DIM, 1-2 CP_NORMAL, 3-4 heat mid, 5-6 heat hi, 7-8 peak.
  function sparkLevel(v, max) {
    if (!(v > 0) || !(max > 0)) return 0;
    var l = Math.floor(v / max * 8 + 0.5);
    return l < 1 ? 1 : l > 8 ? 8 : l;
  }
  function sparkColor(l) {
    var T = theme();
    return l === 0 ? T.dim : l <= 2 ? T.normal : l <= 4 ? T.heat[1] : l <= 6 ? T.heat[2] : T.heat[3];
  }
  // The heat ramp's thresholds, tui_heat's 0.15 / 0.40 / 0.70.
  function heat(f) {
    var T = theme();
    return f < 0.15 ? T.heat[0] : f < 0.40 ? T.heat[1] : f < 0.70 ? T.heat[2] : T.heat[3];
  }

  function getJSON(path) {
    return fetch(scoped(path), { cache: "no-store" }).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok) {
          var e = new Error(j && typeof j.error === "string" ? j.error : String(r.status));
          e.body = j;
          throw e;
        }
        return j;
      });
    });
  }

  function seriesPath(m, key, tier, from, to) {
    var p = "/api/series?metric=" + encodeURIComponent(m) + "&tier=" + tier +
            "&from=" + from + "&to=" + to;
    if (key !== "") p += "&key=" + encodeURIComponent(key);
    return p;
  }

  // Pages back through "more"/"next_to" until the window is covered.
  function series(m, key, tier, from, to) {
    var all = [], pages = 0, src = "";
    function page(t) {
      return getJSON(seriesPath(m, key, tier, from, t)).then(function (j) {
        src = j.source;
        all = (j.points || []).concat(all);
        pages++;
        if (j.more && num(j.next_to) && j.next_to > from && pages < 12)
          return page(j.next_to);
        return { points: all, kind: j.kind, unit: j.unit, step: j.step, source: src };
      });
    }
    return page(to);
  }

  // The 168 cells of a series (/api/baseline), or null.
  function baseline(m, key) {
    var p = "/api/baseline?metric=" + encodeURIComponent(m);
    if (key !== "") p += "&key=" + encodeURIComponent(key);
    return getJSON(p).catch(function () { return null; });
  }

  // The server's cell for unix second t: the local hour of the week
  // its UTC hour bucket (t - t % 3600) was filed under, Monday 00:00
  // first, from the offset /api/baseline reported. The bucket's start,
  // not t itself, as the server scores: in a half-hour zone the two
  // differ for half of every hour.
  function cellOf(t, off) {
    var d = new Date((t - t % 3600 + off) * 1000);
    return ((d.getUTCDay() + 6) % 7) * 24 + d.getUTCHours();
  }

  // The band for each point, [lo, hi, mean, sd] or null where the cell
  // is warming. A cell is [mean, sd, n, sd_hour]: sd is a minute's
  // spread (week to week plus within the hour), sd_hour an hour
  // bucket's (week to week alone), so a bucket of an hour or more uses
  // sd_hour. A counter's baseline is per minute; its bucket of step
  // seconds is scaled to match.
  function bands(pts, bl, kind, step) {
    if (!bl || !bl.cells) return null;
    var scale = kind === "counter" ? 60 / step : 1;
    var out = [];
    for (var i = 0; i < pts.length; i++) {
      var c = bl.cells[cellOf(pts[i][0], bl.utc_offset_s || 0)];
      if (!c || c[2] < bl.warm_n) { out.push(null); continue; }
      var spread = step >= 3600 && num(c[3]) ? c[3] : c[1];
      var mean = c[0] / scale, sd = spread / scale;
      out.push([mean - sens * sd, mean + sens * sd, mean, sd]);
    }
    return out;
  }

  var A = { metrics: [], storeOn: false, keys: [], metric: -1, key: 0,
            last: null, timer: 0, gen: 0 };

  function tierFor(win) {
    if (win <= 86400) return "fine";
    if (!A.storeOn) return "fine";
    return win <= 2592000 ? "minute" : "hour";
  }

  function fmt(v) {
    if (!num(v)) return "-";
    var a = Math.abs(v);
    if (a >= 1e9) return (v / 1e9).toFixed(1) + "G";
    if (a >= 1e6) return (v / 1e6).toFixed(1) + "M";
    if (a >= 1e4) return (v / 1e3).toFixed(1) + "k";
    if (a >= 100 || v === Math.round(v)) return String(Math.round(v));
    return v.toFixed(2);
  }

  function sizeCanvas(c) {
    var dpr = window.devicePixelRatio || 1;
    var w = Math.max(1, Math.round(c.clientWidth * dpr));
    var h = Math.max(1, Math.round(c.clientHeight * dpr));
    if (c.width !== w) c.width = w;
    if (c.height !== h) c.height = h;
    return dpr;
  }

  // One chart: the bucket value as a line over the baseline band
  // (mean ± sensitivity x sd for each bucket's hour of the week, in 12%
  // --data, §8.12) when there is one, else over the bucket's min..max
  // (a gauge's spread inside its bucket). A segment out of the band is
  // drawn in the heat ramp, by how far out it is. Presence draws a
  // strip. A gap of more than two steps breaks the line.
  function draw(c, pts, opt) {
    var T = theme();
    var dpr = sizeCanvas(c);
    var g = c.getContext("2d");
    var W = c.width, H = c.height;
    var padL = opt.axes ? 48 * dpr : 2, padB = opt.axes ? 16 * dpr : 2;
    var padT = 4 * dpr, padR = 4 * dpr;
    var band = opt.band || null;
    g.clearRect(0, 0, W, H);
    var lo = 0, hi = 0;
    for (var i = 0; i < pts.length; i++) {
      var p = pts[i];
      var top = opt.kind === "gauge" && !band ? Math.max(p[1], p[3]) : p[1];
      var bot = opt.kind === "gauge" && !band ? Math.min(p[1], p[2]) : p[1];
      if (band && band[i]) { top = Math.max(top, band[i][1]); bot = Math.min(bot, band[i][0]); }
      if (top > hi) hi = top;
      if (bot < lo) lo = bot;
    }
    if (hi === lo) hi = lo + 1;
    var x0 = padL, x1 = W - padR, y0 = H - padB, y1 = padT;
    function X(t) { return x0 + (t - opt.from) / (opt.to - opt.from) * (x1 - x0); }
    function Y(v) { return y0 - (v - lo) / (hi - lo) * (y0 - y1); }
    if (opt.axes) {
      g.strokeStyle = T.rule;
      g.lineWidth = 1;
      g.beginPath(); g.moveTo(x0, y0 + 0.5); g.lineTo(x1, y0 + 0.5); g.stroke();
      g.fillStyle = T.muted;
      g.font = (10 * dpr) + "px " + css("--font-mono");
      g.textBaseline = "top";
      g.fillText(fmt(hi), 2 * dpr, y1);
      g.textBaseline = "bottom";
      g.fillText(fmt(lo), 2 * dpr, y0);
      g.textBaseline = "top";
      g.fillText(hhmmss(opt.from), x0, y0 + 2 * dpr);
      var endTxt = hhmmss(opt.to);
      g.fillText(endTxt, x1 - g.measureText(endTxt).width, y0 + 2 * dpr);
    }
    var gapS = opt.step * 2.5;
    if (opt.kind === "presence") {
      g.fillStyle = opt.color;
      var bw = Math.max(1, (x1 - x0) * opt.step / (opt.to - opt.from));
      for (i = 0; i < pts.length; i++)
        if (pts[i][1] > 0) g.fillRect(X(pts[i][0]), y1, bw, y0 - y1);
      return;
    }
    function fillRuns(loOf, hiOf, ok) {
      var run = [];
      var flush = function () {
        if (run.length < 1) return;
        g.beginPath();
        g.moveTo(X(run[0][0]), Y(hiOf(run[0])));
        for (var a = 1; a < run.length; a++) g.lineTo(X(run[a][0]), Y(hiOf(run[a])));
        for (var b = run.length - 1; b >= 0; b--) g.lineTo(X(run[b][0]), Y(loOf(run[b])));
        g.closePath();
        g.fill();
        run = [];
      };
      for (var k = 0; k < pts.length; k++) {
        if (!ok(k) || (k && pts[k][0] - pts[k - 1][0] > gapS)) flush();
        if (ok(k)) run.push(pts[k].concat([k]));
      }
      flush();
    }
    g.fillStyle = T.data;
    g.globalAlpha = 0.12;
    if (band) {
      fillRuns(function (r) { return band[r[5]][0]; }, function (r) { return band[r[5]][1]; },
               function (k) { return !!band[k]; });
    } else if (opt.kind === "gauge" && pts.length) {
      fillRuns(function (r) { return r[2]; }, function (r) { return r[3]; },
               function () { return true; });
    }
    g.globalAlpha = 1;
    g.lineWidth = Math.max(1, dpr);
    // A sparkline is graded by level, as the TUI's are.
    var smax = 0;
    if (opt.spark) for (i = 0; i < pts.length; i++) if (pts[i][1] > smax) smax = pts[i][1];
    for (i = 1; i < pts.length; i++) {
      if (pts[i][0] - pts[i - 1][0] > gapS) continue;
      var col = opt.color, b = band && band[i];
      if (opt.spark) {
        g.strokeStyle = sparkColor(sparkLevel(pts[i][1], smax));
        g.beginPath();
        g.moveTo(X(pts[i - 1][0]), Y(pts[i - 1][1]));
        g.lineTo(X(pts[i][0]), Y(pts[i][1]));
        g.stroke();
        continue;
      }
      if (b && b[3] > 0 && (pts[i][1] > b[1] || pts[i][1] < b[0])) {
        var z = Math.abs(pts[i][1] - b[2]) / b[3];
        col = heat(Math.min(1, (z - sens) / 4 + 0.15));
      }
      g.strokeStyle = col;
      g.beginPath();
      g.moveTo(X(pts[i - 1][0]), Y(pts[i - 1][1]));
      g.lineTo(X(pts[i][0]), Y(pts[i][1]));
      g.stroke();
    }
    if (pts.length === 1) {
      g.fillStyle = opt.color;
      g.fillRect(X(pts[0][0]), Y(pts[0][1]), dpr, dpr);
    }
  }

  // The hour-of-week heatmap (§8.4, §8.12): 7 rows from Monday, 24
  // columns, the heat ramp by the cell's mean against the largest, a
  // warming cell (fewer than warm_n samples) grey and hatched, the
  // current cell outlined in --signal.
  var DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  function heatmap(c, bl) {
    var T = theme();
    var dpr = sizeCanvas(c);
    var g = c.getContext("2d");
    var W = c.width, H = c.height;
    g.clearRect(0, 0, W, H);
    var padL = 32 * dpr, padT = 14 * dpr;
    var cw = (W - padL) / 24, ch = (H - padT) / 7;
    g.font = (9 * dpr) + "px " + css("--font-mono");
    g.fillStyle = T.muted;
    g.textBaseline = "middle";
    for (var d = 0; d < 7; d++) g.fillText(DAYS[d], 0, padT + ch * (d + 0.5));
    g.textBaseline = "top";
    for (var h = 0; h < 24; h += 3) g.fillText(String(h), padL + cw * h, 0);
    if (!bl) return;
    // Never fed: every cell is warming.
    var cells = bl.cells || [];
    var warm = num(bl.warm_n) ? bl.warm_n : 3;
    var max = 0;
    for (var i = 0; i < cells.length; i++)
      if (cells[i][2] >= warm && cells[i][0] > max) max = cells[i][0];
    for (i = 0; i < 168; i++) {
      var x = padL + cw * (i % 24), y = padT + ch * Math.floor(i / 24);
      var cell = cells[i] || [0, 0, 0];
      if (cell[2] < warm) {
        g.fillStyle = T.rule;
        g.fillRect(x + 1, y + 1, cw - 2, ch - 2);
        g.save();
        g.beginPath();
        g.rect(x + 1, y + 1, cw - 2, ch - 2);
        g.clip();
        // The hatch carries the meaning, so it is --muted, 3:1 or more
        // on --rule and on --panel (web/README.md, the graphics table).
        g.strokeStyle = T.muted;
        g.lineWidth = 1;
        g.beginPath();
        for (var s = -ch; s < cw; s += 4 * dpr) {
          g.moveTo(x + s, y + ch);
          g.lineTo(x + s + ch, y);
        }
        g.stroke();
        g.restore();
        continue;
      }
      g.fillStyle = heat(max > 0 ? cell[0] / max : 0);
      g.fillRect(x + 1, y + 1, cw - 2, ch - 2);
    }
    var nc = bl.now_cell;
    if (num(nc) && nc >= 0 && nc < 168) {
      g.strokeStyle = T.signal;
      g.lineWidth = 2 * dpr;
      g.strokeRect(padL + cw * (nc % 24) + dpr, padT + ch * Math.floor(nc / 24) + dpr,
                   cw - 2 * dpr, ch - 2 * dpr);
    }
  }

  // ── Overview (§8.4) ───────────────────────────────────────────────
  // Throughput is iface.rx_rate of the interface sloth reported most
  // recently; devices, alerts and anomalies are counts with no stored
  // series behind them, so only throughput has a band.
  var O = { key: null, gen: 0 };
  function overview() {
    var gen = ++O.gen;
    getJSON("/api/keys?metric=iface.rx_rate").then(function (j) {
      var ks = j.keys || [];
      // The keys are the scope's (the server's /api/keys): under
      // Monitor the monitor radio, whose rx is frames heard on the air;
      // under Local the host's own interfaces.
      if (!ks.length || typeof ks[0].key !== "string") {
        set("o-nvn-note", SCOPE === "hybrid" ? "no interface seen yet"
                          : "no " + SCOPE_WORD[SCOPE] + " interface seen yet");
        set("k-tp", "-");
        set("k-tp-key", "");
        return null;
      }
      O.key = ks[0].key;
      set("k-tp-key", O.key);
      set("k-tp-sub", SCOPE === "monitor" ? "the monitor radio's rx (frames heard), 24 h, band = mean ± k sd"
                      : "rx, 24 h, band = mean ± k sd");
      var now = Math.floor(Date.now() / 1000);
      var tier = A.storeOn ? "minute" : "fine";
      var step = tier === "minute" ? 60 : 10;
      var to = now - now % step + step, from = to - 86400;
      return Promise.all([series("iface.rx_rate", O.key, tier, from, to),
                          baseline("iface.rx_rate", O.key)])
        .then(function (r) {
          if (gen !== O.gen) return;
          var s = r[0], bl = r[1];
          var bd = bands(s.points, bl, s.kind, s.step);
          var last = s.points.length ? s.points[s.points.length - 1][1] : NaN;
          set("k-tp", fmt(last) + " B/s");
          var opt = { from: from, to: to, step: s.step, kind: s.kind,
                      color: theme().normal, band: bd };
          opt.axes = false;
          opt.spark = true;
          draw($("k-tp-spark"), s.points, opt);
          opt.axes = true;
          opt.spark = false;
          draw($("o-nvn"), s.points, opt);
          set("o-nvn-note", "iface.rx_rate " + O.key + ", 24 h, " + tier + " tier" +
              (bd ? "" : "; no baseline yet"));
          heatmap($("o-heat"), bl);
          set("o-heat-note", bl && bl.cells ? "iface.rx_rate " + O.key +
              ", mean B/s by local hour of the sensor host" : "no baseline yet");
        });
    }).catch(function (e) { set("o-nvn-note", "error: " + e.message); });
    anomalies();
  }

  // ── Anomalies (§8.7) ──────────────────────────────────────────────
  var N = { kind: "", gen: 0 };

  (function chips() {
    var box = $("n-chips");
    var all = ["all"].concat(KINDS);
    all.forEach(function (k) {
      var b = el("button", k === "all" ? "on" : "", (k === "all" ? "" : kindGlyph(k) + " ") + k);
      b.type = "button";
      b.addEventListener("click", function () {
        N.kind = k === "all" ? "" : k;
        for (var i = 0; i < box.childNodes.length; i++) box.childNodes[i].className = "";
        b.className = "on";
        anomalies();
      });
      box.appendChild(b);
    });
  })();
  $("n-win").addEventListener("change", function () { anomalies(); });

  function stamp(t) {
    if (!num(t)) return "-";
    var d = new Date(t * 1000);
    return d.toLocaleDateString() + " " + hhmmss(t);
  }

  // A rate episode's |z| is its score / 20 (web_anomaly.c z_score), so
  // the sensitivity hides those under it; the server fires at 3 sd, so
  // a setting below that shows what 3 shows.
  function shown(a) {
    return a.kind !== "rate" || !num(a.score) || a.score >= sens * 20 || a.score >= 100;
  }

  function card(a) {
    var c = el("div", "card " + (a.open ? "open" : "closed"));
    var hd = el("div", "hd");
    hd.appendChild(el("span", "gl", kindGlyph(a.kind)));
    hd.appendChild(el("span", "kd", a.kind + " " + a.rule));
    var ky = el("span", "ky");
    ky.appendChild(a.key !== "" ? keySpan(String(a.key)) : el("span", "d-dim", "(sensor)"));
    hd.appendChild(ky);
    c.appendChild(hd);
    var score = num(a.score) ? Math.max(0, Math.min(100, a.score)) : 0;
    var bar = el("div", "bar");
    var fill = el("i");
    fill.style.width = score + "%";
    fill.style.background = heat(score / 100);
    bar.appendChild(fill);
    c.appendChild(bar);
    c.appendChild(richText(el("div", "ev"), a.evidence, 0, "d-normal"));
    if (typeof a.metric === "string") {
      var cv = document.createElement("canvas");
      c.appendChild(cv);
      var now = Math.floor(Date.now() / 1000);
      var to = now - now % 10 + 10, from = to - 3600;
      getJSON(seriesPath(a.metric, a.key, "fine", from, to)).then(function (j) {
        draw(cv, j.points || [], { from: from, to: to, step: 10, kind: j.kind,
                                   color: theme().normal, axes: false, spark: true });
      }).catch(function () { /* the card stands without it */ });
    }
    c.appendChild(el("div", "tm", (a.open ? "open" : "closed") + "  score " + score +
                     "  first " + stamp(a.first_seen) + "  last " + stamp(a.last_seen)));
    // An episode keyed by a MAC opens that device's drawer (§8.7).
    if (typeof a.key === "string" && MAC_RE.test(a.key)) {
      c.className += " go";
      c.addEventListener("click", function () { openDrawer(a.key); });
      c.tabIndex = 0;
    }
    return c;
  }

  // The Anomalies view's episodes as a table too (the "table" button):
  // the same list, sortable and resizable.
  N.table = false;
  N.list = [];
  function anv(k) { return function (a) { return a[k]; }; }
  var DTN = DataTable({ id: "anoms", label: "anomaly episodes", box: $("n-tbox"), head: $("n-head"),
    reset: $("n-tools"), redraw: function () { anomTable(); }, cols: [
      { k: "st", label: "state", w: 7, type: "text", val: function (a) { return a.open ? "open" : "closed"; } },
      { k: "kd", label: "kind", w: 8, type: "text", val: anv("kind") },
      { k: "ru", label: "rule", w: 6, type: "text", val: anv("rule") },
      { k: "ky", label: "key", w: 20, flex: true, type: "text", val: anv("key") },
      { k: "sc", label: "score", w: 7, num: true, type: "num", val: anv("score") },
      { k: "fs", label: "first", w: 20, type: "time", val: anv("first_seen") },
      { k: "ls", label: "last", w: 20, type: "time", val: anv("last_seen") }
    ] });
  function anomTable() {
    var box = $("n-rows");
    while (box.firstChild) box.removeChild(box.firstChild);
    DTN.sort(N.list).forEach(function (a) {
      var row = el("div", "anrow dt-row" + (a.open ? " open" : ""));
      row.appendChild(el("span", a.open ? "warn" : "d-dim", a.open ? "open" : "closed"));
      row.appendChild(el("span", "d-normal", kindGlyph(a.kind) + " " + a.kind));
      row.appendChild(el("span", "d-dim", a.rule));
      var ky = el("span", "");
      ky.appendChild(a.key !== "" ? keySpan(String(a.key)) : el("span", "d-dim", "(sensor)"));
      row.appendChild(ky);
      var score = num(a.score) ? Math.max(0, Math.min(100, a.score)) : 0;
      row.appendChild(el("span", "n " + heatClass(score / 100), String(score)));
      row.appendChild(el("span", "d-dim", stamp(a.first_seen)));
      row.appendChild(el("span", "d-dim", stamp(a.last_seen)));
      if (typeof a.key === "string" && MAC_RE.test(a.key)) {
        row.classList.add("go");
        row.tabIndex = 0;
        row.addEventListener("click", function () { openDrawer(a.key); });
      }
      box.appendChild(row);
    });
    if (!N.list.length) box.appendChild(el("div", "sub", "nothing in this window"));
  }
  $("n-mode").addEventListener("click", function () {
    N.table = !N.table;
    $("n-mode").ariaPressed = N.table ? "true" : "false";
    set("n-mode", N.table ? "cards" : "table");
    $("n-cards").hidden = N.table;
    $("n-tbox").hidden = !N.table;
    $("n-tools").hidden = !N.table;
    if (N.table) anomTable();
  });

  function anomalies() {
    // The open-anomalies tile's view: every open episode, whatever the
    // sensitivity or the chips say, so the count is the tile's.
    var openOnly = view === "anomalies" && VP.state === "open";
    $("n-filter").hidden = !openOnly;
    if (openOnly) set("n-filter-t", "filtered: open episodes only, every one, the sensitivity not applied: the " +
                      $("k-anoms").textContent + " the Overview's open-anomalies tile counts");
    var gen = ++N.gen;
    var now = Math.floor(Date.now() / 1000);
    var win = Number($("n-win").value) || 3600;
    var p = "/api/anomalies?since=" + (now - win);
    if (N.kind) p += "&kind=" + encodeURIComponent(N.kind);
    getJSON(p).then(function (j) {
      if (gen !== N.gen) return;
      var list = (j.anomalies || []).filter(openOnly
        ? function (a) { return a.open === true && (!N.kind || a.kind === N.kind); } : shown);
      N.list = list;
      if (N.table) anomTable();
      var box = $("n-cards");
      while (box.firstChild) box.removeChild(box.firstChild);
      list.forEach(function (a) { box.appendChild(card(a)); });
      set("n-count", list.length + " shown" + (j.more ? ", " + j.omitted + " more on the server" : ""));
      set("n-note", list.length ? "" : "nothing in this window");
      // Overview's top five: open ones, highest score first (the
      // server's order), whatever the chips say.
      var top = $("o-anoms");
      while (top.firstChild) top.removeChild(top.firstChild);
      var open = (j.anomalies || []).filter(function (a) { return a.open && shown(a); });
      if (!open.length) top.appendChild(el("div", "sub", "none open"));
      open.slice(0, 5).forEach(function (a) { top.appendChild(card(a)); });
    }).catch(function (e) { set("n-note", "error: " + e.message); });
  }

  $("sens").addEventListener("input", function () {
    sens = Number($("sens").value) || 2;
    set("sens-v", sens.toFixed(1));
    try { window.localStorage.setItem(SENS_KEY, String(sens)); } catch (e) { /* none */ }
    if (view === "overview") overview();
    if (view === "activity") refresh();
    if (view === "anomalies") anomalies();
  });

  // ── Activity (spec §8.5) ──────────────────────────────────────────
  function selMetric() { return A.metrics[A.metric]; }

  function fillKeys() {
    var m = selMetric();
    var sel = $("a-key");
    while (sel.firstChild) sel.removeChild(sel.firstChild);
    if (!m) return Promise.resolve();
    if (m.keykind === "") {
      A.keys = [""];
      var o = el("option", "", "(global)");
      o.value = "0";
      sel.appendChild(o);
      return Promise.resolve();
    }
    return getJSON("/api/keys?metric=" + encodeURIComponent(m.name)).then(function (j) {
      A.keys = [];
      var ks = j.keys || [];
      for (var i = 0; i < ks.length; i++) if (typeof ks[i].key === "string") A.keys.push(ks[i].key);
      for (i = 0; i < A.keys.length; i++) {
        var op = el("option", "", A.keys[i]);
        op.value = String(i);
        sel.appendChild(op);
      }
      if (A.key >= A.keys.length) A.key = 0;
      sel.value = String(A.key);
      set("a-note", A.keys.length ? (j.total > A.keys.length ? A.keys.length + " of " + j.total + " keys" : "")
                                  : "no " + m.keykind + " seen yet");
    });
  }

  function mainChart() {
    var m = selMetric();
    if (!m || !A.keys.length) { set("a-title", m ? m.name : "-"); return; }
    var key = A.keys[A.key] || "";
    var win = Number($("a-win").value) || 3600;
    var tier = tierFor(win);
    if (tier === "fine" && win > 86400) win = 86400;
    var now = Math.floor(Date.now() / 1000);
    var step = tier === "fine" ? 10 : tier === "minute" ? 60 : 3600;
    var to = now - now % step + step, from = to - win;
    var gen = ++A.gen;
    set("a-title", m.name + (key ? "  " + key : "") + "  (" + m.unit + ")");
    Promise.all([series(m.name, key, tier, from, to), baseline(m.name, key)]).then(function (r) {
      if (gen !== A.gen) return;
      var s = r[0];
      var bd = bands(s.points, r[1], s.kind, s.step);
      A.last = { pts: s.points, from: from, to: to, step: s.step, kind: s.kind, band: bd };
      set("a-src", tier + " tier, " + s.points.length + " buckets, " + s.source +
          (bd ? ", band mean ± " + sens.toFixed(1) + " sd" : ", no baseline yet") +
          (!A.storeOn && Number($("a-win").value) > 86400 ? "; minute and hour tiers need a WITH_SQLITE build" : ""));
      draw($("a-chart"), s.points, { from: from, to: to, step: s.step, kind: s.kind,
                                     color: theme().normal, axes: true, band: bd });
    }).catch(function (e) { set("a-src", "error: " + e.message); });
  }

  // Small multiples: one sparkline per key over the last hour, the
  // highest current value first.
  function multiples() {
    var m = selMetric();
    var box = $("a-multi");
    if (!m) return;
    var keys = A.keys.slice(0, 24);
    var now = Math.floor(Date.now() / 1000);
    var to = now - now % 10 + 10, from = to - 3600;
    var gen = A.gen;
    Promise.all(keys.map(function (k) {
      return getJSON(seriesPath(m.name, k, "fine", from, to))
        .then(function (j) { return { key: k, pts: j.points || [], kind: j.kind }; })
        .catch(function () { return { key: k, pts: [], kind: m.kind }; });
    })).then(function (rows) {
      if (gen !== A.gen) return;
      rows.forEach(function (r) { r.cur = r.pts.length ? r.pts[r.pts.length - 1][1] : 0; });
      rows.sort(function (a, b) { return b.cur - a.cur; });
      while (box.firstChild) box.removeChild(box.firstChild);
      rows.forEach(function (r) {
        var cell = el("div", "cell" + (A.keys[A.key] === r.key ? " on" : ""));
        var nm = el("div", "nm");
        nm.appendChild(r.key ? keySpan(r.key) : el("span", "d-normal", "(global)"));
        cell.appendChild(nm);
        var cv = document.createElement("canvas");
        cell.appendChild(cv);
        cell.appendChild(el("div", "v", fmt(r.cur) + " " + m.unit));
        cell.addEventListener("click", function () {
          var i = A.keys.indexOf(r.key);
          if (i >= 0) { A.key = i; $("a-key").value = String(i); refresh(); }
        });
        box.appendChild(cell);
        draw(cv, r.pts, { from: from, to: to, step: 10, kind: r.kind,
                          color: theme().normal, axes: false, spark: true });
      });
      set("a-multi-note", A.keys.length > 24 ? "the 24 most recently seen of " + A.keys.length : "");
    });
  }

  function refresh() {
    if (view !== "activity") return;
    mainChart();
    multiples();
  }

  $("a-chart").addEventListener("mousemove", function (e) {
    var L = A.last;
    if (!L || !L.pts.length) return;
    var c = $("a-chart");
    var r = c.getBoundingClientRect();
    var padL = 48, padR = 4;
    var f = (e.clientX - r.left - padL) / Math.max(1, r.width - padL - padR);
    var t = L.from + f * (L.to - L.from);
    var bi = 0;
    for (var i = 1; i < L.pts.length; i++)
      if (Math.abs(L.pts[i][0] - t) < Math.abs(L.pts[bi][0] - t)) bi = i;
    var best = L.pts[bi], b = L.band && L.band[bi];
    set("a-hover", hhmmss(best[0]) + "  value " + fmt(best[1]) + "  min " + fmt(best[2]) +
        "  max " + fmt(best[3]) + "  n " + best[4] +
        (b ? "  baseline " + fmt(b[2]) + "  z " + (b[3] > 0 ? ((best[1] - b[2]) / b[3]).toFixed(1) : "-")
           : "  (warming: no baseline for this hour yet)"));
  });

  $("a-metric").addEventListener("change", function () {
    A.metric = Number($("a-metric").value) || 0;
    A.key = 0;
    fillKeys().then(refresh);
  });
  $("a-key").addEventListener("change", function () {
    A.key = Number($("a-key").value) || 0;
    refresh();
  });
  $("a-win").addEventListener("change", refresh);

  var started = false;
  function activity() {
    activityFocus();
    if (started) { fillKeys().then(refresh); return; }
    started = true;
    getJSON("/api/metrics").then(function (j) {
      A.storeOn = !!j.store;
      A.metrics = j.metrics || [];
      var sel = $("a-metric");
      var pick = 0;
      for (var i = 0; i < A.metrics.length; i++) {
        var o = el("option", "", A.metrics[i].name);
        o.value = String(i);
        sel.appendChild(o);
        if (A.metrics[i].name === "iface.rx_rate") pick = i;
      }
      A.metric = pick;
      sel.value = String(pick);
      return fillKeys();
    }).then(refresh).catch(function (e) { set("a-note", "error: " + e.message); });
    A.timer = setInterval(refresh, 10000);
  }

  // ── Devices (§8.6) ────────────────────────────────────────────────
  // sloth.db's devices that the query matches (§9.1; the server parses
  // and binds it), up to DEV_MAX rows paged in, drawn as a virtualised
  // table: only the rows in view exist, recycled as it scrolls. Every
  // value is set with textContent; the MAC's hash colour is on the
  // swatch only.
  var DEV_MAX = 512, DEV_PAGE = 200, ROW_H = 22;
  var D = { rows: [], gen: 0, timer: 0, pool: [], painting: false };
  var SEV_CLASS = ["", "r1", "r2", "r3"];
  var SRC_GLYPH = [[1, "A"], [2, "D"], [16, "P"], [8, "B"], [32, "S"]];
  var ERR_TEXT = {
    "no_sloth_db": "no sloth.db: start slothweb with --sloth-db PATH",
    "sloth_db_missing": "sloth.db is not there yet",
    "sloth_db_refused": "sloth.db was refused (see /api/health db_error)",
    "sloth_db_error": "sloth.db could not be read just now",
    "sloth_db_timeout": "sloth.db was too slow to answer; try again"
  };
  // j: the error's body, when the server said which read failed and how
  // far it got (/api/history/overview: query, rows_read, plan, budget_ms).
  function errText(m, j) {
    if (m === "no_sloth_db" && NOSQL)
      return "this slothweb was built without SQLite (WITH_SQLITE=0): it cannot read sloth.db; rebuild with make web";
    var t = Object.prototype.hasOwnProperty.call(ERR_TEXT, m) ? ERR_TEXT[m] : "error: " + m;
    if (j && typeof j.query === "string" && (m === "sloth_db_timeout" || m === "sloth_db_error")) {
      t += " (" + j.query.slice(0, 32);
      if (num(j.rows_read)) t += ": " + j.rows_read.toLocaleString("en-US") + " rows read";
      if (typeof j.plan === "string") t += " by " + j.plan.slice(0, 8);
      if (m === "sloth_db_timeout" && num(j.budget_ms)) t += " in " + j.budget_ms + " ms";
      t += ")";
    }
    return t;
  }

  // dir is the header's direction, "asc" or "desc", or none.
  function devicesPath(q, sort, offset, dir) {
    var p = "/api/devices?limit=" + DEV_PAGE + "&offset=" + offset +
            "&sort=" + encodeURIComponent(sort);
    if (q !== "") p += "&q=" + encodeURIComponent(q);
    if (dir === "asc" || dir === "desc") p += "&dir=" + dir;
    return p;
  }

  function dv(k) { return function (d) { return d[k]; }; }
  var DTD = DataTable({ id: "devices", label: "devices table", box: $("d-box"), head: $("d-head"),
    reset: $("d-tools"), server: function () { devices(); }, cols: [
      { k: "mac", label: "mac", w: 20, min: 8, type: "mac", srv: "mac", val: dv("mac") },
      { k: "ven", label: "vendor", w: 12, type: "text", srv: "vendor", val: dv("vendor") },
      { k: "ip", label: "ip", w: 15, type: "ip", srv: "ip", val: dv("ip") },
      { k: "nm", label: "name", w: 8, flex: true },
      { k: "ss", label: "ssid", w: 12, type: "text", srv: "ssid", val: dv("ssid") },
      { k: "sig", label: "dBm", w: 4, min: 3, num: true, type: "num", srv: "signal", val: dv("signal") },
      { k: "src", label: "src", w: 6, min: 3, type: "num", srv: "sources", val: dv("sources") },
      { k: "rk", label: "risk", w: 4, min: 3, type: "sev", srv: "risk", val: dv("risk") },
      { k: "fs", label: "first", w: 10, type: "time", srv: "first", val: dv("first_seen") },
      { k: "ls", label: "last", w: 10, type: "time", srv: "last", val: dv("last_seen") },
      { k: "z", label: "z", w: 4, min: 3 },
      { k: "an", label: "anom", w: 6, min: 3 },
      { k: "pr", label: "24 h presence", px: 146 }
    ] });

  function devices() {
    // A drill-down's query (the devices tile: pass:latest) is put in
    // the search box, so the filter applied is the one on screen, and
    // named in the bar above it; the view without one clears it.
    if (view === "devices") {
      if (typeof VP.q === "string") { $("d-q").value = VP.q; D.drill = VP.q; }
      else if (D.drill !== undefined) { if ($("d-q").value === D.drill) $("d-q").value = ""; D.drill = undefined; }
      $("d-filter").hidden = typeof VP.q !== "string";
      if (VP.q === "pass:latest")
        set("d-filter-t", "filtered: pass:latest, the devices in sloth's latest pass, the " +
            $("k-devs").textContent + " the Overview's devices tile counts");
      else if (typeof VP.q === "string") set("d-filter-t", "filtered: " + VP.q);
    }
    var gen = ++D.gen;
    var wd = DTD.word();
    var q = $("d-q").value.trim(), sort = wd ? wd.sort : $("d-sort").value, dir = wd ? wd.dir : "";
    var rows = [];
    function page(off) {
      return getJSON(devicesPath(q, sort, off, dir)).then(function (j) {
        if (gen !== D.gen) return;
        rows = rows.concat(j.rows || []);
        var more = !!j.more;
        if (more && num(j.next_offset) && rows.length < DEV_MAX) return page(j.next_offset);
        D.rows = DTD.sort(rows.slice(0, DEV_MAX), !more && rows.length <= DEV_MAX);
        set("d-count", D.rows.length + " shown" +
            (more || rows.length > DEV_MAX ? "; the first " + D.rows.length + ", narrow the search" : "") +
            (q.indexOf("pass:latest") >= 0 && num(j.pass_size)
              ? "; " + j.pass_size + " in the latest pass, " + D.rows.length + " of them in sloth.db" : ""));
        set("d-note", "vendor table " + j.vendor_table + ", sloth.db schema v" + j.db_schema);
        layout();
      });
    }
    page(0).catch(function (e) {
      if (gen !== D.gen) return;
      D.rows = [];
      set("d-count", "");
      set("d-note", errText(e.message));
      layout();
    });
  }

  function shortStamp(t) {
    if (!num(t)) return "-";
    var now = Date.now() / 1000;
    if (now - t < 86400 && now - t > -60) return hhmmss(t).slice(0, 5);
    var d = new Date(t * 1000);
    function two(n) { return (n < 10 ? "0" : "") + n; }
    return d.getFullYear() + "-" + two(d.getMonth() + 1) + "-" + two(d.getDate());
  }

  function srcGlyphs(bits) {
    var out = "";
    for (var i = 0; i < SRC_GLYPH.length; i++)
      out += (bits & SRC_GLYPH[i][0]) ? SRC_GLYPH[i][1] : ".";
    return out;
  }

  // The cells from the server's 36 hex digits, cell 0 the oldest, its
  // bit the high bit of the first digit; present in --phosphor, absent
  // in --bg (§8.12; present is CP_NORMAL's phosphor now, ruling
  // 2026-10-23). n of them across the width: 144 of 10 minutes on
  // the Devices view and the drawer, History's presence_cells over its
  // range (the rest of the 144 are past it).
  function drawStrip(c, hex, n) {
    var T = theme();
    var dpr = sizeCanvas(c);
    var g = c.getContext("2d");
    var W = c.width, H = c.height;
    g.fillStyle = T.bg;
    g.fillRect(0, 0, W, H);
    if (typeof hex !== "string" || !/^[0-9a-f]{36}$/.test(hex)) return;
    n = num(n) && n >= 1 && n <= 144 ? Math.floor(n) : 144;
    var cw = W / n;
    g.fillStyle = theme().normal;
    for (var i = 0; i < n; i++) {
      var v = parseInt(hex.charAt(i >> 2), 16);
      if (v & (8 >> (i & 3))) g.fillRect(Math.floor(i * cw), 0, Math.max(dpr, Math.ceil(cw)), H);
    }
  }

  function rowEl() {
    var r = { el: el("div", "drow dt-row"), k: -1, mac: "" };
    r.el.role = "row";
    var cols = ["c-mac", "c-ven", "c-ip", "c-nm", "c-ss", "c-sig", "c-src",
                "c-rk", "c-fs", "c-ls", "c-z", "c-an"];
    r.sw = el("span", "sw");
    r.cells = {};
    for (var i = 0; i < cols.length; i++) {
      var sp = el("span", cols[i]);
      r.cells[cols[i]] = sp;
      r.el.appendChild(sp);
    }
    r.macText = el("span", "");
    r.cells["c-mac"].appendChild(r.sw);
    r.cells["c-mac"].appendChild(r.macText);
    r.glyph = el("span", "gl");
    r.nameText = el("span", "");
    r.cells["c-nm"].appendChild(r.glyph);
    r.cells["c-nm"].appendChild(r.nameText);
    r.cv = document.createElement("canvas");
    r.el.appendChild(r.cv);
    r.el.addEventListener("click", function () { if (r.mac) openDrawer(r.mac); });
    r.el.tabIndex = 0;
    return r;
  }

  // One cell's content, replaced.
  function put(cell, node) {
    while (cell.firstChild) cell.removeChild(cell.firstChild);
    cell.appendChild(node);
  }

  // The TUI's device table (src/views/devices.c): the MAC in CP_DIM, a
  // known vendor and a name in CP_BRIGHT (an unknown one dim), source
  // and signal dim, the risk heat-graded by level (MED 0.4, HIGH 0.7,
  // CRIT 1.0, LOW dim), a non-zero count at heat 0.5; the address in
  // its hash colour, the SSID in its own, the name through the brands.
  var RISK_HEAT = [-1, 0.4, 0.7, 1.0];
  function fill(r, d) {
    r.mac = typeof d.mac === "string" ? d.mac : "";
    var risk = num(d.risk) && d.risk >= 0 && d.risk <= 3 ? d.risk : 0;
    r.el.className = "drow dt-row" + (SEV_CLASS[risk] ? " " + SEV_CLASS[risk] : "") +
                     (r.mac === D.sel ? " on" : "");
    r.sw.style.background = keyColor(r.mac);
    r.macText.className = d.random ? "rnd d-dim" : "d-dim";
    r.macText.textContent = (d.random ? "~" : "") + r.mac;
    r.cells["c-ven"].className = "c-ven " + (d.vendor === null ? "d-dim" : "d-bright");
    r.cells["c-ven"].textContent = d.vendor === null ? "?" : String(d.vendor);
    put(r.cells["c-ip"], isIP(d.ip) ? ipSpan(d.ip, IP_SRC.dev)
                                    : el("span", "d-normal", d.ip === null ? "-" : String(d.ip)));
    r.glyph.textContent = d.name_src === null ? "" : String(d.name_src) + " ";
    while (r.nameText.firstChild) r.nameText.removeChild(r.nameText.firstChild);
    if (d.name === null) r.nameText.appendChild(el("span", "d-normal", "-"));
    else brandText(r.nameText, String(d.name), "d-bright");
    put(r.cells["c-ss"], d.ssid === null ? el("span", "d-dim", "-") : ssidSpan(String(d.ssid), d.ssid_k, d.ssid_np));
    r.cells["c-sig"].className = "c-sig d-dim";
    r.cells["c-sig"].textContent = num(d.signal) ? String(d.signal) : "-";
    r.cells["c-src"].className = "c-src d-dim";
    r.cells["c-src"].textContent = srcGlyphs(num(d.sources) ? d.sources : 0);
    r.cells["c-rk"].className = "c-rk " + (RISK_HEAT[risk] > 0 ? heatClass(RISK_HEAT[risk]) : "d-dim");
    r.cells["c-rk"].textContent = String(risk);
    r.cells["c-fs"].className = "c-fs d-dim";
    r.cells["c-fs"].textContent = shortStamp(d.first_seen);
    r.cells["c-ls"].className = "c-ls d-dim";
    r.cells["c-ls"].textContent = shortStamp(d.last_seen);
    r.cells["c-z"].className = "c-z d-normal";
    r.cells["c-z"].textContent = num(d.z) ? d.z.toFixed(1) : "-";
    var an = num(d.anomalies) ? d.anomalies : 0;
    r.cells["c-an"].className = "c-an " + (an > 0 ? heatClass(0.5) : "d-dim");
    r.cells["c-an"].textContent = String(an);
    drawStrip(r.cv, d.presence);
  }

  function layout() {
    $("d-space").style.height = (D.rows.length * ROW_H) + "px";
    for (var i = 0; i < D.pool.length; i++) D.pool[i].k = -1;
    paint();
  }

  function paint() {
    D.painting = false;
    var sc = $("d-scroll");
    var first = Math.max(0, Math.floor(sc.scrollTop / ROW_H) - 5);
    var n = Math.ceil((sc.clientHeight || 600) / ROW_H) + 10;
    var box = $("d-rows");
    while (D.pool.length < n) {
      var nr = rowEl();
      D.pool.push(nr);
      box.appendChild(nr.el);
    }
    for (var i = 0; i < D.pool.length; i++) {
      var r = D.pool[i], k = first + i;
      if (i >= n || k >= D.rows.length) { r.el.hidden = true; r.k = -1; r.mac = ""; continue; }
      r.el.hidden = false;
      r.el.style.top = (k * ROW_H) + "px";
      if (r.k !== k) { fill(r, D.rows[k]); r.k = k; }
    }
  }

  $("d-scroll").addEventListener("scroll", function () {
    if (D.painting) return;
    D.painting = true;
    window.requestAnimationFrame(paint);
  });
  $("d-q").addEventListener("input", function () {
    if (D.timer) clearTimeout(D.timer);
    D.timer = setTimeout(function () { D.timer = 0; devices(); }, 300);
  });
  $("d-q").addEventListener("keydown", function (e) {
    if (e.key === "Enter") { if (D.timer) clearTimeout(D.timer); D.timer = 0; devices(); }
  });
  $("d-sort").addEventListener("change", function () { DTD.clear(); devices(); });

  // ── the drawer (§8.6) ─────────────────────────────────────────────
  // Everything /api/device/MAC knows about one device. The MAC reaches
  // the server only as an encodeURIComponent()'d path segment.
  var DR = { gen: 0 };

  function closeDrawer() {
    $("drawer").hidden = true;
    D.sel = "";
    for (var i = 0; i < D.pool.length; i++) D.pool[i].k = -1;
    if (view === "devices") paint();
    if (DR.back && DR.back.focus && document.body.contains(DR.back)) DR.back.focus();
    DR.back = null;
  }
  $("dr-close").addEventListener("click", closeDrawer);

  // A value is a string (in CP_NORMAL) or a node already coloured.
  function valNode(cls, v) {
    if (v instanceof Node) { var w = el("span", cls); w.appendChild(v); return w; }
    return el("span", cls + " d-normal", v === null || v === undefined ? "-" : v);
  }

  function kvList(box, pairs) {
    var kv = el("div", "kv");
    for (var i = 0; i < pairs.length; i++) {
      if (pairs[i][1] === null || pairs[i][1] === undefined || pairs[i][1] === "") continue;
      kv.appendChild(el("span", "k", pairs[i][0]));
      kv.appendChild(valNode("v", pairs[i][1]));
    }
    box.appendChild(kv);
  }

  // The drawer's and Lookup's coloured values; null stays null, so the
  // row is left out as before.
  function ipVal(v, bit) { return v === null || v === undefined ? null : isIP(String(v)) ? ipSpan(String(v), bit) : String(v); }
  function hostVal(v, extra) {
    if (v === null || v === undefined || v === "") return null;
    var sp = brandSpan(String(v), "d-bright");
    if (extra) sp.appendChild(el("span", "d-dim", extra));
    return sp;
  }
  function ssidVal(v, k, np) { return v === null || v === undefined ? null : ssidSpan(String(v), k, np); }
  function macVal(v) { return v === null || v === undefined ? null : el("span", "d-dim", String(v)); }

  // The drawer's and Lookup's lists are tables too: when, and what,
  // the value sorted as its kind is.
  var ITEM_SORT = {
    "names (passive)": ["text", "name"], "pnl ssids": ["text", "ssid"],
    "associations": ["mac", "bssid"], "arp addresses": ["ip", "addr"],
    "arp macs": ["mac", "addr"], "alerts naming it": ["text", "title"]
  };
  // link, when given, names an item's alert page ("" for none).
  function itemList(box, title, items, line, more, link) {
    var lab = el("div", "label", title + (more ? " (more than shown)" : ""));
    var tools = el("span", "dt-tools");
    lab.appendChild(tools);
    box.appendChild(lab);
    var how = Object.prototype.hasOwnProperty.call(ITEM_SORT, title) ? ITEM_SORT[title] : ["text", "name"];
    var wrap = el("div", "hscroll"), head = el("div", "lsrow dhead"), ol = el("ol", "lst");
    wrap.appendChild(head);
    wrap.appendChild(ol);
    box.appendChild(wrap);
    function draw() {
      while (ol.firstChild) ol.removeChild(ol.firstChild);
      if (!items || !items.length) { ol.appendChild(el("li", "sub", "none")); return; }
      t.sort(items).forEach(function (it) {
        var li = el("li", "lsrow dt-row");
        li.appendChild(el("span", "ts", shortStamp(it.last_seen)));
        li.appendChild(valNode("tx", line(it)));
        if (link && link(it)) alertLink(li, link(it));
        ol.appendChild(li);
      });
    }
    var t = DataTable({ id: "item." + title, label: title, box: wrap, head: head, reset: tools, redraw: draw,
      cols: [{ k: "ls", label: "last", w: 10, type: "time", val: function (x) { return x.last_seen; } },
             { k: "v", label: title, w: 24, flex: true, type: how[0], val: function (x) { return x[how[1]]; } }] });
    draw();
  }

  function ouiPairs(o) {
    if (!o) return [];
    return [["vendor", o.found ? o.vendor : "not in the " + o.table + " table"],
            ["block", o.found ? o.block + " (" + o.registry + ", " + o.bits + " bits)" : null],
            ["registered", o.found ? (o["private"] ? "private" : "vendor") : null],
            ["locally adm.", o.local ? "yes: randomised or software mac" : "no"],
            ["multicast", o.multicast ? "yes" : "no"],
            ["table", o.table + (o.full ? "" : " (not the full IEEE registry)")]];
  }

  function nameLine(n) {
    return hostVal(n.name, "  (" + n.src + ", " + n.where + ")");
  }

  function openDrawer(mac) {
    if (typeof mac !== "string" || !MAC_RE.test(mac)) return;
    var gen = ++DR.gen;
    D.sel = mac;
    for (var i = 0; i < D.pool.length; i++) D.pool[i].k = -1;
    if (view === "devices") paint();
    // Keyboard: what opened the drawer gets the focus back when it closes.
    if ($("drawer").hidden) DR.back = document.activeElement;
    $("drawer").hidden = false;
    $("dr-close").focus();
    set("dr-mac", mac);
    $("dr-sw").style.background = keyColor(mac);
    $("dr-mac").className = "d-dim";
    set("dr-note", "loading");
    getJSON("/api/device/" + encodeURIComponent(mac)).then(function (j) {
      if (gen !== DR.gen) return;
      var box = $("dr-body");
      while (box.firstChild) box.removeChild(box.firstChild);
      set("dr-note", (j.db === "open" ? "sloth.db record" + (j.record ? "" : ": none")
                                      : "sloth.db " + j.db + "; the stream only") +
          (j.in_scope === false ? "; not heard in the " + SCOPE_WORD[SCOPE] + " scope" : "") +
          (SCOPE !== "hybrid" ? "; " + SCOPE_WORD[SCOPE] + "'s fields and presence only" : ""));
      var r = j.record, dt = r && r.detail ? r.detail : {};
      kvList(box, ouiPairs(j.oui).concat(r ? [
        ["ip", ipVal(r.ip, IP_SRC.dev)],
        ["name", r.name === null ? null : hostVal(r.name, " (" + r.name_src + ")")],
        ["hostname", hostVal(dt.hostname)], ["last ssid", ssidVal(r.ssid, r.ssid_k, r.ssid_np)],
        ["signal", num(r.signal) ? r.signal + " dBm" : null],
        ["sources", srcGlyphs(r.sources)], ["risk", String(r.risk)],
        ["first seen", stamp(r.first_seen)], ["last seen", stamp(r.last_seen)],
        ["z now", num(r.z) ? r.z.toFixed(1) : null],
        ["camera", dt.camera_vendor ? dt.camera_vendor + (dt.camera_model ? " " + dt.camera_model : "") : null],
        ["dhcp vci", dt.dhcp_vci]
      ] : [["stream ip", j.stream ? ipVal(j.stream.ip, IP_SRC.dev) : null],
           ["stream first seen", j.stream && num(j.stream.first_seen) ? stamp(j.stream.first_seen) : null]]));
      itemList(box, "names (passive)", j.names, nameLine, false);
      itemList(box, "pnl ssids", j.ssids, function (x) { return ssidSpan(String(x.ssid), x.ssid_k, x.ssid_np); }, j.ssids_more);
      itemList(box, "associations", j.assocs, function (x) {
        var sp = el("span", "");
        sp.appendChild(el("span", "d-dim", x.bssid + "  "));
        if (x.ssid !== null) sp.appendChild(ssidSpan(String(x.ssid), x.ssid_k, x.ssid_np));
        sp.appendChild(el("span", "d-normal", "  ch " + x.channel +
                          (num(x.signal) ? "  " + x.signal + " dBm" : "") + "  source " + x.source));
        return sp;
      }, j.assocs_more);
      itemList(box, "arp addresses", j.ips, function (x) { return ipVal(x.addr, IP_SRC.arp); }, j.ips_more);
      itemList(box, "alerts naming it", j.alerts, function (x) {
        var ok = x.sev >= 0 && x.sev <= 2;
        var sp = el("span", ok ? "sev" + x.sev : "");
        sp.appendChild(el("span", "ty", ok ? SEV_WORD[x.sev] : "?"));
        sp.appendChild(el("span", "d-bright", "  " + x.title));
        sp.appendChild(el("span", x.count > 1 ? heatClass(0.6) : "d-dim", "  x" + x.count));
        if (num(x.incidents) && x.incidents > 1)
          sp.appendChild(el("span", heatClass(0.6), "  " + x.incidents + " incidents"));
        return sp;
      }, j.alerts_more, function (x) { return typeof x.id === "string" ? x.id : ""; });
      // The request's budget stopped sloth.db's walk short of the table's
      // end: the list and its figures are of the rows back to here.
      if (num(j.alerts_reached))
        box.appendChild(el("div", "sub", "alerts read back to " + stamp(j.alerts_reached) +
                           " only (the request's time budget)"));
      drawStrip($("dr-strip"), j.presence);
      var wk = j.week || {};
      var cells = null;
      if (wk.cells && wk.cells.length === 168) {
        cells = [];
        for (var c = 0; c < 168; c++) cells.push([wk.cells[c][0], 0, wk.cells[c][1]]);
      }
      heatmap($("dr-week"), { cells: cells, warm_n: wk.warm_n, now_cell: wk.now_cell });
      set("dr-week-note", cells ? "share of weeks present" : "no baseline yet");
      var an = $("dr-anoms");
      while (an.firstChild) an.removeChild(an.firstChild);
      if (!j.anomalies || !j.anomalies.length) an.appendChild(el("div", "sub", "none"));
      (j.anomalies || []).forEach(function (a) { an.appendChild(card(a)); });
    }).catch(function (e) { if (gen === DR.gen) set("dr-note", errText(e.message)); });
  }

  // ── Lookup (§8.11) ────────────────────────────────────────────────
  // One input, a MAC or an IP. The card is the vendor block and its
  // bits, every passive name with its source and when, and sloth's
  // record. There is no active query: nothing here sends a packet.
  var L = { gen: 0 };
  function lookup() {
    var q = $("l-q").value.trim();
    if (q === "") return;
    var gen = ++L.gen;
    getJSON("/api/lookup?q=" + encodeURIComponent(q)).then(function (j) {
      if (gen !== L.gen) return;
      var box = $("l-card");
      while (box.firstChild) box.removeChild(box.firstChild);
      set("l-src", j.kind + " " + j.q + ", sloth.db " + j.db + (j.ip_in_scope === false
        ? "; Monitor holds no addresses: an IP is the host's own interfaces' (Local)" : ""));
      kvList(box, j.kind === "mac" ? ouiPairs(j.oui) : [["ip", ipVal(j.q, 0)]]);
      itemList(box, "names (passive)", j.names, nameLine, false);
      if (j.kind === "mac")
        itemList(box, "arp addresses", j.ips, function (x) { return ipVal(x.addr, IP_SRC.arp); }, j.ips_more);
      else
        itemList(box, "arp macs", j.macs, function (x) { return macVal(x.addr); }, j.macs_more);
      var d = j.device;
      if (d) {
        kvList(box, [["sloth.db", macVal(d.mac)],
                     ["vendor", d.vendor === null ? null : el("span", "d-bright", String(d.vendor))],
                     ["name", hostVal(d.name)], ["last seen", stamp(d.last_seen)]]);
        var b = el("button", "", "open the drawer");
        b.type = "button";
        b.addEventListener("click", function () { openDrawer(d.mac); });
        box.appendChild(b);
      } else {
        box.appendChild(el("div", "sub", "no sloth.db record"));
      }
    }).catch(function (e) { if (gen === L.gen) set("l-src", errText(e.message)); });
  }
  $("l-go").addEventListener("click", lookup);
  $("l-q").addEventListener("keydown", function (e) { if (e.key === "Enter") lookup(); });

  // ── WiFi (§8.8, M5) ───────────────────────────────────────────────
  // The channel waterfall from /api/wifi/channels, the AP table from
  // /api/wifi/aps (sloth.db through the reader's allow-list), the
  // deauth timeline from /api/wifi/deauth, and probe clients from
  // /api/series with its baseline band. Channel keys, BSSIDs and SSIDs
  // are drawn with fillText or set with textContent, never as markup.
  var WF = { gen: 0, heat: null, mix: null, rows: [], cur: null, apEls: new Map(), geo: null };
  var AP_SORTS = { "last": 1, "ssids": 1, "karma": 1, "bssid": 1 };
  var BAND_WORD = { "2.4": "2.4 GHz", "5": "5 GHz", "6": "6 GHz" };

  function wifiWindow() {
    var win = Number($("w-win").value) || 3600;
    var now = Math.floor(Date.now() / 1000);
    var to = now - now % 10 + 10;
    return { from: to - win, to: to, win: win };
  }

  function wifiGridPath(route, metric, r) {
    var p = "/api/wifi/" + route + "?from=" + r.from + "&to=" + r.to + "&cols=96";
    if (metric !== "") p += "&metric=" + encodeURIComponent(metric);
    return p;
  }

  // The channel x time grid (owner request 2026-10-26). Rows are
  // channels, bands grouped with a rule between them. Each cell is a
  // stacked bar of the busiest five transmitters on that channel in that
  // cell (/api/wifi/channels?mix=1), each band's height its share of the
  // cell's frames, the busiest at the bottom and the rest one grey band
  // on top; an AP in its SSID's hash colour (the server's ssid_k, hashed
  // over the octets, as tui_ssid_addstr() colours it), a client in its
  // MAC's, every cell on CP_MON_ROW's ground: all of it was heard by the
  // monitor radio. A thin strip at each row's left is the row's
  // busyness in the metric the view shows (APs per channel, control
  // frames), in the heat ramp against the busiest row. A cell the mix
  // holds nothing for (the memory ring has moved past it) keeps the
  // heat ramp, dimmed. Pointer, tap or the arrow keys pick a cell; the
  // list under the grid names its five.
  var BAND_RANK = { "2.4": 0, "5": 1, "6": 2 };
  function bandRank(b) { return Object.prototype.hasOwnProperty.call(BAND_RANK, b) ? BAND_RANK[b] : 3; }
  function chanNum(k) { return parseInt(String(k).replace(/^6g/, ""), 10) || 0; }

  function gridRows() {
    var by = new Map(), out = [];
    function add(r) {
      var k = String(r.key), e = by.get(k);
      if (!e) { e = { key: k, band: String(r.band), heat: null, mix: null }; by.set(k, e); out.push(e); }
      return e;
    }
    ((WF.heat && WF.heat.channels) || []).forEach(function (r) { add(r).heat = r; });
    ((WF.mix && WF.mix.channels) || []).forEach(function (r) { add(r).mix = r; });
    out.sort(function (a, b) {
      var d = bandRank(a.band) - bandRank(b.band);
      if (d) return d;
      d = chanNum(a.key) - chanNum(b.key);
      if (d) return d;
      return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
    });
    return out;
  }

  // A row's busyness in the shown metric: a gauge's mean over the cells
  // it has, a counter's sum.
  function rowBusy(r) {
    if (!r.heat || !r.heat.cells) return 0;
    var s = 0, n = 0;
    r.heat.cells.forEach(function (v) { if (num(v)) { s += v; n++; } });
    if (!n) return 0;
    return WF.heat.kind === "gauge" ? s / n : s;
  }

  function txOf(i) {
    var t = WF.mix && WF.mix.tx && WF.mix.tx[i];
    return t && typeof t.id === "string" ? t : null;
  }

  // A band's colour: an AP by its SSID's hash (by its BSSID when it has
  // no name), a client by its MAC's.
  function txColor(t) {
    var T = theme();
    if (!t) return T.heat[0];
    if (t.kind === "ap" && num(t.ssid_k) && t.ssid !== null && t.ssid_k >= 0 && t.ssid_k < 8)
      return T.k[t.ssid_k];
    return keyColor(t.id);
  }

  function channelGrid() {
    var c = $("w-heat");
    var T = theme();
    var dpr = sizeCanvas(c);
    var g = c.getContext("2d");
    var W = c.width, H = c.height;
    g.clearRect(0, 0, W, H);
    var rows = gridRows();
    WF.rows = rows;
    var cols = (WF.mix && num(WF.mix.cols)) ? WF.mix.cols : (WF.heat && num(WF.heat.cols)) ? WF.heat.cols : 0;
    var col_s = (WF.mix && WF.mix.col_s) || (WF.heat && WF.heat.col_s) || 0;
    var from = (WF.mix && WF.mix.from) || (WF.heat && WF.heat.from) || 0;
    WF.geo = null;
    var note = rows.length + " channels";
    if (WF.heat) note += ", " + WF.heat.tier + " tier, " + fmt(WF.heat.col_s) + " s cells" +
                         (WF.heat.more ? ", more channels than shown" : "");
    set("w-heat-note", note);
    if (WF.mix) {
      var nm = (WF.mix.tx || []).length;
      set("w-mix-note", nm + " transmitters, " + WF.mix.source +
          (WF.mix.folded ? "; some folded into other" : "") +
          (WF.mix.more ? "; more channels than shown" : "") +
          (num(WF.mix.ring_from) && WF.mix.ring_from > from
            ? "; detail held from " + hhmmss(WF.mix.ring_from) : ""));
    }
    if (!rows.length || !cols) { mixDetail(); return; }
    var busy = rows.map(rowBusy), bmax = 0;
    busy.forEach(function (v) { if (v > bmax) bmax = v; });
    var hmax = 0;
    rows.forEach(function (r) {
      ((r.heat && r.heat.cells) || []).forEach(function (v) { if (num(v) && v > hmax) hmax = v; });
    });
    var padL = 40 * dpr, strip = 6 * dpr, x0 = padL + strip + 2 * dpr;
    var rh = Math.max(2 * dpr, Math.floor((H - 2 * dpr) / rows.length));
    var cw = (W - x0) / Math.max(1, cols);
    WF.geo = { x0: x0, rh: rh, cw: cw, cols: cols, col_s: col_s, from: from, dpr: dpr };
    g.font = Math.min(10 * dpr, rh) + "px " + css("--font-mono");
    g.textBaseline = "middle";
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i], y = i * rh;
      if (i && rows[i - 1].band !== r.band) {
        g.fillStyle = T.rule;
        g.fillRect(0, y, W, Math.max(1, dpr));
      }
      g.fillStyle = T.muted;
      g.fillText(r.key, 2 * dpr, y + rh / 2);
      g.fillStyle = busy[i] > 0 ? heat(bmax > 0 ? busy[i] / bmax : 0) : T.rule;
      g.fillRect(padL, y + dpr, strip, rh - dpr);
      g.fillStyle = T.mon;
      g.fillRect(x0, y + dpr, W - x0, rh - dpr);
      for (var k = 0; k < cols; k++) {
        var x = x0 + k * cw, w = Math.max(dpr, Math.ceil(cw) - (cw > 3 * dpr ? dpr : 0));
        var m = r.mix && r.mix.cells ? r.mix.cells[k] : null;
        if (Array.isArray(m) && num(m[0]) && m[0] > 0) {
          var tot = m[0], yy = y + rh, hh = rh - dpr;
          for (var e = 2; e + 1 < m.length; e += 2) {
            var bh = hh * m[e + 1] / tot;
            g.fillStyle = txColor(txOf(m[e]));
            yy -= bh;
            g.fillRect(x, yy, w, bh);
          }
          if (num(m[1]) && m[1] > 0) {
            var oh = hh * m[1] / tot;
            g.fillStyle = T.heat[0];
            yy -= oh;
            g.fillRect(x, yy, w, oh);
          }
          continue;
        }
        var v = r.heat && r.heat.cells ? r.heat.cells[k] : null;
        if (!num(v) || v <= 0) continue;
        g.globalAlpha = 0.45;
        g.fillStyle = heat(hmax > 0 ? v / hmax : 0);
        g.fillRect(x, y + dpr, w, rh - dpr);
        g.globalAlpha = 1;
      }
    }
    var cur = WF.cur;
    if (cur && cur.r < rows.length && cur.c < cols) {
      g.strokeStyle = T.signal;
      g.lineWidth = Math.max(1, dpr);
      g.strokeRect(x0 + cur.c * cw + 0.5, cur.r * rh + 0.5, Math.max(dpr, cw - 1), rh - 1);
    }
    mixDetail();
  }

  // The list under the grid: the picked cell's five, each a button that
  // opens the device drawer (a client) or brings its AP's row into view
  // (an AP), and the rest; on CP_MON_ROW's ground, as monitor rows are.
  function mixDetail() {
    var box = $("w-mix");
    while (box.firstChild) box.removeChild(box.firstChild);
    var cur = WF.cur, rows = WF.rows, geo = WF.geo;
    if (!cur || !geo || cur.r >= rows.length || cur.c >= geo.cols) {
      box.appendChild(el("div", "sub", "point at, tap or arrow to a cell for who was transmitting"));
      return;
    }
    var r = rows[cur.r], t0 = geo.from + cur.c * geo.col_s;
    var m = r.mix && r.mix.cells ? r.mix.cells[cur.c] : null;
    var hv = r.heat && r.heat.cells ? r.heat.cells[cur.c] : null;
    var head = "ch " + r.key + "  " + hhmmss(t0) + " to " + hhmmss(t0 + geo.col_s);
    if (Array.isArray(m) && num(m[0])) head += "  " + fmt(m[0]) + " frames";
    if (num(hv)) head += "  (" + (WF.heat.metric === "wifi.ctrl_total" ? "control frames " : "APs ") + fmt(hv) + ")";
    box.appendChild(el("div", "label", head));
    if (!Array.isArray(m) || !num(m[0]) || m[0] <= 0) {
      box.appendChild(el("div", "sub", "no transmitter detail for this cell"));
      return;
    }
    var ol = el("ol", "mixl");
    function share(f) { return (100 * f / m[0]).toFixed(f * 1000 < m[0] ? 2 : 1) + "%"; }
    for (var e = 2; e + 1 < m.length; e += 2) {
      var t = txOf(m[e]);
      if (!t) continue;
      var li = el("li", "mon");
      var b = el("button", "mixgo");
      b.type = "button";
      var sw = el("span", "sw");
      sw.style.background = txColor(t);
      b.appendChild(sw);
      var nm = el("span", "nm");
      if (t.kind === "ap") {
        nm.appendChild(t.ssid === null || t.ssid === undefined ? el("span", "d-dim", "(no name)")
                                                                : ssidSpan(String(t.ssid), t.ssid_k, t.ssid_np));
        nm.appendChild(el("span", "d-dim", "  " + t.id + "  AP"));
      } else {
        nm.appendChild(el("span", "d-normal", t.id));
        nm.appendChild(el("span", "d-dim", (typeof t.vendor === "string" ? "  " + t.vendor : "") + "  client"));
      }
      b.appendChild(nm);
      b.appendChild(el("span", "n d-bright", fmt(m[e + 1])));
      b.appendChild(el("span", "n d-normal", share(m[e + 1])));
      b.addEventListener("click", mixGo(t));
      li.appendChild(b);
      ol.appendChild(li);
    }
    if (num(m[1]) && m[1] > 0) {
      var lo = el("li", "mon");
      var row = el("span", "mixgo");
      var so = el("span", "sw");
      so.style.background = theme().heat[0];
      row.appendChild(so);
      row.appendChild(el("span", "nm d-dim", "other transmitters"));
      row.appendChild(el("span", "n d-bright", fmt(m[1])));
      row.appendChild(el("span", "n d-normal", share(m[1])));
      lo.appendChild(row);
      ol.appendChild(lo);
    }
    box.appendChild(ol);
  }

  function mixGo(t) {
    return function () {
      if (t.kind !== "ap") { openDrawer(t.id); return; }
      var row = WF.apEls.get(t.id);
      if (!row) {
        set("w-mix-note", t.id + " is not among the access points loaded below");
        return;
      }
      WF.apEls.forEach(function (x) { x.classList.remove("hl"); });
      row.classList.add("hl");
      row.tabIndex = -1;
      row.scrollIntoView({ block: "nearest" });
      row.focus();
    };
  }

  function gridPick(ev) {
    var c = $("w-heat"), geo = WF.geo;
    if (!geo) return;
    var b = c.getBoundingClientRect();
    var px = (ev.clientX - b.left) * (c.width / Math.max(1, b.width));
    var py = (ev.clientY - b.top) * (c.height / Math.max(1, b.height));
    var col = Math.floor((px - geo.x0) / geo.cw), row = Math.floor(py / geo.rh);
    if (col < 0 || col >= geo.cols || row < 0 || row >= WF.rows.length) return;
    if (WF.cur && WF.cur.r === row && WF.cur.c === col) return;
    WF.cur = { r: row, c: col };
    channelGrid();
  }
  $("w-heat").tabIndex = 0;
  $("w-heat").addEventListener("pointermove", function (ev) { if (ev.pointerType === "mouse") gridPick(ev); });
  $("w-heat").addEventListener("pointerdown", gridPick);
  $("w-heat").addEventListener("keydown", function (ev) {
    var geo = WF.geo;
    if (!geo || !WF.rows.length) return;
    var cur = WF.cur || { r: 0, c: geo.cols - 1 };
    var MOVE = { ArrowLeft: [0, -1], ArrowRight: [0, 1], ArrowUp: [-1, 0], ArrowDown: [1, 0] };
    var d = Object.prototype.hasOwnProperty.call(MOVE, ev.key) ? MOVE[ev.key] : null;
    if (d) {
      ev.preventDefault();
      cur = { r: Math.max(0, Math.min(WF.rows.length - 1, cur.r + d[0])),
              c: Math.max(0, Math.min(geo.cols - 1, cur.c + d[1])) };
      WF.cur = cur;
      channelGrid();
      return;
    }
    if (ev.key === "Enter" || ev.key === " ") {
      ev.preventDefault();
      if (!WF.cur) { WF.cur = cur; channelGrid(); }
      var first = $("w-mix").querySelector("button");
      if (first) first.focus();
    }
  });
  window.addEventListener("resize", function () { if (view === "wifi" && WF.geo) channelGrid(); });

  function av(k) { return function (a) { return a[k]; }; }
  var DTA = DataTable({ id: "aps", label: "access points", box: $("w-aps-box"), head: $("w-aps-head"),
    reset: $("w-aps-tools"), server: function () { wifiAps(); }, cols: [
      { k: "bs", label: "bssid", w: 19, min: 8, type: "mac", srv: "bssid", val: av("bssid") },
      { k: "ss", label: "ssid", w: 12, flex: true, type: "text", srv: "ssid", val: av("ssid") },
      { k: "ch", label: "ch", w: 4, min: 3, type: "num", srv: "channel", val: av("channel") },
      { k: "sig", label: "dBm", w: 5, min: 3, type: "num", srv: "signal", val: av("signal") },
      { k: "enc", label: "enc / akm", w: 20, type: "text", srv: "enc", val: av("enc") },
      { k: "mfp", label: "mfp", w: 12, type: "num", srv: "mfp", val: av("mfp") },
      { k: "dg", label: "downgrade", w: 16, type: "num", srv: "downgrade", val: av("downgrade") },
      { k: "km", label: "karma", w: 9, type: "num", srv: "karma",
        val: function (a) { return a.karma ? a.karma.score : null; } },
      { k: "ls", label: "last", w: 11, type: "time", srv: "last", val: av("last_seen") }
    ] });

  function apRow(a) {
    var row = el("div", "aprow dt-row" + (a.multi_ssid ? " many-ssid" : ""));
    WF.apEls.set(String(a.bssid), row);
    var bs = el("span", "c-bs");
    var sw = el("span", "sw");
    sw.style.background = keyColor(String(a.bssid));
    bs.appendChild(sw);
    bs.appendChild(el("span", "d-dim", a.bssid));
    row.appendChild(bs);
    // The SSID in its hash colour; the warning (KARMA, multi-VAP) is
    // the "+N ssids" after it, at the heat the TUI warns at.
    var ss = el("span", "c-ssid");
    ss.appendChild(a.ssid === null ? el("span", "d-dim", "(hidden)") : ssidSpan(String(a.ssid), a.ssid_k, a.ssid_np));
    if (a.ssid_count > 1) ss.appendChild(el("span", "warn", "  +" + (a.ssid_count - 1) + " ssids"));
    row.appendChild(ss);
    row.appendChild(el("span", "c-ch d-normal", String(a.channel)));
    row.appendChild(el("span", "c-sig d-dim", num(a.signal) ? String(a.signal) : "-"));
    row.appendChild(el("span", "c-enc d-normal", (a.enc === null ? "?" : a.enc) + " " +
                       (a.akm_names && a.akm_names.length ? a.akm_names.join(",") : "")));
    row.appendChild(el("span", "c-mfp d-normal", "mfp " + a.mfp_word));
    row.appendChild(el("span", "c-dg" + (a.downgrade ? " warn" : " d-dim"),
                       a.downgrade_names && a.downgrade_names.length
                         ? a.downgrade_names.join(", ") : "-"));
    row.appendChild(el("span", "c-km" + (a.karma ? " warn" : " d-dim"),
                       a.karma ? "karma " + a.karma.score : "-"));
    row.appendChild(el("span", "c-ls d-dim", shortStamp(a.last_seen)));
    var box = el("div", "apbox");
    box.appendChild(row);
    if (a.ssid_count > 1 && a.ssids) {
      var hist = el("div", "sub aphist");
      hist.appendChild(document.createTextNode("ssid history: "));
      a.ssids.forEach(function (x, i) {
        if (i) hist.appendChild(document.createTextNode("; "));
        hist.appendChild(ssidSpan(String(x.ssid), x.ssid_k, x.ssid_np));
        hist.appendChild(document.createTextNode(" (" + shortStamp(x.first_seen) + " to " +
                                                 shortStamp(x.last_seen) + ")"));
      });
      if (a.ssids_more) hist.appendChild(document.createTextNode("; more"));
      box.appendChild(hist);
    }
    return box;
  }

  function wifiAps() {
    var gen = WF.gen;
    var sort = $("w-sort").value;
    if (!Object.prototype.hasOwnProperty.call(AP_SORTS, sort)) sort = "last";
    // A header's sort: its word and direction, which the server checks.
    var wd = DTA.word();
    if (wd) sort = wd.sort;
    (wd ? getJSON("/api/wifi/aps?limit=100&sort=" + encodeURIComponent(sort) + "&dir=" + wd.dir)
        : getJSON("/api/wifi/aps?limit=100&sort=" + encodeURIComponent(sort))).then(function (j) {
      if (gen !== WF.gen) return;
      var box = $("w-aps");
      while (box.firstChild) box.removeChild(box.firstChild);
      WF.apEls = new Map();
      DTA.sort(j.rows || [], !j.more).forEach(function (a) { box.appendChild(apRow(a)); });
      if (!j.rows || !j.rows.length) box.appendChild(el("div", "sub", "no beacon_aps rows"));
      set("w-aps-count", (j.rows ? j.rows.length : 0) + " shown" + (j.more ? ", more in sloth.db" : ""));
    }).catch(function (e) {
      if (gen !== WF.gen) return;
      var box = $("w-aps");
      while (box.firstChild) box.removeChild(box.firstChild);
      set("w-aps-count", errText(e.message));
    });
  }

  // Bars per bssid, the frames of each cell against the row's busiest;
  // flood episodes under them in --sev-crit.
  function deauthChart(c, j) {
    var T = theme();
    var dpr = sizeCanvas(c);
    var g = c.getContext("2d");
    var W = c.width, H = c.height;
    g.clearRect(0, 0, W, H);
    var rows = (j.bssids || []).slice(0, 12);
    if (!rows.length) return;
    var padL = 128 * dpr, rh = Math.floor(H / rows.length);
    var cw = (W - padL) / Math.max(1, j.cols);
    var span = j.to - j.from;
    g.font = Math.min(10 * dpr, rh) + "px " + css("--font-mono");
    g.textBaseline = "middle";
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i], y = i * rh;
      g.fillStyle = css("--sev-crit");
      (r.floods || []).forEach(function (f) {
        var a = Math.max(j.from, f[0]), b = Math.min(j.to, f[1] + j.col_s);
        if (b <= a) return;
        g.globalAlpha = 0.35;
        g.fillRect(padL + (a - j.from) / span * (W - padL), y, Math.max(dpr, (b - a) / span * (W - padL)), rh);
        g.globalAlpha = 1;
      });
      g.fillStyle = T.dim;
      g.fillText(String(r.bssid), 2 * dpr, y + rh / 2);
      var max = 0;
      (r.cells || []).forEach(function (v) { if (num(v) && v > max) max = v; });
      g.fillStyle = (r.floods || []).length ? css("--sev-crit") : T.normal;
      for (var k = 0; k < (r.cells || []).length; k++) {
        var v = r.cells[k];
        if (!num(v) || v <= 0 || max <= 0) continue;
        var h = Math.max(dpr, (rh - 2 * dpr) * v / max);
        g.fillRect(padL + k * cw, y + rh - dpr - h, Math.max(dpr, cw - dpr), h);
      }
    }
  }

  // ── the managed card's own scan and link (/api/wifi/local) ────────
  // Local's half of the view, and Hybrid's too: Wi-Fi through the
  // host's own network, never the passive radio. Small lists, held
  // whole, so their headers sort here.
  var WC = { aps: [], stas: [] };
  function bytesText(n) {
    if (!num(n)) return "-";
    var u = ["B", "KB", "MB", "GB", "TB"], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(1) : String(n)) + " " + u[i];
  }
  function rateText(k) { return num(k) && k > 0 ? (k / 1000).toFixed(1) + " Mb/s" : "-"; }
  var DTWS = DataTable({ id: "cardsta", label: "the card's link", box: $("w-sta-box"),
    head: $("w-sta-head"), reset: $("w-sta-tools"), redraw: cardStaDraw, cols: [
      { k: "mac", label: "bssid", w: 19, min: 8, type: "mac", val: av("mac") },
      { k: "sig", label: "dBm", w: 5, min: 3, num: true, type: "num", val: av("signal") },
      { k: "tx", label: "tx rate", w: 10, num: true, type: "num", val: av("tx_kbps") },
      { k: "rx", label: "rx rate", w: 10, num: true, type: "num", val: av("rx_kbps") },
      { k: "up", label: "connected", w: 10, num: true, type: "num", val: av("connected_s") },
      { k: "txb", label: "tx", w: 10, num: true, type: "num", val: av("tx_bytes") },
      { k: "rxb", label: "rx", w: 10, num: true, type: "num", val: av("rx_bytes") },
      { k: "ls", label: "last", w: 11, type: "time", val: av("last_seen") }
    ] });
  var DTWC = DataTable({ id: "cardscan", label: "the card's scan", box: $("w-scan-box"),
    head: $("w-scan-head"), reset: $("w-scan-tools"), redraw: cardScanDraw, cols: [
      { k: "bs", label: "bssid", w: 19, min: 8, type: "mac", val: av("bssid") },
      { k: "ss", label: "ssid", w: 14, flex: true, type: "text", val: av("ssid") },
      { k: "ch", label: "ch", w: 4, min: 3, num: true, type: "num", val: av("channel") },
      { k: "sig", label: "dBm", w: 5, min: 3, num: true, type: "num", val: av("signal") },
      { k: "enc", label: "enc", w: 12, type: "text", val: av("enc") },
      { k: "st", label: "status", w: 13, type: "text", val: av("status") },
      { k: "ls", label: "last", w: 11, type: "time", val: av("last_seen") }
    ] });
  // A MAC with its swatch, as the AP table and the TUI colour one.
  function macCell(mac) {
    var c = el("span", "");
    var sw = el("span", "sw");
    sw.style.background = keyColor(String(mac));
    c.appendChild(sw);
    c.appendChild(el("span", "d-dim", String(mac)));
    return c;
  }
  function cardStaDraw() {
    var box = clear("w-sta");
    DTWS.sort(WC.stas).forEach(function (a) {
      var row = el("div", "dt-row");
      row.appendChild(macCell(a.mac));
      row.appendChild(el("span", "n d-dim", num(a.signal) ? String(a.signal) : "-"));
      row.appendChild(el("span", "n d-normal", rateText(a.tx_kbps)));
      row.appendChild(el("span", "n d-normal", rateText(a.rx_kbps)));
      row.appendChild(el("span", "n d-dim", num(a.connected_s) ? dur(a.connected_s) : "-"));
      row.appendChild(el("span", "n d-dim", bytesText(a.tx_bytes)));
      row.appendChild(el("span", "n d-dim", bytesText(a.rx_bytes)));
      row.appendChild(el("span", "d-dim", shortStamp(a.last_seen)));
      box.appendChild(row);
    });
    if (!WC.stas.length) box.appendChild(el("div", "sub", "no wifi_stas rows: the card is on no AP sloth has seen"));
  }
  function cardScanDraw() {
    var box = clear("w-scan");
    DTWC.sort(WC.aps).forEach(function (a) {
      var row = el("div", "dt-row");
      row.appendChild(macCell(a.bssid));
      var ss = el("span", "");
      ss.appendChild(a.ssid === null ? el("span", "d-dim", "(hidden)") : ssidSpan(String(a.ssid), a.ssid_k, a.ssid_np));
      row.appendChild(ss);
      row.appendChild(el("span", "n d-normal", String(a.channel)));
      row.appendChild(el("span", "n d-dim", num(a.signal) ? String(a.signal) : "-"));
      row.appendChild(el("span", "d-normal", a.enc === null ? "?" : String(a.enc)));
      row.appendChild(el("span", a.status === "associated" ? "d-normal" : "d-dim",
                         a.status === null ? "-" : String(a.status).replace("_", " ")));
      row.appendChild(el("span", "d-dim", shortStamp(a.last_seen)));
      box.appendChild(row);
    });
    if (!WC.aps.length) box.appendChild(el("div", "sub", "no wifi_aps rows"));
  }
  function wifiCard(gen) {
    getJSON("/api/wifi/local").then(function (j) {
      if (gen !== WF.gen) return;
      WC.aps = j.aps || [];
      WC.stas = j.stas || [];
      cardStaDraw();
      cardScanDraw();
      set("w-sta-count", WC.stas.length + " shown" + (j.stas_more ? ", more in sloth.db" : ""));
      set("w-scan-count", WC.aps.length + " shown" + (j.aps_more ? ", more in sloth.db" : ""));
    }).catch(function (e) {
      if (gen !== WF.gen) return;
      clear("w-sta");
      clear("w-scan");
      set("w-sta-count", errText(e.message));
      set("w-scan-count", errText(e.message));
    });
  }

  function wifi() {
    var gen = ++WF.gen;
    // The managed card's panels: Local's and Hybrid's, not Monitor's.
    if (SCOPE !== "monitor") wifiCard(gen);
    // The monitor radio's panels: under Local its empty state says why.
    if (SCOPE === "local") return;
    var r = wifiWindow();
    var metric = $("w-metric").value === "ctrl_total" ? "ctrl_total" : "ap_count";
    WF.heat = null;
    WF.mix = null;
    getJSON(wifiGridPath("channels", metric, r)).then(function (j) {
      if (gen !== WF.gen) return;
      WF.heat = j;
      channelGrid();
    }).catch(function (e) { if (gen === WF.gen) set("w-heat-note", errText(e.message)); });
    // The transmitters behind each cell, on the same grid.
    getJSON(wifiGridPath("channels", "", r) + "&mix=1").then(function (j) {
      if (gen !== WF.gen) return;
      WF.mix = j;
      channelGrid();
    }).catch(function (e) {
      if (gen !== WF.gen) return;
      set("w-mix-note", "no transmitter detail: " + errText(e.message));
    });
    getJSON(wifiGridPath("deauth", "", r)).then(function (j) {
      if (gen !== WF.gen) return;
      deauthChart($("w-deauth"), j);
      var floods = 0;
      (j.bssids || []).forEach(function (b) { floods += (b.floods || []).length; });
      set("w-da-note", (j.bssids || []).length + " bssids, " + floods +
          " flood episode" + (floods === 1 ? "" : "s") + ", sloth.db " + j.db);
    }).catch(function (e) { if (gen === WF.gen) set("w-da-note", errText(e.message)); });
    var tier = tierFor(r.win);
    Promise.all([series("wifi.probe_clients", "", tier, r.from, r.to),
                 baseline("wifi.probe_clients", "")]).then(function (res) {
      if (gen !== WF.gen) return;
      var s = res[0], bl = res[1];
      draw($("w-probe"), s.points, { from: r.from, to: r.to, step: s.step, kind: s.kind,
                                     color: theme().normal, axes: true,
                                     band: bands(s.points, bl, s.kind, s.step) });
      set("w-pc-note", s.points.length + " buckets, " + s.source +
          (bl && bl.cells ? ", band = mean ± " + sens.toFixed(1) + " sd" : ", no baseline yet"));
    }).catch(function (e) { if (gen === WF.gen) set("w-pc-note", errText(e.message)); });
    wifiAps();
  }
  $("w-metric").addEventListener("change", function () { wifi(); });
  $("w-win").addEventListener("change", function () { wifi(); });
  $("w-sort").addEventListener("change", function () { DTA.clear(); wifiAps(); });

  // ── Flows (§8.9, M6) ──────────────────────────────────────────────
  // sloth.db's protocol tables, one tab each (/api/flows, paged), and a
  // chord diagram of the busiest source -> destination pairs
  // (/api/flows/graph): the server ranks and folds, the page draws
  // what it was given and says what was folded. Addresses are drawn
  // with fillText and set with textContent; a protocol name only ever
  // picks from the fixed tables below. mqtt_flows is never read (it
  // holds usernames), and its tab says so.
  var FLOW_TABS = ["ssh", "rdp", "smb", "snmp", "ldap", "kerb", "bgp"];
  var FLOW_LABEL = { "ssh": "SSH", "rdp": "RDP", "smb": "SMB", "snmp": "SNMP",
                     "ldap": "LDAP", "kerb": "Kerberos", "bgp": "BGP" };
  var FLOW_PAGE = 50;
  var F = { proto: "ssh", gen: 0, ggen: 0, rows: [], offset: 0, graph: null,
            tabs: null, hits: [] };

  function flowHue(p) {
    return Object.prototype.hasOwnProperty.call(FLOW_LABEL, p) ? css("--f-" + p) : css("--muted");
  }

  function flowRange() {
    var to = Math.floor(Date.now() / 1000);
    return { from: to - Number($("f-win").value), to: to };
  }

  function flowTabs() {
    var box = $("f-tabs");
    while (box.firstChild) box.removeChild(box.firstChild);
    FLOW_TABS.concat(["mqtt"]).forEach(function (p) {
      var b = el("button", "");
      b.type = "button";
      b.role = "tab";
      var t = F.tabs && F.tabs[p];
      if (p === "mqtt") {
        b.textContent = "MQTT withheld";
        b.title = "mqtt_flows holds MQTT usernames; slothweb never reads it";
        b.disabled = true;
      } else {
        b.textContent = FLOW_LABEL[p] + (t && num(t.rows) ? " " + t.rows : t === null ? " -" : "");
        b.ariaSelected = p === F.proto ? "true" : "false";
        b.addEventListener("click", function () {
          F.proto = p;
          flowTabs();
          flowRows(true);
        });
      }
      box.appendChild(b);
    });
  }

  function flowAddr(a, none) {
    var sp = el("span", "");
    if (typeof a !== "string") { sp.className = "d-dim"; sp.textContent = none; return sp; }
    if (!isIP(a)) { sp.textContent = a; return sp; }
    sp.appendChild(ipSpan(a, IP_SRC.conn));
    return sp;
  }

  function fv(k) { return function (f) { return f[k]; }; }
  var DTF = DataTable({ id: "flows", label: "flows", box: $("f-box"), head: $("f-head"),
    reset: $("f-tools"), server: function () { flowRows(true); }, cols: [
      { k: "s", label: "source", w: 24, min: 8, type: "ip", srv: "src", val: fv("src") },
      { k: "d", label: "destination", w: 24, min: 8, type: "ip", srv: "dst", val: fv("dst") },
      { k: "c", label: "counts", w: 14, flex: true },
      { k: "t", label: "total", w: 9, num: true, type: "num", srv: "total", val: fv("total") },
      { k: "x", label: "", w: 11 },
      { k: "fs", label: "first", w: 11, type: "time", srv: "first", val: fv("first_seen") },
      { k: "ls", label: "last", w: 11, type: "time", srv: "last", val: fv("last_seen") }
    ] });

  function flowRow(f, cols) {
    var from = f.src, to = f.dst;
    var row = el("div", f.smb1 === true ? "frow sev2" : "frow");
    row.classList.add("dt-row");
    // The address columns grow to a full IPv6 address (40ch) when the
    // row has room; narrower, the cell's ellipsis hides the tail, so the
    // whole address is its tooltip.
    // An SMB1 row is the critical colour, its addresses as every other
    // address: the hash colour, or the alert-hot colour while an alert
    // (SMB1_USE) names one.
    var hot = f.smb1 === true;
    var sc = row.appendChild(flowAddr(from, "-"));
    var dc = row.appendChild(flowAddr(to, "(source only)"));
    if (typeof from === "string") sc.title = from;
    if (typeof to === "string") dc.title = to;
    var counts = (f.counts || []).map(function (v, i) {
      return String(cols[i] || "?").replace(/_count$/, "") + " " + fmt(v);
    }).join("  ");
    row.appendChild(el("span", hot ? "" : "d-normal", counts));
    row.appendChild(el("span", hot ? "n" : "n d-bright", fmt(f.total)));
    var extra = "";
    if (num(f.server_port)) extra = ":" + f.server_port;
    if (typeof f.dialect === "string") extra += " " + f.dialect;
    if (num(f.version)) extra = "v" + (f.version === 0 ? "1" : f.version === 1 ? "2c" : f.version === 3 ? "3" : f.version);
    if (num(f.proto_mask)) extra = "mask " + f.proto_mask;
    row.appendChild(el("span", hot ? "" : "d-normal", extra || "-"));
    row.appendChild(el("span", hot ? "" : "d-dim", num(f.first_seen) ? shortStamp(f.first_seen) : "-"));
    row.appendChild(el("span", hot ? "" : "d-dim", num(f.last_seen) ? shortStamp(f.last_seen) : "-"));
    if (typeof from === "string") {
      row.classList.add("go");
      row.tabIndex = 0;
      row.addEventListener("click", function () { $("f-ip").value = from; flowRows(true); });
    }
    return row;
  }

  function flowHead(j) {
    var x = j.proto === "smb" ? "port, dialect" : j.proto === "snmp" ? "version"
          : j.proto === "rdp" ? "protocols" : "";
    DTF.label("d", j.per_source ? "" : "destination");
    DTF.label("x", x);
  }

  function flowRows(fresh) {
    var gen = ++F.gen;
    if (fresh) { F.rows = []; F.offset = 0; }
    var r = flowRange();
    var ip = $("f-ip").value.trim();
    var wd = DTF.word();
    var p = "&from=" + r.from + "&to=" + r.to + "&sort=" + encodeURIComponent(wd ? wd.sort : $("f-sort").value) +
            "&limit=" + FLOW_PAGE + "&offset=" + F.offset;
    if (wd) p += "&dir=" + wd.dir;
    if (ip !== "") p += "&ip=" + encodeURIComponent(ip);
    getJSON("/api/flows?proto=" + encodeURIComponent(F.proto) + p).then(function (j) {
      if (gen !== F.gen) return;
      var box = $("f-rows");
      while (box.firstChild) box.removeChild(box.firstChild);
      flowHead(j);
      F.rows = F.rows.concat(j.rows || []);
      DTF.sort(F.rows, !j.more).forEach(function (f) { box.appendChild(flowRow(f, j.columns || [])); });
      F.offset += num(j.count) ? j.count : 0;
      $("f-more").hidden = !j.more;
      var shown = F.offset;
      if (!j.present) {
        set("f-count", "this sloth.db has no " + j.table + " table");
      } else if (!num(j.total) || j.total === 0) {
        set("f-count", "none in the window" + (ip !== "" ? " for " + ip : ""));
      } else {
        set("f-count", shown + " of " + j.total + " in " + j.table + (ip !== "" ? " naming " + ip : ""));
      }
      set("f-note", typeof j.withheld === "string"
        ? "withheld, never read: " + j.withheld
        : "sloth.db's " + j.table + ", read-only; nothing withheld from this table");
    }).catch(function (e) {
      if (gen !== F.gen) return;
      while ($("f-rows").firstChild) $("f-rows").removeChild($("f-rows").firstChild);
      $("f-more").hidden = true;
      set("f-count", "");
      set("f-note", errText(e.message));
    });
  }

  // A chord label at most maxc characters long. Cut from the left (an
  // address's tail is the part that differs), and only after a "." or
  // ":", behind an ellipsis, so what is left can never read as another
  // whole address: 198.51.100.1 becomes "\u2026.51.100.1", not
  // "8.51.100.1". A label with no separator late enough is cut anywhere,
  // still behind the ellipsis. The node's full address is what a click
  // filters the table by.
  function cutLabel(id, maxc) {
    if (id.length <= maxc) return id;
    for (var i = 1; i < id.length; i++) {
      var c = id.charAt(i);
      if (c === ":" && id.charAt(i + 1) === ":") continue;
      if ((c === "." || c === ":") && id.length - i + 1 <= maxc) return "\u2026" + id.slice(i);
    }
    return id.slice(0, maxc - 1) + "\u2026";
  }

  // The chord: the nodes the server kept on a circle, busiest first
  // from twelve o'clock; each pair a curve through the middle from its
  // source to its destination, an arrowhead at the destination, its
  // width by log of its total.
  function chord(c, g, why) {
    var T = theme();
    var dpr = sizeCanvas(c);
    var x = c.getContext("2d");
    var W = c.width, H = c.height;
    x.clearRect(0, 0, W, H);
    F.hits = [];
    var nodes = (g && g.nodes) || [], edges = (g && g.edges) || [];
    x.font = (11 * dpr) + "px " + css("--font-mono");
    if (!nodes.length) {
      x.fillStyle = T.muted;
      x.textAlign = "center";
      x.fillText(why || "no source -> destination pairs in the window", W / 2, H / 2);
      return;
    }
    var narrow = W / dpr < 520;
    var lab = narrow ? 84 * dpr : 120 * dpr;
    var R = Math.max(20 * dpr, Math.min(W / 2 - lab, H / 2 - 18 * dpr));
    var cx = W / 2, cy = H / 2;
    var pos = nodes.map(function (n, i) {
      var a = -Math.PI / 2 + i / nodes.length * 2 * Math.PI;
      return { x: cx + R * Math.cos(a), y: cy + R * Math.sin(a), a: a };
    });
    var max = 1;
    edges.forEach(function (e) { if (num(e.total) && e.total > max) max = e.total; });
    edges.forEach(function (e) {
      var s = pos[e.s], d = pos[e.d];
      if (!s || !d) return;
      var w = (1 + 5 * Math.log(1 + e.total) / Math.log(1 + max)) * dpr;
      var col = e.smb1 === true ? css("--sev-crit") : flowHue(e.proto);
      x.strokeStyle = col;
      x.globalAlpha = 0.8;
      x.lineWidth = w;
      // A self-pair would be a point: loop it outward instead.
      var qx = s === d ? cx + 1.4 * (s.x - cx) : cx + 0.15 * (s.x + d.x - 2 * cx);
      var qy = s === d ? cy + 1.4 * (s.y - cy) : cy + 0.15 * (s.y + d.y - 2 * cy);
      x.beginPath();
      x.moveTo(s.x, s.y);
      x.quadraticCurveTo(qx, qy, d.x, d.y);
      x.stroke();
      var ang = Math.atan2(d.y - qy, d.x - qx), ah = (4 + w / dpr) * dpr;
      x.globalAlpha = 1;
      x.fillStyle = col;
      x.beginPath();
      x.moveTo(d.x, d.y);
      x.lineTo(d.x - ah * Math.cos(ang - 0.4), d.y - ah * Math.sin(ang - 0.4));
      x.lineTo(d.x - ah * Math.cos(ang + 0.4), d.y - ah * Math.sin(ang + 0.4));
      x.closePath();
      x.fill();
    });
    x.globalAlpha = 1;
    var maxN = 1;
    nodes.forEach(function (n) { if (num(n.total) && n.total > maxN) maxN = n.total; });
    nodes.forEach(function (n, i) {
      var p = pos[i];
      var r = (2 + 4 * Math.sqrt(n.total / maxN)) * dpr;
      var id = String(n.id);
      // A node is an address: its hash colour, bold once cross-panel;
      // an alert-hot one in its CP_ALERT_HOT_* colour, bold from WARN.
      var e = isIP(id) ? ipNote(id, IP_SRC.conn) : null;
      var hot = isIP(id) ? hotCheck(id) : -1;
      x.fillStyle = hot >= 0 ? theme().hot[hot] : keyColor(id);
      x.beginPath();
      x.arc(p.x, p.y, r, 0, 2 * Math.PI);
      x.fill();
      var right = Math.cos(p.a) >= 0;
      x.textAlign = right ? "left" : "right";
      x.textBaseline = "middle";
      x.font = (hot >= 1 || (hot < 0 && e && crossPanel(e.m)) ? "bold " : "") + (11 * dpr) + "px " + css("--font-mono");
      var t = cutLabel(id, narrow ? 11 : 22);
      var lx = p.x + (right ? 1 : -1) * (r + 4 * dpr), ly = p.y;
      x.fillText(t, lx, ly);
      F.hits.push({ x: p.x, y: p.y, r: Math.max(r, 8 * dpr), id: id });
    });
  }

  function flowLegend(g) {
    var box = $("f-legend");
    while (box.firstChild) box.removeChild(box.firstChild);
    var seen = {};
    ((g && g.edges) || []).forEach(function (e) { seen[e.proto] = true; if (e.smb1 === true) seen.smb1 = true; });
    FLOW_TABS.forEach(function (p) {
      if (p === "ldap" || p === "kerb") return;
      var s = el("span", seen[p] ? "" : "sub");
      var i = el("i", "");
      i.style.background = flowHue(p);
      s.appendChild(i);
      s.appendChild(document.createTextNode(FLOW_LABEL[p]));
      box.appendChild(s);
    });
    var s1 = el("span", "");
    var i1 = el("i", "");
    i1.style.background = css("--sev-crit");
    s1.appendChild(i1);
    s1.appendChild(document.createTextNode("SMB1"));
    box.appendChild(s1);
  }

  function flowGraph() {
    var gen = ++F.ggen;
    var r = flowRange();
    var c = $("f-chord");
    var nodes = c.clientWidth < 520 ? 12 : 24;
    getJSON("/api/flows/graph?from=" + r.from + "&to=" + r.to + "&nodes=" + nodes + "&edges=80").then(function (g) {
      if (gen !== F.ggen) return;
      F.graph = g;
      F.tabs = g.tabs || null;
      flowTabs();
      chord(c, g);
      flowLegend(g);
      var f = g.fold || {};
      set("f-fold", num(f.pairs) && f.pairs > 0
        ? (f.pairs_shown + " of " + f.pairs + " pairs, " + f.nodes_shown + " of " + f.nodes +
           " addresses" + (f.pairs_folded > 0
             ? "; folded: " + f.pairs_folded + " pairs, " + fmt(f.flows_folded) + " of " +
               fmt(f.flows) + " counted, " + f.nodes_folded + " addresses"
             : "; nothing folded"))
        : "no pairs in the window");
    }).catch(function (e) {
      if (gen !== F.ggen) return;
      F.graph = null;
      F.tabs = null;
      flowTabs();
      chord(c, null, errText(e.message));
      flowLegend(null);
      set("f-fold", errText(e.message));
    });
  }

  function flows() {
    // The IP capture's view: under Monitor its empty state says why.
    if (SCOPE === "monitor") return;
    flowTabs();
    flowGraph();
    flowRows(true);
  }
  $("f-win").addEventListener("change", flows);
  $("f-sort").addEventListener("change", function () { DTF.clear(); flowRows(true); });
  $("f-more").addEventListener("click", function () { flowRows(false); });
  var fipTimer = 0;
  $("f-ip").addEventListener("input", function () {
    if (fipTimer) clearTimeout(fipTimer);
    fipTimer = setTimeout(function () { fipTimer = 0; flowRows(true); }, 300);
  });
  $("f-chord").addEventListener("click", function (e) {
    var c = $("f-chord"), b = c.getBoundingClientRect();
    var dpr = window.devicePixelRatio || 1;
    var px = (e.clientX - b.left) * dpr, py = (e.clientY - b.top) * dpr;
    for (var i = 0; i < F.hits.length; i++) {
      var h = F.hits[i];
      if ((px - h.x) * (px - h.x) + (py - h.y) * (py - h.y) <= h.r * h.r) {
        $("f-ip").value = h.id;
        flowRows(true);
        return;
      }
    }
  });
  window.addEventListener("resize", function () {
    if (view === "flows" && F.graph) chord($("f-chord"), F.graph);
  });

  // ── History (§8.10, M5) ───────────────────────────────────────────
  // A 30 d strip (/api/history/overview) to drag a range on; for the
  // range, who was here (/api/history/devices, presence restricted to
  // it), the alerts, anomalies and flows in it; the survey sessions as
  // markers, each one click from --report's "new since the previous
  // session" (/api/sessions/new). The SQL box is drawn only when
  // /api/health says the server was started with --web-allow-sql.
  var HS = { gen: 0, from: 0, to: 0, ov: null, drag: null, sessions: [], devs: [], cells: 144,
             alerts: [], flows: [] };

  function histPath(route, from, to, extra) {
    return "/api/history/" + route + "?from=" + from + "&to=" + to + (extra || "");
  }

  function stripX(c, t) {
    var o = HS.ov;
    return (t - o.from) / (o.to - o.from) * c.width;
  }

  function stripT(c, x) {
    var o = HS.ov;
    var t = Math.round(o.from + x / Math.max(1, c.width) * (o.to - o.from));
    return Math.max(o.from, Math.min(o.to, t));
  }

  function drawOverview() {
    var c = $("h-strip"), o = HS.ov;
    if (!o) return;
    var T = theme();
    var dpr = sizeCanvas(c);
    var g = c.getContext("2d");
    var W = c.width, H = c.height;
    g.clearRect(0, 0, W, H);
    var max = 1;
    for (var i = 0; i < o.cols; i++) max = Math.max(max, o.devices[i] || 0, o.alerts[i] || 0);
    var cw = W / Math.max(1, o.cols), h2 = (H - 8 * dpr) / 2;
    for (i = 0; i < o.cols; i++) {
      var d = o.devices[i] || 0, a = o.alerts[i] || 0;
      g.fillStyle = T.normal;
      if (d) g.fillRect(i * cw, h2 - h2 * d / max, Math.max(dpr, cw - dpr), h2 * d / max);
      g.fillStyle = css("--sev-warn");
      if (a) g.fillRect(i * cw, h2 + 2 * dpr, Math.max(dpr, cw - dpr), h2 * a / max);
    }
    g.fillStyle = T.ink;
    HS.sessions.forEach(function (s) {
      var x = stripX(c, s.started);
      g.fillRect(x, 0, Math.max(dpr, 2 * dpr), H);
    });
    var a0 = HS.drag ? Math.min(HS.drag.a, HS.drag.b) : stripX(c, HS.from);
    var a1 = HS.drag ? Math.max(HS.drag.a, HS.drag.b) : stripX(c, HS.to);
    g.strokeStyle = T.signal;
    g.lineWidth = Math.max(1, dpr);
    g.strokeRect(a0 + 0.5, 0.5, Math.max(dpr, a1 - a0), H - 1);
  }

  function sessionChips() {
    var box = $("h-sessions");
    while (box.firstChild) box.removeChild(box.firstChild);
    if (!HS.sessions.length) { box.appendChild(el("span", "sub", "no survey sessions in this window")); return; }
    HS.sessions.forEach(function (s) {
      var b = el("button", "", "#" + s.id + " " + shortStamp(s.started) +
                 (s.label === null ? "" : " " + s.label));
      b.type = "button";
      b.addEventListener("click", function () { newSince(s.id); });
      box.appendChild(b);
    });
  }

  function newSince(id) {
    var gen = ++HS.ngen;
    set("h-new-note", "loading");
    getJSON("/api/sessions/new?id=" + encodeURIComponent(String(id))).then(function (j) {
      if (gen !== HS.ngen) return;
      var box = $("h-new");
      while (box.firstChild) box.removeChild(box.firstChild);
      if (!j.previous) {
        set("h-new-note", "session #" + j.session.id + ": a first visit, nothing to compare with");
        return;
      }
      set("h-new-note", "session #" + j.session.id + " against #" + j.previous.id +
          ", since " + stamp(j.since) + (num(j.until) ? " until " + stamp(j.until) : ""));
      [["access points", j.aps], ["devices", j.devices], ["probe clients", j.probe_clients]]
        .forEach(function (k) {
          var part = k[1];
          if (!part) return;
          box.appendChild(el("div", "label", k[0] + ": " + part.total + " new" +
                             (part.total > part.listed ? ", " + (part.total - part.listed) + " more not listed" : "")));
          var tools = el("span", "dt-tools");
          box.lastChild.appendChild(tools);
          var wrap = el("div", "hscroll"), head = el("div", "nwrow dhead"), ol = el("ol", "lst");
          wrap.appendChild(head);
          wrap.appendChild(ol);
          var rowsOf = part.rows || [];
          var nt = DataTable({ id: "hnew." + k[0], label: "new " + k[0], box: wrap, head: head, reset: tools,
            redraw: function () { drawNew(); }, cols: [
              { k: "fs", label: "first", w: 10, type: "time", val: function (x) { return x.first_seen; } },
              { k: "id", label: k[0] === "access points" ? "bssid" : "mac", w: 20, type: "mac",
                val: function (x) { return x.ident; } },
              { k: "lb", label: k[0] === "devices" ? "name" : "ssid", w: 20, flex: true, type: "text",
                val: function (x) { return x.label; } }
            ] });
          var drawNew = function () {
          while (ol.firstChild) ol.removeChild(ol.firstChild);
          nt.sort(rowsOf).forEach(function (r) {
            var li = el("li", "nwrow dt-row");
            li.appendChild(el("span", "ts", shortStamp(r.first_seen)));
            // ident: a BSSID or a MAC; label: an AP's or a probe's SSID,
            // a device's host name (or vendor).
            li.appendChild(el("span", "d-dim", r.ident));
            var tx = el("span", "tx");
            if (r.label === null || r.label === "") tx.appendChild(el("span", "d-dim", "-"));
            else if (k[0] === "devices") brandText(tx, String(r.label), "d-bright");
            else tx.appendChild(ssidSpan(String(r.label), r.label_k, r.label_np));
            li.appendChild(tx);
            ol.appendChild(li);
          });
          };
          drawNew();
          box.appendChild(wrap);
        });
    }).catch(function (e) { if (gen === HS.ngen) set("h-new-note", errText(e.message)); });
  }
  HS.ngen = 0;

  function hv(k) { return function (d) { return d[k]; }; }
  var DTH = DataTable({ id: "hdevs", label: "who was here", box: $("h-devs-box"), head: $("h-devs-head"),
    reset: $("h-devs-tools"), redraw: function () { histDevs(); }, cols: [
      { k: "mac", label: "mac", w: 21, min: 8, type: "mac", val: hv("mac") },
      { k: "ven", label: "vendor", w: 16, type: "text", val: hv("vendor") },
      { k: "nm", label: "name", w: 10, flex: true, type: "text", val: hv("name") },
      { k: "fs", label: "first", w: 11, type: "time", val: hv("first_seen") },
      { k: "ls", label: "last", w: 11, type: "time", val: hv("last_seen") },
      { k: "pr", label: "presence in the range", px: 146 }
    ] });
  function histDevs() {
    var box = $("h-devs");
    while (box.firstChild) box.removeChild(box.firstChild);
    DTH.sort(HS.devs).forEach(function (d) { histDevRow(d, HS.cells); });
  }
  function hal(k) { return function (a) { return a[k]; }; }
  var DTHA = DataTable({ id: "halerts", label: "alerts in the range", box: $("h-alerts-box"),
    head: $("h-alerts-head"), reset: $("h-alerts-tools"), redraw: function () { histAlerts(); }, cols: [
      { k: "ts", label: "last", w: 10, type: "time", val: hal("last_seen") },
      { k: "sev", label: "sev", w: 6, min: 3, type: "sev", val: hal("sev") },
      { k: "ti", label: "alert", w: 16, flex: true, type: "text", val: hal("title") },
      { k: "ip", label: "ip", w: 15, type: "ip", val: hal("ip") },
      { k: "n", label: "count", w: 7, num: true, type: "num", val: hal("count") },
      // One row per alert key: its incidents in the range, collapsed.
      { k: "in", label: "incidents", w: 9, num: true, type: "num", val: hal("incidents") }
    ] });
  var DTHF = DataTable({ id: "hflows", label: "flows in the range", box: $("h-flows-box"),
    head: $("h-flows-head"), reset: $("h-flows-tools"), redraw: function () { histFlows(); }, cols: [
      { k: "ts", label: "last", w: 10, type: "time", val: hal("last_seen") },
      { k: "pr", label: "proto", w: 7, type: "text", val: hal("proto") },
      { k: "s", label: "source", w: 18, flex: true, type: "ip", val: hal("src") },
      { k: "d", label: "destination", w: 18, flex: true, type: "ip", val: hal("dst") },
      { k: "n", label: "count", w: 7, num: true, type: "num", val: hal("count") }
    ] });

  function histDevRow(d, cells) {
    var row = el("div", "hrow dt-row");
    var mac = el("span", "c-mac");
    var sw = el("span", "sw");
    sw.style.background = keyColor(String(d.mac));
    mac.appendChild(sw);
    mac.appendChild(el("span", d.random ? "rnd d-dim" : "d-dim", (d.random ? "~" : "") + d.mac));
    row.appendChild(mac);
    row.appendChild(el("span", "c-ven " + (d.vendor === null ? "d-dim" : "d-bright"),
                       d.vendor === null ? "?" : d.vendor));
    var nm = el("span", "c-nm");
    if (d.name === null) nm.appendChild(el("span", "d-normal", "-"));
    else brandText(nm, String(d.name), "d-bright");
    row.appendChild(nm);
    row.appendChild(el("span", "c-fs d-dim", shortStamp(d.first_seen)));
    row.appendChild(el("span", "c-ls d-dim", shortStamp(d.last_seen)));
    var cv = document.createElement("canvas");
    row.appendChild(cv);
    row.addEventListener("click", function () { openDrawer(d.mac); });
    row.tabIndex = 0;
    $("h-devs").appendChild(row);
    drawStrip(cv, d.presence, cells);
  }

  function histAlerts() {
    var ol = $("h-alerts");
    while (ol.firstChild) ol.removeChild(ol.firstChild);
    DTHA.sort(HS.alerts).forEach(function (a) {
      var sev = num(a.sev) && a.sev >= 0 && a.sev <= 2 ? a.sev : -1;
      var li = el("li", (sev >= 0 ? "sev" + sev : "") + " halrow dt-row");
      li.appendChild(el("span", "ts", shortStamp(a.last_seen)));
      li.appendChild(el("span", "ty", sev >= 0 ? SEV_WORD[sev] : "?"));
      li.appendChild(alertText(a.title === null ? "?" : a.title, null));
      var ip = el("span", "tx");
      if (a.ip !== null)
        ip.appendChild(isIP(String(a.ip)) ? ipSpan(String(a.ip), IP_SRC.alert)
                                         : el("span", "d-normal", String(a.ip)));
      li.appendChild(ip);
      li.appendChild(el("span", "n " + (a.count > 1 ? heatClass(0.6) : "d-dim"), "x" + a.count));
      li.appendChild(el("span", "n " + (num(a.incidents) && a.incidents > 1 ? heatClass(0.6) : "d-dim"),
                        num(a.incidents) ? String(a.incidents) : "-"));
      if (typeof a.id === "string") alertLink(li, a.id);
      ol.appendChild(li);
    });
    if (!HS.alerts.length) ol.appendChild(el("li", "sub", "none in the range"));
  }

  function histFlows() {
    var ol = $("h-flows");
    while (ol.firstChild) ol.removeChild(ol.firstChild);
    DTHF.sort(HS.flows).forEach(function (f) {
      var li = el("li", "hflrow dt-row");
      li.appendChild(el("span", "ts", shortStamp(f.last_seen)));
      li.appendChild(el("span", "ty", f.proto));
      li.appendChild(flowAddr(f.src, "-"));
      li.appendChild(flowAddr(f.dst, "-"));
      li.appendChild(el("span", "n d-normal", "x" + f.count));
      ol.appendChild(li);
    });
    if (!HS.flows.length) ol.appendChild(el("li", "sub", SCOPE === "monitor"
      ? "none under Monitor: the flows are the IP capture's (Local)" : "none in the range"));
  }

  function historyRange() {
    var gen = ++HS.gen;
    var from = HS.from, to = HS.to;
    set("h-range", stamp(from) + " to " + stamp(to));
    getJSON(histPath("devices", from, to, "&limit=200")).then(function (j) {
      if (gen !== HS.gen) return;
      HS.devs = j.rows || [];
      HS.cells = j.presence_cells;
      histDevs();
      set("h-dev-count", (j.rows || []).length + " overlap the range" +
          (j.more ? ", more than shown" : "") + "; strip: " + fmt(j.presence_cells) +
          " cells of " + fmt(j.presence_cell_s) + " s");
    }).catch(function (e) { if (gen === HS.gen) set("h-dev-count", errText(e.message)); });
    getJSON(histPath("alerts", from, to, "&limit=100")).then(function (j) {
      if (gen !== HS.gen) return;
      (j.alerts || []).forEach(function (a) {
        if (a.ip !== null) noteAlertIp(String(a.ip), a.last_seen, a.sev);
      });
      HS.alerts = j.alerts || [];
      histAlerts();
      // The keys come from the range's newest rows; capped, a key seen
      // only before sc.oldest is not listed (each listed key is counted
      // over the whole range).
      var hs = j.scan || {};
      set("h-al-count", (j.alerts || []).length + (j.more ? "+" : "") +
          (hs.capped ? "; keys from the newest " + hs.cap + " rows, back to " +
            (num(hs.oldest) ? stamp(hs.oldest) : "?") : ""));
    }).catch(function (e) { if (gen === HS.gen) set("h-al-count", errText(e.message)); });
    getJSON(histPath("flows", from, to, "&limit=100")).then(function (j) {
      if (gen !== HS.gen) return;
      HS.flows = j.flows || [];
      histFlows();
    }).catch(function () { /* the list stands empty */ });
    getJSON("/api/anomalies?since=" + from).then(function (j) {
      if (gen !== HS.gen) return;
      var box = $("h-anoms");
      while (box.firstChild) box.removeChild(box.firstChild);
      var list = (j.anomalies || []).filter(function (a) { return num(a.first_seen) && a.first_seen <= to; });
      list.forEach(function (a) { box.appendChild(card(a)); });
      if (!list.length) box.appendChild(el("div", "sub", "none kept for the range (episodes are kept a week)"));
    }).catch(function () { /* the cards stand empty */ });
  }

  function historyView() {
    var now = Math.floor(Date.now() / 1000);
    var to = now, from = to - 30 * 86400;
    getJSON("/api/history/overview?from=" + from + "&to=" + to + "&cols=180").then(function (j) {
      HS.ov = j;
      HS.sessions = (j.sessions || []).filter(function (s) { return num(s.started) && num(s.id); });
      if (!HS.to) { HS.to = j.to; HS.from = Math.max(j.from, j.to - 86400); }
      drawOverview();
      sessionChips();
      historyRange();
      if (HS.sessions.length && !HS.ngen) newSince(HS.sessions[0].id);
    }).catch(function (e) { set("h-range", errText(e.message, e.body)); });
    if (Q.on) recipes();
  }

  // Pointer events: a mouse, a pen or a finger on a narrow screen.
  $("h-strip").addEventListener("pointerdown", function (e) {
    if (!HS.ov) return;
    var c = $("h-strip"), r = c.getBoundingClientRect();
    var x = (e.clientX - r.left) * (c.width / Math.max(1, r.width));
    HS.drag = { a: x, b: x };
  });
  $("h-strip").addEventListener("pointermove", function (e) {
    if (!HS.drag) return;
    var c = $("h-strip"), r = c.getBoundingClientRect();
    HS.drag.b = (e.clientX - r.left) * (c.width / Math.max(1, r.width));
    drawOverview();
  });
  window.addEventListener("pointerup", function () {
    if (!HS.drag) return;
    var c = $("h-strip"), d = HS.drag;
    HS.drag = null;
    var a = stripT(c, Math.min(d.a, d.b)), b = stripT(c, Math.max(d.a, d.b));
    // A click, not a drag: a session marker under it opens its list.
    if (Math.abs(d.b - d.a) < 3) {
      var hit = null;
      HS.sessions.forEach(function (s) {
        if (Math.abs(stripX(c, s.started) - d.a) <= 4 * (window.devicePixelRatio || 1)) hit = s;
      });
      if (hit) newSince(hit.id);
      drawOverview();
      return;
    }
    if (b - a < 60) b = a + 60;
    HS.from = a;
    HS.to = b;
    drawOverview();
    historyRange();
  });

  // ── the SQL box (§7 /api/query, M5) ───────────────────────────────
  // Read-only, one statement, 5 s, 10,000 rows; the server refuses
  // everything else and withholds the credential columns. The recipes
  // are docs/wiki/sqlite-schema.md's, built into the server. Results
  // are cells of textContent.
  var Q = { on: false, gen: 0, recipes: null };

  function recipes() {
    if (Q.recipes) return;
    getJSON("/api/recipes").then(function (j) {
      Q.recipes = j.recipes || [];
      var sel = $("q-recipe");
      while (sel.firstChild) sel.removeChild(sel.firstChild);
      Q.recipes.forEach(function (r, i) {
        var o = el("option", "", r.title);
        o.value = String(i);
        sel.appendChild(o);
      });
      if (Q.recipes.length) $("q-sql").value = Q.recipes[0].sql.trim();
      set("q-note", Q.recipes.length + " recipes from " + j.source);
    }).catch(function (e) { set("q-note", errText(e.message)); });
  }

  function cellText(v) {
    if (v === null) return "NULL";
    if (typeof v === "object" && typeof v.blob === "string") return "x'" + v.blob + "'";
    return String(v);
  }

  function runQuery() {
    var sql = $("q-sql").value;
    if (sql.trim() === "") return;
    var gen = ++Q.gen;
    set("q-note", "running");
    fetch("/api/query?sql=" + encodeURIComponent(sql), { cache: "no-store" }).then(function (r) {
      return r.json().then(function (j) { return { ok: r.ok, j: j }; });
    }).then(function (res) {
      if (gen !== Q.gen) return;
      var box = $("q-out");
      while (box.firstChild) box.removeChild(box.firstChild);
      var j = res.j;
      if (!res.ok) {
        set("q-note", "refused: " + j.error + (typeof j.detail === "string" ? " (" + j.detail + ")" : ""));
        return;
      }
      var tbl = el("table", "qt dt-fixed");
      var thead = el("thead", ""), tbody = el("tbody", "");
      var tr = el("tr", "dt-row");
      thead.appendChild(tr);
      tbl.appendChild(thead);
      tbl.appendChild(tbody);
      var rowsQ = j.rows || [];
      // A column of numbers (and NULLs) sorts as numbers, one of
      // addresses or of MACs as those, any other as its text's bytes.
      // Widths are kept by the column's name (the n-th of that name), so
      // one query's widths go to the same column of the next, not to
      // whatever is in its place.
      var seen = {};
      var cols = (j.columns || []).map(function (c, i) {
        function all(f) {
          var any = false;
          var ok = rowsQ.every(function (row) {
            if (row[i] === null) return true;
            any = true;
            return f(row[i]);
          });
          return ok && any;
        }
        var allNum = all(function (v) { return typeof v === "number"; }) ||
                     rowsQ.every(function (row) { return row[i] === null; });
        var type = allNum ? "num" : all(isIP) ? "ip"
                 : all(function (v) { return typeof v === "string" && MAC_RE.test(v.toLowerCase()); }) ? "mac"
                 : "text";
        var nm = String(c);
        seen[nm] = (seen[nm] || 0) + 1;
        return { k: "n:" + nm + (seen[nm] > 1 ? "#" + seen[nm] : ""), label: nm,
                 w: allNum ? 10 : type === "ip" ? 16 : type === "mac" ? 18 : 24, type: type,
                 num: allNum, val: function (row) { return row[i] === null ? null : cellText(row[i]); } };
      });
      var qtools = el("span", "dt-tools");
      var qt = DataTable({ id: "sql", label: "query result", table: tbl, box: box, head: tr, cols: cols,
                           reset: qtools, redraw: function () { drawQ(); } });
      var drawQ = function () {
        while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
        qt.sort(rowsQ).forEach(function (row) {
          var r = el("tr", "dt-row");
          row.forEach(function (v) { r.appendChild(el("td", v === null ? "nul" : "", cellText(v))); });
          tbody.appendChild(r);
        });
      };
      drawQ();
      box.appendChild(qtools);
      box.appendChild(tbl);
      set("q-note", j.row_count + " rows in " + j.elapsed_ms + " ms" +
          (j.truncated ? ", truncated by " + j.truncated_by : ""));
    }).catch(function (e) { if (gen === Q.gen) set("q-note", "error: " + e.message); });
  }
  $("q-recipe").addEventListener("change", function () {
    var i = Number($("q-recipe").value);
    if (Q.recipes && Q.recipes[i]) $("q-sql").value = Q.recipes[i].sql.trim();
  });
  $("q-run").addEventListener("click", runQuery);

  // ── the Alerts page and an alert's page (owner request 2026-10-23..26)
  // /api/alerts: the stream's open incidents first, then the closed
  // ones and sloth.db's rows, every row of one alert key collapsed into
  // one with its count of incidents. /api/alert?id=: what it is, why it
  // matters, how to investigate and fix it (built in from the rule
  // table, the wiki, the research corpus and the remediation page), the
  // evidence, the key's incidents as runs, the device it names. An id is
  // the server's opaque "s<handle>" or "d<rowid>", checked here before
  // it goes anywhere; it is never alerts.key nor sloth's incident_id.
  var ALERT_ID_RE = /^[sd][0-9A-Za-z]{1,24}$/;
  var SEV_SET = { "": 1, "crit": 1, "warn": 1, "low": 1, "warn,crit": 1 };
  var STATE_SET = { "all": 1, "open": 1, "closed": 1 };
  var EV_WORD = { "create": "opened", "update": "updated", "escalate": "escalated", "resolve": "closed" };
  var ALP = { gen: 0, offset: 0, timer: 0, types: [], rows: [], more: false };

  function sevOf(v) { return num(v) && v >= 0 && v <= 2 ? v : -1; }

  function openAlert(id) {
    if (typeof id !== "string" || !ALERT_ID_RE.test(id)) return;
    go("alert", { id: id });
  }

  // An item that opens an alert's page, by click or by Enter.
  function alertLink(li, id) {
    if (typeof id !== "string" || !ALERT_ID_RE.test(id)) return;
    li.classList.add("go");
    li.tabIndex = 0;
    li.role = "link";
    li.addEventListener("click", function () { openAlert(id); });
  }

  function alertsQuery(off) {
    var p = [];
    var st = $("al-state").value;
    if (st !== "all") p.push("state=" + encodeURIComponent(st));
    var sv = $("al-sev").value;
    if (sv) p.push("sev=" + encodeURIComponent(sv));
    var ty = $("al-type").value;
    if (ty) p.push("type=" + encodeURIComponent(ty));
    // One word: the server's parameters take no space.
    var q = $("al-q").value.trim().split(/\s+/)[0] || "";
    if (q) p.push("q=" + encodeURIComponent(q));
    p.push("window=" + encodeURIComponent($("al-win").value));
    p.push("limit=50");
    if (off) p.push("offset=" + off);
    return p.join("&");
  }

  function alertsView() {
    // A drill-down's filter (the open-alerts tile: state=open) set in
    // the controls, so the filter applied is the one on screen.
    $("al-state").value = STATE_SET[VP.state] ? VP.state : "all";
    $("al-sev").value = typeof VP.sev === "string" && SEV_SET[VP.sev] ? VP.sev : "";
    if (typeof VP.q === "string") $("al-q").value = VP.q;
    else if (ALP.drillQ !== undefined) { $("al-q").value = ""; }
    ALP.drillQ = VP.q;
    ALP.wantType = typeof VP.type === "string" ? VP.type : "";
    // The drill-down as asked, to tell when the controls have left it.
    ALP.drill = (STATE_SET[VP.state] && VP.state !== "all") || (VP.sev && SEV_SET[VP.sev]) ||
               ALP.wantType || (typeof VP.q === "string" && VP.q)
      ? { state: $("al-state").value, sev: $("al-sev").value, type: ALP.wantType,
          q: typeof VP.q === "string" ? (VP.q.trim().split(/\s+/)[0] || "") : "" }
      : null;
    $("al-filter").hidden = true;
    alertsLoad(true);
    if (!ALP.timer) ALP.timer = setInterval(function () { if (view === "alerts" && !ALP.offset) alertsLoad(true); }, 10000);
  }

  function alertRow(a) {
    var sev = sevOf(a.sev);
    var row = el("div", "alprow dt-row" + (a.state === "open" ? " open" : ""));
    row.appendChild(el("span", "ty " + (sev >= 0 ? "sev" + sev : ""), sev >= 0 ? SEV_WORD[sev] : "?"));
    var t = el("span", "");
    t.appendChild(el("span", "d-bright", String(a.title)));
    if (typeof a.type_name === "string" && a.type_name !== a.title)
      t.appendChild(el("span", "d-dim", "  " + a.type_name));
    t.appendChild(el("span", "d-dim", "  " + (a.state === "recorded" ? "sloth.db" : a.state)));
    row.appendChild(t);
    row.appendChild(el("span", "d-normal", a.technique === null ? "-" : String(a.technique)));
    var host = el("span", "");
    if (typeof a.ip === "string" && isIP(a.ip)) {
      noteAlertIp(a.ip, a.last_seen, sev);
      host.appendChild(ipSpan(a.ip, IP_SRC.alert));
      if (num(a.port) && a.port > 0) host.appendChild(el("span", "d-dim", ":" + a.port));
    } else {
      host.appendChild(el("span", "d-dim", "-"));
    }
    row.appendChild(host);
    row.appendChild(el("span", "d-dim", shortStamp(a.first_seen)));
    row.appendChild(el("span", "d-dim", shortStamp(a.last_seen)));
    row.appendChild(el("span", "n d-normal", fmt(a.count)));
    row.appendChild(el("span", "n " + (num(a.incidents) && a.incidents > 1 ? heatClass(0.6) : "d-dim"),
                       num(a.incidents) ? String(a.incidents) : "-"));
    row.tabIndex = 0;
    row.role = "link";
    var id = a.id;
    row.addEventListener("click", function () { openAlert(id); });
    return row;
  }

  // The list is a table: the rows held, in the server's order (open
  // first, then the newest change) until a header sorts them.
  var DTALP = DataTable({ id: "alertspage", label: "alerts", box: $("al-box"), head: $("al-head"),
    reset: $("al-tools"), redraw: alertsDraw, cols: [
      { k: "sev", label: "sev", w: 5, min: 3, type: "sev", val: function (a) { return a.sev; } },
      { k: "ti", label: "title / type", w: 24, flex: true, type: "text", val: function (a) { return a.title; } },
      { k: "te", label: "ATT&CK", w: 10, type: "text", val: function (a) { return a.technique; } },
      { k: "ip", label: "host", w: 18, type: "ip", val: function (a) { return a.ip; } },
      { k: "fs", label: "first", w: 11, type: "time", val: function (a) { return a.first_seen; } },
      { k: "ls", label: "last", w: 11, type: "time", val: function (a) { return a.last_seen; } },
      { k: "n", label: "count", w: 7, num: true, type: "num", val: function (a) { return a.count; } },
      { k: "in", label: "incidents", w: 9, num: true, type: "num", val: function (a) { return a.incidents; } }
    ] });
  function alertsDraw() {
    var box = $("al-rows");
    while (box.firstChild) box.removeChild(box.firstChild);
    DTALP.sort(ALP.rows || [], !ALP.more).forEach(function (a) { box.appendChild(alertRow(a)); });
    if (!(ALP.rows || []).length) box.appendChild(el("div", "sub", "no alert matches"));
  }

  function typeOptions(types) {
    var sel = $("al-type"), keep = ALP.wantType || sel.value;
    while (sel.firstChild) sel.removeChild(sel.firstChild);
    var any = el("option", "", "any");
    any.value = "";
    sel.appendChild(any);
    var seen = false;
    (types || []).forEach(function (t) {
      if (typeof t.name !== "string") return;
      var o = el("option", "", t.name + " (" + t.n + ")");
      o.value = t.name;
      if (t.name === keep) seen = true;
      sel.appendChild(o);
    });
    if (keep && !seen) {
      var o = el("option", "", keep + " (0)");
      o.value = keep;
      sel.appendChild(o);
    }
    sel.value = keep || "";
    ALP.wantType = "";
  }

  // The drill-down's banner, from the controls as they stand and the
  // answer just read: rebuilt on every load, gone once a control has
  // moved off the drill-down (the list then says what it shows itself).
  function alertsBanner(j) {
    var d = ALP.drill, ty = $("al-type").value;
    var q = $("al-q").value.trim().split(/\s+/)[0] || "";
    if (!d || $("al-state").value !== d.state || $("al-sev").value !== d.sev ||
        (d.type && ty !== d.type) || (!d.type && ty) || q !== d.q) {
      ALP.drill = null;
      $("al-filter").hidden = true;
      return;
    }
    var filt = [];
    if (d.state === "open")
      filt.push("open incidents only, " + j.open + " of the " + j.open_all +
                " the Overview's open-alerts tile counts");
    else if (d.state !== "all") filt.push("state " + d.state);
    if (d.sev) filt.push("severity " + d.sev);
    if (d.type) filt.push("type " + d.type);
    if (d.q) filt.push("search " + d.q);
    $("al-filter").hidden = !filt.length;
    set("al-filter-t", "filtered: " + filt.join(", "));
  }

  function alertsLoad(fresh) {
    var gen = ++ALP.gen;
    if (fresh) ALP.offset = 0;
    if (ALP.wantType) typeOptions([]);
    getJSON("/api/alerts?" + alertsQuery(ALP.offset)).then(function (j) {
      if (gen !== ALP.gen) return;
      if (fresh) ALP.rows = [];
      ALP.rows = ALP.rows.concat(j.rows || []);
      ALP.more = !!j.more;
      alertsDraw();
      ALP.offset += num(j.count) ? j.count : 0;
      $("al-more").hidden = !j.more || !num(j.next_offset);
      if (fresh) typeOptions(j.types);
      alertsBanner(j);
      set("al-count", ALP.offset + " of " + j.total + (j.total_more ? "+" : "") + " shown, " +
          j.open + " open");
      var sc = j.scan || {};
      // The filters are applied inside sloth.db's bounded read, so a
      // capped answer is the newest matching rows, back to sc.oldest.
      set("al-note", "stream " + j.stream + ", sloth.db " + j.db +
          (num(sc.rows) && $("al-state").value !== "open" ? "; " + sc.rows + " matching sloth.db rows read" +
            (sc.capped ? ", the newest " + sc.cap + " only, back to " +
              (num(sc.oldest) ? stamp(sc.oldest) : "?") + ": narrow the window or the filters to reach older ones" : "") : ""));
    }).catch(function (e) {
      if (gen !== ALP.gen) return;
      set("al-count", "");
      set("al-note", errText(e.message));
    });
  }
  ["al-state", "al-sev", "al-type", "al-win"].forEach(function (id) {
    $(id).addEventListener("change", function () { alertsLoad(true); });
  });
  $("al-q").addEventListener("input", function () {
    if (ALP.qt) clearTimeout(ALP.qt);
    ALP.qt = setTimeout(function () { ALP.qt = 0; alertsLoad(true); }, 300);
  });
  $("al-more").addEventListener("click", function () { alertsLoad(false); });

  function prose(box, text, cls) {
    if (typeof text !== "string" || text === "") return;
    text.split("\n\n").forEach(function (para) { box.appendChild(el("div", "prose" + (cls ? " " + cls : ""), para)); });
  }

  // Text whose `code spans` are set as code: split on the backticks,
  // every piece by textContent.
  function codeProse(box, text, cls) {
    if (typeof text !== "string" || text === "") return;
    var d = el("div", "prose" + (cls ? " " + cls : ""));
    text.split("`").forEach(function (part, i) {
      if (part === "") return;
      d.appendChild(i % 2 ? el("code", "", part) : document.createTextNode(part));
    });
    box.appendChild(d);
  }

  function steps(box, title, list) {
    box.appendChild(el("div", "label", title));
    var ol = el("ol", "steps");
    (list || []).forEach(function (t) { ol.appendChild(el("li", "", String(t))); });
    if (!list || !list.length) ol.appendChild(el("li", "sub", "none written"));
    box.appendChild(ol);
  }

  function clear(id) {
    var b = $(id);
    while (b.firstChild) b.removeChild(b.firstChild);
    return b;
  }

  var AD = { gen: 0, runs: [], runsOf: "", others: [] };
  // The key's incidents as runs, and the device's other alerts: tables,
  // newest first until a header sorts them.
  var DTRUN = DataTable({ id: "alertruns", label: "history of this alert", box: $("ad-history-box"),
    head: $("ad-history-head"), reset: $("ad-history-tools"), redraw: runsDraw, cols: [
      { k: "fr", label: "from", w: 10, type: "time", val: function (r) { return r.from; } },
      { k: "sev", label: "sev", w: 6, min: 3, type: "sev", val: function (r) { return r.sev; } },
      { k: "sp", label: "span", w: 24, flex: true, type: "time", val: function (r) { return r.to; } },
      { k: "in", label: "incidents", w: 9, num: true, type: "num", val: function (r) { return r.incidents; } },
      { k: "n", label: "count", w: 8, num: true, type: "num", val: function (r) { return r.count; } }
    ] });
  var DTADA = DataTable({ id: "alertdev", label: "its other alerts", box: $("ad-dev-alerts-box"),
    head: $("ad-dev-alerts-head"), reset: $("ad-dev-alerts-tools"), redraw: othersDraw, cols: [
      { k: "ls", label: "last", w: 10, type: "time", val: function (x) { return x.last_seen; } },
      { k: "sev", label: "sev", w: 6, min: 3, type: "sev", val: function (x) { return x.sev; } },
      { k: "ti", label: "alert", w: 24, flex: true, type: "text", val: function (x) { return x.title; } },
      { k: "in", label: "incidents", w: 9, num: true, type: "num", val: function (x) { return x.incidents; } }
    ] });
  function runsDraw() {
    var ol = clear("ad-history-b");
    DTRUN.sort(AD.runs).forEach(function (r) {
      var s3 = sevOf(r.sev);
      var li = el("li", (s3 >= 0 ? "sev" + s3 : "") + " arnrow dt-row");
      li.appendChild(el("span", "ts", shortStamp(r.from)));
      li.appendChild(el("span", "ty", s3 >= 0 ? SEV_WORD[s3] : "?"));
      li.appendChild(el("span", "tx d-normal", stamp(r.from) + " to " + stamp(r.to)));
      li.appendChild(el("span", "n " + (r.incidents > 1 ? heatClass(0.6) : "d-dim"), String(r.incidents)));
      li.appendChild(el("span", "n d-dim", "x" + fmt(r.count)));
      if (r.id !== AD.runsOf) alertLink(li, r.id);
      ol.appendChild(li);
    });
    if (!AD.runs.length) ol.appendChild(el("li", "sub", AD.runsNone || "none"));
  }
  function othersDraw() {
    var ol = clear("ad-dev-alerts");
    DTADA.sort(AD.others).forEach(function (x) {
      var s4 = sevOf(x.sev);
      var li = el("li", (s4 >= 0 ? "sev" + s4 : "") + " adarow dt-row");
      li.appendChild(el("span", "ts", shortStamp(x.last_seen)));
      li.appendChild(el("span", "ty", s4 >= 0 ? SEV_WORD[s4] : "?"));
      li.appendChild(el("span", "tx d-bright", String(x.title)));
      li.appendChild(el("span", "n " + (num(x.incidents) && x.incidents > 1 ? heatClass(0.6) : "d-dim"),
                        num(x.incidents) ? String(x.incidents) : "-"));
      if (typeof x.id === "string") alertLink(li, x.id);
      ol.appendChild(li);
    });
    if (!AD.others.length) ol.appendChild(el("li", "sub", AD.othersNone || "none"));
  }
  function alertView() {
    var id = VP.id;
    var gen = ++AD.gen;
    ["ad-title", "ad-what-b", "ad-why-b", "ad-fix-b", "ad-evidence-b", "ad-history-b",
     "ad-device-b", "ad-dev-alerts", "ad-dev-anoms"].forEach(clear);
    drawStrip($("ad-strip"), null);
    if (typeof id !== "string" || !ALERT_ID_RE.test(id)) {
      set("ad-head", "no alert named");
      set("ad-note", "");
      return;
    }
    set("ad-head", "loading");
    getJSON("/api/alert?id=" + encodeURIComponent(id)).then(function (j) {
      if (gen !== AD.gen) return;
      alertPage(j);
    }).catch(function (e) {
      if (gen !== AD.gen) return;
      set("ad-head", e.message === "no_such_alert" ? "no such alert: it may have closed and left the stream"
                                                   : errText(e.message));
    });
  }

  function alertPage(j) {
    var sev = sevOf(j.sev), k = j.kb || null;
    set("ad-head", (j.type_name || j.title) + ": " + j.state + ", from " + j.source);
    // A link opens its alert whatever the scope; the page says when the
    // scope does not hold its type (the rule's input is the other's).
    set("ad-note", "sloth.db " + j.db + (j.in_scope === false
      ? "; not in the " + SCOPE_WORD[SCOPE] + " scope: its rule reads what the " +
        (SCOPE === "monitor" ? "host's own interfaces carried" : "monitor radio heard")
      : ""));
    var t = $("ad-title");
    t.appendChild(el("span", "ty " + (sev >= 0 ? "sev" + sev : ""), sev >= 0 ? SEV_WORD[sev] : "?"));
    t.appendChild(el("span", "d-bright", String(j.title)));
    if (typeof j.type_name === "string" && j.type_name !== j.title)
      t.appendChild(el("span", "d-dim", "  " + j.type_name));
    if (typeof j.ip === "string" && isIP(j.ip)) {
      noteAlertIp(j.ip, j.last_seen, sev);
      t.appendChild(document.createTextNode("  "));
      t.appendChild(ipSpan(j.ip, IP_SRC.alert));
    }

    // (a) what it is
    var w = $("ad-what-b");
    if (k) {
      prose(w, k.summary || k.what);
      // The rule table's whole entry, its engineering history included,
      // folded away: the page leads with the one sentence above.
      if (k.what && k.what !== k.summary) {
        var dt = el("details", "kbfull");
        dt.appendChild(el("summary", "", "details: the rule table's full entry (docs/views/alerts.md)"));
        codeProse(dt, k.what, "dim");
        w.appendChild(dt);
      }
      kvList(w, [["severity now", sev >= 0 ? el("span", "sev" + sev, SEV_WORD[sev]) : null],
                 ["the rule's", k.sev],
                 ["ATT&CK", j.technique || k.technique || "none: not an adversary technique (agents/AGENTS.md)"],
                 ["names", k.match]]);
      if (k.context) {
        w.appendChild(el("div", "label", "in sloth's docs (docs/wiki/alerts.md)"));
        prose(w, k.context, "dim");
      }
    } else {
      w.appendChild(el("div", "sub", "an alert type this build does not know"));
    }

    // (b) why it matters: the corpus documents that cite it
    var y = $("ad-why-b");
    if (k && k.sources && k.sources.length) {
      k.sources.forEach(function (s) {
        var d = el("div", "src");
        d.appendChild(el("div", "cit", String(s.citation)));
        prose(d, s.lead);
        prose(d, s.excerpt, "dim");
        d.appendChild(el("div", "path", String(s.path)));
        // A source's address as text to copy, not a link: the page
        // sends nothing anywhere but its own server.
        if (s.url) d.appendChild(el("div", "url", String(s.url)));
        y.appendChild(d);
      });
    } else {
      y.appendChild(el("div", "sub", "no corpus document: this reports sloth's own operational state, which has no outside source to cite (agents/AGENTS.md)"));
    }

    // (c) how to investigate and fix it
    var f = $("ad-fix-b");
    if (k) {
      steps(f, "investigate", k.investigate);
      steps(f, "fix", k.fix);
      kvList(f, [["vendor fix", k.vendor_fix], ["rests on", (k.fix_sources || []).join(", ")]]);
    }

    // (d) the evidence
    var ev = $("ad-evidence-b");
    var hist = el("span", "");
    (j.sev_history || []).forEach(function (h, i) {
      var s2 = sevOf(h.sev);
      if (i) hist.appendChild(el("span", "d-dim", ", "));
      hist.appendChild(el("span", s2 >= 0 ? "sev" + s2 : "", (EV_WORD[h.ev] || "?") + " " +
                          (s2 >= 0 ? SEV_WORD[s2] : "?")));
      hist.appendChild(el("span", "d-dim", " " + stamp(h.ts)));
    });
    var pcap = j.pcap === true ? "sloth saved a pcap of this alert's frames (on the sensor, --pcap-dir)"
             : j.pcap === false ? "none saved" : "not known: only the stream's records say";
    var detail;
    if (typeof j.detail === "string") detail = richText(el("span", ""), j.detail, 0, "d-normal");
    else if (j.detail_shown === false)
      detail = el("span", "d-dim", "withheld: this type's detail can carry a credential or free text (web/src/web_alertfmt.h)");
    else detail = "-";
    kvList(ev, [["state", j.state + (j.reason ? ", " + j.reason : "")],
                ["severity", (j.sev_history || []).length ? hist : (sev >= 0 ? SEV_WORD[sev] : "?")],
                ["first seen", stamp(j.first_seen)], ["last seen", stamp(j.last_seen)],
                ["closed", num(j.closed_at) ? stamp(j.closed_at) : null],
                ["count", fmt(j.count) + " evaluations, every incident of the key" +
                  (num(j.latest_count) && j.latest_count !== j.count ? " (" + fmt(j.latest_count) +
                   " in the one this page opened on)" : "")],
                ["observations", num(j.observations) ? fmt(j.observations) : null],
                ["incidents", String(j.incidents)],
                ["pcap", pcap], ["detail", detail],
                ["also", j.stream_id && j.db_id && j.id !== j.db_id ? "sloth.db's rows of it: " + j.db_id : null]]);

    // (e) the history of this alert: every incident of its key, as runs
    var h2 = j.history || {};
    AD.runs = h2.runs || [];
    AD.runsOf = j.id;
    AD.runsNone = j.db === "open" ? "no sloth.db row yet" : "sloth.db is " + j.db;
    runsDraw();
    set("ad-history-note", (num(h2.incidents_read) ? h2.incidents_read + " incidents read" : "") +
        (num(h2.gap_s) ? "; incidents less than " + Math.round(h2.gap_s / 60) + " min apart are one run" : "") +
        (h2.more ? "; more than shown" : ""));

    // (f) the device it names
    alertDevice(j);
  }

  function alertDevice(j) {
    var dev = j.device || {}, box = $("ad-device-b"), gen = AD.gen;
    if (typeof dev.mac === "string" && MAC_RE.test(dev.mac)) {
      var mac = dev.mac;
      set("ad-device-note", "sloth.db's record of " + mac);
      getJSON("/api/device/" + encodeURIComponent(mac)).then(function (d) {
        if (gen !== AD.gen) return;
        var r = d.record || {};
        kvList(box, [["mac", macVal(mac)], ["vendor", d.oui && d.oui.found ? d.oui.vendor : null],
                     ["ip", ipVal(r.ip, IP_SRC.dev)], ["name", hostVal(r.name)],
                     ["first seen", num(r.first_seen) ? stamp(r.first_seen) : null],
                     ["last seen", num(r.last_seen) ? stamp(r.last_seen) : null]]);
        var b = el("button", "", "open the device drawer");
        b.type = "button";
        b.addEventListener("click", function () { openDrawer(mac); });
        box.appendChild(b);
        drawStrip($("ad-strip"), d.presence);
        AD.others = (d.alerts || []).filter(function (x) { return x.id !== j.id && x.id !== j.db_id; });
        AD.othersNone = "none";
        othersDraw();
        var an = $("ad-dev-anoms");
        (d.anomalies || []).forEach(function (a) { an.appendChild(card(a)); });
        if (!(d.anomalies || []).length) an.appendChild(el("div", "sub", "none"));
      }).catch(function (e) { if (gen === AD.gen) set("ad-device-note", errText(e.message)); });
    } else if (typeof dev.ip === "string" && isIP(dev.ip)) {
      var ip = dev.ip;
      set("ad-device-note", "the address it names; no sloth.db device holds it");
      getJSON("/api/lookup?q=" + encodeURIComponent(ip)).then(function (l) {
        if (gen !== AD.gen) return;
        kvList(box, [["ip", ipVal(ip, IP_SRC.alert)], ["arp macs", (l.macs || []).map(function (m) { return m.addr; }).join(", ") || null]]);
        itemList(box, "names (passive)", l.names, nameLine, false);
        if (l.device && MAC_RE.test(l.device.mac)) {
          var b = el("button", "", "open the device drawer");
          b.type = "button";
          b.addEventListener("click", function () { openDrawer(l.device.mac); });
          box.appendChild(b);
        }
      }).catch(function (e) { if (gen === AD.gen) set("ad-device-note", errText(e.message)); });
      AD.others = [];
      AD.othersNone = "-";
      othersDraw();
    } else {
      set("ad-device-note", "this alert names no device or address");
      AD.others = [];
      AD.othersNone = "-";
      othersDraw();
    }
  }

  // ── records by type: the records/s tile's view ─────────────────────
  // /api/live's per-type rates, over the same five seconds as the tile's
  // records/s, so they sum to it; and the ticker, one type or all.
  var RC = { type: "", timer: 0, rows: [], extra: [], total: null, recent: [] };
  // Both are tables: the types by rate until a header sorts them, the
  // other-type and total rows kept under them; the records as the
  // Overview's ticker draws them, newest first.
  var DTRC = DataTable({ id: "rectypes", label: "records by type", box: $("rc-box"), head: $("rc-head"),
    reset: $("rc-tools"), redraw: recordsDraw, cols: [
      { k: "ty", label: "type", w: 16, flex: true, type: "text", val: function (x) { return x.n; } },
      { k: "r", label: "records/s", w: 11, num: true, type: "num", val: function (x) { return x.r10; } },
      { k: "c", label: "since connect", w: 14, num: true, type: "num", val: function (x) { return x.c; } }
    ] });
  var DTRT = DataTable({ id: "rectick", label: "records", box: $("rc-tbox"), head: $("rc-thead"),
    reset: $("rc-ttools"), redraw: recordsTickDraw, cols: [
      { k: "ts", label: "time", w: 9, type: "time", val: function (r) { return r.ts; } },
      { k: "ty", label: "type", w: 14, type: "text", val: function (r) { return r.type; } },
      { k: "tx", label: "record", w: 30, flex: true, type: "text", val: function (r) { return r.text; } }
    ] });
  function rcRow(cls, a, b, c) {
    var row = el("div", "rcrow dt-row" + (cls ? " " + cls : ""));
    row.appendChild(a);
    row.appendChild(el("span", "n d-normal", b));
    row.appendChild(el("span", "n d-dim", c));
    return row;
  }
  function recordsDraw() {
    var box = clear("rc-rows");
    DTRC.sort(RC.rows).forEach(function (x) {
      var row = rcRow(RC.type === x.n ? "on" : "", el("span", typeClass(x.n), x.n),
                      (x.r10 / 10).toFixed(1), String(x.c));
      row.tabIndex = 0;
      row.addEventListener("click", function () { RC.type = RC.type === x.n ? "" : x.n; recordsLoad(); });
      box.appendChild(row);
    });
    RC.extra.forEach(function (x) {
      box.appendChild(rcRow("", el("span", "d-dim", x.n), (x.r10 / 10).toFixed(1), String(x.c)));
    });
    if (RC.total)
      box.appendChild(rcRow("total", el("span", "", "all records"), (RC.total.r10 / 10).toFixed(1),
                            String(RC.total.c)));
  }
  function recordsTickDraw() {
    var ol = clear("rc-ticker");
    DTRT.sort(RC.recent).forEach(function (r) { ol.appendChild(tickRow(r)); });
    if (!RC.recent.length) ol.appendChild(el("li", "sub", "none in the last " + RC.seen + " records"));
  }
  function recordsView() {
    recordsLoad();
    if (!RC.timer) RC.timer = setInterval(function () { if (view === "records") recordsLoad(); }, 2000);
  }
  function recordsLoad() {
    // An answer asked for under another scope is not drawn (as live()).
    var asked = SCOPE;
    getJSON("/api/live").then(function (l) {
      if (view !== "records" || asked !== SCOPE) return;
      var rates = l.types_rate || {}, counts = l.types || {};
      var names = Object.keys(counts).sort(function (a, b) {
        return (Number(rates[b]) || 0) - (Number(rates[a]) || 0) || (counts[b] - counts[a]);
      });
      var sum10 = 0;
      RC.rows = names.map(function (n) {
        var r10 = Math.round((Number(rates[n]) || 0) * 10);
        sum10 += r10;
        return { n: n, r10: r10, c: counts[n] };
      });
      RC.extra = [];
      [["(other types)", l.types_other_rate, l.types_other], ["(not a type)", l.types_invalid_rate, l.types_invalid]]
        .forEach(function (x) {
          var r10 = Math.round((Number(x[1]) || 0) * 10);
          sum10 += r10;
          if (x[2]) RC.extra.push({ n: x[0], r10: r10, c: x[2] });
        });
      RC.total = { r10: sum10, c: l.records };
      recordsDraw();
      // Under a scope each type's own records of it: the table's
      // overflow and the malformed names are no scope's and not listed.
      set("rc-note", "the rates sum to the tile's " + l.records_s + " records/s" +
          (SCOPE === "hybrid" ? "" : ", each type's " + SCOPE_WORD[SCOPE] + " records only"));
      var recent = (l.recent || []).filter(function (r) { return !RC.type || r.type === RC.type; });
      RC.recent = recent.slice().reverse();
      RC.seen = (l.recent || []).length;
      recordsTickDraw();
      set("rc-tick-note", (RC.type ? RC.type + " only, " : "every type, ") + "of the last " +
          (l.recent || []).length + " records");
    }).catch(function (e) { set("rc-note", errText(e.message)); });
  }

  // ── the sensor's health: the sensor-health tile's view ─────────────
  function healthView() {
    var box = clear("hl-rows"), asked = SCOPE;
    Promise.all([getJSON("/api/live"), getJSON("/api/health"),
                 getJSON("/api/devices?limit=1&offset=0&sort=last").catch(function () { return null; })])
      .then(function (r) {
        if (view !== "health" || asked !== SCOPE) return;
        var l = r[0], h = r[1], d = r[2], s = l.sensor || {};
        var word = el("span", "health-" + (s.state === "ok" ? "ok" : s.state === "unknown" ? "unknown" : "bad"),
                      String(s.state));
        var now = Math.floor(Date.now() / 1000);
        var newest = d && d.rows && d.rows.length && num(d.rows[0].last_seen) ? d.rows[0].last_seen : null;
        box.appendChild(el("div", "label", "the sensor (its sensor_health records)"));
        kvList(box, [["state", word],
                     ["report", num(s.age_s) ? dur(s.age_s) + " ago" : "no sensor_health yet"],
                     ["capture", s.capture_iface ? s.capture_iface + (s.capture_open ? (s.capture_running ? " running" : " stopped") : " not open") +
                                 (s.capture_exit ? ", " + s.capture_exit : "") : null],
                     ["monitor", s.monitor_iface ? s.monitor_iface + (s.monitor_open ? (s.monitor_running ? " running" : " stopped") : " not open") +
                                 (s.monitor_exit ? ", " + s.monitor_exit : "") : null],
                     ["scope", s.scope ? s.scope + (s.scope_not_enforced ? ", not enforced" : "") : null]]);
        box.appendChild(el("div", "label", "the stream (the data socket)"));
        kvList(box, [["socket", h.socket + (h.socket_spec ? ", " + h.socket_spec : "")],
                     ["last record", num(h.last_record_age_s) ? dur(h.last_record_age_s) + " ago" : "none yet"],
                     ["records", String(h.socket_records)], ["decode errors", String(h.socket_decode_errors)],
                     ["gaps", String(h.socket_gaps)], ["reconnects", String(h.socket_reconnects)],
                     ["last error", h.socket_last_error]]);
        box.appendChild(el("div", "label", "sloth.db"));
        kvList(box, [["db", String(h.db) + (h.db_mode ? ", " + h.db_mode : "")],
                     ["schema", num(h.db_schema) ? "v" + h.db_schema : null],
                     ["devices", num(h.db_rows) ? String(h.db_rows) : null],
                     ["freshness", newest !== null ? "newest device row seen " + dur(Math.max(0, now - newest)) + " ago" : "no device row to read"],
                     ["error", h.db_error]]);
        box.appendChild(el("div", "label", "slothweb.db"));
        kvList(box, [["store", String(h.store)], ["path", h.store_path]]);
        set("hl-note", "the tile's word is the state above");
      }).catch(function (e) { set("hl-note", errText(e.message)); });
  }

  // ── Activity's throughput drill-down ───────────────────────────────
  // The throughput tile's view: each interface's rx and tx over 24 h,
  // rx over its baseline band, and the top hosts; the first interface's
  // last rx bucket is the tile's number.
  var AF = { gen: 0 };
  function activityFocus() {
    var on = VP.focus === "throughput";
    $("a-focus").hidden = !on;
    $("a-focus-bar").hidden = !on;
    if (!on) return;
    set("a-focus-t", "focused: throughput, every interface's rx and tx, and the top hosts: the tile shows the first interface's rx");
    var gen = ++AF.gen;
    var box = clear("a-ifaces");
    var now = Math.floor(Date.now() / 1000);
    var tier = A.storeOn ? "minute" : "fine";
    var step = tier === "minute" ? 60 : 10;
    var to = now - now % step + step, from = to - 86400;
    getJSON("/api/keys?metric=iface.rx_rate").then(function (j) {
      if (gen !== AF.gen) return;
      var ks = (j.keys || []).filter(function (k) { return typeof k.key === "string"; }).slice(0, 8);
      set("a-focus-note", ks.length ? ks.length + " interfaces, " + tier + " tier" : "no interface seen yet");
      ks.forEach(function (k) {
        var key = k.key;
        var lab = el("div", "label", "");
        lab.appendChild(keySpan(key));
        var val = el("span", "sub", "");
        lab.appendChild(val);
        box.appendChild(lab);
        var rx = document.createElement("canvas"), tx = document.createElement("canvas");
        rx.className = "chart";
        tx.className = "spark";
        box.appendChild(rx);
        box.appendChild(el("div", "sub", "tx"));
        box.appendChild(tx);
        Promise.all([series("iface.rx_rate", key, tier, from, to), baseline("iface.rx_rate", key),
                     series("iface.tx_rate", key, tier, from, to)]).then(function (r) {
          if (gen !== AF.gen) return;
          var s = r[0], t = r[2];
          var bd = bands(s.points, r[1], s.kind, s.step);
          var lr = s.points.length ? s.points[s.points.length - 1][1] : NaN;
          var lt = t.points.length ? t.points[t.points.length - 1][1] : NaN;
          val.textContent = "rx " + fmt(lr) + " B/s, tx " + fmt(lt) + " B/s" + (bd ? "" : "; no baseline yet");
          draw(rx, s.points, { from: from, to: to, step: s.step, kind: s.kind, color: theme().normal,
                               axes: true, band: bd });
          draw(tx, t.points, { from: from, to: to, step: t.step, kind: t.kind, color: theme().normal,
                               axes: false, spark: true });
        });
      });
    }).catch(function (e) { set("a-focus-note", errText(e.message)); });
    var hosts = clear("a-hosts");
    var hto = now - now % 10 + 10, hfrom = hto - 3600;
    getJSON("/api/keys?metric=host.rx_rate").then(function (j) {
      if (gen !== AF.gen) return;
      var ks = (j.keys || []).filter(function (k) { return typeof k.key === "string"; }).slice(0, 12);
      set("a-hosts-note", ks.length ? "host.rx_rate, the " + ks.length + " most recently seen" : "no top host seen yet");
      return Promise.all(ks.map(function (k) {
        return getJSON(seriesPath("host.rx_rate", k.key, "fine", hfrom, hto))
          .then(function (s) { return { key: k.key, pts: s.points || [], kind: s.kind }; })
          .catch(function () { return { key: k.key, pts: [], kind: "gauge" }; });
      })).then(function (rows) {
        if (gen !== AF.gen) return;
        rows.forEach(function (r) { r.cur = r.pts.length ? r.pts[r.pts.length - 1][1] : 0; });
        rows.sort(function (a, b) { return b.cur - a.cur; });
        rows.forEach(function (r) {
          var cell = el("div", "cell");
          var nm = el("div", "nm");
          nm.appendChild(keySpan(r.key));
          cell.appendChild(nm);
          var cv = document.createElement("canvas");
          cell.appendChild(cv);
          cell.appendChild(el("div", "v", fmt(r.cur) + " B/s rx"));
          hosts.appendChild(cell);
          draw(cv, r.pts, { from: hfrom, to: hto, step: 10, kind: r.kind, color: theme().normal,
                            axes: false, spark: true });
        });
      });
    }).catch(function (e) { set("a-hosts-note", errText(e.message)); });
  }

  // The Overview is the first view: learn whether there is a store (for
  // the tier), then draw it, and redraw every minute.
  getJSON("/api/metrics").then(function (j) { A.storeOn = !!j.store; })
    .catch(function () { /* fine tier only */ })
    .then(function () {
      var r = hashRoute();
      if (r && r.v !== "overview") show(r.v, r.p);
      else overview();
    });
  setInterval(function () { if (view === "overview") overview(); }, 60000);
  }
})();
