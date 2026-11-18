// slothweb: identity across the sites (#192 I2, I3, I4, I8;
// docs/wiki/fleet.md, web_fleetid.h). window.SlothFleetId, two hooks
// app.js calls:
//   SlothFleetId.init(h)   once, main()'s helpers lent: el, set, getJSON,
//                          errText, stamp, openDrawer
//   SlothFleetId.show()    when the Fleet view shows: loads, and again
//                          every minute while it is shown
// One panel on the Fleet tab, from this server's /api/fleet/findings
// only: each finding with its class, its subject (a device or AP opens
// its drawer), the sites and each one's part, whether it applies at this
// spacing and why not, and its cited basis on hover; then every verdict a
// peer holds beside this site's, labelled with its site, shown and never
// applied. Every peer string goes in as textContent.
(function () {
  "use strict";
  var H = null;
  var POLL_MS = 60000;
  var MAC = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;
  var S = { timer: 0, gen: 0, sites: {} };

  function $(id) { return document.getElementById(id); }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function dist(m) {
    if (!num(m)) return "-";
    if (m >= 1000) return (m / 1000).toFixed(1) + " km";
    return m.toFixed(m < 100 ? 1 : 0) + " m";
  }
  function words(s) { return String(s || "").replace(/_/g, " "); }
  // A site as the panel names it: its label and host name (owner rule
  // 2026-11-12), else its peer name; this site's with "(here)".
  function siteName(name) {
    var s = S.sites[name];
    var l = s && s.label ? s.label : "", h = s && s.host ? s.host : "";
    var n = l && h && l !== h ? l + " (" + h + ")" : l || h;
    if (name === "self") return n ? n + " (here)" : "this site";
    return n || name;
  }
  // A MAC opens its drawer; anything else (a fingerprint, an SSID) is text.
  function keyEl(k) {
    if (!MAC.test(k)) return H.el("span", "fid-key", k);
    var b = H.el("button", "fid-link", k);
    b.type = "button";
    b.title = "open " + k;
    b.addEventListener("click", function () { H.openDrawer(k); });
    return b;
  }
  function legEl(e) {
    var d = H.el("div", "fid-leg");
    d.appendChild(H.el("span", "fid-who", siteName(e.site) + " (" + e.role + ")"));
    if (e.key !== "" && e.role !== "owner") d.appendChild(keyEl(e.key));
    var bits = [];
    if (num(e.rssi)) bits.push(e.rssi + " dBm");
    if (num(e.first_seen) && num(e.last_seen))
      bits.push(H.stamp(e.first_seen) + (e.last_seen > e.first_seen ? " to " + H.stamp(e.last_seen) : ""));
    if (e.attacks) bits.push("attacks: " + e.attacks.replace(/,/g, ", "));
    if (e.wps) bits.push("WPS " + e.wps.map(function (w) { return w || "-"; }).join(" / "));
    if (e.verdict) bits.push("triaged " + e.verdict);
    if (bits.length) d.appendChild(H.el("span", "", " " + bits.join(", ")));
    return d;
  }
  function status(f) {
    if (f.exonerated) return "exonerated: triaged known at a site";
    if (!f.applicable)
      return "not applicable: " + words(f.reason) + (num(f.distance_m) ? " (" + dist(f.distance_m) +
             (num(f.bound_m) ? ", reach " + dist(f.bound_m) : "") + ")" : "");
    return (f.lead ? "a lead to confirm" : "applies") + (num(f.distance_m) ? " (" + dist(f.distance_m) +
           (num(f.bound_m) ? " apart, reach " + dist(f.bound_m) : " apart") + ")" : "");
  }
  function rows(j) {
    var box = $("fid-rows");
    while (box.firstChild) box.removeChild(box.firstChild);
    j.findings.forEach(function (f) {
      var row = H.el("div", "fid-row" + (f.applicable && !f.exonerated ? "" : " dim"));
      var c = H.el("span", "fid-class", f.class + " " + words(f.kind) + (f.lead ? " (lead)" : ""));
      c.title = f.basis;
      row.appendChild(c);
      var k = H.el("span", "");
      k.appendChild(keyEl(f.key));
      if (f.ssid) k.appendChild(H.el("span", "", " \"" + f.ssid + "\""));
      if (f.alert_type) k.appendChild(H.el("span", "", " " + f.alert_type));
      row.appendChild(k);
      var ev = H.el("span", "");
      f.evidence.forEach(function (e) { ev.appendChild(legEl(e)); });
      row.appendChild(ev);
      var st = H.el("span", f.applicable && !f.exonerated ? "fid-on" : "fid-off", status(f));
      st.title = f.basis;
      if (f.note) st.appendChild(H.el("div", "sub", words(f.note)));
      row.appendChild(st);
      box.appendChild(row);
    });
    if (!box.firstChild) box.appendChild(H.el("div", "sub", "no finding"));
  }
  function verRows(j) {
    var box = $("fid-ver-rows");
    while (box.firstChild) box.removeChild(box.firstChild);
    j.verdicts.forEach(function (v) {
      var row = H.el("div", "fid-ver");
      row.appendChild(keyEl(v.addr));
      row.appendChild(H.el("span", "", v.states.map(function (s) {
        return siteName(s.site) + ": " + s.state + (s.alert_type ? " (" + s.alert_type + ")" : "") +
               ", " + H.stamp(s.ts);
      }).join("; ")));
      box.appendChild(row);
    });
    if (!box.firstChild) box.appendChild(H.el("div", "sub", "no peer has sent a verdict"));
  }
  function load() {
    var gen = ++S.gen;
    return H.getJSON("/api/fleet/findings?limit=200").then(function (j) {
      if (gen !== S.gen) return;
      S.sites = {};
      j.sites.forEach(function (s) { S.sites[s.site] = s; });
      rows(j);
      verRows(j);
      var cf = $("fid-config");
      cf.hidden = !j.configure;
      H.set("fid-config", j.configure || "");
      var c = j.counts, own = j.sites.map(function (s) {
        return siteName(s.site) + " " + (s.offered ? s.own_ssids.length + " SSID, " + s.own_bssids.length +
               " BSSID" : "not offered (older build)");
      });
      var pairs = j.pairs.map(function (p) {
        return siteName(p.a) + " - " + siteName(p.b) + " " + (p.co_located === null ? "no position" :
               dist(p.distance_m) + (p.co_located ? ", co-located" : ", apart"));
      });
      H.set("fid-note", c.I2 + " I2, " + c.I3 + " I3, " + c.I4 + " I4, " + c.I8 + " I8; " +
            c.not_applicable + " not applicable, " + c.exonerated + " exonerated; own networks: " +
            own.join(", ") + (pairs.length ? "; " + pairs.join("; ") : "") + (j.partial ? "; partial" : ""));
    }).catch(function (e) {
      if (gen === S.gen) H.set("fid-note", H.errText(e.message));
    });
  }
  function show() {
    load();
    if (!S.timer) S.timer = setInterval(function () { if (!$("v-fleet").hidden) load(); }, POLL_MS);
  }
  function init(h) { H = h; }
  window.SlothFleetId = { init: init, show: show };
})();
