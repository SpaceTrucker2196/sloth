// slothweb: one SSID's detail (owner request 2026-11-11: "on the wifi tab
// we should be able to select any ssid and get a detail view just like
// we do for a client"; web_ssidview.h). window.SlothSsid, the hooks
// app.js calls:
//   SlothSsid.init(h)          once, main()'s helpers lent: el, getJSON
//                              (scoped), errText, keyColor, stamp,
//                              shortStamp, kvList, drawStrip, ssidPlain,
//                              openDrawer, alertLink, scope
//   SlothSsid.link(node, ssid) node made selectable, by a click, Enter or
//                              Space, and returned; ssid is the display
//                              form the server sent, null for the hidden
//                              (empty) SSID
//   SlothSsid.more(li, ssid)   a small button after a control that
//                              already has an action of its own (the
//                              channel mix's list)
//   SlothSsid.open(ssid)       the drawer, as link() opens it
// The drawer (#sdrawer) is built the way the device drawer is: a key and
// value list, the 24 h presence strip in G5, then lists. Every access
// point and station in it is a button that opens the device drawer, and
// every alert a row that opens the alert's page.
//
// An SSID is octets, not text. The server sends its display form
// (web/src/web_ssid.h): printable UTF-8 as it is, any other octet as
// \xNN, a backslash doubled, which reads back to one octet string only.
// octets() reads it back and param() spells those octets as the route's
// `ssid=` parameter: base64url without padding, or "-" for none. So a
// name that is empty, not UTF-8, 32 octets long or full of % and _
// travels as letters, digits, - and _ and nothing else, and the server
// compares it with = as a bound parameter. Every DOM string is set with
// textContent; an SSID never becomes markup, a class or an attribute.
(function () {
  "use strict";
  var H = null, S = { gen: 0, sel: undefined, back: null };
  var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  var HEX2 = /^[0-9a-f]{2}$/;
  var NEW_S = 86400, CELLS = 144, CELL_S = 600;
  var SEV_WORD = ["low", "warn", "crit"];
  function $(id) { return document.getElementById(id); }
  function num(v) { return typeof v === "number" && isFinite(v); }

  // The display form back to its octets.
  function octets(disp) {
    var s = String(disp), out = [], i = 0;
    while (i < s.length) {
      var c = s.charAt(i);
      if (c === "\\" && s.charAt(i + 1) === "\\") { out.push(0x5c); i += 2; continue; }
      if (c === "\\" && s.charAt(i + 1) === "x" && HEX2.test(s.substr(i + 2, 2))) {
        out.push(parseInt(s.substr(i + 2, 2), 16));
        i += 4;
        continue;
      }
      var cp = s.codePointAt(i);
      i += cp > 0xffff ? 2 : 1;
      if (cp < 0x80) out.push(cp);
      else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 63));
      else if (cp < 0x10000) out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
      else out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
    }
    return out;
  }

  // The route's parameter for a display form: "-" for the hidden SSID,
  // null for what is no SSID at all (more than 32 octets, or a NUL: the
  // stream's U+FFFD marks, three octets where one was lost).
  function param(disp) {
    if (disp === null || disp === undefined || disp === "") return "-";
    var o = octets(disp), out = "", acc = 0, bits = 0;
    if (o.length > 32 || o.indexOf(0) >= 0) return null;
    for (var i = 0; i < o.length; i++) {
      acc = ((acc << 8) | o[i]) & 0xffff;
      bits += 8;
      while (bits >= 6) { bits -= 6; out += B64.charAt((acc >> bits) & 63); }
    }
    if (bits) out += B64.charAt((acc << (6 - bits)) & 63);
    return out;
  }

  function link(node, ssid) {
    node.classList.add("go", "ssidgo");
    node.tabIndex = 0;
    node.role = "link";
    node.title = "the detail of this SSID";
    node.addEventListener("click", function (e) {
      // Inside a row with a click of its own (a device row): only this.
      e.stopPropagation();
      open(ssid);
    });
    return node;
  }

  function more(li, ssid) {
    var b = H.el("button", "dt-reset ssidmore", "ssid");
    b.type = "button";
    b.title = "the detail of this SSID";
    b.addEventListener("click", function () { open(ssid); });
    li.appendChild(b);
    return b;
  }

  function close() {
    if ($("sdrawer").hidden) return;
    $("sdrawer").hidden = true;
    S.sel = undefined;
    S.gen++;
    if (S.back && S.back.focus && document.body.contains(S.back)) S.back.focus();
    S.back = null;
  }

  function clear(id) {
    var b = $(id);
    while (b.firstChild) b.removeChild(b.firstChild);
    return b;
  }

  // A MAC as a button that opens the device drawer over this one.
  function macGo(mac, random) {
    var b = H.el("button", "lk");
    b.type = "button";
    var sw = H.el("span", "sw");
    sw.style.background = H.keyColor(String(mac));
    b.appendChild(sw);
    b.appendChild(H.el("span", random ? "rnd d-dim" : "d-dim", (random ? "~" : "") + mac));
    b.title = "the device drawer of " + mac;
    b.addEventListener("click", function () { H.openDrawer(String(mac)); });
    return b;
  }

  function who(x) {
    return x.random ? "randomised" : typeof x.vendor === "string" ? x.vendor : "?";
  }

  // A titled list: its count beside the title ("12 of 340" when cut),
  // R5's one line when it is empty.
  function list(box, title, items, total, none, row) {
    var n = items ? items.length : 0;
    var lab = H.el("div", "label", title);
    lab.appendChild(H.el("span", "sub", num(total) && total > n ? n + " of " + total : String(n)));
    box.appendChild(lab);
    var ol = H.el("ol", "lst slst");
    if (!n) ol.appendChild(H.el("li", "sub", none));
    for (var i = 0; i < n; i++) {
      var li = H.el("li", "");
      row(li, items[i]);
      ol.appendChild(li);
    }
    box.appendChild(ol);
    return ol;
  }

  function seen(li, x) {
    li.appendChild(H.el("span", "d-dim", H.shortStamp(x.first_seen) + " to " + H.shortStamp(x.last_seen)));
  }

  function bssidRow(newFrom) {
    return function (li, b) {
      if (glyph.isNew(b.first_seen, newFrom) && b.current) {
        var nw = H.el("span", "nw");
        nw.title = "new: first seen in the last 24 h";
        li.appendChild(nw);
      }
      li.appendChild(macGo(b.bssid, false));
      li.appendChild(H.el("span", typeof b.vendor === "string" ? "d-bright" : "d-dim",
                          typeof b.vendor === "string" ? b.vendor : "?"));
      li.appendChild(H.el("span", "d-normal", "ch " + b.channel));
      li.appendChild(H.el("span", "d-normal", (b.enc === null ? "?" : b.enc) +
                          (b.akm_names && b.akm_names.length ? " " + b.akm_names.join(",") : "") +
                          ", mfp " + b.mfp_word));
      li.appendChild(H.el("span", "d-dim", num(b.signal) ? b.signal + " dBm" : "no signal"));
      seen(li, b);
      if (!b.current) li.appendChild(H.el("span", "d-dim", "beaconed it then; another name now"));
      if (b.karma) li.appendChild(H.el("span", "warn", "karma " + b.karma.score));
      if (b.twins && b.twins.length) li.appendChild(H.el("span", "warn", "twin pair"));
    };
  }

  // sloth's own findings on its access points: the KARMA candidates
  // (sloth.db) and the twin pairs the stream's twin_episode named since
  // slothweb started. Hypotheses a passive sensor corroborates, in
  // sloth's words; none is a verdict of the page's.
  function findings(j) {
    var out = [];
    (j.bssids || []).forEach(function (b) {
      if (b.karma) out.push({ bssid: b.bssid, text: "KARMA candidate, score " + b.karma.score + " of 7, " +
                              b.karma.ssid_count + " names beaconed (sloth.db karma_candidates)",
                              first_seen: b.first_seen, last_seen: b.last_seen });
      (b.twins || []).forEach(function (t) {
        if (t.real !== b.bssid) return;
        out.push({ bssid: t.twin, text: "twin pair with " + t.real + ": " +
                   (t.attributed ? "sloth attributes " + t.twin + " as the impostor" : "not attributed: " +
                    "which half is the impostor is not known") +
                   (t.tainted ? ", a deauth flood on the other half within sloth's window" : "") +
                   (num(t.confidence) ? ", confidence " + t.confidence : "") + " (the stream's twin_episode)",
                   first_seen: t.first_seen, last_seen: t.last_seen });
      });
    });
    return out;
  }

  function render(j) {
    var body = clear("sdr-body"), lists = clear("sdr-lists");
    var nm = clear("sdr-name");
    nm.appendChild(j.ssid === null ? H.el("span", "d-dim", "(hidden)") : H.ssidPlain(String(j.ssid), j.ssid_k, j.ssid_np));
    var nb = (j.bssids || []).length, newFrom = num(j.now) ? j.now - NEW_S : null;
    $("sdr-note").textContent = "sloth.db " + j.db + (H.scope() !== "hybrid" ? "; " + H.scope() + " scope" : "");
    H.kvList(body, [
      ["ssid", j.ssid === null ? "none: a hidden network's beacons carry an empty SSID"
                               : H.ssidPlain(String(j.ssid), j.ssid_k, j.ssid_np)],
      ["octets", String(j.octets) + (j.ssid_np ? ", some not printable UTF-8 (shown as \\xNN)" : "")],
      ["first seen", num(j.first_seen) ? H.stamp(j.first_seen) : "no access point in sloth.db beacons it"],
      ["last seen", num(j.last_seen) ? H.stamp(j.last_seen) : null],
      ["designated", "not known here: sloth's --my-ssid is its own setting, in neither sloth.db nor the stream"]
    ]);
    H.drawStrip($("sdr-strip"), j.presence, CELLS,
                glyph.firstCell(j.first_seen, j.presence_from, CELL_S, CELLS));
    $("sdr-strip-note").textContent = glyph.caption({
      source: "dev.present of its " + j.presence_bssids + " current access point" +
              (j.presence_bssids === 1 ? "" : "s") + ", any one present", window: "24 h",
      tier: "10 min cells", n: CELLS,
      state: /^0*$/.test(String(j.presence)) ? "no data" : "" });
    list(lists, "access points beaconing it", j.bssids, j.bssids_more ? j.bssids_total : nb,
         "none in sloth.db's beacon_aps", bssidRow(newFrom));
    list(lists, "clients associated to it", j.assocs, j.assocs_total,
         "no association to it in sloth.db's assocs", function (li, a) {
           li.appendChild(macGo(a.mac, a.random));
           li.appendChild(H.el("span", a.random ? "d-dim" : "d-bright", who(a)));
           li.appendChild(H.el("span", "d-dim", "on " + a.bssid + ", ch " + a.channel +
                               (num(a.signal) ? ", " + a.signal + " dBm" : "")));
           seen(li, a);
         });
    list(lists, "clients probing for it", j.probers, j.probers_total,
         j.hidden ? "none: a wildcard probe names no network" : "no station in sloth.db's pnl_ssids asks for it",
         function (li, p) {
           li.appendChild(macGo(p.mac, p.random));
           li.appendChild(H.el("span", p.random ? "d-dim" : "d-bright", who(p)));
           seen(li, p);
         });
    list(lists, "twin and karma findings", findings(j), null,
         "none: no KARMA candidate among its access points, no twin pair in the stream since slothweb started",
         function (li, f) {
           li.appendChild(macGo(f.bssid, false));
           li.appendChild(H.el("span", "warn", f.text));
           seen(li, f);
         });
    var al = list(lists, "alerts naming it or its access points", j.alerts, null,
                  j.alerts_read ? "none in the last " + j.alerts_days + " d" : "sloth.db's alerts could not be read",
                  function (row, a) {
                    var ok = a.sev >= 0 && a.sev <= 2;
                    row.className = ok ? "sev" + a.sev : "";
                    row.appendChild(H.el("span", "ty", ok ? SEV_WORD[a.sev] : "?"));
                    row.appendChild(H.el("span", "d-bright", a.title));
                    row.appendChild(H.el("span", "d-dim", "x" + a.count +
                                         (a.incidents > 1 ? ", " + a.incidents + " incidents" : "")));
                    seen(row, a);
                    H.alertLink(row, a.id);
                  });
    al.dataset.ssid = "alerts";
    lists.appendChild(H.el("div", "sub", glyph.caption({
      source: "sloth.db alerts whose key names the SSID or a current access point",
      window: j.alerts_days + " d", n: (j.alerts || []).length,
      state: (j.alerts_more ? "more than shown" : "") +
             (num(j.alerts_reached) ? (j.alerts_more ? "; " : "") + "the newest only, read back to " +
              H.shortStamp(j.alerts_reached) + " (the walk's bound)" : "") })));
  }

  function open(disp) {
    if (!H) return;
    var gen = ++S.gen, p = param(disp);
    S.sel = disp === undefined ? null : disp;
    if ($("sdrawer").hidden) S.back = document.activeElement;
    $("sdrawer").hidden = false;
    $("sdr-close").focus();
    var nm = clear("sdr-name");
    nm.appendChild(p === "-" ? H.el("span", "d-dim", "(hidden)") : H.ssidPlain(String(disp), null, false));
    clear("sdr-body");
    clear("sdr-lists");
    H.drawStrip($("sdr-strip"), null, CELLS, -1);
    $("sdr-strip-note").textContent = "";
    if (p === null) {
      $("sdr-note").textContent = "no detail: this name is not an SSID sloth.db can hold (more than 32 " +
        "octets, where the stream replaced lost octets with a mark)";
      return;
    }
    $("sdr-note").textContent = "loading";
    H.getJSON("/api/wifi/ssid?ssid=" + encodeURIComponent(p)).then(function (j) {
      if (gen !== S.gen) return;
      if (j.out_of_scope) {
        $("sdr-note").textContent = "nothing under this scope: " + String(j.reason);
        return;
      }
      render(j);
    }).catch(function (e) { if (gen === S.gen) $("sdr-note").textContent = H.errText(e.message); });
  }

  function init(h) {
    H = h;
    $("sdr-close").addEventListener("click", close);
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") close(); });
    // A device or an alert opened from here takes the screen: this
    // drawer closes under it rather than cover it.
    $("sdr-lists").addEventListener("click", function (e) {
      var t = e.target;
      while (t && t !== this && !(t.classList && (t.classList.contains("lk") ||
                                                  (t.tagName === "LI" && t.classList.contains("go")))))
        t = t.parentNode;
      if (t && t !== this) { $("sdrawer").hidden = true; S.sel = undefined; S.gen++; }
    });
    // The scope switch draws every open view again; this one too.
    function rescope() {
      if (!$("sdrawer").hidden && S.sel !== undefined) setTimeout(function () { open(S.sel); }, 0);
    }
    $("scope").addEventListener("click", rescope);
    $("scope").addEventListener("keydown", rescope);
  }

  window.SlothSsid = { init: init, link: link, more: more, open: open, close: close,
                       param: param, octets: octets };
})();
