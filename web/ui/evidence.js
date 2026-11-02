// The alert page's proof and the drawer's alert rows (owner requests
// 2026-10-27: "show the full packet capture in alerts at the bottom as
// well"; tap the drawer's alert rows for "full verbose details of the
// alert, include bibliography, when possible prove the alert with
// evidence").
//
// One module, one namespace, two hooks in app.js: alertPage() calls
// SlothEvidence.alert(j) with /api/alert's answer, and openDrawer()
// calls SlothEvidence.drawer(box) once its lists are drawn. Everything
// here writes into #ev-alert (the alert page's last section, the
// capture last in it) and decorates the drawer's "alerts naming it"
// rows (#ev-drawer); nothing else on the page is touched, so the other
// slices that edit app.js and index.html merge beside it. The frame
// index is drawn through app.js's one table implementation
// (window.SlothTables.make, its DataTable), like every table on the
// page, and its filter is kept with the page's other controls.
//
// Every value off the server is set as text (textContent, never
// markup). The one way out of the page is the same origin's
// /api/pcap, reached by window.location.assign() with every value
// encoded: the server answers it as an attachment, so the page stays.
window.SlothEvidence = (function () {
  var S = { gen: 0, id: "", caps: [], cur: -1, frames: [], open: {}, next: null, total: 0, rendered: "", t: null };

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = String(text);
    return e;
  }
  function clear(id) {
    var b = $(id);
    if (!b) return null;
    while (b.firstChild) b.removeChild(b.firstChild);
    return b;
  }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function str(v) { return typeof v === "string" ? v : ""; }
  function getJSON(path) {
    return fetch(path, { cache: "no-store" }).then(function (r) {
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
  function kv(box, pairs) {
    var d = el("div", "kv");
    pairs.forEach(function (p) {
      if (p[1] === null || p[1] === undefined || p[1] === "") return;
      d.appendChild(el("span", "k", p[0]));
      var v = p[1] instanceof Node ? p[1] : el("span", "", String(p[1]));
      var w = el("span", "v");
      w.appendChild(v);
      d.appendChild(w);
    });
    box.appendChild(d);
  }
  // Paragraphs, their `code spans` as code: split on the backticks.
  function text(box, t, cls) {
    if (typeof t !== "string" || t === "") return;
    t.split("\n\n").forEach(function (para) {
      var d = el("div", "prose" + (cls ? " " + cls : ""));
      para.split("`").forEach(function (part, i) {
        if (part === "") return;
        d.appendChild(i % 2 ? el("code", "", part) : document.createTextNode(part));
      });
      box.appendChild(d);
    });
  }
  function stamp(sec) {
    if (!num(sec)) return "-";
    var d = new Date(sec * 1000);
    function p2(n) { return n < 10 ? "0" + n : String(n); }
    return d.getFullYear() + "-" + p2(d.getMonth() + 1) + "-" + p2(d.getDate()) + " " +
           p2(d.getHours()) + ":" + p2(d.getMinutes()) + ":" + p2(d.getSeconds());
  }
  function bytes(n) {
    if (!num(n)) return "-";
    return n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KiB" : (n / 1048576).toFixed(1) + " MiB";
  }
  // The record's fraction of a second, in the file's unit.
  function frac(v, ns) {
    if (!num(v)) return "";
    var s = String(v), w = ns ? 9 : 6;
    while (s.length < w) s = "0" + s;
    return "." + s;
  }
  function relTime(ns) {
    if (!num(ns)) return "-";
    return "+" + (ns / 1e9).toFixed(ns < 1e7 ? 6 : 3) + " s";
  }

  var MATCHED = {
    incident: "sloth's incident id, from the manifest",
    record: "the file the alert's own record names",
    rule_time: "the same rule within the alert's time: the manifest names no address, so check it is this alert's"
  };
  var SAYS_CLS = { verified: "ev-ok", mismatch: "ev-bad", no_manifest_entry: "ev-warn" };

  // ── the proof: observed against threshold, why there is no capture ──
  function proof(j) {
    var box = clear("ev-proof"), ev = j.evidence || {};
    if (!box) return;
    var obs = (ev.observed || []).map(function (p) { return [String(p[0]), String(p[1])]; });
    var thr = (ev.thresholds || []).map(function (p) { return [String(p[0]), String(p[1])]; });
    box.appendChild(el("div", "sub", "observed"));
    kv(box, obs.length ? obs : [["observed", "-"]]);
    box.appendChild(el("div", "sub", "threshold" + (ev.thresholds_from ? " (" + ev.thresholds_from + ")" : "")));
    if (thr.length) kv(box, thr);
    else box.appendChild(el("div", "prose dim", "not stated: the rule's threshold is in its row above" +
                            " (what it is); no assessment front matter names one yet"));
    kv(box, [["capture", ev.why_no_capture ? ev.why_no_capture : null],
             ["sloth saves", str(ev.pcap_policy) || null]]);
  }

  // ── the assessment and its bibliography ────────────────────────────
  function assessment(j) {
    var box = clear("ev-asm"), a = j.assessment;
    if (!box) return;
    if (!a) {
      $("ev-asm-note").textContent = "";
      box.appendChild(el("div", "sub", "no assessment yet: docs/wiki/alert-assessments/" +
                         (str(j.type_name) || "TYPE") + ".md is not written"));
      return;
    }
    $("ev-asm-note").textContent = str(a.path) + (a.updated ? ", " + a.updated : "");
    if (a.too_large) {
      box.appendChild(el("div", "sub", "too long to send with the alert's page: read it in the wiki"));
      return;
    }
    if (a.front_matter && a.front_matter.length)
      kv(box, a.front_matter.map(function (p) { return [String(p[0]), String(p[1])]; }));
    (a.sections || []).forEach(function (s) {
      box.appendChild(el("div", "ev-h", str(s.heading)));
      text(box, s.text);
    });
    box.appendChild(el("div", "ev-h", "bibliography"));
    var ol = el("ul", "ev-bib");      // each entry starts with its own [n]
    (a.bibliography || []).forEach(function (b) { ol.appendChild(el("li", "", String(b))); });
    if (!(a.bibliography || []).length) ol.appendChild(el("li", "sub", "none listed"));
    box.appendChild(ol);
    // The Bibliography's own prose (a numbering note, "no public
    // advisory was found"): beside the entries, never one of them.
    text(box, a.bibliography_note, "dim");
  }

  // ── the packet capture ─────────────────────────────────────────────
  function captures(j) {
    var box = clear("ev-caps");
    clear("ev-frames");
    $("ev-more").hidden = true;
    $("ev-dl").hidden = true;
    S.caps = j.captures || [];
    S.cur = -1;
    if (!box) return;
    $("ev-cap-note").textContent = j.captures_note ? j.captures_note : "";
    if (!S.caps.length) {
      box.appendChild(el("div", "sub", (j.evidence && j.evidence.why_no_capture) || "no capture"));
      return;
    }
    var ul = el("ul", "lst ev-files");
    S.caps.forEach(function (c, i) {
      var li = el("li", "go");
      li.tabIndex = 0;
      li.role = "button";
      li.appendChild(el("span", "tx d-bright", str(c.file)));
      li.appendChild(el("span", "d-dim", (c.sink ? c.sink + ", " : "") + bytes(c.size) +
                        (c.written_at ? ", written " + c.written_at : "")));
      li.title = MATCHED[c.matched_by] || "";
      li.addEventListener("click", function () { open(i, 0); });
      li.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(i, 0); }
      });
      ul.appendChild(li);
    });
    box.appendChild(ul);
    open(0, 0);
  }

  // ── the frame index: one of the page's tables (app.js's DataTable:
  // sortable, resizable, its widths and sort kept in this browser) ──
  var COLS = [
    { k: "i", label: "#", w: 5, min: 3, type: "num", num: true, val: function (f) { return f.i; } },
    { k: "t", label: "time", w: 12, type: "num", num: true, val: function (f) { return f.t_rel_ns; } },
    { k: "len", label: "bytes", w: 9, type: "num", num: true, val: function (f) { return f.caplen; } },
    { k: "kind", label: "kind", w: 10, type: "text", val: function (f) { return str(f.kind); } },
    { k: "sum", label: "summary", w: 36, flex: true, type: "text", val: function (f) { return str(f.summary); } },
    { k: "cut", label: "cut", w: 14, type: "text", val: function (f) { return cutOf(f); } }
  ];
  function cutOf(f) { return f.cut ? str(f.cut) : f.truncated ? "cut" : ""; }
  // Made on the first alert page: app.js's DataTable exists once its
  // main() has run, after this module's init.
  function table() {
    if (S.t || !window.SlothTables || !$("ev-frames-box")) return S.t;
    S.t = window.SlothTables.make({ id: "evframes", label: "the capture's frames", box: $("ev-frames-box"),
      head: $("ev-frames-head"), reset: $("ev-frames-tools"), redraw: drawFrames, cols: COLS });
    return S.t;
  }

  function fbody(f) {
    var body = el("div", "ev-fbody");
    var pairs = [["link", str(f.link)], ["from", str(f.from) || null], ["to", str(f.to) || null],
                 ["captured", stamp(f.ts) + frac(f.ts_frac, f.ts_ns)],
                 ["bytes", f.caplen + " of " + f.len + (f.cut ? ": " + f.cut : "")]];
    (f.fields || []).forEach(function (p) { pairs.push([String(p[0]), String(p[1])]); });
    if (f.truncated) pairs.push(["decode", "stopped where the captured bytes end; a field not shown was not captured, not absent"]);
    kv(body, pairs);
    body.appendChild(el("pre", "ev-hex", str(f.hex)));
    if (num(f.hex_more) && f.hex_more > 0)
      body.appendChild(el("div", "sub", f.hex_more + " more bytes in the file: download it for them"));
    return body;
  }

  // A row of cells under the columns, and its fields and bytes under
  // it when opened (a click, Enter or Space); which are open is kept
  // across a sort.
  function frameRow(f) {
    var d = el("div", "ev-frame");
    var r = el("div", "evfrow dt-row");
    r.tabIndex = 0;
    r.appendChild(el("span", "n d-dim", String(f.i)));
    r.appendChild(el("span", "n", relTime(f.t_rel_ns)));
    r.appendChild(el("span", "n d-dim", String(f.caplen) + "/" + String(f.len)));
    r.appendChild(el("span", "d-bright", str(f.kind)));
    r.appendChild(el("span", "tx", str(f.summary)));
    r.appendChild(el("span", "ev-cut", cutOf(f)));
    d.appendChild(r);
    var body = null;
    function show(on) {
      r.ariaExpanded = on ? "true" : "false";
      if (on && !body) { body = fbody(f); d.appendChild(body); }
      if (body) body.hidden = !on;
      if (on) S.open[f.i] = true; else delete S.open[f.i];
    }
    show(!!S.open[f.i]);
    r.addEventListener("click", function () { show(r.ariaExpanded !== "true"); });
    r.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); show(r.ariaExpanded !== "true"); }
    });
    d.dataset.q = (str(f.kind) + " " + str(f.summary) + " " + str(f.from) + " " + str(f.to)).toLowerCase();
    return d;
  }

  // The frames held, in the header's order, the filter applied.
  function drawFrames() {
    var box = clear("ev-frames");
    if (!box) return;
    var t = table();
    (t ? t.sort(S.frames) : S.frames).forEach(function (f) { box.appendChild(frameRow(f)); });
    filter();
  }

  function filter() {
    var q = $("ev-filter").value.trim().toLowerCase(), box = $("ev-frames"), shown = 0;
    if (!box) return;
    for (var c = box.firstChild; c; c = c.nextSibling) {
      if (!c.dataset || typeof c.dataset.q !== "string") continue;
      var on = q === "" || c.dataset.q.indexOf(q) >= 0;
      c.hidden = !on;
      if (on) shown++;
    }
    return shown;
  }

  function open(i, offset) {
    var c = S.caps[i], gen = S.gen, id = S.id;
    if (!c) return;
    if (offset === 0) { clear("ev-frames"); S.cur = i; S.frames = []; S.open = {}; }
    var lis = $("ev-caps").querySelectorAll("li");
    for (var k = 0; k < lis.length; k++) lis[k].classList.toggle("on", k === i);
    $("ev-cap-note").textContent = "loading " + str(c.file);
    getJSON("/api/pcap/frames?id=" + encodeURIComponent(id) + "&n=" + encodeURIComponent(String(i)) +
            "&offset=" + encodeURIComponent(String(offset))).then(function (r) {
      if (gen !== S.gen || S.cur !== i) return;
      if (r.file_name !== c.file) {
        $("ev-cap-note").textContent = "the capture list changed: reload the page";
        return;
      }
      var h = r.hash || {}, fi = r.file || {};
      var head = clear("ev-hash");
      var badge = el("span", "ev-badge " + (SAYS_CLS[h.status] || "ev-warn"), str(h.says));
      head.appendChild(badge);
      head.appendChild(el("span", "d-dim", "  SHA-256 of the " + h.bytes + " bytes read" +
        (h.manifest_sha256 ? ", manifest " + h.manifest_sha256 : "") +
        (h.status === "mismatch" ? ": the file is not the one sloth wrote and hashed" : "") +
        (h.status === "no_manifest_entry" ? ": no manifest line names it, so nothing vouches for its bytes" : "")));
      $("ev-cap-note").textContent = str(c.file) + ": " + str(fi.linktype_name) + ", snaplen " +
        fi.snaplen + ", " + r.frames_total + " frames" + (r.truncated_file ? ", the file ends inside a record" : "") +
        (r.frames_capped ? ", the first 4096 indexed" : "") + "; matched by " + (MATCHED[c.matched_by] || c.matched_by);
      S.frames = S.frames.concat(r.frames || []);
      drawFrames();
      S.next = r.more && num(r.next_offset) ? r.next_offset : null;
      var more = $("ev-more");
      more.hidden = S.next === null;
      if (S.next !== null) more.textContent = "next frames (" + (r.frames_total - S.next) + " more not shown)";
      $("ev-dl").hidden = false;
    }).catch(function (e) {
      if (gen !== S.gen) return;
      clear("ev-hash");
      $("ev-cap-note").textContent = str(c.file) + ": " + (e.body && e.body.message ? e.body.message : e.message);
      $("ev-dl").hidden = false;
    });
  }

  function alert(j) {
    S.gen++;
    S.id = typeof j.id === "string" ? j.id : "";
    S.rendered = location.hash;
    S.frames = [];
    S.open = {};
    table();
    clear("ev-hash");
    proof(j);
    assessment(j);
    captures(j);
  }

  // The drawer's "alerts naming it": each row a tap target that says it
  // is one (#ev-drawer in page.css: the mark and, on a touch screen, a
  // 44 px row), and the drawer closed on the way, or on a phone the
  // alert's page would open under it.
  function drawer(box) {
    if (!box) return;
    // app.js marks the list (data-ev="drawer-alerts"); its label is the
    // element before it.
    var wrap = box.querySelector("[data-ev=\"drawer-alerts\"]");
    if (!wrap) return;
    var old = $("ev-drawer");
    if (old && old !== wrap) old.removeAttribute("id");
    wrap.id = "ev-drawer";
    var lab = wrap.previousElementSibling;
    if (lab && lab.classList.contains("label"))
      lab.appendChild(el("span", "sub", "tap one: its page, evidence, capture and bibliography"));
    wrap.addEventListener("click", function (e) {
      var t = e.target;
      while (t && t !== wrap && !(t.classList && t.classList.contains("go"))) t = t.parentNode;
      if (!t || t === wrap) return;
      var x = $("dr-close");
      if (x && !$("drawer").hidden) x.click();
    });
  }

  // The page's elements exist once it is parsed; app.js waits the same way.
  function init() {
    $("ev-filter").addEventListener("input", filter);
    $("ev-more").addEventListener("click", function () { if (S.next !== null) open(S.cur, S.next); });
    $("ev-dl").addEventListener("click", function () {
      if (S.cur < 0 || !S.id) return;
      window.location.assign("/api/pcap?id=" + encodeURIComponent(S.id) + "&n=" + encodeURIComponent(String(S.cur)));
    });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
  // Another page: what this section showed is not that page's.
  window.addEventListener("hashchange", function () {
    if (location.hash === S.rendered) return;
    S.gen++;
    S.caps = [];
    S.frames = [];
    S.open = {};
    ["ev-proof", "ev-asm", "ev-caps", "ev-hash", "ev-frames"].forEach(clear);
    if ($("ev-more")) $("ev-more").hidden = true;
    if ($("ev-dl")) $("ev-dl").hidden = true;
  });

  return { alert: alert, drawer: drawer };
})();
