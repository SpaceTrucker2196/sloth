// Alert triage and the FRRS emitter record (docs/web-frrs-spec.md §6),
// one module on window.SlothFrrs beside app.js, which reaches it only
// through the named hook points below, each one guarded call, so the
// page works with this file absent and three other slices can change
// app.js at the same time:
//
//   alertLink(li, id)   SlothFrrs.link(li, id)    every linked alert row
//                       (the Overview's latest alerts, History, the
//                       drawer's "alerts naming it", an alert page's
//                       other alerts): its state chip and buttons
//   alertRow(a)         SlothFrrs.cell(a, row)    the Alerts page's
//                       triage column, from the answer's own triage
//   alertsQuery(off)    SlothFrrs.q(p)            triage= on the path
//   show(v, p)          SlothFrrs.show(v, p)      the Alerts page's
//                       select from the address, and the TACDB tab
//   openDrawer(mac)     SlothFrrs.mountDrawer(mac, j)   frrs-drawer
//   alertPage(j)        SlothFrrs.mountAlert(j)   frrs-alert-triage and
//                       frrs-alert
//   main()              SlothFrrs.init({...})     the page's helpers
//
// and offers one to the evidence-bundle slice:
// SlothFrrs.mountBundle(container, kind, id) on the TACDB platform view
// (#bundle-btn-tacdb), which hands the container to
// window.SlothBundle.mount when that module is there.
//
// The location slice's elements (loc-alert, loc-drawer) are never
// touched: a single passive sensor has no location axis, and the
// record says so where FRRS would have one.
//
// Every value is shown with textContent and nothing else, as app.js
// shows the stream's: a note, a name or an SSID holding markup is shown
// as the characters it is. No value becomes a class, an attribute or a
// URL, and no sink that parses markup is used (test_routes.c holds the
// whole page to that; test_frrs.c holds this file to it again). Writes are POST,
// same-origin (the browser sends Origin, the server requires it), JSON,
// and the page redraws from the server's answer, never from what it
// sent.
var SlothFrrs = (function () {
  "use strict";
  var H = null;
  function $(id) { return document.getElementById(id); }
  var ID_RE = /^[sd][0-9A-Za-z]{1,24}$/;
  var MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;
  var STATES = ["untriaged", "false", "noise", "incident", "known"];
  // The severity tokens the page has: noise low, false warn, incident
  // crit; known green (--tri-known, the TUI's bright phosphor), the
  // affiliation colour of a friendly or neutral emitter.
  var CHIP = { "untriaged": "d-dim", "false": "sev1", "noise": "sev0", "incident": "sev2",
               "known": "tri-known" };
  var FILTERS = { "any": 1, "untriaged": 1, "triaged": 1, "out": 1, "false": 1, "noise": 1,
                  "incident": 1, "known": 1 };
  var KNOWN_TITLE = "known good: expected traffic from a friendly or neutral emitter " +
    "(the FRRS/EW affiliation sense: friend, or neutral per MIL-STD-2525's green); " +
    "triaged out like false and noise, never an incident";
  var S = {
    writes: false, store: "none", readOnly: false, recSrc: "none",
    st: {},      // alert id -> its current triage, as the server said
    types: {},   // alert id -> its type's name
    rec: {},     // type name -> /api/frrs/recommend's answer
    recWait: {}, // type name -> true while asked
    reg: {},     // alert id -> the places it is drawn
    seen: {},    // alert id -> when its state was last asked
    queue: [], qt: 0, gen: 0, dgen: 0, tgen: 0
  };

  function el(tag, cls, text) { return H.el(tag, cls, text); }
  function clear(n) { while (n && n.firstChild) n.removeChild(n.firstChild); }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function out(st) { return st === "false" || st === "noise" || st === "known"; }
  function stamp(t) { return num(t) && t > 0 ? H.stamp(t) : "-"; }

  // ── the write path ────────────────────────────────────────────────
  function post(path, body, raw) {
    return fetch(path, {
      method: "POST", cache: "no-store", credentials: "omit",
      headers: { "Content-Type": "application/json" },
      body: raw ? body : JSON.stringify(body)
    }).then(function (r) {
      // --web-read-only takes the POST routes away before the router:
      // its 405 is the server's plain one, not JSON, and means exactly
      // that (a page loaded before the restart still has its buttons).
      if (r.status === 405) {
        S.writes = false;
        throw new Error("read_only");
      }
      return r.json().then(function (j) {
        if (!r.ok) {
          var e = new Error(j && typeof j.error === "string" ? j.error : String(r.status));
          e.body = j;
          throw e;
        }
        return j;
      }, function () { throw new Error(String(r.status)); });
    });
  }
  var WHY = {
    "bad_origin": "refused: not this page's origin",
    "rate_limited": "too many changes at once; wait a moment",
    "no_store": "no store: this slothweb keeps no triage (WITH_SQLITE=0 or no --store)",
    "read_only": "read-only: slothweb was started with --web-read-only; reload to drop the buttons",
    "no_recommendation": "no recommendation yet for this type",
    "no_such_alert": "that alert is gone",
    "triage_full": "the triage store is full and nothing superseded is left to fold; a clear still works",
    "tacdb_full": "the TACDB is full",
    "duplicate_name": "that name is taken",
    "emitter_owned": "that emitter is on another platform",
    "unit_depth": "units go four deep at most",
    "unit_not_empty": "empty the unit first (its subunits and platforms)",
    "too_long": "too long", "bad_text": "a control or bidirectional-override character is not allowed",
    "too_many_triage": "more than 1,000 triage lines in one file; split it (nothing was merged)",
    "bad_addr": "not an address of that kind", "store_busy": "the store is busy; try again"
  };
  function why(e) {
    var m = e && e.message ? e.message : String(e);
    return Object.prototype.hasOwnProperty.call(WHY, m) ? WHY[m] : "error: " + m;
  }

  // ── what the server says about writes, and the open-alerts tile ──
  function summary() {
    H.getJSON("/api/frrs/summary").then(function (j) {
      S.writes = !!j.writes;
      S.store = j.store;
      S.readOnly = !!j.read_only;
      S.recSrc = j.recommendations;
      var o = j.open || {}, line = $("k-alerts-triaged");
      if (!line) return;
      var parts = [];
      if (o.noise) parts.push(o.noise + " noise");
      if (o["false"]) parts.push(o["false"] + " false");
      if (o.known) parts.push(o.known + " known");
      var txt = parts.length ? parts.join(" · ") + " triaged out" : "";
      if (o.incident) txt += (txt ? "; " : "") + o.incident + " incident";
      // Near the cap the oldest superseded rows fold (§3.1): said, so a
      // history shrinking is never a surprise.
      if (j.near_cap && typeof j.rows === "number" && typeof j.cap === "number")
        txt += (txt ? "; " : "") + "triage store " + j.rows + " of " + j.cap +
          " rows: the oldest superseded rows fold";
      // The big number stays the open count: nothing is dropped from
      // it, the triaged-out ones are said beside it.
      line.textContent = txt;
      line.hidden = !txt;
    }).catch(function () { /* the tile keeps its last line */ });
  }

  // ── the recommendation (docs/web-frrs-spec.md §3.1) ──────────────
  function rec(type, then) {
    if (typeof type !== "string" || !type) return;
    if (S.rec[type]) { if (then) then(S.rec[type]); return; }
    if (S.recWait[type]) return;
    S.recWait[type] = true;
    H.getJSON("/api/frrs/recommend?type=" + encodeURIComponent(type)).then(function (j) {
      S.rec[type] = j;
      delete S.recWait[type];
      Object.keys(S.types).forEach(function (id) { if (S.types[id] === type) render(id); });
      if (then) then(j);
    }).catch(function () { delete S.recWait[type]; });
  }

  // ── one alert's chip and buttons, wherever it is drawn ───────────
  function chip(st) {
    var s = st && st.state ? st.state : "untriaged";
    var c = el("span", "tri-chip " + (CHIP[s] || "d-dim"), s);
    if (s === "known") c.title = KNOWN_TITLE;
    if (st && st.via === "recommended") c.appendChild(el("span", "d-dim", " (rec.)"));
    if (st && st.via === "import") c.appendChild(el("span", "d-dim", " (imp.)"));
    return c;
  }
  function act(id, state, note, msg) {
    var by = $("frrs-by") ? $("frrs-by").value.trim() : "";
    var b = { id: id, state: state };
    if (note) b.note = note;
    if (by) b.by = by;
    if (msg) msg.textContent = "saving";
    return post("/api/frrs/triage", b).then(function (j) {
      S.st[id] = j.current;
      if (msg) msg.textContent = "";
      render(id);
      summary();
      if (S.onChange) S.onChange(id);
      return j;
    }).catch(function (e) {
      if (msg) msg.textContent = why(e);
      throw e;
    });
  }
  function buttons(id, msg, always) {
    var box = el("span", "tri-btns" + (always ? " tri-always" : ""));
    if (!S.writes) return box;
    var cur = S.st[id] ? S.st[id].state : "untriaged";
    function b(label, state, cls, title) {
      var x = el("button", "tri-b" + (cls ? " " + cls : ""), label);
      x.type = "button";
      if (title) x.title = title;
      x.disabled = state === cur;
      x.addEventListener("click", function (e) {
        e.stopPropagation();
        e.preventDefault();
        var note = always && $("frrs-note") ? $("frrs-note").value.trim() : "";
        act(id, state, note, msg).then(function () {
          if (always && $("frrs-note")) $("frrs-note").value = "";
        }, function () {});
      });
      x.addEventListener("keydown", function (e) { e.stopPropagation(); });
      box.appendChild(x);
    }
    b("false", "false", "sev1");
    b("noise", "noise", "sev0");
    b("incident", "incident", "sev2");
    b("known", "known", "tri-known", KNOWN_TITLE);
    var t = S.types[id], r = t ? S.rec[t] : null;
    if (t && !r) rec(t);
    var rs = r && typeof r.state === "string" ? r.state : null;
    // No state: either no assessment ("no recommendation yet") or one
    // that does not meet the bar (noise only for false_positive_risk
    // high and noise_verdict noisy): its risk word said, nothing done.
    var fpr = r && r.front_matter && typeof r.front_matter.false_positive_risk === "string"
      ? r.front_matter.false_positive_risk.split(" - ")[0] : null;
    var lbl = rs ? "follow recommended: " + rs
      : r && r.why_none === "no_automatic_triage" ? "no automatic triage: " + (fpr || "-")
      : "no recommendation yet";
    var sbl = rs ? "rec.: " + rs : r && r.why_none === "no_automatic_triage" ? "no auto: " + (fpr || "-") : "no rec. yet";
    var rb = el("button", "tri-b tri-rec", "");
    rb.appendChild(el("span", "tri-long", lbl));
    rb.appendChild(el("span", "tri-short", sbl));
    rb.title = lbl;
    rb.type = "button";
    rb.disabled = !rs || rs === cur;
    rb.addEventListener("click", function (e) {
      e.stopPropagation();
      e.preventDefault();
      act(id, "recommended", always && $("frrs-note") ? $("frrs-note").value.trim() : "", msg)
        .then(function () { if (always && $("frrs-note")) $("frrs-note").value = ""; }, function () {});
    });
    rb.addEventListener("keydown", function (e) { e.stopPropagation(); });
    box.appendChild(rb);
    if (cur !== "untriaged") b("clear", "untriaged", "");
    return box;
  }

  function reg(id, place) {
    if (!S.reg[id]) S.reg[id] = [];
    S.reg[id].push(place);
  }
  // Every place an alert is drawn, again: a row gone from the page is
  // dropped from the list, so a list drawn every few seconds does not
  // grow it without end.
  function render(id) {
    var places = S.reg[id];
    if (!places) return;
    var st = S.st[id] || { state: "untriaged" };
    S.reg[id] = places.filter(function (p) { return p.row && p.row.isConnected; });
    if (!S.reg[id].length) { delete S.reg[id]; return; }
    S.reg[id].forEach(function (p) {
      if (p.a) p.a.triage = { state: st.state, via: st.via || null, ts: st.ts || null };
      if (p.cell) { clear(p.cell); p.cell.appendChild(chip(st)); }
      if (p.line) {
        clear(p.line);
        if (!p.cell && st.state !== "untriaged") p.line.appendChild(chip(st));
        // The Alerts page's column scrolls off at phone width: the line
        // says the state too, shown only there (frrs.css).
        if (p.cell) { var dup = chip(st); dup.classList.add("tri-dup"); p.line.appendChild(dup); }
        var msg = el("span", "sub tri-msg", "");
        p.line.appendChild(buttons(id, msg, false));
        p.line.appendChild(msg);
      }
      p.row.classList.toggle("tri-out", out(st.state));
    });
  }

  // A linked alert row: a line for its chip and buttons, filled once
  // its state is known. The states are asked in batches of sixteen, the
  // route's bound, and again only after ten seconds.
  function link(li, id) {
    if (!H || typeof id !== "string" || !ID_RE.test(id) || !li) return;
    var line = el("span", "tri tri-line");
    li.appendChild(line);
    // The row holds buttons now, which a link may not: a group, still
    // opened by Enter or a click as app.js made it, the buttons its own
    // tab stops.
    li.role = "group";
    li.ariaRoleDescription = "alert, Enter opens it";
    reg(id, { row: li, line: line });
    var t = Date.now();
    if (S.seen[id] && t - S.seen[id] < 10000) { setTimeout(function () { render(id); }, 0); return; }
    if (S.queue.indexOf(id) < 0) S.queue.push(id);
    if (!S.qt) S.qt = setTimeout(flush, 30);
  }
  function flush() {
    S.qt = 0;
    var ids = S.queue.splice(0, S.queue.length);
    for (var i = 0; i < ids.length; i += 16) (function (part) {
      H.getJSON("/api/frrs/states?ids=" + part.join(",")).then(function (j) {
        S.writes = !!j.writes;
        var tri = j.triage || {}, ty = j.types || {}, t = Date.now();
        part.forEach(function (id) {
          S.st[id] = tri[id] || { state: "untriaged" };
          if (typeof ty[id] === "string") S.types[id] = ty[id];
          S.seen[id] = t;
          render(id);
        });
      }).catch(function () { part.forEach(function (id) { render(id); }); });
    })(ids.slice(i, i + 16));
  }

  // The Alerts page's triage column, from the answer's own triage
  // (/api/alerts?triage=): the cell for the column and the line for the
  // buttons, as one fragment.
  function cell(a, row) {
    var f = document.createDocumentFragment();
    var c = el("span", "tri tri-cell");
    var line = el("span", "tri tri-line");
    f.appendChild(c);
    f.appendChild(line);
    if (!H || !a || typeof a.id !== "string" || !ID_RE.test(a.id)) return f;
    if (a.triage && typeof a.triage.state === "string")
      S.st[a.id] = { state: a.triage.state, via: a.triage.via, ts: a.triage.ts };
    if (typeof a.type_name === "string") S.types[a.id] = a.type_name;
    S.seen[a.id] = Date.now();
    reg(a.id, { row: row, cell: c, line: line, a: a });
    // The row is not on the page yet: drawn once it is.
    setTimeout(function () { render(a.id); }, 0);
    return f;
  }

  // triage= on the Alerts page's path (as scoped() adds scope=), and a
  // triage:<state> term typed anywhere in the search box, among other
  // words or alone, moved into the select; the words left stay in the
  // box and the first of them is the server's q, as alertsQuery() takes.
  function q(p) {
    var sel = $("al-triage"), box = $("al-q");
    if (!sel) return;
    if (box) {
      var hit = null, kept = [];
      box.value.trim().split(/\s+/).forEach(function (w) {
        var m = /^triage:([a-z]+)$/.exec(w);
        if (m && FILTERS[m[1]]) hit = m[1]; else if (w) kept.push(w);
      });
      if (hit) {
        sel.value = hit;
        H.prefSet("ctl.al-triage", hit);
        box.value = kept.join(" ");
        for (var i = p.length - 1; i >= 0; i--) if (p[i].indexOf("q=") === 0) p.splice(i, 1);
        if (kept.length) p.push("q=" + encodeURIComponent(kept[0]));
      }
    }
    p.push("triage=" + encodeURIComponent(FILTERS[sel.value] ? sel.value : "any"));
  }

  function show(v, vp) {
    if (!H) return;
    if (v === "alerts" && $("al-triage")) {
      // The address wins (#alerts?triage=out), a link naming any other
      // filter opens on "any", and a bare address on the kept one.
      var named = ["state", "sev", "type", "q", "triage"].some(function (k) { return vp && typeof vp[k] === "string"; });
      var kept = H.prefGet("ctl.al-triage");
      $("al-triage").value = vp && FILTERS[vp.triage] ? vp.triage
        : named ? "any" : typeof kept === "string" && FILTERS[kept] ? kept : "any";
    }
    if (v === "overview") summary();
    if (v === "tacdb") tacdb(vp || {});
  }

  // ── the alert page: the triage panel and the record ──────────────
  var DTH = null;
  function histRows(rows) {
    var ol = $("frrs-hist");
    clear(ol);
    var list = DTH ? DTH.sort(rows || []) : rows || [];
    if (!list.length) { ol.appendChild(el("li", "sub", "no change yet: untriaged")); return; }
    list.forEach(function (r) {
      var li = el("li", "frhrow dt-row");
      li.appendChild(el("span", "ts", H.shortStamp(r.ts)));
      li.appendChild(chip(r));
      li.appendChild(el("span", "d-dim", "was " + r.prev_state));
      li.appendChild(el("span", "d-normal", r.via + (r.basis ? ": " + r.basis : "")));
      li.appendChild(el("span", "d-bright", r.note || "-"));
      // An imported row: who and where are what its file claimed; the
      // peer is the importer.
      li.appendChild(el("span", "d-normal", r.via === "import"
        ? "imported, claimed " + (r.claimed_by || "-") + " from " + (r.claimed_peer || "?") + " · by import from " + (r.peer || "?")
        : (r.by || "-") + " · from " + (r.peer || "?")));
      ol.appendChild(li);
    });
  }
  function hk(k) { return function (r) { return r[k]; }; }
  function mountAlert(j) {
    if (!H || !j || typeof j.id !== "string" || !ID_RE.test(j.id)) return;
    var id = j.id, gen = ++S.gen;
    if (typeof j.type_name === "string") S.types[id] = j.type_name;
    var panel = $("frrs-alert-triage");
    if (panel) {
      panel.hidden = false;
      if (!DTH) DTH = H.DataTable({ id: "frrs.triage", label: "triage history", box: $("frrs-hist-box"),
        head: $("frrs-hist-head"), reset: $("frrs-hist-tools"), redraw: function () { histRows(S.hist); }, cols: [
          { k: "ts", label: "when", w: 11, type: "time", val: hk("ts") },
          { k: "st", label: "state", w: 10, type: "text", val: hk("state") },
          { k: "pr", label: "was", w: 12, type: "text", val: hk("prev_state") },
          { k: "via", label: "how", w: 16, type: "text", val: hk("via") },
          { k: "nt", label: "note", w: 24, flex: true, type: "text", val: hk("note") },
          { k: "by", label: "by, from", w: 22, type: "text", val: hk("by") }
        ] });
      var load = function () {
        H.getJSON("/api/frrs/history?id=" + encodeURIComponent(id)).then(function (h) {
          if (gen !== S.gen) return;
          S.writes = !!h.writes;
          S.st[id] = h.current;
          S.hist = h.rows || [];
          // The answer carries the type's recommendation: the panel's
          // button is drawn from it, not from a second ask that would
          // redraw only the rows registered with reg().
          if (S.types[id] && h.recommend && typeof h.recommend === "object") S.rec[S.types[id]] = h.recommend;
          var cur = $("frrs-tri-cur"), msg = el("span", "sub tri-msg", "");
          clear(cur);
          cur.appendChild(chip(h.current));
          if (h.current && h.current.state !== "untriaged") {
            cur.appendChild(el("span", "d-normal", "  by " + (h.current.by || "-") + " · from " +
                               (h.current.peer || "?") + " · " + stamp(h.current.ts)));
            if (h.current.note) cur.appendChild(el("div", "prose", h.current.note));
          }
          var bb = $("frrs-tri-btns");
          clear(bb);
          bb.appendChild(buttons(id, msg, true));
          bb.appendChild(msg);
          set("frrs-tri-note", h.store !== "open" ? "no store: triage is off (WITH_SQLITE=0 or no --store)"
            : !h.writes ? "read-only (--web-read-only): the state is shown, not changed"
            : "kept in slothweb's store, never sent to sloth; every change is a new row, reversible by another");
          var r = h.recommend || {};
          set("frrs-tri-rec", r.state ? "the assessment recommends " + r.state + " (" + r.basis + ", " + r.file + ")"
            : r.front_matter ? "no automatic triage: the assessment (" + r.file + ") recommends noise only when " +
              "false_positive_risk is high and noise_verdict noisy; it says " +
              ["false_positive_risk", "noise_verdict", "severity_assessment"].map(function (k) {
                return k + " " + (r.front_matter[k] === null ? "-" : r.front_matter[k]);
              }).join(", ")
            : "no recommendation yet: " + (r.source === "none" ? "no assessments directory (--web-assessments unset, or not installed)" : "no " + r.file));
          set("frrs-hist-note", (h.rows || []).length + " of at most " + h.history_cap +
              (h.folded ? " (" + h.folded + " older folded: the first and the newest kept)" : "") +
              "; filed as " + h.subject + (h.finding ? " (sloth.db finding " + h.finding + ")" : " (not in sloth.db yet)"));
          histRows(S.hist);
          render(id);
        }).catch(function (e) {
          if (gen === S.gen) set("frrs-tri-note", why(e));
        });
      };
      S.onChange = function (cid) { if (cid === id && !$("v-alert").hidden) load(); };
      load();
    }
    var box = $("frrs-alert");
    if (!box) return;
    clear(box);
    var sec = el("section", "panel frrs");
    sec.appendChild(el("div", "label", "the FRRS record of the emitter it names"));
    var body = el("div", "");
    body.appendChild(el("div", "sub", "loading"));
    sec.appendChild(body);
    box.appendChild(sec);
    H.getJSON("/api/frrs/report/alert?id=" + encodeURIComponent(id)).then(function (r) {
      if (gen !== S.gen) return;
      clear(body);
      if (!r.record) { body.appendChild(el("div", "sub", r.reason || "no emitter")); return; }
      body.appendChild(el("div", "sub", "the emitter: " + r.alert.emitter_from));
      record(body, r.record);
    }).catch(function (e) { if (gen === S.gen) { clear(body); body.appendChild(el("div", "sub", why(e))); } });
  }
  function set(id, t) { var n = $(id); if (n) n.textContent = String(t); }

  // ── the record (docs/web-frrs-spec.md §4) ─────────────────────────
  var GROUPS = [
    ["report", "Report: what a passive sensor can say (COMINT's seven)", 1],
    ["bei", "BEI: background environment", 2],
    ["scs", "SCS: certification and compliance", 4],
    ["ecs", "EC/S: equipment characteristics", 8],
    ["tacdb", "TACDB: the operator's filing", 16]
  ];
  var REPORT = [
    ["identity", "1 who is transmitting"], ["signal", "2 signal and radio (no location axis)"],
    ["function", "3 function"], ["timing", "4 time, duration and schedule"],
    ["technical", "5 technical characteristics"], ["protection", "6 protection posture"],
    ["peers", "7 addresses and peers"]
  ];
  function isTime(k) { return /(_seen|^since|_ts|^ts|_start|_end|exported)$/.test(k); }
  function vtext(k, v) {
    if (v === null || v === undefined) return null;
    if (typeof v === "boolean") return v ? "yes" : "no";
    if (typeof v === "number") return isTime(k) && v > 1000000000 ? H.stamp(v) : String(v);
    if (typeof v === "string") return v;
    if (Array.isArray(v)) {
      if (!v.length) return "none";
      return v.map(function (x) { return vtext("", x); }).join("; ");
    }
    if (typeof v === "object") {
      return Object.keys(v).filter(function (q) { return v[q] !== null && v[q] !== "" && q !== "src"; })
        .map(function (q) { return q + " " + vtext(q, v[q]); }).join(" · ");
    }
    return String(v);
  }
  // The Report's RSSI against time (rf.rssi.*, docs/web-frrs-spec.md
  // §4.5 item 2) as text: draw_sparkline_at()'s glyphs, one per cell,
  // `_` where a cell has no sample, each graded by glyph.js's port of
  // the TUI's level (glyph.level, glyph.lineToken) on the cell's
  // strength above -100 dBm against the window's strongest, in the heat
  // ramp's classes. Every glyph is a character of SPARK and every class
  // a word of SPARK_CLS: no value from the answer reaches either.
  var SPARK = ["_", "\u2581", "\u2582", "\u2583", "\u2584", "\u2585", "\u2586", "\u2587", "\u2588"];
  var SPARK_CLS = { "--tui-dim": "d-dim", "--tui-normal": "d-normal", "--heat-1": "h1",
                    "--heat-2": "h2", "--heat-3": "h3" };
  var RSSI_FLOOR = -100;
  function rssiSpark(s) {
    var v = el("span", "v fr-spark", "");
    var cells = Array.isArray(s.cells) ? s.cells : [], max = 0, i;
    var lift = function (x) { return num(x) ? Math.max(1, x - RSSI_FLOOR) : 0; };
    for (i = 0; i < cells.length; i++) if (lift(cells[i]) > max) max = lift(cells[i]);
    var line = el("span", "fr-spark-g", "");
    for (i = 0; i < cells.length; i++) {
      var l = typeof glyph !== "undefined" ? glyph.level(lift(cells[i]), max) : (num(cells[i]) ? 8 : 0);
      var tk = typeof glyph !== "undefined" ? glyph.lineToken(l) : (l ? "--tui-normal" : "--tui-dim");
      line.appendChild(el("span", SPARK_CLS[tk] || "d-normal", SPARK[l] || "_"));
    }
    v.appendChild(line);
    var span = num(s.from) && num(s.to) && s.to > s.from ? Math.round((s.to - s.from) / 3600) + " h" : "24 h";
    v.appendChild(el("span", "d-bright", "  min " + (num(s.min_dbm) ? s.min_dbm : "-") + " · max " +
                     (num(s.max_dbm) ? s.max_dbm : "-") + " dBm"));
    v.appendChild(el("span", "d-dim", " · last " + (num(s.last_dbm) ? s.last_dbm : "-") + " dBm" +
                     (num(s.last_t) && s.last_t > 0 ? " at " + H.shortStamp(s.last_t) : "") +
                     " · n=" + (num(s.samples) ? s.samples : 0) + " · " + span + " in " + cells.length +
                     " cells · a sloth gauge, not a calibrated measurement" +
                     (typeof s.history === "string" ? " · the minute tier: " + s.history : "")));
    return v;
  }
  function fields(box, g) {
    var kv = el("div", "frkv");
    Object.keys(g || {}).forEach(function (k) {
      var f = g[k];
      if (!f || typeof f !== "object" || !Object.prototype.hasOwnProperty.call(f, "v")) return;
      kv.appendChild(el("span", "k", k.replace(/_/g, " ")));
      if (k === "series_rssi" && f.v && typeof f.v === "object" && Array.isArray(f.v.cells)) {
        kv.appendChild(rssiSpark(f.v));
        kv.appendChild(el("span", "s d-dim", typeof f["src"] === "string" ? f["src"] : ""));
        return;
      }
      var t = vtext(k, f.v);
      var v = el("span", t === null ? "v d-dim" : "v d-bright", t === null ? (f.why || "not observed") : t);
      if (num(f.since) && f.since > 0) v.appendChild(el("span", "d-dim", "  (as of " + H.shortStamp(f.since) + ")"));
      kv.appendChild(v);
      var from = f["src"];
      kv.appendChild(el("span", "s d-dim", typeof from === "string" ? from : ""));
    });
    box.appendChild(kv);
  }
  function record(box, r) {
    var e = r.emitter || {};
    var head = el("div", "kv");
    [["emitter", (e.kind || "?") + " " + (e.addr || "?")], ["station class", e.station_class],
     ["scope", e.scope], ["sloth.db", r.sources ? r.sources.sloth_db : null],
     ["stream facts", r.sources ? r.sources.ledger : null]].forEach(function (p) {
      if (p[1] === null || p[1] === undefined) return;
      head.appendChild(el("span", "k", p[0]));
      head.appendChild(el("span", "v", String(p[1])));
    });
    box.appendChild(head);
    box.appendChild(el("div", "sub fr-limit", r.position_limit || "no location axis"));
    box.appendChild(el("div", "sub fr-limit", r.content_limit || "sloth decrypts nothing"));
    var open = H.prefGet("frrs.open");
    if (!num(open)) open = 3;
    GROUPS.forEach(function (gd) {
      var g = r[gd[0]];
      var d = el("details", "frgrp");
      d.open = !!(open & gd[2]);
      d.appendChild(el("summary", "", gd[1]));
      d.addEventListener("toggle", function () {
        var o = H.prefGet("frrs.open");
        if (!num(o)) o = 3;
        H.prefSet("frrs.open", d.open ? (o | gd[2]) : (o & ~gd[2]));
      });
      if (gd[0] === "report") {
        REPORT.forEach(function (rd) {
          if (!g || !g[rd[0]]) return;
          d.appendChild(el("div", "label fr-sub", rd[1]));
          fields(d, g[rd[0]]);
        });
      } else if (gd[0] === "tacdb") {
        if (!g) d.appendChild(el("div", "sub", "not filed: no platform in the TACDB holds this emitter (the TACDB tab files it)"));
        else {
          var kv = el("div", "kv");
          [["platform", g.nomenclature], ["class", g["class"]], ["role", g.role], ["label", g.label || null],
           ["unit", g.unit_path], ["emitters on it", g.emitters_on_platform], ["source", g.src]].forEach(function (p) {
            if (p[1] === null || p[1] === undefined) return;
            kv.appendChild(el("span", "k", p[0]));
            kv.appendChild(el("span", "v", String(p[1])));
          });
          d.appendChild(kv);
          if (num(g.platform)) {
            var a = el("button", "tri-b", "open the platform");
            a.type = "button";
            a.addEventListener("click", function () { H.go("tacdb", { id: String(g.platform) }); });
            d.appendChild(a);
          }
        }
      } else {
        fields(d, g);
      }
      box.appendChild(d);
    });
  }

  // The drawer's record: a station's, or a BSSID's when sloth heard it
  // beacon.
  function mountDrawer(mac, j) {
    if (!H || typeof mac !== "string" || !MAC_RE.test(mac)) return;
    var box = $("frrs-drawer");
    if (!box) return;
    var gen = ++S.dgen;
    clear(box);
    var rc = j && j.record ? j.record : null;
    var kind = rc && ((num(rc.sources) && (rc.sources & 8)) || rc.is_ap) ? "bssid" : "sta";
    box.appendChild(el("div", "label", "FRRS record (" + kind + ")"));
    var body = el("div", "");
    body.appendChild(el("div", "sub", "loading"));
    box.appendChild(body);
    H.getJSON("/api/frrs/report?kind=" + kind + "&addr=" + encodeURIComponent(mac)).then(function (r) {
      if (gen !== S.dgen) return;
      clear(body);
      record(body, r);
    }).catch(function (e) { if (gen === S.dgen) { clear(body); body.appendChild(el("div", "sub", why(e))); } });
  }

  // ── the TACDB tab (docs/web-frrs-spec.md §6.3) ────────────────────
  var T = { units: [], plats: [], sugg: [], sel: 0, pid: 0, pv: null, emSel: "" };
  var DTU = null, DTP = null, DTS = null, DTE = null;
  function tk(k) { return function (x) { return x[k]; }; }
  function tables() {
    if (DTU) return;
    DTU = H.DataTable({ id: "tacdb-units", label: "units", box: $("tc-units-box"), head: $("tc-units-head"),
      reset: $("tc-units-tools"), redraw: unitsDraw, cols: [
        { k: "nm", label: "unit", w: 22, flex: true, type: "text", val: tk("name") },
        { k: "kd", label: "kind", w: 8, type: "text", val: tk("kind") },
        { k: "pl", label: "platforms", w: 9, num: true, type: "num", val: tk("platforms") }
      ] });
    DTP = H.DataTable({ id: "tacdb-platforms", label: "platforms", box: $("tc-plat-box"), head: $("tc-plat-head"),
      reset: $("tc-plat-tools"), redraw: platsDraw, cols: [
        { k: "nm", label: "nomenclature", w: 24, flex: true, type: "text", val: tk("nomenclature") },
        { k: "cl", label: "class", w: 10, type: "text", val: tk("class") },
        { k: "un", label: "unit", w: 18, type: "text", val: tk("unit_path") },
        { k: "eq", label: "equipment", w: 14, type: "num", val: function (p) { return (p.emitters || []).length; } },
        { k: "ls", label: "last seen", w: 11, type: "time", val: lastOf },
        { k: "or", label: "origin", w: 10, type: "text", val: tk("origin") }
      ] });
    DTS = H.DataTable({ id: "tacdb-suggest", label: "suggestions", box: $("tc-sug-box"), head: $("tc-sug-head"),
      reset: $("tc-sug-tools"), redraw: suggDraw, cols: [
        { k: "ru", label: "rule", w: 6, type: "text", val: tk("rule") },
        { k: "ab", label: "emitters", w: 20, type: "mac", val: tk("a") },
        { k: "cf", label: "conf.", w: 6, num: true, type: "num", val: tk("confidence") },
        { k: "ev", label: "evidence", w: 26, flex: true, type: "text", val: tk("evidence") },
        { k: "do", label: "", w: 16, type: "none" }
      ] });
    DTE = H.DataTable({ id: "tacdb-emitters", label: "equipment complement", box: $("tc-em-box"), head: $("tc-em-head"),
      reset: $("tc-em-tools"), redraw: emDraw, cols: [
        { k: "kd", label: "kind", w: 6, type: "text", val: tk("kind") },
        { k: "ad", label: "address", w: 20, type: "mac", val: tk("addr") },
        { k: "ro", label: "role", w: 9, type: "text", val: tk("role") },
        { k: "lb", label: "label", w: 14, flex: true, type: "text", val: tk("label") },
        { k: "ls", label: "last seen", w: 11, type: "time", val: tk("last_seen") },
        { k: "sc", label: "scopes", w: 14, type: "text", val: function (x) { return (x.scopes || []).join(" "); } },
        { k: "do", label: "", w: 16, type: "none" }
      ] });
  }
  function lastOf(p) {
    var best = null;
    (p.emitters || []).forEach(function (e) { if (num(e.last_seen) && (best === null || e.last_seen > best)) best = e.last_seen; });
    return best;
  }
  function btn(label, fn, cls) {
    var b = el("button", "tri-b" + (cls ? " " + cls : ""), label);
    b.type = "button";
    b.addEventListener("click", function (e) { e.stopPropagation(); fn(); });
    return b;
  }
  function writesUI() {
    ["tc-u-form", "tc-p-form", "tc-pv-form", "tc-e-form"].forEach(function (f) { if ($(f)) $(f).hidden = !S.writes; });
    ["tc-imp-check", "tc-imp-merge", "tc-imp-file"].forEach(function (f) { if ($(f)) $(f).disabled = !S.writes; });
  }
  function unitOptions(sel, none) {
    if (!sel) return;
    var keep = sel.value;
    clear(sel);
    var o0 = el("option", "", none);
    o0.value = "";
    sel.appendChild(o0);
    T.units.forEach(function (u) {
      if (u.deleted) return;
      var o = el("option", "", new Array(u.depth).join("· ") + u.name + " (" + u.kind + ")");
      o.value = String(u.id);
      sel.appendChild(o);
    });
    sel.value = keep;
    if (sel.value !== keep) sel.value = "";
  }
  function unitsDraw() {
    var box = $("tc-units");
    clear(box);
    // The tree's own order unless a header sorts it.
    var rows = DTU.sort(T.units);
    if (!rows.length) box.appendChild(el("div", "sub", "no unit yet: a site, then its rooms, vehicles and people"));
    rows.forEach(function (u) {
      var r = el("div", "tcurow dt-row" + (u.id === T.sel ? " sel" : "") + (u.deleted ? " tri-out" : ""));
      var nm = el("span", "d-bright", new Array(u.depth).join("    ") + u.name + (u.deleted ? " (deleted)" : ""));
      r.appendChild(nm);
      r.appendChild(el("span", "d-normal", u.kind));
      r.appendChild(el("span", "n d-normal", String(u.platforms)));
      r.tabIndex = 0;
      r.addEventListener("click", function () {
        T.sel = T.sel === u.id ? 0 : u.id;
        if ($("tc-u-name")) $("tc-u-name").value = T.sel ? u.name : "";
        H.prefSet("frrs.tacdb.unit", T.sel || null);
        tacdbLoad();
      });
      box.appendChild(r);
    });
    set("tc-unit-sel", T.sel ? "filtered to the selected unit and its subordinate units; click it again for all" : "every unit");
  }
  function kinds(p) {
    var n = { sta: 0, bssid: 0, ble: 0 };
    (p.emitters || []).forEach(function (e) { if (n[e.kind] !== undefined) n[e.kind]++; });
    var out = [];
    if (n.sta) out.push(n.sta + " sta");
    if (n.bssid) out.push(n.bssid + " bssid");
    if (n.ble) out.push(n.ble + " ble");
    return out.length ? out.join(", ") : "none";
  }
  function platsDraw() {
    var box = $("tc-plat");
    clear(box);
    var rows = DTP.sort(T.plats);
    if (!rows.length) box.appendChild(el("div", "sub", "no platform yet: confirm a suggestion, or name one below"));
    rows.forEach(function (p) {
      var r = el("div", "tcprow dt-row" + (p.id === T.pid ? " sel" : "") + (p.deleted ? " tri-out" : ""));
      r.appendChild(el("span", "d-bright", p.nomenclature));
      r.appendChild(el("span", "d-normal", p["class"]));
      r.appendChild(el("span", "d-normal", p.unit_path || "(unfiled)"));
      r.appendChild(el("span", "d-normal", kinds(p)));
      r.appendChild(el("span", "d-dim", H.shortStamp(lastOf(p))));
      r.appendChild(el("span", "d-dim", p.origin + (p.confirmed ? "" : ", suggested")));
      r.tabIndex = 0;
      r.addEventListener("click", function () { H.go("tacdb", { id: String(p.id) }); });
      box.appendChild(r);
    });
  }
  function suggDraw() {
    var box = $("tc-sug");
    clear(box);
    var rows = DTS.sort(T.sugg);
    if (!rows.length) box.appendChild(el("div", "sub", "none: no correlation sloth recorded is unfiled or undismissed"));
    rows.forEach(function (g) {
      var r = el("div", "tcsrow dt-row");
      r.appendChild(el("span", "d-bright", g.rule));
      r.appendChild(el("span", "d-normal", g.a + (g.b ? " + " + g.b : "")));
      r.appendChild(el("span", "n d-normal", String(g.confidence)));
      r.appendChild(el("span", "d-normal", g.rule_name + ": " + g.evidence));
      var d = el("span", "");
      if (S.writes) {
        d.appendChild(btn("confirm", function () {
          var b = { op: "confirm", suggest: g.token };
          if (T.sel) b.unit = T.sel;
          post("/api/frrs/tacdb/platform", b).then(function (j) {
            set("tc-s-msg", "filed as " + j.platform.nomenclature);
            tacdbLoad();
          }).catch(function (e) { set("tc-s-msg", why(e)); });
        }));
        d.appendChild(btn("dismiss", function () {
          post("/api/frrs/tacdb/dismiss", { suggest: g.token }).then(function () {
            set("tc-s-msg", "dismissed until either address shows new evidence");
            tacdbLoad();
          }).catch(function (e) { set("tc-s-msg", why(e)); });
        }));
      }
      r.appendChild(d);
      box.appendChild(r);
    });
  }
  function emDraw() {
    var box = $("tc-em");
    clear(box);
    var p = T.pv;
    if (!p) return;
    var rows = DTE.sort(p.emitters || []);
    if (!rows.length) box.appendChild(el("div", "sub", "no emitter yet: add one below"));
    rows.forEach(function (e) {
      var r = el("div", "tcerow dt-row" + (e.deleted ? " tri-out" : "") + (T.emSel === e.kind + e.addr ? " sel" : ""));
      r.appendChild(el("span", "d-normal", e.kind));
      r.appendChild(el("span", "d-bright", e.addr));
      r.appendChild(el("span", "d-normal", e.role));
      r.appendChild(el("span", "d-normal", e.label || "-"));
      r.appendChild(el("span", "d-dim", H.shortStamp(e.last_seen)));
      r.appendChild(el("span", "d-dim", (e.scopes || []).join(" + ")));
      var d = el("span", "");
      d.appendChild(btn("EC/S and report", function () { emitterDetail(e); }));
      if (e.kind !== "ble" && MAC_RE.test(e.addr)) d.appendChild(btn("drawer", function () { H.openDrawer(e.addr); }));
      if (S.writes && !e.deleted)
        d.appendChild(btn("remove", function () {
          post("/api/frrs/tacdb/emitter", { op: "remove", platform: p.id, kind: e.kind, addr: e.addr }).then(function () {
            platformLoad(p.id);
          }).catch(function (x) { set("tc-pv-msg", why(x)); });
        }));
      if (S.writes && e.deleted)
        d.appendChild(btn("restore", function () {
          post("/api/frrs/tacdb/emitter", { op: "restore", platform: p.id, kind: e.kind, addr: e.addr }).then(function () {
            platformLoad(p.id);
          }).catch(function (x) { set("tc-pv-msg", why(x)); });
        }));
      r.appendChild(d);
      box.appendChild(r);
    });
  }
  function emitterDetail(e) {
    T.emSel = e.kind + e.addr;
    emDraw();
    var box = $("tc-pv-detail"), gen = ++S.tgen;
    clear(box);
    box.appendChild(el("div", "label", "the record of " + e.kind + " " + e.addr));
    var body = el("div", "");
    body.appendChild(el("div", "sub", "loading"));
    box.appendChild(body);
    H.getJSON("/api/frrs/report?kind=" + e.kind + "&addr=" + encodeURIComponent(e.addr)).then(function (r) {
      if (gen !== S.tgen) return;
      clear(body);
      record(body, r);
    }).catch(function (x) { if (gen === S.tgen) { clear(body); body.appendChild(el("div", "sub", why(x))); } });
  }
  function platformLoad(id) {
    var gen = ++S.tgen;
    H.getJSON("/api/frrs/tacdb/view?id=" + encodeURIComponent(String(id))).then(function (j) {
      if (gen !== S.tgen) return;
      var p = j.platform;
      T.pv = p;
      T.pid = p.id;
      S.writes = !!j.writes;
      writesUI();
      $("tc-platform").hidden = false;
      set("tc-pv-title", p.nomenclature + (p.deleted ? " (deleted)" : ""));
      set("tc-pv-note", p["class"] + ", " + (p.unit_path || "unfiled") + ", " + p.origin +
          "; updated " + stamp(p.updated));
      var kv = $("tc-pv-kv");
      clear(kv);
      var k = el("div", "kv");
      [["vendor", p.vendor || null], ["note", p.note || null], ["equipment", kinds(p)]].forEach(function (x) {
        if (x[1] === null) return;
        k.appendChild(el("span", "k", x[0]));
        k.appendChild(el("span", "v", String(x[1])));
      });
      kv.appendChild(k);
      if ($("tc-pv-nom")) $("tc-pv-nom").value = p.nomenclature;
      unitOptions($("tc-pv-unit"), "(unfiled)");
      if ($("tc-pv-unit")) $("tc-pv-unit").value = p.unit ? String(p.unit) : "";
      mountBundle($("bundle-btn-tacdb"), "platform", String(p.id));
      clear($("tc-pv-detail"));
      emDraw();
      platsDraw();
    }).catch(function (e) {
      if (gen !== S.tgen) return;
      $("tc-platform").hidden = false;
      set("tc-pv-title", "-");
      set("tc-pv-note", why(e));
      T.pv = null;
      emDraw();
    });
  }
  function tacdbLoad() {
    var path = "/api/frrs/tacdb?limit=200" + (T.sel ? "&unit=" + T.sel : "");
    var qv = $("tc-q") ? $("tc-q").value.trim() : "";
    if (qv) path += "&q=" + encodeURIComponent(qv);
    H.getJSON(path).then(function (j) {
      S.writes = !!j.writes;
      writesUI();
      T.units = j.units || [];
      T.plats = j.platforms || [];
      if (T.sel && !T.units.some(function (u) { return u.id === T.sel; })) T.sel = 0;
      unitOptions($("tc-u-parent"), "(top level)");
      unitOptions($("tc-p-unit"), "(unfiled)");
      if (T.sel) { $("tc-u-parent").value = String(T.sel); $("tc-p-unit").value = String(T.sel); }
      var c = j.counts || {};
      set("tc-counts", c.units + " units, " + c.platforms + " platforms, " + c.emitters + " emitters" +
          (S.writes ? "" : "; read-only"));
      set("tc-p-note", j.matched + " matched" + (j.more ? ", more than shown" : ""));
      set("tc-note", j.note + "; platforms span every capture scope: each emitter says which scope heard it");
      unitsDraw();
      platsDraw();
    }).catch(function (e) { set("tc-p-note", why(e)); });
    H.getJSON("/api/frrs/suggest").then(function (j) {
      T.sugg = j.suggestions || [];
      set("tc-s-note", T.sugg.length + " open");
      suggDraw();
    }).catch(function (e) { set("tc-s-note", why(e)); });
  }
  function tacdb(vp) {
    tables();
    if (!T.wired) wire();
    var kept = H.prefGet("frrs.tacdb.unit");
    if (!T.selRead) { T.selRead = true; if (num(kept)) T.sel = kept; }
    var id = vp && typeof vp.id === "string" && /^[0-9]{1,12}$/.test(vp.id) ? parseInt(vp.id, 10) : 0;
    tacdbLoad();
    if (id) platformLoad(id);
    else { T.pid = 0; T.pv = null; $("tc-platform").hidden = true; }
  }
  function wire() {
    T.wired = true;
    var kq = H.prefGet("frrs.tacdb.q");
    if ($("tc-q") && typeof kq === "string" && kq.length <= 63) $("tc-q").value = kq;
    $("tc-q").addEventListener("input", function () {
      H.prefSet("frrs.tacdb.q", $("tc-q").value || null);
      if (T.qt) clearTimeout(T.qt);
      T.qt = setTimeout(function () { T.qt = 0; tacdbLoad(); }, 300);
    });
    $("tc-u-add").addEventListener("click", function () {
      var b = { op: "create", name: $("tc-u-name").value.trim(), kind: $("tc-u-kind").value };
      if ($("tc-u-parent").value) b.parent = parseInt($("tc-u-parent").value, 10);
      post("/api/frrs/tacdb/unit", b).then(function (j) {
        set("tc-u-msg", "unit " + j.unit.name + " made");
        $("tc-u-name").value = "";
        tacdbLoad();
      }).catch(function (e) { set("tc-u-msg", why(e)); });
    });
    $("tc-u-edit").addEventListener("click", function () {
      if (!T.sel) { set("tc-u-msg", "select a unit first"); return; }
      var b = { op: "update", id: T.sel, kind: $("tc-u-kind").value };
      if ($("tc-u-name").value.trim()) b.name = $("tc-u-name").value.trim();
      var pv = $("tc-u-parent").value;
      if (pv !== String(T.sel)) b.parent = pv ? parseInt(pv, 10) : null;
      post("/api/frrs/tacdb/unit", b).then(function (j) {
        set("tc-u-msg", "unit " + j.unit.name + " saved");
        tacdbLoad();
      }).catch(function (e) { set("tc-u-msg", why(e)); });
    });
    $("tc-u-del").addEventListener("click", function () {
      if (!T.sel) { set("tc-u-msg", "select a unit first"); return; }
      var u = T.units.filter(function (x) { return x.id === T.sel; })[0];
      post("/api/frrs/tacdb/unit", { op: u && u.deleted ? "restore" : "delete", id: T.sel }).then(function (j) {
        set("tc-u-msg", "unit " + j.unit.name + (j.unit.deleted ? " deleted (restorable)" : " restored"));
        tacdbLoad();
      }).catch(function (e) { set("tc-u-msg", why(e)); });
    });
    $("tc-p-add").addEventListener("click", function () {
      var b = { op: "create", nomenclature: $("tc-p-nom").value.trim(), "class": $("tc-p-class").value };
      if ($("tc-p-unit").value) b.unit = parseInt($("tc-p-unit").value, 10);
      post("/api/frrs/tacdb/platform", b).then(function (j) {
        set("tc-p-msg", "platform " + j.platform.nomenclature + " made");
        $("tc-p-nom").value = "";
        H.go("tacdb", { id: String(j.platform.id) });
      }).catch(function (e) { set("tc-p-msg", why(e)); });
    });
    $("tc-pv-save").addEventListener("click", function () {
      if (!T.pv) return;
      var b = { op: "update", id: T.pv.id, unit: $("tc-pv-unit").value ? parseInt($("tc-pv-unit").value, 10) : null };
      var nm = $("tc-pv-nom").value.trim();
      if (nm && nm !== T.pv.nomenclature) b.nomenclature = nm;
      post("/api/frrs/tacdb/platform", b).then(function () {
        set("tc-pv-msg", "saved");
        platformLoad(T.pv.id);
        tacdbLoad();
      }).catch(function (e) { set("tc-pv-msg", why(e)); });
    });
    $("tc-pv-del").addEventListener("click", function () {
      if (!T.pv) return;
      post("/api/frrs/tacdb/platform", { op: T.pv.deleted ? "restore" : "delete", id: T.pv.id }).then(function (j) {
        set("tc-pv-msg", j.platform.deleted ? "deleted (restorable)" : "restored");
        platformLoad(T.pv.id);
        tacdbLoad();
      }).catch(function (e) { set("tc-pv-msg", why(e)); });
    });
    $("tc-e-add").addEventListener("click", function () {
      if (!T.pv) return;
      var b = { op: "add", platform: T.pv.id, kind: $("tc-e-kind").value, addr: $("tc-e-addr").value.trim().toLowerCase(),
                role: $("tc-e-role").value };
      if ($("tc-e-label").value.trim()) b.label = $("tc-e-label").value.trim();
      post("/api/frrs/tacdb/emitter", b).then(function () {
        set("tc-pv-msg", "added");
        $("tc-e-addr").value = "";
        $("tc-e-label").value = "";
        platformLoad(T.pv.id);
      }).catch(function (e) { set("tc-pv-msg", why(e)); });
    });
    function imp(mode) {
      var f = $("tc-imp-file").files && $("tc-imp-file").files[0];
      if (!f) { set("tc-imp-msg", "choose an exported file first"); return; }
      if (f.size > 8388608) { set("tc-imp-msg", "larger than an export can be (8 MiB)"); return; }
      var rd = new FileReader();
      rd.onload = function () {
        post("/api/frrs/import?mode=" + mode, String(rd.result), true).then(function (j) {
          var m = j.merged || {};
          set("tc-imp-msg", (mode === "check" ? "checks: would merge " : "merged ") +
              Object.keys(m).map(function (k) { return m[k] + " " + k; }).join(", ") +
              "; " + (j.skipped || []).length + " skipped" + (j.error ? ": " + j.error : ""));
          if (mode === "merge") tacdbLoad();
        }).catch(function (e) {
          var b = e.body || {};
          set("tc-imp-msg", why(e) + (b.line ? " at line " + b.line : "") + (b.why ? " (" + b.why + ")" : ""));
        });
      };
      rd.onerror = function () { set("tc-imp-msg", "the file could not be read"); };
      rd.readAsText(f);
    }
    // The export is an attachment: the browser saves it, the page stays.
    $("tc-export").addEventListener("click", function () { window.location.assign("/api/frrs/export"); });
    $("tc-imp-check").addEventListener("click", function () { imp("check"); });
    $("tc-imp-merge").addEventListener("click", function () { imp("merge"); });
  }

  // The evidence-bundle slice's hook: its button in container, when
  // that module is on the page.
  function mountBundle(container, kind, id) {
    if (!container) return;
    clear(container);
    if (window.SlothBundle && typeof window.SlothBundle.mount === "function")
      window.SlothBundle.mount(container, kind, id);
  }

  function init(h) {
    H = h;
    var by = H.prefGet("frrs.by");
    if ($("frrs-by")) {
      if (typeof by === "string" && by.length <= 32) $("frrs-by").value = by;
      $("frrs-by").addEventListener("input", function () { H.prefSet("frrs.by", $("frrs-by").value || null); });
    }
    if ($("al-triage")) $("al-triage").addEventListener("change", function () {
      H.prefSet("ctl.al-triage", $("al-triage").value);
      H.alertsReload();
    });
    if ($("nav-tacdb")) $("nav-tacdb").addEventListener("click", function () { H.show("tacdb"); });
    var line = $("k-alerts-triaged");
    if (line) line.addEventListener("click", function (e) {
      e.preventDefault();
      e.stopPropagation();
      H.go("alerts", { state: "open", triage: "out" });
    });
    summary();
    setInterval(function () { if (!document.hidden) summary(); }, 10000);
  }

  return { init: init, link: link, cell: cell, q: q, show: show, mountAlert: mountAlert,
           mountDrawer: mountDrawer, mountBundle: mountBundle, tacdb: tacdb, record: record };
})();
