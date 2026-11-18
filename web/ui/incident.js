// Many alerts triaged as one (#198; web/src/web_incident.c): the
// Alerts page's incidents, its selection and its bulk verdict. One
// module on window.SlothIncident beside app.js, reached only through
// these hook points, each one guarded call:
//
//   alertsQuery(off)    SlothIncident.q(p)          incident=none on the
//                       list's path while the page groups by incident
//   alertRow(a)         SlothIncident.pick(t, a)    the row's selection box
//   alertsLoad()        SlothIncident.loaded(j)     the answer's clock, and
//                       the incidents read again
//   alertsView()        SlothIncident.show(vp)      #alerts?incident=N
//                       opens that incident
//   frrs.js mountAlert  SlothIncident.alertLine(box, st)   "member of
//                       incident #N" on the alert's page
//   main()              SlothIncident.init({...})   the page's helpers
//
// Writes go through SlothFrrs's one post(), so the page has one write
// path as the server has one: POST /api/frrs/triage/bulk (the selection,
// at most 100 ids a POST, one token each) and POST /api/frrs/incident.
// Nothing is drawn from a request: the list and the incidents are read
// again once the server has answered, and until then the line says the
// change is pending.
//
// Grouped (the default), the list shows the alerts in no incident and
// this panel one row per incident, which opens to the alerts it holds
// (drawn by app.js's own alertRow()) and its standing filters. An
// incident's alerts read as its state unless one has its own later
// verdict (web_incident.h): the chip says which.
//
// Every value is shown with textContent and nothing else: a title or a
// note holding markup is shown as the characters it is. No value
// becomes a class, an attribute or a URL, nothing is parsed as markup,
// and no link is made from text (test_incident.c holds this file to it).
var SlothIncident = (function () {
  "use strict";
  var H = null, F = null;
  function $(id) { return document.getElementById(id); }
  var ID_RE = /^[sd][0-9A-Za-z]{1,24}$/;
  var IP4_RE = /^\d{1,3}(\.\d{1,3}){3}$/, IP6_RE = /^[0-9A-Fa-f:]+:[0-9A-Fa-f:.]*$/;
  var MAC_RE = /^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$/;
  var DECIDED = ["false", "noise", "incident", "known"];
  var BULK_MAX = 100, COUNT_ROWS = 20, ALL_WINDOW = 34560000;
  var S = {
    sel: {},     // alert id -> true, the selection
    picks: [],   // { cb, id } of every selection box drawn
    open: {},    // incident id -> true while its row is open
    list: [],    // /api/frrs/incidents's rows
    totals: {},  // incident id -> its alerts' total, as /api/alerts said
    cnt: {},     // incident id -> { el, inc }: its row's count, drawn
    writes: false, now: 0, gen: 0, busy: false
  };

  function el(tag, cls, text) { return H.el(tag, cls, text); }
  function clear(n) { while (n && n.firstChild) n.removeChild(n.firstChild); }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function grouped() { return !$("inc-group") || $("inc-group").checked; }
  function msg(t) { var m = $("inc-msg"); if (m) m.textContent = t; }
  function why(e) { return F ? F.why(e) : String(e && e.message ? e.message : e); }
  function by() {
    var b = H.prefGet("frrs.by");
    return typeof b === "string" && b.length <= 32 ? b.trim() : "";
  }
  function selIds() { return Object.keys(S.sel).filter(function (id) { return S.sel[id]; }); }

  var WHY = {
    "incident_closed": "that incident is closed: no member changes after a close",
    "incidents_full": "the incidents store is full",
    "members_full": "that incident holds as many members as it can",
    "filters_full": "that incident holds as many filters as it can",
    "not_agent_incident": "an agent closes only incidents an agent opened",
    "too_many_ids": "at most 100 alerts at once"
  };
  function whyInc(e) {
    var m = e && e.message ? e.message : "";
    return Object.prototype.hasOwnProperty.call(WHY, m) ? WHY[m] : why(e);
  }

  // ── the selection and the bulk verdict ───────────────────────────
  function barCount() {
    var n = selIds().length, c = $("inc-sel-n");
    if (c) c.textContent = n ? n + " selected" : "none selected";
    ["inc-new-sel"].concat(DECIDED.map(function (s) { return "inc-bulk-" + s; })).forEach(function (id) {
      if ($(id)) $(id).disabled = !n || !S.writes || S.busy;
    });
  }
  function mark(b, on) {
    b.textContent = on ? "\u25a0" : "\u25a1";
    b.ariaPressed = on ? "true" : "false";
  }
  function pick(t, a) {
    if (!H || !t || !a || typeof a.id !== "string" || !ID_RE.test(a.id)) return;
    // A toggle button, not a checkbox: the page makes no form control
    // from script (test_prefs.c's census of every control).
    S.picks = S.picks.filter(function (k) { return k.cb.isConnected; });
    var cb = el("button", "inc-pick", "");
    cb.type = "button";
    S.picks.push({ cb: cb, id: a.id });
    mark(cb, !!S.sel[a.id]);
    cb.ariaLabel = "select this alert";
    cb.addEventListener("keydown", function (e) { e.stopPropagation(); });
    cb.addEventListener("click", function (e) {
      e.stopPropagation();
      e.preventDefault();
      if (S.sel[a.id]) delete S.sel[a.id]; else S.sel[a.id] = true;
      mark(cb, !!S.sel[a.id]);
      barCount();
    });
    t.insertBefore(cb, t.firstChild);
  }
  // Every alert drawn on the Alerts page now, the list's and the open
  // incidents' both.
  function selectShown(on) {
    if (!on) S.sel = {};
    S.picks = S.picks.filter(function (k) { return k.cb.isConnected; });
    S.picks.forEach(function (k) {
      if (on) S.sel[k.id] = true;
      mark(k.cb, on);
    });
    barCount();
  }

  // The selection in POSTs of at most BULK_MAX ids, one after another
  // (each one token): each id's outcome counted from the answers.
  function bulk(state) {
    var ids = selIds(), note = $("inc-note") ? $("inc-note").value.trim() : "";
    if (!ids.length || !F || S.busy) return;
    if (note && F.bytes(note) > 240) { msg("note too long: " + F.bytes(note) + " of 240 bytes; nothing was saved"); return; }
    S.busy = true;
    barCount();
    msg("pending: " + ids.length + " alerts, not in the store until the server confirms them");
    var done = 0, same = 0, failed = 0, parts = [];
    for (var i = 0; i < ids.length; i += BULK_MAX) parts.push(ids.slice(i, i + BULK_MAX));
    var step = function (k) {
      if (k >= parts.length) return Promise.resolve();
      var b = { ids: parts[k].join(","), state: state };
      if (note) b.note = note;
      if (by()) b.by = by();
      return F.post("/api/frrs/triage/bulk", b).then(function (j) {
        done += num(j.written) ? j.written : 0;
        same += num(j.unchanged) ? j.unchanged : 0;
        failed += num(j.failed) ? j.failed : 0;
        return step(k + 1);
      });
    };
    step(0).then(function () {
      msg(state + ": " + done + " written, " + same + " already so" + (failed ? ", " + failed + " refused (gone or not found)" : ""));
      S.sel = {};
      if ($("inc-note")) $("inc-note").value = "";
    }, function (e) {
      msg("stopped after " + done + " written: " + whyInc(e));
    }).then(function () {
      S.busy = false;
      barCount();
      H.alertsReload();
    });
  }

  // ── new incidents ────────────────────────────────────────────────
  function addIncident(b, then) {
    var title = $("inc-title") ? $("inc-title").value.trim() : "";
    var state = $("inc-state") ? $("inc-state").value : "";
    var note = $("inc-note") ? $("inc-note").value.trim() : "";
    if (!title) { msg("give the incident a title first"); return; }
    if (DECIDED.indexOf(state) < 0) return;
    b.op = "add";
    b.title = title;
    b.state = state;
    if (note) b.note = note;
    if (by()) b.by = by();
    msg("pending: not in the store until the server confirms it");
    F.post("/api/frrs/incident", b).then(function (j) {
      var r = j.results || [], bad = r.filter(function (x) { return !x.ok; }).length;
      msg("incident #" + j.incident.id + " opened" + (r.length ? ": " + (r.length - bad) + " alerts" +
          (bad ? ", " + bad + " refused" : "") : ""));
      if ($("inc-title")) $("inc-title").value = "";
      if (then) then(j);
      S.open[j.incident.id] = true;
      H.alertsReload();
    }).catch(function (e) { msg(whyInc(e)); });
  }
  function fromSelection() {
    var ids = selIds();
    if (!ids.length || !F) return;
    if (ids.length > BULK_MAX) { msg("at most 100 alerts make a new incident; add the rest from its row"); return; }
    addIncident({ ids: ids.join(",") }, function () { S.sel = {}; barCount(); });
  }
  // The list's filter as an incident's standing filter: its type, and
  // the search word when it is an address; the window as "began in the
  // window". Severity, state and a word that is not an address are not
  // part of one, and the line says so rather than drop them unsaid.
  function fromFilter() {
    if (!F) return;
    var b = {}, left = [];
    var ty = $("al-type") ? $("al-type").value : "";
    var q = $("al-q") ? $("al-q").value.trim().split(/\s+/)[0] || "" : "";
    if (ty) b.type = ty;
    if (q && (IP4_RE.test(q) || IP6_RE.test(q))) b.ip = q;
    else if (q && MAC_RE.test(q)) b.mac = q;
    else if (q) left.push("search " + q);
    if ($("al-sev") && $("al-sev").value) left.push("severity");
    if ($("al-state") && $("al-state").value !== "all") left.push("state");
    if (!b.type && !b.ip && !b.mac) { msg("pick a type or search an address first: that is what an incident's filter holds"); return; }
    var win = $("al-win") ? Number($("al-win").value) : 0;
    if (S.now > 0 && win > 0 && win < ALL_WINDOW) b.from = Math.max(1, S.now - win);
    addIncident(b, function () { if (left.length) msg("opened; not part of its filter: " + left.join(", ")); });
  }

  // ── the incidents panel ──────────────────────────────────────────
  function chipOf(state) { return F ? F.chip({ state: state }) : el("span", "tri-chip", state); }
  function filterText(m) {
    var p = [];
    p.push(typeof m.type === "string" ? m.type : "any type");
    if (m.addr) p.push(m.addr);
    if (m.from || m.to)
      p.push("began " + (m.from ? H.shortStamp(m.from) : "any time") + " to " + (m.to ? H.shortStamp(m.to) : "now"));
    return "filter: " + p.join(", ");
  }
  function writeBtn(label, fn, cls) {
    var b = el("button", "tri-b" + (cls ? " " + cls : ""), label);
    b.type = "button";
    b.addEventListener("click", function (e) { e.stopPropagation(); fn(); });
    return b;
  }
  function memberPost(b, line) {
    if (by()) b.by = by();
    line.textContent = "pending";
    F.post("/api/frrs/incident", b).then(function () { line.textContent = ""; H.alertsReload(); })
      .catch(function (e) { line.textContent = whyInc(e); });
  }
  // One incident opened: its filters (each removable while it is
  // open), then its alerts as the Alerts list draws them, the newest
  // hundred, each removable when it was added by id.
  function body(inc, box) {
    var gen = S.gen;
    var line = el("div", "sub", "loading");
    box.appendChild(line);
    var det = H.getJSON("/api/frrs/incidents?id=" + inc.id);
    var al = H.getJSON("/api/alerts?incident=" + inc.id + "&window=" + ALL_WINDOW + "&limit=100");
    Promise.all([det, al]).then(function (r) {
      if (gen !== S.gen) return;
      clear(box);
      var d = r[0], j = r[1], byId = {};
      var m = el("div", "sub inc-msg", "");
      if (inc.note) box.appendChild(el("div", "prose", inc.note));
      (d.members || []).forEach(function (x) {
        if (x.kind === "alert" && typeof x.id === "string") byId[x.id] = x.member;
        if (x.kind !== "filter") return;
        var f = el("div", "inc-filter");
        f.appendChild(el("span", "d-normal", filterText(x)));
        f.appendChild(el("span", "d-dim", "  " + (x.by || "-") + (x.via === "agent" ? " (agent)" : "")));
        if (S.writes && inc.open)
          f.appendChild(writeBtn("remove", function () { memberPost({ op: "member", incident: inc.id, remove: x.member }, m); }));
        box.appendChild(f);
      });
      var rows = j.rows || [];
      box.appendChild(el("div", "sub", (num(j.total) ? j.total : rows.length) + " alerts" +
                         (j.more ? ", the newest " + rows.length + " shown" : "") +
                         "; an alert with its own later verdict keeps it"));
      rows.forEach(function (a) {
        var row = H.alertRow(a);
        var mid = byId[a.id];
        if (S.writes && inc.open && num(mid)) {
          var x = writeBtn("remove from incident", function () {
            memberPost({ op: "member", incident: inc.id, remove: mid }, m);
          });
          x.classList.add("inc-rm");
          (row.children[1] || row).appendChild(x);
        }
        box.appendChild(row);
      });
      if (d.more) box.appendChild(el("div", "sub", "more members than are listed here"));
      box.appendChild(m);
    }).catch(function (e) { if (gen === S.gen) line.textContent = whyInc(e); });
  }
  function incRow(inc) {
    var wrap = el("div", "inc-item");
    var row = el("div", "inc-row");
    var tg = el("button", "inc-tg", S.open[inc.id] ? "▾" : "▸");
    tg.type = "button";
    tg.ariaExpanded = S.open[inc.id] ? "true" : "false";
    tg.ariaLabel = "open incident " + inc.id;
    row.appendChild(tg);
    row.appendChild(chipOf(inc.state));
    row.appendChild(el("span", "d-dim", "#" + inc.id));
    row.appendChild(el("span", "d-bright inc-title", inc.title));
    var cnt = el("span", "d-normal", "");
    S.cnt[inc.id] = { el: cnt, inc: inc };
    countText(inc.id);
    row.appendChild(cnt);
    row.appendChild(el("span", "d-dim", (inc.by || "-") + (inc.via === "agent" ? " (agent)" : "") + " · " +
                       H.shortStamp(inc.ts) + (inc.closed ? " · closed " + H.shortStamp(inc.closed.ts) : "")));
    var m = el("span", "sub inc-msg", "");
    if (S.writes && inc.open) {
      row.appendChild(writeBtn("close", function () {
        m.textContent = "pending";
        var b = { op: "close", incident: inc.id };
        if (by()) b.by = by();
        F.post("/api/frrs/incident", b).then(function () { H.alertsReload(); })
          .catch(function (e) { m.textContent = whyInc(e); });
      }));
      var ids = selIds();
      if (ids.length && ids.length <= BULK_MAX)
        row.appendChild(writeBtn("add " + ids.length + " selected", function () {
          memberPost({ op: "member", incident: inc.id, ids: ids.join(",") }, m);
          S.sel = {};
          barCount();
        }));
    }
    row.appendChild(m);
    wrap.appendChild(row);
    var box = el("div", "inc-body");
    box.hidden = !S.open[inc.id];
    wrap.appendChild(box);
    if (S.open[inc.id]) body(inc, box);
    tg.addEventListener("click", function () {
      S.open[inc.id] = !S.open[inc.id];
      tg.textContent = S.open[inc.id] ? "▾" : "▸";
      tg.ariaExpanded = S.open[inc.id] ? "true" : "false";
      box.hidden = !S.open[inc.id];
      clear(box);
      if (S.open[inc.id]) body(inc, box);
    });
    return wrap;
  }
  function countText(id) {
    var c = S.cnt[id];
    if (!c) return;
    var n = S.totals[id], inc = c.inc;
    c.el.textContent = (num(n) ? n + " alerts" : inc.alerts + " by id") +
      (inc.filters ? ", " + inc.filters + " filter" + (inc.filters > 1 ? "s" : "") : "");
  }
  function draw() {
    S.cnt = {};
    var box = $("inc-rows");
    if (!box) return;
    clear(box);
    var list = S.list.filter(function (i) { return i.open || ($("inc-closed") && $("inc-closed").checked); });
    list.forEach(function (i) { box.appendChild(incRow(i)); });
    if (!list.length) box.appendChild(el("div", "sub", S.list.length ? "no open incident (closed ones hidden)"
      : "no incident yet: select alerts below, or set a type or an address, and open one"));
    var open = S.list.filter(function (i) { return i.open; }).length;
    if ($("inc-count")) $("inc-count").textContent = S.list.length ? open + " open, " + (S.list.length - open) + " closed" : "";
  }
  // Each listed incident's alert count, one small read each, the first
  // COUNT_ROWS only: the panel's numbers are the server's, by id and by
  // filter both.
  function counts(gen) {
    S.list.slice(0, COUNT_ROWS).forEach(function (i) {
      if (!i.open && !($("inc-closed") && $("inc-closed").checked)) return;
      H.getJSON("/api/alerts?incident=" + i.id + "&window=" + ALL_WINDOW + "&limit=1").then(function (j) {
        if (gen !== S.gen || !num(j.total)) return;
        S.totals[i.id] = j.total;
        countText(i.id);
      }).catch(function () {});
    });
  }
  function reload() {
    var gen = ++S.gen;
    H.getJSON("/api/frrs/incidents").then(function (j) {
      if (gen !== S.gen) return;
      S.writes = !!j.writes;
      S.list = j.incidents || [];
      // No store, no incidents: the panel is not drawn at all.
      $("inc-panel").hidden = j.store !== "open";
      ["inc-new-filter", "inc-title", "inc-state", "inc-note"].forEach(function (id) {
        if ($(id)) $(id).disabled = !S.writes;
      });
      draw();
      barCount();
      counts(gen);
    }).catch(function (e) { if ($("inc-count")) $("inc-count").textContent = whyInc(e); });
  }

  // ── the hooks ────────────────────────────────────────────────────
  function q(p) { if (H && grouped()) p.push("incident=none"); }
  function loaded(j) {
    if (!H) return;
    if (j && num(j.now)) S.now = j.now;
    reload();
  }
  function show(vp) {
    if (!H) return;
    var n = vp && typeof vp.incident === "string" && /^[1-9][0-9]{0,11}$/.test(vp.incident) ? Number(vp.incident) : 0;
    if (n) { S.open[n] = true; if ($("inc-group")) $("inc-group").checked = true; }
  }
  // The alert's page: the incident it reads, and the way to it.
  function alertLine(box, st) {
    if (!H || !box || !st || !st.incident || !num(st.incident.id)) return;
    var i = st.incident, d = el("div", "sub inc-of");
    d.appendChild(el("span", "", "member of incident #" + i.id + " "));
    d.appendChild(el("span", "d-bright", typeof i.title === "string" ? i.title : ""));
    d.appendChild(el("span", "", (i.joined === "filter" ? " by its filter" : " by id") + (i.auto ? ", auto-joined" : "") +
                     (i.governs ? ": the state shown is the incident's" : ": its own later verdict stands")));
    var b = writeBtn("open the incident", function () { H.go("alerts", { incident: String(i.id) }); });
    d.appendChild(b);
    box.appendChild(d);
  }

  function init(h) {
    H = h;
    F = window.SlothFrrs && typeof window.SlothFrrs.post === "function" ? window.SlothFrrs : null;
    if (!F || !$("inc-panel")) { H = null; return; }
    var g = H.prefGet("inc.group");
    if ($("inc-group")) {
      $("inc-group").checked = g !== false;
      $("inc-group").addEventListener("change", function () {
        H.prefSet("inc.group", $("inc-group").checked ? null : false);
        H.alertsReload();
      });
    }
    if ($("inc-closed")) $("inc-closed").addEventListener("change", function () { draw(); counts(S.gen); });
    DECIDED.forEach(function (s) {
      var b = $("inc-bulk-" + s);
      if (b) b.addEventListener("click", function () { bulk(s); });
    });
    if ($("inc-sel-all")) $("inc-sel-all").addEventListener("click", function () { selectShown(true); });
    if ($("inc-sel-none")) $("inc-sel-none").addEventListener("click", function () { selectShown(false); });
    if ($("inc-new-sel")) $("inc-new-sel").addEventListener("click", fromSelection);
    if ($("inc-new-filter")) $("inc-new-filter").addEventListener("click", fromFilter);
    barCount();
  }

  return { init: init, q: q, pick: pick, loaded: loaded, show: show, alertLine: alertLine };
})();
