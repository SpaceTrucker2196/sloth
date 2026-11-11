// Plain notes on the things the page lists that are not findings
// (web/src/web_notes.c; owner request 2026-11-11): a device, a BLE
// advertiser, an SSID, a GNSS satellite, an aircraft, an APRS station.
// One module on window.SlothSubNotes beside app.js, reached only
// through these hook points, each one guarded call:
//
//   openDrawer(mac)       SlothSubNotes.show("dev", "device", mac)
//   openBleDrawer(..)     SlothSubNotes.show("ble", "ble", addr + "/" + type)
//   ssid.js open()        SlothSubNotes.show("ssid", "ssid", param)  (its octets, base64url)
//   gnss.js detail()      SlothSubNotes.show("gnss", "gnss", gnssid + "." + prn)
//   adsb.js detail()      SlothSubNotes.show("adsb", "aircraft", hex)
//   aprs.js detail()      SlothSubNotes.show("aprs", "aprs", call)
//   a table's row         SlothSubNotes.mark(cell, kind, id)
//   notes.js, frrs.js     SlothSubNotes.agent(via)   the "agent" mark on
//                         a triage row or a link an agent wrote
//   main()                SlothSubNotes.init({...})  the page's helpers
//
// An alert's or an anomaly's note is its triage note (frrs.js,
// notes.js): this module draws none of those.
//
// A note is text, who, from where, when and how. "agent" marks a row a
// software agent wrote through slothweb-mcp with the run's agent secret;
// the server decides that word, never the request. A note is never
// deleted: "retract" writes a row that takes it back, and the note
// stays listed, struck, with who took it back.
//
// A row's mark ("note 2", "note 2 agent") comes from one batched read
// of up to 24 ids (/api/frrs/notes/marks), never a request per row, and
// is kept 30 s.
//
// Every value is shown with textContent and nothing else: a note
// holding markup is shown as the characters it is. No value becomes a
// class, an attribute or a URL, nothing is parsed as markup, and no
// link is made from text (test_subnotes.c holds this file to it).
var SlothSubNotes = (function () {
  "use strict";
  var H = null, F = null;
  function $(id) { return document.getElementById(id); }
  // Each kind's id as the server spells it: what is sent is what was
  // validated here, so an id is never percent-encoded into a query.
  var ID_RE = {
    device: /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/,
    ble: /^[0-9a-f]{2}(:[0-9a-f]{2}){5}\/[0-3]$/,
    ssid: /^[A-Za-z0-9_-]{2,43}$/,
    gnss: /^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,4})$/,
    aircraft: /^~?[0-9a-f]{6}$/,
    aprs: /^[A-Z0-9]{1,6}(-[A-Z0-9]{1,2})?$/
  };
  var PLACES = ["dev", "ble", "ssid", "gnss", "adsb", "aprs"];
  var MARK_TTL_MS = 30000, MARK_BATCH = 24, REREAD_MS = 10000;
  var S = {
    at: {},      // place -> { kind, id, gen } shown there now
    marks: {},   // "kind id" -> { t, n, agent } as the server last said
    wait: {},    // kind -> { id: [cells] } asked for and not yet answered
    timer: 0
  };
  var WHY = {
    "no_such_device": "no device of that address is held now; a note is added only to one that is",
    "no_such_ble": "no BLE advertiser of that address and type is held now",
    "no_such_ssid": "sloth.db holds no beacon or probe naming that SSID",
    "no_such_satellite": "that satellite is not in the sky table now",
    "no_such_aircraft": "that aircraft is not in the table now",
    "no_such_station": "that station is not in the table now",
    "no_such_note": "that note is gone (folded away after it was retracted)",
    "no_sloth_db": "no sloth.db to check the SSID against (--sloth-db)",
    "no_holder": "this slothweb has no table to check that subject against",
    "notes_full": "this subject has its 64 notes, or the store its 20,000, and none is retracted to fold: retract one first",
    "missing_text": "a note needs its text",
    "bad_id": "not an id of that kind"
  };

  function el(tag, cls, text) { return H.el(tag, cls, text); }
  function clear(n) { while (n && n.firstChild) n.removeChild(n.firstChild); }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function by() { var v = H.prefGet("frrs.by"); return typeof v === "string" && v.length <= 32 ? v : ""; }
  function ok(kind, id) { return typeof id === "string" && ID_RE.hasOwnProperty(kind) && ID_RE[kind].test(id); }
  function btn(label, fn) {
    var b = el("button", "tri-b", label);
    b.type = "button";
    b.addEventListener("click", function (e) { e.stopPropagation(); e.preventDefault(); fn(); });
    return b;
  }
  // The mark on anything an agent wrote: a fixed word of this page's.
  function agent(via) { return via === "agent" ? el("span", "subnotes-agent", "agent") : null; }
  function who(r) { return (r.by || "-") + " · from " + (r.peer || "?") + " · " + H.shortStamp(r.ts); }

  // ── one subject's notes ───────────────────────────────────────────
  function draw(place, j) {
    var at = S.at[place], ol = $("subnotes-" + place + "-list"), note = $("subnotes-" + place + "-note");
    if (!at || !ol || !note) return;
    clear(ol);
    var rows = j.notes || [];
    if (!rows.length) ol.appendChild(el("li", "sub", "no note yet"));
    rows.forEach(function (r) {
      var li = el("li", "notes-row" + (r.retracted ? " subnotes-gone" : ""));
      li.appendChild(el("span", "ts", H.shortStamp(r.ts)));
      var a = agent(r.via);
      if (a) li.appendChild(a);
      li.appendChild(el("span", r.retracted ? "d-dim subnotes-struck" : "d-bright", r.text || "-"));
      li.appendChild(el("span", "d-dim", who(r)));
      if (r.retracted) {
        li.appendChild(el("span", "sev1", "retracted"));
        var ra = agent(r.retracted.via);
        if (ra) li.appendChild(ra);
        if (r.retracted.reason) li.appendChild(el("span", "d-normal", r.retracted.reason));
        li.appendChild(el("span", "d-dim", who(r.retracted)));
      } else if (j.writes && num(r.note)) {
        li.appendChild(btn("retract", function () { write(place, { op: "retract", note: r.note }); }));
      }
      ol.appendChild(li);
    });
    if (j.more) ol.appendChild(el("li", "sub", "older notes not shown"));
    note.textContent = (j.store !== "open" ? "no store: notes are off (WITH_SQLITE=0 or no --store)"
      : !j.writes ? "read-only (--web-read-only)"
      : "kept in slothweb's store, never sent to sloth; a note is never deleted, retract writes a row") +
      (num(j.live) ? "; " + j.live + " standing of at most " + j.cap + " rows" : "") +
      (num(j.folded) && j.folded > 0 ? " (" + j.folded + " retracted rows folded away)" : "") +
      (j.held === false ? "; not held now: these are what is left of it, and none can be added" : "");
    var add = $("subnotes-" + place + "-add");
    if (add) add.disabled = !j.writes || j.held === false;
    // The table's mark follows what the server just said.
    S.marks[at.kind + " " + at.id] = { t: Date.now(), n: num(j.live) ? j.live : 0, agent: rows.filter(function (r) {
      return !r.retracted && r.via === "agent";
    }).length };
  }
  function load(place) {
    var at = S.at[place];
    if (!at) return;
    var gen = at.gen;
    H.getJSON("/api/frrs/notes?kind=" + at.kind + "&id=" + encodeURIComponent(at.id)).then(function (j) {
      if (S.at[place] && S.at[place].gen === gen) draw(place, j);
    }).catch(function (e) {
      var note = $("subnotes-" + place + "-note");
      if (note && S.at[place] && S.at[place].gen === gen) note.textContent = WHY[e && e.message] || F.why(e);
    });
  }
  function count(place) {
    var t = $("subnotes-" + place + "-text"), c = $("subnotes-" + place + "-n");
    if (!t || !c) return;
    var b = F.bytes(t.value.trim()), m = t.maxLength > 0 ? t.maxLength : 240;
    c.textContent = t.value ? b + " of " + m + " bytes" : "";
    c.classList.toggle("sev2", b > m);
  }
  function write(place, body) {
    var at = S.at[place], msg = $("subnotes-" + place + "-msg");
    if (!at || !msg) return;
    var gen = at.gen;
    body.kind = at.kind;
    body.id = at.id;
    if (by()) body.by = by();
    // Nothing is drawn from the request: the list changes only once
    // the server has the row, and from the server's answer.
    msg.textContent = "pending: not in the store until the server confirms it";
    F.post("/api/frrs/note", body).then(function (j) {
      if (!S.at[place] || S.at[place].gen !== gen) return;
      msg.textContent = "";
      if (body.op === "add") { $("subnotes-" + place + "-text").value = ""; count(place); }
      draw(place, j.notes || {});
    }).catch(function (e) {
      if (S.at[place] && S.at[place].gen === gen) msg.textContent = WHY[e && e.message] || F.why(e);
    });
  }
  function hide(place) {
    var box = $("subnotes-" + place);
    if (box) box.hidden = true;
    if (S.at[place]) S.at[place] = null;
  }
  function show(place, kind, id) {
    var box = $("subnotes-" + place);
    if (!H || !F || !box || PLACES.indexOf(place) < 0 || !ok(kind, id)) { hide(place); return; }
    var prev = S.at[place];
    S.at[place] = { kind: kind, id: id, gen: (prev ? prev.gen : 0) + 1, t: Date.now() };
    // The same subject drawn again (a panel that redraws on every
    // poll, a drawer opened twice) keeps what is typed and what is
    // listed, and reads the list again at most every ten seconds: a
    // note an agent added shows without a reload of the page.
    if (prev && prev.kind === kind && prev.id === id && !box.hidden) {
      S.at[place].gen = prev.gen;
      if (S.at[place].t - prev.t < REREAD_MS) S.at[place].t = prev.t;
      else load(place);
      return;
    }
    box.hidden = false;
    clear($("subnotes-" + place + "-list"));
    $("subnotes-" + place + "-note").textContent = "loading";
    $("subnotes-" + place + "-msg").textContent = "";
    $("subnotes-" + place + "-text").value = "";
    count(place);
    load(place);
  }

  // ── which rows of a table have notes ──────────────────────────────
  function paint(cell, m) {
    if (cell.subMark) { cell.subMark.remove(); cell.subMark = null; }
    if (!m || !(m.n > 0)) return;
    cell.subMark = el("span", "subnotes-mark", "note " + m.n + (m.agent > 0 ? " agent" : ""));
    cell.appendChild(cell.subMark);
  }
  function flush() {
    S.timer = 0;
    Object.keys(S.wait).forEach(function (kind) {
      var w = S.wait[kind], ids = Object.keys(w);
      delete S.wait[kind];
      for (var i = 0; i < ids.length; i += MARK_BATCH) (function (part) {
        H.getJSON("/api/frrs/notes/marks?kind=" + kind + "&ids=" + part.join(",")).then(function (j) {
          var got = j.marks || {}, t = Date.now();
          part.forEach(function (id) {
            var g = got.hasOwnProperty(id) ? got[id] : null;
            var m = { t: t, n: g && num(g.n) ? g.n : 0, agent: g && num(g.agent) ? g.agent : 0 };
            S.marks[kind + " " + id] = m;
            w[id].forEach(function (cell) { if (cell.isConnected && cell.subWant === kind + " " + id) paint(cell, m); });
          });
        }).catch(function () { /* no answer: no mark, and the next paint asks again */ });
      })(ids.slice(i, i + MARK_BATCH));
    });
  }
  function mark(cell, kind, id) {
    if (!H || !cell) return;
    if (!ok(kind, id)) { cell.subWant = ""; paint(cell, null); return; }
    var k = kind + " " + id, m = S.marks[k];
    cell.subWant = k;
    if (m && Date.now() - m.t < MARK_TTL_MS) { paint(cell, m); return; }
    paint(cell, m || null);
    if (!S.wait[kind]) S.wait[kind] = {};
    if (!S.wait[kind][id]) S.wait[kind][id] = [];
    S.wait[kind][id].push(cell);
    if (!S.timer) S.timer = setTimeout(flush, 50);
  }

  function init(h) {
    H = h;
    F = window.SlothFrrs && typeof window.SlothFrrs.post === "function" ? window.SlothFrrs : null;
    if (!F) return;
    PLACES.forEach(function (place) {
      var add = $("subnotes-" + place + "-add"), text = $("subnotes-" + place + "-text");
      if (!add || !text) return;
      text.addEventListener("input", function () { count(place); });
      add.addEventListener("click", function () {
        var msg = $("subnotes-" + place + "-msg"), v = text.value.trim();
        var m = text.maxLength > 0 ? text.maxLength : 240;
        if (!v) { msg.textContent = WHY.missing_text; return; }
        if (F.bytes(v) > m) {
          msg.textContent = "note too long: " + F.bytes(v) + " of " + m + " bytes; nothing was saved";
          return;
        }
        write(place, { op: "add", text: v });
      });
    });
  }

  return { init: init, show: show, hide: hide, mark: mark, agent: agent };
})();
