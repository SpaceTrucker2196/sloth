// Triage notes on slothweb's own anomalies and the links between
// findings (web/src/web_relate.c; owner request 2026-11-11), one module
// on window.SlothNotes beside app.js, which reaches it only through
// these hook points, each one guarded call:
//
//   card(a)             SlothNotes.card(c, a)     every anomaly card (the
//                       Overview's top five, the Anomalies view, the
//                       drawer's, an alert page's): its state chip and
//                       the button that opens its triage
//   openDrawer(mac)     SlothNotes.drawer(mac)    notes-drawer: the links
//                       naming the device
//   alertPage(j)        SlothNotes.alert(j)       notes-alert: the alert's
//                       links to anomalies, and the candidates
//   main()              SlothNotes.init({...})    the page's helpers
//
// An anomaly is triaged exactly as an alert is: the same route
// (/api/frrs/triage), states, note bound and history, through
// SlothFrrs's own post(), chip() and why(), so there is one write path
// in the page as there is one on the server. Without frrs.js this
// module draws nothing.
//
// A link is the operator's. A candidate ("possibly related") is the
// server's offer, never stored until its button is pressed, and worded
// as what it is: the same device or address, at about the same time. A
// link whose other end the server no longer holds says so and can still
// be removed.
//
// Every value is shown with textContent and nothing else: a note or a
// label holding markup is shown as the characters it is. No value
// becomes a class, an attribute or a URL, nothing is parsed as markup,
// and no link is made from text (test_notes.c holds this file to it).
var SlothNotes = (function () {
  "use strict";
  var H = null, F = null;
  function $(id) { return document.getElementById(id); }
  var TID_RE = /^a[0-9a-f]{16}$/;
  var ALERT_RE = /^[sd][0-9A-Za-z]{1,24}$/;
  var MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;
  var REF_RE = /^(a[0-9a-f]{16}|[sd][0-9A-Za-z]{1,24}|[0-9a-f]{2}(:[0-9a-f]{2}){5})$/;
  var STATES = ["false", "noise", "incident", "known"];
  var CLS = { "false": "sev1", "noise": "sev0", "incident": "sev2", "known": "tri-known" };
  var S = {
    st: {},     // anomaly id -> its current triage, as the server said
    reg: {},    // anomaly id -> the cards it is drawn on
    seen: {},   // anomaly id -> when its state was last asked
    writes: false, queue: [], qt: 0, open: "", gen: 0, agen: 0, dgen: 0
  };

  function el(tag, cls, text) { return H.el(tag, cls, text); }
  function clear(n) { while (n && n.firstChild) n.removeChild(n.firstChild); }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function out(st) { return st === "false" || st === "noise" || st === "known"; }
  function by() { var v = H.prefGet("frrs.by"); return typeof v === "string" && v.length <= 32 ? v : ""; }
  function btn(label, cls, fn) {
    var b = el("button", "tri-b" + (cls ? " " + cls : ""), label);
    b.type = "button";
    b.addEventListener("click", function (e) { e.stopPropagation(); e.preventDefault(); fn(); });
    b.addEventListener("keydown", function (e) { e.stopPropagation(); });
    return b;
  }

  // ── a card's chip and button ──────────────────────────────────────
  // The state shown on a card is the finding's: decided on this episode,
  // or carried from an earlier one, and then it says so.
  function chipOf(st) {
    var c = F.chip(st);
    if (st && st.carried && st.state !== "untriaged") c.appendChild(el("span", "d-dim", " (earlier episode)"));
    return c;
  }
  function render(id) {
    var places = S.reg[id];
    if (!places) return;
    var st = S.st[id] || { state: "untriaged" };
    S.reg[id] = places.filter(function (p) { return p.card && p.card.isConnected; });
    if (!S.reg[id].length) { delete S.reg[id]; return; }
    S.reg[id].forEach(function (p) {
      clear(p.line);
      if (st.state !== "untriaged") p.line.appendChild(chipOf(st));
      p.line.appendChild(btn(st.state === "untriaged" ? "triage" : "notes", "", function () { open(id); }));
      p.card.classList.toggle("tri-out", out(st.state) && !st.carried);
    });
  }
  function flush() {
    S.qt = 0;
    var ids = S.queue.splice(0, S.queue.length);
    for (var i = 0; i < ids.length; i += 16) (function (part) {
      H.getJSON("/api/frrs/states?ids=" + part.join(",")).then(function (j) {
        S.writes = !!j.writes;
        var tri = j.triage || {}, t = Date.now();
        part.forEach(function (id) {
          S.st[id] = tri[id] || { state: "untriaged" };
          S.seen[id] = t;
          render(id);
        });
      }).catch(function () { part.forEach(function (id) { render(id); }); });
    })(ids.slice(i, i + 16));
  }
  function card(c, a) {
    if (!H || !F || !c || !a || typeof a.tid !== "string" || !TID_RE.test(a.tid)) return;
    var id = a.tid, line = el("div", "tri notes-line");
    c.appendChild(line);
    if (!S.reg[id]) S.reg[id] = [];
    S.reg[id].push({ card: c, line: line });
    var t = Date.now();
    if (S.seen[id] && t - S.seen[id] < 10000) { setTimeout(function () { render(id); }, 0); return; }
    if (S.queue.indexOf(id) < 0) S.queue.push(id);
    if (!S.qt) S.qt = setTimeout(flush, 30);
  }

  // ── links and candidates, wherever they are listed ───────────────
  function follow(kind, id) {
    if (kind === "alert" && ALERT_RE.test(id)) { close(); H.go("alert", { id: id }); }
    else if (kind === "device" && MAC_RE.test(id)) { close(); H.openDrawer(id); }
    else if (kind === "anomaly" && TID_RE.test(id)) open(id);
  }
  function relate(body, msg, then) {
    if (msg) msg.textContent = "pending: not in the store until the server confirms it";
    return F.post("/api/frrs/relate", body).then(function (j) {
      if (msg) msg.textContent = "";
      then(j.related);
    }).catch(function (e) {
      if (msg) msg.textContent = WHY[e && e.message] || F.why(e);
    });
  }
  var WHY = {
    "no_such_anomaly": "that anomaly is not held and was never triaged or linked",
    "no_such_device": "no device of that address is held",
    "no_such_link": "that link is gone",
    "bad_pair": "a link is from an anomaly: to an alert, another anomaly or a device, never to itself",
    "bad_id": "not an alert id, an anomaly id or a MAC",
    "links_full": "this finding has its 32 links, or the store its 8,192; remove one first",
    "anomaly_subjects_full": "the store holds 8,192 triaged or linked anomalies; no more",
    "id_collision": "refused: that id names a different anomaly in the store"
  };
  // The links of one finding (rel: /api/frrs/related's answer) into
  // box, the candidates into sug. from is the id every write names;
  // redraw takes the server's answer to a write.
  function listLinks(box, sug, rel, from, msg, redraw) {
    clear(box);
    var links = rel.links || [];
    if (!links.length) box.appendChild(el("li", "sub", "no link yet"));
    links.forEach(function (l) {
      var li = el("li", "notes-row");
      li.appendChild(el("span", "d-dim", l.dir === "to" ? "to " + l.kind : "from " + l.kind));
      li.appendChild(el("span", l.held ? "d-bright" : "d-dim", l.label || l.id));
      if (!l.held) li.appendChild(el("span", "sev1", "no longer held"));
      if (l.triage && l.triage.state !== "untriaged") li.appendChild(chipOf(l.triage));
      if (l.note) li.appendChild(el("span", "d-normal", l.note));
      li.appendChild(el("span", "d-dim", (l.by || "-") + " · from " + (l.peer || "?") + " · " + H.shortStamp(l.ts)));
      if (l.held) li.appendChild(btn("open", "", function () { follow(l.kind, l.id); }));
      if (rel.writes) li.appendChild(btn("remove", "", function () {
        relate({ op: "remove", from: from, link: l.link }, msg, redraw);
      }));
      box.appendChild(li);
    });
    if (rel.links_more) box.appendChild(el("li", "sub", "more than " + rel.links_cap + " links: the newest shown"));
    if (!sug) return;
    clear(sug);
    var cs = rel.suggest || [];
    if (!cs.length) sug.appendChild(el("li", "sub", rel.held ? "none in the window" : "none: not held now"));
    cs.forEach(function (c) {
      var li = el("li", "notes-row");
      li.appendChild(el("span", "d-dim", c.kind));
      li.appendChild(el("span", "d-bright", c.label || c.id));
      li.appendChild(el("span", "d-normal", c.basis));
      li.appendChild(el("span", "d-dim", H.shortStamp(c.first_seen) + " to " + H.shortStamp(c.last_seen)));
      li.appendChild(btn("open", "", function () { follow(c.kind, c.id); }));
      // One action accepts it; until then nothing is stored. An anomaly
      // is always the "from" end, so an alert's candidate is linked
      // from the anomaly to the alert.
      if (rel.writes) li.appendChild(btn("link", "", function () {
        var b = rel.kind === "anomaly" ? { op: "add", from: from, to: c.id } : { op: "add", from: c.id, to: from };
        if (by()) b.by = by();
        // The answer lists the "from" end: an alert's list is read again.
        relate(b, msg, rel.kind === "anomaly" ? redraw : function () { redraw(null); });
      }));
      sug.appendChild(li);
    });
  }
  function relNote(rel) {
    return (rel.store !== "open" ? "no store: links are off (WITH_SQLITE=0 or no --store)"
      : !rel.writes ? "read-only (--web-read-only)" : "kept in slothweb's store, never sent to sloth") +
      "; candidates share a MAC or an address and lie within " + Math.round(rel.window_s / 60) +
      " minutes: " + rel.suggest_note +
      (num(rel.alerts_reached) ? "; sloth.db's alerts read back to " + H.shortStamp(rel.alerts_reached) : "");
  }

  // ── the anomaly's triage panel ────────────────────────────────────
  function noteCount() {
    var n = $("notes-note"), c = $("notes-note-n");
    if (!n || !c) return;
    var b = F.bytes(n.value.trim()), m = n.maxLength > 0 ? n.maxLength : 240;
    c.textContent = n.value ? b + " of " + m + " bytes" : "";
    c.classList.toggle("sev2", b > m);
  }
  function act(id, state) {
    var n = $("notes-note"), msg = $("notes-msg");
    var note = n.value.trim(), m = n.maxLength > 0 ? n.maxLength : 240;
    var b = { id: id, state: state };
    if (note) b.note = note;
    if (by()) b.by = by();
    if (note && F.bytes(note) > m) {
      msg.textContent = "note too long: " + F.bytes(note) + " of " + m + " bytes; nothing was saved";
      return;
    }
    // Nothing is drawn from the request: the state and the history
    // change only once the server has the row.
    msg.textContent = "pending: not in the store until the server confirms it";
    F.post("/api/frrs/triage", b).then(function (j) {
      S.st[id] = j.current;
      msg.textContent = "";
      n.value = "";
      noteCount();
      render(id);
      load(id);
    }).catch(function (e) {
      msg.textContent = WHY[e && e.message] || F.why(e);
      load(id);
    });
  }
  function drawRelated(id, rel) {
    if (S.open !== id) return;
    $("notes-rel-note").textContent = relNote(rel);
    listLinks($("notes-links"), $("notes-sugg"), rel, id, $("notes-msg"), function (r) {
      if (r) drawRelated(id, r); else load(id);
    });
    $("notes-add").disabled = !rel.writes;
  }
  function load(id) {
    var gen = ++S.gen;
    H.getJSON("/api/frrs/history?id=" + id).then(function (h) {
      if (gen !== S.gen || S.open !== id) return;
      S.writes = !!h.writes;
      S.st[id] = h.current;
      var a = h.anomaly || {};
      $("notes-title").textContent = (a.rule || "") + " " + (a.kind || "") + " " + (a.key || "(sensor)");
      $("notes-desc").textContent = (a.metric ? a.metric + "; " : "") +
        (a.held ? (a.open ? "open" : "closed") + ", this episode first seen " + H.stamp(a.first_seen) +
          ", last " + H.stamp(a.last_seen)
          : "no longer held: the engine keeps a closed episode a day; the notes stay") +
        "; " + (h.store !== "open" ? "no store: triage is off (WITH_SQLITE=0 or no --store)"
          : !h.writes ? "read-only (--web-read-only): the state is shown, not changed"
          : "a decision is on the finding (this rule, metric and key), every episode of it, as an alert's is " +
            "on every incident of its key; each row says which episode it was made on");
      var cur = $("notes-cur");
      clear(cur);
      cur.appendChild(chipOf(h.current));
      if (h.current && h.current.state !== "untriaged") {
        cur.appendChild(el("span", "d-normal", "  by " + (h.current.by || "-") + " · from " +
                           (h.current.peer || "?") + " · " + H.stamp(h.current.ts)));
        if (h.current.carried) cur.appendChild(el("div", "sev1",
          "decided on an earlier episode (first seen " + H.stamp(h.current.episode) +
          "), not on this one: say it again to make it this episode's"));
        if (h.current.note) cur.appendChild(el("div", "prose", h.current.note));
      }
      var bb = $("notes-btns");
      clear(bb);
      if (h.writes) {
        STATES.forEach(function (s) {
          var x = btn(s, CLS[s], function () { act(id, s); });
          x.disabled = h.current.state === s && !h.current.carried;
          bb.appendChild(x);
        });
        if (h.current.state !== "untriaged") bb.appendChild(btn("clear", "", function () { act(id, "untriaged"); }));
      }
      var rows = h.rows || [], ol = $("notes-hist");
      clear(ol);
      if (!rows.length) ol.appendChild(el("li", "sub", "no change yet: untriaged"));
      rows.forEach(function (r) {
        var li = el("li", "notes-row");
        li.appendChild(el("span", "ts", H.shortStamp(r.ts)));
        li.appendChild(F.chip(r));
        li.appendChild(el("span", "d-dim", "was " + r.prev_state));
        li.appendChild(el("span", "d-bright", r.note || "-"));
        li.appendChild(el("span", "d-normal", (r.by || "-") + " · from " + (r.peer || "?")));
        li.appendChild(el("span", "d-dim", r.episode ? "episode of " + H.shortStamp(r.episode) : "no episode held"));
        ol.appendChild(li);
      });
      $("notes-hist-note").textContent = rows.length + " of at most " + h.history_cap +
        (h.folded ? " (" + h.folded + " older folded: the first and the newest kept)" : "") + "; filed as " + h.subject;
      render(id);
    }).catch(function (e) {
      if (gen === S.gen) $("notes-desc").textContent = WHY[e && e.message] || F.why(e);
    });
    H.getJSON("/api/frrs/related?id=" + id).then(function (rel) {
      if (gen === S.gen) drawRelated(id, rel);
    }).catch(function (e) {
      if (gen === S.gen) $("notes-rel-note").textContent = WHY[e && e.message] || F.why(e);
    });
  }
  function open(id) {
    var d = $("notes-dlg");
    if (!H || !F || !d || typeof id !== "string" || !TID_RE.test(id)) return;
    S.open = id;
    $("notes-msg").textContent = "";
    $("notes-note").value = "";
    $("notes-to").value = "";
    noteCount();
    ["notes-cur", "notes-btns", "notes-hist", "notes-links", "notes-sugg"].forEach(function (k) { clear($(k)); });
    $("notes-title").textContent = id;
    $("notes-desc").textContent = "loading";
    if (!d.open && typeof d.showModal === "function") d.showModal();
    load(id);
  }
  function close() {
    var d = $("notes-dlg");
    S.open = "";
    if (d && d.open) d.close();
  }

  // ── the links on an alert's page and in a device's drawer ────────
  function panel(box, title, id, gen, cur, withSugg) {
    clear(box);
    box.appendChild(el("div", "label", title));
    var note = el("div", "sub", "loading"), msg = el("div", "sub tri-msg", "");
    var links = el("ol", "lst"), sugg = withSugg ? el("ol", "lst") : null;
    box.appendChild(note);
    box.appendChild(links);
    if (sugg) { box.appendChild(el("div", "label", "possibly related anomalies")); box.appendChild(sugg); }
    box.appendChild(msg);
    var draw = function (rel) {
      if (gen !== cur()) return;
      note.textContent = relNote(rel);
      listLinks(links, sugg, rel, id, msg, function () { read(); });
    };
    var read = function () {
      H.getJSON("/api/frrs/related?id=" + encodeURIComponent(id)).then(draw).catch(function (e) {
        if (gen === cur()) note.textContent = WHY[e && e.message] || F.why(e);
      });
    };
    read();
  }
  function alert(j) {
    var box = $("notes-alert");
    if (!H || !F || !box || !j || typeof j.id !== "string" || !ALERT_RE.test(j.id)) return;
    var gen = ++S.agen;
    box.hidden = false;
    panel(box, "related anomalies", j.id, gen, function () { return S.agen; }, true);
  }
  function drawer(mac) {
    var box = $("notes-drawer");
    if (!H || !F || !box || typeof mac !== "string" || !MAC_RE.test(mac)) return;
    var gen = ++S.dgen;
    panel(box, "anomalies linked to this device", mac, gen, function () { return S.dgen; }, false);
  }

  function init(h) {
    H = h;
    F = window.SlothFrrs && typeof window.SlothFrrs.post === "function" ? window.SlothFrrs : null;
    if (!F || !$("notes-dlg")) return;
    $("notes-close").addEventListener("click", close);
    $("notes-dlg").addEventListener("close", function () { S.open = ""; });
    $("notes-note").addEventListener("input", noteCount);
    $("notes-add").addEventListener("click", function () {
      var id = S.open, to = $("notes-to").value.trim().toLowerCase().replace(/-/g, ":");
      if (!id) return;
      // An alert id keeps its case; only a MAC is folded.
      if (!MAC_RE.test(to)) to = $("notes-to").value.trim();
      if (!REF_RE.test(to)) { $("notes-msg").textContent = WHY.bad_id; return; }
      var b = { op: "add", from: id, to: to }, note = $("notes-note").value.trim();
      if (note) b.note = note;
      if (by()) b.by = by();
      relate(b, $("notes-msg"), function (r) {
        $("notes-to").value = "";
        $("notes-note").value = "";
        noteCount();
        drawRelated(id, r);
      });
    });
  }

  return { init: init, card: card, alert: alert, drawer: drawer, open: open };
})();
