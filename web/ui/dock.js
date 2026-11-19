// The detail column (owner request 2026-11-19): what used to slide in
// from the right as a drawer is a column a quarter of the page wide,
// beside the views, that lists every detail opened and not yet closed.
//
//   SlothDock.init(h)             once, from app.js; h: el, getJSON,
//                                 keyColor, shortStamp, prefGet, prefSet,
//                                 relayout, kinds
//   SlothDock.opened(kind, args, title)
//                                 an opener's first call: the detail of
//                                 (kind, args) is this kind's open card
//   SlothDock.closed(kind)        a close function's last call
//   SlothDock.esc(kind)           may Esc close this kind's open card?
//   SlothDock.yield()             something else takes the screen
//   SlothDock.overlay()           the narrow layout, where the column
//                                 lies over the page
//
// A kind (device, ble, ssid, karma) keeps its one detail element, the
// <aside class="drawer"> index.html has always had, and its own open
// and close functions; nothing they draw is drawn here. A card is one
// detail in the list. The kind's element sits in the card that is open;
// every other card of that kind is one line (its name and a summary).
// So one detail of each kind is open at a time and any number are kept
// as lines: opening a line folds the open one of its kind into a line.
//
// Kept current: an open card is asked again by its own opener every
// REFRESH_S, a line's summary every SUMMARY_S, one request a tick, and
// neither while the tab is hidden or the column is folded to its rail.
// Nothing here writes markup: every node is createElement and
// textContent.
(function () {
  "use strict";

  var TICK_MS = 3000, REFRESH_S = 15, SUMMARY_S = 30, MAX = 24;
  var H = null, K = {}, CARDS = [];
  var S = { quiet: false, folding: false, min: false, timer: 0 };
  var MQ = window.matchMedia ? window.matchMedia("(max-width: 900px)") : null;

  function $(id) { return document.getElementById(id); }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function overlay() { return !!(MQ && MQ.matches); }
  function now() { return Date.now() / 1000; }

  function find(kind, key) {
    for (var i = 0; i < CARDS.length; i++)
      if (CARDS[i].kind === kind && CARDS[i].key === key) return CARDS[i];
    return null;
  }
  function openCard(kind) {
    for (var i = 0; i < CARDS.length; i++)
      if (CARDS[i].kind === kind && !CARDS[i].min) return CARDS[i];
    return null;
  }

  // ── what the page keeps: the cards and the column's fold ───────────
  function save() {
    if (!H) return;
    H.prefSet("dock", { min: S.min, cards: CARDS.map(function (c) {
      return { k: c.kind, a: c.args, t: c.title };
    }) });
  }
  function okArgs(a) {
    if (!Array.isArray(a) || !a.length || a.length > 3) return false;
    for (var i = 0; i < a.length; i++)
      if (a[i] !== null && typeof a[i] !== "number" && (typeof a[i] !== "string" || a[i].length > 128))
        return false;
    return true;
  }

  // ── the column ─────────────────────────────────────────────────────
  function count() {
    var n = CARDS.length;
    $("dock-n").textContent = n ? String(n) : "";
    $("dock-all").hidden = !n;
    $("dock-empty").hidden = !!n;
    $("dock").classList.toggle("empty", !n);
    var t = $("dock-toggle");
    t.textContent = S.min ? "details" + (n ? " " + n : "") : "minimize";
    t.title = S.min ? "show the detail column" : "fold the detail column to the page's edge";
    t.ariaExpanded = S.min ? "false" : "true";
  }
  function fold(min, quietly) {
    if (S.min === min) return;
    S.min = min;
    $("dock").classList.toggle("min", min);
    count();
    save();
    // The views' canvases are as wide as they were drawn: the page is
    // told its width changed, and draws the view again.
    // Deferred: a fold made by an opener is not that opener's to draw
    // the view under.
    if (!overlay()) setTimeout(function () {
      window.dispatchEvent(new Event("resize"));
      if (H.relayout) H.relayout();
    }, 0);
    if (!min && !quietly) tick();
  }

  // ── a card ─────────────────────────────────────────────────────────
  function paint(c) {
    c.el.classList.toggle("min", c.min);
    c.go.ariaExpanded = c.min ? "false" : "true";
  }
  function make(kind, key, args, title) {
    var k = K[kind];
    var c = { kind: kind, key: key, args: args, title: title, min: true, sumAt: 0, refAt: 0 };
    c.el = el("section", "dcard min");
    c.el.ariaLabel = k.word + " " + title;
    var row = el("div", "dcard-mini");
    c.go = el("button", "dcard-go");
    c.go.type = "button";
    c.go.title = "open this detail";
    c.go.appendChild(el("span", "dcard-k", k.word));
    if (k.swatch) {
      var sw = el("span", "sw");
      sw.style.background = H.keyColor(String(args[0]));
      c.go.appendChild(sw);
    }
    c.go.appendChild(el("b", "", title));
    c.line = el("span", "sub dcard-line", "");
    c.go.appendChild(c.line);
    c.go.addEventListener("click", function () { K[c.kind].open(c.args); });
    var x = el("button", "dcard-x", "close");
    x.type = "button";
    x.title = "take it off the list";
    x.addEventListener("click", function () { remove(c); });
    row.appendChild(c.go);
    row.appendChild(x);
    c.body = el("div", "dcard-body");
    c.el.appendChild(row);
    c.el.appendChild(c.body);
    CARDS.push(c);
    $("dock-list").appendChild(c.el);
    // The list is bounded: the oldest line goes for the newest card.
    if (CARDS.length > MAX)
      for (var i = 0; i < CARDS.length; i++)
        if (CARDS[i].min && CARDS[i] !== c) { remove(CARDS[i]); break; }
    return c;
  }
  function remove(c) {
    var i = CARDS.indexOf(c);
    if (i < 0) return;
    var k = K[c.kind];
    if (!c.min) {
      // The kind's own close: its selection, its focus; it calls
      // closed(), which comes back here with the card folded.
      c.min = true;
      k.close();
    }
    // The kind's element outlives the card.
    if (k.aside.parentNode === c.body) { k.aside.hidden = true; $("app").appendChild(k.aside); }
    CARDS.splice(i, 1);
    if (c.el.parentNode) c.el.parentNode.removeChild(c.el);
    count();
    save();
  }
  function toLine(c) {
    c.min = true;
    paint(c);
    summary(c);
  }

  // An opener's first call. The kind's element moves into the card of
  // what is being opened; the card that held it becomes a line.
  function opened(kind, args, title) {
    var k = K[kind];
    if (!H || !k) return;
    var key = JSON.stringify(args), c = find(kind, key), cur = openCard(kind);
    if (cur && cur !== c) toLine(cur);
    if (!c) c = make(kind, key, args, String(title));
    if (k.aside.parentNode !== c.body) c.body.appendChild(k.aside);
    if (c.min) { c.min = false; paint(c); }
    c.refAt = now();
    count();
    if (S.quiet) return;
    save();
    fold(false, true);
    // After the opener has shown the element and focused its close.
    setTimeout(function () {
      if (c.el.parentNode && c.el.scrollIntoView) c.el.scrollIntoView({ block: "nearest" });
    }, 0);
  }
  // A close function's last call: the card goes, unless the close was
  // the fold of its card to a line.
  function closed(kind) {
    var c = openCard(kind);
    if (!c) return;
    if (S.folding) { toLine(c); return; }
    c.min = true;
    remove(c);
  }
  function minimise(kind) {
    if (!openCard(kind)) return;
    S.folding = true;
    try { K[kind].close(); } finally { S.folding = false; }
    save();
  }

  // Esc closes the card the focus is in, and no other. In the narrow
  // layout it folds the column instead (the listener in init()).
  function esc(kind) {
    var k = K[kind];
    if (!k || overlay()) return false;
    return !k.aside.hidden && k.aside.contains(document.activeElement);
  }
  // An alert's page or another view opened from a detail. Beside the
  // page the column covers nothing and stays; over it, it folds.
  function yieldScreen() { if (overlay()) fold(true); }

  // ── kept current ───────────────────────────────────────────────────
  // What a line says: the kind's own answer, asked for the summary
  // alone.
  var SUM = {
    device: function (a) {
      return H.getJSON("/api/device/" + encodeURIComponent(a[0])).then(function (j) {
        var r = j.record, p = [];
        if (j.fleet && j.fleet.remote === true) return "another host's";
        if (r && typeof r.name === "string") p.push(r.name);
        else if (j.oui && j.oui.found && typeof j.oui.vendor === "string") p.push(j.oui.vendor);
        if (r && num(r.signal) && r.signal < 0) p.push(r.signal + " dBm");
        if (r && num(r.last_seen)) p.push("seen " + H.shortStamp(r.last_seen));
        return p.length ? p.join(" · ") : "no sloth.db record";
      });
    },
    ble: function (a) {
      var p = "/api/ble/" + encodeURIComponent(a[0]) + (a[1] === null ? "" :
              "?type=" + encodeURIComponent(String(a[1])) + "&iface=" + encodeURIComponent(String(a[2])));
      return H.getJSON(p).then(function (j) {
        var d = j.rows && j.rows.length ? j.rows[0] : null, o = [];
        if (!d) return j.fleet && j.fleet.remote ? "another host's" : "left the table";
        if (typeof d.name === "string") o.push(d.name);
        else if (typeof d.mfr_name === "string") o.push(d.mfr_name);
        if (num(d.rssi)) o.push(d.rssi + " dBm");
        if (num(d.last_seen)) o.push("seen " + H.shortStamp(d.last_seen));
        return o.join(" · ");
      });
    },
    ssid: function (a) {
      var p = window.SlothSsid ? window.SlothSsid.param(a[0] === null ? undefined : a[0]) : null;
      if (p === null) return Promise.resolve("no detail");
      return H.getJSON("/api/wifi/ssid?ssid=" + encodeURIComponent(p)).then(function (j) {
        if (j.out_of_scope) return "nothing under this scope";
        var n = (j.bssids || []).length, t = j.bssids_more && num(j.bssids_total) ? j.bssids_total : n;
        return t + (t === 1 ? " access point" : " access points");
      });
    },
    karma: function (a) {
      return H.getJSON("/api/lures/bssid?bssid=" + encodeURIComponent(a[0])).then(function (j) {
        if (j.out_of_scope) return "nothing under this scope";
        var kk = window.SlothKarma;
        return kk && kk.held(j) ? kk.lineText(j) : "nothing held";
      });
    }
  };
  function summary(c) {
    c.sumAt = now();
    var f = SUM[c.kind];
    if (!f) return;
    f(c.args).then(function (t) { c.line.textContent = String(t); })
             .catch(function () { c.line.textContent = "no answer"; });
  }

  // Someone is typing, or has text selected, in the card: it is not
  // drawn again under them.
  function busy(c) {
    var as = K[c.kind].aside, a = document.activeElement;
    if (a && as.contains(a) && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName)) return true;
    var sel = window.getSelection ? window.getSelection() : null;
    if (sel && !sel.isCollapsed && sel.anchorNode && as.contains(sel.anchorNode)) return true;
    return !!document.querySelector("dialog[open]");
  }
  // The opener draws the card again. It takes the focus and empties
  // what it is about to fill: the focus is put back, and the card keeps
  // its height until the answer is drawn, so the list does not jump.
  function refresh(c) {
    var list = $("dock-list"), top = list.scrollTop, a = document.activeElement;
    c.el.style.minHeight = c.el.offsetHeight + "px";
    S.quiet = true;
    try { K[c.kind].open(c.args); } finally { S.quiet = false; }
    if (a && a !== document.activeElement && document.body.contains(a) && a.focus) a.focus({ preventScroll: true });
    list.scrollTop = top;
    setTimeout(function () { c.el.style.minHeight = ""; }, 2500);
  }
  function tick() {
    if (!H || document.hidden || S.min) return;
    var t = now(), i, c, due = null;
    for (i = 0; i < CARDS.length; i++) {
      c = CARDS[i];
      if (!c.min && t - c.refAt >= REFRESH_S && !busy(c) && (!due || c.refAt < due.refAt)) due = c;
    }
    if (due) { due.refAt = t; refresh(due); return; }
    for (i = 0; i < CARDS.length; i++) {
      c = CARDS[i];
      if (c.min && t - c.sumAt >= SUMMARY_S && (!due || c.sumAt < due.sumAt)) due = c;
    }
    if (due) summary(due);
  }

  function init(h) {
    var dock = $("dock");
    if (!dock || !h || !h.kinds) return;
    H = h;
    Object.keys(h.kinds).forEach(function (name) {
      var d = h.kinds[name], aside = $(d.aside), x = $(d.closeBtn);
      if (!aside || !x) return;
      K[name] = { aside: aside, word: d.word, swatch: !!d.swatch, open: d.open, close: d.close };
      // The fold to a line, beside the element's own close.
      var m = el("button", "dk-min", "minimize");
      m.type = "button";
      m.title = "keep it in the list as one line";
      m.addEventListener("click", function () { minimise(name); });
      x.parentNode.insertBefore(m, x);
    });
    $("dock-toggle").addEventListener("click", function () { fold(!S.min); });
    $("dock-all").addEventListener("click", function () {
      while (CARDS.length) remove(CARDS[CARDS.length - 1]);
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && overlay() && !S.min && CARDS.length) fold(true);
    });
    // The column sticks under the top bar, whatever the bar's height,
    // and ends at the window's foot: at the page's top, where the
    // status strip is still above it, it is that much shorter.
    var bar = document.querySelector(".topbar"), work = $("work");
    function top() {
      var t = bar ? bar.offsetHeight : 0;
      work.style.setProperty("--dock-top", t + "px");
      work.style.setProperty("--dock-h", Math.max(120, window.innerHeight - Math.max(t, work.getBoundingClientRect().top)) + "px");
    }
    top();
    if (bar && window.ResizeObserver) new ResizeObserver(top).observe(bar);
    window.addEventListener("resize", top);
    window.addEventListener("scroll", top, { passive: true });
    // What the last load left: every card a line, asked for its
    // summary a tick at a time.
    var kept = h.prefGet("dock");
    if (kept && typeof kept === "object") {
      S.min = kept.min === true;
      dock.classList.toggle("min", S.min);
      (Array.isArray(kept.cards) ? kept.cards : []).slice(0, MAX).forEach(function (r) {
        if (!r || !K[r.k] || !okArgs(r.a) || typeof r.t !== "string" || r.t.length > 128) return;
        var key = JSON.stringify(r.a);
        if (!find(r.k, key)) make(r.k, key, r.a, r.t);
      });
    }
    count();
    S.timer = setInterval(tick, TICK_MS);
    document.addEventListener("visibilitychange", function () { if (!document.hidden) tick(); });
  }

  window.SlothDock = { init: init, opened: opened, closed: closed, esc: esc,
                       "yield": yieldScreen, overlay: overlay };
})();
