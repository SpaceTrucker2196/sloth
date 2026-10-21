// slothweb M0 client: the tick strip, from the /events stream, and one
// /api/health read. Same-origin relative paths only; the page's CSP
// (connect-src 'self') refuses anything else.
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };

  function set(id, text) { $(id).textContent = text; }

  function state(cls, word) {
    var d = $("dot");
    d.className = "dot " + cls;
    set("conn", word);
  }

  function dur(s) {
    if (s < 60) return s + "s";
    if (s < 3600) return Math.floor(s / 60) + "m" + (s % 60) + "s";
    return Math.floor(s / 3600) + "h" + Math.floor((s % 3600) / 60) + "m";
  }

  var es = new EventSource("/events");
  state("wait", "connecting");
  es.onopen = function () { state("ok", "live"); };
  es.onerror = function () { state("down", "retrying"); };
  es.addEventListener("tick", function (ev) {
    var t;
    try { t = JSON.parse(ev.data); } catch (e) { return; }
    state("ok", "live");
    set("seq", String(t.seq));
    set("hero", String(t.seq));
    set("up", dur(t.uptime_s));
    set("clients", String(t.sse_clients));
  });

  fetch("/api/health", { cache: "no-store" })
    .then(function (r) { return r.json(); })
    .then(function (h) {
      set("sock", h.socket);
      set("db", h.db);
      set("milestone", h.milestone);
    })
    .catch(function () { set("db", "?"); });

  document.addEventListener("keydown", function (e) {
    if (e.target !== document.body) return;
    if (e.key === "[") $("app").classList.toggle("collapsed");
  });
})();
