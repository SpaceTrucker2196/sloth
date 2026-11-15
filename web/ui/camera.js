// slothweb: the Camera tab (2026-11-15, web_camera.h). window.SlothCamera,
// one hook app.js calls when the view shows:
//   SlothCamera.show()   loads /api/camera.jpg into cam-img and refreshes
//                        it every REFRESH_MS while the tab is visible
// The still is the capture helper's latest.jpg; slothweb never drives the
// camera. The page loads no subresource (its CSP and the page audit in
// web/tests/test_routes.c): the JPEG is fetched (connect-src 'self'),
// decoded with createImageBitmap() and drawn on a canvas, so there is no
// image element, no image URL and no source-attribute sink. Every string
// shown goes through textContent.
(function () {
  "use strict";
  var REFRESH_MS = 5000;
  var timer = 0, busy = false;

  function $(id) { return document.getElementById(id); }
  function set(id, text) { var e = $(id); if (e) e.textContent = text; }
  function visible() { var v = $("v-camera"); return v && !v.hidden; }
  function when(ts) {
    var d = new Date(ts * 1000), p = function (n) { return (n < 10 ? "0" : "") + n; };
    return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + " " +
      p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
  }

  function load() {
    if (busy) return;
    busy = true;
    var captured = 0, age = -1;
    fetch("api/camera.jpg", { cache: "no-store" }).then(function (r) {
      if (r.status === 404) throw new Error("no image yet: is the camera helper running?");
      if (!r.ok) throw new Error("camera image unavailable (HTTP " + r.status + ")");
      captured = parseInt(r.headers.get("X-Sloth-Captured") || "0", 10);
      age = parseInt(r.headers.get("X-Sloth-Age") || "-1", 10);
      return r.blob();
    }).then(function (b) {
      if (b.type && b.type !== "image/jpeg") throw new Error("not a JPEG");
      return createImageBitmap(b);
    }).then(function (bmp) {
      var c = $("cam-img");
      c.width = bmp.width;
      c.height = bmp.height;
      c.getContext("2d").drawImage(bmp, 0, 0);
      if (bmp.close) bmp.close();
      c.hidden = false;
      set("cam-err", "");
      var meta = captured > 0 ? "captured " + when(captured) : "";
      if (age >= 0) meta += " (" + age + " s ago)";
      set("cam-meta", meta);
      $("cam-meta").classList.toggle("cam-stale", age > 60);
    }).catch(function (e) {
      set("cam-err", e && e.message ? e.message : String(e));
    }).then(function () { busy = false; });
  }

  function tick() {
    timer = 0;
    if (!visible()) return;
    load();
    timer = setTimeout(tick, REFRESH_MS);
  }

  window.SlothCamera = {
    show: function () {
      if (timer) clearTimeout(timer);
      tick();
    }
  };
})();
