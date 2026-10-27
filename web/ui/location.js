// slothweb: where the sensor was (sloth --location / --gps, 2026-10-27).
// window.SlothLocation, two hooks app.js calls, one per view:
//   SlothLocation.alert(j)   on an alert's page, with /api/alert's
//                            answer: fills #loc-alert from j.loc
//   SlothLocation.drawer(mac) when the device drawer opens: fills
//                            #loc-drawer from /api/positions
// Same-origin relative paths only, values shown with textContent, no
// map tiles: the drawer's picture is a Canvas 2D scatter on a local
// equirectangular projection, so the page still asks its own server
// and nothing else. A sample is where the SENSOR was when it heard the
// device (sloth has no bearing), and the page says so. The exports are
// the same route as attachments: a button navigates to it, and the
// browser saves the file and stays on the page.
(function () {
  "use strict";
  var M_PER_DEG = 111195.08;   // the mean sphere src/gps.c measures on

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function okLoc(l) {
    return l && num(l.lat) && num(l.lon) && l.lat >= -90 && l.lat <= 90 &&
           l.lon >= -180 && l.lon <= 180 && ["gps", "fixed"].indexOf(l.src) >= 0;
  }
  function stamp(ts) {
    if (!num(ts) || ts <= 0) return "?";
    return new Date(ts * 1000).toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
  }
  function coords(l) { return l.lat.toFixed(7) + ", " + l.lon.toFixed(7); }

  function copyButton(text) {
    var b = el("button", "", "copy");
    b.type = "button";
    b.title = "copy the coordinates";
    b.addEventListener("click", function () {
      if (navigator.clipboard && navigator.clipboard.writeText)
        navigator.clipboard.writeText(text).then(function () { b.textContent = "copied"; },
                                                 function () { b.textContent = "copy failed"; });
    });
    return b;
  }

  function alertHook(j) {
    var box = $("loc-alert");
    if (!box) return;
    clear(box);
    var l = j && j.loc;
    if (!okLoc(l)) { box.hidden = true; return; }
    box.hidden = false;
    var lab = el("div", "label", "where the sensor was ");
    lab.appendChild(el("span", "sub", ["gps"].indexOf(l.src) === 0
      ? "GPS fix of " + stamp(l.ts) + ", as the incident opened"
      : "the fixed --location the sensor was given"));
    box.appendChild(lab);
    var line = el("div", "loc-line");
    line.appendChild(el("span", "d-bright", coords(l)));
    if (num(l.acc_m)) line.appendChild(el("span", "d-normal", "  ±" + Math.round(l.acc_m) + " m (estimate)"));
    if (num(l.alt_m)) line.appendChild(el("span", "d-dim", "  alt " + Math.round(l.alt_m) + " m"));
    line.appendChild(copyButton(coords(l)));
    box.appendChild(line);
  }

  function heatVar(rssi) {
    if (!num(rssi)) return "--heat-0";
    var f = (rssi + 95) / 60;       // -95 dBm faint .. -35 dBm strong
    return f < 0.15 ? "--heat-0" : f < 0.40 ? "--heat-1" : f < 0.70 ? "--heat-2" : "--heat-3";
  }
  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";
  }

  // Metres east and north of the samples' mean: x = dlon cos(lat0),
  // y = dlat, both on the mean sphere. Good to well under a metre over
  // the few kilometres a drive-by covers, which is all this draws.
  function scatter(pos, track) {
    var all = pos.concat(track), lat0 = 0, lon0 = 0;
    all.forEach(function (p) { lat0 += p.lat; lon0 += p.lon; });
    lat0 /= all.length; lon0 /= all.length;
    var k = Math.cos(lat0 * Math.PI / 180);
    function xy(p) { return [(p.lon - lon0) * k * M_PER_DEG, (p.lat - lat0) * M_PER_DEG]; }
    var span = 1;
    all.forEach(function (p) { var v = xy(p); span = Math.max(span, Math.abs(v[0]), Math.abs(v[1])); });
    var cv = el("canvas", "loc-map");
    var W = 360, H = 220, pad = 16, dpr = window.devicePixelRatio || 1;
    cv.width = W * dpr;
    cv.height = H * dpr;
    cv.style.width = W + "px";
    cv.style.height = H + "px";
    cv.title = "where the sensor was when it heard the device, metres from the mean, north up";
    var s = (Math.min(W, H) / 2 - pad) / span;
    function px(p) { var v = xy(p); return [W / 2 + v[0] * s, H / 2 - v[1] * s]; }
    var c = cv.getContext("2d");
    if (!c) return cv;
    c.scale(dpr, dpr);
    c.strokeStyle = cssVar("--tui-dim");
    c.strokeRect(0.5, 0.5, W - 1, H - 1);
    if (track.length > 1) {
      c.strokeStyle = cssVar("--tui-normal");
      c.lineWidth = 1.5;
      c.beginPath();
      track.slice().reverse().forEach(function (p, i) {
        var v = px(p);
        if (i) c.lineTo(v[0], v[1]); else c.moveTo(v[0], v[1]);
      });
      c.stroke();
    }
    pos.forEach(function (p) {
      var v = px(p);
      c.fillStyle = cssVar(heatVar(p.rssi));
      c.beginPath();
      c.arc(v[0], v[1], 3, 0, 2 * Math.PI);
      c.fill();
    });
    c.fillStyle = cssVar("--tui-dim");
    c.font = "10px monospace";
    c.fillText("\u00b1" + Math.round(span) + " m around " + lat0.toFixed(5) + ", " +
               lon0.toFixed(5) + "; N up", 4, H - 4);
    return cv;
  }

  var gen = 0;
  function drawerHook(mac) {
    var box = $("loc-drawer");
    if (!box) return;
    var g = ++gen;
    clear(box);
    box.hidden = true;
    if (typeof mac !== "string") return;
    var q = "/api/positions?mac=" + encodeURIComponent(mac);
    fetch(q, { credentials: "same-origin" }).then(function (r) {
      return r.ok ? r.json() : null;
    }).then(function (j) {
      if (g !== gen || !j || !Array.isArray(j.positions)) return;
      var pos = j.positions.filter(okPos), track = Array.isArray(j.track) ? j.track.filter(okPos) : [];
      if (!pos.length) return;
      box.hidden = false;
      var lab = el("div", "label", "where the sensor was when it heard it ");
      lab.appendChild(el("span", "sub", pos.length + " samples" + (j.more ? ", newest only" : "") +
                         "; the sensor's position, not the device's"));
      box.appendChild(lab);
      box.appendChild(scatter(pos, track));
      var links = el("div", "sub", "export: ");
      [["GeoJSON", "geojson"], ["GPX", "gpx"]].forEach(function (f) {
        var b = el("button", "", f[0]);
        b.type = "button";
        b.title = "save the samples and the sensor's track as " + f[0];
        b.addEventListener("click", function () { window.location.assign(q + "&format=" + f[1]); });
        links.appendChild(b);
      });
      box.appendChild(links);
    }).catch(function () { /* no positions: the section stays hidden */ });
  }
  function okPos(p) {
    return p && num(p.lat) && num(p.lon) && p.lat >= -90 && p.lat <= 90 && p.lon >= -180 && p.lon <= 180;
  }

  window.SlothLocation = { alert: alertHook, drawer: drawerHook };
})();
