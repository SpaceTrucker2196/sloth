// The sun's phase at the sensor, for G5's cells (owner ruling
// 2026-11-11: the presence strip is coloured night, sunrise, day,
// sunset).
//
//   SlothSun.elev(t, lat, lon)            the sun's elevation, degrees
//   SlothSun.phases(from, cellS, n, pos)  a phase per cell, or null
//   SlothSun.runs(ph)                     the phases as [phase, cell] runs
//   SlothSun.pos(j)                       the sensor's position out of
//                                         an /api/gnss answer, or null
//
// Pure arithmetic: no request, no library, no clock and no DOM, so
// web/tests/test_glyph.c ports it line for line and pins it out of the
// served page, as it does glyph.js. The position is the sensor's and
// only the sensor's. Nothing here reads the browser's zone or asks the
// browser where it is: the viewer may be a continent from the sensor,
// and the page asks the browser for no permission.
var SlothSun = (function () {
  "use strict";
  // Why 6 degrees, both ways. Below -6 the sun is past civil twilight,
  // the almanac's own line between dusk and night. Above +6 the low
  // warm light (the photographer's golden hour, about 6 degrees) is
  // over. Between them is sunrise or sunset, and the band is wide
  // enough to read: at mid latitudes the sun climbs 12 degrees in an
  // hour or so, six or more ten-minute cells, where the almanac's
  // instant of sunrise would be one cell or none.
  var NIGHT_BELOW = -6, DAY_ABOVE = 6;
  // A cell longer than this spans more than one phase too often to be
  // given one: it keeps the single ink.
  var MAX_CELL_S = 3600;
  // 2100-01-01: the year walk below is bounded by it.
  var T_MAX = 4102444800;
  var TOKENS = ["--sun-night", "--sun-rise", "--sun-day", "--sun-set"];
  var WORDS = ["night", "sunrise", "day", "sunset"];
  var RAD = Math.PI / 180;
  function snum(v) { return typeof v === "number" && isFinite(v); }
  function leap(y) { return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0; }

  // NOAA's low-precision solar position (the Global Monitoring
  // Laboratory's "General Solar Position Calculations", after Spencer
  // 1971): the fractional year g gives the equation of time (minutes)
  // and the declination (radians); the hour angle follows from UTC and
  // the longitude, east positive. Good to a minute or two of sunrise,
  // against cells of ten. Geometric: no refraction, the centre of the
  // disc. t is unix seconds, 0 to T_MAX.
  function elev(t, lat, lon) {
    var day = Math.floor(t / 86400), sec = t - day * 86400, y = 1970, len = 365;
    while (day >= len) { day -= len; y++; len = leap(y) ? 366 : 365; }
    var g = 2 * Math.PI / len * (day + (sec / 3600 - 12) / 24);
    var eq = 229.18 * (0.000075 + 0.001868 * Math.cos(g) - 0.032077 * Math.sin(g) -
                       0.014615 * Math.cos(2 * g) - 0.040849 * Math.sin(2 * g));
    var dec = 0.006918 - 0.399912 * Math.cos(g) + 0.070257 * Math.sin(g) -
              0.006758 * Math.cos(2 * g) + 0.000907 * Math.sin(2 * g) -
              0.002697 * Math.cos(3 * g) + 0.00148 * Math.sin(3 * g);
    var ha = (sec / 60 + eq + 4 * lon) / 4 - 180;
    var s = Math.sin(lat * RAD) * Math.sin(dec) +
            Math.cos(lat * RAD) * Math.cos(dec) * Math.cos(ha * RAD);
    return Math.asin(s < -1 ? -1 : s > 1 ? 1 : s) / RAD;
  }

  // 0 night, 1 sunrise, 2 day, 3 sunset, at t. Rising or setting is the
  // sign of the elevation's change across the cell (half a cell either
  // side of t), so a polar day, a polar night, a night that never gets
  // darker than twilight and a noon that never clears it need no case
  // of their own: the first two never reach the comparison, the others
  // turn from setting to rising at the sun's lowest and back at its
  // highest.
  function phase(t, half, lat, lon) {
    var e = elev(t, lat, lon);
    if (e < NIGHT_BELOW) return 0;
    if (e > DAY_ABOVE) return 2;
    return elev(t + half, lat, lon) >= elev(t - half, lat, lon) ? 1 : 3;
  }

  // A phase for each of n cells of cellS seconds from `from`, taken at
  // each cell's midpoint; null when there is no position, the cell is
  // over MAX_CELL_S, or the window is not one this can answer. Kept by
  // (position to 0.01 degree, from, cellS, n): a table's rows share one
  // window, so its repaint is a lookup and not 144 positions a row. A
  // hundredth of a degree is about a kilometre and under three seconds
  // of sun, so a sensor in a car does not empty the table at every fix.
  var CACHE_MAX = 16, cache = {}, cached = 0;
  function okPos(lat, lon) {
    return snum(lat) && snum(lon) && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;
  }
  function phases(from, cellS, n, pos) {
    if (!pos || !okPos(pos.lat, pos.lon)) return null;
    if (!snum(from) || from < 0 || !(cellS > 0) || cellS > MAX_CELL_S) return null;
    if (!(n >= 1) || n > 1440 || from + n * cellS > T_MAX) return null;
    var lat = Math.round(pos.lat * 100) / 100, lon = Math.round(pos.lon * 100) / 100;
    var key = lat + "," + lon + "," + from + "," + cellS + "," + n;
    if (cache[key]) return cache[key];
    var out = [], half = cellS / 2;
    for (var i = 0; i < n; i++) out.push(phase(from + i * cellS + half, half, lat, lon));
    if (cached >= CACHE_MAX) { cache = {}; cached = 0; }
    cache[key] = out;
    cached++;
    return out;
  }

  // The phases as runs, [phase, first cell], oldest first: what the
  // ruler draws and what a strip's label says in words (R10).
  function runs(ph) {
    var out = [];
    for (var i = 0; ph && i < ph.length; i++)
      if (!i || ph[i] !== ph[i - 1]) out.push([ph[i], i]);
    return out;
  }

  // The sensor's position out of an /api/gnss answer: the newest fix
  // when it is a 2D or 3D one, else the position sensor_health carries
  // (the last fix, or --location), else null. A value out of range is
  // no position, never a clamped one.
  function pos(j) {
    var f = j && j.fix, l = j && j.loc;
    if (f && snum(f.mode) && f.mode >= 2 && okPos(f.lat, f.lon))
      return { lat: f.lat, lon: f.lon, from: "gps fix" };
    if (l && okPos(l.lat, l.lon) && (l["src"] === "gps" || l["src"] === "fixed"))
      return { lat: l.lat, lon: l.lon, from: l["src"] === "gps" ? "last gps fix" : "--location" };
    return null;
  }

  return { elev: elev, phase: phase, phases: phases, runs: runs, pos: pos,
           TOKENS: TOKENS, WORDS: WORDS, NIGHT_BELOW: NIGHT_BELOW, DAY_ABOVE: DAY_ABOVE,
           MAX_CELL_S: MAX_CELL_S };
})();
