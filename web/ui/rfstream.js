// Where the RF tabs' records come from (#216, docs/wiki/slothweb.md "The
// RF stream's state"). Since JSONL 2.0.0 sloth-wifi's stream has no
// ADS-B, APRS, rtl_433 or Victron record: they are sloth-rf's, read on
// --rf-socket. A slothweb with a 2.x sloth-wifi on --socket and no
// --rf-socket would otherwise show four empty tabs and no reason; the
// server says which case it is ("rf_stream" on /api/health and on each
// RF tab's answer, web_live.h) and this is the page's one wording of it.
// One namespace, no DOM: every caller puts the text in with textContent
// or el(), as it does its own.
(function () {
  "use strict";

  // ── the pure half: web/tests/test_twodaemon.c pins these out of the page ──
  function notConfigured(j) {
    return !!(j && j.rf_stream && j.rf_stream.state === "not_configured");
  }
  // "" unless the RF daemon's stream is not configured. `what` is the
  // tab's own records, in its own words ("ADS-B", "rtl_433").
  function text(j, what) {
    if (!notConfigured(j)) return "";
    var v = j.rf_stream.sensor_jsonl_version;
    return "RF daemon not configured: this slothweb reads sloth-wifi's stream" +
      (v ? " (JSONL " + v + ")" : "") + ", which has carried no " + what +
      " records since the sloth-wifi / sloth-rf split (JSONL 2.0.0). They are sloth-rf's: " +
      "start slothweb with --rf-socket (and --rf-db) pointing at it, docs/wiki/deployment.md section 11";
  }
  // One line for the health page, for every state the server names.
  function sourceText(r) {
    if (!r) return null;
    var v = r.sensor_jsonl_version ? "JSONL " + r.sensor_jsonl_version : r.reading || "no version yet";
    if (r.state === "rf_socket") return "sloth-rf's stream (--rf-socket)";
    if (r.state === "sensor_stream")
      return "the sensor's own stream (" + v + ", an unsplit sensor: its decoders' records are on --socket)";
    if (r.state === "rf_daemon_on_socket") return "sloth-rf's stream, on --socket (" + v + ")";
    if (r.state === "not_configured")
      return "NOT CONFIGURED: --socket is sloth-wifi's stream (" + v +
        "), which has no ADS-B, APRS, rtl_433 or Victron records; give slothweb --rf-socket (and --rf-db) for sloth-rf";
    return "not known: no sensor_health on --socket yet";
  }
  // Which contract --socket's stream is. The server names the stream's
  // own MAJOR; this build reads 1.x and 2.x, and says so of any other
  // rather than passing it off as one of those.
  function readingText(r) {
    var rd = r && r.reading;
    if (!rd) return null;
    if (rd === "1.x" || rd === "2.x" || rd === "before 1.0.0") return rd;
    return rd + " (a JSONL MAJOR this slothweb does not know; it reads 1.x and 2.x, so what it shows of this stream may be wrong: upgrade slothweb)";
  }

  window.SlothRfStream = { notConfigured: notConfigured, text: text, sourceText: sourceText, readingText: readingText };
})();
