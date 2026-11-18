#!/usr/bin/env python3
# The drawer's alert rows, tapped on a phone-sized screen (owner request
# 2026-10-27: tap the drawer's alerts for the alert's full page). Not run
# by CI and not part of `make web-test`: it needs a browser. By hand,
# against a running slothweb (the README's quick start with the demo's
# --pcap-dir is enough):
#
#   python3 -I web/tools/tap_check.py http://127.0.0.1:8770/ [CHROMIUM]
#
# It starts Chromium headless with its DevTools protocol on a loopback
# port, sets a 360 x 740 mobile viewport with touch emulation on, opens
# the Devices view, opens the drawer of the first device whose alerts
# the drawer lists, and taps the first row of "alerts naming it"
# (Input.dispatchTouchEvent: a touch start and end through the
# browser's input pipeline, not a scripted click). It passes
# when the tap opened that alert's page (#alert?id=...), closed the
# drawer (which at this width covers the page), and the page's proof
# section was drawn. Exit 0 on a pass, 1 on a failure, 2 when it could
# not run. The standard library only; nothing leaves the host.
import base64
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request


class CDP:
    """A minimal DevTools client: RFC 6455 text frames over one socket."""

    def __init__(self, ws_url):
        assert ws_url.startswith("ws://")
        hostport, path = ws_url[5:].split("/", 1)
        host, port = hostport.split(":")
        self.s = socket.create_connection((host, int(port)), timeout=30)
        key = base64.b64encode(os.urandom(16)).decode()
        req = ("GET /%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % (path, hostport, key))
        self.s.sendall(req.encode())
        head = b""
        while b"\r\n\r\n" not in head:
            head += self.s.recv(1)
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise RuntimeError("websocket upgrade refused")
        self.n = 0

    def _send(self, text):
        data = text.encode()
        hdr = bytearray([0x81])
        mask = os.urandom(4)
        if len(data) < 126:
            hdr.append(0x80 | len(data))
        elif len(data) < 65536:
            hdr.append(0x80 | 126)
            hdr += struct.pack(">H", len(data))
        else:
            hdr.append(0x80 | 127)
            hdr += struct.pack(">Q", len(data))
        self.s.sendall(bytes(hdr) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def _exact(self, n):
        b = b""
        while len(b) < n:
            c = self.s.recv(n - len(b))
            if not c:
                raise RuntimeError("connection closed")
            b += c
        return b

    def _recv(self):
        msg = b""
        while True:
            h = self._exact(2)
            fin, op, ln = h[0] & 0x80, h[0] & 0x0F, h[1] & 0x7F
            if ln == 126:
                ln = struct.unpack(">H", self._exact(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", self._exact(8))[0]
            payload = self._exact(ln)
            if op == 8:
                raise RuntimeError("connection closed")
            if op in (0, 1):
                msg += payload
                if fin:
                    return json.loads(msg.decode())

    def call(self, method, **params):
        self.n += 1
        self._send(json.dumps({"id": self.n, "method": method, "params": params}))
        while True:
            m = self._recv()
            if m.get("id") == self.n:
                if "error" in m:
                    raise RuntimeError("%s: %s" % (method, m["error"]))
                return m.get("result", {})

    def js(self, expr):
        r = self.call("Runtime.evaluate", expression=expr, returnByValue=True, awaitPromise=True)
        return r.get("result", {}).get("value")


def wait(c, expr, secs=15):
    end = time.time() + secs
    while time.time() < end:
        v = c.js(expr)
        if v:
            return v
        time.sleep(0.25)
    return None


def main():
    if len(sys.argv) < 2:
        print("usage: tap_check.py URL [CHROMIUM]", file=sys.stderr)
        return 2
    url = sys.argv[1].rstrip("/") + "/"
    if not url.startswith("http://127.0.0.1:") and not url.startswith("http://[::1]:"):
        print("tap_check: loopback only", file=sys.stderr)
        return 2
    browser = sys.argv[2] if len(sys.argv) > 2 else (shutil.which("chromium") or shutil.which("chromium-browser"))
    if not browser:
        print("tap_check: no chromium", file=sys.stderr)
        return 2
    prof = tempfile.mkdtemp(prefix="tapcheck.")
    port = 20000 + os.getpid() % 20000
    proc = subprocess.Popen([browser, "--headless=new", "--remote-debugging-address=127.0.0.1",
                             "--remote-debugging-port=%d" % port, "--user-data-dir=" + prof,
                             "--no-first-run", "--no-default-browser-check", "about:blank"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        ws = None
        for _ in range(80):
            try:
                with urllib.request.urlopen("http://127.0.0.1:%d/json/list" % port, timeout=2) as r:
                    pages = [t for t in json.load(r) if t.get("type") == "page"]
                if pages:
                    ws = pages[0]["webSocketDebuggerUrl"]
                    break
            except OSError:
                pass
            time.sleep(0.25)
        if not ws:
            print("tap_check: chromium's DevTools did not answer", file=sys.stderr)
            return 2
        c = CDP(ws)
        c.call("Emulation.setDeviceMetricsOverride", width=360, height=740, deviceScaleFactor=2,
               mobile=True)
        c.call("Emulation.setTouchEmulationEnabled", enabled=True, maxTouchPoints=5)
        c.call("Page.enable")
        c.call("Page.navigate", url=url + "#devices")
        if not wait(c, "document.readyState === 'complete' && !!document.getElementById('ev-alert')"):
            print("tap_check: FAIL: the page did not load")
            return 1
        # The first device whose drawer lists an alert: open drawers in
        # turn (a click: the tap under test is the next one).
        found = wait(c, """(async function () {
          var j = await (await fetch('/api/devices?limit=100')).json();
          for (var i = 0; i < (j.rows || []).length; i++) {
            var mac = j.rows[i].mac;
            var d = await (await fetch('/api/device/' + encodeURIComponent(mac))).json();
            if (d.alerts && d.alerts.some(function (a) { return typeof a.id === 'string'; })) return mac;
          }
          return null;
        })()""", 30)
        if not found:
            print("tap_check: FAIL: no device with an alert in sloth.db to open")
            return 1
        ok = wait(c, """(function () {
          var rows = document.querySelectorAll('#d-rows *');
          for (var i = 0; i < rows.length; i++)
            if (rows[i].textContent.indexOf(%s) >= 0 && rows[i].click) { rows[i].click(); return true; }
          return false;
        })()""" % json.dumps(found))
        if not ok or not wait(c, "!!document.querySelector('#ev-drawer li.go')"):
            print("tap_check: FAIL: the drawer of %s drew no tappable alert row" % found)
            return 1
        rect = c.js("""(function () {
          var li = document.querySelector('#ev-drawer li.go');
          li.scrollIntoView({ block: 'center' });
          var r = li.getBoundingClientRect(), s = getComputedStyle(li, '::after');
          return { x: r.left + r.width / 2, y: r.top + r.height / 2, h: r.height,
                   mark: s.content, coarse: matchMedia('(pointer: coarse)').matches };
        })()""")
        # A touch, start and end at one point, through the browser's
        # input pipeline: the page sees pointerdown, touchstart, touchend
        # and the click the browser makes of a tap, as on a phone.
        c.call("Input.dispatchTouchEvent", type="touchStart",
               touchPoints=[{"x": rect["x"], "y": rect["y"]}])
        time.sleep(0.05)
        c.call("Input.dispatchTouchEvent", type="touchEnd", touchPoints=[])
        after = wait(c, """(function () {
          var h = location.hash, dr = document.getElementById('drawer').hidden;
          var proof = document.getElementById('ev-proof').childNodes.length > 0;
          return h.indexOf('#alert?id=') === 0 && dr && proof ? h : null;
        })()""")
        print("tap_check: viewport 360x740 mobile, touch on; row %.0f px tall (coarse pointer: %s), "
              "mark %s" % (rect["h"], rect["coarse"], rect["mark"]))
        if not after:
            print("tap_check: FAIL: the tap did not open the alert's page with the drawer closed "
                  "(hash %s)" % c.js("location.hash"))
            return 1
        if rect["h"] < 44:
            print("tap_check: FAIL: the row is %.0f px tall, under 44" % rect["h"])
            return 1
        print("tap_check: PASS: the tap opened %s, the drawer closed, the proof drawn" % after)
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(prof, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
