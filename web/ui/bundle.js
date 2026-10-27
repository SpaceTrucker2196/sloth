// The "copy JSON" control of every detail view (owner request
// 2026-10-27): fetches /api/bundle for the view's kind and id, puts the
// document on the clipboard, and offers it as a download. Its own
// module so the views' code (app.js) carries one call per view:
//   SlothBundle.mount(container, kind, id, scoped)
// container is the element the control lives in (re-mounting with a new
// id updates the control in place), kind the bundle's kind word (device,
// alert, lookup; ble and platform once their slices land), id the view's
// folded id, scoped app.js's path-with-scope function (optional: app.js
// keeps the scope private). The copy button's id is "bundle-btn-" and
// the view's slot (drawer for a device, alert, lookup), the names
// agreed with the slices that share these views.
// Every node is built with createElement and textContent: the bundle is
// data, never markup. No setting is kept: there is nothing to keep.
// The clipboard wants the write inside the click: Firefox's execCommand
// and Safari's writeText refuse one made after an awaited fetch. So the
// bundle is fetched when the pointer or focus reaches the button, and a
// click that finds it ready copies at once; one that does not hands
// ClipboardItem the fetch as a promise where it exists, and otherwise
// fetches and asks for a second click.
window.SlothBundle = (function () {
  "use strict";

  var ERR = {
    "bad_id": "no such id for this kind",
    "bad_mac": "not a MAC",
    "bad_lookup": "not a MAC or an IP",
    "bad_kind": "unknown bundle kind",
    "kind_not_built": "this build has no bundle for that kind yet",
    "no_such_alert": "no such alert: it may have closed and left the stream",
    "no_sloth_db": "no sloth.db: start slothweb with --sloth-db PATH",
    "sloth_db_timeout": "sloth.db was too slow to answer; try again",
    "sloth_db_error": "sloth.db could not be read just now",
    "bundle_too_large": "the bundle would exceed its size cap"
  };
  function errText(m) {
    return Object.prototype.hasOwnProperty.call(ERR, m) ? ERR[m] : "error: " + m;
  }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = String(text);
    return e;
  }

  // The view word of the address, for page.view.
  function viewWord() {
    var m = /^#([a-z]+)/.exec(String(location.hash || ""));
    return m ? m[1] : null;
  }

  function kb(text) { return Math.max(1, Math.round(text.length / 1024)); }

  function fetchBundle(path) {
    return fetch(path, { cache: "no-store" }).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok) throw new Error(j && typeof j.error === "string" ? j.error : String(r.status));
        return j;
      });
    });
  }

  // The clipboard: navigator.clipboard where the page is a secure
  // context (localhost, https); elsewhere (plain http over a tunnel or
  // Tailscale) it is absent, and a selected hidden textarea with
  // execCommand("copy") is what works. Resolves true when the text was
  // copied.
  function copyText(text) {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      return navigator.clipboard.writeText(text).then(function () { return true; },
                                                    function () { return copyLegacy(text); });
    }
    return Promise.resolve(copyLegacy(text));
  }
  function copyLegacy(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.readOnly = true;
    ta.style.position = "fixed";
    ta.style.top = "0";
    ta.style.left = "0";
    ta.style.width = "1px";
    ta.style.height = "1px";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    var ok = false;
    try {
      ta.focus();
      ta.select();
      ta.setSelectionRange(0, text.length);
      ok = document.execCommand("copy") === true;
    } catch (e) { ok = false; }
    document.body.removeChild(ta);
    return ok;
  }

  // slothweb-<kind>-<id>-<ts>.json: the id with ':' as '-' and anything
  // outside [A-Za-z0-9._-] dropped.
  function fileName(kind, id, ts) {
    var safe = String(id).replace(/:/g, "-").replace(/[^A-Za-z0-9._-]/g, "");
    return "slothweb-" + kind + "-" + safe + "-" + ts + ".json";
  }

  function download(text, name) {
    var blob = new Blob([text], { type: "application/json" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob); /* sink: blob url, constant origin */
    a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }

  // A fetched bundle is copied as is for this long, then fetched again:
  // the views re-render live, and a copy is of the view now.
  var FRESH_MS = 10000;

  // The control's request now: kind, id and the scope in effect, so a
  // scope switch on the same id is a different bundle.
  function pathOf(st) {
    var path = "/api/bundle?kind=" + encodeURIComponent(st.kind) + "&id=" + encodeURIComponent(st.id);
    if (typeof st.scoped === "function") path = st.scoped(path);
    return path;
  }

  // The kept text when it answers the control's request now and is
  // fresh, else null.
  function ready(st) {
    return st.text !== null && st.path === pathOf(st) && Date.now() - st.at < FRESH_MS
      ? st.text : null;
  }

  // The bundle for the control's request now: the kept one while ready,
  // the one in flight for the same request, or a new fetch. An answer
  // for a request the control has moved past is refused ("stale").
  function load(st) {
    if (ready(st) !== null) return Promise.resolve(st);
    var path = pathOf(st);
    if (st.pending && st.pendingPath === path) return st.pending;
    st.pendingPath = path;
    st.pending = fetchBundle(path).then(function (j) {
      if (st.pendingPath === path) st.pending = null;
      if (pathOf(st) !== path) throw new Error("stale");
      if (!j.page || typeof j.page !== "object") j.page = {};
      j.page.url = location.href;
      j.page.view = viewWord();
      // Indented: a person and Claude read it; size is not the constraint.
      st.text = JSON.stringify(j, null, 1);
      st.path = path;
      st.at = Date.now();
      st.ts = j.generated_at && typeof j.generated_at.unix === "number" ? j.generated_at.unix : 0;
      return st;
    }, function (e) {
      if (st.pendingPath === path) st.pending = null;
      throw e;
    });
    return st.pending;
  }

  // ClipboardItem with a promised body keeps the click's activation
  // across the fetch (Safari, Chromium); a secure context only.
  function canClipItem() {
    return typeof window.ClipboardItem === "function" && navigator.clipboard &&
      typeof navigator.clipboard.write === "function";
  }

  var SLOT = { device: "drawer", alert: "alert", lookup: "lookup" };

  function mount(host, kind, id, scoped) {
    if (!host || typeof kind !== "string" || typeof id !== "string" || id === "") return;
    var box = null;
    for (var i = 0; i < host.children.length; i++)
      if (host.children[i].className === "bundle") { box = host.children[i]; break; }
    var st;
    if (box && box.bundleState) {
      // A mount is the view drawn again: nothing kept is reused.
      st = box.bundleState;
      st.kind = kind; st.id = id; st.scoped = scoped;
      st.text = null; st.path = ""; st.at = 0; st.ts = 0;
      st.note.textContent = "";
      return;
    }
    st = { kind: kind, id: id, scoped: scoped, text: null, path: "", at: 0, ts: 0,
           pending: null, pendingPath: "", note: null, busy: false };
    box = el("span", "bundle");
    var copy = el("button", "", "copy JSON");
    copy.type = "button";
    copy.id = "bundle-btn-" + (Object.prototype.hasOwnProperty.call(SLOT, kind) ? SLOT[kind] : kind);
    copy.title = "copy this view's data as JSON, for analysis (e.g. paste it to Claude)";
    var dl = el("button", "", "download .json");
    dl.type = "button";
    st.note = el("span", "sub bundle-note", "");
    box.appendChild(copy);
    box.appendChild(dl);
    box.appendChild(st.note);
    box.bundleState = st;
    host.appendChild(box);

    function fail(e) {
      st.busy = false;
      var m = e && e.message ? e.message : String(e);
      st.note.textContent = m === "stale" ? "" : errText(m);
    }
    function copied(text, ok) {
      st.busy = false;
      if (ok) {
        st.note.textContent = "copied (" + kb(text) + " KB)";
      } else {
        st.note.textContent = "copy failed, download instead";
        dl.focus();
      }
    }
    // Fetched ahead, so the click finds it ready; an error waits for
    // the click to say it.
    function prefetch() {
      if (!st.busy && ready(st) === null) load(st).catch(function () {});
    }
    copy.addEventListener("pointerenter", prefetch);
    copy.addEventListener("focus", prefetch);
    copy.addEventListener("click", function () {
      var text = ready(st);
      if (text !== null) {
        // Still inside the click: the clipboard call is made now.
        copyText(text).then(function (ok) { copied(text, ok); });
        return;
      }
      if (st.busy) return;
      st.busy = true;
      st.note.textContent = "fetching";
      var mine = pathOf(st);
      if (canClipItem()) {
        var body = load(st).then(function (s) {
          if (pathOf(s) !== mine) throw new Error("stale");
          return new Blob([s.text], { type: "text/plain" });
        });
        navigator.clipboard.write([new window.ClipboardItem({ "text/plain": body })]).then(function () {
          copied(st.text, true);
        }, function () {
          body.then(function () {
            st.busy = false;
            st.note.textContent = "ready: click copy again";
          }, fail);
        });
        return;
      }
      load(st).then(function () {
        st.busy = false;
        if (pathOf(st) !== mine) return;
        st.note.textContent = "ready: click copy again";
        copy.focus();
      }).catch(fail);
    });
    dl.addEventListener("click", function () {
      if (st.busy) return;
      st.busy = true;
      st.note.textContent = "fetching";
      var mine = pathOf(st);
      load(st).then(function () {
        st.busy = false;
        if (pathOf(st) !== mine) return;
        download(st.text, fileName(st.kind, st.id, st.ts));
        st.note.textContent = "downloaded (" + kb(st.text) + " KB)";
      }).catch(fail);
    });
  }

  return { mount: mount, fileName: fileName };
})();
