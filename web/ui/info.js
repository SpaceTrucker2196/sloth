// slothweb: the page's source and description notes go behind info
// buttons (owner 2026-11-18: "move all source and description text
// that is usually in light grey to dialogs behind info buttons. the
// goal of this is a more efficient less cluttered display").
// window.SlothInfo; nothing calls it: it runs once when the page is
// parsed, before app.js's main(), so a note is judged on the words
// index.html gave it and never on what a script wrote later.
// A note is a .sub (nothing else in its class) of MIN characters or
// more, in a view and not already behind something the operator opens
// (a drawer, a dialog, a details, the scope legend), not a line a
// script speaks through (role, aria-live), not a control's label and
// not in a .label. A state, a count and an error stay where they are.
// The note stays in the document, hidden by info.css, so the scripts
// that show one of a set (w-hz-sub, w-mx-sub, w-iso-sub) still do; its
// button is in the .label above it, one for every note under that
// label, or, with no label above, where the note was. The dialog shows
// copies of the notes not hidden at the moment it opens: cloneNode of
// the page's own markup, no markup sink, the copies' ids dropped.
(function () {
  "use strict";
  var MIN = 60;
  var SKIP = ".label, label, dialog, details, .drawer, .scope-legend, [role], [aria-live]";
  var dlg = null, dlgTitle = null, dlgBody = null;

  function isNote(e) {
    if (e.className !== "sub") return false;
    if (e.closest(SKIP)) return false;
    return e.textContent.replace(/\s+/g, " ").trim().length >= MIN;
  }

  // The words of a label that are its own: its text nodes, not its
  // counts, buttons or tools.
  function labelText(lab) {
    var t = "", n;
    for (n = lab.firstChild; n; n = n.nextSibling) if (n.nodeType === 3) t += n.nodeValue;
    return t.replace(/\s+/g, " ").trim();
  }

  function labelAbove(e) {
    var p;
    for (p = e.previousElementSibling; p; p = p.previousElementSibling) {
      if (p.classList.contains("label")) return p;
    }
    return null;
  }

  function dialog() {
    if (dlg) return dlg;
    dlg = document.createElement("dialog");
    dlg.className = "info";
    var hd = document.createElement("div"), x = document.createElement("button");
    hd.className = "dr-hd";
    dlgTitle = document.createElement("b");
    dlgTitle.className = "d-normal";
    x.type = "button";
    x.textContent = "close";
    x.addEventListener("click", function () { dlg.close(); });
    hd.appendChild(dlgTitle);
    hd.appendChild(x);
    dlgBody = document.createElement("div");
    dlgBody.className = "info-body";
    dlg.appendChild(hd);
    dlg.appendChild(dlgBody);
    // A click on the backdrop lands on the dialog itself.
    dlg.addEventListener("click", function (ev) { if (ev.target === dlg) dlg.close(); });
    document.body.appendChild(dlg);
    return dlg;
  }

  function copy(note) {
    var c = note.cloneNode(true), ids = c.querySelectorAll("[id]"), i;
    c.removeAttribute("id");
    for (i = 0; i < ids.length; i++) ids[i].removeAttribute("id");
    c.className = "info-p";
    return c;
  }

  function open(title, notes) {
    var d = dialog(), i, n = 0;
    dlgTitle.textContent = title || "about this";
    dlgBody.textContent = "";
    for (i = 0; i < notes.length; i++) {
      if (notes[i].hidden) continue;
      dlgBody.appendChild(copy(notes[i]));
      n++;
    }
    if (!n) dlgBody.textContent = "nothing to say about this as it is shown now";
    if (!d.open) d.showModal();
  }

  function button(title, notes) {
    var b = document.createElement("button");
    b.type = "button";
    b.className = "info-btn";
    b.textContent = "i";
    b.title = "source and description";
    b.ariaLabel = (title ? title + ": " : "") + "source and description";
    b.addEventListener("click", function (ev) {
      // A tile is a link, and a label may be inside one.
      ev.preventDefault();
      ev.stopPropagation();
      open(title, notes);
    });
    return b;
  }

  function init() {
    var all = document.querySelectorAll("main .sub"), i, e, lab, k, tools, title;
    var labs = [], sets = [];
    for (i = 0; i < all.length; i++) {
      e = all[i];
      if (!isNote(e)) continue;
      lab = labelAbove(e);
      if (!lab) {
        e.parentNode.insertBefore(button("", [e]), e);
      } else {
        k = labs.indexOf(lab);
        if (k < 0) {
          labs.push(lab);
          sets.push([e]);
        } else sets[k].push(e);
      }
      e.classList.add("info-src");
    }
    for (i = 0; i < labs.length; i++) {
      lab = labs[i];
      title = labelText(lab);
      tools = lab.querySelector(".dt-tools");
      lab.insertBefore(button(title, sets[i]), tools && tools.parentNode === lab ? tools : null);
    }
  }

  window.SlothInfo = { MIN: MIN, isNote: isNote, labelText: labelText };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
