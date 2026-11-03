# Antenna designs

Owner ruling 2026-11-03: antenna designs live here, in the docs, one
directory per fixture revision. Each revision directory holds what a
second builder needs to reproduce it:

| File | What it is |
|---|---|
| `*.scad` | the parametric OpenSCAD source — the design itself; dimensional fixes (thread scale, XY compensation) go here, not only in a slicer profile |
| `*.stl` / `*.3mf` | exports of that source, when committed, regenerated from it |
| `render.png` | a render for the wiki page |
| `build-guide-original.pdf` | the guide as it was supplied, kept for provenance |

The build, assembly, validation and maintenance guide for each revision
is a wiki page, so it is published with the rest of the wiki:

| Revision | Directory | Guide |
|---|---|---|
| Rev N — three-sector passive Wi-Fi fixture, ABS, 1-1/2 NPT PVC mount | [`rev-n/`](rev-n/) | [`docs/wiki/antenna-fixture-rev-n.md`](../../wiki/antenna-fixture-rev-n.md) |

Rev N's OpenSCAD source has not been committed yet; its guide's §12
says where it goes. A new revision gets a new directory and a new row,
never an edit in place of the old one (the guide's revision rule).

Every fixture here is receive-only (`MISSION.md` §2).
