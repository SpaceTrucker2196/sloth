# sloth — marketing site

A single-page static site at `/docs/index.html` that introduces sloth
to a user-facing audience. Served directly by GitHub Pages from the
`/docs` folder of `main` — no workflow, no build step.

Theme: **vaporwave / tropical-forest / neon-80s** — hot pink + cyan +
jungle-green on space-purple. The hero has a vaporwave sun rising
behind palm silhouettes over a perspective grid floor. Body has a
subtle CRT scanline overlay. The ASCII OSI mockup renders in green
phosphor inside a CRT bezel.

## Files

```
docs/
├── index.html        Single-page site: hero, features, philosophy,
│                     streaming, quickstart, footer.
├── assets/
│   ├── sloth.png     Hero image (copy of /slothwifi.png).
│   └── style.css     All styling. Palette as CSS custom properties.
├── .nojekyll         Disables Jekyll so the existing developer
│                     markdown under views/ and wiki/ isn't auto-
│                     converted to HTML through a theme.
└── (existing developer docs — views/, wiki/, CLAUDE.md, etc. —
    are unchanged and still browsable in your editor and on
    github.com)
```

## Deploying

**One-time setup in the repo's GitHub Settings:**

1. Go to **Settings → Pages**.
2. Under **Build and deployment → Source**, choose **Deploy from a branch**.
3. Set **Branch** to `main` and **Folder** to `/docs`. Save.

That's it. GitHub Pages serves the contents of `/docs` directly.
Every push to `main` that touches `/docs` re-publishes automatically.
The URL gets reported on the same Settings → Pages page. Standard
form:

```
https://<owner>.github.io/<repo>/
```

## Editing

Single-page, single CSS. The palette lives at the top of
`assets/style.css` under `:root`:

```css
--night:        #0a0014;   /* deepest space-black background  */
--space:        #1a0033;   /* main purple section background  */
--magenta:      #ff006e;   /* hero glow, primary accent       */
--hot-pink:     #ff2a95;   /* card titles, hover state        */
--cyan:         #00ffe5;   /* headings, links, secondary CTA  */
--jungle:       #39ff14;   /* eyebrows, palm fronds, CRT      */
--sun-yellow:   #ffec3d;   /* top of vaporwave sun gradient   */
--violet:       #9f00ff;   /* gradient stops, primary CTA tail */
--chrome:       #f0f0ff;   /* body text                       */
```

Tweak those and the whole site re-skins. Two SVG decorations
in `index.html` use these colours directly (they're inline, not
linked from CSS): the hero `.canopy-overlay` (vaporwave sun + palm
silhouettes + grid floor) and the `.wave-divider` (neon horizon
between sections). If you change the palette, glance at those
SVGs to make sure the hex values still match.

## Previewing locally

Any static-file server works. The simplest:

```sh
cd docs
python3 -m http.server 8000
# open http://localhost:8000
```

No build, no `node_modules`, no dependencies. The Google Fonts CSS
import in `index.html` needs network for the heading/body fonts to
load; system fallbacks (Georgia / system sans / Consolas) render
fine offline.

## Why `.nojekyll`?

The default GitHub Pages pipeline runs every `/docs` build through
Jekyll, which would (a) attempt to apply a theme to every `.md` file
it finds and (b) potentially conflict with the existing wiki / view
docs that are written for in-editor reading, not for HTML
publishing. The empty `.nojekyll` file tells Pages to skip Jekyll
and serve files exactly as-is. The marketing site is pure static
HTML / CSS, so nothing is lost.

The existing developer markdown (`docs/views/*.md`,
`docs/wiki/*.md`, etc.) still serves over Pages as raw text. The
canonical reading paths for those files remain github.com (which
renders markdown natively) and a local editor.
