# sloth — marketing site

A single-page static site at `/docs/index.html` that introduces sloth
to a user-facing audience. Served directly by GitHub Pages from the
`/docs` folder of `main` — no workflow, no build step.

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
--canopy-dark:  #14331f;   /* deepest forest green   */
--canopy:       #1A3B2A;   /* dominant section bg    */
--canopy-mid:   #2D6A4F;   /* foliage / links        */
--sunlight:     #E9B44C;   /* CTAs, accents          */
--cream:        #FFF8E7;   /* parchment background   */
--mahogany:     #7B3F00;   /* warm text on cream     */
```

Tweak those six and the whole site re-skins.

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
