# sloth — marketing site

The static HTML/CSS that ships at the project's GitHub Pages URL.
Tropical-forest aesthetic, single page, no JavaScript, no build step.

## Files

```
site/
├── index.html        Single-page site: hero, features, philosophy,
│                     streaming, quickstart, footer.
├── assets/
│   ├── sloth.png     Hero image (copy of /slothwifi.png).
│   └── style.css     All styling. Uses CSS custom properties for
│                     the palette so theme tweaks are one block.
└── README.md         This file.
```

## Deploying

A workflow at [`.github/workflows/pages.yml`](../.github/workflows/pages.yml)
deploys the site automatically on every push to `main` that touches
`site/**` (or via manual Actions tab dispatch).

**One-time setup in the repo's GitHub Settings:**

1. Go to **Settings → Pages**.
2. Under **Build and deployment → Source**, choose **GitHub Actions**.

That's it. The next push under `site/**` triggers the workflow; once
it finishes, the URL is reported in the workflow run summary and on
the Settings → Pages page. Standard URL form:

```
https://<owner>.github.io/<repo>/
```

## Editing

Single-page, single-CSS. The palette lives at the top of
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
cd site
python3 -m http.server 8000
# open http://localhost:8000
```

No build, no node_modules, no dependencies. The Google Fonts CSS
import in `index.html` needs network for the heading/body fonts to
load; system fallbacks (Georgia / system sans / Consolas) render
fine offline.
