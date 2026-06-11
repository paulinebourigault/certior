# certior.io landing page

Self-contained `index.html` for the marketing site. Pure HTML + Tailwind CDN — no build step, no JS framework.

## Local preview

```bash
cd docs/landing
python -m http.server 8080
# open http://localhost:8080
```

## Deploy to a static host

Drop the contents of this directory onto any static host (Netlify, Cloudflare Pages, Vercel, S3 + CloudFront). The page expects:

- `index.html` at the deploy root
- `favicon.png` and `logo.png` alongside it
- `_redirects` (Netlify-style redirect file; routes `/docs/*` to `docs.certior.io/*`)

For a Netlify-style host: connect this repo, set **Publish directory** to `docs/landing`, leave **Build command** empty. Add the custom domain in the host's domain settings; HTTPS provisions automatically.

## Editing tips

- **Tailwind is via CDN** — no npm. The three custom classes (`bg-cream`, `text-ink`, `border-warm`) are defined in the inline `<style>` block at the top of `index.html`.
- **The architecture SVG is hand-written, ~70 lines.** If you change a capability string, update both the SVG and the surrounding prose so the visual and the description match.
- **The contact CTA is a single `mailto:hello@certior.io` button** — no form, no third-party JS, no Netlify Forms dependency.
- **Don't add links to `docs.certior.io` from this page** until that subdomain actually resolves.
