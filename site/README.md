# Memscope documentation site

`site/` builds the Memscope documentation at `https://memscope.esrc.dev` with Astro and Starlight. Documentation lives in `src/content/docs/`; Astro and Starlight provide content loading, rendering, directory URLs, navigation, Pagefind search, the sitemap, responsive behavior, appearance switching, preview, and the 404 page.

The `mcp-site-platform` Starlight plugin supplies shared design tokens and build-time keyboard focusability for overflowing code and tables. Its Cloudflare Pages integration writes exact no-slash redirects and static-response headers into the build output; deployment is a separate step.

## Install and check

Use Node.js 22.12 or newer and the committed lockfile:

```sh
npm ci
npx playwright install chromium
npm run check
```

`npm run check`:

1. builds the current Python tree into a wheel;
2. installs that wheel in a temporary virtual environment;
3. compares its exact ordered 11-tool names, descriptions, input schemas, and output schemas with `tools.json`;
4. typechecks and builds the site;
5. verifies the generated tool reference and static route/link/output contracts; and
6. runs Playwright browser and accessibility coverage.

The wheel step uses `PYTHON` when set, otherwise `python` on Windows. The supported full check runs on Windows because memscope-mcp is a Windows package.

Local development and preview are available through:

```sh
npm run dev
npm run build
npm run preview -- --host 127.0.0.1 --port 4323
```

The production output is `dist/`.

## Tool reference maintenance

`tools.json` records the exact ordered 11-tool interface collected from an installed built wheel: names, descriptions, input schemas, and output schemas. `tool-reference-preamble.md` is prepended to the generated reference page.

After changing the runtime tool contract:

```sh
npm run tools:snapshot:update
npm run check
```

The update command rebuilds and installs the wheel, replaces the tool array in `tools.json`, and renders `src/content/docs/reference/mcp-tools/index.md`. The check fails when either the installed-wheel snapshot or generated Markdown is stale.

## Tests

- `npm run tools:runtime` compares `tools.json` with the installed wheel.
- `npm run tools:check` checks generated Markdown against `tools.json`.
- `npm run typecheck` runs Astro and TypeScript checks.
- `npm run build` produces the static site.
- `npm run test:static` checks routes, metadata, links, fragments, redirects, headers, sitemap, discovery files, tool rendering, Pagefind output, and self-contained assets.
- `npm run test:browser` builds and exercises the production preview with Pagefind, keyboard interaction, responsive layout, the 404 page, and Axe.

The site uses Starlight's standard layout and local assets.
