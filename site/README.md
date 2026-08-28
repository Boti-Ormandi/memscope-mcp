# Memscope product site

`site/` is a conventional nested Astro/Starlight consumer for the static Memscope documentation at `https://memscope.esrc.dev`. Product content lives as ordinary Markdown in `src/content/docs/`; Astro and Starlight own content loading, rendering, directory routes, navigation, Pagefind search, the sitemap, responsive behavior, appearance switching, preview, and the 404 page.

The `mcp-site-platform` Starlight plugin supplies shared design tokens and build-time keyboard focusability for overflowing code and tables. Its Cloudflare Pages integration writes exact no-slash redirects and conventional static-response headers after a successful build. It performs no API, credential, Wrangler, deployment, DNS, or hosted-status operation.

## Install and run

Use Node.js 22.12 or newer. Resolve the ordinary version dependencies from the configured package registry, then run:

```sh
npm install
npm run tools:check
npm run typecheck
npm run build
npm run preview -- --host 127.0.0.1 --port 4323
```

The production output is `dist/`. Local development is available through `npm run dev`.

## Tool reference

`tools.json` is the bounded product-owned runtime snapshot for the exact ordered 11-tool surface. It preserves the installed wheel's names, descriptions (including LF and indentation), input schemas, and output schemas. `tool-reference-preamble.md` is separate consumer-owned ordinary Markdown for the historical page guidance; it sits outside the Starlight docs-loader tree and creates no route. Page metadata and the preamble are supplied through the generic platform CLI options configured identically for both commands:

```sh
npm run tools:render
npm run tools:check
```

`render` writes `src/content/docs/reference/mcp-tools/index.md`; `check` verifies that file without rewriting it. The page retains the canonical `/reference/mcp-tools/` route, historical title and summary, six stable guidance anchors, and all generated schemas.

A separately collected installed-wheel `list_tools` JSON capture can be compared field-for-field without coupling the site build to Python or MCP:

```sh
node tests/runtime-tools-snapshot.mjs <list-tools.json>
```

The capture may be an ordered tool array or an object with a `tools` array. Each entry uses MCP aliases `name`, `description`, `inputSchema`, and optional `outputSchema`; other runtime metadata is ignored because it is not part of this snapshot format. The comparator checks field presence, exact values, and order. Ordinary install, render, check, build, and browser commands do not import or execute Memscope, Python, or the MCP SDK.

## Tests

```sh
npm run test:static
npm run test:browser
npm run check
```

The static suite checks the complete route, metadata, link, fragment, redirect, header, sitemap, discovery-file, tool, search, and self-contained-asset contracts. The Playwright suite exercises the production preview, Pagefind, keyboard navigation and overflow, responsive layout, all canonical pages, the 404 page, and full Axe analysis in light/dark desktop/mobile modes.

The site has no custom layout or Starlight component override, client application, analytics, form, cookie, remote runtime asset, or deployment command.
