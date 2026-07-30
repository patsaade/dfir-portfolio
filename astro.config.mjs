// @ts-check
import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';
import sitemap from '@astrojs/sitemap';
import vercel from '@astrojs/vercel';
import optimizeHtml from './src/integrations/optimizeHtml.mjs';

// https://astro.build/config
export default defineConfig({
  // www is the canonical serving domain in production (the apex domain 307s
  // here); matching it avoids a redirect hop on every generated absolute URL
  // (canonical tags, sitemap, RSS, OG images, JSON-LD).
  site: 'https://www.patricksaade.com',
  output: 'server',
  // Canonical URL form is trailing-slash (matches the canonical tags + sitemap).
  // 'always' 308-redirects any no-slash URL (typed or external) to that form;
  // internal links must therefore end in '/' (see docs/STYLE_GUIDE.md).
  trailingSlash: 'always',
  adapter: vercel({
    webAnalytics: { enabled: true },
  }),
  integrations: [
    mdx(),
    sitemap({
      // Keep the sitemap free of pages that carry a noindex meta tag — listing a
      // noindex URL in the sitemap sends crawlers a contradictory signal, which
      // is exactly the kind of noise to avoid while the whole site is being
      // re-crawled after the URL migration. Three sources of noindex pages:
      //
      //  1. /term-of-the-day/ — legacy URL, meta-refreshes to /reference/glossary/.
      //  2. /reference/event-ids/<digits>/ — bare-numeric convenience stubs that
      //     redirect to the real `{source}-{id}` slug (see that route's own
      //     getStaticPaths). Real slugs are never all-digits, so this pattern
      //     can only ever match a stub.
      //  3. /reference/network-ports/<digits>/ — the same bare-numeric stubs for
      //     ports; real slugs are `{protocol}-{port}` / `port-{port}`.
      //
      // The 404 route is dropped defensively too (the integration already skips
      // it, but it is noindex and must never appear here if that ever changes).
      filter: (page) =>
        !page.includes('/term-of-the-day/') &&
        !/\/reference\/(?:event-ids|network-ports)\/\d+\/?$/.test(page) &&
        !/\/404\/?$/.test(page),
    }),
    // Strips authoring comments and minifies the `is:inline` scripts Astro
    // deliberately leaves alone. Runs last, on the emitted HTML, so the source
    // keeps every comment it has. See the integration for the measurements and
    // the three things it is careful not to break.
    optimizeHtml(),
  ],
  markdown: {
    shikiConfig: {
      // Dark theme for code blocks (matches DFIR aesthetic)
      themes: {
        light: 'github-light',
        dark: 'github-dark',
      },
      wrap: false,
    },
  },
  image: {
    // Allow optimization of local forensics screenshots
    responsiveStyles: true,
  },
  vite: {
    build: {
      // Astro hoists non-`is:inline` component <script> tags into their own
      // chunk, then — by Vite's default assetsInlineLimit (4096 bytes) —
      // silently re-inlines any chunk under that size back into every page
      // that uses it. That's the opposite of what hoisting a shared,
      // site-wide component script (nav, background canvas, …) is for: the
      // point is one cached file, not N re-inlined copies. Only override the
      // threshold for those hoisted-script chunks (named
      // `<Component>.astro_astro_type_script_*`); everything else (images,
      // etc.) keeps Vite's normal inlining behavior.
      assetsInlineLimit: (filePath) =>
        /\.astro_astro_type_script_index_\d+_lang/.test(filePath) ? false : undefined,
      // No source maps in the deployed build — Vite already defaults to this,
      // but stated explicitly so a future Vite default change can't silently
      // start shipping maps (a minor recon aid for an attacker, no upside for
      // a static site with no minified-in-prod-only bug reports to debug).
      sourcemap: false,
    },
  },
});
