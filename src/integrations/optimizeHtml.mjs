// Build-time HTML post-processor: strips authoring comments and minifies the
// inline scripts Astro deliberately never touches.
//
// WHY THIS EXISTS. Two costs were being paid on every one of ~1,730 page views:
//
//  1. `is:inline` scripts are NEVER bundled or minified by Astro — that is the
//     whole point of the directive, and this repo needs it for genuinely
//     pre-paint work (the theme controller must run before first paint or the
//     page flashes the wrong palette). But "not bundled" also meant shipping
//     every explanatory comment and every indent, uncompressed, in the HTML.
//     Measured on a representative page: 15,791 B of inline script that minifies
//     to 7,657 B.
//  2. Authoring comments written as `<!-- … -->` in .astro templates are emitted
//     verbatim. This repo comments heavily and deliberately (that's a feature of
//     the source, not a problem), so the BaseHead font-preload note alone is
//     ~1 KB in every page. Measured: 9 comments / 3,274 B on a typical page.
//
// Measured effect across 5 representative pages: −3,478 B brotli per page, about
// 17% of a typical page's transfer, ≈5.7 MB brotli site-wide. That is paid on
// EVERY view, not once: `public/sw.js` serves HTML network-first, so unlike the
// hashed `/_astro/` assets it is never served from cache.
//
// This runs at `astro:build:done` rather than being a source change on purpose —
// the comments stay exactly where they are for the next person reading the code,
// and only the emitted bytes shrink. Nothing about the source's readability is
// traded away for the win.
//
// SAFETY — three things this must never do, each guarded below:
//  - Corrupt visible content. `<pre>`, `<code>`, `<textarea>`, `<script>` and
//    `<style>` bodies are held out of comment-stripping entirely: this site
//    renders raw sample logs and cheat sheets, and a literal `<!--` inside one
//    would otherwise be eaten along with everything up to the next `-->`.
//    (Verified at the time of writing: 0 of 1,730 pages had `<!--` inside such a
//    region — but the guard is what keeps that true as content is added.)
//  - Mangle a non-JS <script>. JSON-LD and the `data-drill-questions` islands
//    (invariant 15) are `application/(ld+)json`; feeding those to a JS minifier
//    would either throw or silently rewrite them. Only untyped/`module`/
//    `text/javascript` blocks are minified, and both JSON flavours are already
//    emitted compact by `JSON.stringify`, so there is nothing to win there anyway.
//  - Touch an external script. Anything with `src=` is a hashed, cached
//    `/_astro/` chunk that Rollup has already minified.
//
// If a minify ever fails, that one script is left EXACTLY as-is and the build
// continues — a warning, not a broken page.
import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { transformSync } from 'esbuild';

/** Bodies whose contents are literal text, not markup — never strip inside these. */
const PROTECTED = /<(pre|code|script|style|textarea)\b[^>]*>[\s\S]*?<\/\1\s*>/gi;
const HTML_COMMENT = /<!--[\s\S]*?-->/g;
const SCRIPT = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;

/** Script types this minifier understands. Anything else is left untouched. */
const JS_TYPES = new Set(['', 'module', 'text/javascript', 'application/javascript']);

function isMinifiableScript(attrs) {
  if (/\bsrc\s*=/i.test(attrs)) return false; // external, already minified by Rollup
  const m = /\btype\s*=\s*["']?([^"'\s>]*)/i.exec(attrs);
  return JS_TYPES.has(m ? m[1].toLowerCase() : '');
}

function minifyInlineScripts(html, warn) {
  return html.replace(SCRIPT, (whole, attrs, body) => {
    if (!isMinifiableScript(attrs) || !body.trim()) return whole;
    try {
      const out = transformSync(body, { minify: true, loader: 'js' }).code;
      // esbuild appends a trailing newline; and never let a minify make it bigger.
      const code = out.replace(/\n$/, '');
      return code.length < body.length ? `<script${attrs}>${code}</script>` : whole;
    } catch (err) {
      warn(`inline script left unminified: ${err && err.message}`);
      return whole;
    }
  });
}

function stripCommentsOutsideProtected(html) {
  let out = '';
  let last = 0;
  let m;
  PROTECTED.lastIndex = 0;
  while ((m = PROTECTED.exec(html))) {
    out += html.slice(last, m.index).replace(HTML_COMMENT, '');
    out += m[0]; // verbatim — this is content, not markup
    last = m.index + m[0].length;
  }
  return out + html.slice(last).replace(HTML_COMMENT, '');
}

function htmlFilesIn(dir, acc = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) htmlFilesIn(p, acc);
    else if (name.endsWith('.html')) acc.push(p);
  }
  return acc;
}

export default function optimizeHtml() {
  return {
    name: 'optimize-html',
    hooks: {
      'astro:build:done': ({ dir, logger }) => {
        const root = fileURLToPath(dir);
        let files;
        try {
          files = htmlFilesIn(root);
        } catch {
          logger.warn(`no emitted HTML at ${root} — skipping`);
          return;
        }
        let before = 0;
        let after = 0;
        let warned = 0;
        const warn = (msg) => {
          if (warned++ < 3) logger.warn(msg);
        };
        for (const f of files) {
          const src = readFileSync(f, 'utf8');
          // Minify scripts FIRST: comment-stripping treats <script> as protected,
          // so JS comments have to be removed by the minifier, not by the stripper.
          const out = stripCommentsOutsideProtected(minifyInlineScripts(src, warn));
          before += Buffer.byteLength(src);
          after += Buffer.byteLength(out);
          if (out !== src) writeFileSync(f, out);
        }
        const saved = before - after;
        logger.info(
          `optimized ${files.length} pages: ${(saved / 1048576).toFixed(1)} MB raw removed ` +
            `(${((saved / before) * 100).toFixed(1)}%, ~${Math.round(saved / files.length)} B/page)`,
        );
      },
    },
  };
}
