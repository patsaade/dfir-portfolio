# Style Guide

The design language for patricksaade.com. Follow this for any new page, component, or
copy so the site stays consistent. (Architecture rules live in `CLAUDE.md`, kept local to the
project; content/frontmatter rules in [AUTHORING.md](AUTHORING.md).)

## Project direction

The decisions every change should serve:

- **Goal:** land a **DFIR-specific role**. Everything optimizes for that.
- **Audience priority (in order):** 1) hiring managers/recruiters (skim fast), 2) DFIR
  practitioners/peers (read deep), 3) students/newcomers. So: the hero must convey identity +
  current role + headline certs at a glance, and the About page is one click for recruiters —
  but the body goes deep enough for practitioners.
- **Home emphasis:** a **single-screen, minimal-typographic hero** — identity, current role, and
  headline certs at a glance in one line, two CTAs straight into `/blog/`/`/labs/`, sized to need
  no scrolling. Content depth (the full post archive, full certification detail) lives on its own
  pages, not stacked below the fold on the homepage — see CLAUDE.md invariant 14 for the mechanics
  and the cyberkit.win homepage fork this same file also carries.
- **Content pillars (priority order):** **Host forensics** and **Memory forensics** first;
  then EDR analysis, Labs/CTF, Tools/exam-prep.
- **Content source:** **public lab & CTF challenges and personal study only** — CyberDefenders,
  13Cubed, MemLabs, Magnet, home lab. **Never real/employer/client investigations** (employer
  constraint). No redacted-case framing anywhere.
- **Voice:** see *Voice & tone* below — conversational practitioner, first-person, original.
- **Visual direction:** **richly technical** (see *Visual direction* below).
- **Brand:** keep the "Patrick Saade" wordmark, the pixel-star mark (`PixelStar`, also the
  favicon), and current palette system.
- **Contact/CTA:** **LinkedIn only**. No contact form, no résumé PDF, no newsletter,
  no "available for work" banner.
- **Discoverability:** invest in it — be findable by name, profession, experience, labs, and
  blog. Tags/series, search, related posts, structured data all in scope.

## Voice & tone

- **Conversational practitioner**, first person ("here's how I'd approach this", "the artifact
  that cracked it"). Confident but not boastful; show the work, including dead ends.
- **Original** — do not imitate other blogs' style; this is Patrick's voice.
- Lead with the finding/insight, then the evidence. Explain *why*, not just *what*.
- No marketing fluff, no employer name-dropping for cases, no invented metrics.
- **Copy is the site's voice, never the prompt.** Write everything — page copy, glossary
  definitions, metadata — as natural prose Patrick would write. **Never** let task instructions
  or meta-phrasing leak into user-facing text (no "vendor-agnostic", "as requested", "never a
  product", "this glossary", etc.). State the thing itself, plainly; if a rule shaped the copy,
  the rule belongs in this guide, not on the page.
  - **In particular, never restate the content-source / confidentiality constraint as an on-page
    disclaimer** — no "no client data", "no real-incident details", "nothing from employer
    casework", "no redacted real cases". That rule (public-only sources; see CLAUDE.md) governs
    *what* you write, not something to announce. Name the public sources positively instead
    (e.g. "public data lets me walk the whole investigation in the open") and stop there. It
    reads as a compliance disclaimer, not Patrick's voice.
- **Signature capitalization.** Patrick capitalizes **Threat**, **Root Cause Analysis**, and
  **Incident Response** as a deliberate voice tic — but only inside first-person narrative he
  authored (hero, About, colophon, posts). Keep them lowercase everywhere else (headings, meta
  descriptions, glossary definitions, card/label microcopy); they land *because* they're rare.
  (Distinct from DFIR/SIEM/EDR/SOC/IR, which are capped everywhere as acronyms.)

### Glossary terms (Term of the Day)

Entries in `src/data/securityTerms.ts` / `src/data/terms/*.json` are **concepts, techniques,
artifacts, or models — never products, tools, vendors, or companies** (the generic idea, e.g.
"credential dumping", not a named tool). Keep each field tight and factual: `short` ≤ 90 chars,
`definition` 1–2 sentences (what it is), `significance` 1–2 sentences (why it matters in DFIR),
`example` one concrete sentence. Accuracy over volume — only real, established industry terms.

## Visual direction

Aim **richly technical** while keeping the dark, terminal-adjacent base, the ambient node
background, and the theme system. **Exception:** both domains' homepage heroes (`index.astro`)
are deliberately minimal-typographic instead — no diagrams/tables/decorative framing there, just
type, whitespace, and the ambient canvas; don't "correct" them back toward richly-technical.

- Favor **diagrams, annotated screenshots, data tables, and timelines** in posts over plain
  prose where they clarify.
- Lean into **monospace** for artifacts, paths, commands, IOCs, and labels; code blocks are
  first-class (Shiki, copy affordance).
- Forensic/technical motifs (timelines, artifact tables, attack-path diagrams) are encouraged;
  keep them legible and theme-aware (use tokens, never hard-coded colors).

## Color & theming

- Style with the `css()` function from `styled-system/css`. **Never hard-code a color** in
  components — not hex (`#fff`), not `rgb()`/`rgba()`, and not a CSS color keyword (`white`,
  `black`, etc.) — reference semantic tokens so every theme (10 palettes, light + dark) stays
  correct. `test/noHardcodedColors.test.ts` enforces this; a hard-coded color value inside a
  `css()` call fails the test suite.
- Semantic tokens: `bg`, `bgSubtle`, `bgCard`, `border`, `text`, `textMuted`, `primary`,
  `primaryHover`, `accent`, `codeBg`.
- **Text/icons on a `primary`-filled surface (buttons, active chips) must use `onPrimary`,
  never a literal `white`.** Dark themes deliberately use a bright/pastel `primary` (so it pops
  against a dark background) and override `onPrimary` to a near-black color for legibility —
  hard-coding white text on those primaries is close to unreadable (e.g. white on the default
  dark theme's `primary` computes to ~2:1 contrast, well under WCAG AA's 4.5:1). `onPrimary` is
  already used correctly in `BaseLayout`'s skip-link, `BackToTop`, and `FilterBar`'s active chip.
- Inside string values use `token(colors.x)` — e.g. `border: '1px solid token(colors.border)'`.
- Tinted fills use `color-mix` with a token — e.g.
  `bg: 'color-mix(in srgb, token(colors.primary) 13%, transparent)'` (icon tiles, cert chips).
- Palettes/modes are defined in `src/themes.ts`; never add a bare `data-mode` attribute to a
  child element (see CLAUDE.md).

## Typography

The site uses **only two faces**, both under the SIL Open Font License: **Redaction** (by Jeremy
Mickel / MCKL, for Titus Kaphar & Reginald Dwayne Betts' *The Redaction*) for everything readable,
and **Fira Mono** (Mozilla) for code. Both are self-hosted under `public/fonts/`, declared in
`src/styles/fonts.css`, and credited on the colophon. Redaction is a serif with seven optical
**grades of degradation** (0 = clean … 100 = heavily eroded).

- **`fontFamily: 'sans'`** is Redaction **grade 0** (clean), with a Georgia/Times serif
  fallback. Use it for everything readable — body, headings, titles, stat values, and
  metadata/eyebrows/badges.
- **`fontFamily: 'mono'`** is **Fira Mono**, reserved for **code-like text only**: code blocks,
  inline `code`, file paths, IOCs, commands, and the footer version hash. Don't put labels/dates in mono.
- **Degraded grades** are tokens — `redaction20`, `redaction35`, `redaction50` — used only on
  specific display areas: **ticker → 50, wordmark → 50** (applied statically). The **hero `<h1>`
  decodes** from the heaviest grade through to clean (grade 0) via the `declassify` animation, so
  it settles fully clean like every other title — don't pin the hero to a degraded resting grade.
  Keep static degradation to the *medium* range (≤ 50) and to large/display text; the grades share
  metrics with grade 0. The heavier grades (70/100) are self-hosted but reserved for the decode
  animation and big one-off display, never body or small text.
- **Casing scope boundary — page titles vs. section subheadings.** These are two distinct,
  deliberate conventions; don't cross-apply one to the other.
  - **Page-level titles are Title Case.** This covers the `BaseLayout` `title` prop (the
    `<title>`/SEO string), each page's own visible `<h1>` set via `PageHeader`'s `title` prop,
    and eyebrow category labels (`PageHeader`'s/the hero's `eyebrow`) — e.g. "DFIR Deep Dives",
    not "DFIR deep dives". This also covers the hero `<h1>` statement on the home page, e.g.
    "SOC & Incident Response @ First American" — that's the same rule, not a separate exception.
    Use standard English title-case rules: capitalize principal words; lowercase minor words —
    articles, coordinating conjunctions, and short prepositions under ~4 letters (a, an, the,
    and, but, or, for, nor, as, at, by, in, of, on, per, to) — **unless** that word is the first
    or last word of the title, in which case it's always capitalized. A `BaseLayout`/`PageHeader`
    title pair on the same page must match exactly (they're two renderings of one title, not two
    independent strings). For a dynamically built title (e.g. `` `${tool.name} — DFIR Tool` ``,
    `` `Event ${entry.id} — ${entry.name}` ``), title-case only the **static** surrounding text —
    leave interpolated data (tool names, event names, technique IDs) exactly as authored; never
    reflow a real proper noun into title case.
  - **Section-level prose subheadings are sentence case — unchanged by the rule above.** Any
    `<h2>`/`<h3>` *within* a page body (e.g. "What it records", "Common triggers" on Event ID,
    glossary, or tool detail pages) stays sentence case, same as normal prose. This is an
    intentional, distinct convention from page-level titles — don't title-case these, and don't
    read the page-title rule as license to.
  - **Exception (both scopes):** proper nouns and the site/brand wordmark "Patrick Saade" are
    always cased correctly regardless of which rule otherwise applies.

## Emphasis & bolding (copy)

**One rule, applied uniformly — this is the #1 source of past inconsistency.**

In bio / career / experience prose, bold **only employer & company names** with
`<strong class={css({ color: 'text' })}>…</strong>`:

- ✅ Bold: **First American**, **Red Canary**, **Zscaler**, **ReliaQuest**.
- ❌ Do **not** bold role titles, tools/products, or generic phrases. Every role is written
  the same way — `Senior Information Security Analyst at <strong>First American</strong>`,
  `Threat Response Engineer at <strong>Red Canary</strong>` — so current and past roles match.
- Tools/products get emphasis through dedicated UI (the Tools page, badges), **not** bold in
  prose. So no bold for "Velociraptor", "Volatility 3", etc. in sentences.
- This applies to narrative prose only, not compact UI (badges, card sub-labels, stat
  descriptions) — those carry weight via component styling.

**Exception — policy/legal pages** (e.g. `/privacy`): bold may emphasize key *facts/guarantees*
for scannability (e.g. "**no cookies**", "**cookieless**", does "**not**" track). This is a
distinct, intentional pattern; keep it to the key guarantees, not proper nouns.

### Casing in headlines vs. prose
Page-level title casing (headline `<h1>` statements, eyebrows) is covered by the single rule
in *Typography* above. Ordinary sentence prose — the running text in paragraphs, not a title —
still uses normal sentence case, e.g. "…detection-and-response and incident response…"
(lowercase). Don't title-case mid-sentence.

## Language conventions

- Certifications in progress are **"in pursuit of"**, never "in progress". (A degree may use
  "(in progress)".)
- Dates: `Mon YYYY` (e.g. `Jun 2026`); ranges with an en dash: `Aug 2025 – Jun 2026`;
  current roles end in `Present`. **This exact shape is load-bearing, not just style** —
  `src/utils/experience.ts` parses every `period` string on the About page to compute and
  display each role's duration (and a company's total tenure), auto-recomputed from the
  real build date on every rebuild for a `Present` role. A period that doesn't match
  `Mon YYYY – Mon YYYY`/`Present` silently gets no duration shown (see that file's own
  `roleDurationMonths`) rather than breaking the page — but it does mean the two need to
  change together if this date format convention is ever revisited.
- Write **DFIR**, **SIEM**, **EDR**, **SOC**, **IR** in caps. Product names as branded
  (Volatility 3, Velociraptor, CrowdStrike).
- Use em dashes — like this — for asides; "·" as an inline separator in meta rows.
- **Content accuracy:** never invent titles, dates, employers, certs, or metrics
  (see CLAUDE.md).

## Components & patterns

- **Card:** `bg: 'bgCard'`, `border: '1px solid token(colors.border)'`, `borderRadius: 'lg'`,
  optional `boxShadow: 'card'`. Hover: `transform: 'translateY(-2px/-3px)'` +
  `borderColor: 'primary'` (+ `boxShadow: 'cardHover'`), `transition` ~200ms.
- **One card size across listing pages.** The Glossary, Tool Catalog, Certifications, MITRE
  ATT&CK Coverage Map, MITRE D3FEND Map, and Event ID Reference grids all use the single
  shared `.card-grid` class (in `global.css`: `repeat(auto-fill, minmax(min(100%, 232px),
  1fr))`, `gap: 0.65rem`) with `0.7rem 0.85rem` card padding and the `card()` recipe's
  `minH: '4rem'` floor — so cards are a consistent size site-wide, not congested and not
  oversized. Don't fork per-page column widths; change `.card-grid` once if the size needs
  tuning. Pages add only their own `mt` via `css()`. `test/card-consistency.test.ts`
  enforces every listing page composing `card()` (not hand-rolling padding/minH/etc.).
  **Card content must never force a card taller than its neighbors in the same grid row**
  (a CSS grid row stretches every cell to match its tallest one, so one oversized card
  drags the whole row's white space with it). If a field's content can run long (a
  category label, a free-text description), truncate it with `overflow: 'hidden'` +
  `textOverflow: 'ellipsis'` on a single `whiteSpace: 'nowrap'` line (plus a `minW: 0` +
  `flexShrink: 1` on that element so it can actually shrink to fit) rather than letting it
  wrap — wrapping grows the card instead of bounding it. Put the untruncated value in a
  `title` attribute for a hover tooltip, and make sure the full value is still shown
  somewhere unbounded (the item's own detail page) so truncation never destroys
  information, only the card preview's presentation of it.
  **A multi-line free-text field (a description/definition paragraph) needs a fixed
  height, not just a line-clamp.** `overflow: 'hidden'` + the `.totd-clamp2` utility
  class (`global.css`) caps *growth* at 2 lines, but a CSS grid row always stretches
  every card to match its tallest sibling regardless — so a short 1-line description
  next to a clamped 2-line one ends up the same *outer* height but with a visibly dead
  gap above its tag row, while the 2-line card's text fills that same space. That reads
  as "these cards aren't actually the same size" even though the boxes line up exactly.
  Fix it by also giving the field its own fixed `h` (e.g. `h: '2.4rem'` for a 2-line box
  at `fontSize: '0.82rem'`/`lineHeight: 1.45` — recompute for a different size) so every
  card's content area is identically sized up front, independent of its row-mates. Don't
  reach for `minH` here — `test/card-consistency.test.ts` bans it outright at the page
  level, and it wouldn't fix the gap anyway (`min-height` still lets a short block sit
  shorter than a fixed `h` unless something else stretches it). See `certFull` in
  `certifications.astro` for the reference implementation, also applied to `toolUse`
  (`tools.astro`), `cardDesc` (`dfir.astro`), and `cardShort` (`glossary/index.astro`).
  **When a tag row holds more than one chip** (a truncating category/function tag next to
  a fixed badge like "ATT&CK"), the row's `flexWrap` must be `'nowrap'`, never `'wrap'`.
  With `'wrap'`, the browser decides line breaks using each item's un-shrunk hypothetical
  width — so a long tag can push its sibling onto a second line *before* the long tag's own
  truncation gets a chance to make room for it, growing the card even though the truncated
  element "worked." Give the variable-length tag `flexShrink: 1` (it absorbs the squeeze)
  and every other chip in that row `flexShrink: 0` (it never moves) — this is what actually
  guarantees one line, not the truncation alone. Event ID Reference and Tool Catalog both
  hit this for real (their `tagRow`s previously used `flexWrap: 'wrap'`), so treat this as
  the default for any row combining a variable-length tag with a fixed one.
- **Reference and Framework pages share one feature set — ship it with the page, not as a
  follow-up.** Glossary/Tool Catalog/Command Cheat Sheet/Event ID Reference and ATT&CK
  Map/D3FEND Map are all `type: 'reference'` entries in `SITE_ENTRIES` (across the
  `guides-concepts`, `lookup-tables` and `frameworks-maps` categories), and every one needs: (a)
  a dedicated `z.array(z.string())` frontmatter field in `content.config.ts` (matching the
  `tools`/`attack`/`d3fend` pattern) that feeds a "Featured/Mentioned/Covered in my
  writeups" detail-page section plus a matching stat + `FilterToggle` on the index; (b) at
  least one outbound cross-link into an existing dataset (a `glossarySlug`-style pointer, or
  a `<RelatedTools>` block); (c) if its `ListFilter` config exposes a category facet through
  `TagCombobox`, an `urlSync.facetParam` so that facet is bookmarkable, the same way ATT&CK's
  `platform` and D3FEND's `tactic` already are; and (d) `DefinedTerm` (or equivalent)
  structured data on the detail page. A dataset that ships with search-and-toggles but
  without these reads as behind its siblings — that's what happened with Event ID Reference.
  **This checklist governs the heavier index + per-entry-detail-page shape only** (Glossary,
  Tools, Cheat Sheet, Event ID Reference, ATT&CK Map, D3FEND Map — each entry gets its own
  route). A **single-page reference** with no per-entry detail routes (IP & CIDR Reference,
  OSI & TCP/IP Model Reference, and other pages built the same way) has nothing to attach a
  "Mentioned in my writeups" cross-link *to* per entry, so it doesn't need this machinery —
  it still wants at least one outbound cross-link to a related page/tool, just not the full
  writeup-frontmatter-field + FilterToggle + DefinedTerm apparatus. Pick the shape by whether
  the content actually has a real per-item detail page worth linking to, not by category.
- **Icon tile** (stat/section/timeline markers): rounded square (`borderRadius: 'md'`,
  ~2.25rem), `bg` = primary tint (`color-mix … 13%`), `color: 'primary'`, icon ~18px.
- **Badges** ([Badge.astro](../src/components/Badge.astro)): variants `default` (muted),
  `primary` (category — pass `icon`), `accent` (certs/tools/featured), `difficulty`. Mono,
  small, uppercase-ish. Use `categoryIcon()` from `consts.ts` for category badges.
- **Icons** ([Icon.astro](../src/components/Icon.astro)): lucide-style inline SVG, stroke,
  `currentColor`, 24×24 viewBox. Add new ones to the `ICONS` map. Default size 18; 13–15 in
  badges/inline, 20 in section headings.
- **Buttons:** primary = solid `bg: 'primary'` / `color: 'onPrimary'` / `borderRadius: 'md'`,
  hover `bg: 'primaryHover'` + lift; ghost = `border` + transparent, hover `borderColor: 'primary'`.
  **Never compose two independently-called `css()` results as two class-name strings in the same
  `class` attribute** (e.g. `` class={`${base} ${variant}`} ``) **when both define a conditional
  override for the same property** (both have their own `_hover.color`, say). Each `css()` call
  atomizes independently, so the two class names land in the compiled stylesheet in whatever order
  Panda happens to extract them — a plain CSS specificity tie, decided by source order, not by
  which class comes first/last in the `class` string. This is exactly what silently broke the
  "primary" action-button variant (`actionBtn` + `primaryBtn`, used for "Use current time" and the
  Dork Builder/IOC Extractor's own primary buttons): `actionBtn`'s hover sets `color: 'primary'`,
  `primaryBtn`'s hover sets `color: 'onPrimary'` (the correct, contrast-safe choice for text sitting
  on a solid `primary`-colored background) — when `actionBtn`'s rule won the tie, the button's hover
  text color became identical to its own hover background color, so the label/icon visually
  vanished (read as "goes white"/unreadable in light-mode palettes whose `primary` renders pale).
  **Fix: merge the plain style *objects*, not the compiled class strings** — `css(base, variant)`
  (see [Badge.astro](../src/components/Badge.astro)'s `css(base, variants[variant])`) deep-merges
  the objects *before* atomization, so a later object's `_hover.color` deterministically overrides
  an earlier object's, exactly like `{...base, ...variant}` would for plain objects. Keep the base
  style (e.g. `actionBtn`) as its own exported class for standalone use, but build any "variant on
  top of base" button as one `css(baseObj, variantObj)` call — never as two pre-built class strings
  concatenated at the call site.
- **Links:** `color: 'primary'`, underline-on-hover (or persistent underline in prose).
  External links: `target="_blank" rel="noopener"` + an `external-link` icon when it aids clarity.
- **Internal links must end with a trailing slash** — `/blog/`, `/tools/`, `` `/blog/${id}/` ``,
  `` `/reference/glossary/${slug}/` ``. The site sets `trailingSlash: 'always'`, so an unslashed internal link
  **404s in `astro dev`** and 308-redirects in production. File URLs keep their extension and no
  slash (`/rss.xml`). The site root is just `/`.
- **Section heading:** an `<Icon>` (primary) + sentence-case title; see About/Tools.
- **Hover cards:** companies, certs, and key tools auto-render context cards site-wide; tag a
  glossary term inline with `<Term slug="…">` (see AUTHORING + CLAUDE.md invariant 11). Triggers
  show a subtle dotted underline; keep them in prose, not headings.
- **Shared list/detail-page parts — reuse, don't rebuild.** `PageHeader` (eyebrow + title +
  description + breadcrumbs), `Breadcrumbs`, `CollapseAll` (expand/collapse a set of `<details>`),
  `TagCombobox` (typeahead search with removable facet tokens — suggestions appear at 2+ chars;
  drives Blog, Glossary, Tool Catalog, Certifications, and both MITRE maps), `FilterToggle` (the pill
  filters — "Covered only", "In glossary", "Maps to ATT&CK"; `tone` `accent`|`primary`), `EntryNav`
  (prev/next on detail pages), and `ListFilter` — the config-driven controller that actually wires
  search + facet + toggles + collapsible groups together (each page just declares its selectors and
  toggle list; see the component's own doc comment for the config shape). `TagCombobox` drives all
  the list pages (Blog, Labs, Glossary, Tool Catalog, Certifications, both MITRE maps, and the /reference/ and /tools/ section indexes), and `ListFilter` now
  drives all six too — extend it, don't fork it. Blog and Labs needed two capabilities `ListFilter`
  didn't originally have (two-way URL sync via `history.replaceState`, read back on load; and
  AND-tag matching, where a card must carry *every* selected tag, vs. the OR-any matching the other
  four pages use for their single-select facets) — rather than keep them on a bespoke script,
  `ListFilter` gained `urlSync` and `facetMode: 'and'` (plus a `chipGroup` option for a second,
  independent single-select facet — Blog's category chips, Labs' source chips) so they could join
  the shared controller too. The listing grids all use the shared `.card-grid` (above) *except* Blog
  and Labs, which render their own wider content cards (`BlogCard`, `lab-item`; excerpt + tags + meta
  need more room than a 232px tile) — deliberate, not a gap to close. Adding a new toggle to a page is
  normally just: a `data-*` attribute on the card + one `{ id, attr }` entry in that page's
  `ListFilter` config + a matching `<FilterToggle>` button — the controller needs no changes.
  Two more shared, opt-in pieces sit above the grid on these list pages: `GroupOverview` (a
  browsable tile strip — icon + blurb + count per group, links to `#<id>` — for pages whose
  groups are an unordered taxonomy; used on Glossary's categories and Tools' platforms) and
  `TacticStepper` (an ordered, horizontally-scrolling pill sequence sized by item count; for
  pages whose groups are a kill-chain/lifecycle with a real order — used on both MITRE maps).
  Pick by data shape, not by page: unordered groups get `GroupOverview`, ordered ones get
  `TacticStepper`. Either way, the target `<details>` group needs a matching `id` and
  `scrollMarginTop` so the anchor jump clears the sticky header.
- **Experience: detailed vs. condensed.** Headline/relevant roles get full timeline cards
  (company header, per-role title + dates + one-sentence summary + skill tags). Earlier,
  contract, or foundational roles go in **one condensed block** below — a single bordered
  card listing one line each (`title · org` left, `type · year` right, mono/muted), no
  per-role detail. Keeps the trajectory visible without diluting the headline roles.

## Assets & social cards

One Satori-based renderer (`src/og/card.mjs` + `src/og/star.mjs`, self-hosted fonts under
`src/og/fonts/`) draws both the favicon/app-icon family and every page's social-share card —
so the pixel-star mark and the OG cards can never drift into two different looks.

- **Per-page OG images.** `src/og/routes.ts` is the single source of truth for which pages get
  a card and what it says (title + eyebrow, mirroring each page's `PageHeader`). It's a plain
  list of static entries plus every non-draft post/lab/tag, and it's imported by both
  `src/pages/og/[...slug].png.ts` (the endpoint that renders each PNG at build) and `BaseHead`
  (so `<meta og:image>` always points at a slug the endpoint actually generated — it can never
  404). **When you add a new static page, add it to `STATIC_ENTRIES` in `og/routes.ts`** or it
  falls back to the home card. `ogSlugForPath()` is the one place that maps a live URL to its
  OG slug — glossary term pages and the legacy `/term-of-the-day/` redirect
  intentionally all resolve to the shared `glossary` card rather than one image each.
- **Static brand assets.** `scripts/gen-brand.mjs` (`npm run gen:brand`) calls the same renderer
  to (re)generate `favicon.svg`, the favicon/apple-touch/PWA icon PNGs, and the static fallback
  `/og.png`, writing them straight into `public/`. Re-run it after changing the mark or the
  default-dark palette in `card.mjs` — it isn't part of the build, so nothing regenerates these
  automatically.

## Layout & motion

- Content max width **960px**, centered, `px: '1.25rem'`.
- Section rhythm: ~2.5–3.5rem vertical gaps; cards gap ~1–1.25rem.
- Animations are **subtle** (150–300ms) and must respect `prefers-reduced-motion`
  (the background animation disables itself; honor this for anything new).

## Accessibility

- Semantic elements (`<nav>`, `<header>`, `<main>`, `<section>`, `<ol>`); one `<h1>` per page.
- Interactive controls are real `<button>`/`<a>` with `aria-label` when icon-only.
- Decorative SVG/icons get `aria-hidden`; meaningful ones get a `label`.
- Maintain text/background contrast — rely on the semantic tokens, which are tuned per theme.
