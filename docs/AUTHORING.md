# Authoring Guide

How to add and format content. Two collections exist: **blog** (articles) and
**labs** (challenge/CTF writeups). Schemas are enforced at build time by
[`src/content.config.ts`](../src/content.config.ts) — a missing or mistyped field fails
the build, which is intentional.

> **Content source — hard rule.** Write only from **public lab & CTF challenges and personal
> study** (CyberDefenders, 13Cubed, MemLabs, Magnet, home lab). **Never** publish real,
> employer, or client investigations or data — that's an employer/confidentiality breach.
> No "redacted real case" framing.
>
> **Voice:** conversational practitioner, first person, original (see
> [STYLE_GUIDE.md](STYLE_GUIDE.md)). **Priority pillars:** Host forensics & Memory forensics.

---

## Add a blog post

Create `src/content/blog/<slug>.mdx`. The filename (minus extension) becomes the URL:
`src/content/blog/volatility3-installation.mdx` → `/blog/volatility3-installation/`.

### Blog frontmatter

| Field        | Required | Type / values | Notes |
| ------------ | :------: | ------------- | ----- |
| `title`      | ✅ | string | Post title. |
| `date`       | ✅ | date (`YYYY-MM-DD`) | Publish date; used for sorting & RSS. |
| `category`   | ✅ | `Memory Forensics` \| `Host Forensics` \| `EDR Analysis` \| `Labs` \| `Tools` \| `Notes` | Drives the category badge + icon. |
| `excerpt`    | ✅ | string | 1–2 sentence summary (cards, SEO, RSS). |
| `tags`       |   | string[] | Lowercase topic tags, e.g. `["volatility3", "malware"]`. |
| `tools`      |   | string[] | Tools featured, shown as accent badges. |
| `difficulty` |   | `Beginner` \| `Intermediate` \| `Advanced` \| `Hard` | Optional. |
| `author`     |   | string | Defaults to `Patrick Saade`. |
| `readTime`   |   | number | Overrides the auto estimate (minutes). |
| `updated`    |   | date | Last-updated date. |
| `heroImage`  |   | string | Path under `public/`. For post-body images, prefer local relative paths so Astro auto-optimizes them. |
| `series`     |   | string | Group multi-part posts — those sharing this value render a linked series box. |
| `seriesOrder`|   | number | Position within the series (1, 2, 3…). |
| `attack`     |   | string[] | MITRE ATT&CK technique IDs covered, e.g. `["T1003","T1055.012"]`; marks them "covered" on `/reference/attack-map/`. |
| `d3fend`     |   | string[] | MITRE D3FEND technique IDs demonstrated, e.g. `["D3-FH","D3-PM"]`; feeds a "Mentioned in my writeups" link on `/reference/d3fend/[id]/`. |
| `featured`   |   | boolean | `true` surfaces it on the home page. |
| `draft`      |   | boolean | `true` hides it from production builds. |

```mdx
---
title: "Volatility 3: Finding Malware in Memory"
date: 2026-02-20
category: "Memory Forensics"
excerpt: "Detecting injected code and rogue processes in a Windows memory image."
tags: ["volatility3", "malware", "memory analysis"]
tools: ["Volatility 3"]
difficulty: "Intermediate"
featured: true
---

Your intro paragraph here…

## A section heading

Headings render into the auto table of contents (h2 + h3 only).
```

---

## Add a lab writeup

Create `src/content/labs/<slug>.mdx` → `/labs/<slug>/`.

### Lab frontmatter

| Field        | Required | Type / values | Notes |
| ------------ | :------: | ------------- | ----- |
| `title`      | ✅ | string | Prefix with `[Lab Writeup]` by convention. |
| `date`       | ✅ | date | |
| `difficulty` | ✅ | `Beginner` \| `Intermediate` \| `Advanced` \| `Hard` | |
| `source`     | ✅ | string | Platform, e.g. `CyberDefenders`, `13Cubed`, `Home Lab`. |
| `excerpt`    | ✅ | string | |
| `sourceUrl`  |   | url | Link to the challenge. |
| `timeSpent`  |   | string | e.g. `~2.5 hours`. |
| `tags`       |   | string[] | |
| `tools`      |   | string[] | |
| `iocCount`   |   | number | Feeds the CTF/labs stats. |
| `series`     |   | string | Group multi-part labs. |
| `seriesOrder`|   | number | Position within the series. |
| `attack`     |   | string[] | ATT&CK technique IDs covered; feeds `/reference/attack-map/`. |
| `d3fend`     |   | string[] | D3FEND technique IDs demonstrated; feeds `/reference/d3fend/`. |
| `draft`      |   | boolean | |

**Recommended section structure:**

```
## Challenge Summary
## Approach
## Key Findings
## Timeline
## IOCs Extracted
## Lessons Learned
```

> Flags/answers should be omitted or redacted — the methodology is the point.

---

## Add a glossary term (Term of the Day)

The bank lives in `src/data/securityTerms.ts` (a small curated core) and
`src/data/terms/*.json` (per-domain batches). Add terms by appending objects to the
matching `terms/<domain>.json` array:

```json
{
  "term": "Kerberoasting",
  "slug": "kerberoasting",
  "aka": ["SPN roasting"],
  "short": "Cracking service-account passwords from requested Kerberos tickets offline.",
  "definition": "What it is, in 1–2 sentences.",
  "significance": "Why it matters in DFIR / IR, in 1–2 sentences.",
  "example": "One concrete, investigation-flavored sentence.",
  "related": ["another-slug-in-the-bank"]
}
```

Rules: **vendor-agnostic** (a concept/technique/artifact, never a product), `slug` is
lowercase kebab-case, `short` ≤ 90 chars, `aka` optional. The bank de-duplicates by slug
(curated wins) and drops any `related` slug that doesn't resolve, so cross-links can't
break the build. Write each field as natural prose — see the Style Guide's
[Glossary terms](STYLE_GUIDE.md) note. Run `npm test`; `test/securityTerms.test.ts`
enforces the structure.

---

## Formatting reference

- **Code blocks** — fence with a language for syntax highlighting:
  ````
  ```bash
  vol -f memory.raw windows.pslist
  ```
  ````
  Colors follow the active theme's mode (Shiki dual-theme).
- **Inline code** — `` `vol.py` ``.
- **Images** — place under `public/images/blog/` or `public/images/labs/` and reference
  with an absolute path (`/images/blog/foo.png`). They're styled with rounded borders.
- **Internal links** — link related posts with root-relative paths **ending in a slash**, e.g.
  `[Memory Forensics 101](/blog/memory-forensics-101/)` (the site uses `trailingSlash: 'always'`).
  This powers discoverability and the related-posts block (auto-matches by category + shared tags).
- **Hover cards** — companies, certs, and key tools get context cards automatically. To give a
  glossary term an inline hover/tap card, import the component once and wrap the word:
  `import Term from '../../components/Term.astro';` then
  `<Term slug="order-of-volatility">order of volatility</Term>` (slug must exist in the glossary).
- **Tables, blockquotes, lists** — standard Markdown; all are styled in
  [`src/styles/markdown.css`](../src/styles/markdown.css).

---

## Automatic cross-links

Tagging content wires up backlinks for free — nothing to maintain beyond the tag itself:

- **`<Term slug="…">` in a post body** → that term's glossary page lists the post under
  **"Mentioned in my writeups"** (and the inline word also gets a hover/tap card).
- **`attack: ["T1003", …]` frontmatter** → each of those technique pages lists the post under
  **"Covered in my writeups"**, and the technique is marked *covered* on the MITRE ATT&CK map.
- **`tools: ["Volatility 3", …]` frontmatter** → each matching tool's page lists the post under
  **"Featured in my writeups"** (matched by tool name).

So tag accurately — the glossary, the ATT&CK/D3FEND maps, and the tool pages update themselves.

---

## Drafts & preview

- `draft: true` keeps a post out of **production** builds (`npm run build`) and RSS, but
  it's still visible in `npm run dev` so you can preview it. Use this when you're fine
  having the work-in-progress file in the repo.
- To keep an unfinished post **entirely off GitHub**, draft it under `_local/` — that
  directory is gitignored (and Vercel-ignored), so it never reaches the repo, the build,
  or the deploy. The `examples/`, `_local/`, and `evidence/` dirs are all local-only.

## Publishing checklist

- [ ] Frontmatter complete and valid (build passes).
- [ ] `excerpt` is tight and specific.
- [ ] Code examples tested; languages tagged.
- [ ] Images optimized and placed under `public/`.
- [ ] At least one internal link to a related post.
- [ ] `npm run build` succeeds and the page renders in `npm run preview`.
