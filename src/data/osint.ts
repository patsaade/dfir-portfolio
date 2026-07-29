// OSINT data for /tools/osint/, in two halves.
//
// The first half (SEARCH_ENGINES / DORK_OPERATORS / DORK_FOCUSES) drives the
// interactive recipe builder and speaks web-search syntax only — the four
// engines listed below all accept the same literal site:/filetype:/intitle:
// operator family, which is the assumption the whole single-`prefix`-per-
// operator schema rests on.
//
// The second half (PIVOT_PLATFORMS / PIVOT_TRACKS, at the bottom of this file)
// covers the specialist platforms a DFIR responder actually pivots through —
// Shodan, Censys, crt.sh, GitHub code search, urlscan.io, VirusTotal
// Intelligence — whose query languages share nothing with the above. They are
// deliberately kept OUT of the builder's engine switch: pasting Shodan syntax
// into Google returns confident-looking garbage rather than an error, so every
// query there names its target platform and links its own vendor docs.
//
// Recipe-builder model, unchanged: a Focus (culinary "style") highlights
// which Ingredients (operator fields) matter and offers a few named Presets;
// picking a Preset fills those ingredients, and the live-assembled Recipe is
// the final query. Every operator's syntax and support status is verified
// against each engine's own current help documentation — Google has both
// formally deprecated several classic "dork" operators over the years
// (cache:, related:, info:, the + prefix, the ~ synonym operator — all
// excluded here) AND quietly stopped *documenting* several others that are
// still long-standing and functional (intitle:, inurl:, intext:, OR,
// before:/after:) without retiring them; `note` flags that distinction per
// operator rather than presenting undocumented-but-working and officially-
// documented syntax as equivalent. Focuses/presets are well-established
// OSINT patterns, framed for authorized/defensive use (assessing your own
// exposure, or an authorized investigation) — consistent with this site's
// dual-use-tool guidance. A preset's `values` can put multiple alternatives
// on a single prefix-kind ingredient as "termA OR termB" (the builder expands
// this into the correct parenthesized `(filetype:termA OR filetype:termB)`
// syntax) — see DorkBuilder.astro's fragmentFor(). `values.site`, when
// present, deliberately overrides the domain field (e.g. a preset that's
// inherently about a third-party host like an S3 bucket, not the user's own
// site) — the builder only preserves the user's typed domain when a preset
// does NOT specify one.
//
// Engine roster (verified 2026, see each id's DORK_OPERATORS notes for the
// per-operator breakdown): Google, Bing, and DuckDuckGo as before, plus
// **Brave** — Brave Search now runs a fully independent, self-built crawler
// and index (its own docs: search.brave.com/help/brave-search-crawler; Brave
// has publicly described ending its prior fallback calls to Bing), so it's a
// genuine coverage-gap filler, not a re-skin of an engine already listed.
// Brave's own operator documentation (search.brave.com/help/operators) uses
// the *same literal* site:/filetype:/intitle:/""/-/OR syntax already modeled
// below, so it slots into the existing single-`prefix`-per-operator schema
// cleanly — it's deliberately NOT added to inurl:/intext:/before:/after:
// (see those operators' notes: Brave has no URL-substring or date operator,
// and its body-text operator is a differently-named inbody:, not intext:).
// Two other engines were researched and deliberately left out:
//   - **Startpage** — still a privacy-preserving *proxy in front of Google's
//     own index* (confirmed current as of this review), not an independently
//     crawled index. Per this file's own crawler-independence rule, that
//     makes it a redundant duplicate of the Google entry already here, not a
//     coverage-gap filler.
//   - **Yandex** — genuinely independently crawled, with real strength in
//     Russian/CIS-language coverage relevant to some threat-intel OSINT work.
//     Rejected anyway: its own official docs (yandex.com/support/search)
//     show its operator syntax diverges too far from the Google-style syntax
//     this schema assumes for a single shared `prefix` string — `mime:` not
//     `filetype:`, `|` not `OR`, `date:>YYYYMMDD`/`date:<YYYYMMDD` (or a
//     `date:YYYYMMDD..YYYYMMDD` range) not `before:`/`after:`, and a literal-
//     address `url:`/`host:`/`domain:` family rather than a substring
//     `inurl:`. Wiring Yandex in without a per-engine syntax layer (a real
//     but out-of-scope refactor) would silently emit incorrect queries for
//     most of the presets below, so it's excluded rather than guessed at.
//   - (Also researched: **Mojeek**, a genuinely independent UK-based crawler.
//     Its own operator docs — mojeek.com/support/search-operators.html — are
//     an explicit, exhaustive list: site:/intitle:/inurl:/intext:/before:/
//     since:, and nothing else. No filetype:, no OR, no documented exact-
//     phrase or minus-exclude syntax, and its date keyword is `since:` not
//     `after:`. Too little verified, literally-matching overlap with the
//     operators below to support correctly — left out for the same reason
//     as Yandex, not because its index isn't independent.)

type EngineId = 'google' | 'bing' | 'duckduckgo' | 'brave';

export interface SearchEngine {
  id: EngineId;
  label: string;
  /** Prefix; the builder appends `encodeURIComponent(query)`. */
  searchUrl: string;
}

export const SEARCH_ENGINES: SearchEngine[] = [
  { id: 'google', label: 'Google', searchUrl: 'https://www.google.com/search?q=' },
  { id: 'bing', label: 'Bing', searchUrl: 'https://www.bing.com/search?q=' },
  { id: 'duckduckgo', label: 'DuckDuckGo', searchUrl: 'https://duckduckgo.com/?q=' },
  { id: 'brave', label: 'Brave', searchUrl: 'https://search.brave.com/search?q=' },
];

type DorkOperatorKind = 'prefix' | 'phrase' | 'exclude' | 'or';

export interface DorkOperator {
  /** Also the builder's form-field id. */
  id: string;
  label: string;
  placeholder: string;
  description: string;
  kind: DorkOperatorKind;
  /** Literal syntax prefix, e.g. 'site:' — used when kind is 'prefix'. */
  prefix?: string;
  /** Which engines currently honor this operator (drives field visibility). */
  engines: EngineId[];
  /** Cross-engine support caveat, shown in the operator reference table. */
  note?: string;
}

export const DORK_OPERATORS: DorkOperator[] = [
  {
    id: 'site',
    label: 'Site / domain',
    placeholder: 'example.com',
    description: 'Restrict results to one domain (or several, as "a.com OR b.com").',
    kind: 'prefix',
    prefix: 'site:',
    engines: ['google', 'bing', 'duckduckgo', 'brave'],
    note: 'Officially documented on all four engines (Brave: search.brave.com/help/operators). Google\'s own docs note it "doesn\'t necessarily return all indexed URLs" under a domain — treat it as a search convenience, not a guaranteed asset inventory.',
  },
  {
    id: 'filetype',
    label: 'File type',
    placeholder: 'pdf',
    description: 'Only files of this extension (or several, as "pdf OR docx").',
    kind: 'prefix',
    prefix: 'filetype:',
    engines: ['google', 'bing', 'duckduckgo', 'brave'],
    note: 'Officially documented on all four engines (Brave also aliases it as ext:). DuckDuckGo supports a narrower, explicitly listed set of extensions (pdf, doc(x), xls(x), ppt(x), html) than Google/Bing/Brave. Brave\'s own docs flag its whole operator set as "experimental and in the early stage of development."',
  },
  {
    id: 'intitle',
    label: 'Title contains',
    placeholder: 'index of',
    description: 'Only pages with this text in the page title.',
    kind: 'prefix',
    prefix: 'intitle:',
    engines: ['google', 'bing', 'duckduckgo', 'brave'],
    note: 'Officially documented on Bing, DuckDuckGo, and Brave. Long-standing and still functional on Google, but Google\'s current public docs no longer formally list it.',
  },
  {
    id: 'inurl',
    label: 'URL contains',
    placeholder: 'admin',
    description: 'Only pages with this text in the URL path (or several, as "login OR admin").',
    kind: 'prefix',
    prefix: 'inurl:',
    engines: ['google', 'duckduckgo'],
    note: 'Officially documented on DuckDuckGo. Still functional on Google (undocumented). Bing suspended inurl: around 2007 to curb data-mining abuse and never restored it. Brave has no equivalent — its own operator docs list inbody:/inpage: (body/title text) but no URL-substring operator, so it\'s deliberately left out here rather than mapped onto a prefix Brave wouldn\'t recognize.',
  },
  {
    id: 'intext',
    label: 'Body text contains',
    placeholder: 'confidential',
    description: 'Only pages with this text in the page body.',
    kind: 'prefix',
    prefix: 'intext:',
    engines: ['google'],
    note: 'Still functional on Google, but undocumented by Google today. Bing/DuckDuckGo have no direct equivalent operator. Brave has a same-purpose inbody: operator, but under a different literal keyword than intext: — not wired in here, since this schema shares one literal prefix string per operator across engines and inbody: would need its own.',
  },
  {
    id: 'phrase',
    label: 'Exact phrase',
    placeholder: 'internal use only',
    description: 'Match this exact phrase, wrapped in quotes.',
    kind: 'phrase',
    engines: ['google', 'bing', 'duckduckgo', 'brave'],
    note: 'Officially documented, identical behavior, on all four engines.',
  },
  {
    id: 'exclude',
    label: 'Exclude terms',
    placeholder: 'jobs careers',
    description: 'Drop results containing any of these words.',
    kind: 'exclude',
    engines: ['google', 'bing', 'duckduckgo', 'brave'],
    note: 'Officially documented on all four. Bing requires the alternate NOT keyword to be capitalized if used instead of "-". Brave documents the same "-" syntax alongside its logical AND/OR/NOT keywords.',
  },
  {
    id: 'or',
    label: 'Match any of these terms',
    placeholder: 'login signin',
    description: 'Match any one of these words (space-separated) instead of all of them.',
    kind: 'or',
    engines: ['google', 'bing', 'brave'],
    note: 'Officially documented on Bing (capital OR, or "|") and Brave (capital OR, alongside AND/NOT as logical operators). Still functional on Google (undocumented). DuckDuckGo has no explicit OR keyword — space-separated terms already match loosely by default there.',
  },
  {
    id: 'before',
    label: 'Last updated before',
    placeholder: '2024-01-01',
    description: 'Only pages last updated before this date (YYYY-MM-DD or YYYY).',
    kind: 'prefix',
    prefix: 'before:',
    engines: ['google'],
    note: 'Officially documented on Google only. Bing and DuckDuckGo expose date filtering solely as a results-page UI control, not a query operator. Brave\'s own operator docs list no date operator at all.',
  },
  {
    id: 'after',
    label: 'Last updated after',
    placeholder: '2023-01-01',
    description: 'Only pages last updated after this date (YYYY-MM-DD or YYYY).',
    kind: 'prefix',
    prefix: 'after:',
    engines: ['google'],
    note: 'Officially documented on Google only — combine with "before" for a range. Brave\'s own operator docs list no date operator at all.',
  },
];

interface DorkPreset {
  title: string;
  desc: string;
  /** The full, literal, verified query — a `<domain>`/`<name>` placeholder shown as a reference caption. */
  queryTemplate: string;
  /** operator id -> value to hydrate the ingredients when this preset is picked. */
  values: Record<string, string>;
}

export interface DorkFocus {
  id: string;
  label: string;
  desc: string;
  /**
   * Which <optgroup> this focus sits under in the builder's Focus dropdown.
   * Must be one of FOCUS_GROUPS — the builder renders groups in that array's
   * order, not in DORK_FOCUSES' own order, so a focus can be appended to the
   * end of the list below without disturbing where it appears in the UI.
   */
  group: FocusGroup;
  /** Ingredient (operator) ids to visually highlight while this focus is active. */
  highlight: string[];
  presets: DorkPreset[];
  /** A technique worth knowing that doesn't map cleanly onto a single preset. */
  tip?: string;
}

/**
 * The three shapes of work this builder gets used for, in the order the Focus
 * dropdown shows them. Kept as an explicit ordered list rather than derived
 * from first-appearance order in DORK_FOCUSES, so appending a focus never
 * silently reshuffles the dropdown.
 */
export const FOCUS_GROUPS = [
  'Your own exposure',
  'Live investigation',
  'People & organizations',
] as const;
export type FocusGroup = (typeof FOCUS_GROUPS)[number];

export const DORK_FOCUSES: DorkFocus[] = [
  {
    id: 'files',
    group: 'Your own exposure',
    label: 'Exposed Files & Documents',
    desc: 'Publicly indexed files that may have been published by mistake — reports, contracts, or logs never meant for a public page.',
    highlight: ['site', 'filetype', 'intext'],
    presets: [
      {
        title: 'Indexed PDFs & office docs',
        desc: 'Surfaces publicly indexed PDF, Word, and Excel files under a domain — useful for checking whether internal reports, HR documents, or contracts were accidentally published or linked from a public page.',
        queryTemplate: 'site:<domain> (filetype:pdf OR filetype:docx OR filetype:xlsx)',
        values: { filetype: 'pdf OR docx OR xlsx' },
      },
      {
        title: 'Documents with sensitive markings',
        desc: 'Combines a filetype filter with body-text matching to find files marked confidential/internal that still got indexed — a common sign a document was uploaded to a public-facing path by mistake.',
        queryTemplate: 'site:<domain> filetype:pdf intext:confidential',
        values: { filetype: 'pdf', intext: 'confidential' },
      },
      {
        title: 'Log files with secrets',
        desc: 'Finds indexed .log files and filters for common secret-bearing terms — useful for catching error/debug logs that leaked stack traces, passwords, or internal hostnames.',
        queryTemplate: 'site:<domain> filetype:log intext:password',
        values: { filetype: 'log', intext: 'password' },
      },
    ],
  },
  {
    id: 'directories',
    group: 'Your own exposure',
    label: 'Directory Listings',
    desc: "A web server's directory-listing feature left enabled, exposing the raw file/folder structure instead of a proper index page.",
    highlight: ['site', 'intitle', 'inurl'],
    presets: [
      {
        title: 'Open directory index',
        desc: 'A classic misconfiguration that can leak internal files, old backups, or unlinked assets never meant to be browsed directly.',
        queryTemplate: 'site:<domain> intitle:"index of /"',
        values: { intitle: 'index of /' },
      },
      {
        title: 'Backup folder browsing',
        desc: 'Narrows the open-directory search to a specific path — useful for confirming whether a particular known folder on your own infrastructure is inadvertently browsable.',
        queryTemplate: 'site:<domain> intitle:"index of" inurl:backup',
        values: { intitle: 'index of', inurl: 'backup' },
      },
    ],
  },
  {
    id: 'panels',
    group: 'Your own exposure',
    label: 'Login & Admin Panels',
    desc: 'Administrative or database-management interfaces that are internet-facing and discoverable when they should be restricted to a VPN or internal network.',
    highlight: ['site', 'intitle', 'inurl'],
    presets: [
      {
        title: 'Admin login pages',
        desc: 'Finds indexed administrative login pages on a domain.',
        queryTemplate: 'site:<domain> intitle:admin (inurl:login OR inurl:admin)',
        values: { intitle: 'admin', inurl: 'login OR admin' },
      },
      {
        title: 'Common CMS/dashboard paths',
        desc: 'Looks for well-known admin/dashboard URL patterns (wp-admin, /manager, /dashboard) that got indexed.',
        queryTemplate: 'site:<domain> (inurl:wp-admin OR inurl:dashboard OR inurl:manager)',
        values: { inurl: 'wp-admin OR dashboard OR manager' },
      },
      {
        title: 'Internet-facing phpMyAdmin',
        desc: 'Finds indexed phpMyAdmin login interfaces — a widely deployed MySQL admin tool that should never be reachable from the open internet; indexing implies it is publicly routable.',
        queryTemplate: 'site:<domain> intitle:phpMyAdmin inurl:phpmyadmin',
        values: { intitle: 'phpMyAdmin', inurl: 'phpmyadmin' },
      },
      {
        title: 'Other exposed DB admin UIs',
        desc: 'Looks for indexed pages from common database web-management tools (Adminer, pgAdmin).',
        queryTemplate: 'site:<domain> (intitle:Adminer OR intitle:pgAdmin)',
        values: { intitle: 'Adminer OR pgAdmin' },
      },
    ],
  },
  {
    id: 'credentials',
    group: 'Your own exposure',
    label: 'Credentials & Backups',
    desc: 'Config, backup, and dump files that frequently contain database credentials, API keys, and secret tokens.',
    highlight: ['site', 'filetype'],
    presets: [
      {
        title: 'Environment & config files',
        desc: 'Targets .env, .ini, and .conf files, which frequently contain database credentials, API keys, and secret tokens for web frameworks when accidentally deployed to a public web root.',
        queryTemplate: 'site:<domain> (filetype:env OR filetype:ini OR filetype:conf)',
        values: { filetype: 'env OR ini OR conf' },
      },
      {
        title: 'Database dumps & archives',
        desc: 'Finds SQL dumps and generic backup/archive files that may have been left in a web-accessible path — a high-severity finding since these can contain full table exports including user data.',
        queryTemplate: 'site:<domain> (filetype:sql OR filetype:bak OR filetype:zip) intext:backup',
        values: { filetype: 'sql OR bak OR zip', intext: 'backup' },
      },
    ],
  },
  {
    id: 'cloud',
    group: 'Your own exposure',
    label: 'Cloud Storage',
    desc: "Publicly readable cloud storage buckets tied to an organization's name — a very common real-world misconfiguration.",
    highlight: ['site', 'phrase'],
    presets: [
      {
        title: 'Public bucket exposure (S3 / Azure / GCS)',
        desc: "Checks the three major cloud-storage hostnames for indexed content mentioning your organization's name — a publicly readable bucket can expose files, backups, or logs that should be private. Type your company or domain name into the phrase field below.",
        queryTemplate: '(site:s3.amazonaws.com OR site:blob.core.windows.net OR site:storage.googleapis.com) "<company name>"',
        values: { site: 's3.amazonaws.com OR blob.core.windows.net OR storage.googleapis.com' },
      },
    ],
  },
  {
    id: 'assets',
    group: 'Your own exposure',
    label: 'Subdomains, Assets & Source Code',
    desc: 'External asset inventory — forgotten staging hosts, default install pages, and source code or credentials leaked to public repos.',
    highlight: ['site', 'inurl', 'intitle'],
    presets: [
      {
        title: 'Non-production hosts',
        desc: 'Filters indexed subdomains for common pre-production naming patterns (dev/staging/test/uat), which are frequently less hardened than production and a common source of accidental exposure.',
        queryTemplate: 'site:<domain> (inurl:dev OR inurl:staging OR inurl:test OR inurl:uat)',
        values: { inurl: 'dev OR staging OR test OR uat' },
      },
      {
        title: 'Default install/setup pages',
        desc: 'Finds leftover default installation, setup, or "it works" pages for common web software, which reveal the underlying stack and sometimes still allow completing setup if never locked down.',
        queryTemplate: 'site:<domain> intitle:"welcome to" ("nginx" OR "apache" OR "IIS")',
        values: { intitle: 'welcome to', or: 'nginx apache IIS' },
      },
      {
        title: 'Exposed .git directories',
        desc: "Finds indexed .git metadata paths, which indicate a deployed application's source-controlled directory (including history and possibly credentials in old commits) is reachable over HTTP.",
        queryTemplate: 'site:<domain> inurl:.git intitle:"index of"',
        values: { inurl: '.git', intitle: 'index of' },
      },
      {
        title: 'Code or credentials on GitHub',
        desc: "Searches GitHub for references to your domain alongside common secret-bearing terms, which can reveal internal scripts, hardcoded credentials, or infrastructure notes committed to a public repo by mistake. Type your domain into the phrase field below.",
        queryTemplate: 'site:github.com "<domain>" (password OR secret OR api_key)',
        values: { site: 'github.com', or: 'password secret api_key' },
      },
    ],
    tip: 'To enumerate every indexed subdomain at once (excluding just the main www host), try site:*.<domain> -site:www.<domain> directly — it doesn\'t map onto a single ingredient, so it isn\'t a preset above, but it\'s a genuinely useful pattern to type in by hand.',
  },
  {
    id: 'person',
    group: 'People & organizations',
    label: 'Find a Person',
    desc: 'Cross-reference a name against professional, social, and document sources — verifying a claimed identity, vetting a candidate or vendor, or confirming the registrant behind a suspicious contact during an authorized investigation. Type the name into the phrase field below.',
    highlight: ['phrase', 'site'],
    presets: [
      {
        title: 'Professional profile lookup',
        desc: "Finds a person's LinkedIn profile page directly — the well-established recruiter/OSINT \"X-ray search\" technique for bypassing LinkedIn's own limited on-site search. A standard first step for verifying a claimed employer/title on a resume or a threat actor's claimed professional identity.",
        queryTemplate: 'site:linkedin.com/in "<name>"',
        values: { site: 'linkedin.com/in' },
      },
      {
        title: 'Cross-platform social footprint',
        desc: 'Searches multiple major social platforms at once for the same name, surfacing accounts that may not be linked to each other — used to build an authorized subject profile or confirm which public accounts actually belong to a person under investigation, rather than a same-named individual.',
        queryTemplate: '"<name>" (site:facebook.com OR site:twitter.com OR site:instagram.com)',
        values: { site: 'facebook.com OR twitter.com OR instagram.com' },
      },
      {
        title: 'Resume or CV discovery',
        desc: 'Finds resumes/CVs a person has published or had indexed as PDF/Word/Excel/PowerPoint files, often surfacing employment history, a phone number, or an email not shown on a locked-down social profile.',
        queryTemplate: '"<name>" (filetype:pdf OR filetype:docx OR filetype:xlsx OR filetype:pptx) intext:resume',
        values: { filetype: 'pdf OR docx OR xlsx OR pptx', intext: 'resume' },
      },
    ],
    tip: 'To rule out a same-named person, pair the name with a known employer or city as two separate exact phrases: "<name>" "<employer-or-location>". That needs two phrase clauses at once, which doesn\'t map onto a single ingredient — worth typing in by hand.',
  },
  {
    id: 'business',
    group: 'People & organizations',
    label: 'Find a Business',
    desc: "Verify a company's public footprint for vendor risk assessments, threat-actor attribution, or confirming the organization behind a suspicious domain or claimed employer. Type the company name into the phrase field below.",
    highlight: ['phrase', 'site', 'filetype'],
    presets: [
      {
        title: 'Corporate LinkedIn presence',
        desc: "Confirms a company's official LinkedIn footprint and lets you cross-check claimed employees/executives against it — a standard first step in vendor and candidate due diligence.",
        queryTemplate: 'site:linkedin.com/company "<company name>"',
        values: { site: 'linkedin.com/company' },
      },
      {
        title: 'Public reports & documents',
        desc: 'Surfaces publicly indexed PDFs (annual reports, whitepapers, filings) a company has published or accidentally exposed on its own domain — useful for financial/vendor-risk review.',
        queryTemplate: 'site:<domain> filetype:pdf intext:"annual report"',
        values: { filetype: 'pdf', intext: 'annual report' },
      },
      {
        title: 'Press & news wire coverage',
        desc: "Searches the two major newswire services for a company's official press releases and third-party coverage — corroborates claims made by or about the organization (acquisitions, leadership changes, incidents) against independently published material.",
        queryTemplate: '(site:businesswire.com OR site:prnewswire.com) "<company name>"',
        values: { site: 'businesswire.com OR prnewswire.com' },
      },
    ],
  },
  {
    id: 'breach',
    group: 'Your own exposure',
    label: 'Paste Sites & Breach Exposure',
    desc: "Indexed mentions of your organization on public paste sites, or paired with breach/leak vocabulary anywhere on the web — the same low-effort first move a threat actor makes after a suspected compromise, useful defensively to catch exposure early. Type your company name or domain into the phrase field below.",
    highlight: ['site', 'phrase', 'or'],
    presets: [
      {
        title: 'Org name on major paste sites',
        desc: 'Searches the two most-indexed public paste/markdown-paste services for mentions of your organization — a common place stolen credentials, internal notes, or source-code snippets end up, whether pasted unintentionally by an employee or deliberately by an attacker advertising a breach.',
        queryTemplate: '(site:pastebin.com OR site:rentry.co) "<company name>"',
        values: { site: 'pastebin.com OR rentry.co' },
      },
      {
        title: 'Domain paired with breach/leak terminology',
        desc: 'Pairs your domain or organization name with common breach/leak vocabulary — a fast way to check whether it is being discussed anywhere indexed in a breach or leak context, not limited to one specific paste site.',
        queryTemplate: '"<company name>" (breach OR leak OR dump OR compromised OR exposed)',
        values: { or: 'breach leak dump compromised exposed' },
      },
      {
        title: 'Your email domain in indexed credential dumps',
        desc: 'Pairs your own email domain with the vocabulary credential dumps get posted under. Type "@yourdomain.com" — with the @ — into the phrase field, so it matches addresses rather than mentions of the company. A hit here is an immediate forced-reset decision, not a research finding.',
        queryTemplate: '"@<domain>" (site:pastebin.com OR site:github.com OR site:gist.github.com) password OR credentials OR combolist',
        values: { site: 'pastebin.com OR github.com OR gist.github.com', or: 'password credentials combolist' },
      },
    ],
    tip: 'Search-engine indexing of paste sites lags by hours to days, so this is a periodic spot-check rather than monitoring — a dedicated paste/leak feed complements it for anything time-sensitive. For the specific question "are my users\' addresses in a known breach", Have I Been Pwned (haveibeenpwned.com) answers it directly: a single address is a free lookup, and searching every address at a domain requires proving you control that domain first.',
  },
  {
    id: 'executive',
    group: 'People & organizations',
    label: 'Executive & VIP Exposure',
    desc: "Assesses a named executive or public figure's protective-intelligence exposure — publicly aggregated personal data and predictable public appearances — distinct from the Find a Person focus above, which is about verifying a claimed identity rather than assessing exposure risk for someone already known. Type the individual's full name into the phrase field below.",
    highlight: ['phrase', 'site', 'intitle'],
    presets: [
      {
        title: 'Data-broker / people-search exposure',
        desc: "Checks the highest-traffic U.S. people-search and data-broker sites for a named individual — these aggregate home addresses, phone numbers, relatives, and property records from public records, and are the standard starting point for a protective-intelligence exposure review or a pre-opt-out audit.",
        queryTemplate: '"<name>" (site:whitepages.com OR site:spokeo.com OR site:truepeoplesearch.com)',
        values: { site: 'whitepages.com OR spokeo.com OR truepeoplesearch.com' },
      },
      {
        title: 'Public appearance & speaking-schedule exposure',
        desc: "Finds conference, panel, or event pages publishing an individual's name alongside a schedule or agenda — a published keynote listing effectively hands anyone watching that person's location, date, and time, which is exactly the predictable-appearance exposure protective-intelligence teams screen for ahead of travel.",
        queryTemplate: '"<name>" (intitle:speaker OR intitle:agenda OR intitle:schedule)',
        values: { intitle: 'speaker OR agenda OR schedule' },
      },
    ],
    tip: "To narrow a common name to the specific individual, pair it with a known employer or city as a second exact phrase — the same two-phrase-clause technique noted under Find a Person above.",
  },

  // ─────────────────────────────────────────────────────────────────────────
  // Response-side focuses. Everything above starts from "here is my estate,
  // what leaked"; everything below starts from "here is an indicator or an
  // actor, what is already known about it". Same ingredients, same four
  // engines, different direction of travel — which is why they're a separate
  // FOCUS_GROUP in the dropdown rather than more entries in the same list.
  //
  // Every third-party hostname used in a `site:` value below was fetched and
  // confirmed live before being written here, same discipline as tools.ts and
  // eventIds.ts: cloud.google.com/blog/topics/threat-intelligence (Google
  // Threat Intelligence Group / Mandiant), unit42.paloaltonetworks.com,
  // blog.talosintelligence.com, securelist.com, malpedia.caad.fkie.fraunhofer.de,
  // hybrid-analysis.com, app.any.run, otx.alienvault.com (now LevelBlue-branded,
  // same host), bazaar.abuse.ch, urlscan.io, cisa.gov, ncsc.gov.uk,
  // attack.mitre.org, github.io (GitHub Pages' documented default domain),
  // pages.dev (Cloudflare Pages' documented default domain), jotform.com.
  // Vendor URL paths are cited the same way — /RDWeb from Microsoft Learn's RD
  // Web Access docs, /owa from Exchange's own virtual-directory docs, /dana-na
  // from CISA's Pulse/Ivanti Connect Secure exploitation advisories.
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: 'phishing',
    group: 'Live investigation',
    label: 'Phishing & Lookalike Pages',
    desc: 'Brand-impersonation pages and credential-harvest kits that name your organization. Type the brand or organization name into the phrase field below.',
    highlight: ['phrase', 'intitle', 'site', 'after'],
    presets: [
      {
        title: 'Credential-harvest pages naming the brand',
        desc: 'A phishing page almost always claims the brand in its title and asks for a sign-in, so searching indexed titles for that pairing surfaces impersonation pages a takedown request can act on. Put your own domain in the Exclude field as "site:yourdomain.com" so your real login page drops out of the results.',
        queryTemplate: '"<brand>" (intitle:login OR intitle:"sign in" OR intitle:"verify your account")',
        values: { intitle: 'login OR sign in OR verify your account' },
      },
      {
        title: 'Brand pages on free hosting',
        desc: "Phishing kits are cheap to stand up on free hosting, where the operator never registers a lookalike domain at all — so domain-monitoring feeds miss them entirely. github.io and pages.dev are the documented default domains for GitHub Pages and Cloudflare Pages; add whichever hosts your own user reports keep naming.",
        queryTemplate: '"<brand>" (site:github.io OR site:pages.dev)',
        values: { site: 'github.io OR pages.dev' },
      },
      {
        title: 'Brand pages on hosted form services',
        desc: 'Same idea one layer down: the credential capture is a hosted form, so there is no attacker-controlled page to scan and no domain to seize. Worth knowing what is already indexed, because these are the reports that arrive with nothing for a takedown request to point at.',
        queryTemplate: '"<brand>" (site:docs.google.com/forms OR site:forms.office.com OR site:jotform.com)',
        values: { site: 'docs.google.com/forms OR forms.office.com OR jotform.com' },
      },
      {
        title: 'Recently updated pages naming the brand',
        desc: "Narrows to pages Google last saw updated after a date you set — not a registration date, and not a discovery date. Set it to the start of your incident window and it becomes a cheap way to spot pages that changed around the same time as a campaign.",
        queryTemplate: '"<brand>" after:2026-01-01',
        values: { after: '2026-01-01' },
      },
    ],
    tip: 'Search engines only index what they can reach, so a phishing site that is geo-fenced, one-time-token gated, or taken down inside a few hours will never show up here at all. Pair this with certificate transparency (crt.sh, in the Pivot queries section below) — a certificate is logged at issuance whether or not the page was ever crawled.',
  },
  {
    id: 'ioc-context',
    group: 'Live investigation',
    label: 'IOC Context & Reputation',
    desc: 'Take one indicator — a domain, IP, hash, or URL — and find out who has already written about it. Type the indicator into the phrase field below.',
    highlight: ['phrase', 'site'],
    presets: [
      {
        title: 'Indicator across public sandboxes and reputation sites',
        desc: 'Each of these publishes a per-indicator page that search engines index, so one query tells you whether an IOC has already been submitted, detonated, or bundled into somebody else\'s report. A hit gives you context for free; a miss usually means you are early.',
        queryTemplate: '"<indicator>" (site:urlscan.io OR site:otx.alienvault.com OR site:app.any.run OR site:hybrid-analysis.com)',
        values: { site: 'urlscan.io OR otx.alienvault.com OR app.any.run OR hybrid-analysis.com' },
      },
      {
        title: 'Indicator in public code, gists, and pastes',
        desc: 'Detection rules, IR notes, and blocklists get committed to public repos constantly. An indicator that turns up inside somebody\'s Sigma rule or hosts file names the family faster than a sandbox run will.',
        queryTemplate: '"<indicator>" (site:github.com OR site:gist.github.com OR site:pastebin.com)',
        values: { site: 'github.com OR gist.github.com OR pastebin.com' },
      },
      {
        title: 'Indicator named in vendor research',
        desc: 'Restricts to four vendor research blogs that publish full IOC lists alongside their write-ups. If an indicator appears in one, you inherit the attribution, the TTPs, and usually a set of sibling indicators to pivot on.',
        queryTemplate: '"<indicator>" (site:cloud.google.com/blog/topics/threat-intelligence OR site:unit42.paloaltonetworks.com OR site:blog.talosintelligence.com OR site:securelist.com)',
        values: { site: 'cloud.google.com/blog/topics/threat-intelligence OR unit42.paloaltonetworks.com OR blog.talosintelligence.com OR securelist.com' },
      },
    ],
    tip: 'Pasting a live indicator into a public search engine is itself a disclosure — the query is logged, and an actor watching for their own infrastructure to be looked up can read that as notice. During an active intrusion, decide deliberately whether the lookup is worth the tip-off before you run it.',
  },
  {
    id: 'malware-hunt',
    group: 'Live investigation',
    label: 'Malware & Sample Hunting',
    desc: 'Write-ups, sandbox reports, and staging infrastructure for a file you are already holding. Type the hash or family name into the phrase field below.',
    highlight: ['phrase', 'site', 'intitle', 'inurl'],
    presets: [
      {
        title: 'Hash across public sample repositories',
        desc: 'A full SHA-256 is unique enough that one query resolves it across every public repository that indexes per-sample pages. Use SHA-256 rather than MD5 or SHA-1 — both of those collide, and a same-hash page is not necessarily the same file.',
        queryTemplate: '"<sha256>" (site:virustotal.com OR site:bazaar.abuse.ch OR site:app.any.run OR site:hybrid-analysis.com)',
        values: { site: 'virustotal.com OR bazaar.abuse.ch OR app.any.run OR hybrid-analysis.com' },
      },
      {
        title: 'Family write-ups and alias tracking',
        desc: 'Every vendor names things differently. Malpedia and MITRE both maintain alias lists per family and per group, which makes this the fastest way to turn one vendor\'s name for something into every other name the same activity is tracked under.',
        queryTemplate: '"<family>" (site:malpedia.caad.fkie.fraunhofer.de OR site:attack.mitre.org)',
        values: { site: 'malpedia.caad.fkie.fraunhofer.de OR attack.mitre.org' },
      },
      {
        title: 'Open directories staging payloads',
        desc: 'Commodity loaders routinely pull their next stage from a plain open directory, and those get crawled like any other page. Once you have a staging host out of a sample, put it in the Site field and you often get the rest of the campaign\'s payload set with it.',
        queryTemplate: 'intitle:"index of" (inurl:.exe OR inurl:.ps1 OR inurl:.hta OR inurl:.bin)',
        values: { intitle: 'index of', inurl: '.exe OR .ps1 OR .hta OR .bin' },
      },
    ],
    tip: 'Do not submit a sample or a URL from a live intrusion to a public sandbox — the submission is public, and adversaries watch for their own tooling appearing there. Search first, and submit only once you have decided the disclosure is acceptable.',
  },
  {
    id: 'threat-intel',
    group: 'Live investigation',
    label: 'Threat Actor & Campaign Research',
    desc: 'Pull together what is already published about a named actor, malware family, or campaign. Type the name into the phrase field below.',
    highlight: ['phrase', 'site', 'filetype'],
    presets: [
      {
        title: 'Vendor research naming the actor',
        desc: 'Four research teams that publish long-form campaign analysis with the indicators attached. Start here when you have a name from an alert or a colleague and need the primary source behind it rather than a summary of a summary.',
        queryTemplate: '"<actor>" (site:cloud.google.com/blog/topics/threat-intelligence OR site:unit42.paloaltonetworks.com OR site:blog.talosintelligence.com OR site:securelist.com)',
        values: { site: 'cloud.google.com/blog/topics/threat-intelligence OR unit42.paloaltonetworks.com OR blog.talosintelligence.com OR securelist.com' },
      },
      {
        title: 'Government and national CERT advisories',
        desc: 'CISA and the UK NCSC publish joint advisories with detection guidance and mitigations that vendor blogs often omit. These also carry the authority you need when the write-up has to go to somebody outside the security team.',
        queryTemplate: '"<actor>" (site:cisa.gov OR site:ncsc.gov.uk)',
        values: { site: 'cisa.gov OR ncsc.gov.uk' },
      },
      {
        title: 'Full reports as PDF',
        desc: 'Long-form threat reports are usually published as a PDF that the HTML summary only links to, and the appendix is where the complete indicator list lives. Filtering on the body phrase keeps marketing decks out of the results.',
        queryTemplate: '"<actor>" filetype:pdf intext:"indicators of compromise"',
        values: { filetype: 'pdf', intext: 'indicators of compromise' },
      },
      {
        title: 'Alias resolution across trackers',
        desc: 'Actor naming is genuinely fragmented — the same intrusion set can carry six vendor names. MITRE\'s group pages and Malpedia both maintain cross-referenced alias lists, so this is the query that tells you whether two reports are describing the same thing.',
        queryTemplate: '"<actor>" (site:attack.mitre.org OR site:malpedia.caad.fkie.fraunhofer.de)',
        values: { site: 'attack.mitre.org OR malpedia.caad.fkie.fraunhofer.de' },
      },
    ],
    tip: 'This site carries its own ATT&CK coverage map and Threat Actor reference, which cover the same ground without a search engine in the loop — reach for these queries when you specifically need the primary vendor report behind an entry.',
  },
  {
    id: 'code-secrets',
    group: 'Your own exposure',
    label: 'Code & Secret Leakage',
    desc: 'Source, config, and credentials from your organization that ended up in a public repository or registry. Type your domain or organization name into the phrase field below.',
    highlight: ['phrase', 'site', 'inurl', 'or'],
    presets: [
      {
        title: 'Your domain across public code hosts',
        desc: 'The broad first pass. Internal hostnames and email domains get committed by accident constantly — in a README, a test fixture, a sample config — and each one is a small piece of your internal topology published for free.',
        queryTemplate: '"<domain>" (site:github.com OR site:gitlab.com OR site:bitbucket.org)',
        values: { site: 'github.com OR gitlab.com OR bitbucket.org' },
      },
      {
        title: 'Secret-shaped strings alongside your domain',
        desc: 'Pairs your domain with the variable names credentials are conventionally stored under. Not every hit is a live secret — plenty are placeholders — but the ones that are not tend to be the highest-severity finding of the day.',
        queryTemplate: '"<domain>" (site:github.com OR site:gitlab.com) api_key OR client_secret OR aws_access_key_id OR private_key',
        values: { site: 'github.com OR gitlab.com', or: 'api_key client_secret aws_access_key_id private_key' },
      },
      {
        title: 'Config, CI, and infrastructure files',
        desc: 'Targets the file paths that describe how something is deployed rather than what it does. A committed docker-compose file or workflow definition maps your build pipeline, service names, and sometimes the registries and hosts they talk to.',
        queryTemplate: '"<domain>" site:github.com (inurl:.env OR inurl:docker-compose OR inurl:.github/workflows OR inurl:terraform)',
        values: { site: 'github.com', inurl: '.env OR docker-compose OR .github/workflows OR terraform' },
      },
      {
        title: 'Internal names on public package registries',
        desc: 'An internal package name that exists publicly is both a leak and a dependency-confusion setup, since a build that resolves the public one first will happily install someone else\'s code. Worth knowing which of your internal names are already taken.',
        queryTemplate: '"<domain>" (site:npmjs.com OR site:pypi.org OR site:hub.docker.com)',
        values: { site: 'npmjs.com OR pypi.org OR hub.docker.com' },
      },
    ],
    tip: 'Google indexes repository pages it has crawled; it does not search file contents. For that you need GitHub\'s own code search, which is in the Pivot queries section below — it does path: globs and content: matching that no web search engine can express.',
  },
  {
    id: 'remote-access',
    group: 'Your own exposure',
    label: 'Remote Access & Edge Devices',
    desc: 'Internet-facing VPN, remote-desktop, webmail, and out-of-band management entry points on your own estate — the front door a large share of intrusions come through. Type your domain into the Site field below.',
    highlight: ['site', 'inurl', 'intitle'],
    presets: [
      {
        title: 'Remote-desktop and webmail portals',
        desc: '/RDWeb is the default virtual directory Microsoft documents for RD Web Access, and /owa the one Exchange documents for Outlook on the web. If either is indexed, it is reachable from the open internet — which is a decision worth confirming somebody actually made.',
        queryTemplate: 'site:<domain> (inurl:/RDWeb OR inurl:/owa)',
        values: { inurl: '/RDWeb OR /owa' },
      },
      {
        title: 'VPN appliance web paths',
        desc: '/dana-na is the Ivanti (formerly Pulse) Connect Secure web path named in CISA\'s own exploitation advisories, and /vpn the generic gateway path several other appliances use. These devices are a recurring initial-access target, so knowing which of yours are indexed is two minutes well spent.',
        queryTemplate: 'site:<domain> (inurl:/dana-na OR inurl:/vpn)',
        values: { inurl: '/dana-na OR /vpn' },
      },
      {
        title: 'Out-of-band management interfaces',
        desc: 'Dell iDRAC and HPE iLO are baseboard management controllers — full console and power control underneath the operating system. Neither should ever be internet-reachable, so an indexed page carrying the product name in its title is worth chasing to ground the same day.',
        queryTemplate: 'site:<domain> (intitle:iDRAC OR intitle:iLO)',
        values: { intitle: 'iDRAC OR iLO' },
      },
    ],
    tip: 'An empty result here proves nothing. Search engines only index pages they were linked to and allowed to crawl, and appliance login pages are usually neither. Treat this as a fast first pass, then confirm properly with Shodan or Censys in the Pivot queries below — those scan the address space directly instead of waiting on a crawler.',
  },
];

// ───────────────────────────────────────────────────────────────────────────
// Pivot queries — the specialist half of the toolkit.
//
// The recipe builder above only speaks web-search syntax, and deliberately so:
// its four engines all accept the same literal site:/filetype:/intitle: family.
// The platforms below do not. Shodan, Censys, crt.sh, GitHub code search,
// urlscan.io and VirusTotal each have their own field names and operators, and
// pasting one into another produces silent garbage rather than an error — which
// is exactly why these live in their own section with the target platform named
// on every single query, rather than being folded into the builder's engine
// switch.
//
// Field names and operators here were verified against each platform's own
// current documentation before being written:
//   Shodan   — shodan.io/search/filters (the published filter list)
//   Censys   — docs.censys.com/docs/censys-query-language + the Platform host
//              dataset reference (CenQL; the Platform replaced legacy Search)
//   crt.sh   — verified live against the running service, including the SQL
//              LIKE `%` wildcard in both `%.domain` and `%substring%` form
//   GitHub   — docs.github.com/.../understanding-github-code-search-syntax
//   urlscan  — urlscan.io/docs/search/ (Elasticsearch query-string fields)
//   VirusTotal — docs.virustotal.com/docs/file-search-modifiers
// Anything that could not be verified was left out rather than guessed at:
// notably Censys JARM (the field exists but its shape is undocumented), Shodan
// negation syntax, and several vendor appliance URL paths.
// ───────────────────────────────────────────────────────────────────────────

// Kept file-local (not exported), same as DorkPreset above: osint.astro consumes
// PIVOT_PLATFORMS/PIVOT_TRACKS structurally and never imports these names, and
// an exported-but-unimported type is exactly what `npm run audit:deadcode`
// flags. DorkFocus stays exported because DorkBuilder.astro imports it by name.
interface PivotPlatform {
  id: string;
  label: string;
  /** What it actually indexes — one line, so a reader knows why they'd reach for it. */
  what: string;
  /** The honest access story: free, sign-in required, or paid tier. */
  access: string;
  /** Official syntax documentation. */
  docsUrl: string;
  /**
   * Where a query gets run. Deliberately the platform's own search page and
   * not a pre-filled deep link: every query below is a template with a
   * `<placeholder>` still in it, so a deep link would just run a search for
   * the literal angle brackets. Copy, substitute, paste.
   */
  openUrl: string;
}

export const PIVOT_PLATFORMS: PivotPlatform[] = [
  {
    id: 'shodan',
    label: 'Shodan',
    what: 'Internet-wide scan data — open ports, service banners, TLS certificates, HTTP titles and bodies, and screenshots, indexed by host.',
    access: 'Free account for basic search; several filters (including vuln: and tag:) are restricted to paid memberships.',
    docsUrl: 'https://www.shodan.io/search/filters',
    openUrl: 'https://www.shodan.io/',
  },
  {
    id: 'censys',
    label: 'Censys Platform',
    what: 'A second independent internet-wide scan dataset, with hosts, web properties and certificates as separate queryable datasets you can join across.',
    access: 'Free account with a monthly query allowance; CenQL replaced the legacy Censys Search syntax.',
    docsUrl: 'https://docs.censys.com/docs/censys-query-language',
    openUrl: 'https://platform.censys.io/search',
  },
  {
    id: 'crtsh',
    label: 'crt.sh',
    what: 'A searchable mirror of the public certificate transparency logs — every certificate a participating CA has issued, whether or not the host it was issued for was ever online.',
    access: 'Free, no account. `%` is a SQL LIKE wildcard, so `%.example.com` matches subdomains and `%example%` matches a substring anywhere in the identity.',
    docsUrl: 'https://certificate.transparency.dev/',
    openUrl: 'https://crt.sh/',
  },
  {
    id: 'github',
    label: 'GitHub code search',
    what: 'The contents of public repositories — not just the pages a web crawler reached, but the files themselves, searchable by path glob, language, and literal content.',
    access: 'Free, but you must be signed in to GitHub for code search to return results.',
    docsUrl: 'https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax',
    openUrl: 'https://github.com/search?type=code',
  },
  {
    id: 'urlscan',
    label: 'urlscan.io',
    what: 'A public archive of website scans — every request a page made, the files it served, its TLS issuer, its ASN, and a screenshot, for every scan anyone submitted publicly.',
    access: 'Free to search public scans. Queries use Elasticsearch query-string syntax.',
    docsUrl: 'https://urlscan.io/docs/search/',
    openUrl: 'https://urlscan.io/search/',
  },
  {
    id: 'virustotal',
    label: 'VirusTotal Intelligence',
    what: 'Search across VirusTotal\'s sample corpus by structural similarity rather than by exact hash — import hash, fuzzy hash, signer, submission window, engine verdict.',
    access: 'Looking up a single hash is free; the search modifiers below are VirusTotal Intelligence, which is a paid tier.',
    docsUrl: 'https://docs.virustotal.com/docs/file-search-modifiers',
    openUrl: 'https://www.virustotal.com/',
  },
];

interface PivotQuery {
  /** PivotPlatform id. */
  platform: string;
  title: string;
  /** The literal query. `<placeholders>` are the parts you substitute. */
  query: string;
  desc: string;
}

interface PivotTrack {
  id: string;
  label: string;
  desc: string;
  queries: PivotQuery[];
}

export const PIVOT_TRACKS: PivotTrack[] = [
  {
    id: 'infrastructure',
    label: 'Infrastructure pivoting',
    desc: 'One indicator in, related infrastructure out. A single domain, IP, or certificate is almost never the whole picture — these walk outward from it until the edges stop moving.',
    queries: [
      {
        platform: 'shodan',
        title: 'Hosts serving a certificate for a domain',
        query: 'ssl.cert.subject.cn:"<domain>"',
        desc: 'Every scanned host presenting a TLS certificate whose subject common name is this domain, wherever it happens to live. This is how the origin behind a CDN, a staging copy on a different provider, or a box still serving a certificate you thought was retired all surface.',
      },
      {
        platform: 'shodan',
        title: 'Certificate data mentioning an organization',
        query: 'ssl:"<organization name>"',
        desc: 'Broader than the common-name filter: matches the organization string anywhere in the certificate, which catches hosts behind a wildcard or SAN-only certificate that never names an individual domain.',
      },
      {
        platform: 'shodan',
        title: 'Everything scanned in an organization\'s netblocks',
        query: 'org:"<organization name>"',
        desc: 'Keyed on network registration data, which is the weak link — subsidiaries, acquisitions, and anything cloud-hosted usually sit under somebody else\'s org string entirely. Treat a clean result as "this is what is registered to you", not "this is all of you".',
      },
      {
        platform: 'shodan',
        title: 'Everything scanned in a CIDR range',
        query: 'net:<CIDR>',
        desc: 'The precise version of the org: query above, and the one to use once you have the actual allocation out of RIR data rather than trusting a name match.',
      },
      {
        platform: 'shodan',
        title: 'Hosts sharing a favicon',
        query: 'http.favicon.hash:<hash>',
        desc: 'Shodan stores a hash of each host\'s favicon. Two servers built from the same panel or kit serve the same icon, so the hash still matches after the domain, certificate, and IP have all been rotated — one of the few pivots that survives an operator rebuilding.',
      },
      {
        platform: 'shodan',
        title: 'Hosts sharing a TLS stack fingerprint',
        query: 'ssl.jarm:<jarm hash>',
        desc: 'JARM fingerprints how a server\'s TLS stack answers a fixed set of probes. Identical software and configuration produce identical fingerprints, which is what groups C2 servers of one family together across hosting providers. Expect false positives from anything running a stock stack.',
      },
      {
        platform: 'censys',
        title: 'Hosts resolving under a name',
        query: 'host.dns.names:"<domain>"',
        desc: 'The second opinion on Shodan\'s view. The two scan on different schedules from different vantage points, and disagreement between them is itself information — usually about something that recently appeared or recently went away.',
      },
      {
        platform: 'censys',
        title: 'Certificates issued to an organization',
        query: 'cert.parsed.subject.organization:"<organization name>"',
        desc: 'Censys keeps certificates as their own dataset, so this searches issuance records directly rather than only the hosts currently presenting them. Good for finding the certificates behind assets that are already offline.',
      },
      {
        platform: 'censys',
        title: 'Certificates by subject common name',
        query: 'cert.parsed.subject.common_name:"<domain>"',
        desc: 'The certificate-dataset equivalent of Shodan\'s ssl.cert.subject.cn filter. Run both — the two services log from different CT log sets and different scan histories, and neither is complete on its own.',
      },
      {
        platform: 'censys',
        title: 'Hosts that redirect to a domain',
        query: 'host.services.endpoints.http.redirect_chain.hostname="<domain>"',
        desc: 'Hosts whose HTTP redirect chain lands on this domain. Catches parked lookalikes, forgotten vanity domains, and traffic-laundering hops that point at you but carry none of your names in their own certificates.',
      },
      {
        platform: 'censys',
        title: 'Hosts in an ASN running a given service',
        query: 'host.autonomous_system.asn=<number> and host.services.port=443',
        desc: 'CenQL\'s `and` combines conditions across the whole host record. Swap the port for whatever you are chasing; the ASN keeps it to one network rather than the whole internet.',
      },
      {
        platform: 'censys',
        title: 'A specific service on a specific port',
        query: 'host.services: (software.product="<product>" and endpoints.http.html_title="<title>")',
        desc: 'The nested form — parentheses after `host.services:` require both conditions to hold for the same service object, rather than for the host as a whole. Without the nesting you get hosts that run the product somewhere and show that title somewhere else.',
      },
      {
        platform: 'crtsh',
        title: 'Every certificate ever logged for a domain\'s subdomains',
        query: '%.<domain>',
        desc: 'The best free subdomain inventory there is, because certificate transparency records issuance rather than reachability. Hosts that were never linked, never crawled, and are long since decommissioned are all still in here.',
      },
      {
        platform: 'crtsh',
        title: 'Certificates naming an organization',
        query: '<organization name>',
        desc: 'The identity search also matches organization names in certificate subjects, which surfaces assets under domains you did not know to ask about — the usual way a forgotten acquisition\'s infrastructure turns up.',
      },
      {
        platform: 'urlscan',
        title: 'Public scans of a domain',
        query: 'page.domain:"<domain>"',
        desc: 'Everything anyone has publicly scanned on this domain, with the full request chain and a screenshot per scan. Often the only surviving record of what a page looked like before it was pulled.',
      },
      {
        platform: 'urlscan',
        title: 'Where a domain appears as a subresource',
        query: 'domain:"<domain>" AND NOT page.domain:"<domain>"',
        desc: 'Scans that contacted this domain without it being the page being scanned. Read one way it is your third-party dependency footprint on other people\'s sites; read the other way it is every scanned page that reached out to infrastructure you are investigating.',
      },
      {
        platform: 'urlscan',
        title: 'Recent scans of an IP',
        query: 'page.ip:"<ip>" AND date:>now-30d',
        desc: 'Ties an address to the hostnames actually served from it recently. `date:>now-30d` is the documented relative-date form and keeps a long-lived shared-hosting IP from burying the thing you are after.',
      },
    ],
  },
  {
    id: 'phishing',
    label: 'Phishing & malicious domains',
    desc: 'Lookalike registrations, kit reuse, and the certificate trail a phishing site leaves behind before anyone reports it.',
    queries: [
      {
        platform: 'crtsh',
        title: 'Lookalike domains carrying a brand string',
        query: '%<brand>%',
        desc: 'Substring wildcards on both sides match the brand anywhere in a certificate identity, which is how you find brand-alike registrations the moment they request a certificate — typically hours to days before the page goes live and long before anyone reports it.',
      },
      {
        platform: 'crtsh',
        title: 'Certificates for a suspect domain\'s subdomains',
        query: '%.<suspect domain>',
        desc: 'Once you have one confirmed lookalike, this enumerates what else was issued under it. Phishing operators reuse a registration across several targets, so the sibling names usually name the rest of the campaign\'s victims.',
      },
      {
        platform: 'urlscan',
        title: 'Newly registered domains scanned recently',
        query: 'page.domain:"<domain>" AND page.domainAgeDays:<30',
        desc: 'Domain age is a strong phishing signal on its own — legitimate business infrastructure is rarely three weeks old. Both halves are documented urlscan fields; combine with a brand term to scope it.',
      },
      {
        platform: 'urlscan',
        title: 'Community-tagged phishing scans',
        query: 'task.tags:"phishing" AND page.domain:"<domain>"',
        desc: 'Submitters tag scans, and phishing is the most consistently applied tag on the platform. Cheap corroboration when you are deciding whether something is worth escalating.',
      },
      {
        platform: 'urlscan',
        title: 'Pages by certificate issuer and title',
        query: 'page.tlsIssuer:"<issuer>" AND page.title:"<brand>"',
        desc: 'Kits get deployed with the same free-CA certificate and the same copied page title over and over. Pairing the two is a surprisingly durable signature for one operator\'s output.',
      },
      {
        platform: 'shodan',
        title: 'Hosts serving a string from a confirmed kit',
        query: 'http.html:"<distinctive string>"',
        desc: 'Matches a literal string in the page body across everything Shodan has crawled. Take a genuinely distinctive artifact out of a confirmed phishing page — a form action, a misspelled label, a hardcoded element id — and this finds every other host running the same kit.',
      },
      {
        platform: 'shodan',
        title: 'Hosts titled after a brand',
        query: 'http.title:"<brand>"',
        desc: 'Impersonation pages copy the real page title verbatim, because that is what makes the browser tab look right. Noisy on its own; useful once you narrow it with a port, a country, or a certificate filter.',
      },
      {
        platform: 'github',
        title: 'The kit\'s own source',
        query: '"<distinctive string>" NOT is:fork',
        desc: 'Phishing kits are shared as source far more often than people expect. Feeding a distinctive string from a page into code search sometimes lands you the whole kit, including the exfiltration endpoint the operator forgot to change.',
      },
    ],
  },
  {
    id: 'malware',
    label: 'File, hash & sample hunting',
    desc: 'Start from a file you are holding and find its relatives — same builder, same signer, same infrastructure — rather than only its exact hash.',
    queries: [
      {
        platform: 'virustotal',
        title: 'Samples sharing an import hash',
        query: 'entity:file imphash:"<imphash>" p:5+',
        desc: 'The import hash summarises a PE\'s import table, which is a property of how it was compiled rather than of its contents — so it survives repacking and recompilation that change the file hash completely. `p:5+` trims the noise floor to samples at least five engines flag.',
      },
      {
        platform: 'virustotal',
        title: 'Fuzzy-hash neighbours',
        query: 'entity:file ssdeep:"<ssdeep hash>"',
        desc: 'ssdeep is a context-triggered piecewise hash: similar files produce similar hashes. Use it when you suspect you have one build out of a series and want the others.',
      },
      {
        platform: 'virustotal',
        title: 'Structural-similarity neighbours',
        query: 'entity:file vhash:"<vhash>"',
        desc: 'VirusTotal\'s own structural clustering hash. It tends to group a family more tightly than ssdeep does, at the cost of missing more distant relatives — run both and compare the two result sets.',
      },
      {
        platform: 'virustotal',
        title: 'A family within a time window',
        query: 'entity:file engines:"<family name>" fs:2026-01-01+',
        desc: 'Everything any engine labelled with this family name, first submitted after a date. `fs:` is first submission, so this reads as "when did this family start showing up", not "when was it last seen".',
      },
      {
        platform: 'virustotal',
        title: 'Samples signed by one identity',
        query: 'entity:file sigcheck:"<signer name>" p:1+',
        desc: 'Once one abused or stolen code-signing certificate turns up in an investigation, this finds the rest of what was signed with it — usually the fastest route to the full scope of a supply-chain or signed-loader campaign.',
      },
      {
        platform: 'virustotal',
        title: 'A filename that keeps appearing',
        query: 'entity:file name:"<filename>" p:3+',
        desc: 'Matches the names files were submitted under. Weak evidence on its own — names are trivially changed — but a distinctive dropped filename recurring across unrelated submitters is a real lead.',
      },
      {
        platform: 'urlscan',
        title: 'Where a file was served from',
        query: 'files.sha256:"<sha256>"',
        desc: 'urlscan records the files each scanned page served, so this turns a hash into the URLs and hosts that delivered it. Turns "I have the payload" into "I have the delivery chain".',
      },
      {
        platform: 'github',
        title: 'A hash in public detection content',
        query: '"<sha256>" NOT is:fork',
        desc: 'Hashes land in Sigma rules, YARA files, and IOC lists well before they land in a blog post. `NOT is:fork` keeps the same rule repository from being returned three hundred times.',
      },
      {
        platform: 'shodan',
        title: 'Hosts serving the same payload path',
        query: 'http.html:"<staging filename>"',
        desc: 'Once you have a staging filename out of a sample, this finds the other open directories serving it — which is generally the rest of the campaign\'s infrastructure with no further work.',
      },
    ],
  },
  {
    id: 'exposure',
    label: 'Exposed & leaked assets',
    desc: 'What is reachable, published, or committed that should not be. Same question the web-search focuses ask, answered by scanning and by reading files rather than by asking a crawler what it happened to see.',
    queries: [
      {
        platform: 'github',
        title: 'Environment files in an organization',
        query: 'org:<github org> path:*.env',
        desc: 'A committed .env is the single highest-yield finding in this whole section — they exist to hold credentials, and they get committed constantly. `path:` takes globs, so this matches the file wherever it sits in the tree.',
      },
      {
        platform: 'github',
        title: 'Private keys by file content',
        query: 'org:<github org> content:"BEGIN RSA PRIVATE KEY"',
        desc: '`content:` restricts matching to file contents rather than paths or metadata — the thing no web search engine can do. The PEM header is a fixed string, so this has effectively no false-positive rate.',
      },
      {
        platform: 'github',
        title: 'Terraform state files',
        query: '"<domain>" path:*.tfstate',
        desc: 'Terraform state records the resources it manages along with, in older or carelessly configured setups, their secrets in plaintext. It also maps your cloud estate in one file, which is worth just as much to somebody scoping you.',
      },
      {
        platform: 'github',
        title: 'Internal hostnames in live code',
        query: '"<internal hostname>" NOT is:fork NOT is:archived',
        desc: 'Excluding forks and archived repositories cuts most of the duplicate noise, leaving code somebody is plausibly still running. An internal hostname in a public repo maps your network for free.',
      },
      {
        platform: 'github',
        title: 'CI workflow definitions',
        query: '"<domain>" path:.github/workflows',
        desc: 'Workflow files describe the build pipeline, the registries it pushes to, and the names of every secret it consumes. Even with the values redacted, the shape of the pipeline is useful reconnaissance.',
      },
      {
        platform: 'shodan',
        title: 'Screenshots of everything in your estate',
        query: 'org:"<organization name>" has_screenshot:true',
        desc: 'Shodan screenshots services with a visual protocol — RDP, VNC, web panels. Scrolling the grid is genuinely the fastest way to see what your estate looks like from outside, and unattended desktops and default panels are impossible to miss.',
      },
      {
        platform: 'shodan',
        title: 'Exposed remote desktop',
        query: 'org:"<organization name>" port:3389',
        desc: 'RDP straight to the internet remains one of the most common initial-access paths in real incidents. This is the one query on this page worth running against your own org string before you finish reading it.',
      },
      {
        platform: 'shodan',
        title: 'A specific product inside a range',
        query: 'net:<CIDR> product:"<product>"',
        desc: 'Scoped to a range you actually own, this answers "how many of these are exposed" without the ambiguity of matching on a registration name. Use it when a CVE lands and you need a number by the end of the meeting.',
      },
      {
        platform: 'censys',
        title: 'Vulnerable services in a network',
        query: 'host.autonomous_system.asn=<number> and host.services.vulns.id:"<CVE id>"',
        desc: 'Censys attaches vulnerability identifiers to service records, so this scopes a specific CVE to a specific ASN. The equivalent Shodan filter (vuln:) is restricted to paid memberships, which makes this the free route to the same answer.',
      },
      {
        platform: 'crtsh',
        title: 'Shadow IT and forgotten subdomains',
        query: '%.<domain>',
        desc: 'Same query as the infrastructure track, different question. Read the result as an asset inventory: anything in here you cannot account for is either shadow IT, an abandoned project, or somebody else\'s certificate for your name — and all three are worth an answer.',
      },
    ],
  },
  {
    id: 'actor',
    label: 'Actor & campaign research',
    desc: 'Turning a name into detection content, and detection content back into infrastructure.',
    queries: [
      {
        platform: 'github',
        title: 'Detection rules naming an actor',
        query: '"<actor name>" (path:*.yml OR path:*.yar) NOT is:fork',
        desc: 'Sigma rules are YAML and YARA rules are .yar, so the two path globs cover most published detection content. The rule that catches a campaign is usually public before the report describing it is.',
      },
      {
        platform: 'github',
        title: 'Proof-of-concept and exploitation tooling',
        query: '"<CVE id>" path:*.py NOT is:fork',
        desc: 'Tells you how weaponised a vulnerability actually is, which is a different and more useful question than its CVSS score when you are deciding what to patch tonight.',
      },
      {
        platform: 'urlscan',
        title: 'Scans tagged for a campaign',
        query: 'task.tags:"<campaign tag>"',
        desc: 'Researchers tag their submissions, so a campaign tag often gathers scans from several unrelated people. Good corroboration, and occasionally a set of hosts nobody has published yet.',
      },
      {
        platform: 'shodan',
        title: 'Panels by issuer and title together',
        query: 'ssl.cert.issuer.cn:"<CA name>" http.title:"<panel title>"',
        desc: 'C2 panels are consistent about both the free CA they get certificates from and what their login page calls itself. Either filter alone is far too noisy; together they narrow to something reviewable by hand.',
      },
      {
        platform: 'virustotal',
        title: 'Where a family is being submitted from',
        query: 'entity:file engines:"<family name>" submitter:<ISO country code>',
        desc: '`submitter:` takes an ISO 3166-1 alpha-2 country code. Submission geography is a rough proxy for targeting, and a family suddenly appearing from a new region is worth noticing.',
      },
      {
        platform: 'censys',
        title: 'A software and port combination',
        query: 'host.services: (port=<port> and software.product="<product>")',
        desc: 'Once a report names the software and port a campaign\'s servers run, the nested form finds the rest of them. Requires both conditions on the same service object, which is what stops it matching unrelated hosts that happen to satisfy each separately.',
      },
    ],
  },
];
