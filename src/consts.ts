// Site-wide configuration and shared constants.
import type { IconName } from './components/Icon.astro';

export const SITE = {
  title: 'Patrick Saade',
  // Display wordmark (nav + footer). `title` stays formal for <title>/SEO/JSON-LD.
  brand: 'Patrick (Pat) Saade',
  brandShort: 'Pat Saade', // nav wordmark on narrow screens (avoids nav overflow)
  tagline: 'Digital Forensics & Incident Response',
  description:
    'Hands-on DFIR — digital forensics & incident response: memory & host forensics, EDR investigation, timeline reconstruction, and public lab & CTF writeups.',
  // www is the canonical serving domain in production (the apex domain 307s
  // here) — every absolute URL this site generates (canonical tags, sitemap,
  // RSS, OG images, JSON-LD) should point straight at it, not through a redirect.
  url: 'https://www.patricksaade.com',
  author: 'Patrick Saade',
} as const;

export const SOCIALS = {
  linkedin: 'https://www.linkedin.com/in/patsaade',
  github: 'https://github.com/patsaade',
  credly: 'https://www.credly.com/users/patsaade',
} as const;

// Source repository — used for the footer version/commit link (see utils/version.ts)
// and the colophon's own source link. Single source of truth: never hardcode this
// URL at a call site, or a repo rename silently leaves a stale link behind (which
// is exactly what the personal-portfolio → dfir-portfolio rename did).
export const REPO = 'https://github.com/patsaade/dfir-portfolio';

// Plain top-level nav links (Navigation.astro's own Blog/Labs/About map,
// desktop + mobile) and Footer.astro's Explore column. The categorized
// sections are NOT here — they're dropdowns built from SITE_ENTRIES below.
export const NAV_LINKS = [
  { href: '/blog/', label: 'Blog' },
  { href: '/labs/', label: 'Labs' },
  { href: '/about/', label: 'About' },
] as const;

// ---------------------------------------------------------------------------
// The site taxonomy.
//
// ONE AXIS IN THE NAVIGATION; THE OTHER AXIS IS A TAG.
//
// `type` picks the menu — read it (reference), feed it input (tool), practice
// (drill). `category` picks the sub-group within that menu, chosen by the VERB
// (what does it do to the input?), never by subject matter. `domains` is a
// multi-valued TAG that drives filter chips and topic hub pages — it is never
// a location, which is what lets one page be both `networking` and `dfir`
// without living in two menus.
//
// Two structural rules are enforced by test/consts.test.ts, not by convention:
//   - A category needs >= 5 entries to exist. Below that its items belong in
//     the nearest broader category; above ~12, split by the next sub-verb —
//     never by domain, which would reintroduce the two-axis problem.
//   - A domain earns its own hub page at >= 8 tagged entries (`hub: true`).
//     Below that it's filter-only.
// Note that drill entries COUNT toward both rules — `networking` and `systems`
// each sit at exactly 8 and only clear the hub threshold because their drills
// are tagged. Dropping a drill's `domains` tags silently demotes a hub.
// ---------------------------------------------------------------------------

export type EntryType = 'reference' | 'tool' | 'drill';
export type Domain = 'dfir' | 'networking' | 'systems' | 'windows' | 'web' | 'malware';
export type CategoryId =
  | 'lookup-tables'
  | 'guides-concepts'
  | 'frameworks-maps'
  | 'artifact-parsers'
  | 'decoders-extractors'
  | 'converters-calculators'
  | 'rule-query-builders'
  | 'drills';

export interface SiteEntry {
  href: string;
  label: string;
  icon: IconName;
  description: string;
  type: EntryType;
  category: CategoryId;
  domains: readonly [Domain, ...Domain[]]; // non-empty
}

// Category metadata, in display order within each menu. `blurb` is the short
// one-line summary used by jump-strip tiles; `intro` is the longer 2-3
// sentence paragraph used by a section header — deliberately distinct prose
// rather than a paraphrase, since a tile and its section sit close together on
// the same page and identical text there reads as a bug.
export const CATEGORIES: { id: CategoryId; type: EntryType; label: string; blurb: string; intro: string }[] = [
  {
    id: 'lookup-tables',
    type: 'reference',
    label: 'Lookup Tables',
    blurb: 'Tables you scan for one specific value — an event ID, a port, a status code, a record type.',
    intro:
      "Arrive with a number or a code in hand and leave knowing what it means. Each of these is a full, individually-cited table rather than a summary: every Windows Security and Sysmon event ID that matters for DFIR, the TCP/UDP ports worth recognizing in traffic, IANA's own special-use address ranges, every assigned HTTP status code, the common DNS record types, and the whole 7-bit ASCII table.",
  },
  {
    id: 'guides-concepts',
    type: 'reference',
    label: 'Guides & Concepts',
    blurb: 'Material you read through to understand something, rather than look one value up in.',
    intro:
      "These explain rather than enumerate: the vocabulary the rest of the site is written in, a curated catalog of the tools worth knowing, verified command references by platform, regex syntax token by token, and the layered network models everything else gets described in terms of.",
  },
  {
    id: 'frameworks-maps',
    type: 'reference',
    label: 'Frameworks & Maps',
    blurb: 'The published models the industry describes attacks and defenses in terms of.',
    intro:
      "MITRE ATT&CK catalogs how adversaries operate and D3FEND catalogs how to counter them; the kill chain frames where in an intrusion you are, and the Pyramid of Pain frames how much a given indicator actually costs the adversary. Each map here is browsable in full, with its own detail page per technique or group.",
  },
  {
    id: 'artifact-parsers',
    type: 'tool',
    label: 'Artifact Parsers',
    blurb: "Give it a file; get that format's internal structure back, field by field.",
    intro:
      "Each of these parses one specific Windows artifact format from the ground up — a PE binary's headers, sections and imports, a .lnk shortcut's embedded target path, a Prefetch file's run counts and timestamps, or the $STANDARD_INFORMATION vs $FILE_NAME pair in a raw MFT/USN record. The file never leaves your browser.",
  },
  {
    id: 'decoders-extractors',
    type: 'tool',
    label: 'Decoders & Extractors',
    blurb: 'Paste a string or a block of text; get its fields pulled back out and explained.',
    intro:
      "These take something you already have as text — a log excerpt, a raw header block, a token, an address — and recover the structured pieces buried in it, with the caveats spelled out wherever a field is a claim rather than a fact. Nothing pasted in is transmitted anywhere.",
  },
  {
    id: 'converters-calculators',
    type: 'tool',
    label: 'Converters & Calculators',
    blurb: 'Put a value in one representation in; get it back in another, or get the math done.',
    intro:
      'Timestamps across 19 formats, hashes computed and verified locally, obfuscated payloads peeled back a step at a time, numbers across bases, storage units across the decimal/binary split, subnet and VLAN math from CIDR notation, and CVSS scored from its own metric vector.',
  },
  {
    id: 'rule-query-builders',
    type: 'tool',
    label: 'Rule & Query Builders',
    blurb: 'Build a piece of syntax here to run somewhere else — a SIEM, a scanner, a search engine.',
    intro:
      "These don't analyze something already in hand; they help you construct the thing you're about to run elsewhere, and let you test it against a sample first: a regex, a Sigma or YARA rule, a KQL or SPL query, or a search-operator string for OSINT recon.",
  },
  {
    id: 'drills',
    type: 'drill',
    label: 'Drills',
    blurb: "Practice modules that generate their questions from this site's own verified datasets.",
    intro:
      "Each drill draws on the same cited data the reference pages render — real raw log samples, real MITRE technique IDs, real documented actor aliases — so practicing here and looking something up there can never disagree. Every answer links back to the full writeup behind it.",
  },
];

// Domain tags. `hub` marks the three that have earned their own topic hub page
// at >= 8 tagged entries; the rest are filter chips until they qualify.
export const DOMAINS: { id: Domain; label: string; blurb: string; hub: boolean }[] = [
  {
    id: 'dfir',
    label: 'DFIR',
    blurb: 'Digital forensics and incident response — artifacts, detection, and attacker tradecraft.',
    hub: true,
  },
  {
    id: 'networking',
    label: 'Networking',
    blurb: 'Addressing, protocols, ports, and the layered models that describe them.',
    hub: true,
  },
  {
    id: 'systems',
    label: 'Systems',
    blurb: 'Operating-system and general-computing fundamentals — encoding, scheduling, storage, and the shell.',
    hub: true,
  },
  { id: 'windows', label: 'Windows', blurb: 'Windows-specific artifacts, logging, and internals.', hub: false },
  { id: 'web', label: 'Web', blurb: 'HTTP, email, tokens, and the headers that carry them.', hub: false },
  { id: 'malware', label: 'Malware', blurb: 'Binary analysis, obfuscation, and detection rules.', hub: false },
];

// Every navigable reference page, tool, and drill on the site — one flat list,
// ordered by category in menu order. This is the single source of truth: the
// nav, the sidebar, the footer, the section index pages, and the topic hubs
// are all derived from it.
//
// `icon` is consumed by ToolSidebar's rail, which renders every entry of a
// mode together in one list — so icons must be unique within a type and as
// literally relevant to their own label as possible. Labels are kept short:
// the rail's width (`RAIL_W`) is sized to the longest one with no truncation
// ever added, so a tool's fuller descriptive name belongs on its own page
// (H1/title), not here. `description` is the one-line card blurb.
// Ordered within each category by how often a DFIR analyst actually reaches
// for it — most-used first — not alphabetically or by build date. That order
// is what the nav dropdowns, the sidebar rail, the section index pages and the
// topic hubs all render in, so the first thing in each list is the thing most
// people came for.
export const SITE_ENTRIES: SiteEntry[] = [
  // --- Reference › Lookup Tables ------------------------------------------
  {
    href: '/reference/event-ids/',
    label: 'Event ID Reference',
    icon: 'list',
    description: 'Windows Security + Sysmon event IDs that matter for DFIR.',
    type: 'reference',
    category: 'lookup-tables',
    domains: ['dfir', 'windows'],
  },
  {
    href: '/reference/network-ports/',
    label: 'Network Ports',
    icon: 'server',
    description: 'TCP/UDP ports that matter for DFIR, fully cited with confidence levels.',
    type: 'reference',
    category: 'lookup-tables',
    domains: ['dfir', 'networking'],
  },
  {
    href: '/reference/ip-cidr/',
    label: 'IP & CIDR Reference',
    icon: 'wifi',
    description: 'Special-use IPv4/IPv6 ranges plus a CIDR quick reference, sourced from IANA.',
    type: 'reference',
    category: 'lookup-tables',
    domains: ['networking'],
  },
  {
    href: '/reference/http-status-codes/',
    label: 'HTTP Status Codes',
    icon: 'cloud',
    description: 'Every IANA-assigned HTTP status code, grouped by class, with the exact reason phrase.',
    type: 'reference',
    category: 'lookup-tables',
    domains: ['web', 'networking'],
  },
  {
    href: '/reference/dns-records/',
    label: 'DNS Records',
    icon: 'map-pin',
    description: 'The common DNS resource record types — A, MX, TXT, NS, and more — with their TYPE value and purpose.',
    type: 'reference',
    category: 'lookup-tables',
    domains: ['networking'],
  },
  {
    href: '/reference/ascii-table/',
    label: 'ASCII Table',
    icon: 'message-square',
    description: 'The full 7-bit ASCII table with decimal/hex/octal/binary, plus how Unicode and UTF-8 relate to it.',
    type: 'reference',
    category: 'lookup-tables',
    domains: ['systems'],
  },

  // --- Reference › Guides & Concepts ---------------------------------------
  {
    href: '/reference/glossary/',
    label: 'Glossary',
    icon: 'book-open',
    description: 'A cybersecurity & DFIR glossary.',
    type: 'reference',
    category: 'guides-concepts',
    domains: ['dfir'],
  },
  {
    href: '/reference/command-cheatsheet/',
    label: 'Command Reference',
    icon: 'terminal',
    description: 'Verified DFIR commands for the toolkit, by platform.',
    type: 'reference',
    category: 'guides-concepts',
    domains: ['dfir'],
  },
  {
    href: '/reference/regex-cheatsheet/',
    label: 'Regex Cheat Sheet',
    icon: 'tag',
    description: 'Token-by-token JavaScript/ECMAScript regex syntax reference, searchable by category.',
    type: 'reference',
    category: 'guides-concepts',
    domains: ['dfir', 'systems'],
  },
  {
    href: '/reference/kql-cheatsheet/',
    label: 'KQL Cheat Sheet',
    icon: 'cpu',
    description: 'Kusto syntax for Defender XDR and Sentinel hunting — operators, time windows, joins, and aggregation.',
    type: 'reference',
    category: 'guides-concepts',
    domains: ['dfir'],
  },
  {
    href: '/reference/spl-cheatsheet/',
    label: 'SPL Cheat Sheet',
    icon: 'activity',
    description: 'Splunk Search Processing Language — search commands, eval functions, stats, and field extraction.',
    type: 'reference',
    category: 'guides-concepts',
    domains: ['dfir'],
  },
  {
    href: '/reference/s1-cheatsheet/',
    label: 'SentinelOne Cheat Sheet',
    icon: 'lock',
    description: 'SentinelOne Deep Visibility / PowerQuery syntax, with every field name traced to a published source.',
    type: 'reference',
    category: 'guides-concepts',
    domains: ['dfir'],
  },
  {
    href: '/reference/tool-catalog/',
    label: 'Tool Catalog',
    icon: 'wrench',
    description: 'Free & open-source DFIR tools, grouped by platform.',
    type: 'reference',
    category: 'guides-concepts',
    domains: ['dfir'],
  },
  {
    href: '/reference/osi-model/',
    label: 'OSI & TCP/IP Model',
    icon: 'layers',
    description:
      'The OSI seven-layer model and the practical four-layer TCP/IP model, what runs at each layer, and the well-known/registered/dynamic port ranges.',
    type: 'reference',
    category: 'guides-concepts',
    domains: ['networking'],
  },

  // --- Reference › Frameworks & Maps ---------------------------------------
  {
    href: '/reference/attack-map/',
    label: 'ATT&CK Map',
    icon: 'crosshair',
    description: 'MITRE ATT&CK techniques covered across the site.',
    type: 'reference',
    category: 'frameworks-maps',
    domains: ['dfir'],
  },
  {
    href: '/reference/threat-actors/',
    label: 'Threat Actors',
    icon: 'user',
    description: 'MITRE-documented threat actor groups — aliases, techniques, and known tooling.',
    type: 'reference',
    category: 'frameworks-maps',
    domains: ['dfir'],
  },
  {
    href: '/reference/d3fend/',
    label: 'D3FEND Map',
    icon: 'shield',
    description: 'MITRE D3FEND defensive techniques, mapped to ATT&CK.',
    type: 'reference',
    category: 'frameworks-maps',
    domains: ['dfir'],
  },
  {
    href: '/reference/kill-chain/',
    label: 'Cyber Kill Chain',
    icon: 'arrow-right',
    description:
      "Lockheed Martin's 7-phase intrusion model, phase by phase, mapped to MITRE ATT&CK where it fits.",
    type: 'reference',
    category: 'frameworks-maps',
    domains: ['dfir'],
  },
  {
    href: '/reference/pyramid-of-pain/',
    label: 'Pyramid of Pain',
    icon: 'gauge',
    description:
      "David Bianco's six indicator types, from hash values to TTPs, ranked by cost to the adversary.",
    type: 'reference',
    category: 'frameworks-maps',
    domains: ['dfir'],
  },

  // --- Tools › Artifact Parsers (file input) --------------------------------
  {
    href: '/tools/pe-explorer/',
    label: 'PE Header Explorer',
    icon: 'file-text',
    description: 'Parse a local EXE/DLL — headers, sections, imports, imphash.',
    type: 'tool',
    category: 'artifact-parsers',
    domains: ['dfir', 'malware', 'windows'],
  },
  {
    href: '/tools/prefetch-parser/',
    label: 'Prefetch Parser',
    icon: 'download',
    description: 'Parse a Windows Prefetch (.pf) file — executable name, run count, and last-run timestamps.',
    type: 'tool',
    category: 'artifact-parsers',
    domains: ['dfir', 'windows'],
  },
  {
    href: '/tools/lnk-parser/',
    label: 'LNK Parser',
    icon: 'link',
    description: "Parse a .lnk shortcut file's headers and embedded target path.",
    type: 'tool',
    category: 'artifact-parsers',
    domains: ['dfir', 'windows'],
  },
  {
    href: '/tools/mft-usn-analyzer/',
    label: 'Timestomp Analyzer',
    icon: 'history',
    description: 'Compare $SI vs $FN timestamps in a raw MFT/USN record.',
    type: 'tool',
    category: 'artifact-parsers',
    domains: ['dfir', 'windows'],
  },
  {
    href: '/tools/recycle-bin-parser/',
    label: 'Recycle Bin Parser',
    icon: 'trash-2',
    description:
      'Decode a Windows Recycle Bin $I file — original path, size, and deletion time, both format versions.',
    type: 'tool',
    category: 'artifact-parsers',
    domains: ['dfir', 'windows'],
  },

  // --- Tools › Decoders & Extractors (text input) ---------------------------
  {
    href: '/tools/ioc-extractor/',
    label: 'IOC Extractor',
    icon: 'alert-triangle',
    description: 'Paste a log or report and extract every IOC it contains.',
    type: 'tool',
    category: 'decoders-extractors',
    domains: ['dfir'],
  },
  {
    href: '/tools/email-header-analyzer/',
    label: 'Email Header Analyzer',
    icon: 'mail',
    description: 'Walk the Received chain and read SPF/DKIM/DMARC verdicts.',
    type: 'tool',
    category: 'decoders-extractors',
    domains: ['dfir', 'web'],
  },
  {
    href: '/tools/jwt-decoder/',
    label: 'JWT Decoder',
    icon: 'lock',
    description: "Decode a JSON Web Token's header, payload, and claims — signature verification not included.",
    type: 'tool',
    category: 'decoders-extractors',
    domains: ['dfir', 'web'],
  },
  {
    href: '/tools/user-agent-parser/',
    label: 'User-Agent Parser',
    icon: 'monitor',
    description: 'Parse a raw User-Agent header into browser, engine, and OS, with every caveat spelled out.',
    type: 'tool',
    category: 'decoders-extractors',
    domains: ['dfir', 'web'],
  },
  {
    href: '/tools/mac-address/',
    label: 'MAC Analyzer',
    icon: 'radio',
    description:
      "Decode a MAC address into its OUI and NIC-specific bytes, and see what the U/L and I/G bits mean. Decodes structure only — it doesn't identify the manufacturer.",
    type: 'tool',
    category: 'decoders-extractors',
    domains: ['networking'],
  },
  {
    href: '/tools/cron-parser/',
    label: 'Cron Parser',
    icon: 'calendar',
    description: 'Decode a crontab(5) cron expression into plain English, or build one field by field.',
    type: 'tool',
    category: 'decoders-extractors',
    domains: ['systems'],
  },
  {
    href: '/tools/hash-calculator/',
    label: 'Hash Calculator',
    icon: 'hash',
    description: 'Compute, verify, and identify hashes — entirely local.',
    type: 'tool',
    category: 'converters-calculators',
    domains: ['dfir'],
  },

  // --- Tools › Converters & Calculators -------------------------------------
  {
    href: '/tools/timestamp-converter/',
    label: 'Timestamp Converter',
    icon: 'clock',
    description: 'Bidirectional converter across 19 timestamp/epoch formats.',
    type: 'tool',
    category: 'converters-calculators',
    domains: ['dfir'],
  },
  {
    href: '/tools/deobfuscator/',
    label: 'Codec Builder',
    icon: 'key',
    description: 'Chain Base64/hex/XOR/gzip steps to encode or peel back obfuscated payloads.',
    type: 'tool',
    category: 'converters-calculators',
    domains: ['dfir', 'malware'],
  },
  {
    href: '/tools/cidr-calculator/',
    label: 'Subnet & VLAN Calculator',
    icon: 'grid',
    description: 'Compute network/broadcast/netmask/host range from CIDR notation, plus a subnet & VLAN planner.',
    type: 'tool',
    category: 'converters-calculators',
    domains: ['networking'],
  },
  // Text Diff is parked here deliberately: it's a comparator, not a converter.
  // When a Comparators category reaches 5 entries (hash compare, JSON diff,
  // config diff…), split it out — that's the 5-item rule working as intended.
  {
    href: '/tools/text-diff/',
    label: 'Text Diff Tool',
    icon: 'columns',
    description: 'Compare two logs or text blocks and highlight what changed.',
    type: 'tool',
    category: 'converters-calculators',
    domains: ['dfir'],
  },
  {
    href: '/tools/cvss-calculator/',
    label: 'CVSS Calculator',
    icon: 'bug',
    description:
      'Pick the CVSS v3.1 Base metrics (or paste a vector string) and get the score and severity band.',
    type: 'tool',
    category: 'converters-calculators',
    domains: ['dfir'],
  },
  {
    href: '/tools/base-converter/',
    label: 'Number Base Converter',
    icon: 'rotate-cw',
    description:
      'Convert a value between binary, octal, decimal, and hexadecimal live as you type, with an ASCII decode of the underlying bytes.',
    type: 'tool',
    category: 'converters-calculators',
    domains: ['systems'],
  },
  {
    href: '/tools/data-size-converter/',
    label: 'Data Size Converter',
    icon: 'hard-drive',
    description:
      "Convert between bit, byte, decimal, and binary size units — and see why a '500 GB' drive shows less.",
    type: 'tool',
    category: 'converters-calculators',
    domains: ['systems'],
  },

  // --- Tools › Rule & Query Builders ----------------------------------------
  {
    href: '/tools/regex-tester/',
    label: 'Regex Tester',
    icon: 'search',
    description: 'Live regex playground with a library of common DFIR patterns.',
    type: 'tool',
    category: 'rule-query-builders',
    domains: ['dfir', 'systems'],
  },
  {
    href: '/tools/kql-builder/',
    label: 'KQL Builder',
    icon: 'cpu',
    description:
      'Assemble a Kusto hunting query for Defender XDR or Sentinel against real, documented table columns.',
    type: 'tool',
    category: 'rule-query-builders',
    domains: ['dfir'],
  },
  {
    href: '/tools/spl-builder/',
    label: 'SPL Builder',
    icon: 'activity',
    description:
      'Compose a Splunk SPL search step by step — base search plus stats, table, sort, where, and eval.',
    type: 'tool',
    category: 'rule-query-builders',
    domains: ['dfir'],
  },
  {
    href: '/tools/s1-builder/',
    label: 'SentinelOne Builder',
    icon: 'shield',
    description: 'Compose a SentinelOne Deep Visibility PowerQuery against verified field names.',
    type: 'tool',
    category: 'rule-query-builders',
    domains: ['dfir'],
  },
  {
    href: '/tools/sigma-tester/',
    label: 'Sigma Tester',
    icon: 'target',
    description: 'Build or paste a Sigma rule and test it against sample events.',
    type: 'tool',
    category: 'rule-query-builders',
    domains: ['dfir'],
  },
  {
    href: '/tools/yara-tester/',
    label: 'YARA Tester',
    icon: 'star',
    description:
      'Build a YARA rule string by string and scan it live against a pasted sample — real byte-level matching.',
    type: 'tool',
    category: 'rule-query-builders',
    domains: ['dfir', 'malware'],
  },
  {
    href: '/tools/osint/',
    label: 'OSINT Toolkit',
    icon: 'globe',
    description: 'Interactive search-operator (dork) builder plus recon recipes.',
    type: 'tool',
    category: 'rule-query-builders',
    domains: ['dfir'],
  },
  {
    href: '/drills/event-ids/',
    label: 'Windows Event IDs',
    icon: 'list',
    description: 'Read a raw Security or Sysmon log entry and pull out the fields triage actually turns on.',
    type: 'drill',
    category: 'drills',
    domains: ['dfir', 'windows'],
  },
  {
    href: '/drills/attack/',
    label: 'MITRE ATT&CK',
    icon: 'crosshair',
    description: 'Name the technique behind a real documented procedure, and put an intrusion back in order.',
    type: 'drill',
    category: 'drills',
    domains: ['dfir'],
  },
  {
    href: '/drills/hashing/',
    label: 'Hash Identification',
    icon: 'hash',
    description: 'Identify a hash from its length and shape, and sort algorithms by what they are still safe for.',
    type: 'drill',
    category: 'drills',
    domains: ['dfir'],
  },

  // --- Drills ---------------------------------------------------------------
  // Labels are deliberately distinct from any same-topic reference page (e.g.
  // "RegEx Range" not "Regex" — Rule & Query Builders already has "Regex
  // Tester") so two different pages about the same topic never share a name.
  // `icon` matches drills/index.astro's own MODULES array exactly.
  {
    href: '/drills/regex/',
    label: 'RegEx Range',
    icon: 'search',
    description: 'Build a working pattern against real sample text, one construct at a time.',
    type: 'drill',
    category: 'drills',
    domains: ['dfir', 'systems'],
  },
  {
    href: '/drills/ip-cidr/',
    label: 'Subnetting',
    icon: 'wifi',
    description: 'Work out what a given CIDR block actually contains, and which special-use range an address falls in.',
    type: 'drill',
    category: 'drills',
    domains: ['networking'],
  },
  {
    href: '/drills/commands/',
    label: 'Terminal Commands',
    icon: 'terminal',
    description: 'Run real investigative commands against a simulated host — in bash, cmd, or PowerShell.',
    type: 'drill',
    category: 'drills',
    domains: ['dfir', 'systems'],
  },
  {
    href: '/drills/threat-actors/',
    label: 'Threat Actor / APT',
    icon: 'user',
    description: 'Resolve aliases and tooling to the group behind them, and tell confusable actors apart.',
    type: 'drill',
    category: 'drills',
    domains: ['dfir'],
  },
];

// The canonical menu grouping: a type's categories in display order, each
// carrying its own entries. Exported (rather than re-declared per component)
// because Navigation, ToolSidebar, Footer and the section index pages all
// need the identical shape — three hand-copied versions of this is exactly
// how the nav and the sidebar would drift apart.
export const groupsFor = (type: EntryType) =>
  CATEGORIES.filter((c) => c.type === type).map((c) => ({
    category: c.label,
    id: c.id,
    blurb: c.blurb,
    intro: c.intro,
    links: SITE_ENTRIES.filter((e) => e.category === c.id),
  }));

// Personal-identity destinations: the pages that are about Patrick rather than
// about DFIR/IT material. cyberkit.win redirects every one of these at the edge
// (see vercel.json's host-conditional rules — this list and that redirect set
// must stay in step), so any nav/footer row pointing at one is hidden there via
// a `[data-brand="cyberkit"]` toggle rather than left to bounce the visitor.
// One list, consumed by Navigation.astro and Footer.astro, so adding a new
// personal page is a single edit here plus a vercel.json rule.
export const PERSONAL_HREFS: readonly string[] = ['/blog/', '/labs/', '/about/', '/certifications/'];

// Secondary / meta links — surfaced in the nav "More" dropdown and footer column.
export const MORE_LINKS = [
  { href: '/certifications/', label: 'Certifications' },
  { href: '/privacy/', label: 'Privacy' },
  { href: '/colophon/', label: 'Colophon' },
] as const;

// Icon name (see Icon.astro) for each content pillar / category.
const CATEGORY_ICONS: Record<string, IconName> = {
  'Memory Forensics': 'cpu',
  'Host Forensics': 'hard-drive',
  'EDR Analysis': 'shield',
  Labs: 'flask',
  Tools: 'wrench',
  Notes: 'file-text',
};

export const categoryIcon = (category: string): IconName =>
  CATEGORY_ICONS[category] ?? 'activity';
