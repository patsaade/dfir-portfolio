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

// Source repository — used for the footer version/commit link (see utils/version.ts).
export const REPO = 'https://github.com/patsaade/personal-portfolio';

// Plain top-level nav links (Navigation.astro's own Blog/Labs/About map,
// desktop + mobile) and Footer.astro's Explore column. Drills and DFIR are
// NOT here — they're dropdowns (see DRILLS_LINKS/DFIR_GROUPS below), wired
// into Navigation.astro's own `dropdowns` array instead.
export const NAV_LINKS = [
  { href: '/blog/', label: 'Blog' },
  { href: '/labs/', label: 'Labs' },
  { href: '/about/', label: 'About' },
] as const;

// The 7 Drills modules — surfaced in the nav "Drills" dropdown (styled and
// positioned like DFIR's: a real link that navigates to /drills/ on click,
// centered under the whole nav bar on hover), the /drills/ landing page's own
// cards, and (as a third mode alongside DFIR/IT) ToolSidebar's rail — see
// invariant 13. Flat, no sub-categories (DFIR_GROUPS earns its category
// grouping at 21 links across 6 categories; 7 flat modules don't need it) —
// ToolSidebar wraps the whole array as its own single implicit category.
// Labels are deliberately distinct from any same-topic DFIR/IT reference page
// (e.g. "RegEx Range" not "Regex" — the DFIR dropdown already has "Regex
// Tester"; "Subnetting" not "IP & CIDR Math" — IT has "IP & CIDR Reference";
// "Terminal Commands" not "Command Line" — DFIR has "Command Cheat Sheet";
// "Threat Actor / APT" not "Threat Actors" — DFIR has "Threat Actor / APT
// Reference") so two different pages about the same topic never share a name.
// `icon` matches drills/index.astro's own MODULES array exactly (same entity,
// same icon between the landing-page cards and the sidebar rail).
export const DRILLS_LINKS = [
  { href: '/drills/regex/', label: 'RegEx Range', icon: 'search' },
  { href: '/drills/ip-cidr/', label: 'Subnetting', icon: 'wifi' },
  { href: '/drills/hashing/', label: 'Hash Identification', icon: 'hash' },
  { href: '/drills/attack/', label: 'MITRE ATT&CK', icon: 'crosshair' },
  { href: '/drills/event-ids/', label: 'Windows Event IDs', icon: 'list' },
  { href: '/drills/commands/', label: 'Terminal Commands', icon: 'terminal' },
  { href: '/drills/threat-actors/', label: 'Threat Actor / APT', icon: 'user' },
] as const;

// DFIR working / reference resources, grouped under the single nav "DFIR"
// dropdown (short enough to stay on one line), a footer column, and (see
// src/pages/dfir.astro) the /dfir/ landing page. Split into categories by
// *purpose* rather than lumping everything into one bucket — browse-and-
// look-things-up resources, the two paired MITRE framework maps, and (now
// that there are 11 of them) the interactive tools split further by
// workflow shape: extractors, converters, binary-artifact parsers, and
// query/rule builders.
// `icon` is consumed by ToolSidebar's icon rail (see invariant 13) — every
// DFIR_GROUPS entry across all six categories needs one, since the rail
// renders all of them together in one list. Every icon across all six arrays
// must be unique (a repeat makes two different destinations look like the
// same one at a glance) and as literally relevant to its own label as
// possible — pick the most fitting icon per entry first, then break any
// collision by giving ground to whichever entry is less central to that
// icon's meaning.
// Nav labels here are kept short — ToolSidebar's rail width (`RAIL_W`) is
// sized to the longest current label with no truncation ever added, so a
// tool's fuller descriptive name belongs on its own page (H1/title), not
// here. `description` is the one-line card blurb used on /dfir/ only —
// Navigation/Footer/ToolSidebar ignore it.
const REFERENCE_LINKS: { href: string; label: string; icon: IconName; description: string }[] = [
  { href: '/tools/', label: 'Tool Catalog', icon: 'wrench', description: 'Free & open-source DFIR tools, grouped by platform.' },
  { href: '/tools/cheatsheet/', label: 'Command Cheat Sheet', icon: 'terminal', description: 'Verified DFIR commands for the toolkit, by platform.' },
  { href: '/tools/regex-cheatsheet/', label: 'Regex Syntax Cheat Sheet', icon: 'tag', description: 'Token-by-token JavaScript/ECMAScript regex syntax reference, searchable by category.' },
  { href: '/glossary/', label: 'Glossary', icon: 'book-open', description: 'A cybersecurity & DFIR glossary.' },
  { href: '/event-ids/', label: 'Event ID Reference', icon: 'list', description: 'Windows Security + Sysmon event IDs that matter for DFIR.' },
  { href: '/network-ports/', label: 'Network Port Reference', icon: 'server', description: 'TCP/UDP ports that matter for DFIR, fully cited with confidence levels.' },
];

// The two MITRE framework maps — kept together since they're explicit
// offensive/defensive counterparts, cross-linked throughout the site.
const FRAMEWORK_LINKS: { href: string; label: string; icon: IconName; description: string }[] = [
  { href: '/attack-map/', label: 'MITRE ATT&CK Coverage Map', icon: 'crosshair', description: 'MITRE ATT&CK techniques covered across the site.' },
  { href: '/d3fend/', label: 'MITRE D3FEND Map', icon: 'shield', description: 'MITRE D3FEND defensive techniques, mapped to ATT&CK.' },
  { href: '/threat-actors/', label: 'Threat Actor / APT Reference', icon: 'user', description: 'MITRE-documented threat actor groups — aliases, techniques, and known tooling.' },
  { href: '/kill-chain/', label: 'Cyber Kill Chain Reference', icon: 'arrow-right', description: "Lockheed Martin's 7-phase intrusion model, phase by phase, mapped to MITRE ATT&CK where it fits." },
  { href: '/pyramid-of-pain/', label: 'Pyramid of Pain', icon: 'gauge', description: 'David Bianco\'s six indicator types, from hash values to TTPs, ranked by cost to the adversary.' },
];

// Tools that pull structured indicators out of freeform pasted text.
const EXTRACTOR_LINKS: { href: string; label: string; icon: IconName; description: string }[] = [
  { href: '/tools/ioc-extractor/', label: 'IOC Extractor', icon: 'alert-triangle', description: 'Paste a log or report and extract every IOC it contains.' },
  { href: '/tools/email-header-analyzer/', label: 'Email Header Analyzer', icon: 'mail', description: 'Walk the Received chain and read SPF/DKIM/DMARC verdicts.' },
  { href: '/tools/regex-tester/', label: 'Regex Tester', icon: 'search', description: 'Live regex playground with a library of common DFIR patterns.' },
  { href: '/tools/jwt-decoder/', label: 'JWT Decoder', icon: 'lock', description: "Decode a JSON Web Token's header, payload, and claims — signature verification not included." },
  { href: '/tools/user-agent-parser/', label: 'User-Agent String Parser', icon: 'monitor', description: 'Parse a raw User-Agent header into browser, engine, and OS, with every caveat spelled out.' },
];

// Tools that transform or compute a value (a timestamp, a hash, an
// obfuscated blob) rather than extract structure from it.
const CONVERTER_LINKS: { href: string; label: string; icon: IconName; description: string }[] = [
  { href: '/tools/timestamp-converter/', label: 'Timestamp Converter', icon: 'clock', description: 'Bidirectional converter across 19 timestamp/epoch formats.' },
  { href: '/tools/hash-calculator/', label: 'Hash Calculator', icon: 'hash', description: 'Compute, verify, and identify hashes — entirely local.' },
  { href: '/tools/deobfuscator/', label: 'Codec Builder', icon: 'key', description: 'Chain Base64/hex/XOR/gzip steps to encode or peel back obfuscated payloads.' },
  { href: '/tools/text-diff/', label: 'Text Diff Tool', icon: 'columns', description: 'Compare two logs or text blocks and highlight what changed.' },
  { href: '/tools/cvss-calculator/', label: 'CVSS Score Calculator', icon: 'bug', description: 'Pick the CVSS v3.1 Base metrics (or paste a vector string) and get the score and severity band.' },
];

// Tools that parse a specific Windows binary artifact format end to end.
const ARTIFACT_PARSER_LINKS: { href: string; label: string; icon: IconName; description: string }[] = [
  { href: '/tools/pe-explorer/', label: 'PE Header Explorer', icon: 'file-text', description: 'Parse a local EXE/DLL — headers, sections, imports, imphash.' },
  { href: '/tools/lnk-parser/', label: 'LNK Parser', icon: 'link', description: "Parse a .lnk shortcut file's headers and embedded target path." },
  { href: '/tools/mft-usn-analyzer/', label: 'Timestomp Analyzer', icon: 'history', description: 'Compare $SI vs $FN timestamps in a raw MFT/USN record.' },
  { href: '/tools/recycle-bin-parser/', label: 'Recycle Bin ($I) Parser', icon: 'trash-2', description: 'Decode a Windows Recycle Bin $I file — original path, size, and deletion time, both format versions.' },
  { href: '/tools/prefetch-parser/', label: 'Prefetch File Parser', icon: 'download', description: 'Parse a Windows Prefetch (.pf) file — executable name, run count, and last-run timestamps.' },
];

// Tools that build a piece of syntax to run elsewhere (a search engine, a
// detection pipeline) rather than analyze something already in hand.
const QUERY_BUILDER_LINKS: { href: string; label: string; icon: IconName; description: string }[] = [
  { href: '/osint/', label: 'OSINT Toolkit', icon: 'globe', description: 'Interactive search-operator (dork) builder plus recon recipes.' },
  { href: '/tools/sigma-tester/', label: 'Sigma Rule Tester', icon: 'target', description: 'Build or paste a Sigma rule and test it against sample events.' },
  { href: '/tools/yara-tester/', label: 'YARA Rule Tester', icon: 'star', description: 'Build a YARA rule string by string and scan it live against a pasted sample — real byte-level matching.' },
  { href: '/tools/kql-builder/', label: 'KQL Query Builder', icon: 'cpu', description: 'Assemble a Kusto hunting query for Defender XDR or Sentinel against real, documented table columns.' },
  { href: '/tools/spl-builder/', label: 'Splunk SPL Query Builder', icon: 'activity', description: 'Compose a Splunk SPL search step by step — base search plus stats, table, sort, where, and eval.' },
];

// The DFIR dropdown's category groups, in display order — also the section
// order on /dfir/ and the footer's compact anchor list, so a visitor's
// mental model of "category order" never shifts between surfaces. `id` is
// the anchor slug shared verbatim by /dfir/'s <section id> and the footer's
// `/dfir/#${id}` links (one field, not two independently-derived strings,
// so they can't drift apart); `blurb` is the short one-line category summary
// used by /dfir/'s GroupOverview jump-strip tiles (and nowhere else — keep it
// tile-sized, it has to sit next to five siblings); `intro` is a longer
// 2-3 sentence paragraph used by /dfir/'s own section headers, deliberately
// distinct prose from `blurb` rather than a paraphrase of it — the tile and
// the section sit close together on the same page, so identical text there
// reads as a bug, not a feature.
export const DFIR_GROUPS = [
  {
    category: 'Reference',
    id: 'reference',
    blurb: 'Browse-and-look-up material — the tool catalog, command reference, glossary, and event ID lookup.',
    intro: "Start here when you need to look something up rather than run something: the curated tool catalog, a verified command reference by platform, the glossary of terms used throughout the site, and a fully-cited breakdown of the Windows Security and Sysmon event IDs that matter for DFIR. Each page below is a browsable index in its own right, not just a link.",
    links: REFERENCE_LINKS,
  },
  {
    category: 'Frameworks',
    id: 'frameworks',
    blurb: 'The two MITRE maps, cross-linked throughout the site as offensive/defensive counterparts.',
    intro: "MITRE ATT&CK catalogs how adversaries operate; MITRE D3FEND catalogs how to counter them. Together they're this site's shared vocabulary for describing both technique and defense — any post or lab that covers a specific technique links out to its ATT&CK or D3FEND detail page, and each of those pages links back the other way.",
    links: FRAMEWORK_LINKS,
  },
  {
    category: 'Extractors',
    id: 'extractors',
    blurb: 'Tools that pull structured indicators out of freeform pasted text.',
    intro: "These take something messy — a log excerpt, a raw email header block, a report full of buried indicators — and pull the structured pieces back out: IOCs, SPF/DKIM/DMARC verdicts, or regex matches against a library of common DFIR patterns. Nothing pasted into them is transmitted anywhere; every one runs entirely in the browser.",
    links: EXTRACTOR_LINKS,
  },
  {
    category: 'Converters',
    id: 'converters',
    blurb: 'Tools that transform or compute a value rather than extract structure from it.',
    intro: "Where the extractors above find structure in freeform text, these take a single value you already have — a timestamp, a file, an obfuscated string — and transform or compute something from it: a converted time across 19 formats, a verified hash, a peeled-back payload. Same local-only rule applies — nothing you enter leaves the browser.",
    links: CONVERTER_LINKS,
  },
  {
    category: 'Artifact Parsers',
    id: 'artifact-parsers',
    blurb: 'Tools that parse a specific Windows binary artifact format end to end.',
    intro: "Each of these parses one specific Windows artifact format from the ground up — a PE binary's headers, sections, and imports, a .lnk shortcut's embedded target path, or the $STANDARD_INFORMATION vs $FILE_NAME timestamps in a raw MFT/USN record — the kind of structured, field-by-field parsing you'd otherwise reach for a standalone utility to do.",
    links: ARTIFACT_PARSER_LINKS,
  },
  {
    category: 'Query Builders',
    id: 'query-builders',
    blurb: 'Tools that build a piece of syntax to run elsewhere, rather than analyze something already in hand.',
    intro: "These don't analyze anything you already have — they help you construct the query you're about to run somewhere else: a search-engine dork for OSINT recon, or a Sigma detection rule to test against sample events before it ships to a SIEM.",
    links: QUERY_BUILDER_LINKS,
  },
] as const;

// General IT/networking resources that aren't DFIR-specific — split out of
// DFIR_GROUPS into their own nav dropdown (positioned right after DFIR) so
// "DFIR" stays a purely forensics/IR-focused list. See CLAUDE.md's "Nav
// grouping" invariant for the IT-vs-DFIR dividing line (framing, not subject
// matter). Structured the SAME way as DFIR_GROUPS — category objects with
// {category, id, blurb, intro, links} — the same precedent DFIR_GROUPS itself
// already set (CLAUDE.md: "the four tool-category arrays replaced a single
// INTERACTIVE_TOOL_LINKS once it grew past 4 entries — split further the
// same way if any one category gets unwieldy again"). The CIDR & VLAN Calculator's
// own "Subnet & VLAN planner (VLSM)" mode lives here too — it's general
// subnet/VLAN math, not a DFIR-specific workflow.
const IT_REFERENCE_LINKS: { href: string; label: string; icon: IconName; description: string }[] = [
  { href: '/ip-reference/', label: 'IP & CIDR Reference', icon: 'wifi', description: 'Special-use IPv4/IPv6 ranges plus a CIDR quick reference, sourced from IANA.' },
  {
    href: '/osi-model/',
    label: 'OSI & TCP/IP Model Reference',
    icon: 'layers',
    description: 'The OSI seven-layer model and the practical four-layer TCP/IP model, what runs at each layer, and the well-known/registered/dynamic port ranges.',
  },
  { href: '/http-status-codes/', label: 'HTTP Status Code Reference', icon: 'cloud', description: 'Every IANA-assigned HTTP status code, grouped by class, with the exact reason phrase.' },
  { href: '/dns-records/', label: 'DNS Record Type Reference', icon: 'map-pin', description: 'The common DNS resource record types — A, MX, TXT, NS, and more — with their TYPE value and purpose.' },
  { href: '/ascii-table/', label: 'ASCII Table & Character Encoding Reference', icon: 'message-square', description: 'The full 7-bit ASCII table with decimal/hex/octal/binary, plus how Unicode and UTF-8 relate to it.' },
];

const IT_TOOL_LINKS: { href: string; label: string; icon: IconName; description: string }[] = [
  { href: '/tools/cidr-calculator/', label: 'CIDR & VLAN Calculator', icon: 'grid', description: 'Compute network/broadcast/netmask/host range from CIDR notation, plus a subnet & VLAN planner.' },
  {
    href: '/tools/base-converter/',
    label: 'Number Base Converter',
    icon: 'rotate-cw',
    description: 'Convert a value between binary, octal, decimal, and hexadecimal live as you type, with an ASCII decode of the underlying bytes.',
  },
  {
    href: '/tools/mac-address/',
    label: 'MAC Analyzer',
    icon: 'radio',
    description: "Decode a MAC address into its OUI and NIC-specific bytes, and see what the U/L and I/G bits mean. Decodes structure only — it doesn't identify the manufacturer.",
  },
  { href: '/tools/cron-parser/', label: 'Cron Expression Parser & Builder', icon: 'calendar', description: 'Decode a crontab(5) cron expression into plain English, or build one field by field.' },
  { href: '/tools/data-size-converter/', label: 'Data Size & Storage Unit Converter', icon: 'hard-drive', description: "Convert between bit, byte, decimal, and binary size units — and see why a '500 GB' drive shows less." },
];

export const IT_GROUPS = [
  {
    category: 'Reference',
    id: 'reference',
    blurb: 'Browse-and-look-up material for general networking fundamentals.',
    intro: "Start here when you need to look something up rather than compute something: special-use IPv4/IPv6 address ranges and a CIDR quick reference sourced straight from IANA's own registries, plus the OSI and TCP/IP models that everything else in networking gets described in terms of — no DFIR framing, just the fundamentals themselves.",
    links: IT_REFERENCE_LINKS,
  },
  {
    category: 'Tools',
    id: 'tools',
    blurb: 'Interactive calculators for general networking and computing fundamentals.',
    intro: 'Work out the numbers instead of looking them up: network/broadcast/netmask/host-range math from CIDR notation with a subnet & VLAN planner, binary/octal/decimal/hex conversion with an ASCII decode, and a MAC address structure decoder.',
    links: IT_TOOL_LINKS,
  },
] as const;

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

// Headline stats for the home page
export const STATS = [
  { icon: 'shield', title: 'Live incident response', desc: 'Across SOC & IR roles' },
  { icon: 'clock', title: '3+ years hands-on', desc: 'Detection & response' },
  { icon: 'cpu', title: 'Endpoint forensics', desc: 'EDR, host & memory' },
  { icon: 'award', title: 'CISSP certified', desc: 'In pursuit of GCFA / GCFE / GCIH' },
] as const;
