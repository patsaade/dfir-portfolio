// Prerendered site-wide search index, consumed by the ⌘K palette (Search.astro).
// One compact JSON file (cached) covering every navigable destination plus the
// long-tail datasets — so the whole site is searchable client-side with no
// backend. Mirrors the static-CDN model of /reference/glossary/bank.json.
//
// Every row carries a `kind`, and `kind` is the site's own object-type
// vocabulary — Reference / Tool / Drill for navigable destinations, then the
// content kinds (Post, Lab, Term, ATT&CK, …). The palette renders it as a chip
// on each row and groups the result list by it, so the type is never something
// the reader has to infer from the URL.
//
// The three destination kinds are DERIVED FROM `SITE_ENTRIES` (src/consts.ts),
// not hand-listed here — adding a reference page, tool, or drill to that single
// source of truth puts it in search automatically, with its real type, category
// and domain tags attached. `STATIC_PAGES` below is only for the pages that
// aren't `SITE_ENTRIES` rows at all (hubs, personal/meta pages, the per-shell
// sub-drills). `EXTRA_KEYWORDS` is the one hand-kept piece: the synonyms and
// jargon a reader is likely to type that don't appear in a page's own short
// label or description ("checksum", "defang", "vlsm").
import type { APIRoute } from 'astro';
import { getSortedPosts, getSortedLabs } from '../utils/posts';
import { SITE_ENTRIES, CATEGORIES, DOMAINS } from '../consts';
import { SECURITY_TERMS } from '../data/securityTerms';
import { ATTACK_TECHNIQUES } from '../data/references';
import { D3FEND_TECHNIQUES } from '../data/d3fend';
import { TOOLS } from '../data/tools';
import { EVENT_IDS } from '../data/eventIds';
import { NETWORK_PORTS } from '../data/networkPorts';
import { THREAT_ACTORS, threatActorSlug } from '../data/threatActors';

export const prerender = true;

// One row of the palette. Kept to five fields on purpose — this file is fetched
// in full by every visitor who opens ⌘K.
//   title    — matched at the highest weight; also the row's visible name.
//   kind     — the type chip + the group the row is filed under.
//   keywords — type/category/domain words plus curated synonyms; matched at the
//              middle weight (the "metadata" tier).
//   desc     — free body text, matched LAST and clamped to one line on screen.
interface IndexEntry {
  title: string;
  url: string;
  kind: string;
  desc?: string;
  keywords?: string;
}

// Only ever one clamped line renders, and description text is the lowest-weight
// match tier, so full multi-sentence summaries aren't worth the payload.
const DESC_MAX = 120;
const short = (s: string | undefined): string => {
  const v = (s ?? '').replace(/\s+/g, ' ').trim();
  return v.length > DESC_MAX ? v.slice(0, DESC_MAX - 1).trimEnd() + '…' : v;
};

const KIND_BY_TYPE = { reference: 'Reference', tool: 'Tool', drill: 'Drill' } as const;
const CATEGORY_LABEL = new Map(CATEGORIES.map((c) => [c.id, c.label]));
const DOMAIN_LABEL = new Map(DOMAINS.map((d) => [d.id, d.label]));

// Synonyms, jargon, and older names a reader might type that a page's own short
// label and one-line description don't contain. Keyed by href so it stays valid
// as labels get reworded. A page with nothing to add simply isn't listed.
const EXTRA_KEYWORDS: Record<string, string> = {
  // Reference › Guides & Concepts — the query-language sheets
  '/reference/kql-cheatsheet/': 'kusto kql defender advanced hunting sentinel query language operators syntax',
  '/reference/spl-cheatsheet/': 'splunk spl search processing language stats eval sourcetype commands syntax',
  '/reference/s1-cheatsheet/': 'sentinelone s1 deep visibility powerquery singularity data lake syntax fields',
  // Reference › Lookup Tables
  '/reference/event-ids/': 'sysmon security auditing log channel 4624 4688 4672 logon process creation',
  '/reference/network-ports/': 'well-known registered ephemeral dynamic iana rdp smb ssh dns c2 service',
  '/reference/ip-cidr/': 'private public rfc 1918 cgnat loopback link-local multicast documentation ula nat64 iana subnet special-use',
  '/reference/http-status-codes/': '1xx 2xx 3xx 4xx 5xx reason phrase iana rfc 9110 404 500',
  '/reference/dns-records/': 'a aaaa cname mx txt ns soa ptr srv caa resource record type iana',
  '/reference/ascii-table/': 'character encoding decimal hex octal binary unicode utf-8 code point control characters',
  // Reference › Guides & Concepts
  '/reference/glossary/': 'terms definitions vocabulary word of the day term of the day',
  '/reference/tool-catalog/': 'toolkit open source free volatility velociraptor autopsy plaso',
  '/reference/command-cheatsheet/': 'cheat sheet cheatsheet quick reference syntax bash powershell cmd one-liners',
  '/reference/regex-cheatsheet/': 'cheat sheet cheatsheet syntax javascript ecmascript anchors character classes quantifiers groups backreferences lookahead lookbehind flags escapes replacement regexp',
  '/reference/osi-model/': 'seven layer physical data link network transport session presentation application encapsulation port ranges',
  // Reference › Frameworks & Maps
  '/reference/attack-map/': 'mitre techniques tactics coverage matrix enterprise navigator',
  '/reference/threat-actors/': 'apt intrusion set group aliases attribution mitre',
  '/reference/d3fend/': 'mitre countermeasures harden detect isolate deceive evict defensive',
  '/reference/kill-chain/': 'lockheed martin reconnaissance weaponization delivery exploitation installation command and control actions on objectives intrusion',
  '/reference/pyramid-of-pain/': 'david bianco hash values ip addresses domain names network host artifacts ttps indicators cost',
  // Tools › Artifact Parsers
  '/tools/pe-explorer/': 'portable executable dos nt coff optional header section table imports exports imphash static analysis',
  '/tools/prefetch-parser/': 'pf scca run count last run execution evidence',
  '/tools/lnk-parser/': 'shell link shortcut ms-shllink shell item id list recent jump list target',
  '/tools/mft-usn-analyzer/': 'mft usn journal timestomping ntfs standard information file name filetime anti-forensics',
  '/tools/recycle-bin-parser/': 'dollar i $i sinfo deleted original path deletion timestamp',
  // Tools › Decoders & Extractors
  '/tools/ioc-extractor/': 'indicator of compromise defang refang hash ip domain url cve bitcoin triage',
  '/tools/email-header-analyzer/': 'received chain spf dkim dmarc phishing authentication-results reply-to return-path',
  '/tools/jwt-decoder/': 'json web token header payload claims base64url bearer auth',
  '/tools/user-agent-parser/': 'ua string browser engine os chrome firefox safari webkit gecko blink',
  '/tools/mac-address/': 'oui nic ethernet hardware address unicast multicast locally administered universally administered u/l i/g',
  '/tools/cron-parser/': 'crontab schedule minute hour day month vixie posix expression builder',
  // Tools › Converters & Calculators
  '/tools/hash-calculator/': 'md5 sha1 sha256 sha384 sha512 checksum verifier verify identify ntlm digest file',
  '/tools/timestamp-converter/': 'epoch unix filetime webkit chrome uuid v1 gps tai64 .net ticks mac absolute date time',
  '/tools/deobfuscator/': 'deobfuscator deobfuscation recipe chain base64 hex xor rot13 rot47 gzip deflate inflate loader dropper encode decode',
  '/tools/cidr-calculator/': 'cidr netmask wildcard broadcast network address usable hosts rfc 4632 vlsm planner ip range',
  '/tools/text-diff/': 'compare logs changed added removed unified side by side',
  '/tools/cvss-calculator/': 'vulnerability severity base metrics vector string v3.1 attack complexity privileges scope',
  '/tools/base-converter/': 'binary octal decimal hexadecimal hex ascii bit byte radix',
  '/tools/data-size-converter/': 'bit byte kilobyte megabyte gigabyte terabyte kibibyte mebibyte gibibyte decimal binary storage',
  // Tools › Rule & Query Builders
  '/tools/regex-tester/': 'pattern library playground match capture group ipv4 ipv6 sid guid registry key base64',
  '/tools/kql-builder/': 'kusto query language microsoft defender xdr sentinel advanced hunting',
  '/tools/s1-builder/': 'sentinelone s1 deep visibility powerquery singularity builder query composer',
  '/tools/spl-builder/': 'splunk search processing language stats table sort where eval index sourcetype',
  '/tools/sigma-tester/': 'detection engineering yaml siem detection as code rule',
  '/tools/yara-tester/': 'malware signature strings condition ascii wide nocase hex pattern rule scan',
  '/tools/osint/': 'dork dorking google bing duckduckgo search operators recon attack surface open source intelligence',
  // Drills
  '/drills/event-ids/': 'practice quiz sysmon security log sample',
  '/drills/attack/': 'practice quiz technique tactic mitre',
  '/drills/hashing/': 'practice quiz md5 sha1 sha256 identify format',
  '/drills/regex/': 'practice quiz pattern matching range challenge',
  '/drills/ip-cidr/': 'practice quiz subnet netmask cidr special-use',
  '/drills/commands/': 'practice quiz bash cmd powershell shell linux macos windows cli',
  '/drills/threat-actors/': 'practice quiz apt group alias tooling attribution mitre',
};

// Pages that aren't SITE_ENTRIES rows: section and topic hubs, the personal /
// meta pages, and the per-shell sub-drills that live under a parent drill.
const STATIC_PAGES: IndexEntry[] = [
  { title: 'Reference', url: '/reference/', kind: 'Page', desc: 'Everything you read or look a value up in — lookup tables, guides and concepts, and the framework maps.', keywords: 'reference hub lookup tables guides concepts frameworks maps index browse' },
  { title: 'Tools', url: '/tools/', kind: 'Page', desc: 'Every interactive utility on this site. All of them run entirely in your browser.', keywords: 'tools hub artifact parsers decoders extractors converters calculators rule query builders index browse local' },
  { title: 'Drills', url: '/drills/', kind: 'Page', desc: "Short knowledge checks built from the same verified data this site's references render.", keywords: 'drills hub practice quiz knowledge check index browse' },
  { title: 'DFIR', url: '/dfir/', kind: 'Page', desc: 'Everything on this site about digital forensics and incident response, in one place.', keywords: 'dfir hub topic forensics incident response artifacts detection tradecraft' },
  { title: 'Networking', url: '/networking/', kind: 'Page', desc: 'Everything on this site about addressing, protocols, ports and the layered models.', keywords: 'networking hub topic subnet cidr ip dns http ports osi tcp' },
  { title: 'Systems', url: '/systems/', kind: 'Page', desc: 'Everything on this site about operating-system and general-computing fundamentals.', keywords: 'systems hub topic encoding ascii cron storage units shell regex fundamentals' },
  { title: 'Blog', url: '/blog/', kind: 'Page', desc: 'DFIR deep dives.', keywords: 'blog posts writeups articles index' },
  { title: 'Labs', url: '/labs/', kind: 'Page', desc: 'Lab & CTF writeups.', keywords: 'labs ctf writeups cyberdefenders 13cubed index' },
  { title: 'About', url: '/about/', kind: 'Page', desc: 'Patrick Saade — DFIR-focused security analyst.', keywords: 'about bio experience career work history résumé resume' },
  { title: 'Certifications', url: '/certifications/', kind: 'Page', desc: 'Security certifications — CISSP, CompTIA, the GIAC forensics track.', keywords: 'certifications certs cissp giac gcfa comptia credly' },
  { title: 'Colophon', url: '/colophon/', kind: 'Page', desc: 'How this site is built — the stack, the typography, and the craft details.', keywords: 'colophon stack astro panda css fonts redaction build how built' },
  { title: 'Privacy', url: '/privacy/', kind: 'Page', desc: 'What this site stores, what it does not, and why — no cookies, no tracking, local-only tool input.', keywords: 'privacy policy cookies local storage tracking analytics data' },
  { title: 'Bash Commands Drill', url: '/drills/commands/bash/', kind: 'Drill', desc: 'Practice real bash investigative commands against a simulated host.', keywords: 'drill practice quiz bash shell linux macos terminal grep find ps' },
  { title: 'Windows cmd Commands Drill', url: '/drills/commands/cmd/', kind: 'Drill', desc: 'Practice real Windows cmd investigative commands against a simulated host.', keywords: 'drill practice quiz cmd command prompt windows terminal netstat tasklist' },
  { title: 'PowerShell Commands Drill', url: '/drills/commands/powershell/', kind: 'Drill', desc: 'Practice real PowerShell investigative commands against a simulated host.', keywords: 'drill practice quiz powershell windows terminal get-process get-winevent' },
];

// A SITE_ENTRIES row's own type, category and domain tags become searchable
// words — so "tool", "parser", "lookup", "windows" or "networking" reach the
// right destinations without any of that being restated in prose.
const destinations = (): IndexEntry[] =>
  SITE_ENTRIES.map((e) => ({
    title: e.label,
    url: e.href,
    kind: KIND_BY_TYPE[e.type],
    desc: short(e.description),
    keywords: [
      e.type,
      CATEGORY_LABEL.get(e.category) ?? '',
      e.domains.map((d) => DOMAIN_LABEL.get(d) ?? d).join(' '),
      EXTRA_KEYWORDS[e.href] ?? '',
    ]
      .join(' ')
      .toLowerCase()
      .replace(/\s+/g, ' ')
      .trim(),
  }));

export const GET: APIRoute = async () => {
  const [posts, labs] = await Promise.all([getSortedPosts(), getSortedLabs()]);

  const entries: IndexEntry[] = [
    ...destinations(),
    ...STATIC_PAGES,
    ...SECURITY_TERMS.map((t) => ({
      title: t.term,
      url: `/reference/glossary/${t.slug}/`,
      kind: 'Term',
      desc: short(t.short),
      keywords: `${(t.aka ?? []).join(' ')} ${t.category} glossary term definition`.toLowerCase(),
    })),
    ...ATTACK_TECHNIQUES.map((t) => ({
      title: `${t.id} ${t.name}`,
      url: `/reference/attack-map/${t.id}/`,
      kind: 'ATT&CK',
      desc: short(t.summary),
      keywords: `${t.tactics.join(' ')} mitre att&ck attack technique tactic`.toLowerCase(),
    })),
    ...D3FEND_TECHNIQUES.map((t) => ({
      title: `${t.id} ${t.name}`,
      url: `/reference/d3fend/${t.id}/`,
      kind: 'D3FEND',
      desc: short(t.definition),
      keywords: `${t.tactic} mitre d3fend defensive countermeasure technique`.toLowerCase(),
    })),
    // Third-party software in the Tool Catalog — kept distinct from this site's
    // own interactive Tools so the type chip never means two different things.
    ...TOOLS.map((t) => ({
      title: t.name,
      url: `/reference/tool-catalog/${t.slug}/`,
      kind: 'Software',
      desc: short(t.use),
      keywords: `${t.fn} ${t.cost} ${t.platform} ${t.tags.join(' ')} dfir tool catalog software`.toLowerCase(),
    })),
    ...EVENT_IDS.map((e) => ({
      title: `${e.id} ${e.name}`,
      url: `/reference/event-ids/${e.slug}/`,
      kind: 'Event ID',
      desc: short(e.category),
      keywords: `${e.channel} ${e.source} windows event id sysmon log`.toLowerCase(),
    })),
    ...NETWORK_PORTS.map((p) => ({
      title: `${p.port} ${p.name}`,
      url: `/reference/network-ports/${p.slug}/`,
      kind: 'Port',
      desc: short(p.category),
      keywords: `${p.protocol} port ${p.port} network service`.toLowerCase(),
    })),
    ...THREAT_ACTORS.map((a) => ({
      title: `${a.id} ${a.name}`,
      url: `/reference/threat-actors/${threatActorSlug(a.name)}/`,
      kind: 'Threat Actor',
      desc: short(a.summary),
      keywords: `${a.aliases.join(' ')} threat actor apt group intrusion set mitre`.toLowerCase(),
    })),
    ...posts.map((p) => ({
      title: p.data.title,
      url: `/blog/${p.id}/`,
      kind: 'Post',
      desc: short(p.data.excerpt),
      keywords: `${p.data.tags.join(' ')} ${p.data.category} ${p.data.tools.join(' ')} blog post writeup`.toLowerCase(),
    })),
    ...labs.map((l) => ({
      title: l.data.title,
      url: `/labs/${l.id}/`,
      kind: 'Lab',
      desc: short(l.data.excerpt),
      keywords: `${l.data.tags.join(' ')} ${l.data.source} ${l.data.tools.join(' ')} lab writeup ctf`.toLowerCase(),
    })),
  ];

  // First row for a URL wins, so a page listed both in SITE_ENTRIES and by hand
  // can never render as two identical results.
  const seen = new Set<string>();
  const deduped = entries.filter((e) => (seen.has(e.url) ? false : (seen.add(e.url), true)));

  return new Response(JSON.stringify(deduped), {
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
};
