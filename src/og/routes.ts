// Single source of truth for which pages get a social card and what it says.
// Both the OG endpoint (src/pages/og/[...slug].png.ts) and BaseHead import this,
// so the per-page <meta og:image> URL always matches a generated image.
import { getCollection } from 'astro:content';

export interface OgEntry {
  /** Path-style slug, e.g. 'index', 'tools', 'blog/why-dfir'. */
  slug: string;
  title: string;
  eyebrow: string;
}

// Static pages. Titles/eyebrows mirror each page's PageHeader for consistency.
const STATIC_ENTRIES: OgEntry[] = [
  { slug: 'index', title: 'Patrick Saade', eyebrow: 'DFIR portfolio & blog' },
  { slug: 'about', title: 'Patrick Saade', eyebrow: 'About' },
  { slug: 'blog', title: 'DFIR deep dives', eyebrow: 'Blog' },
  { slug: 'labs', title: 'Hands-on challenges, solved', eyebrow: 'Labs' },
  { slug: 'dfir', title: 'DFIR', eyebrow: 'Reference & Tools' },
  { slug: 'it', title: 'IT', eyebrow: 'Reference & Tools' },
  { slug: 'tools', title: 'Tool Catalog', eyebrow: 'Tooling' },
  { slug: 'tools/cheatsheet', title: 'DFIR Command Cheat Sheet', eyebrow: 'Quick Reference' },
  { slug: 'tools/timestamp-converter', title: 'Timestamp Converter', eyebrow: 'Time & Correlation' },
  { slug: 'tools/ioc-extractor', title: 'IOC Extractor', eyebrow: 'Triage & Correlation' },
  { slug: 'tools/hash-calculator', title: 'Hash Calculator & Verifier', eyebrow: 'Triage & Correlation' },
  { slug: 'tools/email-header-analyzer', title: 'Email Header & Auth-Chain Analyzer', eyebrow: 'Triage & Correlation' },
  { slug: 'tools/regex-tester', title: 'DFIR Regex Tester & Pattern Library', eyebrow: 'Triage & Correlation' },
  { slug: 'tools/regex-cheatsheet', title: 'Regex Syntax Cheat Sheet', eyebrow: 'Quick Reference' },
  { slug: 'tools/deobfuscator', title: 'Codec Builder', eyebrow: 'Malware & Static Analysis' },
  { slug: 'tools/text-diff', title: 'Text Diff Tool', eyebrow: 'Triage & Correlation' },
  { slug: 'tools/cidr-calculator', title: 'CIDR & VLAN Calculator', eyebrow: 'IT & Networking' },
  { slug: 'tools/pe-explorer', title: 'PE Header Explorer', eyebrow: 'Malware & Static Analysis' },
  { slug: 'tools/lnk-parser', title: 'LNK (Shell Link) Forensic Parser', eyebrow: 'Host Forensics' },
  { slug: 'tools/mft-usn-analyzer', title: 'MFT & USN Journal Timestomp Analyzer', eyebrow: 'Host Forensics' },
  { slug: 'osint', title: 'OSINT Toolkit', eyebrow: 'Recon & Discovery' },
  { slug: 'tools/sigma-tester', title: 'Sigma Rule Tester & Builder', eyebrow: 'Detection Engineering' },
  { slug: 'glossary', title: 'Cybersecurity glossary', eyebrow: 'Reference' },
  { slug: 'event-ids', title: 'Windows Event ID / Sysmon Reference', eyebrow: 'Reference' },
  { slug: 'network-ports', title: 'Network Port Reference', eyebrow: 'Reference' },
  { slug: 'ip-reference', title: 'IP & CIDR Reference', eyebrow: 'IT & Networking' },
  { slug: 'osi-model', title: 'OSI & TCP/IP Model Reference', eyebrow: 'IT & Networking' },
  { slug: 'tools/base-converter', title: 'Number Base Converter', eyebrow: 'IT & Networking' },
  { slug: 'tools/mac-address', title: 'MAC Analyzer', eyebrow: 'IT & Networking' },
  { slug: 'attack-map', title: 'MITRE ATT&CK Coverage Map', eyebrow: 'Coverage' },
  { slug: 'd3fend', title: 'MITRE D3FEND Map', eyebrow: 'Countermeasures' },
  { slug: 'threat-actors', title: 'Threat Actor / APT Reference', eyebrow: 'Coverage' },
  { slug: 'kill-chain', title: 'Cyber Kill Chain Reference', eyebrow: 'Coverage' },
  { slug: 'pyramid-of-pain', title: 'Pyramid of Pain', eyebrow: 'Coverage' },
  { slug: 'tools/jwt-decoder', title: 'JWT Decoder', eyebrow: 'Triage & Correlation' },
  { slug: 'tools/user-agent-parser', title: 'User-Agent String Parser', eyebrow: 'Triage & Correlation' },
  { slug: 'tools/cvss-calculator', title: 'CVSS Score Calculator', eyebrow: 'Triage & Correlation' },
  { slug: 'tools/recycle-bin-parser', title: 'Recycle Bin ($I) Parser', eyebrow: 'Host Forensics' },
  { slug: 'tools/prefetch-parser', title: 'Prefetch File Parser', eyebrow: 'Host Forensics' },
  { slug: 'tools/yara-tester', title: 'YARA Rule Tester', eyebrow: 'Detection Engineering' },
  { slug: 'tools/kql-builder', title: 'KQL Query Builder', eyebrow: 'Detection Engineering' },
  { slug: 'tools/spl-builder', title: 'Splunk SPL Query Builder', eyebrow: 'Detection Engineering' },
  { slug: 'http-status-codes', title: 'HTTP Status Code Reference', eyebrow: 'IT & Networking' },
  { slug: 'dns-records', title: 'DNS Record Type Reference', eyebrow: 'IT & Networking' },
  { slug: 'ascii-table', title: 'ASCII Table & Character Encoding Reference', eyebrow: 'IT & Networking' },
  { slug: 'tools/cron-parser', title: 'Cron Expression Parser & Builder', eyebrow: 'IT & Networking' },
  { slug: 'tools/data-size-converter', title: 'Data Size & Storage Unit Converter', eyebrow: 'IT & Networking' },
  { slug: 'drills', title: 'Drills', eyebrow: 'Practice' },
  { slug: 'drills/regex', title: 'RegEx Range Drill', eyebrow: 'Practice' },
  { slug: 'drills/ip-cidr', title: 'Subnetting Drill', eyebrow: 'Practice' },
  { slug: 'drills/hashing', title: 'Hash Identification Drill', eyebrow: 'Practice' },
  { slug: 'drills/attack', title: 'MITRE ATT&CK Drill', eyebrow: 'Practice' },
  { slug: 'drills/event-ids', title: 'Windows Event ID Drill', eyebrow: 'Practice' },
  { slug: 'drills/commands', title: 'Terminal Commands Drill', eyebrow: 'Practice' },
  { slug: 'drills/threat-actors', title: 'Threat Actor / APT Drill', eyebrow: 'Practice' },
  { slug: 'certifications', title: 'Certifications', eyebrow: 'Credentials' },
  { slug: 'colophon', title: 'How this site is built', eyebrow: 'Colophon' },
  { slug: 'privacy', title: 'Privacy policy', eyebrow: 'Legal' },
];

const STATIC_SLUGS = new Set(STATIC_ENTRIES.map((e) => e.slug));

/** Every social card to generate: static pages + each post and lab. */
export async function getOgEntries(): Promise<OgEntry[]> {
  const entries: OgEntry[] = [...STATIC_ENTRIES];

  const posts = (await getCollection('blog')).filter((p) => !p.data.draft);
  for (const p of posts) {
    entries.push({ slug: `blog/${p.id}`, title: p.data.title, eyebrow: `Blog · ${p.data.category}` });
  }

  const labs = (await getCollection('labs')).filter((l) => !l.data.draft);
  for (const l of labs) {
    entries.push({ slug: `labs/${l.id}`, title: l.data.title, eyebrow: `Lab · ${l.data.source}` });
  }

  return entries;
}

/**
 * The OG-image slug for a page path. ALWAYS resolves to a slug that
 * getOgEntries() produced, so the <meta og:image> never 404s. Glossary term
 * pages (500+), the legacy redirect pages, every ATT&CK/D3FEND technique
 * detail page (500+ combined), and every threat-actor group detail page
 * (174) share their section's one card rather than generating one image each.
 */
export function ogSlugForPath(pathname: string): string {
  const s = pathname.replace(/^\/+|\/+$/g, '');
  if (s === '') return 'index';
  // The bare 'glossary'/'event-ids'/'attack-map'/'d3fend' slugs are each already
  // in STATIC_SLUGS and fall through to that check below with the same result —
  // only their sub-path prefixes need handling here.
  if (s.startsWith('glossary/')) return 'glossary';
  if (s === 'word-of-the-day' || s === 'term-of-the-day') return 'glossary';
  if (s.startsWith('event-ids/')) return 'event-ids';
  if (s.startsWith('network-ports/')) return 'network-ports';
  // Every technique detail page shares its map's one card, same as glossary terms.
  if (s.startsWith('attack-map/')) return 'attack-map';
  if (s.startsWith('d3fend/')) return 'd3fend';
  if (s.startsWith('threat-actors/')) return 'threat-actors';
  if (STATIC_SLUGS.has(s)) return s;
  if (s.startsWith('blog/') || s.startsWith('labs/')) return s;
  return 'index';
}
