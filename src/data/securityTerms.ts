// ─────────────────────────────────────────────────────────────────────────
// Cybersecurity glossary bank — the single source of truth.
//
// Vendor-agnostic on purpose: every entry is a concept, technique, artifact, or
// model — never a product. Each field is natural prose (see docs/STYLE_GUIDE.md →
// "Glossary terms"); task instructions must never leak into a definition. This
// data drives the /reference/glossary/ index, the prerendered /reference/glossary/[slug]/ detail pages,
// and the site-wide "Term of the Day" ticker.
//
// A small curated core lives in src/data/terms/curated.json; the bulk is authored
// per-domain in src/data/terms/*.json — all merged, de-duplicated, and
// link-sanitized at load (this file is the assembly + lookup logic).
//
// The daily term is chosen deterministically from the calendar date (see
// `termForDate`), so it changes every day and is the same for everyone on a
// given day — no rebuild required. Add a term by appending to SECURITY_TERMS;
// test/securityTerms.test.ts guards slug uniqueness, related-link integrity,
// and the rotation math.
// ─────────────────────────────────────────────────────────────────────────

import type { IconName } from '../components/Icon.astro';
import curatedTerms from './terms/curated.json';
import memoryTerms from './terms/memory.json';
import hostDiskTerms from './terms/host-disk.json';
import malwareReTerms from './terms/malware-re.json';
import networkTerms from './terms/network.json';
import adversaryTerms from './terms/adversary.json';
import credentialIdentityTerms from './terms/credential-identity.json';
import cloudTerms from './terms/cloud.json';
import cryptoTerms from './terms/crypto.json';
import detectionIrTerms from './terms/detection-ir.json';
import threatIntelTerms from './terms/threat-intel-frameworks.json';
import vulnExploitTerms from './terms/vuln-exploit.json';
import webAppEmailTerms from './terms/web-app-email.json';
import loggingTerms from './terms/logging.json';
import linuxMacMobileTerms from './terms/linux-mac-mobile.json';

export const CATEGORIES = [
  'Memory Forensics',
  'Host & Disk Forensics',
  'Malware Analysis & RE',
  'Network Forensics & C2',
  'Adversary Tactics',
  'Credential & Identity Attacks',
  'Cloud & Container Security',
  'Cryptography & Data Protection',
  'Detection, Hunting & IR',
  'Threat Intelligence & Frameworks',
  'Vulnerabilities & Exploitation',
  'Web, Email & Application Security',
  'Logging & Telemetry',
  'Linux, macOS & Mobile Forensics',
] as const;

type SecurityCategory = (typeof CATEGORIES)[number];

export interface SecurityTerm {
  term: string;
  slug: string;
  category: SecurityCategory;
  /** Synonyms / abbreviations shown under the title. */
  aka?: string[];
  /** One-liner for the ticker and glossary cards. Keep it short. */
  short: string;
  /** Where the artifact actually lives (file path / registry key) — only set for
   * terms that name a concrete, locatable artifact, not abstract concepts/techniques. */
  location?: string;
  /** What it is (plain English). */
  definition: string;
  /** Why it matters in DFIR / incident response. */
  significance: string;
  /** A concrete, investigation-flavored example. */
  example: string;
  /** Slugs of related terms (cross-links). */
  related: string[];
}

/** Icon (see Icon.astro) + blurb for each category, used on the glossary index. */
export const CATEGORY_META: Record<SecurityCategory, { icon: IconName; blurb: string }> = {
  'Memory Forensics': { icon: 'cpu', blurb: 'Evidence that lives only in RAM.' },
  'Host & Disk Forensics': { icon: 'hard-drive', blurb: 'Artifacts left behind on disk.' },
  'Malware Analysis & RE': { icon: 'bug', blurb: 'How malicious code hides, runs, and is reversed.' },
  'Network Forensics & C2': { icon: 'radio', blurb: 'Traffic, callbacks, tunnels, and exfil.' },
  'Adversary Tactics': { icon: 'crosshair', blurb: 'How attackers move, escalate, and evade.' },
  'Credential & Identity Attacks': { icon: 'key', blurb: 'Stealing and abusing authentication.' },
  'Cloud & Container Security': { icon: 'cloud', blurb: 'IAM, workloads, and container risk.' },
  'Cryptography & Data Protection': { icon: 'lock', blurb: 'Ciphers, hashing, keys, and PKI.' },
  'Detection, Hunting & IR': { icon: 'shield', blurb: 'Finding, scoping, and responding.' },
  'Threat Intelligence & Frameworks': { icon: 'layers', blurb: 'Actors, models, and shared language.' },
  'Vulnerabilities & Exploitation': { icon: 'alert-triangle', blurb: 'Flaws, classes, and exploit primitives.' },
  'Web, Email & Application Security': { icon: 'globe', blurb: 'Phishing, web, and app-layer attacks.' },
  'Logging & Telemetry': { icon: 'activity', blurb: 'The sources that make detection possible.' },
  'Linux, macOS & Mobile Forensics': { icon: 'terminal', blurb: 'Artifacts beyond Windows.' },
};

// Curated core — hand-written, highest-quality entries, kept in
// src/data/terms/curated.json (each carries its own category). Merged ahead of
// (and de-duplicated against) the per-domain JSON batches below, so on a slug
// collision the curated entry wins.
const CURATED_TERMS = curatedTerms as unknown as SecurityTerm[];

// ─── Assemble the bank, then lookup + rotation helpers (pure; unit-tested) ─────────────────────────

type RawTerm = Omit<SecurityTerm, 'category'>;
const tag = (raw: unknown, category: SecurityCategory): SecurityTerm[] =>
  (raw as RawTerm[]).map((t) => ({ ...t, category }));

// Curated core first (so it wins de-dup), then each per-domain JSON batch.
const ALL_RAW: SecurityTerm[] = [
  ...CURATED_TERMS,
  ...tag(memoryTerms, 'Memory Forensics'),
  ...tag(hostDiskTerms, 'Host & Disk Forensics'),
  ...tag(malwareReTerms, 'Malware Analysis & RE'),
  ...tag(networkTerms, 'Network Forensics & C2'),
  ...tag(adversaryTerms, 'Adversary Tactics'),
  ...tag(credentialIdentityTerms, 'Credential & Identity Attacks'),
  ...tag(cloudTerms, 'Cloud & Container Security'),
  ...tag(cryptoTerms, 'Cryptography & Data Protection'),
  ...tag(detectionIrTerms, 'Detection, Hunting & IR'),
  ...tag(threatIntelTerms, 'Threat Intelligence & Frameworks'),
  ...tag(vulnExploitTerms, 'Vulnerabilities & Exploitation'),
  ...tag(webAppEmailTerms, 'Web, Email & Application Security'),
  ...tag(loggingTerms, 'Logging & Telemetry'),
  ...tag(linuxMacMobileTerms, 'Linux, macOS & Mobile Forensics'),
];

const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const isComplete = (t: SecurityTerm): boolean =>
  !!(t.term && t.slug && t.short && t.definition && t.significance && t.example);

// Dedupe by slug (first occurrence wins), keeping only valid, complete entries.
const deduped: SecurityTerm[] = [];
const seenSlugs = new Set<string>();
for (const t of ALL_RAW) {
  if (!SLUG_RE.test(t.slug) || seenSlugs.has(t.slug) || !isComplete(t)) continue;
  seenSlugs.add(t.slug);
  deduped.push(t);
}

// Sanitize cross-links: drop self-links and any related slug that doesn't resolve.
const validSlugs = new Set(deduped.map((t) => t.slug));

/** The full term bank — curated core + per-domain batches, deduped + sanitized. */
export const SECURITY_TERMS: SecurityTerm[] = deduped.map((t) => ({
  ...t,
  related: (t.related ?? []).filter((r) => r !== t.slug && validSlugs.has(r)).slice(0, 4),
}));

const BY_SLUG: Map<string, SecurityTerm> = new Map(
  SECURITY_TERMS.map((t) => [t.slug, t]),
);

/** Look up a term by slug. */
export function termBySlug(slug: string): SecurityTerm | undefined {
  return BY_SLUG.get(slug);
}

/**
 * Whole days since the Unix epoch for a given calendar date. Timezone-free:
 * it treats the supplied Y/M/D as a UTC date, so the build and every client
 * compute the same serial from the same (UTC) calendar day.
 */
export function daySerial(year: number, monthIndex: number, day: number): number {
  return Math.floor(Date.UTC(year, monthIndex, day) / 86_400_000);
}

/** Map a day serial onto a bank index (safe for negative serials). */
export function termIndexForDay(serial: number, count = SECURITY_TERMS.length): number {
  return ((serial % count) + count) % count;
}

/** The term for a given date, keyed to its UTC calendar day — so the term is
 *  identical for every visitor worldwide and rolls over at 00:00 UTC. */
export function termForDate(date: Date): SecurityTerm {
  const serial = daySerial(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());
  return SECURITY_TERMS[termIndexForDay(serial)];
}
