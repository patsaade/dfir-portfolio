// Entities for the site-wide hover/tap context cards (see components/HoverCards.astro).
//
// These are the AUTO-detected sets — companies, certifications, and a few
// distinctive tools — wrapped wherever their name appears in page content.
// Glossary TERMS are handled separately (manually, via <Term>, sourced from the
// glossary bank). Keep tool aliases distinctive to avoid matching common words.
type EntityType = 'company' | 'cert' | 'tool';

export interface HoverEntity {
  id: string;
  type: EntityType;
  name: string;
  /** Strings to auto-match in content (longest matched first). */
  aliases: string[];
  blurb: string;
  url: string;
}

export const HOVER_ENTITIES: HoverEntity[] = [
  // ── Companies ─────────────────────────────────────────────────────────
  {
    id: 'first-american',
    type: 'company',
    name: 'First American',
    aliases: ['First American'],
    blurb: 'A Fortune 500 title-insurance and real-estate settlement-services company.',
    url: 'https://www.firstam.com/',
  },
  {
    id: 'red-canary',
    type: 'company',
    name: 'Red Canary',
    aliases: ['Red Canary'],
    blurb: 'A managed detection & response (MDR) and security-operations company, now part of Zscaler.',
    url: 'https://redcanary.com/',
  },
  {
    id: 'zscaler',
    type: 'company',
    name: 'Zscaler',
    aliases: ['Zscaler'],
    blurb: 'A cloud-security company known for zero trust and Secure Service Edge (SSE).',
    url: 'https://www.zscaler.com/',
  },
  {
    id: 'reliaquest',
    type: 'company',
    name: 'ReliaQuest',
    aliases: ['ReliaQuest'],
    blurb: 'A security-operations company behind the GreyMatter security-operations platform.',
    url: 'https://www.reliaquest.com/',
  },

  // ── Certifications ────────────────────────────────────────────────────
  {
    id: 'cissp',
    type: 'cert',
    name: 'CISSP',
    aliases: ['CISSP'],
    blurb: 'Certified Information Systems Security Professional — ISC2’s broad information-security certification.',
    url: 'https://www.isc2.org/certifications/cissp',
  },
  {
    id: 'gcfa',
    type: 'cert',
    name: 'GCFA',
    aliases: ['GCFA'],
    blurb: 'GIAC Certified Forensic Analyst — advanced incident response and host forensics.',
    url: 'https://www.giac.org/certifications/certified-forensic-analyst-gcfa/',
  },
  {
    id: 'gcfe',
    type: 'cert',
    name: 'GCFE',
    aliases: ['GCFE'],
    blurb: 'GIAC Certified Forensic Examiner — Windows forensic analysis.',
    url: 'https://www.giac.org/certifications/certified-forensic-examiner-gcfe/',
  },
  {
    id: 'gcih',
    type: 'cert',
    name: 'GCIH',
    aliases: ['GCIH'],
    blurb: 'GIAC Certified Incident Handler — detecting and responding to intrusions.',
    url: 'https://www.giac.org/certifications/certified-incident-handler-gcih/',
  },
  {
    id: 'cysa',
    type: 'cert',
    name: 'CySA+',
    aliases: ['CySA+'],
    blurb: 'CompTIA Cybersecurity Analyst — behavioral analytics and threat detection.',
    url: 'https://www.comptia.org/certifications/cybersecurity-analyst',
  },
  {
    id: 'pentest',
    type: 'cert',
    name: 'PenTest+',
    aliases: ['PenTest+'],
    blurb: 'CompTIA PenTest+ — penetration testing and vulnerability assessment.',
    url: 'https://www.comptia.org/certifications/pentest',
  },
  {
    id: 'securityx',
    type: 'cert',
    name: 'SecurityX',
    aliases: ['SecurityX', 'CASP+'],
    blurb: 'CompTIA SecurityX (formerly CASP+) — advanced security-practitioner certification.',
    url: 'https://www.comptia.org/certifications/securityx',
  },

  // ── Tools (distinctive names only — avoid common words) ────────────────
  {
    id: 'volatility',
    type: 'tool',
    name: 'Volatility 3',
    aliases: ['Volatility 3', 'Volatility'],
    blurb: 'Open-source memory-forensics framework for extracting artifacts from RAM.',
    url: 'https://github.com/volatilityfoundation/volatility3',
  },
  {
    id: 'memprocfs',
    type: 'tool',
    name: 'MemProcFS',
    aliases: ['MemProcFS'],
    blurb: 'Mounts a memory image as a browsable file system for fast triage.',
    url: 'https://github.com/ufrisk/MemProcFS',
  },
  {
    id: 'velociraptor',
    type: 'tool',
    name: 'Velociraptor',
    aliases: ['Velociraptor'],
    blurb: 'Endpoint visibility and remote evidence collection at scale.',
    url: 'https://docs.velociraptor.app/',
  },
  {
    id: 'wireshark',
    type: 'tool',
    name: 'Wireshark',
    aliases: ['Wireshark'],
    blurb: 'Deep packet capture and protocol analysis.',
    url: 'https://www.wireshark.org/',
  },
  {
    id: 'ghidra',
    type: 'tool',
    name: 'Ghidra',
    aliases: ['Ghidra'],
    blurb: 'Open-source software reverse-engineering suite.',
    url: 'https://ghidra-sre.org/',
  },
  {
    id: 'autopsy',
    type: 'tool',
    name: 'Autopsy',
    aliases: ['Autopsy'],
    blurb: 'GUI disk-forensics and artifact-analysis platform.',
    url: 'https://www.autopsy.com/',
  },
  {
    id: 'kape',
    type: 'tool',
    name: 'KAPE',
    aliases: ['KAPE'],
    blurb: 'Targeted artifact collection and module processing.',
    url: 'https://www.kroll.com/kape',
  },
  {
    id: 'cyberchef',
    type: 'tool',
    name: 'CyberChef',
    aliases: ['CyberChef'],
    blurb: 'Web app to decode, deobfuscate, and transform data.',
    url: 'https://gchq.github.io/CyberChef/',
  },
  {
    id: 'virustotal',
    type: 'tool',
    name: 'VirusTotal',
    aliases: ['VirusTotal'],
    blurb: 'Multi-engine file/URL/hash reputation and intelligence.',
    url: 'https://www.virustotal.com/',
  },
  {
    id: 'plaso',
    type: 'tool',
    name: 'Plaso',
    aliases: ['log2timeline', 'Plaso'],
    blurb: 'Super-timeline generation across many artifact types.',
    url: 'https://github.com/log2timeline/plaso',
  },
  {
    id: 'timesketch',
    type: 'tool',
    name: 'Timesketch',
    aliases: ['Timesketch'],
    blurb: 'Collaborative timeline review and annotation.',
    url: 'https://timesketch.org/',
  },
  {
    id: 'sysmon',
    type: 'tool',
    name: 'Sysmon',
    aliases: ['Sysmon'],
    blurb: 'Windows system-activity logging for richer detection telemetry.',
    url: 'https://learn.microsoft.com/sysinternals/downloads/sysmon',
  },
  {
    id: 'hayabusa',
    type: 'tool',
    name: 'Hayabusa',
    aliases: ['Hayabusa'],
    blurb: 'Sigma-based Windows event-log threat hunting.',
    url: 'https://github.com/Yamato-Security/hayabusa',
  },
];

// ── Auto-matched GLOSSARY TERMS ───────────────────────────────────────────
//
// A CURATED allowlist, not the whole glossary. The bank holds 542 terms; auto-
// matching all of them would turn prose into a minefield of dotted underlines
// and would fire on genuinely ambiguous words ("hash", "port", "session",
// "recovery", "alert") — the same reason the tool aliases above are kept
// deliberately distinctive.
//
// WHY THIS EXISTS. `<Term slug>` tagging is manual, and coverage had reached only
// 35 of 1,729 pages — with exactly ONE of those a blog post. So both the term
// cards and the `cursor: help` affordance were effectively unreachable while
// reading prose: the machinery worked, but a reader would almost never meet it.
// Auto-matching a safe subset scales to every future post without the author
// having to remember, which manual tagging demonstrably did not.
//
// Inclusion bar — a term earns a slot only if ALL of these hold:
//   1. It is unmistakable jargon, with no ordinary-English reading in a sentence.
//   2. It plausibly appears in this site's own prose.
//   3. Its shortest alias cannot sit inside an unrelated word. Word boundaries
//      are enforced (so "packing" won't fire inside "unpacking"), but don't lean
//      on that for a genuinely ambiguous word — leave it out instead.
//
// Matching is CASE-INSENSITIVE for terms, because prose writes "lateral
// movement" mid-sentence; the proper-noun entities above stay case-sensitive.
// Only the FIRST mention per term per page is wrapped, and a term already tagged
// by hand with <Term> on that page is skipped entirely, so auto and manual can
// never double-underline the same word.
//
// `test/autoTerms.test.ts` asserts every slug resolves against SECURITY_TERMS,
// so a renamed or removed term fails the suite instead of silently wrapping a
// word whose card then never loads.
export interface AutoTerm {
  /** Glossary slug — must exist in SECURITY_TERMS. */
  slug: string;
  /** Strings to match in prose, case-insensitively (longest matched first). */
  aliases: string[];
}

export const AUTO_TERMS: AutoTerm[] = [
  { slug: 'order-of-volatility', aliases: ['Order of Volatility'] },
  { slug: 'chain-of-custody', aliases: ['Chain of Custody'] },
  { slug: 'master-file-table', aliases: ['Master File Table'] },
  { slug: 'alternate-data-streams', aliases: ['Alternate Data Streams'] },
  { slug: 'usn-journal', aliases: ['USN Journal'] },
  { slug: 'volume-shadow-copy', aliases: ['Volume Shadow Copy'] },
  { slug: 'file-carving', aliases: ['File Carving'] },
  { slug: 'timeline-analysis', aliases: ['Timeline Analysis'] },
  { slug: 'write-blocking', aliases: ['Write Blocking'] },
  { slug: 'live-response', aliases: ['Live Response'] },
  { slug: 'mac-times', aliases: ['MAC(b) Times'] },
  { slug: 'run-keys', aliases: ['Registry Run Keys'] },
  { slug: 'jump-lists', aliases: ['Jump Lists'] },
  { slug: 'lnk-files', aliases: ['LNK Files'] },
  { slug: 'prefetch', aliases: ['Prefetch'] },
  { slug: 'shimcache-appcompatcache', aliases: ['ShimCache'] },
  { slug: 'amcache', aliases: ['AmCache'] },
  { slug: 'shellbags', aliases: ['Shellbags'] },
  { slug: 'timestomping', aliases: ['Timestomping'] },
  { slug: 'living-off-the-land', aliases: ['Living off the Land'] },
  { slug: 'lateral-movement', aliases: ['Lateral Movement'] },
  { slug: 'privilege-escalation', aliases: ['Privilege Escalation'] },
  { slug: 'credential-dumping', aliases: ['Credential Dumping'] },
  { slug: 'indicator-of-compromise', aliases: ['Indicator of Compromise'] },
  { slug: 'process-injection', aliases: ['Process Injection'] },
  { slug: 'process-hollowing', aliases: ['Process Hollowing'] },
  { slug: 'dll-injection', aliases: ['DLL Injection'] },
  { slug: 'command-and-control', aliases: ['Command and Control'] },
  { slug: 'data-exfiltration', aliases: ['Data Exfiltration'] },
  { slug: 'dns-tunneling', aliases: ['DNS Tunneling'] },
  { slug: 'domain-generation-algorithm', aliases: ['Domain Generation Algorithm'] },
  { slug: 'reverse-shell', aliases: ['Reverse Shell'] },
  { slug: 'web-shell', aliases: ['Web Shell'] },
  { slug: 'fileless-malware', aliases: ['Fileless Malware'] },
  { slug: 'kerberoasting', aliases: ['Kerberoasting'] },
  { slug: 'pass-the-hash', aliases: ['Pass-the-Hash'] },
  { slug: 'golden-ticket', aliases: ['Golden Ticket'] },
  { slug: 'ntlm-relay', aliases: ['NTLM Relay'] },
  { slug: 'lsass-credential-theft', aliases: ['LSASS Credential Theft'] },
  { slug: 'persistence-mechanism', aliases: ['Persistence Mechanism'] },
  { slug: 'anti-forensics', aliases: ['Anti-Forensics'] },
  { slug: 'detection-engineering', aliases: ['Detection Engineering'] },
  { slug: 'threat-hunting', aliases: ['Threat Hunting'] },
  { slug: 'sigma-rule', aliases: ['Sigma Rule'] },
  { slug: 'false-positive', aliases: ['False Positive'] },
  { slug: 'alert-fatigue', aliases: ['Alert Fatigue'] },
  { slug: 'dwell-time', aliases: ['Dwell Time'] },
  { slug: 'mean-time-to-detect', aliases: ['Mean Time to Detect'] },
  { slug: 'cyber-kill-chain', aliases: ['Cyber Kill Chain'] },
  { slug: 'pyramid-of-pain', aliases: ['Pyramid of Pain'] },
  { slug: 'threat-actor', aliases: ['Threat Actor'] },
  { slug: 'advanced-persistent-threat', aliases: ['Advanced Persistent Threat'] },
  { slug: 'tactics-techniques-and-procedures', aliases: ['Tactics, Techniques, and Procedures'] },
  { slug: 'event-tracing-for-windows', aliases: ['Event Tracing for Windows'] },
  { slug: 'powershell-logging', aliases: ['PowerShell Logging'] },
  { slug: 'sysmon', aliases: ['Sysmon'] },
  { slug: 'static-analysis', aliases: ['Static Analysis'] },
  { slug: 'dynamic-analysis', aliases: ['Dynamic Analysis'] },
  { slug: 'portable-executable-format', aliases: ['Portable Executable Format'] },
  { slug: 'packing', aliases: ['Packing'] },
  { slug: 'obfuscation', aliases: ['Obfuscation'] },
  { slug: 'shellcode', aliases: ['Shellcode'] },
  { slug: 'sandbox-evasion', aliases: ['Sandbox Evasion'] },
  { slug: 'yara', aliases: ['YARA'] },
  { slug: 'process-creation-auditing', aliases: ['Process Creation Auditing'] },
  { slug: 'windows-event-log', aliases: ['Windows Event Log'] },
  { slug: 'access-token-manipulation', aliases: ['Access Token Manipulation'] },
];
