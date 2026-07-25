// IOC (indicator of compromise) extraction + defang/refang engine — pure
// functions, no DOM dependency, so this is unit-tested directly
// (test/iocs.test.ts) and imported into the client bundle (IocExtractor.astro)
// for live extraction as you type.
//
// Each category is a self-contained global regex; extractIocs() runs every
// one over the pasted text and dedupes exact matches within that category
// (not across categories — a domain that's also part of an extracted URL is
// expected to show up in both lists, which is normal for this kind of tool).
// This is inherently best-effort: domain/ATT&CK-ID matching in particular can
// have false positives on ordinary text that happens to look like an
// indicator — an analyst reviews the results, this doesn't replace judgment.
//
// extractIocs() also scans a refanged shadow copy of the pasted text (see
// refangText() below) so a paste containing already-defanged indicators
// (e.g. copied straight out of a threat report) is recognized too. Each
// returned IocMatch flags whether its value was ONLY recoverable that way
// (viaRefang) — never present, in any form, in the raw pasted text — which is
// what lets the UI's "As found" mode show a genuinely-defanged paste back
// defanged instead of silently upgrading it to the live form.

export interface IocCategory {
  id: string;
  label: string;
  pattern: RegExp;
  placeholder: string;
}

const IPV4 =
  /\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b/g;

// Canonical comprehensive IPv6 pattern (covers full, compressed "::", and
// leading/trailing-compressed forms); a negative lookaround on both sides
// keeps it from matching mid-token inside a longer hex/colon run.
const IPV6 =
  /(?<![\w:])(?:(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}|[A-Fa-f0-9]{1,4}:(?:(?::[A-Fa-f0-9]{1,4}){1,6})|:(?:(?::[A-Fa-f0-9]{1,4}){1,7}|:))(?![\w:])/g;

const URL_RE = /\bhttps?:\/\/[^\s<>"'\)\]]+/gi;

const DOMAIN =
  /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;

const EMAIL = /\b[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;

const MD5 = /\b[a-fA-F0-9]{32}\b/g;
const SHA1 = /\b[a-fA-F0-9]{40}\b/g;
const SHA256 = /\b[a-fA-F0-9]{64}\b/g;
const SHA512 = /\b[a-fA-F0-9]{128}\b/g;

const CVE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const ATTACK_ID = /\bT\d{4}(?:\.\d{3})?\b/g;
const BTC = /\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,90})\b/g;

// Reused verbatim (source + semantics) from the Windows File Path entry in
// src/utils/regexPatterns.ts's DFIR_REGEX_PATTERNS, just with a 'g' flag added
// to match this file's global-scan convention — a drive letter + backslash-
// separated path, excluding characters Windows disallows in file names.
const WINPATH = /[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+/g;

// Reused verbatim from the Registry Key Path entry in regexPatterns.ts (see
// WINPATH above) — a recognized hive (full name or common abbreviation)
// followed by its backslash-separated key path.
const REGKEY =
  /\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)\b(?:\\[^\\\r\n]+)*/g;

// Standard 6-octet MAC address, colon- or hyphen-separated. No 'i' flag
// needed — [0-9A-Fa-f] already covers both cases, same convention as the
// MD5/SHA1/SHA256/SHA512 hash patterns above.
const MAC = /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g;

export const IOC_CATEGORIES: IocCategory[] = [
  { id: 'ipv4', label: 'IPv4 addresses', pattern: IPV4, placeholder: '203.0.113.42' },
  { id: 'ipv6', label: 'IPv6 addresses', pattern: IPV6, placeholder: '2001:db8::8a2e:370:7334' },
  { id: 'url', label: 'URLs', pattern: URL_RE, placeholder: 'http://example.com/path' },
  { id: 'domain', label: 'Domains', pattern: DOMAIN, placeholder: 'evil-domain.example' },
  { id: 'email', label: 'Email addresses', pattern: EMAIL, placeholder: 'user@example.com' },
  { id: 'md5', label: 'MD5 hashes', pattern: MD5, placeholder: '32 hex chars' },
  { id: 'sha1', label: 'SHA1 hashes', pattern: SHA1, placeholder: '40 hex chars' },
  { id: 'sha256', label: 'SHA256 hashes', pattern: SHA256, placeholder: '64 hex chars' },
  { id: 'sha512', label: 'SHA512 hashes', pattern: SHA512, placeholder: '128 hex chars' },
  { id: 'cve', label: 'CVE IDs', pattern: CVE, placeholder: 'CVE-2021-44228' },
  { id: 'attack', label: 'MITRE ATT&CK IDs', pattern: ATTACK_ID, placeholder: 'T1055.001' },
  { id: 'btc', label: 'Bitcoin addresses', pattern: BTC, placeholder: 'bc1q… / 1… / 3…' },
  { id: 'winpath', label: 'Windows file paths', pattern: WINPATH, placeholder: 'C:\\Users\\...\\file.exe' },
  { id: 'regkey', label: 'Registry key paths', pattern: REGKEY, placeholder: 'HKLM\\Software\\...' },
  { id: 'mac', label: 'MAC addresses', pattern: MAC, placeholder: '00:1A:2B:3C:4D:5E' },
];

/** Extract + dedupe every category's matches from a block of text. */
// The URL pattern's character class is deliberately permissive (a real URL can
// contain almost anything in its path/query), which means a URL sitting at the
// end of a sentence in ordinary prose greedily swallows the sentence's own
// trailing punctuation too ("...see http://evil.example/x." -> matches the
// trailing "."). Trim that back off; URLs essentially never legitimately end
// in these characters when embedded in prose, and this is standard practice
// for link-extraction tools generally.
function trimTrailingPunctuation(value: string): string {
  return value.replace(/[.,;:!?'")\]}]+$/, '');
}

// Best-effort refang of a whole block of PASTED TEXT (distinct from
// refangValue above, which reverses a single already-extracted value) — used
// internally so extraction also recognizes indicators that were pasted
// already-defanged (e.g. copied straight out of a threat report). Only
// reverses unambiguous, bracket/paren-wrapped defanging markers — never bare
// words like "dot"/"at" in ordinary prose, which would false-positive constantly
// (e.g. "I dot my i's"). This never touches what's displayed; it's purely an
// internal second look so mixed fanged/defanged pastes both get recognized.
function refangText(text: string): string {
  return text
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, '.')
    .replace(/hxxps/gi, 'https')
    .replace(/hxxp/gi, 'http')
    .replace(/\[at\]|\(at\)|\[@\]/gi, '@')
    .replace(/\[:\]/g, ':');
}

/** True if the text contains any recognized defanging marker — lets the UI
 *  surface that its extracted indicators were recovered from defanged input. */
export function containsDefanged(text: string): boolean {
  return refangText(text) !== text;
}

export interface IocMatch {
  /** The fully live/canonical form of the extracted value. */
  value: string;
  /** True if this value was ONLY found by scanning the refanged shadow copy
   *  — i.e. it never appeared, in any form, in the raw pasted text (the user
   *  pasted it already defanged). False if it appeared live in the raw text
   *  at all (including when it *also* showed up defanged elsewhere). */
  viaRefang: boolean;
}

export function extractIocs(text: string): Record<string, IocMatch[]> {
  const refanged = refangText(text);
  // Run extraction on the raw text AND (when it actually differs) the
  // refanged version, unioning results per category — this is what lets a
  // paste containing already-defanged indicators (or a mix of live and
  // defanged) get recognized the same as fully-live text, since the matched
  // value always ends up in its live form either way. The raw-text pass is
  // tracked in its own seen-set so callers can tell which values were only
  // recoverable via the refanged shadow copy (see IocMatch.viaRefang).
  const sources = refanged === text ? [text] : [text, refanged];
  const result: Record<string, IocMatch[]> = {};
  for (const cat of IOC_CATEGORIES) {
    const rawSeen = new Set<string>();
    const order: string[] = [];
    const allSeen = new Set<string>();
    for (let i = 0; i < sources.length; i++) {
      const source = sources[i];
      const isRawSource = i === 0; // sources[0] is always the raw pasted text
      // Reuse the category's own compiled pattern (reset to scan from the
      // start) rather than re-compiling a fresh RegExp from its source/flags
      // on every call — this runs on every keystroke, so avoiding needless
      // re-compilation matters. Safe because this loop runs synchronously to
      // completion before the next category's scan begins.
      cat.pattern.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = cat.pattern.exec(source))) {
        const value = cat.id === 'url' ? trimTrailingPunctuation(m[0]) : m[0];
        if (value) {
          if (isRawSource) rawSeen.add(value);
          if (!allSeen.has(value)) {
            allSeen.add(value);
            order.push(value);
          }
        }
        if (m.index === cat.pattern.lastIndex) cat.pattern.lastIndex += 1; // guard a zero-width match from looping forever
      }
    }
    result[cat.id] = order.map((value) => ({ value, viaRefang: !rawSeen.has(value) }));
  }
  return result;
}

const DEFANGABLE_DOT = new Set(['ipv4', 'domain', 'email', 'url']);

/** Defang one extracted IOC value for safe sharing (e.g. in a report) — reversible via refangValue. */
export function defangValue(value: string, categoryId: string): string {
  let out = value;
  if (categoryId === 'url') out = out.replace(/https?/gi, (m) => (m[m.length - 1].toLowerCase() === 's' ? 'hxxps' : 'hxxp'));
  if (categoryId === 'ipv6') out = out.replace(/:/g, '[:]');
  if (DEFANGABLE_DOT.has(categoryId)) out = out.replace(/\./g, '[.]');
  if (categoryId === 'email') out = out.replace(/@/g, '[at]');
  return out;
}

/** Reverse defangValue. */
export function refangValue(value: string, categoryId: string): string {
  let out = value;
  if (categoryId === 'url') out = out.replace(/hxxps/gi, 'https').replace(/hxxp/gi, 'http');
  if (categoryId === 'ipv6') out = out.replace(/\[:\]/g, ':');
  if (DEFANGABLE_DOT.has(categoryId)) out = out.replace(/\[\.\]/g, '.');
  if (categoryId === 'email') out = out.replace(/\[at\]/gi, '@');
  return out;
}
