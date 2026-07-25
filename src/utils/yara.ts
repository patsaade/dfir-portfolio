// YARA Rule Tester & Builder — pure functions, no DOM dependency (unit tested
// directly in test/yara.test.ts, imported into the client bundle by
// YaraTester.astro for live evaluation as you type).
//
// This implements an EXPLICITLY-SCOPED SUBSET of the YARA rule language
// (https://yara.readthedocs.io/en/stable/writingrules.html), not full-language
// parity — same discipline as this codebase's Sigma tester (src/utils/sigma.ts):
// everything in scope is implemented for real against a byte-level scan of the
// pasted sample, and everything out of scope produces a specific, named error
// instead of a silent guess or a fabricated result.
//
// SUPPORTED:
//   - one rule per source, identified by name only (YARA identifier rules:
//     alphanumerics + underscore, may not start with a digit, max 128 chars).
//   - a `strings:` section of two string kinds:
//       * TEXT strings — `$id = "value"` with the `ascii`, `wide` and `nocase`
//         modifiers. Per YARA's own docs: ASCII is the default, so `ascii`
//         alone is allowed but redundant; `wide` interleaves each byte of the
//         string with a 0x00 byte; `ascii wide` searches for BOTH forms;
//         `nocase` is ASCII-range case-insensitive matching and combines with
//         either form. Escape sequences understood inside the literal are
//         \" \\ \n \r \t and \xHH (see decodeTextLiteral — any other escape is
//         an error, deliberately stricter than YARA rather than guessing at a
//         byte value).
//       * HEX strings — `$id = { E8 ?? ?? ?? ?? }`. Wildcards are nibble-wise
//         exactly as YARA documents them, so `??` (whole byte unknown) and the
//         half-byte forms `A?` / `?A` are all supported.
//   - a `condition:` limited to `any of them`, `all of them`, `N of them`
//     (integer N), and a plain and/or list of individual string identifiers
//     (`$a and $b`, `$a or $b`, or a single `$a`). Mixing `and` and `or` in one
//     condition is reported as an error rather than guessing at precedence —
//     same call sigma.ts makes for the same reason.
//   - matching runs for real, byte-for-byte, against the parsed sample: every
//     occurrence (including overlapping ones, which is what YARA's own `#a`
//     counts) is found and its offset reported. There is no canned result path
//     anywhere in this file.
//
// EXPLICITLY NOT SUPPORTED — deliberate scope cuts, not silent gaps. Each one
// below is detected and reported by name (see UNSUPPORTED_YARA_FEATURES, which
// is also what the tool page's own "outside this tool's scope" table renders
// from, so the docs and the parser can't drift apart):
//   - MODULES (`import "pe"`, `pe.entry_point`, `math.entropy`, `hash.md5`, …)
//     and therefore every module-provided condition term.
//   - EXTERNAL VARIABLES (values a caller injects at scan time) — this tool has
//     no scan-time context to inject them from.
//   - REGULAR-EXPRESSION strings (`$re = /ab+c/`). Text and hex only.
//   - STRING COUNT / OFFSET / LENGTH expressions — `#a`, `@a`, `!a`,
//     `$a at 0`, `$a in (0..100)`. A string is a plain boolean here.
//   - RULE METADATA beyond the name: no `meta:` section, no rule tags
//     (`rule R : tag1`), no `global`/`private` rule modifiers, no rule
//     references or `for..of` / `for..in` loops in the condition, no
//     `filesize`/`entrypoint` terms, and no `not`.
//   - The remaining string modifiers `fullword`, `xor`, `base64`,
//     `base64wide`, `private`.
//   - Hex-string JUMPS (`[4-6]`), ALTERNATIVES (`( 62 B4 | 56 )`) and the
//     not-operator (`~00`). Nibble wildcards are the only hex construct here.
//   - `none of them` (YARA 4.3.0+) and explicit string sets in the `of`
//     operator (`any of ($a, $b)`, `2 of ($foo*)`) — only `them` is understood.
//   - the anonymous `$` string identifier.
//   - more than one rule in a single source.
//
// parseYaraRule() below is the import-side half of generateYaraRule(): it
// round-trips the exact source shape generateYaraRule itself emits, not a
// general-purpose YARA parser. Anything outside that shape comes back as a
// specific friendly error naming what's unsupported, never a best-effort guess.

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type YaraTextModifier = 'ascii' | 'wide' | 'nocase';

/** Single source of truth for the modifier checkboxes in the builder AND the
 *  "supported modifiers" reference table on the tool's page — mirrors
 *  SIGMA_MODIFIERS' role in utils/sigma.ts. */
export const YARA_TEXT_MODIFIERS: { id: YaraTextModifier; label: string; hint: string }[] = [
  {
    id: 'ascii',
    label: 'ascii',
    hint: 'Search for the plain single-byte form. This is YARA’s default, so it only needs writing out when it is paired with wide to search for both forms at once.',
  },
  {
    id: 'wide',
    label: 'wide',
    hint: 'Search for the form with each byte of the string interleaved with a 0x00 byte — how a UTF-16LE-encoded ASCII string looks on disk or in memory.',
  },
  {
    id: 'nocase',
    label: 'nocase',
    hint: 'Case-insensitive across the ASCII letter range (A–Z / a–z). Combines with either the ascii or the wide form.',
  },
];

/** Documented scope cuts — rendered as the tool page's own "outside this
 *  tool's scope" table so the page copy and the parser's own error messages
 *  come from one list instead of drifting apart. */
export const UNSUPPORTED_YARA_FEATURES: { feature: string; example: string; note: string }[] = [
  { feature: 'Modules', example: 'import "pe"', note: 'The pe, math, hash, elf, magic and cuckoo modules, and every condition term they provide.' },
  { feature: 'External variables', example: 'filename matches /\\.exe$/', note: 'Values a caller injects at scan time — this tool has no scan-time context to inject.' },
  { feature: 'Regex strings', example: '$re = /ab+c/', note: 'Only text strings and hex strings are supported.' },
  { feature: 'Count / offset / length', example: '#a > 3, @a, !a, $a at 0', note: 'A string is a plain boolean here — no occurrence count, match offset or length arithmetic in the condition.' },
  { feature: 'Rule metadata', example: 'meta: author = "…"', note: 'Nothing beyond the rule name: no meta block, no rule tags, no global/private modifiers.' },
  { feature: 'Other string modifiers', example: '"a" fullword xor base64', note: 'fullword, xor, base64, base64wide and private are all out of scope.' },
  { feature: 'Hex jumps & alternatives', example: '{ 8D [2-3] 6A ( 04 | 05 ) }', note: 'Nibble wildcards (?? / A? / ?A) are the only hex construct supported; jumps, alternatives and the ~ not-operator are not.' },
  { feature: 'Other condition forms', example: 'none of them, 2 of ($a*)', note: 'Only "them" is understood in the of-operator. none of them (YARA 4.3.0+), explicit string sets, for-loops, not, filesize and entrypoint are out of scope.' },
];

export interface YaraTextString {
  kind: 'text';
  /** Identifier WITHOUT the leading `$`. */
  id: string;
  /** The raw source text that sits between the quotes — escape sequences are
   *  stored unexpanded (`\n` is two characters here), so the builder input,
   *  the generated rule source and the parsed-back value are all the same
   *  string and nothing is lost round-tripping. Decoded to bytes only at
   *  compile time, by decodeTextLiteral. */
  value: string;
  modifiers: YaraTextModifier[];
}

export interface YaraHexString {
  kind: 'hex';
  id: string;
  /** Raw source between the braces, e.g. `E8 ?? ?? ?? ??`. */
  value: string;
}

export type YaraString = YaraTextString | YaraHexString;

export interface YaraRule {
  name: string;
  strings: YaraString[];
  /** Raw condition text — see parseYaraCondition for the supported grammar. */
  condition: string;
}

// ---------------------------------------------------------------------------
// Byte matchers — the one representation every compiled pattern reduces to
// ---------------------------------------------------------------------------

/** A single byte position in a compiled pattern: matches `b` when
 *  `(b & mask) === value`. Exact bytes use mask 0xFF; a `??` hex wildcard uses
 *  mask 0x00; the half-byte forms `A?`/`?A` use 0xF0/0x0F; and a `nocase`
 *  ASCII letter uses 0xDF, which is exactly the pair {upper, lower} for
 *  A–Z/a–z and nothing else (0xDF clears only bit 0x20). Non-letter bytes are
 *  never masked that way — `[` (0x5B) and `{` (0x7B) also differ by 0x20, so
 *  masking them would wrongly conflate the two. */
interface ByteMatcher {
  value: number;
  mask: number;
}

/** One compiled searchable form of a string. A text string with both `ascii`
 *  and `wide` compiles to two of these; a hex string to exactly one. */
export interface CompiledForm {
  form: 'ascii' | 'wide' | 'hex';
  matchers: ByteMatcher[];
}

export interface CompiledString {
  id: string;
  forms: CompiledForm[];
  error: string | null;
}

const ASCII_UPPER_A = 0x41;
const ASCII_UPPER_Z = 0x5a;
const ASCII_LOWER_A = 0x61;
const ASCII_LOWER_Z = 0x7a;
const NOCASE_MASK = 0xdf;

function isAsciiLetter(byte: number): boolean {
  return (byte >= ASCII_UPPER_A && byte <= ASCII_UPPER_Z) || (byte >= ASCII_LOWER_A && byte <= ASCII_LOWER_Z);
}

function exactMatchers(bytes: number[], nocase: boolean): ByteMatcher[] {
  return bytes.map((b) => (nocase && isAsciiLetter(b) ? { value: b & NOCASE_MASK, mask: NOCASE_MASK } : { value: b, mask: 0xff }));
}

/** Interleave each byte with a trailing 0x00 — YARA's documented `wide`
 *  behavior ("interleaves the ASCII codes of the characters in the string
 *  with zeroes"). The zero bytes are always matched exactly, even under
 *  nocase. */
function wideMatchers(bytes: number[], nocase: boolean): ByteMatcher[] {
  const out: ByteMatcher[] = [];
  for (const b of bytes) {
    out.push(nocase && isAsciiLetter(b) ? { value: b & NOCASE_MASK, mask: NOCASE_MASK } : { value: b, mask: 0xff });
    out.push({ value: 0x00, mask: 0xff });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Text-literal decoding
// ---------------------------------------------------------------------------

const SIMPLE_ESCAPES: Record<string, number> = {
  '"': 0x22,
  '\\': 0x5c,
  n: 0x0a,
  r: 0x0d,
  t: 0x09,
};

export interface DecodedLiteral {
  bytes: number[] | null;
  /** True when the literal contains any byte above 0x7F (a non-ASCII source
   *  character, UTF-8 encoded, or an explicit high \xHH escape). YARA's `wide`
   *  modifier is documented in terms of ASCII codes, so combining it with such
   *  a literal is rejected rather than guessed at — see compileYaraString. */
  hasNonAscii: boolean;
  error: string | null;
}

/** Decode the raw inner text of a `"…"` YARA text string into bytes. Never
 *  throws. Understands \" \\ \n \r \t and \xHH; any other escape is an error
 *  naming it, rather than YARA 4.x's "treat the character as itself" leniency
 *  — being stricter here can only reject a rule, never mis-match one. A
 *  non-ASCII source character is UTF-8 encoded, which is what YARA would read
 *  out of a UTF-8 rule file. */
export function decodeTextLiteral(raw: string): DecodedLiteral {
  const bytes: number[] = [];
  let hasNonAscii = false;
  const utf8 = (s: string): void => {
    for (const b of new TextEncoder().encode(s)) {
      if (b > 0x7f) hasNonAscii = true;
      bytes.push(b);
    }
  };

  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch === '"') {
      return { bytes: null, hasNonAscii, error: 'An unescaped " inside a text string — write it as \\" instead.' };
    }
    if (ch !== '\\') {
      utf8(ch);
      continue;
    }
    const next = raw[i + 1];
    if (next === undefined) {
      return { bytes: null, hasNonAscii, error: 'The text string ends with a lone backslash — write it as \\\\ to mean a literal backslash.' };
    }
    if (Object.prototype.hasOwnProperty.call(SIMPLE_ESCAPES, next)) {
      bytes.push(SIMPLE_ESCAPES[next]);
      i += 1;
      continue;
    }
    if (next === 'x' || next === 'X') {
      const hex = raw.slice(i + 2, i + 4);
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) {
        return { bytes: null, hasNonAscii, error: `"\\${next}" must be followed by exactly two hex digits, e.g. \\x41.` };
      }
      const b = parseInt(hex, 16);
      if (b > 0x7f) hasNonAscii = true;
      bytes.push(b);
      i += 3;
      continue;
    }
    return {
      bytes: null,
      hasNonAscii,
      error: `Unsupported escape sequence "\\${next}" — this tool understands \\" \\\\ \\n \\r \\t and \\xHH only.`,
    };
  }
  if (bytes.length === 0) {
    return { bytes: null, hasNonAscii, error: 'A text string can’t be empty.' };
  }
  return { bytes, hasNonAscii, error: null };
}

// ---------------------------------------------------------------------------
// Hex-pattern compiling
// ---------------------------------------------------------------------------

export interface CompiledHex {
  matchers: ByteMatcher[] | null;
  error: string | null;
}

const HEX_TOKEN_RE = /^[0-9a-fA-F?]{2}$/;

/** Compile the raw inner text of a `{ … }` YARA hex string into byte matchers.
 *  Nibble-wise wildcards (`??`, `A?`, `?A`) are supported exactly as YARA
 *  documents them. Jumps, alternatives and the `~` not-operator are detected
 *  and reported by name (see this file's header) rather than ignored. Never
 *  throws. */
export function compileHexPattern(raw: string): CompiledHex {
  if (/[[\]]/.test(raw)) {
    return { matchers: null, error: 'Hex jumps like [4-6] are outside this tool’s scope — spell the unknown bytes out as ?? instead.' };
  }
  if (/[()|]/.test(raw)) {
    return { matchers: null, error: 'Hex alternatives like ( 62 B4 | 56 ) are outside this tool’s scope.' };
  }
  if (raw.includes('~')) {
    return { matchers: null, error: 'The hex not-operator (~00) is outside this tool’s scope.' };
  }

  const tokens = raw.trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) {
    return { matchers: null, error: 'A hex string can’t be empty.' };
  }

  const matchers: ByteMatcher[] = [];
  for (const token of tokens) {
    if (!HEX_TOKEN_RE.test(token)) {
      return {
        matchers: null,
        error: `"${token}" isn’t a hex byte — write bytes as two hex digits separated by spaces, using ? for an unknown nibble (e.g. E8 ?? 6A A?).`,
      };
    }
    const hi = token[0];
    const lo = token[1];
    let value = 0;
    let mask = 0;
    if (hi !== '?') {
      value |= parseInt(hi, 16) << 4;
      mask |= 0xf0;
    }
    if (lo !== '?') {
      value |= parseInt(lo, 16);
      mask |= 0x0f;
    }
    matchers.push({ value, mask });
  }
  return { matchers, error: null };
}

// ---------------------------------------------------------------------------
// String compiling (text/hex -> searchable forms)
// ---------------------------------------------------------------------------

const ID_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

/** Compile one builder/parsed string into the forms actually searched for.
 *  A text string with both `ascii` and `wide` yields two forms — that's YARA's
 *  own "search for both encodings" behavior, not two separate strings. */
export function compileYaraString(s: YaraString): CompiledString {
  const fail = (error: string): CompiledString => ({ id: s.id, forms: [], error });
  if (!ID_RE.test(s.id)) {
    return fail(`"$${s.id}" isn’t a valid string identifier — use letters, digits and underscores, not starting with a digit.`);
  }

  if (s.kind === 'hex') {
    const { matchers, error } = compileHexPattern(s.value);
    if (!matchers) return fail(error || 'Invalid hex string.');
    return { id: s.id, forms: [{ form: 'hex', matchers }], error: null };
  }

  const decoded = decodeTextLiteral(s.value);
  if (!decoded.bytes) return fail(decoded.error || 'Invalid text string.');

  const nocase = s.modifiers.includes('nocase');
  const wide = s.modifiers.includes('wide');
  // ASCII is YARA's default: the plain form is searched unless `wide` was
  // given on its own. `ascii wide` searches for both.
  const ascii = s.modifiers.includes('ascii') || !wide;

  if (wide && decoded.hasNonAscii) {
    return fail('The wide modifier is defined in terms of ASCII codes, so this tool won’t apply it to a string containing non-ASCII bytes — use \\xHH escapes to spell the exact bytes you want instead.');
  }

  const forms: CompiledForm[] = [];
  if (ascii) forms.push({ form: 'ascii', matchers: exactMatchers(decoded.bytes, nocase) });
  if (wide) forms.push({ form: 'wide', matchers: wideMatchers(decoded.bytes, nocase) });
  return { id: s.id, forms, error: null };
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/** Every offset in `data` where `matchers` matches, including overlapping
 *  occurrences — which is what YARA's own occurrence count (`#a`) reports. */
export function findMatchOffsets(data: Uint8Array, matchers: ByteMatcher[]): number[] {
  const out: number[] = [];
  const n = matchers.length;
  if (n === 0 || data.length < n) return out;
  const last = data.length - n;
  for (let i = 0; i <= last; i++) {
    let ok = true;
    for (let j = 0; j < n; j++) {
      const m = matchers[j];
      if ((data[i + j] & m.mask) !== m.value) {
        ok = false;
        break;
      }
    }
    if (ok) out.push(i);
  }
  return out;
}

export interface YaraStringMatch {
  offset: number;
  length: number;
  form: 'ascii' | 'wide' | 'hex';
}

export interface YaraStringResult {
  id: string;
  matched: boolean;
  /** First MAX_REPORTED_MATCHES occurrences, offset-ordered. */
  matches: YaraStringMatch[];
  /** Total occurrences found, even when more than `matches` lists. */
  totalMatches: number;
  error: string | null;
}

export const MAX_REPORTED_MATCHES = 20;

/** Scan one string against the sample. A string that fails to compile comes
 *  back with `error` set and `matched: false` — never a throw, and never a
 *  match claimed for a string that couldn't be compiled. */
export function scanYaraString(s: YaraString, data: Uint8Array): YaraStringResult {
  const compiled = compileYaraString(s);
  if (compiled.error) {
    return { id: s.id, matched: false, matches: [], totalMatches: 0, error: compiled.error };
  }
  const all: YaraStringMatch[] = [];
  for (const form of compiled.forms) {
    for (const offset of findMatchOffsets(data, form.matchers)) {
      all.push({ offset, length: form.matchers.length, form: form.form });
    }
  }
  all.sort((a, b) => a.offset - b.offset || a.length - b.length);
  return {
    id: s.id,
    matched: all.length > 0,
    matches: all.slice(0, MAX_REPORTED_MATCHES),
    totalMatches: all.length,
    error: null,
  };
}

// ---------------------------------------------------------------------------
// Condition parsing + evaluation
// ---------------------------------------------------------------------------

type YaraConditionParsed =
  | { type: 'them'; op: 'any' | 'all' }
  | { type: 'them-n'; n: number }
  | { type: 'list'; op: 'and' | 'or'; ids: string[] };

export interface YaraConditionParseResult {
  parsed: YaraConditionParsed | null;
  error: string | null;
}

const STRING_REF_RE = /^\$([A-Za-z_][A-Za-z0-9_]{0,127})$/;

// Each pattern is anchored on whitespace/start rather than \b, so a string
// identifier that merely *contains* a keyword ($not_signed, $format) isn't
// mistaken for the keyword itself.
const OUT_OF_SCOPE_CONDITION_TERMS: { test: RegExp; message: string }[] = [
  { test: /(^|\s)none\s+of(\s|$)/, message: '"none of them" (YARA 4.3.0+) is outside this tool’s supported condition subset.' },
  { test: /(^|\s)of\s*\(/, message: 'Explicit string sets in the of-operator, like "any of ($a, $b)", are outside this tool’s scope — only "of them" is supported.' },
  { test: /(^|\s)for(\s|$)/, message: 'for..of / for..in loops are outside this tool’s supported condition subset.' },
  { test: /(^|\s)not(\s|$)/, message: 'The "not" operator is outside this tool’s supported condition subset.' },
  { test: /(^|\s)filesize(\s|$)/, message: '"filesize" is outside this tool’s supported condition subset.' },
  { test: /(^|\s)entrypoint(\s|$)/, message: '"entrypoint" is outside this tool’s supported condition subset.' },
  { test: /[#@!]\s*[A-Za-z_]/, message: 'String count/offset/length expressions (#a, @a, !a) are outside this tool’s supported condition subset.' },
  { test: /\$[A-Za-z0-9_]*\s+(at|in)(\s|$)/, message: 'Offset expressions like "$a at 0" and "$a in (0..100)" are outside this tool’s supported condition subset.' },
  { test: /(^|\s)(pe|math|hash|elf|magic|cuckoo)\s*\./, message: 'Module expressions (pe.*, math.*, hash.*, …) are outside this tool’s scope — modules aren’t supported.' },
];

/** Parse a `condition:` body into one of this tool's supported forms. Never
 *  throws — an unsupported or malformed condition comes back as
 *  { parsed: null, error: <friendly message> }. YARA keywords are lowercase
 *  and case-sensitive, so a wrong-case keyword is called out by name instead
 *  of silently accepted. */
export function parseYaraCondition(condition: string): YaraConditionParseResult {
  const trimmed = condition.trim().replace(/\s+/g, ' ');
  if (!trimmed) return { parsed: null, error: 'The condition is empty.' };

  for (const { test, message } of OUT_OF_SCOPE_CONDITION_TERMS) {
    if (test.test(trimmed)) return { parsed: null, error: message };
  }

  if (/^(any|all|[0-9]+) of them$/i.test(trimmed) && !/^(any|all|[0-9]+) of them$/.test(trimmed)) {
    return { parsed: null, error: `YARA keywords are lowercase — write "${trimmed.toLowerCase()}".` };
  }

  let m = /^(any|all) of them$/.exec(trimmed);
  if (m) return { parsed: { type: 'them', op: m[1] as 'any' | 'all' }, error: null };

  m = /^([0-9]+) of them$/.exec(trimmed);
  if (m) {
    const n = parseInt(m[1], 10);
    if (n < 1) {
      return { parsed: null, error: '"0 of them" is outside this tool’s scope — YARA 4.3.0+ spells that "none of them", which this tool doesn’t support either.' };
    }
    return { parsed: { type: 'them-n', n }, error: null };
  }

  if (/\$\s/.test(trimmed) || /\$$/.test(trimmed)) {
    return { parsed: null, error: 'The anonymous "$" string identifier is outside this tool’s scope — give every string its own name.' };
  }

  const hasAnd = /\band\b/.test(trimmed);
  const hasOr = /\bor\b/.test(trimmed);
  if (hasAnd && hasOr) {
    return { parsed: null, error: 'Mixing "and" and "or" in one condition is outside this tool’s supported subset.' };
  }

  const op: 'and' | 'or' = hasOr ? 'or' : 'and';
  const parts = trimmed.split(hasOr ? /\s+or\s+/ : /\s+and\s+/).map((p) => p.trim()).filter(Boolean);
  const ids: string[] = [];
  for (const part of parts) {
    const ref = STRING_REF_RE.exec(part);
    if (!ref) {
      return { parsed: null, error: `Unrecognized term "${part}" — this tool’s conditions are "any/all/N of them" or a plain and/or list of string identifiers like $a and $b.` };
    }
    ids.push(ref[1]);
  }
  if (ids.length === 0) {
    return { parsed: null, error: 'Unrecognized condition syntax for this tool’s supported subset.' };
  }
  return { parsed: { type: 'list', op, ids }, error: null };
}

export interface YaraConditionEvalResult {
  matched: boolean;
  /** String identifiers (without `$`) that actually contributed to a true
   *  result. Empty when `matched` is false. */
  matchedIds: string[];
  error: string | null;
}

/** Evaluate a condition against already-scanned string results. Unknown
 *  identifiers and an out-of-range `N of them` come back as a friendly error
 *  — YARA's own docs require N to be less than or equal to the number of
 *  strings in the set, so a larger N is a rule bug, not a false result. */
export function evaluateYaraCondition(condition: string, stringResults: YaraStringResult[]): YaraConditionEvalResult {
  const { parsed, error } = parseYaraCondition(condition);
  if (!parsed) return { matched: false, matchedIds: [], error };

  const matchMap: Record<string, boolean> = {};
  for (const r of stringResults) matchMap[r.id] = r.matched;
  const allIds = stringResults.map((r) => r.id);

  if (parsed.type === 'them' || parsed.type === 'them-n') {
    if (allIds.length === 0) return { matched: false, matchedIds: [], error: 'There are no strings to evaluate.' };
    const hit = allIds.filter((id) => matchMap[id]);
    if (parsed.type === 'them') {
      const matched = parsed.op === 'any' ? hit.length > 0 : hit.length === allIds.length;
      return { matched, matchedIds: matched ? hit : [], error: null };
    }
    if (parsed.n > allIds.length) {
      return {
        matched: false,
        matchedIds: [],
        error: `"${parsed.n} of them" asks for more strings than the rule has (${allIds.length}) — YARA requires that number to be at most the size of the string set.`,
      };
    }
    const matched = hit.length >= parsed.n;
    return { matched, matchedIds: matched ? hit : [], error: null };
  }

  const unknown = parsed.ids.filter((id) => !(id in matchMap));
  if (unknown.length > 0) {
    return {
      matched: false,
      matchedIds: [],
      error: `Unknown string identifier${unknown.length > 1 ? 's' : ''}: ${unknown.map((u) => '$' + u).join(', ')}`,
    };
  }
  const hit = parsed.ids.filter((id) => matchMap[id]);
  const matched = parsed.op === 'and' ? hit.length === parsed.ids.length : hit.length > 0;
  return { matched, matchedIds: matched ? hit : [], error: null };
}

// ---------------------------------------------------------------------------
// Condition-builder UI helper (guided dropdown -> canonical condition string)
// ---------------------------------------------------------------------------

export type YaraConditionUiType = 'any-of-them' | 'all-of-them' | 'n-of-them' | 'list-and' | 'list-or';

/** Single source of truth for the guided builder's condition dropdown and the
 *  page's "supported condition forms" table. */
export const YARA_CONDITION_UI_TYPES: { id: YaraConditionUiType; label: string; syntax: string; hint: string }[] = [
  { id: 'any-of-them', label: 'Any of them', syntax: 'any of them', hint: 'At least one string in the rule has to be found in the sample.' },
  { id: 'all-of-them', label: 'All of them', syntax: 'all of them', hint: 'Every string in the rule has to be found.' },
  { id: 'n-of-them', label: 'N of them', syntax: 'N of them', hint: 'At least N of the rule’s strings have to be found. N must not exceed the number of strings.' },
  { id: 'list-and', label: 'These strings, all of them (and)', syntax: '$a and $b', hint: 'Only the strings you tick, and all of them must be found.' },
  { id: 'list-or', label: 'These strings, any of them (or)', syntax: '$a or $b', hint: 'Only the strings you tick, and any one of them is enough.' },
];

/** Build a canonical condition string from a guided-builder choice. Pure +
 *  exported so the client script and the test suite share one code path. */
export function buildYaraCondition(type: YaraConditionUiType, opts: { n?: number; ids?: string[] } = {}): string {
  switch (type) {
    case 'any-of-them':
      return 'any of them';
    case 'all-of-them':
      return 'all of them';
    case 'n-of-them': {
      const n = typeof opts.n === 'number' && isFinite(opts.n) ? Math.max(1, Math.floor(opts.n)) : 1;
      return `${n} of them`;
    }
    case 'list-and':
      return (opts.ids ?? []).map((id) => `$${id}`).join(' and ');
    case 'list-or':
      return (opts.ids ?? []).map((id) => `$${id}`).join(' or ');
    default:
      return '';
  }
}

// ---------------------------------------------------------------------------
// Whole-rule evaluation
// ---------------------------------------------------------------------------

export interface YaraEvalResult {
  matched: boolean;
  stringResults: YaraStringResult[];
  matchedIds: string[];
  conditionError: string | null;
}

/** Scan every string, then evaluate the condition over the results. This is
 *  the single entry point the tool's UI calls — there is no code path here
 *  that reports a match without having actually found the bytes. */
export function evaluateYaraRule(rule: YaraRule, data: Uint8Array): YaraEvalResult {
  const stringResults = rule.strings.map((s) => scanYaraString(s, data));
  const { matched, matchedIds, error } = evaluateYaraCondition(rule.condition, stringResults);
  return { matched, stringResults, matchedIds, conditionError: error };
}

// ---------------------------------------------------------------------------
// Sample parsing — pasted text or pasted hex bytes
// ---------------------------------------------------------------------------

export type YaraSampleMode = 'text' | 'hex';

export interface YaraSampleResult {
  bytes: Uint8Array | null;
  error: string | null;
}

/** Turn a pasted sample into the raw bytes that get scanned.
 *  - `text`: UTF-8 encoded, which is what YARA would read from a UTF-8 file.
 *  - `hex`: a run of hex byte pairs, tolerating whitespace, newlines, commas
 *    and per-token `0x` prefixes. A full hex *dump* (offset column + ASCII
 *    gutter) is rejected with a specific message rather than silently
 *    mis-parsed — strip it to bytes first.
 *  Never throws. */
export function parseYaraSample(input: string, mode: YaraSampleMode): YaraSampleResult {
  if (!input.trim()) return { bytes: null, error: 'Paste a sample to scan.' };

  if (mode === 'text') {
    return { bytes: new TextEncoder().encode(input), error: null };
  }

  const tokens = input.split(/[\s,]+/).filter(Boolean).map((t) => (/^0[xX]/.test(t) ? t.slice(2) : t));
  const cleaned = tokens.join('');
  if (!/^[0-9a-fA-F]*$/.test(cleaned)) {
    return { bytes: null, error: 'This doesn’t look like plain hex bytes. Paste hex digits only — an offset column or ASCII gutter from a hex dump has to be stripped first.' };
  }
  if (cleaned.length === 0) return { bytes: null, error: 'Paste a sample to scan.' };
  if (cleaned.length % 2 !== 0) {
    return { bytes: null, error: `Hex input has an odd number of digits (${cleaned.length}) — every byte needs two.` };
  }
  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
  return { bytes, error: null };
}

/** Render a byte range as a printable preview: printable ASCII kept as-is,
 *  everything else shown as a dot — the same convention a hex editor's ASCII
 *  gutter uses. Used to show what a hex-pattern match actually landed on. */
export function previewBytes(data: Uint8Array, offset: number, length: number): string {
  let out = '';
  const end = Math.min(offset + length, data.length);
  for (let i = offset; i < end; i++) {
    const b = data[i];
    out += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.';
  }
  return out;
}

/** Render a byte range as spaced uppercase hex — the companion to
 *  previewBytes for the same match. */
export function hexBytes(data: Uint8Array, offset: number, length: number): string {
  const parts: string[] = [];
  const end = Math.min(offset + length, data.length);
  for (let i = offset; i < end; i++) parts.push(data[i].toString(16).toUpperCase().padStart(2, '0'));
  return parts.join(' ');
}

/** Zero-padded hex offset, the way a hex editor or YARA's own `-s` output
 *  prints a match location. */
export function formatOffset(offset: number): string {
  return '0x' + offset.toString(16).toUpperCase().padStart(4, '0');
}

// ---------------------------------------------------------------------------
// Rule-source generation (builder state -> display)
// ---------------------------------------------------------------------------

/** Render the current builder state as YARA rule source. Incomplete rows
 *  (blank identifier or blank value) are skipped rather than emitted
 *  half-written, and the emitted rule deliberately carries no meta block,
 *  tags or imports (see this file's header for the full scope). */
export function generateYaraRule(rule: YaraRule): string {
  const name = rule.name.trim() || 'Untitled_rule';
  const lines: string[] = [
    '/*',
    ' * Generated from the builder above (read-only preview) — rule name,',
    ' * strings and condition only. Modules, meta, tags and the rest of the',
    ' * YARA language are outside this tool’s scope; this is not a general',
    ' * YARA editor.',
    ' */',
    `rule ${name}`,
    '{',
  ];

  const usable = rule.strings.filter((s) => s.id.trim() && s.value.trim());
  if (usable.length > 0) {
    lines.push('    strings:');
    const pad = Math.max(...usable.map((s) => s.id.trim().length));
    for (const s of usable) {
      const id = ('$' + s.id.trim()).padEnd(pad + 1, ' ');
      if (s.kind === 'hex') {
        lines.push(`        ${id} = { ${s.value.trim().replace(/\s+/g, ' ')} }`);
      } else {
        const mods = YARA_TEXT_MODIFIERS.filter((m) => s.modifiers.includes(m.id)).map((m) => m.id);
        lines.push(`        ${id} = "${s.value}"${mods.length ? ' ' + mods.join(' ') : ''}`);
      }
    }
    lines.push('');
  }

  lines.push('    condition:');
  lines.push(`        ${rule.condition.trim() || '<no condition set>'}`);
  lines.push('}');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Rule-source parsing (import side of generateYaraRule — see file header)
// ---------------------------------------------------------------------------

export interface YaraParseResult {
  rule: YaraRule | null;
  error: string | null;
}

/** Strip line comments and block comments (C-style, both forms) while leaving
 *  the contents of `"…"` string literals untouched — a comment opener inside a
 *  literal is data, not a comment. Removed characters are replaced with
 *  spaces so every remaining character keeps its original index. */
function stripComments(src: string): string {
  let out = '';
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (ch === '"') {
      out += ch;
      i += 1;
      while (i < src.length) {
        out += src[i];
        if (src[i] === '\\' && i + 1 < src.length) {
          out += src[i + 1];
          i += 2;
          continue;
        }
        if (src[i] === '"') {
          i += 1;
          break;
        }
        i += 1;
      }
      continue;
    }
    if (ch === '/' && src[i + 1] === '/') {
      while (i < src.length && src[i] !== '\n') {
        out += ' ';
        i += 1;
      }
      continue;
    }
    if (ch === '/' && src[i + 1] === '*') {
      while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) {
        out += src[i] === '\n' ? '\n' : ' ';
        i += 1;
      }
      out += '  ';
      i += 2;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

/** Blank out the *contents* of every `"…"` literal (quotes kept, each inner
 *  character replaced by a space) so keyword searches — `rule`, `meta:`,
 *  `strings:`, `condition:` — can't be tricked by a literal that happens to
 *  contain one of those words. Length is preserved character-for-character, so
 *  an index found in the masked copy indexes the original identically. */
function maskLiterals(src: string): string {
  let out = '';
  let i = 0;
  while (i < src.length) {
    if (src[i] !== '"') {
      out += src[i];
      i += 1;
      continue;
    }
    out += '"';
    i += 1;
    while (i < src.length && src[i] !== '"') {
      if (src[i] === '\\' && i + 1 < src.length) {
        out += '  ';
        i += 2;
        continue;
      }
      out += src[i] === '\n' ? '\n' : ' ';
      i += 1;
    }
    if (i < src.length) {
      out += '"';
      i += 1;
    }
  }
  return out;
}

/** Index of the `}` that closes the `{` at `open`, skipping over `"…"`
 *  literals so a brace inside a string literal doesn't unbalance the count.
 *  Returns -1 when unbalanced. */
function findClosingBrace(src: string, open: number): number {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    const ch = src[i];
    if (ch === '"') {
      i += 1;
      while (i < src.length && src[i] !== '"') {
        if (src[i] === '\\') i += 1;
        i += 1;
      }
      continue;
    }
    if (ch === '{') depth += 1;
    else if (ch === '}') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

const UNSUPPORTED_STRING_MODIFIERS = ['fullword', 'xor', 'base64wide', 'base64', 'private'];

/** Parse YARA rule source in the subset generateYaraRule() itself produces
 *  (one rule: name + strings + condition) back into a YaraRule. Never throws —
 *  any problem, from a missing section to a construct outside this tool's
 *  scope, comes back as { rule: null, error: <friendly message> }. */
export function parseYaraRule(text: string): YaraParseResult {
  try {
    const src = stripComments(text);
    if (!src.trim()) return { rule: null, error: 'Paste a rule to load.' };
    // Keyword/section searches run against `masked` (same length, literal
    // contents blanked); every slice that produces real content still comes
    // from `src`, so the indices are interchangeable.
    const masked = maskLiterals(src);

    if (/\bimport\s+"/.test(masked)) {
      return { rule: null, error: 'This rule imports a module — modules (pe, math, hash, …) are outside this tool’s scope.' };
    }
    if (/\binclude\s+"/.test(masked)) {
      return { rule: null, error: 'include directives are outside this tool’s scope — paste the single rule you want to test.' };
    }
    if (/\b(global|private)\s+rule\b/.test(masked)) {
      return { rule: null, error: 'global/private rule modifiers are outside this tool’s scope.' };
    }

    const ruleMatches = masked.match(/\brule\s+/g) || [];
    if (ruleMatches.length === 0) return { rule: null, error: 'Missing a "rule <name>" declaration.' };
    if (ruleMatches.length > 1) return { rule: null, error: 'This source contains more than one rule — this tool tests a single rule at a time.' };

    const header = /\brule\s+([^\s{:]+)\s*([:{])/.exec(masked);
    if (!header) return { rule: null, error: 'Couldn’t read the rule name — expected "rule <name> {".' };
    const name = header[1];
    if (header[2] === ':') {
      return { rule: null, error: 'Rule tags (rule Name : tag) are outside this tool’s scope — metadata beyond the rule name isn’t supported.' };
    }
    if (!ID_RE.test(name)) {
      return { rule: null, error: `"${name}" isn’t a valid rule name — YARA identifiers are letters, digits and underscores, may not start with a digit, and are at most 128 characters.` };
    }

    const open = src.indexOf('{', header.index);
    const close = findClosingBrace(src, open);
    if (close === -1) return { rule: null, error: 'The rule body isn’t closed — check the braces.' };
    const body = src.slice(open + 1, close);
    const maskedBody = masked.slice(open + 1, close);

    if (/(^|\s)meta\s*:/.test(maskedBody)) {
      return { rule: null, error: 'A meta: block is outside this tool’s scope — the rule name is the only metadata supported.' };
    }

    const condIdx = maskedBody.search(/(^|\s)condition\s*:/);
    if (condIdx === -1) return { rule: null, error: 'Missing a "condition:" section.' };
    const condStart = maskedBody.indexOf(':', condIdx) + 1;
    const condition = body.slice(condStart).trim();

    const strIdx = maskedBody.search(/(^|\s)strings\s*:/);
    const strings: YaraString[] = [];
    if (strIdx !== -1) {
      if (strIdx > condIdx) {
        return { rule: null, error: 'The strings: section has to come before condition: for this tool to read it.' };
      }
      const strBody = body.slice(maskedBody.indexOf(':', strIdx) + 1, condIdx);
      const parsed = parseStringsSection(strBody);
      if (parsed.error) return { rule: null, error: parsed.error };
      strings.push(...parsed.strings);
    }

    if (strings.length === 0) {
      return { rule: null, error: 'No strings found — this tool needs at least one text or hex string to test.' };
    }
    const seen: Record<string, boolean> = {};
    for (const s of strings) {
      if (seen[s.id]) return { rule: null, error: `Duplicate string identifier "$${s.id}".` };
      seen[s.id] = true;
    }

    const { error: condError } = parseYaraCondition(condition);
    if (condError) return { rule: null, error: condError };

    return { rule: { name, strings, condition }, error: null };
  } catch {
    return { rule: null, error: 'Couldn’t parse this rule — check that it matches the format this tool generates.' };
  }
}

/** Character-scanning parser for the body of a `strings:` section. Split out
 *  of parseYaraRule purely for readability; same never-throw contract. */
function parseStringsSection(body: string): { strings: YaraString[]; error: string | null } {
  const strings: YaraString[] = [];
  let i = 0;

  const skipSpace = (): void => {
    while (i < body.length && /\s/.test(body[i])) i += 1;
  };

  while (true) {
    skipSpace();
    if (i >= body.length) break;

    if (body[i] !== '$') {
      const stray = body.slice(i).split(/\s/)[0];
      return { strings: [], error: `Unrecognized text in the strings section: "${stray}" — every entry has to start with a $identifier.` };
    }
    i += 1;
    const idStart = i;
    while (i < body.length && /[A-Za-z0-9_]/.test(body[i])) i += 1;
    const id = body.slice(idStart, i);
    if (!id) {
      return { strings: [], error: 'The anonymous "$" string identifier is outside this tool’s scope — give every string its own name.' };
    }
    if (!ID_RE.test(id)) {
      return { strings: [], error: `"$${id}" isn’t a valid string identifier — use letters, digits and underscores, not starting with a digit.` };
    }

    skipSpace();
    if (body[i] !== '=') return { strings: [], error: `Expected "=" after "$${id}".` };
    i += 1;
    skipSpace();

    const opener = body[i];
    if (opener === '/') {
      return { strings: [], error: `"$${id}" is a regular-expression string — regex strings are outside this tool’s scope (text and hex only).` };
    }

    if (opener === '{') {
      const end = body.indexOf('}', i);
      if (end === -1) return { strings: [], error: `The hex string "$${id}" isn’t closed — expected a "}".` };
      const value = body.slice(i + 1, end).trim();
      const compiled = compileHexPattern(value);
      if (compiled.error) return { strings: [], error: `$${id}: ${compiled.error}` };
      strings.push({ kind: 'hex', id, value: value.replace(/\s+/g, ' ') });
      i = end + 1;
      continue;
    }

    if (opener !== '"') {
      return { strings: [], error: `Expected a "text string" or { hex string } after "$${id} =".` };
    }

    i += 1;
    const valStart = i;
    let closed = false;
    while (i < body.length) {
      if (body[i] === '\\') {
        i += 2;
        continue;
      }
      if (body[i] === '"') {
        closed = true;
        break;
      }
      i += 1;
    }
    if (!closed) return { strings: [], error: `The text string "$${id}" isn’t closed — expected a closing quote.` };
    const value = body.slice(valStart, i);
    i += 1;

    const decoded = decodeTextLiteral(value);
    if (decoded.error) return { strings: [], error: `$${id}: ${decoded.error}` };

    // Modifiers run to the next `$` entry or the end of the section.
    const nextDollar = body.indexOf('$', i);
    const modEnd = nextDollar === -1 ? body.length : nextDollar;
    const modTokens = body.slice(i, modEnd).trim().split(/\s+/).filter(Boolean);
    i = modEnd;

    const modifiers: YaraTextModifier[] = [];
    for (const token of modTokens) {
      const bare = token.replace(/\(.*$/, '');
      if (UNSUPPORTED_STRING_MODIFIERS.includes(bare)) {
        return { strings: [], error: `The "${bare}" modifier on $${id} is outside this tool’s scope — only ascii, wide and nocase are supported.` };
      }
      if (bare === 'ascii' || bare === 'wide' || bare === 'nocase') {
        if (!modifiers.includes(bare)) modifiers.push(bare);
        continue;
      }
      return { strings: [], error: `Unrecognized modifier "${token}" on $${id} — this tool supports ascii, wide and nocase.` };
    }
    strings.push({ kind: 'text', id, value, modifiers });
  }

  return { strings, error: null };
}

// ---------------------------------------------------------------------------
// Starter example content — CLEARLY FABRICATED for illustration. This is not a
// real detection rule and the sample is not captured telemetry from any real
// investigation (see CLAUDE.md "Content accuracy"). The API names are genuine
// Windows APIs and the hex bytes are genuine ASCII codes; the pairing of them
// into a "rule" here exists only to demonstrate the tool.
// ---------------------------------------------------------------------------

export const STARTER_YARA_RULE: YaraRule = {
  name: 'Fabricated_Injection_Strings_Example',
  strings: [
    { kind: 'text', id: 'api1', value: 'CreateRemoteThread', modifiers: ['ascii', 'wide'] },
    { kind: 'text', id: 'api2', value: 'virtualallocex', modifiers: ['nocase'] },
    // "KERNEL" ?? ?? ".dll" — the two wildcard bytes stand in for the version
    // digits, so this matches KERNEL32.dll without hardcoding the "32".
    { kind: 'hex', id: 'dll', value: '4B 45 52 4E 45 4C ?? ?? 2E 64 6C 6C' },
  ],
  condition: 'all of them',
};

/** A fabricated `strings`-style dump — the sort of output a triage tool prints
 *  for a Windows binary — used as the default sample so every starter string
 *  has something real to match against. */
export const STARTER_YARA_SAMPLE = [
  '.text',
  '.rdata',
  'KERNEL32.dll',
  'VirtualAllocEx',
  'CreateRemoteThread',
  'WriteProcessMemory',
].join('\n');
