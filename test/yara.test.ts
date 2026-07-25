import { describe, it, expect } from 'vitest';
import {
  decodeTextLiteral,
  compileHexPattern,
  compileYaraString,
  scanYaraString,
  findMatchOffsets,
  parseYaraCondition,
  evaluateYaraCondition,
  buildYaraCondition,
  evaluateYaraRule,
  parseYaraSample,
  previewBytes,
  hexBytes,
  formatOffset,
  generateYaraRule,
  parseYaraRule,
  YARA_TEXT_MODIFIERS,
  YARA_CONDITION_UI_TYPES,
  UNSUPPORTED_YARA_FEATURES,
  STARTER_YARA_RULE,
  STARTER_YARA_SAMPLE,
  type YaraRule,
  type YaraString,
  type YaraStringResult,
} from '../src/utils/yara';

const bytes = (s: string): Uint8Array => new TextEncoder().encode(s);
const hex = (s: string): Uint8Array => {
  const { bytes: b, error } = parseYaraSample(s, 'hex');
  if (!b) throw new Error(error || 'bad hex fixture');
  return b;
};

const text = (id: string, value: string, modifiers: ('ascii' | 'wide' | 'nocase')[] = []): YaraString => ({
  kind: 'text',
  id,
  value,
  modifiers,
});
const hexStr = (id: string, value: string): YaraString => ({ kind: 'hex', id, value });

// ---------------------------------------------------------------------------
// Text-literal decoding
// ---------------------------------------------------------------------------

describe('decodeTextLiteral — escape handling', () => {
  it('decodes plain ASCII to its byte values', () => {
    expect(decodeTextLiteral('MZ').bytes).toEqual([0x4d, 0x5a]);
  });

  it('decodes the supported escape sequences', () => {
    expect(decodeTextLiteral('a\\nb').bytes).toEqual([0x61, 0x0a, 0x62]);
    expect(decodeTextLiteral('a\\rb').bytes).toEqual([0x61, 0x0d, 0x62]);
    expect(decodeTextLiteral('a\\tb').bytes).toEqual([0x61, 0x09, 0x62]);
    expect(decodeTextLiteral('a\\\\b').bytes).toEqual([0x61, 0x5c, 0x62]);
    expect(decodeTextLiteral('a\\"b').bytes).toEqual([0x61, 0x22, 0x62]);
    expect(decodeTextLiteral('\\x41\\x42').bytes).toEqual([0x41, 0x42]);
  });

  it('rejects an unsupported escape by name instead of guessing at a byte', () => {
    const r = decodeTextLiteral('a\\qb');
    expect(r.bytes).toBeNull();
    expect(r.error).toContain('\\q');
  });

  it('rejects a malformed \\xHH escape', () => {
    expect(decodeTextLiteral('\\xZZ').bytes).toBeNull();
    expect(decodeTextLiteral('\\x4').bytes).toBeNull();
  });

  it('rejects an unescaped quote and a trailing lone backslash', () => {
    expect(decodeTextLiteral('a"b').error).toContain('\\"');
    expect(decodeTextLiteral('ab\\').error).toContain('backslash');
  });

  it('rejects an empty string', () => {
    expect(decodeTextLiteral('').error).toBe('A text string can’t be empty.');
  });

  it('UTF-8 encodes a non-ASCII character and flags it', () => {
    const r = decodeTextLiteral('é');
    expect(r.bytes).toEqual([0xc3, 0xa9]);
    expect(r.hasNonAscii).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Hex patterns
// ---------------------------------------------------------------------------

describe('compileHexPattern — bytes and nibble wildcards', () => {
  it('compiles exact bytes with a full mask', () => {
    expect(compileHexPattern('4D 5A').matchers).toEqual([
      { value: 0x4d, mask: 0xff },
      { value: 0x5a, mask: 0xff },
    ]);
  });

  it('compiles ?? as a fully-unknown byte', () => {
    expect(compileHexPattern('E8 ??').matchers).toEqual([
      { value: 0xe8, mask: 0xff },
      { value: 0x00, mask: 0x00 },
    ]);
  });

  it('compiles the nibble-wise half-byte forms A? and ?A', () => {
    expect(compileHexPattern('A? ?A').matchers).toEqual([
      { value: 0xa0, mask: 0xf0 },
      { value: 0x0a, mask: 0x0f },
    ]);
  });

  it('tolerates arbitrary whitespace between bytes', () => {
    expect(compileHexPattern('  4D\n  5A  ').matchers).toHaveLength(2);
  });

  it('names the out-of-scope hex constructs rather than ignoring them', () => {
    expect(compileHexPattern('8D [2-3] 6A').error).toContain('jumps');
    expect(compileHexPattern('F4 ( 62 | 56 )').error).toContain('alternatives');
    expect(compileHexPattern('~00 4D').error).toContain('not-operator');
  });

  it('rejects a malformed byte token and an empty pattern', () => {
    expect(compileHexPattern('4D 5').error).toContain('"5"');
    expect(compileHexPattern('ZZ').error).toContain('"ZZ"');
    expect(compileHexPattern('   ').error).toBe('A hex string can’t be empty.');
  });
});

describe('findMatchOffsets — real byte scanning', () => {
  it('finds every occurrence, including overlapping ones', () => {
    const data = bytes('aaaa');
    const pattern = compileHexPattern('61 61').matchers!;
    expect(findMatchOffsets(data, pattern)).toEqual([0, 1, 2]);
  });

  it('returns nothing when the pattern is longer than the data', () => {
    expect(findMatchOffsets(bytes('ab'), compileHexPattern('61 62 63').matchers!)).toEqual([]);
  });

  it('honors a ?? wildcard in the middle of a pattern', () => {
    const data = hex('E8 11 22 33 44 90');
    expect(findMatchOffsets(data, compileHexPattern('E8 ?? ?? ?? ??').matchers!)).toEqual([0]);
    expect(findMatchOffsets(data, compileHexPattern('E8 ?? ?? ?? ?? 91').matchers!)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Text-string modifiers (ascii / wide / nocase)
// ---------------------------------------------------------------------------

describe('compileYaraString + scanYaraString — ascii/wide/nocase semantics', () => {
  it('defaults to the single-byte ascii form when no modifier is given', () => {
    const compiled = compileYaraString(text('a', 'MZ'));
    expect(compiled.forms.map((f) => f.form)).toEqual(['ascii']);
    expect(scanYaraString(text('a', 'MZ'), bytes('__MZ__')).matched).toBe(true);
  });

  it('the redundant ascii modifier behaves identically to no modifier', () => {
    expect(compileYaraString(text('a', 'MZ', ['ascii'])).forms.map((f) => f.form)).toEqual(['ascii']);
  });

  it('wide alone searches only the zero-interleaved form', () => {
    const s = text('a', 'MZ', ['wide']);
    expect(compileYaraString(s).forms.map((f) => f.form)).toEqual(['wide']);
    expect(scanYaraString(s, hex('4D 00 5A 00')).matched).toBe(true);
    // MUST NOT match: the plain single-byte form is not the wide form.
    expect(scanYaraString(s, bytes('MZ')).matched).toBe(false);
  });

  it('ascii + wide searches for both forms and reports which one hit', () => {
    const s = text('a', 'MZ', ['ascii', 'wide']);
    expect(compileYaraString(s).forms.map((f) => f.form)).toEqual(['ascii', 'wide']);
    expect(scanYaraString(s, bytes('MZ')).matches[0].form).toBe('ascii');
    expect(scanYaraString(s, hex('4D 00 5A 00')).matches[0].form).toBe('wide');
  });

  it('nocase folds the ASCII letter range only', () => {
    const s = text('a', 'mz', ['nocase']);
    expect(scanYaraString(s, bytes('MZ')).matched).toBe(true);
    expect(scanYaraString(s, bytes('mZ')).matched).toBe(true);
    // MUST NOT match: nocase must not blur non-letter bytes that happen to
    // differ by the same 0x20 bit — '[' (0x5B) vs '{' (0x7B).
    expect(scanYaraString(text('b', '[', ['nocase']), bytes('{')).matched).toBe(false);
  });

  it('nocase combines with wide (letters folded, the 0x00 fillers exact)', () => {
    const s = text('a', 'mz', ['nocase', 'wide']);
    expect(scanYaraString(s, hex('4D 00 5A 00')).matched).toBe(true);
    expect(scanYaraString(s, hex('4D 01 5A 00')).matched).toBe(false);
  });

  it('refuses to guess at wide for a non-ASCII literal', () => {
    expect(compileYaraString(text('a', 'é', ['wide'])).error).toContain('wide modifier');
  });

  it('rejects an invalid string identifier', () => {
    expect(compileYaraString(text('1bad', 'MZ')).error).toContain('identifier');
  });

  it('reports match offsets and caps the reported list while still counting all', () => {
    const r = scanYaraString(text('a', 'a'), bytes('a'.repeat(40)));
    expect(r.totalMatches).toBe(40);
    expect(r.matches).toHaveLength(20);
    expect(r.matches[0].offset).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Conditions
// ---------------------------------------------------------------------------

describe('parseYaraCondition — supported grammar', () => {
  it('parses the of-them forms', () => {
    expect(parseYaraCondition('any of them').parsed).toEqual({ type: 'them', op: 'any' });
    expect(parseYaraCondition('all of them').parsed).toEqual({ type: 'them', op: 'all' });
    expect(parseYaraCondition('2 of them').parsed).toEqual({ type: 'them-n', n: 2 });
  });

  it('parses and/or identifier lists, and a single identifier', () => {
    expect(parseYaraCondition('$a and $b').parsed).toEqual({ type: 'list', op: 'and', ids: ['a', 'b'] });
    expect(parseYaraCondition('$a or $b or $c').parsed).toEqual({ type: 'list', op: 'or', ids: ['a', 'b', 'c'] });
    expect(parseYaraCondition('$a').parsed).toEqual({ type: 'list', op: 'and', ids: ['a'] });
  });

  it('refuses to guess at precedence when and/or are mixed', () => {
    expect(parseYaraCondition('$a and $b or $c').error).toContain('Mixing');
  });

  it('calls out wrong-case keywords instead of silently accepting them', () => {
    const r = parseYaraCondition('ALL of them');
    expect(r.parsed).toBeNull();
    expect(r.error).toContain('lowercase');
  });

  it('names each out-of-scope condition construct', () => {
    expect(parseYaraCondition('none of them').error).toContain('none of them');
    expect(parseYaraCondition('any of ($a, $b)').error).toContain('string sets');
    expect(parseYaraCondition('#a > 3').error).toContain('count/offset/length');
    expect(parseYaraCondition('$a at 0').error).toContain('Offset expressions');
    expect(parseYaraCondition('not $a').error).toContain('"not"');
    expect(parseYaraCondition('filesize < 100').error).toContain('filesize');
    expect(parseYaraCondition('pe.entry_point == 0').error).toContain('Module expressions');
    expect(parseYaraCondition('for any i in (0..10) : ( true )').error).toContain('for..of');
    expect(parseYaraCondition('0 of them').error).toContain('none of them');
    expect(parseYaraCondition('').error).toBe('The condition is empty.');
  });

  it('does not mistake an identifier that merely contains a keyword for the keyword', () => {
    expect(parseYaraCondition('$not_signed and $format').parsed).toEqual({ type: 'list', op: 'and', ids: ['not_signed', 'format'] });
  });
});

describe('evaluateYaraCondition — each supported form against real results', () => {
  const results = (map: Record<string, boolean>): YaraStringResult[] =>
    Object.entries(map).map(([id, matched]) => ({ id, matched, matches: [], totalMatches: matched ? 1 : 0, error: null }));

  it('any of them', () => {
    expect(evaluateYaraCondition('any of them', results({ a: false, b: true })).matched).toBe(true);
    expect(evaluateYaraCondition('any of them', results({ a: false, b: false })).matched).toBe(false);
  });

  it('all of them', () => {
    expect(evaluateYaraCondition('all of them', results({ a: true, b: true })).matched).toBe(true);
    expect(evaluateYaraCondition('all of them', results({ a: true, b: false })).matched).toBe(false);
  });

  it('N of them', () => {
    expect(evaluateYaraCondition('2 of them', results({ a: true, b: true, c: false })).matched).toBe(true);
    expect(evaluateYaraCondition('3 of them', results({ a: true, b: true, c: false })).matched).toBe(false);
  });

  it('N of them errors when N exceeds the string count (YARA requires N <= set size)', () => {
    const r = evaluateYaraCondition('5 of them', results({ a: true, b: true }));
    expect(r.matched).toBe(false);
    expect(r.error).toContain('more strings than the rule has');
  });

  it('$a and $b / $a or $b', () => {
    expect(evaluateYaraCondition('$a and $b', results({ a: true, b: true, c: false })).matched).toBe(true);
    expect(evaluateYaraCondition('$a and $b', results({ a: true, b: false })).matched).toBe(false);
    expect(evaluateYaraCondition('$a or $b', results({ a: false, b: true })).matched).toBe(true);
    expect(evaluateYaraCondition('$a or $b', results({ a: false, b: false })).matched).toBe(false);
  });

  it('reports only the identifiers that actually contributed', () => {
    expect(evaluateYaraCondition('any of them', results({ a: false, b: true, c: true })).matchedIds).toEqual(['b', 'c']);
    expect(evaluateYaraCondition('any of them', results({ a: false })).matchedIds).toEqual([]);
  });

  it('errors on an unknown identifier and on an empty string set', () => {
    expect(evaluateYaraCondition('$a and $zzz', results({ a: true })).error).toContain('$zzz');
    expect(evaluateYaraCondition('any of them', []).error).toBe('There are no strings to evaluate.');
  });
});

describe('buildYaraCondition — guided builder produces parseable conditions', () => {
  it('emits the canonical form for every UI type', () => {
    expect(buildYaraCondition('any-of-them')).toBe('any of them');
    expect(buildYaraCondition('all-of-them')).toBe('all of them');
    expect(buildYaraCondition('n-of-them', { n: 3 })).toBe('3 of them');
    expect(buildYaraCondition('list-and', { ids: ['a', 'b'] })).toBe('$a and $b');
    expect(buildYaraCondition('list-or', { ids: ['a', 'b'] })).toBe('$a or $b');
  });

  it('clamps a nonsensical N rather than emitting an unparseable condition', () => {
    expect(buildYaraCondition('n-of-them', { n: 0 })).toBe('1 of them');
    expect(buildYaraCondition('n-of-them', { n: 2.7 })).toBe('2 of them');
  });

  it('every declared UI type round-trips through the parser', () => {
    for (const t of YARA_CONDITION_UI_TYPES) {
      const built = buildYaraCondition(t.id, { n: 2, ids: ['a', 'b'] });
      expect(parseYaraCondition(built).error, `${t.id} -> "${built}"`).toBeNull();
    }
  });
});

// ---------------------------------------------------------------------------
// Sample parsing + formatting helpers
// ---------------------------------------------------------------------------

describe('parseYaraSample', () => {
  it('UTF-8 encodes a text sample', () => {
    expect(Array.from(parseYaraSample('MZ', 'text').bytes!)).toEqual([0x4d, 0x5a]);
  });

  it('parses hex with whitespace, newlines, commas and 0x prefixes', () => {
    expect(Array.from(parseYaraSample('4D 5A\n0x90, FF', 'hex').bytes!)).toEqual([0x4d, 0x5a, 0x90, 0xff]);
  });

  it('rejects non-hex input and an odd digit count rather than silently truncating', () => {
    expect(parseYaraSample('00000000  4d 5a  |MZ|', 'hex').error).toContain('plain hex bytes');
    expect(parseYaraSample('4D 5', 'hex').error).toContain('odd number of digits');
    expect(parseYaraSample('   ', 'hex').error).toBe('Paste a sample to scan.');
  });
});

describe('offset/preview formatting', () => {
  const data = hex('4D 5A 00 41');
  it('formats a hex byte run and a printable preview', () => {
    expect(hexBytes(data, 0, 4)).toBe('4D 5A 00 41');
    expect(previewBytes(data, 0, 4)).toBe('MZ.A');
  });
  it('clamps a read that runs past the end of the sample', () => {
    expect(hexBytes(data, 2, 99)).toBe('00 41');
  });
  it('formats offsets the way a hex editor prints them', () => {
    expect(formatOffset(0)).toBe('0x0000');
    expect(formatOffset(13)).toBe('0x000D');
    expect(formatOffset(255)).toBe('0x00FF');
  });
});

// ---------------------------------------------------------------------------
// Whole-rule evaluation
// ---------------------------------------------------------------------------

describe('evaluateYaraRule — end-to-end', () => {
  const rule: YaraRule = {
    name: 'Mixed_Kinds',
    strings: [text('t', 'MZ'), hexStr('h', '90 ?? 90')],
    condition: 'all of them',
  };

  it('matches only when every string is genuinely present', () => {
    expect(evaluateYaraRule(rule, hex('4D 5A 90 CC 90')).matched).toBe(true);
    // MUST NOT match: the hex pattern is absent.
    const miss = evaluateYaraRule(rule, hex('4D 5A 90 CC'));
    expect(miss.matched).toBe(false);
    expect(miss.stringResults.find((r) => r.id === 'h')!.matched).toBe(false);
  });

  it('surfaces a per-string compile error without claiming a match', () => {
    const bad: YaraRule = { name: 'Bad', strings: [hexStr('h', 'GG')], condition: 'any of them' };
    const r = evaluateYaraRule(bad, hex('4D 5A'));
    expect(r.matched).toBe(false);
    expect(r.stringResults[0].error).toContain('"GG"');
  });

  it('surfaces a condition error without claiming a match', () => {
    const r = evaluateYaraRule({ ...rule, condition: 'pe.is_dll' }, hex('4D 5A 90 CC 90'));
    expect(r.matched).toBe(false);
    expect(r.conditionError).toContain('Module expressions');
  });
});

// ---------------------------------------------------------------------------
// The starter rule + the worked example printed on the tool page
// ---------------------------------------------------------------------------

describe('starter rule — the worked example the page prints', () => {
  const data = parseYaraSample(STARTER_YARA_SAMPLE, 'text').bytes!;
  const result = evaluateYaraRule(STARTER_YARA_RULE, data);

  it('every starter string genuinely matches the starter sample', () => {
    expect(result.stringResults.map((r) => [r.id, r.matched])).toEqual([
      ['api1', true],
      ['api2', true],
      ['dll', true],
    ]);
    expect(result.stringResults.every((r) => r.error === null)).toBe(true);
  });

  it('"all of them" therefore evaluates true', () => {
    expect(result.matched).toBe(true);
    expect(result.matchedIds).toEqual(['api1', 'api2', 'dll']);
  });

  // These three offsets are quoted verbatim in the tool page's worked-example
  // table, so a change to the starter content fails here first.
  it('matches land at the offsets the page quotes', () => {
    const at = (id: string) => result.stringResults.find((r) => r.id === id)!.matches[0];
    expect(formatOffset(at('api1').offset)).toBe('0x0029');
    expect(at('api1').form).toBe('ascii');
    expect(formatOffset(at('api2').offset)).toBe('0x001A');
    expect(formatOffset(at('dll').offset)).toBe('0x000D');
    expect(at('dll').form).toBe('hex');
  });

  it('the hex wildcard is what makes $dll match KERNEL32.dll', () => {
    const at = result.stringResults.find((r) => r.id === 'dll')!.matches[0];
    expect(previewBytes(data, at.offset, at.length)).toBe('KERNEL32.dll');
    // MUST NOT match: without the wildcards the literal bytes are "KERNEL..dll".
    expect(scanYaraString(hexStr('x', '4B 45 52 4E 45 4C 2E 64 6C 6C'), data).matched).toBe(false);
  });

  it('$api2 only matches because of nocase (the sample spells it VirtualAllocEx)', () => {
    expect(scanYaraString(text('x', 'virtualallocex'), data).matched).toBe(false);
    expect(scanYaraString(text('x', 'virtualallocex', ['nocase']), data).matched).toBe(true);
  });

  it('$api1 matches its ascii form only — the sample holds no UTF-16LE copy', () => {
    expect(scanYaraString(text('x', 'CreateRemoteThread', ['wide']), data).matched).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Rule-source generation + parsing
// ---------------------------------------------------------------------------

describe('generateYaraRule', () => {
  const src = generateYaraRule(STARTER_YARA_RULE);

  it('emits the starter rule exactly as the page shows it', () => {
    expect(src).toContain('rule Fabricated_Injection_Strings_Example');
    expect(src).toContain('        $api1 = "CreateRemoteThread" ascii wide');
    expect(src).toContain('        $api2 = "virtualallocex" nocase');
    expect(src).toContain('        $dll  = { 4B 45 52 4E 45 4C ?? ?? 2E 64 6C 6C }');
    expect(src).toContain('    condition:\n        all of them');
  });

  it('skips half-written rows instead of emitting them', () => {
    const out = generateYaraRule({ name: 'R', strings: [text('a', 'MZ'), text('', ''), hexStr('b', '')], condition: 'any of them' });
    expect(out).toContain('$a = "MZ"');
    expect(out).not.toContain('$b');
  });

  it('falls back to visible placeholders rather than emitting nothing', () => {
    const out = generateYaraRule({ name: '', strings: [], condition: '' });
    expect(out).toContain('rule Untitled_rule');
    expect(out).toContain('<no condition set>');
  });
});

describe('parseYaraRule — round-trip with generateYaraRule', () => {
  it('round-trips the starter rule byte-for-byte through generate -> parse', () => {
    const { rule, error } = parseYaraRule(generateYaraRule(STARTER_YARA_RULE));
    expect(error).toBeNull();
    expect(rule).toEqual(STARTER_YARA_RULE);
  });

  it('accepts hand-written source with comments and odd spacing', () => {
    const { rule, error } = parseYaraRule(`
      // a leading line comment
      rule Hand_Written /* inline */ {
        strings:
          $a = "abc" nocase
          $h={ AA ?? BB }
        condition:
          $a or $h
      }
    `);
    expect(error).toBeNull();
    expect(rule).toEqual({
      name: 'Hand_Written',
      strings: [text('a', 'abc', ['nocase']), hexStr('h', 'AA ?? BB')],
      condition: '$a or $h',
    });
  });

  it('is not fooled by section keywords appearing inside a string literal', () => {
    const { rule, error } = parseYaraRule('rule R { strings: $a = "condition: meta: rule X" condition: $a }');
    expect(error).toBeNull();
    expect(rule!.strings[0].value).toBe('condition: meta: rule X');
    expect(rule!.condition).toBe('$a');
  });

  it('names every out-of-scope construct rather than failing generically', () => {
    const err = (src: string) => parseYaraRule(src).error || '';
    expect(err('import "pe"\nrule R { strings: $a = "x" condition: $a }')).toContain('modules');
    expect(err('global rule R { strings: $a = "x" condition: $a }')).toContain('global/private');
    expect(err('rule R : apt { strings: $a = "x" condition: $a }')).toContain('Rule tags');
    expect(err('rule R { meta: author = "me" strings: $a = "x" condition: $a }')).toContain('meta:');
    expect(err('rule R { strings: $re = /ab+c/ condition: $re }')).toContain('regular-expression');
    expect(err('rule R { strings: $a = "x" fullword condition: $a }')).toContain('fullword');
    expect(err('rule R { strings: $a = "x" xor condition: $a }')).toContain('xor');
    expect(err('rule R { strings: $h = { 8D [2-3] 6A } condition: $h }')).toContain('jumps');
    expect(err('rule A { strings: $a = "x" condition: $a }\nrule B { strings: $b = "y" condition: $b }')).toContain('more than one rule');
  });

  it('reports structural problems specifically', () => {
    const err = (src: string) => parseYaraRule(src).error || '';
    expect(err('')).toBe('Paste a rule to load.');
    expect(err('strings: $a = "x"')).toContain('rule <name>');
    expect(err('rule 9bad { strings: $a = "x" condition: $a }')).toContain('valid rule name');
    expect(err('rule R { strings: $a = "x" }')).toContain('condition:');
    expect(err('rule R { condition: any of them }')).toContain('at least one');
    expect(err('rule R { strings: $a = "x" $a = "y" condition: $a }')).toContain('Duplicate');
    expect(err('rule R { strings: $a = "x" $b = { AA condition: $a }')).toContain('isn’t closed');
  });

  it('loads a rule whose condition names a missing string, leaving it for the live evaluator to report', () => {
    // Deliberate: parseYaraRule validates condition *syntax* only, so a rule
    // with a typo'd identifier still loads into the builder where it can be
    // fixed — the unknown name surfaces as a live evaluation error instead.
    const { rule, error } = parseYaraRule('rule R { strings: $a = "x" condition: $a and $b }');
    expect(error).toBeNull();
    expect(evaluateYaraRule(rule!, bytes('x')).conditionError).toContain('$b');
  });

  it('an unterminated quote is caught (the literal swallows the closing brace)', () => {
    // The quote runs to end-of-input, so the brace matcher never sees the
    // rule's closing "}" — an accurate report of a genuinely malformed rule,
    // not a silent partial parse.
    const r = parseYaraRule('rule R { strings: $a = "unterminated condition: $a }');
    expect(r.rule).toBeNull();
    expect(r.error).toContain('isn’t closed');
  });

  it('rejects a rule whose braces never close', () => {
    expect(parseYaraRule('rule R { strings: $a = "x" condition: $a').error).toContain('isn’t closed');
  });
});

// ---------------------------------------------------------------------------
// Declarative tables the page renders from
// ---------------------------------------------------------------------------

describe('page-facing constant tables', () => {
  it('exposes exactly the three supported text modifiers, in emission order', () => {
    expect(YARA_TEXT_MODIFIERS.map((m) => m.id)).toEqual(['ascii', 'wide', 'nocase']);
    expect(YARA_TEXT_MODIFIERS.every((m) => m.hint.length > 20)).toBe(true);
  });

  it('exposes the five supported condition forms with non-empty copy', () => {
    expect(YARA_CONDITION_UI_TYPES).toHaveLength(5);
    expect(YARA_CONDITION_UI_TYPES.every((t) => t.label && t.syntax && t.hint)).toBe(true);
  });

  it('documents the scope cuts the parser actually enforces', () => {
    expect(UNSUPPORTED_YARA_FEATURES.length).toBeGreaterThanOrEqual(8);
    expect(UNSUPPORTED_YARA_FEATURES.every((f) => f.feature && f.example && f.note)).toBe(true);
  });
});
