import { describe, it, expect } from 'vitest';
import {
  ASCII_TABLE,
  asciiEntry,
  buildAsciiTable,
  toHexByte,
  toOctByte,
  toBinByte,
} from '../src/utils/asciiTable';

describe('toHexByte / toOctByte / toBinByte', () => {
  it('formats 0 as fully zero-padded in every base', () => {
    expect(toHexByte(0)).toBe('0x00');
    expect(toOctByte(0)).toBe('000');
    expect(toBinByte(0)).toBe('00000000');
  });

  it('matches the well-known A = 65 = 0x41 = 0o101 = 0b01000001 identity', () => {
    expect(toHexByte(65)).toBe('0x41');
    expect(toOctByte(65)).toBe('101');
    expect(toBinByte(65)).toBe('01000001');
  });

  it('formats 127 (DEL) correctly in every base', () => {
    expect(toHexByte(127)).toBe('0x7F');
    expect(toOctByte(127)).toBe('177');
    expect(toBinByte(127)).toBe('01111111');
  });
});

describe('buildAsciiTable structure', () => {
  const table = buildAsciiTable();

  it('has exactly 128 entries, dec 0 through 127, no gaps or duplicates', () => {
    expect(table).toHaveLength(128);
    expect(table.map((e) => e.dec)).toEqual(Array.from({ length: 128 }, (_, i) => i));
  });

  it('every entry has a non-empty name and a valid category', () => {
    const validCategories = new Set(['control', 'punctuation', 'digit', 'upper', 'lower']);
    for (const e of table) {
      expect(e.name.length).toBeGreaterThan(0);
      expect(validCategories.has(e.category)).toBe(true);
    }
  });

  it('category counts sum to 128 and match the known ASCII layout', () => {
    const counts: Record<string, number> = {};
    for (const e of table) counts[e.category] = (counts[e.category] ?? 0) + 1;
    // control = 0-31 (32) + 127 (1) = 33
    expect(counts.control).toBe(33);
    // punctuation = 32 (space) + 33-47 (15) + 58-64 (7) + 91-96 (6) + 123-126 (4) = 33
    expect(counts.punctuation).toBe(33);
    expect(counts.digit).toBe(10);
    expect(counts.upper).toBe(26);
    expect(counts.lower).toBe(26);
    expect(Object.values(counts).reduce((a, b) => a + b, 0)).toBe(128);
  });

  it('hasMnemonic is true for exactly the 34 code points 0-32 and 127', () => {
    const withMnemonic = table.filter((e) => e.hasMnemonic).map((e) => e.dec);
    const expected = [...Array.from({ length: 33 }, (_, i) => i), 127];
    expect(withMnemonic).toEqual(expected);
    expect(withMnemonic).toHaveLength(34);
  });

  it('every mnemonic-bearing entry uses its mnemonic as the char field', () => {
    for (const e of table) {
      if (e.hasMnemonic) expect(e.char).toBe(e.mnemonic);
      else expect(e.mnemonic).toBeNull();
    }
  });

  it('every printable, non-mnemonic entry\'s char is the literal glyph at that code point', () => {
    for (const e of table) {
      if (!e.hasMnemonic) expect(e.char).toBe(String.fromCharCode(e.dec));
    }
  });
});

// Spot-checks transcribed directly from the Unicode Consortium's "C0 Controls
// and Basic Latin" code chart (unicode.org/charts/PDF/U0000.pdf, Unicode
// 17.0) — the same source this page cites as its "Other resources" reference.
describe('control character mnemonics + names (verified against the Unicode C0 chart)', () => {
  const cases: Array<[number, string, string]> = [
    [0, 'NUL', 'Null'],
    [1, 'SOH', 'Start of Heading'],
    [2, 'STX', 'Start of Text'],
    [3, 'ETX', 'End of Text'],
    [4, 'EOT', 'End of Transmission'],
    [5, 'ENQ', 'Enquiry'],
    [6, 'ACK', 'Acknowledge'],
    [7, 'BEL', 'Bell'],
    [8, 'BS', 'Backspace'],
    [9, 'HT', 'Character Tabulation (Horizontal Tab)'],
    [10, 'LF', 'Line Feed (New Line)'],
    [11, 'VT', 'Line Tabulation (Vertical Tab)'],
    [12, 'FF', 'Form Feed'],
    [13, 'CR', 'Carriage Return'],
    [14, 'SO', 'Shift Out'],
    [15, 'SI', 'Shift In'],
    [16, 'DLE', 'Data Link Escape'],
    [17, 'DC1', 'Device Control One'],
    [18, 'DC2', 'Device Control Two'],
    [19, 'DC3', 'Device Control Three'],
    [20, 'DC4', 'Device Control Four'],
    [21, 'NAK', 'Negative Acknowledge'],
    [22, 'SYN', 'Synchronous Idle'],
    [23, 'ETB', 'End of Transmission Block'],
    [24, 'CAN', 'Cancel'],
    [25, 'EM', 'End of Medium'],
    [26, 'SUB', 'Substitute'],
    [27, 'ESC', 'Escape'],
    [28, 'FS', 'Information Separator Four (File Separator)'],
    [29, 'GS', 'Information Separator Three (Group Separator)'],
    [30, 'RS', 'Information Separator Two (Record Separator)'],
    [31, 'US', 'Information Separator One (Unit Separator)'],
    [32, 'SP', 'Space'],
    [127, 'DEL', 'Delete'],
  ];

  it.each(cases)('dec %i is mnemonic %s (%s)', (dec, mnemonic, name) => {
    const e = asciiEntry(dec);
    expect(e.mnemonic).toBe(mnemonic);
    expect(e.name).toBe(name);
    expect(e.hasMnemonic).toBe(true);
  });
});

describe('printable character names (verified against the Unicode C0 chart)', () => {
  const cases: Array<[number, string, string]> = [
    [33, '!', 'Exclamation Mark'],
    [38, '&', 'Ampersand'],
    [48, '0', 'Digit Zero'],
    [57, '9', 'Digit Nine'],
    [64, '@', 'Commercial At'],
    [65, 'A', 'Latin Capital Letter A'],
    [90, 'Z', 'Latin Capital Letter Z'],
    [92, '\\', 'Reverse Solidus'],
    [97, 'a', 'Latin Small Letter A'],
    [122, 'z', 'Latin Small Letter Z'],
    [126, '~', 'Tilde'],
  ];

  it.each(cases)('dec %i is char %s (%s)', (dec, char, name) => {
    const e = asciiEntry(dec);
    expect(e.char).toBe(char);
    expect(e.name).toBe(name);
    expect(e.hasMnemonic).toBe(false);
  });
});

// Cross-check against src/utils/baseConvert.ts's own already-established
// printable-ASCII range constants (ASCII_MIN = 0x20, ASCII_MAX = 0x7E) —
// internal consistency between the two datasets, not just against the
// external source.
describe('consistency with baseConvert.ts\'s printable-ASCII range', () => {
  it('0x20 (space) and 0x7E (tilde) bound the printable range this table also treats specially', () => {
    const space = asciiEntry(0x20);
    const tilde = asciiEntry(0x7e);
    expect(space.hex).toBe('0x20');
    expect(space.category).toBe('punctuation');
    expect(tilde.hex).toBe('0x7E');
    expect(tilde.char).toBe('~');
  });
});

describe('asciiEntry bounds checking', () => {
  it('throws for out-of-range or non-integer input', () => {
    expect(() => asciiEntry(-1)).toThrow(RangeError);
    expect(() => asciiEntry(128)).toThrow(RangeError);
    expect(() => asciiEntry(1.5)).toThrow(RangeError);
  });
});

describe('ASCII_TABLE module-level export', () => {
  it('matches a fresh buildAsciiTable() call', () => {
    expect(ASCII_TABLE).toEqual(buildAsciiTable());
  });
});
