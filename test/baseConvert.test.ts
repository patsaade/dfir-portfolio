import { describe, it, expect } from 'vitest';
import { parseInBase, formatInBase, decodeAscii, convert, convertFromInput, NUMBER_BASES } from '../src/utils/baseConvert';

describe('parseInBase', () => {
  it('parses a simple value in every base', () => {
    expect(parseInBase('101010', 'binary')).toBe(42n);
    expect(parseInBase('52', 'octal')).toBe(42n);
    expect(parseInBase('42', 'decimal')).toBe(42n);
    expect(parseInBase('2a', 'hex')).toBe(42n);
  });

  it('parses zero', () => {
    expect(parseInBase('0', 'binary')).toBe(0n);
    expect(parseInBase('0', 'octal')).toBe(0n);
    expect(parseInBase('0', 'decimal')).toBe(0n);
    expect(parseInBase('0', 'hex')).toBe(0n);
  });

  it('parses a single digit', () => {
    expect(parseInBase('1', 'binary')).toBe(1n);
    expect(parseInBase('7', 'octal')).toBe(7n);
    expect(parseInBase('9', 'decimal')).toBe(9n);
    expect(parseInBase('f', 'hex')).toBe(15n);
  });

  it('accepts recognized prefixes, case-insensitively', () => {
    expect(parseInBase('0b101010', 'binary')).toBe(42n);
    expect(parseInBase('0B101010', 'binary')).toBe(42n);
    expect(parseInBase('0o52', 'octal')).toBe(42n);
    expect(parseInBase('0O52', 'octal')).toBe(42n);
    expect(parseInBase('0x2a', 'hex')).toBe(42n);
    expect(parseInBase('0X2a', 'hex')).toBe(42n);
  });

  it('handles uppercase and lowercase hex digits, including mixed case', () => {
    expect(parseInBase('ff', 'hex')).toBe(255n);
    expect(parseInBase('FF', 'hex')).toBe(255n);
    expect(parseInBase('fF', 'hex')).toBe(255n);
    expect(parseInBase('0xAbCd', 'hex')).toBe(0xabcdn);
  });

  it('tolerates surrounding whitespace', () => {
    expect(parseInBase('  42 ', 'decimal')).toBe(42n);
    expect(parseInBase('\t0x2a\n', 'hex')).toBe(42n);
  });

  it('preserves leading zeros as the same numeric value', () => {
    expect(parseInBase('007', 'decimal')).toBe(7n);
    expect(parseInBase('0x00ff', 'hex')).toBe(255n);
    expect(parseInBase('00000101', 'binary')).toBe(5n);
    expect(parseInBase('000', 'octal')).toBe(0n);
  });

  it('handles a value that overflows a 32-bit integer', () => {
    // 2^32 = 4294967296 — one past the unsigned 32-bit ceiling; a
    // >>>0-based implementation (this codebase's own IPv4 CIDR math, by
    // design, since IPv4 addresses genuinely are 32-bit) would wrap this to
    // 0, which would be silently wrong for a general-purpose converter.
    const value = 2n ** 32n;
    expect(parseInBase('4294967296', 'decimal')).toBe(value);
    expect(formatInBase(value, 'hex')).toBe('100000000');
    expect(formatInBase(value, 'binary')).toBe('1' + '0'.repeat(32));
  });

  it('handles a value that overflows JS safe integer precision (2^53)', () => {
    // Number.MAX_SAFE_INTEGER is 2^53 - 1 = 9007199254740991. One past it,
    // 9007199254740993 (itself odd, so distinguishable from any nearby
    // double-precision rounding), is where a naive parseInt/Number-based
    // implementation silently loses precision.
    const decimalStr = '9007199254740993';
    const value = parseInBase(decimalStr, 'decimal');
    expect(value).toBe(9007199254740993n);
    // Compared as strings, not numeric literals — a numeric literal for this
    // value would itself already be rounded by the JS parser, silently
    // hiding the exact bug this test exists to catch. Number(value) rounds
    // to the nearest representable double (9007199254740992, rounds-to-even
    // past 2^53), which is exactly the precision loss a naive
    // parseInt/Number-based implementation would have baked in from the start.
    expect(String(Number(value))).not.toBe(decimalStr);
    // Round-trips through hex without any precision loss.
    const hex = formatInBase(value!, 'hex');
    expect(parseInBase(hex, 'hex')).toBe(value);
  });

  it('rejects invalid digits per base', () => {
    expect(parseInBase('2', 'binary')).toBeNull(); // 2 isn't a binary digit
    expect(parseInBase('8', 'octal')).toBeNull(); // 8 isn't an octal digit
    expect(parseInBase('a', 'decimal')).toBeNull(); // a isn't a decimal digit
    expect(parseInBase('g', 'hex')).toBeNull(); // g isn't a hex digit
  });

  it('rejects a prefix that belongs to a different base rather than partially parsing', () => {
    expect(parseInBase('0xff', 'binary')).toBeNull();
    expect(parseInBase('0b11', 'decimal')).toBeNull();
  });

  it('rejects empty input, a bare prefix, and whitespace-only input', () => {
    expect(parseInBase('', 'decimal')).toBeNull();
    expect(parseInBase('   ', 'decimal')).toBeNull();
    expect(parseInBase('0x', 'hex')).toBeNull();
    expect(parseInBase('0b', 'binary')).toBeNull();
  });

  it('rejects a negative sign (unsigned-only converter)', () => {
    expect(parseInBase('-1', 'decimal')).toBeNull();
    expect(parseInBase('-0x1', 'hex')).toBeNull();
  });

  it('rejects non-string input defensively', () => {
    // @ts-expect-error — exercising the runtime guard for a non-string caller
    expect(parseInBase(42, 'decimal')).toBeNull();
  });

  it('rejects a pathologically long input', () => {
    expect(parseInBase('1'.repeat(5000), 'decimal')).toBeNull();
  });
});

describe('formatInBase', () => {
  it('renders zero as "0" in every base', () => {
    expect(formatInBase(0n, 'binary')).toBe('0');
    expect(formatInBase(0n, 'octal')).toBe('0');
    expect(formatInBase(0n, 'decimal')).toBe('0');
    expect(formatInBase(0n, 'hex')).toBe('0');
  });

  it('never emits leading zeros for a non-zero value', () => {
    expect(formatInBase(5n, 'binary')).toBe('101');
    expect(formatInBase(255n, 'hex')).toBe('ff');
  });

  it('emits lowercase hex digits', () => {
    expect(formatInBase(0xabcdefn, 'hex')).toBe('abcdef');
  });

  it('throws for a negative value', () => {
    expect(() => formatInBase(-1n, 'hex')).toThrow(RangeError);
  });
});

describe('decodeAscii', () => {
  it('decodes a multi-byte printable value ("Hi")', () => {
    // 0x48 = 'H', 0x69 = 'i'
    const result = decodeAscii(0x4869n);
    expect(result.printable).toBe(true);
    expect(result.text).toBe('Hi');
    expect(result.reason).toBeNull();
  });

  it('decodes a single printable byte', () => {
    const result = decodeAscii(0x41n); // 'A'
    expect(result.printable).toBe(true);
    expect(result.text).toBe('A');
  });

  it('pads to a whole byte rather than misreading an odd hex-digit count', () => {
    // 0x148 is 3 hex digits; padded to 0x0148 it's the two bytes 0x01, 0x48
    // ('H') — not a single out-of-range "0x148" byte.
    const result = decodeAscii(0x148n);
    expect(result.printable).toBe(false);
    expect(result.reason).toContain('0x01');
  });

  it('reports zero as a non-printable NUL byte', () => {
    const result = decodeAscii(0n);
    expect(result.printable).toBe(false);
    expect(result.text).toBeNull();
    expect(result.reason).toContain('0x00');
  });

  it('flags a control character below the printable range', () => {
    const result = decodeAscii(0x09n); // tab, 0x09 < 0x20
    expect(result.printable).toBe(false);
    expect(result.reason).toContain('0x09');
  });

  it('flags DEL and bytes above the printable ASCII range', () => {
    expect(decodeAscii(0x7fn).printable).toBe(false); // DEL
    expect(decodeAscii(0xffn).printable).toBe(false); // outside ASCII entirely
  });

  it('reports the first non-printable byte in a multi-byte value', () => {
    // 'H' (0x48) followed by a non-printable 0x01
    const result = decodeAscii(0x4801n);
    expect(result.printable).toBe(false);
    expect(result.reason).toContain('Byte 2 of 2');
    expect(result.reason).toContain('0x01');
  });

  it('accepts the printable-range boundaries (space and tilde)', () => {
    expect(decodeAscii(0x20n).printable).toBe(true); // space
    expect(decodeAscii(0x20n).text).toBe(' ');
    expect(decodeAscii(0x7en).printable).toBe(true); // '~'
    expect(decodeAscii(0x7en).text).toBe('~');
  });
});

describe('convert', () => {
  it('produces every base representation plus the ASCII decode for a single value', () => {
    const result = convert(0x4869n);
    expect(result.value).toBe(0x4869n);
    expect(result.decimal).toBe('18537');
    expect(result.hex).toBe('4869');
    expect(result.octal).toBe('44151');
    expect(result.binary).toBe('100100001101001');
    expect(result.ascii.printable).toBe(true);
    expect(result.ascii.text).toBe('Hi');
  });

  it('every representation round-trips back to the same value through parseInBase', () => {
    const value = 123456789012345678901234567890n; // well beyond 2^53 and beyond 64-bit too
    const result = convert(value);
    expect(parseInBase(result.binary, 'binary')).toBe(value);
    expect(parseInBase(result.octal, 'octal')).toBe(value);
    expect(parseInBase(result.decimal, 'decimal')).toBe(value);
    expect(parseInBase(result.hex, 'hex')).toBe(value);
  });

  it('throws for a negative value', () => {
    expect(() => convert(-1n)).toThrow(RangeError);
  });
});

describe('convertFromInput', () => {
  it('parses and converts in one step', () => {
    const result = convertFromInput('0x2a', 'hex');
    expect(result).not.toBeNull();
    expect(result!.value).toBe(42n);
    expect(result!.decimal).toBe('42');
    expect(result!.binary).toBe('101010');
  });

  it('returns null for invalid input rather than throwing', () => {
    expect(convertFromInput('not a number', 'decimal')).toBeNull();
    expect(convertFromInput('', 'hex')).toBeNull();
  });
});

describe('NUMBER_BASES metadata', () => {
  it('lists all four bases with matching ids and correct radixes', () => {
    expect(NUMBER_BASES.map((b) => b.id).sort()).toEqual(['binary', 'decimal', 'hex', 'octal']);
    const byId = Object.fromEntries(NUMBER_BASES.map((b) => [b.id, b]));
    expect(byId.binary.radix).toBe(2);
    expect(byId.octal.radix).toBe(8);
    expect(byId.decimal.radix).toBe(10);
    expect(byId.hex.radix).toBe(16);
    expect(byId.decimal.prefix).toBeNull();
    expect(byId.hex.prefix).toBe('0x');
  });
});
