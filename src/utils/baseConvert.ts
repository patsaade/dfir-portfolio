// Number Base Converter — pure bigint arithmetic converting a value between
// binary, octal, decimal, and hexadecimal, plus an ASCII/text interpretation
// of the value's underlying bytes. Everything routes through `bigint`, never
// `number`: a naive `parseInt(str, radix)` implementation silently loses
// precision past Number.MAX_SAFE_INTEGER (2^53 - 1) — trivially reachable
// from a 64-bit hex literal, or even a fairly short binary string — and
// `bigint` has no such ceiling. No external research needed here either;
// this is plain positional-notation arithmetic (the same base-N expansion
// every base uses) plus the fixed ASCII printable-range definition
// (0x20–0x7E), so it's fully unit-testable without a DOM.

export type NumberBase = 'binary' | 'octal' | 'decimal' | 'hex';

interface BaseInfo {
  radix: bigint;
  /** Every valid digit for this base, lowercased, ordered by value (index = digit value). */
  digits: string;
  /** Case-insensitive prefixes this base recognizes and strips before parsing (decimal has none). */
  prefixes: string[];
}

const BASES: Record<NumberBase, BaseInfo> = {
  binary: { radix: 2n, digits: '01', prefixes: ['0b'] },
  octal: { radix: 8n, digits: '01234567', prefixes: ['0o'] },
  decimal: { radix: 10n, digits: '0123456789', prefixes: [] },
  hex: { radix: 16n, digits: '0123456789abcdef', prefixes: ['0x'] },
};

// Metadata for rendering a reference table on the tool's page — mirrors
// hashes.ts's own HASH_ALGORITHMS convention (a single typed array the page
// maps over, rather than duplicating this info in the .astro file).
export interface BaseMeta {
  id: NumberBase;
  label: string;
  radix: number;
  /** The recognized input prefix, or null for decimal (which has none). */
  prefix: string | null;
  /** Human-readable digit range, for display only. */
  digitRange: string;
}

export const NUMBER_BASES: BaseMeta[] = [
  { id: 'binary', label: 'Binary', radix: 2, prefix: '0b', digitRange: '0–1' },
  { id: 'octal', label: 'Octal', radix: 8, prefix: '0o', digitRange: '0–7' },
  { id: 'decimal', label: 'Decimal', radix: 10, prefix: null, digitRange: '0–9' },
  { id: 'hex', label: 'Hexadecimal', radix: 16, prefix: '0x', digitRange: '0–9, a–f' },
];

// A pathologically long literal (many thousands of digits) is still valid
// input mathematically, but the digit-by-digit accumulation below is O(n^2)
// in the number of digits (each multiply grows the working bigint) — this
// caps input length so a mis-paste can't hang the tab. Well beyond any
// realistic use (even a 4096-bit key rendered in binary is 4096 characters).
const MAX_INPUT_LENGTH = 4096;

/**
 * Parses `input` as a non-negative integer literal in `base`. Tolerates
 * surrounding whitespace and an optional, case-insensitive radix prefix
 * (`0b`/`0o`/`0x` — decimal has none). Validation is strict: any character
 * outside that base's own digit set — including a prefix that belongs to a
 * *different* base, e.g. typing `0xff` into the binary field — rejects the
 * whole string, rather than silently parsing a leading valid run the way
 * `parseInt` does. Returns null for anything invalid, including empty input,
 * a bare prefix with nothing after it (`0x`), or a negative sign (this
 * converter is unsigned-only, matching how binary/octal/hex literals are
 * conventionally read).
 */
export function parseInBase(input: string, base: NumberBase): bigint | null {
  if (typeof input !== 'string') return null;
  let s = input.trim();
  if (s === '' || s.length > MAX_INPUT_LENGTH) return null;

  const info = BASES[base];
  for (const prefix of info.prefixes) {
    if (s.slice(0, prefix.length).toLowerCase() === prefix) {
      s = s.slice(prefix.length);
      break;
    }
  }
  if (s === '') return null;

  const lower = s.toLowerCase();
  for (let i = 0; i < lower.length; i++) {
    if (info.digits.indexOf(lower[i]) === -1) return null;
  }

  let value = 0n;
  for (let i = 0; i < lower.length; i++) {
    value = value * info.radix + BigInt(info.digits.indexOf(lower[i]));
  }
  return value;
}

/**
 * Renders a non-negative `value` as a canonical, prefix-free digit string in
 * `base` — no leading zeros (other than "0" itself), lowercase hex digits.
 */
export function formatInBase(value: bigint, base: NumberBase): string {
  if (value < 0n) throw new RangeError('formatInBase does not support negative values');
  if (value === 0n) return '0';
  const info = BASES[base];
  let v = value;
  let out = '';
  while (v > 0n) {
    out = info.digits[Number(v % info.radix)] + out;
    v /= info.radix;
  }
  return out;
}

export interface AsciiDecode {
  /** True when every byte of the value falls in the printable ASCII range. */
  printable: boolean;
  /** The decoded text, only set when printable is true. */
  text: string | null;
  /** A human-readable explanation of the first non-printable byte found, only set when printable is false. */
  reason: string | null;
}

const ASCII_MIN = 0x20; // space
const ASCII_MAX = 0x7e; // ~

/**
 * Interprets `value`'s bytes (its minimal big-endian byte representation —
 * the same bytes its hex form encodes, padded to a whole number of bytes)
 * as ASCII text. A value's "bytes" here means the shortest hex expansion
 * with an even digit count — e.g. 0x48 is one byte, 0x148 pads to 0x0148
 * (two bytes) rather than being read as a single out-of-range byte. Every
 * byte must fall within the printable ASCII range (0x20 space – 0x7E `~`)
 * for the value to be reported as printable; anything else (control
 * characters, DEL, and the whole non-ASCII 0x80–0xFF range) is reported
 * explicitly rather than rendered as replacement-character garbage.
 */
export function decodeAscii(value: bigint): AsciiDecode {
  if (value < 0n) return { printable: false, text: null, reason: 'Negative values have no byte representation.' };

  let hex = formatInBase(value, 'hex');
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const byteCount = hex.length / 2;

  let text = '';
  for (let i = 0; i < byteCount; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (byte < ASCII_MIN || byte > ASCII_MAX) {
      return {
        printable: false,
        text: null,
        reason: `Byte ${i + 1} of ${byteCount} is 0x${byte.toString(16).padStart(2, '0')}, outside the printable ASCII range (0x20–0x7E).`,
      };
    }
    text += String.fromCharCode(byte);
  }
  return { printable: true, text, reason: null };
}

export interface ConversionResult {
  value: bigint;
  binary: string;
  octal: string;
  decimal: string;
  hex: string;
  ascii: AsciiDecode;
}

/** Produces every base representation plus the ASCII decode for a single non-negative value. */
export function convert(value: bigint): ConversionResult {
  if (value < 0n) throw new RangeError('convert does not support negative values');
  return {
    value,
    binary: formatInBase(value, 'binary'),
    octal: formatInBase(value, 'octal'),
    decimal: formatInBase(value, 'decimal'),
    hex: formatInBase(value, 'hex'),
    ascii: decodeAscii(value),
  };
}

/** Convenience wrapper: parses `input` as `base`, then converts it — null if `input` isn't valid in that base. */
export function convertFromInput(input: string, base: NumberBase): ConversionResult | null {
  const value = parseInBase(input, base);
  if (value === null) return null;
  return convert(value);
}
