// Data Size & Storage Unit Converter — pure conversion math between bit,
// byte, and the two competing families of size prefixes used across
// computing: decimal SI prefixes (kB/MB/GB/TB/PB, exact powers of 1000 — the
// convention storage manufacturers use to label drive/media capacity) and
// binary IEC prefixes (KiB/MiB/GiB/TiB/PiB, exact powers of 1024 — the
// convention most operating systems and software have traditionally used to
// report it, since memory/addressing is inherently binary). Every multiplier
// in DATA_UNITS below is verified against NIST's own reference for the
// binary prefixes (https://physics.nist.gov/cuu/Units/binary.html — "1 byte
// = 8 bit", "1 MiB = 2^20 B = 1 048 576 B", "1 GiB = 2^30 B = 1 073 741 824
// B"), itself citing the IEC standard that defines them (first adopted as
// Amendment 2 to IEC 60027-2 in 1998, folded into the second edition of IEC
// 60027-2 in 2000, and now specified by IEC 80000-13:2008). Decimal SI
// prefixes (kilo=10^3 through peta=10^15) are the ordinary SI system, not a
// DFIR- or computing-specific fact. All arithmetic here is plain
// floating-point multiplication/division through a common "bytes" base
// unit — no further external research needed beyond this fixed, cited
// multiplier table; see test/dataSize.test.ts for the exact figures,
// including the real-world "500 GB drive shows ~465 GB in Windows" example
// (independently corroborated by Seagate's own support knowledge base).

export type DataUnitSystem = 'base' | 'decimal' | 'binary';

export type DataUnitId = 'bit' | 'byte' | 'kB' | 'MB' | 'GB' | 'TB' | 'PB' | 'KiB' | 'MiB' | 'GiB' | 'TiB' | 'PiB';

export interface DataUnitMeta {
  id: DataUnitId;
  label: string;
  /** Short symbol/abbreviation, for compact display. */
  symbol: string;
  system: DataUnitSystem;
  /** Exact number of bytes in one of this unit — the single source of truth every conversion routes through. */
  bytesPerUnit: number;
}

// bit and byte are base units (system: 'base'), not part of either prefix
// family. Decimal prefixes are exact powers of 1000; binary (IEC) prefixes
// are exact powers of 1024 — see file header for the NIST citation.
export const DATA_UNITS: DataUnitMeta[] = [
  { id: 'bit', label: 'Bit', symbol: 'bit', system: 'base', bytesPerUnit: 1 / 8 },
  { id: 'byte', label: 'Byte', symbol: 'B', system: 'base', bytesPerUnit: 1 },
  { id: 'kB', label: 'Kilobyte', symbol: 'kB', system: 'decimal', bytesPerUnit: 1000 },
  { id: 'MB', label: 'Megabyte', symbol: 'MB', system: 'decimal', bytesPerUnit: 1000 ** 2 },
  { id: 'GB', label: 'Gigabyte', symbol: 'GB', system: 'decimal', bytesPerUnit: 1000 ** 3 },
  { id: 'TB', label: 'Terabyte', symbol: 'TB', system: 'decimal', bytesPerUnit: 1000 ** 4 },
  { id: 'PB', label: 'Petabyte', symbol: 'PB', system: 'decimal', bytesPerUnit: 1000 ** 5 },
  { id: 'KiB', label: 'Kibibyte', symbol: 'KiB', system: 'binary', bytesPerUnit: 1024 },
  { id: 'MiB', label: 'Mebibyte', symbol: 'MiB', system: 'binary', bytesPerUnit: 1024 ** 2 },
  { id: 'GiB', label: 'Gibibyte', symbol: 'GiB', system: 'binary', bytesPerUnit: 1024 ** 3 },
  { id: 'TiB', label: 'Tebibyte', symbol: 'TiB', system: 'binary', bytesPerUnit: 1024 ** 4 },
  { id: 'PiB', label: 'Pebibyte', symbol: 'PiB', system: 'binary', bytesPerUnit: 1024 ** 5 },
];

const UNIT_MAP: Record<DataUnitId, DataUnitMeta> = DATA_UNITS.reduce(
  (acc, u) => {
    acc[u.id] = u;
    return acc;
  },
  {} as Record<DataUnitId, DataUnitMeta>
);

/** Looks up a unit's metadata by id. */
export function unitMeta(id: DataUnitId): DataUnitMeta {
  return UNIT_MAP[id];
}

/** Converts a non-negative `value` in `unit` to its exact byte count. */
export function toBytes(value: number, unit: DataUnitId): number {
  return value * UNIT_MAP[unit].bytesPerUnit;
}

/** Converts a byte count back into `unit`. */
export function fromBytes(bytes: number, unit: DataUnitId): number {
  return bytes / UNIT_MAP[unit].bytesPerUnit;
}

export type DataSizeResult = Record<DataUnitId, number>;

/** Converts `value` in `unit` to every unit in DATA_UNITS at once. */
export function convertDataSize(value: number, unit: DataUnitId): DataSizeResult {
  const bytes = toBytes(value, unit);
  const out = {} as DataSizeResult;
  DATA_UNITS.forEach((u) => {
    out[u.id] = fromBytes(bytes, u.id);
  });
  return out;
}

// A generous ceiling well past any realistic storage size (1 ZB = 1e21
// bytes is already far beyond total global data storage capacity as of this
// writing) — guards against a mis-paste producing Infinity/absurd output
// rather than a useful conversion.
const MAX_SAFE_VALUE = 1e21;

/**
 * Parses a data-size value typed by a user: a non-negative, finite decimal
 * number (optionally with surrounding whitespace; a leading "+" is
 * accepted since Number() itself accepts it). Returns null for anything
 * invalid — empty input, a negative number (a size can't be negative),
 * NaN/Infinity, or a value so large it's almost certainly a mistake rather
 * than a real size.
 */
export function parseDataSizeInput(input: string): number | null {
  if (typeof input !== 'string') return null;
  const s = input.trim();
  if (s === '') return null;
  const n = Number(s);
  if (!Number.isFinite(n)) return null;
  if (n < 0) return null;
  if (n > MAX_SAFE_VALUE) return null;
  return n;
}

/**
 * Formats a converted value for display: up to `sigFigs` significant
 * figures (default 6), trimming insignificant trailing zeros.
 *
 * Fixed-point notation is used for anything in a plausible "human size"
 * range (down to a billionth, up to just past this file's own
 * MAX_SAFE_VALUE input ceiling) — even when that means printing a long
 * integer (e.g. 500 GB expressed in bits is exactly 4,000,000,000,000, and
 * this shows the full digit string rather than "4e+12"), matching this
 * codebase's existing convention of never truncating an exact integer
 * result (see BaseConverter/baseConvert.ts, which shows full-length
 * binary/decimal strings for arbitrarily large values). Only genuinely
 * extreme magnitudes outside that range fall back to scientific notation,
 * where a wall of zeros would be worse.
 *
 * The significant digits themselves always come from
 * `Number.prototype.toPrecision` (which does its own correct rounding) —
 * this function only ever *reformats* those digits into fixed-point
 * position, rather than re-deriving the decimal exponent via `Math.log10`,
 * which is not exact for values that are precisely a power of ten (e.g.
 * `Math.log10(0.001)` is not guaranteed to be exactly -3 in IEEE-754
 * double-precision) and can silently be off by one.
 */
export function formatDataValue(value: number, sigFigs = 6): string {
  if (!Number.isFinite(value)) return '—';
  if (value === 0) return '0';

  const sign = value < 0 ? '-' : '';
  const abs = Math.abs(value);
  const precise = abs.toPrecision(sigFigs);

  // Extract the significant digits (no sign, no decimal point) and the
  // base-10 exponent of the leading digit from toPrecision's own output,
  // regardless of whether it chose fixed or exponential form.
  let digits: string;
  let exp: number;
  const eIdx = precise.indexOf('e');
  if (eIdx !== -1) {
    const mantissa = precise.slice(0, eIdx);
    exp = parseInt(precise.slice(eIdx + 1), 10);
    digits = mantissa.replace('.', '');
  } else {
    const dotIdx = precise.indexOf('.');
    if (dotIdx === -1) {
      digits = precise;
      exp = digits.length - 1;
    } else {
      const intPart = precise.slice(0, dotIdx);
      const fracPart = precise.slice(dotIdx + 1);
      if (intPart !== '0') {
        digits = intPart + fracPart;
        exp = intPart.length - 1;
      } else {
        const firstSig = fracPart.search(/[1-9]/);
        digits = fracPart.slice(firstSig);
        exp = -(firstSig + 1);
      }
    }
  }

  // Genuinely extreme magnitudes: render as trimmed scientific notation.
  if (exp >= 21 || exp < -9) {
    const mantissaStr = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
    const trimmedMantissa = mantissaStr.indexOf('.') !== -1 ? mantissaStr.replace(/0+$/, '').replace(/\.$/, '') : mantissaStr;
    return `${sign}${trimmedMantissa}e${exp >= 0 ? '+' : ''}${exp}`;
  }

  // Fixed-point notation, reconstructed from the significant digits + exponent.
  let str: string;
  if (exp >= 0) {
    str = exp + 1 >= digits.length ? digits + '0'.repeat(exp + 1 - digits.length) : `${digits.slice(0, exp + 1)}.${digits.slice(exp + 1)}`;
  } else {
    str = `0.${'0'.repeat(-exp - 1)}${digits}`;
  }
  if (str.indexOf('.') !== -1) str = str.replace(/0+$/, '').replace(/\.$/, '');
  return sign + str;
}
