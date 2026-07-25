import { describe, it, expect } from 'vitest';
import {
  DATA_UNITS,
  unitMeta,
  toBytes,
  fromBytes,
  convertDataSize,
  parseDataSizeInput,
  formatDataValue,
} from '../src/utils/dataSize';

describe('DATA_UNITS metadata', () => {
  it('lists all twelve units with unique ids', () => {
    const ids = DATA_UNITS.map((u) => u.id);
    expect(ids.length).toBe(12);
    expect(new Set(ids).size).toBe(12);
  });

  it('bit is 1/8 of a byte (1 byte = 8 bit, per NIST)', () => {
    expect(unitMeta('bit').bytesPerUnit).toBe(0.125);
    expect(unitMeta('byte').bytesPerUnit).toBe(1);
  });

  it('decimal SI prefixes are exact powers of 1000', () => {
    expect(unitMeta('kB').bytesPerUnit).toBe(1000);
    expect(unitMeta('MB').bytesPerUnit).toBe(1_000_000);
    expect(unitMeta('GB').bytesPerUnit).toBe(1_000_000_000);
    expect(unitMeta('TB').bytesPerUnit).toBe(1_000_000_000_000);
    expect(unitMeta('PB').bytesPerUnit).toBe(1_000_000_000_000_000);
  });

  it('binary IEC prefixes are exact powers of 1024, matching NIST’s own published values', () => {
    // https://physics.nist.gov/cuu/Units/binary.html
    expect(unitMeta('KiB').bytesPerUnit).toBe(1024);
    expect(unitMeta('MiB').bytesPerUnit).toBe(1_048_576);
    expect(unitMeta('GiB').bytesPerUnit).toBe(1_073_741_824);
    expect(unitMeta('TiB').bytesPerUnit).toBe(1_099_511_627_776);
    expect(unitMeta('PiB').bytesPerUnit).toBe(1_125_899_906_842_624);
  });

  it('every decimal/binary unit at the same tier differs by exactly the 1000 vs 1024 ratio', () => {
    expect(unitMeta('KiB').bytesPerUnit / unitMeta('kB').bytesPerUnit).toBeCloseTo(1.024, 10);
    expect(unitMeta('GiB').bytesPerUnit / unitMeta('GB').bytesPerUnit).toBeCloseTo(1.073741824, 10);
  });

  it('tags each unit with the correct system', () => {
    expect(unitMeta('bit').system).toBe('base');
    expect(unitMeta('byte').system).toBe('base');
    expect(unitMeta('kB').system).toBe('decimal');
    expect(unitMeta('PB').system).toBe('decimal');
    expect(unitMeta('KiB').system).toBe('binary');
    expect(unitMeta('PiB').system).toBe('binary');
  });
});

describe('toBytes / fromBytes', () => {
  it('converts a simple byte-based value both ways', () => {
    expect(toBytes(1, 'kB')).toBe(1000);
    expect(toBytes(1, 'KiB')).toBe(1024);
    expect(fromBytes(1024, 'KiB')).toBe(1);
    expect(fromBytes(1000, 'kB')).toBe(1);
  });

  it('converts bits to bytes correctly', () => {
    expect(toBytes(8, 'bit')).toBe(1);
    expect(toBytes(1, 'bit')).toBe(0.125);
    expect(fromBytes(1, 'bit')).toBe(8);
  });

  it('round-trips through bytes without drift for whole-unit values', () => {
    DATA_UNITS.forEach((u) => {
      const bytes = toBytes(5, u.id);
      expect(fromBytes(bytes, u.id)).toBeCloseTo(5, 9);
    });
  });
});

describe('convertDataSize', () => {
  it('produces every unit for a simple 1-byte value', () => {
    const result = convertDataSize(1, 'byte');
    expect(result.bit).toBe(8);
    expect(result.byte).toBe(1);
    expect(result.kB).toBeCloseTo(0.001, 12);
    expect(result.KiB).toBeCloseTo(1 / 1024, 12);
  });

  it('1024 bytes is exactly 1 KiB but only 1.024 kB', () => {
    const result = convertDataSize(1024, 'byte');
    expect(result.KiB).toBe(1);
    expect(result.kB).toBeCloseTo(1.024, 10);
  });

  it('1 MiB (2^20 bytes) round-trips to the documented byte count', () => {
    const result = convertDataSize(1, 'MiB');
    expect(result.byte).toBe(1_048_576);
  });

  it('1 GiB (2^30 bytes) round-trips to the documented byte count', () => {
    const result = convertDataSize(1, 'GiB');
    expect(result.byte).toBe(1_073_741_824);
  });

  it('converting from any unit and back through byte agrees for every unit pair', () => {
    DATA_UNITS.forEach((from) => {
      const result = convertDataSize(3, from.id);
      DATA_UNITS.forEach((to) => {
        // Re-converting the derived value in `to` back to `from`'s unit
        // should recover the original 3, within floating-point tolerance.
        const back = convertDataSize(result[to.id], to.id);
        expect(back[from.id]).toBeCloseTo(3, 6);
      });
    });
  });

  it('handles zero', () => {
    const result = convertDataSize(0, 'GB');
    DATA_UNITS.forEach((u) => expect(result[u.id]).toBe(0));
  });

  // The single most useful, non-obvious fact this tool teaches: a "500 GB"
  // drive is labeled using the decimal (manufacturer) convention, but an OS
  // that reports storage in binary units shows a smaller number for the
  // exact same physical capacity. Verified independently against Seagate's
  // own support knowledge base
  // (https://www.seagate.com/support/kb/why-does-my-hard-drive-report-less-capacity-than-indicated-on-the-drives-label-172191en/),
  // which states: "A 500 GB hard drive is approximately 500,000,000,000
  // bytes... When using the GB binary calculation, (500,000,000,000 /
  // 1,073,741,824) that same 500 GB will show as 465 gigabytes."
  it('worked example: a 500 GB (decimal) drive is ~465.66 GiB (binary) — the classic "missing" drive space', () => {
    const result = convertDataSize(500, 'GB');
    expect(result.byte).toBe(500_000_000_000);
    expect(result.GiB).toBeCloseTo(465.66128730773926, 6);
    // Rounded to a whole number, this matches Seagate's own stated figure.
    expect(Math.round(result.GiB)).toBe(466); // 465.661... rounds to 466, not 465 (Seagate rounds down/truncates in their prose)
    expect(Math.trunc(result.GiB)).toBe(465); // truncating (not rounding) matches the commonly cited "~465 GB" figure
  });

  it('worked example: a 5 TB (decimal) drive is ~4.55 TiB (binary)', () => {
    // Corroborated by the same Seagate KB source: "a 5 TB hard drive is
    // approximately 5,000,000,000,000 bytes... that same 5 TB will show as
    // 4.54 terabytes" (their figure uses a coarser rounding than the exact
    // value computed here).
    const result = convertDataSize(5, 'TB');
    expect(result.byte).toBe(5_000_000_000_000);
    expect(result.TiB).toBeCloseTo(4.547473508864641, 6);
  });
});

describe('parseDataSizeInput', () => {
  it('parses a simple positive number', () => {
    expect(parseDataSizeInput('500')).toBe(500);
    expect(parseDataSizeInput('1.5')).toBe(1.5);
  });

  it('parses zero', () => {
    expect(parseDataSizeInput('0')).toBe(0);
  });

  it('tolerates surrounding whitespace', () => {
    expect(parseDataSizeInput('  42 ')).toBe(42);
    expect(parseDataSizeInput('\t8\n')).toBe(8);
  });

  it('rejects empty and whitespace-only input', () => {
    expect(parseDataSizeInput('')).toBeNull();
    expect(parseDataSizeInput('   ')).toBeNull();
  });

  it('rejects non-numeric input', () => {
    expect(parseDataSizeInput('abc')).toBeNull();
    expect(parseDataSizeInput('12gb')).toBeNull();
  });

  it('rejects negative values (a data size cannot be negative)', () => {
    expect(parseDataSizeInput('-1')).toBeNull();
    expect(parseDataSizeInput('-0.5')).toBeNull();
  });

  it('rejects NaN and Infinity', () => {
    expect(parseDataSizeInput('NaN')).toBeNull();
    expect(parseDataSizeInput('Infinity')).toBeNull();
  });

  it('rejects a pathologically large value', () => {
    expect(parseDataSizeInput('1e30')).toBeNull();
  });

  it('rejects non-string input defensively', () => {
    // @ts-expect-error — exercising the runtime guard for a non-string caller
    expect(parseDataSizeInput(42)).toBeNull();
  });
});

describe('formatDataValue', () => {
  it('formats a whole number with no trailing decimal', () => {
    expect(formatDataValue(500)).toBe('500');
    expect(formatDataValue(1024)).toBe('1024');
  });

  it('formats zero as "0"', () => {
    expect(formatDataValue(0)).toBe('0');
  });

  it('trims insignificant trailing zeros', () => {
    expect(formatDataValue(1.5)).toBe('1.5');
    expect(formatDataValue(0.001, 6)).toBe('0.001');
  });

  it('rounds to the requested significant figures', () => {
    expect(formatDataValue(465.66128730773926, 6)).toBe('465.661');
    expect(formatDataValue(4.547473508864641, 6)).toBe('4.54747');
  });

  it('formats a very small value using scientific notation', () => {
    // 1 bit expressed in PiB: 0.125 / 2^50
    const tinyValue = 0.125 / 1_125_899_906_842_624;
    const formatted = formatDataValue(tinyValue, 6);
    expect(formatted).toContain('e-');
    // Round-trips back to (approximately) the original value.
    expect(Number(formatted)).toBeCloseTo(tinyValue, 20);
  });

  it('formats a large-but-plausible exact integer in full, not scientific notation', () => {
    // 500 GB expressed in bits: 500,000,000,000 bytes * 8 — a real value
    // this converter produces from its own default (500 GB), and a real
    // regression this function once had (rendered "4e+12" instead).
    expect(formatDataValue(4_000_000_000_000, 6)).toBe('4000000000000');
    expect(formatDataValue(500_000_000_000, 6)).toBe('500000000000');
  });

  it('preserves an exact power-of-ten value without an off-by-one digit error', () => {
    // Regression guard: reconstructing fixed-point notation from
    // toPrecision's own digits/exponent (rather than re-deriving the
    // exponent via Math.log10, which is not exact for values that are
    // precisely a power of ten) must not shift the decimal point.
    expect(formatDataValue(1000, 6)).toBe('1000');
    expect(formatDataValue(0.001, 6)).toBe('0.001');
    expect(formatDataValue(1, 6)).toBe('1');
    expect(formatDataValue(100, 6)).toBe('100');
  });

  it('caps significant figures for a large non-round number rather than showing every digit', () => {
    // 5 TB expressed in bits: 5,000,000,000,000,000 * 8 = 40,000,000,000,000,000 (round already);
    // use a non-round large value instead to confirm sigFigs rounding still applies before the
    // integer digits are padded out with zeros.
    expect(formatDataValue(1_234_567_890, 6)).toBe('1234570000');
  });

  it('renders every unit’s exact bytesPerUnit at 16 significant figures without rounding it away', () => {
    // Regression guard for the page's own "Unit reference" table, which
    // calls formatDataValue(u.bytesPerUnit, 16): the largest bytesPerUnit
    // in DATA_UNITS (PiB, 2^50) has exactly 16 significant digits, so
    // anything less than 16 sig figs would silently round its last digit
    // away in a table whose whole point is to show the exact byte count.
    DATA_UNITS.forEach((u) => {
      const formatted = formatDataValue(u.bytesPerUnit, 16);
      expect(Number(formatted)).toBe(u.bytesPerUnit);
    });
    expect(formatDataValue(unitMeta('PiB').bytesPerUnit, 16)).toBe('1125899906842624');
  });

  it('formats negative values with a leading minus sign', () => {
    expect(formatDataValue(-500)).toBe('-500');
  });

  it('returns an em dash for non-finite input', () => {
    expect(formatDataValue(NaN)).toBe('—');
    expect(formatDataValue(Infinity)).toBe('—');
  });
});
