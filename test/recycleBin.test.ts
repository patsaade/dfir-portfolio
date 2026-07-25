import { describe, it, expect } from 'vitest';
import {
  parseRecycleBinIndex,
  splitWindowsPath,
  companionRName,
  formatByteSize,
  hexToBytes,
  V1_RECORD_SIZE,
  SAMPLE_V2_HEX,
} from '../src/utils/recycleBin';

// ---------------------------------------------------------------------------
// Hand-constructed $I record fixtures.
//
// Nothing below is a captured real artifact — each buffer is built
// byte-by-byte against the documented layout in src/utils/recycleBin.ts's own
// header comment (version @ 0x00, original size @ 0x08, deletion FILETIME @
// 0x10, then either a fixed 260-character path field @ 0x18 for version 1, or
// a 4-byte character count @ 0x18 plus a variable path @ 0x1C for version 2).
// Same fixture style as test/mftUsn.test.ts / test/pe.test.ts.
// ---------------------------------------------------------------------------

/** Windows FILETIME ticks (100ns since 1601-01-01) for a known UTC instant,
 *  computed here independently of the parser so the assertion is a real
 *  round-trip rather than the code checking itself. */
function filetimeFor(iso: string): bigint {
  const unixSeconds = BigInt(Math.floor(Date.parse(iso) / 1000));
  return (unixSeconds + 11_644_473_600n) * 10_000_000n;
}

function writeUtf16le(view: DataView, offset: number, s: string) {
  for (let i = 0; i < s.length; i++) view.setUint16(offset + i * 2, s.charCodeAt(i), true);
  view.setUint16(offset + s.length * 2, 0, true); // terminating NUL
}

/** Build a version-1 ($I as written by Vista / 7 / 8 / 8.1) record: a fixed
 *  544 bytes, with the path NUL-terminated and then zero-padded. */
function buildV1(path: string, sizeBytes: bigint, deletedIso: string): Uint8Array {
  const bytes = new Uint8Array(V1_RECORD_SIZE);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(0x00, 1n, true);
  view.setBigUint64(0x08, sizeBytes, true);
  view.setBigUint64(0x10, filetimeFor(deletedIso), true);
  writeUtf16le(view, 0x18, path);
  return bytes;
}

/** Build a version-2 ($I as written by Windows 10 / 11) record: a 28-byte
 *  header whose character count INCLUDES the terminating NUL, then the
 *  UTF-16LE path. */
function buildV2(path: string, sizeBytes: bigint, deletedIso: string): Uint8Array {
  const chars = path.length + 1; // + terminating NUL, per the documented count
  const bytes = new Uint8Array(0x1c + chars * 2);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(0x00, 2n, true);
  view.setBigUint64(0x08, sizeBytes, true);
  view.setBigUint64(0x10, filetimeFor(deletedIso), true);
  view.setUint32(0x18, chars, true);
  writeUtf16le(view, 0x1c, path);
  return bytes;
}

// ---------------------------------------------------------------------------

describe('parseRecycleBinIndex — version 1 (Vista / 7 / 8 / 8.1)', () => {
  const PATH = 'C:\\Users\\jsmith\\Desktop\\quarterly notes.txt';
  const bytes = buildV1(PATH, 8192n, '2013-07-04T18:05:11Z');

  it('is exactly 544 bytes, the documented fixed version 1 record size', () => {
    expect(bytes.length).toBe(544);
    expect(V1_RECORD_SIZE).toBe(544);
  });

  it('parses the version, size, deletion time and full original path', () => {
    const result = parseRecycleBinIndex(bytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.record.version).toBe(1);
    expect(result.record.versionLabel).toBe('Version 1 — Windows Vista, 7, 8 and 8.1');
    expect(result.record.originalSize.bytes).toBe(8192n);
    expect(result.record.originalSize.display).toBe('8.00 KiB');
    expect(result.record.deletionTime.ticks).toBe(130_174_347_110_000_000n);
    expect(result.record.deletionTime.isZero).toBe(false);
    expect(result.record.deletionTime.display).toContain('2013-07-04');
    expect(result.record.path.full).toBe(PATH);
    expect(result.record.path.fileName).toBe('quarterly notes.txt');
    expect(result.record.path.directory).toBe('C:\\Users\\jsmith\\Desktop');
    expect(result.record.path.extension).toBe('.txt');
    expect(result.record.path.driveLetter).toBe('C:');
    // Version 1 has no length prefix — the path field is a fixed size.
    expect(result.record.declaredPathChars).toBeNull();
    expect(result.record.recordSize).toBe(544);
    expect(result.record.notes).toEqual([]);
  });

  it('stops the path at the NUL terminator, not at the end of the padded field', () => {
    const result = parseRecycleBinIndex(bytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.record.path.full.length).toBe(PATH.length);
    expect(result.record.path.full).not.toContain('\x00');
  });

  it('flags a version 1 record that is not the fixed 544 bytes', () => {
    const short = bytes.slice(0, 200);
    const result = parseRecycleBinIndex(short);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.record.path.full).toBe(PATH); // still fully recoverable here
    expect(result.record.notes.join(' ')).toContain('fixed 544 bytes');
  });
});

describe('parseRecycleBinIndex — version 2 (Windows 10 / 11)', () => {
  const PATH = 'D:\\Shared\\payroll-2025.xlsx';
  const bytes = buildV2(PATH, 1_048_576n, '2025-11-02T04:17:59Z');

  it('sizes the record from the length prefix: 28 + (chars incl. NUL) * 2', () => {
    expect(bytes.length).toBe(28 + (PATH.length + 1) * 2);
  });

  it('parses the version, size, deletion time, length prefix and path', () => {
    const result = parseRecycleBinIndex(bytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.record.version).toBe(2);
    expect(result.record.versionLabel).toBe('Version 2 — Windows 10 and 11');
    expect(result.record.originalSize.bytes).toBe(1_048_576n);
    expect(result.record.originalSize.display).toBe('1.00 MiB');
    expect(result.record.deletionTime.ticks).toBe(134_065_306_790_000_000n);
    expect(result.record.deletionTime.display).toContain('2025-11-02');
    expect(result.record.path.full).toBe(PATH);
    expect(result.record.path.fileName).toBe('payroll-2025.xlsx');
    expect(result.record.path.directory).toBe('D:\\Shared');
    expect(result.record.path.driveLetter).toBe('D:');
    // The documented count includes the terminating NUL.
    expect(result.record.declaredPathChars).toBe(PATH.length + 1);
    expect(result.record.recordSize).toBe(bytes.length);
    expect(result.record.inputSize).toBe(bytes.length);
    expect(result.record.notes).toEqual([]);
  });

  it('recognizes a UNC original path and notes it', () => {
    const unc = buildV2('\\\\fileserver\\finance\\ledger.db', 512n, '2025-01-09T12:00:00Z');
    const result = parseRecycleBinIndex(unc);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.record.path.isUnc).toBe(true);
    expect(result.record.path.driveLetter).toBeNull();
    expect(result.record.notes.join(' ')).toContain('UNC network path');
  });

  it('reports a zero deletion timestamp as not-set instead of the 1601 epoch', () => {
    const zeroed = buildV2('C:\\tmp\\a.txt', 10n, '2025-01-01T00:00:00Z');
    new DataView(zeroed.buffer).setBigUint64(0x10, 0n, true);
    const result = parseRecycleBinIndex(zeroed);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.record.deletionTime.isZero).toBe(true);
    expect(result.record.deletionTime.display).not.toContain('1601');
    expect(result.record.notes.join(' ')).toContain('deletion timestamp field is zero');
  });

  it('notes trailing bytes beyond the declared record length', () => {
    const padded = new Uint8Array(bytes.length + 6);
    padded.set(bytes, 0);
    const result = parseRecycleBinIndex(padded);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.record.recordSize).toBe(bytes.length);
    expect(result.record.notes.join(' ')).toContain('6 byte(s) follow');
  });
});

describe('parseRecycleBinIndex — malformed input', () => {
  it('rejects a buffer too short to hold even a header', () => {
    const result = parseRecycleBinIndex(new Uint8Array(12));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('Too short');
  });

  it('rejects an undocumented version rather than force-fitting a layout', () => {
    const bytes = buildV2('C:\\a.txt', 1n, '2025-01-01T00:00:00Z');
    new DataView(bytes.buffer).setBigUint64(0, 7n, true);
    const result = parseRecycleBinIndex(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('Unrecognized $I format version 7');
  });

  it('rejects a version 2 length prefix that runs past the end of the data', () => {
    const bytes = buildV2('C:\\a.txt', 1n, '2025-01-01T00:00:00Z');
    new DataView(bytes.buffer).setUint32(0x18, 500, true);
    const result = parseRecycleBinIndex(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('Truncated version 2');
  });

  it('rejects a zero version 2 length prefix', () => {
    const bytes = buildV2('C:\\a.txt', 1n, '2025-01-01T00:00:00Z');
    new DataView(bytes.buffer).setUint32(0x18, 0, true);
    const result = parseRecycleBinIndex(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('path length field is 0');
  });

  it('rejects an implausibly large version 2 length prefix', () => {
    const bytes = buildV2('C:\\a.txt', 1n, '2025-01-01T00:00:00Z');
    new DataView(bytes.buffer).setUint32(0x18, 0xffffff, true);
    const result = parseRecycleBinIndex(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('beyond any valid Windows path');
  });
});

// ---------------------------------------------------------------------------
// The sample record the tool ships and the page prints as its worked example.
// These assertions are what stop a wrong printed value from shipping.
// ---------------------------------------------------------------------------

describe('SAMPLE_V2_HEX — the worked example printed on the page', () => {
  it('is valid hex that decodes to a 126-byte record', () => {
    const bytes = hexToBytes(SAMPLE_V2_HEX);
    expect(bytes).not.toBeNull();
    expect(bytes!.length).toBe(126);
  });

  it('parses to exactly the values the page prints', () => {
    const bytes = hexToBytes(SAMPLE_V2_HEX)!;
    const result = parseRecycleBinIndex(bytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const r = result.record;

    expect(r.version).toBe(2);
    expect(r.versionLabel).toBe('Version 2 — Windows 10 and 11');
    expect(r.originalSize.bytes).toBe(1_234_567n);
    expect(r.originalSize.display).toBe('1.18 MiB');
    expect(r.deletionTime.ticks).toBe(133_864_179_970_000_000n);
    expect(r.deletionTime.display).toBe('2025-03-14T09:26:37Z');
    expect(r.path.full).toBe('C:\\Users\\analyst\\Documents\\quarterly-report.xlsx');
    expect(r.path.directory).toBe('C:\\Users\\analyst\\Documents');
    expect(r.path.fileName).toBe('quarterly-report.xlsx');
    expect(r.path.extension).toBe('.xlsx');
    expect(r.path.driveLetter).toBe('C:');
    expect(r.declaredPathChars).toBe(49);
    expect(r.recordSize).toBe(126);
    expect(r.notes).toEqual([]);
  });

  it('matches the FILETIME independently derived from its UTC instant', () => {
    expect(filetimeFor('2025-03-14T09:26:37Z')).toBe(133_864_179_970_000_000n);
  });
});

// ---------------------------------------------------------------------------

describe('splitWindowsPath', () => {
  it('splits a drive-letter path', () => {
    const p = splitWindowsPath('C:\\Users\\bob\\report.docx');
    expect(p.driveLetter).toBe('C:');
    expect(p.directory).toBe('C:\\Users\\bob');
    expect(p.fileName).toBe('report.docx');
    expect(p.extension).toBe('.docx');
    expect(p.isUnc).toBe(false);
  });

  it('handles a UNC path with no drive letter', () => {
    const p = splitWindowsPath('\\\\srv01\\share\\notes.md');
    expect(p.isUnc).toBe(true);
    expect(p.driveLetter).toBeNull();
    expect(p.fileName).toBe('notes.md');
  });

  it('reports no extension for a name without one', () => {
    expect(splitWindowsPath('C:\\data\\LICENSE').extension).toBeNull();
  });

  it('does not treat a leading dot as an extension boundary', () => {
    const p = splitWindowsPath('C:\\Users\\bob\\.gitconfig');
    expect(p.fileName).toBe('.gitconfig');
    expect(p.extension).toBeNull();
  });

  it('handles a deleted folder (no trailing separator, no extension)', () => {
    const p = splitWindowsPath('C:\\Users\\bob\\Downloads');
    expect(p.fileName).toBe('Downloads');
    expect(p.extension).toBeNull();
    expect(p.directory).toBe('C:\\Users\\bob');
  });
});

describe('companionRName', () => {
  it('derives the paired $R content file from an $I metadata file name', () => {
    expect(companionRName('$IA1B2C3.xlsx')).toBe('$RA1B2C3.xlsx');
    expect(companionRName('$I9ZQ4WK.docx')).toBe('$R9ZQ4WK.docx');
  });

  it('accepts a lowercase $i prefix and keeps the rest verbatim', () => {
    expect(companionRName('$iA1B2C3.txt')).toBe('$RA1B2C3.txt');
  });

  it('returns null for a name that is not an $I file rather than guessing', () => {
    expect(companionRName('$RA1B2C3.xlsx')).toBeNull();
    expect(companionRName('notes.txt')).toBeNull();
    expect(companionRName('')).toBeNull();
  });
});

describe('formatByteSize', () => {
  it('renders small values as an exact byte count', () => {
    expect(formatByteSize(0n)).toBe('0 bytes');
    expect(formatByteSize(1n)).toBe('1 byte');
    expect(formatByteSize(1023n)).toBe('1023 bytes');
  });

  it('renders binary units with an unambiguous IEC label', () => {
    expect(formatByteSize(1024n)).toBe('1.00 KiB');
    expect(formatByteSize(1_048_576n)).toBe('1.00 MiB');
    expect(formatByteSize(1_073_741_824n)).toBe('1.00 GiB');
  });
});
