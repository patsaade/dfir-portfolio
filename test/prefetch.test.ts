// Windows Prefetch (.pf) parser tests — src/utils/prefetch.ts.
//
// Every fixture here is hand-assembled byte-by-byte at the offsets taken from
// the libyal/libscca "Windows Prefetch File (PF) format" documentation, so a
// wrong offset in the parser fails loudly instead of quietly producing a
// plausible-looking timestamp. The two SAMPLE_* constants the tool's own
// "Load sample" buttons use are fed through the real parser here as well, so
// the worked example printed on /tools/prefetch-parser/ can never drift from
// what the code actually returns.
import { describe, it, expect } from 'vitest';
import {
  parsePrefetch,
  versionInfo,
  PREFETCH_VERSIONS,
  SAMPLE_V23_HEX,
  SAMPLE_MAM_HEX,
} from '../src/utils/prefetch';

// ---------------------------------------------------------------------------
// Fixture builders — the layout under test, written out explicitly.
// File header: version(0,4) "SCCA"(4,4) unknown(8,4) fileSize(12,4)
//              exeName(16,60) hash(76,4) unknown(80,4)  => 84 bytes
// File information starts at 84. Relative offsets by version:
//   v17: lastRunTime +36 (1 slot), runCount +60,  struct 68 bytes
//   v23: lastRunTime +44 (1 slot), runCount +68,  struct 156 bytes
//   v26: lastRunTimes +44 (8 slots), runCount +124, struct 220 bytes
// ---------------------------------------------------------------------------

const HEADER = 84;
const STRUCT_SIZE: Record<number, number> = { 17: 68, 23: 156, 26: 220 };
const LAST_RUN_REL: Record<number, number> = { 17: 36, 23: 44, 26: 44 };
const RUN_COUNT_REL: Record<number, number> = { 17: 60, 23: 68, 26: 124 };

/** Windows FILETIME (100-ns ticks since 1601-01-01) for an ISO instant. */
function filetime(iso: string): bigint {
  return (BigInt(Date.parse(iso)) / 1000n + 11_644_473_600n) * 10_000_000n;
}

interface FixtureOptions {
  version: number;
  name?: string;
  hash?: number;
  runCount?: number;
  runTimes?: bigint[];
  /** Override the declared file-size field (defaults to the real length). */
  declaredSize?: number;
  signature?: string;
  /** Truncate the finished buffer to this many bytes. */
  truncateTo?: number;
}

function buildPrefetch(opts: FixtureOptions): Uint8Array {
  const {
    version,
    name = 'NOTEPAD.EXE',
    hash = 0x9b3f10c2,
    runCount = 1,
    runTimes = [],
    signature = 'SCCA',
  } = opts;
  const total = HEADER + STRUCT_SIZE[version];
  const bytes = new Uint8Array(total);
  const dv = new DataView(bytes.buffer);

  dv.setUint32(0, version, true);
  for (let i = 0; i < 4; i++) bytes[4 + i] = signature.charCodeAt(i);
  dv.setUint32(8, 0, true);
  dv.setUint32(12, opts.declaredSize ?? total, true);
  for (let i = 0; i < name.length; i++) dv.setUint16(16 + i * 2, name.charCodeAt(i), true);
  dv.setUint32(76, hash, true);
  dv.setUint32(80, 0, true);

  runTimes.forEach((ticks, i) => {
    dv.setBigUint64(HEADER + LAST_RUN_REL[version] + i * 8, ticks, true);
  });
  dv.setUint32(HEADER + RUN_COUNT_REL[version], runCount, true);

  return opts.truncateTo !== undefined ? bytes.slice(0, opts.truncateTo) : bytes;
}

function hexToBytes(hex: string): Uint8Array {
  const cleaned = hex.replace(/\s+/g, '');
  const out = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ---------------------------------------------------------------------------

describe('PREFETCH_VERSIONS table', () => {
  it('marks exactly the uncompressed versions (17/23/26) as supported', () => {
    const supported = PREFETCH_VERSIONS.filter((v) => v.supported).map((v) => v.version);
    expect(supported).toEqual([17, 23, 26]);
  });

  it('marks the Windows 10/11 versions as MAM-compressed and unsupported', () => {
    for (const version of [30, 31]) {
      const info = versionInfo(version)!;
      expect(info.storage).toBe('mam-compressed');
      expect(info.supported).toBe(false);
    }
  });

  it('has no duplicate version numbers', () => {
    const versions = PREFETCH_VERSIONS.map((v) => v.version);
    expect(new Set(versions).size).toBe(versions.length);
  });

  it('returns null for a version it does not know', () => {
    expect(versionInfo(99)).toBeNull();
  });
});

describe('parsePrefetch — version 17 (Windows XP / Server 2003)', () => {
  const bytes = buildPrefetch({
    version: 17,
    name: 'CMD.EXE',
    hash: 0x0a1b2c3d,
    runCount: 12,
    runTimes: [filetime('2006-11-02T18:05:44Z')],
  });

  it('parses the header, run count and single last-run timestamp', () => {
    const result = parsePrefetch(bytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.formatVersion).toBe(17);
    expect(result.data.windows).toBe('Windows XP, Windows Server 2003');
    expect(result.data.executableName).toBe('CMD.EXE');
    expect(result.data.prefetchHashHex).toBe('0A1B2C3D');
    expect(result.data.expectedFileName).toBe('CMD.EXE-0A1B2C3D.pf');
    expect(result.data.runCount).toBe(12);
    expect(result.data.runTimes).toHaveLength(1);
    expect(result.data.lastRunTime.iso).toBe('2006-11-02T18:05:44Z');
  });

  it('reports no notes for a well-formed file', () => {
    const result = parsePrefetch(bytes);
    expect(result.ok && result.data.notes).toEqual([]);
  });
});

describe('parsePrefetch — version 23 (Windows Vista / 7)', () => {
  it('reads the last-run time from offset 44 of the file information structure', () => {
    const bytes = buildPrefetch({
      version: 23,
      name: 'RUNDLL32.EXE',
      runCount: 3,
      runTimes: [filetime('2011-08-19T07:12:00Z')],
    });
    const result = parsePrefetch(bytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.windows).toBe('Windows Vista, Windows 7');
    expect(result.data.executableName).toBe('RUNDLL32.EXE');
    expect(result.data.runCount).toBe(3);
    expect(result.data.lastRunTime.iso).toBe('2011-08-19T07:12:00Z');
    expect(result.data.lastRunTime.ticks).toBe(filetime('2011-08-19T07:12:00Z').toString());
  });

  it('would NOT decode correctly at version 17 offsets (guards against an offset mix-up)', () => {
    // Same bytes, but the version field says 17 — the v17 layout reads the
    // run count from a different place, so the value must not still be 3.
    const bytes = buildPrefetch({
      version: 23,
      runCount: 3,
      runTimes: [filetime('2011-08-19T07:12:00Z')],
    });
    new DataView(bytes.buffer).setUint32(0, 17, true);
    const result = parsePrefetch(bytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.runCount).not.toBe(3);
    expect(result.data.lastRunTime.iso).not.toBe('2011-08-19T07:12:00Z');
  });
});

describe('parsePrefetch — version 26 (Windows 8 / 8.1)', () => {
  const runs = [
    filetime('2014-05-01T10:00:00Z'),
    filetime('2014-04-30T09:30:00Z'),
    filetime('2014-04-29T08:15:00Z'),
  ];
  const bytes = buildPrefetch({
    version: 26,
    name: 'SVCHOST.EXE',
    runCount: 41,
    runTimes: runs,
  });

  it('exposes all eight last-run slots, with unused slots reported as null', () => {
    const result = parsePrefetch(bytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.runTimes).toHaveLength(8);
    expect(result.data.runTimes.slice(0, 3).map((t) => t.iso)).toEqual([
      '2014-05-01T10:00:00Z',
      '2014-04-30T09:30:00Z',
      '2014-04-29T08:15:00Z',
    ]);
    expect(result.data.runTimes.slice(3).every((t) => t.iso === null && t.ticks === '0')).toBe(true);
    expect(result.data.runTimes.map((t) => t.slot)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
  });

  it('reads the run count from offset 124 of the file information structure', () => {
    const result = parsePrefetch(bytes);
    expect(result.ok && result.data.runCount).toBe(41);
  });

  it('notes how many of the eight slots are populated', () => {
    const result = parsePrefetch(bytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.notes.some((n) => n.startsWith('3 of the 8 last-run timestamp slots are populated'))).toBe(true);
  });
});

describe('parsePrefetch — Windows 10/11 MAM container (the documented limitation)', () => {
  it('detects the MAM signature and returns the friendly unsupported result', () => {
    const result = parsePrefetch(hexToBytes(SAMPLE_MAM_HEX));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('compressed');
    if (result.reason !== 'compressed') return;
    expect(result.mam.signature).toBe('MAM');
    expect(result.mam.compressionMethodByte).toBe(0x04);
    expect(result.mam.compressionMethod).toBe('LZXPRESS Huffman (COMPRESSION_FORMAT_XPRESS_HUFF)');
    expect(result.mam.uncompressedSize).toBe(3078);
    expect(result.error).toContain('not implemented');
    expect(result.error).toContain('PECmd');
  });

  it('labels an unrecognized compression-method byte instead of assuming Xpress Huffman', () => {
    const bytes = new Uint8Array([0x4d, 0x41, 0x4d, 0x09, 0x10, 0x00, 0x00, 0x00]);
    const result = parsePrefetch(bytes);
    expect(result.ok).toBe(false);
    if (result.ok || result.reason !== 'compressed') return;
    expect(result.mam.compressionMethod).toContain('unrecognized');
    expect(result.mam.compressionMethod).toContain('0x09');
  });

  it('never misreads an uncompressed file as MAM (version byte 0x11/0x17/0x1A is never 0x4D)', () => {
    for (const version of [17, 23, 26]) {
      const result = parsePrefetch(buildPrefetch({ version }));
      expect(result.ok).toBe(true);
    }
  });
});

describe('parsePrefetch — rejection paths', () => {
  it('rejects a file with the wrong signature', () => {
    const result = parsePrefetch(buildPrefetch({ version: 23, signature: 'ABCD' }));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('invalid');
    expect(result.error).toContain('SCCA');
  });

  it('rejects a version 30/31 SCCA payload rather than guessing its layout', () => {
    for (const version of [30, 31]) {
      const bytes = buildPrefetch({ version: 26 });
      new DataView(bytes.buffer).setUint32(0, version, true);
      const result = parsePrefetch(bytes);
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.reason).toBe('unsupported-version');
      if (result.reason !== 'unsupported-version') return;
      expect(result.formatVersion).toBe(version);
      expect(result.error).toContain('not supported');
    }
  });

  it('rejects an unrecognized format version', () => {
    const bytes = buildPrefetch({ version: 26 });
    new DataView(bytes.buffer).setUint32(0, 42, true);
    const result = parsePrefetch(bytes);
    expect(result.ok).toBe(false);
    if (result.ok || result.reason !== 'unsupported-version') return;
    expect(result.error).toContain('17, 23 and 26');
  });

  it('rejects a truncated file instead of reading past the end', () => {
    const result = parsePrefetch(buildPrefetch({ version: 26, truncateTo: 150 }));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('invalid');
    expect(result.error).toContain('Truncated');
  });

  it('rejects input far too short to be a Prefetch file', () => {
    const result = parsePrefetch(new Uint8Array([0x17, 0x00]));
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe('invalid');
  });
});

describe('parsePrefetch — non-fatal notes', () => {
  it('flags a declared file size that disagrees with the bytes supplied', () => {
    const result = parsePrefetch(buildPrefetch({ version: 23, declaredSize: 999999 }));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.declaredFileSize).toBe(999999);
    expect(result.data.actualFileSize).toBe(240);
    expect(result.data.notes.some((n) => n.includes('truncated, carved, or padded'))).toBe(true);
  });

  it('flags an empty executable-name field', () => {
    const result = parsePrefetch(buildPrefetch({ version: 23, name: '' }));
    expect(result.ok && result.data.notes.some((n) => n.includes('executable name field is empty'))).toBe(true);
  });

  it('explains a run count of 0 rather than implying the program never ran', () => {
    const result = parsePrefetch(buildPrefetch({ version: 23, runCount: 0 }));
    expect(result.ok && result.data.notes.some((n) => n.includes('run count is 0'))).toBe(true);
  });

  it('reports an unused last-run slot as null rather than the 1601 epoch', () => {
    const result = parsePrefetch(buildPrefetch({ version: 23, runTimes: [0n] }));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.lastRunTime.iso).toBeNull();
    expect(result.data.lastRunTime.ticks).toBe('0');
  });
});

// ---------------------------------------------------------------------------
// The worked example the page prints. Every value asserted below is rendered
// verbatim in src/pages/tools/prefetch-parser.astro's "Worked example" table,
// so a wrong example cannot ship.
// ---------------------------------------------------------------------------

describe('SAMPLE_V23_HEX — the page’s worked example', () => {
  const result = parsePrefetch(hexToBytes(SAMPLE_V23_HEX));

  it('parses cleanly', () => {
    expect(result.ok).toBe(true);
  });

  it('decodes exactly the values the page claims', () => {
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.formatVersion).toBe(23);
    expect(result.data.windows).toBe('Windows Vista, Windows 7');
    expect(result.data.executableName).toBe('POWERSHELL.EXE');
    expect(result.data.prefetchHashHex).toBe('1A2B3C4D');
    expect(result.data.expectedFileName).toBe('POWERSHELL.EXE-1A2B3C4D.pf');
    expect(result.data.runCount).toBe(4);
    expect(result.data.lastRunTime.iso).toBe('2024-03-12T09:41:07Z');
    expect(result.data.declaredFileSize).toBe(240);
    expect(result.data.actualFileSize).toBe(240);
    expect(result.data.notes).toEqual([]);
  });
});
