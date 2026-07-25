// Windows Recycle Bin $I metadata-file parser — decodes one $I<######>.<ext>
// record from `C:\$Recycle.Bin\<SID>\` entirely client-side, as pure
// DOM-free functions (unit-tested in test/recycleBin.test.ts, imported into
// the client bundle by RecycleBinParser.astro). Nothing parsed here is ever
// transmitted anywhere — the caller reads a local file via
// File#arrayBuffer() (or a pasted hex string) and hands the raw bytes
// straight to parseRecycleBinIndex().
//
// SCOPE — explicitly bounded, same discipline as ../utils/sigma.ts and
// ../utils/lnk.ts. What IS implemented:
//
//   * Format version 1 ($I as written by Windows Vista / 7 / 8 / 8.1)
//   * Format version 2 ($I as written by Windows 10 / 11)
//
// Byte layout, per Joachim Metz's libyal/dtformats "Windows Recycle.Bin file
// formats" documentation (the byte-level reference this implements), with
// the version-1 fixed record size and the version-2 length-prefix behavior
// independently corroborated by Abel Cheung's rifiuti2 parser source and by
// published named forensic write-ups (see the page's own "Other resources"
// section for the links):
//
//   Version 1 — fixed 544-byte record
//     0x00  8  format version (little-endian, value 1)
//     0x08  8  original file size in bytes (little-endian)
//     0x10  8  deletion time, Windows FILETIME (little-endian, UTC)
//     0x18  520 original full path, UTF-16LE, NUL-terminated and then
//              zero-padded out to 260 UTF-16 characters (MAX_PATH)
//
//   Version 2 — variable-length record
//     0x00  8  format version (little-endian, value 2)
//     0x08  8  original file size in bytes (little-endian)
//     0x10  8  deletion time, Windows FILETIME (little-endian, UTC)
//     0x18  4  original path length, in UTF-16 CHARACTERS, including the
//              terminating NUL (so the string occupies count * 2 bytes)
//     0x1C  *  original full path, UTF-16LE, NUL-terminated
//
// What is deliberately NOT implemented, and is reported rather than guessed:
//
//   * Any other value in the version field. A record whose first 8 bytes are
//     neither 1 nor 2 fails with the observed value named, rather than being
//     force-fit into one of the two documented layouts. (Some published
//     write-ups describe encrypted/other $I first-byte values; no
//     authoritative layout for those was located, so this tool says so
//     instead of inventing one.)
//   * The $R companion file. $R holds the deleted file's actual CONTENT and
//     has no header of its own — it is simply the original bytes under a new
//     name — so there is nothing to parse. companionRName() below only
//     derives what the paired $R file should be CALLED.
//   * The Recycle Bin's own `desktop.ini`, and the pre-Vista INFO2 index
//     format (a single index file for all deleted items, a genuinely
//     different structure) — both out of scope.
//
// Every multi-byte field is read little-endian through a small bounds-checked
// cursor (same shape as ../utils/mftUsn.ts / ../utils/pe.ts): a truncated or
// malformed record never throws out of this module, it returns a specific
// error message instead. FILETIME conversion is never reimplemented here —
// the raw tick count is handed to ../utils/timestamps.ts's own tested
// "filetime" TimestampFormat via formatById(), the same code path the
// Timestamp Converter tool uses. hexToBytes is likewise reused from
// ../utils/mftUsn.ts rather than duplicated.

import { formatById, DEFAULT_CONTEXT } from './timestamps';
import { hexToBytes } from './mftUsn';

export { hexToBytes };

const FILETIME_FORMAT = formatById('filetime');
const ISO_FORMAT = formatById('iso8601');
if (!FILETIME_FORMAT || !ISO_FORMAT) {
  // Unreachable — both ids are registered in TIMESTAMP_FORMATS — but fail
  // loudly at module load rather than silently mis-format a deletion time.
  throw new Error('recycleBin.ts: expected "filetime"/"iso8601" formats to be registered in timestamps.ts');
}

// ---------------------------------------------------------------------------
// Documented layout constants (see the header comment for the source)
// ---------------------------------------------------------------------------

/** Offset of the 8-byte little-endian original-file-size field (both versions). */
const SIZE_OFFSET = 0x08;
/** Offset of the 8-byte little-endian deletion FILETIME (both versions). */
const FILETIME_OFFSET = 0x10;
/** Version 1: offset where the fixed-size UTF-16LE original path begins. */
const V1_PATH_OFFSET = 0x18;
/** Version 1: the path field is a fixed 260 UTF-16 characters (MAX_PATH). */
const V1_PATH_CHARS = 260;
/** Version 1 records are a fixed 544 bytes: 24 header + 260 * 2 path bytes. */
export const V1_RECORD_SIZE = V1_PATH_OFFSET + V1_PATH_CHARS * 2; // 544
/** Version 2: offset of the 4-byte little-endian path length, in characters. */
const V2_NAME_LENGTH_OFFSET = 0x18;
/** Version 2: offset where the variable-length UTF-16LE original path begins. */
const V2_PATH_OFFSET = 0x1c;

/** Upper bound on a version-2 declared path length before it's treated as
 *  corrupt rather than parsed. Windows paths can exceed the legacy 260-char
 *  MAX_PATH when long-path support is on, so this is set far above any
 *  plausible real path (the NT namespace limit is 32,767 characters) — it
 *  exists only to reject a garbage length field, not to enforce MAX_PATH. */
const MAX_PLAUSIBLE_PATH_CHARS = 32_767;

// ---------------------------------------------------------------------------
// Bounds-checked cursor
// ---------------------------------------------------------------------------

class BoundsError extends Error {}

class Cursor {
  private readonly view: DataView;
  private readonly len: number;
  constructor(bytes: Uint8Array) {
    // Honour byteOffset/byteLength so a Uint8Array that's a *view* into a
    // larger buffer (e.g. a record sliced out of a whole-image read) is read
    // from its own start, not the underlying buffer's.
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.len = bytes.byteLength;
  }

  private need(offset: number, size: number, what: string): void {
    if (offset < 0 || size < 0 || offset + size > this.len) {
      throw new BoundsError(
        `Truncated or malformed $I record — expected to read ${what} at offset ${offset}, but only ${this.len} bytes were supplied.`,
      );
    }
  }

  u32(offset: number, what: string): number {
    this.need(offset, 4, what);
    return this.view.getUint32(offset, true);
  }

  u64(offset: number, what: string): bigint {
    this.need(offset, 8, what);
    return this.view.getBigUint64(offset, true);
  }

  /** Decode `chars` UTF-16LE code units starting at `offset`, stopping at the
   *  first NUL (the documented end-of-string character). Returns the decoded
   *  text plus whether a NUL was actually found inside the range. */
  utf16le(offset: number, chars: number, what: string): { text: string; terminated: boolean } {
    this.need(offset, chars * 2, what);
    const units: number[] = [];
    let terminated = false;
    for (let i = 0; i < chars; i++) {
      const unit = this.view.getUint16(offset + i * 2, true);
      if (unit === 0) {
        terminated = true;
        break;
      }
      units.push(unit);
    }
    // Chunked so a very long path can't blow the argument limit of apply().
    let text = '';
    for (let i = 0; i < units.length; i += 4096) {
      text += String.fromCharCode.apply(null, units.slice(i, i + 4096));
    }
    return { text, terminated };
  }
}

// ---------------------------------------------------------------------------
// Field value shapes
// ---------------------------------------------------------------------------

interface DeletionTime {
  /** Raw 100-ns ticks since 1601-01-01T00:00:00Z, exactly as stored on disk. */
  ticks: bigint;
  /** Canonical nanoseconds since the Unix epoch, or null if unrepresentable. */
  ns: bigint | null;
  /** ISO 8601 UTC rendering, or an explicit note when the raw value can't be one. */
  display: string;
  /** True when the raw field is 0 — "not set", never rendered as the 1601 epoch. */
  isZero: boolean;
}

interface OriginalSize {
  /** Exact byte count as stored in the record. */
  bytes: bigint;
  /** Rounded binary-unit rendering (KiB/MiB/...), for display alongside `bytes`. */
  display: string;
}

/** The parts of the recorded original path, split for display. Every field is
 *  derived from the recorded string itself — nothing is inferred about a
 *  volume or user that the record doesn't actually contain. */
export interface PathParts {
  /** The full recorded path, exactly as decoded. */
  full: string;
  /** Everything before the final separator, or '' when the path has none. */
  directory: string;
  /** The final path component (the deleted item's own name). */
  fileName: string;
  /** Lower-cased extension including the dot, or null when there isn't one. */
  extension: string | null;
  /** e.g. 'C:' for a drive-letter path, else null (UNC paths have no letter). */
  driveLetter: string | null;
  /** True for a `\\server\share\...` UNC path. */
  isUnc: boolean;
}

interface RecycleBinRecord {
  /** 1 or 2 — the documented format version, straight from the record. */
  version: 1 | 2;
  /** Human label naming the Windows releases that write this version. */
  versionLabel: string;
  originalSize: OriginalSize;
  deletionTime: DeletionTime;
  path: PathParts;
  /** Version 2 only: the declared path length in UTF-16 characters (the
   *  terminating NUL is included in this count). Null for version 1, whose
   *  path field is a fixed size with no length prefix. */
  declaredPathChars: number | null;
  /** How many bytes this record occupies per its own layout — always 544 for
   *  version 1; 28 + declaredPathChars * 2 for version 2. */
  recordSize: number;
  /** How many bytes the caller actually supplied. */
  inputSize: number;
  /** Factual observations about this specific record. Never speculation —
   *  each note states something directly readable from the bytes. */
  notes: string[];
}

export type RecycleBinParseResult = { ok: true; record: RecycleBinRecord } | { ok: false; error: string };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BINARY_UNITS = ['bytes', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'] as const;

/** Render an exact byte count as a rounded binary-unit string. Kept separate
 *  from the exact `bytes` value so the UI can always show both — a rounded
 *  size is for reading, the exact count is what gets recorded in notes. */
export function formatByteSize(bytes: bigint): string {
  if (bytes < 0n) return `${bytes} bytes`;
  if (bytes < 1024n) return `${bytes} ${bytes === 1n ? 'byte' : 'bytes'}`;
  let value = Number(bytes);
  let unit = 0;
  while (value >= 1024 && unit < BINARY_UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value < 10 ? 2 : 1)} ${BINARY_UNITS[unit]}`;
}

/** Convert raw FILETIME ticks into a displayable deletion time, reusing
 *  timestamps.ts's own tested "filetime" epoch math (never reimplemented). */
function readDeletionTime(ticks: bigint): DeletionTime {
  if (ticks === 0n) {
    return { ticks, ns: null, display: '(not set — the field is zero)', isZero: true };
  }
  const ns = FILETIME_FORMAT!.parse(ticks.toString(), DEFAULT_CONTEXT);
  const iso = ns !== null ? ISO_FORMAT!.format(ns, DEFAULT_CONTEXT) : '';
  return {
    ticks,
    ns,
    display: iso || `(ticks: ${ticks} — outside the representable date range)`,
    isZero: false,
  };
}

/** Split a recorded Windows path into its display parts. Purely string work
 *  on what the record actually stored — no filesystem access, no guessing. */
export function splitWindowsPath(full: string): PathParts {
  const isUnc = full.startsWith('\\\\');
  const driveMatch = /^([A-Za-z]:)(?=\\|$)/.exec(full);
  const sep = full.lastIndexOf('\\');
  const directory = sep >= 0 ? full.slice(0, sep) : '';
  const fileName = sep >= 0 ? full.slice(sep + 1) : full;
  const dot = fileName.lastIndexOf('.');
  const extension = dot > 0 ? fileName.slice(dot).toLowerCase() : null;
  return {
    full,
    directory,
    fileName,
    extension,
    driveLetter: driveMatch ? driveMatch[1].toUpperCase() : null,
    isUnc,
  };
}

/** Given the name of an `$I` metadata file, derive the name its paired `$R`
 *  content file must have: the two differ only in that single letter, sharing
 *  the same random identifier and the original extension. Returns null for a
 *  name that isn't an `$I` file, rather than guessing. */
export function companionRName(iFileName: string): string | null {
  const trimmed = iFileName.trim();
  if (!/^\$I/i.test(trimmed)) return null;
  return '$R' + trimmed.slice(2);
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

const VERSION_LABELS: Record<1 | 2, string> = {
  1: 'Version 1 — Windows Vista, 7, 8 and 8.1',
  2: 'Version 2 — Windows 10 and 11',
};

/**
 * Parse one `$I` Recycle Bin metadata file. `bytes` should be the whole file.
 * Returns a specific, human-readable error rather than throwing on anything
 * malformed, truncated, or written in a version this tool doesn't document.
 */
export function parseRecycleBinIndex(bytes: Uint8Array): RecycleBinParseResult {
  try {
    const len = bytes.length;
    if (len < V2_PATH_OFFSET) {
      return {
        ok: false,
        error: `Too short to be a $I record — ${len} byte${len === 1 ? '' : 's'} supplied, but at least ${V2_PATH_OFFSET} bytes are needed to identify the version and reach any path data.`,
      };
    }

    const c = new Cursor(bytes);
    const rawVersion = c.u64(0, 'the format version field');
    if (rawVersion !== 1n && rawVersion !== 2n) {
      return {
        ok: false,
        error: `Unrecognized $I format version ${rawVersion} (0x${rawVersion.toString(16)}). Only version 1 (Windows Vista/7/8/8.1) and version 2 (Windows 10/11) have a documented layout, so this record is not being force-fit into either.`,
      };
    }
    const version = Number(rawVersion) as 1 | 2;

    const sizeBytes = c.u64(SIZE_OFFSET, 'the original file size');
    const deletionTime = readDeletionTime(c.u64(FILETIME_OFFSET, 'the deletion timestamp'));

    const notes: string[] = [];
    let pathText: string;
    let terminated: boolean;
    let declaredPathChars: number | null;
    let recordSize: number;

    if (version === 1) {
      declaredPathChars = null;
      recordSize = V1_RECORD_SIZE;
      if (len !== V1_RECORD_SIZE) {
        notes.push(
          `Version 1 records are a fixed ${V1_RECORD_SIZE} bytes, but ${len} bytes were supplied — the path field is being read only as far as the data allows.`,
        );
      }
      // Read as much of the fixed 260-character path field as actually exists.
      const availableChars = Math.min(V1_PATH_CHARS, Math.max(0, Math.floor((len - V1_PATH_OFFSET) / 2)));
      if (availableChars === 0) {
        return {
          ok: false,
          error: `Truncated version 1 $I record — the original-path field starts at offset ${V1_PATH_OFFSET}, but only ${len} bytes were supplied.`,
        };
      }
      const decoded = c.utf16le(V1_PATH_OFFSET, availableChars, 'the original path');
      pathText = decoded.text;
      terminated = decoded.terminated;
    } else {
      const declared = c.u32(V2_NAME_LENGTH_OFFSET, 'the path length field');
      if (declared === 0) {
        return {
          ok: false,
          error: 'Malformed version 2 $I record — the path length field is 0, but the documented count always includes at least the terminating null character.',
        };
      }
      if (declared > MAX_PLAUSIBLE_PATH_CHARS) {
        return {
          ok: false,
          error: `Malformed version 2 $I record — the path length field claims ${declared.toLocaleString('en-US')} UTF-16 characters, far beyond any valid Windows path. Treating this as corrupt rather than reading ${(declared * 2).toLocaleString('en-US')} bytes.`,
        };
      }
      const needed = V2_PATH_OFFSET + declared * 2;
      if (needed > len) {
        return {
          ok: false,
          error: `Truncated version 2 $I record — the path length field declares ${declared} UTF-16 characters (${declared * 2} bytes from offset ${V2_PATH_OFFSET}, so ${needed} bytes total), but only ${len} bytes were supplied.`,
        };
      }
      declaredPathChars = declared;
      recordSize = needed;
      const decoded = c.utf16le(V2_PATH_OFFSET, declared, 'the original path');
      pathText = decoded.text;
      terminated = decoded.terminated;
      if (!terminated) {
        notes.push(
          'The declared path length does not end in a UTF-16 null terminator — the documented character count includes one, so this record may be malformed or hand-edited.',
        );
      }
      if (len > needed) {
        notes.push(`${len - needed} byte(s) follow the end of this record and were not parsed.`);
      }
    }

    if (version === 1 && !terminated) {
      notes.push(
        'The version 1 path field has no null terminator within the data supplied — the recorded path may be truncated.',
      );
    }
    if (pathText.length === 0) {
      notes.push('The recorded original path is empty.');
    }
    if (deletionTime.isZero) {
      notes.push('The deletion timestamp field is zero, so no deletion time was recorded in this record.');
    }
    if (sizeBytes === 0n) {
      notes.push('The recorded original size is 0 bytes.');
    }

    const path = splitWindowsPath(pathText);
    if (path.isUnc) {
      notes.push('The recorded path is a UNC network path, so the deleted item did not live on a local drive letter.');
    }

    return {
      ok: true,
      record: {
        version,
        versionLabel: VERSION_LABELS[version],
        originalSize: { bytes: sizeBytes, display: formatByteSize(sizeBytes) },
        deletionTime,
        path,
        declaredPathChars,
        recordSize,
        inputSize: len,
        notes,
      },
    };
  } catch (err) {
    if (err instanceof BoundsError) return { ok: false, error: err.message };
    return { ok: false, error: 'Could not parse these bytes as a $I record.' };
  }
}

// ---------------------------------------------------------------------------
// Sample record
//
// A synthetic, hand-built version 2 record used by the tool's "Load sample"
// button and printed as the worked example on the page. It is NOT a captured
// real artifact — it was constructed byte-by-byte against the layout above:
//   version 2, original size 1,234,567 bytes, deletion FILETIME
//   133864179970000000, path length 49 characters (48 + terminator), and the
//   UTF-16LE path "C:\Users\analyst\Documents\quarterly-report.xlsx".
// test/recycleBin.test.ts asserts that parsing this exact constant produces
// exactly the values the page prints, so a wrong example cannot ship.
// ---------------------------------------------------------------------------

export const SAMPLE_V2_HEX =
  '020000000000000087d612000000000080c4422fc394db013100000043003a005c00' +
  '550073006500720073005c0061006e0061006c007900730074005c0044006f006300' +
  '75006d0065006e00740073005c0071007500610072007400650072006c0079002d00' +
  '7200650070006f00720074002e0078006c00730078000000';
