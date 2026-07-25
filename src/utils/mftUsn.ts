// MFT FILE record & USN journal record parser for the MFT & USN Journal
// Timestomp Analyzer tool — pure functions, no DOM dependency, so this is
// unit-tested directly (test/mftUsn.test.ts) and imported into the client
// bundle (MftUsnAnalyzer.astro) for parsing a single, already-carved-out
// record entirely in the browser. Nothing parsed here is ever transmitted
// anywhere — the caller reads a local file via File#arrayBuffer() (or a
// pasted hex string) and hands the raw bytes straight to parseMftRecord()/
// parseUsnRecord().
//
// Scope is deliberately narrow: ONE already-carved-out record at a time, as
// if extracted by a real tool first (MFTECmd, a hex editor, a $UsnJrnl
// carver, ...). Bulk/whole-$MFT parsing and $LogFile transaction-log parsing
// are both out of scope — this never walks a $MFT file or a journal stream
// looking for record boundaries itself.
//
// Every multi-byte field is read little-endian, explicitly, via a small
// bounds-checked Cursor over a DataView (same pattern as ../utils/pe.ts) — a
// truncated or malformed record never throws an uncaught exception; every
// failure path returns a specific, friendly *ParseResult error message
// instead. FILETIME conversion is never reimplemented here — every Windows
// timestamp field is handed to ../utils/timestamps.ts's own "filetime"
// TimestampFormat (parse: raw 100-ns-tick decimal string -> canonical ns
// since the Unix epoch; format: canonical ns -> a human string) via
// formatById(), the same tested code path the Timestamp Converter tool uses.

import { formatById, DEFAULT_CONTEXT } from './timestamps';

const FILETIME_FORMAT = formatById('filetime');
const ISO_FORMAT = formatById('iso8601');
if (!FILETIME_FORMAT || !ISO_FORMAT) {
  // Should be unreachable — both ids are registered in TIMESTAMP_FORMATS —
  // but fail loudly at module load rather than silently mis-format dates.
  throw new Error('mftUsn.ts: expected "filetime"/"iso8601" formats to be registered in timestamps.ts');
}

// ---------------------------------------------------------------------------
// Shared: FILETIME rendering
// ---------------------------------------------------------------------------

interface FileTimeValue {
  /** Raw 100-ns ticks since 1601-01-01T00:00:00Z, exactly as stored on disk. */
  ticks: bigint;
  /** Canonical nanoseconds since the Unix epoch, or null if unrepresentable. */
  ns: bigint | null;
  /** Human-readable ISO 8601 UTC rendering, or a fallback note if out of range. */
  display: string;
}

/** Convert raw FILETIME ticks (100-ns intervals since 1601-01-01) into a
 *  displayable value, reusing timestamps.ts's own tested "filetime" format
 *  for the epoch math and "iso8601" for the human rendering — never
 *  reimplemented here. */
function formatFiletime(ticks: bigint): FileTimeValue {
  const ns = FILETIME_FORMAT!.parse(ticks.toString(), DEFAULT_CONTEXT);
  const iso = ns !== null ? ISO_FORMAT!.format(ns, DEFAULT_CONTEXT) : '';
  return {
    ticks,
    ns,
    display: iso || `(ticks: ${ticks} — outside the representable date range)`,
  };
}

/** Decode an NTFS file reference (used for $MFT base-record links, USN
 *  FileReferenceNumber/ParentFileReferenceNumber): the low 48 bits are the
 *  MFT record (segment) number, the high 16 bits are that record slot's
 *  reuse/sequence number. */
export interface FileReference {
  raw: bigint;
  recordNumber: bigint;
  sequenceNumber: number;
}
export function decodeFileReference(raw: bigint): FileReference {
  return {
    raw,
    recordNumber: raw & 0xffffffffffffn,
    sequenceNumber: Number((raw >> 48n) & 0xffffn),
  };
}

// ---------------------------------------------------------------------------
// hex-paste parsing shared by both record types
// ---------------------------------------------------------------------------

/** Parse a pasted hex string into raw bytes. Accepts the common ways hex
 *  gets pasted out of a hex editor or forensic tool: "0x" prefixes,
 *  whitespace/newlines, and comma separators. Returns null (not a throw) for
 *  anything that isn't a clean, even-length run of hex digits once those are
 *  stripped. */
export function hexToBytes(input: string): Uint8Array | null {
  const cleaned = input.replace(/0x/gi, '').replace(/[\s,]+/g, '');
  if (cleaned.length === 0 || cleaned.length % 2 !== 0) return null;
  if (!/^[0-9a-fA-F]+$/.test(cleaned)) return null;
  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Bounds-checked cursor (same shape as ../utils/pe.ts's Cursor) — an
// out-of-range read throws a BoundsError with a specific message that every
// top-level parse function below catches and turns into a friendly
// *ParseResult failure instead of an uncaught exception.
// ---------------------------------------------------------------------------

class BoundsError extends Error {}

class Cursor {
  constructor(
    private readonly view: DataView,
    private readonly len: number,
  ) {}

  private need(offset: number, size: number, what: string): void {
    if (offset < 0 || size < 0 || offset + size > this.len) {
      throw new BoundsError(
        `Truncated or malformed record — expected to read ${what} at offset ${offset}, but the record is only ${this.len} bytes.`,
      );
    }
  }

  u8(offset: number, what = 'a byte'): number {
    this.need(offset, 1, what);
    return this.view.getUint8(offset);
  }
  u16(offset: number, what = 'a 16-bit field'): number {
    this.need(offset, 2, what);
    return this.view.getUint16(offset, true);
  }
  u32(offset: number, what = 'a 32-bit field'): number {
    this.need(offset, 4, what);
    return this.view.getUint32(offset, true);
  }
  u64(offset: number, what = 'a 64-bit field'): bigint {
    this.need(offset, 8, what);
    return this.view.getBigUint64(offset, true);
  }
  i64(offset: number, what = 'a 64-bit field'): bigint {
    this.need(offset, 8, what);
    return this.view.getBigInt64(offset, true);
  }
  /** UTF-16LE string, `charCount` UTF-16 code units long. */
  utf16(offset: number, charCount: number, what = 'a UTF-16 string'): string {
    this.need(offset, charCount * 2, what);
    let out = '';
    for (let i = 0; i < charCount; i++) {
      out += String.fromCharCode(this.view.getUint16(offset + i * 2, true));
    }
    return out;
  }
}

// ---------------------------------------------------------------------------
// MFT FILE record
// ---------------------------------------------------------------------------

const MFT_SECTOR_SIZE = 512;

export type MftFixupResult =
  | { ok: true; data: Uint8Array; usn: number; sectorsChecked: number }
  | { ok: false; error: string };

/**
 * Apply the NTFS per-sector "fixup" (Update Sequence Array) correction to a
 * raw FILE record BEFORE any attribute data is read.
 *
 * Layout: the record header's UpdateSequenceArrayOffset points at a small
 * array of 2-byte USHORTs: [USN, original_last_2_bytes_of_sector_0,
 * original_last_2_bytes_of_sector_1, ...] — one fixup entry per 512-byte
 * sector the record spans. At write time NTFS overwrites the LAST 2 bytes of
 * every sector with the USN (as a torn-write detector) and stashes the real
 * bytes that belonged there in this array. To recover the true attribute
 * bytes: for each sector, verify its last 2 bytes on disk equal the stored
 * USN (if they don't, the write was torn mid-transfer and the record is
 * corrupt), then replace those 2 bytes with the matching fixup-array entry.
 * Returns a NEW Uint8Array with the correction applied — the input buffer is
 * never mutated, and nothing downstream may read attribute bytes from the
 * uncorrected buffer.
 */
export function applyMftFixup(bytes: Uint8Array): MftFixupResult {
  if (bytes.length < 8) {
    return { ok: false, error: 'Record is too short to contain an Update Sequence Array header.' };
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const usaOffset = view.getUint16(4, true);
  const usaSize = view.getUint16(6, true);

  if (usaSize < 1) {
    return { ok: false, error: 'Update Sequence Array size is 0 — no Update Sequence Number to validate against; malformed record.' };
  }
  if (usaOffset + usaSize * 2 > bytes.length) {
    return { ok: false, error: 'Update Sequence Array runs past the end of the record — truncated or malformed data.' };
  }

  const usn = view.getUint16(usaOffset, true);
  const sectorCount = usaSize - 1;
  const out = bytes.slice(); // never mutate the caller's buffer
  const outView = new DataView(out.buffer, out.byteOffset, out.byteLength);

  for (let s = 0; s < sectorCount; s++) {
    const sectorEnd = (s + 1) * MFT_SECTOR_SIZE;
    if (sectorEnd > out.length) {
      return {
        ok: false,
        error: `Record is shorter than the ${sectorCount} sector(s) implied by its Update Sequence Array (needs at least ${sectorEnd} bytes, has ${out.length}).`,
      };
    }
    const checkOffset = sectorEnd - 2;
    const storedMarker = outView.getUint16(checkOffset, true);
    if (storedMarker !== usn) {
      return {
        ok: false,
        error:
          `Fixup check failed at sector ${s + 1} of ${sectorCount} (bytes ${checkOffset}-${checkOffset + 1}): ` +
          `the sector's last 2 bytes (0x${storedMarker.toString(16).padStart(4, '0')}) don't match the record's ` +
          `Update Sequence Number (0x${usn.toString(16).padStart(4, '0')}). This means the sectors were torn ` +
          `during an incomplete write — the record is corrupt and its attribute data can't be trusted.`,
      };
    }
    // The replacement value is read from the ORIGINAL (unmodified) buffer's
    // USA — `out` is never the source for these reads, only the destination.
    const original = view.getUint16(usaOffset + 2 + s * 2, true);
    outView.setUint16(checkOffset, original, true);
  }

  return { ok: true, data: out, usn, sectorsChecked: sectorCount };
}

interface MftHeaderInfo {
  signature: 'FILE';
  sequenceNumber: number;
  hardLinkCount: number;
  inUse: boolean;
  isDirectory: boolean;
  usedSize: number;
  allocatedSize: number;
  baseFileRecord: FileReference;
  mftRecordNumber: number | null;
}

interface StandardInformation {
  created: FileTimeValue;
  modified: FileTimeValue;
  mftModified: FileTimeValue;
  accessed: FileTimeValue;
  fileAttributes: number;
}

interface FileNameAttribute {
  parentDirectory: FileReference;
  created: FileTimeValue;
  modified: FileTimeValue;
  mftModified: FileTimeValue;
  accessed: FileTimeValue;
  allocatedSize: bigint;
  realSize: bigint;
  flags: number;
  fileName: string;
  namespace: number;
  namespaceLabel: string;
}

const FILE_NAME_NAMESPACES: Record<number, string> = {
  0: 'POSIX',
  1: 'Win32',
  2: 'DOS (8.3)',
  3: 'Win32 & DOS',
};

type TimestampField = 'created' | 'modified' | 'mftModified' | 'accessed';

interface TimestampComparison {
  field: TimestampField;
  label: string;
  standardInformation: FileTimeValue;
  fileName: FileTimeValue;
  /** Absolute difference in seconds, or null when either side is unrepresentable. */
  deltaSeconds: number | null;
  /** True when the two sides disagree by more than MISMATCH_THRESHOLD_SECONDS — the classic timestomping indicator. */
  mismatch: boolean;
}

/** A $SI/$FN pair disagreeing by more than this is flagged as a mismatch —
 *  "a couple of seconds", generous enough to absorb normal sub-second/timer
 *  rounding noise between the two attributes NTFS itself writes together on
 *  a legitimate create, while still catching a genuinely altered value. */
export const MISMATCH_THRESHOLD_SECONDS = 2;

const TIMESTAMP_FIELDS: { field: TimestampField; label: string }[] = [
  { field: 'created', label: 'Created' },
  { field: 'modified', label: 'Modified' },
  { field: 'mftModified', label: 'MFT Modified' },
  { field: 'accessed', label: 'Accessed' },
];

function compareTimestamps(si: StandardInformation, fn: FileNameAttribute): TimestampComparison[] {
  return TIMESTAMP_FIELDS.map(({ field, label }) => {
    const siVal = si[field];
    const fnVal = fn[field];
    let deltaSeconds: number | null = null;
    if (siVal.ns !== null && fnVal.ns !== null) {
      const deltaNs = siVal.ns > fnVal.ns ? siVal.ns - fnVal.ns : fnVal.ns - siVal.ns;
      deltaSeconds = Number(deltaNs) / 1e9;
    }
    return {
      field,
      label,
      standardInformation: siVal,
      fileName: fnVal,
      deltaSeconds,
      mismatch: deltaSeconds !== null && deltaSeconds > MISMATCH_THRESHOLD_SECONDS,
    };
  });
}

interface ParsedMftRecord {
  header: MftHeaderInfo;
  fixup: { usn: number; sectorsChecked: number };
  standardInformation: StandardInformation | null;
  fileName: FileNameAttribute | null;
  comparisons: TimestampComparison[];
  timestompDetected: boolean;
  notes: string[];
}

export type MftParseResult = { ok: true; record: ParsedMftRecord } | { ok: false; error: string };

interface RawAttribute {
  type: number;
  offset: number;
  length: number;
  nonResident: boolean;
}

/** Walk the attribute list starting at `start`, stopping at the 0xFFFFFFFF
 *  end marker or `boundEnd`, whichever comes first. */
function walkAttributes(c: Cursor, start: number, boundEnd: number): RawAttribute[] {
  const attrs: RawAttribute[] = [];
  let offset = start;
  while (offset + 4 <= boundEnd) {
    const type = c.u32(offset, 'an attribute type code');
    if (type === 0xffffffff) break; // end-of-attributes marker
    if (offset + 8 > boundEnd) break;
    const length = c.u32(offset + 4, 'an attribute length');
    if (length < 8 || offset + length > boundEnd) break; // malformed — stop rather than loop forever
    const nonResident = c.u8(offset + 8, 'the resident/non-resident flag') !== 0;
    attrs.push({ type, offset, length, nonResident });
    offset += length;
  }
  return attrs;
}

/** Resident attributes only (both $STANDARD_INFORMATION and $FILE_NAME are
 *  always resident in every real-world NTFS record) — returns the byte range
 *  of the attribute's content within the record. */
function residentContentRange(c: Cursor, attrOffset: number): { start: number; length: number } {
  const length = c.u32(attrOffset + 16, "an attribute's resident content length");
  const contentOffset = c.u16(attrOffset + 20, "an attribute's resident content offset");
  return { start: attrOffset + contentOffset, length };
}

function parseStandardInformation(c: Cursor, attr: RawAttribute): StandardInformation | null {
  if (attr.nonResident) return null;
  const { start, length } = residentContentRange(c, attr.offset);
  if (length < 32) return null; // not enough room for all 4 FILETIMEs
  return {
    created: formatFiletime(c.u64(start + 0, '$STANDARD_INFORMATION Created time')),
    modified: formatFiletime(c.u64(start + 8, '$STANDARD_INFORMATION Modified time')),
    mftModified: formatFiletime(c.u64(start + 16, '$STANDARD_INFORMATION MFT Modified time')),
    accessed: formatFiletime(c.u64(start + 24, '$STANDARD_INFORMATION Accessed time')),
    fileAttributes: length >= 36 ? c.u32(start + 32, '$STANDARD_INFORMATION file attributes') : 0,
  };
}

function parseFileName(c: Cursor, attr: RawAttribute): FileNameAttribute | null {
  if (attr.nonResident) return null;
  const { start, length } = residentContentRange(c, attr.offset);
  if (length < 66) return null; // not enough room for the fixed portion + name-length byte
  const nameLenChars = c.u8(start + 64, '$FILE_NAME name length');
  const namespace = c.u8(start + 65, '$FILE_NAME namespace');
  const nameByteLen = nameLenChars * 2;
  const fileName = length >= 66 + nameByteLen ? c.utf16(start + 66, nameLenChars, '$FILE_NAME file name') : '(name unavailable — attribute truncated)';
  return {
    parentDirectory: decodeFileReference(c.u64(start + 0, '$FILE_NAME parent directory reference')),
    created: formatFiletime(c.u64(start + 8, '$FILE_NAME Created time')),
    modified: formatFiletime(c.u64(start + 16, '$FILE_NAME Modified time')),
    mftModified: formatFiletime(c.u64(start + 24, '$FILE_NAME MFT Modified time')),
    accessed: formatFiletime(c.u64(start + 32, '$FILE_NAME Accessed time')),
    allocatedSize: c.u64(start + 40, '$FILE_NAME allocated size'),
    realSize: c.u64(start + 48, '$FILE_NAME real size'),
    flags: c.u32(start + 56, '$FILE_NAME flags'),
    fileName,
    namespace,
    namespaceLabel: FILE_NAME_NAMESPACES[namespace] ?? `Unknown (${namespace})`,
  };
}

/**
 * Parse a single, already-carved-out 1024-byte (or otherwise fixed-size) MFT
 * FILE record. Verifies the "FILE" magic, applies the Update Sequence Array
 * fixup BEFORE reading any attribute, then extracts $STANDARD_INFORMATION
 * and $FILE_NAME and flags any of the 4 timestamp pairs that disagree by
 * more than MISMATCH_THRESHOLD_SECONDS — the classic timestomping /
 * anti-forensics indicator.
 */
export function parseMftRecord(bytes: Uint8Array): MftParseResult {
  try {
    if (bytes.length < 48) {
      return { ok: false, error: 'Record is too short to contain a valid MFT FILE record header (needs at least 48 bytes).' };
    }
    const magic = String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]);
    if (magic === 'BAAD') {
      return {
        ok: false,
        error:
          '"BAAD" magic found instead of "FILE" — NTFS itself writes this when a record fails its own fixup check. ' +
          'This is a corrupted or unrepaired MFT record; its attribute data cannot be trusted or parsed further.',
      };
    }
    if (magic !== 'FILE') {
      const shown = Array.from(bytes.slice(0, 4))
        .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.'))
        .join('');
      return { ok: false, error: `Not a valid MFT FILE record — expected the "FILE" magic at offset 0, found "${shown}".` };
    }

    const fixup = applyMftFixup(bytes);
    if (!fixup.ok) return { ok: false, error: fixup.error };

    // Every read from here on is against the FIXED-UP buffer — never the
    // original — so attribute content always reflects the true on-disk bytes.
    const fixedBytes = fixup.data;
    const view = new DataView(fixedBytes.buffer, fixedBytes.byteOffset, fixedBytes.byteLength);
    const c = new Cursor(view, fixedBytes.length);

    const sequenceNumber = c.u16(16, 'the record sequence number');
    const hardLinkCount = c.u16(18, 'the hard link count');
    const firstAttributeOffset = c.u16(20, 'the first attribute offset');
    const flags = c.u16(22, 'the record flags');
    const usedSize = c.u32(24, 'the record used size');
    const allocatedSize = c.u32(28, 'the record allocated size');
    const baseFileRecord = decodeFileReference(c.u64(32, 'the base file record reference'));
    const mftRecordNumber = fixedBytes.length >= 48 ? c.u32(44, 'the MFT record number') : null;

    const boundEnd = usedSize > 0 && usedSize <= fixedBytes.length ? usedSize : fixedBytes.length;
    const attrs = walkAttributes(c, firstAttributeOffset, boundEnd);

    const siAttr = attrs.find((a) => a.type === 0x10);
    const fnAttr = attrs.find((a) => a.type === 0x30);
    const notes: string[] = [];

    const standardInformation = siAttr ? parseStandardInformation(c, siAttr) : null;
    if (siAttr && !standardInformation) notes.push('$STANDARD_INFORMATION was found but is non-resident or truncated — its timestamps could not be read.');
    if (!siAttr) notes.push('No $STANDARD_INFORMATION (type 0x10) attribute found in this record.');

    const fileName = fnAttr ? parseFileName(c, fnAttr) : null;
    if (fnAttr && !fileName) notes.push('$FILE_NAME was found but is non-resident or truncated — its timestamps could not be read.');
    if (!fnAttr) notes.push('No $FILE_NAME (type 0x30) attribute found in this record.');

    const comparisons = standardInformation && fileName ? compareTimestamps(standardInformation, fileName) : [];
    const timestompDetected = comparisons.some((cmp) => cmp.mismatch);

    return {
      ok: true,
      record: {
        header: {
          signature: 'FILE',
          sequenceNumber,
          hardLinkCount,
          inUse: (flags & 0x0001) !== 0,
          isDirectory: (flags & 0x0002) !== 0,
          usedSize,
          allocatedSize,
          baseFileRecord,
          mftRecordNumber,
        },
        fixup: { usn: fixup.usn, sectorsChecked: fixup.sectorsChecked },
        standardInformation,
        fileName,
        comparisons,
        timestompDetected,
        notes,
      },
    };
  } catch (e) {
    if (e instanceof BoundsError) return { ok: false, error: e.message };
    return { ok: false, error: 'Not a valid MFT FILE record — the record is malformed in a way this parser could not recover from.' };
  }
}

// ---------------------------------------------------------------------------
// USN_RECORD_V2
// ---------------------------------------------------------------------------

// Reason bitmask flags — from Microsoft's own USN_RECORD_V2 documentation
// (Win32 winioctl.h USN_REASON_* constants, "USN_RECORD_V2 structure" on
// Microsoft Learn). Every flag below is real and independently verifiable
// against that header; this list is the full canonical set as of Windows 10/11.
export interface UsnReasonFlag {
  bit: number;
  name: string;
  description: string;
}

export const USN_REASON_FLAGS: UsnReasonFlag[] = [
  { bit: 0x00000001, name: 'DATA_OVERWRITE', description: 'The data in the file or directory was overwritten.' },
  { bit: 0x00000002, name: 'DATA_EXTEND', description: 'The file or directory was extended (data added).' },
  { bit: 0x00000004, name: 'DATA_TRUNCATION', description: 'The data in the file or directory was truncated.' },
  { bit: 0x00000010, name: 'NAMED_DATA_OVERWRITE', description: 'The data in an alternate data stream was overwritten.' },
  { bit: 0x00000020, name: 'NAMED_DATA_EXTEND', description: 'An alternate data stream was extended (data added).' },
  { bit: 0x00000040, name: 'NAMED_DATA_TRUNCATION', description: 'An alternate data stream was truncated.' },
  { bit: 0x00000100, name: 'FILE_CREATE', description: 'The file or directory was created for the first time.' },
  { bit: 0x00000200, name: 'FILE_DELETE', description: 'The file or directory was deleted.' },
  { bit: 0x00000400, name: 'EA_CHANGE', description: 'The extended attributes for the file or directory changed.' },
  { bit: 0x00000800, name: 'SECURITY_CHANGE', description: 'The access rights (security descriptor) for the file or directory changed.' },
  { bit: 0x00001000, name: 'RENAME_OLD_NAME', description: 'The file or directory was renamed — this is the record for the old name.' },
  { bit: 0x00002000, name: 'RENAME_NEW_NAME', description: 'The file or directory was renamed — this is the record for the new name.' },
  { bit: 0x00004000, name: 'INDEXABLE_CHANGE', description: 'A user changed whether the file or directory is indexed for content searching.' },
  { bit: 0x00008000, name: 'BASIC_INFO_CHANGE', description: 'A change was made to attributes or timestamps (creation, last access, last write).' },
  { bit: 0x00010000, name: 'HARD_LINK_CHANGE', description: 'A hard link was added to or removed from the file or directory.' },
  { bit: 0x00020000, name: 'COMPRESSION_CHANGE', description: "The compression state of the file or directory changed." },
  { bit: 0x00040000, name: 'ENCRYPTION_CHANGE', description: 'The file or directory was encrypted or decrypted.' },
  { bit: 0x00080000, name: 'OBJECT_ID_CHANGE', description: 'The object identifier for the file or directory changed.' },
  { bit: 0x00100000, name: 'REPARSE_POINT_CHANGE', description: 'The reparse point for the file or directory changed, or a reparse point was added or removed.' },
  { bit: 0x00200000, name: 'STREAM_CHANGE', description: 'A named stream was added to or removed from the file, or a named stream was renamed.' },
  { bit: 0x00400000, name: 'TRANSACTED_CHANGE', description: 'The given stream change was made as part of a transaction.' },
  { bit: 0x00800000, name: 'INTEGRITY_CHANGE', description: 'The integrity state of the file or directory changed (ReFS/Storage Spaces).' },
  { bit: 0x80000000, name: 'CLOSE', description: 'The handle used to make changes was closed — the reasons in this record are final for that handle.' },
];

/** Decode a Reason bitmask into every flag it sets, in the order above.
 *  Uses `& !== 0` (never `=== bit`) so the top bit (0x80000000) still
 *  decodes correctly despite JS bitwise operators working on signed Int32. */
export function decodeUsnReason(reason: number): UsnReasonFlag[] {
  return USN_REASON_FLAGS.filter((f) => (reason & f.bit) !== 0);
}

interface ParsedUsnRecord {
  recordLength: number;
  majorVersion: number;
  minorVersion: number;
  fileReferenceNumber: FileReference;
  parentFileReferenceNumber: FileReference;
  usn: bigint;
  timeStamp: FileTimeValue;
  reason: number;
  reasonFlags: UsnReasonFlag[];
  sourceInfo: number;
  securityId: number;
  fileAttributes: number;
  fileName: string;
}

export type UsnParseResult = { ok: true; record: ParsedUsnRecord } | { ok: false; error: string };

// Fixed portion of USN_RECORD_V2 up to (not including) the variable-length
// FileName — RecordLength(4) MajorVersion(2) MinorVersion(2)
// FileReferenceNumber(8) ParentFileReferenceNumber(8) Usn(8) TimeStamp(8)
// Reason(4) SourceInfo(4) SecurityId(4) FileAttributes(4) FileNameLength(2)
// FileNameOffset(2) = 60 bytes.
const USN_V2_HEADER_SIZE = 60;

/**
 * Parse a single USN_RECORD_V2 (the only USN journal record version this
 * tool supports — V3/V4 use 128-bit object IDs and a different layout).
 * FileNameLength is a BYTE count, not a character count — the filename is
 * decoded as FileNameLength/2 UTF-16LE code units, never FileNameLength
 * characters.
 */
export function parseUsnRecord(bytes: Uint8Array): UsnParseResult {
  try {
    if (bytes.length < USN_V2_HEADER_SIZE) {
      return {
        ok: false,
        error: `Buffer is too short to be a USN_RECORD_V2 — needs at least ${USN_V2_HEADER_SIZE} bytes for the fixed header, got ${bytes.length}.`,
      };
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const c = new Cursor(view, bytes.length);

    const recordLength = c.u32(0, 'RecordLength');
    const majorVersion = c.u16(4, 'MajorVersion');
    const minorVersion = c.u16(6, 'MinorVersion');
    if (majorVersion !== 2) {
      return {
        ok: false,
        error: `MajorVersion is ${majorVersion}, not 2 — this parser only supports USN_RECORD_V2 (V3/V4 use 128-bit file IDs and a different record layout).`,
      };
    }

    const fileReferenceNumber = decodeFileReference(c.u64(8, 'FileReferenceNumber'));
    const parentFileReferenceNumber = decodeFileReference(c.u64(16, 'ParentFileReferenceNumber'));
    const usn = c.i64(24, 'Usn');
    // TimeStamp is documented as "the time this change occurred, in the
    // format of a FILETIME structure" — a FILETIME is a 64-bit unsigned tick
    // count, so this must be read unsigned like every other FILETIME field
    // in this file (the four MFT $SI/$FN timestamps), even though the Win32
    // LARGE_INTEGER container type it's declared as is nominally signed.
    const timeStampTicks = c.u64(32, 'TimeStamp');
    const reason = c.u32(40, 'Reason');
    const sourceInfo = c.u32(44, 'SourceInfo');
    const securityId = c.u32(48, 'SecurityId');
    const fileAttributes = c.u32(52, 'FileAttributes');
    const fileNameLength = c.u16(56, 'FileNameLength'); // BYTES, not characters
    const fileNameOffset = c.u16(58, 'FileNameOffset');

    if (fileNameOffset + fileNameLength > bytes.length) {
      return {
        ok: false,
        error: `FileName extends past the end of the buffer (offset ${fileNameOffset} + length ${fileNameLength} bytes > ${bytes.length} bytes available) — truncated or malformed record.`,
      };
    }
    const fileName = c.utf16(fileNameOffset, Math.floor(fileNameLength / 2), 'FileName');

    return {
      ok: true,
      record: {
        recordLength,
        majorVersion,
        minorVersion,
        fileReferenceNumber,
        parentFileReferenceNumber,
        usn,
        timeStamp: formatFiletime(timeStampTicks),
        reason,
        reasonFlags: decodeUsnReason(reason),
        sourceInfo,
        securityId,
        fileAttributes,
        fileName,
      },
    };
  } catch (e) {
    if (e instanceof BoundsError) return { ok: false, error: e.message };
    return { ok: false, error: 'Not a valid USN_RECORD_V2 — the record is malformed in a way this parser could not recover from.' };
  }
}
