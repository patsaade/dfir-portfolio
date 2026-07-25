// Windows Prefetch (.pf) forensic parser — pure functions, no DOM
// dependency (unit tested directly in test/prefetch.test.ts, imported into
// the client bundle by PrefetchParser.astro so a chosen file is read locally
// via File#arrayBuffer() and never uploaded).
//
// SCOPE — read this before changing anything here.
//
// A Prefetch file is stored one of two completely different ways depending
// on the Windows version that wrote it:
//
//   * format versions 17 (Windows XP / Server 2003), 23 (Vista / 7) and
//     26 (Windows 8 / 8.1) are written UNCOMPRESSED — the "SCCA" file header
//     starts at byte 0 and every structure can be read straight off disk.
//   * format versions 30 (Windows 10) and 31 (Windows 11) are wrapped in a
//     "MAM" container and COMPRESSED with LZXPRESS Huffman (the algorithm
//     Windows exposes as COMPRESSION_FORMAT_XPRESS_HUFF to
//     RtlDecompressBufferEx). The SCCA header only exists *after* that
//     container is decompressed.
//
// This module implements the UNCOMPRESSED versions only (17 / 23 / 26).
// LZXPRESS Huffman decompression is DELIBERATELY NOT IMPLEMENTED: a
// subtly-wrong from-scratch Huffman decoder would not fail loudly, it would
// emit plausible-looking but wrong executable names, run counts and
// timestamps — far worse in a forensic context than plainly not supporting
// the format. parsePrefetch() therefore DETECTS the MAM container and
// returns a specific, friendly "not implemented here, use a tool that does"
// result (reason: 'compressed'), never a guess.
//
// Also explicitly out of scope (documented cuts, not silent gaps):
//   * Already-decompressed version 30/31 payloads. Two different file
//     information layouts are documented for version 30 (one 220 bytes with
//     the run count at relative offset 124, one 212 bytes with it at 116),
//     and the public format documentation gives no reliable way to tell them
//     apart from the header alone — picking the wrong one silently yields a
//     wrong run count, so this returns reason: 'unsupported-version' instead.
//   * The file metrics array, trace chains, filename string block and volume
//     information sections. Only the header plus the executable name, run
//     count and last-run FILETIME(s) are decoded — the fields that actually
//     carry the proof-of-execution story.
//   * Validating the stored prefetch hash. Windows has used several
//     different path-hashing functions across releases; recomputing one and
//     comparing would risk reporting a false "hash mismatch", so the stored
//     value is only ever displayed, never re-derived.
//
// Offsets below come from the libyal/libscca "Windows Prefetch File (PF)
// format" documentation (github.com/libyal/libscca) and agree with the
// Forensics Wiki's independent write-up (forensics.wiki). FILETIME
// conversion is never reimplemented here — every timestamp is handed to
// ../utils/timestamps.ts's own tested "filetime" format via formatById(),
// the same code path the Timestamp Converter and the MFT/USN analyzer use.

import { formatById, DEFAULT_CONTEXT } from './timestamps';

const FILETIME_FORMAT = formatById('filetime');
const ISO_FORMAT = formatById('iso8601');
if (!FILETIME_FORMAT || !ISO_FORMAT) {
  // Unreachable — both ids are registered in TIMESTAMP_FORMATS — but fail at
  // module load rather than silently mis-format a forensic timestamp.
  throw new Error('prefetch.ts: expected "filetime"/"iso8601" formats to be registered in timestamps.ts');
}

// ---------------------------------------------------------------------------
// Format version table — single source of truth for both the parser's own
// labels and the "which versions are supported" table on the tool's page
// (same role SIGMA_MODIFIERS plays in utils/sigma.ts).
// ---------------------------------------------------------------------------

export interface PrefetchVersionInfo {
  /** The 32-bit format version value stored at file offset 0. */
  version: number;
  /** Windows releases known to write this version. */
  windows: string;
  /** How the file is stored on disk. */
  storage: 'uncompressed' | 'mam-compressed';
  /** Whether this module can parse it. */
  supported: boolean;
  /** How many last-run FILETIME slots the file information structure holds. */
  runTimeSlots: number;
  note: string;
}

export const PREFETCH_VERSIONS: readonly PrefetchVersionInfo[] = [
  {
    version: 17,
    windows: 'Windows XP, Windows Server 2003',
    storage: 'uncompressed',
    supported: true,
    runTimeSlots: 1,
    note: 'One last-run timestamp only.',
  },
  {
    version: 23,
    windows: 'Windows Vista, Windows 7',
    storage: 'uncompressed',
    supported: true,
    runTimeSlots: 1,
    note: 'One last-run timestamp only.',
  },
  {
    version: 26,
    windows: 'Windows 8, Windows 8.1',
    storage: 'uncompressed',
    supported: true,
    runTimeSlots: 8,
    note: 'Eight last-run timestamp slots; unused slots are zero.',
  },
  {
    version: 30,
    windows: 'Windows 10',
    storage: 'mam-compressed',
    supported: false,
    runTimeSlots: 8,
    note: 'Wrapped in a MAM container, LZXPRESS Huffman compressed — decompression is not implemented here.',
  },
  {
    version: 31,
    windows: 'Windows 11',
    storage: 'mam-compressed',
    supported: false,
    runTimeSlots: 8,
    note: 'Wrapped in a MAM container, LZXPRESS Huffman compressed — decompression is not implemented here.',
  },
] as const;

export function versionInfo(version: number): PrefetchVersionInfo | null {
  return PREFETCH_VERSIONS.find((v) => v.version === version) ?? null;
}

// ---------------------------------------------------------------------------
// Demo samples — SYNTHETIC, hand-assembled byte sequences, not captured from
// any real machine. They exist so the tool's "Load sample" buttons and the
// worked example printed on the page come from the same single source of
// truth the unit tests assert against (test/prefetch.test.ts feeds these
// exact strings through parsePrefetch and checks every value the page
// claims), which is what makes it impossible to ship a wrong example.
// ---------------------------------------------------------------------------

/** A complete, valid, uncompressed format-version-23 (Vista / 7) Prefetch
 *  file: POWERSHELL.EXE, run count 4, last run 2024-03-12T09:41:07Z. */
export const SAMPLE_V23_HEX = `17 00 00 00 53 43 43 41 00 00 00 00 F0 00 00 00
50 00 4F 00 57 00 45 00 52 00 53 00 48 00 45 00
4C 00 4C 00 2E 00 45 00 58 00 45 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 4D 3C 2B 1A
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
80 FB 37 68 61 74 DA 01 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00`;

/** Just the 8-byte MAM container header a Windows 10/11 Prefetch file starts
 *  with (declaring a 3,078-byte uncompressed payload), plus placeholder
 *  bytes where the LZXPRESS Huffman stream would be. Enough to exercise the
 *  detection path — nothing here is decompressed, so the payload is inert. */
export const SAMPLE_MAM_HEX = `4D 41 4D 04 06 0C 00 00 00 00 00 00 00 00 00 00`;

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

/** File header: format version (0,4) + "SCCA" (4,4) + unknown (8,4) +
 *  file size (12,4) + executable filename (16,60) + prefetch hash (76,4) +
 *  unknown/flags (80,4). The file information structure follows at 84. */
const HEADER_SIZE = 84;
const OFF_FORMAT_VERSION = 0;
const OFF_SIGNATURE = 4;
const OFF_FILE_SIZE = 12;
const OFF_EXE_NAME = 16;
/** 60 bytes = 30 UTF-16 code units (29 characters + a terminating NUL). */
const EXE_NAME_CHARS = 30;
const OFF_PREFETCH_HASH = 76;

/** Per-version file information layout, as offsets RELATIVE to the start of
 *  the file information structure (i.e. relative to byte 84 of the file). */
interface FileInfoLayout {
  lastRunTimes: number;
  runTimeSlots: number;
  runCount: number;
}
const FILE_INFO_LAYOUTS: Record<number, FileInfoLayout> = {
  17: { lastRunTimes: 36, runTimeSlots: 1, runCount: 60 },
  23: { lastRunTimes: 44, runTimeSlots: 1, runCount: 68 },
  26: { lastRunTimes: 44, runTimeSlots: 8, runCount: 124 },
};

/** MAM container header: "MAM" + a 1-byte compression-method value, then the
 *  32-bit total uncompressed size. */
const MAM_SIGNATURE = [0x4d, 0x41, 0x4d]; // 'M','A','M'
const COMPRESSION_XPRESS_HUFF = 0x04;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/** A single last-run FILETIME slot. `ticks` is kept as a decimal STRING (not
 *  a bigint) so the whole result object stays JSON-serializable for the
 *  tool's "copy as JSON" button without a custom replacer. */
interface PrefetchRunTime {
  /** 0-based index into the file's last-run-time array. */
  slot: number;
  /** Raw 100-ns ticks since 1601-01-01, exactly as stored, in decimal. */
  ticks: string;
  /** ISO 8601 UTC rendering, or null when the raw value is 0 (unused slot). */
  iso: string | null;
}

interface PrefetchFile {
  formatVersion: number;
  /** e.g. "Windows Vista, Windows 7" — from PREFETCH_VERSIONS, never guessed. */
  windows: string;
  /** Executable name as stored in the header (Windows stores it uppercase). */
  executableName: string;
  /** Stored path hash, as an unsigned 32-bit value. */
  prefetchHash: number;
  /** Same value as 8 uppercase hex digits — the form used in the .pf filename. */
  prefetchHashHex: string;
  /** `<EXECUTABLE>-<HASH>.pf`, rebuilt from the two stored fields above. */
  expectedFileName: string;
  /** The total file length the header claims. */
  declaredFileSize: number;
  /** The number of bytes actually supplied to the parser. */
  actualFileSize: number;
  /** How many times Windows recorded this executable running. */
  runCount: number;
  /** Every last-run slot the version defines (1 for v17/v23, 8 for v26). */
  runTimes: PrefetchRunTime[];
  /** Slot 0 — the field libscca labels "last run time" in every version. */
  lastRunTime: PrefetchRunTime;
  /** Non-fatal observations worth surfacing (size mismatch, empty slots, …). */
  notes: string[];
}

/** MAM container header of a Windows 10/11 compressed Prefetch file. Parsed
 *  and reported even though the payload itself is not decompressed. */
interface PrefetchMamHeader {
  /** Always 'MAM' when this branch is taken. */
  signature: string;
  /** The byte following "MAM" — 0x04 for LZXPRESS Huffman. */
  compressionMethodByte: number;
  /** Human label for that byte, or an explicit "unrecognized" note. */
  compressionMethod: string;
  /** Total uncompressed payload size the container declares, in bytes. */
  uncompressedSize: number;
}

export type PrefetchParseResult =
  | { ok: true; data: PrefetchFile }
  | { ok: false; reason: 'compressed'; error: string; mam: PrefetchMamHeader }
  | { ok: false; reason: 'unsupported-version'; error: string; formatVersion: number }
  | { ok: false; reason: 'invalid'; error: string };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Convert raw FILETIME ticks to a PrefetchRunTime. A stored value of 0 means
 *  "this slot was never used" — reported as iso: null, never rendered as the
 *  literal 1601-01-01 epoch instant. */
function toRunTime(slot: number, ticks: bigint): PrefetchRunTime {
  if (ticks === 0n) return { slot, ticks: '0', iso: null };
  const ns = FILETIME_FORMAT!.parse(ticks.toString(), DEFAULT_CONTEXT);
  const iso = ns !== null ? ISO_FORMAT!.format(ns, DEFAULT_CONTEXT) : '';
  return { slot, ticks: ticks.toString(), iso: iso || null };
}

/** Read a fixed-width UTF-16LE string, stopping at the first NUL. */
function readUtf16(view: DataView, offset: number, maxChars: number): string {
  let out = '';
  for (let i = 0; i < maxChars; i++) {
    const code = view.getUint16(offset + i * 2, true);
    if (code === 0) break;
    out += String.fromCharCode(code);
  }
  return out;
}

function startsWithMam(bytes: Uint8Array): boolean {
  return bytes.length >= MAM_SIGNATURE.length && MAM_SIGNATURE.every((b, i) => bytes[i] === b);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Parse the raw bytes of a Windows Prefetch (.pf) file.
 *
 * Detection order matters and is unambiguous: a valid SCCA file stores its
 * format version at offset 0, so its first byte is 0x11/0x17/0x1A/0x1E/0x1F —
 * never 'M' (0x4D). Checking for the MAM container first therefore cannot
 * misclassify an uncompressed file.
 */
export function parsePrefetch(bytes: Uint8Array): PrefetchParseResult {
  if (bytes.length < 8) {
    return {
      ok: false,
      reason: 'invalid',
      error: `Only ${bytes.length} byte(s) supplied — far too short to be a Prefetch file (the header alone is ${HEADER_SIZE} bytes).`,
    };
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  // --- Windows 10/11: MAM-compressed container ---------------------------
  if (startsWithMam(bytes)) {
    const methodByte = bytes[3];
    const mam: PrefetchMamHeader = {
      signature: 'MAM',
      compressionMethodByte: methodByte,
      compressionMethod:
        methodByte === COMPRESSION_XPRESS_HUFF
          ? 'LZXPRESS Huffman (COMPRESSION_FORMAT_XPRESS_HUFF)'
          : `unrecognized compression method byte (0x${methodByte.toString(16).toUpperCase().padStart(2, '0')})`,
      uncompressedSize: view.getUint32(4, true),
    };
    return {
      ok: false,
      reason: 'compressed',
      error:
        'This is a compressed Windows 10/11 Prefetch file (MAM container, LZXPRESS Huffman). ' +
        'Decompression is deliberately not implemented in this browser tool — decompress it first with ' +
        "Eric Zimmerman's PECmd or libyal's sccainfo, then the decompressed SCCA data can be read.",
      mam,
    };
  }

  // --- Uncompressed: validate the SCCA signature --------------------------
  const signature = String.fromCharCode(bytes[OFF_SIGNATURE], bytes[OFF_SIGNATURE + 1], bytes[OFF_SIGNATURE + 2], bytes[OFF_SIGNATURE + 3]);
  if (signature !== 'SCCA') {
    return {
      ok: false,
      reason: 'invalid',
      error: `Not a Prefetch file — expected the "SCCA" signature at offset 4, found "${signature.replace(/[^\x20-\x7e]/g, '.')}". A Windows 10/11 file would start with "MAM" instead.`,
    };
  }

  const formatVersion = view.getUint32(OFF_FORMAT_VERSION, true);
  const layout = FILE_INFO_LAYOUTS[formatVersion];
  if (!layout) {
    const known = versionInfo(formatVersion);
    const error = known
      ? `Format version ${formatVersion} (${known.windows}) is not supported by this tool. ` +
        'Its file information structure has more than one documented layout, and the public format ' +
        'documentation gives no reliable way to tell them apart from the header alone — guessing would ' +
        'produce a wrong run count, so nothing is reported rather than something wrong.'
      : `Unrecognized Prefetch format version ${formatVersion}. This tool supports versions 17, 23 and 26 (the uncompressed Windows XP through 8.1 formats).`;
    return { ok: false, reason: 'unsupported-version', error, formatVersion };
  }

  // Every field this parser reads must fit; the run count sits last.
  const runCountOffset = HEADER_SIZE + layout.runCount;
  const needed = runCountOffset + 4;
  if (bytes.length < needed) {
    return {
      ok: false,
      reason: 'invalid',
      error: `Truncated version ${formatVersion} Prefetch file — the run count field ends at byte ${needed}, but only ${bytes.length} byte(s) were supplied.`,
    };
  }

  const info = versionInfo(formatVersion)!;
  const executableName = readUtf16(view, OFF_EXE_NAME, EXE_NAME_CHARS);
  const prefetchHash = view.getUint32(OFF_PREFETCH_HASH, true);
  const prefetchHashHex = prefetchHash.toString(16).toUpperCase().padStart(8, '0');
  const declaredFileSize = view.getUint32(OFF_FILE_SIZE, true);
  const runCount = view.getUint32(runCountOffset, true);

  const runTimes: PrefetchRunTime[] = [];
  for (let i = 0; i < layout.runTimeSlots; i++) {
    const offset = HEADER_SIZE + layout.lastRunTimes + i * 8;
    runTimes.push(toRunTime(i, view.getBigUint64(offset, true)));
  }

  const notes: string[] = [];
  if (declaredFileSize !== bytes.length) {
    notes.push(
      `The header declares a total file size of ${declaredFileSize} bytes, but ${bytes.length} byte(s) were supplied — ` +
        'the file may be truncated, carved, or padded.',
    );
  }
  if (!executableName) {
    notes.push('The executable name field is empty — unusual for a genuine Prefetch file.');
  }
  if (runCount === 0) {
    notes.push('The run count is 0. Windows resets this field in some situations (for example after a Prefetch file is rebuilt), so it does not by itself mean the program never ran.');
  }
  if (layout.runTimeSlots > 1) {
    const used = runTimes.filter((t) => t.iso !== null).length;
    notes.push(
      `${used} of the ${layout.runTimeSlots} last-run timestamp slots are populated; the rest are zero (never used). ` +
        'Slot 0 is the last run time — it occupies the same field offset that version 23 uses for its single last-run value. ' +
        'The published format documentation does not state an ordering for slots 1-7, so they are labelled by slot index here rather than assumed to be strictly most-recent-first.',
    );
  }

  return {
    ok: true,
    data: {
      formatVersion,
      windows: info.windows,
      executableName,
      prefetchHash,
      prefetchHashHex,
      expectedFileName: `${executableName}-${prefetchHashHex}.pf`,
      declaredFileSize,
      actualFileSize: bytes.length,
      runCount,
      runTimes,
      lastRunTime: runTimes[0],
      notes,
    },
  };
}
