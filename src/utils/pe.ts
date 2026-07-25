// PE (Portable Executable) header parser for the PE Header Explorer tool —
// pure functions, no DOM dependency, so this is unit-tested directly
// (test/pe.test.ts) and imported into the client bundle (PeExplorer.astro)
// for parsing a locally-chosen EXE/DLL entirely in the browser. Nothing
// parsed here is ever transmitted anywhere — the caller reads the file via
// File#arrayBuffer() and hands the raw bytes straight to parsePe().
//
// Covers: the DOS header (MZ magic + e_lfanew), the PE signature + COFF File
// Header, the Optional Header (PE32 vs PE32+, entry point, image base, data
// directories), the Section Table, the Import Directory Table (DLL names +
// imported function names, falling back to "ordinal N" for by-ordinal
// imports), the Export Table when present, the Resource Directory tree
// (Type -> Name/ID -> Language, walked structurally — see
// parseResourceDirectory below), and a computed imphash (the Mandiant-style
// MD5 of the lowercased, comma-joined "dllbasename.function" import list, in
// import-table order — see computeImphash below). MD5 itself is never
// reimplemented here; it's imported from ../utils/hashes.
//
// The Resource Directory walk is structure-only, the same scope discipline
// already applied to imports/exports/sections above: every resource entry's
// type, name-or-ID, language, and size is surfaced, but no resource's actual
// content (icon bitmaps, version-string values, manifest XML text, dialog
// templates, ...) is ever read or rendered.
//
// Deliberately out of scope (the caller surfaces this as a plain note, never
// a silent no-op): disassembly, resource *content* rendering (see above),
// .NET/CLR metadata (a CLR binary is still a normal PE underneath — its
// DOS/COFF/Optional headers, sections, and native import/export tables all
// parse the same as any other PE; only the COR20/.NET-specific metadata
// inside the CLR runtime header's data is skipped), and digital-signature
// verification.
//
// Every multi-byte field is read little-endian, explicitly, via a small
// bounds-checked Cursor over a DataView — a truncated or malformed file never
// throws an uncaught exception; every failure path returns a specific,
// friendly PeParseResult error message instead.

import { md5Hex } from './hashes';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

interface DosHeaderInfo {
  magic: 'MZ';
  /** File offset of the PE signature (IMAGE_DOS_HEADER.e_lfanew). */
  e_lfanew: number;
}

interface CoffHeaderInfo {
  machine: number;
  machineName: string;
  numberOfSections: number;
  /** Raw COFF TimeDateStamp — seconds since the Unix epoch (UTC), per the PE spec. */
  timeDateStamp: number;
  /** ISO-8601 UTC rendering of timeDateStamp, or null if it's 0 (unset). */
  timeDateStampIso: string | null;
  pointerToSymbolTable: number;
  numberOfSymbols: number;
  sizeOfOptionalHeader: number;
  characteristics: number;
  characteristicsFlags: string[];
}

interface DataDirectoryEntry {
  name: string;
  virtualAddress: number;
  size: number;
}

interface OptionalHeaderInfo {
  magic: number;
  magicName: 'PE32' | 'PE32+';
  addressOfEntryPoint: number;
  /** bigint so PE32+'s 64-bit image base never loses precision. */
  imageBase: bigint;
  subsystem: number;
  subsystemName: string;
  sizeOfImage: number;
  dataDirectories: DataDirectoryEntry[];
}

interface SectionInfo {
  name: string;
  virtualSize: number;
  virtualAddress: number;
  sizeOfRawData: number;
  pointerToRawData: number;
  characteristics: number;
  characteristicsFlags: string[];
}

interface ImportedFunction {
  name: string;
  isOrdinal: boolean;
  ordinal?: number;
}

interface ImportedDll {
  name: string;
  functions: ImportedFunction[];
}

interface ExportedFunction {
  /** Function name, or null when exported by ordinal only. */
  name: string | null;
  ordinal: number;
  /** RVA of the exported function/forwarder. */
  rva: number;
}

interface ResourceEntry {
  /** Numeric RT_* type ID, or null if the Type-level directory entry was
   *  itself a string name rather than numeric (rare, but the spec allows it). */
  typeId: number | null;
  /** RT_* friendly name (e.g. "VERSION"), the string name if Type was named,
   *  or a "Type <N>" fallback for an unrecognized numeric type. */
  typeName: string;
  /** Resolved string name, or the numeric ID rendered as a string. */
  nameOrId: string;
  /** Numeric language ID, or null when the tree didn't go a full 3 levels
   *  deep (Type -> Name/ID -> Language) to reach this leaf. */
  languageId: number | null;
  size: number;
  codePage: number;
}

interface PeInfo {
  dos: DosHeaderInfo;
  coff: CoffHeaderInfo;
  optional: OptionalHeaderInfo;
  sections: SectionInfo[];
  imports: ImportedDll[];
  exports: ExportedFunction[] | null;
  exportDllName: string | null;
  /** MD5 imphash, or null when the file has no imports to hash. */
  imphash: string | null;
  /** Resource directory tree entries (structure only — see ResourceEntry),
   *  or null when the file has no Resource Table data directory at all.
   *  An empty array means the directory is present but has no entries (or
   *  none survived a corrupt/truncated tree). */
  resources: ResourceEntry[] | null;
  /** Plain-language out-of-scope call-outs (CLR metadata, resource content, etc.) — always includes the disassembly/signature note. */
  notes: string[];
  isDll: boolean;
  isPe32Plus: boolean;
}

export type PeParseResult = { ok: true; info: PeInfo } | { ok: false; error: string };

// ---------------------------------------------------------------------------
// Lookup tables
// ---------------------------------------------------------------------------

const MACHINE_TYPES: Record<number, string> = {
  0x0: 'UNKNOWN',
  0x1d3: 'AM33',
  0x8664: 'AMD64 (x64)',
  0x1c0: 'ARM',
  0xaa64: 'ARM64',
  0x1c4: 'ARM Thumb-2 (ARMNT)',
  0xebc: 'EFI Byte Code',
  0x14c: 'I386 (x86)',
  0x200: 'IA64',
  0x9041: 'M32R',
  0x266: 'MIPS16',
  0x366: 'MIPSFPU',
  0x466: 'MIPSFPU16',
  0x1f0: 'POWERPC',
  0x1f1: 'POWERPCFP',
  0x166: 'R4000',
  0x5032: 'RISCV32',
  0x5064: 'RISCV64',
  0x5128: 'RISCV128',
  0x1a2: 'SH3',
  0x1a3: 'SH3DSP',
  0x1a6: 'SH4',
  0x1a8: 'SH5',
  0x1c2: 'THUMB',
  0x169: 'WCEMIPSV2',
};

const SUBSYSTEMS: Record<number, string> = {
  0: 'UNKNOWN',
  1: 'NATIVE',
  2: 'WINDOWS_GUI',
  3: 'WINDOWS_CUI',
  5: 'OS2_CUI',
  7: 'POSIX_CUI',
  9: 'WINDOWS_CE_GUI',
  10: 'EFI_APPLICATION',
  11: 'EFI_BOOT_SERVICE_DRIVER',
  12: 'EFI_RUNTIME_DRIVER',
  13: 'EFI_ROM',
  14: 'XBOX',
  16: 'WINDOWS_BOOT_APPLICATION',
};

const DATA_DIRECTORY_NAMES = [
  'Export Table',
  'Import Table',
  'Resource Table',
  'Exception Table',
  'Certificate Table',
  'Base Relocation Table',
  'Debug',
  'Architecture',
  'Global Ptr',
  'TLS Table',
  'Load Config Table',
  'Bound Import',
  'Import Address Table (IAT)',
  'Delay Import Descriptor',
  'CLR Runtime Header',
  'Reserved',
];

const FILE_CHARACTERISTICS: { bit: number; name: string }[] = [
  { bit: 0x0001, name: 'RELOCS_STRIPPED' },
  { bit: 0x0002, name: 'EXECUTABLE_IMAGE' },
  { bit: 0x0004, name: 'LINE_NUMS_STRIPPED' },
  { bit: 0x0008, name: 'LOCAL_SYMS_STRIPPED' },
  { bit: 0x0010, name: 'AGGRESSIVE_WS_TRIM' },
  { bit: 0x0020, name: 'LARGE_ADDRESS_AWARE' },
  { bit: 0x0080, name: 'BYTES_REVERSED_LO' },
  { bit: 0x0100, name: '32BIT_MACHINE' },
  { bit: 0x0200, name: 'DEBUG_STRIPPED' },
  { bit: 0x0400, name: 'REMOVABLE_RUN_FROM_SWAP' },
  { bit: 0x0800, name: 'NET_RUN_FROM_SWAP' },
  { bit: 0x1000, name: 'SYSTEM' },
  { bit: 0x2000, name: 'DLL' },
  { bit: 0x4000, name: 'UP_SYSTEM_ONLY' },
  { bit: 0x8000, name: 'BYTES_REVERSED_HI' },
];

// A representative subset of IMAGE_SECTION_HEADER.Characteristics — always
// includes the three the brief calls out (MEM_EXECUTE/MEM_READ/MEM_WRITE)
// plus the other flags an analyst actually cares about at a glance.
const SECTION_CHARACTERISTICS: { bit: number; name: string }[] = [
  { bit: 0x00000020, name: 'CNT_CODE' },
  { bit: 0x00000040, name: 'CNT_INITIALIZED_DATA' },
  { bit: 0x00000080, name: 'CNT_UNINITIALIZED_DATA' },
  { bit: 0x02000000, name: 'MEM_DISCARDABLE' },
  { bit: 0x04000000, name: 'MEM_NOT_CACHED' },
  { bit: 0x08000000, name: 'MEM_NOT_PAGED' },
  { bit: 0x10000000, name: 'MEM_SHARED' },
  { bit: 0x20000000, name: 'MEM_EXECUTE' },
  { bit: 0x40000000, name: 'MEM_READ' },
  { bit: 0x80000000, name: 'MEM_WRITE' },
];

function decodeFlags(value: number, table: { bit: number; name: string }[]): string[] {
  return table.filter((f) => (value & f.bit) !== 0).map((f) => f.name);
}

// Well-known RT_* resource type IDs (winuser.h). Anything not in this table
// renders as `Type <N>`, matching MACHINE_TYPES/SUBSYSTEMS's "Unknown (0x...)"
// fallback convention above.
const RESOURCE_TYPES: Record<number, string> = {
  1: 'CURSOR',
  2: 'BITMAP',
  3: 'ICON',
  4: 'MENU',
  5: 'DIALOG',
  6: 'STRING',
  7: 'FONTDIR',
  8: 'FONT',
  9: 'ACCELERATOR',
  10: 'RCDATA',
  11: 'MESSAGETABLE',
  12: 'GROUP_CURSOR',
  14: 'GROUP_ICON',
  16: 'VERSION',
  17: 'DLGINCLUDE',
  19: 'PLUGPLAY',
  20: 'VXD',
  21: 'ANICURSOR',
  22: 'ANIICON',
  23: 'HTML',
  24: 'MANIFEST',
};

// ---------------------------------------------------------------------------
// Bounds-checked byte reader — every read explicitly little-endian, every
// out-of-range read throws a BoundsError with a specific message that
// parsePe() catches and turns into a friendly PeParseResult failure instead
// of letting an uncaught RangeError reach the caller.
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
        `Truncated or malformed file — expected to read ${what} at offset ${offset}, but the file is only ${this.len} bytes.`,
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

  bytes(offset: number, length: number, what = 'bytes'): Uint8Array {
    this.need(offset, length, what);
    return new Uint8Array(this.view.buffer, this.view.byteOffset + offset, length);
  }

  /** Reads a NUL-terminated ASCII string, capped at maxLen bytes. Never
   *  throws on truncation — a string running off the end of the file just
   *  returns whatever bytes were readable, since a malformed tail string is
   *  common in corrupted samples and shouldn't fail the whole parse. */
  cstringAscii(offset: number, maxLen = 256): string {
    let out = '';
    for (let i = 0; i < maxLen; i++) {
      if (offset + i >= this.len || offset + i < 0) break;
      const b = this.view.getUint8(offset + i);
      if (b === 0) break;
      out += String.fromCharCode(b);
    }
    return out;
  }
}

// ---------------------------------------------------------------------------
// RVA -> file-offset resolution via the section table (the standard PE
// loader's own lookup: find the section whose virtual address range contains
// the RVA, then translate via that section's own raw-data pointer).
// ---------------------------------------------------------------------------

function rvaToOffset(rva: number, sections: SectionInfo[], sizeOfHeaders: number): number | null {
  for (const s of sections) {
    const span = Math.max(s.virtualSize, s.sizeOfRawData);
    if (span > 0 && rva >= s.virtualAddress && rva < s.virtualAddress + span) {
      const delta = rva - s.virtualAddress;
      if (delta < s.sizeOfRawData) return s.pointerToRawData + delta;
      return null; // falls in the section's virtual-only tail (e.g. uninitialized .bss) — no file bytes there
    }
  }
  // Headers are identity-mapped at RVA 0 for SizeOfHeaders bytes — some data
  // directories (rare, but seen in hand-built/minimal PEs) point inside them.
  if (rva >= 0 && rva < sizeOfHeaders) return rva;
  return null;
}

/** Standard imphash convention: strip a known DLL-ish extension, lowercase
 *  everything. Anything else about the name (path, casing) is left intact —
 *  real import descriptors store a bare filename, not a path. */
function stripKnownExtension(name: string): string {
  return name.replace(/\.(dll|ocx|sys)$/i, '');
}

/** Mandiant-style imphash: MD5 of the lowercased, comma-joined
 *  "dllbasename.functionname" list, in import-table order. Ordinal-only
 *  imports render as "dllbasename.ord<N>". Returns null when there are no
 *  imports at all to hash (nothing meaningful to compute). */
function computeImphash(imports: ImportedDll[]): string | null {
  const parts: string[] = [];
  for (const dll of imports) {
    const base = stripKnownExtension(dll.name).toLowerCase();
    for (const fn of dll.functions) {
      const fnPart = fn.isOrdinal ? `ord${fn.ordinal}` : fn.name.toLowerCase();
      parts.push(`${base}.${fnPart}`);
    }
  }
  if (parts.length === 0) return null;
  return md5Hex(new TextEncoder().encode(parts.join(',')));
}

// ---------------------------------------------------------------------------
// Resource Directory (.rsrc) tree walk — structural metadata only (type,
// name-or-ID, language, size). Every offset inside the resource tree (a
// Name field that's a string offset, or an OffsetToData field pointing at a
// subdirectory or a leaf IMAGE_RESOURCE_DATA_ENTRY) is relative to the START
// of the resource section (resourceBaseOffset — the file offset the
// Resource Table data directory's virtualAddress resolves to via
// rvaToOffset), never to the current subdirectory's own position. The tree
// is conventionally exactly 3 levels deep (Type -> Name/ID -> Language) but
// this walks generically/recursively — any entry with the subdirectory bit
// set recurses, any entry without it is a leaf — so a non-conventional depth
// doesn't break it. Bounded by a hard depth cap and a hard total-entries-
// visited cap so a corrupt or adversarial resource directory can never hang
// or crash the parser, mirroring this file's existing
// "for (let d = 0; d < 1000; d++)" / "for (let t = 0; t < 10000; t++)"
// defensive loop caps. Every read is manually bounds-checked before it's
// made (rather than relying on Cursor's throwing bounds check), so a
// truncated/corrupt subtree degrades to a partial (or empty) result — it
// never throws BoundsError and never fails the overall parse.
// ---------------------------------------------------------------------------

const RESOURCE_MAX_DEPTH = 8;
const RESOURCE_MAX_VISITED = 5000;

/** One resolved IMAGE_RESOURCE_DIRECTORY_ENTRY name at some level of the
 *  tree — either a numeric ID (top bit of Name clear) or a resolved string
 *  name (top bit set). */
interface ResourcePathLevel {
  idValue: number | null;
  nameValue: string | null;
}

function parseResourceDirectory(c: Cursor, fileLen: number, resourceBaseOffset: number): ResourceEntry[] {
  const entries: ResourceEntry[] = [];
  let visited = 0;

  /** Reads an IMAGE_RESOURCE_DIR_STRING_U (u16 char count followed by that
   *  many UTF-16LE code units, NOT null-terminated) at a resourceBaseOffset-
   *  relative offset. Returns null if it doesn't fully fit in the file —
   *  the caller degrades that to an empty name rather than aborting the walk. */
  function readResourceString(relOffset: number): string | null {
    const abs = resourceBaseOffset + relOffset;
    if (abs < 0 || abs + 2 > fileLen) return null;
    const count = c.u16(abs);
    const charsStart = abs + 2;
    const byteLen = count * 2;
    if (charsStart + byteLen > fileLen) return null;
    let s = '';
    for (let i = 0; i < count; i++) {
      s += String.fromCharCode(c.u16(charsStart + i * 2));
    }
    return s;
  }

  function walk(dirRelOffset: number, depth: number, path: ResourcePathLevel[]): void {
    if (depth >= RESOURCE_MAX_DEPTH || visited >= RESOURCE_MAX_VISITED) return;
    const dirAbs = resourceBaseOffset + dirRelOffset;
    if (dirAbs < 0 || dirAbs + 16 > fileLen) return; // truncated IMAGE_RESOURCE_DIRECTORY header — stop this branch

    const numNamed = c.u16(dirAbs + 12);
    const numId = c.u16(dirAbs + 14);
    const total = numNamed + numId;
    const entriesStart = dirAbs + 16;

    for (let i = 0; i < total; i++) {
      if (visited >= RESOURCE_MAX_VISITED) break;
      visited++;
      const entryOff = entriesStart + i * 8;
      if (entryOff + 8 > fileLen) break; // truncated entry table — keep what parsed so far, same style as the section/import table loops above

      const nameField = c.u32(entryOff + 0);
      const offsetField = c.u32(entryOff + 4);

      let idValue: number | null = null;
      let nameValue: string | null = null;
      if ((nameField & 0x80000000) !== 0) {
        nameValue = readResourceString(nameField & 0x7fffffff) ?? '';
      } else {
        idValue = nameField;
      }
      const nextPath = path.concat([{ idValue, nameValue }]);

      if ((offsetField & 0x80000000) !== 0) {
        // Subdirectory — recurse one level deeper.
        walk(offsetField & 0x7fffffff, depth + 1, nextPath);
        continue;
      }

      // Leaf — IMAGE_RESOURCE_DATA_ENTRY (16 bytes).
      const dataAbs = resourceBaseOffset + offsetField;
      if (dataAbs < 0 || dataAbs + 16 > fileLen) continue; // corrupt leaf pointer — skip just this one entry

      const size = c.u32(dataAbs + 4);
      const codePage = c.u32(dataAbs + 8);
      // dataAbs+0 (OffsetToData) is a real image RVA; not resolved further —
      // only the tree's own structural metadata is surfaced, never the
      // resource's actual bytes (icon/version/manifest/dialog content).

      const typeLevel = nextPath[0] ?? null;
      const nameLevel = nextPath[1] ?? null;
      const langLevel = nextPath[2] ?? null;

      const typeId = typeLevel?.idValue ?? null;
      const typeName =
        typeLevel == null
          ? 'Type ?'
          : typeLevel.idValue != null
            ? (RESOURCE_TYPES[typeLevel.idValue] ?? `Type ${typeLevel.idValue}`)
            : typeLevel.nameValue || 'Type ?';
      const nameOrId =
        nameLevel == null ? '' : nameLevel.idValue != null ? String(nameLevel.idValue) : (nameLevel.nameValue ?? '');
      const languageId = langLevel?.idValue ?? null;

      entries.push({ typeId, typeName, nameOrId, languageId, size, codePage });
    }
  }

  walk(0, 0, []);
  return entries;
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

const MZ0 = 0x4d; // 'M'
const MZ1 = 0x5a; // 'Z'

export function parsePe(bytes: Uint8Array): PeParseResult {
  try {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const c = new Cursor(view, bytes.byteLength);
    const fail = (error: string): PeParseResult => ({ ok: false, error });

    // --- DOS header ---------------------------------------------------
    if (bytes.byteLength < 0x40) {
      return fail('Not a valid PE file — the file is too small to contain a DOS header.');
    }
    if (c.u8(0) !== MZ0 || c.u8(1) !== MZ1) {
      return fail('Not a valid PE file — missing MZ signature.');
    }
    const e_lfanew = c.u32(0x3c);
    if (e_lfanew < 0 || e_lfanew + 4 > bytes.byteLength) {
      return fail(
        `Not a valid PE file — the PE header offset (e_lfanew = 0x${e_lfanew.toString(16)}) points past the end of the file (${bytes.byteLength} bytes).`,
      );
    }

    // --- PE signature ---------------------------------------------------
    const sig = c.bytes(e_lfanew, 4, 'the PE signature');
    if (!(sig[0] === 0x50 && sig[1] === 0x45 && sig[2] === 0x00 && sig[3] === 0x00)) {
      return fail(`Not a valid PE file — missing PE signature at the expected offset (0x${e_lfanew.toString(16)}).`);
    }

    // --- COFF File Header (20 bytes, right after the 4-byte signature) --
    const coffOffset = e_lfanew + 4;
    if (coffOffset + 20 > bytes.byteLength) {
      return fail('Not a valid PE file — truncated COFF file header.');
    }
    const machine = c.u16(coffOffset + 0);
    const numberOfSections = c.u16(coffOffset + 2);
    const timeDateStamp = c.u32(coffOffset + 4);
    const pointerToSymbolTable = c.u32(coffOffset + 8);
    const numberOfSymbols = c.u32(coffOffset + 12);
    const sizeOfOptionalHeader = c.u16(coffOffset + 16);
    const characteristics = c.u16(coffOffset + 18);

    // --- Optional Header --------------------------------------------------
    const optOffset = coffOffset + 20;
    if (sizeOfOptionalHeader < 2 || optOffset + sizeOfOptionalHeader > bytes.byteLength) {
      return fail('Not a valid PE file — truncated or missing optional header.');
    }
    const magic = c.u16(optOffset);
    let isPe32Plus: boolean;
    if (magic === 0x10b) isPe32Plus = false;
    else if (magic === 0x20b) isPe32Plus = true;
    else {
      return fail(
        `Not a valid PE file — unrecognized Optional Header magic (0x${magic.toString(16)}); expected PE32 (0x10b) or PE32+ (0x20b).`,
      );
    }

    const addressOfEntryPoint = c.u32(optOffset + 16);
    let imageBase: bigint;
    let dataDirOffset: number;
    let numberOfRvaAndSizesOffset: number;
    if (!isPe32Plus) {
      imageBase = BigInt(c.u32(optOffset + 28));
      numberOfRvaAndSizesOffset = optOffset + 92;
      dataDirOffset = optOffset + 96;
    } else {
      imageBase = c.u64(optOffset + 24);
      numberOfRvaAndSizesOffset = optOffset + 108;
      dataDirOffset = optOffset + 112;
    }
    const sizeOfImage = c.u32(optOffset + 56);
    const sizeOfHeaders = c.u32(optOffset + 60);
    const subsystem = c.u16(optOffset + 68);
    const rawRvaCount = c.u32(numberOfRvaAndSizesOffset);
    const numberOfRvaAndSizes = Math.min(rawRvaCount, 16); // clamp — a corrupt huge count shouldn't blow up the loop

    const dataDirectories: DataDirectoryEntry[] = [];
    for (let i = 0; i < 16; i++) {
      const entryOffset = dataDirOffset + i * 8;
      if (i < numberOfRvaAndSizes && entryOffset + 8 <= bytes.byteLength) {
        dataDirectories.push({
          name: DATA_DIRECTORY_NAMES[i] ?? `Reserved ${i}`,
          virtualAddress: c.u32(entryOffset),
          size: c.u32(entryOffset + 4),
        });
      } else {
        dataDirectories.push({ name: DATA_DIRECTORY_NAMES[i] ?? `Reserved ${i}`, virtualAddress: 0, size: 0 });
      }
    }

    // --- Section Table ----------------------------------------------------
    const sectionTableOffset = optOffset + sizeOfOptionalHeader;
    const sections: SectionInfo[] = [];
    for (let i = 0; i < numberOfSections; i++) {
      const base = sectionTableOffset + i * 40;
      if (base + 40 > bytes.byteLength) break; // truncated section table — keep what parsed so far rather than failing the whole file
      const nameBytes = c.bytes(base, 8);
      let rawName = '';
      for (let j = 0; j < 8; j++) {
        if (nameBytes[j] === 0) break;
        rawName += String.fromCharCode(nameBytes[j]);
      }
      const sectionCharacteristics = c.u32(base + 36);
      sections.push({
        name: rawName || `(unnamed section ${i})`,
        virtualSize: c.u32(base + 8),
        virtualAddress: c.u32(base + 12),
        sizeOfRawData: c.u32(base + 16),
        pointerToRawData: c.u32(base + 20),
        characteristics: sectionCharacteristics,
        characteristicsFlags: decodeFlags(sectionCharacteristics, SECTION_CHARACTERISTICS),
      });
    }

    // --- Import Directory Table --------------------------------------------
    const imports: ImportedDll[] = [];
    const importDir = dataDirectories[1];
    if (importDir && importDir.virtualAddress > 0) {
      const importTableOffset = rvaToOffset(importDir.virtualAddress, sections, sizeOfHeaders);
      if (importTableOffset != null) {
        for (let d = 0; d < 1000; d++) {
          const descBase = importTableOffset + d * 20;
          if (descBase + 20 > bytes.byteLength) break;
          const originalFirstThunk = c.u32(descBase + 0);
          const descTimeDate = c.u32(descBase + 4);
          const forwarderChain = c.u32(descBase + 8);
          const nameRva = c.u32(descBase + 12);
          const firstThunk = c.u32(descBase + 16);
          if (originalFirstThunk === 0 && descTimeDate === 0 && forwarderChain === 0 && nameRva === 0 && firstThunk === 0) {
            break; // all-zero IMAGE_IMPORT_DESCRIPTOR terminator
          }
          if (nameRva === 0) continue;
          const nameOffset = rvaToOffset(nameRva, sections, sizeOfHeaders);
          const dllName = nameOffset != null ? c.cstringAscii(nameOffset, 256) : '(unresolvable DLL name)';

          const functions: ImportedFunction[] = [];
          const thunkRva = originalFirstThunk !== 0 ? originalFirstThunk : firstThunk;
          if (thunkRva !== 0) {
            const thunkOffset = rvaToOffset(thunkRva, sections, sizeOfHeaders);
            if (thunkOffset != null) {
              const entrySize = isPe32Plus ? 8 : 4;
              for (let t = 0; t < 10000; t++) {
                const entryOffset = thunkOffset + t * entrySize;
                if (entryOffset + entrySize > bytes.byteLength) break;
                if (isPe32Plus) {
                  const raw = c.u64(entryOffset);
                  if (raw === 0n) break;
                  if ((raw & 0x8000000000000000n) !== 0n) {
                    const ordinal = Number(raw & 0xffffn);
                    functions.push({ name: `ordinal ${ordinal}`, isOrdinal: true, ordinal });
                  } else {
                    const hintNameRva = Number(raw & 0xffffffffn);
                    const hnOffset = rvaToOffset(hintNameRva, sections, sizeOfHeaders);
                    const fname = hnOffset != null ? c.cstringAscii(hnOffset + 2, 256) : '';
                    functions.push({ name: fname || '(unresolvable import name)', isOrdinal: false });
                  }
                } else {
                  const raw = c.u32(entryOffset);
                  if (raw === 0) break;
                  if ((raw & 0x80000000) !== 0) {
                    const ordinal = raw & 0xffff;
                    functions.push({ name: `ordinal ${ordinal}`, isOrdinal: true, ordinal });
                  } else {
                    const hintNameRva = raw & 0x7fffffff;
                    const hnOffset = rvaToOffset(hintNameRva, sections, sizeOfHeaders);
                    const fname = hnOffset != null ? c.cstringAscii(hnOffset + 2, 256) : '';
                    functions.push({ name: fname || '(unresolvable import name)', isOrdinal: false });
                  }
                }
              }
            }
          }
          imports.push({ name: dllName, functions });
        }
      }
    }

    // --- Export Table -------------------------------------------------------
    let exports: ExportedFunction[] | null = null;
    let exportDllName: string | null = null;
    const exportDir = dataDirectories[0];
    if (exportDir && exportDir.virtualAddress > 0) {
      const expOffset = rvaToOffset(exportDir.virtualAddress, sections, sizeOfHeaders);
      if (expOffset != null && expOffset + 40 <= bytes.byteLength) {
        const nameRva = c.u32(expOffset + 12);
        const base = c.u32(expOffset + 16);
        const numberOfFunctions = Math.min(c.u32(expOffset + 20), 100000);
        const numberOfNames = Math.min(c.u32(expOffset + 24), 100000);
        const addressOfFunctionsRva = c.u32(expOffset + 28);
        const addressOfNamesRva = c.u32(expOffset + 32);
        const addressOfNameOrdinalsRva = c.u32(expOffset + 36);

        const nameOff = rvaToOffset(nameRva, sections, sizeOfHeaders);
        exportDllName = nameOff != null ? c.cstringAscii(nameOff, 256) : null;

        const funcTableOffset = rvaToOffset(addressOfFunctionsRva, sections, sizeOfHeaders);
        const namesTableOffset = rvaToOffset(addressOfNamesRva, sections, sizeOfHeaders);
        const ordinalsTableOffset = rvaToOffset(addressOfNameOrdinalsRva, sections, sizeOfHeaders);

        const namedByIndex = new Map<number, string>();
        if (namesTableOffset != null && ordinalsTableOffset != null) {
          for (let i = 0; i < numberOfNames; i++) {
            const nRvaOff = namesTableOffset + i * 4;
            const ordOff = ordinalsTableOffset + i * 2;
            if (nRvaOff + 4 > bytes.byteLength || ordOff + 2 > bytes.byteLength) break;
            const nRva = c.u32(nRvaOff);
            const ordIndex = c.u16(ordOff);
            const nOff = rvaToOffset(nRva, sections, sizeOfHeaders);
            const fname = nOff != null ? c.cstringAscii(nOff, 256) : '';
            if (fname) namedByIndex.set(ordIndex, fname);
          }
        }

        if (funcTableOffset != null) {
          exports = [];
          for (let i = 0; i < numberOfFunctions; i++) {
            const fOff = funcTableOffset + i * 4;
            if (fOff + 4 > bytes.byteLength) break;
            const rva = c.u32(fOff);
            if (rva === 0) continue; // gap in the ordinal sequence — no function at this index
            exports.push({ name: namedByIndex.get(i) ?? null, ordinal: base + i, rva });
          }
        }
      }
    }

    // --- Resource Directory (.rsrc) -----------------------------------------
    let resources: ResourceEntry[] | null = null;
    const resourceDir = dataDirectories[2];
    if (resourceDir && resourceDir.virtualAddress > 0) {
      resources = [];
      const resourceBaseOffset = rvaToOffset(resourceDir.virtualAddress, sections, sizeOfHeaders);
      if (resourceBaseOffset != null) {
        resources = parseResourceDirectory(c, bytes.byteLength, resourceBaseOffset);
      }
    }

    // --- Out-of-scope notes --------------------------------------------------
    const notes: string[] = [];
    const clrDir = dataDirectories[14];
    if (clrDir && clrDir.virtualAddress > 0) {
      notes.push(
        "This file has a .NET/CLR runtime header (a managed assembly) — its COR20 header and managed metadata (MSIL, .NET-specific import tables) aren't parsed here. The headers, sections, and native import/export tables above reflect the underlying native PE wrapper only.",
      );
    }
    if (sections.some((s) => s.name === '.rsrc')) {
      notes.push(
        "This file has a resource section (.rsrc) — its resource directory tree (type, name/ID, language, and size) is listed below, but the resources' actual content (icon bitmaps, version-string values, manifest XML text, dialog templates) is not rendered here.",
      );
    }
    notes.push('Disassembly and digital-signature verification are out of scope for this tool.');

    const info: PeInfo = {
      dos: { magic: 'MZ', e_lfanew },
      coff: {
        machine,
        machineName: MACHINE_TYPES[machine] ?? `Unknown (0x${machine.toString(16)})`,
        numberOfSections,
        timeDateStamp,
        timeDateStampIso: timeDateStamp > 0 ? new Date(timeDateStamp * 1000).toISOString() : null,
        pointerToSymbolTable,
        numberOfSymbols,
        sizeOfOptionalHeader,
        characteristics,
        characteristicsFlags: decodeFlags(characteristics, FILE_CHARACTERISTICS),
      },
      optional: {
        magic,
        magicName: isPe32Plus ? 'PE32+' : 'PE32',
        addressOfEntryPoint,
        imageBase,
        subsystem,
        subsystemName: SUBSYSTEMS[subsystem] ?? `Unknown (${subsystem})`,
        sizeOfImage,
        dataDirectories,
      },
      sections,
      imports,
      exports,
      resources,
      exportDllName,
      imphash: computeImphash(imports),
      notes,
      isDll: (characteristics & 0x2000) !== 0,
      isPe32Plus,
    };
    return { ok: true, info };
  } catch (e) {
    if (e instanceof BoundsError) return { ok: false, error: e.message };
    return {
      ok: false,
      error: 'Not a valid PE file — the file is malformed or truncated in a way this parser could not recover from.',
    };
  }
}
