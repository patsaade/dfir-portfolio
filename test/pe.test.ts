import { describe, it, expect } from 'vitest';
import { parsePe } from '../src/utils/pe';
import { md5Hex } from '../src/utils/hashes';

// ---------------------------------------------------------------------------
// Hand-constructed minimal PE byte buffers. Every offset below is computed
// against the real IMAGE_DOS_HEADER / IMAGE_NT_HEADERS / IMAGE_SECTION_HEADER
// / IMAGE_IMPORT_DESCRIPTOR layouts (see src/utils/pe.ts's own header comment
// for the field-by-field breakdown) — nothing here is a captured real binary,
// it's a synthetic fixture built byte-by-byte for the test.
// ---------------------------------------------------------------------------

function u8(view: DataView, off: number, v: number) {
  view.setUint8(off, v);
}
function u16(view: DataView, off: number, v: number) {
  view.setUint16(off, v, true);
}
function u32(view: DataView, off: number, v: number) {
  view.setUint32(off, v, true);
}
function u64(view: DataView, off: number, v: bigint) {
  view.setBigUint64(off, v, true);
}
function ascii(bytes: Uint8Array, off: number, s: string) {
  for (let i = 0; i < s.length; i++) bytes[off + i] = s.charCodeAt(i);
}

/**
 * A minimal but fully valid PE32 image: DOS header -> PE signature -> COFF
 * File Header (1 section) -> PE32 Optional Header (Magic 0x10b) -> one
 * ".text" section table entry -> that section's raw data holding a single
 * IMAGE_IMPORT_DESCRIPTOR for KERNEL32.dll importing ExitProcess by name.
 *
 * Layout (file offsets):
 *   0x000            DOS header (64 bytes), e_lfanew = 0x40
 *   0x040            "PE\0\0" signature
 *   0x044            COFF File Header (20 bytes)
 *   0x058            PE32 Optional Header (0xE0 = 224 bytes)
 *   0x138            Section table, 1 entry (40 bytes)
 *   0x200            Section ".text" raw data starts (RVA 0x1000)
 *     0x200            Import Directory Table: 1 descriptor + zero terminator
 *     0x230            Import Address Table (FirstThunk): 1 entry + terminator
 *     0x240            DLL name "KERNEL32.dll\0"
 *     0x250            IMAGE_IMPORT_BY_NAME: Hint(0) + "ExitProcess\0"
 *   0x400            end of file
 */
function buildValidPe32(): Uint8Array {
  const bytes = new Uint8Array(0x400);
  const view = new DataView(bytes.buffer);

  // DOS header
  bytes[0] = 0x4d; // 'M'
  bytes[1] = 0x5a; // 'Z'
  u32(view, 0x3c, 0x40); // e_lfanew

  // PE signature
  bytes[0x40] = 0x50; // 'P'
  bytes[0x41] = 0x45; // 'E'
  bytes[0x42] = 0x00;
  bytes[0x43] = 0x00;

  // COFF File Header @ 0x44
  u16(view, 0x44, 0x14c); // Machine = IMAGE_FILE_MACHINE_I386
  u16(view, 0x46, 1); // NumberOfSections
  u32(view, 0x48, 1600000000); // TimeDateStamp (2020-09-13T12:26:40Z)
  u32(view, 0x4c, 0); // PointerToSymbolTable
  u32(view, 0x50, 0); // NumberOfSymbols
  u16(view, 0x54, 0xe0); // SizeOfOptionalHeader (PE32 standard size)
  u16(view, 0x56, 0x0102); // Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE

  // PE32 Optional Header @ 0x58
  const opt = 0x58;
  u16(view, opt + 0, 0x10b); // Magic = PE32
  u8(view, opt + 2, 14); // MajorLinkerVersion
  u8(view, opt + 3, 0); // MinorLinkerVersion
  u32(view, opt + 4, 0x200); // SizeOfCode
  u32(view, opt + 8, 0x200); // SizeOfInitializedData
  u32(view, opt + 12, 0); // SizeOfUninitializedData
  u32(view, opt + 16, 0x1000); // AddressOfEntryPoint
  u32(view, opt + 20, 0x1000); // BaseOfCode
  u32(view, opt + 24, 0x2000); // BaseOfData (PE32 only)
  u32(view, opt + 28, 0x400000); // ImageBase
  u32(view, opt + 32, 0x1000); // SectionAlignment
  u32(view, opt + 36, 0x200); // FileAlignment
  u16(view, opt + 40, 6); // MajorOperatingSystemVersion
  u16(view, opt + 42, 0);
  u16(view, opt + 44, 0);
  u16(view, opt + 46, 0);
  u16(view, opt + 48, 6); // MajorSubsystemVersion
  u16(view, opt + 50, 0);
  u32(view, opt + 52, 0); // Win32VersionValue
  u32(view, opt + 56, 0x3000); // SizeOfImage
  u32(view, opt + 60, 0x200); // SizeOfHeaders
  u32(view, opt + 64, 0); // CheckSum
  u16(view, opt + 68, 3); // Subsystem = WINDOWS_CUI
  u16(view, opt + 70, 0); // DllCharacteristics
  u32(view, opt + 72, 0x100000); // SizeOfStackReserve
  u32(view, opt + 76, 0x1000); // SizeOfStackCommit
  u32(view, opt + 80, 0x100000); // SizeOfHeapReserve
  u32(view, opt + 84, 0x1000); // SizeOfHeapCommit
  u32(view, opt + 88, 0); // LoaderFlags
  u32(view, opt + 92, 16); // NumberOfRvaAndSizes
  // DataDirectory[16] @ opt+96 — all zero except index 1 (Import Table)
  const dataDir = opt + 96;
  u32(view, dataDir + 1 * 8 + 0, 0x1000); // Import Table VirtualAddress
  u32(view, dataDir + 1 * 8 + 4, 0x28); // Import Table Size

  // Section table @ 0x138 (= opt + 0xE0), 1 entry
  const sec = 0x138;
  ascii(bytes, sec, '.text'); // 8-byte Name field, null-padded
  u32(view, sec + 8, 0x200); // VirtualSize
  u32(view, sec + 12, 0x1000); // VirtualAddress
  u32(view, sec + 16, 0x200); // SizeOfRawData
  u32(view, sec + 20, 0x200); // PointerToRawData
  u32(view, sec + 24, 0); // PointerToRelocations
  u32(view, sec + 28, 0); // PointerToLinenumbers
  u16(view, sec + 32, 0); // NumberOfRelocations
  u16(view, sec + 34, 0); // NumberOfLinenumbers
  u32(view, sec + 36, 0xe0000020); // Characteristics: CNT_CODE|MEM_EXECUTE|MEM_READ|MEM_WRITE

  // Import Directory Table @ file offset 0x200 (RVA 0x1000)
  const importDir = 0x200;
  u32(view, importDir + 0, 0); // OriginalFirstThunk (unused — no-ILT form)
  u32(view, importDir + 4, 0); // TimeDateStamp
  u32(view, importDir + 8, 0); // ForwarderChain
  u32(view, importDir + 12, 0x1040); // Name RVA -> "KERNEL32.dll"
  u32(view, importDir + 16, 0x1030); // FirstThunk RVA
  // second descriptor (terminator) at importDir+20 stays all-zero

  // Import Address Table (FirstThunk) @ file offset 0x230 (RVA 0x1030)
  const thunk = 0x230;
  u32(view, thunk + 0, 0x1050); // -> IMAGE_IMPORT_BY_NAME RVA (high bit clear = by name)
  // terminator entry at thunk+4 stays zero

  // DLL name @ file offset 0x240 (RVA 0x1040)
  ascii(bytes, 0x240, 'KERNEL32.dll');

  // IMAGE_IMPORT_BY_NAME @ file offset 0x250 (RVA 0x1050): Hint(2) + Name
  u16(view, 0x250, 0);
  ascii(bytes, 0x252, 'ExitProcess');

  return bytes;
}

/**
 * A minimal valid PE32 image whose only section is ".rsrc", containing a
 * conventional 3-level resource directory tree (Type -> Name/ID -> Language)
 * with exactly one leaf: RT_VERSION (type 16) / ID 1 / language 0x409
 * (en-US), pointing at a 0x1A4-byte, code-page-1200 resource blob.
 *
 * Layout (file offsets):
 *   0x000            DOS header (64 bytes), e_lfanew = 0x40
 *   0x040            "PE\0\0" signature
 *   0x044            COFF File Header (20 bytes)
 *   0x058            PE32 Optional Header (0xE0 = 224 bytes) — DataDirectory[2]
 *                    (Resource Table) -> VirtualAddress 0x1000, Size 0x58
 *   0x138            Section table, 1 entry (".rsrc", RVA 0x1000)
 *   0x200            ".rsrc" raw data starts (resourceBaseOffset) — every
 *                    offset inside the tree below is relative to THIS offset:
 *     0x200 (+0x00)    root IMAGE_RESOURCE_DIRECTORY: 1 ID entry
 *     0x210 (+0x10)    root entry: Name=16 (RT_VERSION), OffsetToData -> +0x18 (subdir)
 *     0x218 (+0x18)    Name-level IMAGE_RESOURCE_DIRECTORY: 1 ID entry
 *     0x228 (+0x28)    Name-level entry: Name=1, OffsetToData -> +0x30 (subdir)
 *     0x230 (+0x30)    Language-level IMAGE_RESOURCE_DIRECTORY: 1 ID entry
 *     0x240 (+0x40)    Language-level entry: Name=0x409, OffsetToData -> +0x48 (leaf)
 *     0x248 (+0x48)    IMAGE_RESOURCE_DATA_ENTRY: OffsetToData(RVA)=0x1100, Size=0x1A4, CodePage=1200
 *   0x300            end of file
 */
function buildPeWithResourceTree(): Uint8Array {
  const bytes = new Uint8Array(0x300);
  const view = new DataView(bytes.buffer);

  // DOS header
  bytes[0] = 0x4d;
  bytes[1] = 0x5a;
  u32(view, 0x3c, 0x40);

  // PE signature
  bytes[0x40] = 0x50;
  bytes[0x41] = 0x45;
  bytes[0x42] = 0x00;
  bytes[0x43] = 0x00;

  // COFF File Header @ 0x44
  u16(view, 0x44, 0x14c); // Machine = I386
  u16(view, 0x46, 1); // NumberOfSections
  u32(view, 0x48, 1600000000); // TimeDateStamp
  u32(view, 0x4c, 0);
  u32(view, 0x50, 0);
  u16(view, 0x54, 0xe0); // SizeOfOptionalHeader
  u16(view, 0x56, 0x0102); // Characteristics

  // PE32 Optional Header @ 0x58
  const opt = 0x58;
  u16(view, opt + 0, 0x10b); // Magic = PE32
  u8(view, opt + 2, 14);
  u8(view, opt + 3, 0);
  u32(view, opt + 4, 0x200);
  u32(view, opt + 8, 0x200);
  u32(view, opt + 12, 0);
  u32(view, opt + 16, 0x1000); // AddressOfEntryPoint
  u32(view, opt + 20, 0x1000);
  u32(view, opt + 24, 0x2000);
  u32(view, opt + 28, 0x400000); // ImageBase
  u32(view, opt + 32, 0x1000);
  u32(view, opt + 36, 0x200);
  u16(view, opt + 40, 6);
  u16(view, opt + 42, 0);
  u16(view, opt + 44, 0);
  u16(view, opt + 46, 0);
  u16(view, opt + 48, 6);
  u16(view, opt + 50, 0);
  u32(view, opt + 52, 0);
  u32(view, opt + 56, 0x3000); // SizeOfImage
  u32(view, opt + 60, 0x200); // SizeOfHeaders
  u32(view, opt + 64, 0);
  u16(view, opt + 68, 3); // Subsystem
  u16(view, opt + 70, 0);
  u32(view, opt + 72, 0x100000);
  u32(view, opt + 76, 0x1000);
  u32(view, opt + 80, 0x100000);
  u32(view, opt + 84, 0x1000);
  u32(view, opt + 88, 0);
  u32(view, opt + 92, 16); // NumberOfRvaAndSizes
  const dataDir = opt + 96;
  u32(view, dataDir + 2 * 8 + 0, 0x1000); // Resource Table VirtualAddress
  u32(view, dataDir + 2 * 8 + 4, 0x58); // Resource Table Size

  // Section table @ 0x138, 1 entry: ".rsrc"
  const sec = 0x138;
  ascii(bytes, sec, '.rsrc');
  u32(view, sec + 8, 0x58); // VirtualSize
  u32(view, sec + 12, 0x1000); // VirtualAddress
  u32(view, sec + 16, 0x58); // SizeOfRawData
  u32(view, sec + 20, 0x200); // PointerToRawData
  u32(view, sec + 24, 0);
  u32(view, sec + 28, 0);
  u16(view, sec + 32, 0);
  u16(view, sec + 34, 0);
  u32(view, sec + 36, 0x40000040); // CNT_INITIALIZED_DATA | MEM_READ

  // Resource directory tree @ file offset 0x200 (RVA 0x1000) = resourceBaseOffset
  const rsrcBase = 0x200;

  // Root IMAGE_RESOURCE_DIRECTORY (Type level)
  u32(view, rsrcBase + 0, 0); // Characteristics
  u32(view, rsrcBase + 4, 0); // TimeDateStamp
  u16(view, rsrcBase + 8, 0); // MajorVersion
  u16(view, rsrcBase + 10, 0); // MinorVersion
  u16(view, rsrcBase + 12, 0); // NumberOfNamedEntries
  u16(view, rsrcBase + 14, 1); // NumberOfIdEntries
  // Root entry @ rsrcBase+0x10 -> Type = RT_VERSION (16), subdir @ +0x18
  u32(view, rsrcBase + 0x10 + 0, 16);
  u32(view, rsrcBase + 0x10 + 4, 0x80000000 | 0x18);

  // Name-level IMAGE_RESOURCE_DIRECTORY @ rsrcBase+0x18
  u32(view, rsrcBase + 0x18 + 0, 0);
  u32(view, rsrcBase + 0x18 + 4, 0);
  u16(view, rsrcBase + 0x18 + 8, 0);
  u16(view, rsrcBase + 0x18 + 10, 0);
  u16(view, rsrcBase + 0x18 + 12, 0); // NumberOfNamedEntries
  u16(view, rsrcBase + 0x18 + 14, 1); // NumberOfIdEntries
  // Name-level entry @ rsrcBase+0x28 -> ID = 1, subdir @ +0x30
  u32(view, rsrcBase + 0x28 + 0, 1);
  u32(view, rsrcBase + 0x28 + 4, 0x80000000 | 0x30);

  // Language-level IMAGE_RESOURCE_DIRECTORY @ rsrcBase+0x30
  u32(view, rsrcBase + 0x30 + 0, 0);
  u32(view, rsrcBase + 0x30 + 4, 0);
  u16(view, rsrcBase + 0x30 + 8, 0);
  u16(view, rsrcBase + 0x30 + 10, 0);
  u16(view, rsrcBase + 0x30 + 12, 0); // NumberOfNamedEntries
  u16(view, rsrcBase + 0x30 + 14, 1); // NumberOfIdEntries
  // Language-level entry @ rsrcBase+0x40 -> language 0x409 (en-US), leaf @ +0x48
  u32(view, rsrcBase + 0x40 + 0, 0x409);
  u32(view, rsrcBase + 0x40 + 4, 0x48); // top bit clear -> leaf, not a subdirectory

  // IMAGE_RESOURCE_DATA_ENTRY @ rsrcBase+0x48
  u32(view, rsrcBase + 0x48 + 0, 0x1100); // OffsetToData (a real RVA — not resolved further)
  u32(view, rsrcBase + 0x48 + 4, 0x1a4); // Size
  u32(view, rsrcBase + 0x48 + 8, 1200); // CodePage
  u32(view, rsrcBase + 0x48 + 12, 0); // Reserved

  return bytes;
}

/** Same tree as buildPeWithResourceTree(), but the root directory's
 *  NumberOfIdEntries is corrupted to claim 9999 entries while the file is
 *  truncated immediately after the 16-byte root directory header — so not
 *  even the first IMAGE_RESOURCE_DIRECTORY_ENTRY (8 bytes) actually fits. */
function buildPeWithTruncatedResourceDirectory(): Uint8Array {
  const full = buildPeWithResourceTree();
  const view = new DataView(full.buffer);
  const rsrcBase = 0x200;
  u16(view, rsrcBase + 14, 9999); // NumberOfIdEntries lies — claims 9999 entries
  return full.slice(0, rsrcBase + 16); // truncate right after the directory header
}

/** A minimal PE32+ (64-bit) header with no sections — just enough to prove
 *  the Magic=0x20b branch parses the widened ImageBase/no-BaseOfData layout
 *  correctly. ImageBase is deliberately > 0xFFFFFFFF so a 32-bit read could
 *  never produce the right value — only the true 8-byte read can. */
function buildMinimalPe32Plus(): Uint8Array {
  const bytes = new Uint8Array(0x148); // ends exactly at the end of the optional header
  const view = new DataView(bytes.buffer);

  bytes[0] = 0x4d;
  bytes[1] = 0x5a;
  u32(view, 0x3c, 0x40);

  bytes[0x40] = 0x50;
  bytes[0x41] = 0x45;
  bytes[0x42] = 0x00;
  bytes[0x43] = 0x00;

  u16(view, 0x44, 0x8664); // Machine = AMD64
  u16(view, 0x46, 0); // NumberOfSections
  u32(view, 0x48, 1650000000); // TimeDateStamp
  u32(view, 0x4c, 0);
  u32(view, 0x50, 0);
  u16(view, 0x54, 0xf0); // SizeOfOptionalHeader (PE32+ standard size)
  u16(view, 0x56, 0x0022); // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

  const opt = 0x58;
  u16(view, opt + 0, 0x20b); // Magic = PE32+
  u8(view, opt + 2, 14);
  u8(view, opt + 3, 0);
  u32(view, opt + 4, 0);
  u32(view, opt + 8, 0);
  u32(view, opt + 12, 0);
  u32(view, opt + 16, 0x2000); // AddressOfEntryPoint
  u32(view, opt + 20, 0x1000); // BaseOfCode
  u64(view, opt + 24, 0x140000000n); // ImageBase (8 bytes, no BaseOfData in PE32+)
  u32(view, opt + 32, 0x1000); // SectionAlignment
  u32(view, opt + 36, 0x200); // FileAlignment
  u16(view, opt + 40, 6);
  u16(view, opt + 42, 0);
  u16(view, opt + 44, 0);
  u16(view, opt + 46, 0);
  u16(view, opt + 48, 6);
  u16(view, opt + 50, 0);
  u32(view, opt + 52, 0); // Win32VersionValue
  u32(view, opt + 56, 0x4000); // SizeOfImage
  u32(view, opt + 60, 0x148); // SizeOfHeaders
  u32(view, opt + 64, 0); // CheckSum
  u16(view, opt + 68, 3); // Subsystem
  u16(view, opt + 70, 0); // DllCharacteristics
  u64(view, opt + 72, 0x100000n); // SizeOfStackReserve
  u64(view, opt + 80, 0x1000n); // SizeOfStackCommit
  u64(view, opt + 88, 0x100000n); // SizeOfHeapReserve
  u64(view, opt + 96, 0x1000n); // SizeOfHeapCommit
  u32(view, opt + 104, 0); // LoaderFlags
  u32(view, opt + 108, 16); // NumberOfRvaAndSizes
  // DataDirectory[16] @ opt+112 — all zero (buffer already zero-initialized)

  return bytes;
}

describe('parsePe — valid PE32', () => {
  const result = parsePe(buildValidPe32());

  it('parses successfully', () => {
    expect(result.ok).toBe(true);
  });

  if (!result.ok) throw new Error('setup failed'); // narrow the type for the rest of this block

  it('reads the DOS header (MZ magic + e_lfanew)', () => {
    expect(result.info.dos.magic).toBe('MZ');
    expect(result.info.dos.e_lfanew).toBe(0x40);
  });

  it('reads the COFF File Header, decoding Machine/Characteristics and formatting TimeDateStamp as UTC', () => {
    expect(result.info.coff.machine).toBe(0x14c);
    expect(result.info.coff.machineName).toBe('I386 (x86)');
    expect(result.info.coff.numberOfSections).toBe(1);
    expect(result.info.coff.timeDateStamp).toBe(1600000000);
    expect(result.info.coff.timeDateStampIso).toBe(new Date(1600000000 * 1000).toISOString());
    expect(result.info.coff.characteristicsFlags).toEqual(['EXECUTABLE_IMAGE', '32BIT_MACHINE']);
  });

  it('reads the PE32 Optional Header (Magic, entry point, image base)', () => {
    expect(result.info.optional.magic).toBe(0x10b);
    expect(result.info.optional.magicName).toBe('PE32');
    expect(result.info.optional.addressOfEntryPoint).toBe(0x1000);
    expect(result.info.optional.imageBase).toBe(0x400000n);
    expect(result.info.isPe32Plus).toBe(false);
  });

  it('reads the section table, decoding characteristics including MEM_EXECUTE/MEM_READ/MEM_WRITE', () => {
    expect(result.info.sections).toHaveLength(1);
    const sec = result.info.sections[0];
    expect(sec.name).toBe('.text');
    expect(sec.virtualSize).toBe(0x200);
    expect(sec.virtualAddress).toBe(0x1000);
    expect(sec.sizeOfRawData).toBe(0x200);
    expect(sec.characteristicsFlags).toEqual(expect.arrayContaining(['MEM_EXECUTE', 'MEM_READ', 'MEM_WRITE']));
  });

  it('walks the Import Directory Table and resolves the DLL + function name', () => {
    expect(result.info.imports).toHaveLength(1);
    expect(result.info.imports[0].name).toBe('KERNEL32.dll');
    expect(result.info.imports[0].functions).toEqual([{ name: 'ExitProcess', isOrdinal: false }]);
  });

  it('has no export table (data directory entry is empty)', () => {
    expect(result.info.exports).toBeNull();
    expect(result.info.exportDllName).toBeNull();
  });

  it('has no resource directory (data directory entry is empty)', () => {
    expect(result.info.resources).toBeNull();
  });

  it('computes the correct imphash: MD5 of the lowercased "kernel32.exitprocess"', () => {
    const expected = md5Hex(new TextEncoder().encode('kernel32.exitprocess'));
    expect(result.info.imphash).toBe(expected);
  });

  it('always includes the disassembly/signature-verification out-of-scope note', () => {
    expect(result.info.notes.some((n) => /disassembly/i.test(n) && /signature/i.test(n))).toBe(true);
  });

  it('does not flag CLR or .rsrc notes for a plain native PE', () => {
    expect(result.info.notes.some((n) => /\.NET|CLR/i.test(n))).toBe(false);
    expect(result.info.notes.some((n) => /\.rsrc/i.test(n))).toBe(false);
  });
});

describe('parsePe — Resource Directory (.rsrc) tree', () => {
  it('walks a 3-level Type -> Name/ID -> Language tree and recovers exactly one RT_VERSION entry', () => {
    const result = parsePe(buildPeWithResourceTree());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const resources = result.info.resources;
    if (resources == null) throw new Error('expected a resolved resource directory'); // narrow the type for the rest of this test
    expect(resources).toHaveLength(1);
    const r = resources[0];
    expect(r.typeId).toBe(16);
    expect(r.typeName).toBe('VERSION');
    expect(r.nameOrId).toBe('1');
    expect(r.languageId).toBe(0x409);
    expect(r.size).toBe(0x1a4);
    expect(r.codePage).toBe(1200);
  });

  it('updates the .rsrc note to say entries are listed structurally but content is not rendered', () => {
    const result = parsePe(buildPeWithResourceTree());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const note = result.info.notes.find((n) => /\.rsrc/.test(n));
    expect(note).toBeDefined();
    expect(note).toMatch(/resource directory tree/i);
    expect(note).toMatch(/not rendered/i);
  });

  it('gracefully degrades a truncated/corrupt resource directory instead of failing the whole parse', () => {
    const result = parsePe(buildPeWithTruncatedResourceDirectory());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // The root directory (falsely) claims 9999 entries, but the file is
    // truncated immediately after the 16-byte directory header, so not even
    // the first 8-byte entry fits — the walk stops immediately, same
    // "break early, keep what parsed so far" convention used by the
    // truncated section/import-table loops above, rather than throwing.
    expect(result.info.resources).toEqual([]);
  });

  it('never throws on a resource directory built from hostile/random bytes', () => {
    const bytes = buildPeWithResourceTree();
    const view = new DataView(bytes.buffer);
    // Corrupt the Name-level directory's entry count to something huge
    // without truncating the file — forces the walk to run off the end of
    // legitimate resource data into the rest of the buffer.
    view.setUint16(0x200 + 0x18 + 14, 0xffff, true);
    expect(() => parsePe(bytes)).not.toThrow();
    const result = parsePe(bytes);
    expect(result.ok).toBe(true);
  });
});

describe('parsePe — valid PE32+', () => {
  it('parses the 64-bit Optional Header branch (Magic 0x20b), correctly reading an 8-byte ImageBase', () => {
    const result = parsePe(buildMinimalPe32Plus());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.info.optional.magic).toBe(0x20b);
    expect(result.info.optional.magicName).toBe('PE32+');
    expect(result.info.isPe32Plus).toBe(true);
    expect(result.info.optional.addressOfEntryPoint).toBe(0x2000);
    // > 0xFFFFFFFF — only a genuine 64-bit read can produce this value.
    expect(result.info.optional.imageBase).toBe(0x140000000n);
    expect(result.info.coff.machineName).toBe('AMD64 (x64)');
  });
});

describe('parsePe — malformed input fails cleanly with a specific message', () => {
  it('rejects a file missing the MZ signature', () => {
    const bytes = buildValidPe32();
    bytes[0] = 0x00; // corrupt 'M'
    const result = parsePe(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe('Not a valid PE file — missing MZ signature.');
  });

  it('rejects an e_lfanew that points past the end of the file', () => {
    const bytes = buildValidPe32();
    const view = new DataView(bytes.buffer);
    u32(view, 0x3c, bytes.length + 500); // way past EOF
    const result = parsePe(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('e_lfanew');
    expect(result.error).toContain('points past the end of the file');
  });

  it('rejects a bad PE signature at the expected offset', () => {
    const bytes = buildValidPe32();
    bytes[0x40] = 0x00; // corrupt 'P' of "PE\0\0"
    const result = parsePe(bytes);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe('Not a valid PE file — missing PE signature at the expected offset (0x40).');
  });

  it('rejects a file too small to even contain a DOS header', () => {
    const result = parsePe(new Uint8Array(10));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe('Not a valid PE file — the file is too small to contain a DOS header.');
  });

  it('never throws — every failure path returns a result object', () => {
    // A grab-bag of hostile/garbage input that must not crash the parser.
    expect(() => parsePe(new Uint8Array(0))).not.toThrow();
    expect(() => parsePe(new Uint8Array([0x4d, 0x5a]))).not.toThrow();
    expect(() => parsePe(crypto.getRandomValues(new Uint8Array(2048)))).not.toThrow();
  });
});
