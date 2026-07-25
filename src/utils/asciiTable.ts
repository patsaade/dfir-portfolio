// The full standard 7-bit ASCII table (decimal 0-127) — dec/hex/oct/bin plus
// the character (or, for the 33 non-printable code points, its standard
// mnemonic and full name). Every mnemonic and name below is transcribed
// directly from the Unicode Consortium's own "C0 Controls and Basic Latin"
// code chart (https://www.unicode.org/charts/PDF/U0000.pdf, Unicode 17.0),
// the same authoritative source this project's Number Base Converter already
// cites for its own printable-ASCII range check — ASCII (ANSI X3.4, née
// ASA X3.4-1963) is normatively equivalent to Unicode code points U+0000
// through U+007F, so that chart is the correct ground truth for this table,
// not a second-hand "ASCII table" website. Pure data + pure derivation
// functions, no DOM — see test/asciiTable.test.ts, which round-trips every
// entry's hex/oct/bin against hand-computed values and checks the mnemonic/
// name transcription against the chart.

export type AsciiCategory = 'control' | 'punctuation' | 'digit' | 'upper' | 'lower';

export interface AsciiEntry {
  /** 0-127 */
  dec: number;
  /** "0x" + 2-digit uppercase hex, e.g. "0x41" */
  hex: string;
  /** 3-digit zero-padded octal, e.g. "101" */
  oct: string;
  /** 8-bit zero-padded binary (the 7-bit value with a leading 0), e.g. "01000001" */
  bin: string;
  /** The literal glyph for a printable character, or the standard mnemonic
   *  (e.g. "NUL", "LF", "DEL") for the 33 code points with no visible glyph
   *  of their own — see `hasMnemonic`. */
  char: string;
  /** The mnemonic alone when `hasMnemonic` is true, else null. */
  mnemonic: string | null;
  /** True for the 32 C0 controls (0-31), SPACE (32), and DEL (127) — the
   *  code points this table displays by mnemonic rather than literal glyph. */
  hasMnemonic: boolean;
  /** Full character name, transcribed from the Unicode chart (e.g. "Line Feed (New Line)", "Latin Capital Letter A"). */
  name: string;
  category: AsciiCategory;
}

// Mnemonic + name for every code point the chart labels as a <control>, plus
// SPACE (0x20, which the chart's own grid renders with the same 2-letter
// boxed-mnemonic convention as the C0 controls even though it's technically
// categorized under "ASCII punctuation and symbols") and DEL (0x7F).
// Transcribed 1:1 from the chart's "C0 controls" and "Control character"
// sections (pages 3 and 7 of the PDF above).
const CONTROL_NAMES: Record<number, { mnemonic: string; name: string }> = {
  0: { mnemonic: 'NUL', name: 'Null' },
  1: { mnemonic: 'SOH', name: 'Start of Heading' },
  2: { mnemonic: 'STX', name: 'Start of Text' },
  3: { mnemonic: 'ETX', name: 'End of Text' },
  4: { mnemonic: 'EOT', name: 'End of Transmission' },
  5: { mnemonic: 'ENQ', name: 'Enquiry' },
  6: { mnemonic: 'ACK', name: 'Acknowledge' },
  7: { mnemonic: 'BEL', name: 'Bell' },
  8: { mnemonic: 'BS', name: 'Backspace' },
  9: { mnemonic: 'HT', name: 'Character Tabulation (Horizontal Tab)' },
  10: { mnemonic: 'LF', name: 'Line Feed (New Line)' },
  11: { mnemonic: 'VT', name: 'Line Tabulation (Vertical Tab)' },
  12: { mnemonic: 'FF', name: 'Form Feed' },
  13: { mnemonic: 'CR', name: 'Carriage Return' },
  14: { mnemonic: 'SO', name: 'Shift Out' },
  15: { mnemonic: 'SI', name: 'Shift In' },
  16: { mnemonic: 'DLE', name: 'Data Link Escape' },
  17: { mnemonic: 'DC1', name: 'Device Control One' },
  18: { mnemonic: 'DC2', name: 'Device Control Two' },
  19: { mnemonic: 'DC3', name: 'Device Control Three' },
  20: { mnemonic: 'DC4', name: 'Device Control Four' },
  21: { mnemonic: 'NAK', name: 'Negative Acknowledge' },
  22: { mnemonic: 'SYN', name: 'Synchronous Idle' },
  23: { mnemonic: 'ETB', name: 'End of Transmission Block' },
  24: { mnemonic: 'CAN', name: 'Cancel' },
  25: { mnemonic: 'EM', name: 'End of Medium' },
  26: { mnemonic: 'SUB', name: 'Substitute' },
  27: { mnemonic: 'ESC', name: 'Escape' },
  28: { mnemonic: 'FS', name: 'Information Separator Four (File Separator)' },
  29: { mnemonic: 'GS', name: 'Information Separator Three (Group Separator)' },
  30: { mnemonic: 'RS', name: 'Information Separator Two (Record Separator)' },
  31: { mnemonic: 'US', name: 'Information Separator One (Unit Separator)' },
  32: { mnemonic: 'SP', name: 'Space' },
  127: { mnemonic: 'DEL', name: 'Delete' },
};

// Full character names for every printable code point (33-126), transcribed
// from the chart's own per-character entries (pages 3-7). Digits and letters
// follow the chart's own "DIGIT <word>" / "LATIN {CAPITAL,SMALL} LETTER <X>"
// naming exactly, generated below rather than hand-typed 62 times.
const DIGIT_WORDS = ['Zero', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven', 'Eight', 'Nine'];

const PUNCTUATION_NAMES: Record<number, string> = {
  33: 'Exclamation Mark',
  34: 'Quotation Mark',
  35: 'Number Sign',
  36: 'Dollar Sign',
  37: 'Percent Sign',
  38: 'Ampersand',
  39: 'Apostrophe',
  40: 'Left Parenthesis',
  41: 'Right Parenthesis',
  42: 'Asterisk',
  43: 'Plus Sign',
  44: 'Comma',
  45: 'Hyphen-Minus',
  46: 'Full Stop',
  47: 'Solidus',
  58: 'Colon',
  59: 'Semicolon',
  60: 'Less-Than Sign',
  61: 'Equals Sign',
  62: 'Greater-Than Sign',
  63: 'Question Mark',
  64: 'Commercial At',
  91: 'Left Square Bracket',
  92: 'Reverse Solidus',
  93: 'Right Square Bracket',
  94: 'Circumflex Accent',
  95: 'Low Line',
  96: 'Grave Accent',
  123: 'Left Curly Bracket',
  124: 'Vertical Line',
  125: 'Right Curly Bracket',
  126: 'Tilde',
};

function categoryFor(dec: number): AsciiCategory {
  if (dec <= 31 || dec === 127) return 'control';
  if (dec >= 48 && dec <= 57) return 'digit';
  if (dec >= 65 && dec <= 90) return 'upper';
  if (dec >= 97 && dec <= 122) return 'lower';
  return 'punctuation'; // 32 (space), 33-47, 58-64, 91-96, 123-126
}

function nameFor(dec: number): string {
  if (dec in CONTROL_NAMES) return CONTROL_NAMES[dec].name;
  if (dec >= 48 && dec <= 57) return `Digit ${DIGIT_WORDS[dec - 48]}`;
  if (dec >= 65 && dec <= 90) return `Latin Capital Letter ${String.fromCharCode(dec)}`;
  if (dec >= 97 && dec <= 122) return `Latin Small Letter ${String.fromCharCode(dec - 32)}`;
  return PUNCTUATION_NAMES[dec];
}

/** Formats `dec` (0-255) as "0x" + 2-digit uppercase hex, e.g. 65 -> "0x41". */
export function toHexByte(dec: number): string {
  return '0x' + dec.toString(16).toUpperCase().padStart(2, '0');
}

/** Formats `dec` (0-255) as 3-digit zero-padded octal, e.g. 65 -> "101". */
export function toOctByte(dec: number): string {
  return dec.toString(8).padStart(3, '0');
}

/** Formats `dec` (0-255) as 8-bit zero-padded binary, e.g. 65 -> "01000001". */
export function toBinByte(dec: number): string {
  return dec.toString(2).padStart(8, '0');
}

/** Builds one AsciiEntry for a single code point (0-127). */
export function asciiEntry(dec: number): AsciiEntry {
  if (!Number.isInteger(dec) || dec < 0 || dec > 127) {
    throw new RangeError(`asciiEntry: dec must be an integer 0-127, got ${dec}`);
  }
  const control = CONTROL_NAMES[dec];
  const hasMnemonic = control !== undefined;
  return {
    dec,
    hex: toHexByte(dec),
    oct: toOctByte(dec),
    bin: toBinByte(dec),
    char: hasMnemonic ? control.mnemonic : String.fromCharCode(dec),
    mnemonic: hasMnemonic ? control.mnemonic : null,
    hasMnemonic,
    name: nameFor(dec),
    category: categoryFor(dec),
  };
}

/** The full, ordered (0-127) standard 7-bit ASCII table. */
export function buildAsciiTable(): AsciiEntry[] {
  const out: AsciiEntry[] = [];
  for (let dec = 0; dec <= 127; dec++) out.push(asciiEntry(dec));
  return out;
}

export const ASCII_TABLE: AsciiEntry[] = buildAsciiTable();

export const ASCII_CATEGORY_LABELS: Record<AsciiCategory, string> = {
  control: 'Control characters',
  punctuation: 'Punctuation & symbols',
  digit: 'Digits',
  upper: 'Uppercase letters',
  lower: 'Lowercase letters',
};
