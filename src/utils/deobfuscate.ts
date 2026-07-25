// Codec Builder — a chainable pipeline of reversible transforms
// (Base64/hex/URL encode+decode, ROT13/ROT47, single-byte XOR, and Gzip/
// Deflate inflate) applied in order, each step's output feeding the next
// step's input. Every transform runs entirely client-side and operates on
// raw bytes (Uint8Array) as the canonical representation flowing through the
// pipeline — not JS strings — so a step never has to guess an encoding for
// data that might be arbitrary binary partway through a chain (e.g. the
// output of an XOR step). Text-oriented transforms (Base64/hex/URL) read and
// write that byte stream as a Latin-1 "binary string" (one JS char code per
// byte, exactly how atob/btoa already treat their input) rather than via
// UTF-8, which would misinterpret bytes that aren't valid UTF-8.
//
// Scope is deliberately fixed to the steps above — no multi-byte XOR with an
// unknown key length, no other ciphers. See DeobfuscatorBuilder.astro.

export type StepKind =
  | 'base64-decode'
  | 'base64-encode'
  | 'hex-decode'
  | 'hex-encode'
  | 'url-decode'
  | 'url-encode'
  | 'rot13'
  | 'rot47'
  | 'xor'
  | 'gzip-inflate'
  | 'deflate-inflate'
  | 'utf16le-decode';

export interface StepDefinition {
  id: StepKind;
  label: string;
  /** Short form for the compact rail badge. */
  shortLabel: string;
  /** True for the two steps that need the DecompressionStream Web API. */
  needsDecompressionStream?: boolean;
}

export const DEOBFUSCATE_STEPS: StepDefinition[] = [
  { id: 'base64-decode', label: 'Base64 decode', shortLabel: 'B64 decode' },
  { id: 'base64-encode', label: 'Base64 encode', shortLabel: 'B64 encode' },
  { id: 'hex-decode', label: 'Hex decode', shortLabel: 'Hex decode' },
  { id: 'hex-encode', label: 'Hex encode', shortLabel: 'Hex encode' },
  { id: 'url-decode', label: 'URL decode', shortLabel: 'URL decode' },
  { id: 'url-encode', label: 'URL encode', shortLabel: 'URL encode' },
  { id: 'rot13', label: 'ROT13', shortLabel: 'ROT13' },
  { id: 'rot47', label: 'ROT47', shortLabel: 'ROT47' },
  { id: 'xor', label: 'XOR (single byte)', shortLabel: 'XOR' },
  { id: 'gzip-inflate', label: 'Gzip inflate', shortLabel: 'Gzip inflate', needsDecompressionStream: true },
  { id: 'deflate-inflate', label: 'Deflate inflate (zlib)', shortLabel: 'Deflate inflate', needsDecompressionStream: true },
  { id: 'utf16le-decode', label: 'UTF-16LE decode (e.g. PowerShell -EncodedCommand)', shortLabel: 'UTF-16LE decode' },
];

export function stepDefinition(kind: StepKind): StepDefinition {
  const def = DEOBFUSCATE_STEPS.find((s) => s.id === kind);
  if (!def) throw new Error(`Unknown deobfuscation step: ${kind}`);
  return def;
}

// ---------------------------------------------------------------------------
// Byte <-> "binary string" helpers. A binary string is a JS string where each
// UTF-16 code unit is exactly one byte's value (0-255) — the same convention
// atob/btoa use — so it round-trips arbitrary bytes losslessly, unlike a
// UTF-8 decode/encode round trip.
// ---------------------------------------------------------------------------

function bytesToBinaryString(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
  return out;
}

function binaryStringToBytes(str: string): Uint8Array {
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i) & 0xff;
  return bytes;
}

/** A byte-producing result: either the transformed bytes, or a friendly error. */
export type ByteResult = { ok: true; bytes: Uint8Array } | { ok: false; error: string };

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

export function toHexString(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

/** Fraction of bytes that are printable ASCII (or common whitespace) — used both
 *  to rank XOR brute-force candidates and to decide whether the final output
 *  is likely text or likely binary. */
export function printableAsciiRatio(bytes: Uint8Array): number {
  if (bytes.length === 0) return 1;
  let printable = 0;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if ((b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d) printable++;
  }
  return printable / bytes.length;
}

/** Heuristic: below this printable-ASCII ratio, treat the data as binary for display purposes. */
const BINARY_RATIO_THRESHOLD = 0.85;

export function isLikelyBinary(bytes: Uint8Array): boolean {
  return bytes.length > 0 && printableAsciiRatio(bytes) < BINARY_RATIO_THRESHOLD;
}

/** Best-effort UTF-8 text rendering for display — never throws (invalid
 *  sequences render as the U+FFFD replacement character), since this only
 *  feeds a read-only preview, never a further pipeline step. */
export function bytesToDisplayText(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

/** A short, always-printable preview (non-printable bytes shown as `.`), used
 *  for the XOR brute-force candidate list. */
export function bytesToPreviewText(bytes: Uint8Array, maxLen = 96): string {
  const limit = Math.min(bytes.length, maxLen);
  let out = '';
  for (let i = 0; i < limit; i++) {
    const b = bytes[i];
    out += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.';
  }
  return bytes.length > maxLen ? out + '…' : out;
}

// ---------------------------------------------------------------------------
// Base64
// ---------------------------------------------------------------------------

export function base64EncodeBytes(input: Uint8Array): Uint8Array {
  return binaryStringToBytes(btoa(bytesToBinaryString(input)));
}

export function base64DecodeBytes(input: Uint8Array): ByteResult {
  const text = bytesToBinaryString(input).trim().replace(/\s+/g, '');
  if (text.length === 0) return { ok: true, bytes: new Uint8Array(0) };
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text) || text.length % 4 !== 0) {
    return { ok: false, error: 'Not valid Base64 at this step — unexpected characters or length.' };
  }
  try {
    return { ok: true, bytes: binaryStringToBytes(atob(text)) };
  } catch {
    return { ok: false, error: 'Not valid Base64 at this step — unexpected characters or length.' };
  }
}

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------

export function hexEncodeBytes(input: Uint8Array): Uint8Array {
  return binaryStringToBytes(toHexString(input));
}

export function hexDecodeBytes(input: Uint8Array): ByteResult {
  // Tolerate common copy-paste noise: a leading 0x, and whitespace/colon/dash
  // byte separators (e.g. "de ad be ef" or "de:ad:be:ef").
  const text = bytesToBinaryString(input).trim().replace(/^0x/i, '').replace(/[\s:,-]/g, '');
  if (text.length === 0) return { ok: true, bytes: new Uint8Array(0) };
  if (!/^[0-9a-fA-F]+$/.test(text)) return { ok: false, error: 'Not valid hex at this step — non-hex characters found.' };
  if (text.length % 2 !== 0) return { ok: false, error: 'Not valid hex at this step — odd number of hex digits.' };
  const bytes = new Uint8Array(text.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return { ok: true, bytes };
}

// ---------------------------------------------------------------------------
// URL (percent) encoding — operates byte-for-byte (RFC 3986 unreserved set),
// deliberately not `application/x-www-form-urlencoded`'s "+ means space", so
// encode/decode round-trip cleanly for arbitrary binary data.
// ---------------------------------------------------------------------------

const URL_UNRESERVED = /[A-Za-z0-9\-_.~]/;

export function urlEncodeBytes(input: Uint8Array): Uint8Array {
  let out = '';
  for (let i = 0; i < input.length; i++) {
    const b = input[i];
    const ch = String.fromCharCode(b);
    out += b < 128 && URL_UNRESERVED.test(ch) ? ch : '%' + b.toString(16).toUpperCase().padStart(2, '0');
  }
  return binaryStringToBytes(out);
}

export function urlDecodeBytes(input: Uint8Array): ByteResult {
  const text = bytesToBinaryString(input);
  const out: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '%') {
      const hex = text.slice(i + 1, i + 3);
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) {
        return { ok: false, error: `Not valid URL-encoding at this step — malformed "%" escape near position ${i}.` };
      }
      out.push(parseInt(hex, 16));
      i += 2;
    } else {
      out.push(ch.charCodeAt(0) & 0xff);
    }
  }
  return { ok: true, bytes: Uint8Array.from(out) };
}

// ---------------------------------------------------------------------------
// UTF-16LE decode — PowerShell's `-EncodedCommand` convention is Base64 of a
// UTF-16LE string (not UTF-8), so a straight Base64 decode alone leaves a
// null byte between every character when displayed. This step re-decodes the
// pipeline's byte stream as UTF-16LE and re-encodes it as UTF-8 bytes, so it
// slots back into this file's own byte-stream convention (bytesToDisplayText
// always decodes as UTF-8 for display — see this file's header comment).
// ---------------------------------------------------------------------------

export function utf16leDecodeBytes(input: Uint8Array): ByteResult {
  if (input.length % 2 !== 0) {
    return { ok: false, error: 'Not valid UTF-16LE at this step — odd number of bytes (each UTF-16 code unit is 2 bytes).' };
  }
  try {
    const text = new TextDecoder('utf-16le', { fatal: true }).decode(input);
    return { ok: true, bytes: new TextEncoder().encode(text) };
  } catch {
    return { ok: false, error: 'Not valid UTF-16LE at this step — contains an invalid UTF-16 code unit sequence.' };
  }
}

// ---------------------------------------------------------------------------
// ROT13 / ROT47 — both self-inverse, so one step handles encode and decode.
// ---------------------------------------------------------------------------

export function rot13Bytes(input: Uint8Array): Uint8Array {
  const out = new Uint8Array(input.length);
  for (let i = 0; i < input.length; i++) {
    const b = input[i];
    if (b >= 65 && b <= 90) out[i] = ((b - 65 + 13) % 26) + 65;
    else if (b >= 97 && b <= 122) out[i] = ((b - 97 + 13) % 26) + 97;
    else out[i] = b;
  }
  return out;
}

export function rot47Bytes(input: Uint8Array): Uint8Array {
  const out = new Uint8Array(input.length);
  for (let i = 0; i < input.length; i++) {
    const b = input[i];
    out[i] = b >= 33 && b <= 126 ? 33 + ((b - 33 + 47) % 94) : b;
  }
  return out;
}

// ---------------------------------------------------------------------------
// XOR (single byte key)
// ---------------------------------------------------------------------------

export function xorBytes(input: Uint8Array, key: number): Uint8Array {
  const k = key & 0xff;
  const out = new Uint8Array(input.length);
  for (let i = 0; i < input.length; i++) out[i] = input[i] ^ k;
  return out;
}

/** Parse a user-typed XOR key — plain decimal ("42") or 0x-prefixed hex
 *  ("0x2a") — into a single byte (0-255). Returns null for anything that
 *  isn't a valid single-byte key (empty, non-numeric, out of range, or a
 *  non-integer), so the caller can represent "no valid key yet" distinctly
 *  from a real key of 0. */
export function parseXorKey(raw: string): number | null {
  const text = raw.trim();
  if (text.length === 0) return null;
  let value: number;
  if (/^0x[0-9a-fA-F]+$/i.test(text)) {
    value = parseInt(text.slice(2), 16);
  } else if (/^[0-9]+$/.test(text)) {
    value = parseInt(text, 10);
  } else {
    return null;
  }
  if (!Number.isInteger(value) || value < 0 || value > 255) return null;
  return value;
}

export interface XorCandidate {
  key: number;
  printableRatio: number;
  preview: string;
}

/** Try every possible single-byte key (0-255), rank by printable-ASCII ratio
 *  of the resulting plaintext, and return the top `topN` (default 5). Ties
 *  break by ascending key so results are deterministic. */
export function xorBruteForce(input: Uint8Array, topN = 5): XorCandidate[] {
  const candidates: XorCandidate[] = [];
  for (let key = 0; key <= 255; key++) {
    const out = xorBytes(input, key);
    candidates.push({ key, printableRatio: printableAsciiRatio(out), preview: bytesToPreviewText(out) });
  }
  candidates.sort((a, b) => b.printableRatio - a.printableRatio || a.key - b.key);
  return candidates.slice(0, topN);
}

// ---------------------------------------------------------------------------
// Gzip / Deflate inflate — via the native DecompressionStream Web API. The
// component feature-detects availability and hides/disables these two step
// options when absent; this still fails cleanly here as a defensive fallback.
// ---------------------------------------------------------------------------

async function inflateWithFormat(input: Uint8Array, format: 'gzip' | 'deflate'): Promise<ByteResult> {
  if (typeof DecompressionStream === 'undefined') {
    return { ok: false, error: 'Decompression isn\'t supported in this browser.' };
  }
  try {
    const ds = new DecompressionStream(format);
    const writer = ds.writable.getWriter();
    const reader = ds.readable.getReader();
    // Copy into a plain Uint8Array view so a sliced/offset input can't upset
    // the stream implementation.
    const chunk = input.slice();

    // Write and read concurrently (not write-then-read) so a larger payload
    // can't deadlock on the writable stream's internal backpressure buffer.
    // Both promises are awaited inside this try block — critically, NOT
    // fire-and-forgotten — because a malformed stream (bad gzip/deflate
    // header) can reject either side, and an un-awaited rejection here would
    // surface as an unhandled promise rejection instead of the friendly
    // error this function returns.
    const parts: Uint8Array[] = [];
    let total = 0;
    const writeDone = writer.write(chunk).then(() => writer.close());
    const readDone = (async () => {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          parts.push(value);
          total += value.length;
        }
      }
    })();
    await Promise.all([writeDone, readDone]);

    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return { ok: true, bytes: out };
  } catch {
    const label = format === 'gzip' ? 'gzip' : 'zlib-wrapped Deflate';
    return { ok: false, error: `Not valid ${label} data at this step.` };
  }
}

export function gzipInflate(input: Uint8Array): Promise<ByteResult> {
  return inflateWithFormat(input, 'gzip');
}

export function deflateInflate(input: Uint8Array): Promise<ByteResult> {
  return inflateWithFormat(input, 'deflate');
}

// ---------------------------------------------------------------------------
// Pipeline — runs an ordered list of configured steps, each fed the previous
// step's output, stopping at the first failure so the UI can show exactly
// where a chain breaks rather than cascading garbage through every step
// after it.
// ---------------------------------------------------------------------------

export interface PipelineStepConfig {
  kind: StepKind;
  /** Required only for 'xor' steps; a brute-force step with no key chosen
   *  yet is represented by leaving this undefined. */
  xorKey?: number;
}

type PipelineStatus = 'ok' | 'error' | 'pending' | 'skipped';

export interface PipelineStepResult {
  kind: StepKind;
  status: PipelineStatus;
  bytes: Uint8Array;
  error?: string;
}

/** Apply a single configured step to `input`. Exported for direct testing and
 *  for the component to preview one step's effect in isolation. */
export async function applyStep(kind: StepKind, input: Uint8Array, options: { xorKey?: number } = {}): Promise<ByteResult> {
  switch (kind) {
    case 'base64-decode':
      return base64DecodeBytes(input);
    case 'base64-encode':
      return { ok: true, bytes: base64EncodeBytes(input) };
    case 'hex-decode':
      return hexDecodeBytes(input);
    case 'hex-encode':
      return { ok: true, bytes: hexEncodeBytes(input) };
    case 'url-decode':
      return urlDecodeBytes(input);
    case 'url-encode':
      return { ok: true, bytes: urlEncodeBytes(input) };
    case 'rot13':
      return { ok: true, bytes: rot13Bytes(input) };
    case 'rot47':
      return { ok: true, bytes: rot47Bytes(input) };
    case 'xor': {
      const key = options.xorKey;
      if (key === undefined || key === null || !Number.isInteger(key) || key < 0 || key > 255) {
        return { ok: false, error: 'XOR key must be a whole number between 0 and 255.' };
      }
      return { ok: true, bytes: xorBytes(input, key) };
    }
    case 'gzip-inflate':
      return gzipInflate(input);
    case 'deflate-inflate':
      return deflateInflate(input);
    case 'utf16le-decode':
      return utf16leDecodeBytes(input);
    default:
      return { ok: false, error: 'Unknown step.' };
  }
}

/** Run every configured step in order against `input`. A step that fails, or
 *  an XOR step still in brute-force mode with no key picked yet ('pending'),
 *  halts the chain — every step after it is marked 'skipped' rather than run
 *  against stale/garbage data. */
export async function runPipeline(input: Uint8Array, steps: PipelineStepConfig[]): Promise<PipelineStepResult[]> {
  const results: PipelineStepResult[] = [];
  let current = input;
  let halted = false;

  for (const step of steps) {
    if (halted) {
      results.push({ kind: step.kind, status: 'skipped', bytes: new Uint8Array(0) });
      continue;
    }
    if (step.kind === 'xor' && (step.xorKey === undefined || step.xorKey === null)) {
      results.push({ kind: step.kind, status: 'pending', bytes: new Uint8Array(0) });
      halted = true;
      continue;
    }
    const outcome = await applyStep(step.kind, current, { xorKey: step.xorKey });
    if (outcome.ok) {
      results.push({ kind: step.kind, status: 'ok', bytes: outcome.bytes });
      current = outcome.bytes;
    } else {
      results.push({ kind: step.kind, status: 'error', bytes: new Uint8Array(0), error: outcome.error });
      halted = true;
    }
  }

  return results;
}
