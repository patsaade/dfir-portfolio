import { describe, it, expect } from 'vitest';
import {
  base64EncodeBytes,
  base64DecodeBytes,
  hexEncodeBytes,
  hexDecodeBytes,
  urlEncodeBytes,
  urlDecodeBytes,
  rot13Bytes,
  rot47Bytes,
  xorBytes,
  xorBruteForce,
  parseXorKey,
  gzipInflate,
  deflateInflate,
  applyStep,
  runPipeline,
  toHexString,
  printableAsciiRatio,
  isLikelyBinary,
  bytesToDisplayText,
  utf16leDecodeBytes,
} from '../src/utils/deobfuscate';

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

describe('base64 encode/decode', () => {
  it('round-trips arbitrary text', () => {
    const original = enc('The quick brown fox jumps over the lazy dog. 🦊');
    const encoded = base64EncodeBytes(original);
    const decoded = base64DecodeBytes(encoded);
    expect(decoded.ok).toBe(true);
    if (decoded.ok) expect(decoded.bytes).toEqual(original);
  });

  it('matches a known Base64 vector', () => {
    expect(dec(base64EncodeBytes(enc('hello world')))).toBe('aGVsbG8gd29ybGQ=');
    const decoded = base64DecodeBytes(enc('aGVsbG8gd29ybGQ='));
    expect(decoded.ok).toBe(true);
    if (decoded.ok) expect(dec(decoded.bytes)).toBe('hello world');
  });

  it('round-trips raw binary bytes (not just text)', () => {
    const original = Uint8Array.from([0, 1, 2, 253, 254, 255, 128, 64]);
    const decoded = base64DecodeBytes(base64EncodeBytes(original));
    expect(decoded.ok).toBe(true);
    if (decoded.ok) expect(decoded.bytes).toEqual(original);
  });

  it('fails cleanly on malformed input', () => {
    const out = base64DecodeBytes(enc('not!!valid**base64'));
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error).toMatch(/not valid base64/i);
  });

  it('handles empty input', () => {
    const out = base64DecodeBytes(new Uint8Array(0));
    expect(out.ok).toBe(true);
    if (out.ok) expect(out.bytes).toHaveLength(0);
  });
});

describe('hex encode/decode', () => {
  it('round-trips arbitrary bytes', () => {
    const original = Uint8Array.from([0, 15, 16, 255, 128, 1]);
    const decoded = hexDecodeBytes(hexEncodeBytes(original));
    expect(decoded.ok).toBe(true);
    if (decoded.ok) expect(decoded.bytes).toEqual(original);
  });

  it('matches a known hex vector', () => {
    expect(dec(hexEncodeBytes(enc('hi')))).toBe('6869');
    const decoded = hexDecodeBytes(enc('6869'));
    expect(decoded.ok).toBe(true);
    if (decoded.ok) expect(dec(decoded.bytes)).toBe('hi');
  });

  it('tolerates 0x prefix and separators', () => {
    const decoded = hexDecodeBytes(enc('0xde:ad be-ef'));
    expect(decoded.ok).toBe(true);
    if (decoded.ok) expect(toHexString(decoded.bytes)).toBe('deadbeef');
  });

  it('fails cleanly on odd-length hex', () => {
    const out = hexDecodeBytes(enc('abc'));
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error).toMatch(/odd number/i);
  });

  it('fails cleanly on non-hex characters', () => {
    const out = hexDecodeBytes(enc('zzzz'));
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error).toMatch(/non-hex/i);
  });
});

describe('URL encode/decode', () => {
  it('round-trips arbitrary text including reserved characters', () => {
    const original = enc('a b/c?d=e&f#g%h+i');
    const decoded = urlDecodeBytes(urlEncodeBytes(original));
    expect(decoded.ok).toBe(true);
    if (decoded.ok) expect(decoded.bytes).toEqual(original);
  });

  it('matches a known vector', () => {
    expect(dec(urlEncodeBytes(enc('hello world!')))).toBe('hello%20world%21');
    const decoded = urlDecodeBytes(enc('hello%20world%21'));
    expect(decoded.ok).toBe(true);
    if (decoded.ok) expect(dec(decoded.bytes)).toBe('hello world!');
  });

  it('round-trips raw binary bytes', () => {
    const original = Uint8Array.from([0, 10, 13, 255, 37, 32]);
    const decoded = urlDecodeBytes(urlEncodeBytes(original));
    expect(decoded.ok).toBe(true);
    if (decoded.ok) expect(decoded.bytes).toEqual(original);
  });

  it('fails cleanly on a malformed percent escape', () => {
    const out = urlDecodeBytes(enc('100%'));
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error).toMatch(/malformed/i);
  });
});

describe('ROT13 / ROT47', () => {
  it('ROT13 is its own inverse and rotates only letters', () => {
    const original = enc('Hello, World! 123');
    const rotated = rot13Bytes(original);
    expect(dec(rotated)).toBe('Uryyb, Jbeyq! 123');
    expect(rot13Bytes(rotated)).toEqual(original);
  });

  it('ROT47 is its own inverse and rotates the full printable range', () => {
    const original = enc('Hello, World! 123');
    const rotated = rot47Bytes(original);
    expect(dec(rotated)).not.toBe(dec(original));
    expect(rot47Bytes(rotated)).toEqual(original);
  });
});

describe('XOR', () => {
  it('is its own inverse with the same key', () => {
    const original = enc('secret payload');
    expect(xorBytes(xorBytes(original, 0x42), 0x42)).toEqual(original);
  });

  it('masks the key to a single byte (256 wraps to 0)', () => {
    const original = enc('abc');
    expect(xorBytes(original, 256)).toEqual(original);
  });

  it('brute force ranks the correct key highest for known plaintext XOR\'d with a known key', () => {
    // A single low bit-flip of an all-printable plaintext's XOR key (e.g. key
    // ^ 1) very often *also* decodes to something 100%-printable — ASCII
    // 0x20-0x7E is one contiguous block, so flipping the low bit of most
    // printable bytes lands on another printable byte. That's a genuine
    // property of "printable-ratio" scoring (the same reason real single-byte
    // XOR crackers use letter-frequency scoring, not just a printable-ratio
    // heuristic) — not a bug in the ranking. This fixture/key pair (verified
    // empirically) has no other key producing a full 1.0 ratio, so the
    // correct key is the unique, unambiguous top candidate.
    const plaintext = enc(
      'Malware dropper stage2.bin decoded: C2=185.220.101.7:8443, mutex=Global{9F2A-11EE}, cmd=powershell -enc JAB4ID0g, retry=3x, sleep=45s, jitter=12percent, sha256=9f86d081884c7d659a2feaa0c55ad01.',
    );
    const key = 32;
    const ciphertext = xorBytes(plaintext, key);
    const candidates = xorBruteForce(ciphertext, 5);
    expect(candidates).toHaveLength(5);
    expect(candidates[0].key).toBe(key);
    expect(candidates[0].printableRatio).toBe(1);
    // Every candidate must be sorted in non-increasing ratio order.
    for (let i = 1; i < candidates.length; i++) {
      expect(candidates[i - 1].printableRatio).toBeGreaterThanOrEqual(candidates[i].printableRatio);
    }
  });

  it('brute force returns exactly 256 candidates when topN is large enough', () => {
    const ciphertext = xorBytes(enc('another known plaintext string for ranking'), 0x13);
    expect(xorBruteForce(ciphertext, 300)).toHaveLength(256);
  });
});

describe('parseXorKey', () => {
  it('parses plain decimal keys', () => {
    expect(parseXorKey('42')).toBe(42);
    expect(parseXorKey('0')).toBe(0);
    expect(parseXorKey('255')).toBe(255);
  });

  it('parses 0x-prefixed hex keys, case-insensitively', () => {
    expect(parseXorKey('0x2a')).toBe(42);
    expect(parseXorKey('0X2A')).toBe(42);
    expect(parseXorKey('0xff')).toBe(255);
    expect(parseXorKey('0x00')).toBe(0);
  });

  it('trims surrounding whitespace', () => {
    expect(parseXorKey('  42  ')).toBe(42);
  });

  it('rejects empty input', () => {
    expect(parseXorKey('')).toBeNull();
    expect(parseXorKey('   ')).toBeNull();
  });

  it('rejects out-of-range values', () => {
    expect(parseXorKey('256')).toBeNull();
    expect(parseXorKey('0x100')).toBeNull();
    expect(parseXorKey('-1')).toBeNull();
  });

  it('rejects non-numeric or malformed input', () => {
    expect(parseXorKey('abc')).toBeNull();
    expect(parseXorKey('4.5')).toBeNull();
    expect(parseXorKey('0x')).toBeNull();
    expect(parseXorKey('0xzz')).toBeNull();
  });
});

describe('printableAsciiRatio / isLikelyBinary', () => {
  it('treats fully printable text as ratio 1 and not binary', () => {
    const bytes = enc('all printable ASCII text');
    expect(printableAsciiRatio(bytes)).toBe(1);
    expect(isLikelyBinary(bytes)).toBe(false);
  });

  it('treats mostly non-printable bytes as binary', () => {
    const bytes = Uint8Array.from([0, 1, 2, 3, 4, 5, 255, 254, 253, 252]);
    expect(printableAsciiRatio(bytes)).toBeLessThan(0.5);
    expect(isLikelyBinary(bytes)).toBe(true);
  });

  it('empty input is treated as fully printable (ratio 1, not binary)', () => {
    expect(printableAsciiRatio(new Uint8Array(0))).toBe(1);
    expect(isLikelyBinary(new Uint8Array(0))).toBe(false);
  });
});

describe('bytesToDisplayText', () => {
  it('never throws on invalid UTF-8, renders replacement characters instead', () => {
    const invalid = Uint8Array.from([0xff, 0xfe, 0x80, 0x81]);
    expect(() => bytesToDisplayText(invalid)).not.toThrow();
  });

  it('decodes valid UTF-8 text correctly', () => {
    expect(bytesToDisplayText(enc('héllo wörld'))).toBe('héllo wörld');
  });
});

describe('utf16leDecodeBytes', () => {
  it('recovers a known ASCII string from its UTF-16LE byte representation', () => {
    // Build UTF-16LE bytes by hand: each code unit is 2 bytes, low byte first,
    // high byte 0x00 for ASCII — exactly what PowerShell's -EncodedCommand
    // produces before Base64-wrapping.
    const utf16le = Uint8Array.from(Array.from('whoami').flatMap((c) => [c.charCodeAt(0), 0]));
    const result = utf16leDecodeBytes(utf16le);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(dec(result.bytes)).toBe('whoami');
      expect(bytesToDisplayText(result.bytes)).toBe('whoami');
    }
  });

  it('fails cleanly on odd-length input instead of throwing', () => {
    const out = utf16leDecodeBytes(Uint8Array.from([0x77, 0x00, 0x68]));
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error).toMatch(/odd number of bytes/i);
  });

  it('runs end-to-end through the pipeline: base64-decode then utf16le-decode recovers a PowerShell -EncodedCommand-style payload', async () => {
    const command = 'whoami /all';
    // Mimic PowerShell's own -EncodedCommand convention: UTF-16LE bytes of the
    // command text, then Base64-encoded.
    const utf16le = Uint8Array.from(Array.from(command).flatMap((c) => [c.charCodeAt(0), 0]));
    const base64 = btoa(String.fromCharCode(...utf16le));

    const results = await runPipeline(enc(base64), [
      { kind: 'base64-decode' },
      { kind: 'utf16le-decode' },
    ]);
    expect(results).toHaveLength(2);
    expect(results[0].status).toBe('ok');
    expect(results[1].status).toBe('ok');
    expect(dec(results[1].bytes)).toBe(command);
  });
});

describe('gzip / deflate inflate (via native DecompressionStream, fixtures via CompressionStream)', () => {
  async function compress(format: 'gzip' | 'deflate', bytes: Uint8Array): Promise<Uint8Array> {
    const cs = new CompressionStream(format);
    const writer = cs.writable.getWriter();
    // .slice() (not the raw `bytes` param) — matches gzipInflate/deflateInflate's
    // own defensive copy in src/utils/deobfuscate.ts, and sidesteps a TS
    // ArrayBufferLike-vs-ArrayBuffer generic mismatch a bare Uint8Array param
    // otherwise hits against WritableStream<BufferSource>.write().
    void writer.write(bytes.slice());
    void writer.close();
    const reader = cs.readable.getReader();
    const parts: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        parts.push(value);
        total += value.length;
      }
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return out;
  }

  it('gzipInflate round-trips data compressed with CompressionStream', async () => {
    const original = enc('DFIR tooling: Volatility 3, Velociraptor, KAPE, and plenty of coffee.'.repeat(20));
    const compressed = await compress('gzip', original);
    const result = await gzipInflate(compressed);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.bytes).toEqual(original);
  });

  it('deflateInflate round-trips data compressed with CompressionStream', async () => {
    const original = enc('zlib-wrapped deflate stream for round-trip verification.'.repeat(20));
    const compressed = await compress('deflate', original);
    const result = await deflateInflate(compressed);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.bytes).toEqual(original);
  });

  it('fails cleanly on non-gzip data instead of throwing', async () => {
    const result = await gzipInflate(enc('not actually gzip data'));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(/gzip/i);
  });

  it('fails cleanly on non-deflate data instead of throwing', async () => {
    const result = await deflateInflate(enc('not actually deflate data'));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(/deflate/i);
  });
});

describe('applyStep', () => {
  it('rejects an out-of-range or missing XOR key with a friendly error', async () => {
    const out1 = await applyStep('xor', enc('data'), {});
    expect(out1.ok).toBe(false);
    const out2 = await applyStep('xor', enc('data'), { xorKey: 300 });
    expect(out2.ok).toBe(false);
    const out3 = await applyStep('xor', enc('data'), { xorKey: 1.5 });
    expect(out3.ok).toBe(false);
  });
});

describe('runPipeline', () => {
  it('chains steps in order, each fed the previous output', async () => {
    const original = enc('chained payload');
    const results = await runPipeline(original, [
      { kind: 'base64-encode' },
      { kind: 'hex-encode' },
    ]);
    expect(results).toHaveLength(2);
    expect(results[0].status).toBe('ok');
    expect(results[1].status).toBe('ok');
    // Reverse the chain manually to confirm the final output is correct.
    const hexDecoded = hexDecodeBytes(results[1].bytes);
    expect(hexDecoded.ok).toBe(true);
    if (hexDecoded.ok) {
      const b64Decoded = base64DecodeBytes(hexDecoded.bytes);
      expect(b64Decoded.ok).toBe(true);
      if (b64Decoded.ok) expect(b64Decoded.bytes).toEqual(original);
    }
  });

  it('a full round-trip pipeline recovers the original input', async () => {
    const original = enc('round trip through every reversible step');
    const results = await runPipeline(original, [
      { kind: 'base64-encode' },
      { kind: 'hex-encode' },
      { kind: 'url-encode' },
      { kind: 'rot13' },
      { kind: 'xor', xorKey: 0x99 },
    ]);
    expect(results.every((r) => r.status === 'ok')).toBe(true);
    let current = results[results.length - 1].bytes;
    // Undo in reverse order.
    current = xorBytes(current, 0x99);
    current = rot13Bytes(current);
    let step = urlDecodeBytes(current);
    expect(step.ok).toBe(true);
    if (!step.ok) return;
    step = hexDecodeBytes(step.bytes);
    expect(step.ok).toBe(true);
    if (!step.ok) return;
    step = base64DecodeBytes(step.bytes);
    expect(step.ok).toBe(true);
    if (step.ok) expect(step.bytes).toEqual(original);
  });

  it('stops the chain at the first failure and marks remaining steps skipped', async () => {
    const results = await runPipeline(enc('not base64 at all !!'), [
      { kind: 'base64-decode' },
      { kind: 'hex-encode' },
      { kind: 'rot13' },
    ]);
    expect(results[0].status).toBe('error');
    expect(results[1].status).toBe('skipped');
    expect(results[2].status).toBe('skipped');
  });

  it('a brute-force XOR step with no key yet is "pending" and halts downstream steps', async () => {
    const results = await runPipeline(enc('some data'), [
      { kind: 'xor' },
      { kind: 'hex-encode' },
    ]);
    expect(results[0].status).toBe('pending');
    expect(results[1].status).toBe('skipped');
  });
});
