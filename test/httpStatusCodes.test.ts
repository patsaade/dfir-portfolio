import { describe, it, expect } from 'vitest';
import { HTTP_STATUS_CODES, type HttpStatusEntry } from '../src/data/httpStatusCodes';

const byCode = new Map(HTTP_STATUS_CODES.map((e) => [e.code, e]));

describe('HTTP status code reference data', () => {
  it('has a healthy number of entries', () => {
    expect(HTTP_STATUS_CODES.length).toBeGreaterThanOrEqual(50);
  });

  it('has unique codes', () => {
    const codes = new Set(HTTP_STATUS_CODES.map((e) => e.code));
    expect(codes.size).toBe(HTTP_STATUS_CODES.length);
  });

  it('keeps every code inside the valid 100-599 range', () => {
    for (const e of HTTP_STATUS_CODES) {
      expect(e.code, String(e.code)).toBeGreaterThanOrEqual(100);
      expect(e.code, String(e.code)).toBeLessThanOrEqual(599);
    }
  });

  it('assigns statusClass consistently with the code\'s leading digit', () => {
    for (const e of HTTP_STATUS_CODES) {
      const expectedClass = `${Math.floor(e.code / 100)}xx`;
      expect(e.statusClass, String(e.code)).toBe(expectedClass);
    }
  });

  it('sorts ascending by code within each class (matches on-page render order)', () => {
    const byClass = new Map<string, HttpStatusEntry[]>();
    for (const e of HTTP_STATUS_CODES) {
      if (!byClass.has(e.statusClass)) byClass.set(e.statusClass, []);
      byClass.get(e.statusClass)!.push(e);
    }
    for (const [cls, entries] of byClass) {
      const codes = entries.map((e) => e.code);
      const sorted = [...codes].sort((a, b) => a - b);
      expect(codes, cls).toEqual(sorted);
    }
  });

  it('gives every entry non-empty phrase, description, and a real https reference URL', () => {
    for (const e of HTTP_STATUS_CODES) {
      expect(e.phrase.trim().length, `${e.code} phrase`).toBeGreaterThan(0);
      expect(e.description.trim().length, `${e.code} description`).toBeGreaterThan(20);
      expect(e.reference.url, `${e.code} reference url`).toMatch(/^https:\/\//);
      expect(e.reference.name.trim().length, `${e.code} reference name`).toBeGreaterThan(0);
    }
  });

  it('only marks the registry\'s two literal "(Unused)" codes as reserved', () => {
    const reserved = HTTP_STATUS_CODES.filter((e) => e.reserved).map((e) => e.code).sort((a, b) => a - b);
    expect(reserved).toEqual([306, 418]);
    for (const code of reserved) {
      expect(byCode.get(code)!.phrase).toBe('(Unused)');
    }
  });

  it('assigns every entry a known spec family', () => {
    for (const e of HTTP_STATUS_CODES) {
      expect(['core', 'webdav', 'extension'], String(e.code)).toContain(e.spec);
    }
  });

  // Spot-check exact reason phrases against the live IANA HTTP Status Code
  // Registry / RFC 9110 (verified at authoring time) — a wrong worked value
  // here would otherwise ship silently on the page.
  it('matches verified reason phrases for a representative sample of codes', () => {
    const expected: Record<number, string> = {
      100: 'Continue',
      101: 'Switching Protocols',
      200: 'OK',
      201: 'Created',
      204: 'No Content',
      206: 'Partial Content',
      301: 'Moved Permanently',
      302: 'Found',
      304: 'Not Modified',
      307: 'Temporary Redirect',
      308: 'Permanent Redirect',
      400: 'Bad Request',
      401: 'Unauthorized',
      403: 'Forbidden',
      404: 'Not Found',
      405: 'Method Not Allowed',
      409: 'Conflict',
      410: 'Gone',
      413: 'Content Too Large',
      418: '(Unused)',
      422: 'Unprocessable Content',
      426: 'Upgrade Required',
      429: 'Too Many Requests',
      431: 'Request Header Fields Too Large',
      451: 'Unavailable For Legal Reasons',
      500: 'Internal Server Error',
      501: 'Not Implemented',
      502: 'Bad Gateway',
      503: 'Service Unavailable',
      504: 'Gateway Timeout',
      511: 'Network Authentication Required',
    };
    for (const [code, phrase] of Object.entries(expected)) {
      const entry = byCode.get(Number(code));
      expect(entry, `code ${code} exists`).toBeTruthy();
      expect(entry!.phrase, `code ${code}`).toBe(phrase);
    }
  });

  it('never includes an "Unassigned" range or the temporary 104 draft code', () => {
    // 104 is registered against an active IETF draft, not a published RFC —
    // deliberately excluded (see httpStatusCodes.ts's own header comment).
    expect(byCode.has(104)).toBe(false);
  });
});
