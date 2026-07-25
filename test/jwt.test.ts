import { describe, it, expect } from 'vitest';
import { decodeJwt } from '../src/utils/jwt';

// ---------------------------------------------------------------------------
// Hand-constructed JWT fixtures. Each header/payload JSON object below is
// base64url-encoded independently via Node's own `Buffer#toString('base64url')`
// (a different code path than src/utils/jwt.ts's atob/TextDecoder-based
// decoder under test), so a correct round-trip here is a genuine cross-check,
// not a tautology. Every claim value is fabricated (fake domains, a fake
// UUID) — never a real captured token, per this site's content-accuracy rule.
// ---------------------------------------------------------------------------

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

// This is exactly the demo token JwtDecoder.astro ships as its default
// paste-box content — kept in sync here so a wrong on-page worked example
// can't ship silently. iat/nbf = 2020-01-01T00:00:00Z, exp = 2020-01-01T01:00:00Z
// (one hour later), both permanently in the past relative to any real visit,
// so the "expired" verdict the demo is meant to illustrate is always true.
const DEMO_HEADER = { alg: 'HS256', typ: 'JWT' };
const DEMO_PAYLOAD = {
  iss: 'https://auth.example.com',
  sub: 'user:9001',
  aud: 'https://api.example.com',
  iat: 1577836800,
  nbf: 1577836800,
  exp: 1577840400,
  jti: '018f1b6b-0000-7000-8000-000000000000',
};
const DEMO_SIGNATURE = Buffer.from('not-a-real-signature-this-is-a-fabricated-demo').toString('base64url');
export const DEMO_TOKEN = `${b64url(DEMO_HEADER)}.${b64url(DEMO_PAYLOAD)}.${DEMO_SIGNATURE}`;

describe('decodeJwt', () => {
  describe('the shipped demo token', () => {
    it('decodes the exact string JwtDecoder.astro embeds as its example', () => {
      expect(DEMO_TOKEN).toBe(
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyOjkwMDEiLCJhdWQiOiJodHRwczovL2FwaS5leGFtcGxlLmNvbSIsImlhdCI6MTU3NzgzNjgwMCwibmJmIjoxNTc3ODM2ODAwLCJleHAiOjE1Nzc4NDA0MDAsImp0aSI6IjAxOGYxYjZiLTAwMDAtNzAwMC04MDAwLTAwMDAwMDAwMDAwMCJ9.bm90LWEtcmVhbC1zaWduYXR1cmUtdGhpcy1pcy1hLWZhYnJpY2F0ZWQtZGVtbw'
      );
    });

    it('parses header fields correctly', () => {
      const result = decodeJwt(DEMO_TOKEN, Date.now());
      if (!result.ok) throw new Error('expected ok');
      expect(result.header).toEqual(DEMO_HEADER);
      expect(result.algorithm).toBe('HS256');
      expect(result.algorithmDescription).toBe('HMAC using SHA-256');
      expect(result.isUnsecured).toBe(false);
      expect(result.type).toBe('JWT');
    });

    it('parses payload fields and every registered claim, in RFC 7519 order', () => {
      const result = decodeJwt(DEMO_TOKEN, Date.now());
      if (!result.ok) throw new Error('expected ok');
      expect(result.payload).toEqual(DEMO_PAYLOAD);
      expect(result.registeredClaims.map((c) => c.claim)).toEqual(['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti']);

      const iss = result.registeredClaims.find((c) => c.claim === 'iss')!;
      expect(iss.value).toBe('https://auth.example.com');
      expect(iss.display).toBe('https://auth.example.com');

      const jti = result.registeredClaims.find((c) => c.claim === 'jti')!;
      expect(jti.value).toBe('018f1b6b-0000-7000-8000-000000000000');
    });

    it('never decodes the signature — it stays the raw base64url segment', () => {
      const result = decodeJwt(DEMO_TOKEN, Date.now());
      if (!result.ok) throw new Error('expected ok');
      expect(result.signature).toBe(DEMO_SIGNATURE);
    });

    it('renders exp/nbf/iat as their exact ISO 8601 instants', () => {
      const result = decodeJwt(DEMO_TOKEN, Date.now());
      if (!result.ok) throw new Error('expected ok');
      const exp = result.registeredClaims.find((c) => c.claim === 'exp')!;
      const nbf = result.registeredClaims.find((c) => c.claim === 'nbf')!;
      const iat = result.registeredClaims.find((c) => c.claim === 'iat')!;
      expect(exp.date?.toISOString()).toBe('2020-01-01T01:00:00.000Z');
      expect(exp.display).toBe('2020-01-01T01:00:00.000Z');
      expect(nbf.date?.toISOString()).toBe('2020-01-01T00:00:00.000Z');
      expect(iat.date?.toISOString()).toBe('2020-01-01T00:00:00.000Z');
    });

    it('is permanently "expired" relative to any real-world `now`, matching the page copy about this demo', () => {
      // Any timestamp after this repo's earliest possible commit is well
      // past the demo's fixed 2020-01-01T01:00:00Z exp.
      const result = decodeJwt(DEMO_TOKEN, Date.now());
      if (!result.ok) throw new Error('expected ok');
      expect(result.isExpired).toBe(true);
      expect(result.isNotYetValid).toBe(false);
    });
  });

  describe('expiration / not-before math (exp vs. nbf vs. `now`)', () => {
    const iat = 1700000000; // 2023-11-14T22:13:20.000Z
    const nbf = 1700000000;
    const exp = 1700003600; // one hour later: 2023-11-14T23:13:20.000Z
    const token = `${b64url({ alg: 'HS256' })}.${b64url({ iat, nbf, exp })}.${Buffer.from('sig').toString('base64url')}`;

    it('is neither expired nor not-yet-valid strictly between nbf and exp', () => {
      const result = decodeJwt(token, 1700001800 * 1000); // 30 min in
      if (!result.ok) throw new Error('expected ok');
      expect(result.isExpired).toBe(false);
      expect(result.isNotYetValid).toBe(false);
    });

    it('treats `now` exactly equal to exp as expired ("on or after" MUST NOT accept, RFC 7519 §4.1.4)', () => {
      const result = decodeJwt(token, exp * 1000);
      if (!result.ok) throw new Error('expected ok');
      expect(result.isExpired).toBe(true);
    });

    it('treats `now` after exp as expired', () => {
      const result = decodeJwt(token, (exp + 1) * 1000);
      if (!result.ok) throw new Error('expected ok');
      expect(result.isExpired).toBe(true);
    });

    it('treats `now` exactly equal to nbf as valid (RFC 7519 §4.1.5 requires MUST NOT accept only *before* nbf)', () => {
      const result = decodeJwt(token, nbf * 1000);
      if (!result.ok) throw new Error('expected ok');
      expect(result.isNotYetValid).toBe(false);
    });

    it('treats `now` before nbf as not yet valid', () => {
      const result = decodeJwt(token, (nbf - 1) * 1000);
      if (!result.ok) throw new Error('expected ok');
      expect(result.isNotYetValid).toBe(true);
    });

    it('reports null isExpired/isNotYetValid when exp/nbf claims are absent', () => {
      const noExpToken = `${b64url({ alg: 'HS256' })}.${b64url({ sub: 'x' })}.${Buffer.from('sig').toString('base64url')}`;
      const result = decodeJwt(noExpToken, Date.now());
      if (!result.ok) throw new Error('expected ok');
      expect(result.isExpired).toBeNull();
      expect(result.isNotYetValid).toBeNull();
      expect(result.registeredClaims.map((c) => c.claim)).toEqual(['sub']);
    });

    it('reports null isExpired when exp is present but not a valid NumericDate', () => {
      const badExpToken = `${b64url({ alg: 'HS256' })}.${b64url({ exp: 'not-a-number' })}.${Buffer.from('sig').toString('base64url')}`;
      const result = decodeJwt(badExpToken, Date.now());
      if (!result.ok) throw new Error('expected ok');
      expect(result.isExpired).toBeNull();
      const exp = result.registeredClaims.find((c) => c.claim === 'exp')!;
      expect(exp.date).toBeNull();
      // A string claim value displays as the plain string itself (no
      // wrapping quotes) — only non-string JSON values fall back to
      // JSON.stringify() in displayClaimValue().
      expect(exp.display).toBe('not-a-number');
    });
  });

  describe('algorithm reporting', () => {
    it('flags alg: "none" as an Unsecured JWS', () => {
      const token = `${b64url({ alg: 'none' })}.${b64url({ sub: 'x' })}.`;
      const result = decodeJwt(token, Date.now());
      if (!result.ok) throw new Error('expected ok');
      expect(result.algorithm).toBe('none');
      expect(result.isUnsecured).toBe(true);
      expect(result.algorithmDescription).toContain('Unsecured JWS');
    });

    it('describes every RFC 7518 §3.1 algorithm this module knows about', () => {
      const knownAndDescribed: [string, string][] = [
        ['HS256', 'HMAC using SHA-256'],
        ['HS384', 'HMAC using SHA-384'],
        ['HS512', 'HMAC using SHA-512'],
        ['RS256', 'RSASSA-PKCS1-v1_5 using SHA-256'],
        ['ES256', 'ECDSA using P-256 and SHA-256'],
        ['PS256', 'RSASSA-PSS using SHA-256 and MGF1 with SHA-256'],
      ];
      for (const [alg, desc] of knownAndDescribed) {
        const token = `${b64url({ alg })}.${b64url({})}.`;
        const result = decodeJwt(token, Date.now());
        if (!result.ok) throw new Error('expected ok');
        expect(result.algorithmDescription).toBe(desc);
      }
    });

    it('returns null algorithmDescription for an alg it does not recognize, and null algorithm when alg is absent', () => {
      const withUnknownAlg = decodeJwt(`${b64url({ alg: 'XYZ999' })}.${b64url({})}.`, Date.now());
      if (!withUnknownAlg.ok) throw new Error('expected ok');
      expect(withUnknownAlg.algorithm).toBe('XYZ999');
      expect(withUnknownAlg.algorithmDescription).toBeNull();

      const withoutAlg = decodeJwt(`${b64url({})}.${b64url({})}.`, Date.now());
      if (!withoutAlg.ok) throw new Error('expected ok');
      expect(withoutAlg.algorithm).toBeNull();
    });
  });

  describe('the "aud" claim (string or array form)', () => {
    it('joins an array-form audience for display but keeps the raw array as `value`', () => {
      const token = `${b64url({ alg: 'HS256' })}.${b64url({ aud: ['svc-a', 'svc-b'] })}.`;
      const result = decodeJwt(token, Date.now());
      if (!result.ok) throw new Error('expected ok');
      const aud = result.registeredClaims.find((c) => c.claim === 'aud')!;
      expect(aud.value).toEqual(['svc-a', 'svc-b']);
      expect(aud.display).toBe('svc-a, svc-b');
    });
  });

  describe('structural error handling', () => {
    it('rejects an empty token', () => {
      const result = decodeJwt('', Date.now());
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error('expected error');
      expect(result.error).toMatch(/paste a token/i);
    });

    it('rejects a token with the wrong number of segments', () => {
      const result = decodeJwt('only.two', Date.now());
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error('expected error');
      expect(result.error).toMatch(/found 2/i);
    });

    it('gives a specific error for a 5-segment JWE-shaped token instead of a generic count error', () => {
      const result = decodeJwt('a.b.c.d.e', Date.now());
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error('expected error');
      expect(result.error).toMatch(/JWE/);
    });

    it('rejects a header segment that is not valid base64url/JSON', () => {
      const result = decodeJwt('not-valid-base64!!!.eyJhIjoxfQ.sig', Date.now());
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error('expected error');
      expect(result.error).toMatch(/header/i);
    });

    it('rejects a payload segment that decodes to a JSON array instead of an object', () => {
      const token = `${b64url({ alg: 'HS256' })}.${b64url([1, 2, 3])}.sig`;
      const result = decodeJwt(token, Date.now());
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error('expected error');
      expect(result.error).toMatch(/payload/i);
      expect(result.error).toMatch(/array/i);
    });

    it('strips a leading "Bearer " prefix before parsing', () => {
      const withoutPrefix = decodeJwt(DEMO_TOKEN, 1600000000000);
      const withPrefix = decodeJwt(`Bearer ${DEMO_TOKEN}`, 1600000000000);
      expect(withPrefix).toEqual(withoutPrefix);
    });
  });
});
