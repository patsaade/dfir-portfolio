// JWT (JSON Web Token) structural decoder — pure functions, no DOM.
//
// Scope, deliberately narrow: this decodes a JWT's own three-segment compact
// serialization (RFC 7519 §3, RFC 7515 §3.1/§7.1 — "BASE64URL(header) || '.'
// || BASE64URL(payload) || '.' || BASE64URL(signature)") into JSON, reads the
// declared algorithm ("alg", RFC 7515 §4.1.1) and standard type ("typ", RFC
// 7519 §5.1) out of the header, and surfaces every RFC 7519 §4.1 Registered
// Claim Name present in the payload — including a computed "is this token
// currently expired" verdict for "exp" (RFC 7519 §4.1.4) and a "not yet
// valid" verdict for "nbf" (RFC 7519 §4.1.5).
//
// THIS DOES NOT AND CANNOT VERIFY THE SIGNATURE. Verifying a JWS signature
// requires the signing secret (HMAC) or the issuer's public key (RSA/ECDSA/
// EdDSA) — neither of which a client-side decoder ever has. The signature
// segment is surfaced only as an opaque, undecoded base64url string; nothing
// in this file ever attempts to check it. Callers must not present a
// structurally well-formed token as a "valid" or "trusted" one — see this
// module's own JwtDecodeOk.isUnsecured flag and the page's own copy for how
// that's communicated to the reader.
//
// A JWT can also be a JWE (JSON Web Encryption, 5 dot-separated segments)
// rather than a JWS — this decoder only handles the far more common signed
// (JWS) form and reports a clear structural error for anything else, rather
// than guessing.
//
// "now" (expiration/not-before math) is ALWAYS an explicit parameter — epoch
// milliseconds, i.e. whatever `Date.now()` returns — never read internally
// via `Date.now()`/`new Date()` in this module. That's what makes the
// "currently expired" verdict a pure, deterministic function of its inputs
// and testable without mocking the clock (see test/jwt.test.ts).
//
// Sources (WebFetched directly from the RFCs, not a third-party summary):
//   RFC 7519 (JSON Web Token) — https://www.rfc-editor.org/rfc/rfc7519.html
//   RFC 7515 (JSON Web Signature) — https://www.rfc-editor.org/rfc/rfc7515.html
//   RFC 7518 (JSON Web Algorithms) §3.1/§3.6 — alg values + "none" (Unsecured
//   JWS) — https://www.rfc-editor.org/rfc/rfc7518.html

/**
 * RFC 7519 §4.1 Registered Claim Names, in the order the RFC defines them.
 * Not exported — nothing outside this module imports it by name, only by
 * shape via REGISTERED_CLAIM_DEFS/JwtRegisteredClaim's own `claim` field
 * (Astro's structural-typing pattern per CLAUDE.md's Code health guidance).
 */
type RegisteredClaimName = 'iss' | 'sub' | 'aud' | 'exp' | 'nbf' | 'iat' | 'jti';

export interface RegisteredClaimDef {
  claim: RegisteredClaimName;
  label: string;
  /** Paraphrased from the claim's own RFC 7519 §4.1.x definition. */
  description: string;
}

/**
 * RFC 7519 §4.1.1–§4.1.7, in document order. Exported so the tool page's own
 * "Registered claims" reference table renders from this exact array rather
 * than a hand-copied duplicate that could silently drift from what the
 * decoder itself uses.
 */
export const REGISTERED_CLAIM_DEFS: readonly RegisteredClaimDef[] = [
  { claim: 'iss', label: 'Issuer', description: 'Identifies the principal that issued the JWT.' },
  { claim: 'sub', label: 'Subject', description: 'Identifies the principal that is the subject of the JWT — the entity the claims are about.' },
  { claim: 'aud', label: 'Audience', description: 'Identifies the recipient(s) the JWT is intended for. A recipient not identified by a value in this claim should reject the JWT.' },
  { claim: 'exp', label: 'Expiration Time', description: 'The expiration time on or after which the JWT MUST NOT be accepted for processing.' },
  { claim: 'nbf', label: 'Not Before', description: 'The time before which the JWT MUST NOT be accepted for processing.' },
  { claim: 'iat', label: 'Issued At', description: 'The time at which the JWT was issued.' },
  { claim: 'jti', label: 'JWT ID', description: 'A unique identifier for the JWT, intended to prevent the token from being replayed.' },
];

export interface JwtAlgorithmDef {
  code: string;
  description: string;
}

/**
 * RFC 7518 §3.1 "alg" values ("JSON Web Signature and Encryption Algorithms"
 * registry), in the RFC's own table order — descriptions paraphrased from
 * that section. §3.6 defines "none" as an Unsecured JWS (no signature at
 * all). Exported for the same single-source-of-truth reason as
 * REGISTERED_CLAIM_DEFS above; KNOWN_ALGORITHMS (the lookup this module uses
 * internally) is derived from it, not the other way around.
 */
export const KNOWN_JWS_ALGORITHMS: readonly JwtAlgorithmDef[] = [
  { code: 'HS256', description: 'HMAC using SHA-256' },
  { code: 'HS384', description: 'HMAC using SHA-384' },
  { code: 'HS512', description: 'HMAC using SHA-512' },
  { code: 'RS256', description: 'RSASSA-PKCS1-v1_5 using SHA-256' },
  { code: 'RS384', description: 'RSASSA-PKCS1-v1_5 using SHA-384' },
  { code: 'RS512', description: 'RSASSA-PKCS1-v1_5 using SHA-512' },
  { code: 'ES256', description: 'ECDSA using P-256 and SHA-256' },
  { code: 'ES384', description: 'ECDSA using P-384 and SHA-384' },
  { code: 'ES512', description: 'ECDSA using P-521 and SHA-512' },
  { code: 'PS256', description: 'RSASSA-PSS using SHA-256 and MGF1 with SHA-256' },
  { code: 'PS384', description: 'RSASSA-PSS using SHA-384 and MGF1 with SHA-384' },
  { code: 'PS512', description: 'RSASSA-PSS using SHA-512 and MGF1 with SHA-512' },
  { code: 'none', description: 'Unsecured JWS — no signature or integrity protection at all (RFC 7518 §3.6).' },
];

const KNOWN_ALGORITHMS: Record<string, string> = Object.fromEntries(KNOWN_JWS_ALGORITHMS.map((a) => [a.code, a.description]));

// Not exported — reached only structurally, as the element type of
// JwtDecodeOk.registeredClaims, which is itself reached via decodeJwt()'s
// return type. Nothing outside this module imports it by name.
interface JwtRegisteredClaim {
  claim: RegisteredClaimName;
  label: string;
  description: string;
  /** The raw JSON value exactly as parsed from the payload. */
  value: unknown;
  /** A deterministic, human-readable rendering of `value` (ISO 8601 for exp/nbf/iat when it's a valid NumericDate). */
  display: string;
  /** Only set for exp/nbf/iat when `value` is a valid RFC 7519 §2 NumericDate (seconds since the Unix epoch). */
  date: Date | null;
}

// Not exported — reached only structurally, as one arm of the exported
// JwtDecodeResult union (decodeJwt()'s own return type). Nothing outside
// this module imports it by name.
interface JwtDecodeOk {
  ok: true;
  /** Parsed JOSE header (RFC 7515 §4). */
  header: Record<string, unknown>;
  /** Parsed JWT Claims Set (RFC 7519 §3), i.e. the payload. */
  payload: Record<string, unknown>;
  /** Pretty-printed (2-space) JSON of `header`. */
  headerJson: string;
  /** Pretty-printed (2-space) JSON of `payload`. */
  payloadJson: string;
  /** The raw, still base64url-encoded signature segment — deliberately never decoded or checked. */
  signature: string;
  /** header.alg (RFC 7515 §4.1.1), or null if absent/not a string. */
  algorithm: string | null;
  /** RFC 7518-sourced description of `algorithm`, or null if it isn't a value this module recognizes. */
  algorithmDescription: string | null;
  /** true when algorithm === 'none' — an Unsecured JWS with no signature at all (RFC 7518 §3.6). */
  isUnsecured: boolean;
  /** header.typ (RFC 7519 §5.1), or null if absent/not a string. */
  type: string | null;
  /** Every RFC 7519 §4.1 registered claim actually present in the payload, in RFC order. */
  registeredClaims: JwtRegisteredClaim[];
  /**
   * Whether `now` is on/after the token's "exp" claim (RFC 7519 §4.1.4).
   * null when there is no "exp" claim, or its value isn't a valid NumericDate.
   */
  isExpired: boolean | null;
  /**
   * Whether `now` is still before the token's "nbf" claim (RFC 7519 §4.1.5) —
   * i.e. the token is not yet valid. null when there is no "nbf" claim, or
   * its value isn't a valid NumericDate.
   */
  isNotYetValid: boolean | null;
}

// Not exported — reached only structurally, as the other arm of the
// exported JwtDecodeResult union. Nothing outside this module imports it by
// name.
interface JwtDecodeErr {
  ok: false;
  error: string;
}

export type JwtDecodeResult = JwtDecodeOk | JwtDecodeErr;

/** RFC 7519 §2 "NumericDate": seconds (fractional allowed) since 1970-01-01T00:00:00Z UTC. */
function isNumericDate(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function numericDateToDate(value: unknown): Date | null {
  return isNumericDate(value) ? new Date(value * 1000) : null;
}

function displayClaimValue(claim: RegisteredClaimName, value: unknown, date: Date | null): string {
  if ((claim === 'exp' || claim === 'nbf' || claim === 'iat') && date) return date.toISOString();
  if (claim === 'aud' && Array.isArray(value)) return value.map((v) => String(v)).join(', ');
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

/**
 * Decodes a base64url (RFC 4648 §5) string — the alphabet JWTs use, with
 * '-'/'_' in place of '+'/'/' and trailing '=' padding always omitted (RFC
 * 7515 §2's "Base64url Encoding" terminology) — into its raw bytes.
 * Throws on invalid input (surfaced by the caller as a structural error).
 */
function base64UrlToBytes(segment: string): Uint8Array {
  const base64 = segment.replace(/-/g, '+').replace(/_/g, '/');
  const padLength = (4 - (base64.length % 4)) % 4;
  const padded = base64 + '='.repeat(padLength);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Decodes a base64url segment as UTF-8 text (claim values may be non-ASCII). */
function base64UrlToUtf8(segment: string): string {
  return new TextDecoder('utf-8', { fatal: true }).decode(base64UrlToBytes(segment));
}

/** Decodes one compact-serialization segment into a parsed JSON object, with every failure mode named after `segmentName` (e.g. "Header", "Payload"). */
function decodeSegmentAsJsonObject(segment: string, segmentName: string): Record<string, unknown> {
  let text: string;
  try {
    text = base64UrlToUtf8(segment);
  } catch (e) {
    throw new Error(`${segmentName} segment isn't valid base64url (${e instanceof Error ? e.message : 'decode error'}).`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error(`${segmentName} segment isn't valid JSON (${e instanceof Error ? e.message : 'parse error'}).`);
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${segmentName} segment must decode to a JSON object, not ${Array.isArray(parsed) ? 'an array' : typeof parsed}.`);
  }
  return parsed as Record<string, unknown>;
}

/**
 * Decodes a JWT's compact serialization into its header, payload, and raw
 * signature, plus derived algorithm/registered-claim/expiration info.
 *
 * @param token The raw token string, e.g. pasted from an Authorization
 *   header ("Bearer <token>" prefixes are stripped automatically).
 * @param now Epoch milliseconds (i.e. `Date.now()`'s own return shape) to
 *   evaluate "exp"/"nbf" against. Always passed in — never read internally —
 *   so the expiration verdict is a pure, deterministic function of its
 *   inputs.
 */
export function decodeJwt(token: string, now: number): JwtDecodeResult {
  const trimmed = token.trim().replace(/^Bearer\s+/i, '');
  if (!trimmed) return { ok: false, error: 'Paste a token to decode.' };

  const parts = trimmed.split('.');
  if (parts.length !== 3) {
    if (parts.length === 5) {
      return {
        ok: false,
        error: 'This has 5 dot-separated segments, which is the shape of a JWE (an encrypted JWT), not a JWS. This decoder only handles the signed (JWS) compact serialization — header.payload.signature — since a JWE payload is encrypted ciphertext, not readable JSON.',
      };
    }
    return {
      ok: false,
      error: `A JWT's compact serialization is exactly 3 base64url segments separated by '.' (header.payload.signature) — found ${parts.length}.`,
    };
  }
  const [headerSeg, payloadSeg, signatureSeg] = parts;

  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = decodeSegmentAsJsonObject(headerSeg, 'Header');
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'Header segment could not be decoded.' };
  }
  try {
    payload = decodeSegmentAsJsonObject(payloadSeg, 'Payload');
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'Payload segment could not be decoded.' };
  }

  const algorithm = typeof header.alg === 'string' ? header.alg : null;
  const algorithmDescription = algorithm && algorithm in KNOWN_ALGORITHMS ? KNOWN_ALGORITHMS[algorithm] : null;
  const type = typeof header.typ === 'string' ? header.typ : null;

  const registeredClaims: JwtRegisteredClaim[] = [];
  for (const def of REGISTERED_CLAIM_DEFS) {
    if (!Object.prototype.hasOwnProperty.call(payload, def.claim)) continue;
    const value = payload[def.claim];
    const date = def.claim === 'exp' || def.claim === 'nbf' || def.claim === 'iat' ? numericDateToDate(value) : null;
    registeredClaims.push({
      claim: def.claim,
      label: def.label,
      description: def.description,
      value,
      display: displayClaimValue(def.claim, value, date),
      date,
    });
  }

  const expClaim = registeredClaims.find((c) => c.claim === 'exp');
  const nbfClaim = registeredClaims.find((c) => c.claim === 'nbf');
  const isExpired = expClaim && expClaim.date ? now >= expClaim.date.getTime() : null;
  const isNotYetValid = nbfClaim && nbfClaim.date ? now < nbfClaim.date.getTime() : null;

  return {
    ok: true,
    header,
    payload,
    headerJson: JSON.stringify(header, null, 2),
    payloadJson: JSON.stringify(payload, null, 2),
    signature: signatureSeg,
    algorithm,
    algorithmDescription,
    isUnsecured: algorithm === 'none',
    type,
    registeredClaims,
    isExpired,
    isNotYetValid,
  };
}
