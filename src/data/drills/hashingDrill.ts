// Question bank for the Hash Identification Drill (/drills/hashing/).
// Every fact below traces to this repo's own src/utils/hashes.ts — the same
// module that backs the live Hash Calculator & Verifier — not hand-invented
// quiz copy:
//
//   - The five algorithm answers come from HASH_ALGORITHMS itself (label +
//     bits/hexLength), so they can't drift out of sync with the real table.
//   - The "identify this ambiguous/prefixed format" questions (Q6-Q9) call
//     the real identifyHash() at module load and read its actual
//     `confidence`/`note` fields straight into the explanation —
//     identifyHash() is a pure, synchronous function, so this is a plain,
//     safe top-level call in both the Node (SSR) and browser (client
//     hydration) evaluations of this module.
//   - The digest hex strings in DIGEST_SAMPLES (Q1-Q5, Q10) were computed
//     OFFLINE by literally executing this repo's own digestHex()/md5Hex()
//     against each sample word (esbuild-bundled src/utils/hashes.ts, run
//     under Node, which has global Web Crypto). They're embedded as literal
//     data rather than recomputed at runtime because digestHex() is async
//     (the SHA family goes through crypto.subtle) and DrillConfig's
//     `nextQuestion(index): DrillQuestion` contract must return
//     synchronously — see drillEngine.ts. To regenerate/verify any of them,
//     run e.g.:
//       node --input-type=module -e "
//         import { digestHex } from './src/utils/hashes.ts';
//         console.log(await digestHex('sha256', new TextEncoder().encode('root')));"
//     (after transpiling with esbuild, since this is a plain node -e run).
//
// formatHex() inserts a space every 8 hex characters purely so the digest
// wraps inside DrillEngine's prompt <p> (a plain textContent node with no
// word-break override) instead of overflowing — it doesn't change the value.

import { HASH_ALGORITHMS, identifyHash } from '../../utils/hashes';
import type { DrillQuestion } from '../../scripts/drillEngine';

function formatHex(hex: string): string {
  return hex.replace(/(.{8})/g, '$1 ').trim();
}

function bitsFor(id: string): number {
  return HASH_ALGORITHMS.find((a) => a.id === id)!.bits;
}

function noteFor(candidates: { algorithm: string; confidence: string; note: string }[], algorithm: string): string {
  return candidates.find((c) => c.algorithm === algorithm)?.note ?? '';
}

function confidenceFor(candidates: { algorithm: string; confidence: string; note: string }[], algorithm: string): string {
  return candidates.find((c) => c.algorithm === algorithm)?.confidence ?? '';
}

const REF = { referenceHref: '/tools/hash-calculator/', referenceLabel: 'Try it in the Hash Calculator' };

// Lenient short-answer grading shared by every question below: lowercase,
// strip everything but letters/digits, so "SHA-256", "sha256", and "Sha 256"
// all normalize identically — the learner is being tested on recognizing the
// algorithm/format, not on typing punctuation exactly.
function normalizeToken(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]/g, '');
}

// Digests computed offline via this repo's own digestHex()/md5Hex() — see
// header comment. sample = plaintext hashed, algo = HASH_ALGORITHMS id,
// hex = the real resulting digest.
const DIGEST_SAMPLES: { sample: string; algo: string; label: string; hex: string }[] = [
  { sample: 'admin', algo: 'md5', label: 'MD5', hex: '21232f297a57a5a743894a0e4a801fc3' },
  { sample: 'password123', algo: 'sha1', label: 'SHA-1', hex: 'cbfdac6008f9cab4083784cbd1874f76618d2a97' },
  { sample: 'root', algo: 'sha256', label: 'SHA-256', hex: '4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2' },
  {
    sample: 'svc_backup',
    algo: 'sha384',
    label: 'SHA-384',
    hex: '2eb894fab92f51d6aa26a2ced87121f2f6a1ec243763d9243ab8776cf91c1440e062a7a0baa7bf8ad2c30e27cc470c0e',
  },
  {
    sample: 'administrator',
    algo: 'sha512',
    label: 'SHA-512',
    hex: 'cf835de3d4ea01367c45e412e7a9393a85a4e40af149ed8c3ed6c37c05b67b27813d7ff8072c1035cedd19415adf17128d63186f05f0d656002b0ca1c34f44a0',
  },
];

function digestQuestion(entry: (typeof DIGEST_SAMPLES)[number]): DrillQuestion {
  const acceptable = new Set([normalizeToken(entry.algo), normalizeToken(entry.label)]);
  return {
    prompt: `Hashing the string "${entry.sample}" with one of this tool's supported algorithms produced this digest:\n\n${formatHex(entry.hex)}\n\nThat's ${entry.hex.length} hex characters (${bitsFor(entry.algo)} bits). Which algorithm produced it? (e.g. "MD5", "SHA-256")`,
    explanation: `${entry.label} always produces a ${bitsFor(entry.algo)}-bit digest — ${entry.hex.length} hex characters — regardless of input length. Every algorithm in the reference table has one fixed output length, which is the first thing to check when you don't know a hash's source.`,
    answerType: 'text',
    correctAnswer: entry.label,
    grade: (ans) => acceptable.has(normalizeToken(ans)),
    ...REF,
  };
}

// --- identifyHash() candidates for two real hex strings (a genuine tie and
// a genuine high-confidence single answer) — reused from DIGEST_SAMPLES
// where possible so there's one source of truth per hex value. ---
const md5AdminCandidates = identifyHash(DIGEST_SAMPLES[0].hex); // 32 hex -> MD5/NTLM/LM
const sha1PasswordCandidates = identifyHash(DIGEST_SAMPLES[1].hex); // 40 hex -> SHA-1/RIPEMD-160

// --- Two real prefixed-format examples, run through identifyHash() live. ---
// bcrypt modular-crypt format: $2b$<cost>$<53 chars of [./A-Za-z0-9]> — an
// illustrative, syntactically valid example (not a hash of any real
// password), built only to satisfy identifyHash()'s own bcrypt regex.
const BCRYPT_SAMPLE = '$2b$12$KIXQeYQ9Z5W8n1JlY0m0uOe3z7Q4rXk9pC2mN6sT1vB5dF7gH8jK9';
const bcryptCandidates = identifyHash(BCRYPT_SAMPLE);

// $6$ modular-crypt format (SHA-512 crypt, Linux/BSD /etc/shadow) — the
// regex only checks the $6$ prefix, so any well-formed-looking salt/hash
// tail is enough to exercise the real match.
const SHA512_CRYPT_SAMPLE =
  '$6$rounds=656000$abcXYZ123saltHere$Qk9z5W8n1JlY0m0uOe3z7Q4rXk9pC2mN6sT1vB5dF7gH8jK0m0uOe3z7Q4rXk9pC2mN6sT1vB5dF7gH8jK.';
const sha512CryptCandidates = identifyHash(SHA512_CRYPT_SAMPLE);

const QUESTIONS: DrillQuestion[] = [
  ...DIGEST_SAMPLES.map(digestQuestion),

  // Q6 — genuine ambiguity: identifyHash() ties MD5 and NTLM at 32 hex chars.
  {
    prompt: `An analyst finds this bare hex string pasted into a ticket, with no other context:\n\n${formatHex(DIGEST_SAMPLES[0].hex)}\n\nIt's ${DIGEST_SAMPLES[0].hex.length} hex characters. True or false: its format alone is enough to say with confidence that it's an MD5 digest and nothing else.`,
    explanation: `False. ${noteFor(md5AdminCandidates, 'NTLM')} The Identify panel marks both MD5 and NTLM as ${confidenceFor(md5AdminCandidates, 'MD5')} confidence here, not a single certain answer — the string's origin (a file hash vs. a SAM/NTDS dump) is what actually disambiguates them, not the hex itself.`,
    answerType: 'text',
    correctAnswer: 'False',
    grade: (ans) => normalizeToken(ans) === 'false',
    ...REF,
  },

  // Q7 — genuine single high-confidence answer at 40 hex chars.
  {
    prompt: `The same Identify panel is given this 40-hex-character string:\n\n${formatHex(DIGEST_SAMPLES[1].hex)}\n\nWhat confidence level (High/Medium/Low) does it assign to SHA-1 as the source?`,
    explanation: `High. ${noteFor(sha1PasswordCandidates, 'SHA-1')} (RIPEMD-160 shares the exact same 160-bit/40-hex format, but is rare enough in DFIR contexts to only rate low confidence.)`,
    answerType: 'text',
    correctAnswer: 'High',
    grade: (ans) => normalizeToken(ans) === 'high',
    ...REF,
  },

  // Q8 — prefixed-format recognition: bcrypt.
  {
    prompt: `This string turns up in a leaked database dump:\n\n${BCRYPT_SAMPLE}\n\nWhat hashing scheme is this? (short answer — name the format, e.g. "sha256", "crc32", "bcrypt")`,
    explanation: `${noteFor(bcryptCandidates, 'bcrypt')} Recognizing the $2b$ prefix is faster and more reliable than reasoning about hex length here, since bcrypt output is not raw hex at all.`,
    answerType: 'text',
    correctAnswer: 'bcrypt',
    grade: (ans) => normalizeToken(ans).includes('bcrypt'),
    ...REF,
  },

  // Q9 — prefixed-format recognition: $6$ shadow crypt.
  {
    prompt: `This string turns up in a copied /etc/shadow line:\n\n${SHA512_CRYPT_SAMPLE}\n\nWhat format is this? (short answer, e.g. "bcrypt", "md5crypt", "sha512crypt")`,
    explanation: `${noteFor(sha512CryptCandidates, 'SHA-512 crypt (Unix /etc/shadow)')} $5$ is the SHA-256 equivalent of this format; $1$ is the older, weaker MD5 crypt.`,
    answerType: 'text',
    correctAnswer: 'sha512crypt',
    grade: (ans) => {
      const n = normalizeToken(ans);
      return n.includes('sha512') && n.includes('crypt');
    },
    ...REF,
  },

  // Q10 — plain reference-table lookup (no digest computation involved).
  {
    prompt: 'Per the algorithm reference table, how many bits does a SHA-384 digest produce? (numeric answer)',
    explanation: `SHA-384 always produces a ${bitsFor('sha384')}-bit digest — ${HASH_ALGORITHMS.find((a) => a.id === 'sha384')!.hexLength} hex characters — regardless of input length. Fixed output length per algorithm is exactly what makes length-based identification possible in the first place.`,
    answerType: 'text',
    correctAnswer: String(bitsFor('sha384')),
    ...REF,
  },
];

/** Deterministic — every index maps to the same fixed question, so
 *  question 0 is identical between the server-rendered firstQuestion prop
 *  and the client script's own initial nextQuestion(0) call (see
 *  DrillEngine.astro's no-JS-flash contract). */
export function getHashingDrillQuestion(index: number): DrillQuestion {
  return QUESTIONS[index % QUESTIONS.length];
}

export const HASHING_DRILL_TOTAL = QUESTIONS.length;
