import { describe, it, expect } from 'vitest';
import { getHashingDrillQuestion, HASHING_DRILL_TOTAL } from '../src/data/drills/hashingDrill';
import { HASH_ALGORITHMS, identifyHash } from '../src/utils/hashes';

describe('getHashingDrillQuestion', () => {
  it('is deterministic for a given index (required for the no-JS SSR/hydration contract)', () => {
    for (let i = 0; i < HASHING_DRILL_TOTAL; i++) {
      const a = getHashingDrillQuestion(i);
      const b = getHashingDrillQuestion(i);
      expect(b.prompt).toBe(a.prompt);
      expect(b.explanation).toBe(a.explanation);
      expect(b.correctAnswer).toBe(a.correctAnswer);
    }
  });

  it('wraps safely for an out-of-range index instead of throwing', () => {
    expect(() => getHashingDrillQuestion(HASHING_DRILL_TOTAL)).not.toThrow();
    expect(getHashingDrillQuestion(HASHING_DRILL_TOTAL).prompt).toBe(getHashingDrillQuestion(0).prompt);
  });

  it('every question has a non-empty prompt/explanation and links back to the Hash Calculator', () => {
    for (let i = 0; i < HASHING_DRILL_TOTAL; i++) {
      const q = getHashingDrillQuestion(i);
      expect(q.prompt.length).toBeGreaterThan(0);
      expect(q.explanation.length).toBeGreaterThan(0);
      expect(q.referenceHref).toBe('/tools/hash-calculator/');
    }
  });

  it('the original ten questions are free-text recall (no choice, no match)', () => {
    for (let i = 0; i < 10; i++) {
      const q = getHashingDrillQuestion(i);
      expect(q.answerType).toBe('text');
      expect(q.choices).toBeUndefined();
    }
  });

  it('the drill now has exactly three additive match-type "triage batch" questions after the original ten', () => {
    expect(HASHING_DRILL_TOTAL).toBe(13);
    const matchQuestions = Array.from({ length: HASHING_DRILL_TOTAL }, (_, i) => getHashingDrillQuestion(i)).filter(
      (q) => q.answerType === 'match',
    );
    expect(matchQuestions.length).toBe(3);
    for (let i = 10; i < 13; i++) {
      expect(getHashingDrillQuestion(i).answerType).toBe('match');
    }
  });

  it('every question with a custom grade() genuinely accepts its own real correctAnswer (not just string-equal by luck)', () => {
    for (let i = 0; i < HASHING_DRILL_TOTAL; i++) {
      const q = getHashingDrillQuestion(i);
      if (typeof q.grade !== 'function') continue;
      expect(q.grade(q.correctAnswer!), `question ${i} grade() rejected its own correctAnswer "${q.correctAnswer}"`).toBe(true);
      expect(q.grade('definitely-the-wrong-answer'), `question ${i} grade() accepted an obviously wrong answer`).toBe(false);
    }
  });

  it('the five algorithm-identification questions grade both the real HASH_ALGORITHMS label and id, case/punctuation-insensitively', () => {
    const digestQuestions = Array.from({ length: HASHING_DRILL_TOTAL }, (_, i) => getHashingDrillQuestion(i)).filter((q) =>
      q.prompt.includes('Hashing the string'),
    );
    expect(digestQuestions.length).toBe(5);
    for (const q of digestQuestions) {
      const algo = HASH_ALGORITHMS.find((a) => a.label === q.correctAnswer)!;
      expect(algo, `no HASH_ALGORITHMS entry for correctAnswer "${q.correctAnswer}"`).toBeDefined();
      expect(q.grade!(algo.label)).toBe(true);
      expect(q.grade!(algo.id)).toBe(true);
      expect(q.grade!(algo.label.toLowerCase().replace(/-/g, ''))).toBe(true);
    }
  });

  it('every digest-length claim in a prompt matches the real HASH_ALGORITHMS hexLength/bits for that algorithm', () => {
    for (const a of HASH_ALGORITHMS) {
      const q = Array.from({ length: HASHING_DRILL_TOTAL }, (_, i) => getHashingDrillQuestion(i)).find(
        (q) => q.correctAnswer === a.label && q.prompt.includes('Hashing the string'),
      );
      expect(q, `no digest question found for ${a.label}`).toBeDefined();
      expect(q!.prompt).toContain(`${a.hexLength} hex characters`);
      expect(q!.prompt).toContain(`${a.bits} bits`);
    }
  });

  it('the ambiguous-32-hex question (MD5 vs NTLM) grades False, and the underlying identifyHash() call genuinely ties both at medium confidence', () => {
    const q = getHashingDrillQuestion(5);
    expect(q.correctAnswer).toBe('False');
    expect(q.grade!('False')).toBe(true);
    expect(q.grade!('false')).toBe(true);
    expect(q.grade!('True')).toBe(false);
    // formatHex() joins the real digest as space-separated 8-char groups —
    // pull that run back out of the prompt and re-run the real identifyHash()
    // to confirm it produces the tie this question's explanation is built from.
    const digestMatch = q.prompt.match(/[0-9a-f]{8}(?:\s[0-9a-f]{8})+/i);
    expect(digestMatch, 'prompt should embed a space-grouped 32-hex digest').not.toBeNull();
    const hex = digestMatch![0].replace(/\s/g, '');
    expect(hex).toHaveLength(32);
    const candidates = identifyHash(hex);
    expect(candidates.some((c) => c.algorithm === 'MD5' && c.confidence === 'medium')).toBe(true);
    expect(candidates.some((c) => c.algorithm === 'NTLM' && c.confidence === 'medium')).toBe(true);
  });

  it('the 40-hex confidence question grades High, matching identifyHash()\'s real SHA-1 confidence at that length', () => {
    const q = getHashingDrillQuestion(6);
    expect(q.correctAnswer).toBe('High');
    expect(q.grade!('High')).toBe(true);
    expect(q.grade!('high')).toBe(true);
    expect(q.grade!('Low')).toBe(false);
    const candidates = identifyHash('a'.repeat(40));
    expect(candidates.find((c) => c.algorithm === 'SHA-1')?.confidence).toBe('high');
  });

  it('the bcrypt format question\'s prompt string is genuinely recognized as bcrypt by the real identifyHash(), and grade() accepts "bcrypt"', () => {
    const q = getHashingDrillQuestion(7);
    expect(q.grade!('bcrypt')).toBe(true);
    expect(q.grade!('BCrypt')).toBe(true);
    expect(q.grade!('sha256')).toBe(false);
    const bcryptMatch = q.prompt.match(/\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}/);
    expect(bcryptMatch, 'prompt should embed a syntactically valid bcrypt string').not.toBeNull();
    expect(identifyHash(bcryptMatch![0])).toEqual([
      expect.objectContaining({ algorithm: 'bcrypt', confidence: 'high' }),
    ]);
  });

  it('the $6$ shadow-crypt question\'s prompt string is genuinely recognized by the real identifyHash(), and grade() accepts common phrasings', () => {
    const q = getHashingDrillQuestion(8);
    expect(q.grade!('sha512crypt')).toBe(true);
    expect(q.grade!('SHA-512 crypt')).toBe(true);
    expect(q.grade!('bcrypt')).toBe(false);
    expect(q.prompt).toContain('$6$');
    const shadowMatch = q.prompt.match(/\$6\$\S+/);
    expect(shadowMatch).not.toBeNull();
    const candidates = identifyHash(shadowMatch![0]);
    expect(candidates).toEqual([expect.objectContaining({ algorithm: 'SHA-512 crypt (Unix /etc/shadow)', confidence: 'high' })]);
  });

  it('the final reference-lookup question answers with the real SHA-384 bit count from HASH_ALGORITHMS, via the default grading fallback', () => {
    const q = getHashingDrillQuestion(9);
    expect(q.answerType).toBe('text');
    expect(q.grade).toBeUndefined();
    const sha384 = HASH_ALGORITHMS.find((a) => a.id === 'sha384')!;
    expect(q.correctAnswer).toBe(String(sha384.bits));
  });

  describe('match-type triage batch questions (Q11-Q13)', () => {
    it('Q11 sorts all five real digests by their true HASH_ALGORITHMS length, every algorithm used exactly once', () => {
      const q = getHashingDrillQuestion(10);
      expect(q.answerType).toBe('match');
      expect(q.matchItems).toHaveLength(5);
      for (const item of q.matchItems!) {
        const algo = HASH_ALGORITHMS.find((a) => a.label === item.correctCategory);
        expect(algo, `no HASH_ALGORITHMS entry for correctCategory "${item.correctCategory}"`).toBeDefined();
        expect(item.text).toHaveLength(algo!.hexLength);
        expect(item.text).toMatch(/^[0-9a-f]+$/i);
      }
      // Every HASH_ALGORITHMS label is the correct category for exactly one item — a genuine 1:1 sort.
      const usedLabels = q.matchItems!.map((i) => i.correctCategory).sort();
      expect(usedLabels).toEqual(HASH_ALGORITHMS.map((a) => a.label).sort());
      expect(q.matchCategories!.sort()).toEqual(HASH_ALGORITHMS.map((a) => a.label).sort());
    });

    it('Q11 items are not in DIGEST_SAMPLES\' own ascending-length order (position alone gives no hint)', () => {
      const q = getHashingDrillQuestion(10);
      const lengths = q.matchItems!.map((i) => i.text.length);
      const sorted = [...lengths].sort((a, b) => a - b);
      expect(lengths).not.toEqual(sorted);
    });

    it('Q12\'s correctCategory for every item is genuinely the top result of the real identifyHash(), not a hand-typed guess, and tiers are genuinely mixed', () => {
      const q = getHashingDrillQuestion(11);
      expect(q.answerType).toBe('match');
      expect(q.matchCategories).toEqual(['High confidence', 'Medium confidence', 'Low confidence']);
      for (const item of q.matchItems!) {
        const real = identifyHash(item.text)[0];
        expect(real, `identifyHash() returned nothing for "${item.text}"`).toBeDefined();
        const expectedLabel =
          real!.confidence === 'high' ? 'High confidence' : real!.confidence === 'medium' ? 'Medium confidence' : 'Low confidence';
        expect(item.correctCategory).toBe(expectedLabel);
      }
      const tiers = new Set(q.matchItems!.map((i) => i.correctCategory));
      expect(tiers.size).toBeGreaterThan(1);
    });

    it('Q13 reuses one real 32-hex digest across all four framings, matching the genuine identifyHash() MD5/NTLM/LM tie', () => {
      const q0 = getHashingDrillQuestion(0); // the MD5-of-"admin" digest question
      const digestMatch = q0.prompt.match(/[0-9a-f]{8}(?:\s[0-9a-f]{8})+/i);
      expect(digestMatch, 'Q1 prompt should embed a space-grouped 32-hex digest').not.toBeNull();
      const realHex = digestMatch![0].replace(/\s/g, '');
      expect(realHex).toHaveLength(32);

      const q = getHashingDrillQuestion(12);
      expect(q.answerType).toBe('match');
      expect(q.matchItems).toHaveLength(4);
      for (const item of q.matchItems!) {
        const embedded = item.text.match(/[0-9a-f]{32}/i)?.[0];
        expect(embedded).toBe(realHex);
      }

      const candidates = identifyHash(realHex);
      expect(candidates.find((c) => c.algorithm === 'MD5')?.confidence).toBe('medium');
      expect(candidates.find((c) => c.algorithm === 'NTLM')?.confidence).toBe('medium');
      expect(candidates.find((c) => c.algorithm === 'LM hash (legacy)')?.confidence).toBe('low');

      // Every real identifyHash() candidate name is offered as its own category button, verbatim.
      for (const c of candidates) expect(q.matchCategories).toContain(c.algorithm);
      // Plus exactly one more "no context" option beyond the three real candidates.
      expect(q.matchCategories!.length).toBe(candidates.length + 1);

      // Each of the four items lands in a distinct category (no two framings share a "correct" answer).
      const categoriesUsed = new Set(q.matchItems!.map((item) => item.correctCategory));
      expect(categoriesUsed.size).toBe(4);
    });
  });
});
