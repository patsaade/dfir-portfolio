import { describe, it, expect } from 'vitest';
import { getAttackDrillQuestion, attackDrillQuestionBank, ATTACK_DRILL_TOTAL } from '../src/data/drills/attackDrill';
import { assertBankSerialisesFaithfully } from './helpers/graderEquivalence';
import { ATTACK_TACTIC_ORDER } from '../src/data/references';

const TEXT_QUESTIONS_TOTAL = 10;

describe('getAttackDrillQuestion', () => {
  it('is deterministic for a given index (required for the no-JS SSR/hydration contract)', () => {
    for (let i = 0; i < ATTACK_DRILL_TOTAL; i++) {
      const a = getAttackDrillQuestion(i);
      const b = getAttackDrillQuestion(i);
      expect(b.prompt).toBe(a.prompt);
      expect(b.explanation).toBe(a.explanation);
      expect(b.correctAnswer).toBe(a.correctAnswer);
      expect(b.correctOrder).toEqual(a.correctOrder);
      expect(b.sequenceItems).toEqual(a.sequenceItems);
    }
  });

  it('does not throw for an out-of-range index (defensive only — the live UI never advances past ATTACK_DRILL_TOTAL)', () => {
    // Unlike the other drill modules' simple `index % QUESTIONS.length`, the
    // text-question half of this generator strides through a much larger
    // pool via `(index * stride) % POOL.length`, so index === ATTACK_DRILL_TOTAL
    // is NOT guaranteed to reproduce index 0's exact question — only that it
    // stays in-bounds (it lands back in the sequence-question rotation).
    expect(() => getAttackDrillQuestion(ATTACK_DRILL_TOTAL)).not.toThrow();
    const q = getAttackDrillQuestion(ATTACK_DRILL_TOTAL);
    expect(q.prompt.length).toBeGreaterThan(0);
  });

  describe('text questions (indices 0..9 — unchanged by the added sequence questions)', () => {
    it('every text question is free-text recall, never multiple choice', () => {
      for (let i = 0; i < TEXT_QUESTIONS_TOTAL; i++) {
        const q = getAttackDrillQuestion(i);
        expect(q.answerType).toBe('text');
        expect(q.choices).toBeUndefined();
      }
    });

    it('every text question has a non-empty prompt/explanation, a working grade(), and a real ATT&CK map reference link', () => {
      for (let i = 0; i < TEXT_QUESTIONS_TOTAL; i++) {
        const q = getAttackDrillQuestion(i);
        expect(q.prompt.length).toBeGreaterThan(0);
        expect(q.explanation.length).toBeGreaterThan(0);
        expect(typeof q.grade).toBe('function');
        expect(q.grade!(q.correctAnswer!), `question ${i} grade() rejected its own correctAnswer "${q.correctAnswer}"`).toBe(true);
        expect(q.grade!('definitely-wrong'), `question ${i} grade() accepted an obviously wrong answer`).toBe(false);
        expect(q.referenceHref).toMatch(/^\/reference\/attack-map\//);
      }
    });

    it('even-index questions ask for a technique ID and grade case-insensitively / embedded in a sentence', () => {
      for (let i = 0; i < TEXT_QUESTIONS_TOTAL; i += 2) {
        const q = getAttackDrillQuestion(i);
        expect(q.prompt).toMatch(/technique ID/);
        expect(q.correctAnswer).toMatch(/^T\d{4}(\.\d{3})?$/);
        expect(q.explanation).toContain(q.correctAnswer);
        expect(q.grade!(q.correctAnswer!.toLowerCase())).toBe(true);
        expect(q.grade!(`technique ${q.correctAnswer}`)).toBe(true);
        expect(q.grade!('T9999')).toBe(false);
      }
    });

    it('odd-index questions ask for a tactic and grade a real Enterprise tactic name, hyphen/case-insensitively', () => {
      for (let i = 1; i < TEXT_QUESTIONS_TOTAL; i += 2) {
        const q = getAttackDrillQuestion(i);
        expect(q.prompt).toMatch(/which MITRE ATT&CK tactic/);
        expect(ATTACK_TACTIC_ORDER).toContain(q.correctAnswer);
        expect(q.grade!(q.correctAnswer!.toUpperCase())).toBe(true);
        expect(q.grade!(q.correctAnswer!.toLowerCase())).toBe(true);
        expect(q.grade!('not-a-real-tactic')).toBe(false);
      }
    });

    it('the "Command and Control" tactic (if sampled) is also accepted as its common "C2" abbreviation', () => {
      for (let i = 1; i < TEXT_QUESTIONS_TOTAL; i += 2) {
        const q = getAttackDrillQuestion(i);
        if (q.correctAnswer === 'Command and Control') {
          expect(q.grade!('C2')).toBe(true);
          expect(q.grade!('c2')).toBe(true);
        }
      }
    });
  });

  describe('"Order the intrusion" sequence questions (indices 10+)', () => {
    it('every sequence question is answerType "sequence" with matching tile sets', () => {
      for (let i = TEXT_QUESTIONS_TOTAL; i < ATTACK_DRILL_TOTAL; i++) {
        const q = getAttackDrillQuestion(i);
        expect(q.answerType).toBe('sequence');
        expect(q.prompt.length).toBeGreaterThan(0);
        expect(q.explanation.length).toBeGreaterThan(0);
        expect(Array.isArray(q.sequenceItems)).toBe(true);
        expect(Array.isArray(q.correctOrder)).toBe(true);
        expect(q.sequenceItems!.length).toBe(q.correctOrder!.length);
        expect(q.sequenceItems!.length).toBeGreaterThanOrEqual(4);
        // Same multiset of tiles, just reordered — a shuffle, not a
        // different set of items.
        expect([...q.sequenceItems!].sort()).toEqual([...q.correctOrder!].sort());
        // The shuffle must actually be a shuffle: the tiles must NOT already
        // render in the correct order (that would make the question
        // trivially "already solved" with no reordering required).
        expect(q.sequenceItems).not.toEqual(q.correctOrder);
      }
    });

    it('every sequence question links to the real ATT&CK map and ships a hint naming the real tactic order', () => {
      for (let i = TEXT_QUESTIONS_TOTAL; i < ATTACK_DRILL_TOTAL; i++) {
        const q = getAttackDrillQuestion(i);
        expect(q.referenceHref).toBe('/reference/attack-map/');
        expect(q.hint).toBeTruthy();
        for (const tactic of ATTACK_TACTIC_ORDER) {
          expect(q.hint).toContain(tactic);
        }
      }
    });

    it('every tile is formatted "T#### — Technique Name" with a real technique id', () => {
      for (let i = TEXT_QUESTIONS_TOTAL; i < ATTACK_DRILL_TOTAL; i++) {
        const q = getAttackDrillQuestion(i);
        for (const tile of q.correctOrder!) {
          expect(tile).toMatch(/^T\d{4}(\.\d{3})? — .+/);
        }
      }
    });

    it("correctOrder's tactics are strictly ascending in ATTACK_TACTIC_ORDER (the real MITRE kill-chain order)", () => {
      // Cross-check against the live dataset via the same explanation string
      // buildSequenceQuestion() derives its ordering assertion from — every
      // tactic named in the explanation, in the order it appears, must be
      // strictly increasing in ATTACK_TACTIC_ORDER.
      for (let i = TEXT_QUESTIONS_TOTAL; i < ATTACK_DRILL_TOTAL; i++) {
        const q = getAttackDrillQuestion(i);
        const tacticsInOrder = [...q.explanation.matchAll(/\(([^()]+)\)/g)].map((m) => m[1]);
        expect(tacticsInOrder.length).toBe(q.correctOrder!.length);
        let lastPos = -1;
        for (const tactic of tacticsInOrder) {
          expect(ATTACK_TACTIC_ORDER).toContain(tactic);
          const pos = ATTACK_TACTIC_ORDER.indexOf(tactic);
          expect(pos, `tactic "${tactic}" is not strictly after the previous one in ${JSON.stringify(tacticsInOrder)}`).toBeGreaterThan(lastPos);
          lastPos = pos;
        }
      }
    });

    it('has no duplicate tiles within a single sequence question', () => {
      for (let i = TEXT_QUESTIONS_TOTAL; i < ATTACK_DRILL_TOTAL; i++) {
        const q = getAttackDrillQuestion(i);
        expect(new Set(q.correctOrder)).toEqual(new Set(q.correctOrder!.map((s) => s)));
        expect(new Set(q.correctOrder).size).toBe(q.correctOrder!.length);
      }
    });
  });
});

// The /drills/attack/ page no longer imports this generator client-side — it
// materialises the whole bank at build time and ships it as JSON, so the
// dataset stays out of the page bundle (see src/data/drills/graders.ts). That
// only holds together if the serialised `grader` descriptors grade EXACTLY
// like the closures they replace.
describe('attackDrillQuestionBank (build-time serialisation)', () => {
  it('every question serialises, round-trips through JSON, and grades identically to its original closure', () => {
    assertBankSerialisesFaithfully(ATTACK_DRILL_TOTAL, getAttackDrillQuestion, attackDrillQuestionBank);
  });

  it('uses the expected grader descriptor per question shape — technique-id for the id questions, tactic for the tactic ones, none for the sequence ones', () => {
    for (let i = 0; i < TEXT_QUESTIONS_TOTAL; i++) {
      const q = getAttackDrillQuestion(i);
      expect(q.grader?.kind).toBe(i % 2 === 0 ? 'technique-id' : 'tactic');
    }
    for (let i = TEXT_QUESTIONS_TOTAL; i < ATTACK_DRILL_TOTAL; i++) {
      // 'sequence' questions are graded positionally against correctOrder by
      // the engine itself — no closure, so nothing to describe.
      expect(getAttackDrillQuestion(i).grader).toBeUndefined();
      expect(getAttackDrillQuestion(i).grade).toBeUndefined();
    }
  });

  it("the descriptor captures only the small scalar, never the technique object (this is what makes the payload fix possible)", () => {
    const idQ = getAttackDrillQuestion(0);
    expect(idQ.grader).toEqual({ kind: 'technique-id', correctId: idQ.correctAnswer });
    const tacticQ = getAttackDrillQuestion(1);
    expect(tacticQ.grader).toEqual({ kind: 'tactic', correct: tacticQ.correctAnswer });
  });

  it('the serialised bank carries no ATT&CK dataset beyond the questions themselves', () => {
    const bank = attackDrillQuestionBank();
    const keys = new Set(bank.flatMap((q) => Object.keys(q)));
    // Anything not on this list would mean toSerialisableQuestion started
    // carrying a field the engine never reads — dead weight in the island.
    const allowed = new Set([
      'prompt',
      'explanation',
      'answerType',
      'referenceHref',
      'referenceLabel',
      'hint',
      'artifact',
      'correctAnswer',
      'grader',
      'choices',
      'testCases',
      'fields',
      'matchItems',
      'matchCategories',
      'sequenceItems',
      'correctOrder',
    ]);
    for (const k of keys) expect(allowed.has(k), `unexpected serialised field "${k}"`).toBe(true);
  });
});
