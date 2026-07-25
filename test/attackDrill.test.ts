import { describe, it, expect } from 'vitest';
import { getAttackDrillQuestion, ATTACK_DRILL_TOTAL } from '../src/data/drills/attackDrill';
import { ATTACK_TACTIC_ORDER } from '../src/data/references';

describe('getAttackDrillQuestion', () => {
  it('is deterministic for a given index (required for the no-JS SSR/hydration contract)', () => {
    for (let i = 0; i < ATTACK_DRILL_TOTAL; i++) {
      const a = getAttackDrillQuestion(i);
      const b = getAttackDrillQuestion(i);
      expect(b.prompt).toBe(a.prompt);
      expect(b.explanation).toBe(a.explanation);
      expect(b.correctAnswer).toBe(a.correctAnswer);
    }
  });

  it('does not throw for an out-of-range index (defensive only — the live UI never advances past ATTACK_DRILL_TOTAL)', () => {
    // Unlike the other drill modules' simple `index % QUESTIONS.length`, this
    // generator strides through a much larger pool via `(index * stride) %
    // POOL.length`, so index === ATTACK_DRILL_TOTAL is NOT guaranteed to
    // reproduce index 0's exact question — only that it stays in-bounds.
    expect(() => getAttackDrillQuestion(ATTACK_DRILL_TOTAL)).not.toThrow();
    const q = getAttackDrillQuestion(ATTACK_DRILL_TOTAL);
    expect(q.prompt.length).toBeGreaterThan(0);
  });

  it('no question is multiple choice — every question is free-text recall', () => {
    for (let i = 0; i < ATTACK_DRILL_TOTAL; i++) {
      const q = getAttackDrillQuestion(i);
      expect(q.answerType).toBe('text');
      expect(q.choices).toBeUndefined();
    }
  });

  it('every question has a non-empty prompt/explanation, a working grade(), and a real ATT&CK map reference link', () => {
    for (let i = 0; i < ATTACK_DRILL_TOTAL; i++) {
      const q = getAttackDrillQuestion(i);
      expect(q.prompt.length).toBeGreaterThan(0);
      expect(q.explanation.length).toBeGreaterThan(0);
      expect(typeof q.grade).toBe('function');
      expect(q.grade!(q.correctAnswer), `question ${i} grade() rejected its own correctAnswer "${q.correctAnswer}"`).toBe(true);
      expect(q.grade!('definitely-wrong'), `question ${i} grade() accepted an obviously wrong answer`).toBe(false);
      expect(q.referenceHref).toMatch(/^\/attack-map\//);
    }
  });

  it('even-index questions ask for a technique ID and grade case-insensitively / embedded in a sentence', () => {
    for (let i = 0; i < ATTACK_DRILL_TOTAL; i += 2) {
      const q = getAttackDrillQuestion(i);
      expect(q.prompt).toMatch(/technique ID/);
      expect(q.correctAnswer).toMatch(/^T\d{4}(\.\d{3})?$/);
      expect(q.explanation).toContain(q.correctAnswer);
      expect(q.grade!(q.correctAnswer.toLowerCase())).toBe(true);
      expect(q.grade!(`technique ${q.correctAnswer}`)).toBe(true);
      expect(q.grade!('T9999')).toBe(false);
    }
  });

  it('odd-index questions ask for a tactic and grade a real Enterprise tactic name, hyphen/case-insensitively', () => {
    for (let i = 1; i < ATTACK_DRILL_TOTAL; i += 2) {
      const q = getAttackDrillQuestion(i);
      expect(q.prompt).toMatch(/which MITRE ATT&CK tactic/);
      expect(ATTACK_TACTIC_ORDER).toContain(q.correctAnswer);
      expect(q.grade!(q.correctAnswer.toUpperCase())).toBe(true);
      expect(q.grade!(q.correctAnswer.toLowerCase())).toBe(true);
      expect(q.grade!('not-a-real-tactic')).toBe(false);
    }
  });

  it('the "Command and Control" tactic (if sampled) is also accepted as its common "C2" abbreviation', () => {
    for (let i = 1; i < ATTACK_DRILL_TOTAL; i += 2) {
      const q = getAttackDrillQuestion(i);
      if (q.correctAnswer === 'Command and Control') {
        expect(q.grade!('C2')).toBe(true);
        expect(q.grade!('c2')).toBe(true);
      }
    }
  });
});
