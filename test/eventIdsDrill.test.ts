import { describe, it, expect } from 'vitest';
import { getEventIdsDrillQuestion, EVENT_IDS_DRILL_TOTAL } from '../src/data/drills/eventIdsDrill';

describe('getEventIdsDrillQuestion', () => {
  it('is deterministic for a given index (required for the no-JS SSR/hydration contract)', () => {
    for (let i = 0; i < EVENT_IDS_DRILL_TOTAL; i++) {
      const a = getEventIdsDrillQuestion(i);
      const b = getEventIdsDrillQuestion(i);
      expect(b.prompt).toBe(a.prompt);
      expect(b.explanation).toBe(a.explanation);
      expect(b.correctAnswer).toBe(a.correctAnswer);
    }
  });

  it('wraps safely for an out-of-range index instead of throwing', () => {
    expect(() => getEventIdsDrillQuestion(EVENT_IDS_DRILL_TOTAL)).not.toThrow();
    expect(getEventIdsDrillQuestion(EVENT_IDS_DRILL_TOTAL).prompt).toBe(getEventIdsDrillQuestion(0).prompt);
  });

  it('no question is multiple choice — every question (including the ATT&CK bonus questions) is free-text recall', () => {
    for (let i = 0; i < EVENT_IDS_DRILL_TOTAL; i++) {
      const q = getEventIdsDrillQuestion(i);
      expect(q.answerType).toBe('text');
      expect(q.choices).toBeUndefined();
    }
  });

  it('every question has a non-empty prompt/explanation, a working grade(), and a real event-id reference link', () => {
    for (let i = 0; i < EVENT_IDS_DRILL_TOTAL; i++) {
      const q = getEventIdsDrillQuestion(i);
      expect(q.prompt.length).toBeGreaterThan(0);
      expect(q.explanation.length).toBeGreaterThan(0);
      expect(typeof q.grade).toBe('function');
      expect(q.grade!(q.correctAnswer), `question ${i} grade() rejected its own correctAnswer "${q.correctAnswer}"`).toBe(true);
      expect(q.grade!('definitely-wrong'), `question ${i} grade() accepted an obviously wrong answer`).toBe(false);
      expect(q.referenceHref).toMatch(/^\/event-ids\//);
    }
  });

  it('"identify" questions grade a bare event ID number leniently regardless of surrounding text', () => {
    const q = getEventIdsDrillQuestion(0); // security-4624
    expect(q.correctAnswer).toBe('4624');
    expect(q.grade!('Event ID 4624')).toBe(true);
    expect(q.grade!('id: 4624')).toBe(true);
    expect(q.grade!('4625')).toBe(false);
  });

  it('"attack" bonus questions ask for a technique ID and grade case-insensitively / embedded in a sentence', () => {
    const attackIndices = [2, 5, 8]; // security-4720, sysmon-10, security-7045 per PICKS
    for (const i of attackIndices) {
      const q = getEventIdsDrillQuestion(i);
      expect(q.prompt).toMatch(/technique ID/);
      expect(q.correctAnswer).toMatch(/^T\d{4}(\.\d{3})?$/);
      expect(q.explanation).toContain(q.correctAnswer);
      expect(q.grade!(q.correctAnswer.toLowerCase())).toBe(true);
      expect(q.grade!(`technique ${q.correctAnswer}`)).toBe(true);
      expect(q.grade!('T9999')).toBe(false);
    }
  });
});
