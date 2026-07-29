import { describe, it, expect } from 'vitest';
import { getRegexDrillQuestion, REGEX_DRILL_TOTAL, REGEX_RANGE_CHALLENGES } from '../src/data/drills/regexDrill';

describe('getRegexDrillQuestion (RegEx Range)', () => {
  it('TOTAL matches the number of authored challenges', () => {
    expect(REGEX_DRILL_TOTAL).toBe(REGEX_RANGE_CHALLENGES.length);
    expect(REGEX_DRILL_TOTAL).toBeGreaterThanOrEqual(10);
  });

  it('is deterministic for a given index (required for the no-JS SSR/hydration contract)', () => {
    for (let i = 0; i < REGEX_DRILL_TOTAL; i++) {
      const a = getRegexDrillQuestion(i);
      const b = getRegexDrillQuestion(i);
      expect(b.prompt).toBe(a.prompt);
      expect(b.explanation).toBe(a.explanation);
      expect(b.testCases).toEqual(a.testCases);
    }
  });

  it('wraps safely for an out-of-range index instead of throwing', () => {
    expect(() => getRegexDrillQuestion(REGEX_DRILL_TOTAL)).not.toThrow();
    expect(getRegexDrillQuestion(REGEX_DRILL_TOTAL).prompt).toBe(getRegexDrillQuestion(0).prompt);
  });

  it('every question is a construct-type challenge with a prompt, explanation, hint, and both should/should-not test cases', () => {
    for (let i = 0; i < REGEX_DRILL_TOTAL; i++) {
      const q = getRegexDrillQuestion(i);
      expect(q.answerType).toBe('construct');
      expect(q.prompt.length).toBeGreaterThan(0);
      expect(q.explanation.length).toBeGreaterThan(0);
      expect(q.hint && q.hint.length).toBeGreaterThan(0);
      expect(typeof q.validate).toBe('function');
      expect(q.testCases && q.testCases.length).toBeGreaterThan(0);
      const hasMustMatch = q.testCases!.some((tc) => tc.shouldMatch);
      const hasMustNotMatch = q.testCases!.some((tc) => !tc.shouldMatch);
      expect(hasMustMatch, `challenge ${i} has no must-match case`).toBe(true);
      expect(hasMustNotMatch, `challenge ${i} has no must-NOT-match case`).toBe(true);
    }
  });

  it('the only challenge with a reference link is the capstone, and it points at the live Regex Tester', () => {
    for (let i = 0; i < REGEX_DRILL_TOTAL; i++) {
      const q = getRegexDrillQuestion(i);
      if (i === REGEX_DRILL_TOTAL - 1) {
        expect(q.referenceHref).toBe('/tools/regex-tester/');
      } else {
        expect(q.referenceHref).toBeUndefined();
      }
    }
  });

  it('every authored reference solution actually passes its own challenge, via the real validate() the UI calls', () => {
    for (let i = 0; i < REGEX_DRILL_TOTAL; i++) {
      const challenge = REGEX_RANGE_CHALLENGES[i];
      const q = getRegexDrillQuestion(i);
      const outcome = q.validate!(challenge.referenceSolution);
      expect(outcome.ok, `challenge "${challenge.id}" reference pattern failed to compile`).toBe(true);
      if (outcome.ok) {
        expect(outcome.pass, `challenge "${challenge.id}" reference pattern didn't pass its own test cases: ${JSON.stringify(outcome.results)}`).toBe(true);
      }
    }
  });

  it('a clearly wrong pattern fails every challenge (proves validate() actually discriminates, not just returns true)', () => {
    for (let i = 0; i < REGEX_DRILL_TOTAL; i++) {
      const q = getRegexDrillQuestion(i);
      const outcome = q.validate!('this will absolutely never match any test case here');
      expect(outcome.ok).toBe(true);
      if (outcome.ok) expect(outcome.pass).toBe(false);
    }
  });

  it('an invalid regex (unclosed group) is reported as a compile error, not a silent failure or a throw', () => {
    for (let i = 0; i < REGEX_DRILL_TOTAL; i++) {
      const q = getRegexDrillQuestion(i);
      expect(() => q.validate!('(')).not.toThrow();
      const outcome = q.validate!('(');
      expect(outcome.ok).toBe(false);
      if (!outcome.ok) expect(outcome.error && outcome.error.length).toBeGreaterThan(0);
    }
  });

  it('the capstone challenge specifically rejects a naive digit-counting pattern that does not range-check octets (proves the test data forces real regex understanding, not a shortcut)', () => {
    const capstone = getRegexDrillQuestion(REGEX_DRILL_TOTAL - 1);
    const naive = capstone.validate!(String.raw`\d{1,3}(\.\d{1,3}){3}`);
    expect(naive.ok).toBe(true);
    if (naive.ok) expect(naive.pass).toBe(false);
  });

  it('challenge ids are unique and every concept name is distinct (no duplicated lesson)', () => {
    const ids = REGEX_RANGE_CHALLENGES.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
    const concepts = REGEX_RANGE_CHALLENGES.map((c) => c.concept);
    expect(new Set(concepts).size).toBe(concepts.length);
  });

  it('every authored reference solution also passes its own hiddenTestCases, via the real validate() the UI calls', () => {
    // A reference solution that only clears the VISIBLE cases but trips its
    // own hidden generalization check would be a broken "correct answer" —
    // this would show up as outcome.pass === false (with a
    // generalizationGap) even though it's the authored right answer.
    for (let i = 0; i < REGEX_DRILL_TOTAL; i++) {
      const challenge = REGEX_RANGE_CHALLENGES[i];
      const q = getRegexDrillQuestion(i);
      const outcome = q.validate!(challenge.referenceSolution);
      expect(outcome.ok).toBe(true);
      if (outcome.ok) {
        expect(outcome.pass, `challenge "${challenge.id}" reference pattern failed its own hidden generalization check: ${JSON.stringify(outcome.generalizationGap)}`).toBe(true);
        expect(outcome.generalizationGap, `challenge "${challenge.id}" reference pattern unexpectedly flagged a generalization gap`).toBeUndefined();
      }
    }
  });

  it('every challenge with hiddenTestCases catches a pattern that only fits the visible samples (proves the generalization check actually discriminates)', () => {
    // One concrete "wrong concept, but happens to fit every VISIBLE sample"
    // pattern per challenge that ships hiddenTestCases — each was verified
    // directly against this file's own compileRegexSafely/findAllMatches
    // before being hardcoded here (see regexDrill.ts's own comments next to
    // each hiddenTestCases entry for the reasoning).
    const wrongButFitsVisible: Record<string, string> = {
      literals: 'power',
      'character-classes': '[CDE]',
      quantifiers: String.raw`\d.*\d.*\d.*\d`,
      alternation: 'vbs|ps|bat',
      'word-boundaries': ' admin ',
      'negated-classes': String.raw`\[(WARN|ERROR|CRIT)\]`,
      backreferences: String.raw`\b(the the|user user|error error)\b`,
      capstone: String.raw`\b(?!(?:300|256|999)\b)\d{1,3}(\.(?!(?:300|256|999)\b)\d{1,3}){3}\b`,
    };
    const withHidden = REGEX_RANGE_CHALLENGES.filter((c) => c.hiddenTestCases && c.hiddenTestCases.length > 0);
    expect(withHidden.length).toBe(Object.keys(wrongButFitsVisible).length);

    for (const challenge of withHidden) {
      const wrongPattern = wrongButFitsVisible[challenge.id];
      expect(wrongPattern, `no "wrong but fits visible" pattern authored for challenge "${challenge.id}"`).toBeDefined();
      const index = REGEX_RANGE_CHALLENGES.indexOf(challenge);
      const q = getRegexDrillQuestion(index);
      const outcome = q.validate!(wrongPattern);
      expect(outcome.ok, `challenge "${challenge.id}"'s wrong pattern failed to compile`).toBe(true);
      if (!outcome.ok) continue;

      // Must actually fit every VISIBLE sample — otherwise this isn't
      // testing the generalization check at all, just an ordinary wrong answer.
      const visiblePass = outcome.results!.every((r) => r.actualMatch === r.shouldMatch);
      expect(visiblePass, `challenge "${challenge.id}"'s wrong pattern doesn't even fit the visible test cases — not a valid generalization-gap fixture`).toBe(true);

      // But must NOT be reported as solved, and must carry a generalizationGap
      // naming exactly the hidden case it tripped on.
      expect(outcome.pass, `challenge "${challenge.id}"'s wrong pattern was incorrectly accepted as solved`).toBe(false);
      expect(outcome.generalizationGap, `challenge "${challenge.id}" didn't report a generalizationGap for its wrong pattern`).toBeDefined();
      const expectedHidden = challenge.hiddenTestCases![0];
      expect(outcome.generalizationGap!.text).toBe(expectedHidden.text);
      expect(outcome.generalizationGap!.shouldMatch).toBe(expectedHidden.shouldMatch);
      expect(outcome.generalizationGap!.actualMatch).toBe(!expectedHidden.shouldMatch);
    }
  });

  it('anchors, escaping, and lookahead were deliberately left without hiddenTestCases', () => {
    const noHidden = ['anchors', 'escaping', 'lookahead'];
    for (const id of noHidden) {
      const challenge = REGEX_RANGE_CHALLENGES.find((c) => c.id === id);
      expect(challenge, `challenge "${id}" not found`).toBeDefined();
      expect(challenge!.hiddenTestCases, `challenge "${id}" unexpectedly has hiddenTestCases`).toBeUndefined();
    }
  });
});
