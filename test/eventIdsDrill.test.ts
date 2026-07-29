import { describe, it, expect } from 'vitest';
import { getEventIdsDrillQuestion, eventIdsDrillQuestionBank, EVENT_IDS_DRILL_TOTAL } from '../src/data/drills/eventIdsDrill';
import { hydrateQuestion, toSerialisableQuestion } from '../src/data/drills/graders';
import { assertBankSerialisesFaithfully, fieldPasses as sharedFieldPasses } from './helpers/graderEquivalence';
import { eventIdBySlug } from '../src/data/eventIds';
import type { DrillExtractField } from '../src/scripts/drillEngine';

// Mirrors drillEngine.ts's own handleExtractCheck grading logic exactly: the
// engine trims the raw input once, then either calls the field's own
// grade() or falls back to a case-insensitive trimmed compare against
// correctValue. Kept in lockstep with that function on purpose so this test
// file exercises the same grading contract the live UI does.
function fieldPasses(field: DrillExtractField, rawAnswer: string): boolean {
  const trimmed = rawAnswer.trim();
  return typeof field.grade === 'function'
    ? Boolean(field.grade(trimmed))
    : trimmed.toLowerCase() === String(field.correctValue).trim().toLowerCase();
}

// Per PICKS in src/data/drills/eventIdsDrill.ts.
const ATTACK_INDICES = [2, 5, 8]; // security-4720, sysmon-10, security-7045
const EXTRACT_INDICES = [0, 1, 3, 4, 6, 7, 9]; // security-4624, sysmon-11, security-1102, sysmon-22, security-4625, security-4672, sysmon-3

function slugFromReferenceHref(href: string): string {
  return href.replace(/^\/reference\/event-ids\//, '').replace(/\/$/, '');
}

describe('getEventIdsDrillQuestion', () => {
  it('is deterministic for a given index (required for the no-JS SSR/hydration contract)', () => {
    for (let i = 0; i < EVENT_IDS_DRILL_TOTAL; i++) {
      const a = getEventIdsDrillQuestion(i);
      const b = getEventIdsDrillQuestion(i);
      expect(b.prompt).toBe(a.prompt);
      expect(b.explanation).toBe(a.explanation);
      expect(b.answerType).toBe(a.answerType);
      if (a.answerType === 'extract') {
        expect(b.fields).toBe(a.fields);
        expect(b.artifact).toBe(a.artifact);
      } else {
        expect(b.correctAnswer).toBe(a.correctAnswer);
      }
    }
  });

  it('wraps safely for an out-of-range index instead of throwing', () => {
    expect(() => getEventIdsDrillQuestion(EVENT_IDS_DRILL_TOTAL)).not.toThrow();
    expect(getEventIdsDrillQuestion(EVENT_IDS_DRILL_TOTAL).prompt).toBe(getEventIdsDrillQuestion(0).prompt);
  });

  it('every question is either an "extract" triage or a free-text ATT&CK recall — never multiple choice', () => {
    for (let i = 0; i < EVENT_IDS_DRILL_TOTAL; i++) {
      const q = getEventIdsDrillQuestion(i);
      expect(['extract', 'text']).toContain(q.answerType);
      expect(q.choices).toBeUndefined();
    }
  });

  it('every question has a non-empty prompt/explanation and a real event-id reference link', () => {
    for (let i = 0; i < EVENT_IDS_DRILL_TOTAL; i++) {
      const q = getEventIdsDrillQuestion(i);
      expect(q.prompt.length).toBeGreaterThan(0);
      expect(q.explanation.length).toBeGreaterThan(0);
      expect(q.referenceHref).toMatch(/^\/reference\/event-ids\//);
      const entry = eventIdBySlug(slugFromReferenceHref(q.referenceHref!));
      expect(entry, `question ${i}'s referenceHref "${q.referenceHref}" doesn't resolve to a real EVENT_IDS entry`).toBeTruthy();
    }
  });

  it('"attack" bonus questions ask for a technique ID and grade case-insensitively / embedded in a sentence', () => {
    for (const i of ATTACK_INDICES) {
      const q = getEventIdsDrillQuestion(i);
      expect(q.answerType).toBe('text');
      expect(q.prompt).toMatch(/technique ID/);
      expect(q.correctAnswer).toMatch(/^T\d{4}(\.\d{3})?$/);
      expect(q.explanation).toContain(q.correctAnswer);
      expect(typeof q.grade).toBe('function');
      expect(q.grade!(q.correctAnswer!.toLowerCase())).toBe(true);
      expect(q.grade!(`technique ${q.correctAnswer}`)).toBe(true);
      expect(q.grade!('T9999')).toBe(false);
    }
  });

  it('"extract" triage questions show the entry\'s real sampleLog verbatim as the artifact', () => {
    for (const i of EXTRACT_INDICES) {
      const q = getEventIdsDrillQuestion(i);
      expect(q.answerType).toBe('extract');
      const entry = eventIdBySlug(slugFromReferenceHref(q.referenceHref!));
      expect(entry).toBeTruthy();
      expect(entry!.sampleLog).toBeTruthy();
      expect(q.artifact).toBe(entry!.sampleLog);
    }
  });

  it('"extract" triage questions render 3-4 independently-labeled fields, each with a unique label', () => {
    for (const i of EXTRACT_INDICES) {
      const q = getEventIdsDrillQuestion(i);
      expect(q.fields).toBeTruthy();
      const fields = q.fields!;
      expect(fields.length).toBeGreaterThanOrEqual(3);
      expect(fields.length).toBeLessThanOrEqual(4);
      const labels = fields.map((f) => f.label);
      expect(new Set(labels).size, `question ${i} has duplicate field labels: ${labels.join(', ')}`).toBe(labels.length);
    }
  });

  it('every "extract" field\'s correctValue is a real, verbatim substring of that entry\'s own sampleLog — never invented', () => {
    for (const i of EXTRACT_INDICES) {
      const q = getEventIdsDrillQuestion(i);
      const entry = eventIdBySlug(slugFromReferenceHref(q.referenceHref!))!;
      for (const field of q.fields!) {
        expect(
          entry.sampleLog!.includes(field.correctValue),
          `"${field.correctValue}" (field "${field.label}") is not a literal substring of ${entry.slug}'s real sampleLog`
        ).toBe(true);
      }
    }
  });

  it('every "extract" field grades its own correctValue as a pass and an obviously wrong value as a fail', () => {
    for (const i of EXTRACT_INDICES) {
      const q = getEventIdsDrillQuestion(i);
      for (const field of q.fields!) {
        expect(fieldPasses(field, field.correctValue), `field "${field.label}" rejected its own correctValue`).toBe(true);
        expect(fieldPasses(field, 'totally-wrong-value'), `field "${field.label}" accepted an obviously wrong value`).toBe(false);
      }
    }
  });

  it('grades an "extract" field case-insensitively and trims surrounding whitespace, matching the engine\'s own default', () => {
    const q = getEventIdsDrillQuestion(0); // security-4624
    const logonType = q.fields!.find((f) => f.label === 'Logon Type')!;
    expect(fieldPasses(logonType, '  3  ')).toBe(true);
    const accountName = q.fields!.find((f) => f.label === 'Account Name (New Logon)')!;
    expect(fieldPasses(accountName, 'JSMITH')).toBe(true);
    expect(fieldPasses(accountName, ' jsmith ')).toBe(true);
  });

  it('security-4624 disambiguates the same field name ("Account Name") appearing twice in different log blocks with different values', () => {
    const q = getEventIdsDrillQuestion(0); // security-4624
    const subject = q.fields!.find((f) => f.label === 'Account Name (Subject)');
    const newLogon = q.fields!.find((f) => f.label === 'Account Name (New Logon)');
    expect(subject).toBeTruthy();
    expect(newLogon).toBeTruthy();
    expect(subject!.correctValue).toBe('WORKSTATION01$');
    expect(newLogon!.correctValue).toBe('jsmith');
    expect(subject!.correctValue).not.toBe(newLogon!.correctValue);
  });

  it('sysmon-22\'s QueryResults field tolerates Sysmon\'s trailing ";" list-marker being omitted', () => {
    const q = getEventIdsDrillQuestion(4); // sysmon-22
    const field = q.fields!.find((f) => f.label === 'QueryResults')!;
    expect(field.correctValue).toBe('::ffff:198.51.100.42;');
    expect(fieldPasses(field, '::ffff:198.51.100.42;')).toBe(true);
    expect(fieldPasses(field, '::ffff:198.51.100.42')).toBe(true); // trailing ";" omitted — still correct
    expect(fieldPasses(field, '198.51.100.42')).toBe(false); // not the real recorded value
  });
});

// The /drills/event-ids/ page no longer imports this generator client-side —
// it materialises the whole bank at build time and ships it as JSON, so
// EVENT_IDS (every raw sampleLog) and the ATT&CK set stay out of the page
// bundle (see src/data/drills/graders.ts). That only holds together if the
// serialised `grader` descriptors grade EXACTLY like the closures they
// replace — including the per-FIELD one, which is the easiest to lose
// silently (a dropped field closure falls back to the engine's stricter
// default and starts marking a correct answer wrong).
describe('eventIdsDrillQuestionBank (build-time serialisation)', () => {
  it('every question serialises, round-trips through JSON, and grades identically to its original closure', () => {
    assertBankSerialisesFaithfully(EVENT_IDS_DRILL_TOTAL, getEventIdsDrillQuestion, eventIdsDrillQuestionBank);
  });

  it("uses a 'technique-id' descriptor on the ATT&CK-mapping questions and none on the extract ones", () => {
    for (let i = 0; i < EVENT_IDS_DRILL_TOTAL; i++) {
      const q = getEventIdsDrillQuestion(i);
      if (q.answerType === 'text') {
        expect(q.grader).toEqual({ kind: 'technique-id', correctId: q.correctAnswer });
      } else {
        // 'extract' questions grade per-field, not top-level.
        expect(q.grade).toBeUndefined();
        expect(q.grader).toBeUndefined();
      }
    }
  });

  it("sysmon-22's QueryResults field keeps its trailing-';' tolerance after serialisation (the one per-field closure in this drill)", () => {
    const q = getEventIdsDrillQuestion(4); // sysmon-22
    const original = q.fields!.find((f) => f.label === 'QueryResults')!;
    expect(original.grader).toEqual({ kind: 'trailing-list-value', correct: '::ffff:198.51.100.42;' });

    const rebuilt = hydrateQuestion(JSON.parse(JSON.stringify(toSerialisableQuestion(q)))).fields!.find(
      (f) => f.label === 'QueryResults'
    )!;
    expect(sharedFieldPasses(rebuilt, '::ffff:198.51.100.42;')).toBe(true);
    expect(sharedFieldPasses(rebuilt, '::ffff:198.51.100.42')).toBe(true); // trailing ";" omitted — still correct
    expect(sharedFieldPasses(rebuilt, '  ::FFFF:198.51.100.42  ')).toBe(true);
    expect(sharedFieldPasses(rebuilt, '198.51.100.42')).toBe(false);
  });

  it('every other extract field falls through to the engine default (no descriptor needed) and still grades identically', () => {
    for (let i = 0; i < EVENT_IDS_DRILL_TOTAL; i++) {
      const q = getEventIdsDrillQuestion(i);
      for (const f of q.fields ?? []) {
        if (f.label === 'QueryResults') continue;
        expect(f.grade, `field "${f.label}" unexpectedly has a custom closure`).toBeUndefined();
        expect(f.grader, `field "${f.label}" unexpectedly has a descriptor`).toBeUndefined();
      }
    }
  });
});
