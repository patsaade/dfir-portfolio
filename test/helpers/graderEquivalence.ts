// Shared assertions proving that a drill's SERIALISED question bank grades
// identically to the live `grade()` closures its generator still produces.
//
// Three drills (/drills/event-ids/, /drills/attack/, /drills/threat-actors/)
// materialise their whole bank at build time and ship it to the client as JSON
// — see src/data/drills/graders.ts for why. JSON can't carry a function, so
// each `grade` closure is mirrored by a serialisable `grader` descriptor that a
// small client-side shim rebuilds. The closure remains the source of truth in
// the data module; these helpers are what keep the descriptor honest.
//
// NOT a *.test.ts file, so vitest's `include: ['test/**/*.test.ts']` never
// collects it as a suite of its own — it's imported by the three drill suites.
import { expect } from 'vitest';
import {
  hydrateGrader,
  hydrateQuestion,
  toSerialisableQuestion,
  type DrillGrader,
  type HydratedDrillExtractField,
} from '../../src/data/drills/graders';
import type { DrillQuestion } from '../../src/scripts/drillEngine';

/** Reproduces drillEngine.ts's own per-field grading in handleExtractCheck:
 *  a custom `grade` when present, else a trimmed case-insensitive exact match
 *  against `correctValue`. Kept here so the equivalence check exercises the
 *  real engine semantics rather than only the custom-grader half. (A live
 *  DrillExtractField is structurally a HydratedDrillExtractField, so this takes
 *  both the original and the rehydrated shape.) */
export function fieldPasses(field: HydratedDrillExtractField, rawValue: string): boolean {
  const raw = String(rawValue == null ? '' : rawValue).trim();
  return typeof field.grade === 'function'
    ? Boolean(field.grade(raw))
    : raw.toLowerCase() === String(field.correctValue).trim().toLowerCase();
}

/** Every string a descriptor captured — the values a probe set should be built
 *  around, since those are exactly the inputs where the two implementations
 *  could plausibly disagree. */
function graderSeeds(grader: DrillGrader): string[] {
  switch (grader.kind) {
    case 'technique-id':
      return [grader.correctId];
    case 'tactic':
      return [grader.correct];
    case 'group-name':
      return grader.names;
    case 'any-of':
      return grader.accepted;
    case 'trailing-list-value':
      return [grader.correct];
  }
}

/** Near-miss variants of a known-correct answer: the case/whitespace/
 *  punctuation neighbourhood where a normalisation mismatch between the closure
 *  and the descriptor would show up. */
function mutations(s: string): string[] {
  return [
    s,
    s.toUpperCase(),
    s.toLowerCase(),
    `  ${s}  `,
    `\t${s}\n`,
    `${s};`,
    `${s}.`,
    `the ${s}`,
    `${s} group`,
    s.replace(/[\s\-_]+/g, ''),
    s.replace(/[\s\-_]+/g, '-'),
    s.slice(0, Math.max(1, s.length - 1)),
    s.split('').reverse().join(''),
  ];
}

/** Answers that belong in every probe set regardless of question: empties, a
 *  wrong technique id, a wrong tactic, the "C2" special case, junk. */
const UNIVERSAL_PROBES = [
  '',
  '   ',
  '\t\n',
  'x',
  '0',
  'T1059',
  'T9999',
  't1059.001',
  'technique T1003',
  'C2',
  'c2',
  'command and control',
  'Command-and-Control',
  'Credential Access',
  'Fancy Bear',
  'APT28',
  'CrowdStrike',
  '::ffff:198.51.100.42',
  '::ffff:198.51.100.42;',
  'undefined',
  'null',
];

/** The full probe set for one question: universal answers plus mutations of
 *  everything the question itself considers correct. */
function probesFor(q: DrillQuestion): string[] {
  const seeds = new Set<string>();
  if (q.correctAnswer) seeds.add(q.correctAnswer);
  if (q.grader) for (const s of graderSeeds(q.grader)) seeds.add(s);
  for (const f of q.fields ?? []) seeds.add(f.correctValue);
  const probes = new Set<string>(UNIVERSAL_PROBES);
  for (const seed of seeds) for (const m of mutations(seed)) probes.add(m);
  return [...probes];
}

/** Deep scan for anything `JSON.stringify` would silently drop — a function, or
 *  an `undefined` sitting where the client expects a value. */
function assertNoFunctions(value: unknown, path: string): void {
  if (typeof value === 'function') throw new Error(`serialised question still carries a function at ${path}`);
  if (Array.isArray(value)) {
    value.forEach((v, i) => assertNoFunctions(v, `${path}[${i}]`));
    return;
  }
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) assertNoFunctions(v, `${path}.${k}`);
  }
}

/**
 * The core contract this whole refactor rests on: for question `index` of a
 * drill's bank, the serialised-then-rehydrated question grades EVERY probe
 * answer exactly as the generator's own live closure does — top-level and
 * per-extract-field alike — and survives a real `JSON.parse(JSON.stringify())`
 * round-trip unchanged (which is literally what the page's JSON island does).
 *
 * Also asserts the display fields the engine reads back are preserved, so a
 * future field added to DrillQuestion but forgotten in `toSerialisableQuestion`
 * fails here rather than silently vanishing from the hydrated page.
 */
function assertSerialisedQuestionGradesIdentically(q: DrillQuestion, index: number): void {
  const at = `question #${index} (${q.answerType})`;

  const serialised = toSerialisableQuestion(q);
  assertNoFunctions(serialised, at);

  // Exactly what the JSON island does at runtime.
  const roundTripped = JSON.parse(JSON.stringify(serialised));
  expect(roundTripped, `${at} did not survive a JSON round-trip byte-for-byte`).toEqual(serialised);

  const hydrated = hydrateQuestion(roundTripped);

  // Display/behaviour fields drillEngine.ts reads.
  expect(hydrated.prompt, `${at} prompt`).toBe(q.prompt);
  expect(hydrated.explanation, `${at} explanation`).toBe(q.explanation);
  expect(hydrated.answerType, `${at} answerType`).toBe(q.answerType);
  expect(hydrated.referenceHref, `${at} referenceHref`).toBe(q.referenceHref);
  expect(hydrated.referenceLabel, `${at} referenceLabel`).toBe(q.referenceLabel);
  expect(hydrated.hint, `${at} hint`).toBe(q.hint);
  expect(hydrated.artifact, `${at} artifact`).toBe(q.artifact);
  expect(hydrated.correctAnswer, `${at} correctAnswer`).toBe(q.correctAnswer);
  expect(hydrated.choices, `${at} choices`).toEqual(q.choices);
  expect(hydrated.matchItems, `${at} matchItems`).toEqual(q.matchItems);
  expect(hydrated.matchCategories, `${at} matchCategories`).toEqual(q.matchCategories);
  expect(hydrated.sequenceItems, `${at} sequenceItems`).toEqual(q.sequenceItems);
  expect(hydrated.correctOrder, `${at} correctOrder`).toEqual(q.correctOrder);

  const probes = probesFor(q);

  // Top-level grading.
  if (typeof q.grade === 'function') {
    expect(q.grader, `${at} has a grade() closure but no grader descriptor`).toBeTruthy();
    expect(typeof hydrated.grade, `${at} hydrated grade`).toBe('function');
    for (const probe of probes) {
      expect(
        hydrated.grade!(probe),
        `${at}: descriptor ${JSON.stringify(q.grader)} disagreed with the original closure on ${JSON.stringify(probe)}`
      ).toBe(q.grade(probe));
    }
    // The standalone shim must agree with the closure too, not just the
    // question-level wrapper around it.
    const shim = hydrateGrader(q.grader!);
    for (const probe of probes) expect(shim(probe)).toBe(q.grade(probe));
  } else {
    expect(hydrated.grade, `${at} should have no grade()`).toBeUndefined();
    expect(hydrated.grader, `${at} should have no grader`).toBeUndefined();
  }

  // Per-field ('extract') grading, through the engine's own field path.
  const originalFields = q.fields ?? [];
  expect(hydrated.fields?.length ?? 0, `${at} field count`).toBe(originalFields.length);
  originalFields.forEach((original, i) => {
    const rebuilt = hydrated.fields![i];
    expect(rebuilt.label, `${at} field #${i} label`).toBe(original.label);
    expect(rebuilt.correctValue, `${at} field #${i} correctValue`).toBe(original.correctValue);
    if (typeof original.grade === 'function') {
      expect(original.grader, `${at} field "${original.label}" has a grade() closure but no grader descriptor`).toBeTruthy();
    }
    for (const probe of probes) {
      expect(
        fieldPasses(rebuilt, probe),
        `${at} field "${original.label}": serialised grading disagreed with the original on ${JSON.stringify(probe)}`
      ).toBe(fieldPasses(original, probe));
    }
  });
}

/**
 * Runs the contract above across a drill's whole bank, and asserts the
 * build-time bank builder (`*QuestionBank()`, what the page frontmatter calls)
 * produces exactly the same array.
 */
export function assertBankSerialisesFaithfully(
  total: number,
  getQuestion: (index: number) => DrillQuestion,
  bank: () => ReturnType<typeof toSerialisableQuestion>[]
): void {
  const built = bank();
  expect(built.length, 'bank length must match the drill total the page renders').toBe(total);
  for (let i = 0; i < total; i++) {
    assertSerialisedQuestionGradesIdentically(getQuestion(i), i);
    expect(built[i], `bank entry #${i} must equal toSerialisableQuestion(getQuestion(${i}))`).toEqual(
      toSerialisableQuestion(getQuestion(i))
    );
  }
}
