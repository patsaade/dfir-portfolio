// Serialisable grader descriptors + the tiny client-side shim that turns one
// back into the `grade()` closure DrillEngine's own runtime expects.
//
// WHY THIS EXISTS — the payload problem it solves.
// A DrillQuestion carries FUNCTION members (`grade`, and per-field
// `DrillExtractField.grade`). Three drills — /drills/event-ids/,
// /drills/attack/, /drills/threat-actors/ — used to import their whole
// question generator into their own CLIENT script, and each generator
// transitively imports a full generated dataset (the entire ATT&CK Enterprise
// set, all 125 eventIds entries including every raw sampleLog, the whole
// threat-actors generated file). Rollup therefore bundled the entire corpus
// into the page — ~1.37 MB raw / ~242 KB brotli across the three — to ask ten
// questions each.
//
// Every one of those generators is a PURE, DETERMINISTIC function of a
// question index with a fixed total, so the complete bank can be materialised
// at BUILD time in the page's frontmatter and handed to the client as data.
// The only thing that can't cross that boundary is a function: JSON has no
// way to carry a closure. Hence this file.
//
// The saving grace, and the reason the refactor is safe at all: every one of
// those `grade` closures captures a SMALL SCALAR (a technique id, a tactic
// name) or a SMALL ARRAY OF STRINGS (a group's own names/aliases, a naming
// fact's acceptable phrasings) — never the dataset it came from. So a closure
// can be replaced, losslessly, by a descriptor naming (a) which grading rule
// applies and (b) the small captured value it applies to. `hydrateGrader()`
// rebuilds the exact same predicate on the client from that descriptor.
//
// GRADING SEMANTICS ARE LOAD-BEARING. Each `kind` below reproduces one
// specific original closure character for character — same normalisation, same
// case handling, same accepted-alias behaviour, same empty-input handling. A
// subtle difference here silently changes which answers are marked correct,
// which no test outside test/*Drill.test.ts's descriptor-vs-closure
// equivalence assertions would catch. Note in particular that 'group-name'
// rejects an empty answer up front while 'any-of' does NOT — that asymmetry is
// inherited verbatim from the two original closures (threatActorsDrill's
// `matchesGroupName` guards `if (!n) return false`; its `buildNamingConvention`
// grader does not) and is deliberately preserved rather than "tidied up".
//
// This module imports NOTHING — no dataset, no sibling drill module, not even
// a type from drillEngine.ts (which would create an import cycle, since that
// file's own DrillQuestion/DrillExtractField types reference DrillGrader). It
// is the only drill-data file that ships to the browser, and it stays a few
// hundred bytes.

/** How a serialised question (or extract field) is graded once rehydrated. */
export type DrillGrader =
  /**
   * "Type the MITRE ATT&CK technique ID." Accepts the id anywhere in the
   * answer, case-insensitively — "T1059", "t1059", "technique T1059" all
   * grade correct — while still rejecting a bare number or a different id.
   * Reproduces attackDrill's `idQuestion` and eventIdsDrill's
   * `buildAttackQuestion` graders (both were `extractTechniqueId(ans) ===
   * correctId.toUpperCase()`, over identical local copies of that helper).
   */
  | { kind: 'technique-id'; correctId: string }
  /**
   * "Type the tactic this technique maps to." Punctuation/spacing-insensitive
   * and case-insensitive, with "C2" accepted for "Command and Control".
   * Reproduces attackDrill's `tacticQuestion` grader.
   */
  | { kind: 'tactic'; correct: string }
  /**
   * "Name the threat actor group." Accepts the group's canonical name OR any
   * of its own real aliases, trimmed + case-insensitive; an empty answer is
   * always wrong. `names` is `[actor.name, ...actor.aliases]`.
   * Reproduces threatActorsDrill's `matchesGroupName`.
   */
  | { kind: 'group-name'; names: string[] }
  /**
   * A hand-authored list of verified acceptable phrasings, compared trimmed +
   * case-insensitive. Reproduces threatActorsDrill's `buildNamingConvention`
   * grader (`spec.acceptableAnswers`) and `buildApplyNaming`'s single-value
   * one (`normalize(ans) === normalize(spec.code)`, i.e. `accepted: [code]`).
   * Deliberately has NO empty-answer guard — see this file's header.
   */
  | { kind: 'any-of'; accepted: string[] }
  /**
   * Extract-field grader for a Sysmon multi-value list: Sysmon appends a
   * trailing ";" after a value list even with one value present, so a learner
   * who types the value without it is still right. Reproduces eventIdsDrill's
   * `normalizeTrailingListMarker`-based per-field grader.
   */
  | { kind: 'trailing-list-value'; correct: string };

/** threatActorsDrill's `normalize`, verbatim. */
function normalize(s: unknown): string {
  return String(s ?? '').trim().toLowerCase();
}

/** attackDrill's / eventIdsDrill's `extractTechniqueId`, verbatim (they were
 *  byte-identical local copies of each other). */
function extractTechniqueId(s: string): string | null {
  const m = String(s)
    .toUpperCase()
    .match(/T\d{4}(?:\.\d{3})?/);
  return m ? m[0] : null;
}

/** attackDrill's `normalizeTactic`, verbatim. */
function normalizeTactic(s: string): string {
  const n = String(s)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
  return n === 'c2' ? 'command and control' : n;
}

/** eventIdsDrill's `normalizeTrailingListMarker`, verbatim. */
function normalizeTrailingListMarker(s: string): string {
  return String(s).trim().replace(/;$/, '').trim();
}

/**
 * Rebuild the `grade(userAnswer) => boolean` predicate a descriptor stands
 * for. Pure and dataset-free — this is the whole client-side cost of the
 * build-time materialisation.
 */
export function hydrateGrader(grader: DrillGrader): (userAnswer: string) => boolean {
  switch (grader.kind) {
    case 'technique-id': {
      const target = grader.correctId.toUpperCase();
      return (ans) => extractTechniqueId(ans) === target;
    }
    case 'tactic': {
      const target = normalizeTactic(grader.correct);
      return (ans) => normalizeTactic(ans) === target;
    }
    case 'group-name': {
      const targets = grader.names.map(normalize);
      return (ans) => {
        const n = normalize(ans);
        if (!n) return false;
        return targets.some((t) => t === n);
      };
    }
    case 'any-of': {
      const targets = grader.accepted.map(normalize);
      return (ans) => {
        const n = normalize(ans);
        return targets.some((t) => t === n);
      };
    }
    case 'trailing-list-value': {
      const target = normalizeTrailingListMarker(grader.correct).toLowerCase();
      return (v) => normalizeTrailingListMarker(v).toLowerCase() === target;
    }
    default: {
      // Exhaustiveness guard — a new kind added to the union without a case
      // here is a compile error, not a silently always-wrong question.
      const never: never = grader;
      throw new Error(`hydrateGrader: unknown grader kind ${JSON.stringify(never)}`);
    }
  }
}

// File-local (knip: not exported — nothing outside this module names it).
type DrillAnswerType = 'text' | 'choice' | 'construct' | 'subnet' | 'extract' | 'match' | 'sequence';

/** An 'extract' blank, minus its closure. File-local: consumers name the
 *  hydrated form (HydratedDrillExtractField) instead. */
interface SerialisableDrillExtractField {
  label: string;
  correctValue: string;
  /** Present only where the original field carried a custom `grade` closure;
   *  absent means the engine's own default (trimmed, case-insensitive exact
   *  match against `correctValue`), which needs no descriptor. */
  grader?: DrillGrader;
}

/**
 * A DrillQuestion reduced to exactly what survives `JSON.stringify` AND what
 * drillEngine.ts actually reads back out. Every function member is gone;
 * `grade` is replaced by `grader`.
 */
export interface SerialisableDrillQuestion {
  prompt: string;
  explanation: string;
  answerType: DrillAnswerType;
  referenceHref?: string;
  referenceLabel?: string;
  hint?: string;
  artifact?: string;
  correctAnswer?: string;
  grader?: DrillGrader;
  choices?: string[];
  testCases?: { text: string; shouldMatch: boolean }[];
  fields?: SerialisableDrillExtractField[];
  matchItems?: { text: string; correctCategory: string }[];
  matchCategories?: string[];
  sequenceItems?: string[];
  correctOrder?: string[];
}

/** Structural shape `toSerialisableQuestion` accepts — a DrillQuestion, without
 *  importing DrillQuestion (see this file's "imports NOTHING" note). The
 *  function members are typed loosely on purpose: this function only ever
 *  checks whether they're present, never calls them. */
interface SerialisableQuestionInput extends SerialisableDrillQuestion {
  grade?: (userAnswer: string) => boolean;
  validate?: unknown;
  subnetStart?: unknown;
  subnetBuild?: unknown;
  subnetParse?: unknown;
  subnetPreview?: unknown;
  matchEquals?: unknown;
  hiddenTestCases?: unknown;
  fields?: HydratedDrillExtractField[];
}

/** An 'extract' blank with its closure back on (the shape drillEngine.ts's
 *  handleExtractCheck reads) — also, structurally, exactly what a live
 *  DrillExtractField is. */
export interface HydratedDrillExtractField extends SerialisableDrillExtractField {
  grade?: (userValue: string) => boolean;
}

/** What `hydrateQuestion` hands back to the engine: a serialised question with
 *  its `grade` closures rebuilt from the descriptors. */
// File-local — `hydrateQuestion`'s return type; nothing outside names it.
interface HydratedDrillQuestion extends Omit<SerialisableDrillQuestion, 'fields'> {
  fields?: HydratedDrillExtractField[];
  grade?: (userAnswer: string) => boolean;
}

/**
 * BUILD-TIME ONLY (called from a page's frontmatter). Reduces one generated
 * DrillQuestion to its JSON-safe form, and — critically — THROWS rather than
 * silently dropping anything it cannot carry across the boundary.
 *
 * That guard is the whole point of doing this explicitly instead of leaning on
 * `JSON.stringify`'s own silent function-dropping: if a future change gives one
 * of these three drills a `validate`/`subnetBuild`/`matchEquals` closure, or a
 * `grade` with no matching `grader` descriptor, the build fails loudly instead
 * of shipping a question that grades every answer wrong (or, worse, one that
 * quietly falls back to a laxer default and marks wrong answers correct).
 */
export function toSerialisableQuestion(q: SerialisableQuestionInput): SerialisableDrillQuestion {
  const where = `${q.answerType} question "${String(q.prompt).slice(0, 60)}…"`;
  for (const fn of ['validate', 'subnetBuild', 'subnetParse', 'subnetPreview', 'matchEquals'] as const) {
    if (typeof q[fn] === 'function') {
      throw new Error(
        `toSerialisableQuestion: ${where} carries a live \`${fn}()\` closure, which cannot be serialised. ` +
          `Drills that need one (regex, ip-cidr) must keep importing their generator client-side.`
      );
    }
  }
  if (typeof q.grade === 'function' && !q.grader) {
    throw new Error(`toSerialisableQuestion: ${where} has a grade() closure but no \`grader\` descriptor to rebuild it from.`);
  }

  // Non-function members this serialiser also does not carry. Guarded rather
  // than dropped: `subnetStart` is read on its own by DrillEngine.astro for the
  // no-JS pre-fill, so losing it silently would quietly degrade that render —
  // exactly the failure mode this function's doc comment promises to prevent.
  for (const k of ['subnetStart', 'hiddenTestCases'] as const) {
    if (q[k] !== undefined) {
      throw new Error(
        `toSerialisableQuestion: ${where} carries \`${k}\`, which is not carried across the JSON boundary.`
      );
    }
  }

  // Each field is copied only when actually set, so the emitted island never
  // carries a run of `"x":null` for the ones this answerType doesn't use.
  // Written out longhand rather than looped over a key list: this is the
  // definitive statement of what does and doesn't cross the boundary, and a
  // field added to DrillQuestion but forgotten here fails the "display fields
  // are preserved" assertion in test/helpers/graderEquivalence.ts.
  const out: SerialisableDrillQuestion = {
    prompt: q.prompt,
    explanation: q.explanation,
    answerType: q.answerType,
  };
  if (q.referenceHref !== undefined) out.referenceHref = q.referenceHref;
  if (q.referenceLabel !== undefined) out.referenceLabel = q.referenceLabel;
  if (q.hint !== undefined) out.hint = q.hint;
  if (q.artifact !== undefined) out.artifact = q.artifact;
  if (q.correctAnswer !== undefined) out.correctAnswer = q.correctAnswer;
  if (q.grader !== undefined) out.grader = q.grader;
  if (q.choices !== undefined) out.choices = q.choices;
  if (q.testCases !== undefined) out.testCases = q.testCases;
  if (q.matchItems !== undefined) out.matchItems = q.matchItems;
  if (q.matchCategories !== undefined) out.matchCategories = q.matchCategories;
  if (q.sequenceItems !== undefined) out.sequenceItems = q.sequenceItems;
  if (q.correctOrder !== undefined) out.correctOrder = q.correctOrder;

  if (q.fields) {
    out.fields = q.fields.map((f) => {
      if (typeof f.grade === 'function' && !f.grader) {
        throw new Error(
          `toSerialisableQuestion: ${where} field "${f.label}" has a grade() closure but no \`grader\` descriptor to rebuild it from.`
        );
      }
      const field: SerialisableDrillExtractField = { label: f.label, correctValue: f.correctValue };
      if (f.grader) field.grader = f.grader;
      return field;
    });
  }
  return out;
}

/**
 * CLIENT-SIDE. The inverse: put the closures back so drillEngine.ts sees the
 * exact same object shape it always did. A page's `nextQuestion` becomes
 * `(i) => hydrateQuestion(QUESTIONS[i])`.
 */
export function hydrateQuestion(q: SerialisableDrillQuestion): HydratedDrillQuestion {
  const out: HydratedDrillQuestion = { ...q };
  if (q.grader) out.grade = hydrateGrader(q.grader);
  if (q.fields) {
    out.fields = q.fields.map((f) => (f.grader ? { ...f, grade: hydrateGrader(f.grader) } : { ...f }));
  }
  return out;
}
