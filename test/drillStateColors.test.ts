// Guards the pass/fail color pairing in DrillEngine.astro.
//
// THE REGRESSION THIS EXISTS FOR. Every affirmative drill state (`pass`,
// `correct`, `data-correct`) once used the `accent` token, because at the time
// there was no `success` token to reach for. `accent` is a DECORATIVE color and
// is amber/terracotta/salmon in 6 of the 10 palettes — the same warm hue family
// as `danger` — so pass and fail were genuinely hard to tell apart in the
// drills, which is the entire point of those indicators.
//
// Contrast checks cannot catch it (both colors passed AA happily) and neither
// can a type checker, since both are valid token names. It also survived one
// targeted sweep: `data-state="correct"` was missed because the sweep matched
// only `data-state="pass"` and `data-correct`, leaving the most prominent
// indicator of all — the verdict banner — still amber. Hence a test that
// enumerates the states rather than trusting a grep.
//
// test/themeContrast.test.ts covers the other half (success and danger must stay
// far apart in hue, and success must actually be green).
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const SRC = readFileSync(join(process.cwd(), 'src/components/DrillEngine.astro'), 'utf8');

/** Selector fragments that mean "the learner got this right". */
const AFFIRMATIVE = ['data-state="pass"', 'data-state="correct"', 'data-correct]'];
/** Selector fragments that mean "the learner got this wrong". */
const NEGATIVE = ['data-state="fail"', 'data-state="incorrect"', 'data-incorrect]'];

/** Every line binding a color to one of the given state fragments. */
const linesFor = (fragments: string[]) =>
  SRC.split('\n')
    .map((line, i) => ({ line, n: i + 1 }))
    .filter(({ line }) => fragments.some((f) => line.includes(f)))
    .filter(({ line }) => /borderColor|token\(colors\.|color:/.test(line));

describe('drill pass/fail colors', () => {
  it('binds every affirmative state to `success`, never `accent`', () => {
    const rows = linesFor(AFFIRMATIVE);
    expect(rows.length).toBeGreaterThan(0); // the selectors still exist at all
    const offenders = rows
      .filter(({ line }) => /\baccent\b/.test(line))
      .map(({ n, line }) => `DrillEngine.astro:${n}  ${line.trim()}`);
    expect(offenders).toEqual([]);
    // and each one positively uses success
    const missing = rows
      .filter(({ line }) => !/\bsuccess\b/.test(line))
      .map(({ n, line }) => `DrillEngine.astro:${n}  ${line.trim()}`);
    expect(missing).toEqual([]);
  });

  it('binds every negative state to `danger`, never the raw `red` keyword', () => {
    const rows = linesFor(NEGATIVE);
    expect(rows.length).toBeGreaterThan(0);
    const offenders = rows
      .filter(({ line }) => !/\bdanger\b/.test(line) || /['"]red['"]|:\s*red\b/.test(line))
      .map(({ n, line }) => `DrillEngine.astro:${n}  ${line.trim()}`);
    expect(offenders).toEqual([]);
  });

  // SITE-WIDE, not just DrillEngine. Scoping the guard above to one file is
  // exactly why this class of bug survived: a later audit found the raw `red`
  // keyword signalling error state in 12 OTHER components (41 occurrences —
  // HashCalculator, JwtDecoder, SigmaTester, YaraTester, RegexTester,
  // EmailHeaderAnalyzer, CronParser, CidrCalculator, PeExplorer,
  // TimestampConverter, MftUsnAnalyzer, RecycleBinParser), and TextDiffTool was
  // signalling "added" with `accent` — the same decorative warm token that made
  // the drills' pass/fail confusable.
  //
  // `danger` exists precisely because raw `red` is not per-palette
  // contrast-checked (it only reached ~3.8-4.2:1 against these surfaces, below
  // the 4.5:1 AA floor for normal text). A raw keyword also can't be tuned per
  // theme, so it reads identically on all 10 palettes regardless of their
  // backgrounds.
  it('never signals state with a raw color keyword anywhere in src/', () => {
    const offenders: string[] = [];
    const RAW = /color-mix\(\s*in srgb,\s*(red|green|lime|crimson)\b|:\s*(red|green|crimson)\s*[;'"]/;
    const walk = (dir: string) => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        const p = join(dir, e.name);
        if (e.isDirectory()) walk(p);
        else if (/\.(astro|css|ts)$/.test(e.name)) {
          readFileSync(p, 'utf8')
            .split('\n')
            .forEach((line, i) => {
              if (RAW.test(line)) offenders.push(`${p}:${i + 1}  ${line.trim().slice(0, 90)}`);
            });
        }
      }
    };
    walk(join(process.cwd(), 'src'));
    expect(offenders).toEqual([]);
  });

  it('pairs each affirmative state with a negative one', () => {
    // A pass style with no matching fail style (or vice versa) means one of the
    // two indicators silently renders in the neutral default.
    expect(linesFor(['data-state="pass"']).length).toBe(linesFor(['data-state="fail"']).length);
    expect(linesFor(['data-correct]']).length).toBe(linesFor(['data-incorrect]']).length);
    expect(linesFor(['data-state="correct"']).length).toBe(linesFor(['data-state="incorrect"']).length);
  });
});
