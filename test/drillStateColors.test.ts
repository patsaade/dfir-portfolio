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
import { readFileSync } from 'node:fs';
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

  it('pairs each affirmative state with a negative one', () => {
    // A pass style with no matching fail style (or vice versa) means one of the
    // two indicators silently renders in the neutral default.
    expect(linesFor(['data-state="pass"']).length).toBe(linesFor(['data-state="fail"']).length);
    expect(linesFor(['data-correct]']).length).toBe(linesFor(['data-incorrect]']).length);
    expect(linesFor(['data-state="correct"']).length).toBe(linesFor(['data-state="incorrect"']).length);
  });
});
