// Validates every CSS selector string literal in the source.
//
// THE BUG THIS EXISTS FOR. A sweep that added an attribute to markup —
// `role="radiogroup"` -> `role="radiogroup" data-no-radiokeys"` — was applied as a
// blind string replacement, so it also rewrote a selector INSIDE a client script:
//
//     menu.querySelectorAll('[role="radiogroup" data-no-radiokeys]')
//
// That is not a valid CSS selector. querySelectorAll THROWS on it, the exception
// killed the whole ThemePicker IIFE, and the theme button silently stopped
// working — in production. Nothing caught it: it is valid TypeScript, valid
// Astro, the build succeeded, `astro check` reported zero errors, and the axe
// gate passed because the markup was fine. Only clicking the button revealed it.
//
// This is the third time a blind find/replace has broken this repo in a way the
// type checker cannot see (see CLAUDE.md's Debugging section: the `</label>` ->
// `</span>` sweep, and the URL-shaped sweep that corrupted file paths). The
// lesson that keeps not sticking is that a string replacement hits comments and
// string literals, not just the syntax you pictured — so this test checks the
// literals directly rather than trusting the sweep.
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { JSDOM } from 'jsdom';

const { document } = new JSDOM('').window;

/** DOM methods whose first argument must be a valid CSS selector. */
const SELECTOR_CALL =
  /\.(?:querySelectorAll|querySelector|closest|matches)\(\s*(['"])((?:\\.|(?!\1)[^\\])*)\1\s*\)/g;

function sourceFiles(dir: string, acc: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) sourceFiles(p, acc);
    else if (/\.(astro|ts)$/.test(e.name)) acc.push(p);
  }
  return acc;
}

describe('CSS selector literals', () => {
  it('is actually able to detect an invalid selector', () => {
    // Guard against the check silently becoming a no-op.
    expect(() => document.querySelector('[role="radiogroup" data-no-radiokeys]')).toThrow();
    expect(() => document.querySelector('[role="radiogroup"]')).not.toThrow();
  });

  it('every selector passed to querySelector/closest/matches is valid CSS', () => {
    const bad: string[] = [];
    let checked = 0;
    for (const file of sourceFiles(join(process.cwd(), 'src'))) {
      const src = readFileSync(file, 'utf8');
      src.split('\n').forEach((line, i) => {
        for (const m of line.matchAll(SELECTOR_CALL)) {
          const selector = m[2];
          // Skip anything built at runtime — a literal containing a template
          // placeholder isn't the final selector and can't be validated here.
          if (selector.includes('${')) continue;
          checked++;
          try {
            document.querySelector(selector);
          } catch {
            bad.push(`${file.replace(process.cwd() + '/', '')}:${i + 1}  ${selector}`);
          }
        }
      });
    }
    // If this ever drops to ~0 the regex has stopped matching and the test is
    // vacuous, which would be worse than failing.
    expect(checked).toBeGreaterThan(50);
    expect(bad).toEqual([]);
  });
});
