// Enforces src/themes.ts's stated contrast contract.
//
// That contract used to live only in a comment ("Changing any of these values
// means re-deriving the whole matrix, not just eyeballing the one pair you
// touched") with nothing checking it — so the matrix was verified once by hand
// and could silently rot on the next palette tweak. This encodes it: every
// foreground token is checked against every surface it can actually land on, for
// all 10 palettes, using the WCAG relative-luminance formula.
//
// Deliberately NOT a snapshot of hex values — a snapshot would just need
// updating whenever a color changes, teaching the next author to rubber-stamp it.
// This asserts the property the design cares about instead.
import { describe, it, expect } from 'vitest';
import { THEMES, type ThemeColors } from '../src/themes';

/** WCAG 2.x relative luminance for an #rrggbb string. */
function luminance(hex: string): number {
  const m = /^#([0-9a-f]{6})$/i.exec(hex.trim());
  if (!m) throw new Error(`themeContrast: expected #rrggbb, got "${hex}"`);
  const [r, g, b] = [0, 2, 4].map((i) => {
    const c = parseInt(m[1].slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: string, b: string): number {
  const [l1, l2] = [luminance(a), luminance(b)];
  return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
}

/** Every surface a foreground color can be painted on. */
const SURFACES: (keyof ThemeColors)[] = ['bg', 'bgSubtle', 'bgCard', 'codeBg'];

/** >= 4.5:1 as normal text (WCAG 1.4.3 AA). */
const TEXT_TOKENS: (keyof ThemeColors)[] = [
  'text',
  'textMuted',
  'primary',
  'primaryHover',
  'accent',
  'success',
  'danger',
];

describe('theme contrast contract', () => {
  it('sanity-checks the luminance implementation against known WCAG values', () => {
    // Black on white is exactly 21:1; a color against itself is exactly 1:1.
    expect(contrast('#000000', '#ffffff')).toBeCloseTo(21, 5);
    expect(contrast('#ffffff', '#ffffff')).toBeCloseTo(1, 5);
    // #767676 on white is the canonical "just passes 4.5:1" grey.
    expect(contrast('#767676', '#ffffff')).toBeGreaterThanOrEqual(4.5);
    expect(contrast('#777777', '#ffffff')).toBeLessThan(4.54);
  });

  it('clears 4.5:1 for every text token on every surface, in every palette', () => {
    const failures: string[] = [];
    for (const theme of THEMES) {
      for (const token of TEXT_TOKENS) {
        for (const surface of SURFACES) {
          const r = contrast(theme.colors[token] as string, theme.colors[surface] as string);
          if (r < 4.5) {
            failures.push(`${theme.id}: ${token} (${theme.colors[token]}) on ${surface} (${theme.colors[surface]}) = ${r.toFixed(2)}:1`);
          }
        }
      }
    }
    expect(failures).toEqual([]);
  });

  it('clears 3:1 for borderStrong on every surface (WCAG 1.4.11)', () => {
    const failures: string[] = [];
    for (const theme of THEMES) {
      for (const surface of SURFACES) {
        const r = contrast(theme.colors.borderStrong, theme.colors[surface] as string);
        if (r < 3) failures.push(`${theme.id}: borderStrong on ${surface} = ${r.toFixed(2)}:1`);
      }
    }
    expect(failures).toEqual([]);
  });

  it('clears 4.5:1 for on-fill text against its own fill', () => {
    const failures: string[] = [];
    for (const theme of THEMES) {
      const onPrimary = theme.colors.onPrimary ?? '#ffffff';
      for (const [fg, bg, label] of [
        [onPrimary, theme.colors.primary, 'onPrimary/primary'],
        [onPrimary, theme.colors.primaryHover, 'onPrimary/primaryHover'],
        [theme.colors.onDanger, theme.colors.danger, 'onDanger/danger'],
      ] as const) {
        const r = contrast(fg, bg);
        if (r < 4.5) failures.push(`${theme.id}: ${label} = ${r.toFixed(2)}:1`);
      }
    }
    expect(failures).toEqual([]);
  });

  // The regression this token exists to prevent. Pass state used to borrow
  // `accent`, which is amber/terracotta/salmon in 6 of 10 palettes — so pass and
  // fail rendered in the same warm hue family and were hard to tell apart in the
  // drills. Contrast alone cannot catch that: both colors passed AA happily while
  // being nearly the same hue. This asserts the thing that actually matters —
  // that pass and fail are separated by HUE.
  it('keeps success and danger far apart in hue, in every palette', () => {
    const hue = (hex: string) => {
      const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
      const mx = Math.max(r, g, b), mn = Math.min(r, g, b), d = mx - mn;
      if (!d) return 0;
      const h = mx === r ? ((g - b) / d + (g < b ? 6 : 0)) : mx === g ? ((b - r) / d + 2) : ((r - g) / d + 4);
      return h * 60;
    };
    const failures: string[] = [];
    for (const theme of THEMES) {
      const hs = hue(theme.colors.success);
      const hd = hue(theme.colors.danger);
      // shortest angular distance on the hue circle
      const delta = Math.min(Math.abs(hs - hd), 360 - Math.abs(hs - hd));
      if (delta < 60) {
        failures.push(`${theme.id}: success ${theme.colors.success} (${hs.toFixed(0)}deg) vs danger ${theme.colors.danger} (${hd.toFixed(0)}deg) = ${delta.toFixed(0)}deg apart`);
      }
      // success must actually read as green, not merely "not red"
      if (hs < 80 || hs > 175) {
        failures.push(`${theme.id}: success ${theme.colors.success} hue ${hs.toFixed(0)}deg is outside the green band (80-175)`);
      }
    }
    expect(failures).toEqual([]);
  });
});
