import { describe, it, expect } from 'vitest';
import { metaDescription, META_DESCRIPTION_MAX } from '../src/utils/metaDescription';

describe('metaDescription', () => {
  it('leaves an already-short description untouched', () => {
    const s = 'A short, perfectly good description.';
    expect(metaDescription(s)).toBe(s);
  });

  it('never exceeds the limit', () => {
    const long = 'word '.repeat(200);
    expect(metaDescription(long).length).toBeLessThanOrEqual(META_DESCRIPTION_MAX);
  });

  it('never cuts mid-word', () => {
    const long = 'antidisestablishmentarianism '.repeat(20);
    const out = metaDescription(long);
    // every emitted token except a trailing ellipsis must be a whole word
    for (const w of out.replace(/…$/, '').trim().split(' ')) {
      expect(w).toBe('antidisestablishmentarianism');
    }
  });

  it('prefers a sentence boundary when one falls late enough', () => {
    const s = 'A'.repeat(150) + '. ' + 'B'.repeat(200);
    const out = metaDescription(s);
    expect(out.endsWith('.')).toBe(true);
    expect(out).not.toContain('B');
    expect(out).not.toContain('…');
  });

  it('ignores an early sentence end that would gut the description', () => {
    // The period at index ~4 is far below 60% of the budget; cutting there would
    // leave "e.g." as the whole description.
    const s = 'e.g. ' + 'meaningful content here '.repeat(30);
    const out = metaDescription(s);
    expect(out.length).toBeGreaterThan(META_DESCRIPTION_MAX * 0.6);
  });

  it('collapses whitespace so multi-line source prose emits one clean line', () => {
    expect(metaDescription('a\n\n  b\tc')).toBe('a b c');
  });

  it('handles null/undefined without throwing', () => {
    expect(metaDescription(undefined as unknown as string)).toBe('');
    expect(metaDescription(null as unknown as string)).toBe('');
  });

  it('trims dangling punctuation before the ellipsis', () => {
    const s = 'alpha beta, ' + 'x'.repeat(400);
    const out = metaDescription(s, 20);
    expect(out).not.toMatch(/[,;:]…$/);
  });
});
