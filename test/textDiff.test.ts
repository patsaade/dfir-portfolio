import { describe, it, expect } from 'vitest';
import { diffLines, MAX_DIFF_LINES } from '../src/utils/textDiff';

/** Pull just the {type, text} pair out of a diff result's lines for
 *  assertions that don't care about the original/changed line numbers. */
function shape(result: ReturnType<typeof diffLines>) {
  return result.lines.map((l) => ({ type: l.type, text: l.text }));
}

describe('diffLines — identical inputs', () => {
  it('marks every line as unchanged for byte-identical multi-line input', () => {
    const text = 'line one\nline two\nline three';
    const result = diffLines(text, text);
    expect(shape(result)).toEqual([
      { type: 'same', text: 'line one' },
      { type: 'same', text: 'line two' },
      { type: 'same', text: 'line three' },
    ]);
    expect(result.stats).toEqual({ added: 0, removed: 0, unchanged: 3 });
  });

  it('preserves both original and changed line numbers for unchanged lines', () => {
    const result = diffLines('a\nb\nc', 'a\nb\nc');
    for (const [idx, line] of result.lines.entries()) {
      expect(line.originalLine).toBe(idx + 1);
      expect(line.changedLine).toBe(idx + 1);
    }
  });
});

describe('diffLines — completely different inputs', () => {
  it('marks every original line removed and every changed line added, in order', () => {
    const result = diffLines('foo\nbar', 'baz\nqux');
    expect(shape(result)).toEqual([
      { type: 'removed', text: 'foo' },
      { type: 'removed', text: 'bar' },
      { type: 'added', text: 'baz' },
      { type: 'added', text: 'qux' },
    ]);
    expect(result.stats).toEqual({ added: 2, removed: 2, unchanged: 0 });
  });

  it('assigns null changedLine to removed lines and null originalLine to added lines', () => {
    const result = diffLines('foo\nbar', 'baz\nqux');
    for (const line of result.lines) {
      if (line.type === 'removed') {
        expect(line.changedLine).toBeNull();
        expect(line.originalLine).not.toBeNull();
      } else if (line.type === 'added') {
        expect(line.originalLine).toBeNull();
        expect(line.changedLine).not.toBeNull();
      }
    }
  });
});

describe('diffLines — realistic interleaved case', () => {
  it('correctly identifies a mix of unchanged, added, and removed lines', () => {
    // A small log-export-style before/after: one line dropped, one line
    // added, one line changed (renders as remove+add), the rest unchanged.
    const original = ['2026-01-01 boot', '2026-01-01 login user=admin', '2026-01-01 logout user=admin', '2026-01-01 shutdown'].join('\n');
    const changed = ['2026-01-01 boot', '2026-01-01 login user=admin', '2026-01-01 login user=root', '2026-01-01 shutdown', '2026-01-01 reboot'].join(
      '\n',
    );
    const result = diffLines(original, changed);
    expect(shape(result)).toEqual([
      { type: 'same', text: '2026-01-01 boot' },
      { type: 'same', text: '2026-01-01 login user=admin' },
      { type: 'removed', text: '2026-01-01 logout user=admin' },
      { type: 'added', text: '2026-01-01 login user=root' },
      { type: 'same', text: '2026-01-01 shutdown' },
      { type: 'added', text: '2026-01-01 reboot' },
    ]);
    expect(result.stats).toEqual({ added: 2, removed: 1, unchanged: 3 });
  });

  it('finds a single line inserted in the middle of otherwise-identical text', () => {
    const result = diffLines('a\nb\nd', 'a\nb\nc\nd');
    expect(shape(result)).toEqual([
      { type: 'same', text: 'a' },
      { type: 'same', text: 'b' },
      { type: 'added', text: 'c' },
      { type: 'same', text: 'd' },
    ]);
  });

  it('finds a single line deleted from the middle of otherwise-identical text', () => {
    const result = diffLines('a\nb\nc\nd', 'a\nb\nd');
    expect(shape(result)).toEqual([
      { type: 'same', text: 'a' },
      { type: 'same', text: 'b' },
      { type: 'removed', text: 'c' },
      { type: 'same', text: 'd' },
    ]);
  });
});

describe('diffLines — empty-input edge cases', () => {
  it('treats two empty strings as zero lines with no differences', () => {
    const result = diffLines('', '');
    expect(result.lines).toEqual([]);
    expect(result.stats).toEqual({ added: 0, removed: 0, unchanged: 0 });
  });

  it('treats an empty original against non-empty changed text as pure additions', () => {
    const result = diffLines('', 'first line\nsecond line');
    expect(shape(result)).toEqual([
      { type: 'added', text: 'first line' },
      { type: 'added', text: 'second line' },
    ]);
    expect(result.stats).toEqual({ added: 2, removed: 0, unchanged: 0 });
  });

  it('treats a non-empty original against empty changed text as pure removals', () => {
    const result = diffLines('first line\nsecond line', '');
    expect(shape(result)).toEqual([
      { type: 'removed', text: 'first line' },
      { type: 'removed', text: 'second line' },
    ]);
    expect(result.stats).toEqual({ added: 0, removed: 2, unchanged: 0 });
  });
});

describe('diffLines — single-line inputs', () => {
  it('marks a single identical line as unchanged', () => {
    const result = diffLines('the only line', 'the only line');
    expect(shape(result)).toEqual([{ type: 'same', text: 'the only line' }]);
  });

  it('marks a single differing line as a remove+add pair', () => {
    const result = diffLines('old value', 'new value');
    expect(shape(result)).toEqual([
      { type: 'removed', text: 'old value' },
      { type: 'added', text: 'new value' },
    ]);
  });
});

describe('diffLines — trailing/leading blank lines', () => {
  it('treats a trailing newline as a real trailing empty line', () => {
    // 'foo\n'.split('\n') -> ['foo', ''] — the trailing blank line is
    // genuine content (present in one side, absent in the other) and
    // should show up as an addition, not be silently swallowed.
    const result = diffLines('foo', 'foo\n');
    expect(shape(result)).toEqual([
      { type: 'same', text: 'foo' },
      { type: 'added', text: '' },
    ]);
  });

  it('treats matching leading blank lines as unchanged', () => {
    const result = diffLines('\nfoo\nbar', '\nfoo\nbar');
    expect(shape(result)).toEqual([
      { type: 'same', text: '' },
      { type: 'same', text: 'foo' },
      { type: 'same', text: 'bar' },
    ]);
  });

  it('detects a removed leading blank line', () => {
    const result = diffLines('\nfoo', 'foo');
    expect(shape(result)).toEqual([
      { type: 'removed', text: '' },
      { type: 'same', text: 'foo' },
    ]);
  });

  it('detects an added blank line in the middle', () => {
    const result = diffLines('foo\nbar', 'foo\n\nbar');
    expect(shape(result)).toEqual([
      { type: 'same', text: 'foo' },
      { type: 'added', text: '' },
      { type: 'same', text: 'bar' },
    ]);
  });
});

describe('diffLines — truncation cap', () => {
  it('does not truncate input at exactly MAX_DIFF_LINES lines', () => {
    const text = Array.from({ length: MAX_DIFF_LINES }, (_, i) => `line ${i}`).join('\n');
    const result = diffLines(text, text);
    expect(result.truncated).toBe(false);
    expect(result.lines).toHaveLength(MAX_DIFF_LINES);
  });

  it('truncates input exceeding MAX_DIFF_LINES and flags it', () => {
    const over = MAX_DIFF_LINES + 50;
    const original = Array.from({ length: over }, (_, i) => `orig ${i}`).join('\n');
    const changed = Array.from({ length: over }, (_, i) => `changed ${i}`).join('\n');
    const result = diffLines(original, changed);
    expect(result.truncated).toBe(true);
    // Every line still present after truncation is either an original or
    // changed line drawn from within the first MAX_DIFF_LINES of its side.
    for (const line of result.lines) {
      if (line.originalLine !== null) expect(line.originalLine).toBeLessThanOrEqual(MAX_DIFF_LINES);
      if (line.changedLine !== null) expect(line.changedLine).toBeLessThanOrEqual(MAX_DIFF_LINES);
    }
  });

  it('only truncates the side that actually exceeds the cap', () => {
    const short = 'a\nb\nc';
    const long = Array.from({ length: MAX_DIFF_LINES + 10 }, (_, i) => `x${i}`).join('\n');
    const result = diffLines(short, long);
    expect(result.truncated).toBe(true);
    const addedCount = result.lines.filter((l) => l.type === 'added').length;
    expect(addedCount).toBe(MAX_DIFF_LINES); // long side capped at MAX_DIFF_LINES, short side untouched
  });
});

describe('diffLines — word-level highlighting for modified lines', () => {
  /** Rejoins a wordDiff's segment texts back into a single string. */
  function join(segments: { text: string }[] | undefined): string {
    return (segments ?? []).map((s) => s.text).join('');
  }

  it('attaches a wordDiff to a paired removed/added line that changed by one word', () => {
    const result = diffLines('the quick fox jumps', 'the slow fox jumps');
    const removed = result.lines.find((l) => l.type === 'removed')!;
    const added = result.lines.find((l) => l.type === 'added')!;
    expect(removed.wordDiff).toBeDefined();
    expect(added.wordDiff).toBeDefined();
    // Rejoining each line's own wordDiff must reproduce that line's exact text.
    expect(join(removed.wordDiff)).toBe('the quick fox jumps');
    expect(join(added.wordDiff)).toBe('the slow fox jumps');
    // The removed line's wordDiff never contains an 'added' segment (and
    // vice versa) — each side only ever sees its own text.
    expect(removed.wordDiff!.some((s) => s.type === 'added')).toBe(false);
    expect(added.wordDiff!.some((s) => s.type === 'removed')).toBe(false);
    // The single changed word shows up as removed on one side, added on the other.
    expect(removed.wordDiff).toContainEqual({ type: 'removed', text: 'quick' });
    expect(added.wordDiff).toContainEqual({ type: 'added', text: 'slow' });
    // Unchanged words on both sides are shared 'same' segments.
    expect(removed.wordDiff!.filter((s) => s.type === 'same').length).toBeGreaterThan(0);
  });

  it('does not attach a wordDiff to a pure insertion with no removed counterpart', () => {
    const result = diffLines('a\nb', 'a\nb\nc');
    const added = result.lines.find((l) => l.type === 'added')!;
    expect(added.wordDiff).toBeUndefined();
  });

  it('does not attach a wordDiff to a pure deletion with no added counterpart', () => {
    const result = diffLines('a\nb\nc', 'a\nb');
    const removed = result.lines.find((l) => l.type === 'removed')!;
    expect(removed.wordDiff).toBeUndefined();
  });

  it('does not attach a wordDiff to unchanged lines', () => {
    const result = diffLines('same line', 'same line');
    expect(result.lines[0].wordDiff).toBeUndefined();
  });

  it('only pairs up to the shorter run when removed/added run lengths differ', () => {
    // Two removed lines replaced by three added lines: only the first two
    // get paired (index-aligned from the top of each run); the third added
    // line has no counterpart and stays a plain, unpaired addition.
    const result = diffLines('alpha one\nbeta two', 'alpha uno\nbeta dos\ngamma tres');
    const removedLines = result.lines.filter((l) => l.type === 'removed');
    const addedLines = result.lines.filter((l) => l.type === 'added');
    expect(removedLines.every((l) => l.wordDiff !== undefined)).toBe(true);
    expect(addedLines[0].wordDiff).toBeDefined();
    expect(addedLines[1].wordDiff).toBeDefined();
    expect(addedLines[2].wordDiff).toBeUndefined();
  });

  it('degrades gracefully for two completely unrelated paired lines', () => {
    // A single word each side, so there's no shared whitespace token to
    // coincidentally match as 'same' — every token genuinely differs.
    const result = diffLines('foo', 'bazqux');
    const removed = result.lines.find((l) => l.type === 'removed')!;
    const added = result.lines.find((l) => l.type === 'added')!;
    // Still reconstructs each line's own text exactly, just with no shared words.
    expect(join(removed.wordDiff)).toBe('foo');
    expect(join(added.wordDiff)).toBe('bazqux');
    expect(removed.wordDiff!.every((s) => s.type === 'removed')).toBe(true);
    expect(added.wordDiff!.every((s) => s.type === 'added')).toBe(true);
  });
});

describe('diffLines — order guarantee for a full block replacement', () => {
  it('lists every removed line before every added line, not interleaved', () => {
    // Regression guard for the backtrack tie-break: on a tie in LCS length,
    // the algorithm must prefer the "added" step so removed lines settle
    // before added lines once reversed into forward order.
    const result = diffLines('one\ntwo\nthree', 'four\nfive\nsix');
    const types = result.lines.map((l) => l.type);
    expect(types).toEqual(['removed', 'removed', 'removed', 'added', 'added', 'added']);
  });
});
