// Line-based text diff for the Text Diff Tool — pure, dependency-free,
// browser-side (nothing pasted here is ever transmitted anywhere). Splits
// both inputs on '\n' and computes a minimal edit script (unchanged/added/
// removed lines) with a classic dynamic-programming LCS (longest common
// subsequence), the same core approach `diff`/`git diff` are built on: an
// (n+1)x(m+1) table of LCS lengths, then a backward walk from the table's
// corner that reconstructs the actual line-by-line operations. A changed
// line still renders as one removed + one added line (not merged into a
// single "modified" row) — but adjacent removed/added runs get a second,
// word-level LCS pass (attachWordDiffs/diffTokens below) so a one-word edit
// highlights just that word instead of tinting the whole line.
//
// Bounded to MAX_DIFF_LINES per side: the DP table is O(n*m) in both time
// and memory, so an unbounded paste (a full disk image's worth of log
// lines, say) could otherwise lock up the tab. Every tool on this site is
// local/client-side and already expects reasonably-sized pastes, so a
// truncation cap here matches that existing convention rather than
// introducing a new one.

type DiffLineType = 'same' | 'added' | 'removed';

/** One word-level run within a modified line — see {@link attachWordDiffs}. */
interface WordSegment {
  type: DiffLineType;
  text: string;
}

interface DiffLine {
  /** Whether this line is unchanged, only in the changed text, or only in the original text. */
  type: DiffLineType;
  /** The line's text content (never includes the trailing newline). */
  text: string;
  /** 1-based line number in the original ("before") text — null for an added line. */
  originalLine: number | null;
  /** 1-based line number in the changed ("after") text — null for a removed line. */
  changedLine: number | null;
  /**
   * Word-level breakdown of *this line's own* text, present only when this
   * line was paired with its counterpart in an adjacent removed/added run
   * (see {@link attachWordDiffs}) — lets the UI highlight just the words
   * that changed within an otherwise-unchanged line, instead of tinting the
   * whole line. `type: 'same'` segments are shared with the paired line;
   * `'removed'` segments only ever appear on a removed line's own
   * `wordDiff`, `'added'` only on an added line's. Absent for a `'same'`
   * line or an unpaired added/removed line (a pure insertion/deletion has
   * no counterpart to diff against).
   */
  wordDiff?: WordSegment[];
}

interface DiffStats {
  added: number;
  removed: number;
  unchanged: number;
}

export interface DiffResult {
  /** The full edit script, in original document order — a unified view can
   *  render this directly; a side-by-side view groups by originalLine/changedLine. */
  lines: DiffLine[];
  stats: DiffStats;
  /** True if either input exceeded MAX_DIFF_LINES and was truncated before diffing. */
  truncated: boolean;
}

/** Per-side line cap. The DP table below is O(n*m) cells, so 2000x2000 is
 *  already 4 million cells (well within a browser tab's budget); this stays
 *  well clear of the pathological blowup a much larger paste would cause. */
export const MAX_DIFF_LINES = 2000;

// Splitting '' would otherwise yield [''] (one phantom empty line) per
// String#split semantics — treated here as zero lines instead, matching how
// a genuinely empty file/paste has no lines to diff. A *non*-empty string
// still splits normally, so a trailing newline ("foo\n") correctly yields a
// trailing empty line (["foo", ""]) — that trailing blank line is real
// content the diff should be able to show as added/removed.
function splitLines(text: string): string[] {
  if (text === '') return [];
  return text.split('\n');
}

// Builds the (n+1)x(m+1) LCS-length table as a flat, row-major Uint32Array
// (cell [i][j] at index i*(m+1)+j) — far more memory-efficient than an
// array of arrays for a table that can run into the millions of cells.
function buildLcsTable(a: string[], b: string[]): Uint32Array {
  const n = a.length;
  const m = b.length;
  const width = m + 1;
  const table = new Uint32Array((n + 1) * width);
  for (let i = 1; i <= n; i++) {
    const rowOffset = i * width;
    const prevRowOffset = (i - 1) * width;
    for (let j = 1; j <= m; j++) {
      if (a[i - 1] === b[j - 1]) {
        table[rowOffset + j] = table[prevRowOffset + (j - 1)] + 1;
      } else {
        const up = table[prevRowOffset + j];
        const left = table[rowOffset + (j - 1)];
        table[rowOffset + j] = up >= left ? up : left;
      }
    }
  }
  return table;
}

// Walks backward from the table's bottom-right corner to reconstruct the
// edit script, then reverses it into forward (top-to-bottom) order. Tie
// handling on a non-match (equal LCS length going up vs. left) intentionally
// favors an "added" step — this is what makes a full-replace region render
// as "every removed original line, in order" followed by "every added
// changed line, in order" (matching the conventional diff/git reading of a
// replaced block), rather than the two interleaved in the opposite order.
function backtrack(a: string[], b: string[], table: Uint32Array, width: number): DiffLine[] {
  const out: DiffLine[] = [];
  let i = a.length;
  let j = b.length;

  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && a[i - 1] === b[j - 1]) {
      out.push({ type: 'same', text: a[i - 1], originalLine: i, changedLine: j });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || table[i * width + (j - 1)] >= table[(i - 1) * width + j])) {
      out.push({ type: 'added', text: b[j - 1], originalLine: null, changedLine: j });
      j--;
    } else {
      out.push({ type: 'removed', text: a[i - 1], originalLine: i, changedLine: null });
      i--;
    }
  }

  out.reverse();
  return out;
}

// Splits on whitespace boundaries while keeping every character: each token
// is either a run of non-whitespace or a run of whitespace, so rejoining a
// token array reproduces the source text exactly. Word-granularity (not
// character-granularity) matches how `git diff --word-diff` and similar
// tools highlight a modified line — a one-word edit reads as "this word
// changed," not a scatter of single-character fragments.
function tokenize(text: string): string[] {
  return text.match(/\S+|\s+/g) ?? [];
}

// Same LCS-table technique as buildLcsTable/backtrack above, applied to word
// tokens instead of lines — reused as-is since buildLcsTable is already
// generic over string[]. No line-number bookkeeping (word diffs don't need
// it), and adjacent same-type tokens are merged into one segment so e.g. a
// 3-word insertion renders as one highlighted run instead of three.
function diffTokens(a: string, b: string): WordSegment[] {
  const aTokens = tokenize(a);
  const bTokens = tokenize(b);
  const table = buildLcsTable(aTokens, bTokens);
  const width = bTokens.length + 1;

  const out: WordSegment[] = [];
  let i = aTokens.length;
  let j = bTokens.length;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && aTokens[i - 1] === bTokens[j - 1]) {
      out.push({ type: 'same', text: aTokens[i - 1] });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || table[i * width + (j - 1)] >= table[(i - 1) * width + j])) {
      out.push({ type: 'added', text: bTokens[j - 1] });
      j--;
    } else {
      out.push({ type: 'removed', text: aTokens[i - 1] });
      i--;
    }
  }
  out.reverse();

  const merged: WordSegment[] = [];
  for (const seg of out) {
    const last = merged[merged.length - 1];
    if (last && last.type === seg.type) last.text += seg.text;
    else merged.push({ ...seg });
  }
  return merged;
}

// Finds adjacent removed-then-added runs (the shape backtrack() produces for
// a modified block — see its own comment on the removed-before-added tie
// break) and pairs them up index-aligned from the top of each run, then
// attaches each pair's word-level diff to both lines. A run-length mismatch
// (e.g. one line replaced by two) leaves the extra, unpaired lines with no
// wordDiff — they render as plain whole-line removed/added, same as before
// this feature existed. Two genuinely unrelated adjacent lines degrade
// gracefully too: with no shared tokens, the word diff is just "all
// removed"/"all added," visually identical to the un-highlighted line.
function attachWordDiffs(lines: DiffLine[]): void {
  let k = 0;
  while (k < lines.length) {
    if (lines[k].type !== 'removed') {
      k++;
      continue;
    }
    let removedEnd = k;
    while (removedEnd < lines.length && lines[removedEnd].type === 'removed') removedEnd++;
    let addedEnd = removedEnd;
    while (addedEnd < lines.length && lines[addedEnd].type === 'added') addedEnd++;

    const pairCount = Math.min(removedEnd - k, addedEnd - removedEnd);
    for (let p = 0; p < pairCount; p++) {
      const removedLine = lines[k + p];
      const addedLine = lines[removedEnd + p];
      const tokens = diffTokens(removedLine.text, addedLine.text);
      removedLine.wordDiff = tokens.filter((seg) => seg.type !== 'added');
      addedLine.wordDiff = tokens.filter((seg) => seg.type !== 'removed');
    }
    k = addedEnd;
  }
}

/**
 * Computes a line-based diff between two blocks of text — e.g. two exported
 * log files, or two versions of a config or script. Both inputs are split on
 * '\n'; a minimal edit script is then computed via LCS dynamic programming,
 * the same technique behind `diff`/`git diff`.
 *
 * Each side is capped at {@link MAX_DIFF_LINES} lines before diffing (see
 * `truncated` on the result) to keep the O(n*m) table bounded.
 */
export function diffLines(originalText: string, changedText: string): DiffResult {
  const originalAll = splitLines(originalText);
  const changedAll = splitLines(changedText);

  const truncated = originalAll.length > MAX_DIFF_LINES || changedAll.length > MAX_DIFF_LINES;
  const a = truncated ? originalAll.slice(0, MAX_DIFF_LINES) : originalAll;
  const b = truncated ? changedAll.slice(0, MAX_DIFF_LINES) : changedAll;

  const table = buildLcsTable(a, b);
  const lines = backtrack(a, b, table, b.length + 1);
  attachWordDiffs(lines);

  const stats: DiffStats = { added: 0, removed: 0, unchanged: 0 };
  for (const line of lines) {
    if (line.type === 'added') stats.added++;
    else if (line.type === 'removed') stats.removed++;
    else stats.unchanged++;
  }

  return { lines, stats, truncated };
}
