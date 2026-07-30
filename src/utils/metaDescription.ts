// Trim a meta description to a sensible SERP length without cutting mid-word.
//
// WHY. Most of this site's descriptions are hand-written and already short — 1,519
// of 1,728 pages sit at or under 160 characters. The exceptions are the pages
// whose description is GENERATED from a dataset's own prose: the D3FEND detail
// pages pass MITRE's raw `definition` straight through, which runs to 606
// characters on D3-AMED and 602 on D3-UBA. Search engines truncate the snippet
// well before that, so the tail is never read — and worse, an arbitrary cut lands
// mid-sentence.
//
// Deliberately NOT applied site-wide. The 161-200 character band is perfectly
// normal (Google renders ~155-160 on desktop and frequently rewrites the snippet
// from page content anyway), so blanket-truncating 206 pages would churn a lot of
// good copy to fix eight outliers. This exists for the generated pages only.
//
// Trimming prefers, in order: a sentence end, then a word boundary. It never
// emits a partial word, and it returns short input untouched rather than
// pointlessly re-wrapping it.

/** Longest description worth emitting. Past this a crawler shows an ellipsis. */
export const META_DESCRIPTION_MAX = 200;

/**
 * Trim `text` to at most `max` characters at the nearest sentence boundary,
 * falling back to a word boundary with an ellipsis.
 *
 * Returns the input unchanged when it already fits, so callers can apply it
 * unconditionally without worrying about mangling already-good copy.
 */
export function metaDescription(text: string, max: number = META_DESCRIPTION_MAX): string {
  const s = String(text ?? '').replace(/\s+/g, ' ').trim();
  if (s.length <= max) return s;

  // Prefer ending on a real sentence. Only accept one that keeps at least 60% of
  // the budget — otherwise an early "e.g." or an abbreviation's period would
  // truncate the description to a uselessly short fragment.
  const window = s.slice(0, max + 1);
  const sentenceEnd = Math.max(window.lastIndexOf('. '), window.lastIndexOf('! '), window.lastIndexOf('? '));
  if (sentenceEnd >= max * 0.6) return s.slice(0, sentenceEnd + 1).trim();

  // Otherwise cut at the last whitespace before the limit and mark the elision.
  // The ellipsis has to fit INSIDE `max`, not push past it.
  const hard = s.slice(0, max - 1);
  const lastSpace = hard.lastIndexOf(' ');
  return (lastSpace > 0 ? hard.slice(0, lastSpace) : hard).replace(/[,;:.\s]+$/, '') + '…';
}
