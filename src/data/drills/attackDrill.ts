// Pure, deterministic question generator for the MITRE ATT&CK drill
// (/drills/attack/, src/pages/drills/attack/index.astro). Every prompt,
// answer, and explanation is built from ATTACK_TECHNIQUES — the same
// generated-from-MITRE's-STIX-bundle dataset the /attack-map/ pages render
// (see src/data/references.ts) — never a hand-invented technique name, id,
// tactic, or procedure string. Two question shapes, alternating by index:
//   even  -> a real MITRE procedure example, type the technique ID it describes
//   odd   -> a technique's name + id, type the tactic it maps to
// Both are free-text recall (not multiple choice) — grading is against the
// real dataset value itself, never a hand-picked distractor set.
//
// Deterministic by design (no Math.random anywhere): DrillEngine.astro's
// no-JS shell calls getAttackDrillQuestion(0) once at build time, and
// initDrill()'s client script calls it again once on mount (see that
// component's own header comment on why question 0 must match exactly to
// avoid a post-hydration flash). Every question is a pure function of its
// index into a stably-sorted pool, so both calls agree without any shared
// state or seed.
import { ATTACK_TECHNIQUES, resolveAttackLink, type AttackTechnique } from '../references';
import type { DrillQuestion } from '../../scripts/drillEngine';

/** Total questions this module's page wires into DrillEngine/initDrill. */
export const ATTACK_DRILL_TOTAL = 10;

// Only techniques with a substantive MITRE description AND at least one
// real, reasonably-sized procedure example make a fair quiz prompt — a thin
// one-line description or no examples[] entry would produce an unanswerable
// or unhelpfully vague question. Sorted by id for a stable order (the
// generated dataset's own array order isn't a documented contract, so this
// file doesn't rely on it).
const POOL: AttackTechnique[] = ATTACK_TECHNIQUES.filter(
  (t) => (t.description?.length ?? 0) >= 120 && Array.isArray(t.examples) && t.examples.some((e) => e.length >= 40 && e.length <= 260)
)
  .slice()
  .sort((a, b) => a.id.localeCompare(b.id));

/** Prefer a mid-length example (readable inline in a quiz prompt). */
function exampleFor(t: AttackTechnique): string {
  const sized = (t.examples ?? []).filter((e) => e.length >= 40 && e.length <= 260);
  return sized[0] ?? (t.examples ?? [])[0] ?? t.summary ?? t.description ?? '';
}

function referenceFor(t: AttackTechnique): { referenceHref: string; referenceLabel: string } {
  const link = resolveAttackLink(t.id);
  return { referenceHref: link.href, referenceLabel: `View ${t.id} on the ATT&CK map` };
}

// Extracts a Txxxx or Txxxx.xxx id from free text, case-insensitively — lets
// the learner type "T1059", "t1059.001", or "technique T1059" and still
// grade correctly, without accepting a bare number or the wrong id.
function extractTechniqueId(s: string): string | null {
  const m = String(s)
    .toUpperCase()
    .match(/T\d{4}(?:\.\d{3})?/);
  return m ? m[0] : null;
}

function normalizeTactic(s: string): string {
  const n = s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
  return n === 'c2' ? 'command and control' : n;
}

/** "Type the technique ID from a real procedure example" question. */
function idQuestion(t: AttackTechnique): DrillQuestion {
  const example = exampleFor(t);
  return {
    prompt: `Which MITRE ATT&CK technique ID does this real procedure example describe? "${example}"\n\n(Answer with the technique ID, e.g. "T1059" or "T1059.001".)`,
    answerType: 'text',
    correctAnswer: t.id,
    grade: (ans) => extractTechniqueId(ans) === t.id.toUpperCase(),
    explanation: `${t.name} (${t.id}) — ${t.description ?? t.summary ?? ''}`,
    ...referenceFor(t),
  };
}

/** "Type the tactic this technique maps to" question. */
function tacticQuestion(t: AttackTechnique): DrillQuestion {
  const correctTactic = t.tactics[0];
  const explanation =
    t.tactics.length > 1
      ? `${t.name} (${t.id}) maps to ${t.tactics.join(', ')} in the Enterprise matrix — ${correctTactic} is the one this question checked.`
      : `${t.name} (${t.id}) maps to the ${correctTactic} tactic in the Enterprise matrix.`;
  return {
    prompt: `${t.name} (${t.id}) maps to which MITRE ATT&CK tactic? (type the tactic name, e.g. "Credential Access")`,
    answerType: 'text',
    correctAnswer: correctTactic,
    grade: (ans) => normalizeTactic(ans) === normalizeTactic(correctTactic),
    explanation,
    ...referenceFor(t),
  };
}

/**
 * The module's `nextQuestion` — evenly strides through the sorted pool (not
 * just its first TOTAL entries) so the drill samples techniques spread
 * across the whole Enterprise matrix, alternating the two question shapes
 * by parity of `index`.
 */
export function getAttackDrillQuestion(index: number): DrillQuestion {
  const stride = Math.max(1, Math.floor(POOL.length / ATTACK_DRILL_TOTAL));
  const poolIndex = (index * stride) % POOL.length;
  const t = POOL[poolIndex];
  return index % 2 === 0 ? idQuestion(t) : tacticQuestion(t);
}
