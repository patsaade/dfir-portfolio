// Pure, deterministic question generator for the MITRE ATT&CK drill
// (/drills/attack/, src/pages/drills/attack/index.astro). Every prompt,
// answer, and explanation is built from ATTACK_TECHNIQUES — the same
// generated-from-MITRE's-STIX-bundle dataset the /attack-map/ pages render
// (see src/data/references.ts) — never a hand-invented technique name, id,
// tactic, or procedure string. Three question shapes:
//   index 0..9 (even) -> a real MITRE procedure example, type the technique ID it describes
//   index 0..9 (odd)  -> a technique's name + id, type the tactic it maps to
//   index 10+         -> "Order the intrusion": arrange several real techniques
//                        (drawn from tactics they exclusively belong to) into
//                        their real MITRE Enterprise kill-chain tactic order
// The first two are free-text recall (not multiple choice) — grading is
// against the real dataset value itself, never a hand-picked distractor set.
// The third is the 'sequence' answerType (iterate-until-correct — see
// drillEngine.ts).
//
// Deterministic by design (no Math.random anywhere): DrillEngine.astro's
// no-JS shell calls getAttackDrillQuestion(0) once at build time, and
// initDrill()'s client script calls it again once on mount (see that
// component's own header comment on why question 0 must match exactly to
// avoid a post-hydration flash). Every question is a pure function of its
// index into a stably-sorted pool, so both calls agree without any shared
// state or seed.
//
// PAYLOAD NOTE — this module is BUILD-TIME ONLY. It imports the full ATT&CK
// Enterprise technique set; importing it from a client <script> pulled ~490 KB
// raw into /drills/attack/ to ask fourteen questions. The page now materialises
// the entire bank in its frontmatter via `attackDrillQuestionBank()` below and
// ships it as a JSON island, so nothing here reaches the browser. Keep it that
// way: never import this file from a `<script>` block.
import { ATTACK_TECHNIQUES, ATTACK_TECHNIQUE_BY_ID, ATTACK_TACTIC_ORDER, resolveAttackLink, type AttackTechnique } from '../references';
import type { DrillQuestion } from '../../scripts/drillEngine';
import { toSerialisableQuestion, type SerialisableDrillQuestion } from './graders';

/** Question count for the original two (text) shapes — kept as its own
 *  constant so the stride math below (`POOL.length / TEXT_QUESTIONS_TOTAL`)
 *  stays exactly what it was before the 'sequence' shape was added, which in
 *  turn keeps every one of these 10 questions' generated content unchanged. */
const TEXT_QUESTIONS_TOTAL = 10;

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
    // Serialisable twin of the closure above — captures only the id string,
    // never the technique object (see ./graders.ts).
    grader: { kind: 'technique-id', correctId: t.id },
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
    // Serialisable twin of the closure above — captures only the tactic name.
    grader: { kind: 'tactic', correct: correctTactic },
    explanation,
    ...referenceFor(t),
  };
}

function tile(t: AttackTechnique): string {
  return `${t.id} — ${t.name}`;
}

/** One "Order the intrusion" sequence question, authored as a list of real
 *  technique ids already in their correct kill-chain tactic order, plus a
 *  fixed permutation of their indices to render as the shuffled tiles. */
interface SequenceSpec {
  /** Real MITRE technique ids, authored in the order their tactics actually
   *  occur in ATTACK_TACTIC_ORDER (strictly ascending — asserted below). */
  ids: string[];
  /** A permutation of `ids`' indices (0-based) that is NOT the identity —
   *  the shuffled order the tiles render in before the learner reorders them. */
  shuffle: number[];
  prompt: string;
}

/**
 * Builds a real 'sequence' DrillQuestion from a SequenceSpec, looking every
 * id up in ATTACK_TECHNIQUE_BY_ID (the same generated-from-MITRE dataset
 * every other question in this file uses) rather than hand-copying names —
 * so a future ATT&CK regeneration that renames/re-tactics a technique can't
 * silently drift out of sync with what's authored here. Throws at module
 * load (not at quiz time) if a spec ever stops being valid: unknown id,
 * more than one tactic (this drill only uses techniques whose tactics[] has
 * exactly one entry, so "the" tactic position is unambiguous), ids authored
 * out of real kill-chain order, or a shuffle that happens to equal the
 * correct order (which would make the question trivially "already solved").
 */
function buildSequenceQuestion(spec: SequenceSpec): DrillQuestion {
  const techs = spec.ids.map((id) => {
    const t = ATTACK_TECHNIQUE_BY_ID.get(id);
    if (!t) throw new Error(`attackDrill: unknown technique id "${id}" in a sequence spec`);
    if (!t.tactics || t.tactics.length !== 1) {
      throw new Error(`attackDrill: sequence technique ${id} must map to exactly one tactic, got ${JSON.stringify(t.tactics)}`);
    }
    return t;
  });
  let lastPos = -1;
  for (const t of techs) {
    const pos = ATTACK_TACTIC_ORDER.indexOf(t.tactics[0]);
    if (pos <= lastPos) {
      throw new Error(`attackDrill: sequence spec ids are not in strictly ascending tactic order at ${t.id} (${t.tactics[0]})`);
    }
    lastPos = pos;
  }
  const correctOrder = techs.map(tile);
  const sequenceItems = spec.shuffle.map((i) => correctOrder[i]);
  if (sequenceItems.every((s, i) => s === correctOrder[i])) {
    throw new Error('attackDrill: sequence spec shuffle must not equal the correct order');
  }
  const chain = techs.map((t) => `${t.id} ${t.name} (${t.tactics[0]})`).join(' → ');
  return {
    prompt: spec.prompt,
    answerType: 'sequence',
    sequenceItems,
    correctOrder,
    explanation: `Real MITRE ATT&CK kill-chain order: ${chain}.`,
    referenceHref: '/reference/attack-map/',
    referenceLabel: 'Explore the ATT&CK map',
    hint: `Enterprise tactics run in this order: ${ATTACK_TACTIC_ORDER.join(' → ')}.`,
  };
}

// Four "Order the intrusion" specs, each drawing 4-5 techniques from
// DIFFERENT tactics (every id below has exactly one tactics[] entry —
// verified live against ATTACK_TECHNIQUES, not assumed) so there's never an
// ambiguous "which of its tactics counts" question. Real technique ids,
// names, and tactics only — nothing invented — checked against
// src/data/attack-techniques.generated.ts.
const SEQUENCE_SPECS: SequenceSpec[] = [
  {
    // Initial Access -> Execution -> Credential Access -> Discovery -> Exfiltration
    ids: ['T1566', 'T1059', 'T1003', 'T1082', 'T1041'],
    shuffle: [3, 4, 0, 2, 1],
    prompt:
      'These five real MITRE ATT&CK techniques all show up in one intrusion. Click them into the order their tactics actually occur in the Enterprise kill chain (earliest first).',
  },
  {
    // Reconnaissance -> Resource Development -> Persistence -> Command and Control
    ids: ['T1595', 'T1583', 'T1136', 'T1105'],
    shuffle: [3, 2, 0, 1],
    prompt:
      'Order these four real MITRE ATT&CK techniques — from pre-attack recon through an established C2 channel — by where their tactics fall in the Enterprise kill chain (earliest first).',
  },
  {
    // Privilege Escalation -> Lateral Movement -> Collection -> Command and Control -> Impact
    ids: ['T1548', 'T1021', 'T1114', 'T1071', 'T1486'],
    shuffle: [4, 3, 0, 2, 1],
    prompt:
      'Order these five real MITRE ATT&CK techniques — from privilege escalation through to a ransomware-style impact — by where their tactics fall in the Enterprise kill chain (earliest first).',
  },
  {
    // Stealth -> Defense Impairment -> Discovery -> Exfiltration
    ids: ['T1027', 'T1553', 'T1083', 'T1567'],
    shuffle: [3, 0, 2, 1],
    prompt:
      'Order these four real MITRE ATT&CK techniques — spanning stealth through exfiltration — by where their tactics fall in the Enterprise kill chain (earliest first).',
  },
];

const SEQUENCE_QUESTIONS: DrillQuestion[] = SEQUENCE_SPECS.map(buildSequenceQuestion);

/** Total questions this module's page wires into DrillEngine/initDrill:
 *  the original 10 free-text questions plus the new sequence questions. */
export const ATTACK_DRILL_TOTAL = TEXT_QUESTIONS_TOTAL + SEQUENCE_QUESTIONS.length;

/**
 * The module's `nextQuestion` — indices below TEXT_QUESTIONS_TOTAL evenly
 * stride through the sorted text-question pool (not just its first TOTAL
 * entries) so the drill samples techniques spread across the whole
 * Enterprise matrix, alternating the two free-text shapes by parity of
 * `index`; indices at or past TEXT_QUESTIONS_TOTAL cycle through the
 * "Order the intrusion" sequence questions instead.
 */
export function getAttackDrillQuestion(index: number): DrillQuestion {
  if (index >= TEXT_QUESTIONS_TOTAL) {
    return SEQUENCE_QUESTIONS[(index - TEXT_QUESTIONS_TOTAL) % SEQUENCE_QUESTIONS.length];
  }
  const stride = Math.max(1, Math.floor(POOL.length / TEXT_QUESTIONS_TOTAL));
  const poolIndex = (index * stride) % POOL.length;
  const t = POOL[poolIndex];
  return index % 2 === 0 ? idQuestion(t) : tacticQuestion(t);
}

/**
 * The whole bank, materialised into its JSON-safe form. Called ONCE, in
 * /drills/attack/'s frontmatter, and shipped to the client as a JSON island —
 * which is what keeps ATTACK_TECHNIQUES out of the page bundle. Every `grade`
 * closure is replaced by its `grader` descriptor; the 'sequence' questions
 * carry no closure at all (the engine grades them positionally against
 * `correctOrder`) and serialise unchanged.
 */
export function attackDrillQuestionBank(): SerialisableDrillQuestion[] {
  return Array.from({ length: ATTACK_DRILL_TOTAL }, (_, i) => toSerialisableQuestion(getAttackDrillQuestion(i)));
}
