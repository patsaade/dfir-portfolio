// Question generator for the Windows Event ID Drill (/drills/event-ids/).
// Pure, deterministic function of `index` — no randomness — so
// DrillEngine.astro's server-rendered `firstQuestion` prop and the page's
// own client-side `getEventIdsDrillQuestion(0)` call are always
// byte-identical (see DrillEngine.astro's header comment on why
// nextQuestion(0) has to be deterministic; this module goes further and
// keeps every index deterministic, not just the first, so there's no
// post-hydration flash on ANY question).
//
// Every prompt, correct answer, and explanation traces to REAL data —
// src/data/eventIds.ts's own EVENT_IDS (the same dataset behind the live
// /event-ids/ reference and its detail pages) for the "identify this event"
// questions, and src/data/references.ts's ATTACK_TECHNIQUE_BY_ID (the same
// map /attack-map/ and /event-ids/[slug].astro's own "MITRE ATT&CK"
// cross-links use) for the bonus "which technique does this map to"
// questions. Nothing here is hand-invented.
//
// PICKS below is a hand-curated (not random) sequence of ten (slug, mode)
// entries — chosen for a mix of well-known Security events, compact Sysmon
// events, and (for 'attack' mode) the specific entries whose
// EventIdEntry.attackTechniques[0] id actually resolves in
// ATTACK_TECHNIQUE_BY_ID. That resolution check matters: quite a few
// eventIds.ts entries cite a sub-technique id (e.g. "T1562.002") that isn't
// present in this site's own generated ATT&CK technique set yet, so the
// bonus question only ever draws from entries confirmed (by hand, this
// session) to resolve — see this file's own `mustResolveTechnique` guard,
// which throws at build time rather than silently rendering "undefined" if
// that ever stops being true.
import { eventIdBySlug, type EventIdEntry } from '../eventIds';
import { ATTACK_TECHNIQUE_BY_ID } from '../references';
import type { DrillQuestion } from '../../scripts/drillEngine';

type Mode = 'identify' | 'attack';

interface Pick {
  slug: string;
  mode: Mode;
}

// Every slug below was confirmed to exist in EVENT_IDS / ATTACK_TECHNIQUE_BY_ID
// before being added — see this repo's CLAUDE.md "Content accuracy" rule
// (never fabricate a fact this site shows as real). 7 'identify' + 3 'attack'
// bonus questions.
const PICKS: Pick[] = [
  { slug: 'security-4624', mode: 'identify' },
  { slug: 'sysmon-11', mode: 'identify' },
  { slug: 'security-4720', mode: 'attack' },
  { slug: 'security-1102', mode: 'identify' },
  { slug: 'sysmon-22', mode: 'identify' },
  { slug: 'sysmon-10', mode: 'attack' },
  { slug: 'security-4625', mode: 'identify' },
  { slug: 'security-4672', mode: 'identify' },
  { slug: 'security-7045', mode: 'attack' },
  { slug: 'sysmon-3', mode: 'identify' },
];

export const EVENT_IDS_DRILL_TOTAL = PICKS.length;

function mustGetEntry(slug: string): EventIdEntry {
  const e = eventIdBySlug(slug);
  if (!e) throw new Error(`Event ID drill: unknown slug "${slug}"`);
  return e;
}

function mustResolveTechnique(id: string): { name: string } {
  const t = ATTACK_TECHNIQUE_BY_ID.get(id);
  if (!t) throw new Error(`Event ID drill: technique "${id}" not found in ATTACK_TECHNIQUE_BY_ID`);
  return t;
}

// Extracts a Txxxx or Txxxx.xxx id from free text, case-insensitively — lets
// the learner type "T1098", "t1098", or "technique T1098" and still grade
// correctly, without accepting a bare number or the wrong id.
function extractTechniqueId(s: string): string | null {
  const m = String(s)
    .toUpperCase()
    .match(/T\d{4}(?:\.\d{3})?/);
  return m ? m[0] : null;
}

function buildIdentifyQuestion(entry: EventIdEntry): DrillQuestion {
  const sourceLabel = entry.source === 'sysmon' ? 'Sysmon' : 'Windows';
  const log = (entry.sampleLog ?? entry.example ?? '').trim();
  return {
    prompt: `Identify the ${sourceLabel} Event ID (channel: ${entry.channel}) that generated this raw log entry:\n\n${log}`,
    answerType: 'text',
    correctAnswer: entry.id,
    // Lenient on purpose: strips anything but digits before comparing, so
    // "Event ID 4624", "4624", or "id: 4624" all grade the same — the
    // number is what's actually being tested, not exact phrasing.
    grade(userAnswer: string): boolean {
      return userAnswer.replace(/[^0-9]/g, '') === entry.id;
    },
    explanation: `Event ID ${entry.id} — "${entry.name}." ${entry.what} ${entry.why}`,
    referenceHref: `/event-ids/${entry.slug}/`,
    referenceLabel: `Full reference: Event ID ${entry.id}`,
  };
}

function buildAttackQuestion(entry: EventIdEntry): DrillQuestion {
  const correctId = entry.attackTechniques[0];
  if (!correctId) throw new Error(`Event ID drill: "${entry.slug}" has no attackTechniques to quiz on`);
  const correct = mustResolveTechnique(correctId);
  return {
    prompt: `Which MITRE ATT&CK technique ID does Event ID ${entry.id} ("${entry.name}", channel: ${entry.channel}) most commonly map to? (e.g. "T1078")`,
    answerType: 'text',
    correctAnswer: correctId,
    grade: (ans) => extractTechniqueId(ans) === correctId.toUpperCase(),
    explanation: `${entry.why} This maps to ${correct.name} (${correctId}) — see the full technique writeup on the ATT&CK Coverage Map for detection guidance and mitigations.`,
    referenceHref: `/event-ids/${entry.slug}/`,
    referenceLabel: `Full reference: Event ID ${entry.id}`,
  };
}

export function getEventIdsDrillQuestion(index: number): DrillQuestion {
  const pick = PICKS[((index % PICKS.length) + PICKS.length) % PICKS.length];
  const entry = mustGetEntry(pick.slug);
  return pick.mode === 'attack' ? buildAttackQuestion(entry) : buildIdentifyQuestion(entry);
}
