// Question generator for the Windows Event ID Drill (/drills/event-ids/).
// Pure, deterministic function of `index` — no randomness — so
// DrillEngine.astro's server-rendered `firstQuestion` prop and the page's
// own client-side `getEventIdsDrillQuestion(0)` call are always
// byte-identical (see DrillEngine.astro's header comment on why
// nextQuestion(0) has to be deterministic; this module goes further and
// keeps every index deterministic, not just the first, so there's no
// post-hydration flash on ANY question).
//
// Two modes, both real recall/comprehension tasks over the same dataset:
//
// - 'extract' — a "triage the log" question. Shows the entry's own real,
//   full `sampleLog` (src/data/eventIds.ts, verbatim) as the answerType's
//   `artifact`, and asks the learner to read it and type the actual value of
//   3-4 independently-labeled fields (DrillExtractField[]) — an
//   iterate-until-correct 'extract' question (see drillEngine.ts), not a
//   single-shot recall of the event ID itself. Every field's `label` traces
//   to that entry's own curated `EventIdEntry.keyFields[].name` (a couple of
//   entries whose own keyFields list is short add one or two extra
//   real-but-uncurated fields straight from the sampleLog to round out to
//   3-4 blanks — see EXTRACT_FIELDS's own comment) and every `correctValue`
//   is copied verbatim from that same entry's `sampleLog` — never invented.
//   Several entries (4624, 4625) have the SAME field name (e.g. "Account
//   Name") appear twice in different blocks of the same raw log with
//   different values — those are disambiguated as "Account Name (Subject)"
//   vs "Account Name (New Logon)" etc., matching the block headers the raw
//   log itself uses.
// - 'attack' — unchanged from before: a free-text recall of the MITRE
//   ATT&CK technique ID a given event commonly maps to, cross-checked
//   against src/data/references.ts's own ATTACK_TECHNIQUE_BY_ID (the same
//   map /attack-map/ and /event-ids/[slug].astro's own cross-links use). A
//   genuinely different recall task from field-extraction, so it stays
//   'text' rather than being folded into 'extract'.
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
// that ever stops being true. Every 'extract' entry is likewise guarded by
// `buildExtractQuestion`'s own checks (a slug missing from EXTRACT_FIELDS, or
// missing its own sampleLog, throws at build time instead of rendering an
// empty triage question).
//
// PAYLOAD NOTE — this module is BUILD-TIME ONLY. It transitively imports the
// whole EVENT_IDS corpus (every raw sampleLog) plus the full ATT&CK technique
// set; importing it from a client <script> pulled ~777 KB raw into
// /drills/event-ids/ to ask ten questions. The page now materialises the
// entire bank in its frontmatter via `eventIdsDrillQuestionBank()` below and
// ships it as a JSON island, so nothing here reaches the browser. Keep it that
// way: never import this file from a `<script>` block.
import { eventIdBySlug, type EventIdEntry } from '../eventIds';
import { ATTACK_TECHNIQUE_BY_ID } from '../references';
import type { DrillExtractField, DrillQuestion } from '../../scripts/drillEngine';
import { toSerialisableQuestion, type SerialisableDrillQuestion } from './graders';

type Mode = 'extract' | 'attack';

interface Pick {
  slug: string;
  mode: Mode;
}

// Every slug below was confirmed to exist in EVENT_IDS / ATTACK_TECHNIQUE_BY_ID
// before being added — see this repo's CLAUDE.md "Content accuracy" rule
// (never fabricate a fact this site shows as real). 7 'extract' (triage the
// log) + 3 'attack' (ATT&CK-mapping) bonus questions.
const PICKS: Pick[] = [
  { slug: 'security-4624', mode: 'extract' },
  { slug: 'sysmon-11', mode: 'extract' },
  { slug: 'security-4720', mode: 'attack' },
  { slug: 'security-1102', mode: 'extract' },
  { slug: 'sysmon-22', mode: 'extract' },
  { slug: 'sysmon-10', mode: 'attack' },
  { slug: 'security-4625', mode: 'extract' },
  { slug: 'security-4672', mode: 'extract' },
  { slug: 'security-7045', mode: 'attack' },
  { slug: 'sysmon-3', mode: 'extract' },
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

// Sysmon's own log format appends a trailing ";" after a value list even
// when only one value is present (see sysmon-22's real "QueryResults:
// ::ffff:198.51.100.42;" sample) — that trailing punctuation is an artifact
// of Sysmon's multi-value-list convention, not part of the IP itself, so a
// learner who reasonably types the value without it should still grade
// correct. Used as a per-field `grade` override (default field grading is
// otherwise a plain case-insensitive/trimmed exact match, applied by
// drillEngine.ts itself — see DrillExtractField's own doc comment).
function normalizeTrailingListMarker(s: string): string {
  return s.trim().replace(/;$/, '').trim();
}

// Hand-curated per-entry 'extract' fields. Every `label` traces to that
// entry's own EventIdEntry.keyFields[].name (disambiguated with a
// parenthetical block name where the same field name appears twice in the
// same raw log at different values — 4624's two "Account Name" blocks and
// 4625's Subject-vs-"Account For Which Logon Failed" block). Every
// `correctValue` is copied verbatim from that same entry's real
// EVENT_IDS[].sampleLog — confirmed by hand against src/data/eventIds.ts and
// re-checked by test/eventIdsDrill.test.ts's own "every correctValue is a
// literal substring of the real sampleLog" assertion. A couple of entries
// (4672, 1102, sysmon-3) whose own curated keyFields list is short (2-3
// entries) or includes a field whose sample value is just a placeholder dash
// (sysmon-3's DestinationHostname, 4624's Process Name) round out to 3-4
// blanks with a genuinely present, frequently-cross-referenced field instead
// (Logon ID — the correlation key 4624's own `why` text calls out as tying a
// session to its later 4634/4672/4688 events) rather than padding with an
// empty/placeholder value.
const EXTRACT_FIELDS: Record<string, DrillExtractField[]> = {
  'security-4624': [
    { label: 'Logon Type', correctValue: '3' },
    { label: 'Account Name (Subject)', correctValue: 'WORKSTATION01$' },
    { label: 'Account Name (New Logon)', correctValue: 'jsmith' },
    { label: 'Source Network Address', correctValue: '203.0.113.10' },
  ],
  'security-4625': [
    { label: 'Logon Type', correctValue: '3' },
    { label: 'Account Name (Account For Which Logon Failed)', correctValue: 'jsmith' },
    { label: 'Sub Status', correctValue: '0xC000006A' },
    { label: 'Source Network Address', correctValue: '203.0.113.15' },
  ],
  'security-4672': [
    { label: 'Account Name (Subject)', correctValue: 'administrator' },
    { label: 'Logon ID', correctValue: '0x8A2F1' },
    { label: 'Privilege granting LSASS memory access (used by tools like Mimikatz)', correctValue: 'SeDebugPrivilege' },
  ],
  'security-1102': [
    { label: 'Account Name (Subject)', correctValue: 'administrator' },
    { label: 'Domain Name', correctValue: 'CORP' },
    { label: 'Logon ID', correctValue: '0x3E7F2A1' },
  ],
  'sysmon-3': [
    { label: 'Image', correctValue: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' },
    { label: 'DestinationIp', correctValue: '203.0.113.10' },
    { label: 'DestinationPort', correctValue: '443' },
    { label: 'User', correctValue: 'CORP\\jsmith' },
  ],
  'sysmon-11': [
    { label: 'Image', correctValue: 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\invoice.exe' },
    { label: 'TargetFilename', correctValue: 'C:\\Users\\jsmith\\AppData\\Roaming\\update.dll' },
    { label: 'CreationUtcTime', correctValue: '2024-01-15 14:42:33.012' },
  ],
  'sysmon-22': [
    { label: 'QueryName', correctValue: 'update.example.com' },
    { label: 'Image', correctValue: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' },
    { label: 'QueryStatus', correctValue: '0' },
    {
      label: 'QueryResults',
      correctValue: '::ffff:198.51.100.42;',
      grade: (v) => normalizeTrailingListMarker(v).toLowerCase() === normalizeTrailingListMarker('::ffff:198.51.100.42;').toLowerCase(),
      // Serialisable twin of the closure directly above — the client only ever
      // sees this one (see ./graders.ts). test/eventIdsDrill.test.ts asserts
      // the two agree on every probe answer.
      grader: { kind: 'trailing-list-value', correct: '::ffff:198.51.100.42;' },
    },
  ],
};

function buildExtractQuestion(entry: EventIdEntry): DrillQuestion {
  const fields = EXTRACT_FIELDS[entry.slug];
  if (!fields || !fields.length) throw new Error(`Event ID drill: no extract fields curated for "${entry.slug}"`);
  if (!entry.sampleLog) throw new Error(`Event ID drill: "${entry.slug}" has no sampleLog to triage`);
  const sourceLabel = entry.source === 'sysmon' ? 'Sysmon' : 'Windows';
  return {
    prompt: `Triage this raw ${sourceLabel} log for Event ID ${entry.id} ("${entry.name}", channel: ${entry.channel}). Read it and type what was actually recorded for each field below.`,
    answerType: 'extract',
    artifact: entry.sampleLog,
    fields,
    explanation: `Event ID ${entry.id} — "${entry.name}." ${entry.what} ${entry.why}`,
    referenceHref: `/reference/event-ids/${entry.slug}/`,
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
    // Serialisable twin of the closure above — captures only the id string.
    grader: { kind: 'technique-id', correctId },
    explanation: `${entry.why} This maps to ${correct.name} (${correctId}) — see the full technique writeup on the ATT&CK Coverage Map for detection guidance and mitigations.`,
    referenceHref: `/reference/event-ids/${entry.slug}/`,
    referenceLabel: `Full reference: Event ID ${entry.id}`,
  };
}

export function getEventIdsDrillQuestion(index: number): DrillQuestion {
  const pick = PICKS[((index % PICKS.length) + PICKS.length) % PICKS.length];
  const entry = mustGetEntry(pick.slug);
  return pick.mode === 'attack' ? buildAttackQuestion(entry) : buildExtractQuestion(entry);
}

/**
 * The whole bank, materialised into its JSON-safe form. Called ONCE, in
 * /drills/event-ids/'s frontmatter, and shipped to the client as a JSON island
 * — which is what keeps EVENT_IDS (and its sampleLogs) out of the page bundle.
 * Every `grade` closure is replaced by its `grader` descriptor;
 * `toSerialisableQuestion` throws at build if anything else here ever stops
 * being serialisable.
 */
export function eventIdsDrillQuestionBank(): SerialisableDrillQuestion[] {
  return Array.from({ length: EVENT_IDS_DRILL_TOTAL }, (_, i) => toSerialisableQuestion(getEventIdsDrillQuestion(i)));
}
