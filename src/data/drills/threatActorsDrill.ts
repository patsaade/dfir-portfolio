// Question generator for the Threat Actor / APT Drill (/drills/threat-actors/).
// Pure, deterministic function of `index` (wraps via modulo) — no randomness
// — so DrillEngine.astro's server-rendered `firstQuestion` prop and the
// page's own client-side `getThreatActorsQuestion(0)` call are always
// byte-identical (same contract as eventIdsDrill.ts/commands.ts).
//
// Deliberately excludes pure ID/string recall (e.g. "what's APT29's MITRE
// ID?", "name any APT28 alias", "type a technique ID from memory") — no
// working analyst free-recalls a catalog number or an arbitrary technique
// id, so quizzing that teaches nothing beyond the quiz itself. Every
// question here instead tests one of three real analyst skills:
//
// 1. RECOGNITION (`clueToName` / `aliasToName` / `software`) — given a real,
//    distinguishing fact, alias, or malware/tool name pulled straight from a
//    group's own MITRE profile, identify which tracked group it is. This
//    mirrors actually reading threat intel: resolving an unfamiliar
//    codename or IOC to a known actor profile.
// 2. STRUCTURAL UNDERSTANDING (`namingConvention`) — how each vendor's own
//    naming grammar works (the maturity ladder behind Mandiant's
//    UNC->APT/FIN, what a specific code word denotes) — hand-verified
//    facts about vendor TAXONOMY, not about any one tracked group.
// 3. APPLICATION (`applyNaming`) — given a country/motivation and a named
//    vendor, derive what code that vendor's own real, published scheme
//    would assign — applying an already-understood rule to a new (but
//    always real, verified) input, rather than recalling one memorized
//    example of it.
//
// Two separately-verified sources feed this drill:
//
// 1. `clueToName`/`aliasToName`/`software` PICKS (`groupId` + `mode`) trace
//    to REAL data — src/data/threatActors.ts's own THREAT_ACTORS (the same
//    MITRE-STIX-generated dataset behind the live /threat-actors/ reference
//    and its detail pages). Every hand-written "clue" is a verified,
//    literal fact pulled from that group's own `description`/`summary`/
//    `aliases`/`software` fields (cross-checked for uniqueness against every
//    OTHER group in the dataset before being added — see
//    test/threatActorsDrill.test.ts).
// 2. `namingConvention` and `applyNaming` PICKS trace to a DIFFERENT but
//    equally rigorous source: src/data/threatActorNaming.ts's
//    VENDOR_NAMING_SCHEMES — hand-verified facts about how MITRE/Mandiant/
//    CrowdStrike/Microsoft/Secureworks each derive their own threat-actor
//    names, each checked against that vendor's own live documentation (see
//    that file's `sourceUrl` per scheme) rather than against THREAT_ACTORS.
//    These are facts about vendor TAXONOMY, not about any one specific
//    tracked group.
//
// Nothing in either category is invented, per this repo's "no fabricated
// content" rule.
//
// Free-text recall, not multiple choice, matching this site's drill
// philosophy: an alias/software/naming question grades a single normalized
// string; a clueToName question grades against the group's real canonical
// name OR any of its own real aliases, since MITRE documents several valid
// names per group — any one of them is a correct answer, not just one
// specific string, same lenient-but-correct spirit as commands.ts's grade()
// functions. namingConvention/applyNaming questions grade against a
// hand-written, verified list of acceptable phrasings for the same reason —
// not just one exact string.
import { THREAT_ACTORS, threatActorSlug, type ThreatActor } from '../threatActors';
import type { DrillQuestion } from '../../scripts/drillEngine';

type Mode = 'aliasToName' | 'clueToName' | 'software' | 'namingConvention' | 'applyNaming';

interface GroupPick {
  groupId: string;
  mode: Extract<Mode, 'aliasToName' | 'clueToName' | 'software'>;
  /** A hand-picked, verified-unique fact driving the prompt — an alias, a
   *  malware/tool name, or a short paraphrase of a distinguishing sentence
   *  from the group's own real `description`. Never invented. */
  clue: string;
}

interface NamingPick {
  mode: 'namingConvention';
  /** Index into NAMING_SPECS below — a hand-verified vendor-taxonomy fact,
   *  never derived from THREAT_ACTORS (see this file's header comment). */
  specIndex: number;
}

interface ApplyNamingPick {
  mode: 'applyNaming';
  /** Index into APPLY_NAMING_SPECS below. */
  specIndex: number;
}

type Pick = GroupPick | NamingPick | ApplyNamingPick;

/** A single hand-authored, hand-verified vendor-naming-taxonomy question.
 *  Every fact referenced here is cross-checked against
 *  VENDOR_NAMING_SCHEMES (threatActorNaming.ts) by
 *  test/threatActorsDrill.test.ts, the same "verify, don't trust the typed
 *  string" discipline threat-actors.astro's own NAMING_EXAMPLES uses for its
 *  live-dataset cross-references. */
interface NamingSpec {
  prompt: string;
  hint: string;
  correctAnswer: string;
  /** Accepted case/whitespace-insensitive answers — several valid phrasings
   *  for the same verified fact, same lenient-but-grounded spirit as
   *  matchesGroupName below. */
  acceptableAnswers: string[];
  explanation: string;
}

const NAMING_SPECS: NamingSpec[] = [
  {
    prompt:
      "Which vendor's naming scheme uses a two-word cryptonym where the second word is an animal indicating nation-state nexus or motivation (e.g. Bear, Panda, Spider)?",
    hint: 'Its own public "Adversary Universe" groups dozens of named actors under each animal word.',
    correctAnswer: 'CrowdStrike',
    acceptableAnswers: ['CrowdStrike'],
    explanation:
      'CrowdStrike assigns every tracked adversary a two-word cryptonym — a unique first-word qualifier plus a shared second-word category term (Bear = Russia, Panda = China, Spider = eCrime, and more).',
  },
  {
    prompt: 'In CrowdStrike\'s naming scheme, what does the qualifier "Panda" indicate?',
    hint: "It's the same category word CrowdStrike uses for every nation-state actor it attributes to this one country.",
    correctAnswer: 'China',
    acceptableAnswers: ['China', 'China (nation-state)', 'Chinese', 'PRC'],
    explanation:
      'CrowdStrike\'s "Panda" category word marks a nation-state actor attributed to China — the second word in a CrowdStrike cryptonym indicates nation-nexus or motivation, never the specific actor.',
  },
  {
    prompt: 'Mandiant designates a group it assesses to be financially motivated (not nation-state espionage) with what letter-prefixed code?',
    hint: 'The nation-state-espionage equivalent uses the prefix "APT" instead.',
    correctAnswer: 'FIN',
    acceptableAnswers: ['FIN', 'FIN##', 'FIN#'],
    explanation:
      'Mandiant/Google Threat Intelligence uses "FIN##" for a group it assesses as financially motivated (cybercrime) — separate from "APT##" for nation-state espionage and "UNC####" for a cluster not yet classified either way.',
  },
  {
    prompt: 'Mandiant opens a new, not-yet-attributed cluster of intrusion activity under what prefix, before it has enough evidence to classify it as APT or FIN?',
    hint: 'It stands for "uncategorized."',
    correctAnswer: 'UNC',
    acceptableAnswers: ['UNC', 'UNC####', 'UNC#'],
    explanation:
      'Mandiant\'s "UNC####" designation is deliberately non-committal — it tracks a cluster of related intrusion activity without yet claiming a motivation or nation-state attribution, and can later graduate into a named APT/FIN group.',
  },
  {
    prompt: 'Since April 2023, Microsoft names every threat actor after a shared theme. What is that theme?',
    hint: 'Individual actors get a unique adjective prefixed to a shared family word from this theme (e.g. "Midnight Blizzard").',
    correctAnswer: 'weather',
    acceptableAnswers: ['weather', 'weather-themed', 'weather themes', 'weather phenomena'],
    explanation:
      "Microsoft's post-April-2023 taxonomy assigns every threat actor a weather-themed family name — mapping to a country for nation-state actors, or a motivation/category otherwise — which replaced its older chemical-element codenames (e.g. STRONTIUM, NOBELIUM).",
  },
  {
    prompt: 'In Microsoft\'s current weather-themed taxonomy, what does the family name "Blizzard" indicate?',
    hint: 'The same nation CrowdStrike calls "Bear" and Secureworks calls "IRON."',
    correctAnswer: 'Russia',
    acceptableAnswers: ['Russia', 'Russia (nation-state)', 'Russian'],
    explanation:
      'Microsoft\'s "Blizzard" family name is Russia-attributed nation-state activity — "Midnight Blizzard" and "Forest Blizzard" are two distinct Russia-attributed groups sharing that one family name.',
  },
  {
    prompt: "A Microsoft-tracked cluster that's newly discovered or not yet fully attributed gets what temporary designation, before it converts to a permanent weather-themed name?",
    hint: 'Format: a fixed word plus a sequential number, e.g. "____-0875."',
    correctAnswer: 'Storm',
    acceptableAnswers: ['Storm', 'Storm-####', 'Storm-#'],
    explanation:
      'Microsoft assigns a temporary "Storm-####" designation to a newly discovered or still-developing cluster; once Microsoft reaches high confidence on origin/identity, it converts to a permanent named actor or merges into an existing one.',
  },
  {
    prompt: 'Secureworks Counter Threat Unit (CTU) names every threat group after a metal or chemical element plus a nickname. What does the element "IRON" denote?',
    hint: 'The same nation CrowdStrike calls "Bear" and Microsoft calls "Blizzard."',
    correctAnswer: 'Russia',
    acceptableAnswers: ['Russia', 'Russian'],
    explanation:
      'Secureworks CTU\'s "IRON" element prefix denotes Russia — e.g. "IRON TWILIGHT" (APT28/G0007) and "IRON RITUAL"/"IRON HEMLOCK" (APT29/G0016) are both Russia-attributed.',
  },
  {
    prompt: 'MITRE ATT&CK currently labels the field listing every other publicly reported name for a tracked group what — having renamed it from "Aliases"?',
    hint: 'Two words; the first describes how the names relate to each other, the second is the noun MITRE tracks.',
    correctAnswer: 'Associated Groups',
    acceptableAnswers: ['Associated Groups', 'Associated Group'],
    explanation:
      'MITRE\'s own group pages currently label this field "Associated Groups" (with a parenthetical noting it was formerly labeled "Aliases") — every other vendor\'s publicly reported name for the same tracked activity, regardless of who coined it.',
  },
];

/** A single hand-authored "apply the rule" question — a fact pattern (a
 *  country or motivation) plus a named vendor, testing whether the learner
 *  can DERIVE that vendor's own real code/qualifier for it rather than
 *  recall one memorized example. `vendor` and `code` are both cross-checked
 *  against a real VENDOR_NAMING_SCHEMES mapping by
 *  test/threatActorsDrill.test.ts — every code here is real and currently
 *  in use by that vendor, not invented for the quiz. */
interface ApplyNamingSpec {
  /** Must match a VENDOR_NAMING_SCHEMES[].vendor exactly. */
  vendor: string;
  /** Must match one of that vendor's mappings[].code exactly. */
  code: string;
  scenario: string;
  hint: string;
  explanation: string;
}

const APPLY_NAMING_SPECS: ApplyNamingSpec[] = [
  {
    vendor: 'CrowdStrike',
    code: 'Bear',
    scenario: 'CrowdStrike is naming a newly discovered nation-state adversary it attributes to Russia.',
    hint: 'CrowdStrike pairs a unique qualifier with a shared category animal per nation — this is the same nation Secureworks marks "IRON" and Microsoft marks "Blizzard."',
    explanation:
      'CrowdStrike would use "Bear" as the shared category word — every Russia-attributed CrowdStrike adversary carries it (Cozy Bear, Fancy Bear, Venomous Bear), paired with a unique qualifier for that specific actor.',
  },
  {
    vendor: 'CrowdStrike',
    code: 'Chollima',
    scenario: 'CrowdStrike is naming a newly discovered nation-state adversary it attributes to North Korea.',
    hint: "It's the name of the mythical winged horse from Korean folklore.",
    explanation: 'CrowdStrike uses "Chollima" as its category word for North Korea-attributed nation-state activity.',
  },
  {
    vendor: 'CrowdStrike',
    code: 'Spider',
    scenario: 'CrowdStrike is naming a newly discovered adversary it assesses as financially motivated (eCrime), not nation-state.',
    hint: "Non-nation-state categories get their own dedicated word too — this one isn't a country animal at all.",
    explanation: 'CrowdStrike reserves "Spider" for eCrime/financially motivated activity, separate from any of its nation-state animal words.',
  },
  {
    vendor: 'Microsoft',
    code: 'Typhoon',
    scenario: 'Microsoft is naming a newly attributed nation-state actor tied to China.',
    hint: "Microsoft's post-2023 scheme is entirely weather-themed — this family name is the one it maps to China.",
    explanation: 'Microsoft assigns China-attributed nation-state actors to its "Typhoon" family (e.g. Volt Typhoon, Flax Typhoon).',
  },
  {
    vendor: 'Microsoft',
    code: 'Sleet',
    scenario: 'Microsoft is naming a newly attributed nation-state actor tied to North Korea.',
    hint: 'A cold-weather word, distinct from the family Microsoft uses for Russia.',
    explanation: 'Microsoft\'s "Sleet" family name maps to North Korea-attributed nation-state activity.',
  },
  {
    vendor: 'Microsoft',
    code: 'Tempest',
    scenario: 'Microsoft is naming a newly discovered actor it assesses as financially motivated, not nation-state.',
    hint: "Not every Microsoft family name maps to a country — this one marks a motivation instead.",
    explanation: 'Microsoft uses "Tempest" for financially motivated (non-nation-state) activity — motivation-based, not country-based, unlike most of its other weather families.',
  },
  {
    vendor: 'Secureworks Counter Threat Unit (now part of Sophos)',
    code: 'BRONZE',
    scenario: 'Secureworks CTU is naming a newly tracked threat group it attributes to China.',
    hint: 'Secureworks pairs a metal/element prefix with a nickname — this element is the one it maps to China.',
    explanation: 'Secureworks CTU prefixes China-attributed groups with "BRONZE" (e.g. BRONZE UNION, formerly tracked as TG-3390).',
  },
  {
    vendor: 'Secureworks Counter Threat Unit (now part of Sophos)',
    code: 'NICKEL',
    scenario: 'Secureworks CTU is naming a newly tracked threat group it attributes to North Korea.',
    hint: "A different element than the one Secureworks uses for Russia (IRON) or China (BRONZE).",
    explanation: 'Secureworks CTU prefixes North Korea-attributed groups with "NICKEL."',
  },
  {
    vendor: 'Secureworks Counter Threat Unit (now part of Sophos)',
    code: 'GOLD',
    scenario: 'Secureworks CTU is naming a newly tracked threat group it assesses as cybercrime/financially motivated.',
    hint: "Not every Secureworks element prefix maps to a country — this one marks a motivation instead.",
    explanation: 'Secureworks CTU prefixes financially motivated/cybercrime groups with "GOLD" — motivation-based, not country-based, unlike most of its other element prefixes.',
  },
];

// 9 group-derived recognition challenges + 9 vendor-naming-structure
// challenges + 9 apply-the-rule challenges. Every groupId below was
// confirmed to exist in THREAT_ACTORS before being added; every specIndex
// below was confirmed to exist in its respective spec array (and,
// transitively via test/threatActorsDrill.test.ts, in
// VENDOR_NAMING_SCHEMES) — see this repo's CLAUDE.md "Content accuracy"
// rule (never fabricate a fact this site shows as real).
const PICKS: Pick[] = [
  { groupId: 'G0016', mode: 'aliasToName', clue: 'Cozy Bear' },
  {
    groupId: 'G0035',
    mode: 'clueToName',
    clue: 'attributed to Russia’s FSB "Center 16" and known for targeting critical infrastructure and industrial control systems since 2010',
  },
  {
    groupId: 'G0010',
    mode: 'clueToName',
    clue: 'attributed to Russia’s FSB and known for its Uroburos malware and long-running espionage campaigns',
  },
  {
    groupId: 'G0046',
    mode: 'clueToName',
    clue: 'that ran point-of-sale malware campaigns through a front company called Combi Security',
  },
  {
    groupId: 'G0008',
    mode: 'clueToName',
    clue: 'that MITRE notes may be linked to Cobalt Group and FIN7, who have also used its namesake malware',
  },
  {
    groupId: 'G1015',
    mode: 'clueToName',
    clue: 'that is native English-speaking, active since 2022, and initially targeted CRM/BPO/telecom providers before expanding into gaming and hospitality',
  },
  {
    groupId: 'G0006',
    mode: 'clueToName',
    clue: 'whose Military Unit Cover Designator (MUCD) is Unit 61398',
  },
  { groupId: 'G0032', mode: 'software', clue: 'BLINDINGCAN' },
  { groupId: 'G0046', mode: 'software', clue: 'BOOSTWRITE' },
  // Vendor-naming-STRUCTURE questions (see NAMING_SPECS above) — how each
  // scheme itself works, covering all 5 verified vendor schemes
  // (CrowdStrike x2, Mandiant x2, Microsoft x3, Secureworks, MITRE ATT&CK
  // itself).
  { mode: 'namingConvention', specIndex: 0 },
  { mode: 'namingConvention', specIndex: 1 },
  { mode: 'namingConvention', specIndex: 2 },
  { mode: 'namingConvention', specIndex: 3 },
  { mode: 'namingConvention', specIndex: 4 },
  { mode: 'namingConvention', specIndex: 5 },
  { mode: 'namingConvention', specIndex: 6 },
  { mode: 'namingConvention', specIndex: 7 },
  { mode: 'namingConvention', specIndex: 8 },
  // Apply-the-rule questions (see APPLY_NAMING_SPECS above) — 3 vendors x 3
  // fact patterns each (a Russia or China example, a North Korea example,
  // and a financially-motivated example), so the same "nation-state gets a
  // country code, motivation gets its own dedicated code" pattern surfaces
  // across all three schemes rather than looking like one vendor's quirk.
  { mode: 'applyNaming', specIndex: 0 },
  { mode: 'applyNaming', specIndex: 1 },
  { mode: 'applyNaming', specIndex: 2 },
  { mode: 'applyNaming', specIndex: 3 },
  { mode: 'applyNaming', specIndex: 4 },
  { mode: 'applyNaming', specIndex: 5 },
  { mode: 'applyNaming', specIndex: 6 },
  { mode: 'applyNaming', specIndex: 7 },
  { mode: 'applyNaming', specIndex: 8 },
];

export const THREAT_ACTORS_DRILL_TOTAL = PICKS.length;

function mustGetActor(groupId: string): ThreatActor {
  const a = THREAT_ACTORS.find((x) => x.id === groupId);
  if (!a) throw new Error(`Threat actor drill: unknown group id "${groupId}"`);
  return a;
}

function mustGetNamingSpec(index: number): NamingSpec {
  const s = NAMING_SPECS[index];
  if (!s) throw new Error(`Threat actor drill: unknown naming spec index ${index}`);
  return s;
}

function mustGetApplyNamingSpec(index: number): ApplyNamingSpec {
  const s = APPLY_NAMING_SPECS[index];
  if (!s) throw new Error(`Threat actor drill: unknown apply-naming spec index ${index}`);
  return s;
}

function normalize(s: unknown): string {
  return String(s ?? '').trim().toLowerCase();
}

// Accepts the group's canonical name OR any of its own real aliases,
// case-insensitively — a learner who knows a group only by a common alias
// (e.g. "Fancy Bear" instead of "APT28") shouldn't be marked wrong.
function matchesGroupName(userAnswer: string, actor: ThreatActor): boolean {
  const n = normalize(userAnswer);
  if (!n) return false;
  if (normalize(actor.name) === n) return true;
  return actor.aliases.some((a) => normalize(a) === n);
}

function refFor(actor: ThreatActor) {
  return {
    referenceHref: `/threat-actors/${threatActorSlug(actor.name)}/`,
    referenceLabel: `Full profile: ${actor.name}`,
  };
}

function buildAliasToName(actor: ThreatActor, alias: string): DrillQuestion {
  return {
    prompt: `The alias "${alias}" refers to which MITRE-tracked threat actor group?`,
    hint: `This alias and ${actor.id} name the same tracked group.`,
    answerType: 'text',
    correctAnswer: actor.name,
    grade: (ans) => matchesGroupName(ans, actor),
    explanation: `"${alias}" is one of ${actor.aliases.length} publicly known aliases for ${actor.name}. ${actor.summary}`,
    ...refFor(actor),
  };
}

function buildClueToName(actor: ThreatActor, clue: string): DrillQuestion {
  return {
    prompt: `Name the threat actor group ${clue}.`,
    hint: `Starts with "${actor.name[0]}."`,
    answerType: 'text',
    correctAnswer: actor.name,
    grade: (ans) => matchesGroupName(ans, actor),
    explanation: `${actor.name} (${actor.id}) is the group ${clue}. ${actor.summary}`,
    ...refFor(actor),
  };
}

function buildSoftware(actor: ThreatActor, software: string): DrillQuestion {
  return {
    prompt: `Which threat actor group is documented using the malware/tool "${software}"?`,
    hint: 'Check the "Malware & tools" list on the group’s own profile page.',
    answerType: 'text',
    correctAnswer: actor.name,
    grade: (ans) => matchesGroupName(ans, actor),
    explanation: `${software} is documented malware/tooling used by ${actor.name} (${actor.id}).`,
    ...refFor(actor),
  };
}

// namingConvention questions have no groupId (they're vendor-taxonomy facts,
// not per-group ones — see this file's header comment), so they're graded
// against the hand-authored NAMING_SPECS list rather than THREAT_ACTORS: any
// of a fact's verified acceptable phrasings counts, same lenient-but-grounded
// spirit as matchesGroupName above. referenceHref points at the live
// "Naming conventions" section on /threat-actors/ (threat-actors.astro's
// `id="naming-conventions"` heading) rather than one specific group's
// profile, since the fact being tested isn't about any single group.
function buildNamingConvention(spec: NamingSpec): DrillQuestion {
  return {
    prompt: spec.prompt,
    hint: spec.hint,
    answerType: 'text',
    correctAnswer: spec.correctAnswer,
    grade: (ans) => {
      const n = normalize(ans);
      return spec.acceptableAnswers.some((a) => normalize(a) === n);
    },
    explanation: spec.explanation,
    referenceHref: '/threat-actors/#naming-conventions',
    referenceLabel: 'Naming conventions: why one group has so many names',
  };
}

// applyNaming questions ask the learner to DERIVE a vendor's real code from
// a fact pattern (a country/motivation), rather than recall one memorized
// example of it — same grading/reference shape as namingConvention (a
// vendor-taxonomy fact, not a per-group one), but the prompt is phrased as
// a scenario to apply the rule to instead of a direct question about it.
function buildApplyNaming(spec: ApplyNamingSpec): DrillQuestion {
  return {
    prompt: `${spec.scenario} Applying that vendor's own real naming convention, what code/qualifier would it assign?`,
    hint: spec.hint,
    answerType: 'text',
    correctAnswer: spec.code,
    grade: (ans) => normalize(ans) === normalize(spec.code),
    explanation: spec.explanation,
    referenceHref: '/threat-actors/#naming-conventions',
    referenceLabel: `Naming conventions: ${spec.vendor}'s own scheme`,
  };
}

function buildQuestion(pick: Pick): DrillQuestion {
  if (pick.mode === 'namingConvention') {
    return buildNamingConvention(mustGetNamingSpec(pick.specIndex));
  }
  if (pick.mode === 'applyNaming') {
    return buildApplyNaming(mustGetApplyNamingSpec(pick.specIndex));
  }
  const actor = mustGetActor(pick.groupId);
  switch (pick.mode) {
    case 'aliasToName':
      return buildAliasToName(actor, pick.clue);
    case 'clueToName':
      return buildClueToName(actor, pick.clue);
    case 'software':
      return buildSoftware(actor, pick.clue);
    default:
      throw new Error(`Threat actor drill: unknown mode`);
  }
}

/** Pure, deterministic function of `index` (wraps via modulo) — see
 *  DrillEngine.astro's header comment on why nextQuestion(0) must be
 *  deterministic (its SSR firstQuestion prop and the client's own mount-time
 *  call must agree). */
export function getThreatActorsQuestion(index: number): DrillQuestion {
  const len = PICKS.length;
  const pick = PICKS[((index % len) + len) % len];
  return buildQuestion(pick);
}
