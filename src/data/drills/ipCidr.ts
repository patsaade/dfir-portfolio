// Pure, deterministic question generator for the /drills/ip-cidr/ module.
//
// Two question shapes:
//  (a) "Build the CIDR" — a 'subnet'-type exercise: DrillEngine renders an
//      interactive block builder (four octet controls + a prefix-length
//      slider) whose derived network/broadcast/host-range readout and
//      per-address containment marks update live as the learner adjusts,
//      then a Check grades it. Mechanically it is 'construct' (see
//      src/data/drills/regexDrill.ts's header comment for the shared
//      mechanics — live preview, iterate-until-correct, no single-shot
//      end-of-question on a wrong attempt) with a richer input control; the
//      grading contract is byte-for-byte the same, which is why validate()
//      below returns the same DrillValidateResult and the engine routes
//      'subnet' straight into handleConstructCheck.
//      Each scenario gives a short containment story plus 2-5 REAL IPv4
//      addresses tagged whether they should fall inside the block the
//      learner builds — reusing the exact {text, shouldMatch} testCases
//      shape 'construct' already uses for regex sample strings, just
//      re-interpreted as address/containment rather than string/pattern-
//      match (shouldMatch === "should be inside the block"). validate()
//      parses the built block with this repo's REAL src/utils/cidr.ts
//      functions (parseCidr() / parseIPv4() — the exact same ones the live
//      CIDR & VLAN Calculator and this drill's own category questions below
//      already use), then checks every listed address for containment in the
//      resulting network..broadcast range. As with the regex drill, there is
//      no single hardcoded "correct string" — any CIDR block that correctly
//      includes every "should be inside" address and excludes every "should
//      NOT" address passes; `referenceSolution`/`correctAnswer` is just ONE
//      verified-working answer, shown for the no-JS fallback and asserted in
//      test/ipCidr.test.ts to actually pass its own scenario.
//      Each scenario also carries a `subnetStart` — the block the builder
//      opens on. It is deliberately a WRONG-but-plausible block (usually the
//      exact near-miss that scenario's explanation calls out, e.g. the /25
//      that undershoots .200), never the answer; test/ipCidr.test.ts asserts
//      it parses AND fails its own validate(), so the drill can never open
//      already-solved.
//  (b) Special-use range CATEGORY recall (100.64.0.0/10, 169.254.0.0/16,
//      192.0.2.0/24) — genuine "what IS this block for" knowledge, not
//      arithmetic, so these three stay plain 'text' recall questions graded
//      against real src/data/ipRanges.ts (IP_RANGES) entries, unchanged from
//      this drill's original design (and still at the same array positions
//      — 1, 4, 7 — as before, so the recall "breaks" land in the same place
//      relative to the harder builder questions around them).
//
// All subnet arithmetic — here AND in the engine's live readout — goes
// through src/utils/cidr.ts. The three exported helpers at the bottom of
// this file (controlsToCidr / cidrToControls / subnetPreview) are the pure,
// unit-tested seam between the builder's DOM controls and that math:
// drillEngine.ts only moves strings and numbers between inputs, it never
// does bit math of its own.
//
// Index -> question is a fixed lookup into a small curated bank, not
// Math.random(), so nextQuestion(0) is byte-identical between this page's
// own build-time frontmatter call and the client script's post-hydration
// re-render (see DrillEngine.astro's header comment on why that matters for
// the no-JS/no-flash contract) and totalQuestions can stay a plain constant.
import { parseCidr, parseIPv4 } from '../../utils/cidr';
import { IP_RANGES } from '../ipRanges';

// NOTE on typing: the per-test-case and validate() result shapes are imported
// straight from drillEngine.ts — they're the real contract its
// handleConstructCheck reads, including the `pass` field. (This file used to
// carry a local `IpCidrValidateResult` stand-in because that exported
// interface was missing `pass`; that gap has since been fixed at the source,
// so the duplicate is gone.)
//
// `IpCidrDrillQuestion` below is still local, for a different and still-valid
// reason: unlike regexDrill.ts — which only ever produces ONE question shape
// (always 'construct') — this file mixes 'text' (category recall) and
// 'subnet' (build-the-CIDR) questions. Annotating against the full
// DrillQuestion would make TypeScript infer a genuine union of two
// differently-shaped object types for `getIpCidrQuestion`'s return value, and
// accessing a subnet-only field (`testCases`, `validate`) or a text-only
// one (`grade`) on that union errors without an explicit `answerType`
// narrowing check first. It's structurally a valid subtype of the real
// DrillQuestion, so nothing downstream is affected.
import type { DrillValidateResult, DrillTestCaseResult, DrillSubnetPreview } from '../../scripts/drillEngine';

interface IpCidrDrillQuestion {
  prompt: string;
  explanation: string;
  referenceHref?: string;
  referenceLabel?: string;
  answerType: 'text' | 'subnet';
  correctAnswer?: string;
  /** 'text' (category recall) only. */
  grade?: (userAnswer: string) => boolean;
  /** 'subnet' (build-the-CIDR) only. */
  testCases?: { text: string; shouldMatch: boolean }[];
  /** 'subnet' (build-the-CIDR) only. */
  validate?: (userAnswer: string) => DrillValidateResult;
  /** 'subnet' only — the block the builder opens on. Deliberately wrong (see
   *  this file's header comment); asserted non-passing in test/ipCidr.test.ts. */
  subnetStart?: string;
  /** 'subnet' only — the builder's pure seam, handed to the engine (see
   *  subnetQuestion below). Types mirror DrillQuestion's own fields. */
  subnetBuild?: (octets: number[], prefix: number) => string;
  subnetParse?: (cidr: string) => { octets: number[]; prefix: number } | null;
  subnetPreview?: (cidr: string) => DrillSubnetPreview | null;
  hint?: string;
}

// Same human labels as ip-reference.astro's own page-local `catLabel` map
// (that one is page-scoped, not exported, so this is a deliberate small
// duplication rather than a cross-page import of a private const).
const CATEGORY_LABELS: Record<string, string> = {
  'private-use': 'Private-use',
  'shared-address-space': 'Shared address space (CGNAT)',
  loopback: 'Loopback',
  'link-local': 'Link-local',
  multicast: 'Multicast',
  documentation: 'Documentation',
  benchmarking: 'Benchmarking',
  translation: 'Translation',
  reserved: 'Reserved',
  broadcast: 'Broadcast',
  'unique-local': 'Unique local (ULA)',
  'global-unicast': 'Global unicast',
};

function rangeFor(cidr: string) {
  const entry = IP_RANGES.find((r) => r.cidr === cidr);
  if (!entry) throw new Error(`ipCidr drill: no IP_RANGES entry for ${cidr}`);
  return entry;
}

// ── Special-use range category recognition (real IP_RANGES data) ──────────

// Lenient category grading: strips parenthetical asides (e.g. "(CGNAT)",
// "(ULA)") and collapses everything else down to lowercase words, so both
// the hyphenated category id ("shared-address-space") and its human label
// ("Shared address space (CGNAT)") normalize to the same string — the
// learner can type either form, with or without hyphens.
function normalizeCategory(s: string): string {
  return s
    .toLowerCase()
    .replace(/\(.*?\)/g, '')
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
}

function categoryQuestion(cidrStr: string, exampleAddr: string): IpCidrDrillQuestion {
  const r = rangeFor(cidrStr);
  const correctLabel = CATEGORY_LABELS[r.category] ?? r.category;
  const acceptable = new Set([normalizeCategory(r.category), normalizeCategory(correctLabel)]);
  return {
    prompt: `${exampleAddr} falls inside ${r.cidr} (${r.name}). What category does this block belong to?`,
    explanation: r.note,
    referenceHref: r.references[0]?.url,
    referenceLabel: r.references[0]?.name,
    hint: `Answer with the plain-English category name, e.g. "private-use", "multicast", or "loopback" — hyphens or spaces both work.`,
    answerType: 'text' as const,
    correctAnswer: correctLabel,
    grade: (ans: string) => acceptable.has(normalizeCategory(ans)),
  };
}

// ── "Build the CIDR" subnet scenarios ──────────────────────────────────────

interface SubnetScenario {
  id: string;
  prompt: string;
  /** Real IPv4 addresses tagged whether they should fall inside the block the
   *  learner builds — reuses 'construct's {text, shouldMatch} test-case
   *  shape, re-interpreted as address/containment rather than
   *  string/pattern-match (shouldMatch === "should be inside the block"). */
  testCases: { text: string; shouldMatch: boolean }[];
  explanation: string;
  hint: string;
  /** One verified-working reference CIDR — NOT the only valid answer
   *  (grading is containment-based against testCases, same non-unique-answer
   *  philosophy as the regex drill's construct questions); just what the
   *  no-JS fallback / reference display shows. Checked against its own
   *  scenario by test/ipCidr.test.ts, same discipline as regexDrill.ts's
   *  referenceSolution. */
  referenceSolution: string;
  /** Where the builder's octet/prefix controls start. Deliberately a
   *  wrong-but-plausible block — usually the exact near-miss this scenario's
   *  own explanation calls out — so the learner starts from a concrete,
   *  visibly-failing state rather than a blank field, and can never open the
   *  question already solved (asserted in test/ipCidr.test.ts). */
  subnetStart: string;
  referenceHref?: string;
  referenceLabel?: string;
}

// Real IANA benchmarking-range citation (RFC 2544), reused rather than
// hand-typed — same rangeFor() helper the category questions above use.
const BENCHMARKING_REF = rangeFor('198.18.0.0/15').references[0];

const SUBNET_SCENARIOS: SubnetScenario[] = [
  // 1. Easiest — a single, already-aligned block. Straight prefix sizing.
  {
    id: 'single-clean-block',
    prompt:
      'A new lab segment needs a single CIDR block that exactly covers the 16 addresses from 10.30.6.0 through 10.30.6.15 — no more, no fewer. Build the block.',
    testCases: [
      { text: '10.30.6.0', shouldMatch: true },
      { text: '10.30.6.15', shouldMatch: true },
      { text: '10.30.6.16', shouldMatch: false },
      { text: '10.30.5.255', shouldMatch: false },
    ],
    explanation:
      '16 addresses is 2⁴, so the prefix is /28 (32 − 4). 10.30.6.0/28 has network address 10.30.6.0 and broadcast address 10.30.6.15 — exactly the requested range, with 10.30.6.16 and 10.30.5.255 falling just outside it in the neighboring blocks.',
    hint: 'Count the requested addresses (16 = 2⁴), so the prefix length is 32 − 4 = 28. The lowest address in the range is the block’s own network address.',
    referenceSolution: '10.30.6.0/28',
    // Right network, far too big — both "outside" addresses land inside it,
    // so the containment marks show the problem immediately.
    subnetStart: '10.30.0.0/16',
  },
  // 2. A naive smallest-guess undershoots — forces widening the prefix.
  {
    id: 'boundary-exclude-size-bump',
    prompt:
      "Team A's workstation pool must include 172.20.14.10 and 172.20.14.200. Team B owns the /24 blocks immediately before and after it. Build a single CIDR block that covers both of Team A's addresses without reaching into Team B's space.",
    testCases: [
      { text: '172.20.14.10', shouldMatch: true },
      { text: '172.20.14.200', shouldMatch: true },
      { text: '172.20.13.255', shouldMatch: false },
      { text: '172.20.15.0', shouldMatch: false },
    ],
    explanation:
      'A /25 only reaches 172.20.14.0–.127 — too small to cover .200. Bumping up to /24 gives 172.20.14.0–172.20.14.255, which covers both required addresses while still stopping cleanly at the neighboring /24s on either side.',
    hint: 'Try the smallest block that covers .10 first — does it actually reach .200 too? If not, widen the prefix (a smaller prefix number, a bigger block) until both addresses fit.',
    referenceSolution: '172.20.14.0/24',
    // The naive undershoot this scenario is built around: a /25 stops at
    // .127, so .200 shows as outside until the learner widens the prefix.
    subnetStart: '172.20.14.0/25',
  },
  // 3. Same skill as #2, plus an extra unrelated exclude address as a
  // deliberate red herring (a block sized correctly for .64-.95 already
  // clears 10.50.9.1 without any extra effort).
  {
    id: 'three-exclude',
    prompt:
      'A firewall rule must match traffic from 10.50.8.64 and 10.50.8.95 only — not from 10.50.8.63, 10.50.8.96, or the unrelated address 10.50.9.1. Build the CIDR block.',
    testCases: [
      { text: '10.50.8.64', shouldMatch: true },
      { text: '10.50.8.95', shouldMatch: true },
      { text: '10.50.8.63', shouldMatch: false },
      { text: '10.50.8.96', shouldMatch: false },
      { text: '10.50.9.1', shouldMatch: false },
    ],
    explanation:
      '64 through 95 inclusive is 32 addresses — 2⁵, a /27. 10.50.8.64/27 aligns cleanly (64 is a multiple of 32), giving network 10.50.8.64 and broadcast 10.50.8.95, with .63 and .96 falling just outside in the neighboring /27s and .9.1 sitting in an entirely different /24.',
    hint: 'Count the addresses between .64 and .95 inclusive — that count tells you the prefix. Then check that .64 actually sits on a valid boundary for a block that size.',
    referenceSolution: '10.50.8.64/27',
    // A whole /24 — covers both required addresses but also swallows .63 and
    // .96, so the two near-neighbour excludes fail from the first frame.
    subnetStart: '10.50.8.0/24',
  },
  // 4. Edge-case knowledge, not just arithmetic — RFC 3021's /31 special
  // case (also called out in src/utils/cidr.ts's own usableHostsForPrefix
  // comment).
  {
    id: 'point-to-point-link',
    prompt:
      'A WAN link uses an RFC 3021 point-to-point IPv4 addressing scheme with just two host addresses and no separate network/broadcast address: 10.255.255.0 and 10.255.255.1. Build the smallest CIDR block containing both.',
    testCases: [
      { text: '10.255.255.0', shouldMatch: true },
      { text: '10.255.255.1', shouldMatch: true },
      { text: '10.255.254.255', shouldMatch: false },
      { text: '10.255.255.2', shouldMatch: false },
    ],
    explanation:
      'RFC 3021 repurposes /31 for exactly this case — a 2-address block with no wasted network/broadcast address, both addresses usable as hosts. 10.255.255.0/31 covers precisely 10.255.255.0 and .1, with the neighboring addresses on either side falling outside it.',
    hint: 'Two addresses total means 2¹ = 2, so the prefix is 32 − 1 = 31. A /31 is a documented special case (RFC 3021) — a two-host link with no dedicated network/broadcast address.',
    referenceSolution: '10.255.255.0/31',
    // One size too big: a /30 reaches .3, so 10.255.255.2 shows as inside.
    // The readout's own usable-host line is the tell — a /30 spends two of
    // its four addresses on network + broadcast, which is exactly what RFC
    // 3021's /31 exists to avoid.
    subnetStart: '10.255.255.0/30',
  },
  // 5. Real supernetting — the two addresses differ in the third octet, so
  // no /24 (or even /16) can cover both; the aligned block that does is
  // noticeably bigger than either address needs on its own.
  {
    id: 'supernet-two-far-apart',
    prompt:
      'An incident report references two hosts inside the same site allocation: 10.4.1.5 and 10.7.254.20. Build the smallest single CIDR block that contains both addresses.',
    testCases: [
      { text: '10.4.1.5', shouldMatch: true },
      { text: '10.7.254.20', shouldMatch: true },
      { text: '10.3.255.255', shouldMatch: false },
      { text: '10.8.0.0', shouldMatch: false },
    ],
    explanation:
      '10.4.1.5 and 10.7.254.20 are far enough apart (third octet 4 vs. 7) that no /24, or even /16, covers both while staying aligned — the smallest block that does is 10.4.0.0/14, spanning 10.4.0.0 through 10.7.255.255. That’s a real supernetting move: the covering block is much bigger than either address individually needs, but it’s the smallest one that’s actually valid.',
    hint: 'Start from a small block and keep widening (lower the prefix number) until BOTH addresses land inside it. Since the addresses differ in the third octet, you’ll need more than a /16.',
    referenceSolution: '10.4.0.0/14',
    // A /16 covers 10.4.x only — 10.7.254.20 sits outside it, so the learner
    // has to keep widening past the octet boundary the eye wants to stop at.
    subnetStart: '10.4.0.0/16',
  },
  // 6. Real IANA data (distinct from the three category-recall questions'
  // own ranges), sized as an odd (non-byte-aligned) supernet prefix.
  {
    id: 'benchmarking-real-range',
    prompt:
      "An analyst wants a single rule that flags any traffic from IANA's benchmarking address space (RFC 2544) — reserved for testing network-interconnect throughput so a benchmark never floods a real internet address. A benchmarking host lives at 198.18.0.1, another at 198.19.255.254. Build the CIDR block that covers the whole benchmarking range.",
    testCases: [
      { text: '198.18.0.1', shouldMatch: true },
      { text: '198.19.255.254', shouldMatch: true },
      { text: '198.17.255.255', shouldMatch: false },
      { text: '198.20.0.0', shouldMatch: false },
    ],
    explanation:
      'IANA reserves 198.18.0.0/15 for benchmarking (RFC 2544) — a /15 spans two consecutive /16s (198.18.0.0–198.19.255.255), exactly the range needed to cover both sample hosts while stopping at the surrounding address space.',
    hint: 'The two sample addresses sit at opposite ends of a block bigger than a single /16 — try widening from /16 until both fit, then check exactly where the result starts and ends.',
    referenceSolution: '198.18.0.0/15',
    // Half the real range — 198.19.255.254 falls outside a single /16.
    subnetStart: '198.18.0.0/16',
    referenceHref: BENCHMARKING_REF?.url,
    referenceLabel: BENCHMARKING_REF?.name,
  },
  // 7. Capstone — supernetting across two adjacent /24s, plus the
  // "supernetting can swallow address space you didn't ask for" lesson
  // src/utils/cidr.ts's own supernetFor() comment calls out explicitly.
  {
    id: 'capstone-adjacent-supernet',
    prompt:
      "A report cites hosts at 203.0.113.10 and 203.0.114.250 — addresses in two adjacent /24s from this site's own documentation-range examples. Build the smallest single CIDR block that contains both addresses.",
    testCases: [
      { text: '203.0.113.10', shouldMatch: true },
      { text: '203.0.114.250', shouldMatch: true },
      { text: '203.0.111.255', shouldMatch: false },
      { text: '203.0.116.0', shouldMatch: false },
    ],
    explanation:
      "203.0.113.10 and 203.0.114.250 sit in two different /24s, so the smallest block that contains both is 203.0.112.0/22 — spanning 203.0.112.0 through 203.0.115.255. Notice that block also swallows 203.0.112.0/24 and 203.0.115.0/24, neither of which was asked for: that's inherent to supernetting, not a mistake — there's no smaller single CIDR block that covers two addresses this far apart.",
    hint: 'The two addresses are in different /24s, one octet apart — the smallest aligned block containing both will be considerably larger than either /24 alone.',
    referenceSolution: '203.0.112.0/22',
    // Covers the first host only — and widening it in place to a /23 still
    // won't reach .114, since 203.0.113.0 isn't a /23 boundary. Watching the
    // readout's own network address snap back is the lesson.
    subnetStart: '203.0.113.0/24',
    referenceHref: '/tools/cidr-calculator/',
    referenceLabel: "Try it in the CIDR & VLAN Calculator's Supernet mode",
  },
];

/** Parses `userAnswer` with the real parseCidr()/parseIPv4() and checks
 *  every one of `scenario.testCases` for containment in the resulting
 *  network..broadcast range — the CIDR-drill equivalent of regexDrill.ts's
 *  own validateChallenge(), which compiles+runs a user pattern against
 *  string test cases instead of checking address containment. */
function validateSubnetScenario(scenario: SubnetScenario, userAnswer: string): DrillValidateResult {
  const parsed = parseCidr(userAnswer);
  if (!parsed) {
    return { ok: false as const, error: 'Not a valid CIDR block — expected an IPv4 address and prefix, e.g. 10.0.0.0/24.' };
  }
  const networkInt = parseIPv4(parsed.network)!;
  const broadcastInt = parseIPv4(parsed.broadcast)!;
  const results: DrillTestCaseResult[] = scenario.testCases.map((tc) => {
    const addrInt = parseIPv4(tc.text);
    const actualMatch = addrInt !== null && addrInt >= networkInt && addrInt <= broadcastInt;
    return { text: tc.text, shouldMatch: tc.shouldMatch, actualMatch };
  });
  const pass = results.every((r) => r.actualMatch === r.shouldMatch);
  return { ok: true as const, pass, results };
}

function subnetQuestion(scenario: SubnetScenario): IpCidrDrillQuestion {
  return {
    prompt: scenario.prompt,
    explanation: scenario.explanation,
    referenceHref: scenario.referenceHref,
    referenceLabel: scenario.referenceLabel,
    answerType: 'subnet' as const,
    correctAnswer: scenario.referenceSolution,
    testCases: scenario.testCases,
    subnetStart: scenario.subnetStart,
    hint: scenario.hint,
    validate: (userAnswer: string) => validateSubnetScenario(scenario, userAnswer),
    // The builder's pure seam, INJECTED rather than imported by
    // drillEngine.ts — that engine ships on six drill pages and must not
    // pull this module (and ipRanges.ts's tables) into all of them just to
    // do IPv4 math for one. Same shape as `validate` above: the drill owns
    // the logic, the engine owns the DOM.
    subnetBuild: controlsToCidr,
    subnetParse: cidrToControls,
    subnetPreview,
  };
}

// Category recall stays at the same three positions (1, 4, 7) it occupied
// before this drill was reworked — everything else is now a "build the
// CIDR" subnet scenario, ordered easiest to hardest.
const QUESTIONS: IpCidrDrillQuestion[] = [
  subnetQuestion(SUBNET_SCENARIOS[0]), // single-clean-block
  categoryQuestion('100.64.0.0/10', '100.64.55.10'),
  subnetQuestion(SUBNET_SCENARIOS[1]), // boundary-exclude-size-bump
  subnetQuestion(SUBNET_SCENARIOS[2]), // three-exclude
  categoryQuestion('169.254.0.0/16', '169.254.10.5'),
  subnetQuestion(SUBNET_SCENARIOS[3]), // point-to-point-link
  subnetQuestion(SUBNET_SCENARIOS[4]), // supernet-two-far-apart
  categoryQuestion('192.0.2.0/24', '192.0.2.55'),
  subnetQuestion(SUBNET_SCENARIOS[5]), // benchmarking-real-range
  subnetQuestion(SUBNET_SCENARIOS[6]), // capstone-adjacent-supernet
];

export function getIpCidrQuestion(index: number): IpCidrDrillQuestion {
  return QUESTIONS[((index % QUESTIONS.length) + QUESTIONS.length) % QUESTIONS.length];
}

// ── Builder ⟷ CIDR seam (pure, unit-tested) ───────────────────────────────
// drillEngine.ts's 'subnet' renderer owns DOM only: it reads the four octet
// controls + the prefix slider, hands the numbers to controlsToCidr(), and
// paints whatever subnetPreview() hands back. Every bit of actual subnet
// arithmetic stays here, delegated to src/utils/cidr.ts — the engine never
// masks, shifts, or counts anything itself.

/** Joins four octet values + a prefix length into a CIDR string, clamping
 *  each input to its legal range and flooring to an integer — so a control
 *  that somehow reports 300, -1, or 24.5 still yields a parseable block
 *  rather than a string parseCidr() would reject. */
export function controlsToCidr(octets: number[], prefix: number): string {
  const clamp = (v: number, max: number) => {
    const n = Math.floor(Number(v));
    if (!Number.isFinite(n)) return 0;
    return Math.min(Math.max(n, 0), max);
  };
  const four = [0, 1, 2, 3].map((i) => clamp(octets[i] ?? 0, 255));
  return `${four.join('.')}/${clamp(prefix, 32)}`;
}

/** The inverse: splits a CIDR string into the values the builder's controls
 *  should show. Returns the address exactly as written (via parseCidr's own
 *  `ip`), NOT the network address — typing 10.30.6.5/28 should leave the
 *  octet controls on .5 while the readout separately reports the block's
 *  real network address, which is the whole point of the readout. */
export function cidrToControls(cidr: string): { octets: number[]; prefix: number } | null {
  const parsed = parseCidr(cidr);
  if (!parsed) return null;
  return { octets: parsed.ip.split('.').map(Number), prefix: parsed.prefix };
}

/** Everything the builder's live readout shows, derived entirely from
 *  parseCidr(). Null for an unparseable block (the readout then shows
 *  em-dashes rather than stale values from the last valid state). The
 *  `note` covers the two prefixes whose host range doesn't mean what it
 *  does everywhere else: /31 (RFC 3021 point-to-point, both addresses
 *  usable) and /32 (a single host, no network/broadcast pair). */
export function subnetPreview(cidr: string): DrillSubnetPreview | null {
  const parsed = parseCidr(cidr);
  if (!parsed) return null;
  const hostRange =
    parsed.firstHost && parsed.lastHost
      ? parsed.firstHost === parsed.lastHost
        ? parsed.firstHost
        : `${parsed.firstHost} – ${parsed.lastHost}`
      : 'none';
  let note: string | undefined;
  if (parsed.prefix === 31) note = 'RFC 3021 point-to-point — both addresses are usable hosts.';
  else if (parsed.prefix === 32) note = 'Single host — no network or broadcast address.';
  return {
    cidr: parsed.input,
    prefix: parsed.prefix,
    network: parsed.network,
    broadcast: parsed.broadcast,
    netmask: parsed.netmask,
    hostRange,
    usableHosts: parsed.usableHosts,
    totalHosts: parsed.totalHosts,
    note,
  };
}
