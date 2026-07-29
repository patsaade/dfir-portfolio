import { describe, it, expect } from 'vitest';
import { getIpCidrQuestion, controlsToCidr, cidrToControls, subnetPreview } from '../src/data/drills/ipCidr';

const TOTAL = 10;
// Category recall stayed at the same three positions the original bank used;
// everything else is now a "build the CIDR" subnet scenario.
const TEXT_INDEXES = [1, 4, 7];
const SUBNET_INDEXES = [0, 2, 3, 5, 6, 8, 9];

describe('getIpCidrQuestion', () => {
  it('is deterministic for a given index (required for the no-JS SSR/hydration contract)', () => {
    for (let i = 0; i < TOTAL; i++) {
      const a = getIpCidrQuestion(i);
      const b = getIpCidrQuestion(i);
      expect(b.prompt).toBe(a.prompt);
      expect(b.explanation).toBe(a.explanation);
      expect(b.correctAnswer).toBe(a.correctAnswer);
      expect(b.testCases).toEqual(a.testCases);
    }
  });

  it('wraps safely for an out-of-range index instead of throwing', () => {
    expect(() => getIpCidrQuestion(TOTAL)).not.toThrow();
    expect(getIpCidrQuestion(TOTAL).prompt).toBe(getIpCidrQuestion(0).prompt);
  });

  it('the three category-recognition questions are free-text recall; the seven CIDR-building questions use the interactive subnet builder', () => {
    for (let i = 0; i < TOTAL; i++) {
      const q = getIpCidrQuestion(i);
      if (TEXT_INDEXES.includes(i)) {
        expect(q.answerType).toBe('text');
        expect(q.testCases).toBeUndefined();
        expect(q.subnetStart, `text question ${i} shouldn't carry builder state`).toBeUndefined();
      } else {
        expect(SUBNET_INDEXES, `index ${i} is neither a known text nor subnet index`).toContain(i);
        expect(q.answerType).toBe('subnet');
      }
    }
    expect(TEXT_INDEXES.length + SUBNET_INDEXES.length).toBe(TOTAL);
  });

  it('every question has a non-empty prompt/explanation; text questions have a working grade() that accepts their own correctAnswer', () => {
    for (let i = 0; i < TOTAL; i++) {
      const q = getIpCidrQuestion(i);
      expect(q.prompt.length).toBeGreaterThan(0);
      expect(q.explanation.length).toBeGreaterThan(0);
      if (q.answerType === 'text') {
        expect(typeof q.grade).toBe('function');
        expect(q.grade!(q.correctAnswer!), `question ${i} grade() rejected its own correctAnswer "${q.correctAnswer}"`).toBe(true);
        expect(q.grade!('definitely-wrong'), `question ${i} grade() accepted an obviously wrong answer`).toBe(false);
      }
    }
  });

  it('the three category-recognition questions (100.64.0.0/10, 169.254.0.0/16, 192.0.2.0/24) accept both the hyphenated id and the human label, case/hyphen-insensitively', () => {
    const cgnat = getIpCidrQuestion(1);
    expect(cgnat.correctAnswer).toBe('Shared address space (CGNAT)');
    expect(cgnat.grade!('shared-address-space')).toBe(true);
    expect(cgnat.grade!('Shared Address Space')).toBe(true);
    expect(cgnat.grade!('private-use')).toBe(false);

    const linkLocal = getIpCidrQuestion(4);
    expect(linkLocal.correctAnswer).toBe('Link-local');
    expect(linkLocal.grade!('link local')).toBe(true);
    expect(linkLocal.grade!('Link-Local')).toBe(true);

    const documentation = getIpCidrQuestion(7);
    expect(documentation.correctAnswer).toBe('Documentation');
    expect(documentation.grade!('documentation')).toBe(true);
    expect(documentation.grade!('multicast')).toBe(false);
  });

  it('every subnet question has a validate() function, at least one must-include and one must-NOT-include address, and a non-empty hint', () => {
    for (const i of SUBNET_INDEXES) {
      const q = getIpCidrQuestion(i);
      expect(typeof q.validate).toBe('function');
      expect(q.testCases && q.testCases.length).toBeGreaterThan(0);
      const hasInclude = q.testCases!.some((tc) => tc.shouldMatch);
      const hasExclude = q.testCases!.some((tc) => !tc.shouldMatch);
      expect(hasInclude, `question ${i} has no must-include address`).toBe(true);
      expect(hasExclude, `question ${i} has no must-NOT-include address`).toBe(true);
      expect(q.hint && q.hint.length).toBeGreaterThan(0);
    }
  });

  it("every subnet question's reference CIDR actually passes its own scenario, via the real validate() the UI calls (the whole question shape's core guarantee)", () => {
    for (const i of SUBNET_INDEXES) {
      const q = getIpCidrQuestion(i);
      const outcome = q.validate!(q.correctAnswer!);
      expect(outcome.ok, `question ${i} reference CIDR "${q.correctAnswer}" failed to parse`).toBe(true);
      if (outcome.ok) {
        expect(outcome.pass, `question ${i} reference CIDR didn't pass its own scenario: ${JSON.stringify(outcome.results)}`).toBe(true);
      }
    }
  });

  it('an obviously unrelated /32 fails every subnet question (proves validate() actually discriminates containment, not just returns true)', () => {
    for (const i of SUBNET_INDEXES) {
      const q = getIpCidrQuestion(i);
      const outcome = q.validate!('1.2.3.4/32');
      expect(outcome.ok).toBe(true);
      if (outcome.ok) expect(outcome.pass).toBe(false);
    }
  });

  it('an invalid CIDR string is reported as a parse error, not a silent failure or a throw', () => {
    for (const i of SUBNET_INDEXES) {
      const q = getIpCidrQuestion(i);
      expect(() => q.validate!('not-a-cidr')).not.toThrow();
      const outcome = q.validate!('not-a-cidr');
      expect(outcome.ok).toBe(false);
      if (!outcome.ok) expect(outcome.error && outcome.error.length).toBeGreaterThan(0);
    }
  });

  it('single-clean-block (Q0): an oversized guess wrongly includes the exclude addresses too, and correctly fails', () => {
    const q = getIpCidrQuestion(0);
    const outcome = q.validate!('10.30.0.0/16'); // way too big -- swallows both "exclude" addresses
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.pass).toBe(false);
  });

  it('boundary-exclude-size-bump (Q2): the naive smallest-looking guess (/25) undershoots and fails', () => {
    const q = getIpCidrQuestion(2);
    const outcome = q.validate!('172.20.14.0/25'); // only reaches .0-.127, misses .200
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.pass).toBe(false);
  });

  it('three-exclude (Q3): a too-small block misses a required address, and a too-big block wrongly includes the near excludes', () => {
    const q = getIpCidrQuestion(3);
    const tooSmall = q.validate!('10.50.8.64/28'); // only .64-.79, misses .95
    expect(tooSmall.ok).toBe(true);
    if (tooSmall.ok) expect(tooSmall.pass).toBe(false);

    const tooBig = q.validate!('10.50.8.0/24'); // wrongly includes .63 and .96
    expect(tooBig.ok).toBe(true);
    if (tooBig.ok) expect(tooBig.pass).toBe(false);
  });

  it('point-to-point-link (Q5): a /32 (single host) fails because it can only ever contain one of the two required addresses', () => {
    const q = getIpCidrQuestion(5);
    const outcome = q.validate!('10.255.255.0/32');
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.pass).toBe(false);
  });

  it('supernet-two-far-apart (Q6): a /16 undershoots (misses the second address entirely)', () => {
    const q = getIpCidrQuestion(6);
    const outcome = q.validate!('10.4.0.0/16');
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.pass).toBe(false);
  });

  it('benchmarking-real-range (Q8): a single /16 undershoots (misses the second half of the real /15)', () => {
    const q = getIpCidrQuestion(8);
    const outcome = q.validate!('198.18.0.0/16');
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.pass).toBe(false);
  });

  it('capstone-adjacent-supernet (Q9): a single /24 undershoots (misses the address in the adjacent /24)', () => {
    const q = getIpCidrQuestion(9);
    const outcome = q.validate!('203.0.113.0/24');
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.pass).toBe(false);
  });

  it('every subnet question has a distinct reference CIDR and no duplicated test-case addresses within its own scenario', () => {
    const solutions = SUBNET_INDEXES.map((i) => getIpCidrQuestion(i).correctAnswer);
    expect(new Set(solutions).size).toBe(solutions.length);
    for (const i of SUBNET_INDEXES) {
      const q = getIpCidrQuestion(i);
      const addrs = q.testCases!.map((tc) => tc.text);
      expect(new Set(addrs).size, `question ${i} has a duplicated test-case address`).toBe(addrs.length);
    }
  });
});

// The 'subnet' answerType's own contract with DrillEngine: every question
// hands the engine a starting block plus the three pure helpers the builder
// drives its controls and readout with. drillEngine.ts does no subnet math
// of its own, so if these are wrong the builder is wrong — and there's no
// DOM in this test environment to catch it downstream.
describe("'subnet' builder contract", () => {
  it('every subnet question ships a starting block and all three builder helpers', () => {
    for (const i of SUBNET_INDEXES) {
      const q = getIpCidrQuestion(i);
      expect(typeof q.subnetStart, `question ${i} has no subnetStart`).toBe('string');
      expect(typeof q.subnetBuild).toBe('function');
      expect(typeof q.subnetParse).toBe('function');
      expect(typeof q.subnetPreview).toBe('function');
    }
  });

  it('every starting block is a real, parseable CIDR the builder can open on', () => {
    for (const i of SUBNET_INDEXES) {
      const q = getIpCidrQuestion(i);
      const controls = q.subnetParse!(q.subnetStart!);
      expect(controls, `question ${i} starting block "${q.subnetStart}" doesn't parse`).not.toBeNull();
      expect(controls!.octets).toHaveLength(4);
      expect(q.subnetPreview!(q.subnetStart!)).not.toBeNull();
    }
  });

  it('no question opens already solved — every starting block FAILS its own validate()', () => {
    for (const i of SUBNET_INDEXES) {
      const q = getIpCidrQuestion(i);
      const outcome = q.validate!(q.subnetStart!);
      expect(outcome.ok, `question ${i} starting block failed to parse`).toBe(true);
      if (outcome.ok) {
        expect(
          outcome.pass,
          `question ${i} opens on "${q.subnetStart}", which already passes — the builder would start solved`,
        ).toBe(false);
      }
      expect(q.subnetStart).not.toBe(q.correctAnswer);
    }
  });

  it('the builder can express every reference answer: parse → rebuild → validate still passes', () => {
    // This is the round trip the UI actually performs on every control move
    // (syncInputFromControls in drillEngine.ts): read the octet/prefix
    // values, rebuild the CIDR string, grade it. If a reference answer
    // couldn't survive that trip, the question would be unsolvable with the
    // sliders even though typing it works.
    for (const i of SUBNET_INDEXES) {
      const q = getIpCidrQuestion(i);
      const controls = q.subnetParse!(q.correctAnswer!);
      expect(controls, `question ${i} reference "${q.correctAnswer}" doesn't parse back into controls`).not.toBeNull();
      const rebuilt = q.subnetBuild!(controls!.octets, controls!.prefix);
      expect(rebuilt, `question ${i} round-tripped to "${rebuilt}" instead of "${q.correctAnswer}"`).toBe(q.correctAnswer);
      const outcome = q.validate!(rebuilt);
      expect(outcome.ok).toBe(true);
      if (outcome.ok) expect(outcome.pass, `question ${i}'s rebuilt reference answer stopped passing`).toBe(true);
    }
  });

  it("every starting block's own live readout is real derived math, not a placeholder", () => {
    for (const i of SUBNET_INDEXES) {
      const q = getIpCidrQuestion(i);
      const p = q.subnetPreview!(q.subnetStart!)!;
      // The network address of the starting block must actually be the
      // masked form, and the block must span exactly 2^(32-prefix).
      expect(p.totalHosts).toBe(2 ** (32 - p.prefix));
      expect(p.network).toBe(subnetPreview(p.network + '/' + p.prefix)!.network);
      expect(p.netmask.split('.')).toHaveLength(4);
      expect(p.hostRange.length).toBeGreaterThan(0);
    }
  });
});

describe('controlsToCidr / cidrToControls (builder ⟷ CIDR seam)', () => {
  it('joins control values into a CIDR string', () => {
    expect(controlsToCidr([10, 30, 6, 0], 28)).toBe('10.30.6.0/28');
    expect(controlsToCidr([0, 0, 0, 0], 0)).toBe('0.0.0.0/0');
    expect(controlsToCidr([255, 255, 255, 255], 32)).toBe('255.255.255.255/32');
  });

  it('clamps out-of-range and non-integer control values instead of emitting an unparseable block', () => {
    // A number input can legitimately report 999 (typed) or a float; the
    // result still has to be something parseCidr() accepts.
    expect(controlsToCidr([999, -4, 24.7, 10], 99)).toBe('255.0.24.10/32');
    expect(controlsToCidr([Number.NaN, 1, 2, 3], Number.NaN)).toBe('0.1.2.3/0');
    expect(cidrToControls(controlsToCidr([999, -4, 24.7, 10], 99))).not.toBeNull();
  });

  it('pads a short octet array rather than producing a malformed address', () => {
    expect(controlsToCidr([10, 1], 24)).toBe('10.1.0.0/24');
  });

  it('parses a CIDR back into control values, keeping the address AS TYPED (not the network address)', () => {
    // The readout is what reports the real network address; snapping the
    // octet controls to it would silently rewrite what the learner typed.
    expect(cidrToControls('10.30.6.5/28')).toEqual({ octets: [10, 30, 6, 5], prefix: 28 });
    expect(cidrToControls('192.0.2.0/24')).toEqual({ octets: [192, 0, 2, 0], prefix: 24 });
  });

  it('returns null for anything unparseable, so the controls can stay put mid-typing', () => {
    expect(cidrToControls('')).toBeNull();
    expect(cidrToControls('10.0.0.0')).toBeNull();
    expect(cidrToControls('10.0.0.0/')).toBeNull();
    expect(cidrToControls('10.0.0.0/33')).toBeNull();
    expect(cidrToControls('999.0.0.0/24')).toBeNull();
    expect(cidrToControls('not-a-cidr')).toBeNull();
  });

  it('round-trips any valid block through both directions unchanged', () => {
    for (const cidr of ['10.30.6.0/28', '172.20.14.0/24', '198.18.0.0/15', '10.255.255.0/31', '203.0.112.0/22']) {
      const c = cidrToControls(cidr)!;
      expect(controlsToCidr(c.octets, c.prefix)).toBe(cidr);
    }
  });
});

describe('subnetPreview (the builder live readout)', () => {
  it('derives network, broadcast, netmask, host range and counts from the real CIDR math', () => {
    const p = subnetPreview('10.30.6.5/28')!;
    expect(p.prefix).toBe(28);
    expect(p.network).toBe('10.30.6.0');
    expect(p.broadcast).toBe('10.30.6.15');
    expect(p.netmask).toBe('255.255.255.240');
    expect(p.hostRange).toBe('10.30.6.1 – 10.30.6.14');
    expect(p.usableHosts).toBe(14);
    expect(p.totalHosts).toBe(16);
    expect(p.note).toBeUndefined();
  });

  it('reports a /31 as an RFC 3021 point-to-point link with both addresses usable', () => {
    const p = subnetPreview('10.255.255.0/31')!;
    expect(p.network).toBe('10.255.255.0');
    expect(p.broadcast).toBe('10.255.255.1');
    expect(p.usableHosts).toBe(2);
    expect(p.totalHosts).toBe(2);
    expect(p.hostRange).toBe('10.255.255.0 – 10.255.255.1');
    expect(p.note).toMatch(/3021/);
  });

  it('reports a /32 as a single host, with no range implying two endpoints', () => {
    const p = subnetPreview('192.0.2.55/32')!;
    expect(p.totalHosts).toBe(1);
    expect(p.usableHosts).toBe(1);
    expect(p.hostRange).toBe('192.0.2.55');
    expect(p.note).toMatch(/[Ss]ingle host/);
  });

  it('handles the whole address space at /0 without special-casing', () => {
    const p = subnetPreview('0.0.0.0/0')!;
    expect(p.network).toBe('0.0.0.0');
    expect(p.broadcast).toBe('255.255.255.255');
    expect(p.totalHosts).toBe(2 ** 32);
  });

  it('returns null for an unparseable block so the readout can blank rather than go stale', () => {
    expect(subnetPreview('10.0.0.0')).toBeNull();
    expect(subnetPreview('10.0.0.0/33')).toBeNull();
    expect(subnetPreview('')).toBeNull();
  });
});
