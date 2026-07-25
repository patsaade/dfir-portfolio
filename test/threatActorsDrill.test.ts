import { describe, it, expect } from 'vitest';
import { getThreatActorsQuestion, THREAT_ACTORS_DRILL_TOTAL } from '../src/data/drills/threatActorsDrill';
import { THREAT_ACTORS } from '../src/data/threatActors';
import { VENDOR_NAMING_SCHEMES } from '../src/data/threatActorNaming';

const apt29 = THREAT_ACTORS.find((a) => a.id === 'G0016')!;
const lazarus = THREAT_ACTORS.find((a) => a.id === 'G0032')!;
const fin7 = THREAT_ACTORS.find((a) => a.id === 'G0046')!;

// Helper for the namingConvention/applyNaming cross-checks below: find a
// vendor's own scheme by name, and assert it actually exists (a typo'd
// vendor name here would otherwise silently pass every other assertion).
function mustGetScheme(vendor: string) {
  const s = VENDOR_NAMING_SCHEMES.find((x) => x.vendor === vendor);
  expect(s, `no VENDOR_NAMING_SCHEMES entry for "${vendor}"`).toBeDefined();
  return s!;
}
function mustGetMapping(vendor: string, code: string) {
  const scheme = mustGetScheme(vendor);
  const m = scheme.mappings.find((x) => x.code === code);
  expect(m, `no "${code}" mapping in ${vendor}'s VENDOR_NAMING_SCHEMES entry`).toBeDefined();
  return m!;
}

describe('getThreatActorsQuestion', () => {
  it('is deterministic for a given index (required for the no-JS SSR/hydration contract)', () => {
    for (let i = 0; i < THREAT_ACTORS_DRILL_TOTAL; i++) {
      const a = getThreatActorsQuestion(i);
      const b = getThreatActorsQuestion(i);
      expect(b.prompt).toBe(a.prompt);
      expect(b.explanation).toBe(a.explanation);
      expect(b.correctAnswer).toBe(a.correctAnswer);
    }
  });

  it('wraps safely for an out-of-range index instead of throwing', () => {
    expect(() => getThreatActorsQuestion(THREAT_ACTORS_DRILL_TOTAL)).not.toThrow();
    expect(getThreatActorsQuestion(THREAT_ACTORS_DRILL_TOTAL).prompt).toBe(getThreatActorsQuestion(0).prompt);
    // A large multiple should wrap the same way negative indices don't occur in practice, but modulo math
    // should still be safe for any positive multiple of the total.
    expect(getThreatActorsQuestion(THREAT_ACTORS_DRILL_TOTAL * 3 + 2).prompt).toBe(getThreatActorsQuestion(2).prompt);
  });

  it('no question is multiple choice — every question is free-text recall', () => {
    for (let i = 0; i < THREAT_ACTORS_DRILL_TOTAL; i++) {
      const q = getThreatActorsQuestion(i);
      expect(q.answerType).toBe('text');
      expect(q.choices).toBeUndefined();
    }
  });

  it('no question is a bare ID/technique recall (this drill deliberately excludes pure memorization)', () => {
    for (let i = 0; i < THREAT_ACTORS_DRILL_TOTAL; i++) {
      const q = getThreatActorsQuestion(i);
      expect(q.prompt).not.toMatch(/MITRE ATT&CK group ID/i);
      expect(q.prompt).not.toMatch(/technique ID documented for/i);
    }
  });

  it('every question has a non-empty prompt/explanation/hint, a working grade() that accepts its own correctAnswer and rejects an obviously wrong answer, and a real reference link into /threat-actors/', () => {
    for (let i = 0; i < THREAT_ACTORS_DRILL_TOTAL; i++) {
      const q = getThreatActorsQuestion(i);
      expect(q.prompt.length).toBeGreaterThan(0);
      expect(q.explanation.length).toBeGreaterThan(0);
      expect(q.hint && q.hint.length).toBeGreaterThan(0);
      expect(typeof q.grade).toBe('function');
      expect(q.grade!(q.correctAnswer), `question ${i} grade() rejected its own correctAnswer "${q.correctAnswer}"`).toBe(true);
      expect(q.grade!('definitely not a real threat actor fact'), `question ${i} grade() accepted an obviously wrong answer`).toBe(
        false,
      );
      // Either a specific group's profile page (the group-derived modes) or
      // the reference's own "Naming conventions" section anchor (the
      // namingConvention/applyNaming modes — those facts aren't about any
      // one group, see threatActorsDrill.ts's header comment) — both are
      // real, working links into /threat-actors/, just two legitimately
      // different target shapes.
      const isGroupProfile = /^\/threat-actors\/[a-z0-9-]+\/$/.test(q.referenceHref ?? '');
      const isNamingSection = q.referenceHref === '/threat-actors/#naming-conventions';
      expect(isGroupProfile || isNamingSection, `question ${i} has an unexpected referenceHref "${q.referenceHref}"`).toBe(true);
    }
  });

  it('every challenge has a unique prompt (no duplicated lesson)', () => {
    const all = Array.from({ length: THREAT_ACTORS_DRILL_TOTAL }, (_, i) => getThreatActorsQuestion(i));
    const prompts = all.map((q) => q.prompt);
    expect(new Set(prompts).size).toBe(prompts.length);
  });

  it('#0 aliasToName: "Cozy Bear" -> APT29', () => {
    expect(apt29.aliases).toContain('Cozy Bear');
    const q = getThreatActorsQuestion(0);
    expect(q.prompt).toContain('Cozy Bear');
    expect(q.correctAnswer).toBe('APT29');
    expect(q.grade!('APT29')).toBe(true);
    expect(q.grade!('apt29')).toBe(true);
    expect(q.grade!('The Dukes')).toBe(true); // another real APT29 alias
    expect(q.grade!('APT28')).toBe(false);
  });

  it('#1 clueToName: FSB "Center 16" / critical infrastructure clue -> Dragonfly', () => {
    const q = getThreatActorsQuestion(1);
    expect(q.correctAnswer).toBe('Dragonfly');
    expect(q.grade!('Dragonfly')).toBe(true);
    expect(q.grade!('dragonfly')).toBe(true);
    expect(q.grade!('Turla')).toBe(false); // also FSB, but not "Center 16"
  });

  it('#2 clueToName: Uroburos malware clue -> Turla', () => {
    const q = getThreatActorsQuestion(2);
    expect(q.prompt).toContain('Uroburos');
    expect(q.correctAnswer).toBe('Turla');
    expect(q.grade!('Turla')).toBe(true);
    expect(q.grade!('turla')).toBe(true);
    expect(q.grade!('Dragonfly')).toBe(false);
  });

  it('#3 clueToName: Combi Security front company clue -> FIN7', () => {
    const q = getThreatActorsQuestion(3);
    expect(q.correctAnswer).toBe('FIN7');
    expect(q.grade!('FIN7')).toBe(true);
    expect(q.grade!('Carbon Spider')).toBe(true); // a real FIN7 alias
    expect(q.grade!('Carbanak')).toBe(false); // a different, related-but-distinct MITRE group
  });

  it('#4 clueToName: Cobalt Group/FIN7 linkage clue -> Carbanak', () => {
    const q = getThreatActorsQuestion(4);
    expect(q.correctAnswer).toBe('Carbanak');
    expect(q.grade!('Carbanak')).toBe(true);
    expect(q.grade!('Anunak')).toBe(true); // a real Carbanak (G0008) alias
    expect(q.grade!('FIN7')).toBe(false);
  });

  it('#5 clueToName: native English-speaking cybercriminal group clue -> Scattered Spider', () => {
    const q = getThreatActorsQuestion(5);
    expect(q.correctAnswer).toBe('Scattered Spider');
    expect(q.grade!('Scattered Spider')).toBe(true);
    expect(q.grade!('Octo Tempest')).toBe(true); // a real Scattered Spider alias
    expect(q.grade!('FIN7')).toBe(false);
  });

  it('#6 clueToName: PLA Unit 61398 clue -> APT1', () => {
    const q = getThreatActorsQuestion(6);
    expect(q.correctAnswer).toBe('APT1');
    expect(q.grade!('APT1')).toBe(true);
    expect(q.grade!('APT28')).toBe(false);
  });

  it('#7 software: BLINDINGCAN -> Lazarus Group', () => {
    const q = getThreatActorsQuestion(7);
    expect(lazarus.software).toContain('BLINDINGCAN');
    expect(q.prompt).toContain('BLINDINGCAN');
    expect(q.correctAnswer).toBe('Lazarus Group');
    expect(q.grade!('Lazarus Group')).toBe(true);
    expect(q.grade!('lazarus group')).toBe(true);
    expect(q.grade!('HIDDEN COBRA')).toBe(true); // a real Lazarus Group alias
    expect(q.grade!('FIN7')).toBe(false);
  });

  it('#8 software: BOOSTWRITE -> FIN7', () => {
    const q = getThreatActorsQuestion(8);
    expect(fin7.software).toContain('BOOSTWRITE');
    expect(q.prompt).toContain('BOOSTWRITE');
    expect(q.correctAnswer).toBe('FIN7');
    expect(q.grade!('FIN7')).toBe(true);
    expect(q.grade!('Lazarus Group')).toBe(false);
  });

  describe('namingConvention questions (#9-17) — vendor naming STRUCTURE, verified against VENDOR_NAMING_SCHEMES rather than THREAT_ACTORS', () => {
    it('every namingConvention question points at the "Naming conventions" section, not a specific group profile', () => {
      for (let i = 9; i <= 17; i++) {
        const q = getThreatActorsQuestion(i);
        expect(q.referenceHref).toBe('/threat-actors/#naming-conventions');
        expect(q.answerType).toBe('text');
      }
    });

    it('#9: which vendor uses an animal cryptonym for nation-nexus/motivation -> CrowdStrike', () => {
      const q = getThreatActorsQuestion(9);
      expect(q.correctAnswer).toBe('CrowdStrike');
      expect(q.grade!('CrowdStrike')).toBe(true);
      expect(q.grade!('crowdstrike')).toBe(true);
      expect(q.grade!('  CrowdStrike  ')).toBe(true);
      expect(q.grade!('Microsoft')).toBe(false);
      const scheme = mustGetScheme('CrowdStrike');
      expect(scheme.mappings.some((m) => m.code === 'Bear')).toBe(true);
      expect(scheme.mappings.some((m) => m.code === 'Panda')).toBe(true);
    });

    it('#10: CrowdStrike "Panda" -> China, cross-checked against VENDOR_NAMING_SCHEMES', () => {
      const q = getThreatActorsQuestion(10);
      expect(q.correctAnswer).toBe('China');
      expect(q.grade!('China')).toBe(true);
      expect(q.grade!('china')).toBe(true);
      expect(q.grade!('Russia')).toBe(false);
      const mapping = mustGetMapping('CrowdStrike', 'Panda');
      expect(mapping.meaning).toContain('China');
    });

    it('#11: Mandiant financially-motivated prefix -> FIN, cross-checked against VENDOR_NAMING_SCHEMES', () => {
      const q = getThreatActorsQuestion(11);
      expect(q.correctAnswer).toBe('FIN');
      expect(q.grade!('FIN')).toBe(true);
      expect(q.grade!('fin')).toBe(true);
      expect(q.grade!('FIN##')).toBe(true);
      expect(q.grade!('APT')).toBe(false);
      const mapping = mustGetMapping('Mandiant / Google Threat Intelligence', 'FIN##');
      expect(mapping.meaning.toLowerCase()).toContain('financially motivated');
    });

    it('#12: Mandiant uncategorized-cluster prefix -> UNC, cross-checked against VENDOR_NAMING_SCHEMES', () => {
      const q = getThreatActorsQuestion(12);
      expect(q.correctAnswer).toBe('UNC');
      expect(q.grade!('UNC')).toBe(true);
      expect(q.grade!('unc####')).toBe(true);
      expect(q.grade!('FIN')).toBe(false);
      const mapping = mustGetMapping('Mandiant / Google Threat Intelligence', 'UNC####');
      expect(mapping.meaning.toLowerCase()).toContain('uncategorized');
    });

    it('#13: Microsoft post-2023 naming theme -> weather', () => {
      const q = getThreatActorsQuestion(13);
      expect(q.correctAnswer).toBe('weather');
      expect(q.grade!('weather')).toBe(true);
      expect(q.grade!('Weather-themed')).toBe(true);
      expect(q.grade!('chemical elements')).toBe(false);
    });

    it('#14: Microsoft "Blizzard" family -> Russia, cross-checked against VENDOR_NAMING_SCHEMES', () => {
      const q = getThreatActorsQuestion(14);
      expect(q.correctAnswer).toBe('Russia');
      expect(q.grade!('Russia')).toBe(true);
      expect(q.grade!('China')).toBe(false);
      const mapping = mustGetMapping('Microsoft', 'Blizzard');
      expect(mapping.meaning).toContain('Russia');
    });

    it('#15: Microsoft temporary-cluster prefix -> Storm, cross-checked against VENDOR_NAMING_SCHEMES', () => {
      const q = getThreatActorsQuestion(15);
      expect(q.correctAnswer).toBe('Storm');
      expect(q.grade!('Storm')).toBe(true);
      expect(q.grade!('storm-####')).toBe(true);
      expect(q.grade!('Blizzard')).toBe(false);
      expect(mustGetScheme('Microsoft').mappings.some((m) => m.code === 'Storm-####')).toBe(true);
    });

    it('#16: Secureworks "IRON" element -> Russia, cross-checked against VENDOR_NAMING_SCHEMES', () => {
      const q = getThreatActorsQuestion(16);
      expect(q.correctAnswer).toBe('Russia');
      expect(q.grade!('Russia')).toBe(true);
      expect(q.grade!('Iran')).toBe(false);
      const mapping = mustGetMapping('Secureworks Counter Threat Unit (now part of Sophos)', 'IRON');
      expect(mapping.meaning).toBe('Russia');
    });

    it('#17: MITRE\'s current name for the alias field -> Associated Groups', () => {
      const q = getThreatActorsQuestion(17);
      expect(q.correctAnswer).toBe('Associated Groups');
      expect(q.grade!('Associated Groups')).toBe(true);
      expect(q.grade!('associated groups')).toBe(true);
      expect(q.grade!('Aliases')).toBe(false);
    });
  });

  describe('applyNaming questions (#18-26) — apply a real vendor rule to a new fact pattern, cross-checked against VENDOR_NAMING_SCHEMES', () => {
    it('every applyNaming question points at the "Naming conventions" section and its correctAnswer is a real code in that vendor\'s own scheme', () => {
      const vendorsSeen = new Set<string>();
      for (let i = 18; i <= 26; i++) {
        const q = getThreatActorsQuestion(i);
        expect(q.referenceHref).toBe('/threat-actors/#naming-conventions');
        expect(q.answerType).toBe('text');
        // The prompt must name a real vendor whose scheme actually contains
        // this exact code — otherwise this would be an invented fact.
        const scheme = VENDOR_NAMING_SCHEMES.find((s) => q.referenceLabel?.includes(s.vendor));
        expect(scheme, `question ${i}: referenceLabel "${q.referenceLabel}" doesn't name a real vendor`).toBeDefined();
        expect(
          scheme!.mappings.some((m) => m.code === q.correctAnswer),
          `question ${i}: "${q.correctAnswer}" is not a real ${scheme!.vendor} mapping code`,
        ).toBe(true);
        vendorsSeen.add(scheme!.vendor);
      }
      // Covers all 3 vendors this mode draws from, not just one.
      expect(vendorsSeen.size).toBe(3);
    });

    it('#18: CrowdStrike + Russia nation-state -> Bear', () => {
      const q = getThreatActorsQuestion(18);
      expect(q.correctAnswer).toBe('Bear');
      expect(q.grade!('Bear')).toBe(true);
      expect(q.grade!('bear')).toBe(true);
      expect(q.grade!('Panda')).toBe(false);
    });

    it('#19: CrowdStrike + North Korea nation-state -> Chollima', () => {
      const q = getThreatActorsQuestion(19);
      expect(q.correctAnswer).toBe('Chollima');
      expect(q.grade!('Chollima')).toBe(true);
      expect(q.grade!('Bear')).toBe(false);
    });

    it('#20: CrowdStrike + financially motivated -> Spider', () => {
      const q = getThreatActorsQuestion(20);
      expect(q.correctAnswer).toBe('Spider');
      expect(q.grade!('Spider')).toBe(true);
      expect(q.grade!('Jackal')).toBe(false);
    });

    it('#21: Microsoft + China nation-state -> Typhoon', () => {
      const q = getThreatActorsQuestion(21);
      expect(q.correctAnswer).toBe('Typhoon');
      expect(q.grade!('Typhoon')).toBe(true);
      expect(q.grade!('Sandstorm')).toBe(false);
    });

    it('#22: Microsoft + North Korea nation-state -> Sleet', () => {
      const q = getThreatActorsQuestion(22);
      expect(q.correctAnswer).toBe('Sleet');
      expect(q.grade!('Sleet')).toBe(true);
      expect(q.grade!('Typhoon')).toBe(false);
    });

    it('#23: Microsoft + financially motivated -> Tempest', () => {
      const q = getThreatActorsQuestion(23);
      expect(q.correctAnswer).toBe('Tempest');
      expect(q.grade!('Tempest')).toBe(true);
      expect(q.grade!('Blizzard')).toBe(false);
    });

    it('#24: Secureworks + China -> BRONZE', () => {
      const q = getThreatActorsQuestion(24);
      expect(q.correctAnswer).toBe('BRONZE');
      expect(q.grade!('BRONZE')).toBe(true);
      expect(q.grade!('bronze')).toBe(true);
      expect(q.grade!('IRON')).toBe(false);
    });

    it('#25: Secureworks + North Korea -> NICKEL', () => {
      const q = getThreatActorsQuestion(25);
      expect(q.correctAnswer).toBe('NICKEL');
      expect(q.grade!('NICKEL')).toBe(true);
      expect(q.grade!('BRONZE')).toBe(false);
    });

    it('#26: Secureworks + financially motivated/cybercrime -> GOLD', () => {
      const q = getThreatActorsQuestion(26);
      expect(q.correctAnswer).toBe('GOLD');
      expect(q.grade!('GOLD')).toBe(true);
      expect(q.grade!('IRON')).toBe(false);
    });
  });

  it('every acceptableAnswers-graded question accepts its own displayed correctAnswer (so a learner who types the exact displayed answer is never marked wrong)', () => {
    for (let i = 9; i < THREAT_ACTORS_DRILL_TOTAL; i++) {
      const q = getThreatActorsQuestion(i);
      expect(q.grade!(q.correctAnswer), `question ${i}: grade() rejected its own correctAnswer`).toBe(true);
    }
  });
});
