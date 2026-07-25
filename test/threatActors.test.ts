import { describe, it, expect } from 'vitest';
import {
  THREAT_ACTORS,
  THREAT_ACTORS_TOTAL,
  THREAT_ACTORS_ATTACK_VERSION,
  threatActorSlug,
  threatActorBySlug,
} from '../src/data/threatActors';
import { resolveAttackLink } from '../src/data/references';

const ids = new Set(THREAT_ACTORS.map((a) => a.id));
const slugs = THREAT_ACTORS.map((a) => threatActorSlug(a.name));

describe('threat actors dataset', () => {
  it('matches its own reported total and has a substantial number of real groups', () => {
    expect(THREAT_ACTORS.length).toBe(THREAT_ACTORS_TOTAL);
    expect(THREAT_ACTORS.length).toBeGreaterThan(100);
  });

  it('records the ATT&CK version it was generated from', () => {
    expect(THREAT_ACTORS_ATTACK_VERSION).toMatch(/^\d+(\.\d+)*$/);
  });

  it('uses unique MITRE group ids', () => {
    expect(ids.size).toBe(THREAT_ACTORS.length);
    for (const a of THREAT_ACTORS) expect(a.id).toMatch(/^G\d{4}$/);
  });

  it('derives unique URL slugs from group names (no two groups collide)', () => {
    expect(new Set(slugs).size).toBe(THREAT_ACTORS.length);
    for (const s of slugs) expect(s.length).toBeGreaterThan(0);
  });

  it('gives every group a non-empty name, summary, description, and canonical MITRE url', () => {
    for (const a of THREAT_ACTORS) {
      expect(a.name.length).toBeGreaterThan(0);
      expect(a.summary.length).toBeGreaterThan(0);
      expect(a.description.length).toBeGreaterThan(0);
      expect(a.url).toMatch(/^https:\/\/attack\.mitre\.org\/groups\/G\d{4}$/);
    }
  });

  it('records aliases and software as arrays with no duplicate entries', () => {
    for (const a of THREAT_ACTORS) {
      expect(Array.isArray(a.aliases)).toBe(true);
      expect(Array.isArray(a.software)).toBe(true);
      expect(new Set(a.aliases).size).toBe(a.aliases.length);
      expect(new Set(a.software).size).toBe(a.software.length);
    }
  });

  it('records technique ids in valid ATT&CK format with no duplicates, and a sane techniquesTotal', () => {
    for (const a of THREAT_ACTORS) {
      expect(new Set(a.techniques).size).toBe(a.techniques.length);
      for (const t of a.techniques) expect(t).toMatch(/^T\d{4}(\.\d{3})?$/);
      if (typeof a.techniquesTotal === 'number') {
        expect(a.techniquesTotal).toBeGreaterThanOrEqual(a.techniques.length);
      }
    }
  });

  it('is sorted by MITRE group id (drives detail-page prev/next order)', () => {
    for (let i = 1; i < THREAT_ACTORS.length; i++) {
      expect(THREAT_ACTORS[i].id >= THREAT_ACTORS[i - 1].id).toBe(true);
    }
  });
});

describe('threatActorSlug / threatActorBySlug', () => {
  it('slugifies a name to a lowercase, hyphenated, URL-safe string', () => {
    expect(threatActorSlug('APT28')).toBe('apt28');
    expect(threatActorSlug('admin@338')).toBe('admin-338');
    expect(threatActorSlug('Lazarus Group')).toBe('lazarus-group');
  });

  it('resolves every group by its own derived slug, and rejects an unknown one', () => {
    for (const a of THREAT_ACTORS) {
      expect(threatActorBySlug(threatActorSlug(a.name))?.id).toBe(a.id);
    }
    expect(threatActorBySlug('definitely-not-a-real-group')).toBeUndefined();
  });
});

describe('cross-links into the ATT&CK map', () => {
  it('resolveAttackLink never breaks on a threat-actor-referenced technique id', () => {
    for (const a of THREAT_ACTORS) {
      for (const t of a.techniques) {
        const link = resolveAttackLink(t);
        expect(link.href.length).toBeGreaterThan(0);
        if (link.onSite) expect(link.href).toBe(`/attack-map/${t}/`);
        else expect(link.href).toMatch(/^https:\/\/attack\.mitre\.org\/techniques\//);
      }
    }
  });

  it('at least some referenced techniques resolve on-site (the curated ATT&CK map isn\'t empty)', () => {
    const anyOnSite = THREAT_ACTORS.some((a) => a.techniques.some((t) => resolveAttackLink(t).onSite));
    expect(anyOnSite).toBe(true);
  });
});
