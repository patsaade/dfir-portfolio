// Guardrails for the site taxonomy in src/consts.ts.
//
// These encode the structural rules the information architecture depends on —
// the 5-item category floor and the 8-item domain-hub threshold — so that a
// future edit that quietly breaks one fails here rather than shipping a
// two-item menu or a hub page with nothing on it.
import { describe, it, expect } from 'vitest';
import { SITE_ENTRIES, CATEGORIES, DOMAINS, groupsFor } from '../src/consts';
import type { CategoryId, Domain } from '../src/consts';

const CATEGORY_IDS = new Set(CATEGORIES.map((c) => c.id));
const DOMAIN_IDS = new Set(DOMAINS.map((d) => d.id));

describe('SITE_ENTRIES', () => {
  it('has a unique href for every entry', () => {
    const seen = new Map<string, string>();
    for (const e of SITE_ENTRIES) {
      expect(seen.has(e.href), `duplicate href ${e.href} (${seen.get(e.href)} and ${e.label})`).toBe(false);
      seen.set(e.href, e.label);
    }
    expect(seen.size).toBe(SITE_ENTRIES.length);
  });

  it('has a unique label for every entry', () => {
    const labels = SITE_ENTRIES.map((e) => e.label);
    expect(new Set(labels).size, `duplicate label among: ${labels.join(', ')}`).toBe(labels.length);
  });

  it('starts and ends every href with a slash', () => {
    for (const e of SITE_ENTRIES) {
      expect(e.href.startsWith('/'), `${e.href} must start with /`).toBe(true);
      expect(e.href.endsWith('/'), `${e.href} must end with /`).toBe(true);
    }
  });

  it('gives every entry a non-empty label, icon, and description', () => {
    for (const e of SITE_ENTRIES) {
      expect(e.label.length, `${e.href} has an empty label`).toBeGreaterThan(0);
      expect(e.icon.length, `${e.href} has an empty icon`).toBeGreaterThan(0);
      expect(e.description.length, `${e.href} has an empty description`).toBeGreaterThan(0);
    }
  });

  it('references only known category ids', () => {
    for (const e of SITE_ENTRIES) {
      expect(CATEGORY_IDS.has(e.category), `${e.href} has unknown category ${e.category}`).toBe(true);
    }
  });

  it("matches each entry's type to its category's own type", () => {
    const typeOfCategory = new Map<CategoryId, string>(CATEGORIES.map((c) => [c.id, c.type]));
    for (const e of SITE_ENTRIES) {
      expect(e.type, `${e.href} is type ${e.type} but sits in ${e.category}`).toBe(
        typeOfCategory.get(e.category)
      );
    }
  });

  it('gives every entry a non-empty, duplicate-free, known set of domains', () => {
    for (const e of SITE_ENTRIES) {
      expect(e.domains.length, `${e.href} has no domain tag`).toBeGreaterThan(0);
      expect(new Set(e.domains).size, `${e.href} repeats a domain tag`).toBe(e.domains.length);
      for (const d of e.domains) {
        expect(DOMAIN_IDS.has(d), `${e.href} has unknown domain ${d}`).toBe(true);
      }
    }
  });

  it('keeps icons unique within each entry type', () => {
    // ToolSidebar renders one mode's entries together in a single list, so a
    // repeated icon inside a type makes two destinations look identical.
    for (const type of ['reference', 'tool', 'drill'] as const) {
      const icons = SITE_ENTRIES.filter((e) => e.type === type).map((e) => e.icon);
      const dupes = icons.filter((ic, i) => icons.indexOf(ic) !== i);
      expect(dupes, `duplicate icon(s) within type "${type}": ${dupes.join(', ')}`).toEqual([]);
    }
  });
});

describe('CATEGORIES', () => {
  it('has a unique id per category', () => {
    const ids = CATEGORIES.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('gives every category a label, blurb, and intro', () => {
    for (const c of CATEGORIES) {
      expect(c.label.length, `${c.id} has no label`).toBeGreaterThan(0);
      expect(c.blurb.length, `${c.id} has no blurb`).toBeGreaterThan(0);
      expect(c.intro.length, `${c.id} has no intro`).toBeGreaterThan(0);
      expect(c.blurb, `${c.id}'s blurb and intro are identical`).not.toBe(c.intro);
    }
  });

  // Rule 4: a category needs 5 entries to exist. Below that its items belong
  // in the nearest broader category. This is the guardrail that stops a
  // 2-item category from being created.
  it('has at least 5 entries in every category', () => {
    for (const c of CATEGORIES) {
      const n = SITE_ENTRIES.filter((e) => e.category === c.id).length;
      expect(n, `category "${c.id}" has ${n} entries, below the 5-item floor`).toBeGreaterThanOrEqual(5);
    }
  });

  it('has no category declared without entries, and no entry in an undeclared category', () => {
    const used = new Set(SITE_ENTRIES.map((e) => e.category));
    for (const c of CATEGORIES) {
      expect(used.has(c.id), `category "${c.id}" is declared but has no entries`).toBe(true);
    }
    for (const id of used) {
      expect(CATEGORY_IDS.has(id), `entries use category "${id}" which is not declared`).toBe(true);
    }
  });
});

describe('DOMAINS', () => {
  it('has a unique id per domain', () => {
    const ids = DOMAINS.map((d) => d.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('has at least one tagged entry for every declared domain', () => {
    for (const d of DOMAINS) {
      const n = SITE_ENTRIES.filter((e) => (e.domains as readonly Domain[]).includes(d.id)).length;
      expect(n, `domain "${d.id}" is declared but tags nothing`).toBeGreaterThan(0);
    }
  });

  // A domain earns its own /[domain]/ hub page at 8+ tagged entries; below
  // that it is filter-only. Drill entries count — networking and systems each
  // sit at exactly 8 and clear the threshold ONLY because their drills are
  // tagged, so this test is what catches a dropped drill tag demoting a hub.
  it('has at least 8 tagged entries for every hub domain', () => {
    for (const d of DOMAINS.filter((x) => x.hub)) {
      const n = SITE_ENTRIES.filter((e) => (e.domains as readonly Domain[]).includes(d.id)).length;
      expect(n, `hub domain "${d.id}" has ${n} tagged entries, below the 8-item threshold`).toBeGreaterThanOrEqual(8);
    }
  });

  // `hubHref` is the single source for a hub's path — read by DomainHub's
  // sibling chips, the Footer's "By topic" column, and the topic tiles on
  // /reference/ and /tools/. It used to be spelled separately in each of those,
  // so this pins the two fields together in both directions: a domain promoted
  // to hub: true without a path would render dead links in three places, and a
  // stray hubHref on a filter-only domain would advertise a page that 404s.
  it('gives every hub domain a hubHref, and no other domain one', () => {
    for (const d of DOMAINS) {
      if (d.hub) {
        expect(d.hubHref, `hub domain "${d.id}" has no hubHref`).toBeTruthy();
        expect(d.hubHref, `hub domain "${d.id}" hubHref must be a rooted, trailing-slash path`).toBe(`/${d.id}/`);
      } else {
        expect(d.hubHref, `filter-only domain "${d.id}" must not carry a hubHref`).toBeUndefined();
      }
    }
  });

  it('gives every domain an icon for the topic tiles', () => {
    for (const d of DOMAINS) {
      expect(d.icon, `domain "${d.id}" has no icon`).toBeTruthy();
    }
  });

  it('leaves every non-hub domain below the 8-entry hub threshold', () => {
    // If a filter-only domain reaches 8 it has earned a hub; that is a
    // deliberate decision to make, not something to let drift silently.
    for (const d of DOMAINS.filter((x) => !x.hub)) {
      const n = SITE_ENTRIES.filter((e) => (e.domains as readonly Domain[]).includes(d.id)).length;
      expect(n, `domain "${d.id}" now tags ${n} entries — it has earned a hub, set hub: true`).toBeLessThan(8);
    }
  });
});

describe('groupsFor', () => {
  // The one derivation the nav, the sidebar, the footer, both section index
  // pages and the topic hubs all render from — if it drops an entry, it drops
  // it everywhere at once.
  it('covers every entry exactly once across the three types', () => {
    const grouped = (['reference', 'tool', 'drill'] as const).flatMap((t) =>
      groupsFor(t).flatMap((g) => g.links.map((l) => l.href))
    );
    expect(new Set(grouped).size, 'an entry appears in more than one group').toBe(grouped.length);
    expect([...grouped].sort()).toEqual([...SITE_ENTRIES.map((e) => e.href)].sort());
  });

  it('returns each type\'s categories in CATEGORIES order', () => {
    for (const type of ['reference', 'tool', 'drill'] as const) {
      expect(groupsFor(type).map((g) => g.id)).toEqual(
        CATEGORIES.filter((c) => c.type === type).map((c) => c.id)
      );
    }
  });

  it('gives every group a category label, id, blurb, and intro', () => {
    for (const type of ['reference', 'tool', 'drill'] as const) {
      for (const g of groupsFor(type)) {
        expect(g.category.length).toBeGreaterThan(0);
        expect(g.id.length).toBeGreaterThan(0);
        expect(g.blurb.length).toBeGreaterThan(0);
        expect(g.intro.length).toBeGreaterThan(0);
      }
    }
  });

  it('never returns an empty group', () => {
    for (const type of ['reference', 'tool', 'drill'] as const) {
      for (const g of groupsFor(type)) {
        expect(g.links.length, `group "${g.id}" is empty`).toBeGreaterThan(0);
      }
    }
  });
});
