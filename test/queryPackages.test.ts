import { describe, it, expect } from 'vitest';
import {
  KQL_PACKAGES,
  QUERY_PACKAGES,
  S1_PACKAGES,
  SPL_PACKAGES,
  packagesFor,
  queryPackageText,
  themesFor,
} from '../src/data/queryPackages';
import { ATTACK_TECHNIQUE_BY_ID } from '../src/data/references';
import { buildKqlQuery, findColumn, findOperator, findTable } from '../src/utils/kql';
import { SPL_AGG_FUNCTIONS, validateSplQuery } from '../src/utils/spl';
import { buildS1Query, findS1Aggregation, findS1Field, findS1Operator } from '../src/utils/s1';

describe('package library shape', () => {
  it('has globally unique ids', () => {
    const ids = QUERY_PACKAGES.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('splits cleanly by language', () => {
    expect(packagesFor('kql')).toEqual(KQL_PACKAGES);
    expect(packagesFor('spl')).toEqual(SPL_PACKAGES);
    expect(packagesFor('s1')).toEqual(S1_PACKAGES);
    expect(KQL_PACKAGES.length + SPL_PACKAGES.length + S1_PACKAGES.length).toBe(QUERY_PACKAGES.length);
  });

  it('prefixes each id with its own language', () => {
    for (const pkg of QUERY_PACKAGES) expect(pkg.id.startsWith(`${pkg.language}-`)).toBe(true);
  });

  it('gives every package the prose a responder needs before running it', () => {
    for (const pkg of QUERY_PACKAGES) {
      expect(pkg.title.length).toBeGreaterThan(0);
      expect(pkg.finds.length).toBeGreaterThan(0);
      // `dataSource` and `tuning` are the two lines that decide whether a hunt
      // is usable, so neither is allowed to be a token phrase.
      expect(pkg.dataSource.length).toBeGreaterThan(30);
      expect(pkg.tuning.length).toBeGreaterThan(30);
    }
  });

  it('lists every theme that its packages actually use', () => {
    for (const language of ['kql', 'spl', 's1'] as const) {
      const themes = themesFor(language);
      expect(new Set(themes).size).toBe(themes.length);
      for (const pkg of packagesFor(language)) expect(themes).toContain(pkg.theme);
    }
  });
});

describe('ATT&CK cross-links', () => {
  // A package may only cite a technique that resolves on this site's own ATT&CK
  // map — otherwise the link on each builder page 404s.
  it('only cites technique ids this site has a page for', () => {
    for (const pkg of QUERY_PACKAGES) {
      if (!pkg.attack) continue;
      expect(ATTACK_TECHNIQUE_BY_ID.get(pkg.attack), `${pkg.id} cites ${pkg.attack}`).toBeDefined();
    }
  });
});

describe('every package assembles into a real query', () => {
  it('produces non-empty text for all of them', () => {
    for (const pkg of QUERY_PACKAGES) {
      expect(queryPackageText(pkg).trim().length, pkg.id).toBeGreaterThan(0);
    }
  });

  it('produces no builder warnings for any KQL package', () => {
    for (const pkg of KQL_PACKAGES) {
      expect(buildKqlQuery(pkg.spec).warnings, pkg.id).toEqual([]);
    }
  });

  it('produces no builder warnings for any SentinelOne package', () => {
    for (const pkg of S1_PACKAGES) {
      expect(buildS1Query(pkg.spec).warnings, pkg.id).toEqual([]);
    }
  });

  it('produces no validation errors for any SPL package', () => {
    for (const pkg of SPL_PACKAGES) {
      const errors = validateSplQuery(pkg.spec).filter((i) => i.severity === 'error');
      expect(errors, pkg.id).toEqual([]);
    }
  });
});

describe('KQL packages reference only verified schema', () => {
  it('names a real table, and real columns on it', () => {
    for (const pkg of KQL_PACKAGES) {
      const table = findTable(pkg.spec.table);
      expect(table, pkg.id).toBeDefined();
      for (const clause of pkg.spec.where) {
        expect(findColumn(table, clause.column), `${pkg.id}: ${clause.column}`).toBeDefined();
        expect(findOperator(clause.operatorId), `${pkg.id}: ${clause.operatorId}`).toBeDefined();
      }
      for (const column of pkg.spec.project) {
        expect(findColumn(table, column), `${pkg.id}: ${column}`).toBeDefined();
      }
      for (const column of pkg.spec.summarize?.by ?? []) {
        expect(findColumn(table, column), `${pkg.id}: ${column}`).toBeDefined();
      }
    }
  });

  it('always scopes by time', () => {
    // An unscoped advanced-hunting query reads the whole retained window and is
    // the usual cause of a timeout — no package should ship without a timespan.
    for (const pkg of KQL_PACKAGES) expect(pkg.spec.timespan, pkg.id).not.toBe('');
  });
});

describe('SPL packages state what they need', () => {
  it('always names an index and a sourcetype', () => {
    for (const pkg of SPL_PACKAGES) {
      expect(pkg.spec.base.index, pkg.id).not.toBe('');
      expect(pkg.spec.base.sourcetype, pkg.id).not.toBe('');
    }
  });

  it('always sets a time range', () => {
    for (const pkg of SPL_PACKAGES) {
      expect(pkg.spec.base.earliest, pkg.id).not.toBe('');
    }
  });

  // The SplBuilder UI renders exactly one card per command kind, so a package
  // that used a kind twice could not be represented faithfully when loaded.
  it('uses each pipe command at most once', () => {
    for (const pkg of SPL_PACKAGES) {
      const kinds = pkg.spec.commands.map((c) => c.kind);
      expect(new Set(kinds).size, pkg.id).toBe(kinds.length);
    }
  });

  // The UI's fixed row counts — 4 base filters, 3 aggregations, 2 sort fields.
  it('fits the builder form', () => {
    for (const pkg of SPL_PACKAGES) {
      expect(pkg.spec.base.filters.length, pkg.id).toBeLessThanOrEqual(4);
      for (const command of pkg.spec.commands) {
        if (command.kind === 'stats') expect(command.aggregations.length, pkg.id).toBeLessThanOrEqual(3);
        if (command.kind === 'sort') expect(command.fields.length, pkg.id).toBeLessThanOrEqual(2);
      }
    }
  });

  it('only uses aggregate functions the builder can emit', () => {
    const known = SPL_AGG_FUNCTIONS.map((f) => f.id);
    for (const pkg of SPL_PACKAGES) {
      for (const command of pkg.spec.commands) {
        if (command.kind !== 'stats') continue;
        for (const agg of command.aggregations) expect(known, pkg.id).toContain(agg.fn);
      }
    }
  });
});

describe('SentinelOne packages reference only verified fields', () => {
  it('names real fields, operators and aggregates', () => {
    for (const pkg of S1_PACKAGES) {
      for (const term of pkg.spec.filters) {
        expect(findS1Field(term.field), `${pkg.id}: ${term.field}`).toBeDefined();
        expect(findS1Operator(term.operatorId), `${pkg.id}: ${term.operatorId}`).toBeDefined();
      }
      for (const column of pkg.spec.columns) {
        expect(findS1Field(column), `${pkg.id}: ${column}`).toBeDefined();
      }
      for (const agg of pkg.spec.group?.aggregations ?? []) {
        const meta = findS1Aggregation(agg.aggregationId);
        expect(meta, `${pkg.id}: ${agg.aggregationId}`).toBeDefined();
        if (meta?.needsField) expect(findS1Field(agg.field), `${pkg.id}: ${agg.field}`).toBeDefined();
      }
      for (const field of pkg.spec.group?.by ?? []) {
        expect(findS1Field(field), `${pkg.id}: ${field}`).toBeDefined();
      }
    }
  });

  // The S1Builder UI renders 3 aggregate rows and 2 group-by pickers.
  it('fits the builder form', () => {
    for (const pkg of S1_PACKAGES) {
      expect((pkg.spec.group?.aggregations ?? []).length, pkg.id).toBeLessThanOrEqual(3);
      expect((pkg.spec.group?.by ?? []).length, pkg.id).toBeLessThanOrEqual(2);
    }
  });

  it('starts every package with at least one filter term', () => {
    for (const pkg of S1_PACKAGES) expect(pkg.spec.filters.length, pkg.id).toBeGreaterThan(0);
  });
});
