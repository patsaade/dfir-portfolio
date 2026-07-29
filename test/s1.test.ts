import { describe, it, expect } from 'vitest';
import { S1_AGGREGATIONS, S1_EVENT_TYPES, S1_FIELDS, S1_OPERATORS } from '../src/data/s1';
import {
  buildS1Query,
  defaultS1Spec,
  findS1Aggregation,
  findS1Field,
  findS1Operator,
  parseS1List,
  quoteS1String,
  renderS1Term,
  renderS1Value,
  s1AvailableColumns,
  s1OperatorsForKind,
  s1OutputColumns,
  type S1QuerySpec,
} from '../src/utils/s1';

// A minimal spec factory so each test only states what it actually cares about.
function spec(overrides: Partial<S1QuerySpec> = {}): S1QuerySpec {
  return {
    filters: [{ field: 'event.type', operatorId: 'eq', value: 'Process Creation' }],
    group: null,
    postFilter: null,
    sort: '',
    limit: null,
    columns: [],
    ...overrides,
  };
}

describe('S1 reference data', () => {
  it('has unique field names', () => {
    const names = S1_FIELDS.map((f) => f.name);
    expect(new Set(names).size).toBe(names.length);
  });

  it('has unique operator ids and symbols', () => {
    expect(new Set(S1_OPERATORS.map((o) => o.id)).size).toBe(S1_OPERATORS.length);
    expect(new Set(S1_OPERATORS.map((o) => o.symbol)).size).toBe(S1_OPERATORS.length);
  });

  it('has unique aggregation ids and aliases', () => {
    expect(new Set(S1_AGGREGATIONS.map((a) => a.id)).size).toBe(S1_AGGREGATIONS.length);
    expect(new Set(S1_AGGREGATIONS.map((a) => a.alias)).size).toBe(S1_AGGREGATIONS.length);
  });

  it('has unique event type values', () => {
    const values = S1_EVENT_TYPES.map((t) => t.value);
    expect(new Set(values).size).toBe(values.length);
  });

  // The whole point of src/data/s1.ts is that no name got in on a guess, so the
  // provenance field is checked rather than assumed to be filled in.
  it('records a sourcing tier for every field and event type', () => {
    for (const field of S1_FIELDS) expect(['sentinelone', 'corroborated']).toContain(field.source);
    for (const type of S1_EVENT_TYPES) expect(['sentinelone', 'corroborated']).toContain(type.source);
  });

  it('offers at least one operator for every field kind in use', () => {
    for (const field of S1_FIELDS) expect(s1OperatorsForKind(field.kind).length).toBeGreaterThan(0);
  });

  it('only offers aggregations whose field kinds exist on real fields', () => {
    const kinds = new Set(S1_FIELDS.map((f) => f.kind));
    for (const agg of S1_AGGREGATIONS) {
      if (!agg.needsField) continue;
      expect(agg.fieldKinds.some((k) => kinds.has(k))).toBe(true);
    }
  });
});

describe('lookups', () => {
  it('finds a field, operator and aggregation by name/id', () => {
    expect(findS1Field('tgt.process.cmdline')?.kind).toBe('string');
    expect(findS1Operator('contains_ci')?.symbol).toBe('contains:anycase');
    expect(findS1Aggregation('count')?.needsField).toBe(false);
  });

  it('returns undefined for something that does not exist', () => {
    expect(findS1Field('tgt.process.nope')).toBeUndefined();
    expect(findS1Operator('regexp')).toBeUndefined();
  });

  it('keeps string operators off numeric fields', () => {
    const numeric = s1OperatorsForKind('numeric').map((o) => o.id);
    expect(numeric).not.toContain('contains');
    expect(numeric).toContain('gte');
  });
});

describe('quoting', () => {
  it('single-quotes a plain value', () => {
    expect(quoteS1String('powershell.exe').text).toBe("'powershell.exe'");
  });

  // SentinelOne's own published queries write a literal backslash doubled.
  it('doubles backslashes', () => {
    expect(quoteS1String('C:\\Users\\Public').text).toBe("'C:\\\\Users\\\\Public'");
  });

  it('switches to double quotes when the value contains a single quote', () => {
    expect(quoteS1String("O'Brien").text).toBe('"O\'Brien"');
  });

  // There is no verified escape sequence for this case, so it is refused
  // rather than guessed at — see the module header.
  it('refuses a value containing both quote characters', () => {
    const result = quoteS1String(`it's a "test"`);
    expect(result.text).toBeNull();
    expect(result.error).toContain('both');
  });
});

describe('value rendering', () => {
  it('emits a numeric value bare', () => {
    expect(renderS1Value('443', 'numeric', 'dst.port.number').text).toBe('443');
  });

  it('rejects a non-number for a numeric field', () => {
    const result = renderS1Value('https', 'numeric', 'dst.port.number');
    expect(result.text).toBeNull();
    expect(result.error).toContain('numeric');
  });

  it('rejects an empty value', () => {
    expect(renderS1Value('   ', 'string', 'endpoint.name').text).toBeNull();
  });
});

describe('parseS1List', () => {
  it('splits, trims and drops blanks', () => {
    expect(parseS1List('a, b ,, c ')).toEqual(['a', 'b', 'c']);
  });

  it('strips quotes the user typed themselves', () => {
    expect(parseS1List(`'a', "b"`)).toEqual(['a', 'b']);
  });
});

describe('renderS1Term', () => {
  it('renders a binary term', () => {
    const result = renderS1Term({ field: 'event.type', operatorId: 'eq', value: 'Process Creation' });
    expect(result.text).toBe("event.type = 'Process Creation'");
  });

  it('renders a list term', () => {
    const result = renderS1Term({ field: 'tgt.process.name', operatorId: 'in', value: 'cmd.exe, powershell.exe' });
    expect(result.text).toBe("tgt.process.name in ('cmd.exe', 'powershell.exe')");
  });

  it('drops a term whose operator does not apply to the field kind', () => {
    const result = renderS1Term({ field: 'dst.port.number', operatorId: 'contains', value: '443' });
    expect(result.text).toBeNull();
    expect(result.warnings.length).toBe(1);
  });

  it('reports an unfinished (blank) term as a tip, not a warning', () => {
    const result = renderS1Term({ field: 'tgt.process.cmdline', operatorId: 'contains_ci', value: '' });
    expect(result.text).toBeNull();
    expect(result.warnings).toEqual([]);
    expect(result.tips.length).toBe(1);
  });

  it('nudges toward contains:anycase on a case-sensitive string equality', () => {
    const result = renderS1Term({ field: 'endpoint.name', operatorId: 'eq', value: 'WS-01' });
    expect(result.tips.join(' ')).toContain('contains:anycase');
  });
});

describe('output columns', () => {
  it('returns null when there is no group stage', () => {
    expect(s1OutputColumns(spec())).toBeNull();
  });

  it('returns the by fields plus each aggregate alias', () => {
    const built = s1OutputColumns(
      spec({
        group: {
          aggregations: [
            { aggregationId: 'count', field: '', alias: 'hits' },
            { aggregationId: 'estimate_distinct', field: 'endpoint.name', alias: '' },
          ],
          by: ['tgt.process.name'],
        },
      }),
    );
    expect(built).toEqual(['tgt.process.name', 'hits', 'distinct_values']);
  });

  it('falls back to every field when nothing narrows the output', () => {
    expect(s1AvailableColumns(spec()).length).toBe(S1_FIELDS.length);
  });
});

describe('buildS1Query', () => {
  it('emits a bare filter expression', () => {
    expect(buildS1Query(spec()).query).toBe("event.type = 'Process Creation'");
  });

  it('joins several terms with a space (implicit AND)', () => {
    const result = buildS1Query(
      spec({
        filters: [
          { field: 'event.type', operatorId: 'eq', value: 'Process Creation' },
          { field: 'tgt.process.cmdline', operatorId: 'contains_ci', value: 'lsass' },
        ],
      }),
    );
    expect(result.query).toBe("event.type = 'Process Creation' tgt.process.cmdline contains:anycase 'lsass'");
  });

  it('returns nothing at all when no term survives', () => {
    const result = buildS1Query(spec({ filters: [] }));
    expect(result.query).toBe('');
    expect(result.tips.join(' ')).toContain('at least one filter term');
  });

  it('emits the full pipeline in its fixed order', () => {
    const result = buildS1Query(
      spec({
        group: {
          aggregations: [{ aggregationId: 'count', field: '', alias: 'launches' }],
          by: ['src.process.name', 'tgt.process.name'],
        },
        postFilter: { column: 'launches', operatorId: 'lte', value: '5' },
        sort: 'launches',
        limit: 100,
      }),
    );
    expect(result.query.split('\n')).toEqual([
      "event.type = 'Process Creation'",
      '| group launches = count() by src.process.name, tgt.process.name',
      '| filter launches <= 5',
      '| sort -launches',
      '| limit 100',
    ]);
    expect(result.warnings).toEqual([]);
  });

  it('drops a sort on a column the group stage does not produce', () => {
    const result = buildS1Query(
      spec({
        group: { aggregations: [{ aggregationId: 'count', field: '', alias: 'hits' }], by: ['endpoint.name'] },
        sort: 'tgt.process.cmdline',
      }),
    );
    expect(result.query).not.toContain('| sort');
    expect(result.warnings.join(' ')).toContain('does not carry a column');
  });

  it('drops a columns stage entry that is not a real field', () => {
    const result = buildS1Query(spec({ columns: ['endpoint.name', 'not.a.field'] }));
    expect(result.query).toContain('| columns endpoint.name');
    expect(result.warnings.join(' ')).toContain('not.a.field');
  });

  it('rejects a non-integer limit rather than emitting it', () => {
    const result = buildS1Query(spec({ limit: 0 }));
    expect(result.query).not.toContain('| limit');
    expect(result.warnings.join(' ')).toContain('positive whole number');
  });

  it('drops an aggregate applied to a field kind it cannot take', () => {
    const result = buildS1Query(
      spec({ group: { aggregations: [{ aggregationId: 'sum', field: 'endpoint.name', alias: '' }], by: [] } }),
    );
    expect(result.query).not.toContain('| group');
    expect(result.warnings.join(' ')).toContain('cannot be applied');
  });

  // The builder deliberately never writes an ascending sort — see the module
  // header. This guards that decision against a well-meaning future change.
  it('only ever emits a descending sort', () => {
    const result = buildS1Query(spec({ sort: 'endpoint.name' }));
    expect(result.query).toContain('| sort -endpoint.name');
    expect(result.query).not.toContain('| sort +');
  });
});

describe('defaultS1Spec', () => {
  it('builds a query with no warnings', () => {
    const result = buildS1Query(defaultS1Spec());
    expect(result.warnings).toEqual([]);
    expect(result.query.length).toBeGreaterThan(0);
  });

  it('only references fields and operators that exist', () => {
    const built = defaultS1Spec();
    for (const filter of built.filters) {
      expect(findS1Field(filter.field)).toBeDefined();
      expect(findS1Operator(filter.operatorId)).toBeDefined();
    }
    for (const column of built.columns) expect(findS1Field(column)).toBeDefined();
  });
});
