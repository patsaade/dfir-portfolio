import { describe, it, expect } from 'vitest';
import {
  KQL_AGGREGATIONS,
  KQL_BIN_SIZES,
  KQL_OPERATORS,
  KQL_TABLES,
  KQL_TIMESPANS,
} from '../src/data/kql';
import {
  KQL_EXAMPLE_HUNTS,
  TIME_BUCKET_ALIAS,
  availableSortColumns,
  buildKqlQuery,
  findAggregation,
  findColumn,
  findOperator,
  findTable,
  operatorsForKind,
  outputColumns,
  parseKqlList,
  quoteKqlString,
  renderValue,
  renderWhereClause,
  type KqlQuerySpec,
} from '../src/utils/kql';

// A minimal spec factory so each test only states what it actually cares
// about.
function spec(overrides: Partial<KqlQuerySpec> = {}): KqlQuerySpec {
  return {
    table: 'DeviceProcessEvents',
    timespan: '7d',
    where: [],
    project: [],
    summarize: null,
    sort: null,
    limit: null,
    ...overrides,
  };
}

describe('KQL reference data integrity', () => {
  it('has unique table names', () => {
    const names = KQL_TABLES.map((t) => t.name);
    expect(new Set(names).size).toBe(names.length);
  });

  it('gives every table a documented time column that exists in its own column list', () => {
    for (const table of KQL_TABLES) {
      const column = table.columns.find((c) => c.name === table.timeColumn);
      expect(column, `${table.name} is missing its ${table.timeColumn} column`).toBeDefined();
      expect(column?.kind, `${table.name}.${table.timeColumn} must be a datetime`).toBe('datetime');
    }
  });

  it('uses Timestamp for Defender tables and TimeGenerated for Sentinel tables', () => {
    for (const table of KQL_TABLES) {
      const expected = table.product === 'Microsoft Defender XDR' ? 'Timestamp' : 'TimeGenerated';
      expect(table.timeColumn, `${table.name}`).toBe(expected);
    }
  });

  it('has unique, non-empty column names per table', () => {
    for (const table of KQL_TABLES) {
      const names = table.columns.map((c) => c.name);
      expect(new Set(names).size, `${table.name} has duplicate columns`).toBe(names.length);
      for (const name of names) expect(name.length).toBeGreaterThan(0);
    }
  });

  it('uses only bare KQL identifiers as column names (no bracket-quoting needed)', () => {
    for (const table of KQL_TABLES) {
      for (const column of table.columns) {
        expect(column.name, `${table.name}.${column.name}`).toMatch(/^[A-Za-z][A-Za-z0-9_]*$/);
      }
    }
  });

  it('ships no dynamic/JSON columns, per the documented scope cut', () => {
    for (const table of KQL_TABLES) {
      for (const column of table.columns) {
        expect(column.type, `${table.name}.${column.name}`).not.toBe('dynamic');
      }
    }
  });

  it('points every table at a Microsoft Learn documentation URL', () => {
    for (const table of KQL_TABLES) {
      expect(table.docUrl).toMatch(/^https:\/\/learn\.microsoft\.com\//);
    }
  });

  it('has unique operator ids and symbols', () => {
    const ids = KQL_OPERATORS.map((o) => o.id);
    const symbols = KQL_OPERATORS.map((o) => o.symbol);
    expect(new Set(ids).size).toBe(ids.length);
    expect(new Set(symbols).size).toBe(symbols.length);
  });

  it('gives every operator at least one applicable column kind', () => {
    for (const operator of KQL_OPERATORS) {
      expect(operator.kinds.length, operator.id).toBeGreaterThan(0);
    }
  });

  it('offers at least one operator for every column kind in use', () => {
    const kinds = new Set(KQL_TABLES.flatMap((t) => t.columns.map((c) => c.kind)));
    for (const kind of kinds) {
      expect(operatorsForKind(kind).length, kind).toBeGreaterThan(0);
    }
  });

  it('has unique aggregation ids and output aliases', () => {
    const ids = KQL_AGGREGATIONS.map((a) => a.id);
    const aliases = KQL_AGGREGATIONS.map((a) => a.alias);
    expect(new Set(ids).size).toBe(ids.length);
    expect(new Set(aliases).size).toBe(aliases.length);
  });

  it('restricts timespan and bin literals to hour/day suffixes', () => {
    for (const span of [...KQL_TIMESPANS, ...KQL_BIN_SIZES]) {
      expect(span.id, span.label).toMatch(/^\d+[hd]$/);
    }
  });

  it('resolves known lookups and rejects unknown ones', () => {
    expect(findTable('DeviceProcessEvents')?.name).toBe('DeviceProcessEvents');
    expect(findTable('NoSuchTable')).toBeUndefined();
    expect(findColumn(findTable('DeviceProcessEvents'), 'ProcessCommandLine')?.kind).toBe('string');
    expect(findColumn(findTable('DeviceProcessEvents'), 'NoSuchColumn')).toBeUndefined();
    expect(findOperator('has')?.symbol).toBe('has');
    expect(findOperator('nope')).toBeUndefined();
    expect(findAggregation('dcount')?.fn).toBe('dcount');
  });
});

describe('quoteKqlString', () => {
  it('wraps a plain value in double quotes', () => {
    expect(quoteKqlString('powershell.exe')).toBe('"powershell.exe"');
  });

  it('uses a verbatim literal for a Windows path so backslashes stay literal', () => {
    expect(quoteKqlString('C:\\Users\\Public')).toBe('@"C:\\Users\\Public"');
  });

  it('uses a verbatim literal for a regex containing escapes', () => {
    expect(quoteKqlString('\\d{3}-\\d{4}')).toBe('@"\\d{3}-\\d{4}"');
  });

  it('falls back to escaping when the value also contains a quote', () => {
    expect(quoteKqlString('C:\\a "b"')).toBe('"C:\\\\a \\"b\\""');
  });

  it('escapes an embedded double quote', () => {
    expect(quoteKqlString('say "hi"')).toBe('"say \\"hi\\""');
  });

  it('escapes tab, newline and carriage return', () => {
    expect(quoteKqlString('a\tb\nc\rd')).toBe('"a\\tb\\nc\\rd"');
  });

  it('leaves a single quote alone inside a double-quoted literal', () => {
    expect(quoteKqlString("it's")).toBe('"it\'s"');
  });

  it('handles an empty string', () => {
    expect(quoteKqlString('')).toBe('""');
  });
});

describe('renderValue', () => {
  it('quotes string values', () => {
    expect(renderValue('cmd.exe', 'string', 'FileName').text).toBe('"cmd.exe"');
  });

  it('emits numbers unquoted', () => {
    expect(renderValue('4624', 'numeric', 'EventID').text).toBe('4624');
    expect(renderValue('-1', 'numeric', 'EventID').text).toBe('-1');
    expect(renderValue('1.5', 'numeric', 'FileSize').text).toBe('1.5');
  });

  it('rejects a non-numeric value for a numeric column instead of quoting it', () => {
    const result = renderValue('cmd.exe', 'numeric', 'ProcessId');
    expect(result.text).toBeNull();
    expect(result.error).toContain('not a number');
  });

  it('normalises boolean values and rejects anything else', () => {
    expect(renderValue('TRUE', 'bool', 'IsLocalAdmin').text).toBe('true');
    expect(renderValue('false', 'bool', 'IsLocalAdmin').text).toBe('false');
    expect(renderValue('yes', 'bool', 'IsLocalAdmin').text).toBeNull();
  });

  it('wraps a bare ISO date in datetime() and passes function calls through', () => {
    expect(renderValue('2026-01-31', 'datetime', 'Timestamp').text).toBe('datetime(2026-01-31)');
    expect(renderValue('2026-01-31T09:15:00Z', 'datetime', 'Timestamp').text).toBe('datetime(2026-01-31T09:15:00Z)');
    expect(renderValue('ago(7d)', 'datetime', 'Timestamp').text).toBe('ago(7d)');
    expect(renderValue('now()', 'datetime', 'Timestamp').text).toBe('now()');
  });

  it('rejects an unrecognised datetime expression rather than guessing', () => {
    const result = renderValue('last tuesday', 'datetime', 'Timestamp');
    expect(result.text).toBeNull();
    expect(result.error).toContain('datetime column');
  });

  it('treats an empty value as unrenderable', () => {
    expect(renderValue('   ', 'string', 'FileName').text).toBeNull();
  });
});

describe('parseKqlList', () => {
  it('splits on commas and trims', () => {
    expect(parseKqlList('a, b ,c')).toEqual(['a', 'b', 'c']);
  });

  it('drops empty entries', () => {
    expect(parseKqlList('a,,b, ,')).toEqual(['a', 'b']);
  });

  it('strips quotes the user typed so values are not double-quoted', () => {
    expect(parseKqlList('"a", \'b\', c')).toEqual(['a', 'b', 'c']);
  });

  it('returns an empty array for empty input', () => {
    expect(parseKqlList('   ')).toEqual([]);
  });
});

describe('renderWhereClause', () => {
  const table = findTable('DeviceProcessEvents');
  const sentinel = findTable('SecurityEvent');

  it('renders a case-insensitive equality', () => {
    const result = renderWhereClause(table, { column: 'FileName', operatorId: 'eq_ci', value: 'rundll32.exe' });
    expect(result.text).toBe('FileName =~ "rundll32.exe"');
    expect(result.warnings).toEqual([]);
  });

  it('renders an in~ list with a space before the parenthesis', () => {
    const result = renderWhereClause(table, {
      column: 'FileName',
      operatorId: 'in_ci',
      value: 'net.exe, net1.exe',
    });
    expect(result.text).toBe('FileName in~ ("net.exe", "net1.exe")');
  });

  it('renders has_any as a call with no space before the parenthesis', () => {
    const result = renderWhereClause(table, {
      column: 'ProcessCommandLine',
      operatorId: 'has_any',
      value: 'whoami, nltest',
    });
    expect(result.text).toBe('ProcessCommandLine has_any("whoami", "nltest")');
  });

  it('renders a function-form predicate with no value', () => {
    const result = renderWhereClause(table, { column: 'ProcessCommandLine', operatorId: 'isnotempty', value: '' });
    expect(result.text).toBe('isnotempty(ProcessCommandLine)');
    expect(result.warnings).toEqual([]);
  });

  it('renders a numeric comparison without quotes', () => {
    const result = renderWhereClause(sentinel, { column: 'EventID', operatorId: 'eq', value: '4624' });
    expect(result.text).toBe('EventID == 4624');
  });

  it('drops a clause whose operator does not apply to the column kind', () => {
    const result = renderWhereClause(sentinel, { column: 'EventID', operatorId: 'startswith', value: '46' });
    expect(result.text).toBeNull();
    expect(result.warnings[0]).toContain('does not apply');
  });

  it('drops a clause referencing an unknown column', () => {
    const result = renderWhereClause(table, { column: 'Nope', operatorId: 'eq', value: 'x' });
    expect(result.text).toBeNull();
    expect(result.warnings[0]).toContain('Unknown column');
  });

  it('treats an empty binary value as an unfinished step, not an error', () => {
    const result = renderWhereClause(table, { column: 'FileName', operatorId: 'eq', value: '' });
    expect(result.text).toBeNull();
    expect(result.warnings).toEqual([]);
    expect(result.tips.length).toBe(1);
  });

  it('flags contains as slower than has', () => {
    const result = renderWhereClause(table, {
      column: 'ProcessCommandLine',
      operatorId: 'contains',
      value: 'DownloadString',
    });
    expect(result.text).toBe('ProcessCommandLine contains "DownloadString"');
    expect(result.tips.join(' ')).toContain('term index');
  });

  it('flags a has-family term of fewer than three characters as unindexed', () => {
    const result = renderWhereClause(table, { column: 'ProcessCommandLine', operatorId: 'has', value: 'ex' });
    expect(result.text).toBe('ProcessCommandLine has "ex"');
    expect(result.tips.join(' ')).toContain('fewer than three characters');
  });

  it('does not flag a has term of three characters or more (Kusto indexes 3+ char terms)', () => {
    const result = renderWhereClause(table, { column: 'ProcessCommandLine', operatorId: 'has', value: 'iex' });
    expect(result.tips).toEqual([]);
  });

  it('drops only the invalid entries of a mixed numeric list', () => {
    const result = renderWhereClause(sentinel, { column: 'EventID', operatorId: 'in', value: '4624, oops, 4625' });
    expect(result.text).toBe('EventID in (4624, 4625)');
    expect(result.warnings.length).toBe(1);
  });

  it('drops the whole clause when no list entry survives', () => {
    const result = renderWhereClause(sentinel, { column: 'EventID', operatorId: 'in', value: 'a, b' });
    expect(result.text).toBeNull();
    expect(result.warnings.length).toBe(2);
  });
});

describe('outputColumns and availableSortColumns', () => {
  it('returns null when the query keeps every column', () => {
    expect(outputColumns(spec())).toBeNull();
    expect(availableSortColumns(spec())).toContain('ProcessCommandLine');
  });

  it('returns the project list when one is set', () => {
    const s = spec({ project: ['Timestamp', 'FileName'] });
    expect(outputColumns(s)).toEqual(['Timestamp', 'FileName']);
    expect(availableSortColumns(s)).toEqual(['Timestamp', 'FileName']);
  });

  it('drops unknown and duplicate project columns', () => {
    const s = spec({ project: ['Timestamp', 'Timestamp', 'Nope'] });
    expect(outputColumns(s)).toEqual(['Timestamp']);
  });

  it('returns the group keys plus the aggregate alias when summarizing', () => {
    const s = spec({
      summarize: { aggregationId: 'count', aggColumn: '', by: ['DeviceName'], binColumn: '', binSize: '' },
    });
    expect(outputColumns(s)).toEqual(['DeviceName', 'Count']);
  });

  it('includes the named time bucket when bin() is used', () => {
    const s = spec({
      summarize: { aggregationId: 'count', aggColumn: '', by: ['DeviceName'], binColumn: 'Timestamp', binSize: '1h' },
    });
    expect(outputColumns(s)).toEqual(['DeviceName', TIME_BUCKET_ALIAS, 'Count']);
  });

  it('ignores the project list entirely once a summarize is configured', () => {
    const s = spec({
      project: ['FileName'],
      summarize: { aggregationId: 'count', aggColumn: '', by: [], binColumn: '', binSize: '' },
    });
    expect(outputColumns(s)).toEqual(['Count']);
  });
});

describe('buildKqlQuery', () => {
  it('emits the table alone when nothing else is configured', () => {
    expect(buildKqlQuery(spec({ timespan: '' })).query).toBe('DeviceProcessEvents');
  });

  it('puts the time filter on the table time column, first', () => {
    expect(buildKqlQuery(spec()).query).toBe('DeviceProcessEvents\n| where Timestamp > ago(7d)');
  });

  it('uses TimeGenerated for a Sentinel workspace table', () => {
    expect(buildKqlQuery(spec({ table: 'SigninLogs', timespan: '1d' })).query).toBe(
      'SigninLogs\n| where TimeGenerated > ago(1d)',
    );
  });

  it('warns when there is no time filter at all', () => {
    const result = buildKqlQuery(spec({ timespan: '' }));
    expect(result.tips.join(' ')).toContain('No time filter');
  });

  it('emits one where line per filter, in order', () => {
    const result = buildKqlQuery(
      spec({
        where: [
          { column: 'FileName', operatorId: 'eq_ci', value: 'cmd.exe' },
          { column: 'AccountName', operatorId: 'has', value: 'administrator' },
        ],
      }),
    );
    expect(result.lines).toEqual([
      'DeviceProcessEvents',
      '| where Timestamp > ago(7d)',
      '| where FileName =~ "cmd.exe"',
      '| where AccountName has "administrator"',
    ]);
  });

  it('emits summarize, sort and limit in pipeline order', () => {
    const result = buildKqlQuery(
      spec({
        timespan: '1d',
        summarize: {
          aggregationId: 'dcount',
          aggColumn: 'RemoteIP',
          by: ['DeviceName'],
          binColumn: '',
          binSize: '',
        },
        table: 'DeviceNetworkEvents',
        sort: { column: 'DistinctCount', direction: 'desc' },
        limit: 20,
      }),
    );
    expect(result.query).toBe(
      [
        'DeviceNetworkEvents',
        '| where Timestamp > ago(1d)',
        '| summarize DistinctCount = dcount(RemoteIP) by DeviceName',
        '| sort by DistinctCount desc',
        '| limit 20',
      ].join('\n'),
    );
  });

  it('renders a named bin() group key', () => {
    const result = buildKqlQuery(
      spec({
        summarize: { aggregationId: 'count', aggColumn: '', by: ['DeviceName'], binColumn: 'Timestamp', binSize: '1h' },
      }),
    );
    expect(result.query).toContain('| summarize Count = count() by DeviceName, TimeBucket = bin(Timestamp, 1h)');
  });

  it('omits the by clause for a whole-table aggregate', () => {
    const result = buildKqlQuery(
      spec({ summarize: { aggregationId: 'count', aggColumn: '', by: [], binColumn: '', binSize: '' } }),
    );
    expect(result.query).toContain('| summarize Count = count()');
    expect(result.query).not.toContain(' by ');
  });

  it('refuses to aggregate a string column with avg()', () => {
    const result = buildKqlQuery(
      spec({ summarize: { aggregationId: 'avg', aggColumn: 'FileName', by: [], binColumn: '', binSize: '' } }),
    );
    expect(result.query).not.toContain('summarize');
    expect(result.warnings[0]).toContain('cannot be applied');
  });

  it('refuses to bin() a non-datetime column', () => {
    const result = buildKqlQuery(
      spec({
        summarize: { aggregationId: 'count', aggColumn: '', by: [], binColumn: 'FileName', binSize: '1h' },
      }),
    );
    expect(result.warnings[0]).toContain('needs a datetime column');
    expect(result.query).toContain('| summarize Count = count()');
  });

  it('drops the project list when a summarize is present and says why', () => {
    const result = buildKqlQuery(
      spec({
        project: ['FileName', 'DeviceName'],
        summarize: { aggregationId: 'count', aggColumn: '', by: ['DeviceName'], binColumn: '', binSize: '' },
      }),
    );
    expect(result.query).not.toContain('| project');
    expect(result.tips.join(' ')).toContain('Project list ignored');
  });

  it('emits project when there is no summarize', () => {
    const result = buildKqlQuery(spec({ project: ['Timestamp', 'DeviceName', 'FileName'] }));
    expect(result.query).toContain('| project Timestamp, DeviceName, FileName');
  });

  it('drops a sort on a column the projection removed', () => {
    const result = buildKqlQuery(
      spec({ project: ['Timestamp'], sort: { column: 'FileName', direction: 'asc' } }),
    );
    expect(result.query).not.toContain('| sort');
    expect(result.warnings[0]).toContain('not one of the columns this query returns');
  });

  it('always writes the sort direction rather than relying on the KQL default', () => {
    const asc = buildKqlQuery(spec({ sort: { column: 'Timestamp', direction: 'asc' } }));
    const desc = buildKqlQuery(spec({ sort: { column: 'Timestamp', direction: 'desc' } }));
    expect(asc.query).toContain('| sort by Timestamp asc');
    expect(desc.query).toContain('| sort by Timestamp desc');
  });

  it('rejects a non-positive or fractional row limit', () => {
    expect(buildKqlQuery(spec({ limit: 0 })).warnings[0]).toContain('positive whole number');
    expect(buildKqlQuery(spec({ limit: -5 })).warnings[0]).toContain('positive whole number');
    expect(buildKqlQuery(spec({ limit: 2.5 })).warnings[0]).toContain('positive whole number');
    expect(buildKqlQuery(spec({ limit: 10 })).query).toContain('| limit 10');
  });

  it('reports an unknown table instead of emitting anything', () => {
    const result = buildKqlQuery(spec({ table: 'Nope' }));
    expect(result.query).toBe('');
    expect(result.warnings[0]).toContain('Unknown table');
  });

  it('never emits a lone or trailing pipe', () => {
    for (const example of KQL_EXAMPLE_HUNTS) {
      const { query } = buildKqlQuery(example.spec);
      expect(query.endsWith('|'), example.id).toBe(false);
      for (const line of query.split('\n').slice(1)) {
        expect(line.startsWith('| '), `${example.id}: ${line}`).toBe(true);
        expect(line.trim().length, example.id).toBeGreaterThan(2);
      }
    }
  });

  it('deduplicates repeated tips', () => {
    const result = buildKqlQuery(
      spec({
        where: [
          { column: 'ProcessCommandLine', operatorId: 'contains', value: 'DownloadString' },
          { column: 'ProcessCommandLine', operatorId: 'contains', value: 'DownloadString' },
        ],
      }),
    );
    expect(result.tips.length).toBe(1);
  });
});

// Every example the page prints verbatim is asserted here against the real
// builder output, so a wrong example is a failing test rather than shipped
// copy. See KQL_EXAMPLE_HUNTS' own doc comment.
describe('KQL_EXAMPLE_HUNTS render exactly as published', () => {
  const EXPECTED: Record<string, string> = {
    'office-spawns-shell': [
      'DeviceProcessEvents',
      '| where Timestamp > ago(7d)',
      '| where FileName in~ ("powershell.exe", "pwsh.exe")',
      '| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "outlook.exe")',
      '| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName',
      '| sort by Timestamp desc',
      '| limit 100',
    ].join('\n'),
    'execution-from-public': [
      'DeviceProcessEvents',
      '| where Timestamp > ago(7d)',
      '| where FolderPath startswith @"C:\\Users\\Public"',
      '| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine',
      '| sort by Timestamp desc',
      '| limit 100',
    ].join('\n'),
    'wide-outbound-fanout': [
      'DeviceNetworkEvents',
      '| where Timestamp > ago(1d)',
      '| where RemoteIPType == "Public"',
      '| summarize DistinctCount = dcount(RemoteIP) by InitiatingProcessFileName',
      '| sort by DistinctCount desc',
      '| limit 50',
    ].join('\n'),
    'failed-signins-by-source': [
      'SigninLogs',
      '| where TimeGenerated > ago(1d)',
      '| where ResultType != "0"',
      '| summarize Count = count() by IPAddress, UserPrincipalName',
      '| sort by Count desc',
      '| limit 25',
    ].join('\n'),
    'run-key-persistence': [
      'DeviceRegistryEvents',
      '| where Timestamp > ago(7d)',
      '| where RegistryKey contains @"CurrentVersion\\Run"',
      '| summarize Count = count() by DeviceName, TimeBucket = bin(Timestamp, 1h)',
      '| sort by Count desc',
      '| limit 50',
    ].join('\n'),
  };

  it('covers every published example', () => {
    expect(Object.keys(EXPECTED).sort()).toEqual(KQL_EXAMPLE_HUNTS.map((e) => e.id).sort());
    expect(new Set(KQL_EXAMPLE_HUNTS.map((e) => e.id)).size).toBe(KQL_EXAMPLE_HUNTS.length);
  });

  for (const example of KQL_EXAMPLE_HUNTS) {
    it(`builds "${example.title}" exactly`, () => {
      const result = buildKqlQuery(example.spec);
      expect(result.query).toBe(EXPECTED[example.id]);
      expect(result.warnings, `${example.id} should build cleanly`).toEqual([]);
    });
  }

  it('only references real tables, columns, operators and aggregations', () => {
    for (const example of KQL_EXAMPLE_HUNTS) {
      const table = findTable(example.spec.table);
      expect(table, example.id).toBeDefined();
      for (const clause of example.spec.where) {
        expect(findColumn(table, clause.column), `${example.id}: ${clause.column}`).toBeDefined();
        expect(findOperator(clause.operatorId), `${example.id}: ${clause.operatorId}`).toBeDefined();
      }
      for (const name of example.spec.project) {
        expect(findColumn(table, name), `${example.id}: ${name}`).toBeDefined();
      }
      if (example.spec.summarize) {
        expect(findAggregation(example.spec.summarize.aggregationId), example.id).toBeDefined();
        for (const name of example.spec.summarize.by) {
          expect(findColumn(table, name), `${example.id}: ${name}`).toBeDefined();
        }
      }
    }
  });
});
