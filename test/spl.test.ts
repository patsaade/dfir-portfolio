import { describe, it, expect } from 'vitest';
import {
  buildSpl,
  buildSplQuery,
  emptySplSpec,
  formatAggregation,
  formatBaseSearch,
  formatCommand,
  isRelativeSplTime,
  quoteSplValue,
  splFieldRef,
  validateSplQuery,
  SPL_AGG_FUNCTIONS,
  SPL_PIPE_COMMANDS,
  SPL_PRESETS,
  SPL_SEARCH_OPERATORS,
  SPL_WHERE_OPERATORS,
  type SplQuerySpec,
} from '../src/utils/spl';

function spec(partial: Partial<SplQuerySpec>): SplQuerySpec {
  const empty = emptySplSpec();
  return { base: { ...empty.base, ...(partial.base ?? {}) }, commands: partial.commands ?? [] };
}

describe('quoteSplValue — Splunk quoting rules', () => {
  it('leaves simple values unquoted', () => {
    expect(quoteSplValue('4625')).toBe('4625');
    expect(quoteSplValue('WinEventLog:Security')).toBe('WinEventLog:Security');
  });

  it('leaves wildcards unquoted, matching Splunk’s own host=webserver* example', () => {
    expect(quoteSplValue('webserver*')).toBe('webserver*');
    expect(quoteSplValue('*California*')).toBe('*California*');
  });

  it('quotes values containing white space', () => {
    expect(quoteSplValue('Northern California')).toBe('"Northern California"');
  });

  it('quotes values containing a comma, pipe, or bracket', () => {
    expect(quoteSplValue('a,b')).toBe('"a,b"');
    expect(quoteSplValue('a|b')).toBe('"a|b"');
    expect(quoteSplValue('a[b]')).toBe('"a[b]"');
  });

  it('escapes a literal double quote and quotes the result', () => {
    expect(quoteSplValue('say "hi"')).toBe('"say \\"hi\\""');
    // A quote alone still forces quoting, since " is in the documented set.
    expect(quoteSplValue('a"b')).toBe('"a\\"b"');
  });

  it('escapes a literal backslash without forcing quotes', () => {
    expect(quoteSplValue('C:\\Windows\\System32')).toBe('C:\\\\Windows\\\\System32');
  });

  it('escapes backslashes inside a value that also needs quoting', () => {
    expect(quoteSplValue('C:\\Program Files')).toBe('"C:\\\\Program Files"');
  });
});

describe('splFieldRef — eval/where field-name quoting', () => {
  it('leaves plain field names bare', () => {
    expect(splFieldRef('clientip')).toBe('clientip');
    expect(splFieldRef('Account_Name')).toBe('Account_Name');
  });

  it('leaves Splunk internal underscore fields bare', () => {
    expect(splFieldRef('_time')).toBe('_time');
    expect(splFieldRef('_raw')).toBe('_raw');
  });

  it('single-quotes a name that starts with a digit or holds a special character', () => {
    expect(splFieldRef('1stField')).toBe("'1stField'");
    expect(splFieldRef('Last.Name')).toBe("'Last.Name'");
    expect(splFieldRef('server-1')).toBe("'server-1'");
  });
});

describe('isRelativeSplTime — documented relative-time grammar', () => {
  it('accepts the documented forms', () => {
    expect(isRelativeSplTime('now')).toBe(true);
    expect(isRelativeSplTime('-1h@h')).toBe(true);
    expect(isRelativeSplTime('-2d@d')).toBe(true);
    expect(isRelativeSplTime('-24h')).toBe(true);
    expect(isRelativeSplTime('+15m')).toBe(true);
    expect(isRelativeSplTime('@d')).toBe(true);
    expect(isRelativeSplTime('@d-2h')).toBe(true);
  });

  it('accepts every documented spelling of a unit, long or short', () => {
    expect(isRelativeSplTime('-30mins')).toBe(true);
    expect(isRelativeSplTime('-1mon')).toBe(true);
    expect(isRelativeSplTime('-1months')).toBe(true);
    expect(isRelativeSplTime('-2qtrs')).toBe(true);
    expect(isRelativeSplTime('-1yr')).toBe(true);
    expect(isRelativeSplTime('-500ms')).toBe(true);
  });

  it('rejects anything outside that grammar, including absolute timestamps', () => {
    expect(isRelativeSplTime('')).toBe(false);
    expect(isRelativeSplTime('yesterday')).toBe(false);
    expect(isRelativeSplTime('-1hour ago')).toBe(false);
    expect(isRelativeSplTime('10/27/2025:00:00:00')).toBe(false);
    expect(isRelativeSplTime('-1z')).toBe(false);
  });
});

describe('formatBaseSearch', () => {
  it('emits index and sourcetype as key-value pairs', () => {
    expect(formatBaseSearch({ index: 'wineventlog', sourcetype: 'WinEventLog:Security', earliest: '', latest: '', filters: [] })).toBe(
      'index=wineventlog sourcetype=WinEventLog:Security',
    );
  });

  it('space-separates terms, which Splunk documents as an implied AND', () => {
    expect(
      formatBaseSearch({
        index: 'web',
        sourcetype: '',
        earliest: '',
        latest: '',
        filters: [
          { field: 'status', operator: '=', value: '404' },
          { field: 'clientip', operator: '=', value: '10.0.0.5' },
        ],
      }),
    ).toBe('index=web status=404 clientip=10.0.0.5');
  });

  it('supports every documented comparison operator', () => {
    expect(
      formatBaseSearch({
        index: 'app',
        sourcetype: '',
        earliest: '',
        latest: '',
        filters: [
          { field: 'code', operator: '!=', value: '200' },
          { field: 'bytes', operator: '>', value: '1000' },
          { field: 'bytes', operator: '<=', value: '9000' },
        ],
      }),
    ).toBe('index=app code!=200 bytes>1000 bytes<=9000');
  });

  it('places the time modifiers after the search terms and never quotes them', () => {
    expect(formatBaseSearch({ index: 'web', sourcetype: '', earliest: '-1h@h', latest: 'now', filters: [] })).toBe(
      'index=web earliest=-1h@h latest=now',
    );
  });

  it('drops half-filled filters instead of emitting broken syntax', () => {
    expect(
      formatBaseSearch({
        index: 'web',
        sourcetype: '',
        earliest: '',
        latest: '',
        filters: [
          { field: 'status', operator: '=', value: '' },
          { field: '', operator: '=', value: '404' },
        ],
      }),
    ).toBe('index=web');
  });

  it('returns an empty string when nothing at all is specified', () => {
    expect(formatBaseSearch(emptySplSpec().base)).toBe('');
  });
});

describe('formatAggregation', () => {
  it('emits bare count when no field is given', () => {
    expect(formatAggregation({ fn: 'count', field: '', alias: '' })).toBe('count');
  });

  it('emits count(field) when a field is given', () => {
    expect(formatAggregation({ fn: 'count', field: '_raw', alias: '' })).toBe('count(_raw)');
  });

  it('emits the parenthesised form for the field-taking functions', () => {
    expect(formatAggregation({ fn: 'dc', field: 'user', alias: '' })).toBe('dc(user)');
    expect(formatAggregation({ fn: 'sum', field: 'bytes', alias: '' })).toBe('sum(bytes)');
    expect(formatAggregation({ fn: 'avg', field: 'kbps', alias: '' })).toBe('avg(kbps)');
    expect(formatAggregation({ fn: 'min', field: 'mag', alias: '' })).toBe('min(mag)');
    expect(formatAggregation({ fn: 'max', field: 'mag', alias: '' })).toBe('max(mag)');
  });

  it('appends AS for a rename, quoting the alias only when it has white space', () => {
    expect(formatAggregation({ fn: 'sum', field: 'price', alias: 'Revenue' })).toBe('sum(price) AS Revenue');
    expect(formatAggregation({ fn: 'sum', field: 'price', alias: 'Total Revenue' })).toBe('sum(price) AS "Total Revenue"');
  });
});

describe('formatCommand — one stage at a time', () => {
  it('renders stats with comma-separated aggregations and a BY clause', () => {
    expect(
      formatCommand({
        kind: 'stats',
        aggregations: [
          { fn: 'count', field: '', alias: '' },
          { fn: 'dc', field: 'user', alias: 'users' },
        ],
        by: ['host', 'status'],
      }),
    ).toBe('stats count, dc(user) AS users BY host, status');
  });

  it('renders stats with no BY clause', () => {
    expect(formatCommand({ kind: 'stats', aggregations: [{ fn: 'dc', field: 'host', alias: '' }], by: [] })).toBe('stats dc(host)');
  });

  it('renders sort with the documented +/- direction prefixes', () => {
    expect(
      formatCommand({
        kind: 'sort',
        limit: '',
        fields: [
          { field: '_time', direction: 'asc' },
          { field: 'host', direction: 'desc' },
        ],
      }),
    ).toBe('sort +_time, -host');
  });

  it('renders sort with a leading count', () => {
    expect(formatCommand({ kind: 'sort', limit: '1', fields: [{ field: '_time', direction: 'desc' }] })).toBe('sort 1 -_time');
    expect(formatCommand({ kind: 'sort', limit: '0', fields: [{ field: 'count', direction: 'asc' }] })).toBe('sort 0 +count');
  });

  it('renders table as a comma-separated field list', () => {
    expect(formatCommand({ kind: 'table', fields: ['_time', 'host', 'user'] })).toBe('table _time, host, user');
  });

  it('renders head with and without a count', () => {
    expect(formatCommand({ kind: 'head', limit: '20' })).toBe('head 20');
    expect(formatCommand({ kind: 'head', limit: '' })).toBe('head');
  });

  it('renders eval assignments comma-separated', () => {
    expect(
      formatCommand({
        kind: 'eval',
        assignments: [
          { field: 'velocity', expression: 'distance/time' },
          { field: 'low_user', expression: 'lower(username)' },
        ],
      }),
    ).toBe('eval velocity=distance/time, low_user=lower(username)');
  });

  it('passes an eval expression through verbatim, quotes and all', () => {
    expect(formatCommand({ kind: 'eval', assignments: [{ field: 'error', expression: 'if(status == 200, "OK", "Problem")' }] })).toBe(
      'eval error=if(status == 200, "OK", "Problem")',
    );
  });

  it('double-quotes a where string operand but not a field operand', () => {
    expect(formatCommand({ kind: 'where', left: 'ipaddress', operator: '=', right: 'clientip', rightKind: 'field' })).toBe(
      'where ipaddress = clientip',
    );
    expect(formatCommand({ kind: 'where', left: 'user', operator: '=', right: 'svc_backup', rightKind: 'string' })).toBe(
      'where user = "svc_backup"',
    );
    expect(formatCommand({ kind: 'where', left: 'count', operator: '>', right: '100', rightKind: 'number' })).toBe('where count > 100');
  });

  it('renders the LIKE operator as a spaced word', () => {
    expect(formatCommand({ kind: 'where', left: 'src', operator: 'LIKE', right: '10.9.165.%', rightKind: 'string' })).toBe(
      'where src LIKE "10.9.165.%"',
    );
  });

  it('returns an empty string for a stage with nothing renderable', () => {
    expect(formatCommand({ kind: 'table', fields: [] })).toBe('');
    expect(formatCommand({ kind: 'sort', limit: '20', fields: [] })).toBe('');
    expect(formatCommand({ kind: 'stats', aggregations: [{ fn: 'sum', field: '', alias: '' }], by: ['host'] })).toBe('');
    expect(formatCommand({ kind: 'eval', assignments: [{ field: 'x', expression: '' }] })).toBe('');
    expect(formatCommand({ kind: 'where', left: '', operator: '=', right: 'x', rightKind: 'string' })).toBe('');
  });
});

describe('buildSplQuery — full assembly', () => {
  it('joins the base search and each stage with a pipe', () => {
    expect(
      buildSplQuery(
        spec({
          base: { index: 'web', sourcetype: 'access_combined', earliest: '', latest: '', filters: [] },
          commands: [
            { kind: 'stats', aggregations: [{ fn: 'count', field: '', alias: '' }], by: ['status'] },
            { kind: 'sort', limit: '', fields: [{ field: 'count', direction: 'desc' }] },
          ],
        }),
      ),
    ).toBe('index=web sourcetype=access_combined | stats count BY status | sort -count');
  });

  it('preserves the pipeline order given, never reordering it', () => {
    const stages = spec({
      base: { index: 'web', sourcetype: '', earliest: '', latest: '', filters: [] },
      commands: [
        { kind: 'head', limit: '10' },
        { kind: 'table', fields: ['_time'] },
      ],
    });
    expect(buildSplQuery(stages)).toBe('index=web | head 10 | table _time');
  });

  it('skips unrenderable stages rather than emitting a dangling pipe', () => {
    expect(
      buildSplQuery(
        spec({
          base: { index: 'web', sourcetype: '', earliest: '', latest: '', filters: [] },
          commands: [{ kind: 'table', fields: [] }, { kind: 'head', limit: '5' }],
        }),
      ),
    ).toBe('index=web | head 5');
  });

  it('returns an empty string when there is no base search', () => {
    expect(buildSplQuery(spec({ commands: [{ kind: 'head', limit: '5' }] }))).toBe('');
  });
});

describe('validateSplQuery — reports, never rewrites', () => {
  function messages(s: SplQuerySpec) {
    return validateSplQuery(s).map((i) => `${i.severity}:${i.scope}`);
  }

  it('errors when there is no base search at all', () => {
    expect(messages(emptySplSpec())).toContain('error:base');
  });

  it('warns when a sourcetype is given but no index', () => {
    const issues = validateSplQuery(spec({ base: { index: '', sourcetype: 'access_combined', earliest: '', latest: '', filters: [] } }));
    expect(issues).toHaveLength(1);
    expect(issues[0].severity).toBe('warning');
    expect(issues[0].message).toContain('No index specified');
  });

  it('is silent on a well-formed simple query', () => {
    expect(
      validateSplQuery(
        spec({
          base: { index: 'web', sourcetype: '', earliest: '-1h@h', latest: 'now', filters: [{ field: 'status', operator: '=', value: '404' }] },
          commands: [{ kind: 'table', fields: ['_time', 'clientip'] }],
        }),
      ),
    ).toEqual([]);
  });

  it('errors on a half-filled filter and names the offending part', () => {
    const issues = validateSplQuery(
      spec({ base: { index: 'web', sourcetype: '', earliest: '', latest: '', filters: [{ field: 'status', operator: '=', value: '' }] } }),
    );
    expect(issues).toHaveLength(1);
    expect(issues[0].message).toContain('"status"');
  });

  it('errors when a field-taking aggregation has no field', () => {
    const issues = validateSplQuery(
      spec({
        base: { index: 'web', sourcetype: '', earliest: '', latest: '', filters: [] },
        commands: [{ kind: 'stats', aggregations: [{ fn: 'avg', field: '', alias: '' }], by: [] }],
      }),
    );
    expect(issues.some((i) => i.severity === 'error' && i.scope === 'stats' && i.message.includes('avg(<field>)'))).toBe(true);
  });

  it('accepts a bare count, which is the one documented field-free aggregation', () => {
    expect(
      validateSplQuery(
        spec({
          base: { index: 'web', sourcetype: '', earliest: '', latest: '', filters: [] },
          commands: [{ kind: 'stats', aggregations: [{ fn: 'count', field: '', alias: '' }], by: ['host'] }],
        }),
      ),
    ).toEqual([]);
  });

  it('errors on a non-integer head or sort count', () => {
    expect(
      messages(
        spec({
          base: { index: 'web', sourcetype: '', earliest: '', latest: '', filters: [] },
          commands: [{ kind: 'head', limit: 'ten' }],
        }),
      ),
    ).toContain('error:head');
    expect(
      messages(
        spec({
          base: { index: 'web', sourcetype: '', earliest: '', latest: '', filters: [] },
          commands: [{ kind: 'sort', limit: '1.5', fields: [{ field: 'count', direction: 'desc' }] }],
        }),
      ),
    ).toContain('error:sort');
  });

  it('warns that a bare head falls back to the documented default of 10', () => {
    const issues = validateSplQuery(
      spec({ base: { index: 'web', sourcetype: '', earliest: '', latest: '', filters: [] }, commands: [{ kind: 'head', limit: '' }] }),
    );
    expect(issues[0].message).toContain('default of 10');
  });

  it('errors when a where operand is marked numeric but is not a number', () => {
    const issues = validateSplQuery(
      spec({
        base: { index: 'web', sourcetype: '', earliest: '', latest: '', filters: [] },
        commands: [{ kind: 'where', left: 'user', operator: '=', right: 'admin', rightKind: 'number' }],
      }),
    );
    expect(issues.some((i) => i.severity === 'error' && i.scope === 'where')).toBe(true);
  });

  it('warns that a non-relative time value is passed through verbatim', () => {
    const issues = validateSplQuery(
      spec({ base: { index: 'web', sourcetype: '', earliest: 'yesterday', latest: '', filters: [] } }),
    );
    expect(issues.some((i) => i.severity === 'warning' && i.message.includes('passed through exactly as typed'))).toBe(true);
  });

  it('warns that stages after stats only see what stats produced', () => {
    const issues = validateSplQuery(
      spec({
        base: { index: 'web', sourcetype: '', earliest: '', latest: '', filters: [] },
        commands: [
          { kind: 'stats', aggregations: [{ fn: 'count', field: '', alias: '' }], by: ['host'] },
          { kind: 'table', fields: ['_raw'] },
        ],
      }),
    );
    expect(issues.some((i) => i.severity === 'warning' && i.scope === 'stats')).toBe(true);
  });

  it('does not raise that warning when nothing follows stats', () => {
    expect(
      validateSplQuery(
        spec({
          base: { index: 'web', sourcetype: '', earliest: '', latest: '', filters: [] },
          commands: [{ kind: 'stats', aggregations: [{ fn: 'count', field: '', alias: '' }], by: ['host'] }],
        }),
      ),
    ).toEqual([]);
  });
});

describe('buildSpl — combined wrapper', () => {
  it('returns both the query text and its issues', () => {
    const result = buildSpl(
      spec({
        base: { index: '', sourcetype: 'access_combined', earliest: '', latest: '', filters: [] },
        commands: [{ kind: 'head', limit: '5' }],
      }),
    );
    expect(result.query).toBe('sourcetype=access_combined | head 5');
    expect(result.issues).toHaveLength(1);
    expect(result.issues[0].severity).toBe('warning');
  });
});

// ---------------------------------------------------------------------------
// The worked examples the page prints. These assertions are the reason the
// page never hardcodes a query string: it renders buildSplQuery(preset.spec),
// so a preset that assembled wrongly would fail here before it could ship.
// ---------------------------------------------------------------------------

describe('SPL_PRESETS — the worked examples printed on the page', () => {
  function preset(id: string) {
    const found = SPL_PRESETS.find((p) => p.id === id);
    expect(found, `preset "${id}" exists`).toBeDefined();
    return found!;
  }

  it('assembles the failed-logon example exactly', () => {
    expect(buildSplQuery(preset('failed-logons').spec)).toBe(
      'index=wineventlog sourcetype=WinEventLog:Security EventCode=4625 earliest=-24h@h latest=now' +
        ' | stats count, dc(Account_Name) AS distinct_accounts BY src_ip' +
        ' | sort 20 -count',
    );
  });

  it('assembles the rare-parent-process example exactly', () => {
    expect(buildSplQuery(preset('rare-parents').spec)).toBe(
      'index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1 earliest=-7d@d latest=now' +
        ' | stats count BY ParentImage, Image' +
        ' | where count < 5' +
        ' | sort 0 +count' +
        ' | table count, ParentImage, Image',
    );
  });

  it('assembles the field-comparison example exactly', () => {
    expect(buildSplQuery(preset('field-comparison').spec)).toBe(
      'index=proxy earliest=-1h@h latest=now | where src_ip != dest_ip | head 100',
    );
  });

  it('assembles the derived-field example exactly', () => {
    expect(buildSplQuery(preset('derived-field').spec)).toBe(
      'index=web sourcetype=access_combined earliest=-4h@h latest=now' +
        ' | eval kb=bytes/1024' +
        ' | where kb > 500' +
        ' | table _time, clientip, uri_path, kb' +
        ' | sort -kb',
    );
  });

  it('gives every preset a unique id and a non-empty assembled query', () => {
    const ids = SPL_PRESETS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const p of SPL_PRESETS) {
      expect(buildSplQuery(p.spec), p.id).not.toBe('');
      expect(p.label.length, p.id).toBeGreaterThan(0);
      expect(p.description.length, p.id).toBeGreaterThan(0);
    }
  });

  // SplBuilder.astro renders exactly one card per command kind, so a preset
  // using the same command twice could not be loaded back into the UI
  // faithfully. Guarding it here keeps that coupling from breaking silently.
  it('uses each command kind at most once per preset', () => {
    for (const p of SPL_PRESETS) {
      const kinds = p.spec.commands.map((c) => c.kind);
      expect(new Set(kinds).size, `${p.id} uses each command at most once`).toBe(kinds.length);
    }
  });

  it('ships no preset that its own validator flags as an error', () => {
    for (const p of SPL_PRESETS) {
      const errors = validateSplQuery(p.spec).filter((i) => i.severity === 'error');
      expect(errors, `${p.id} has no validation errors`).toEqual([]);
    }
  });
});

describe('reference tables rendered on the page', () => {
  it('documents every aggregation function the builder can emit', () => {
    const ids = SPL_AGG_FUNCTIONS.map((f) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
    // count is the only field-free one, per Splunk's own stats examples.
    expect(SPL_AGG_FUNCTIONS.filter((f) => !f.requiresField).map((f) => f.id)).toEqual(['count']);
    for (const f of SPL_AGG_FUNCTIONS) {
      expect(f.syntax, f.id).toContain(f.id === 'dc' ? 'dc(' : f.id);
      expect(f.hint.length, f.id).toBeGreaterThan(0);
    }
  });

  it('documents every pipe command the builder can emit, with a doc link each', () => {
    const ids = SPL_PIPE_COMMANDS.map((c) => c.id).sort();
    expect(ids).toEqual(['eval', 'head', 'sort', 'stats', 'table', 'where']);
    for (const c of SPL_PIPE_COMMANDS) {
      expect(c.syntax.startsWith(c.id), c.id).toBe(true);
      expect(c.docUrl.startsWith('https://help.splunk.com/'), c.id).toBe(true);
      expect(c.summary.length, c.id).toBeGreaterThan(0);
    }
  });

  it('lists the operator sets the builder offers', () => {
    expect(SPL_SEARCH_OPERATORS.map((o) => o.id)).toEqual(['=', '!=', '<', '<=', '>', '>=']);
    expect(SPL_WHERE_OPERATORS).toEqual(['=', '==', '!=', '<', '<=', '>', '>=', 'LIKE']);
  });
});
