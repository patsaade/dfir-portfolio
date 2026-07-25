// KQL Query Builder — pure functions, no DOM dependency (unit tested directly
// in test/kql.test.ts, imported into the client bundle by KqlBuilder.astro to
// re-assemble the query live as the form changes).
//
// This ASSEMBLES KQL TEXT. It does not parse, execute, or validate a query
// against a real tenant — there is no backend here and nothing is ever sent
// anywhere. The output is meant to be copied into the Microsoft Defender
// portal's advanced hunting page or a Microsoft Sentinel Logs blade and run
// there.
//
// EXPLICITLY-SCOPED SUBSET (documented cuts, not silent gaps) — same
// discipline as utils/sigma.ts. Supported pipeline, in this fixed order:
//
//   <Table>
//   | where <timeColumn> > ago(<timespan>)     -- optional
//   | where <column> <operator> <value>        -- zero or more
//   | summarize <Alias> = <agg>(<col>) by ...  -- optional
//   | project <columns>                        -- optional, and mutually
//                                                 exclusive with summarize
//   | sort by <column> asc|desc                -- optional
//   | limit <n>                                -- optional
//
// NOT supported, deliberately:
//   - join / union / let / extend / parse / externaldata / mv-expand, or any
//     multi-table correlation. One table, one linear pipeline.
//   - Nested boolean logic. Every `| where` line is AND-ed with the others
//     (that is exactly what a sequence of `where` operators means in KQL);
//     there is no OR grouping or parenthesised predicate builder. Use an
//     `in`/`has_any` list operator for the common "any of these values" case.
//   - `dynamic`/JSON column access (`tostring(Col.prop)`, `parse_json()`).
//     Those columns are excluded from the reference data — see src/data/kql.ts.
//   - Renaming projected columns, computed columns, or custom aggregate
//     aliases. The aggregate alias is fixed per aggregation function.
//   - summarize + project together. `project` after a `summarize` can only
//     reference the summarize output columns, so pairing the two in a
//     builder is a reliable way to generate a query that errors. When a
//     summarize is configured the project list is dropped and a note says so,
//     rather than emitting something that looks right and fails.
//
// Anything this module cannot render correctly is DROPPED and reported in
// `warnings` — it is never guessed at and never emitted as broken KQL.

import {
  KQL_AGGREGATIONS,
  KQL_OPERATORS,
  KQL_TABLES,
  type KqlAggregation,
  type KqlColumn,
  type KqlColumnKind,
  type KqlOperator,
  type KqlTable,
} from '../data/kql';

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

export function findTable(name: string): KqlTable | undefined {
  return KQL_TABLES.find((t) => t.name === name);
}

export function findColumn(table: KqlTable | undefined, name: string): KqlColumn | undefined {
  if (!table) return undefined;
  return table.columns.find((c) => c.name === name);
}

export function findOperator(id: string): KqlOperator | undefined {
  return KQL_OPERATORS.find((o) => o.id === id);
}

export function findAggregation(id: string): KqlAggregation | undefined {
  return KQL_AGGREGATIONS.find((a) => a.id === id);
}

/** Operators offered for a given column kind — drives the operator dropdown
 *  so a numeric column never gets `startswith` and a string column never gets
 *  `>`. */
export function operatorsForKind(kind: KqlColumnKind): KqlOperator[] {
  return KQL_OPERATORS.filter((o) => o.kinds.includes(kind));
}

// ---------------------------------------------------------------------------
// Value rendering
// ---------------------------------------------------------------------------

const NUMERIC_RE = /^-?\d+(\.\d+)?$/;
/** A bare date or date-time the builder can safely wrap in `datetime(...)`. */
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}([T ][0-9:.]+Z?)?$/;
/** Any `something(...)` call — `ago(7d)`, `now()`, `datetime(2026-01-01)`. */
const FUNCTION_CALL_RE = /^[A-Za-z_][A-Za-z0-9_]*\s*\(.*\)$/;

/**
 * Encode a value as a KQL `string` literal.
 *
 * Two forms, both straight out of the Kusto string-literal rules:
 *   - A **verbatim** literal `@"..."` when the value contains a backslash and
 *     nothing that would need escaping inside one. In a verbatim literal the
 *     backslash stands for itself, which is what makes `@"C:\Windows\System32"`
 *     the readable, idiomatic way to write a Windows path or a regex — and
 *     this tool's values are overwhelmingly paths and regexes.
 *   - Otherwise a standard double-quoted literal, escaping the backslash
 *     itself, the enclosing double quote, and the tab/newline/return
 *     characters.
 *
 * Single quotes are kept out of the verbatim branch as well: quote characters
 * have their own doubling rules inside verbatim literals, and the escaped
 * form is unambiguously correct for them.
 */
export function quoteKqlString(raw: string): string {
  const hasBackslash = raw.indexOf('\\') !== -1;
  const needsEscaping = /["'\n\r\t]/.test(raw);
  if (hasBackslash && !needsEscaping) return '@"' + raw + '"';
  return (
    '"' +
    raw
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/\t/g, '\\t')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r') +
    '"'
  );
}

export interface RenderedValue {
  /** null when the value could not be rendered for this column kind. */
  text: string | null;
  error?: string;
}

/** Render a single scalar right-hand side for a column of the given kind. */
export function renderValue(raw: string, kind: KqlColumnKind, columnName: string): RenderedValue {
  const value = raw.trim();
  if (value === '') return { text: null, error: `${columnName}: no value entered — filter skipped.` };

  if (kind === 'numeric') {
    if (!NUMERIC_RE.test(value)) {
      return { text: null, error: `${columnName} is a numeric column but "${value}" is not a number — filter skipped.` };
    }
    return { text: value };
  }

  if (kind === 'bool') {
    const lower = value.toLowerCase();
    if (lower !== 'true' && lower !== 'false') {
      return { text: null, error: `${columnName} is a boolean column — enter true or false, not "${value}". Filter skipped.` };
    }
    return { text: lower };
  }

  if (kind === 'datetime') {
    if (ISO_DATE_RE.test(value)) return { text: `datetime(${value})` };
    if (FUNCTION_CALL_RE.test(value)) return { text: value };
    return {
      text: null,
      error: `${columnName} is a datetime column — use ago(7d), now(), datetime(2026-01-31), or a plain 2026-01-31 date. "${value}" was skipped.`,
    };
  }

  return { text: quoteKqlString(value) };
}

/**
 * Split the comma-separated text behind a list operator (`in`, `in~`, `!in`,
 * `has_any`, `has_all`) into its individual values, dropping blanks and
 * stripping any quotes the user typed themselves so they are not double-quoted
 * in the output.
 */
export function parseKqlList(raw: string): string[] {
  return raw
    .split(',')
    .map((part) => {
      const trimmed = part.trim();
      if (trimmed.length >= 2) {
        const first = trimmed[0];
        const last = trimmed[trimmed.length - 1];
        if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
          return trimmed.slice(1, -1).trim();
        }
      }
      return trimmed;
    })
    .filter((part) => part !== '');
}

// ---------------------------------------------------------------------------
// Where clauses
// ---------------------------------------------------------------------------

export interface KqlWhereClause {
  column: string;
  operatorId: string;
  value: string;
}

export interface RenderedClause {
  /** The full predicate text, e.g. `FileName =~ "rundll32.exe"`. null when the
   *  clause is incomplete or invalid and was dropped. */
  text: string | null;
  /** A real problem: the clause was dropped and the reader needs to know. */
  warnings: string[];
  /** Performance/behaviour guidance, straight from Microsoft's own advanced
   *  hunting best-practices page. Never a reason to drop a clause. */
  tips: string[];
}

const TERM_OPERATOR_IDS = ['has', 'nhas', 'has_cs', 'has_any', 'has_all'];

/** Render one `where` predicate. Returns text:null (plus a warning) rather
 *  than guessing whenever the value does not fit the column's type. */
export function renderWhereClause(table: KqlTable | undefined, clause: KqlWhereClause): RenderedClause {
  const warnings: string[] = [];
  const tips: string[] = [];
  const column = findColumn(table, clause.column);
  const operator = findOperator(clause.operatorId);

  if (!column) {
    return { text: null, warnings: [`Unknown column "${clause.column}" — filter skipped.`], tips };
  }
  if (!operator) {
    return { text: null, warnings: [`Unknown operator for ${column.name} — filter skipped.`], tips };
  }
  if (!operator.kinds.includes(column.kind)) {
    return {
      text: null,
      warnings: [`${operator.symbol} does not apply to ${column.name} (${column.type}) — filter skipped.`],
      tips,
    };
  }

  if (operator.form === 'function') {
    return { text: `${operator.symbol}(${column.name})`, warnings, tips };
  }

  if (operator.form === 'list') {
    const items = parseKqlList(clause.value);
    if (items.length === 0) {
      return { text: null, warnings: [], tips: [`${column.name}: no values entered for ${operator.symbol} — filter skipped.`] };
    }
    const rendered: string[] = [];
    for (const item of items) {
      const value = renderValue(item, column.kind, column.name);
      if (value.text === null) {
        warnings.push(value.error ?? `${column.name}: could not render "${item}".`);
        continue;
      }
      rendered.push(value.text);
    }
    if (rendered.length === 0) return { text: null, warnings, tips };
    // `in (...)` takes a space before the parenthesis; `has_any(...)` and
    // `has_all(...)` are written as calls, matching Microsoft's own examples.
    const separator = operator.symbol === 'has_any' || operator.symbol === 'has_all' ? '' : ' ';
    if (TERM_OPERATOR_IDS.includes(operator.id)) {
      collectShortTermTip(items, column.name, tips);
    }
    return { text: `${column.name} ${operator.symbol}${separator}(${rendered.join(', ')})`, warnings, tips };
  }

  // Binary form.
  const value = renderValue(clause.value, column.kind, column.name);
  if (value.text === null) {
    // An empty box on a freshly added row is not a mistake, just an unfinished
    // step — report it as a tip, not a warning.
    const message = value.error ?? `${column.name}: could not render value.`;
    if (clause.value.trim() === '') return { text: null, warnings: [], tips: [message] };
    return { text: null, warnings: [message], tips };
  }
  if (TERM_OPERATOR_IDS.includes(operator.id)) {
    collectShortTermTip([clause.value.trim()], column.name, tips);
  }
  if (operator.id === 'contains' || operator.id === 'ncontains' || operator.id === 'contains_cs') {
    tips.push(
      `${column.name} uses ${operator.symbol}, which scans the column instead of using its term index. Microsoft recommends has where the value is a whole term bounded by non-alphanumeric characters.`,
    );
  }
  return { text: `${column.name} ${operator.symbol} ${value.text}`, warnings, tips };
}

/** Microsoft: terms of fewer than three characters are not indexed, so a
 *  has-family match on one costs more resources than it looks like it should. */
function collectShortTermTip(items: string[], columnName: string, tips: string[]): void {
  const shortItems = items.filter((item) => item.length > 0 && item.length < 3);
  if (shortItems.length === 0) return;
  tips.push(
    `${columnName}: "${shortItems[0]}" is fewer than three characters. Kusto only indexes terms of three characters or more, so this match has to scan.`,
  );
}

// ---------------------------------------------------------------------------
// Query assembly
// ---------------------------------------------------------------------------

export interface KqlSummarize {
  aggregationId: string;
  /** Column the aggregation is applied to. Ignored when the aggregation takes
   *  no argument (count()). */
  aggColumn: string;
  /** Group-by columns, in order. May be empty for a whole-table aggregate. */
  by: string[];
  /** When set, an extra `TimeBucket = bin(<column>, <binSize>)` group key. */
  binColumn: string;
  binSize: string;
}

export interface KqlQuerySpec {
  table: string;
  /** Timespan literal for the `ago()` filter, or '' for no time filter. */
  timespan: string;
  where: KqlWhereClause[];
  project: string[];
  summarize: KqlSummarize | null;
  sort: { column: string; direction: 'asc' | 'desc' } | null;
  limit: number | null;
}

export interface KqlBuildResult {
  /** The assembled query, one pipeline step per line. */
  query: string;
  lines: string[];
  warnings: string[];
  tips: string[];
}

/** The fixed output column name the builder gives a bin() group key. Named
 *  explicitly rather than relying on the implicit name KQL would assign. */
export const TIME_BUCKET_ALIAS = 'TimeBucket';

/**
 * Which columns the pipeline actually emits, given the spec — `null` means
 * "every column of the table" (no summarize and no project). Drives both the
 * sort dropdown and the check that a sort column survived the projection.
 */
export function outputColumns(spec: KqlQuerySpec): string[] | null {
  const table = findTable(spec.table);
  if (!table) return null;

  if (spec.summarize) {
    const aggregation = findAggregation(spec.summarize.aggregationId);
    const columns: string[] = [];
    for (const name of spec.summarize.by) {
      if (name && findColumn(table, name) && !columns.includes(name)) columns.push(name);
    }
    if (spec.summarize.binColumn && findColumn(table, spec.summarize.binColumn)) {
      if (!columns.includes(TIME_BUCKET_ALIAS)) columns.push(TIME_BUCKET_ALIAS);
    }
    if (aggregation) columns.push(aggregation.alias);
    return columns;
  }

  const projected = spec.project.filter((name, index) => findColumn(table, name) && spec.project.indexOf(name) === index);
  return projected.length > 0 ? projected : null;
}

/** Columns a `sort by` can legally reference for this spec. */
export function availableSortColumns(spec: KqlQuerySpec): string[] {
  const explicit = outputColumns(spec);
  if (explicit) return explicit;
  const table = findTable(spec.table);
  return table ? table.columns.map((c) => c.name) : [];
}

/** Assemble the query. Never throws; anything unrenderable is dropped and
 *  reported in `warnings`. */
export function buildKqlQuery(spec: KqlQuerySpec): KqlBuildResult {
  const warnings: string[] = [];
  const tips: string[] = [];
  const table = findTable(spec.table);

  if (!table) {
    return { query: '', lines: [], warnings: [`Unknown table "${spec.table}".`], tips };
  }

  const lines: string[] = [table.name];

  // 1. Time filter first — Microsoft's advanced hunting guidance is to apply
  //    time and other filters before anything that transforms the data.
  if (spec.timespan) {
    lines.push(`| where ${table.timeColumn} > ago(${spec.timespan})`);
  } else {
    tips.push(
      `No time filter. Microsoft's advanced hunting guidance is to scope every query by ${table.timeColumn} first — an unscoped query reads the whole retained window and is the usual cause of a timeout.`,
    );
  }

  // 2. Filters, one `| where` per clause. Sequential where operators are
  //    AND-ed; this builder has no OR grouping (see the file header).
  for (const clause of spec.where) {
    const rendered = renderWhereClause(table, clause);
    for (const w of rendered.warnings) warnings.push(w);
    for (const t of rendered.tips) tips.push(t);
    if (rendered.text) lines.push(`| where ${rendered.text}`);
  }

  // 3. summarize, or project — never both (see the file header).
  let summarized = false;
  if (spec.summarize) {
    const aggregation = findAggregation(spec.summarize.aggregationId);
    if (!aggregation) {
      warnings.push('Unknown aggregation — summarize step skipped.');
    } else {
      let call: string | null = null;
      if (!aggregation.needsColumn) {
        call = `${aggregation.fn}()`;
      } else {
        const aggColumn = findColumn(table, spec.summarize.aggColumn);
        if (!aggColumn) {
          warnings.push(`${aggregation.fn}() needs a column to aggregate — summarize step skipped.`);
        } else if (!aggregation.columnKinds.includes(aggColumn.kind)) {
          warnings.push(
            `${aggregation.fn}() cannot be applied to ${aggColumn.name} (${aggColumn.type}) — summarize step skipped.`,
          );
        } else {
          call = `${aggregation.fn}(${aggColumn.name})`;
        }
      }

      if (call) {
        const groupKeys: string[] = [];
        for (const name of spec.summarize.by) {
          if (!name) continue;
          const column = findColumn(table, name);
          if (!column) {
            warnings.push(`Unknown group-by column "${name}" — dropped from summarize.`);
            continue;
          }
          if (!groupKeys.includes(column.name)) groupKeys.push(column.name);
        }
        if (spec.summarize.binColumn) {
          const binColumn = findColumn(table, spec.summarize.binColumn);
          if (!binColumn) {
            warnings.push(`Unknown bin column "${spec.summarize.binColumn}" — time bucketing dropped.`);
          } else if (binColumn.kind !== 'datetime') {
            warnings.push(`bin() bucketing needs a datetime column; ${binColumn.name} is ${binColumn.type} — time bucketing dropped.`);
          } else if (!spec.summarize.binSize) {
            warnings.push('No bucket width chosen for bin() — time bucketing dropped.');
          } else {
            groupKeys.push(`${TIME_BUCKET_ALIAS} = bin(${binColumn.name}, ${spec.summarize.binSize})`);
          }
        }
        const by = groupKeys.length > 0 ? ` by ${groupKeys.join(', ')}` : '';
        lines.push(`| summarize ${aggregation.alias} = ${call}${by}`);
        summarized = true;
      }
    }
    if (summarized && spec.project.length > 0) {
      tips.push(
        'Project list ignored: after a summarize the pipeline only carries the group-by keys and the aggregate, so a project of the original table columns would error.',
      );
    }
  }

  if (!summarized && spec.project.length > 0) {
    const seen: string[] = [];
    for (const name of spec.project) {
      const column = findColumn(table, name);
      if (!column) {
        warnings.push(`Unknown column "${name}" — dropped from project.`);
        continue;
      }
      if (!seen.includes(column.name)) seen.push(column.name);
    }
    if (seen.length > 0) lines.push(`| project ${seen.join(', ')}`);
  }

  // 4. sort, restricted to columns that survived the pipeline.
  if (spec.sort && spec.sort.column) {
    const allowed = availableSortColumns(spec);
    if (allowed.includes(spec.sort.column)) {
      // Direction is always written out. `sort by` defaults to desc, but
      // relying on a default in generated text is how a query quietly starts
      // meaning something else.
      lines.push(`| sort by ${spec.sort.column} ${spec.sort.direction}`);
    } else {
      warnings.push(
        `Cannot sort by ${spec.sort.column}: it is not one of the columns this query returns — sort step skipped.`,
      );
    }
  }

  // 5. limit last, so the row cap applies to the final shape of the result.
  if (spec.limit !== null && spec.limit !== undefined) {
    if (!Number.isInteger(spec.limit) || spec.limit <= 0) {
      warnings.push(`Row limit must be a positive whole number — "${spec.limit}" ignored.`);
    } else {
      lines.push(`| limit ${spec.limit}`);
    }
  }

  return { query: lines.join('\n'), lines, warnings, tips: dedupe(tips) };
}

function dedupe(values: string[]): string[] {
  const out: string[] = [];
  for (const value of values) if (!out.includes(value)) out.push(value);
  return out;
}

// ---------------------------------------------------------------------------
// Worked examples
// ---------------------------------------------------------------------------

export interface KqlExampleHunt {
  id: string;
  title: string;
  /** Why an analyst would run this, in one line. */
  rationale: string;
  spec: KqlQuerySpec;
}

/**
 * Starter hunts the page offers as presets and prints verbatim.
 *
 * These are NOT hand-written query text. Each one is a spec; the page renders
 * `buildKqlQuery(spec).query` for it, and test/kql.test.ts asserts the exact
 * expected output of every single one. A wrong example therefore cannot ship —
 * either the builder produces the query in the test or the suite fails.
 */
export const KQL_EXAMPLE_HUNTS: KqlExampleHunt[] = [
  {
    id: 'office-spawns-shell',
    title: 'Office application spawning a shell',
    rationale:
      'A Word, Excel, or Outlook process starting PowerShell is a classic macro/phishing execution chain. Case-insensitive matching on the file names keeps the hunt durable against command-line tricks.',
    spec: {
      table: 'DeviceProcessEvents',
      timespan: '7d',
      where: [
        { column: 'FileName', operatorId: 'in_ci', value: 'powershell.exe, pwsh.exe' },
        { column: 'InitiatingProcessFileName', operatorId: 'in_ci', value: 'winword.exe, excel.exe, outlook.exe' },
      ],
      project: ['Timestamp', 'DeviceName', 'AccountName', 'ProcessCommandLine', 'InitiatingProcessFileName'],
      summarize: null,
      sort: { column: 'Timestamp', direction: 'desc' },
      limit: 100,
    },
  },
  {
    id: 'execution-from-public',
    title: 'Execution from a world-writable path',
    rationale:
      'Binaries running out of C:\\Users\\Public are worth a look on their own. Shows how a Windows path is emitted as a verbatim string literal so the backslashes stay literal.',
    spec: {
      table: 'DeviceProcessEvents',
      timespan: '7d',
      where: [{ column: 'FolderPath', operatorId: 'startswith', value: 'C:\\Users\\Public' }],
      project: ['Timestamp', 'DeviceName', 'FileName', 'FolderPath', 'ProcessCommandLine'],
      summarize: null,
      sort: { column: 'Timestamp', direction: 'desc' },
      limit: 100,
    },
  },
  {
    id: 'wide-outbound-fanout',
    title: 'Processes talking to many public addresses',
    rationale:
      'Counting distinct public destinations per process surfaces both scanning behaviour and beaconing implants hiding inside an otherwise unremarkable binary.',
    spec: {
      table: 'DeviceNetworkEvents',
      timespan: '1d',
      where: [{ column: 'RemoteIPType', operatorId: 'eq', value: 'Public' }],
      project: [],
      summarize: {
        aggregationId: 'dcount',
        aggColumn: 'RemoteIP',
        by: ['InitiatingProcessFileName'],
        binColumn: '',
        binSize: '',
      },
      sort: { column: 'DistinctCount', direction: 'desc' },
      limit: 50,
    },
  },
  {
    id: 'failed-signins-by-source',
    title: 'Failed sign-ins grouped by source address',
    rationale:
      'ResultType is 0 on success, so anything else is a failure. Grouping by IP and account is the first pass at telling password spraying apart from one user fat-fingering a password.',
    spec: {
      table: 'SigninLogs',
      timespan: '1d',
      where: [{ column: 'ResultType', operatorId: 'neq', value: '0' }],
      project: [],
      summarize: {
        aggregationId: 'count',
        aggColumn: '',
        by: ['IPAddress', 'UserPrincipalName'],
        binColumn: '',
        binSize: '',
      },
      sort: { column: 'Count', direction: 'desc' },
      limit: 25,
    },
  },
  {
    id: 'run-key-persistence',
    title: 'Run-key persistence written over time',
    rationale:
      'Registry Run keys are still one of the most common persistence footholds. Bucketing by hour turns a flat list into something you can eyeball for a burst. Uses contains rather than has because the key fragment spans a path separator, so it is not a single indexed term.',
    spec: {
      table: 'DeviceRegistryEvents',
      timespan: '7d',
      where: [{ column: 'RegistryKey', operatorId: 'contains', value: 'CurrentVersion\\Run' }],
      project: [],
      summarize: {
        aggregationId: 'count',
        aggColumn: '',
        by: ['DeviceName'],
        binColumn: 'Timestamp',
        binSize: '1h',
      },
      sort: { column: 'Count', direction: 'desc' },
      limit: 50,
    },
  },
];
