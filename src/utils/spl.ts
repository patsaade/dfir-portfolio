// Splunk SPL Query Builder — pure, DOM-free query-assembly functions (unit
// tested directly in test/spl.test.ts, imported into the client bundle by
// SplBuilder.astro so the assembled query re-renders live as you type).
//
// This assembles an EXPLICITLY-SCOPED SUBSET of Splunk's Search Processing
// Language (SPL, not SPL2), verified command-by-command against Splunk's own
// Search Reference on help.splunk.com. It is a *writer*, never a parser and
// never a search engine — it turns a structured spec into query text you copy
// into your own Splunk search bar. Nothing here connects to a Splunk instance.
//
// Supported:
//   - a base search: `index=`, `sourcetype=`, the `earliest=`/`latest=` time
//     modifiers, and any number of `field<op>value` filters using the six
//     comparison operators the `search` command documents (= != < <= > >=).
//     Terms are space-separated, which the docs define as an implied AND.
//   - six pipe commands, each matching its documented syntax:
//       | where <eval-expression>            (one guided comparison)
//       | eval <field>=<expr>[, <field>=<expr>]...
//       | stats <agg>(<field>) [AS <name>][, ...] [BY <field-list>]
//       | sort [<count>] (+|-)<field>[, ...]
//       | table <field-list>
//       | head [<N>]
//   - the quoting/escaping rules Splunk documents: values containing white
//     space, commas, pipes, quotation marks, or brackets get double-quoted;
//     a literal backslash is escaped as `\\` and a literal double quote as
//     `\"`. Callers pass the LITERAL value they want matched — escaping is
//     this module's job, not the user's.
//
// Explicitly NOT supported (deliberate scope cuts, documented on the page, not
// silent gaps):
//   - Reading SPL. There is no parser; the data flow is one-way (spec → text),
//     unlike utils/sigma.ts which round-trips its own generated shape.
//   - Validating the free-text halves. An `eval` expression and the right-hand
//     operand of a `where` comparison are passed through VERBATIM — this module
//     will not second-guess, reformat, or syntax-check them, because doing so
//     without implementing Splunk's full eval grammar would mean guessing.
//     Same for `earliest`/`latest`: the value is emitted exactly as typed
//     (Splunk accepts relative *and* absolute forms), with a warning when it
//     doesn't match the documented relative-time grammar.
//   - Aggregation functions beyond the six on Splunk's "Aggregate functions"
//     page that this tool could verify a syntax line for (count, dc, sum, avg,
//     min, max). Splunk has many more, including multivalue ones like
//     `values()`; they're out of scope rather than half-verified.
//   - Everything else in SPL: subsearches, macros, lookups, `tstats`/data
//     models, `transaction`, `rex`/field extraction, `timechart`/`chart`,
//     `dedup`/`top`/`rare`, `rename`, `fields`, real-time (`rt`) time
//     modifiers, and SPL2 syntax.
//
// Sources (Splunk Search Reference / Search Manual, help.splunk.com):
//   search, stats, sort, where, eval, table, head command pages; the
//   "Aggregate functions", "Time modifiers", and "Backslashes" pages.

// ---------------------------------------------------------------------------
// Quoting & escaping
// ---------------------------------------------------------------------------

/** The character classes Splunk's `search` docs name as requiring quotation
 *  marks around a value: white space, commas, pipes, quotation marks, and
 *  brackets. Deliberately NOT broader than what's documented — `host=web*`
 *  and `status=404` stay unquoted, matching Splunk's own examples. */
const NEEDS_QUOTES = /[\s,|"[\]]/;

/** A field name simple enough to write bare in an eval/where expression.
 *  Splunk's `eval` docs require single quotes around a field name that starts
 *  with a number or contains non-alphanumeric characters; the leading
 *  underscore of Splunk's own internal fields (`_time`, `_raw`) is written
 *  bare throughout the official examples, so it's allowed here too. */
const PLAIN_FIELD = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** Escape the two characters Splunk documents an escape sequence for: a
 *  literal backslash (`\\`) and a literal double quote (`\"`). Applied before
 *  any quoting decision, so `C:\Windows` becomes `C:\\Windows` whether or not
 *  the value also ends up wrapped in quotes. */
function escapeSplLiteral(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/** Render a literal value for the right-hand side of a `search` key-value
 *  pair, quoting only when Splunk's own rules call for it. */
export function quoteSplValue(value: string): string {
  const escaped = escapeSplLiteral(value);
  // A value that needed escaping contained a quote or a backslash; a quote
  // forces quoting via NEEDS_QUOTES below, a bare backslash does not.
  return NEEDS_QUOTES.test(value) || value === '' ? `"${escaped}"` : escaped;
}

/** Render a field NAME for use inside an eval/where expression, single-quoting
 *  it when Splunk requires that (leading digit, or any character outside
 *  `[A-Za-z0-9_]`). */
export function splFieldRef(name: string): string {
  return PLAIN_FIELD.test(name) ? name : `'${name.replace(/'/g, "\\'")}'`;
}

// ---------------------------------------------------------------------------
// Spec types
// ---------------------------------------------------------------------------

/** The comparison operators the `search` command documents for a
 *  `<field><comparison-operator><value>` expression. */
export type SplComparison = '=' | '!=' | '<' | '<=' | '>' | '>=';

export const SPL_SEARCH_OPERATORS: { id: SplComparison; hint: string }[] = [
  { id: '=', hint: 'Equals. String values compare literally; wildcards (*) are allowed.' },
  { id: '!=', hint: 'Not equal to. Also compares string values literally.' },
  { id: '<', hint: 'Less than — a numeric comparison.' },
  { id: '<=', hint: 'Less than or equal to — a numeric comparison.' },
  { id: '>', hint: 'Greater than — a numeric comparison.' },
  { id: '>=', hint: 'Greater than or equal to — a numeric comparison.' },
];

/** The operators Splunk's `eval` Usage table lists, which `where` reuses
 *  because it shares eval's expression syntax. Restricted here to the
 *  comparison/matching subset a guided two-operand row can express — the
 *  arithmetic (`+ - * / %`), concatenation (`.`) and multi-clause boolean
 *  (`AND OR NOT XOR`) operators from that same table are reachable through the
 *  free-text `eval` stage instead. */
export type SplWhereOperator = '=' | '==' | '!=' | '<' | '<=' | '>' | '>=' | 'LIKE';

export const SPL_WHERE_OPERATORS: SplWhereOperator[] = ['=', '==', '!=', '<', '<=', '>', '>=', 'LIKE'];

/** How the right-hand operand of a `where` comparison should be rendered. This
 *  is the distinction Splunk's own `where` docs call out as the command's
 *  biggest gotcha versus `search`: `where ipaddress=clientip` compares two
 *  FIELDS, while a string literal has to be double-quoted to be a literal. */
type SplOperandKind = 'string' | 'number' | 'field';

interface SplFilter {
  field: string;
  operator: SplComparison;
  value: string;
}

export interface SplBaseSearch {
  index: string;
  sourcetype: string;
  /** Emitted verbatim — see the file header. */
  earliest: string;
  /** Emitted verbatim — see the file header. */
  latest: string;
  filters: SplFilter[];
}

/** The aggregate functions this builder could verify a documented syntax line
 *  for on Splunk's "Aggregate functions" page. `requiresField` is the real
 *  documented distinction: `count` is the only one Splunk's own stats examples
 *  use bare (`| stats count BY status, host`); every other function here takes
 *  a field in parentheses. */
export type SplAggFunction = 'count' | 'dc' | 'sum' | 'avg' | 'min' | 'max';

export const SPL_AGG_FUNCTIONS: {
  id: SplAggFunction;
  label: string;
  syntax: string;
  requiresField: boolean;
  hint: string;
}[] = [
  {
    id: 'count',
    label: 'count',
    syntax: 'count or count(<field>)',
    requiresField: false,
    hint: 'Bare `count` counts the events in each group. With a field, it counts occurrences of that field.',
  },
  {
    id: 'dc',
    label: 'dc (distinct_count)',
    syntax: 'dc(<field>)',
    requiresField: true,
    hint: 'Counts how many distinct values the field takes — the go-to for spotting one account touching many hosts.',
  },
  { id: 'sum', label: 'sum', syntax: 'sum(<field>)', requiresField: true, hint: 'Adds up the values of a numeric field.' },
  { id: 'avg', label: 'avg', syntax: 'avg(<field>)', requiresField: true, hint: 'Averages the values of a numeric field.' },
  { id: 'min', label: 'min', syntax: 'min(<field>)', requiresField: true, hint: 'The smallest value the field takes in the group.' },
  { id: 'max', label: 'max', syntax: 'max(<field>)', requiresField: true, hint: 'The largest value the field takes in the group.' },
];

export interface SplAggregation {
  fn: SplAggFunction;
  field: string;
  /** Optional `AS <name>` rename. Quoted automatically when it contains
   *  white space, matching Splunk's own `AS "Product Name"` example. */
  alias: string;
}

interface SplStatsCommand {
  kind: 'stats';
  aggregations: SplAggregation[];
  /** The `BY <field-list>` group-by fields; emitted comma-separated. */
  by: string[];
}

interface SplTableCommand {
  kind: 'table';
  fields: string[];
}

interface SplSortField {
  field: string;
  direction: 'asc' | 'desc';
}

interface SplSortCommand {
  kind: 'sort';
  /** Optional leading `<count>`. Splunk documents 0 as "return everything". */
  limit: string;
  fields: SplSortField[];
}

interface SplWhereCommand {
  kind: 'where';
  left: string;
  operator: SplWhereOperator;
  right: string;
  rightKind: SplOperandKind;
}

interface SplEvalAssignment {
  field: string;
  /** Free text, emitted verbatim — see the file header. */
  expression: string;
}

interface SplEvalCommand {
  kind: 'eval';
  assignments: SplEvalAssignment[];
}

interface SplHeadCommand {
  kind: 'head';
  /** Blank emits a bare `| head`, whose documented default is 10. */
  limit: string;
}

export type SplCommand =
  | SplWhereCommand
  | SplEvalCommand
  | SplStatsCommand
  | SplSortCommand
  | SplTableCommand
  | SplHeadCommand;

export type SplCommandKind = SplCommand['kind'];

/** Metadata for the page's own command reference table — one row per pipe
 *  command this builder can emit, with the documented syntax line and the
 *  official one-line description from Splunk's command quick reference. */
export const SPL_PIPE_COMMANDS: {
  id: SplCommandKind;
  syntax: string;
  summary: string;
  docUrl: string;
}[] = [
  {
    id: 'where',
    syntax: 'where <eval-expression>',
    summary: 'Filters results with an eval expression, so you can compare one field against another.',
    docUrl: 'https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/search-commands/where',
  },
  {
    id: 'eval',
    syntax: 'eval <field>=<expression>[, <field>=<expression>]...',
    summary: 'Calculates an expression and puts the result into a new or existing field.',
    docUrl: 'https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/search-commands/eval',
  },
  {
    id: 'stats',
    syntax: 'stats <agg-function>(<field>) [AS <name>] [BY <field-list>]',
    summary: 'Aggregates events into statistics, optionally grouped by one or more fields.',
    docUrl: 'https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/search-commands/stats',
  },
  {
    id: 'sort',
    syntax: 'sort [<count>] (+|-)<field>[, (+|-)<field>]...',
    summary: 'Orders results by the given fields — minus for descending, plus for ascending.',
    docUrl: 'https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/search-commands/sort',
  },
  {
    id: 'table',
    syntax: 'table <field-list>',
    summary: 'Keeps only the listed fields and renders them as a table, in the order given.',
    docUrl: 'https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/search-commands/table',
  },
  {
    id: 'head',
    syntax: 'head [<N>]',
    summary: 'Returns only the first N results. Splunk documents the default N as 10.',
    docUrl: 'https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/search-commands/head',
  },
];

export interface SplQuerySpec {
  base: SplBaseSearch;
  /** Emitted in array order — the pipeline is ordered, and this module never
   *  reorders it. Which order makes sense is the analyst's call. */
  commands: SplCommand[];
}

export interface SplIssue {
  severity: 'error' | 'warning';
  /** Which part of the spec the issue belongs to, for UI grouping. */
  scope: 'base' | SplCommandKind;
  message: string;
}

export interface SplBuildResult {
  /** The assembled query, or '' when the base search is empty. */
  query: string;
  issues: SplIssue[];
}

// ---------------------------------------------------------------------------
// Time modifiers
// ---------------------------------------------------------------------------

/** Every abbreviation Splunk's "Time modifiers" page lists as a valid time
 *  unit, longest-first so the alternation below can't match a prefix ("s")
 *  where a longer unit ("secs") was written. */
const TIME_UNITS = [
  'us', 'ms', 'cs', 'ds',
  'seconds', 'second', 'secs', 'sec', 's',
  'minutes', 'minute', 'mins', 'min', 'm',
  'hours', 'hour', 'hrs', 'hr', 'h',
  'days', 'day', 'd',
  'weeks', 'week', 'w',
  'months', 'month', 'mon',
  'quarters', 'quarter', 'qtrs', 'qtr', 'q',
  'years', 'year', 'yrs', 'yr', 'y',
].sort((a, b) => b.length - a.length);

/** The documented relative-time grammar: an optional signed offset, then an
 *  optional `@` snap-to unit which may itself chain further offsets (the docs'
 *  own `@d-2h` example). `now` is accepted as its own literal. Anything else
 *  isn't rejected — it's flagged as "passed through verbatim", since Splunk
 *  also accepts absolute timestamps this module deliberately doesn't model. */
const UNIT_ALT = TIME_UNITS.join('|');
const RELATIVE_TIME = new RegExp(
  `^(?:now|(?:[+-]?\\d+(?:${UNIT_ALT}))?(?:@(?:${UNIT_ALT})(?:[+-]\\d+(?:${UNIT_ALT}))*)?)$`,
);

/** True when `value` matches Splunk's documented relative-time format
 *  (`[+|-]<integer><unit>@<unit>`, `now`, or a bare `@<unit>` snap). */
export function isRelativeSplTime(value: string): boolean {
  const v = value.trim();
  if (v === '') return false;
  // The optional-everything alternation above would otherwise match a bare
  // "@" or an empty string; require at least a digit or an @ to be present.
  if (!/[\d@]/.test(v) && v !== 'now') return false;
  return RELATIVE_TIME.test(v);
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function splitList(raw: string[]): string[] {
  return raw.map((f) => f.trim()).filter(Boolean);
}

/** Render one `stats` aggregation term, e.g. `count`, `dc(user)`,
 *  `sum(bytes) AS "Total bytes"`. */
export function formatAggregation(agg: SplAggregation): string {
  const field = agg.field.trim();
  const head = agg.fn === 'count' && field === '' ? 'count' : `${agg.fn}(${field})`;
  const alias = agg.alias.trim();
  return alias === '' ? head : `${head} AS ${quoteSplValue(alias)}`;
}

/** Render the right-hand operand of a `where` comparison according to how the
 *  caller said it should be read. */
function formatWhereOperand(value: string, kind: SplOperandKind): string {
  if (kind === 'field') return splFieldRef(value);
  if (kind === 'number') return value;
  return `"${escapeSplLiteral(value)}"`;
}

/** Render the base search (everything before the first pipe). Returns '' when
 *  nothing at all was specified. */
export function formatBaseSearch(base: SplBaseSearch): string {
  const parts: string[] = [];
  const index = base.index.trim();
  const sourcetype = base.sourcetype.trim();
  if (index !== '') parts.push(`index=${quoteSplValue(index)}`);
  if (sourcetype !== '') parts.push(`sourcetype=${quoteSplValue(sourcetype)}`);
  for (const f of base.filters) {
    const field = f.field.trim();
    const value = f.value.trim();
    if (field === '' || value === '') continue;
    parts.push(`${field}${f.operator}${quoteSplValue(value)}`);
  }
  // Time modifiers land last so the readable subject of the search (index,
  // sourcetype, filters) stays at the front of the line.
  const earliest = base.earliest.trim();
  const latest = base.latest.trim();
  if (earliest !== '') parts.push(`earliest=${earliest}`);
  if (latest !== '') parts.push(`latest=${latest}`);
  // Terms are space-separated: Splunk documents AND as implied between them.
  return parts.join(' ');
}

/** Render a single pipe command WITHOUT its leading `| `. Returns '' when the
 *  command has nothing renderable (e.g. a `table` with no fields) — callers
 *  drop those rather than emitting a syntactically broken stage. */
export function formatCommand(cmd: SplCommand): string {
  switch (cmd.kind) {
    case 'where': {
      const left = cmd.left.trim();
      const right = cmd.right.trim();
      if (left === '' || right === '') return '';
      // Spaces around the operator throughout, matching Splunk's own
      // `where distance/time > 100` example — and required for LIKE, which is
      // a word rather than a symbol.
      return `where ${splFieldRef(left)} ${cmd.operator} ${formatWhereOperand(right, cmd.rightKind)}`;
    }
    case 'eval': {
      const pairs = cmd.assignments
        .map((a) => ({ field: a.field.trim(), expression: a.expression.trim() }))
        .filter((a) => a.field !== '' && a.expression !== '')
        .map((a) => `${splFieldRef(a.field)}=${a.expression}`);
      return pairs.length === 0 ? '' : `eval ${pairs.join(', ')}`;
    }
    case 'stats': {
      const terms = cmd.aggregations
        .filter((a) => a.fn === 'count' || a.field.trim() !== '')
        .map(formatAggregation);
      if (terms.length === 0) return '';
      const by = splitList(cmd.by);
      const tail = by.length === 0 ? '' : ` BY ${by.join(', ')}`;
      return `stats ${terms.join(', ')}${tail}`;
    }
    case 'sort': {
      const fields = cmd.fields
        .map((f) => ({ field: f.field.trim(), direction: f.direction }))
        .filter((f) => f.field !== '')
        .map((f) => `${f.direction === 'desc' ? '-' : '+'}${f.field}`);
      if (fields.length === 0) return '';
      const limit = cmd.limit.trim();
      return `sort ${limit === '' ? '' : `${limit} `}${fields.join(', ')}`;
    }
    case 'table': {
      const fields = splitList(cmd.fields);
      return fields.length === 0 ? '' : `table ${fields.join(', ')}`;
    }
    case 'head': {
      const limit = cmd.limit.trim();
      return limit === '' ? 'head' : `head ${limit}`;
    }
  }
}

/** Assemble the full query text: base search, then each renderable command
 *  joined by ` | `. Returns '' when the base search is empty, since SPL has no
 *  meaning without one. */
export function buildSplQuery(spec: SplQuerySpec): string {
  const base = formatBaseSearch(spec.base);
  if (base === '') return '';
  const stages = spec.commands.map(formatCommand).filter((s) => s !== '');
  return [base, ...stages].join(' | ');
}

// ---------------------------------------------------------------------------
// Validation — report, never guess
// ---------------------------------------------------------------------------

const INTEGER = /^\d+$/;

/** Collect everything questionable about a spec. Errors mean the query text
 *  is incomplete or would not run as written; warnings mean it will run but
 *  probably not the way you intended. Nothing here rewrites the spec. */
export function validateSplQuery(spec: SplQuerySpec): SplIssue[] {
  const issues: SplIssue[] = [];
  const { base } = spec;

  const hasIndex = base.index.trim() !== '';
  const hasSourcetype = base.sourcetype.trim() !== '';
  const activeFilters = base.filters.filter((f) => f.field.trim() !== '' && f.value.trim() !== '');

  if (!hasIndex && !hasSourcetype && activeFilters.length === 0) {
    issues.push({
      severity: 'error',
      scope: 'base',
      message: 'Add at least an index, a sourcetype, or one field filter — SPL needs a base search before the first pipe.',
    });
  } else if (!hasIndex) {
    issues.push({
      severity: 'warning',
      scope: 'base',
      message: 'No index specified. The search will run against whatever indexes your role defaults to, which is usually slower and broader than you want.',
    });
  }

  for (const f of base.filters) {
    const field = f.field.trim();
    const value = f.value.trim();
    if (field === '' && value !== '') {
      issues.push({ severity: 'error', scope: 'base', message: `Filter value "${value}" has no field name, so it was left out of the query.` });
    }
    if (field !== '' && value === '') {
      issues.push({ severity: 'error', scope: 'base', message: `Filter on "${field}" has no value, so it was left out of the query.` });
    }
    if (field !== '' && /\s/.test(field)) {
      issues.push({ severity: 'warning', scope: 'base', message: `Field name "${field}" contains a space. Splunk field names normally don't.` });
    }
  }

  for (const [key, value] of [
    ['earliest', base.earliest],
    ['latest', base.latest],
  ] as const) {
    const v = value.trim();
    if (v !== '' && !isRelativeSplTime(v)) {
      issues.push({
        severity: 'warning',
        scope: 'base',
        message: `${key}="${v}" isn't Splunk's relative-time format ([+|-]<integer><unit>@<unit>, or now). It's passed through exactly as typed — correct for an absolute timestamp, a typo otherwise.`,
      });
    }
  }

  for (const cmd of spec.commands) {
    switch (cmd.kind) {
      case 'where': {
        const left = cmd.left.trim();
        const right = cmd.right.trim();
        if (left === '' || right === '') {
          issues.push({ severity: 'error', scope: 'where', message: 'The where stage needs both a field on the left and a value on the right.' });
        }
        if (cmd.rightKind === 'number' && right !== '' && !/^[+-]?\d+(\.\d+)?$/.test(right)) {
          issues.push({ severity: 'error', scope: 'where', message: `"${right}" is set to compare as a number but isn't one. Switch it to a string or a field name.` });
        }
        if (cmd.operator === 'LIKE' && cmd.rightKind !== 'string') {
          issues.push({ severity: 'warning', scope: 'where', message: 'LIKE compares against a quoted pattern — set the right-hand side to a string.' });
        }
        break;
      }
      case 'eval': {
        for (const a of cmd.assignments) {
          const field = a.field.trim();
          const expression = a.expression.trim();
          if (field === '' && expression !== '') {
            issues.push({ severity: 'error', scope: 'eval', message: 'An eval expression has no destination field name, so it was left out of the query.' });
          }
          if (field !== '' && expression === '') {
            issues.push({ severity: 'error', scope: 'eval', message: `The eval field "${field}" has no expression, so it was left out of the query.` });
          }
        }
        if (cmd.assignments.every((a) => a.field.trim() === '' || a.expression.trim() === '')) {
          issues.push({ severity: 'error', scope: 'eval', message: 'The eval stage is empty — it needs at least one complete field=expression pair.' });
        }
        break;
      }
      case 'stats': {
        const usable = cmd.aggregations.filter((a) => a.fn === 'count' || a.field.trim() !== '');
        for (const a of cmd.aggregations) {
          const meta = SPL_AGG_FUNCTIONS.find((m) => m.id === a.fn);
          if (meta && meta.requiresField && a.field.trim() === '') {
            issues.push({ severity: 'error', scope: 'stats', message: `${meta.syntax} needs a field. Only count can be written bare.` });
          }
        }
        if (usable.length === 0) {
          issues.push({ severity: 'error', scope: 'stats', message: 'The stats stage needs at least one aggregation.' });
        }
        break;
      }
      case 'sort': {
        if (splitList(cmd.fields.map((f) => f.field)).length === 0) {
          issues.push({ severity: 'error', scope: 'sort', message: 'The sort stage needs at least one field to sort on.' });
        }
        const limit = cmd.limit.trim();
        if (limit !== '' && !INTEGER.test(limit)) {
          issues.push({ severity: 'error', scope: 'sort', message: `sort's leading count must be a whole number ("${limit}" isn't). Splunk reads 0 as "return every result".` });
        }
        break;
      }
      case 'table': {
        if (splitList(cmd.fields).length === 0) {
          issues.push({ severity: 'error', scope: 'table', message: 'The table stage needs at least one field name.' });
        }
        break;
      }
      case 'head': {
        const limit = cmd.limit.trim();
        if (limit === '') {
          issues.push({ severity: 'warning', scope: 'head', message: 'head has no count, so Splunk applies its documented default of 10 results.' });
        } else if (!INTEGER.test(limit)) {
          issues.push({ severity: 'error', scope: 'head', message: `head's count must be a whole number ("${limit}" isn't).` });
        }
        break;
      }
    }
  }

  // A stats stage collapses events into aggregate rows, so any later stage
  // can only see the fields stats produced. This is the single most common
  // "why is my table empty" mistake in SPL, and it's structural — detectable
  // from the pipeline shape alone, without guessing at field names.
  const statsAt = spec.commands.findIndex((c) => c.kind === 'stats');
  if (statsAt !== -1) {
    const afterStats = spec.commands.slice(statsAt + 1);
    if (afterStats.some((c) => c.kind === 'eval' || c.kind === 'where' || c.kind === 'table' || c.kind === 'sort')) {
      issues.push({
        severity: 'warning',
        scope: 'stats',
        message: 'Stages after stats only see the fields stats produced (its aggregations and its BY fields) — raw event fields are gone by that point.',
      });
    }
  }

  return issues;
}

/** Convenience wrapper: assemble and validate in one call. */
export function buildSpl(spec: SplQuerySpec): SplBuildResult {
  return { query: buildSplQuery(spec), issues: validateSplQuery(spec) };
}

// ---------------------------------------------------------------------------
// Presets
// ---------------------------------------------------------------------------

/** An empty spec — the builder's own starting state and the base every preset
 *  below is written against. */
export function emptySplSpec(): SplQuerySpec {
  return {
    base: { index: '', sourcetype: '', earliest: '', latest: '', filters: [] },
    commands: [],
  };
}

export interface SplPreset {
  id: string;
  label: string;
  /** What the shape of the query is doing — deliberately about the SPL
   *  pattern, not a claim about any particular deployment's field names. */
  description: string;
  spec: SplQuerySpec;
}

/** Worked examples of the *query shapes* this builder produces. The index,
 *  sourcetype, and field names are the ones Splunk's own Windows/Linux add-ons
 *  conventionally create, but every deployment onboards data differently —
 *  these are starting points to adapt, not universal truths, and the page says
 *  so. Each preset's assembled text is asserted in test/spl.test.ts, so a
 *  broken example can't ship. */
export const SPL_PRESETS: SplPreset[] = [
  {
    id: 'failed-logons',
    label: 'Failed logons, by source',
    description:
      'The classic password-spray / brute-force shape: count one event code over a time window, grouped by where it came from, worst first.',
    spec: {
      base: {
        index: 'wineventlog',
        sourcetype: 'WinEventLog:Security',
        earliest: '-24h@h',
        latest: 'now',
        filters: [{ field: 'EventCode', operator: '=', value: '4625' }],
      },
      commands: [
        {
          kind: 'stats',
          aggregations: [
            { fn: 'count', field: '', alias: '' },
            { fn: 'dc', field: 'Account_Name', alias: 'distinct_accounts' },
          ],
          by: ['src_ip'],
        },
        { kind: 'sort', limit: '20', fields: [{ field: 'count', direction: 'desc' }] },
      ],
    },
  },
  {
    id: 'rare-parents',
    label: 'Unusual process parents',
    description:
      'A frequency-analysis shape: aggregate process launches by parent, then keep only the rare ones — the same "least common is most interesting" logic behind stack counting.',
    spec: {
      base: {
        index: 'endpoint',
        sourcetype: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
        earliest: '-7d@d',
        latest: 'now',
        filters: [{ field: 'EventCode', operator: '=', value: '1' }],
      },
      commands: [
        {
          kind: 'stats',
          aggregations: [{ fn: 'count', field: '', alias: '' }],
          by: ['ParentImage', 'Image'],
        },
        { kind: 'where', left: 'count', operator: '<', right: '5', rightKind: 'number' },
        { kind: 'sort', limit: '0', fields: [{ field: 'count', direction: 'asc' }] },
        { kind: 'table', fields: ['count', 'ParentImage', 'Image'] },
      ],
    },
  },
  {
    id: 'field-comparison',
    label: 'Compare two fields',
    description:
      "Shows the difference between search and where: `where` reads a bare name on the right as another FIELD, so this finds events where the two addresses disagree — something the base search syntax can't express.",
    spec: {
      base: {
        index: 'proxy',
        sourcetype: '',
        earliest: '-1h@h',
        latest: 'now',
        filters: [],
      },
      commands: [
        { kind: 'where', left: 'src_ip', operator: '!=', right: 'dest_ip', rightKind: 'field' },
        { kind: 'head', limit: '100' },
      ],
    },
  },
  {
    id: 'derived-field',
    label: 'Derive a field, then filter on it',
    description:
      'The eval-then-where pattern: build a new field from the raw event, then filter on the thing you just built. Order matters — where can only test a field that already exists.',
    spec: {
      base: {
        index: 'web',
        sourcetype: 'access_combined',
        earliest: '-4h@h',
        latest: 'now',
        filters: [],
      },
      commands: [
        { kind: 'eval', assignments: [{ field: 'kb', expression: 'bytes/1024' }] },
        { kind: 'where', left: 'kb', operator: '>', right: '500', rightKind: 'number' },
        { kind: 'table', fields: ['_time', 'clientip', 'uri_path', 'kb'] },
        { kind: 'sort', limit: '', fields: [{ field: 'kb', direction: 'desc' }] },
      ],
    },
  },
];
