// SentinelOne PowerQuery Builder — pure, DOM-free query-assembly functions
// (unit tested in test/s1.test.ts, imported into the client bundle by
// S1Builder.astro so the query re-renders live as the form changes).
//
// This ASSEMBLES POWERQUERY TEXT. It never parses, executes, or validates a
// query against a SentinelOne console — there is no backend here and nothing
// typed into the tool leaves the browser. The output is meant to be pasted
// into Singularity's own Event Search / PowerQuery bar and run there.
//
// EXPLICITLY-SCOPED SUBSET (documented cuts, not silent gaps). Supported
// pipeline, in this fixed order:
//
//   <field> <op> <value> <field> <op> <value> ...   -- one or more, implicit AND
//   | group <alias> = <agg>(<field>)[, ...] by <fields>   -- optional
//   | filter <field> <op> <number>                       -- optional
//   | sort -<field>                                      -- optional
//   | limit <n>                                          -- optional
//   | columns <fields>                                   -- optional
//
// NOT supported, deliberately:
//   - `join`, `union`, `transpose`, `parse`, `let`. All four are real
//     PowerQuery commands (SentinelOne names them in its own PowerQuery
//     overview) — they're out of scope for a guided builder, not absent from
//     the language.
//   - OR grouping and parenthesised boolean logic. Terms in the filter
//     expression are space-separated, which SentinelOne's own examples define
//     as an implicit AND. For "any of these values" use the `in` operator
//     rather than several rows.
//   - ASCENDING sort. SentinelOne's published examples only ever show the
//     descending form (`| sort -field`); no public SentinelOne material this
//     was checked against shows the ascending spelling, so the builder emits
//     descending only rather than guessing at a `+` prefix. To surface the
//     RARE end of a distribution, group and then use the `| filter` stage
//     (`| filter hosts <= 2`) — which is exactly how SentinelOne's own worked
//     example narrows a grouped result.
//   - Conditional aggregates (`count(status >= 500)`). Real syntax, but it
//     needs a second expression grammar the builder doesn't model.
//
// Anything this module cannot render correctly is DROPPED and reported in
// `warnings` — never guessed at, never emitted as broken PowerQuery.

import {
  S1_AGGREGATIONS,
  S1_FIELDS,
  S1_OPERATORS,
  type S1Aggregation,
  type S1Field,
  type S1FieldKind,
  type S1Operator,
} from '../data/s1';

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

export function findS1Field(name: string): S1Field | undefined {
  return S1_FIELDS.find((f) => f.name === name);
}

export function findS1Operator(id: string): S1Operator | undefined {
  return S1_OPERATORS.find((o) => o.id === id);
}

export function findS1Aggregation(id: string): S1Aggregation | undefined {
  return S1_AGGREGATIONS.find((a) => a.id === id);
}

/** Operators offered for a field kind — keeps `contains` off a numeric field
 *  and `>` off a string one. */
export function s1OperatorsForKind(kind: S1FieldKind): S1Operator[] {
  return S1_OPERATORS.filter((o) => o.kinds.includes(kind));
}

// ---------------------------------------------------------------------------
// Value rendering
// ---------------------------------------------------------------------------

const S1_NUMERIC_RE = /^-?\d+(\.\d+)?$/;

export interface S1RenderedValue {
  /** null when the value could not be encoded from verified rules. */
  text: string | null;
  error?: string;
}

/**
 * Encode a string literal.
 *
 * SentinelOne's own published queries use BOTH quote characters —
 * `event.type = 'Process Creation'` and `tgt.file.sha1 in ("<sha1>", ...)` —
 * and show a literal backslash written doubled inside a quoted value
 * (`tgt.file.path contains '\\bun_environment.js'`). Those two rules are the
 * only string-encoding behaviour that could be verified, so this function is
 * built out of exactly them and nothing else:
 *
 *   - default: single quotes, every backslash doubled;
 *   - a value containing a single quote but no double quote: double quotes
 *     instead, so the quote character needs no escape sequence at all;
 *   - a value containing both: refused. There is no verified escape sequence
 *     for a quote character inside a literal of the same kind, and inventing
 *     one would be exactly the guess this whole tool exists to avoid.
 */
export function quoteS1String(raw: string): S1RenderedValue {
  const hasSingle = raw.indexOf("'") !== -1;
  const hasDouble = raw.indexOf('"') !== -1;
  const escaped = raw.replace(/\\/g, '\\\\');
  if (hasSingle && hasDouble) {
    return {
      text: null,
      error: `"${raw}" contains both a single and a double quote. Neither quoting form can carry it without an escape sequence this builder could verify, so the filter was skipped.`,
    };
  }
  if (hasSingle) return { text: `"${escaped}"` };
  return { text: `'${escaped}'` };
}

/** Render one scalar right-hand side for a field of the given kind. */
export function renderS1Value(raw: string, kind: S1FieldKind, fieldName: string): S1RenderedValue {
  const value = raw.trim();
  if (value === '') return { text: null, error: `${fieldName}: no value entered — filter skipped.` };
  if (kind === 'numeric') {
    if (!S1_NUMERIC_RE.test(value)) {
      return { text: null, error: `${fieldName} is a numeric field but "${value}" is not a number — filter skipped.` };
    }
    return { text: value };
  }
  return quoteS1String(value);
}

/** Split the comma-separated text behind the `in` operator, dropping blanks and
 *  stripping quotes the user typed themselves so they are not double-quoted. */
export function parseS1List(raw: string): string[] {
  return raw
    .split(',')
    .map((part) => {
      const trimmed = part.trim();
      if (trimmed.length >= 2) {
        const first = trimmed[0];
        const last = trimmed[trimmed.length - 1];
        if ((first === '"' && last === '"') || (first === "'" && last === "'")) return trimmed.slice(1, -1).trim();
      }
      return trimmed;
    })
    .filter((part) => part !== '');
}

// ---------------------------------------------------------------------------
// Spec
// ---------------------------------------------------------------------------

export interface S1FilterTerm {
  field: string;
  operatorId: string;
  value: string;
}

interface S1GroupAggregation {
  aggregationId: string;
  /** Field the aggregate applies to. Ignored for count(). */
  field: string;
  /** Output column name. Blank falls back to the aggregation's own alias. */
  alias: string;
}

interface S1GroupStage {
  aggregations: S1GroupAggregation[];
  /** `by` fields, in order. May be empty for a whole-result aggregate. */
  by: string[];
}

/** The post-group `| filter` narrowing stage. One numeric comparison — the
 *  shape SentinelOne's own worked example uses to keep only the interesting
 *  end of a grouped distribution. */
interface S1PostFilter {
  /** A group alias, or a numeric field when there is no group stage. */
  column: string;
  operatorId: string;
  value: string;
}

export interface S1QuerySpec {
  filters: S1FilterTerm[];
  group: S1GroupStage | null;
  postFilter: S1PostFilter | null;
  /** Column to sort on. Always descending — see the file header. '' for none. */
  sort: string;
  limit: number | null;
  columns: string[];
}

export interface S1BuildResult {
  /** The assembled query, one pipeline stage per line. */
  query: string;
  lines: string[];
  warnings: string[];
  tips: string[];
}

// ---------------------------------------------------------------------------
// Output shape
// ---------------------------------------------------------------------------

function aliasFor(agg: S1GroupAggregation, meta: S1Aggregation): string {
  const explicit = agg.alias.trim();
  return explicit === '' ? meta.alias : explicit;
}

/**
 * Which columns the pipeline carries after the group stage. `null` means "every
 * field of the raw event" (no group). Drives both the sort picker and the check
 * that a returned column still exists.
 */
export function s1OutputColumns(spec: S1QuerySpec): string[] | null {
  if (!spec.group) return null;
  const columns: string[] = [];
  for (const name of spec.group.by) {
    if (name && findS1Field(name) && !columns.includes(name)) columns.push(name);
  }
  for (const agg of spec.group.aggregations) {
    const meta = findS1Aggregation(agg.aggregationId);
    if (!meta) continue;
    if (meta.needsField && !findS1Field(agg.field)) continue;
    const alias = aliasFor(agg, meta);
    if (!columns.includes(alias)) columns.push(alias);
  }
  return columns;
}

/** Columns a `sort`, `filter` or `columns` stage can legally reference. */
export function s1AvailableColumns(spec: S1QuerySpec): string[] {
  const explicit = s1OutputColumns(spec);
  if (explicit) return explicit;
  return S1_FIELDS.map((f) => f.name);
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

/** Render one filter term. Returns text:null (plus a warning) rather than
 *  guessing whenever the value does not fit the field's type. */
export function renderS1Term(term: S1FilterTerm): { text: string | null; warnings: string[]; tips: string[] } {
  const warnings: string[] = [];
  const tips: string[] = [];
  const field = findS1Field(term.field);
  const operator = findS1Operator(term.operatorId);

  if (!field) return { text: null, warnings: [`Unknown field "${term.field}" — filter skipped.`], tips };
  if (!operator) return { text: null, warnings: [`Unknown operator for ${field.name} — filter skipped.`], tips };
  if (!operator.kinds.includes(field.kind)) {
    return { text: null, warnings: [`${operator.symbol} does not apply to ${field.name} (${field.kind}) — filter skipped.`], tips };
  }

  if (operator.form === 'list') {
    const items = parseS1List(term.value);
    if (items.length === 0) {
      return { text: null, warnings: [], tips: [`${field.name}: no values entered for ${operator.symbol} — filter skipped.`] };
    }
    const rendered: string[] = [];
    for (const item of items) {
      const value = renderS1Value(item, field.kind, field.name);
      if (value.text === null) {
        warnings.push(value.error ?? `${field.name}: could not render "${item}".`);
        continue;
      }
      rendered.push(value.text);
    }
    if (rendered.length === 0) return { text: null, warnings, tips };
    return { text: `${field.name} in (${rendered.join(', ')})`, warnings, tips };
  }

  const value = renderS1Value(term.value, field.kind, field.name);
  if (value.text === null) {
    const message = value.error ?? `${field.name}: could not render value.`;
    // A blank box on a freshly added row is an unfinished step, not a mistake.
    if (term.value.trim() === '') return { text: null, warnings: [], tips: [message] };
    return { text: null, warnings: [message], tips };
  }
  if (operator.id === 'eq' && field.kind === 'string') {
    tips.push(
      `${field.name} uses =, which compares case-sensitively. Use contains:anycase where the casing of a path, host name, or command line could vary.`,
    );
  }
  return { text: `${field.name} ${operator.symbol} ${value.text}`, warnings, tips };
}

/** Assemble the query. Never throws; anything unrenderable is dropped and
 *  reported in `warnings`. */
export function buildS1Query(spec: S1QuerySpec): S1BuildResult {
  const warnings: string[] = [];
  const tips: string[] = [];

  // 1. The filter expression — implicit AND between space-separated terms.
  const terms: string[] = [];
  for (const term of spec.filters) {
    const rendered = renderS1Term(term);
    for (const w of rendered.warnings) warnings.push(w);
    for (const t of rendered.tips) tips.push(t);
    if (rendered.text) terms.push(rendered.text);
  }

  if (terms.length === 0) {
    tips.push('Add at least one filter term. PowerQuery has no meaning without something before the first pipe.');
    return { query: '', lines: [], warnings, tips: dedupe(tips) };
  }

  const lines: string[] = [terms.join(' ')];

  // 2. group.
  let grouped = false;
  if (spec.group) {
    const rendered: string[] = [];
    for (const agg of spec.group.aggregations) {
      const meta = findS1Aggregation(agg.aggregationId);
      if (!meta) {
        warnings.push('Unknown aggregate function — dropped from the group stage.');
        continue;
      }
      if (!meta.needsField) {
        rendered.push(`${aliasFor(agg, meta)} = ${meta.fn}()`);
        continue;
      }
      const field = findS1Field(agg.field);
      if (!field) {
        warnings.push(`${meta.fn}() needs a field to aggregate — that aggregate was dropped.`);
        continue;
      }
      if (!meta.fieldKinds.includes(field.kind)) {
        warnings.push(`${meta.fn}() cannot be applied to ${field.name} (${field.kind}) — that aggregate was dropped.`);
        continue;
      }
      rendered.push(`${aliasFor(agg, meta)} = ${meta.fn}(${field.name})`);
    }

    if (rendered.length === 0) {
      warnings.push('The group stage needs at least one aggregate — it was skipped.');
    } else {
      const keys: string[] = [];
      for (const name of spec.group.by) {
        if (!name) continue;
        const field = findS1Field(name);
        if (!field) {
          warnings.push(`Unknown group-by field "${name}" — dropped from the group stage.`);
          continue;
        }
        if (!keys.includes(field.name)) keys.push(field.name);
      }
      const by = keys.length > 0 ? ` by ${keys.join(', ')}` : '';
      lines.push(`| group ${rendered.join(', ')}${by}`);
      grouped = true;
    }
  }

  const available = grouped ? (s1OutputColumns(spec) ?? []) : null;
  const canReference = (name: string) => (available === null ? !!findS1Field(name) : available.includes(name));

  // 3. filter — the post-group numeric narrowing stage.
  if (spec.postFilter && spec.postFilter.column) {
    const { column, operatorId, value } = spec.postFilter;
    const operator = findS1Operator(operatorId);
    if (!canReference(column)) {
      warnings.push(`Cannot filter on ${column}: this query does not carry a column by that name — filter stage skipped.`);
    } else if (!operator) {
      warnings.push('Unknown operator on the filter stage — it was skipped.');
    } else if (!S1_NUMERIC_RE.test(value.trim())) {
      warnings.push(`The filter stage compares against a number; "${value.trim()}" is not one — filter stage skipped.`);
    } else {
      lines.push(`| filter ${column} ${operator.symbol} ${value.trim()}`);
    }
  }

  // 4. sort — descending only, see the file header.
  if (spec.sort) {
    if (canReference(spec.sort)) lines.push(`| sort -${spec.sort}`);
    else warnings.push(`Cannot sort by ${spec.sort}: this query does not carry a column by that name — sort stage skipped.`);
  }

  // 5. limit.
  if (spec.limit !== null && spec.limit !== undefined) {
    if (!Number.isInteger(spec.limit) || spec.limit <= 0) {
      warnings.push(`Row limit must be a positive whole number — "${spec.limit}" ignored.`);
    } else {
      lines.push(`| limit ${spec.limit}`);
    }
  }

  // 6. columns last, matching SentinelOne's own worked example.
  if (spec.columns.length > 0) {
    const kept: string[] = [];
    for (const name of spec.columns) {
      if (!canReference(name)) {
        warnings.push(`Unknown column "${name}" for this query — dropped from the columns stage.`);
        continue;
      }
      if (!kept.includes(name)) kept.push(name);
    }
    if (kept.length > 0) lines.push(`| columns ${kept.join(', ')}`);
  }

  return { query: lines.join('\n'), lines, warnings, tips: dedupe(tips) };
}

function dedupe(values: string[]): string[] {
  const out: string[] = [];
  for (const value of values) if (!out.includes(value)) out.push(value);
  return out;
}

/** The builder's own starting state — a plain, immediately-runnable process
 *  execution hunt rather than an empty form. */
export function defaultS1Spec(): S1QuerySpec {
  return {
    filters: [
      { field: 'event.type', operatorId: 'eq', value: 'Process Creation' },
      { field: 'tgt.process.cmdline', operatorId: 'contains_ci', value: '' },
    ],
    group: null,
    postFilter: null,
    sort: '',
    limit: 100,
    columns: ['event.time', 'endpoint.name', 'src.process.user', 'src.process.name', 'tgt.process.name', 'tgt.process.cmdline'],
  };
}
