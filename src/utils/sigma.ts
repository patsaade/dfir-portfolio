// Sigma Rule Tester & Builder — pure functions, no DOM dependency (unit
// tested directly in test/sigma.test.ts, imported into the client bundle by
// SigmaTester.astro for live evaluation as you type).
//
// This implements an EXPLICITLY-SCOPED SUBSET of the Sigma detection-rule
// spec (https://github.com/SigmaHQ/sigma-specification), not full spec
// parity. Supported:
//   - field-value matching with modifiers: bare equals, |contains,
//     |startswith, |endswith, |re (a JS RegExp, compiled defensively — see
//     compileSigmaRegex).
//   - selection-combination logic in detection.condition: "1 of <prefix>*",
//     "all of <prefix>*", "1 of them", "all of them", and a bare "and"/"or"
//     list of selection names (mixing "and" and "or" in one condition is not
//     supported — the parser reports it as an error rather than guessing
//     precedence).
// Explicitly NOT supported (deliberate v1 scope cuts, not silent gaps):
//   - glob/wildcard FIELD-NAME matching (e.g. `Field*: value`) — every field
//     name in a selection is matched exactly. The only wildcard this tool
//     understands is on a *selection name prefix* in a condition like
//     "1 of selection*", which is a different, simpler mechanism.
//   - list-of-values-under-one-key OR semantics (real Sigma lets a single
//     field key map to a YAML list, meaning "any of these values"). This
//     tool's builder produces one row per field constraint; rows are always
//     AND'd together within a selection, never OR'd by shared field name.
//   - logsource, level, tags, and any other rule metadata beyond title +
//     detection — see generateYaml.
//   - parseSigmaYaml (below) is the matching import-side half of
//     generateYaml — it round-trips exactly the line shape generateYaml
//     itself emits (title + detection: selections + condition), not a
//     general-purpose Sigma/YAML parser. Anything outside that shape
//     (logsource/level/tags, glob field names, list-of-values-under-one-key,
//     mixed and/or conditions, multi-document YAML, block scalars, etc.)
//     comes back as a specific friendly error naming what's unsupported,
//     never a silent best-effort guess.

export type SigmaModifier = 'equals' | 'contains' | 'startswith' | 'endswith' | 're';

/** Single source of truth for the modifier dropdown + the small "supported
 *  subset" reference table on the tool's page — mirrors HASH_ALGORITHMS'
 *  role in utils/hashes.ts. */
export const SIGMA_MODIFIERS: { id: SigmaModifier; label: string; syntax: string; hint: string }[] = [
  { id: 'equals', label: 'equals', syntax: '(bare field name)', hint: 'Exact match, case-insensitive.' },
  { id: 'contains', label: 'contains', syntax: '|contains', hint: 'Substring match, case-insensitive.' },
  { id: 'startswith', label: 'starts with', syntax: '|startswith', hint: 'Prefix match, case-insensitive.' },
  { id: 'endswith', label: 'ends with', syntax: '|endswith', hint: 'Suffix match, case-insensitive.' },
  { id: 're', label: 'regex (|re)', syntax: '|re', hint: 'JavaScript regular expression match against the field value.' },
];

export interface SigmaFieldValue {
  field: string;
  modifier: SigmaModifier;
  value: string;
}

/** A named selection: every field row is AND'd together (see file header —
 *  no same-field OR-list support in this subset). */
export interface SigmaSelection {
  name: string;
  fields: SigmaFieldValue[];
}

export interface SigmaRule {
  title: string;
  selections: SigmaSelection[];
  /** Raw condition text — see parseCondition for the supported grammar. */
  condition: string;
}

// ---------------------------------------------------------------------------
// Field-value matching
// ---------------------------------------------------------------------------

/** Safely compile a user-supplied regex (the |re modifier) — same
 *  never-throw-uncaught discipline as this codebase's Regex Tester tool.
 *  Returns null on an invalid pattern instead of throwing. */
export function compileSigmaRegex(pattern: string): RegExp | null {
  try {
    return new RegExp(pattern);
  } catch {
    return null;
  }
}

/** True if a single field:modifier:value row matches an event. Field-name
 *  matching is exact (see file header — no glob support in v1). Missing or
 *  null/undefined fields never match. String comparison is case-insensitive
 *  for equals/contains/startswith/endswith (matches Sigma's own default
 *  case-insensitive string matching); |re is matched with the pattern
 *  exactly as authored (no implicit flags). */
export function fieldValueMatches(fv: SigmaFieldValue, event: Record<string, unknown>): boolean {
  if (!fv.field || !Object.prototype.hasOwnProperty.call(event, fv.field)) return false;
  const raw = event[fv.field];
  if (raw === null || raw === undefined) return false;
  const haystack = String(raw);
  switch (fv.modifier) {
    case 'equals':
      return haystack.toLowerCase() === fv.value.toLowerCase();
    case 'contains':
      return haystack.toLowerCase().includes(fv.value.toLowerCase());
    case 'startswith':
      return haystack.toLowerCase().startsWith(fv.value.toLowerCase());
    case 'endswith':
      return haystack.toLowerCase().endsWith(fv.value.toLowerCase());
    case 're': {
      const re = compileSigmaRegex(fv.value);
      return re ? re.test(haystack) : false;
    }
    default:
      return false;
  }
}

/** A selection matches an event iff it has at least one field row AND every
 *  row matches (AND across rows). An empty selection (no complete rows) never
 *  matches anything — that's a deliberate "incomplete state" default, not a
 *  vacuous-truth trap. */
export function selectionMatches(selection: SigmaSelection, event: Record<string, unknown>): boolean {
  if (selection.fields.length === 0) return false;
  return selection.fields.every((fv) => fieldValueMatches(fv, event));
}

// ---------------------------------------------------------------------------
// Condition parsing + evaluation
// ---------------------------------------------------------------------------

type SigmaConditionParsed =
  | { type: 'them'; op: 'any' | 'all' }
  | { type: 'wildcard'; op: 'any' | 'all'; prefix: string }
  | { type: 'list'; op: 'and' | 'or'; names: string[] };

export interface SigmaConditionParseResult {
  parsed: SigmaConditionParsed | null;
  error: string | null;
}

const NAME_RE = /^[A-Za-z0-9_]+$/;

/** Parse a detection.condition string into one of this tool's supported
 *  forms. Never throws — an unsupported/malformed condition comes back as
 *  { parsed: null, error: <friendly message> }. */
export function parseCondition(condition: string): SigmaConditionParseResult {
  const trimmed = condition.trim();
  if (!trimmed) return { parsed: null, error: 'The condition is empty.' };

  let m = /^(1|all)\s+of\s+them$/i.exec(trimmed);
  if (m) return { parsed: { type: 'them', op: m[1] === '1' ? 'any' : 'all' }, error: null };

  m = /^(1|all)\s+of\s+([A-Za-z0-9_]+)\*$/i.exec(trimmed);
  if (m) return { parsed: { type: 'wildcard', op: m[1] === '1' ? 'any' : 'all', prefix: m[2] }, error: null };

  const andParts = trimmed.split(/\s+and\s+/i).map((s) => s.trim()).filter(Boolean);
  const orParts = trimmed.split(/\s+or\s+/i).map((s) => s.trim()).filter(Boolean);

  if (andParts.length > 1 && orParts.length > 1) {
    return { parsed: null, error: 'Mixing "and" and "or" in one condition is outside this tool’s supported subset.' };
  }
  if (andParts.length > 1) {
    if (!andParts.every((n) => NAME_RE.test(n))) {
      return { parsed: null, error: 'Unrecognized selection name in the condition.' };
    }
    return { parsed: { type: 'list', op: 'and', names: andParts }, error: null };
  }
  if (orParts.length > 1) {
    if (!orParts.every((n) => NAME_RE.test(n))) {
      return { parsed: null, error: 'Unrecognized selection name in the condition.' };
    }
    return { parsed: { type: 'list', op: 'or', names: orParts }, error: null };
  }
  if (NAME_RE.test(trimmed)) {
    return { parsed: { type: 'list', op: 'and', names: [trimmed] }, error: null };
  }
  return { parsed: null, error: 'Unrecognized condition syntax for this tool’s supported subset.' };
}

export interface ConditionEvalResult {
  matched: boolean;
  /** Selection names that actually contributed to a true result. Empty when
   *  matched is false. */
  matchedSelections: string[];
  error: string | null;
}

/** Evaluate a parsed (or freshly-parsed) condition against a rule's
 *  selections for one event. Unknown selection names / an empty wildcard
 *  match set come back as a friendly error, never a throw. */
export function evaluateCondition(
  condition: string,
  selections: SigmaSelection[],
  event: Record<string, unknown>,
): ConditionEvalResult {
  const { parsed, error } = parseCondition(condition);
  if (!parsed) return { matched: false, matchedSelections: [], error };

  const matchMap: Record<string, boolean> = {};
  for (const sel of selections) matchMap[sel.name] = selectionMatches(sel, event);

  if (parsed.type === 'them') {
    const names = selections.map((s) => s.name);
    if (names.length === 0) return { matched: false, matchedSelections: [], error: 'There are no selections to evaluate.' };
    const matchedNames = names.filter((n) => matchMap[n]);
    const matched = parsed.op === 'any' ? matchedNames.length > 0 : matchedNames.length === names.length;
    return { matched, matchedSelections: matched ? matchedNames : [], error: null };
  }

  if (parsed.type === 'wildcard') {
    const names = selections.map((s) => s.name).filter((n) => n.startsWith(parsed.prefix));
    if (names.length === 0) {
      return { matched: false, matchedSelections: [], error: `No selection name starts with "${parsed.prefix}".` };
    }
    const matchedNames = names.filter((n) => matchMap[n]);
    const matched = parsed.op === 'any' ? matchedNames.length > 0 : matchedNames.length === names.length;
    return { matched, matchedSelections: matched ? matchedNames : [], error: null };
  }

  // list
  const unknown = parsed.names.filter((n) => !(n in matchMap));
  if (unknown.length > 0) {
    return { matched: false, matchedSelections: [], error: `Unknown selection name${unknown.length > 1 ? 's' : ''}: ${unknown.join(', ')}` };
  }
  const matchedNames = parsed.names.filter((n) => matchMap[n]);
  const matched = parsed.op === 'and' ? matchedNames.length === parsed.names.length : matchedNames.length > 0;
  return { matched, matchedSelections: matched ? matchedNames : [], error: null };
}

// ---------------------------------------------------------------------------
// Condition-builder UI helper (guided dropdown/radio -> canonical condition string)
// ---------------------------------------------------------------------------

export type SigmaConditionUiType = 'list-and' | 'list-or' | 'them-all' | 'them-any' | 'wildcard-all' | 'wildcard-any';

/** Single source of truth for the guided builder's "combination logic"
 *  dropdown — mirrors HASH_ALGORITHMS' declarative-array role. */
export const CONDITION_UI_TYPES: { id: SigmaConditionUiType; label: string }[] = [
  { id: 'list-and', label: 'Selected selections must all match (and)' },
  { id: 'list-or', label: 'Any one selected selection matches (or)' },
  { id: 'them-all', label: 'All of them' },
  { id: 'them-any', label: '1 of them' },
  { id: 'wildcard-all', label: 'All of <prefix>*' },
  { id: 'wildcard-any', label: '1 of <prefix>*' },
];

/** Build a canonical condition string from a guided-builder UI choice. Pure
 *  + exported so the client script and the test suite share one code path. */
export function buildConditionString(type: SigmaConditionUiType, opts: { prefix?: string; names?: string[] } = {}): string {
  switch (type) {
    case 'them-any':
      return '1 of them';
    case 'them-all':
      return 'all of them';
    case 'wildcard-any':
      return `1 of ${(opts.prefix || 'selection').trim()}*`;
    case 'wildcard-all':
      return `all of ${(opts.prefix || 'selection').trim()}*`;
    case 'list-and':
      return (opts.names ?? []).join(' and ');
    case 'list-or':
      return (opts.names ?? []).join(' or ');
    default:
      return '';
  }
}

// ---------------------------------------------------------------------------
// Rule evaluation (ties selections + condition together for one event)
// ---------------------------------------------------------------------------

export interface RuleEvalResult {
  matched: boolean;
  matchedSelections: string[];
  selectionResults: Record<string, boolean>;
  conditionError: string | null;
}

export function evaluateRule(rule: SigmaRule, event: Record<string, unknown>): RuleEvalResult {
  const selectionResults: Record<string, boolean> = {};
  for (const sel of rule.selections) selectionResults[sel.name] = selectionMatches(sel, event);
  const { matched, matchedSelections, error } = evaluateCondition(rule.condition, rule.selections, event);
  return { matched, matchedSelections, selectionResults, conditionError: error };
}

// ---------------------------------------------------------------------------
// Sample-event parsing — auto-detect JSON vs. key=value per line
// ---------------------------------------------------------------------------

const KV_RE = /([A-Za-z0-9_.]+)=("([^"]*)"|'([^']*)'|(\S+))/g;

/** Parse one line of pasted sample-event text as either JSON (tried first)
 *  or whitespace-separated key=value tokens (fallback). Returns null for a
 *  blank line or a line that matches neither shape — callers should render
 *  that as a friendly per-line "couldn't parse this line" note, never throw. */
export function parseEventLine(line: string): Record<string, unknown> | null {
  const trimmed = line.trim();
  if (!trimmed) return null;

  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // Not JSON — fall through to key=value parsing.
  }

  const out: Record<string, unknown> = {};
  let match: RegExpExecArray | null;
  let found = false;
  KV_RE.lastIndex = 0;
  while ((match = KV_RE.exec(trimmed))) {
    found = true;
    const key = match[1];
    const value = match[3] !== undefined ? match[3] : match[4] !== undefined ? match[4] : match[5];
    out[key] = value;
  }
  return found ? out : null;
}

// ---------------------------------------------------------------------------
// Read-only YAML generation (builder state -> display, one-way — see file header)
// ---------------------------------------------------------------------------

function yamlScalar(value: string): string {
  if (value === '') return "''";
  const looksReserved = /^(true|false|null|~|yes|no)$/i.test(value) || /^-?\d+(\.\d+)?$/.test(value);
  const needsQuote = looksReserved || /^\s|\s$|[:#[\]{}&*!|>'"%@`]/.test(value);
  if (!needsQuote) return value;
  return `'${value.replace(/'/g, "''")}'`;
}

/** Render the current builder state as Sigma-flavored YAML. This is a
 *  display-only, one-way renderer (see file header) — there is no matching
 *  parser, and the rendered rule intentionally omits logsource/level/tags/
 *  and other metadata this tool doesn't collect. Incomplete rows (blank
 *  field name or value) are skipped rather than emitted half-written. */
export function generateYaml(rule: SigmaRule): string {
  const lines: string[] = [
    '# Generated from the builder above (read-only preview) — title + detection',
    '# only. logsource, level, tags, and other Sigma fields are outside this',
    '# tool’s scope; this is not a general Sigma YAML editor.',
    `title: ${yamlScalar(rule.title || 'Untitled rule')}`,
    'detection:',
  ];
  for (const sel of rule.selections) {
    const name = sel.name.trim() || 'selection';
    const fields = sel.fields.filter((f) => f.field.trim() && f.value.trim());
    lines.push(`  ${name}:`);
    if (fields.length === 0) {
      lines.push('    {}');
      continue;
    }
    for (const f of fields) {
      const key = f.modifier === 'equals' ? f.field : `${f.field}|${f.modifier}`;
      lines.push(`    ${key}: ${yamlScalar(f.value)}`);
    }
  }
  lines.push(`  condition: ${rule.condition.trim() || '<no condition set>'}`);
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Parsing pasted YAML back into builder state (import side of generateYaml
// above — see file header for exactly what's in vs. out of scope). This is
// a line-oriented parser of generateYaml's own output shape, not a general
// YAML parser: it never throws, and any unsupported construct comes back as
// a specific, friendly error rather than a guess.
// ---------------------------------------------------------------------------

export interface SigmaParseResult {
  rule: SigmaRule | null;
  error: string | null;
}

const SIGMA_MODIFIER_IDS = SIGMA_MODIFIERS.map((m) => m.id);

/** A friendly name for Sigma rule fields this tool deliberately doesn't
 *  collect (logsource/level/tags/etc — see file header). Used to give a
 *  specific "that's out of scope" error instead of a generic parse failure
 *  when a pasted rule includes one of them. */
const OUT_OF_SCOPE_TOP_KEYS = [
  'logsource', 'level', 'tags', 'status', 'description', 'references',
  'author', 'date', 'modified', 'falsepositives', 'id', 'related', 'fields',
];

/** Reverse of yamlScalar(): unquote a single-quoted YAML scalar (the ''
 *  escaped-quote convention), or return a bare scalar as-is. Never throws. */
function parseYamlScalar(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.length >= 2 && trimmed.startsWith("'") && trimmed.endsWith("'")) {
    return trimmed.slice(1, -1).replace(/''/g, "'");
  }
  return trimmed;
}

const LIST_VALUE_ERROR = 'This rule uses list-valued fields (one key mapped to multiple values) — that OR-list shorthand isn’t supported by this tool.';

/** Parse text in the exact subset of Sigma YAML that generateYaml() itself
 *  produces (title + detection: selections + condition — see file header)
 *  back into a SigmaRule. Never throws — any problem, from a missing
 *  required line to a construct outside this tool's scope, comes back as
 *  { rule: null, error: <friendly message> } instead. */
export function parseSigmaYaml(text: string): SigmaParseResult {
  try {
    const rawLines = text.split(/\r\n|\r|\n/);
    const lines: { indent: number; content: string }[] = [];
    for (const raw of rawLines) {
      if (/^\s*#/.test(raw)) continue; // comment line — skip/ignore
      if (raw.trim() === '') continue; // blank line — skip/ignore
      const m = /^( *)(.*)$/.exec(raw);
      const indent = m ? m[1].length : 0;
      const content = (m ? m[2] : raw).replace(/\s+$/, '');
      lines.push({ indent, content });
    }

    const titleIdx = lines.findIndex((l) => l.indent === 0 && l.content.startsWith('title:'));
    if (titleIdx === -1) return { rule: null, error: 'Missing a "title:" line.' };
    const title = parseYamlScalar(lines[titleIdx].content.slice('title:'.length));

    const detectionIdx = lines.findIndex((l, idx) => idx > titleIdx && l.indent === 0 && l.content.trim() === 'detection:');
    if (detectionIdx === -1) return { rule: null, error: 'Missing a "detection:" line.' };

    // Anything at indent 0 between title and detection is metadata this tool
    // doesn't collect (or unrecognized) — call it out specifically rather
    // than silently skipping it.
    for (let idx = titleIdx + 1; idx < detectionIdx; idx++) {
      const line = lines[idx];
      if (line.indent !== 0) continue;
      const key = line.content.split(':')[0].trim().toLowerCase();
      if (OUT_OF_SCOPE_TOP_KEYS.includes(key)) {
        return { rule: null, error: `"${key}:" is outside this tool’s scope — only title and detection are supported.` };
      }
      return { rule: null, error: `Unrecognized line before "detection:": "${line.content}"` };
    }

    const selections: SigmaSelection[] = [];
    let condition: string | null = null;
    let currentSelection: SigmaSelection | null = null;

    for (let idx = detectionIdx + 1; idx < lines.length; idx++) {
      const line = lines[idx];
      if (line.indent === 0) break; // back out to top level — outside this tool's title+detection scope

      if (line.indent === 2) {
        if (line.content.startsWith('condition:')) {
          condition = line.content.slice('condition:'.length).trim();
          currentSelection = null;
          continue;
        }
        const headerMatch = /^([A-Za-z0-9_]+):\s*$/.exec(line.content);
        if (!headerMatch) {
          if (/[*?]/.test(line.content.split(':')[0])) {
            return { rule: null, error: 'Glob/wildcard selection names aren’t supported by this tool.' };
          }
          return { rule: null, error: `Unrecognized line in detection: "${line.content}"` };
        }
        currentSelection = { name: headerMatch[1], fields: [] };
        selections.push(currentSelection);
        continue;
      }

      if (line.indent === 4) {
        if (!currentSelection) {
          return { rule: null, error: `Found a field row before any selection name: "${line.content}"` };
        }
        if (line.content === '{}') continue; // empty selection body — zero field rows
        if (/^-\s/.test(line.content)) return { rule: null, error: LIST_VALUE_ERROR };

        const colonIdx = line.content.indexOf(':');
        if (colonIdx === -1) return { rule: null, error: `Unrecognized field row: "${line.content}"` };
        const rawKey = line.content.slice(0, colonIdx).trim();
        const rawValue = line.content.slice(colonIdx + 1).trim();
        if (rawValue === '') return { rule: null, error: LIST_VALUE_ERROR };
        if (/^\[.*\]$/.test(rawValue)) return { rule: null, error: LIST_VALUE_ERROR };

        let field: string;
        let modifier: SigmaModifier;
        const pipeIdx = rawKey.indexOf('|');
        if (pipeIdx === -1) {
          field = rawKey;
          modifier = 'equals';
        } else {
          field = rawKey.slice(0, pipeIdx);
          const modStr = rawKey.slice(pipeIdx + 1);
          if (!SIGMA_MODIFIER_IDS.includes(modStr as SigmaModifier)) {
            return { rule: null, error: `Unrecognized modifier "|${modStr}" — supported modifiers are ${SIGMA_MODIFIER_IDS.join(', ')}.` };
          }
          modifier = modStr as SigmaModifier;
        }
        if (field.includes('*') || field.includes('?')) {
          return { rule: null, error: 'Glob/wildcard field names aren’t supported by this tool.' };
        }
        currentSelection.fields.push({ field, modifier, value: parseYamlScalar(rawValue) });
        continue;
      }

      return { rule: null, error: `Unexpected indentation in detection: "${line.content}"` };
    }

    if (condition === null) return { rule: null, error: 'Missing a "condition:" line.' };
    if (selections.length === 0) return { rule: null, error: 'No selections found under "detection:".' };

    const { error: conditionError } = parseCondition(condition);
    if (conditionError) return { rule: null, error: conditionError };

    return { rule: { title, selections, condition }, error: null };
  } catch {
    return { rule: null, error: 'Couldn’t parse this rule — check that it matches the format this tool generates.' };
  }
}

// ---------------------------------------------------------------------------
// Starter example content — CLEARLY FABRICATED for illustration, not a real
// captured detection or real telemetry (see CLAUDE.md "Content accuracy").
// ---------------------------------------------------------------------------

export const STARTER_RULE: SigmaRule = {
  title: 'Suspicious PowerShell EncodedCommand Usage (fabricated example)',
  selections: [
    { name: 'selection_process', fields: [{ field: 'Image', modifier: 'endswith', value: '\\powershell.exe' }] },
    { name: 'selection_cli', fields: [{ field: 'CommandLine', modifier: 'contains', value: '-EncodedCommand' }] },
  ],
  condition: 'selection_process and selection_cli',
};

export const STARTER_EVENTS = [
  '{"EventID": 4104, "Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", "CommandLine": "powershell.exe -EncodedCommand SQBmACgAJABQAFMAVgBlAHIAcwBpAG8AbgBUAGEAYgBsAGUA"}',
  '{"EventID": 4104, "Image": "C:\\\\Windows\\\\System32\\\\cmd.exe", "CommandLine": "cmd.exe /c whoami"}',
].join('\n');
