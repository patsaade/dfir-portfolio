// Cron expression parser + human-readable describer — pure functions, no DOM
// (unit-tested directly in test/cron.test.ts, imported into the client bundle
// by CronParser.astro for live parsing as the visitor types).
//
// SCOPE & STANDARD FOLLOWED — read this before changing a grammar rule.
// This covers the classic 5-field crontab(5) syntax (minute hour
// day-of-month month day-of-week) as documented by the cronie project's
// crontab(5) man page (https://man7.org/linux/man-pages/man5/crontab.5.html
// — the crond most Linux distributions ship, tracing back to Paul Vixie's
// original cron), independently cross-checked against the narrower POSIX
// crontab specification (IEEE Std 1003.1-2017 / The Open Group Base
// Specifications, "crontab" utility:
// https://pubs.opengroup.org/onlinepubs/9699919799/utilities/crontab.html).
// Both were WebFetched and diffed against each other before any rule below
// was encoded — see each rule's own comment for which source it came from.
//
// POSIX itself only defines: five numeric fields (day-of-week strictly
// 0-6, 0 = Sunday), an asterisk, comma-separated lists, and hyphenated
// ranges. It does NOT define step values (the */n syntax) or month/
// day-of-week *names* — those are real, but they're an extension beyond
// bare POSIX. cronie's crontab(5) is a superset that adds:
//   - names for month/day-of-week (first three letters, case-insensitive)
//   - step values, only after a range or an asterisk ("0-23/2", "*/2") —
//     NOT after a bare number ("5/15" is rejected here, not silently
//     reinterpreted, since that shorthand isn't documented in either source)
//   - day-of-week accepts 0-7, with BOTH 0 and 7 meaning Sunday
//   - when day-of-month AND day-of-week are both restricted (neither is
//     '*'), cron runs the command when EITHER field matches — an OR, not
//     an AND. This is easy to get wrong and describeCron() below encodes
//     it explicitly.
// This tool follows cronie's (POSIX-superset) grammar, since that's the
// portable, practically-universal one — plain POSIX crontab, with no names
// and no step values, is impractical for almost anything anyone actually
// writes. See src/pages/tools/cron-parser.astro for the citations as
// rendered on the page itself.
//
// '@'-prefixed nicknames (@reboot, @yearly, @daily, ...) are even further
// out of the core grammar — cronie's own man page lists them under a
// separate "EXTENSIONS" heading, not as part of the 5-field spec, and
// POSIX doesn't mention them at all. parseCronExpression() still accepts
// the 7 nicknames cronie documents (expanding the 6 schedule-equivalent
// ones to their literal 5-field form, and modeling @reboot as its own
// non-schedule case — it runs once at daemon startup, with no 5-field
// equivalent), but every one of them is presented on the page as an
// extension, never implied to be portable/POSIX.
//
// Deliberately out of scope (documented here, not silently ignored):
//   - 6-field variants: a system crontab's (/etc/crontab) extra leading
//     "user" field, or a scheduler like Quartz's extra leading "seconds"
//     field — this parser always expects exactly 5 fields.
//   - Calendar-aware validation (e.g. flagging "31 2 * *" as impossible
//     because February never has a 31st) — real cron doesn't do this
//     either; the day-of-month and month fields are matched completely
//     independently, so a day that can't occur in a given month simply
//     never fires that combination. describeCron() reports what the
//     expression says, not whether it's a "useful" schedule.
//   - Computing next/previous run times — this tool explains what an
//     expression MEANS, it doesn't simulate a scheduler.

export type CronFieldName = 'minute' | 'hour' | 'dayOfMonth' | 'month' | 'dayOfWeek';

export const CRON_FIELD_ORDER: CronFieldName[] = ['minute', 'hour', 'dayOfMonth', 'month', 'dayOfWeek'];

export const CRON_FIELD_LABELS: Record<CronFieldName, string> = {
  minute: 'Minute',
  hour: 'Hour',
  dayOfMonth: 'Day of month',
  month: 'Month',
  dayOfWeek: 'Day of week',
};

/** Shown as placeholder/help text next to each builder field. */
export const CRON_FIELD_RANGE_HINT: Record<CronFieldName, string> = {
  minute: '0–59',
  hour: '0–23',
  dayOfMonth: '1–31',
  month: '1–12 or Jan–Dec',
  dayOfWeek: '0–7 (0 and 7 are both Sunday) or Sun–Sat',
};

// ---------------------------------------------------------------------------
// Field shape — the parsed structure of ONE field's value, used both to
// validate it and to drive describeCron()'s wording.
// ---------------------------------------------------------------------------

export type LeafShape =
  | { kind: 'single'; value: number }
  | { kind: 'range'; start: number; end: number }
  | { kind: 'rangeStep'; start: number; end: number; step: number }
  | { kind: 'everyStep'; step: number };

export type FieldShape = { kind: 'every' } | { kind: 'list'; items: LeafShape[] } | LeafShape;

export interface ParsedCronField {
  /** The exact text the visitor typed for this field (post-whitespace-split, pre-parse). */
  raw: string;
  shape: FieldShape;
}

export interface CronSchedule {
  kind: 'schedule';
  minute: ParsedCronField;
  hour: ParsedCronField;
  dayOfMonth: ParsedCronField;
  month: ParsedCronField;
  dayOfWeek: ParsedCronField;
  /** The lowercased nickname the visitor typed (e.g. '@daily'), or null for a plain 5-field expression. */
  nickname: string | null;
}

/** '@reboot' has no 5-field equivalent — it runs once when the cron daemon starts, not on a schedule. */
export interface CronReboot {
  kind: 'reboot';
}

export type ParsedCron = CronSchedule | CronReboot;

export interface CronParseError {
  /** Which field the problem is in, or null for a whole-expression-level problem (wrong field count, unknown nickname). */
  field: CronFieldName | null;
  message: string;
}

export interface CronParseResult {
  cron: ParsedCron | null;
  error: CronParseError | null;
}

// ---------------------------------------------------------------------------
// Field specs
// ---------------------------------------------------------------------------

interface FieldSpec {
  label: string;
  min: number;
  max: number;
  /** Lowercase 3-letter names, index-aligned starting at `nameBase`. */
  names?: string[];
  nameBase?: number;
  nameExample?: string;
}

// First three letters, case-insensitive — verified against cronie's crontab(5): "Names can also
// be used for the 'month' and 'day of week' fields. Use the first three letters of the particular
// day or month (case does not matter)."
const MONTH_NAMES = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
const MONTH_FULL = [
  'January', 'February', 'March', 'April', 'May', 'June',
  'July', 'August', 'September', 'October', 'November', 'December',
];
const DOW_NAMES = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
const DOW_FULL = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

const MINUTE_SPEC: FieldSpec = { label: 'Minute', min: 0, max: 59 };
const HOUR_SPEC: FieldSpec = { label: 'Hour', min: 0, max: 23 };
const DOM_SPEC: FieldSpec = { label: 'Day of month', min: 1, max: 31 };
const MONTH_SPEC: FieldSpec = { label: 'Month', min: 1, max: 12, names: MONTH_NAMES, nameBase: 1, nameExample: 'Jan' };
// Verified against cronie's crontab(5) field table: "day of week 0-7 (0 or 7 is Sunday, or use
// names)" — deliberately wider than POSIX's strict 0-6.
const DOW_SPEC: FieldSpec = { label: 'Day of week', min: 0, max: 7, names: DOW_NAMES, nameBase: 0, nameExample: 'Mon' };

const FIELD_SPECS: Record<CronFieldName, FieldSpec> = {
  minute: MINUTE_SPEC,
  hour: HOUR_SPEC,
  dayOfMonth: DOM_SPEC,
  month: MONTH_SPEC,
  dayOfWeek: DOW_SPEC,
};

function monthName(n: number): string {
  return MONTH_FULL[n - 1] ?? String(n);
}
// Both 0 and 7 mean Sunday (DOW_FULL index 0) — applying % 7 at display time means a raw range
// like "5-7" (Fri-Sun) never needs its endpoints normalized before the start<=end check below.
function dowName(n: number): string {
  return DOW_FULL[n % 7] ?? String(n);
}

// ---------------------------------------------------------------------------
// Token / part / field parsing
// ---------------------------------------------------------------------------

function resolveToken(token: string, spec: FieldSpec): number | null {
  const t = token.trim();
  if (spec.names) {
    const lower = t.toLowerCase();
    if (/^[a-z]{3}$/.test(lower)) {
      const idx = spec.names.indexOf(lower);
      return idx === -1 ? null : (spec.nameBase ?? 0) + idx;
    }
  }
  if (!/^\d+$/.test(t)) return null;
  const n = Number(t);
  if (n < spec.min || n > spec.max) return null;
  return n;
}

function invalidTokenMessage(tok: string, spec: FieldSpec): string {
  const nameMsg = spec.names ? `, or a 3-letter name like '${spec.nameExample}'` : '';
  return `'${tok}' isn't a valid ${spec.label.toLowerCase()} value — expected a number from ${spec.min} to ${spec.max}${nameMsg}.`;
}

/** Parse one comma-list item: a single value, a range, a range with a step, or '*' with a step.
 *  Never called with a bare '*' — that's handled one level up, since it can only ever appear alone. */
function parseFieldPart(part: string, spec: FieldSpec): { shape: LeafShape } | { error: string } {
  const stepOnly = /^\*\/(\d+)$/.exec(part);
  if (stepOnly) {
    const step = Number(stepOnly[1]);
    if (step < 1) return { error: `Step value must be a positive integer (found '${stepOnly[1]}').` };
    return { shape: { kind: 'everyStep', step } };
  }
  if (part.includes('*')) {
    return { error: `'*' must be used alone or as '*/N' — found '${part}'.` };
  }

  const slashIdx = part.indexOf('/');
  const base = slashIdx === -1 ? part : part.slice(0, slashIdx);
  const stepStr = slashIdx === -1 ? null : part.slice(slashIdx + 1);
  let step: number | null = null;
  if (stepStr !== null) {
    if (!/^\d+$/.test(stepStr) || Number(stepStr) < 1) {
      return { error: `Step value must be a positive integer (found '${stepStr}').` };
    }
    step = Number(stepStr);
  }

  const dashIdx = base.indexOf('-');
  if (dashIdx === -1) {
    if (step !== null) {
      // Verified against cronie's crontab(5): step values are documented as following a RANGE
      // or an asterisk ("0-23/2", "*/2") — a bare number before the slash isn't a documented
      // form, so this is rejected rather than guessed at.
      return {
        error: `A step value ('/${step}') must follow a range or '*' — not a single value like '${base}/${step}'. Use '${base}-${spec.max}/${step}' or '*/${step}' instead.`,
      };
    }
    const value = resolveToken(base, spec);
    if (value === null) return { error: invalidTokenMessage(base, spec) };
    return { shape: { kind: 'single', value } };
  }

  const startTok = base.slice(0, dashIdx);
  const endTok = base.slice(dashIdx + 1);
  if (!startTok || !endTok) return { error: `'${base}' isn't a valid range.` };
  const start = resolveToken(startTok, spec);
  if (start === null) return { error: invalidTokenMessage(startTok, spec) };
  const end = resolveToken(endTok, spec);
  if (end === null) return { error: invalidTokenMessage(endTok, spec) };
  if (start > end) {
    return { error: `'${base}' is a descending range (${startTok} is after ${endTok}) — wrap-around ranges aren't supported.` };
  }
  return step !== null ? { shape: { kind: 'rangeStep', start, end, step } } : { shape: { kind: 'range', start, end } };
}

function parseField(raw: string, spec: FieldSpec): { shape: FieldShape } | { error: string } {
  const trimmed = raw.trim();
  if (!trimmed) return { error: 'Field is empty.' };
  if (trimmed === '*') return { shape: { kind: 'every' } };

  const parts = trimmed.split(',').map((p) => p.trim());
  if (parts.some((p) => p === '')) return { error: `Empty item in a comma-separated list ('${trimmed}').` };

  if (parts.length === 1) {
    const r = parseFieldPart(parts[0], spec);
    return 'error' in r ? r : { shape: r.shape };
  }
  if (parts.includes('*')) {
    return { error: `'*' can't be combined with other values in a list — use '*' alone to mean 'every value'.` };
  }
  const items: LeafShape[] = [];
  for (const p of parts) {
    const r = parseFieldPart(p, spec);
    if ('error' in r) return r;
    items.push(r.shape);
  }
  return { shape: { kind: 'list', items } };
}

function parseFiveFields(
  expr: string,
): { fields: Omit<CronSchedule, 'kind' | 'nickname'> } | { error: CronParseError } {
  const parts = expr.trim().split(/\s+/).filter(Boolean);
  if (parts.length !== 5) {
    return {
      error: {
        field: null,
        message: `Expected exactly 5 fields (minute hour day-of-month month day-of-week), got ${parts.length}. This tool covers the classic 5-field crontab(5) syntax only — not 6-field variants like a system crontab's leading "user" field or a scheduler's leading "seconds" field.`,
      },
    };
  }
  const resolved = {} as Omit<CronSchedule, 'kind' | 'nickname'>;
  for (let i = 0; i < CRON_FIELD_ORDER.length; i++) {
    const name = CRON_FIELD_ORDER[i];
    const spec = FIELD_SPECS[name];
    const raw = parts[i];
    const r = parseField(raw, spec);
    if ('error' in r) {
      return { error: { field: name, message: `${spec.label} field ('${raw}'): ${r.error}` } };
    }
    resolved[name] = { raw, shape: r.shape };
  }
  return { fields: resolved };
}

// Verified against cronie's crontab(5) EXTENSIONS section (@reboot excluded — it has no
// equivalent 5-field expression) — every equivalent below is quoted verbatim from that source.
const NICKNAMES: Record<string, string> = {
  '@yearly': '0 0 1 1 *',
  '@annually': '0 0 1 1 *',
  '@monthly': '0 0 1 * *',
  '@weekly': '0 0 * * 0',
  '@daily': '0 0 * * *',
  '@hourly': '0 * * * *',
};
export const CRON_NICKNAMES = ['@reboot', ...Object.keys(NICKNAMES)];

/** Parse a cron expression: either a plain 5-field schedule, or one of the 7 '@'-nickname
 *  extensions cronie's crontab(5) documents. Never throws — any problem comes back as
 *  `{ cron: null, error }` with a field-scoped, human-readable message. */
export function parseCronExpression(expr: string): CronParseResult {
  const trimmed = expr.trim();
  if (!trimmed) return { cron: null, error: { field: null, message: 'Enter a cron expression.' } };

  if (trimmed.startsWith('@')) {
    const key = trimmed.toLowerCase();
    if (key === '@reboot') return { cron: { kind: 'reboot' }, error: null };
    const expansion = NICKNAMES[key];
    if (!expansion) {
      return {
        cron: null,
        error: {
          field: null,
          message: `Unknown nickname '${trimmed}'. Supported: ${CRON_NICKNAMES.join(', ')} — these are a documented extension (cronie's crontab(5) "EXTENSIONS" section), not part of the core 5-field grammar or of POSIX crontab.`,
        },
      };
    }
    const result = parseFiveFields(expansion);
    if ('error' in result) return { cron: null, error: result.error };
    return { cron: { kind: 'schedule', ...result.fields, nickname: key }, error: null };
  }

  const result = parseFiveFields(trimmed);
  if ('error' in result) return { cron: null, error: result.error };
  return { cron: { kind: 'schedule', ...result.fields, nickname: null }, error: null };
}

// ---------------------------------------------------------------------------
// Human-readable description
// ---------------------------------------------------------------------------

function pad2(n: number): string {
  return n < 10 ? '0' + n : String(n);
}
function formatClockTime(hour: number, minute: number): string {
  const period = hour < 12 ? 'AM' : 'PM';
  let h12 = hour % 12;
  if (h12 === 0) h12 = 12;
  return `${h12}:${pad2(minute)} ${period}`;
}
function formatHourLabel(hour: number): string {
  const period = hour < 12 ? 'AM' : 'PM';
  let h12 = hour % 12;
  if (h12 === 0) h12 = 12;
  return `${h12} ${period}`;
}
function capitalize(s: string): string {
  return s.length ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}
function joinWithAnd(items: string[]): string {
  if (items.length === 0) return '';
  if (items.length === 1) return items[0];
  if (items.length === 2) return `${items[0]} and ${items[1]}`;
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}
function describeLeaf(item: LeafShape, name?: (n: number) => string): string {
  const fmt = (n: number) => (name ? name(n) : String(n));
  switch (item.kind) {
    case 'single':
      return fmt(item.value);
    case 'range':
      return `${fmt(item.start)} through ${fmt(item.end)}`;
    case 'rangeStep':
      return `every ${item.step} from ${fmt(item.start)} through ${fmt(item.end)}`;
    case 'everyStep':
      return `every ${item.step}`;
  }
}

function minutePhrase(shape: FieldShape): string {
  switch (shape.kind) {
    case 'every':
      return 'every minute';
    case 'everyStep':
      return `every ${shape.step} minutes`;
    case 'single':
      return `at minute ${shape.value}`;
    case 'range':
      return `at minutes ${shape.start} through ${shape.end}`;
    case 'rangeStep':
      return `at every ${shape.step} minutes from minute ${shape.start} through ${shape.end}`;
    case 'list':
      return `at minutes ${joinWithAnd(shape.items.map((i) => describeLeaf(i)))}`;
  }
}
function hourPhrase(shape: FieldShape): string {
  switch (shape.kind) {
    case 'every':
      return 'every hour';
    case 'everyStep':
      return `every ${shape.step} hours`;
    case 'single':
      return `during hour ${shape.value} (${formatHourLabel(shape.value)})`;
    case 'range':
      return `during hours ${shape.start} through ${shape.end}`;
    case 'rangeStep':
      return `during every ${shape.step} hours from hour ${shape.start} through ${shape.end}`;
    case 'list':
      return `during hours ${joinWithAnd(shape.items.map((i) => describeLeaf(i)))}`;
  }
}

/** The minute+hour clause — the one place a fixed clock time ("At 3:00 AM") gets produced. */
function describeTimeOfDay(minute: FieldShape, hour: FieldShape): string {
  if (minute.kind === 'single' && hour.kind === 'single') return `At ${formatClockTime(hour.value, minute.value)}`;
  if (minute.kind === 'every' && hour.kind === 'every') return 'Every minute';
  if (minute.kind === 'everyStep' && hour.kind === 'every') return `Every ${minute.step} minutes`;
  if (minute.kind === 'every' && hour.kind === 'everyStep') return `Every minute, every ${hour.step} hours`;
  if (minute.kind === 'everyStep' && hour.kind === 'everyStep') return `Every ${minute.step} minutes, every ${hour.step} hours`;
  if (minute.kind === 'single' && hour.kind === 'every') return `At minute ${minute.value} past every hour`;
  if (minute.kind === 'single' && hour.kind === 'everyStep') return `At minute ${minute.value} past every ${hour.step} hours`;
  if (minute.kind === 'every' && hour.kind === 'single') return `Every minute, during the ${formatHourLabel(hour.value)} hour`;
  if (minute.kind === 'everyStep' && hour.kind === 'single') return `Every ${minute.step} minutes, during the ${formatHourLabel(hour.value)} hour`;

  const mPhrase = capitalize(minutePhrase(minute));
  const hPhrase = hourPhrase(hour);
  return hour.kind === 'every' ? mPhrase : `${mPhrase}, ${hPhrase}`;
}

/** `standalone` picks "only on ..." (nothing else restricts which days this runs on) vs.
 *  "on ..." (paired with an "or" clause from the other of day-of-month/day-of-week). */
function describeDomClause(shape: FieldShape, standalone: boolean): string {
  const lead = standalone ? 'only on' : 'on';
  switch (shape.kind) {
    case 'every':
      return 'every day of the month';
    case 'everyStep':
      return `every ${shape.step} days of the month`;
    case 'single':
      return `${lead} day ${shape.value} of the month`;
    case 'range':
      return `${lead} days ${shape.start} through ${shape.end} of the month`;
    case 'rangeStep':
      return `${lead} every ${shape.step} days from day ${shape.start} through day ${shape.end} of the month`;
    case 'list':
      return `${lead} days ${joinWithAnd(shape.items.map((i) => describeLeaf(i)))} of the month`;
  }
}
function describeDowClause(shape: FieldShape, standalone: boolean): string {
  const lead = standalone ? 'only on' : 'on';
  switch (shape.kind) {
    case 'every':
      return 'every day of the week';
    case 'everyStep':
      return `every ${shape.step} days of the week`;
    case 'single':
      return `${lead} ${dowName(shape.value)}`;
    case 'range':
      return `${lead} ${dowName(shape.start)} through ${dowName(shape.end)}`;
    case 'rangeStep':
      return `${lead} every ${shape.step} days from ${dowName(shape.start)} through ${dowName(shape.end)}`;
    case 'list':
      return `${lead} ${joinWithAnd(shape.items.map((i) => describeLeaf(i, dowName)))}`;
  }
}
function describeMonthClause(shape: FieldShape): string {
  switch (shape.kind) {
    case 'every':
      return 'every month';
    case 'everyStep':
      return `every ${shape.step} months`;
    case 'single':
      return `in ${monthName(shape.value)}`;
    case 'range':
      return `in ${monthName(shape.start)} through ${monthName(shape.end)}`;
    case 'rangeStep':
      return `every ${shape.step} months from ${monthName(shape.start)} through ${monthName(shape.end)}`;
    case 'list':
      return `in ${joinWithAnd(shape.items.map((i) => describeLeaf(i, monthName)))}`;
  }
}

/** A full English sentence for a parsed expression. Aims to read naturally for the shapes real
 *  crontabs actually use most (fixed clock times, "every N minutes/hours", weekday/hour ranges,
 *  the day-of-month/day-of-week OR rule); rarer or highly composite expressions still get an
 *  accurate, if plainer, field-by-field sentence rather than a guessed-at one. No trailing period,
 *  to match this tool's own worked example ("At 3:00 AM, only on Monday"). */
export function describeCron(cron: ParsedCron): string {
  if (cron.kind === 'reboot') {
    return 'Runs once, when the cron daemon starts (typically at system boot) — @reboot has no equivalent 5-field schedule.';
  }
  const { minute, hour, dayOfMonth, month, dayOfWeek } = cron;
  const clauses: string[] = [describeTimeOfDay(minute.shape, hour.shape)];

  if (month.shape.kind !== 'every') clauses.push(describeMonthClause(month.shape));

  const domRestricted = dayOfMonth.shape.kind !== 'every';
  const dowRestricted = dayOfWeek.shape.kind !== 'every';
  if (domRestricted && dowRestricted) {
    // Verified against cronie's crontab(5): "If both fields are restricted (i.e., do not contain
    // the '*' character), the command will be run when EITHER field matches the current time" —
    // an OR, not an AND, so this is worded as one explicitly.
    clauses.push(`${describeDomClause(dayOfMonth.shape, false)} or ${describeDowClause(dayOfWeek.shape, false)}`);
  } else if (domRestricted) {
    clauses.push(describeDomClause(dayOfMonth.shape, true));
  } else if (dowRestricted) {
    clauses.push(describeDowClause(dayOfWeek.shape, true));
  }

  return clauses.join(', ');
}

/** A short, standalone one-liner for a single field — used by the "field breakdown" list in the
 *  UI so each of the 5 boxes explains itself even before the full sentence is read. */
export function describeCronField(fieldName: CronFieldName, shape: FieldShape): string {
  switch (fieldName) {
    case 'minute':
      return capitalize(minutePhrase(shape));
    case 'hour':
      return capitalize(hourPhrase(shape));
    case 'dayOfMonth':
      return capitalize(describeDomClause(shape, true).replace(/^only /, ''));
    case 'month':
      return capitalize(describeMonthClause(shape));
    case 'dayOfWeek':
      return capitalize(describeDowClause(shape, true).replace(/^only /, ''));
  }
}
