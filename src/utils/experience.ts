// Pure duration math for the About page's work-history timeline
// (src/pages/about.astro). Periods are hand-authored strings like
// "Jun 2026 – Present" or "Aug 2025 – Jun 2026" — parsed here rather than
// storing a second, separately-typed {start,end} field per role, so there's
// one source of truth for the displayed range and no risk of the two
// drifting apart.
//
// Duration convention: LinkedIn-style INCLUSIVE month counting — since the
// source data only carries month+year (no exact day), a role spanning
// "Jul 2023 – Apr 2024" is treated as having some presence in both the
// start and end month, giving Jul,Aug,...,Apr = 10 months, not 9. This
// matches how LinkedIn (which this timeline's shape is modeled on) computes
// and displays "X mos"/"X yrs Y mos" from month/year-only ranges.
//
// `now` is always passed in rather than read internally (no bare
// `new Date()` in here) — about.astro calls `new Date()` once at build
// time and threads it through, so every function here stays pure/testable,
// same precedent as termForDate(new Date()) (CLAUDE.md invariant 10). A
// rebuild (this site's daily 00:10 UTC redeploy, invariant 10) is what
// keeps the "Present" role's month count current — there's no client JS
// involved.

const MONTH_ABBR = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];

export interface MonthYear {
  year: number;
  /** 0-11 */
  month: number;
}

/** Parses a single "Mon YYYY" token (e.g. "Jun 2026"). Returns null for
 *  anything that doesn't match — callers treat that as "can't compute a
 *  duration for this one," not a crash, since a future hand-typed period
 *  string is exactly the kind of real authoring slip this should degrade
 *  gracefully from rather than break the whole page over. */
export function parseMonthYear(token: string): MonthYear | null {
  const m = token.trim().match(/^([A-Za-z]{3})[A-Za-z]*\s+(\d{4})$/);
  if (!m) return null;
  const month = MONTH_ABBR.indexOf(m[1].toLowerCase());
  if (month === -1) return null;
  return { year: Number(m[2]), month };
}

/** Parses a full "Mon YYYY – Mon YYYY" or "Mon YYYY – Present" range.
 *  Accepts en dash, em dash, or a plain hyphen between the two tokens
 *  (hand-typed prose drifts on which dash character gets used). */
export function parsePeriod(period: string, now: MonthYear): { start: MonthYear; end: MonthYear } | null {
  const parts = period.split(/\s[–—-]\s/);
  if (parts.length !== 2) return null;
  const start = parseMonthYear(parts[0]);
  if (!start) return null;
  const end = /^present$/i.test(parts[1].trim()) ? now : parseMonthYear(parts[1]);
  if (!end) return null;
  return { start, end };
}

/** Inclusive month count between two Mon/Year points — see this file's
 *  header comment for why +1. */
export function monthsBetween(start: MonthYear, end: MonthYear): number {
  return (end.year - start.year) * 12 + (end.month - start.month) + 1;
}

/** Parses `period` and returns its inclusive duration in months, or null if
 *  the string doesn't match the expected "Mon YYYY – Mon YYYY"/"Present"
 *  shape. */
export function roleDurationMonths(period: string, now: MonthYear): number | null {
  const parsed = parsePeriod(period, now);
  return parsed ? monthsBetween(parsed.start, parsed.end) : null;
}

/** A company's total tenure is the span from its EARLIEST role's start to
 *  its LATEST role's end (a promotion's boundary month shouldn't be counted
 *  twice, which summing each role's own duration would do) — same
 *  continuous-tenure convention LinkedIn itself uses for a multi-role
 *  company block. Returns null if any role's period fails to parse, rather
 *  than silently totaling a partial/wrong span. */
export function companyTotalMonths(periods: string[], now: MonthYear): number | null {
  let earliestStart: MonthYear | null = null;
  let latestEnd: MonthYear | null = null;
  for (const period of periods) {
    const parsed = parsePeriod(period, now);
    if (!parsed) return null;
    const startOrdinal = parsed.start.year * 12 + parsed.start.month;
    const endOrdinal = parsed.end.year * 12 + parsed.end.month;
    if (!earliestStart || startOrdinal < earliestStart.year * 12 + earliestStart.month) earliestStart = parsed.start;
    if (!latestEnd || endOrdinal > latestEnd.year * 12 + latestEnd.month) latestEnd = parsed.end;
  }
  if (!earliestStart || !latestEnd) return null;
  return monthsBetween(earliestStart, latestEnd);
}

/** "7 mos", "1 yr", "1 yr 3 mos", "2 yrs" — singular/plural-correct,
 *  omits a zero component instead of showing "2 yrs 0 mos". */
export function formatDuration(totalMonths: number): string {
  const years = Math.floor(totalMonths / 12);
  const months = totalMonths % 12;
  const parts: string[] = [];
  if (years > 0) parts.push(`${years} yr${years === 1 ? '' : 's'}`);
  if (months > 0 || years === 0) parts.push(`${months} mo${months === 1 ? '' : 's'}`);
  return parts.join(' ');
}
