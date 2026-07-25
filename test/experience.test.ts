import { describe, it, expect } from 'vitest';
import {
  parseMonthYear,
  parsePeriod,
  monthsBetween,
  roleDurationMonths,
  companyTotalMonths,
  formatDuration,
  type MonthYear,
} from '../src/utils/experience';

describe('parseMonthYear', () => {
  it('parses a standard 3-letter month abbreviation + year', () => {
    expect(parseMonthYear('Jun 2026')).toEqual({ year: 2026, month: 5 });
    expect(parseMonthYear('Jan 2020')).toEqual({ year: 2020, month: 0 });
    expect(parseMonthYear('Dec 1999')).toEqual({ year: 1999, month: 11 });
  });

  it('is case-insensitive and tolerates a longer month spelling', () => {
    expect(parseMonthYear('jun 2026')).toEqual({ year: 2026, month: 5 });
    expect(parseMonthYear('June 2026')).toEqual({ year: 2026, month: 5 });
  });

  it('returns null for garbage input instead of throwing', () => {
    expect(parseMonthYear('Present')).toBeNull();
    expect(parseMonthYear('2026')).toBeNull();
    expect(parseMonthYear('Xyz 2026')).toBeNull();
    expect(parseMonthYear('')).toBeNull();
  });
});

describe('parsePeriod', () => {
  const now: MonthYear = { year: 2026, month: 6 }; // Jul 2026

  it('parses a closed "Mon YYYY – Mon YYYY" range with an en dash', () => {
    expect(parsePeriod('Jul 2023 – Apr 2024', now)).toEqual({
      start: { year: 2023, month: 6 },
      end: { year: 2024, month: 3 },
    });
  });

  it('resolves "Present" to the passed-in now', () => {
    expect(parsePeriod('Jun 2026 – Present', now)).toEqual({
      start: { year: 2026, month: 5 },
      end: now,
    });
  });

  it('tolerates an em dash or plain hyphen between tokens', () => {
    expect(parsePeriod('Jun 2026 — Present', now)?.start).toEqual({ year: 2026, month: 5 });
    expect(parsePeriod('Jun 2026 - Present', now)?.start).toEqual({ year: 2026, month: 5 });
  });

  it('returns null for a malformed period rather than throwing', () => {
    expect(parsePeriod('not a real period', now)).toBeNull();
    expect(parsePeriod('Jun 2026', now)).toBeNull();
  });
});

describe('monthsBetween', () => {
  it('counts inclusively (same month on both ends = 1 month)', () => {
    expect(monthsBetween({ year: 2024, month: 3 }, { year: 2024, month: 3 })).toBe(1);
  });

  it('counts a same-year span correctly', () => {
    // Apr 2024 -> Oct 2024: Apr,May,Jun,Jul,Aug,Sep,Oct = 7
    expect(monthsBetween({ year: 2024, month: 3 }, { year: 2024, month: 9 })).toBe(7);
  });

  it('counts a cross-year span correctly', () => {
    // Jul 2023 -> Apr 2024: 10 months
    expect(monthsBetween({ year: 2023, month: 6 }, { year: 2024, month: 3 })).toBe(10);
    // Aug 2025 -> Jun 2026: 11 months
    expect(monthsBetween({ year: 2025, month: 7 }, { year: 2026, month: 5 })).toBe(11);
  });
});

describe('roleDurationMonths', () => {
  const now: MonthYear = { year: 2026, month: 6 }; // Jul 2026

  it('matches every real period string currently on the About page (regression guard — if this fails, a hand-edited period drifted out of the "Mon YYYY – Mon YYYY"/"Present" shape)', () => {
    const realPeriods = [
      'Jun 2026 – Present',
      'Aug 2025 – Jun 2026',
      'Apr 2025 – Aug 2025',
      'Feb 2025 – Apr 2025',
      'Oct 2024 – Feb 2025',
      'Apr 2024 – Oct 2024',
      'Jul 2023 – Apr 2024',
    ];
    for (const period of realPeriods) {
      expect(roleDurationMonths(period, now), `"${period}" failed to parse`).not.toBeNull();
    }
  });

  it('computes the current role\'s duration from the passed-in "now" (this is what keeps it auto-updating on rebuild)', () => {
    expect(roleDurationMonths('Jun 2026 – Present', now)).toBe(2); // Jun, Jul
    expect(roleDurationMonths('Jun 2026 – Present', { year: 2027, month: 0 })).toBe(8); // Jun'26..Jan'27
  });

  it('returns null for an unparseable period', () => {
    expect(roleDurationMonths('sometime last year', now)).toBeNull();
  });
});

describe('companyTotalMonths', () => {
  const now: MonthYear = { year: 2026, month: 6 }; // Jul 2026

  it('spans earliest start to latest end across multiple roles, not a naive sum (a promotion boundary month must not be double-counted)', () => {
    // ReliaQuest: Jul 2023 -> Apr 2025 across 4 roles = 22 months.
    // Summing each role's own inclusive duration would double-count the
    // Apr2024/Oct2024/Feb2025/Apr2025 boundary months and overcount.
    const reliaquest = ['Feb 2025 – Apr 2025', 'Oct 2024 – Feb 2025', 'Apr 2024 – Oct 2024', 'Jul 2023 – Apr 2024'];
    expect(companyTotalMonths(reliaquest, now)).toBe(22);
  });

  it('is order-independent (roles aren\'t guaranteed to be passed oldest-first)', () => {
    const forward = ['Jul 2023 – Apr 2024', 'Apr 2024 – Oct 2024'];
    const reversed = ['Apr 2024 – Oct 2024', 'Jul 2023 – Apr 2024'];
    expect(companyTotalMonths(forward, now)).toBe(companyTotalMonths(reversed, now));
  });

  it('handles a single-role company (uses that role\'s own span)', () => {
    expect(companyTotalMonths(['Jun 2026 – Present'], now)).toBe(2);
  });

  it('returns null if any role period fails to parse', () => {
    expect(companyTotalMonths(['Jun 2026 – Present', 'garbage'], now)).toBeNull();
  });
});

describe('formatDuration', () => {
  it('formats months-only durations, singular and plural', () => {
    expect(formatDuration(1)).toBe('1 mo');
    expect(formatDuration(7)).toBe('7 mos');
  });

  it('formats whole-year durations without a redundant "0 mos"', () => {
    expect(formatDuration(12)).toBe('1 yr');
    expect(formatDuration(24)).toBe('2 yrs');
  });

  it('formats mixed year+month durations, singular and plural', () => {
    expect(formatDuration(13)).toBe('1 yr 1 mo');
    expect(formatDuration(22)).toBe('1 yr 10 mos');
    expect(formatDuration(27)).toBe('2 yrs 3 mos');
  });
});
