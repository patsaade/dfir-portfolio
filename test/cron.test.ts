import { describe, it, expect } from 'vitest';
import { parseCronExpression, describeCron, type CronSchedule } from '../src/utils/cron';

function schedule(expr: string): CronSchedule {
  const r = parseCronExpression(expr);
  expect(r.error).toBeNull();
  expect(r.cron).not.toBeNull();
  expect(r.cron!.kind).toBe('schedule');
  return r.cron as CronSchedule;
}
function describe_(expr: string): string {
  return describeCron(schedule(expr));
}
function errorOf(expr: string): string | null {
  const r = parseCronExpression(expr);
  expect(r.cron).toBeNull();
  return r.error ? r.error.message : null;
}

describe('parseCronExpression — valid 5-field expressions', () => {
  it('accepts the all-wildcard expression', () => {
    const c = schedule('* * * * *');
    expect(c.minute.shape).toEqual({ kind: 'every' });
    expect(c.hour.shape).toEqual({ kind: 'every' });
    expect(c.dayOfMonth.shape).toEqual({ kind: 'every' });
    expect(c.month.shape).toEqual({ kind: 'every' });
    expect(c.dayOfWeek.shape).toEqual({ kind: 'every' });
    expect(c.nickname).toBeNull();
  });

  it('parses single numeric values', () => {
    const c = schedule('0 3 1 1 1');
    expect(c.minute.shape).toEqual({ kind: 'single', value: 0 });
    expect(c.hour.shape).toEqual({ kind: 'single', value: 3 });
    expect(c.dayOfMonth.shape).toEqual({ kind: 'single', value: 1 });
    expect(c.month.shape).toEqual({ kind: 'single', value: 1 });
    expect(c.dayOfWeek.shape).toEqual({ kind: 'single', value: 1 });
  });

  it('parses step-of-asterisk values', () => {
    const c = schedule('*/5 */2 * * *');
    expect(c.minute.shape).toEqual({ kind: 'everyStep', step: 5 });
    expect(c.hour.shape).toEqual({ kind: 'everyStep', step: 2 });
  });

  it('parses ranges and range/step', () => {
    const c = schedule('0 9-17 1-15 * *');
    expect(c.hour.shape).toEqual({ kind: 'range', start: 9, end: 17 });
    expect(c.dayOfMonth.shape).toEqual({ kind: 'range', start: 1, end: 15 });
    const c2 = schedule('0-30/10 * * * *');
    expect(c2.minute.shape).toEqual({ kind: 'rangeStep', start: 0, end: 30, step: 10 });
  });

  it('parses comma lists of singles', () => {
    const c = schedule('0,30 9,17 * * *');
    expect(c.minute.shape).toEqual({
      kind: 'list',
      items: [
        { kind: 'single', value: 0 },
        { kind: 'single', value: 30 },
      ],
    });
    expect(c.hour.shape).toEqual({
      kind: 'list',
      items: [
        { kind: 'single', value: 9 },
        { kind: 'single', value: 17 },
      ],
    });
  });

  it('parses a list mixing singles, ranges, and steps', () => {
    const c = schedule('0-10/5,45 * * * *');
    expect(c.minute.shape).toEqual({
      kind: 'list',
      items: [
        { kind: 'rangeStep', start: 0, end: 10, step: 5 },
        { kind: 'single', value: 45 },
      ],
    });
  });

  it('resolves 3-letter month and day-of-week names, case-insensitively', () => {
    const c = schedule('0 9 * JAN mon');
    expect(c.month.shape).toEqual({ kind: 'single', value: 1 });
    expect(c.dayOfWeek.shape).toEqual({ kind: 'single', value: 1 });
    const c2 = schedule('0 9 * dec Sun');
    expect(c2.month.shape).toEqual({ kind: 'single', value: 12 });
    expect(c2.dayOfWeek.shape).toEqual({ kind: 'single', value: 0 });
  });

  it('resolves name ranges', () => {
    const c = schedule('0 9 * * mon-fri');
    expect(c.dayOfWeek.shape).toEqual({ kind: 'range', start: 1, end: 5 });
  });

  it('accepts day-of-week 7 as Sunday, including a 5-7 range spanning the wrap', () => {
    const c = schedule('0 0 * * 7');
    expect(c.dayOfWeek.shape).toEqual({ kind: 'single', value: 7 });
    const c2 = schedule('0 0 * * 5-7');
    expect(c2.dayOfWeek.shape).toEqual({ kind: 'range', start: 5, end: 7 });
  });

  it('tolerates extra/mixed whitespace between fields', () => {
    const c = schedule('  0   3  *  *   1  ');
    expect(c.minute.shape).toEqual({ kind: 'single', value: 0 });
    expect(c.dayOfWeek.shape).toEqual({ kind: 'single', value: 1 });
  });
});

describe('parseCronExpression — rejected input', () => {
  it('rejects the wrong number of fields', () => {
    expect(errorOf('* * * *')).toMatch(/Expected exactly 5 fields/);
    expect(errorOf('* * * * * *')).toMatch(/Expected exactly 5 fields/);
  });

  it('rejects out-of-range numeric values per field', () => {
    expect(errorOf('60 * * * *')).toMatch(/minute/i);
    expect(errorOf('* 24 * * *')).toMatch(/hour/i);
    expect(errorOf('* * 0 * *')).toMatch(/day of month/i);
    expect(errorOf('* * 32 * *')).toMatch(/day of month/i);
    expect(errorOf('* * * 0 *')).toMatch(/month/i);
    expect(errorOf('* * * 13 *')).toMatch(/month/i);
    expect(errorOf('* * * * 8')).toMatch(/day of week/i);
  });

  it('rejects a descending range', () => {
    expect(errorOf('* * * * 7-5')).toMatch(/descending range/);
    expect(errorOf('22-2 * * * *')).toMatch(/descending range/);
  });

  it('rejects a step value following a bare number instead of a range or asterisk', () => {
    expect(errorOf('5/15 * * * *')).toMatch(/must follow a range or '\*'/);
  });

  it('rejects a step value of zero', () => {
    expect(errorOf('*/0 * * * *')).toMatch(/positive integer/);
    expect(errorOf('1-10/0 * * * *')).toMatch(/positive integer/);
  });

  it("rejects '*' combined with other values in a list", () => {
    expect(errorOf('*,5 * * * *')).toMatch(/can't be combined/);
  });

  it('rejects a month/day-of-week name spelled out beyond 3 letters', () => {
    expect(errorOf('0 0 1 January *')).toMatch(/month/i);
    expect(errorOf('0 0 * * Monday')).toMatch(/day of week/i);
  });

  it('rejects a name in a field that has no names (minute/hour/day-of-month)', () => {
    expect(errorOf('Jan * * * *')).toMatch(/minute/i);
  });

  it('rejects an empty expression', () => {
    expect(errorOf('')).toMatch(/Enter a cron expression/);
    expect(errorOf('   ')).toMatch(/Enter a cron expression/);
  });

  it('rejects an unknown nickname', () => {
    expect(errorOf('@fortnightly')).toMatch(/Unknown nickname/);
  });
});

describe('@-nickname expansion', () => {
  it('expands the 6 schedule nicknames to their documented 5-field equivalents', () => {
    const cases: [string, string][] = [
      ['@yearly', '0 0 1 1 *'],
      ['@annually', '0 0 1 1 *'],
      ['@monthly', '0 0 1 * *'],
      ['@weekly', '0 0 * * 0'],
      ['@daily', '0 0 * * *'],
      ['@hourly', '0 * * * *'],
    ];
    for (const [nickname, equivalent] of cases) {
      const nick = schedule(nickname);
      const equiv = schedule(equivalent);
      expect(nick.minute.shape).toEqual(equiv.minute.shape);
      expect(nick.hour.shape).toEqual(equiv.hour.shape);
      expect(nick.dayOfMonth.shape).toEqual(equiv.dayOfMonth.shape);
      expect(nick.month.shape).toEqual(equiv.month.shape);
      expect(nick.dayOfWeek.shape).toEqual(equiv.dayOfWeek.shape);
      expect(nick.nickname).toBe(nickname.toLowerCase());
      expect(describeCron(nick)).toBe(describeCron(equiv));
    }
  });

  it('is case-insensitive for nicknames', () => {
    const c = schedule('@DAILY');
    expect(c.nickname).toBe('@daily');
  });

  it('models @reboot as a non-schedule case with its own description', () => {
    const r = parseCronExpression('@reboot');
    expect(r.error).toBeNull();
    expect(r.cron).toEqual({ kind: 'reboot' });
    expect(describeCron(r.cron!)).toMatch(/@reboot has no equivalent 5-field schedule/);
  });
});

describe('describeCron — worked examples (every one of these is cited verbatim on the page)', () => {
  it('"0 3 * * 1" -> "At 3:00 AM, only on Monday" (this tool\'s own headline example)', () => {
    expect(describe_('0 3 * * 1')).toBe('At 3:00 AM, only on Monday');
  });

  it('"* * * * *" -> "Every minute"', () => {
    expect(describe_('* * * * *')).toBe('Every minute');
  });

  it('"*/5 * * * *" -> "Every 5 minutes"', () => {
    expect(describe_('*/5 * * * *')).toBe('Every 5 minutes');
  });

  it('"0 * * * *" -> "At minute 0 past every hour" (the @hourly equivalent)', () => {
    expect(describe_('0 * * * *')).toBe('At minute 0 past every hour');
  });

  it('"0 0 * * *" -> "At 12:00 AM" (the @daily equivalent — midnight, 12-hour clock)', () => {
    expect(describe_('0 0 * * *')).toBe('At 12:00 AM');
  });

  it('"0 12 * * *" -> "At 12:00 PM" (noon)', () => {
    expect(describe_('0 12 * * *')).toBe('At 12:00 PM');
  });

  it('"0 0 * * 0" -> "At 12:00 AM, only on Sunday" (the @weekly equivalent)', () => {
    expect(describe_('0 0 * * 0')).toBe('At 12:00 AM, only on Sunday');
  });

  it('"0 0 1 * *" -> "At 12:00 AM, only on day 1 of the month" (the @monthly equivalent)', () => {
    expect(describe_('0 0 1 * *')).toBe('At 12:00 AM, only on day 1 of the month');
  });

  it('"0 0 1 1 *" -> "At 12:00 AM, in January, only on day 1 of the month" (the @yearly equivalent)', () => {
    expect(describe_('0 0 1 1 *')).toBe('At 12:00 AM, in January, only on day 1 of the month');
  });

  it('"0 9 * * 1-5" -> "At 9:00 AM, only on Monday through Friday" (weekday range)', () => {
    expect(describe_('0 9 * * 1-5')).toBe('At 9:00 AM, only on Monday through Friday');
  });

  it('"0 9,17 * * *" -> a fixed minute combined with a list of hours', () => {
    expect(describe_('0 9,17 * * *')).toBe('At minute 0, during hours 9 and 17');
  });

  it('"*/15 9-17 * * 1-5" -> every-15-minutes during a business-hours range on weekdays', () => {
    expect(describe_('*/15 9-17 * * 1-5')).toBe('Every 15 minutes, during hours 9 through 17, only on Monday through Friday');
  });

  it('"0 0 1,15 * *" -> a list of two days of the month', () => {
    expect(describe_('0 0 1,15 * *')).toBe('At 12:00 AM, only on days 1 and 15 of the month');
  });

  it('"0 0 1 * 1" -> day-of-month AND day-of-week both restricted are OR\'d together', () => {
    expect(describe_('0 0 1 * 1')).toBe('At 12:00 AM, on day 1 of the month or on Monday');
  });

  it('"0 9 * * mon,wed,fri" -> a 3-item weekday list joins with commas and "and"', () => {
    expect(describe_('0 9 * * mon,wed,fri')).toBe('At 9:00 AM, only on Monday, Wednesday and Friday');
  });

  it('"* * * * 7" -> day-of-week 7 describes as Sunday, same as 0', () => {
    expect(describe_('* * * * 7')).toBe(describe_('* * * * 0'));
    expect(describe_('* * * * 7')).toBe('Every minute, only on Sunday');
  });

  it('describeCron never appends a trailing period', () => {
    expect(describe_('0 3 * * 1').endsWith('.')).toBe(false);
  });
});
