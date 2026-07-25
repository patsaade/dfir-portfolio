import { describe, it, expect } from 'vitest';
import {
  fieldValueMatches,
  selectionMatches,
  compileSigmaRegex,
  parseCondition,
  evaluateCondition,
  evaluateRule,
  parseEventLine,
  generateYaml,
  buildConditionString,
  parseSigmaYaml,
  STARTER_RULE,
  STARTER_EVENTS,
  type SigmaFieldValue,
  type SigmaSelection,
  type SigmaRule,
} from '../src/utils/sigma';

describe('fieldValueMatches — per-modifier field-value matching', () => {
  const event = { Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', CommandLine: 'powershell.exe -EncodedCommand SQBmAA==', EventID: 4104 };

  it('equals: matches exact value, case-insensitively', () => {
    const fv: SigmaFieldValue = { field: 'EventID', modifier: 'equals', value: '4104' };
    expect(fieldValueMatches(fv, event)).toBe(true);
    expect(fieldValueMatches({ field: 'EventID', modifier: 'equals', value: '9999' }, event)).toBe(false);
  });

  it('equals is case-insensitive for string fields', () => {
    const exact = { field: 'CommandLine', modifier: 'equals' as const, value: event.CommandLine.toUpperCase() };
    expect(fieldValueMatches(exact, event)).toBe(true);
    expect(fieldValueMatches({ field: 'CommandLine', modifier: 'equals', value: 'totally different text' }, event)).toBe(false);
  });

  it('contains: matches a substring anywhere', () => {
    const fv: SigmaFieldValue = { field: 'CommandLine', modifier: 'contains', value: '-encodedcommand' };
    expect(fieldValueMatches(fv, event)).toBe(true);
    expect(fieldValueMatches({ field: 'CommandLine', modifier: 'contains', value: 'nope' }, event)).toBe(false);
  });

  it('startswith: matches a prefix only', () => {
    expect(fieldValueMatches({ field: 'CommandLine', modifier: 'startswith', value: 'powershell.exe' }, event)).toBe(true);
    expect(fieldValueMatches({ field: 'CommandLine', modifier: 'startswith', value: '-EncodedCommand' }, event)).toBe(false);
  });

  it('endswith: matches a suffix, and the exact powershell.exe path check', () => {
    expect(fieldValueMatches({ field: 'Image', modifier: 'endswith', value: '\\powershell.exe' }, event)).toBe(true);
    expect(fieldValueMatches({ field: 'Image', modifier: 'endswith', value: '\\cmd.exe' }, event)).toBe(false);
  });

  it('|re: matches via a compiled JS RegExp', () => {
    expect(fieldValueMatches({ field: 'CommandLine', modifier: 're', value: '-[Ee]ncoded[Cc]ommand\\s+\\S+' }, event)).toBe(true);
    expect(fieldValueMatches({ field: 'CommandLine', modifier: 're', value: '^cmd\\.exe' }, event)).toBe(false);
  });

  it('|re: an invalid pattern fails cleanly (no match, no throw) via compileSigmaRegex', () => {
    expect(compileSigmaRegex('(unterminated[')).toBeNull();
    expect(() => fieldValueMatches({ field: 'CommandLine', modifier: 're', value: '(unterminated[' }, event)).not.toThrow();
    expect(fieldValueMatches({ field: 'CommandLine', modifier: 're', value: '(unterminated[' }, event)).toBe(false);
  });

  it('a missing field never matches, regardless of modifier', () => {
    expect(fieldValueMatches({ field: 'NoSuchField', modifier: 'contains', value: 'x' }, event)).toBe(false);
  });

  it('field-name matching is exact — a near-miss key name does not match (no glob support, see file header)', () => {
    expect(fieldValueMatches({ field: 'command_line', modifier: 'contains', value: 'powershell' }, event)).toBe(false);
  });
});

describe('selectionMatches — AND across a selection’s field rows', () => {
  const event = { Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', CommandLine: 'powershell.exe -EncodedCommand abc' };

  it('matches only when every row in the selection matches', () => {
    const sel: SigmaSelection = {
      name: 'selection1',
      fields: [
        { field: 'Image', modifier: 'endswith', value: '\\powershell.exe' },
        { field: 'CommandLine', modifier: 'contains', value: '-EncodedCommand' },
      ],
    };
    expect(selectionMatches(sel, event)).toBe(true);
  });

  it('fails if any single row fails', () => {
    const sel: SigmaSelection = {
      name: 'selection1',
      fields: [
        { field: 'Image', modifier: 'endswith', value: '\\powershell.exe' },
        { field: 'CommandLine', modifier: 'contains', value: 'this-is-not-present' },
      ],
    };
    expect(selectionMatches(sel, event)).toBe(false);
  });

  it('a selection with zero field rows never matches (no vacuous truth)', () => {
    expect(selectionMatches({ name: 'empty', fields: [] }, event)).toBe(false);
  });
});

describe('parseCondition — supported condition-logic grammar', () => {
  it('parses "1 of them"', () => {
    expect(parseCondition('1 of them')).toEqual({ parsed: { type: 'them', op: 'any' }, error: null });
  });

  it('parses "all of them", case-insensitively', () => {
    expect(parseCondition('ALL of Them')).toEqual({ parsed: { type: 'them', op: 'all' }, error: null });
  });

  it('parses "1 of selection*" as a wildcard-prefix form', () => {
    expect(parseCondition('1 of selection*')).toEqual({ parsed: { type: 'wildcard', op: 'any', prefix: 'selection' }, error: null });
  });

  it('parses "all of sel*"', () => {
    expect(parseCondition('all of sel*')).toEqual({ parsed: { type: 'wildcard', op: 'all', prefix: 'sel' }, error: null });
  });

  it('parses a bare "and" list of selection names', () => {
    expect(parseCondition('selection1 and selection2')).toEqual({ parsed: { type: 'list', op: 'and', names: ['selection1', 'selection2'] }, error: null });
  });

  it('parses a bare "or" list of selection names', () => {
    expect(parseCondition('selection1 or selection2 or selection3')).toEqual({
      parsed: { type: 'list', op: 'or', names: ['selection1', 'selection2', 'selection3'] },
      error: null,
    });
  });

  it('parses a single bare selection name', () => {
    expect(parseCondition('selection')).toEqual({ parsed: { type: 'list', op: 'and', names: ['selection'] }, error: null });
  });

  it('rejects mixing "and" and "or" in one condition with a friendly error', () => {
    const { parsed, error } = parseCondition('selection1 and selection2 or selection3');
    expect(parsed).toBeNull();
    expect(error).toMatch(/and.*or|mixing/i);
  });

  it('rejects an empty condition with a friendly error, not a throw', () => {
    expect(() => parseCondition('')).not.toThrow();
    expect(parseCondition('  ').parsed).toBeNull();
  });

  it('rejects unrecognized syntax with a friendly error', () => {
    const { parsed, error } = parseCondition('selection1 && selection2');
    expect(parsed).toBeNull();
    expect(error).toBeTruthy();
  });
});

describe('evaluateCondition — condition logic against a multi-selection rule', () => {
  const selections: SigmaSelection[] = [
    { name: 'selection1', fields: [{ field: 'A', modifier: 'equals', value: '1' }] },
    { name: 'selection2', fields: [{ field: 'B', modifier: 'equals', value: '2' }] },
    { name: 'selection3', fields: [{ field: 'C', modifier: 'equals', value: '3' }] },
  ];

  it('"1 of them": matches if any selection matches, reports which one', () => {
    const event = { A: '1', B: 'nope', C: 'nope' };
    const result = evaluateCondition('1 of them', selections, event);
    expect(result.matched).toBe(true);
    expect(result.matchedSelections).toEqual(['selection1']);
    expect(result.error).toBeNull();
  });

  it('"1 of them": no match when nothing matches', () => {
    const event = { A: 'x', B: 'y', C: 'z' };
    const result = evaluateCondition('1 of them', selections, event);
    expect(result.matched).toBe(false);
    expect(result.matchedSelections).toEqual([]);
  });

  it('"all of them": requires every selection to match', () => {
    const allMatch = { A: '1', B: '2', C: '3' };
    expect(evaluateCondition('all of them', selections, allMatch).matched).toBe(true);
    const partial = { A: '1', B: '2', C: 'nope' };
    const result = evaluateCondition('all of them', selections, partial);
    expect(result.matched).toBe(false);
    expect(result.matchedSelections).toEqual([]);
  });

  it('"1 of selection*": wildcard prefix matches any selection starting with the prefix', () => {
    const event = { A: 'x', B: '2', C: 'x' };
    const result = evaluateCondition('1 of selection*', selections, event);
    expect(result.matched).toBe(true);
    expect(result.matchedSelections).toEqual(['selection2']);
  });

  it('"all of selection*": requires every prefix-matching selection to match', () => {
    const event = { A: '1', B: '2', C: '3' };
    expect(evaluateCondition('all of selection*', selections, event).matched).toBe(true);
    expect(evaluateCondition('all of selection*', selections, { A: '1', B: '2', C: 'x' }).matched).toBe(false);
  });

  it('bare "and" list: requires the named selections (only) to all match', () => {
    const event = { A: '1', B: '2', C: 'irrelevant-does-not-matter' };
    const result = evaluateCondition('selection1 and selection2', selections, event);
    expect(result.matched).toBe(true);
    expect(result.matchedSelections.sort()).toEqual(['selection1', 'selection2']);
  });

  it('bare "or" list: matches if any named selection matches', () => {
    const event = { A: 'x', B: '2', C: 'x' };
    const result = evaluateCondition('selection1 or selection2', selections, event);
    expect(result.matched).toBe(true);
    expect(result.matchedSelections).toEqual(['selection2']);
  });

  it('reports an error for an unknown selection name instead of silently failing', () => {
    const result = evaluateCondition('selection1 and doesnotexist', selections, { A: '1' });
    expect(result.matched).toBe(false);
    expect(result.error).toMatch(/unknown/i);
  });

  it('propagates a parse error (e.g. empty condition) without throwing', () => {
    const result = evaluateCondition('', selections, { A: '1' });
    expect(result.matched).toBe(false);
    expect(result.error).toBeTruthy();
  });
});

describe('buildConditionString — guided dropdown -> canonical condition text', () => {
  it('builds each UI type into its matching condition grammar', () => {
    expect(buildConditionString('them-any')).toBe('1 of them');
    expect(buildConditionString('them-all')).toBe('all of them');
    expect(buildConditionString('wildcard-any', { prefix: 'selection' })).toBe('1 of selection*');
    expect(buildConditionString('wildcard-all', { prefix: 'sel' })).toBe('all of sel*');
    expect(buildConditionString('list-and', { names: ['a', 'b'] })).toBe('a and b');
    expect(buildConditionString('list-or', { names: ['a', 'b', 'c'] })).toBe('a or b or c');
  });

  it('falls back to "selection" for a blank wildcard prefix', () => {
    expect(buildConditionString('wildcard-any', {})).toBe('1 of selection*');
  });

  it('the built string round-trips through parseCondition', () => {
    const str = buildConditionString('list-and', { names: ['selection1', 'selection2'] });
    expect(parseCondition(str).parsed).toEqual({ type: 'list', op: 'and', names: ['selection1', 'selection2'] });
  });
});

describe('parseEventLine — auto-detect JSON vs. key=value per line', () => {
  it('parses a JSON object line', () => {
    expect(parseEventLine('{"EventID": 4104, "Image": "powershell.exe"}')).toEqual({ EventID: 4104, Image: 'powershell.exe' });
  });

  it('falls back to key=value parsing when JSON.parse fails', () => {
    expect(parseEventLine('EventID=4104 Image=powershell.exe')).toEqual({ EventID: '4104', Image: 'powershell.exe' });
  });

  it('key=value parsing supports double-quoted values containing spaces', () => {
    expect(parseEventLine('CommandLine="powershell.exe -EncodedCommand abc" EventID=4104')).toEqual({
      CommandLine: 'powershell.exe -EncodedCommand abc',
      EventID: '4104',
    });
  });

  it('returns null for a blank line', () => {
    expect(parseEventLine('')).toBeNull();
    expect(parseEventLine('   ')).toBeNull();
  });

  it('returns null (fails cleanly, no throw) for a line that is neither valid JSON nor key=value shaped', () => {
    expect(() => parseEventLine('just some prose, not an event at all')).not.toThrow();
    expect(parseEventLine('just some prose, not an event at all')).toBeNull();
  });

  it('a JSON array is not treated as an event object', () => {
    expect(parseEventLine('[1,2,3]')).toBeNull();
  });
});

describe('generateYaml — read-only rendering of builder state', () => {
  it('renders title, selections, and condition', () => {
    const rule: SigmaRule = {
      title: 'Test Rule',
      selections: [{ name: 'selection1', fields: [{ field: 'Image', modifier: 'endswith', value: '\\powershell.exe' }] }],
      condition: 'selection1',
    };
    const yaml = generateYaml(rule);
    expect(yaml).toContain('title: Test Rule');
    expect(yaml).toContain('selection1:');
    expect(yaml).toContain('Image|endswith:');
    expect(yaml).toContain('condition: selection1');
  });

  it('renders a bare-equals field without a |modifier suffix', () => {
    const rule: SigmaRule = { title: 't', selections: [{ name: 's', fields: [{ field: 'EventID', modifier: 'equals', value: '4104' }] }], condition: 's' };
    // A numeric-looking string value is single-quoted so it round-trips as a
    // YAML string rather than being reinterpreted as an integer.
    expect(generateYaml(rule)).toContain("EventID: '4104'");
    expect(generateYaml(rule)).not.toContain('EventID|equals');
  });

  it('skips incomplete rows (blank field or value) rather than emitting half-written YAML', () => {
    const rule: SigmaRule = {
      title: 't',
      selections: [{ name: 's', fields: [{ field: '', modifier: 'equals', value: 'x' }, { field: 'A', modifier: 'equals', value: '' }] }],
      condition: 's',
    };
    expect(generateYaml(rule)).toContain('{}');
  });
});

describe('parseSigmaYaml — import side of generateYaml (round-trips its own output shape only)', () => {
  it('round-trips generateYaml(STARTER_RULE) back into the exact same rule, ignoring the leading comment lines', () => {
    const yaml = generateYaml(STARTER_RULE);
    expect(yaml.startsWith('# Generated from')).toBe(true); // sanity: the comment lines really are there to be skipped
    const { rule, error } = parseSigmaYaml(yaml);
    expect(error).toBeNull();
    expect(rule).toEqual(STARTER_RULE);
  });

  it('parses an empty selection body ("{}") as a selection with zero field rows', () => {
    const yaml = ['title: t', 'detection:', '  selection_empty:', '    {}', '  condition: selection_empty'].join('\n');
    const { rule, error } = parseSigmaYaml(yaml);
    expect(error).toBeNull();
    expect(rule).toEqual({ title: 't', selections: [{ name: 'selection_empty', fields: [] }], condition: 'selection_empty' });
  });

  it('parses a field row using the |re modifier', () => {
    const yaml = ['title: t', 'detection:', '  selection1:', '    CommandLine|re: ^cmd\\.exe', '  condition: selection1'].join('\n');
    const { rule, error } = parseSigmaYaml(yaml);
    expect(error).toBeNull();
    expect(rule?.selections).toEqual([{ name: 'selection1', fields: [{ field: 'CommandLine', modifier: 're', value: '^cmd\\.exe' }] }]);
  });

  it('rejects an unrecognized modifier with a specific error naming it', () => {
    const yaml = ['title: t', 'detection:', '  selection1:', '    Field|bogus: x', '  condition: selection1'].join('\n');
    const { rule, error } = parseSigmaYaml(yaml);
    expect(rule).toBeNull();
    expect(error).toMatch(/bogus/);
    expect(error).toMatch(/equals|contains|startswith|endswith|re/);
  });

  it('surfaces the same "mixed and/or" error parseCondition already reports, rather than duplicating that logic', () => {
    const yaml = [
      'title: t',
      'detection:',
      '  selection1:',
      '    A: 1',
      '  selection2:',
      '    B: 2',
      '  selection3:',
      '    C: 3',
      '  condition: selection1 and selection2 or selection3',
    ].join('\n');
    const { rule, error } = parseSigmaYaml(yaml);
    expect(rule).toBeNull();
    const expectedError = parseCondition('selection1 and selection2 or selection3').error;
    expect(expectedError).toBeTruthy();
    expect(error).toBe(expectedError);
  });

  it('never throws on completely garbage input, and reports a specific missing-title/detection error', () => {
    expect(() => parseSigmaYaml('this is not yaml at all, just prose')).not.toThrow();
    const { rule, error } = parseSigmaYaml('this is not yaml at all, just prose');
    expect(rule).toBeNull();
    expect(error).toMatch(/title/i);
  });

  it('reports a specific missing-detection error when title is present but detection is not', () => {
    const { rule, error } = parseSigmaYaml('title: Just a title\nno detection here');
    expect(rule).toBeNull();
    expect(error).toMatch(/detection/i);
  });

  it('reports a specific error for list-valued fields (OR-list shorthand) rather than crashing', () => {
    const withNestedList = ['title: t', 'detection:', '  selection1:', '    Field:', '      - a', '      - b', '  condition: selection1'].join('\n');
    expect(() => parseSigmaYaml(withNestedList)).not.toThrow();
    expect(parseSigmaYaml(withNestedList).rule).toBeNull();
    expect(parseSigmaYaml(withNestedList).error).toMatch(/list/i);

    const withBracketList = ['title: t', 'detection:', '  selection1:', '    Field: [a, b]', '  condition: selection1'].join('\n');
    expect(parseSigmaYaml(withBracketList).rule).toBeNull();
    expect(parseSigmaYaml(withBracketList).error).toMatch(/list/i);
  });

  it('reports a specific out-of-scope error for logsource/level/tags rather than silently dropping them', () => {
    const yaml = ['title: t', 'logsource:', '  category: process_creation', 'detection:', '  selection1:', '    A: 1', '  condition: selection1'].join('\n');
    const { rule, error } = parseSigmaYaml(yaml);
    expect(rule).toBeNull();
    expect(error).toMatch(/logsource/i);
  });

  it('is not thrown off by a bare field-name (equals) row mixed with a modifier row', () => {
    const yaml = ['title: t', 'detection:', '  selection1:', '    EventID: 4104', '    Image|endswith: \\powershell.exe', '  condition: selection1'].join('\n');
    const { rule, error } = parseSigmaYaml(yaml);
    expect(error).toBeNull();
    expect(rule?.selections[0].fields).toEqual([
      { field: 'EventID', modifier: 'equals', value: '4104' },
      { field: 'Image', modifier: 'endswith', value: '\\powershell.exe' },
    ]);
  });
});

describe('end-to-end: evaluateRule against a matching and a non-matching sample event', () => {
  const rule: SigmaRule = {
    title: 'Suspicious PowerShell EncodedCommand Usage (fabricated example)',
    selections: [
      { name: 'selection_process', fields: [{ field: 'Image', modifier: 'endswith', value: '\\powershell.exe' }] },
      { name: 'selection_cli', fields: [{ field: 'CommandLine', modifier: 'contains', value: '-EncodedCommand' }] },
    ],
    condition: 'selection_process and selection_cli',
  };

  it('matches a PowerShell EncodedCommand event and reports both contributing selections', () => {
    const event = parseEventLine(STARTER_EVENTS.split('\n')[0])!;
    const result = evaluateRule(rule, event);
    expect(result.matched).toBe(true);
    expect(result.matchedSelections.sort()).toEqual(['selection_cli', 'selection_process']);
    expect(result.selectionResults).toEqual({ selection_process: true, selection_cli: true });
    expect(result.conditionError).toBeNull();
  });

  it('does not match an unrelated cmd.exe event', () => {
    const event = parseEventLine(STARTER_EVENTS.split('\n')[1])!;
    const result = evaluateRule(rule, event);
    expect(result.matched).toBe(false);
    expect(result.matchedSelections).toEqual([]);
    expect(result.selectionResults.selection_process).toBe(false);
    expect(result.selectionResults.selection_cli).toBe(false);
  });

  it('the starter rule + starter events ship in an internally-consistent match/no-match pair', () => {
    expect(STARTER_RULE.condition).toBe(rule.condition);
    const lines = STARTER_EVENTS.split('\n');
    expect(lines).toHaveLength(2);
    const [matchEvent, noMatchEvent] = lines.map((l) => parseEventLine(l)!);
    expect(evaluateRule(STARTER_RULE, matchEvent).matched).toBe(true);
    expect(evaluateRule(STARTER_RULE, noMatchEvent).matched).toBe(false);
  });
});
