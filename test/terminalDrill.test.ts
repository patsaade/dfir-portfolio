// Regression coverage for the pure parts of src/scripts/terminalDrill.ts —
// specifically unmetInvestigateGates()/investigateSatisfied(), the
// "investigate before you act" gate checkChallenge() applies to the 3
// destructive challenges (bash `kill`, cmd.exe `taskkill`, PowerShell
// `Stop-Process`) before letting a syntactically-correct destructive
// command finish the challenge. There is no other test file for this
// drill's client script today (it's the one DOM-manipulating piece of the
// terminal drill, per this repo's own Testing/QA convention of only
// unit-testing the pure/extracted logic — see terminalDrill.ts's own
// header comment) — test/terminalChallenges.test.ts and
// test/terminalEnvironments.test.ts already cover the separate concerns of
// grading and simulation.

import { describe, it, expect } from 'vitest';
import { unmetInvestigateGates, investigateSatisfied } from '../src/scripts/terminalDrill';
import { BASH_CHALLENGES, CMD_CHALLENGES, POWERSHELL_CHALLENGES } from '../src/data/drills/terminalChallenges';

describe('unmetInvestigateGates / investigateSatisfied — pure gate logic', () => {
  it('no `investigate` field at all is always fully satisfied, regardless of history', () => {
    expect(unmetInvestigateGates(undefined, [])).toEqual([]);
    expect(unmetInvestigateGates(undefined, ['whoami', 'ls'])).toEqual([]);
    expect(investigateSatisfied(undefined, [])).toBe(true);
  });

  it('an empty `investigate` array is always fully satisfied', () => {
    expect(unmetInvestigateGates([], ['whoami'])).toEqual([]);
    expect(investigateSatisfied([], [])).toBe(true);
  });

  it('a single gate is unmet against empty history', () => {
    const gate = [{ description: 'check X first', test: (raw: string) => raw === 'check-x' }];
    expect(unmetInvestigateGates(gate, [])).toEqual(['check X first']);
    expect(investigateSatisfied(gate, [])).toBe(false);
  });

  it('a single gate becomes satisfied once a matching command appears ANYWHERE in history, not just the most recent one', () => {
    const gate = [{ description: 'check X first', test: (raw: string) => raw === 'check-x' }];
    expect(investigateSatisfied(gate, ['check-x', 'something-else'])).toBe(true);
    expect(investigateSatisfied(gate, ['something-else', 'check-x'])).toBe(true);
    expect(investigateSatisfied(gate, ['something-else', 'still-not-it'])).toBe(false);
  });

  it('multiple gates: unmetInvestigateGates returns only the descriptions of the ones NOT yet satisfied, in order', () => {
    const gates = [
      { description: 'gate A', test: (raw: string) => raw === 'a' },
      { description: 'gate B', test: (raw: string) => raw === 'b' },
      { description: 'gate C', test: (raw: string) => raw === 'c' },
    ];
    expect(unmetInvestigateGates(gates, [])).toEqual(['gate A', 'gate B', 'gate C']);
    expect(unmetInvestigateGates(gates, ['a'])).toEqual(['gate B', 'gate C']);
    expect(unmetInvestigateGates(gates, ['a', 'c'])).toEqual(['gate B']);
    expect(unmetInvestigateGates(gates, ['a', 'b', 'c'])).toEqual([]);
    expect(investigateSatisfied(gates, ['a', 'b', 'c'])).toBe(true);
  });

  it('a gate whose test() throws is treated as "not matched" rather than propagating the error', () => {
    const gate = [
      {
        description: 'a gate that blows up',
        test: () => {
          throw new Error('boom');
        },
      },
    ];
    expect(() => unmetInvestigateGates(gate, ['anything'])).not.toThrow();
    expect(unmetInvestigateGates(gate, ['anything'])).toEqual(['a gate that blows up']);
    expect(investigateSatisfied(gate, ['anything'])).toBe(false);
  });

  it('one throwing gate does not stop the others from being checked correctly', () => {
    const gates = [
      { description: 'ok gate', test: (raw: string) => raw === 'ok' },
      {
        description: 'throwing gate',
        test: () => {
          throw new Error('boom');
        },
      },
    ];
    expect(unmetInvestigateGates(gates, ['ok'])).toEqual(['throwing gate']);
  });
});

describe('the 3 real destructive-challenge investigate gates', () => {
  const bashKill = BASH_CHALLENGES.find((c) => c.id === 'bash-kill')!;
  const cmdTaskkill = CMD_CHALLENGES.find((c) => c.id === 'cmd-taskkill')!;
  const psStopProcess = POWERSHELL_CHALLENGES.find((c) => c.id === 'powershell-stop-process')!;

  it('every other challenge (non-destructive) has no `investigate` field at all', () => {
    for (const track of [BASH_CHALLENGES, CMD_CHALLENGES, POWERSHELL_CHALLENGES]) {
      for (const c of track) {
        if (c.id === 'bash-kill' || c.id === 'cmd-taskkill' || c.id === 'powershell-stop-process') continue;
        expect(c.investigate, `${c.id} should not have an investigate gate`).toBeUndefined();
      }
    }
  });

  describe('bash-kill: must have checked netstat -tulpn (any flag order/case) before killing 4521', () => {
    it('is unmet with empty history, and the destructive command alone does not satisfy it', () => {
      expect(investigateSatisfied(bashKill.investigate, [])).toBe(false);
      expect(investigateSatisfied(bashKill.investigate, ['kill -9 4521'])).toBe(false);
    });

    it('is satisfied once netstat -tulpn (or a leniency-accepted flag-order/case variant) is in history', () => {
      expect(investigateSatisfied(bashKill.investigate, ['netstat -tulpn'])).toBe(true);
      expect(investigateSatisfied(bashKill.investigate, ['netstat -nlput'])).toBe(true);
      expect(investigateSatisfied(bashKill.investigate, ['netstat -TULPN'])).toBe(true);
      expect(investigateSatisfied(bashKill.investigate, ['netstat -tulpn | grep 4444'])).toBe(true);
    });

    it('is NOT satisfied by an incomplete flag set or an unrelated command', () => {
      expect(investigateSatisfied(bashKill.investigate, ['netstat -tulp'])).toBe(false); // missing a flag
      expect(investigateSatisfied(bashKill.investigate, ['ps aux | grep chrome'])).toBe(false);
      expect(investigateSatisfied(bashKill.investigate, ['whoami'])).toBe(false);
    });

    it('unmetInvestigateGates names the netstat check when unmet', () => {
      const unmet = unmetInvestigateGates(bashKill.investigate, []);
      expect(unmet).toHaveLength(1);
      expect(unmet[0]).toContain('netstat -tulpn');
      expect(unmet[0]).toContain('4521');
    });
  });

  describe('cmd-taskkill: must have run tasklist before killing 4521', () => {
    it('is unmet with empty history', () => {
      expect(investigateSatisfied(cmdTaskkill.investigate, [])).toBe(false);
      expect(investigateSatisfied(cmdTaskkill.investigate, ['taskkill /PID 4521 /F'])).toBe(false);
    });

    it('is satisfied by a bare tasklist or the piped findstr form, case-insensitively', () => {
      expect(investigateSatisfied(cmdTaskkill.investigate, ['tasklist'])).toBe(true);
      expect(investigateSatisfied(cmdTaskkill.investigate, ['TASKLIST'])).toBe(true);
      expect(investigateSatisfied(cmdTaskkill.investigate, ['tasklist | findstr chrome'])).toBe(true);
    });

    it('is NOT satisfied by an unrelated command', () => {
      expect(investigateSatisfied(cmdTaskkill.investigate, ['dir'])).toBe(false);
      expect(investigateSatisfied(cmdTaskkill.investigate, ['whoami'])).toBe(false);
    });
  });

  describe('powershell-stop-process: must have run Get-Process before stopping 4521', () => {
    it('is unmet with empty history', () => {
      expect(investigateSatisfied(psStopProcess.investigate, [])).toBe(false);
      expect(investigateSatisfied(psStopProcess.investigate, ['Stop-Process -Id 4521 -Force'])).toBe(false);
    });

    it('is satisfied by a bare Get-Process or the piped Where-Object form, case-insensitively', () => {
      expect(investigateSatisfied(psStopProcess.investigate, ['Get-Process'])).toBe(true);
      expect(investigateSatisfied(psStopProcess.investigate, ['get-process'])).toBe(true);
      expect(investigateSatisfied(psStopProcess.investigate, ['Get-Process | Where-Object {$_.Name -like "*chrome*"}'])).toBe(true);
    });

    it('is NOT satisfied by an unrelated command', () => {
      expect(investigateSatisfied(psStopProcess.investigate, ['Get-ChildItem'])).toBe(false);
      expect(investigateSatisfied(psStopProcess.investigate, ['whoami'])).toBe(false);
    });
  });
});
