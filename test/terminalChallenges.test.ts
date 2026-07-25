// Regression coverage for src/data/drills/terminalChallenges.ts's grade()
// functions — the regex-based grading logic that determines when a terminal
// drill challenge is "solved". This logic was lifted verbatim from the now-
// deleted src/data/drills/commands.ts (see that file's own header comment
// and test/commands.test.ts, which this file replaces the coverage of).
// test/terminalEnvironments.test.ts already thoroughly covers the *simulated
// output* of each command; this file covers the separate concern of whether
// a given raw command STRING is graded correct — same distinction the
// terminalChallenges.ts header comment draws (this file never simulates
// anything, it only grades text).
//
// Every challenge gets: (1) the exact documented answer passes, (2) every
// documented leniency (flag order, aliases, quote style, case) still
// passes, and (3) a clearly wrong/incomplete answer fails — so a future
// accidental tightening OR loosening of a regex is caught.

import { describe, it, expect } from 'vitest';
import { BASH_CHALLENGES, CMD_CHALLENGES, POWERSHELL_CHALLENGES } from '../src/data/drills/terminalChallenges';

describe('track shapes', () => {
  it('bash track has 9 challenges (whoami + 8), cmd/PowerShell have 5 each (whoami + 4)', () => {
    expect(BASH_CHALLENGES).toHaveLength(9);
    expect(CMD_CHALLENGES).toHaveLength(5);
    expect(POWERSHELL_CHALLENGES).toHaveLength(5);
  });

  it('every challenge id is unique within its own track', () => {
    for (const track of [BASH_CHALLENGES, CMD_CHALLENGES, POWERSHELL_CHALLENGES]) {
      const ids = track.map((c) => c.id);
      expect(new Set(ids).size).toBe(ids.length);
    }
  });

  it('whoami is the first challenge in every track, with identical wording', () => {
    for (const track of [BASH_CHALLENGES, CMD_CHALLENGES, POWERSHELL_CHALLENGES]) {
      expect(track[0].prompt).toBe('Any shell — bash, cmd.exe, or PowerShell: show the current username.');
      expect(track[0].grade('whoami')).toBe(true);
      expect(track[0].grade('WHOAMI')).toBe(false); // whoami is case-SENSITIVE by design (a real shell command name)
      expect(track[0].grade('whoami -v')).toBe(false);
    }
  });
});

describe('bash track grading', () => {
  const byId = (id: string) => BASH_CHALLENGES.find((c) => c.id === id)!;

  it('pwd: exact only, no flags', () => {
    const g = byId('bash-pwd').grade;
    expect(g('pwd')).toBe(true);
    expect(g('  pwd  ')).toBe(true); // collapse() trims
    expect(g('pwd -L')).toBe(false);
    expect(g('cd')).toBe(false);
  });

  it('ls -la: accepts -la, -al, -a -l, -l -a; rejects a single flag alone', () => {
    const g = byId('bash-ls-la').grade;
    expect(g('ls -la')).toBe(true);
    expect(g('ls -al')).toBe(true);
    expect(g('ls -a -l')).toBe(true);
    expect(g('ls -l -a')).toBe(true);
    expect(g('ls -l')).toBe(false);
    expect(g('ls -a')).toBe(false);
    expect(g('ls')).toBe(false);
  });

  it('cat notes.txt: exact filename required', () => {
    const g = byId('bash-cat').grade;
    expect(g('cat notes.txt')).toBe(true);
    expect(g('cat   notes.txt')).toBe(true); // collapse() normalizes internal whitespace too
    expect(g('cat auth.log')).toBe(false);
    expect(g('less notes.txt')).toBe(false);
  });

  it('grep "Failed password" auth.log: single or double quotes, exact pattern/file', () => {
    const g = byId('bash-grep').grade;
    expect(g('grep "Failed password" auth.log')).toBe(true);
    expect(g("grep 'Failed password' auth.log")).toBe(true);
    expect(g('grep Failed password auth.log')).toBe(false); // unquoted multi-word pattern
    expect(g('grep "failed password" auth.log')).toBe(false); // wrong case, regex is case-sensitive here
    expect(g('grep "Failed password" notes.txt')).toBe(false);
  });

  it('ps aux | grep chrome: optional dash on aux, exact filter term', () => {
    const g = byId('bash-ps-grep').grade;
    expect(g('ps aux | grep chrome')).toBe(true);
    expect(g('ps -aux | grep chrome')).toBe(true);
    expect(g('ps aux|grep chrome')).toBe(true); // collapse() only normalizes whitespace runs, spacing around | is optional in the regex
    expect(g('ps aux | grep sshd')).toBe(false);
    expect(g('ps aux')).toBe(false);
  });

  it('kill -9 4521: accepts -9, -SIGKILL, -KILL (case-insensitive), fixed PID', () => {
    const g = byId('bash-kill').grade;
    expect(g('kill -9 4521')).toBe(true);
    expect(g('kill -SIGKILL 4521')).toBe(true);
    expect(g('kill -sigkill 4521')).toBe(true);
    expect(g('kill -KILL 4521')).toBe(true);
    expect(g('kill -9 9999')).toBe(false); // wrong PID
    expect(g('kill -15 4521')).toBe(false); // SIGTERM, not SIGKILL
  });

  it('netstat -tulpn: any order/case of the 5 flags, nothing else', () => {
    const g = byId('bash-netstat').grade;
    expect(g('netstat -tulpn')).toBe(true);
    expect(g('netstat -nlput')).toBe(true);
    expect(g('netstat -TULPN')).toBe(true);
    expect(g('netstat -tulp')).toBe(false); // missing a flag
    expect(g('netstat -tulpnx')).toBe(false); // extra flag
  });

  it('capstone netstat -tulpn | grep 4444: same flag leniency, fixed port', () => {
    const g = byId('bash-capstone').grade;
    expect(g('netstat -tulpn | grep 4444')).toBe(true);
    expect(g('netstat -nlput | grep 4444')).toBe(true);
    expect(g('netstat -tulpn | grep 443')).toBe(false); // wrong port
    expect(g('netstat -tulpn')).toBe(false); // missing the pipe
  });
});

describe('cmd.exe track grading', () => {
  const byId = (id: string) => CMD_CHALLENGES.find((c) => c.id === id)!;

  it('dir: exact, case-insensitive', () => {
    const g = byId('cmd-dir').grade;
    expect(g('dir')).toBe(true);
    expect(g('DIR')).toBe(true);
    expect(g('dir /a')).toBe(false);
  });

  it('tasklist | findstr chrome: command/pipe keywords case-insensitive, but the search TERM is case-sensitive (matches findstr\'s own real behavior, and the simulation)', () => {
    const g = byId('cmd-tasklist-findstr').grade;
    expect(g('tasklist | findstr chrome')).toBe(true);
    expect(g('TASKLIST | FINDSTR chrome')).toBe(true); // keyword case doesn't matter
    expect(g('tasklist|findstr chrome')).toBe(true);
    expect(g('tasklist | findstr explorer')).toBe(false);
    // The term itself is case-sensitive, matching findstr's real default and
    // this environment's own findstrRun simulation (see terminalEnvironments.test.ts's
    // "findstr is case-sensitive by default" case) — "CHROME" must NOT grade
    // as correct, since the simulated output for it is genuinely empty.
    expect(g('tasklist | findstr CHROME')).toBe(false);
  });

  it('taskkill /PID 4521 /F: order-independent, case-insensitive, fixed PID', () => {
    const g = byId('cmd-taskkill').grade;
    expect(g('taskkill /PID 4521 /F')).toBe(true);
    expect(g('taskkill /F /PID 4521')).toBe(true);
    expect(g('taskkill /pid 4521 /f')).toBe(true);
    expect(g('taskkill /PID 9999 /F')).toBe(false);
    expect(g('taskkill /PID 4521')).toBe(false); // missing /F
  });

  it('schtasks /query: exact, case-insensitive', () => {
    const g = byId('cmd-schtasks').grade;
    expect(g('schtasks /query')).toBe(true);
    expect(g('SCHTASKS /QUERY')).toBe(true);
    expect(g('schtasks')).toBe(false);
  });
});

describe('PowerShell track grading', () => {
  const byId = (id: string) => POWERSHELL_CHALLENGES.find((c) => c.id === id)!;

  it('Get-ChildItem: accepts get-childitem, dir, gci, ls (case-insensitive)', () => {
    const g = byId('powershell-get-childitem').grade;
    for (const answer of ['Get-ChildItem', 'get-childitem', 'dir', 'gci', 'ls', 'GCI']) {
      expect(g(answer)).toBe(true);
    }
    expect(g('Get-Item')).toBe(false);
  });

  it('Get-Content notes.txt: accepts get-content, gc, cat, type (case-insensitive), fixed filename', () => {
    const g = byId('powershell-get-content').grade;
    for (const verb of ['Get-Content', 'gc', 'cat', 'type']) {
      expect(g(`${verb} notes.txt`)).toBe(true);
    }
    expect(g('Get-Content auth.log')).toBe(false);
    expect(g('Get-Content')).toBe(false); // missing filename
  });

  it('Get-Process | Where-Object {...}: accepts Where-Object/where/?, Name or ProcessName, single or double quotes', () => {
    const g = byId('powershell-get-process-where').grade;
    expect(g('Get-Process | Where-Object {$_.Name -like "*chrome*"}')).toBe(true);
    expect(g('Get-Process | Where-Object {$_.ProcessName -like "*chrome*"}')).toBe(true);
    expect(g("Get-Process | where {$_.Name -like '*chrome*'}")).toBe(true);
    expect(g('Get-Process | ? {$_.Name -like "*chrome*"}')).toBe(true);
    expect(g('Get-Process | Where-Object {$_.Name -like "*sshd*"}')).toBe(false);
    expect(g('Get-Process')).toBe(false); // missing the filter
  });

  it('Stop-Process -Id 4521 -Force: order-independent, case-insensitive, fixed PID', () => {
    const g = byId('powershell-stop-process').grade;
    expect(g('Stop-Process -Id 4521 -Force')).toBe(true);
    expect(g('Stop-Process -Force -Id 4521')).toBe(true);
    expect(g('stop-process -id 4521 -force')).toBe(true);
    expect(g('Stop-Process -Id 9999 -Force')).toBe(false);
    expect(g('Stop-Process -Id 4521')).toBe(false); // missing -Force
  });
});
