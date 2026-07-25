import { describe, it, expect } from 'vitest';
import {
  runTerminalCommand,
  PROMPTS,
  ENV_FILES,
  ENV_PROCESSES,
  ENV_LISTENERS,
  ENV_SCHEDULED_TASKS,
  type ShellId,
} from '../src/data/terminalEnvironments';

function joined(shell: ShellId, input: string): string {
  return runTerminalCommand(shell, input).lines.join('\n');
}

describe('PROMPTS', () => {
  it('matches the fixed per-shell prompt strings exactly', () => {
    expect(PROMPTS.bash).toBe('analyst@wks01:~$ ');
    expect(PROMPTS.cmd).toBe('C:\\Users\\analyst>');
    expect(PROMPTS.powershell).toBe('PS C:\\Users\\analyst> ');
  });
});

describe('fixed environment facts', () => {
  it('has the exact notes.txt and auth.log content', () => {
    const notes = ENV_FILES.find((f) => f.name === 'notes.txt')!;
    const auth = ENV_FILES.find((f) => f.name === 'auth.log')!;
    expect(notes.content).toBe(
      'Case notes - host appears compromised.\nCheck auth.log for failed login attempts overnight.\nConfirm the PID of the rogue chrome process before killing it.\n',
    );
    expect(auth.content).toBe(
      'Jan 10 02:14:01 sshd[1122]: Accepted password for analyst from 10.0.0.5 port 51322 ssh2\n' +
        'Jan 10 02:31:47 sshd[1130]: Failed password for root from 185.220.101.7 port 40210 ssh2\n' +
        'Jan 10 02:31:52 sshd[1130]: Failed password for root from 185.220.101.7 port 40214 ssh2\n' +
        'Jan 10 02:32:10 sshd[1131]: Failed password for invalid user admin from 185.220.101.7 port 40391 ssh2\n' +
        'Jan 10 06:02:15 sshd[1190]: Accepted password for analyst from 10.0.0.5 port 51890 ssh2\n',
    );
  });

  it('has exactly 3 "Failed password" lines in auth.log', () => {
    const auth = ENV_FILES.find((f) => f.name === 'auth.log')!;
    const count = auth.content.split('\n').filter((l) => l.includes('Failed password')).length;
    expect(count).toBe(3);
  });

  it('has the fixed PIDs/process names', () => {
    expect(ENV_PROCESSES).toEqual([
      { pid: 812, bashName: 'sshd', windowsName: 'explorer.exe', role: 'benign' },
      { pid: 2044, bashName: 'cron', windowsName: 'svchost.exe', role: 'benign' },
      { pid: 4520, bashName: 'chrome', windowsName: 'chrome.exe', role: 'legitimate browser instance' },
      { pid: 4521, bashName: 'chrome', windowsName: 'chrome.exe', role: 'rogue/masquerading process' },
    ]);
  });

  it('has the fixed network listeners, including 4521 owning port 4444', () => {
    const listener4444 = ENV_LISTENERS.find((l) => l.localAddress === '0.0.0.0:4444');
    expect(listener4444?.pid).toBe(4521);
    expect(listener4444?.proto).toBe('tcp');
  });

  it('has the fixed scheduled tasks, including SystemHealthCheck', () => {
    const task = ENV_SCHEDULED_TASKS.find((t) => t.taskName === 'SystemHealthCheck');
    expect(task?.status).toBe('Ready');
    expect(task?.taskToRun).toBe('C:\\Users\\Public\\upd.exe');
  });
});

describe('bash track', () => {
  it('whoami prints the bare username', () => {
    expect(joined('bash', 'whoami')).toBe('analyst');
  });

  it('pwd prints an absolute path', () => {
    expect(joined('bash', 'pwd')).toMatch(/^\//);
  });

  it('ls -la lists both files with realistic long-format detail', () => {
    const out = joined('bash', 'ls -la');
    expect(out).toContain('notes.txt');
    expect(out).toContain('auth.log');
    expect(out).toMatch(/^d/m); // a directory entry (. or ..) rendered somewhere
  });

  it('bare ls (no flags) still lists filenames', () => {
    const out = joined('bash', 'ls');
    expect(out).toContain('notes.txt');
    expect(out).toContain('auth.log');
  });

  it('cat notes.txt prints the exact file content', () => {
    const out = joined('bash', 'cat notes.txt');
    expect(out).toBe(
      'Case notes - host appears compromised.\nCheck auth.log for failed login attempts overnight.\nConfirm the PID of the rogue chrome process before killing it.',
    );
  });

  it('cat on an unknown file returns a realistic error, not a crash', () => {
    const out = joined('bash', 'cat nope.txt');
    expect(out).toContain('No such file or directory');
  });

  it('grep "Failed password" auth.log returns exactly the 3 matching lines', () => {
    const result = runTerminalCommand('bash', 'grep "Failed password" auth.log');
    expect(result.lines).toHaveLength(3);
    for (const l of result.lines) expect(l).toContain('Failed password');
  });

  it('ps aux lists every fixed process by PID and name', () => {
    const out = joined('bash', 'ps aux');
    expect(out).toContain('812');
    expect(out).toContain('sshd');
    expect(out).toContain('2044');
    expect(out).toContain('cron');
    expect(out).toContain('4520');
    expect(out).toContain('4521');
    expect(out).toContain('chrome');
  });

  it('ps aux | grep chrome narrows the process list down to only the chrome rows', () => {
    const result = runTerminalCommand('bash', 'ps aux | grep chrome');
    expect(result.lines.length).toBeGreaterThan(0);
    for (const l of result.lines) expect(l).toContain('chrome');
    expect(result.lines.some((l) => l.includes('sshd'))).toBe(false);
    expect(result.lines.some((l) => l.includes('cron'))).toBe(false);
    expect(result.lines.join('\n')).toContain('4520');
    expect(result.lines.join('\n')).toContain('4521');
  });

  it('kill -9 4521 on the real PID is silent (no output) — real bash behavior', () => {
    const result = runTerminalCommand('bash', 'kill -9 4521');
    expect(result.lines).toEqual([]);
    expect(result.notFound).toBe(false);
  });

  it('kill -9 on a nonexistent PID reports an error', () => {
    const out = joined('bash', 'kill -9 9999');
    expect(out).toContain('No such process');
  });

  it('netstat -tulpn lists all 3 listeners including 4521 on port 4444', () => {
    const out = joined('bash', 'netstat -tulpn');
    expect(out).toContain('0.0.0.0:4444');
    expect(out).toContain('4521');
    expect(out).toContain('0.0.0.0:443');
    expect(out).toContain('812');
    expect(out).toContain('127.0.0.1:53');
    expect(out).toContain('2044');
  });

  it('netstat -tulpn | grep 4444 narrows to just the one listener owned by 4521', () => {
    const result = runTerminalCommand('bash', 'netstat -tulpn | grep 4444');
    expect(result.lines).toHaveLength(1);
    expect(result.lines[0]).toContain('4521');
    expect(result.lines[0]).not.toContain(':443');
  });
});

describe('cmd.exe track', () => {
  it('whoami prints the domain-qualified username', () => {
    expect(joined('cmd', 'whoami')).toBe('WKS01\\analyst');
  });

  it('dir lists both files with sizes and a directory header', () => {
    const out = joined('cmd', 'dir');
    expect(out).toContain('Directory of C:\\Users\\analyst');
    expect(out).toContain('notes.txt');
    expect(out).toContain('auth.log');
    expect(out).toContain('File(s)');
  });

  it('tasklist lists every fixed process by PID and Windows image name', () => {
    const out = joined('cmd', 'tasklist');
    expect(out).toContain('explorer.exe');
    expect(out).toContain('812');
    expect(out).toContain('svchost.exe');
    expect(out).toContain('2044');
    expect(out).toContain('chrome.exe');
    expect(out).toContain('4520');
    expect(out).toContain('4521');
  });

  it('tasklist | findstr chrome narrows down to only the chrome.exe rows', () => {
    const result = runTerminalCommand('cmd', 'tasklist | findstr chrome');
    expect(result.lines.length).toBeGreaterThan(0);
    for (const l of result.lines) expect(l).toContain('chrome');
    expect(result.lines.some((l) => l.includes('explorer'))).toBe(false);
    expect(result.lines.some((l) => l.includes('svchost'))).toBe(false);
    expect(result.lines.join('\n')).toContain('4520');
    expect(result.lines.join('\n')).toContain('4521');
  });

  it('findstr is case-sensitive by default (unlike bash grep leniency)', () => {
    const result = runTerminalCommand('cmd', 'tasklist | findstr CHROME');
    expect(result.lines).toEqual([]);
  });

  it('taskkill /PID 4521 /F reports success for the real PID', () => {
    const out = joined('cmd', 'taskkill /PID 4521 /F');
    expect(out).toContain('SUCCESS');
    expect(out).toContain('4521');
  });

  it('taskkill on a nonexistent PID reports an error', () => {
    const out = joined('cmd', 'taskkill /PID 9999 /F');
    expect(out).toContain('ERROR');
  });

  it('schtasks /query lists all 3 fixed tasks including the suspicious one', () => {
    const out = joined('cmd', 'schtasks /query');
    expect(out).toContain('GoogleUpdateTaskMachineCore');
    expect(out).toContain('\\Microsoft\\Windows\\Defrag\\ScheduledDefrag');
    expect(out).toContain('SystemHealthCheck');
    expect(out).toContain('C:\\Users\\Public\\upd.exe');
    expect(out).toContain('Ready');
  });
});

describe('PowerShell track', () => {
  it('whoami prints the lowercase domain-qualified username', () => {
    expect(joined('powershell', 'whoami')).toBe('wks01\\analyst');
  });

  it('Get-ChildItem lists both files with a Directory header', () => {
    const out = joined('powershell', 'Get-ChildItem');
    expect(out).toContain('Directory: C:\\Users\\analyst');
    expect(out).toContain('notes.txt');
    expect(out).toContain('auth.log');
  });

  it('real PowerShell aliases (dir, gci, ls) simulate identically to Get-ChildItem', () => {
    const canonical = joined('powershell', 'Get-ChildItem');
    expect(joined('powershell', 'dir')).toBe(canonical);
    expect(joined('powershell', 'gci')).toBe(canonical);
    expect(joined('powershell', 'ls')).toBe(canonical);
  });

  it('Get-Content notes.txt matches the exact notes.txt content', () => {
    const out = joined('powershell', 'Get-Content notes.txt');
    expect(out).toBe(
      'Case notes - host appears compromised.\nCheck auth.log for failed login attempts overnight.\nConfirm the PID of the rogue chrome process before killing it.',
    );
  });

  it('real aliases (gc, cat, type) simulate Get-Content identically', () => {
    const canonical = joined('powershell', 'Get-Content notes.txt');
    expect(joined('powershell', 'gc notes.txt')).toBe(canonical);
    expect(joined('powershell', 'cat notes.txt')).toBe(canonical);
    expect(joined('powershell', 'type notes.txt')).toBe(canonical);
  });

  it('Get-Process lists every fixed process by PID and PowerShell-style name (no .exe)', () => {
    const out = joined('powershell', 'Get-Process');
    expect(out).toContain('812');
    expect(out).toContain('explorer');
    expect(out).toContain('2044');
    expect(out).toContain('svchost');
    expect(out).toContain('4520');
    expect(out).toContain('4521');
    expect(out).toContain('chrome');
    expect(out).not.toContain('chrome.exe');
  });

  it('Get-Process | Where-Object {$_.Name -like "*chrome*"} narrows to only the chrome rows', () => {
    const result = runTerminalCommand('powershell', 'Get-Process | Where-Object {$_.Name -like "*chrome*"}');
    expect(result.lines.length).toBeGreaterThan(0);
    for (const l of result.lines) expect(l.toLowerCase()).toContain('chrome');
    expect(result.lines.some((l) => l.includes('explorer'))).toBe(false);
    expect(result.lines.some((l) => l.includes('svchost'))).toBe(false);
    expect(result.lines.join('\n')).toContain('4520');
    expect(result.lines.join('\n')).toContain('4521');
  });

  it('the ? and Where alias forms filter identically to Where-Object', () => {
    const canonical = joined('powershell', 'Get-Process | Where-Object {$_.Name -like "*chrome*"}');
    expect(joined('powershell', 'Get-Process | ? {$_.Name -like "*chrome*"}')).toBe(canonical);
    expect(joined('powershell', 'Get-Process | Where {$_.Name -like "*chrome*"}')).toBe(canonical);
  });

  it('-like matching is case-insensitive, matching real PowerShell semantics', () => {
    const out = joined('powershell', 'Get-Process | Where-Object {$_.Name -like "*CHROME*"}');
    expect(out.toLowerCase()).toContain('chrome');
  });

  it('Stop-Process -Id 4521 -Force on the real PID is silent — real PowerShell behavior without -PassThru', () => {
    const result = runTerminalCommand('powershell', 'Stop-Process -Id 4521 -Force');
    expect(result.lines).toEqual([]);
    expect(result.notFound).toBe(false);
  });

  it('Stop-Process on a nonexistent PID reports an error', () => {
    const out = joined('powershell', 'Stop-Process -Id 9999 -Force');
    expect(out).toContain('Cannot find a process');
  });
});

describe('command-not-found handling', () => {
  it('bash uses the real "command not found" phrasing', () => {
    const result = runTerminalCommand('bash', 'nosuchcommand');
    expect(result.notFound).toBe(true);
    expect(result.clear).toBe(false);
    expect(joined('bash', 'nosuchcommand')).toBe('bash: nosuchcommand: command not found');
  });

  it('cmd.exe uses the real "is not recognized" phrasing', () => {
    const result = runTerminalCommand('cmd', 'nosuchcommand');
    expect(result.notFound).toBe(true);
    expect(joined('cmd', 'nosuchcommand')).toContain("'nosuchcommand' is not recognized as an internal or external command");
    expect(joined('cmd', 'nosuchcommand')).toContain('operable program or batch file.');
  });

  it('PowerShell uses the real "term is not recognized" phrasing', () => {
    const result = runTerminalCommand('powershell', 'nosuchcommand');
    expect(result.notFound).toBe(true);
    expect(joined('powershell', 'nosuchcommand')).toContain(
      "The term 'nosuchcommand' is not recognized as the name of a cmdlet, function, script file, or operable program.",
    );
  });

  it('an unresolvable filter stage after a pipe is also reported as not found', () => {
    const result = runTerminalCommand('bash', 'ps aux | nosuchfilter chrome');
    expect(result.notFound).toBe(true);
  });
});

describe('help systems', () => {
  it('bash: `help` lists commands including ls and grep', () => {
    const out = joined('bash', 'help');
    expect(out).toContain('ls');
    expect(out).toContain('grep');
  });

  it('bash: `man ls` gives detailed help matching the ls-la explanation', () => {
    const out = joined('bash', 'man ls');
    expect(out).toContain('SYNOPSIS');
    expect(out).toContain('DESCRIPTION');
    expect(out).toContain('short flags like these combine in any order');
  });

  it('bash: `grep --help` gives the same detail as `man grep`', () => {
    const manOut = joined('bash', 'man grep');
    const flagOut = joined('bash', 'grep --help');
    expect(flagOut).toBe(manOut);
    expect(flagOut).toContain('multi-word pattern needs quotes');
  });

  it('bash: `man` on an unknown command reports no manual entry', () => {
    expect(joined('bash', 'man bogus')).toContain('No manual entry for bogus');
  });

  it('cmd: `help` lists commands including DIR and TASKLIST', () => {
    const out = joined('cmd', 'help');
    expect(out).toContain('DIR');
    expect(out).toContain('TASKLIST');
  });

  it('cmd: `dir /?` gives detailed help about dir', () => {
    const out = joined('cmd', 'dir /?');
    expect(out).toContain("Windows counterpart to ls");
  });

  it('cmd: `schtasks /?` gives detailed help about schtasks', () => {
    const out = joined('cmd', 'schtasks /?');
    expect(out.toLowerCase()).toContain('persistence');
  });

  it('PowerShell: bare `Get-Help` lists cmdlets including Get-ChildItem and Stop-Process', () => {
    const out = joined('powershell', 'Get-Help');
    expect(out).toContain('Get-ChildItem');
    expect(out).toContain('Stop-Process');
  });

  it('PowerShell: `Get-Help Stop-Process` gives detailed help', () => {
    const out = joined('powershell', 'Get-Help Stop-Process');
    expect(out).toContain('SYNOPSIS');
    expect(out).toContain('-Force skips the confirmation prompt');
  });

  it('PowerShell: `Get-Help` on an unknown cmdlet reports no match', () => {
    expect(joined('powershell', 'Get-Help Bogus-Verb')).toContain('No help matches the search criteria');
  });
});

describe('clear-screen signal', () => {
  it('bash: `clear` signals clear with no output lines', () => {
    const result = runTerminalCommand('bash', 'clear');
    expect(result.clear).toBe(true);
    expect(result.lines).toEqual([]);
    expect(result.notFound).toBe(false);
  });

  it('bash: `cls` is NOT recognized (that is the Windows spelling)', () => {
    const result = runTerminalCommand('bash', 'cls');
    expect(result.clear).toBe(false);
    expect(result.notFound).toBe(true);
  });

  it('cmd.exe: `cls` signals clear', () => {
    const result = runTerminalCommand('cmd', 'cls');
    expect(result.clear).toBe(true);
    expect(result.lines).toEqual([]);
  });

  it('cmd.exe: `clear` is NOT recognized (that is the Unix spelling)', () => {
    const result = runTerminalCommand('cmd', 'clear');
    expect(result.clear).toBe(false);
    expect(result.notFound).toBe(true);
  });

  it('PowerShell: both `clear` and `cls` signal clear (both are real aliases)', () => {
    expect(runTerminalCommand('powershell', 'clear').clear).toBe(true);
    expect(runTerminalCommand('powershell', 'cls').clear).toBe(true);
  });
});

describe('misc robustness', () => {
  it('empty input produces no output and no error', () => {
    const result = runTerminalCommand('bash', '   ');
    expect(result.lines).toEqual([]);
    expect(result.notFound).toBe(false);
    expect(result.clear).toBe(false);
  });

  it('is whitespace/case tolerant on the base command name', () => {
    expect(joined('bash', '  whoami  ')).toBe('analyst');
    expect(runTerminalCommand('cmd', 'DIR').notFound).toBe(false);
  });

  it('a stray trailing pipe does not throw', () => {
    expect(() => runTerminalCommand('bash', 'ps aux |')).not.toThrow();
  });
});
