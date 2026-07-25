// Pure, dependency-free simulation of a tiny fake Linux/Windows host, used by
// the three interactive terminal drills at /drills/commands/{bash,cmd,powershell}/.
// Nothing here touches the DOM — src/scripts/terminalDrill.ts is the client
// layer that feeds keystrokes in and renders `TerminalCommandResult.lines`
// out. This file owns the "world": which files/processes/listeners/scheduled
// tasks exist, and a per-shell registry of realistically-formatted command
// output for interacting with that world (including a working help system),
// so a learner can explore the fake host freely, not just recall one exact
// answer string per challenge (that's what src/data/drills/terminalChallenges.ts
// grades separately, against the raw text typed — this file never grades
// anything, it only simulates).
//
// The underlying facts (PIDs, filenames, ports, task names) are FIXED and
// identical across all three shells — only the OUTPUT FORMATTING differs,
// matching each real shell's own genuine conventions (ls -la vs dir vs
// Get-ChildItem, etc.). Every simulated command is a pure function of its
// input tokens plus the constant environment data below, so this whole file
// is trivially unit-testable without a browser (see test/terminalEnvironments.test.ts).

export type ShellId = 'bash' | 'cmd' | 'powershell';

/** Exact prompt string this shell renders before the cursor, per the fixed scenario. */
export const PROMPTS: Record<ShellId, string> = {
  bash: 'analyst@wks01:~$ ',
  cmd: 'C:\\Users\\analyst>',
  powershell: 'PS C:\\Users\\analyst> ',
};

export const SHELL_DISPLAY_NAMES: Record<ShellId, string> = {
  bash: 'bash',
  cmd: 'cmd.exe',
  powershell: 'PowerShell',
};

// ── The fixed world ─────────────────────────────────────────────────────

export interface EnvFile {
  name: string;
  content: string;
  /** ls -la style timestamp, e.g. "Jan 10 06:12". */
  mtimeUnix: string;
  /** dir / Get-ChildItem style timestamp, e.g. "01/10/2026  06:12 AM". */
  mtimeWindows: string;
}

export const ENV_FILES: EnvFile[] = [
  {
    name: 'auth.log',
    content:
      'Jan 10 02:14:01 sshd[1122]: Accepted password for analyst from 10.0.0.5 port 51322 ssh2\n' +
      'Jan 10 02:31:47 sshd[1130]: Failed password for root from 185.220.101.7 port 40210 ssh2\n' +
      'Jan 10 02:31:52 sshd[1130]: Failed password for root from 185.220.101.7 port 40214 ssh2\n' +
      'Jan 10 02:32:10 sshd[1131]: Failed password for invalid user admin from 185.220.101.7 port 40391 ssh2\n' +
      'Jan 10 06:02:15 sshd[1190]: Accepted password for analyst from 10.0.0.5 port 51890 ssh2\n',
    mtimeUnix: 'Jan 10 06:02',
    mtimeWindows: '01/10/2026  06:02 AM',
  },
  {
    name: 'notes.txt',
    content:
      'Case notes - host appears compromised.\n' +
      'Check auth.log for failed login attempts overnight.\n' +
      'Confirm the PID of the rogue chrome process before killing it.\n',
    mtimeUnix: 'Jan 10 06:12',
    mtimeWindows: '01/10/2026  06:12 AM',
  },
];

export interface EnvProcess {
  pid: number;
  /** Process image name as it appears in a bash environment (ps/kill). */
  bashName: string;
  /** Process image name as it appears in cmd.exe/PowerShell (tasklist/Get-Process). */
  windowsName: string;
  role: string;
}

export const ENV_PROCESSES: EnvProcess[] = [
  { pid: 812, bashName: 'sshd', windowsName: 'explorer.exe', role: 'benign' },
  { pid: 2044, bashName: 'cron', windowsName: 'svchost.exe', role: 'benign' },
  { pid: 4520, bashName: 'chrome', windowsName: 'chrome.exe', role: 'legitimate browser instance' },
  { pid: 4521, bashName: 'chrome', windowsName: 'chrome.exe', role: 'rogue/masquerading process' },
];

export interface EnvListener {
  proto: 'tcp' | 'udp';
  localAddress: string;
  pid: number;
}

// bash-only in the curriculum (no netstat-equivalent challenge on the
// Windows tracks), but the data lives here regardless of which shells
// currently query it.
export const ENV_LISTENERS: EnvListener[] = [
  { proto: 'tcp', localAddress: '0.0.0.0:4444', pid: 4521 },
  { proto: 'tcp', localAddress: '0.0.0.0:443', pid: 812 },
  { proto: 'udp', localAddress: '127.0.0.1:53', pid: 2044 },
];

export interface EnvScheduledTask {
  taskName: string;
  status: string;
  taskToRun: string;
}

// cmd-only in the curriculum (this challenge is cmd.exe-specific).
export const ENV_SCHEDULED_TASKS: EnvScheduledTask[] = [
  {
    taskName: 'GoogleUpdateTaskMachineCore',
    status: 'Ready',
    taskToRun: '"C:\\Program Files\\Google\\Update\\GoogleUpdate.exe" /c',
  },
  {
    taskName: '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag',
    status: 'Ready',
    taskToRun: '%windir%\\system32\\defrag.exe -c',
  },
  { taskName: 'SystemHealthCheck', status: 'Ready', taskToRun: 'C:\\Users\\Public\\upd.exe' },
];

const WHOAMI_OUTPUT: Record<ShellId, string> = {
  bash: 'analyst',
  cmd: 'WKS01\\analyst',
  powershell: 'wks01\\analyst',
};

const PWD_OUTPUT_BASH = '/home/analyst';

// ── Tokenizing a typed command line ─────────────────────────────────────

// Splits on whitespace, but: (1) single/double-quoted spans become one
// token with the quote characters stripped (so `grep "Failed password"
// auth.log` yields the pattern as ONE token), and (2) a `{...}` span (a
// PowerShell script block, e.g. Where-Object's filter) is kept as one
// literal token, quotes and all, so its own -like pattern can be pulled out
// later — braces take priority over quote-handling so a quote inside a
// block is never treated as opening/closing a token-level quote. A bare `|`
// outside any quote/brace is emitted as its own token so callers can split
// the pipeline on it.
function tokenize(input: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let hasCurrent = false;
  let quote: string | null = null;
  let braceDepth = 0;

  const flush = () => {
    if (hasCurrent) {
      tokens.push(current);
      current = '';
      hasCurrent = false;
    }
  };

  for (const ch of input) {
    if (braceDepth > 0) {
      if (ch === '{') braceDepth++;
      else if (ch === '}') braceDepth--;
      current += ch;
      hasCurrent = true;
      continue;
    }
    if (quote) {
      if (ch === quote) quote = null;
      else current += ch;
      hasCurrent = true;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      hasCurrent = true;
      continue;
    }
    if (ch === '{') {
      braceDepth = 1;
      current += ch;
      hasCurrent = true;
      continue;
    }
    if (ch === '|') {
      flush();
      tokens.push('|');
      continue;
    }
    if (/\s/.test(ch)) {
      flush();
      continue;
    }
    current += ch;
    hasCurrent = true;
  }
  flush();
  return tokens;
}

/** Splits a token stream into pipeline stages on bare `|` tokens, dropping any empty stage (a stray/trailing pipe). */
function splitPipeline(tokens: string[]): string[][] {
  const stages: string[][] = [[]];
  for (const t of tokens) {
    if (t === '|') stages.push([]);
    else stages[stages.length - 1].push(t);
  }
  return stages.filter((s) => s.length > 0);
}

/** Splits a string on '\n', dropping one trailing empty element from a final newline (so a 3-line file with a trailing \n yields exactly 3 lines, not 4). */
function linesOf(content: string): string[] {
  const parts = content.split('\n');
  if (parts.length > 0 && parts[parts.length - 1] === '') parts.pop();
  return parts;
}

function findFile(name: string | undefined, caseSensitive: boolean): EnvFile | undefined {
  if (!name) return undefined;
  return caseSensitive
    ? ENV_FILES.find((f) => f.name === name)
    : ENV_FILES.find((f) => f.name.toLowerCase() === name.toLowerCase());
}

function containsPattern(line: string, pattern: string, caseSensitive: boolean): boolean {
  if (!pattern) return true;
  return caseSensitive ? line.includes(pattern) : line.toLowerCase().includes(pattern.toLowerCase());
}

// ── Command registry ─────────────────────────────────────────────────────

interface RunContext {
  /** null on the first (leftmost) pipeline stage; the previous stage's output lines on every later stage. */
  pipedLines: string[] | null;
}

interface CommandDef {
  /** Canonical, properly-cased name shown in help output (e.g. "Get-ChildItem"). */
  displayName: string;
  /** Every recognized invocation, lowercase — must include displayName.toLowerCase(). */
  names: string[];
  /** One-line syntax example, shown in both the summary list and the detail view. */
  usage: string;
  /** One-line description, shown next to the name in a bare `help`/`Get-Help` listing. */
  summary: string;
  /** Longer explanation, shown in `man`/`--help`/`/?`/`Get-Help <name>` detail view — lifted verbatim from the matching src/data/drills/terminalChallenges.ts entry's explanation. */
  detail: string;
  /** Optional short tip appended to the detail view — lifted from the matching challenge's hint. */
  hint?: string;
  run: (args: string[], ctx: RunContext) => string[];
}

// ── bash ──

function lsRunBash(args: string[]): string[] {
  const flagChars = args
    .filter((a) => a.startsWith('-'))
    .join('')
    .replace(/-/g, '')
    .toLowerCase();
  const long = flagChars.includes('l');
  if (!long) return [ENV_FILES.map((f) => f.name).join('  ')];
  const lines = ['total 8', 'drwxr-xr-x  2 analyst analyst 4096 Jan 10 06:15 .', 'drwxr-xr-x  3 root    root    4096 Jan  9 22:00 ..'];
  for (const f of ENV_FILES) {
    lines.push(`-rw-r--r--  1 analyst analyst ${String(f.content.length).padStart(5)} ${f.mtimeUnix} ${f.name}`);
  }
  return lines;
}

function catRunBash(args: string[]): string[] {
  const file = findFile(args[0], true);
  if (!file) return [`cat: ${args[0] ?? ''}: No such file or directory`];
  return linesOf(file.content);
}

function grepRun(args: string[], ctx: RunContext, caseSensitive: boolean): string[] {
  if (ctx.pipedLines) {
    const pattern = args[0] ?? '';
    return ctx.pipedLines.filter((l) => containsPattern(l, pattern, caseSensitive));
  }
  if (args.length < 2) return ['Usage: grep [PATTERN] [FILE]'];
  const filename = args[args.length - 1];
  const pattern = args.slice(0, -1).join(' ');
  const file = findFile(filename, caseSensitive);
  if (!file) return [`grep: ${filename}: No such file or directory`];
  return linesOf(file.content).filter((l) => containsPattern(l, pattern, caseSensitive));
}

function psOutputBash(): string[] {
  const lines = ['USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND'];
  for (const p of ENV_PROCESSES) {
    lines.push(`analyst   ${String(p.pid).padStart(5)}  0.0  0.1  12345  2345 ?        Ss   06:00   0:00 ${p.bashName}`);
  }
  return lines;
}

function killRunBash(args: string[]): string[] {
  const pidTok = args.find((a) => /^\d+$/.test(a));
  const pid = pidTok ? Number(pidTok) : NaN;
  const exists = ENV_PROCESSES.some((p) => p.pid === pid);
  // Real `kill` on a valid, permitted PID is silent — this simulation is
  // stateless (killing 4521 doesn't remove it from a later `ps aux`), which
  // matches this environment's own "fixed facts, freely explorable" design.
  if (!exists) return [`bash: kill: (${pidTok ?? '?'}) - No such process`];
  return [];
}

function netstatOutputBash(): string[] {
  const header = 'Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name';
  const rows = ENV_LISTENERS.map((l) => {
    const owner = ENV_PROCESSES.find((p) => p.pid === l.pid);
    const state = l.proto === 'tcp' ? 'LISTEN' : '-';
    return `${l.proto.padEnd(6)} 0      0 ${l.localAddress.padEnd(24)}0.0.0.0:*               ${state.padEnd(11)} ${l.pid}/${owner ? owner.bashName : '?'}`;
  });
  return [header, ...rows];
}

const BASH_COMMANDS: CommandDef[] = [
  {
    displayName: 'whoami',
    names: ['whoami'],
    usage: 'whoami',
    summary: 'Show the current username',
    detail:
      'whoami is one of the rare commands with the exact same name everywhere — though the output differs: Windows shows DOMAIN\\username, bash shows just the username.',
    hint: 'Same word, every shell.',
    run: () => [WHOAMI_OUTPUT.bash],
  },
  {
    displayName: 'pwd',
    names: ['pwd'],
    usage: 'pwd',
    summary: 'Print the current working directory',
    detail: "pwd prints the shell's current working directory as an absolute path — the most basic orientation command in any Unix shell.",
    hint: 'Three letters, no flags.',
    run: () => [PWD_OUTPUT_BASH],
  },
  {
    displayName: 'ls',
    names: ['ls'],
    usage: 'ls [-la]',
    summary: 'List directory contents',
    detail: '-a shows hidden files, -l shows details — short flags like these combine in any order: -la, -al, or separately.',
    hint: '-a for hidden, -l for long — combine them.',
    run: (args) => lsRunBash(args),
  },
  {
    displayName: 'cat',
    names: ['cat'],
    usage: 'cat <file>',
    summary: "Print a file's contents",
    detail: 'cat dumps a file straight to stdout — the fastest way to read a small file.',
    hint: "Short for 'concatenate'.",
    run: (args) => catRunBash(args),
  },
  {
    displayName: 'grep',
    names: ['grep'],
    usage: 'grep "<pattern>" <file>   (or  <command> | grep <pattern>)',
    summary: 'Search text for a pattern',
    detail: 'grep searches file contents for a pattern — a multi-word pattern needs quotes so the shell treats it as one argument.',
    hint: 'grep "pattern" file — quotes matter here.',
    run: (args, ctx) => grepRun(args, ctx, true),
  },
  {
    displayName: 'ps',
    names: ['ps'],
    usage: 'ps aux   (or  ps aux | grep <term>)',
    summary: 'List running processes',
    detail: 'ps aux lists every process for every user; piping into grep chrome filters it down. The pipe (|) feeds one command straight into the next.',
    hint: 'ps aux lists everything; pipe into grep to narrow it.',
    run: () => psOutputBash(),
  },
  {
    displayName: 'kill',
    names: ['kill'],
    usage: 'kill -9 <pid>',
    summary: 'Terminate a process by PID',
    detail: "-9 sends SIGKILL — a signal the process can't catch, block, or ignore, so it dies immediately.",
    hint: 'Signal number 9 = SIGKILL, no mercy.',
    run: (args) => killRunBash(args),
  },
  {
    displayName: 'netstat',
    names: ['netstat'],
    usage: 'netstat -tulpn   (or  netstat -tulpn | grep <port>)',
    summary: 'List listening network ports and their owning process',
    detail:
      'netstat -tulpn shows every listening socket and which process owns it — a standard first move to spot an unexpected listener. Linux-specific: macOS netstat has no process/PID flag at all.',
    hint: 't=TCP, u=UDP, l=listening, p=process, n=numeric — any order works.',
    run: () => netstatOutputBash(),
  },
];

// ── cmd.exe ──

function dirOutputCmd(): string[] {
  const dirMtime = ENV_FILES[0].mtimeWindows;
  const lines = [
    ' Volume in drive C has no label.',
    ' Volume Serial Number is 1A2B-3C4D',
    '',
    ' Directory of C:\\Users\\analyst',
    '',
    `${dirMtime}    <DIR>          .`,
    `${dirMtime}    <DIR>          ..`,
  ];
  let totalBytes = 0;
  for (const f of ENV_FILES) {
    totalBytes += f.content.length;
    lines.push(`${f.mtimeWindows}    ${String(f.content.length).padStart(15)} ${f.name}`);
  }
  lines.push(`               ${ENV_FILES.length} File(s)  ${totalBytes} bytes`);
  lines.push('               2 Dir(s)  10,000,000,000 bytes free');
  return lines;
}

function tasklistOutputCmd(): string[] {
  const header = 'Image Name                     PID Session Name        Session#    Mem Usage';
  const sep = '========================= ======== ================ =========== ============';
  const rows = ENV_PROCESSES.map(
    (p) => `${p.windowsName.padEnd(25)} ${String(p.pid).padStart(8)} Console                    1     45,120 K`,
  );
  return [header, sep, ...rows];
}

function findstrRun(args: string[], ctx: RunContext): string[] {
  // findstr is case-sensitive by default (unlike grep's own default, which
  // also happens to be case-sensitive here — but findstr has NO -i-style
  // leniency without an explicit /I switch, and this environment doesn't
  // model /I).
  if (ctx.pipedLines) {
    const pattern = args[0] ?? '';
    return ctx.pipedLines.filter((l) => containsPattern(l, pattern, true));
  }
  if (args.length < 2) return ['FINDSTR: Search string not found'];
  const filename = args[args.length - 1];
  const pattern = args.slice(0, -1).join(' ');
  const file = findFile(filename, false);
  if (!file) return [`FINDSTR: Cannot open ${filename}`];
  return linesOf(file.content).filter((l) => containsPattern(l, pattern, true));
}

function taskkillRunCmd(args: string[]): string[] {
  const pidTok = args.find((a) => /^\d+$/.test(a));
  const pid = pidTok ? Number(pidTok) : NaN;
  const exists = ENV_PROCESSES.some((p) => p.pid === pid);
  if (!exists) return [`ERROR: The process "${pidTok ?? '?'}" not found.`];
  return [`SUCCESS: The process with PID ${pid} has been terminated.`];
}

function schtasksOutputCmd(): string[] {
  const nameWidth = Math.max(...ENV_SCHEDULED_TASKS.map((t) => t.taskName.length)) + 2;
  const statusWidth = 15;
  const header = `${'TaskName'.padEnd(nameWidth)}${'Status'.padEnd(statusWidth)}Task To Run`;
  const sep = `${'='.repeat(nameWidth - 1)} ${'='.repeat(statusWidth - 1)} ${'='.repeat(45)}`;
  const rows = ENV_SCHEDULED_TASKS.map((t) => `${t.taskName.padEnd(nameWidth)}${t.status.padEnd(statusWidth)}${t.taskToRun}`);
  return [header, sep, ...rows];
}

const CMD_COMMANDS: CommandDef[] = [
  {
    displayName: 'whoami',
    names: ['whoami'],
    usage: 'whoami',
    summary: 'Show the current username',
    detail:
      'whoami is one of the rare commands with the exact same name everywhere — though the output differs: Windows shows DOMAIN\\username, bash shows just the username.',
    hint: 'Same word, every shell.',
    run: () => [WHOAMI_OUTPUT.cmd],
  },
  {
    displayName: 'dir',
    names: ['dir'],
    usage: 'dir',
    summary: 'List the files and folders in the current directory',
    detail: "dir is cmd.exe's native directory-listing command — the Windows counterpart to ls.",
    hint: 'Same idea as ls, different name.',
    run: () => dirOutputCmd(),
  },
  {
    displayName: 'tasklist',
    names: ['tasklist'],
    usage: 'tasklist   (or  tasklist | findstr <term>)',
    summary: 'List running processes',
    detail:
      'tasklist enumerates every process; piping into findstr narrows it down — the same idea as ps | grep on Unix. Note: findstr is case-sensitive by default.',
    hint: 'tasklist | findstr <term>.',
    run: () => tasklistOutputCmd(),
  },
  {
    displayName: 'findstr',
    names: ['findstr'],
    usage: 'findstr <pattern> [<file>]   (or  <command> | findstr <pattern>)',
    summary: 'Search text for a pattern (case-sensitive)',
    detail: 'findstr searches text for a pattern — commonly used to filter piped output, the Windows counterpart to grep.',
    hint: 'Case-sensitive by default — no /I switch modeled here.',
    run: (args, ctx) => findstrRun(args, ctx),
  },
  {
    displayName: 'taskkill',
    names: ['taskkill'],
    usage: 'taskkill /PID <pid> /F',
    summary: 'Forcibly terminate a process by PID',
    detail: '/PID targets the process by its numeric ID; /F forces termination without prompting. The two flags can appear in either order.',
    hint: "/PID <id> /F — order doesn't matter.",
    run: (args) => taskkillRunCmd(args),
  },
  {
    displayName: 'schtasks',
    names: ['schtasks'],
    usage: 'schtasks /query',
    summary: 'List every scheduled task on the system',
    detail: 'schtasks /query lists every scheduled task — attackers commonly abuse Scheduled Tasks for persistence, making this a standard triage command.',
    hint: "Windows' native task-scheduler CLI, queried.",
    run: () => schtasksOutputCmd(),
  },
];

// ── PowerShell ──

function gciOutputPS(): string[] {
  const lines = ['', '    Directory: C:\\Users\\analyst', '', 'Mode                 LastWriteTime         Length Name', '----                 -------------         ------ ----'];
  for (const f of ENV_FILES) {
    lines.push(`-a----         ${f.mtimeWindows.padEnd(21)}${String(f.content.length).padStart(7)} ${f.name}`);
  }
  return lines;
}

function gcRunPS(args: string[]): string[] {
  const file = findFile(args[0], false);
  if (!file) return [`Get-Content : Cannot find path 'C:\\Users\\analyst\\${args[0] ?? ''}' because it does not exist.`];
  return linesOf(file.content);
}

function gpOutputPS(): string[] {
  const lines = [' Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName', ' -------  ------    -----      -----     ------     --  -- -----------'];
  for (const p of ENV_PROCESSES) {
    const name = p.windowsName.replace(/\.exe$/i, '');
    lines.push(`     ${String(300 + (p.pid % 100)).padStart(3)}      ${String(10 + (p.pid % 20)).padStart(2)}    ${String(20000 + p.pid).padStart(5)}    ${String(30000 + p.pid).padStart(6)}       1.25   ${String(p.pid).padStart(4)}   1 ${name}`);
  }
  return lines;
}

function whereObjectRun(args: string[], ctx: RunContext): string[] {
  if (!ctx.pipedLines) return [];
  const raw = args.join(' ');
  // Extracts the bare pattern out of a `-like "*chrome*"` / `-like '*chrome*'`
  // style filter regardless of quote style — the two asterisks are the only
  // thing we rely on, so this reads any of grade()'s accepted quote variants.
  const m = raw.match(/\*([^*"']+)\*/);
  const pattern = m ? m[1] : '';
  // -like is case-insensitive by default in real PowerShell — a deliberate
  // simplification vs. real Where-Object: this filters the already-formatted
  // TEXT lines from the previous stage (a header/separator row naturally
  // drops out since it never contains the pattern), rather than filtering
  // live objects and re-running the table formatter, which would be needed
  // for a byte-perfect reproduction of a freshly-headered table.
  return ctx.pipedLines.filter((l) => containsPattern(l, pattern, false));
}

function stopProcessRunPS(args: string[]): string[] {
  const idx = args.findIndex((a) => a.toLowerCase() === '-id');
  const pidTok = idx >= 0 ? args[idx + 1] : args.find((a) => /^\d+$/.test(a));
  const pid = pidTok ? Number(pidTok) : NaN;
  const exists = ENV_PROCESSES.some((p) => p.pid === pid);
  if (!exists) return [`Stop-Process : Cannot find a process with the process identifier ${Number.isNaN(pid) ? '' : pid}.`];
  // Real Stop-Process is silent on success unless -PassThru is given.
  return [];
}

const POWERSHELL_COMMANDS: CommandDef[] = [
  {
    displayName: 'whoami',
    names: ['whoami'],
    usage: 'whoami',
    summary: 'Show the current username',
    detail:
      'whoami is one of the rare commands with the exact same name everywhere — though the output differs: Windows shows DOMAIN\\username, bash shows just the username.',
    hint: 'Same word, every shell.',
    run: () => [WHOAMI_OUTPUT.powershell],
  },
  {
    displayName: 'Get-ChildItem',
    names: ['get-childitem', 'dir', 'gci', 'ls'],
    usage: 'Get-ChildItem [-Path <path>]',
    summary: 'List the files and folders in the current directory',
    detail: 'Get-ChildItem is the real cmdlet; dir, gci, and (on Windows) ls are all built-in aliases for it.',
    hint: 'PowerShell cmdlets follow a Verb-Noun pattern.',
    run: () => gciOutputPS(),
  },
  {
    displayName: 'Get-Content',
    names: ['get-content', 'gc', 'cat', 'type'],
    usage: 'Get-Content <path>',
    summary: "Print a file's contents",
    detail: 'Get-Content is the real cmdlet; gc and cat/type are built-in aliases for it — the same alias pattern as Get-ChildItem.',
    hint: 'Same verb-noun pattern as the last PowerShell answer.',
    run: (args) => gcRunPS(args),
  },
  {
    displayName: 'Get-Process',
    names: ['get-process'],
    usage: 'Get-Process   (or  Get-Process | Where-Object {$_.Name -like "*pattern*"})',
    summary: 'List running processes',
    detail: 'Get-Process lists every running process on the system — the PowerShell object-pipeline counterpart to ps (bash) or tasklist (cmd.exe).',
    hint: 'Get-Process on its own lists everything; pipe into Where-Object to narrow it.',
    run: () => gpOutputPS(),
  },
  {
    displayName: 'Where-Object',
    names: ['where-object', 'where', '?'],
    usage: '<cmdlet> | Where-Object {$_.Property -like "*pattern*"}',
    summary: 'Filter objects in the pipeline',
    detail:
      'Where-Object filters a stream of OBJECTS, not text lines — $_ is the current object, -like does wildcard matching. This is the key difference from bash/cmd pipes, which only ever pass plain text.',
    hint: 'Get-Process | Where-Object {$_.Name -like "*pattern*"}.',
    run: (args, ctx) => whereObjectRun(args, ctx),
  },
  {
    displayName: 'Stop-Process',
    names: ['stop-process'],
    usage: 'Stop-Process -Id <id> -Force',
    summary: 'Forcibly terminate a process by ID',
    detail: "-Id targets the process by its numeric ID; -Force skips the confirmation prompt Stop-Process shows for processes you don't own.",
    hint: 'Stop-Process -Id <id> -Force.',
    run: (args) => stopProcessRunPS(args),
  },
];

const REGISTRIES: Record<ShellId, CommandDef[]> = {
  bash: BASH_COMMANDS,
  cmd: CMD_COMMANDS,
  powershell: POWERSHELL_COMMANDS,
};

function buildMap(defs: CommandDef[]): Map<string, CommandDef> {
  const map = new Map<string, CommandDef>();
  for (const def of defs) {
    for (const n of def.names) map.set(n.toLowerCase(), def);
  }
  return map;
}

const MAPS: Record<ShellId, Map<string, CommandDef>> = {
  bash: buildMap(BASH_COMMANDS),
  cmd: buildMap(CMD_COMMANDS),
  powershell: buildMap(POWERSHELL_COMMANDS),
};

// ── Help system ──────────────────────────────────────────────────────────

function detailHelpLines(shell: ShellId, def: CommandDef): string[] {
  const tip = def.hint ? [`TIP: ${def.hint}`] : [];
  if (shell === 'cmd') {
    return [def.detail, '', def.usage, ...(tip.length ? ['', ...tip] : [])];
  }
  return [
    'NAME',
    shell === 'bash' ? `    ${def.displayName} - ${def.summary}` : `    ${def.displayName}`,
    '',
    'SYNOPSIS',
    `    ${def.usage}`,
    '',
    'DESCRIPTION',
    `    ${def.detail}`,
    ...(tip.length ? ['', ...tip] : []),
  ];
}

function listHelpLines(shell: ShellId): string[] {
  const defs = REGISTRIES[shell];
  if (shell === 'bash') {
    const lines = ['Available commands in this simulated shell:'];
    for (const d of defs) lines.push(`  ${d.displayName.padEnd(10)} ${d.summary}`);
    lines.push(`  ${'clear'.padEnd(10)} Clear the terminal screen`);
    lines.push('');
    lines.push('Type "man <command>" or "<command> --help" for details.');
    return lines;
  }
  if (shell === 'cmd') {
    const lines: string[] = [];
    for (const d of defs) lines.push(`${d.displayName.toUpperCase().padEnd(12)}${d.summary}.`);
    lines.push(`${'CLS'.padEnd(12)}Clears the screen.`);
    lines.push('');
    lines.push('For more information on a specific command, type command-name /?');
    return lines;
  }
  const lines = ['Name                Synopsis', '----                --------'];
  for (const d of defs) lines.push(`${d.displayName.padEnd(20)}${d.usage}`);
  lines.push('');
  lines.push('Type "Get-Help <cmdlet-name>" for more information.');
  return lines;
}

function tryMetaHelp(shell: ShellId, tokens: string[]): string[] | null {
  const name = tokens[0].toLowerCase();
  if (shell === 'bash') {
    if (name === 'help') return listHelpLines('bash');
    if (name === 'man') {
      const target = tokens[1];
      if (!target) return ['What manual page do you want?'];
      const def = MAPS.bash.get(target.toLowerCase());
      return def ? detailHelpLines('bash', def) : [`No manual entry for ${target}`];
    }
    return null;
  }
  if (shell === 'cmd') {
    if (name === 'help') {
      const target = tokens[1];
      if (!target) return listHelpLines('cmd');
      const def = MAPS.cmd.get(target.toLowerCase());
      return def ? detailHelpLines('cmd', def) : ['This command is not supported by the help utility.'];
    }
    return null;
  }
  if (name === 'get-help') {
    const target = tokens[1];
    if (!target) return listHelpLines('powershell');
    const def = MAPS.powershell.get(target.toLowerCase());
    return def ? detailHelpLines('powershell', def) : ['Get-Help : No help matches the search criteria.'];
  }
  return null;
}

function hasInlineHelpFlag(shell: ShellId, args: string[]): boolean {
  if (shell === 'bash') return args.some((a) => a.toLowerCase() === '--help');
  if (shell === 'cmd') return args.some((a) => a === '/?');
  return false;
}

function isClearCommand(shell: ShellId, name: string): boolean {
  if (shell === 'bash') return name === 'clear';
  if (shell === 'cmd') return name === 'cls';
  return name === 'clear' || name === 'cls';
}

function commandNotFoundMessage(shell: ShellId, name: string): string[] {
  if (shell === 'bash') return [`bash: ${name}: command not found`];
  if (shell === 'cmd') return [`'${name}' is not recognized as an internal or external command,`, 'operable program or batch file.'];
  return [
    `${name}: The term '${name}' is not recognized as the name of a cmdlet, function, script file, or operable program.`,
    'Check the spelling of the name, or if a path was included, verify that the path is correct and try again.',
  ];
}

// ── Public entry point ───────────────────────────────────────────────────

export interface TerminalCommandResult {
  /** Output lines to append to the scrollback, in order. Empty = a real, silent success (e.g. bash `kill` or PowerShell `Stop-Process`). */
  lines: string[];
  /** True when the typed command wasn't recognized in this shell — `lines` already holds that shell's own "not found" message. */
  notFound: boolean;
  /** True for clear/cls — the UI should wipe the scrollback; `lines` is always empty alongside this. */
  clear: boolean;
}

/**
 * Simulates running one line of input in the given shell against the fixed
 * environment above. Pure function of (shell, input) — no state is carried
 * between calls, so the same input always produces the same result (the
 * environment is a fixed scenario, not a mutable filesystem/process table).
 */
export function runTerminalCommand(shell: ShellId, input: string): TerminalCommandResult {
  const trimmed = input.trim();
  if (!trimmed) return { lines: [], notFound: false, clear: false };

  const stages = splitPipeline(tokenize(trimmed));
  if (stages.length === 0) return { lines: [], notFound: false, clear: false };

  const first = stages[0];
  const firstRawName = first[0];
  const firstName = firstRawName.toLowerCase();

  if (stages.length === 1) {
    if (isClearCommand(shell, firstName)) return { lines: [], notFound: false, clear: true };
    const metaLines = tryMetaHelp(shell, first);
    if (metaLines) return { lines: metaLines, notFound: false, clear: false };
  }

  const map = MAPS[shell];
  const def = map.get(firstName);
  if (!def) return { lines: commandNotFoundMessage(shell, firstRawName), notFound: true, clear: false };

  if (hasInlineHelpFlag(shell, first.slice(1))) {
    return { lines: detailHelpLines(shell, def), notFound: false, clear: false };
  }

  let lines = def.run(first.slice(1), { pipedLines: null });
  for (let i = 1; i < stages.length; i++) {
    const stage = stages[i];
    const stageDef = map.get(stage[0].toLowerCase());
    if (!stageDef) return { lines: commandNotFoundMessage(shell, stage[0]), notFound: true, clear: false };
    lines = stageDef.run(stage.slice(1), { pipedLines: lines });
  }
  return { lines, notFound: false, clear: false };
}
