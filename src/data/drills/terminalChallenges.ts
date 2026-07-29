// Challenge banks for the three interactive terminal drills at
// /drills/commands/{bash,cmd,powershell}/ — the successor to the old
// text-box quiz that lived in this same file's now-superseded sibling,
// src/data/drills/commands.ts (kept alongside this file only until the new
// TerminalDrill.astro/terminalDrill.ts UI is built and verified end to end;
// see that file's own header comment).
//
// Every prompt/hint/explanation/grade() below is lifted VERBATIM from the
// matching entry in src/data/drills/commands.ts — same wording, same
// regex-based grading, same documented leniency (flag order, common
// aliases) — this file does not weaken or reinvent any of it, it only
// regroups the 17 existing challenges into three per-OS tracks (bash, 9;
// cmd.exe, 5; PowerShell, 5 — whoami is shared as each track's first/intro
// challenge, so 17 unique challenges total, same as before) and drops the
// DrillQuestion-shaped wrapper (answerType/correctAnswer/choices) that only
// made sense for the old free-text-recall UI. The learner now runs the
// command for real in a simulated terminal (see ../terminalEnvironments.ts)
// instead of typing a recalled answer into a text box — grade() is what
// decides a challenge is "solved" once the exact right command comes through,
// unchanged from its original job.
//
// The two pure helpers below (collapse/hasExactFlagSet) are copied, not
// imported, from commands.ts — deliberately, since commands.ts is deleted
// once this replacement ships (see the top-level task plan), and importing
// from a file slated for deletion would leave this one broken.
//
// The 3 destructive challenges (bash `kill`, cmd.exe `taskkill`, PowerShell
// `Stop-Process`) additionally carry an `investigate` gate — see the
// interface doc below and terminalDrill.ts's checkChallenge(), which
// requires every predicate here to already match something in the
// session's own command history before the syntactically-correct
// destructive command is allowed to finish the challenge. Every gate below
// is built only from facts terminalEnvironments.ts already models (the
// PID 4521 / port 4444 listener bash's netstat -tulpn exposes; the fact
// that tasklist/Get-Process are this environment's only way to confirm a
// PID is a real running process on the two Windows tracks, which have no
// netstat equivalent modeled) — no new simulated facts are invented here.

function collapse(s: string): string {
  return String(s ?? '').trim().replace(/\s+/g, ' ');
}

// Accepts any order/case of a combined short-flag group, e.g. "-tulpn",
// "-nlput", "-TULPN" all equally valid — GNU getopt-style combined boolean
// flags don't care about order, so a fixed-order regex would wrongly reject
// a correct answer.
function hasExactFlagSet(flagString: string, required: string): boolean {
  return flagString.toLowerCase().split('').sort().join('') === required.split('').sort().join('');
}

export interface TerminalChallenge {
  /** Stable, unique-within-its-own-track id (for tests/keys — not shown in the UI). */
  id: string;
  prompt: string;
  hint: string;
  explanation: string;
  grade: (raw: string) => boolean;
  referenceHref?: string;
  referenceLabel?: string;
  /**
   * Optional "investigate before you act" gate, used on the 3 destructive
   * challenges (bash `kill`, cmd.exe `taskkill`, PowerShell `Stop-Process`).
   * Even once `grade()` returns true for a typed command, every predicate
   * here must ALSO already match some earlier command in the session's own
   * continuous history — see terminalDrill.ts's checkChallenge() and its
   * unmetInvestigateGates()/investigateSatisfied() helpers. If a gate is
   * unmet, the challenge stays open (the real simulated command output
   * still plays in full either way) and a `description` line naming what
   * to check first is appended to the terminal instead of the usual
   * "✓ Correct" callout.
   */
  investigate?: { description: string; test: (raw: string) => boolean }[];
}

// Shared across all three tracks as each one's first/intro challenge —
// defined once and spread into each array below so the wording can't drift
// between tracks.
const WHOAMI_CHALLENGE: Omit<TerminalChallenge, 'id'> = {
  prompt: 'Any shell — bash, cmd.exe, or PowerShell: show the current username.',
  hint: 'Same word, every shell.',
  explanation:
    'whoami is one of the rare commands with the exact same name everywhere — though the output differs: Windows shows DOMAIN\\username, bash shows just the username.',
  grade: (ans) => collapse(ans) === 'whoami',
};

// ── bash track (9: whoami + 8) ──────────────────────────────────────────

export const BASH_CHALLENGES: TerminalChallenge[] = [
  { id: 'bash-whoami', ...WHOAMI_CHALLENGE },
  {
    id: 'bash-pwd',
    prompt: 'bash (Linux/macOS): print the full path of your current directory.',
    hint: 'Three letters, no flags.',
    explanation: "pwd prints the shell's current working directory as an absolute path — the most basic orientation command in any Unix shell.",
    grade: (ans) => collapse(ans) === 'pwd',
  },
  {
    id: 'bash-ls-la',
    prompt: 'bash: list ALL files (including hidden ones) in long format.',
    hint: '-a for hidden, -l for long — combine them.',
    explanation: '-a shows hidden files, -l shows details — short flags like these combine in any order: -la, -al, or separately.',
    grade: (ans) => /^ls\s+(-la|-al|-a\s+-l|-l\s+-a)$/.test(collapse(ans)),
  },
  {
    id: 'bash-cat',
    prompt: 'bash: print the contents of notes.txt to the screen.',
    hint: "Short for 'concatenate'.",
    explanation: 'cat dumps a file straight to stdout — the fastest way to read a small file.',
    grade: (ans) => collapse(ans) === 'cat notes.txt',
  },
  {
    id: 'bash-grep',
    prompt: 'bash: search auth.log for lines containing "Failed password".',
    hint: 'grep "pattern" file — quotes matter here.',
    explanation: 'grep searches file contents for a pattern — a multi-word pattern needs quotes so the shell treats it as one argument.',
    grade: (ans) => /^grep\s+["']Failed password["']\s+auth\.log$/.test(collapse(ans)),
  },
  {
    id: 'bash-ps-grep',
    prompt: "bash: list all running processes and filter for 'chrome' — pipe two commands together.",
    hint: 'ps aux lists everything; pipe into grep to narrow it.',
    explanation: 'ps aux lists every process for every user; piping into grep chrome filters it down. The pipe (|) feeds one command straight into the next.',
    grade: (ans) => /^ps\s+-?aux\s*\|\s*grep\s+chrome$/.test(collapse(ans)),
  },
  {
    id: 'bash-kill',
    prompt: 'bash: forcibly terminate process ID 4521.',
    hint: 'Signal number 9 = SIGKILL, no mercy.',
    explanation: "-9 sends SIGKILL — a signal the process can't catch, block, or ignore, so it dies immediately.",
    grade: (ans) => /^kill\s+-(9|sigkill|kill)\s+4521$/i.test(collapse(ans)),
    investigate: [
      {
        description: 'Check what is actually bound to port 4444 before killing PID 4521 — run netstat -tulpn first.',
        test: (raw) => {
          const m = collapse(raw).match(/^netstat\s+-([a-z]+)/i);
          return m ? hasExactFlagSet(m[1], 'tulpn') : false;
        },
      },
    ],
  },
  {
    id: 'bash-netstat',
    prompt: 'Linux: list every listening TCP/UDP port along with the owning process.',
    hint: 't=TCP, u=UDP, l=listening, p=process, n=numeric — any order works.',
    explanation: 'netstat -tulpn shows every listening socket and which process owns it — a standard first move to spot an unexpected listener. Linux-specific: macOS netstat has no process/PID flag at all.',
    grade: (ans) => {
      const m = collapse(ans).match(/^netstat\s+-([a-z]+)$/i);
      return m ? hasExactFlagSet(m[1], 'tulpn') : false;
    },
    referenceHref: '/reference/network-ports/',
    referenceLabel: 'Network Port Reference',
  },
  {
    id: 'bash-capstone',
    prompt: 'Linux capstone: using netstat and grep together, find any listener bound to port 4444.',
    hint: 'Reuse netstat -tulpn from before, then pipe into grep 4444.',
    explanation: 'Combining netstat -tulpn with grep — exactly like ps aux | grep earlier — is a classic way to hunt one specific port, e.g. a suspicious backdoor listener.',
    grade: (ans) => {
      const m = collapse(ans).match(/^netstat\s+-([a-z]+)\s*\|\s*grep\s+4444$/i);
      return m ? hasExactFlagSet(m[1], 'tulpn') : false;
    },
    referenceHref: '/reference/network-ports/',
    referenceLabel: 'Network Port Reference',
  },
];

// ── cmd.exe track (5: whoami + 4) ───────────────────────────────────────

export const CMD_CHALLENGES: TerminalChallenge[] = [
  { id: 'cmd-whoami', ...WHOAMI_CHALLENGE },
  {
    id: 'cmd-dir',
    prompt: 'cmd.exe: list the files and folders in the current directory.',
    hint: 'Same idea as ls, different name.',
    explanation: "dir is cmd.exe's native directory-listing command — the Windows counterpart to ls.",
    grade: (ans) => /^dir$/i.test(collapse(ans)),
  },
  {
    id: 'cmd-tasklist-findstr',
    prompt: "cmd.exe: list running processes and filter for 'chrome' — pipe two commands together.",
    hint: 'tasklist | findstr <term>.',
    explanation: 'tasklist enumerates every process; piping into findstr narrows it down — the same idea as ps | grep on Unix. Note: findstr is case-sensitive by default.',
    // Command/pipe keywords stay case-insensitive (cmd.exe itself is), but the
    // search TERM is graded case-sensitively — deliberately, matching findstr's
    // own real case-sensitive-by-default behavior (this challenge's own
    // explanation above teaches exactly that). A prior version graded the
    // whole regex under a single /i flag, which also made the term lenient —
    // that let e.g. "findstr CHROME" grade as solved even though the terminal
    // simulation (correctly case-sensitive, see terminalEnvironments.ts's
    // findstrRun) shows zero matching rows for it, contradicting the "Correct"
    // banner shown right above that empty output.
    grade: (ans) => {
      const m = collapse(ans).match(/^tasklist\s*\|\s*findstr\s+(\S+)$/i);
      return m ? m[1] === 'chrome' : false;
    },
  },
  {
    id: 'cmd-taskkill',
    prompt: 'cmd.exe: forcibly terminate process ID 4521.',
    hint: "/PID <id> /F — order doesn't matter.",
    explanation: '/PID targets the process by its numeric ID; /F forces termination without prompting. The two flags can appear in either order.',
    grade: (ans) => /^taskkill\s+(\/pid\s+4521\s+\/f|\/f\s+\/pid\s+4521)$/i.test(collapse(ans)),
    investigate: [
      {
        description: 'Confirm PID 4521 actually shows up as a running chrome.exe process before force-killing it — run tasklist first.',
        test: (raw) => /^tasklist\b/i.test(collapse(raw)),
      },
    ],
  },
  {
    id: 'cmd-schtasks',
    prompt: 'cmd.exe: list every scheduled task on the system.',
    hint: "Windows' native task-scheduler CLI, queried.",
    explanation: 'schtasks /query lists every scheduled task — attackers commonly abuse Scheduled Tasks for persistence, making this a standard triage command.',
    grade: (ans) => /^schtasks\s+\/query$/i.test(collapse(ans)),
  },
];

// ── PowerShell track (5: whoami + 4) ────────────────────────────────────

export const POWERSHELL_CHALLENGES: TerminalChallenge[] = [
  { id: 'powershell-whoami', ...WHOAMI_CHALLENGE },
  {
    id: 'powershell-get-childitem',
    prompt: 'PowerShell: list the files and folders in the current directory.',
    hint: 'PowerShell cmdlets follow a Verb-Noun pattern.',
    explanation: 'Get-ChildItem is the real cmdlet; dir, gci, and (on Windows) ls are all built-in aliases for it.',
    grade: (ans) => /^(get-childitem|dir|gci|ls)$/i.test(collapse(ans)),
  },
  {
    id: 'powershell-get-content',
    prompt: 'PowerShell: print the contents of notes.txt to the screen.',
    hint: 'Same verb-noun pattern as the last PowerShell answer.',
    explanation: 'Get-Content is the real cmdlet; gc and cat/type are built-in aliases for it — the same alias pattern as Get-ChildItem.',
    grade: (ans) => /^(get-content|gc|cat|type)\s+notes\.txt$/i.test(collapse(ans)),
  },
  {
    id: 'powershell-get-process-where',
    prompt: 'PowerShell: list processes and filter for ones named like "chrome" — using the object pipeline.',
    hint: 'Get-Process | Where-Object {$_.Name -like "*pattern*"}.',
    explanation: 'Where-Object filters a stream of OBJECTS, not text lines — $_ is the current object, -like does wildcard matching. This is the key difference from bash/cmd pipes, which only ever pass plain text.',
    grade: (ans) =>
      /^get-process\s*\|\s*(where-object|where|\?)\s*\{\s*\$_\.(name|processname)\s*-like\s*["']\*chrome\*["']\s*\}$/i.test(
        collapse(ans),
      ),
  },
  {
    id: 'powershell-stop-process',
    prompt: 'PowerShell: forcibly terminate process ID 4521.',
    hint: 'Stop-Process -Id <id> -Force.',
    explanation: "-Id targets the process by its numeric ID; -Force skips the confirmation prompt Stop-Process shows for processes you don't own.",
    grade: (ans) => /^stop-process\s+(-id\s+4521\s+-force|-force\s+-id\s+4521)$/i.test(collapse(ans)),
    investigate: [
      {
        description: 'Confirm PID 4521 actually shows up as a running process before force-stopping it — run Get-Process first.',
        test: (raw) => /^get-process\b/i.test(collapse(raw)),
      },
    ],
  },
];
