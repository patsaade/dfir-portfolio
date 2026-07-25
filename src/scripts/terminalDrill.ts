// @ts-nocheck — vanilla DOM client utility
//
// Client layer for the three interactive terminal drills at
// /drills/commands/{bash,cmd,powershell}/ — mirrors drillEngine.ts's own
// shape (data-* attribute wiring, <template> cloning, no framework) but
// adapted for a real scrollback terminal instead of a single-input quiz.
// Each page's own inline <script> calls initTerminalDrill() directly, the
// same "mount only where needed" reasoning as drillEngine.ts's own header
// comment (CLAUDE.md invariant 5) — this is NOT a global BaseLayout mount.
//
// The terminal's scrollback (and command history) is a single continuous
// session across the whole track — advancing to the next challenge only
// re-renders the challenge banner (goal/hint/progress), it never clears the
// terminal, matching this feature's own "genuine sandbox, explore freely"
// design (see terminalEnvironments.ts's header comment). Only "Try again"
// resets the scrollback, mirroring drillEngine.ts's own restart semantics
// (index/score back to zero).
//
// Deliberate deviation from DrillEngine's own "single render path, re-clone
// even question 0" rule: this component's server-rendered welcome line is
// left untouched on mount, and this script only ever APPENDS from then on.
// That rule existed in drillEngine.ts because a "question" is regenerated
// from a pure function on every state change, so re-rendering question 0
// through that same path avoided a second bespoke code path. A terminal's
// scrollback isn't a re-derived "current state" the same way — it's a
// genuine append-only transcript of what the learner actually typed — so
// there is no equivalent pure re-render to reuse, and leaving the SSR
// welcome line alone is both simpler and safer (zero risk of a mount-time
// flash, since nothing is replaced).
//
// All command simulation is delegated to runTerminalCommand() in
// terminalEnvironments.ts — this file only renders lines into the DOM and
// checks the current challenge's own grade() against the raw text typed,
// the same job gradeAnswer() does for DrillEngine's own questions.

import { runTerminalCommand, PROMPTS, SHELL_DISPLAY_NAMES } from '../data/terminalEnvironments';

// File-local only (knip-flagged unused export) — nothing outside this file
// imports it; the .astro caller types its own `challenges` prop directly
// against `TerminalChallenge` from terminalChallenges.ts instead.
interface TerminalChallengeLike {
  prompt: string;
  hint: string;
  explanation: string;
  grade: (raw: string) => boolean;
  referenceHref?: string;
  referenceLabel?: string;
}

interface TerminalDrillConfig {
  root: Element;
  /** Which shell's simulation/prompt to use — passed straight through to runTerminalCommand(). */
  shell: 'bash' | 'cmd' | 'powershell';
  challenges: TerminalChallengeLike[];
}

export function initTerminalDrill(config) {
  var root = config.root;
  var shell = config.shell;
  var challenges = config.challenges;
  var total = challenges.length;
  if (!root || root.__terminalDrillInit || total === 0) return;
  root.__terminalDrillInit = true;

  var promptText = PROMPTS[shell];
  var welcomeText = 'Simulated ' + SHELL_DISPLAY_NAMES[shell] + ' — type "help" to see available commands.';

  var goalEl = root.querySelector('[data-terminal-goal]');
  var progressEl = root.querySelector('[data-terminal-progress]');
  var hintBtn = root.querySelector('[data-terminal-hint-btn]');
  var hintTextEl = root.querySelector('[data-terminal-hint-text]');
  var outputEl = root.querySelector('[data-terminal-output]');
  var inputEl = root.querySelector('[data-terminal-input]');
  var nextBtn = root.querySelector('[data-terminal-next]');
  var summaryEl = root.querySelector('[data-terminal-summary]');
  var restartBtn = root.querySelector('[data-terminal-restart]');
  var lineTemplate = root.querySelector('[data-terminal-line-template]');
  var linkLineTemplate = root.querySelector('[data-terminal-link-line-template]');
  var windowEl = root.querySelector('[data-terminal-window]');
  if (!goalEl || !progressEl || !outputEl || !inputEl || !nextBtn || !lineTemplate) return;

  var index = 0;
  var solvedCount = 0;
  var solvedThisChallenge = false;
  var history = [];
  var historyPos = 0; // equals history.length when "past the end" (a fresh, not-yet-submitted line)

  function scrollToBottom() {
    outputEl.scrollTop = outputEl.scrollHeight;
  }

  function addLine(text, kind) {
    var el = lineTemplate.content.firstElementChild.cloneNode(true);
    el.textContent = text;
    if (kind) el.setAttribute('data-kind', kind);
    outputEl.appendChild(el);
    return el;
  }

  function addLinkLine(href, label) {
    if (!linkLineTemplate) return;
    var el = linkLineTemplate.content.firstElementChild.cloneNode(true);
    var a = el.querySelector('[data-terminal-line-link]');
    if (a) {
      a.href = href;
      a.textContent = label || 'Learn more';
    }
    outputEl.appendChild(el);
  }

  function updateProgress() {
    progressEl.textContent = 'Challenge ' + (index + 1) + ' of ' + total + ' — ' + solvedCount + ' solved';
  }

  function renderChallenge(i) {
    var challenge = challenges[i];
    goalEl.textContent = challenge.prompt;
    solvedThisChallenge = false;
    // Hidden synchronously as the very first thing on a "Next" click (see
    // that handler below), same reasoning as drillEngine.ts's own
    // renderQuestion(): a real double-click can't advance the index twice
    // once the button is non-hit-testable.
    nextBtn.hidden = true;
    if (summaryEl) summaryEl.hidden = true;
    if (restartBtn) restartBtn.hidden = true;
    if (hintBtn) {
      var hasHint = Boolean(challenge.hint);
      hintBtn.hidden = !hasHint;
      hintBtn.setAttribute('aria-expanded', 'false');
      if (hintTextEl) {
        hintTextEl.hidden = true;
        hintTextEl.textContent = hasHint ? challenge.hint : '';
      }
    }
    updateProgress();
  }

  // Checked after EVERY command, solved or not — the terminal never locks
  // out a wrong-but-valid attempt (that's the whole point of a free-explore
  // sandbox); a challenge already solved this "turn" is simply not
  // re-checked, so exploring further doesn't spam a second "Correct" line.
  function checkChallenge(raw) {
    if (solvedThisChallenge) return;
    var challenge = challenges[index];
    var ok = false;
    try {
      ok = Boolean(challenge.grade(raw));
    } catch (e) {
      ok = false;
    }
    if (!ok) return;
    solvedThisChallenge = true;
    solvedCount += 1;
    addLine('✓ Correct', 'correct');
    addLine(challenge.explanation, 'correct-explain');
    if (challenge.referenceHref) addLinkLine(challenge.referenceHref, challenge.referenceLabel);
    updateProgress();
    var isLast = index + 1 >= total;
    if (isLast) {
      nextBtn.hidden = true;
      if (summaryEl) {
        summaryEl.hidden = false;
        summaryEl.textContent = 'Completed all ' + total + ' challenges.';
      }
      if (restartBtn) restartBtn.hidden = false;
    } else {
      nextBtn.hidden = false;
    }
  }

  function runCommand(raw) {
    addLine(promptText + raw, 'cmd');
    var result = runTerminalCommand(shell, raw);
    if (result.clear) {
      outputEl.innerHTML = '';
    } else {
      result.lines.forEach(function (line) {
        addLine(line, result.notFound ? 'error' : 'out');
      });
    }
    checkChallenge(raw);
    scrollToBottom();
  }

  inputEl.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      var raw = inputEl.value.trim();
      inputEl.value = '';
      if (!raw) {
        addLine(promptText, 'cmd');
        scrollToBottom();
        return;
      }
      history.push(raw);
      historyPos = history.length;
      runCommand(raw);
    } else if (e.key === 'ArrowUp') {
      if (history.length === 0) return;
      e.preventDefault();
      historyPos = Math.max(0, historyPos - 1);
      inputEl.value = history[historyPos] || '';
      var len = inputEl.value.length;
      inputEl.setSelectionRange(len, len);
    } else if (e.key === 'ArrowDown') {
      if (history.length === 0) return;
      e.preventDefault();
      historyPos = Math.min(history.length, historyPos + 1);
      inputEl.value = historyPos < history.length ? history[historyPos] : '';
      var len2 = inputEl.value.length;
      inputEl.setSelectionRange(len2, len2);
    }
  });

  // Clicking anywhere in the terminal window refocuses the input — standard
  // terminal-emulator UX (there's no other focusable target inside it worth
  // preserving focus on).
  if (windowEl) {
    windowEl.addEventListener('click', function () {
      inputEl.focus();
    });
  }

  if (hintBtn) {
    hintBtn.addEventListener('click', function () {
      if (!hintTextEl) return;
      var showing = hintTextEl.hidden === false;
      hintTextEl.hidden = showing;
      hintBtn.setAttribute('aria-expanded', String(!showing));
    });
  }

  nextBtn.addEventListener('click', function () {
    nextBtn.hidden = true;
    index += 1;
    renderChallenge(index);
    goalEl.focus();
  });

  if (restartBtn) {
    restartBtn.addEventListener('click', function () {
      index = 0;
      solvedCount = 0;
      history = [];
      historyPos = 0;
      outputEl.innerHTML = '';
      addLine(welcomeText, 'hint');
      renderChallenge(0);
      inputEl.focus();
    });
  }

  renderChallenge(0);
}
