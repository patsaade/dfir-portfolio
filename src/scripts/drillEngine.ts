// @ts-nocheck — vanilla DOM client utility
//
// Generic interactive-quiz engine shared by the 6 /drills/* modules (regex,
// IP & CIDR math, hash ID, MITRE ATT&CK, Windows Event IDs, command line).
// Each drill page owns its own question generator + grading and calls
// `initDrill()` directly from its own inline module script — this is
// deliberately NOT mounted through BaseLayout the way animatedDetails.ts /
// animatedSwitch.ts are (see CLAUDE.md invariant 5's "minimal JS, mount only
// where needed": this is a 6-page feature, not site-wide).
//
// Renders into the static shell DrillEngine.astro already put in the DOM
// server-side (see that file's header comment for the no-JS fallback
// contract) and re-renders the SAME slots on every question change — always
// clearing + repopulating from the two <template>s (never
// `document.createElement` + a hardcoded class-name string), which is the
// one code path used for question 0 too, not just subsequent questions.
// That means the very first paint after JS takes over briefly replaces the
// server-rendered question-0 markup with a freshly cloned, byte-for-byte
// equivalent (assuming `nextQuestion(0)` is deterministic) — a deliberate
// simplification (one rendering path, not two) rather than trying to
// "adopt" the existing SSR nodes and attach listeners to them directly.
//
// All interactive state (correct/incorrect, disabled, hidden) is expressed
// via plain HTML attributes that DrillEngine.astro's own css() already
// styles by attribute selector (`data-state`, `data-correct`,
// `data-incorrect`, `disabled`, `hidden`) — this file never needs to know a
// single Panda-generated class name, matching the `<template>`-cloning
// convention IocExtractor.astro's own script uses for the same reason.

interface DrillTestCaseResult {
  text: string;
  shouldMatch: boolean;
  actualMatch: boolean;
}

interface DrillValidateResult {
  ok: boolean;
  /** Set when ok is false (e.g. the user's pattern failed to compile) — shown in place of the test-case list. */
  error?: string;
  /** Per-test-case outcome, set when ok is true. */
  results?: DrillTestCaseResult[];
}

export interface DrillQuestion {
  prompt: string;
  explanation: string;
  referenceHref?: string;
  referenceLabel?: string;
  answerType: 'text' | 'choice' | 'construct';
  choices?: string[];
  correctAnswer: string;
  grade?: (userAnswer: string) => boolean;
  /** 'construct' only: the test cases to render (and re-render on every Check). */
  testCases?: { text: string; shouldMatch: boolean }[];
  /** 'construct' only: compile/run the user's input against every testCase. Called on every "Check answer" click — unlike 'text'/'choice', a wrong or non-compiling attempt does NOT end the question, so this can be called repeatedly as the learner iterates. */
  validate?: (userAnswer: string) => DrillValidateResult;
  /** Optional — shown behind a "Show hint" toggle, any answerType. Revealing it doesn't affect scoring. */
  hint?: string;
}

interface DrillConfig {
  root: Element;
  totalQuestions: number;
  nextQuestion: (index: number) => DrillQuestion;
}

export function initDrill(config) {
  var root = config.root;
  var totalQuestions = config.totalQuestions;
  var nextQuestion = config.nextQuestion;
  if (!root || root.__drillEngineInit) return;
  root.__drillEngineInit = true;

  var promptEl = root.querySelector('[data-drill-prompt]');
  var answerEl = root.querySelector('[data-drill-answer]');
  var checkBtn = root.querySelector('[data-drill-check]');
  var feedbackEl = root.querySelector('[data-drill-feedback]');
  var feedbackStateEl = root.querySelector('[data-drill-feedback-state]');
  var explanationEl = root.querySelector('[data-drill-feedback-explanation]');
  var refLinkEl = root.querySelector('[data-drill-feedback-link]');
  var progressEl = root.querySelector('[data-drill-progress]');
  var nextBtn = root.querySelector('[data-drill-next]');
  var summaryEl = root.querySelector('[data-drill-summary]');
  var restartBtn = root.querySelector('[data-drill-restart]');
  var textInputTemplate = root.querySelector('[data-drill-text-input-template]');
  var choiceTemplate = root.querySelector('[data-drill-choice-template]');
  var testCaseTemplate = root.querySelector('[data-drill-testcase-template]');
  var hintBtn = root.querySelector('[data-drill-hint-btn]');
  var hintTextEl = root.querySelector('[data-drill-hint-text]');
  if (!promptEl || !answerEl || !checkBtn || !feedbackEl || !progressEl || !nextBtn || !textInputTemplate || !choiceTemplate) {
    return;
  }

  var index = 0;
  var score = 0;
  var current = null;
  var answered = false;

  function updateProgress() {
    progressEl.textContent = 'Question ' + (index + 1) + ' of ' + totalQuestions + ' — ' + score + ' correct';
  }

  // Robust semantic comparison when the drill supplies one (e.g. reusing the
  // same pure parsing function the live tool uses), otherwise a
  // case-insensitive trimmed fallback.
  function gradeAnswer(question, rawAnswer) {
    var trimmed = String(rawAnswer == null ? '' : rawAnswer).trim();
    if (typeof question.grade === 'function') return Boolean(question.grade(trimmed));
    return trimmed.toLowerCase() === String(question.correctAnswer).trim().toLowerCase();
  }

  function clearFeedback() {
    feedbackEl.hidden = true;
    feedbackEl.removeAttribute('data-state');
    if (feedbackStateEl) feedbackStateEl.textContent = '';
    if (explanationEl) explanationEl.textContent = '';
    if (refLinkEl) {
      refLinkEl.hidden = true;
      refLinkEl.textContent = '';
      refLinkEl.removeAttribute('href');
    }
  }

  function showFeedback(correct, question) {
    feedbackEl.hidden = false;
    feedbackEl.setAttribute('data-state', correct ? 'correct' : 'incorrect');
    if (feedbackStateEl) feedbackStateEl.textContent = correct ? 'Correct' : 'Not quite';
    if (explanationEl) explanationEl.textContent = question.explanation;
    if (refLinkEl) {
      if (question.referenceHref) {
        refLinkEl.href = question.referenceHref;
        refLinkEl.textContent = question.referenceLabel || 'Learn more';
        refLinkEl.hidden = false;
      } else {
        refLinkEl.hidden = true;
      }
    }
  }

  function renderTextInput() {
    answerEl.innerHTML = '';
    checkBtn.hidden = false;
    checkBtn.disabled = false;
    var input = textInputTemplate.content.firstElementChild.cloneNode(true);
    answerEl.appendChild(input);
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && !answered) {
        e.preventDefault();
        handleCheck();
      }
    });
    input.focus();
  }

  // Renders (or re-renders, after a Check) the test-case list for a
  // 'construct' question. `results` is omitted on first render (every case
  // shows a neutral "not checked yet" state) and passed in after each Check
  // click (each case then shows pass/fail per `actualMatch` vs
  // `shouldMatch`). Always clones from testCaseTemplate — same convention
  // as every other dynamic list in this file.
  function renderTestCaseRows(container, testCases, results) {
    container.innerHTML = '';
    if (!testCaseTemplate) return;
    testCases.forEach(function (tc, i) {
      var row = testCaseTemplate.content.firstElementChild.cloneNode(true);
      var textEl = row.querySelector('[data-drill-testcase-text]');
      var labelEl = row.querySelector('[data-drill-testcase-label]');
      var iconEl = row.querySelector('[data-drill-testcase-icon]');
      if (textEl) textEl.textContent = tc.text;
      if (labelEl) labelEl.textContent = tc.shouldMatch ? 'should match' : 'should NOT match';
      var result = results ? results[i] : null;
      if (result) {
        var pass = result.actualMatch === result.shouldMatch;
        row.setAttribute('data-state', pass ? 'pass' : 'fail');
        if (iconEl) iconEl.textContent = pass ? '✓' : '✕';
      } else {
        row.setAttribute('data-state', 'pending');
        if (iconEl) iconEl.textContent = '•';
      }
      container.appendChild(row);
    });
  }

  // Live-preview pass/fail for a 'construct' question as the learner types —
  // debounced the same 200ms as the live Regex Tester's own recompute (see
  // RegexTester.astro), reusing the SAME question.validate() the explicit
  // "Check answer" click calls. Deliberately does NOT call finish() or show
  // the feedback banner on its own: a transient full-pass while still mid-
  // edit (e.g. typing "vbs|ps1|bat" character by character can flash green
  // on an earlier partial pattern) shouldn't silently end the question out
  // from under the learner — only a real Check click locks in the answer and
  // advances score/progress. An empty or non-compiling in-progress pattern
  // just resets the rows to their neutral pending state rather than showing
  // an alarming "Pattern error" banner on every incomplete keystroke — that
  // banner stays exclusive to the explicit Check flow (handleConstructCheck).
  function liveUpdateTestCases(question, list, rawValue) {
    if (typeof question.validate !== 'function') return;
    var trimmed = String(rawValue == null ? '' : rawValue);
    if (!trimmed) {
      renderTestCaseRows(list, question.testCases || [], null);
      return;
    }
    var outcome = question.validate(trimmed);
    renderTestCaseRows(list, question.testCases || [], outcome && outcome.ok ? outcome.results || [] : null);
  }

  function renderConstruct(question) {
    answerEl.innerHTML = '';
    checkBtn.hidden = false;
    checkBtn.disabled = false;
    var input = textInputTemplate.content.firstElementChild.cloneNode(true);
    input.setAttribute('aria-label', 'Your pattern');
    input.placeholder = 'Type your pattern';
    answerEl.appendChild(input);
    var list = document.createElement('ul');
    list.setAttribute('data-drill-testcases', '');
    list.setAttribute('aria-label', 'Test cases');
    renderTestCaseRows(list, question.testCases || [], null);
    answerEl.appendChild(list);
    var liveTimer = null;
    input.addEventListener('input', function () {
      if (answered) return;
      clearTimeout(liveTimer);
      liveTimer = setTimeout(function () {
        liveUpdateTestCases(question, list, input.value);
      }, 200);
    });
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && !answered) {
        e.preventDefault();
        clearTimeout(liveTimer);
        handleCheck();
      }
    });
    input.focus();
  }

  function renderChoices(question) {
    answerEl.innerHTML = '';
    checkBtn.hidden = true;
    var group = document.createElement('div');
    group.setAttribute('role', 'group');
    group.setAttribute('aria-label', 'Answer choices');
    (question.choices || []).forEach(function (choiceText) {
      var btn = choiceTemplate.content.firstElementChild.cloneNode(true);
      btn.textContent = choiceText;
      btn.addEventListener('click', function () {
        if (answered) return;
        finish(question, gradeAnswer(question, choiceText), btn);
      });
      group.appendChild(btn);
    });
    answerEl.appendChild(group);
  }

  function disableAnswerArea() {
    var input = answerEl.querySelector('[data-drill-text-input]');
    if (input) input.disabled = true;
    checkBtn.disabled = true;
    var choiceBtns = answerEl.querySelectorAll('[data-drill-choice-btn]');
    Array.prototype.forEach.call(choiceBtns, function (b) {
      b.disabled = true;
    });
  }

  function finish(question, correct, clickedBtn) {
    answered = true;
    if (correct) score += 1;
    disableAnswerArea();
    if (clickedBtn) {
      clickedBtn.setAttribute(correct ? 'data-correct' : 'data-incorrect', '');
      if (!correct) {
        // Also flag whichever choice WAS correct, so the learner sees the
        // right answer, not just that theirs was wrong.
        var choiceBtns = answerEl.querySelectorAll('[data-drill-choice-btn]');
        Array.prototype.forEach.call(choiceBtns, function (b) {
          if (b.textContent.trim() === String(question.correctAnswer).trim()) b.setAttribute('data-correct', '');
        });
      }
    }
    showFeedback(correct, question);
    updateProgress();
    var isLast = index + 1 >= totalQuestions;
    if (isLast) {
      nextBtn.hidden = true;
      if (summaryEl) {
        var pct = totalQuestions > 0 ? Math.round((score / totalQuestions) * 100) : 0;
        summaryEl.hidden = false;
        summaryEl.textContent = 'Drill complete — ' + score + '/' + totalQuestions + ' correct (' + pct + '%).';
      }
      if (restartBtn) restartBtn.hidden = false;
    } else {
      nextBtn.hidden = false;
      nextBtn.focus();
    }
  }

  // 'construct' questions are iterative, unlike 'text'/'choice': a wrong or
  // non-compiling attempt does NOT end the question (no finish(), input
  // stays enabled) — the learner keeps refining the same pattern until
  // every test case passes, which is the whole point of a golf-style
  // challenge. Only a fully-passing attempt calls finish().
  function handleConstructCheck(question) {
    var input = answerEl.querySelector('[data-drill-text-input]');
    var list = answerEl.querySelector('[data-drill-testcases]');
    var raw = input ? input.value : '';
    if (typeof question.validate !== 'function') return;
    var outcome = question.validate(raw);
    if (!outcome || !outcome.ok) {
      if (list) renderTestCaseRows(list, question.testCases || [], null);
      feedbackEl.hidden = false;
      feedbackEl.setAttribute('data-state', 'incorrect');
      if (feedbackStateEl) feedbackStateEl.textContent = 'Pattern error';
      if (explanationEl) explanationEl.textContent = (outcome && outcome.error) || 'That pattern could not be evaluated.';
      if (refLinkEl) refLinkEl.hidden = true;
      return;
    }
    if (list) renderTestCaseRows(list, question.testCases || [], outcome.results || []);
    if (outcome.pass) {
      finish(question, true, null);
    } else {
      // Not solved yet — clear any earlier compile-error banner (the
      // per-row pass/fail marks above are the real feedback now) and let
      // the learner try again; nothing is locked.
      clearFeedback();
    }
  }

  function handleCheck() {
    if (answered || !current) return;
    if (current.answerType === 'construct') {
      handleConstructCheck(current);
      return;
    }
    var input = answerEl.querySelector('[data-drill-text-input]');
    var raw = input ? input.value : '';
    finish(current, gradeAnswer(current, raw), null);
  }

  function renderQuestion(i) {
    current = nextQuestion(i);
    answered = false;
    promptEl.textContent = current.prompt;
    clearFeedback();
    // Hidden synchronously as the very first thing on a "Next" click (see
    // that handler below) so a real double-click can't advance the index
    // twice — the button becomes non-hit-testable before a second physical
    // click could land on it.
    nextBtn.hidden = true;
    if (summaryEl) summaryEl.hidden = true;
    if (restartBtn) restartBtn.hidden = true;
    if (hintBtn) {
      var hasHint = Boolean(current.hint);
      hintBtn.hidden = !hasHint;
      hintBtn.setAttribute('aria-expanded', 'false');
      if (hintTextEl) {
        hintTextEl.hidden = true;
        hintTextEl.textContent = hasHint ? current.hint : '';
      }
    }
    if (current.answerType === 'choice') renderChoices(current);
    else if (current.answerType === 'construct') renderConstruct(current);
    else renderTextInput();
    updateProgress();
  }

  checkBtn.addEventListener('click', handleCheck);

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
    renderQuestion(index);
    promptEl.focus();
  });

  if (restartBtn) {
    restartBtn.addEventListener('click', function () {
      index = 0;
      score = 0;
      renderQuestion(0);
    });
  }

  renderQuestion(0);
}
