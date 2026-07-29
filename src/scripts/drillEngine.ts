// @ts-nocheck — vanilla DOM client utility
//
// Generic interactive-quiz engine shared by 6 of the 7 /drills/* modules
// (regex, IP & CIDR math, hash ID, MITRE ATT&CK, Windows Event IDs; Terminal
// Commands opted out entirely into its own bespoke engine — see
// terminalDrill.ts — since it simulates a live shell rather than a
// question/answer loop). Each drill page owns its own question generator +
// grading and calls `initDrill()` directly from its own inline module script
// — this is deliberately NOT mounted through BaseLayout the way
// animatedDetails.ts / animatedSwitch.ts are (see CLAUDE.md invariant 5's
// "minimal JS, mount only where needed": this is a handful of pages, not
// site-wide).
//
// Seven answerTypes, in increasing "how hands-on" order: 'text' (recall,
// typed, single-shot) / 'choice' (recall, picked, single-shot) / 'construct'
// (build something real — e.g. a regex — validated live, iterate until it
// passes, optionally checked against hiddenTestCases never shown to the
// learner, to catch a pattern that only fits the visible samples) / 'subnet'
// ('construct' with an interactive CIDR builder instead of a bare text field
// — four octet controls + a prefix slider driving a live network/broadcast/
// host-range readout and the same per-address containment marks; see
// renderSubnet below) / 'extract' (read a shown `artifact`, fill several
// labeled blanks, iterate — right fields lock, wrong ones stay open) /
// 'match' (sort several items into a small fixed set of categories,
// iterate) / 'sequence' (click tiles into the one correct order, iterate).
// 'construct'/'subnet'/'extract'/'match'/'sequence' all share the same
// non-punitive philosophy: a Check that isn't fully correct never ends the
// question or costs anything, it just shows what's still wrong and lets the
// learner keep going — only 'text'/'choice' are single-shot, since there
// both correctness and completion are the same instant.
//
// 'subnet' is deliberately a PRESENTATION variant of 'construct', not a
// second grading path: its builder writes into the very same
// `[data-drill-text-input]` element every typed answerType uses, so
// handleConstructCheck grades it unchanged, and every scrap of subnet
// arithmetic is INJECTED by the drill (subnetBuild/subnetParse/
// subnetPreview below) rather than imported here — this generic engine ships
// on six drill pages and must not pull one drill's data module (and its
// IANA range tables) into all of them.
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

// Type-only import (erased at build — no runtime dependency added to this
// engine). See src/data/drills/graders.ts for why a serialisable descriptor
// exists alongside the live `grade` closure on three of these drills.
import type { DrillGrader } from '../data/drills/graders';

export interface DrillTestCaseResult {
  text: string;
  shouldMatch: boolean;
  actualMatch: boolean;
}

export interface DrillValidateResult {
  ok: boolean;
  /** Set when ok is false (e.g. the user's pattern failed to compile) — shown in place of the test-case list. */
  error?: string;
  /** Per-test-case outcome, set when ok is true. */
  results?: DrillTestCaseResult[];
  /** Set when ok===true: whether every visible test case (and, if checked, every hiddenTestCases entry) passed — this is what handleConstructCheck actually reads to decide finish() vs. "keep iterating." Always required when ok is true; a drill's own validate() must compute it (typically `results.every(r => r.actualMatch === r.shouldMatch)`, further gated by hiddenTestCases — see generalizationGap below). */
  pass?: boolean;
  /** 'construct' only, set only when ok===true and every entry in `results`
   *  already passes but the question also ships `hiddenTestCases` (never
   *  shown to the learner) and at least one of THOSE failed. Presence means
   *  the question is NOT solved — a pattern that only fits the visible
   *  samples hasn't actually learned the taught rule. Carries the first
   *  such failure so the feedback banner can name it without ever having
   *  shown it before now. When generalizationGap is set, `pass` must be
   *  false (never true) — the engine only checks `pass`, but a drill's own
   *  validate() should never mark both. */
  generalizationGap?: { text: string; shouldMatch: boolean; actualMatch: boolean };
}

/** 'subnet' only — everything the builder's live readout displays for the
 *  block currently in the CIDR field. Produced by the drill's own
 *  `subnetPreview`, which must derive every value from src/utils/cidr.ts;
 *  this engine only paints the strings/numbers it's handed. */
export interface DrillSubnetPreview {
  /** The block as parsed (e.g. "10.30.6.5/28"). */
  cidr: string;
  prefix: number;
  network: string;
  broadcast: string;
  netmask: string;
  /** Usable-host range, e.g. "10.30.6.1 – 10.30.6.14". */
  hostRange: string;
  usableHosts: number;
  totalHosts: number;
  /** Optional caveat for a prefix whose host range doesn't mean what it does
   *  elsewhere (/31 RFC 3021, /32 single host) — shown under the readout. */
  note?: string;
}

export interface DrillExtractField {
  /** Label shown next to the blank, e.g. "Account Name (New Logon)" — disambiguates same-named fields appearing in different blocks of the same raw artifact. */
  label: string;
  /** Expected value exactly as it appears in the artifact shown in `prompt` (or a dedicated `artifact` block — see DrillQuestion.artifact). Default grading target when `grade` is omitted: case-insensitive, trimmed exact match. */
  correctValue: string;
  /** Optional per-field custom grader (e.g. tolerate hex-case variance). */
  grade?: (userValue: string) => boolean;
  /** Serialisable stand-in for `grade`, for a drill whose question bank is
   *  materialised at build time and shipped as JSON (functions can't cross
   *  that boundary — see src/data/drills/graders.ts). Set it alongside
   *  `grade`, never instead of it: `grade` stays the source of truth the unit
   *  tests grade the descriptor against. */
  grader?: DrillGrader;
}

export interface DrillQuestion {
  prompt: string;
  explanation: string;
  referenceHref?: string;
  referenceLabel?: string;
  answerType: 'text' | 'choice' | 'construct' | 'subnet' | 'extract' | 'match' | 'sequence';
  choices?: string[];
  /** Required for 'text'/'choice'/'construct'/'subnet' (the latter two use it only as a no-JS/reference display fallback, grading goes through validate()); meaningless for 'extract'/'match'/'sequence', whose grading reads `fields`/`matchItems`/`correctOrder` instead — optional so those three don't need a synthesized placeholder string. */
  correctAnswer?: string;
  grade?: (userAnswer: string) => boolean;
  /** Serialisable stand-in for `grade` — see DrillExtractField.grader above
   *  and src/data/drills/graders.ts. Required (build throws otherwise) on any
   *  question whose drill materialises its bank at build time. */
  grader?: DrillGrader;
  /** A longer artifact to show above the answer area verbatim (a raw log excerpt, etc.) — currently used by 'extract' questions, but not exclusive to them. Rendered in a monospace block distinct from `prompt`. */
  artifact?: string;
  /** 'construct'/'subnet': the test cases to render (and re-render on every Check). For 'subnet' these are IPv4 addresses and `shouldMatch` means "must fall inside the block", labeled accordingly. */
  testCases?: { text: string; shouldMatch: boolean }[];
  /** 'construct' only, optional: cases NEVER rendered to the learner — checked only after every visible testCases entry already passes, to catch a pattern that fits only the shown samples rather than the taught rule. See DrillValidateResult.generalizationGap. */
  hiddenTestCases?: { text: string; shouldMatch: boolean }[];
  /** 'construct'/'subnet': compile/run the user's input against every testCase (+ hiddenTestCases once visible ones all pass). Called on every "Check answer" click — unlike 'text'/'choice', a wrong or non-compiling attempt does NOT end the question, so this can be called repeatedly as the learner iterates. */
  validate?: (userAnswer: string) => DrillValidateResult;
  /** 'subnet' only: the CIDR block the builder opens on. Should be a valid but WRONG block (the drill's own tests should assert it fails its own validate()) — the learner starts from a concrete, visibly-failing state instead of a blank field. Also read by DrillEngine.astro to pre-fill the server-rendered input. */
  subnetStart?: string;
  /** 'subnet' only: join the four octet-control values + prefix-slider value into a CIDR string, clamping out-of-range input. Injected by the drill (see src/data/drills/ipCidr.ts) so this engine imports no subnet math. */
  subnetBuild?: (octets: number[], prefix: number) => string;
  /** 'subnet' only: the inverse — split a CIDR string back into control values, or null if it doesn't parse (the controls then simply stay put while the learner is mid-typing). */
  subnetParse?: (cidr: string) => { octets: number[]; prefix: number } | null;
  /** 'subnet' only: derive the live readout (network/broadcast/netmask/host range/counts) for the current block, or null if it doesn't parse. All three of subnetBuild/subnetParse/subnetPreview must be present for the builder to mount; with any of them missing the question degrades to the plain typed-CIDR control, which grades identically. */
  subnetPreview?: (cidr: string) => DrillSubnetPreview | null;
  /** 'extract' only: one labeled blank per field to pull out of `artifact`/`prompt`. Graded together on Check; correct fields lock, incorrect ones stay editable — iterate until every field passes, same non-punitive philosophy as 'construct'. */
  fields?: DrillExtractField[];
  /** 'match' only: the items to sort, each into one of `matchCategories`. */
  matchItems?: { text: string; correctCategory: string }[];
  /** 'match' only: the fixed, shared set of category buttons every item row offers, in display order. */
  matchCategories?: string[];
  /** 'match' only, optional custom comparator (defaults to case-insensitive/trimmed equality). */
  matchEquals?: (assignedCategory: string, correctCategory: string) => boolean;
  /** 'sequence' only: the items to arrange, already shuffled into the order to render as click-to-place tiles. */
  sequenceItems?: string[];
  /** 'sequence' only: the same strings from sequenceItems, reordered into the single correct sequence. Graded position-by-position (exact string equality). */
  correctOrder?: string[];
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
  var subnetTemplate = root.querySelector('[data-drill-subnet-template]');
  var extractFieldTemplate = root.querySelector('[data-drill-extract-field-template]');
  var matchItemTemplate = root.querySelector('[data-drill-match-item-template]');
  var matchCategoryBtnTemplate = root.querySelector('[data-drill-match-category-btn-template]');
  var sequenceTileTemplate = root.querySelector('[data-drill-sequence-tile-template]');
  var artifactEl = root.querySelector('[data-drill-artifact]');
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

  // A 'subnet' question's test cases are addresses, not sample strings, so
  // "should match" would read as nonsense next to one. Same rows, same
  // states, different wording — and DrillEngine.astro's own server-rendered
  // list uses the identical pair, so the first paint and the hydrated
  // re-render still agree word for word.
  function testCaseLabels(question) {
    return question && question.answerType === 'subnet'
      ? { yes: 'must be inside', no: 'must be outside' }
      : { yes: 'should match', no: 'should NOT match' };
  }

  // Renders (or re-renders, after a Check) the test-case list for a
  // 'construct'/'subnet' question. `results` is omitted on first render
  // (every case shows a neutral "not checked yet" state) and passed in after
  // each Check click (each case then shows pass/fail per `actualMatch` vs
  // `shouldMatch`). Always clones from testCaseTemplate — same convention
  // as every other dynamic list in this file.
  function renderTestCaseRows(container, testCases, results, labels) {
    container.innerHTML = '';
    if (!testCaseTemplate) return;
    var text = labels || { yes: 'should match', no: 'should NOT match' };
    testCases.forEach(function (tc, i) {
      var row = testCaseTemplate.content.firstElementChild.cloneNode(true);
      var textEl = row.querySelector('[data-drill-testcase-text]');
      var labelEl = row.querySelector('[data-drill-testcase-label]');
      var iconEl = row.querySelector('[data-drill-testcase-icon]');
      if (textEl) textEl.textContent = tc.text;
      if (labelEl) labelEl.textContent = tc.shouldMatch ? text.yes : text.no;
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
    var labels = testCaseLabels(question);
    var trimmed = String(rawValue == null ? '' : rawValue);
    if (!trimmed) {
      renderTestCaseRows(list, question.testCases || [], null, labels);
      return;
    }
    var outcome = question.validate(trimmed);
    renderTestCaseRows(list, question.testCases || [], outcome && outcome.ok ? outcome.results || [] : null, labels);
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
    renderTestCaseRows(list, question.testCases || [], null, testCaseLabels(question));
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

  // 'subnet' — 'construct' with an interactive CIDR builder in front of the
  // same text input. The input remains the single source of truth for the
  // answer (it carries [data-drill-text-input], so handleConstructCheck and
  // disableAnswerArea both find it exactly as they do for every other typed
  // type); the octet/prefix controls are a second, equivalent way to edit
  // that one value, kept in two-way sync with it.
  //
  // Everything below is DOM plumbing only — the CIDR string is built by the
  // drill's injected subnetBuild(), parsed back by subnetParse(), and the
  // readout comes from subnetPreview(). No masking, shifting, or host
  // counting happens in this file.
  function renderSubnet(question) {
    answerEl.innerHTML = '';
    checkBtn.hidden = false;
    checkBtn.disabled = false;
    var labels = testCaseLabels(question);

    var input = textInputTemplate.content.firstElementChild.cloneNode(true);
    input.id = 'drill-subnet-cidr';
    input.setAttribute('aria-label', 'Your CIDR block');
    input.placeholder = 'e.g. 10.0.0.0/24';
    input.value = question.subnetStart || '';

    var list = document.createElement('ul');
    list.setAttribute('data-drill-testcases', '');
    list.setAttribute('aria-label', 'Addresses to cover');

    // The builder needs its template AND all three injected helpers. Missing
    // any of them, the question falls back to the bare text input — which is
    // exactly the server-rendered no-JS shape and grades identically, so a
    // partial contract degrades instead of rendering a dead control.
    var canBuild =
      subnetTemplate &&
      typeof question.subnetBuild === 'function' &&
      typeof question.subnetParse === 'function' &&
      typeof question.subnetPreview === 'function';
    var builder = canBuild ? subnetTemplate.content.firstElementChild.cloneNode(true) : null;

    var octetNums = [];
    var octetRanges = [];
    var prefixRange = null;
    var prefixValueEl = null;
    var noteEl = null;
    var out = null;

    if (builder) {
      var slot = builder.querySelector('[data-drill-subnet-input-slot]');
      if (slot && slot.parentNode) slot.parentNode.replaceChild(input, slot);
      else builder.appendChild(input);
      for (var i = 0; i < 4; i++) {
        octetNums.push(builder.querySelector('[data-drill-subnet-octet="' + i + '"]'));
        octetRanges.push(builder.querySelector('[data-drill-subnet-octet-range="' + i + '"]'));
      }
      prefixRange = builder.querySelector('[data-drill-subnet-prefix]');
      prefixValueEl = builder.querySelector('[data-drill-subnet-prefix-value]');
      noteEl = builder.querySelector('[data-drill-subnet-note]');
      out = {
        network: builder.querySelector('[data-drill-subnet-network]'),
        broadcast: builder.querySelector('[data-drill-subnet-broadcast]'),
        netmask: builder.querySelector('[data-drill-subnet-netmask]'),
        hostRange: builder.querySelector('[data-drill-subnet-hostrange]'),
        hostCount: builder.querySelector('[data-drill-subnet-hostcount]'),
      };
      answerEl.appendChild(builder);
    } else {
      answerEl.appendChild(input);
    }

    renderTestCaseRows(list, question.testCases || [], null, labels);
    answerEl.appendChild(list);

    var DASH = '—';
    function setText(el, value) {
      if (el) el.textContent = value;
    }

    function paintReadout() {
      if (!out) return;
      var p = question.subnetPreview(input.value);
      setText(out.network, p ? p.network : DASH);
      setText(out.broadcast, p ? p.broadcast : DASH);
      setText(out.netmask, p ? p.netmask : DASH);
      setText(out.hostRange, p ? p.hostRange : DASH);
      setText(
        out.hostCount,
        p ? p.usableHosts.toLocaleString() + ' usable of ' + p.totalHosts.toLocaleString() : DASH
      );
      setText(prefixValueEl, p ? '/' + p.prefix : '/' + DASH);
      if (noteEl) {
        var note = p && p.note ? p.note : '';
        noteEl.textContent = note;
        noteEl.hidden = !note;
      }
    }

    function refresh() {
      paintReadout();
      liveUpdateTestCases(question, list, input.value);
    }

    // Only write a control's value when it actually differs: assigning to an
    // <input>'s value moves the text cursor to the end even when the string
    // is unchanged, which would fight the learner mid-keystroke.
    function setControl(el, value) {
      if (el && el.value !== value) el.value = value;
    }

    // input -> controls. A block that doesn't parse leaves the controls
    // exactly where they are (the learner is mid-typing, not asking for the
    // sliders to jump to 0.0.0.0/0).
    function syncControlsFromInput() {
      if (!builder) return;
      var parsed = question.subnetParse(input.value);
      if (!parsed) return;
      for (var i = 0; i < 4; i++) {
        var v = String(parsed.octets[i]);
        setControl(octetNums[i], v);
        setControl(octetRanges[i], v);
      }
      setControl(prefixRange, String(parsed.prefix));
    }

    // controls -> input. Round-tripping back through syncControlsFromInput()
    // is what normalizes a clamped entry (typing 999 into an octet settles
    // the control on 255 rather than leaving the field disagreeing with the
    // block it produced).
    function syncInputFromControls() {
      var octets = [];
      for (var i = 0; i < 4; i++) octets.push(octetNums[i] ? Number(octetNums[i].value) : 0);
      input.value = question.subnetBuild(octets, prefixRange ? Number(prefixRange.value) : 0);
      syncControlsFromInput();
      refresh();
    }

    function onEnterCheck(e) {
      if (e.key === 'Enter' && !answered) {
        e.preventDefault();
        handleCheck();
      }
    }

    if (builder) {
      for (var j = 0; j < 4; j++) {
        (function (k) {
          var num = octetNums[k];
          var range = octetRanges[k];
          if (num) {
            num.addEventListener('input', function () {
              if (answered) return;
              // An empty field means "clearing it to retype", not "0" —
              // jumping the block to 0 on the way to typing "64" is exactly
              // the kind of thrash that makes a live control feel hostile.
              if (num.value === '') return;
              syncInputFromControls();
            });
            num.addEventListener('keydown', onEnterCheck);
          }
          if (range) {
            range.addEventListener('input', function () {
              if (answered) return;
              setControl(num, range.value);
              syncInputFromControls();
            });
          }
        })(j);
      }
      if (prefixRange) {
        prefixRange.addEventListener('input', function () {
          if (answered) return;
          syncInputFromControls();
        });
      }
    }

    // Typing the CIDR directly stays on the same 200ms debounce 'construct'
    // uses (a half-typed block shouldn't repaint on every keystroke), while
    // the sliders/number fields above update immediately — a drag that
    // lagged 200ms behind the thumb would defeat the point of dragging it.
    var liveTimer = null;
    input.addEventListener('input', function () {
      if (answered) return;
      clearTimeout(liveTimer);
      liveTimer = setTimeout(function () {
        syncControlsFromInput();
        refresh();
      }, 200);
    });
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && !answered) {
        e.preventDefault();
        clearTimeout(liveTimer);
        handleCheck();
      }
    });

    // First paint: the starting block is deliberately wrong, so the
    // containment marks and readout are already meaningful before the
    // learner touches anything.
    syncControlsFromInput();
    refresh();
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
    // 'subnet' builder controls (octet number fields + sliders + the prefix
    // slider). The CIDR text input inside the same block is already covered
    // by the [data-drill-text-input] lookup above; disabling it twice is
    // harmless and keeps this a single, obvious query.
    var subnetInputs = answerEl.querySelectorAll('[data-drill-subnet] input');
    Array.prototype.forEach.call(subnetInputs, function (i) {
      i.disabled = true;
    });
    var extractInputs = answerEl.querySelectorAll('[data-drill-extract-input]');
    Array.prototype.forEach.call(extractInputs, function (i) {
      i.disabled = true;
    });
    var matchBtns = answerEl.querySelectorAll('[data-drill-match-btn]');
    Array.prototype.forEach.call(matchBtns, function (b) {
      b.disabled = true;
    });
    var sequenceTiles = answerEl.querySelectorAll('[data-drill-sequence-tile]');
    Array.prototype.forEach.call(sequenceTiles, function (t) {
      t.disabled = true;
    });
    var resetBtn = answerEl.querySelector('[data-drill-sequence-reset]');
    if (resetBtn) resetBtn.disabled = true;
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

  // 'construct' (and 'subnet', which shares this path verbatim — see
  // renderSubnet) questions are iterative, unlike 'text'/'choice': a wrong
  // or non-compiling attempt does NOT end the question (no finish(), input
  // stays enabled) — the learner keeps refining the same pattern until
  // every test case passes, which is the whole point of a golf-style
  // challenge. Only a fully-passing attempt calls finish().
  function handleConstructCheck(question) {
    var input = answerEl.querySelector('[data-drill-text-input]');
    var list = answerEl.querySelector('[data-drill-testcases]');
    var raw = input ? input.value : '';
    var labels = testCaseLabels(question);
    var isSubnet = question.answerType === 'subnet';
    if (typeof question.validate !== 'function') return;
    var outcome = question.validate(raw);
    if (!outcome || !outcome.ok) {
      if (list) renderTestCaseRows(list, question.testCases || [], null, labels);
      feedbackEl.hidden = false;
      feedbackEl.setAttribute('data-state', 'incorrect');
      if (feedbackStateEl) feedbackStateEl.textContent = isSubnet ? 'Invalid block' : 'Pattern error';
      if (explanationEl) {
        explanationEl.textContent =
          (outcome && outcome.error) ||
          (isSubnet ? 'That block could not be evaluated.' : 'That pattern could not be evaluated.');
      }
      if (refLinkEl) refLinkEl.hidden = true;
      return;
    }
    if (list) renderTestCaseRows(list, question.testCases || [], outcome.results || [], labels);
    if (outcome.generalizationGap) {
      // Every VISIBLE case already passes (rows above show all-green), but
      // a held-out case the learner never saw broke — the pattern fits the
      // sample, not the taught rule. Not solved: no finish(), input stays
      // enabled, same "keep iterating" ethos as an ordinary non-passing
      // attempt, just with its own distinct banner naming what broke.
      var gap = outcome.generalizationGap;
      feedbackEl.hidden = false;
      feedbackEl.setAttribute('data-state', 'generalization');
      if (feedbackStateEl) feedbackStateEl.textContent = 'Almost — check your assumptions';
      if (explanationEl) {
        explanationEl.textContent =
          'Every case above passes, but your pattern doesn\'t generalize: "' + gap.text + '" ' +
          (gap.shouldMatch ? 'should match and doesn\'t.' : 'matches, but shouldn\'t.') + ' Keep refining.';
      }
      if (refLinkEl) refLinkEl.hidden = true;
      return;
    }
    if (outcome.pass) {
      finish(question, true, null);
    } else {
      // Not solved yet — clear any earlier compile-error banner (the
      // per-row pass/fail marks above are the real feedback now) and let
      // the learner try again; nothing is locked.
      clearFeedback();
    }
  }

  // Writes the non-color half of a pass/fail signal onto one row/tile: a
  // ✓/✕ glyph in an aria-hidden span (sighted, color-independent) and the
  // literal word "correct"/"incorrect" in a visually-hidden span (screen
  // readers). `pass === null` clears both back to the ungraded state.
  // WCAG 1.4.1 — the border/background tint alone is never the only signal.
  function setRowStatus(el, iconSel, statusSel, pass) {
    var iconEl = el.querySelector(iconSel);
    if (iconEl) iconEl.textContent = pass == null ? '' : pass ? '✓' : '✕';
    var statusEl = el.querySelector(statusSel);
    if (statusEl) statusEl.textContent = pass == null ? '' : pass ? ' — correct' : ' — incorrect';
  }

  // Shared by 'extract'/'match'/'sequence': like 'construct', a not-yet-
  // fully-correct Check does NOT end the question — whatever's already
  // right stays visibly marked, whatever's wrong stays editable, and the
  // learner keeps iterating. Only every-row/field/position correct calls
  // finish(). This mirrors handleConstructCheck's own non-punitive shape
  // rather than 'text'/'choice's single-shot one.
  function handleExtractCheck(question) {
    var rows = answerEl.querySelectorAll('[data-drill-extract-row]');
    if (!rows.length) return;
    var allPass = true;
    Array.prototype.forEach.call(rows, function (row, i) {
      var field = (question.fields || [])[i];
      if (!field) return;
      var input = row.querySelector('[data-drill-extract-input]');
      var raw = input ? String(input.value == null ? '' : input.value).trim() : '';
      var pass = typeof field.grade === 'function'
        ? Boolean(field.grade(raw))
        : raw.toLowerCase() === String(field.correctValue).trim().toLowerCase();
      row.setAttribute('data-state', pass ? 'pass' : 'fail');
      var iconEl = row.querySelector('[data-drill-extract-icon]');
      if (iconEl) iconEl.textContent = pass ? '✓' : '✕';
      if (input) input.disabled = pass; // lock a correct field so the learner's remaining effort focuses on what's still wrong
      if (!pass) allPass = false;
    });
    if (allPass) {
      finish(question, true, null);
    } else {
      clearFeedback();
    }
  }

  function renderExtract(question) {
    answerEl.innerHTML = '';
    checkBtn.hidden = false;
    checkBtn.disabled = false;
    (question.fields || []).forEach(function (field) {
      if (!extractFieldTemplate) return;
      var row = extractFieldTemplate.content.firstElementChild.cloneNode(true);
      row.setAttribute('data-state', 'pending');
      var labelEl = row.querySelector('[data-drill-extract-label]');
      var input = row.querySelector('[data-drill-extract-input]');
      if (labelEl) labelEl.textContent = field.label;
      if (input) {
        input.setAttribute('aria-label', field.label);
        input.addEventListener('keydown', function (e) {
          if (e.key === 'Enter' && !answered) {
            e.preventDefault();
            handleCheck();
          }
        });
      }
      answerEl.appendChild(row);
    });
    var firstInput = answerEl.querySelector('[data-drill-extract-input]');
    if (firstInput) firstInput.focus();
  }

  function handleMatchCheck(question) {
    var rows = answerEl.querySelectorAll('[data-drill-match-row]');
    if (!rows.length) return;
    var allPass = true;
    Array.prototype.forEach.call(rows, function (row, i) {
      var item = (question.matchItems || [])[i];
      if (!item) return;
      var active = row.querySelector('[data-drill-match-btn][data-active]');
      var assigned = active ? active.getAttribute('data-category') : null;
      var pass = assigned != null && (
        typeof question.matchEquals === 'function'
          ? question.matchEquals(assigned, item.correctCategory)
          : assigned.trim().toLowerCase() === String(item.correctCategory).trim().toLowerCase()
      );
      row.setAttribute('data-state', assigned == null ? 'pending' : pass ? 'pass' : 'fail');
      // Never signal pass/fail by the row's border/background tint alone
      // (WCAG 1.4.1 Use of Color) — mirror 'construct'/'extract' exactly:
      // a ✓/✕ glyph for sighted users plus a visually-hidden word so the
      // state is in the accessibility tree too.
      setRowStatus(row, '[data-drill-match-icon]', '[data-drill-match-status]', assigned == null ? null : pass);
      if (!pass) allPass = false;
      var btns = row.querySelectorAll('[data-drill-match-btn]');
      Array.prototype.forEach.call(btns, function (b) {
        // A locked-in-correct row's buttons stop taking input; a still-wrong
        // row's buttons stay clickable so the learner can pick again.
        b.disabled = pass;
      });
    });
    if (allPass) {
      finish(question, true, null);
    } else {
      clearFeedback();
    }
  }

  function renderMatch(question) {
    answerEl.innerHTML = '';
    checkBtn.hidden = false;
    checkBtn.disabled = false;
    var categories = question.matchCategories || [];
    (question.matchItems || []).forEach(function (item) {
      if (!matchItemTemplate) return;
      var row = matchItemTemplate.content.firstElementChild.cloneNode(true);
      row.setAttribute('data-state', 'pending');
      var textEl = row.querySelector('[data-drill-match-text]');
      var groupEl = row.querySelector('[data-drill-match-group]');
      if (textEl) textEl.textContent = item.text;
      if (groupEl && matchCategoryBtnTemplate) {
        categories.forEach(function (cat) {
          var btn = matchCategoryBtnTemplate.content.firstElementChild.cloneNode(true);
          btn.textContent = cat;
          btn.setAttribute('data-category', cat);
          btn.addEventListener('click', function () {
            if (answered) return;
            var siblingBtns = groupEl.querySelectorAll('[data-drill-match-btn]');
            Array.prototype.forEach.call(siblingBtns, function (b) {
              b.removeAttribute('data-active');
            });
            btn.setAttribute('data-active', '');
            row.setAttribute('data-state', 'pending');
            // Back to ungraded — drop the ✓/✕ and the announced word too,
            // or a re-picked row keeps claiming its previous verdict.
            setRowStatus(row, '[data-drill-match-icon]', '[data-drill-match-status]', null);
          });
          groupEl.appendChild(btn);
        });
      }
      answerEl.appendChild(row);
    });
  }

  // A tile's own visible text lives in its `data-drill-sequence-label` span,
  // never directly on the button — the button also holds an aria-hidden ✓/✕
  // glyph and a visually-hidden status word, so `tile.textContent` would
  // fold those into the comparison. Always grade against the label.
  function tileLabel(tile) {
    var labelEl = tile.querySelector('[data-drill-sequence-label]');
    return labelEl ? labelEl.textContent : tile.textContent;
  }

  function handleSequenceCheck(question) {
    var orderEl = answerEl.querySelector('[data-drill-sequence-order]');
    if (!orderEl) return;
    var placed = Array.prototype.map.call(orderEl.querySelectorAll('[data-drill-sequence-tile]'), tileLabel);
    var correctOrder = question.correctOrder || [];
    if (placed.length < correctOrder.length) {
      // Not every tile placed yet — nothing to grade, just no-op rather
      // than showing a misleading all-fail state.
      return;
    }
    var allPass = true;
    Array.prototype.forEach.call(orderEl.querySelectorAll('[data-drill-sequence-tile]'), function (tile, i) {
      var pass = tileLabel(tile) === correctOrder[i];
      tile.setAttribute('data-state', pass ? 'pass' : 'fail');
      // WCAG 1.4.1 — border/background tint is never the only signal.
      setRowStatus(tile, '[data-drill-sequence-icon]', '[data-drill-sequence-status]', pass);
      if (!pass) allPass = false;
    });
    if (allPass) {
      finish(question, true, null);
    } else {
      clearFeedback();
    }
  }

  function renderSequence(question) {
    answerEl.innerHTML = '';
    checkBtn.hidden = false;
    checkBtn.disabled = false;
    var poolEl = document.createElement('div');
    poolEl.setAttribute('data-drill-sequence-pool', '');
    poolEl.setAttribute('role', 'group');
    poolEl.setAttribute('aria-label', 'Available items');
    var orderEl = document.createElement('ol');
    orderEl.setAttribute('data-drill-sequence-order', '');
    orderEl.setAttribute('aria-label', 'Your sequence');
    var resetBtn = document.createElement('button');
    resetBtn.type = 'button';
    resetBtn.setAttribute('data-drill-sequence-reset', '');
    resetBtn.textContent = 'Reset order';

    function makeTile(text) {
      if (!sequenceTileTemplate) return null;
      var tile = sequenceTileTemplate.content.firstElementChild.cloneNode(true);
      var labelEl = tile.querySelector('[data-drill-sequence-label]');
      if (labelEl) labelEl.textContent = text;
      else tile.textContent = text;
      tile.setAttribute('data-drill-sequence-tile', '');
      tile.addEventListener('click', function () {
        if (answered) return;
        if (tile.parentElement === poolEl) {
          orderEl.appendChild(tile);
        } else {
          tile.removeAttribute('data-state');
          setRowStatus(tile, '[data-drill-sequence-icon]', '[data-drill-sequence-status]', null);
          poolEl.appendChild(tile);
        }
        // appendChild on an ALREADY-ATTACHED node is a remove-then-insert,
        // which drops focus to <body> — a keyboard user would lose their
        // place mid-task on every single tile move (WCAG 2.4.3 Focus
        // Order). Put focus back on the tile the user just acted on, which
        // is also where it belongs: the tile has simply moved lists.
        tile.focus();
        clearFeedback();
      });
      return tile;
    }

    (question.sequenceItems || []).forEach(function (text) {
      var tile = makeTile(text);
      if (tile) poolEl.appendChild(tile);
    });
    resetBtn.addEventListener('click', function () {
      if (answered) return;
      Array.prototype.forEach.call(orderEl.querySelectorAll('[data-drill-sequence-tile]'), function (tile) {
        tile.removeAttribute('data-state');
        setRowStatus(tile, '[data-drill-sequence-icon]', '[data-drill-sequence-status]', null);
        poolEl.appendChild(tile);
      });
      // Same remove-then-insert focus loss as a tile click (WCAG 2.4.3):
      // if focus happened to be on a tile inside the order list, moving
      // every tile back to the pool would strand it on <body>. Reset was
      // the user's own action, so keep focus on the button they pressed.
      resetBtn.focus();
      clearFeedback();
    });

    answerEl.appendChild(poolEl);
    answerEl.appendChild(orderEl);
    answerEl.appendChild(resetBtn);
  }

  function handleCheck() {
    if (answered || !current) return;
    if (current.answerType === 'construct' || current.answerType === 'subnet') {
      // 'subnet' grades through the identical path: its builder writes into
      // the same [data-drill-text-input] this reads.
      handleConstructCheck(current);
      return;
    }
    if (current.answerType === 'extract') {
      handleExtractCheck(current);
      return;
    }
    if (current.answerType === 'match') {
      handleMatchCheck(current);
      return;
    }
    if (current.answerType === 'sequence') {
      handleSequenceCheck(current);
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
    if (artifactEl) {
      var hasArtifact = Boolean(current.artifact);
      artifactEl.hidden = !hasArtifact;
      artifactEl.textContent = hasArtifact ? current.artifact : '';
    }
    if (current.answerType === 'choice') renderChoices(current);
    else if (current.answerType === 'construct') renderConstruct(current);
    else if (current.answerType === 'subnet') renderSubnet(current);
    else if (current.answerType === 'extract') renderExtract(current);
    else if (current.answerType === 'match') renderMatch(current);
    else if (current.answerType === 'sequence') renderSequence(current);
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
