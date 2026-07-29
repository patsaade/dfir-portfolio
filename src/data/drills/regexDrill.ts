// Question generator for the RegEx Range Drill (/drills/regex/) — a
// construct-the-pattern progression, NOT a multiple-choice/text-recall quiz:
// each challenge gives a set of sample strings that SHOULD match your
// pattern and a set that should NOT, and you write the actual regular
// expression yourself. Checking is real — DrillEngine's 'construct'
// answerType (see src/scripts/drillEngine.ts) compiles whatever you type
// with the exact same `compileRegexSafely` + `findAllMatches` pure functions
// the live Regex Tester uses (src/utils/regexPatterns.ts) and runs it
// against every test case. Test-case pass/fail updates LIVE as you type
// (debounced, see drillEngine.ts's `liveUpdateTestCases`) as well as on an
// explicit "Check answer" click — the live preview never locks in an answer
// or shows an error banner on its own, only Check does that. Unlike
// 'text'/'choice' questions, a wrong or non-compiling attempt does NOT end
// the challenge — you keep refining the same pattern until every case passes.
//
// The 11 challenges are original to this site (not lifted from any existing
// problem set or collection) and are ordered to teach one new syntax concept at a time,
// easy to hard: literals, character classes, quantifiers, anchors,
// alternation, escaping, word boundaries, negated classes, capturing
// groups + backreferences, lookahead, and a capstone that reuses the site's
// own real IPv4 pattern. Every "reference solution" below was verified —
// compiled and run against its own test cases with the SAME functions the
// live grading uses — before being hardcoded (see test/regexDrill.test.ts,
// which re-checks this on every test run rather than trusting a one-time
// check). Sample strings are hand-authored fixtures (quiz data, not claims
// about a real incident — same "fabricating a plausible fixture is fine"
// rule this site's other drills already follow).
//
// 8 of the 11 challenges additionally ship `hiddenTestCases` — see
// RegexRangeChallenge's own doc comment and the comment above
// REGEX_RANGE_CHALLENGES below for what these catch and why the remaining 3
// (anchors, escaping, lookahead) were deliberately left without one.

import { compileRegexSafely, findAllMatches } from '../../utils/regexPatterns';

export interface RegexRangeChallenge {
  id: string;
  concept: string;
  prompt: string;
  testCases: { text: string; shouldMatch: boolean }[];
  explanation: string;
  hint: string;
  /** One verified-working reference pattern (not shown to the learner directly — see the page's own "give up" affordance, if any). */
  referenceSolution: string;
  referenceHref?: string;
  referenceLabel?: string;
  /** Never shown to the learner — checked only after every visible testCases
   *  entry already passes, to catch a pattern that fits only the shown
   *  samples rather than the taught concept (e.g. a literal-text challenge
   *  "solved" with just a matching prefix, or a quantifier challenge
   *  "solved" by checking for scattered occurrences instead of a run). Every
   *  entry here was verified two ways (see test/regexDrill.test.ts and this
   *  file's own header comment): the authored `referenceSolution` passes it,
   *  and a concrete "wrong concept, still fits every visible sample"
   *  pattern fails it. Only added where such a real gap could be
   *  constructed — see this array's own doc comment on `REGEX_RANGE_CHALLENGES`
   *  for which challenges were left without one and why. */
  hiddenTestCases?: { text: string; shouldMatch: boolean }[];
}

// 8 of the 11 challenges below carry `hiddenTestCases` — added after an
// audit for "does it actually generalize?" gaps: a wrong-concept pattern
// that fits every VISIBLE sample by accident rather than actually solving
// what the challenge teaches. Each one was verified two ways with this
// file's own compileRegexSafely/findAllMatches (see test/regexDrill.test.ts):
// the authored referenceSolution passes it, and a concrete "wrong but fits
// every visible case" pattern fails it. The remaining 3 — anchors, escaping,
// lookahead — were checked the same way and left alone:
//   - anchors: every plausible "forgot the anchor" or "anchored the wrong
//     thing" mistake (plain `ERROR`, `^.*ERROR`) already gets caught by the
//     existing visible cases (`Got ERROR from server` / `MINOR_ERROR_CODE`).
//   - escaping: every plausible "forgot to escape the dot" mistake (plain
//     `4624.`, or `462[0-9].` with an unescaped trailing dot) already fails
//     the existing visible "extra digit"/"extra character" cases — that's
//     the exact gap those cases were built to catch.
//   - lookahead: the reference solution itself is a document-wide condition
//     (each `(?=...)` can be satisfied by a digit/uppercase anywhere in the
//     whole string, not scoped to one contiguous token) — any hidden case
//     built to expose that scoping gap would fail the REFERENCE solution
//     too (verified), so there's no fair "wrong pattern only" gap to add
//     here without also breaking the reference.
export const REGEX_RANGE_CHALLENGES: RegexRangeChallenge[] = [
  {
    id: 'literals',
    concept: 'Literal characters',
    prompt: 'Find any mention of PowerShell in a log line. Plain characters in a regex match themselves — no special syntax needed yet.',
    testCases: [
      { text: 'powershell.exe launched', shouldMatch: true },
      { text: 'detected: powershell -nop -w hidden', shouldMatch: true },
      { text: 'started a new powershell session', shouldMatch: true },
      { text: 'cmd.exe launched', shouldMatch: false },
      { text: 'wscript.exe running', shouldMatch: false },
      { text: 'started a new cmd session', shouldMatch: false },
    ],
    hint: 'Just type the word you want to find — regular expressions match literal text by default.',
    explanation: 'powershell (or any pattern containing it) matches every should-match case because plain characters match themselves literally. This is the baseline every other regex feature builds on top of.',
    referenceSolution: 'powershell',
    // Catches a partial-prefix "solution" like `power` — none of the visible
    // should-NOT-match cases happen to contain "power" outside of
    // "powershell", so a prefix shortcut fits every shown sample but was
    // never actually asked to match the full word. Verified: `power` passes
    // all 6 visible cases here but wrongly matches this hidden one.
    hiddenTestCases: [{ text: 'power outage detected on the UPS', shouldMatch: false }],
  },
  {
    id: 'character-classes',
    concept: 'Character classes ([...])',
    prompt: 'Match a drive-letter reference to C:, D:, or E: — but not other drive letters. [ABC] matches any ONE of the characters inside the brackets.',
    testCases: [
      { text: 'Files copied to C:\\Temp', shouldMatch: true },
      { text: 'Backup on D:', shouldMatch: true },
      { text: 'Mounted E:\\ as new volume', shouldMatch: true },
      { text: 'Files copied to F:\\Temp', shouldMatch: false },
      { text: 'Backup on Z:', shouldMatch: false },
      { text: 'Mounted A:\\ as new volume', shouldMatch: false },
    ],
    hint: 'A character class [XYZ] matches exactly one character, as long as it is X, Y, or Z.',
    explanation: "[CDE]: matches a single C, D, or E immediately followed by a colon — a bracket character class is an OR across individual characters, distinct from alternation (|) which ORs whole sub-patterns (you'll meet that in a later challenge).",
    referenceSolution: '[CDE]:',
    // Catches dropping the colon entirely (`[CDE]` alone) — none of the
    // visible should-NOT-match cases happen to contain a stray uppercase
    // C/D/E elsewhere, so the class-without-colon fits every shown sample
    // without ever actually requiring "drive letter followed by a colon".
    // Verified: `[CDE]` passes all 6 visible cases but wrongly matches this
    // hidden one (a bare uppercase D with no colon in sight).
    hiddenTestCases: [{ text: 'Report card D listed as final', shouldMatch: false }],
  },
  {
    id: 'quantifiers',
    concept: 'Digit ranges & quantifiers ({n,})',
    prompt: 'Match a process-ID-looking reference of 4 or more digits in a row (real Windows PIDs are rarely shorter).',
    testCases: [
      { text: 'PID 4624', shouldMatch: true },
      { text: 'pid=88213', shouldMatch: true },
      { text: 'spawned process 10245', shouldMatch: true },
      { text: 'PID 42', shouldMatch: false },
      { text: 'pid=7', shouldMatch: false },
      { text: 'spawned process 913', shouldMatch: false },
    ],
    hint: '\\d matches one digit. A quantifier like {4,} right after something means "four or more in a row", with no upper limit.',
    explanation: '\\d{4,} (equally [0-9]{4,}) matches four or more consecutive digits. {min,} with nothing after the comma means "at least min, unlimited max" — {min,max} would cap it, and {exact} would require exactly that many.',
    referenceSolution: '\\d{4,}',
    // Catches a pattern that checks for four digits scattered ANYWHERE in
    // the string rather than four IN A ROW (e.g. `\d.*\d.*\d.*\d`). Every
    // visible should-match case's digits happen to be contiguous, and every
    // visible should-NOT-match case has fewer than 4 digits total — so the
    // "4 digits somewhere" misreading fits every shown sample without ever
    // being asked to reject a string with 4+ digits that AREN'T consecutive.
    // Verified: `\d.*\d.*\d.*\d` passes all 6 visible cases but wrongly
    // matches this hidden one (4 digits present, none of them adjacent).
    hiddenTestCases: [{ text: 'user42 has 99 items', shouldMatch: false }],
  },
  {
    id: 'anchors',
    concept: 'Anchors (^ start / $ end)',
    prompt: 'Match lines that START with the word ERROR — not lines where ERROR merely appears somewhere inside.',
    testCases: [
      { text: 'ERROR: access denied', shouldMatch: true },
      { text: 'ERROR failed to bind port', shouldMatch: true },
      { text: 'Got ERROR from server', shouldMatch: false },
      { text: 'MINOR_ERROR_CODE set', shouldMatch: false },
      { text: 'an ERROR occurred', shouldMatch: false },
    ],
    hint: '^ anchors a pattern to the very beginning of the string — it does not match any character itself, it just fixes the position.',
    explanation: "^ERROR only matches when ERROR is the very first thing in the string. Without the anchor, plain ERROR would also match 'Got ERROR from server' — exactly what the should-NOT-match cases are testing for.",
    referenceSolution: '^ERROR',
  },
  {
    id: 'alternation',
    concept: 'Alternation (|)',
    prompt: 'Match a mention of one of three commonly-abused script extensions: vbs, ps1, or bat.',
    testCases: [
      { text: 'payload.vbs dropped', shouldMatch: true },
      { text: 'run.ps1 executed', shouldMatch: true },
      { text: 'install.bat triggered', shouldMatch: true },
      { text: 'notes.txt saved', shouldMatch: false },
      { text: 'report.pdf opened', shouldMatch: false },
      { text: 'image.png created', shouldMatch: false },
    ],
    hint: 'A|B|C matches any ONE of A, B, or C — an OR across whole sub-patterns, not single characters like a character class.',
    explanation: 'vbs|ps1|bat matches any one of three literal alternatives. Alternation is how a single pattern accepts several genuinely different substrings, not just different single characters.',
    referenceSolution: 'vbs|ps1|bat',
    // Catches dropping the trailing "1" (`vbs|ps|bat`) — "ps" alone still
    // happens to appear inside "run.ps1 executed" (as a substring of "ps1"),
    // and none of the visible should-NOT-match cases coincidentally contain
    // a stray "ps", so the truncated alternative fits every shown sample
    // without ever actually requiring the ".ps1" extension. Verified:
    // `vbs|ps|bat` passes all 6 visible cases but wrongly matches this
    // hidden one ("helps.txt" contains "ps" but isn't a ps1 script).
    hiddenTestCases: [{ text: 'the coach helps.txt was modified', shouldMatch: false }],
  },
  {
    id: 'escaping',
    concept: 'Escaping special characters (\\.)',
    prompt: "Match the literal text '4624' followed by a period — but not '4624' followed by any OTHER single character. A bare . normally matches ANY character.",
    testCases: [
      { text: 'Event 4624. Logon successful', shouldMatch: true },
      { text: 'ref 4624.', shouldMatch: true },
      { text: 'Event 46249 was logged', shouldMatch: false },
      { text: 'value 4624X noted', shouldMatch: false },
      { text: 'code 46245', shouldMatch: false },
    ],
    hint: 'Escape a special character with a backslash to make it literal: \\. matches an actual period, not "any character".',
    explanation: "4624\\. escapes the dot so it matches a literal period only. Without the backslash, . would match ANY character right after 4624 — including the '9' in '46249' and the 'X' in '4624X', which is exactly what those should-NOT-match cases are built to catch.",
    referenceSolution: '4624\\.',
  },
  {
    id: 'word-boundaries',
    concept: 'Word boundaries (\\b)',
    prompt: "Match the standalone word 'admin' as a username — not as part of a longer word like 'administrator' or 'badmin'.",
    testCases: [
      { text: 'user: admin logged in', shouldMatch: true },
      { text: 'login as admin failed', shouldMatch: true },
      { text: 'administrator account used', shouldMatch: false },
      { text: 'badmin_tool.exe run', shouldMatch: false },
      { text: 'administered by IT', shouldMatch: false },
    ],
    hint: '\\b matches the invisible boundary between a word character and a non-word character (or the start/end of the string) — it consumes no characters itself.',
    explanation: "\\badmin\\b only matches 'admin' as a complete word. The boundaries on each side stop it from also matching inside 'administrator' or 'badmin_tool' — without them, plain admin would match all five test cases, not just the first two.",
    referenceSolution: '\\badmin\\b',
    // Catches substituting literal spaces for \b (` admin ` instead of
    // \badmin\b) — every visible should-match case happens to have a space
    // on both sides of "admin", and every visible should-NOT-match case
    // lacks one, so the literal-space version fits every shown sample
    // without ever being asked to handle "admin" at the very start of a
    // string (a real word boundary — start-of-string counts — but not a
    // literal space character). Verified: ` admin ` passes all 5 visible
    // cases but wrongly fails to match this hidden one.
    hiddenTestCases: [{ text: 'admin escalated privileges', shouldMatch: true }],
  },
  {
    id: 'negated-classes',
    concept: 'Negated character classes ([^...])',
    prompt: 'Match a bracketed severity tag that is NOT [INFO] — e.g. [WARN], [ERROR], [CRIT]. A caret right after the opening bracket of a character class negates it.',
    testCases: [
      { text: '[WARN] disk space low', shouldMatch: true },
      { text: '[ERROR] connection refused', shouldMatch: true },
      { text: '[CRIT] service crashed', shouldMatch: true },
      { text: '[INFO] service started', shouldMatch: false },
      { text: '[INFO] heartbeat ok', shouldMatch: false },
    ],
    hint: "[^X] matches any ONE character that is NOT X. You only need to rule out enough to separate this data — you don't need to spell out every tag that should match.",
    explanation: "\\[[^I] matches an opening bracket followed by any character that isn't 'I'. Since INFO is the only tag here starting with I, that's enough to separate it from WARN/ERROR/CRIT — a classic minimal-pattern move: exploit whatever detail actually distinguishes YOUR data, rather than exhaustively spelling out every valid tag. A more bulletproof real-world version would use a negative lookahead, \\[(?!INFO\\]) — you'll meet lookaheads in a later challenge.",
    referenceSolution: '\\[[^I]',
    // Catches enumerating the exact three tags shown (`\[(WARN|ERROR|CRIT)\]`)
    // instead of actually negating on the distinguishing character — every
    // visible should-match case IS one of those three tags, so the
    // hardcoded list fits every shown sample without ever being asked about
    // a fourth, never-shown tag. Verified: the enumeration passes all 5
    // visible cases but wrongly fails to match this hidden one (a new tag,
    // not [INFO], that the real "not-I" rule handles fine).
    hiddenTestCases: [{ text: '[DEBUG] verbose trace enabled', shouldMatch: true }],
  },
  {
    id: 'backreferences',
    concept: 'Capturing groups & backreferences (\\1)',
    prompt: 'Detect a word typed twice in a row with a space between (a common paste-duplication artifact) — match only when the SAME word repeats.',
    testCases: [
      { text: 'the the file was deleted', shouldMatch: true },
      { text: 'user user logged in twice', shouldMatch: true },
      { text: 'error error repeated in log', shouldMatch: true },
      { text: 'the file was deleted', shouldMatch: false },
      { text: 'a user logged in', shouldMatch: false },
      { text: 'an error occurred once', shouldMatch: false },
    ],
    hint: 'Wrap part of your pattern in ( ) to capture it, then refer back to exactly what it captured with \\1.',
    explanation: '(\\w+) captures a run of word characters, and \\1 requires that SAME captured text to appear again right after a space. A backreference is the only way to require two parts of a match to be identical without knowing the word in advance — you cannot express "whatever this matched, again" with a character class or quantifier alone.',
    referenceSolution: '\\b(\\w+) \\1\\b',
    // Catches enumerating the exact three repeated words shown
    // (`\b(the the|user user|error error)\b`) instead of a real backreference
    // — every visible should-match case IS one of those three pairs, so the
    // hardcoded list fits every shown sample without ever proving it can
    // detect an arbitrary repeated word. Verified: the enumeration passes
    // all 6 visible cases but wrongly fails to match this hidden one (a
    // fourth, never-shown word repeated the same way).
    hiddenTestCases: [{ text: 'please please respond quickly', shouldMatch: true }],
  },
  {
    id: 'lookahead',
    concept: 'Lookahead ((?=...))',
    prompt: 'Match a credential-looking token containing BOTH a digit and an uppercase letter, in any order.',
    testCases: [
      { text: 'key: Ab3xkT9', shouldMatch: true },
      { text: 'token=aB1', shouldMatch: true },
      { text: 'secret9X', shouldMatch: true },
      { text: 'key: abcxyz', shouldMatch: false },
      { text: 'token=123456', shouldMatch: false },
      { text: 'secret_only_lower', shouldMatch: false },
    ],
    hint: '(?=...) checks that something appears ahead WITHOUT consuming any characters. Stack two of them to require both conditions, regardless of which comes first.',
    explanation: '(?=.*[0-9]) asserts a digit exists somewhere ahead; (?=.*[A-Z]) asserts an uppercase letter exists somewhere ahead. Together they require both, in either order — an order-independent AND. A sequential pattern like [0-9].*[A-Z]|[A-Z].*[0-9] could do the same for two conditions, but a lookahead chain stays simple as more conditions stack up, where the alternation approach grows combinatorially worse.',
    referenceSolution: '(?=.*[0-9])(?=.*[A-Z])',
  },
  {
    id: 'capstone',
    concept: 'Putting it together — a real IPv4 matcher',
    prompt: 'Final challenge: match a genuine IPv4 address — four dot-separated numbers, each in the real 0–255 range — while correctly REJECTING an out-of-range octet like 300 or 999. Counting digits alone will not be enough here.',
    testCases: [
      { text: 'Connection from 192.168.1.10', shouldMatch: true },
      { text: 'src=10.0.0.255', shouldMatch: true },
      { text: '8.8.8.8 responded', shouldMatch: true },
      { text: '0.0.0.0 bound', shouldMatch: true },
      { text: 'Connection from 300.168.1.10', shouldMatch: false },
      { text: 'src=10.0.256.5', shouldMatch: false },
      { text: '192.168.1.999 pinged', shouldMatch: false },
      { text: '999.999.999.999 invalid', shouldMatch: false },
    ],
    hint: 'Break each octet down by how many digits it has: 250–255, or 200–249, or 100–199, or 0–99. Write each range as its own alternative inside one group, then repeat that whole group 3 more times separated by literal dots.',
    explanation: "This is a simplified form of the exact pattern this site's own Regex Tester ships with for IPv4 detection (see the Pattern library above, or the live tool linked below). Counting digits alone (\\d{1,3} four times) is not enough — it would also accept '300' or '999' as a valid octet, which is exactly what the should-NOT-match cases test for. Range-checking each octet with alternation — 25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d — is what correctly rejects an out-of-range value while still accepting every real 0–255 octet.",
    referenceSolution: '\\b(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}\\b',
    referenceHref: '/tools/regex-tester/',
    referenceLabel: 'See the full pattern in the Regex Tester',
    // Catches blacklisting the exact three invalid octets shown (300, 256,
    // 999) via a negative lookahead instead of doing real 0–255 range
    // checking — every visible should-NOT-match case uses one of those
    // three values, so the blacklist fits every shown sample without ever
    // being asked about a DIFFERENT out-of-range octet. Verified: the
    // blacklist pattern passes all 8 visible cases but wrongly matches this
    // hidden one (octet 260 — out of range, but not one of the blacklisted
    // three).
    hiddenTestCases: [{ text: 'gateway at 192.168.1.260 is unreachable', shouldMatch: false }],
  },
];

export const REGEX_DRILL_TOTAL = REGEX_RANGE_CHALLENGES.length;

/** Compiles `userPattern` (always case-sensitive — every challenge above was
 *  deliberately written so no challenge needs the `i` flag, keeping the UI to
 *  a single pattern input with no separate flags field) and runs it against
 *  every one of `challenge`'s VISIBLE test cases using the exact same pure
 *  functions the live Regex Tester uses. If every visible case passes and the
 *  challenge also ships `hiddenTestCases` (never shown to the learner — see
 *  RegexRangeChallenge's own doc comment), those are checked too: any hidden
 *  failure means the pattern only fit the shown samples, not the taught
 *  concept, so this returns `pass: false` (never `pass: true`) plus a
 *  `generalizationGap` naming the first such failure — matching the exact
 *  DrillValidateResult contract drillEngine.ts's handleConstructCheck reads. */
function validateChallenge(challenge: RegexRangeChallenge, userPattern: string) {
  const compiled = compileRegexSafely(userPattern, '');
  if (!compiled.ok) return { ok: false as const, error: compiled.error };
  const results = challenge.testCases.map((tc) => ({
    text: tc.text,
    shouldMatch: tc.shouldMatch,
    actualMatch: findAllMatches(compiled.regex, tc.text).length > 0,
  }));
  const visiblePass = results.every((r) => r.actualMatch === r.shouldMatch);
  if (visiblePass && challenge.hiddenTestCases && challenge.hiddenTestCases.length > 0) {
    for (const tc of challenge.hiddenTestCases) {
      const actualMatch = findAllMatches(compiled.regex, tc.text).length > 0;
      if (actualMatch !== tc.shouldMatch) {
        return {
          ok: true as const,
          pass: false,
          results,
          generalizationGap: { text: tc.text, shouldMatch: tc.shouldMatch, actualMatch },
        };
      }
    }
  }
  return { ok: true as const, pass: visiblePass, results };
}

/** Pure, deterministic function of `index` (wraps via modulo) — see
 *  DrillEngine.astro's header comment on why nextQuestion(0) must be
 *  deterministic (its SSR firstQuestion prop and the client's own mount-time
 *  call must agree). */
export function getRegexDrillQuestion(index: number) {
  const len = REGEX_RANGE_CHALLENGES.length;
  const challenge = REGEX_RANGE_CHALLENGES[((index % len) + len) % len];
  return {
    prompt: challenge.prompt,
    explanation: challenge.explanation,
    referenceHref: challenge.referenceHref,
    referenceLabel: challenge.referenceLabel,
    answerType: 'construct' as const,
    correctAnswer: challenge.referenceSolution,
    testCases: challenge.testCases,
    hint: challenge.hint,
    validate: (userAnswer: string) => validateChallenge(challenge, userAnswer),
  };
}
