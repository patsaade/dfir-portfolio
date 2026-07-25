// Regex Syntax Cheat Sheet — a token-by-token reference for JavaScript/ECMAScript
// regular-expression SYNTAX (anchors, character classes, quantifiers, groups,
// lookaround, flags, escapes, replacement patterns, and the RegExp/String API
// surface), distinct from src/utils/regexPatterns.ts's DFIR_REGEX_PATTERNS —
// that's a curated library of pre-built, ready-to-use patterns (IPv4, SID,
// GUID, ...); this is the underlying grammar those patterns (and any pattern
// you write yourself) are built from. Every entry describes the exact engine
// this site actually runs: native `new RegExp(pattern, flags)`, invoked
// through regexPatterns.ts's own compileRegexSafely() — the same engine
// behind the Regex Tester, the RegEx Range Drill, and Sigma's `|re` field
// modifier (SigmaTester runs it through the identical compileRegexSafely()
// call). It is NOT PCRE/PCRE2, Python's `re`, POSIX BRE/ERE, or any other
// regex flavor — several constructs common in those engines don't exist in
// JavaScript at all:
//
//   - No possessive quantifiers (*+, ++, ?+, {n,m}+) — PCRE2 has them.
//   - No atomic groups ((?>...)) — PCRE2 has them; JS can only approximate
//     the effect with a lookahead+backreference trick, (?=(pattern))\1.
//   - No recursive patterns or subroutine calls ((?R), (?1), (?&name)).
//   - No backtracking-control verbs (*COMMIT, *PRUNE, *SKIP, *THEN, *FAIL).
//   - No Python-style named groups — JS supports only (?<name>...) with
//     \k<name> backreferences, not PCRE2/Python's alternate (?P<name>...)
//     and (?P=name) syntax.
//   - No /x "extended/verbose" flag for whitespace-insensitive patterns with
//     inline comments.
//
// These are deliberate omissions from JS itself, not gaps in this reference —
// there's no JS syntax entry to document for a construct JS doesn't have.
// Everywhere JS syntax genuinely differs in behavior from what a PCRE2/Python
// background might assume (lookbehind's late ES2018 arrival and patchier
// older-browser support, \p{...}/\P{...} needing an explicit u/v flag where
// PCRE2 uses a separate UCP option, un-flagged . / character classes
// splitting a supplementary-plane character across its UTF-16 surrogate
// pair), the entry's own description below calls it out inline.
//
// Content is sourced from WebFetch-verified research (MDN's JavaScript
// regex Guide + Reference, the ECMA-262 spec) — see externalResources.ts's
// 'regex-cheatsheet' entry for the citations. Entries are pure data with no
// authored embellishment; add to a category by appending an entry, or add a
// new category by introducing a new `category` value (the page groups
// entries by first-occurrence order, so category order here IS display order).

export interface RegexSyntaxEntry {
  category: string;
  syntax: string;
  description: string;
  example: string;
}

export const REGEX_CHEAT_SHEET: RegexSyntaxEntry[] = [
  {
    category: "Anchors & Boundaries",
    syntax: "^",
    description: "Matches the start of the string, or the start of a line when the m (multiline) flag is set.",
    example: "/^ERROR/m flags every line that begins with \"ERROR\" in a multi-line log paste.",
  },
  {
    category: "Anchors & Boundaries",
    syntax: "$",
    description: "Matches the end of the string, or the end of a line when the m flag is set.",
    example: "/\\.ps1$/i matches a line ending in the literal \".ps1\" extension.",
  },
  {
    category: "Anchors & Boundaries",
    syntax: "\\b",
    description: "Zero-width word boundary — matches the position between a \\w character and a non-word character (or a string edge).",
    example: "/\\bcmd\\.exe\\b/ matches \"cmd.exe\" as a distinct token in \"ran cmd.exe -c whoami\", not a bare substring.",
  },
  {
    category: "Anchors & Boundaries",
    syntax: "\\B",
    description: "Zero-width non-boundary — matches a position where \\b would NOT match (between two word characters, or two non-word characters).",
    example: "/\\Bnet\\B/ matches \"net\" inside \"subnet\" but not the standalone word \"net\".",
  },
  {
    category: "Character Classes",
    syntax: ".",
    description: "Matches any single character except line terminators, unless the s (dotAll) flag is set.",
    example: "/power.hell/i matches \"powershell\" — the dot stands in for the 's'.",
  },
  {
    category: "Character Classes",
    syntax: "\\d",
    description: "Matches a single decimal digit; equivalent to [0-9].",
    example: "/\\d{4}/ pulls the 4-digit code out of \"Event ID 4624\".",
  },
  {
    category: "Character Classes",
    syntax: "\\D",
    description: "Matches any character that is not a decimal digit; equivalent to [^0-9].",
    example: "/\\D+/ matches the \"PID-\" prefix in \"PID-4821\".",
  },
  {
    category: "Character Classes",
    syntax: "\\w",
    description: "Matches a \"word\" character: any of [A-Za-z0-9_] — ASCII only, it does not match accented or non-Latin letters.",
    example: "/\\w+\\.dll/ matches \"kernel32.dll\"'s filename portion.",
  },
  {
    category: "Character Classes",
    syntax: "\\W",
    description: "Matches any character that is not a word character; equivalent to [^A-Za-z0-9_].",
    example: "/\\W/ matches the hyphens inside \"S-1-5-21-...\".",
  },
  {
    category: "Character Classes",
    syntax: "\\s",
    description: "Matches a whitespace character — JS's built-in \\s is broader than just space/tab/newline; it also covers several Unicode space separators and line terminators.",
    example: "/\\s+/ splits fields apart in a space-padded fixed-width log line.",
  },
  {
    category: "Character Classes",
    syntax: "\\S",
    description: "Matches any non-whitespace character.",
    example: "/\\S+@\\S+/ grabs the non-space local-part@domain chunk of an email out of surrounding log text.",
  },
  {
    category: "Character Classes",
    syntax: "[...]",
    description: "Character class — matches any one character listed inside the brackets; most metacharacters lose their special meaning inside a class.",
    example: "/[A-Fa-f0-9]/ matches a single hex digit, the building block of a hash or GUID pattern.",
  },
  {
    category: "Character Classes",
    syntax: "[^...]",
    description: "Negated character class — matches any one character NOT listed inside the brackets.",
    example: "/[^\\\\]+/ matches one path segment up to the next backslash in a Windows path.",
  },
  {
    category: "Character Classes",
    syntax: "[a-z]",
    description: "A range inside a character class — matches any single character between the two endpoints, inclusive.",
    example: "/[0-9A-Fa-f]{40}/ matches a bare SHA-1 hex digest.",
  },
  {
    category: "Character Classes",
    syntax: "\\p{...}",
    description: "Unicode property escape — matches any character with the given Unicode property or script; requires the u or v flag, otherwise \\p is just a literal \"p\".",
    example: "/\\p{Script=Cyrillic}/u flags a Cyrillic character hiding in an otherwise-Latin domain name (a homoglyph/IDN-spoofing tell).",
  },
  {
    category: "Character Classes",
    syntax: "\\P{...}",
    description: "Negated Unicode property escape — matches any character that does NOT have the given property; also requires u or v.",
    example: "/\\P{ASCII}/u finds the first non-ASCII byte in a string dump suspected of encoding-based obfuscation.",
  },
  {
    category: "Quantifiers",
    syntax: "*",
    description: "Matches the preceding element zero or more times, greedily.",
    example: "/0*4624/ matches \"4624\" or a zero-padded \"004624\".",
  },
  {
    category: "Quantifiers",
    syntax: "+",
    description: "Matches the preceding element one or more times, greedily.",
    example: "/\\d+/ captures the full digit run of a PID rather than stopping at one digit.",
  },
  {
    category: "Quantifiers",
    syntax: "?",
    description: "Matches the preceding element zero or one times (makes it optional).",
    example: "/https?:\\/\\// matches both \"http://\" and \"https://\".",
  },
  {
    category: "Quantifiers",
    syntax: "{n}",
    description: "Matches the preceding element exactly n times.",
    example: "/[A-Fa-f0-9]{32}/ matches a bare MD5 hex digest.",
  },
  {
    category: "Quantifiers",
    syntax: "{n,}",
    description: "Matches the preceding element n or more times.",
    example: "/[A-Za-z0-9+/]{20,}/ matches a base64-looking run of 20+ characters.",
  },
  {
    category: "Quantifiers",
    syntax: "{n,m}",
    description: "Matches the preceding element between n and m times, inclusive.",
    example: "/\\d{1,3}/ matches one candidate IPv4 octet, 1 to 3 digits long.",
  },
  {
    category: "Quantifiers",
    syntax: "*?",
    description: "Lazy version of * — matches as few repetitions as possible, only backtracking to take more if the rest of the pattern requires it.",
    example: "/<.*?>/ matches just \"<a>\" out of \"<a><b>\" instead of greedily swallowing to the final \">\".",
  },
  {
    category: "Quantifiers",
    syntax: "+?",
    description: "Lazy version of + — matches the fewest repetitions (at least one) needed for the overall match to succeed.",
    example: "/\".+?\"/ matches the first quoted field in a CSV log row instead of everything up to the last quote.",
  },
  {
    category: "Quantifiers",
    syntax: "??",
    description: "Lazy version of ? — prefers to match zero occurrences, only taking one if required.",
    example: "/colou??r/ tries to match \"color\" first, backtracking to also match \"colour\" when needed.",
  },
  {
    category: "Quantifiers",
    syntax: "{n,m}?",
    description: "Lazy version of {n,m} — matches as close to the minimum n as possible.",
    example: "/\\d{2,4}?/ against \"123456\" matches just \"12\", the 2-digit minimum, rather than grabbing up to 4.",
  },
  {
    category: "Groups & Backreferences",
    syntax: "(...)",
    description: "Capturing group — groups a sub-pattern and remembers the text it matched, numbered by the order of its opening parenthesis.",
    example: "/(\\d{1,3}\\.){3}\\d{1,3}/ groups each octet-and-dot chunk of a loosely-matched IPv4 address.",
  },
  {
    category: "Groups & Backreferences",
    syntax: "(?:...)",
    description: "Non-capturing group — groups a sub-pattern (e.g. for alternation or a quantifier) without creating a numbered capture.",
    example: "/(?:HKLM|HKEY_LOCAL_MACHINE)\\\\/ groups the hive-name alternation without adding an extra capture slot.",
  },
  {
    category: "Groups & Backreferences",
    syntax: "(?<name>...)",
    description: "Named capturing group — same as a numbered group, but also accessible by name via the match's .groups object.",
    example: "/(?<hive>HK[A-Z]+)\\\\(?<key>.+)/ exposes match.groups.hive and match.groups.key separately.",
  },
  {
    category: "Groups & Backreferences",
    syntax: "|",
    description: "Alternation — matches whichever of the patterns on either side succeeds first.",
    example: "/\\.exe$|\\.dll$|\\.scr$/i flags a line ending in any one of three suspicious extensions.",
  },
  {
    category: "Groups & Backreferences",
    syntax: "\\1, \\2, ...",
    description: "Numbered backreference — matches the same text that a previous numbered capturing group matched.",
    example: "/(['\"]).*?\\1/ matches a quoted string, requiring the closing quote to match whichever one opened it.",
  },
  {
    category: "Groups & Backreferences",
    syntax: "\\k<name>",
    description: "Named backreference — matches the same text a previous named capturing group matched.",
    example: "/(?<q>['\"]).*?\\k<q>/ is the named-group equivalent of the numbered backreference above.",
  },
  {
    category: "Groups & Backreferences",
    syntax: "(?:...)?",
    description: "An optional non-capturing group — a common way to make a whole clause optional without capturing it.",
    example: "/Get-Process(?:\\s+-Name\\s+\\S+)?/ matches the command with or without its -Name argument.",
  },
  {
    category: "Lookaround (Lookahead/Lookbehind)",
    syntax: "(?=...)",
    description: "Positive lookahead — asserts that the given pattern matches immediately after the current position, without consuming those characters.",
    example: "/\\d+(?=\\s*bytes)/ captures \"4096\" from \"Size: 4096 bytes\" without including \" bytes\" in the match.",
  },
  {
    category: "Lookaround (Lookahead/Lookbehind)",
    syntax: "(?!...)",
    description: "Negative lookahead — asserts that the given pattern does NOT match immediately after the current position.",
    example: "/powershell(?!\\.exe)/i matches a \"powershell\" reference that isn't immediately followed by \".exe\".",
  },
  {
    category: "Lookaround (Lookahead/Lookbehind)",
    syntax: "(?<=...)",
    description: "Positive lookbehind — asserts that the given pattern matches immediately before the current position, without consuming those characters. A comparatively late addition to JS (ES2018); very old browser engines may lack it.",
    example: "/(?<=PID:\\s)\\d+/ captures \"4821\" from \"explorer.exe PID: 4821\" without including the \"PID: \" label.",
  },
  {
    category: "Lookaround (Lookahead/Lookbehind)",
    syntax: "(?<!...)",
    description: "Negative lookbehind — asserts that the given pattern does NOT match immediately before the current position.",
    example: "/(?<!\\.)\\bexe\\b/ matches a bare word \"exe\" but skips the \"exe\" inside a \".exe\" file extension.",
  },
  {
    category: "Flags",
    syntax: "g",
    description: "Global — find all matches in the string instead of stopping after the first, and makes exec()/replaceAll() scan forward via lastIndex.",
    example: "/\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/g finds every IPv4-shaped string in a whole log file, not just the first.",
  },
  {
    category: "Flags",
    syntax: "i",
    description: "Case-insensitive — letters match regardless of case.",
    example: "/malicious/i matches \"Malicious\", \"MALICIOUS\", and \"malicious\" alike.",
  },
  {
    category: "Flags",
    syntax: "m",
    description: "Multiline — makes ^ and $ additionally match right after/before line terminators, not just the string's absolute start/end.",
    example: "/^Error:/m flags every line starting with \"Error:\" in a multi-line paste, not just the first one.",
  },
  {
    category: "Flags",
    syntax: "s",
    description: "dotAll — lets . also match line terminators, which it otherwise excludes.",
    example: "/-----BEGIN.*END-----/s matches across the newlines inside a multi-line PEM-style block.",
  },
  {
    category: "Flags",
    syntax: "u",
    description: "Unicode — treats the pattern as a sequence of Unicode code points rather than raw UTF-16 code units, enables \\u{...} and \\p{...}/\\P{...} escapes, and rejects several otherwise-lenient escape typos. Without it, a supplementary-plane character (like most emoji) can be split into its two surrogate halves by . or a character class.",
    example: "/\\u{1F4BE}/u matches a single floppy-disk emoji code point as one unit.",
  },
  {
    category: "Flags",
    syntax: "v",
    description: "unicodeSets — a strict superset of u (added in ES2024) that additionally allows set operations (union, intersection, subtraction) inside character classes; u and v cannot both be set on the same pattern.",
    example: "/[\\p{Emoji}--\\p{ASCII}]/v matches an emoji character while excluding plain ASCII.",
  },
  {
    category: "Flags",
    syntax: "y",
    description: "Sticky — matches only starting exactly at lastIndex, without scanning forward to find the next possible match position.",
    example: "Repeated regex.exec() calls with y set can tokenize a log line field-by-field from a moving cursor, instead of free-scanning ahead.",
  },
  {
    category: "Flags",
    syntax: "d",
    description: "hasIndices — makes the match result carry an additional .indices array (and .indices.groups for named groups) giving each match/group's [start, end] character offsets.",
    example: "/(?<ts>\\d{4}-\\d{2}-\\d{2})/d exposes exactly which offsets in the original string the ts capture spanned.",
  },
  {
    category: "Escape Sequences & Special Characters",
    syntax: "\\\\",
    description: "Escapes a following regex metacharacter so it is matched as a literal character.",
    example: "/C:\\\\Windows\\\\System32/ matches a literal Windows path with real backslash separators.",
  },
  {
    category: "Escape Sequences & Special Characters",
    syntax: "\\.",
    description: "Matches a literal dot character (a bare . means \"any character\").",
    example: "/\\.evtx$/ matches a filename ending in the literal \".evtx\" extension.",
  },
  {
    category: "Escape Sequences & Special Characters",
    syntax: "\\n",
    description: "Matches a line feed (LF, U+000A) character.",
    example: "/\\r?\\n/ splits a raw multi-line log blob into individual lines, whether it uses CRLF or bare LF endings.",
  },
  {
    category: "Escape Sequences & Special Characters",
    syntax: "\\r",
    description: "Matches a carriage return (CR, U+000D) character.",
    example: "Paired with \\n above to handle Windows-style CRLF line endings in exported log files.",
  },
  {
    category: "Escape Sequences & Special Characters",
    syntax: "\\t",
    description: "Matches a horizontal tab character.",
    example: "/\\t/ splits fields in a tab-separated (TSV) triage export.",
  },
  {
    category: "Escape Sequences & Special Characters",
    syntax: "\\0",
    description: "Matches the NUL (U+0000) character, as long as it isn't immediately followed by another digit.",
    example: "/\\0/ flags an embedded NUL byte inside what should have been a clean ASCII string.",
  },
  {
    category: "Escape Sequences & Special Characters",
    syntax: "\\xHH",
    description: "Matches the character with the given 2-digit hexadecimal code (the Latin-1 range, 00–FF).",
    example: "/\\x00/ is the hex-escaped equivalent of matching a NUL byte.",
  },
  {
    category: "Escape Sequences & Special Characters",
    syntax: "\\uHHHH",
    description: "Matches the UTF-16 code unit with the given 4-digit hexadecimal code.",
    example: "/\\u200B/ matches a zero-width space, sometimes inserted mid-word to defeat naive keyword matching (e.g. an invisible character hidden inside \"paypal\").",
  },
  {
    category: "Escape Sequences & Special Characters",
    syntax: "\\u{HHHHH}",
    description: "Matches the full Unicode code point with the given hex value (1–6 digits); requires the u or v flag. Correctly matches supplementary-plane characters as one unit instead of splitting their UTF-16 surrogate pair.",
    example: "/\\u{1F600}/u matches a single emoji code point above the Basic Multilingual Plane.",
  },
  {
    category: "Escape Sequences & Special Characters",
    syntax: "[\\b]",
    description: "Inside a character class only, \\b means the backspace control character (U+0008) — not a word boundary; \\b only means \"word boundary\" outside a character class.",
    example: "[\\b] would match a literal backspace byte occasionally found in raw terminal-capture artifacts.",
  },
  {
    category: "Replacement Patterns",
    syntax: "$1, $2, ...",
    description: "In a String.prototype.replace()/replaceAll() replacement string, inserts the text captured by numbered group n.",
    example: "\"jdoe@corp.local\".replace(/(.+)@(.+)/, '$1[at]$2') defangs an email address for safe pasting into a report.",
  },
  {
    category: "Replacement Patterns",
    syntax: "$<name>",
    description: "Inserts the text captured by a named group, in a replacement string.",
    example: "Using $<user> to rebuild a redacted string from a pattern that captured (?<user>...).",
  },
  {
    category: "Replacement Patterns",
    syntax: "$&",
    description: "Inserts the entire matched substring.",
    example: "text.replace(ipv4Regex, '[$&]') wraps every IP match in brackets to defang it, without needing to know its value up front.",
  },
  {
    category: "Replacement Patterns",
    syntax: "$`",
    description: "Inserts the portion of the input string that comes before the matched substring.",
    example: "Rarely needed directly, but available for context-aware substitutions.",
  },
  {
    category: "Replacement Patterns",
    syntax: "$'",
    description: "Inserts the portion of the input string that comes after the matched substring.",
    example: "The counterpart to $` — the remainder of the string following the match.",
  },
  {
    category: "Replacement Patterns",
    syntax: "$$",
    description: "Inserts a literal dollar-sign character in the output (escapes the special meaning of $).",
    example: "'$100'.replace(/\\d+/, '$$$&') turns \"$100\" into \"$$100\" by combining a literal $ with the matched digits.",
  },
  {
    category: "Replacement Patterns",
    syntax: "function replacer",
    description: "A function, instead of a string pattern, can be passed as the replacement — it's called once per match and its return value is substituted in.",
    example: "text.replace(hashRegex, m => m.toUpperCase()) normalizes every matched hex hash to uppercase.",
  },
  {
    category: "RegExp Methods & Properties (JS API)",
    syntax: ".test(str)",
    description: "RegExp method — returns true or false depending on whether the pattern matches anywhere in the string.",
    example: "ipv4Regex.test(line) quickly flags whether a log line contains an IP address at all.",
  },
  {
    category: "RegExp Methods & Properties (JS API)",
    syntax: ".exec(str)",
    description: "RegExp method — returns the next match (as an array with capture groups) or null; with the g or y flag, it advances .lastIndex so a repeated call continues from where the last one left off.",
    example: "Looping while ((m = regex.exec(text))) walks every match in a large pasted log blob.",
  },
  {
    category: "RegExp Methods & Properties (JS API)",
    syntax: "String.prototype.match()",
    description: "Without the g flag, returns one match array (with groups); with g, returns all matched substrings as a plain array with no group info.",
    example: "line.match(/\\d+/g) returns every number found in a line, but not which capture group each came from.",
  },
  {
    category: "RegExp Methods & Properties (JS API)",
    syntax: "String.prototype.matchAll()",
    description: "Returns an iterator over every match, each a full match object (with .groups); requires the regex to have the g flag or it throws.",
    example: "[...text.matchAll(ipv4Regex)] gets every IP match along with its exact position in one pass.",
  },
  {
    category: "RegExp Methods & Properties (JS API)",
    syntax: ".replace() / .replaceAll()",
    description: "Substitutes matches with a replacement string or function; replaceAll() specifically requires a global (g) regex, or it throws a TypeError.",
    example: "text.replaceAll(ipv4Regex, '[REDACTED-IP]') scrubs every IP address out of a log before sharing it.",
  },
  {
    category: "RegExp Methods & Properties (JS API)",
    syntax: "String.prototype.search()",
    description: "Returns the character index of the first match, or -1 if there isn't one (ignores any g flag).",
    example: "line.search(/error/i) finds where \"error\" first shows up in a line, case-insensitively.",
  },
  {
    category: "RegExp Methods & Properties (JS API)",
    syntax: "String.prototype.split()",
    description: "Splits a string into an array of substrings wherever the pattern matches.",
    example: "line.split(/\\s+/) tokenizes a space-delimited log line into its individual fields.",
  },
  {
    category: "RegExp Methods & Properties (JS API)",
    syntax: ".lastIndex",
    description: "A property on a global (g) or sticky (y) RegExp object marking where the next exec()/test() call resumes from; forgetting to reset it to 0 before re-scanning a string from the start is a classic source of silently skipped matches.",
    example: "A regex literal reused across two separate scans without resetting .lastIndex = 0 in between will start the second scan partway through, not at position 0.",
  },
];
