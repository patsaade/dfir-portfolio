// User-Agent String Parser — best-effort, heuristic extraction of a browser
// family + version, rendering engine, and OS/platform from a raw HTTP
// User-Agent string. Pure functions, no DOM dependency — unit-tested
// directly (test/userAgent.test.ts) and imported into the client bundle by
// UserAgentParser.astro for live parsing as you type. Nothing pasted here
// is ever transmitted anywhere; this only re-reads what's already written
// in the string you give it.
//
// *** UA strings are trivially attacker-controlled and NEVER a security
// control. *** Any HTTP client can send literally any string as its
// User-Agent header — curl, a Python script, Burp Suite, a browser
// extension, a hand-crafted implant beacon — so a "recognized" result here
// is never proof of what software actually made a request, and an
// "unrecognized" result is never proof it didn't come from a real browser
// (see "Explicitly NOT supported" below for cases a real, unmodified
// browser can still fail to match). The genuine DFIR use case this tool
// supports is spotting a RARE, MALFORMED, or internally INCONSISTENT UA
// string in a web server/proxy/WAF/EDR log as something worth a second
// look — a beaconing implant with a hardcoded or subtly-wrong UA, a scanner
// that didn't bother crafting a convincing one, a string that claims a
// browser/engine/OS combination that doesn't exist in the real world — not
// to confirm a visitor's real browser, device, or identity. See the tool's
// own page copy for the full caveat; don't strip this warning from any UI
// built on top of this module.
//
// This implements an EXPLICITLY-SCOPED SUBSET of real-world UA string
// conventions, verified against MDN's own documentation (User-Agent header
// reference, the Firefox UA string reference, and the browser-detection
// guidance page), Microsoft's official Edge user-agent-guidance doc, and
// Samsung's own developer UA-format doc (see the tool page's "Other
// resources" section for exact URLs) — not full parity with a real UA
// database. A real one (ua-parser-js's regex table, or a commercial
// database like WURFL/DeviceAtlas) tracks thousands of device/browser/bot
// variants and is kept current by a maintainer; this is a small, literal,
// well-documented subset covering only the browsers/platforms named below.
//
// Supported — browser family + version, checked in this priority order
// (most-specific token first). This order matters: a Chromium-based
// browser's UA string contains several OTHER browsers' own tokens too —
// every Chrome UA also contains "Safari/", and every desktop/Android Edge
// UA contains BOTH "Chrome/" and "Safari/" on top of its own "Edg"-family
// token — so checking in the wrong order silently mislabels one browser as
// another instead of reporting "unrecognized".
//   1. Microsoft Edge (Chromium) — "EdgiOS/" (iPhone/iPad), "EdgA/"
//      (Android), or "Edg/" (Windows/Mac/Linux desktop). Per Microsoft's own
//      user-agent-guidance doc, Microsoft deliberately chose the shortened
//      "Edg" token (rather than "Edge") specifically so it would NOT match
//      the legacy pre-Chromium EdgeHTML browser's own "Edge/" token — that
//      legacy browser is unsupported/EOL and explicitly NOT recognized here
//      (see below); "Edg/" and "Edge/" are deliberately different tokens,
//      not a typo.
//   2. Firefox for iOS — "FxiOS/". Apple requires every third-party iOS
//      browser to embed Apple's own WebKit engine (its own Gecko engine
//      never actually runs on iOS), so Firefox-on-iOS's UA string doesn't
//      contain a "Firefox/" token at all — only "FxiOS/", inside an
//      otherwise ordinary Mobile-Safari-shaped string.
//   3. Chrome for iOS — "CriOS/", same WebKit-mandate reasoning as FxiOS.
//   4. Chrome (desktop or Android) — "Chrome/", EXCLUDING any UA string
//      that also carries "OPR/" (Opera), "SamsungBrowser/" (Samsung
//      Internet), or "Chromium/" (the open-source upstream project itself,
//      shipped as its own distinct browser on Linux). All three are real,
//      separate Chromium-fork/upstream browsers whose own UA strings also
//      embed a "Chrome/" token for site-compatibility reasons (confirmed
//      against Samsung's own developer UA-format documentation, and against
//      Chromium's own UA string, which reads e.g. "... Ubuntu
//      Chromium/76.0.3809.100 Chrome/76.0.3809.100 Safari/537.36") —
//      without this exclusion they'd be silently mislabeled as Chrome,
//      which this tool treats as worse than reporting them as unrecognized
//      (none of the three gets its own positive match here — see
//      "Explicitly NOT supported").
//   5. Firefox (desktop or Android) — "Firefox/", excluding "Seamonkey/"
//      (an unrelated, much rarer Mozilla-derived browser whose UA string
//      can also carry a same-shaped token — MDN's own browser-detection
//      guidance calls this exact exclusion out for Firefox specifically).
//   6. Safari (desktop, or the default "Mobile Safari" on iOS) — a
//      "Safari/" token alongside a "Version/" token, and NOT any of the
//      Chrome/Chromium/CriOS/Edg tokens above. A bare "Safari/" token alone
//      is not sufficient — it appears in nearly every WebKit- AND
//      Blink-based UA string (Chrome's own UA ends in "Safari/537.36" for
//      historical compatibility) — MDN's browser-detection table gives this
//      same must-not-contain-Chrome rule for Safari.
//
// Engine — Blink (Edge, Chrome, when NOT running on iOS), Gecko (Firefox,
// when NOT running on iOS — engine version is read from the UA string's own
// "rv:x.y" token, NOT the adjacent "Gecko/gecko-trail" token, because
// desktop Firefox hardcodes that trail to the fixed placeholder "20100101"
// regardless of the real engine version, a documented historical Gecko UA
// quirk), and WebKit for Safari and for EVERY browser above when it's
// running on iOS — verified fact: Apple's platform policy forces every
// third-party iOS browser onto WebKit, so Chrome/Firefox/Edge-for-iOS all
// genuinely run WebKit under the hood despite being Blink/Gecko browsers
// everywhere else, and their UA strings reflect that (an "AppleWebKit/x.y"
// token, not "Chrome/" driving the actual rendering).
//
// OS/platform — checked in this order (again, most-specific/most-easily-
// confused first):
//   1. iOS/iPadOS — "iPhone"/"iPad"/"iPod" alongside a "CPU ... OS x_y ...
//      like Mac OS X" token. Checked BEFORE macOS below, because every iOS
//      UA string contains the literal substring "like Mac OS X" as part of
//      its own OS token.
//   2. macOS — a "Mac OS X x_y[_z]" token (Chromium/WebKit browsers
//      underscore-separate the version; verified Firefox instead
//      dot-separates it, e.g. "Mac OS X 10.15" — both forms are handled).
//      Two real, documented caveats surface as a `notes` entry when hit:
//      (a) modern macOS (Big Sur/11 and later) freezes this token at
//      "10.15.7" (Chromium browsers) or "10.15" (Firefox) on every release
//      to avoid breaking version-comparison logic elsewhere on the web, so
//      the real macOS version can't be recovered from the UA string once
//      frozen; (b) an iPad running the default desktop-class Safari mode
//      (the default since iPadOS 13) sends this EXACT SAME string as a real
//      Mac — genuinely indistinguishable from UA alone, a well-documented
//      Apple/WebKit behavior, not a gap specific to this tool.
//   3. Android — an "Android x.y" token, checked BEFORE generic Linux below
//      because every Android UA string also contains "Linux". Chrome's
//      documented "User-Agent reduction" freezes this at exactly "Android
//      10" regardless of the device's real OS version once a browser opts
//      into the reduced UA — surfaced as a `notes` entry when the parsed
//      version is exactly "10".
//   4. Windows — a "Windows NT x.y" token, mapped to its marketing name via
//      the well-documented NT-version table. Windows 10 and 11 both report
//      "Windows NT 10.0" — verified directly against Microsoft's own
//      user-agent-guidance doc, which says this token "hasn't been updated
//      for Windows 11" and recommends the separate `Sec-CH-UA-Platform-
//      Version` Client Hint instead — surfaced as a `notes` entry.
//   5. Linux — a generic "Linux" token (e.g. "X11; Linux x86_64") with no
//      version captured, since the kernel/distro string that follows isn't
//      a standardized version number the way the other platforms above are.
//
// Explicitly NOT supported (deliberate scope cuts, not silent gaps):
//   - Opera, Samsung Internet, Brave, Vivaldi, and other Chromium-fork
//     browsers are never given their own positive match or name — see
//     Chrome step 4 above. They come back as an unrecognized browser rather
//     than a wrong one.
//   - Legacy pre-Chromium Microsoft Edge (EdgeHTML, bare "Edge/" token) and
//     Internet Explorer ("MSIE"/"Trident/" tokens) — both are effectively
//     end-of-life and neither is named.
//   - User-Agent Client Hints (the `Sec-CH-UA-*` request headers, and
//     `navigator.userAgentData` client-side) — a separate, structured,
//     explicitly less-spoofable mechanism modern Chromium browsers also
//     send alongside the classic string, and the one MDN/Microsoft/Chrome's
//     own docs now recommend over UA-string parsing for anything that
//     actually matters. This tool only ever reads the classic User-Agent
//     string — it has no access to Client Hints from pasted text alone.
//   - Bot/crawler/tooling UA strings (curl, python-requests, Googlebot, a
//     hand-written implant string, etc.) are not specifically named — they
//     simply won't match any browser/OS pattern below and come back
//     unrecognized, which is itself the useful DFIR signal this tool is
//     for (see the module-level warning above).
//   - Chrome OS, other embedded/IoT/smart-TV platforms, and any operating
//     system outside Windows/macOS/iOS-iPadOS/Android/Linux.
//   - Tablet vs. phone vs. desktop form factor. The only device-class
//     signal this tool surfaces is `isMobileToken` — whether the literal
//     substring "Mobi" appears anywhere in the string, which MDN's own
//     browser-detection guidance recommends as the least-unreliable UA
//     signal for "this is probably a phone-sized touch device" — it is
//     still a heuristic, not a guarantee, and (per the macOS/iPadOS note
//     above) cannot identify an iPad specifically.

export interface UaComponent {
  /** Human-readable name, e.g. "Chrome", "Windows 10", "Blink". */
  name: string;
  /** Version string as found in the UA (dots, not underscores), or null if this tool doesn't capture one for this match. */
  version: string | null;
}

export interface ParsedUserAgent {
  /** The original, untrimmed input. */
  raw: string;
  /** null when no supported browser token matched (see module header). */
  browser: UaComponent | null;
  /** null when the browser (or engine token) couldn't be determined. */
  engine: UaComponent | null;
  /** null when no supported OS/platform token matched. */
  os: UaComponent | null;
  /** Whether the literal substring "Mobi" appears anywhere in the string (MDN's own recommended mobile-detection signal). */
  isMobileToken: boolean;
  /** Best-effort caveats specific to this particular parse — frozen/ambiguous version tokens, unrecognized browser/OS, missing the historical "Mozilla/" prefix, etc. Empty for a blank input. */
  notes: string[];
}

type Platform = 'ios' | 'android' | 'desktop' | 'other';

interface BrowserMatch {
  name: string;
  version: string;
  platform: Platform;
}

const WINDOWS_NT_NAMES: Record<string, string> = {
  '5.0': 'Windows 2000',
  '5.1': 'Windows XP',
  '5.2': 'Windows XP x64 / Server 2003',
  '6.0': 'Windows Vista',
  '6.1': 'Windows 7',
  '6.2': 'Windows 8',
  '6.3': 'Windows 8.1',
  '10.0': 'Windows 10',
};

function detectBrowser(ua: string): BrowserMatch | null {
  let m: RegExpMatchArray | null;

  if ((m = ua.match(/EdgiOS\/([\d.]+)/))) return { name: 'Microsoft Edge', version: m[1], platform: 'ios' };
  if ((m = ua.match(/EdgA\/([\d.]+)/))) return { name: 'Microsoft Edge', version: m[1], platform: 'android' };
  if ((m = ua.match(/Edg\/([\d.]+)/))) return { name: 'Microsoft Edge', version: m[1], platform: 'desktop' };

  if ((m = ua.match(/FxiOS\/([\d.]+)/))) return { name: 'Firefox', version: m[1], platform: 'ios' };
  if ((m = ua.match(/CriOS\/([\d.]+)/))) return { name: 'Chrome', version: m[1], platform: 'ios' };

  // Real, separate Chromium-fork/upstream browsers that also embed a
  // "Chrome/" token — excluded so they're reported unrecognized rather than
  // mislabeled. See module header, Chrome step 4.
  const isOtherChromiumFork = /OPR\//.test(ua) || /SamsungBrowser\//.test(ua) || /Chromium\//.test(ua);
  if (!isOtherChromiumFork && (m = ua.match(/Chrome\/([\d.]+)/))) {
    return { name: 'Chrome', version: m[1], platform: /Android/.test(ua) ? 'android' : 'desktop' };
  }

  if (!/Seamonkey\//.test(ua) && (m = ua.match(/Firefox\/([\d.]+)/))) {
    return { name: 'Firefox', version: m[1], platform: /Android/.test(ua) ? 'android' : 'desktop' };
  }

  if (
    /Safari\//.test(ua) &&
    !/Chrome\/|Chromium\/|CriOS\/|Edg\//.test(ua) &&
    (m = ua.match(/Version\/([\d.]+)/))
  ) {
    return { name: 'Safari', version: m[1], platform: /iPhone|iPad|iPod/.test(ua) ? 'ios' : 'desktop' };
  }

  return null;
}

function detectEngine(ua: string, browser: BrowserMatch | null): UaComponent | null {
  const webkitVersion = () => {
    const m = ua.match(/AppleWebKit\/([\d.]+)/);
    return m ? m[1] : null;
  };
  const blinkVersion = () => {
    const m = ua.match(/Chrome\/([\d.]+)/);
    return m ? m[1] : null;
  };
  const geckoVersion = () => {
    // Prefer the true "rv:" token over the adjacent "Gecko/20100101"
    // placeholder trail — see module header.
    const rv = ua.match(/rv:([\d.]+)/);
    if (rv) return rv[1];
    return browser?.version ?? null;
  };

  if (browser) {
    if (browser.platform === 'ios' || browser.name === 'Safari') {
      return { name: 'WebKit', version: webkitVersion() };
    }
    if (browser.name === 'Microsoft Edge' || browser.name === 'Chrome') {
      return { name: 'Blink', version: blinkVersion() };
    }
    if (browser.name === 'Firefox') {
      return { name: 'Gecko', version: geckoVersion() };
    }
  }

  // Browser wasn't one of the ones this tool names — still surface a raw
  // engine-token sniff where possible, checked Blink-before-WebKit for the
  // same reason as the browser table (a Blink UA also literally contains
  // "AppleWebKit/x.y (KHTML, like Gecko)").
  if (/Chrome\//.test(ua)) return { name: 'Blink', version: blinkVersion() };
  if (/rv:[\d.]+/.test(ua) && /Gecko\//.test(ua)) return { name: 'Gecko', version: geckoVersion() };
  if (/AppleWebKit\//.test(ua)) return { name: 'WebKit', version: webkitVersion() };
  return null;
}

function detectOs(ua: string, notes: string[]): UaComponent | null {
  let m: RegExpMatchArray | null;

  // iOS/iPadOS — checked before macOS; see module header.
  if ((m = ua.match(/CPU (?:iPhone )?OS ([\d_]+) like Mac OS X/))) {
    const version = m[1].replace(/_/g, '.');
    return { name: /iPad/.test(ua) ? 'iPadOS' : 'iOS', version };
  }

  // macOS — Chromium/WebKit underscore the version, Firefox dot-separates it.
  if ((m = ua.match(/Mac OS X ([\d_.]+)/))) {
    const version = m[1].replace(/_/g, '.');
    if (version === '10.15.7' || version === '10.15') {
      notes.push(
        `macOS version reported as ${version} — modern macOS (Big Sur/11 and later) freezes this token at ${version === '10.15.7' ? '"10.15.7" (Chromium/WebKit browsers)' : '"10.15" (Firefox)'} on every release since, so the real macOS version can't be read from the UA string alone. An iPad in the default desktop-class Safari mode (the default since iPadOS 13) sends this exact same string too — indistinguishable from a real Mac by User-Agent alone.`
      );
    }
    return { name: 'macOS', version };
  }

  // Android — checked before generic Linux; see module header.
  if ((m = ua.match(/Android ([\d.]+)/))) {
    const version = m[1];
    if (version === '10') {
      notes.push(
        'Android version reported as "10" — Chromium\'s User-Agent reduction freezes the OS version at "10" regardless of the device\'s real Android version once a browser opts into the reduced UA, so this may not be the device\'s actual OS version.'
      );
    }
    return { name: 'Android', version };
  }

  if ((m = ua.match(/Windows NT ([\d.]+)/))) {
    const version = m[1];
    const name = WINDOWS_NT_NAMES[version] ?? `Windows (unrecognized NT ${version})`;
    if (version === '10.0') {
      notes.push('"Windows NT 10.0" covers both Windows 10 and Windows 11 — the classic UA string has no token that tells them apart (Microsoft\'s own guidance points to the separate Sec-CH-UA-Platform-Version Client Hint instead).');
    }
    return { name, version };
  }

  if (/Linux/.test(ua)) {
    return { name: 'Linux', version: null };
  }

  return null;
}

export function parseUserAgent(rawUa: string): ParsedUserAgent {
  const ua = rawUa.trim();

  if (!ua) {
    return { raw: rawUa, browser: null, engine: null, os: null, isMobileToken: false, notes: [] };
  }

  const notes: string[] = [];
  const browserMatch = detectBrowser(ua);
  const browser: UaComponent | null = browserMatch ? { name: browserMatch.name, version: browserMatch.version } : null;
  const engine = detectEngine(ua, browserMatch);
  const os = detectOs(ua, notes);
  const isMobileToken = /Mobi/.test(ua);

  // Virtually every real browser — including non-Mozilla ones like Chrome,
  // Safari, and Edge — has carried a leading "Mozilla/" compatibility token
  // since the mid-1990s browser wars (confirmed by MDN's own Firefox UA
  // string reference: "Mozilla/5.0 is the general token that says the
  // browser is Mozilla compatible, and is common to almost every browser
  // today"). Its absence doesn't prove a string is fake, but it's unusual
  // enough to be worth a second look in a log.
  if (!ua.startsWith('Mozilla/')) {
    notes.push('This string does not start with the historical "Mozilla/" compatibility token nearly every real browser carries. Not proof of spoofing on its own, but unusual and worth a second look.');
  }

  if (!browser) {
    notes.push('No recognized browser token matched. This may be a non-browser HTTP client (a script, an API client, a scanner), a Chromium-based browser this tool doesn\'t specifically name (e.g. Opera, Samsung Internet), or a hand-crafted/spoofed string.');
  }
  if (!os) {
    notes.push('No recognized OS/platform token matched.');
  }

  return { raw: rawUa, browser, engine, os, isMobileToken, notes };
}

/** Reference table for the page's own "what this tool recognizes" section — mirrors HASH_ALGORITHMS' role in utils/hashes.ts. */
export const UA_BROWSER_TOKENS: { name: string; tokens: string; note: string }[] = [
  { name: 'Microsoft Edge (Chromium)', tokens: 'Edg/ (desktop) · EdgA/ (Android) · EdgiOS/ (iOS)', note: 'Checked first — Edge UA strings also contain Chrome/ and Safari/ tokens.' },
  { name: 'Firefox', tokens: 'Firefox/ (desktop, Android) · FxiOS/ (iOS)', note: 'Excludes Seamonkey/.' },
  { name: 'Chrome', tokens: 'Chrome/ (desktop, Android) · CriOS/ (iOS)', note: 'Excludes strings also carrying OPR/ (Opera) or SamsungBrowser/.' },
  { name: 'Safari', tokens: 'Safari/ + Version/ (desktop, or the default "Mobile Safari" on iOS)', note: 'Excludes any Chrome/Chromium/CriOS/Edg token.' },
];

export const UA_OS_TOKENS: { name: string; tokens: string; note: string }[] = [
  { name: 'iOS / iPadOS', tokens: 'iPhone/iPad/iPod; CPU … OS <version> like Mac OS X', note: 'An iPad in default desktop-mode Safari instead sends the plain macOS string below — indistinguishable.' },
  { name: 'macOS', tokens: 'Macintosh; … Mac OS X <version>', note: 'Frozen at 10.15.7 (Chromium/WebKit) or 10.15 (Firefox) on every release since macOS 11.' },
  { name: 'Android', tokens: 'Android <version>', note: 'Chrome\'s reduced UA freezes this at "10" regardless of the real OS version.' },
  { name: 'Windows', tokens: 'Windows NT <version>', note: 'NT 10.0 covers both Windows 10 and Windows 11.' },
  { name: 'Linux', tokens: 'X11; Linux …', note: 'No version captured — the following kernel/distro string isn\'t a standardized version number.' },
];
