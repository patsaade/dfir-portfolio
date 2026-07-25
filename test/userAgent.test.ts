import { describe, it, expect } from 'vitest';
import { parseUserAgent } from '../src/utils/userAgent';

// Every UA string below is either copied verbatim from an authoritative
// source or constructed by combining documented token conventions from
// those same sources — never invented. Sources (also cited in
// src/utils/userAgent.ts's own header and the tool page's "Other
// resources"):
//   - MDN, "User-Agent header": developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/User-Agent
//   - MDN, "Browser detection using the user agent": developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Browser_detection_using_the_user_agent
//   - MDN, "Firefox user agent string reference": developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/User-Agent/Firefox
//   - Microsoft Learn, "Detecting Microsoft Edge from your website": learn.microsoft.com/en-us/microsoft-edge/web-platform/user-agent-guidance
//     (the exact source of the Windows/Android Edge examples AND the
//     legacy-EdgeHTML "Edge/18.19582" example below)
//   - Chromium docs, "User Agent in Chrome for iOS": chromium.googlesource.com/chromium/src/+/lkgr/docs/ios/user_agent.md
//     (the exact source of the CriOS example below)
//   - Widely-mirrored real-world capture of Firefox for iOS's FxiOS token
//     shape (same WebKit-shell convention Chromium's own doc confirms for CriOS)

describe('parseUserAgent', () => {
  it('parses Chrome on Windows 10 (MDN example)', () => {
    const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36';
    const result = parseUserAgent(ua);
    expect(result.browser).toEqual({ name: 'Chrome', version: '143.0.0.0' });
    expect(result.engine).toEqual({ name: 'Blink', version: '143.0.0.0' });
    expect(result.os).toEqual({ name: 'Windows 10', version: '10.0' });
    expect(result.isMobileToken).toBe(false);
    expect(result.notes.some((n) => /Windows 10 and Windows 11/.test(n))).toBe(true);
  });

  it('parses Chrome Mobile on Android (MDN example)', () => {
    const ua = 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Mobile Safari/537.36';
    const result = parseUserAgent(ua);
    expect(result.browser).toEqual({ name: 'Chrome', version: '143.0.0.0' });
    expect(result.engine).toEqual({ name: 'Blink', version: '143.0.0.0' });
    expect(result.os).toEqual({ name: 'Android', version: '10' });
    expect(result.isMobileToken).toBe(true);
    expect(result.notes.some((n) => /reduction freezes/.test(n))).toBe(true);
  });

  it('parses Chrome on iOS (Chromium project\'s own documented CriOS example)', () => {
    const ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 10_3 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) CriOS/56.0.2924.75 Mobile/14E5239e Safari/602.1';
    const result = parseUserAgent(ua);
    expect(result.browser).toEqual({ name: 'Chrome', version: '56.0.2924.75' });
    // Apple forces WebKit for every iOS browser, including Chrome-for-iOS.
    expect(result.engine).toEqual({ name: 'WebKit', version: '602.1.50' });
    expect(result.os).toEqual({ name: 'iOS', version: '10.3' });
    expect(result.isMobileToken).toBe(true);
  });

  it('parses Firefox on macOS (MDN example)', () => {
    const ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0';
    const result = parseUserAgent(ua);
    expect(result.browser).toEqual({ name: 'Firefox', version: '138.0' });
    // Engine version comes from rv:, not the fixed "20100101" trail.
    expect(result.engine).toEqual({ name: 'Gecko', version: '138.0' });
    expect(result.os).toEqual({ name: 'macOS', version: '10.15' });
    expect(result.notes.some((n) => /freezes this token/.test(n))).toBe(true);
  });

  it('parses Firefox on Linux (MDN Firefox UA reference format)', () => {
    const ua = 'Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0';
    const result = parseUserAgent(ua);
    expect(result.browser).toEqual({ name: 'Firefox', version: '139.0' });
    expect(result.engine).toEqual({ name: 'Gecko', version: '139.0' });
    expect(result.os).toEqual({ name: 'Linux', version: null });
    expect(result.isMobileToken).toBe(false);
  });

  it('parses Firefox Mobile on Android (MDN example)', () => {
    const ua = 'Mozilla/5.0 (Android 15; Mobile; rv:136.0) Gecko/136.0 Firefox/136.0';
    const result = parseUserAgent(ua);
    expect(result.browser).toEqual({ name: 'Firefox', version: '136.0' });
    expect(result.engine).toEqual({ name: 'Gecko', version: '136.0' });
    expect(result.os).toEqual({ name: 'Android', version: '15' });
    expect(result.isMobileToken).toBe(true);
    // Not frozen at "10" here, so no reduction note.
    expect(result.notes.some((n) => /reduction freezes/.test(n))).toBe(false);
  });

  it('parses Firefox on iOS (documented FxiOS WebKit-shell convention)', () => {
    const ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) FxiOS/1.0 Mobile/12F69 Safari/600.1.4';
    const result = parseUserAgent(ua);
    expect(result.browser).toEqual({ name: 'Firefox', version: '1.0' });
    expect(result.engine).toEqual({ name: 'WebKit', version: '600.1.4' });
    expect(result.os).toEqual({ name: 'iOS', version: '8.3' });
  });

  it('parses Safari on macOS (MDN example)', () => {
    const ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15';
    const result = parseUserAgent(ua);
    expect(result.browser).toEqual({ name: 'Safari', version: '26.0' });
    expect(result.engine).toEqual({ name: 'WebKit', version: '605.1.15' });
    expect(result.os).toEqual({ name: 'macOS', version: '10.15.7' });
    expect(result.notes.some((n) => /iPad in the default desktop-class Safari mode/.test(n))).toBe(true);
  });

  it('parses Mobile Safari on iOS (MDN example)', () => {
    const ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1';
    const result = parseUserAgent(ua);
    expect(result.browser).toEqual({ name: 'Safari', version: '26.0' });
    expect(result.engine).toEqual({ name: 'WebKit', version: '605.1.15' });
    expect(result.os).toEqual({ name: 'iOS', version: '18.6' });
    expect(result.isMobileToken).toBe(true);
  });

  it('parses Edge (Chromium) on Windows (Microsoft\'s own documented example)', () => {
    const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0';
    const result = parseUserAgent(ua);
    expect(result.browser).toEqual({ name: 'Microsoft Edge', version: '120.0.0.0' });
    expect(result.engine).toEqual({ name: 'Blink', version: '120.0.0.0' });
    expect(result.os).toEqual({ name: 'Windows 10', version: '10.0' });
  });

  it('parses Edge (Chromium) on Android (Microsoft\'s own documented example)', () => {
    const ua = 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 EdgA/120.0.0.0';
    const result = parseUserAgent(ua);
    expect(result.browser).toEqual({ name: 'Microsoft Edge', version: '120.0.0.0' });
    expect(result.engine).toEqual({ name: 'Blink', version: '120.0.0.0' });
    expect(result.os).toEqual({ name: 'Android', version: '10' });
    expect(result.isMobileToken).toBe(true);
  });

  it('parses Edge (Chromium) on iOS (documented EdgiOS token + standard iOS WebKit shell)', () => {
    const ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 EdgiOS/121.2277.107 Mobile/15E148 Safari/605.1.15';
    const result = parseUserAgent(ua);
    expect(result.browser).toEqual({ name: 'Microsoft Edge', version: '121.2277.107' });
    // iOS forces WebKit even for Edge.
    expect(result.engine).toEqual({ name: 'WebKit', version: '605.1.15' });
    expect(result.os).toEqual({ name: 'iOS', version: '17.4' });
  });

  it('does not mislabel Opera (OPR/) as Chrome despite the shared Chrome/ token', () => {
    const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 OPR/126.0.0.0';
    const result = parseUserAgent(ua);
    expect(result.browser).toBeNull();
    expect(result.notes.some((n) => /No recognized browser token/.test(n))).toBe(true);
  });

  it('does not mislabel Samsung Internet (SamsungBrowser/) as Chrome', () => {
    const ua = 'Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36';
    const result = parseUserAgent(ua);
    expect(result.browser).toBeNull();
  });

  it('does not mislabel the Chromium upstream browser (Chromium/) as Chrome despite the shared Chrome/ token', () => {
    const ua = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/76.0.3809.100 Chrome/76.0.3809.100 Safari/537.36';
    const result = parseUserAgent(ua);
    expect(result.browser).toBeNull();
  });

  it('does not recognize legacy pre-Chromium EdgeHTML (bare Edge/ token) as the modern browser (Microsoft\'s own documented legacy example)', () => {
    const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19582';
    const result = parseUserAgent(ua);
    // Falls through to a Chrome match (it carries an unexcluded Chrome/
    // token and none of Edg/EdgA/EdgiOS match a bare "Edge/" token) — this
    // is a documented, deliberate scope cut, not a false claim of Edge
    // support. See module header's "Explicitly NOT supported".
    expect(result.browser).toEqual({ name: 'Chrome', version: '70.0.3538.102' });
  });

  it('flags a UA string with no leading "Mozilla/" token as unusual', () => {
    const ua = 'curl/8.4.0';
    const result = parseUserAgent(ua);
    expect(result.browser).toBeNull();
    expect(result.os).toBeNull();
    expect(result.notes.some((n) => /does not start with the historical/.test(n))).toBe(true);
    expect(result.notes.some((n) => /No recognized browser token/.test(n))).toBe(true);
    expect(result.notes.some((n) => /No recognized OS\/platform token/.test(n))).toBe(true);
  });

  it('returns an empty, note-free result for blank input', () => {
    const result = parseUserAgent('   ');
    expect(result.browser).toBeNull();
    expect(result.engine).toBeNull();
    expect(result.os).toBeNull();
    expect(result.isMobileToken).toBe(false);
    expect(result.notes).toEqual([]);
  });

  it('maps every documented Windows NT version to its marketing name', () => {
    const cases: [string, string][] = [
      ['5.1', 'Windows XP'],
      ['6.1', 'Windows 7'],
      ['6.2', 'Windows 8'],
      ['6.3', 'Windows 8.1'],
      ['10.0', 'Windows 10'],
    ];
    for (const [nt, name] of cases) {
      const ua = `Mozilla/5.0 (Windows NT ${nt}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36`;
      const result = parseUserAgent(ua);
      expect(result.os?.name).toBe(name);
      expect(result.os?.version).toBe(nt);
    }
  });
});
