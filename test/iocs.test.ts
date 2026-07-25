import { describe, it, expect } from 'vitest';
import { extractIocs, defangValue, refangValue, containsDefanged, IOC_CATEGORIES, type IocMatch } from '../src/utils/iocs';

/** Pull just the `.value` field out of a category's IocMatch[] for assertions
 *  that only care about which values were found, not their viaRefang flag. */
function vals(matches: IocMatch[]): string[] {
  return matches.map((m) => m.value);
}

describe('extractIocs', () => {
  it('extracts IPv4 addresses and ignores out-of-range octets', () => {
    const out = extractIocs('beaconed to 203.0.113.42 and 10.0.0.1, but 999.1.1.1 is not valid');
    expect(vals(out.ipv4).sort()).toEqual(['10.0.0.1', '203.0.113.42']);
  });

  it('extracts IPv6 in full and compressed forms', () => {
    const out = extractIocs('full 2001:0db8:85a3:0000:0000:8a2e:0370:7334 loopback ::1 compressed fe80::1');
    expect(vals(out.ipv6)).toContain('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
    expect(vals(out.ipv6)).toContain('::1');
    expect(vals(out.ipv6)).toContain('fe80::1');
  });

  it('extracts URLs', () => {
    const out = extractIocs('phished via http://evil-domain.example/login and https://second.example/a?b=1');
    expect(vals(out.url)).toEqual(['http://evil-domain.example/login', 'https://second.example/a?b=1']);
  });

  it('trims trailing sentence punctuation off a URL at the end of a sentence', () => {
    const out = extractIocs('The payload phoned home to http://evil.example/reset?token=abc123. Then it moved laterally.');
    expect(vals(out.url)).toEqual(['http://evil.example/reset?token=abc123']);
  });

  it('trims a URL wrapped in a parenthetical, not just sentence-final', () => {
    const out = extractIocs('(see http://evil.example/x, for details)');
    expect(vals(out.url)).toEqual(['http://evil.example/x']);
  });

  it('extracts domains (including ones embedded in a URL) and dedupes', () => {
    const out = extractIocs('C2 at evil-domain.example, also seen evil-domain.example again, and in http://evil-domain.example/x');
    expect(vals(out.domain)).toEqual(['evil-domain.example']);
  });

  it('extracts email addresses', () => {
    const out = extractIocs('phishing sender was attacker@evil-domain.example');
    expect(vals(out.email)).toEqual(['attacker@evil-domain.example']);
  });

  it('extracts hashes by exact length without cross-category contamination', () => {
    const md5 = 'd41d8cd98f00b204e9800998ecf8427e';
    const sha1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
    const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const sha512 =
      'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e';
    const out = extractIocs(`md5=${md5} sha1=${sha1} sha256=${sha256} sha512=${sha512}`);
    expect(vals(out.md5)).toEqual([md5]);
    expect(vals(out.sha1)).toEqual([sha1]);
    expect(vals(out.sha256)).toEqual([sha256]);
    expect(vals(out.sha512)).toEqual([sha512]);
  });

  it('does not let a longer hash bleed into a shorter hash category', () => {
    const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const out = extractIocs(`hash: ${sha256}`);
    expect(out.md5).toEqual([]);
    expect(out.sha1).toEqual([]);
    expect(vals(out.sha256)).toEqual([sha256]);
  });

  it('extracts CVE IDs case-insensitively', () => {
    const out = extractIocs('exploited via CVE-2021-44228 and cve-2017-0144');
    expect(vals(out.cve)).toEqual(['CVE-2021-44228', 'cve-2017-0144']);
  });

  it('extracts MITRE ATT&CK technique IDs including sub-techniques', () => {
    const out = extractIocs('mapped to T1055 and T1055.001, plus T1059');
    expect(vals(out.attack).sort()).toEqual(['T1055', 'T1055.001', 'T1059']);
  });

  it('extracts Bitcoin addresses (legacy and bech32)', () => {
    const out = extractIocs(
      'ransom to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 or bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',
    );
    expect(vals(out.btc)).toContain('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2');
    expect(vals(out.btc)).toContain('bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq');
  });

  it('extracts a Windows file path', () => {
    // The reused pattern only stops at a character Windows disallows in file
    // names (backslash, forward slash, colon, *, ?, ", <, >, |, CR/LF) — not
    // at whitespace — so the path is quoted here the way it'd realistically
    // appear in a log line, giving the match a real character to stop at.
    const out = extractIocs('dropped payload at "C:\\Users\\admin\\AppData\\Local\\Temp\\evil.exe" on disk');
    expect(vals(out.winpath)).toContain('C:\\Users\\admin\\AppData\\Local\\Temp\\evil.exe');
  });

  it('does not match a Windows-style path missing its drive letter', () => {
    const out = extractIocs('shared payload from \\\\fileserver\\share\\evil.exe over SMB');
    expect(out.winpath).toEqual([]);
  });

  it('extracts a registry key path, both hive abbreviation and full hive name', () => {
    // Each backslash-delimited segment of the reused pattern runs until the
    // next backslash (or CR/LF), so the two mentions are put on separate
    // lines here — otherwise the ordinary prose between them (no backslash
    // until the second hive's own path) would merge into a single match.
    const out = extractIocs(
      'persistence via HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\nalso seen: HKEY_CURRENT_USER\\Software\\Classes',
    );
    expect(vals(out.regkey)).toContain('HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run');
    expect(vals(out.regkey)).toContain('HKEY_CURRENT_USER\\Software\\Classes');
  });

  it('does not match an unrecognized hive-like prefix', () => {
    const out = extractIocs('config stored under HK\\Software\\Foo');
    expect(out.regkey).toEqual([]);
  });

  it('extracts MAC addresses, colon- or hyphen-separated', () => {
    const out = extractIocs('NIC observed as 00:1A:2B:3C:4D:5E and also 00-1A-2B-3C-4D-5E');
    expect(vals(out.mac)).toContain('00:1A:2B:3C:4D:5E');
    expect(vals(out.mac)).toContain('00-1A-2B-3C-4D-5E');
  });

  it('does not match a 5-octet MAC address', () => {
    const out = extractIocs('truncated NIC id 00:1A:2B:3C:4D seen in the log');
    expect(out.mac).toEqual([]);
  });

  it('returns an empty array per category for text with nothing to find', () => {
    const out = extractIocs('nothing indicator-shaped here');
    for (const cat of IOC_CATEGORIES) expect(out[cat.id]).toEqual([]);
  });

  it('every category id in IOC_CATEGORIES appears as a key in the result', () => {
    const out = extractIocs('');
    for (const cat of IOC_CATEGORIES) expect(Object.prototype.hasOwnProperty.call(out, cat.id)).toBe(true);
  });

  it('recognizes a defanged IPv4 address ([.]) and extracts it in live form', () => {
    const out = extractIocs('beaconed to 203[.]0[.]113[.]42');
    expect(vals(out.ipv4)).toEqual(['203.0.113.42']);
  });

  it('recognizes a defanged domain and URL (hxxp + [.]) in live form', () => {
    const out = extractIocs('phished via hxxp://evil-domain[.]example/login');
    expect(vals(out.url)).toEqual(['http://evil-domain.example/login']);
    expect(vals(out.domain)).toContain('evil-domain.example');
  });

  it('recognizes a defanged https URL, preserving the "s"', () => {
    const out = extractIocs('C2 at hxxps://evil[.]example/beacon');
    expect(vals(out.url)).toEqual(['https://evil.example/beacon']);
  });

  it('recognizes a defanged email address ([at] + [.])', () => {
    const out = extractIocs('sender was attacker[at]evil-domain[.]example');
    expect(vals(out.email)).toEqual(['attacker@evil-domain.example']);
  });

  it('recognizes a defanged IPv6 address ([:])', () => {
    const out = extractIocs('loopback [:][:]1 and fe80[:][:]1');
    expect(vals(out.ipv6)).toContain('::1');
    expect(vals(out.ipv6)).toContain('fe80::1');
  });

  it('recognizes (dot) and (at) parenthesized defanging too', () => {
    const out = extractIocs('contact attacker(at)evil-domain(dot)example');
    expect(vals(out.email)).toEqual(['attacker@evil-domain.example']);
  });

  it('handles text that mixes already-live and defanged indicators together', () => {
    const out = extractIocs('seen 203.0.113.42 and also 198[.]51[.]100[.]7');
    expect(vals(out.ipv4).sort()).toEqual(['198.51.100.7', '203.0.113.42']);
  });

  it('does not double-count when the same IP appears in both live and defanged form', () => {
    const out = extractIocs('203.0.113.42 vs 203[.]0[.]113[.]42');
    expect(vals(out.ipv4)).toEqual(['203.0.113.42']);
  });

  describe('viaRefang tracking', () => {
    it('flags viaRefang false for a value found directly in the raw text', () => {
      const out = extractIocs('beaconed to 203.0.113.42');
      expect(out.ipv4).toEqual([{ value: '203.0.113.42', viaRefang: false }]);
    });

    it('flags viaRefang true for a value ONLY recoverable via the refanged shadow copy, with the fully live value in .value', () => {
      const out = extractIocs('phished via hxxp://evil-domain[.]example/login');
      expect(out.url).toEqual([{ value: 'http://evil-domain.example/login', viaRefang: true }]);
      expect(out.domain).toContainEqual({ value: 'evil-domain.example', viaRefang: true });
    });

    it('flags viaRefang false when the same value appears in both live and defanged form (found live wins)', () => {
      const out = extractIocs('203.0.113.42 vs 203[.]0[.]113[.]42');
      expect(out.ipv4).toEqual([{ value: '203.0.113.42', viaRefang: false }]);
    });

    it('tracks viaRefang independently per value when live and defanged indicators are mixed', () => {
      const out = extractIocs('seen 203.0.113.42 and also 198[.]51[.]100[.]7');
      const byValue = Object.fromEntries(out.ipv4.map((m) => [m.value, m.viaRefang]));
      expect(byValue['203.0.113.42']).toBe(false);
      expect(byValue['198.51.100.7']).toBe(true);
    });

    it('flags viaRefang true for a defanged email address ([at] + [.])', () => {
      const out = extractIocs('sender was attacker[at]evil-domain[.]example');
      expect(out.email).toEqual([{ value: 'attacker@evil-domain.example', viaRefang: true }]);
    });
  });
});

describe('containsDefanged', () => {
  it('detects bracketed-dot defanging', () => {
    expect(containsDefanged('203[.]0[.]113[.]42')).toBe(true);
  });

  it('detects hxxp defanging', () => {
    expect(containsDefanged('hxxp://evil.example')).toBe(true);
  });

  it('returns false for plain live text', () => {
    expect(containsDefanged('http://evil.example, 203.0.113.42')).toBe(false);
  });

  it('does not false-positive on ordinary prose containing the words "dot" or "at"', () => {
    expect(containsDefanged('meet me at the dot on the map')).toBe(false);
  });
});

describe('defangValue / refangValue', () => {
  it('defangs and refangs an IPv4 address', () => {
    const defanged = defangValue('203.0.113.42', 'ipv4');
    expect(defanged).toBe('203[.]0[.]113[.]42');
    expect(refangValue(defanged, 'ipv4')).toBe('203.0.113.42');
  });

  it('defangs and refangs a domain', () => {
    const defanged = defangValue('evil-domain.example', 'domain');
    expect(defanged).toBe('evil-domain[.]example');
    expect(refangValue(defanged, 'domain')).toBe('evil-domain.example');
  });

  it('defangs and refangs a URL, preserving http vs https', () => {
    const http = defangValue('http://evil.example/x', 'url');
    expect(http).toBe('hxxp://evil[.]example/x');
    expect(refangValue(http, 'url')).toBe('http://evil.example/x');

    const https = defangValue('https://evil.example/x', 'url');
    expect(https).toBe('hxxps://evil[.]example/x');
    expect(refangValue(https, 'url')).toBe('https://evil.example/x');
  });

  it('defangs and refangs an email address', () => {
    const defanged = defangValue('attacker@evil.example', 'email');
    expect(defanged).toBe('attacker[at]evil[.]example');
    expect(refangValue(defanged, 'email')).toBe('attacker@evil.example');
  });

  it('defangs and refangs an IPv6 address', () => {
    const defanged = defangValue('fe80::1', 'ipv6');
    expect(defanged).toBe('fe80[:][:]1');
    expect(refangValue(defanged, 'ipv6')).toBe('fe80::1');
  });

  it('leaves non-defangable categories (hashes, CVE, ATT&CK, BTC, Windows paths, registry keys, MAC addresses) unchanged', () => {
    const md5 = 'd41d8cd98f00b204e9800998ecf8427e';
    expect(defangValue(md5, 'md5')).toBe(md5);
    expect(defangValue('CVE-2021-44228', 'cve')).toBe('CVE-2021-44228');
    expect(defangValue('T1055.001', 'attack')).toBe('T1055.001');
    expect(defangValue('C:\\Users\\admin\\evil.exe', 'winpath')).toBe('C:\\Users\\admin\\evil.exe');
    expect(defangValue('HKLM\\Software\\Run', 'regkey')).toBe('HKLM\\Software\\Run');
    expect(defangValue('00:1A:2B:3C:4D:5E', 'mac')).toBe('00:1A:2B:3C:4D:5E');
  });
});
