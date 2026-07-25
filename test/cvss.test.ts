import { describe, it, expect } from 'vitest';
import {
  computeCvssV31BaseScore,
  cvssRoundUp,
  cvssSeverityRating,
  buildCvssV31VectorString,
  parseCvssV31VectorString,
  CVSS_METRIC_ORDER,
  DEFAULT_CVSS_METRICS,
  type CvssV31Metrics,
} from '../src/utils/cvss';

// ---------------------------------------------------------------------------
// Worked examples published by FIRST.org itself:
// https://www.first.org/cvss/v3-1/examples — every vector + Base Score pair
// below was copied verbatim from that page (WebFetch-verified against the
// live page, not transcribed from memory). If computeCvssV31BaseScore ever
// disagrees with one of these, the formula implementation has a bug — these
// are not approximate/rounded targets, they're FIRST's own reference
// answers for a deterministic formula.
// ---------------------------------------------------------------------------
const FIRST_ORG_EXAMPLES: { name: string; vector: string; score: number }[] = [
  { name: 'MySQL Stored SQL Injection (CVE-2013-0375)', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N', score: 6.4 },
  { name: 'SSLv3 POODLE (CVE-2014-3566)', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N', score: 3.1 },
  { name: 'VMware Guest to Host Escape (CVE-2012-1516)', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', score: 9.9 },
  { name: 'Apache Tomcat XML Parser (CVE-2009-0783)', vector: 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L', score: 4.2 },
  { name: 'Cisco IOS Command Execution (CVE-2012-0384)', vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', score: 7.2 },
  { name: 'Apple iWork Denial of Service (CVE-2015-1098)', vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', score: 7.8 },
  { name: 'OpenSSL Heartbleed (CVE-2014-0160)', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', score: 7.5 },
  { name: 'GNU Bash Shellshock (CVE-2014-6271)', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', score: 9.8 },
  { name: 'DNS Kaminsky Bug (CVE-2008-1447)', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N', score: 6.8 },
  { name: 'Sophos Login Screen Bypass (CVE-2014-2005)', vector: 'CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', score: 6.8 },
  { name: 'Joomla Directory Traversal (CVE-2010-0467)', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N', score: 5.8 },
  { name: 'Cisco ACL Bypass (CVE-2012-1342)', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N', score: 5.8 },
  { name: 'Juniper Proxy ARP DoS (CVE-2013-6014)', vector: 'CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H', score: 9.3 },
  { name: 'Cantemo Portal XSS (CVE-2019-7551)', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H', score: 9.0 },
  { name: 'Adobe Acrobat Buffer Overflow (CVE-2009-0658)', vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', score: 7.8 },
  { name: 'Windows Bluetooth RCE (CVE-2011-1265)', vector: 'CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', score: 8.8 },
  { name: 'Apple iOS iCloud Bypass (CVE-2014-2019)', vector: 'CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N', score: 4.6 },
  { name: 'SearchBlox CSRF (CVE-2015-0970)', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', score: 8.8 },
  { name: 'SSL/TLS MITM (CVE-2014-0224)', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N', score: 7.4 },
  { name: 'Chrome Sandbox Bypass (CVE-2012-5376)', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H', score: 9.6 },
  { name: 'Chrome PDFium JPEG 2000 RCE (CVE-2016-1645)', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', score: 8.8 },
  { name: 'SAMR/LSAD Privilege Escalation (CVE-2016-0128)', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N', score: 6.8 },
  { name: 'SAMR/LSAD Privilege Escalation (CVE-2016-2118)', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H', score: 7.5 },
  { name: 'WordPress WP Mail XSS (CVE-2017-5942)', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', score: 6.1 },
  { name: 'Opera DLL Search Order Hijacking (CVE-2018-18913)', vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', score: 7.8 },
  { name: 'Oracle Outside In Technology (CVE-2016-5558)', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L', score: 8.6 },
  { name: 'Lenovo ThnkPwn (CVE-2016-5729)', vector: 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H', score: 8.2 },
  { name: 'Flash Lock on Resume (CVE-2015-2890)', vector: 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H', score: 6.0 },
  { name: 'Intel DCI Issue (CVE-2018-3652)', vector: 'CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', score: 7.6 },
  { name: 'Scripting Engine Memory Corruption - IE (CVE-2019-0884)', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H', score: 7.5 },
  { name: 'Scripting Engine Memory Corruption - Edge (CVE-2019-0884)', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N', score: 4.2 },
];

describe('computeCvssV31BaseScore — FIRST.org published worked examples', () => {
  for (const example of FIRST_ORG_EXAMPLES) {
    it(`${example.name}: ${example.vector} -> ${example.score}`, () => {
      const parsed = parseCvssV31VectorString(example.vector);
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) return;
      const result = computeCvssV31BaseScore(parsed.metrics);
      expect(result.baseScore).toBeCloseTo(example.score, 5);
      expect(result.baseScore).toBe(example.score);
    });
  }
});

describe('cvssRoundUp — the spec Appendix A Roundup function', () => {
  it('returns an already-1-decimal value unchanged', () => {
    expect(cvssRoundUp(4.0)).toBe(4.0);
    expect(cvssRoundUp(7.5)).toBe(7.5);
    expect(cvssRoundUp(10)).toBe(10);
    expect(cvssRoundUp(0)).toBe(0);
  });

  it('rounds UP (never down) to the next one-decimal value', () => {
    expect(cvssRoundUp(4.01)).toBe(4.1);
    expect(cvssRoundUp(4.02)).toBe(4.1);
    expect(cvssRoundUp(4.09999)).toBe(4.1);
    expect(cvssRoundUp(6.42)).toBe(6.5);
  });
});

describe('cvssSeverityRating — Base severity bands (Section 5)', () => {
  it('0.0 -> None', () => {
    expect(cvssSeverityRating(0)).toBe('None');
  });
  it('0.1-3.9 -> Low', () => {
    expect(cvssSeverityRating(0.1)).toBe('Low');
    expect(cvssSeverityRating(3.9)).toBe('Low');
  });
  it('4.0-6.9 -> Medium', () => {
    expect(cvssSeverityRating(4.0)).toBe('Medium');
    expect(cvssSeverityRating(6.9)).toBe('Medium');
  });
  it('7.0-8.9 -> High', () => {
    expect(cvssSeverityRating(7.0)).toBe('High');
    expect(cvssSeverityRating(8.9)).toBe('High');
  });
  it('9.0-10.0 -> Critical', () => {
    expect(cvssSeverityRating(9.0)).toBe('Critical');
    expect(cvssSeverityRating(10.0)).toBe('Critical');
  });

  it('every FIRST.org example score maps to the severity band its own CVE is publicly rated at', () => {
    // Cross-check severity derivation end-to-end using the real examples above.
    expect(cvssSeverityRating(9.8)).toBe('Critical'); // Shellshock
    expect(cvssSeverityRating(7.5)).toBe('High'); // Heartbleed
    expect(cvssSeverityRating(3.1)).toBe('Low'); // POODLE
  });
});

describe('impact <= 0 short-circuit', () => {
  it('an all-None impact vector scores exactly 0.0 (None), not a tiny positive number', () => {
    const metrics: CvssV31Metrics = { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'N' };
    const result = computeCvssV31BaseScore(metrics);
    expect(result.baseScore).toBe(0);
    expect(result.severity).toBe('None');
  });
});

describe('buildCvssV31VectorString', () => {
  it('builds the canonical vector string in fixed metric order', () => {
    const metrics: CvssV31Metrics = { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' };
    expect(buildCvssV31VectorString(metrics)).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  });

  it('round-trips through parseCvssV31VectorString for every FIRST.org example', () => {
    for (const example of FIRST_ORG_EXAMPLES) {
      const parsed = parseCvssV31VectorString(example.vector);
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) return;
      expect(buildCvssV31VectorString(parsed.metrics)).toBe(example.vector);
    }
  });

  it('round-trips the DEFAULT_CVSS_METRICS starting point', () => {
    const vector = buildCvssV31VectorString(DEFAULT_CVSS_METRICS);
    const parsed = parseCvssV31VectorString(vector);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(parsed.metrics).toEqual(DEFAULT_CVSS_METRICS);
  });
});

describe('parseCvssV31VectorString — error handling (documented subset: Base metrics only)', () => {
  it('rejects an empty string', () => {
    const result = parseCvssV31VectorString('');
    expect(result.ok).toBe(false);
  });

  it('rejects a missing/wrong CVSS version prefix', () => {
    expect(parseCvssV31VectorString('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').ok).toBe(false);
    expect(parseCvssV31VectorString('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').ok).toBe(false);
    expect(parseCvssV31VectorString('CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').ok).toBe(false);
  });

  it('rejects a vector missing metrics', () => {
    const result = parseCvssV31VectorString('CVSS:3.1/AV:N/AC:L/PR:N');
    expect(result.ok).toBe(false);
  });

  it('rejects a vector with an invalid value for a metric', () => {
    const result = parseCvssV31VectorString('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(result.ok).toBe(false);
  });

  it('rejects out-of-order metrics', () => {
    const result = parseCvssV31VectorString('CVSS:3.1/AC:L/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(result.ok).toBe(false);
  });

  it('rejects a metric segment with more than one ":" instead of silently ignoring the trailing junk', () => {
    const result = parseCvssV31VectorString('CVSS:3.1/AV:N:BOGUS/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(result.ok).toBe(false);
  });

  it('rejects a vector with trailing Temporal/Environmental metrics (out of scope)', () => {
    const result = parseCvssV31VectorString('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:O/RC:C');
    expect(result.ok).toBe(false);
  });

  it('accepts a valid vector and returns the exact metrics', () => {
    const result = parseCvssV31VectorString('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.metrics).toEqual({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' });
    }
  });
});

describe('CVSS_METRIC_ORDER', () => {
  it('is the 8 Base metrics in the spec canonical order', () => {
    expect(CVSS_METRIC_ORDER).toEqual(['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']);
  });
});
