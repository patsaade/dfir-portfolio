import { describe, it, expect } from 'vitest';
import { parseIPv6, formatIPv6, parseCidr6, isSameSubnet6 } from '../src/utils/cidr6';

describe('parseIPv6/formatIPv6', () => {
  it('round-trips a full 8-group address', () => {
    const v = parseIPv6('2001:0db8:0000:0000:0000:8a2e:0370:7334')!;
    expect(formatIPv6(v)).toBe('2001:db8::8a2e:370:7334');
  });

  it('parses and canonicalizes a "::"-compressed address', () => {
    expect(formatIPv6(parseIPv6('2001:db8::1')!)).toBe('2001:db8::1');
  });

  it('parses the loopback address', () => {
    expect(formatIPv6(parseIPv6('::1')!)).toBe('::1');
  });

  it('parses the unspecified address', () => {
    expect(formatIPv6(parseIPv6('::')!)).toBe('::');
  });

  it('parses an embedded IPv4 dotted-quad (IPv4-mapped)', () => {
    const v = parseIPv6('::ffff:192.168.1.1')!;
    expect(v).not.toBeNull();
    expect(formatIPv6(v)).toBe('::ffff:c0a8:101');
  });

  it('parses an embedded IPv4 dotted-quad after a non-empty head (NAT64-style)', () => {
    const v = parseIPv6('64:ff9b::192.168.1.1')!;
    expect(formatIPv6(v)).toBe('64:ff9b::c0a8:101');
  });

  it('rejects two "::" in one address', () => {
    expect(parseIPv6('2001::db8::1')).toBeNull();
  });

  it('rejects an invalid hex group', () => {
    expect(parseIPv6('2001:zzzz::1')).toBeNull();
  });

  it('rejects a full address with the wrong group count', () => {
    expect(parseIPv6('2001:db8:1:2:3:4:5')).toBeNull(); // 7 groups, no "::"
  });

  it('rejects malformed embedded IPv4', () => {
    expect(parseIPv6('::ffff:999.168.1.1')).toBeNull();
  });

  it('strips a zone index', () => {
    expect(formatIPv6(parseIPv6('fe80::1%eth0')!)).toBe('fe80::1');
  });

  it('canonicalization compresses the longest run, first-occurring on a tie', () => {
    // Two equal-length one-group zero runs at positions 1 and 4 (0-indexed):
    // 2001:0:1:2:0:3:4:5 -> both runs are length 1, so neither should compress
    // (RFC 5952: never compress a single lone zero group).
    expect(formatIPv6(parseIPv6('2001:0:1:2:0:3:4:5')!)).toBe('2001:0:1:2:0:3:4:5');
    // Two runs of length 2 each: prefer the first (positions 1-2) over the
    // second (positions 5-6).
    expect(formatIPv6(parseIPv6('2001:0:0:2:3:0:0:6')!)).toBe('2001::2:3:0:0:6');
  });

  it('expand renders the full 8-group zero-padded form', () => {
    expect(formatIPv6(parseIPv6('::1')!, { expand: true })).toBe('0000:0000:0000:0000:0000:0000:0000:0001');
  });
});

describe('parseCidr6', () => {
  it('computes a /64', () => {
    const r = parseCidr6('2001:db8:1:2::/64')!;
    expect(r.network).toBe('2001:db8:1:2::');
    expect(r.lastAddress).toBe('2001:db8:1:2:ffff:ffff:ffff:ffff');
  });

  it('computes a /128 (single address)', () => {
    const r = parseCidr6('::1/128')!;
    expect(r.network).toBe('::1');
    expect(r.lastAddress).toBe('::1');
    expect(r.totalAddressesLabel).toBe('1');
  });

  it('computes /0 (the whole address space)', () => {
    const r = parseCidr6('::/0')!;
    expect(r.network).toBe('::');
    expect(r.lastAddress).toBe('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');
  });

  it('normalizes a host address down to its network', () => {
    const r = parseCidr6('2001:db8::1234/32')!;
    expect(r.ip).toBe('2001:db8::1234');
    expect(r.network).toBe('2001:db8::');
  });

  it('formats a huge address count as a power of two, not a raw digit string', () => {
    const r = parseCidr6('2001:db8::/32')!;
    expect(r.totalAddressesLabel).toMatch(/^2\^96 \(~/);
  });

  it('shows an exact digit count for a small enough block', () => {
    const r = parseCidr6('2001:db8::/120')!;
    expect(r.totalAddressesLabel).toBe('256');
  });

  it('rejects a bad prefix', () => {
    expect(parseCidr6('2001:db8::/129')).toBeNull();
    expect(parseCidr6('2001:db8::/-1')).toBeNull();
  });

  it('rejects malformed input', () => {
    expect(parseCidr6('2001:db8::')).toBeNull();
    expect(parseCidr6('not-a-cidr')).toBeNull();
  });
});

describe('isSameSubnet6', () => {
  it('confirms two addresses in the same /64', () => {
    expect(isSameSubnet6('2001:db8:1:2::1', '2001:db8:1:2:ffff::9', 64)).toBe(true);
  });
  it('rejects two addresses in different /64s', () => {
    expect(isSameSubnet6('2001:db8:1:2::1', '2001:db8:1:3::1', 64)).toBe(false);
  });
  it('returns false for an unparseable address', () => {
    expect(isSameSubnet6('not-an-ip', '::1', 64)).toBe(false);
  });
});
