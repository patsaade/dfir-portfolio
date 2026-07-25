import { describe, it, expect } from 'vitest';
import { parseMacAddress } from '../src/utils/macAddress';

describe('parseMacAddress — valid input shapes', () => {
  it('parses a colon-separated address', () => {
    const r = parseMacAddress('00:1a:2b:3c:4d:5e')!;
    expect(r).not.toBeNull();
    expect(r.octets).toEqual(['00', '1a', '2b', '3c', '4d', '5e']);
    expect(r.formatted).toBe('00:1a:2b:3c:4d:5e');
  });

  it('parses a hyphen-separated address', () => {
    const r = parseMacAddress('00-1a-2b-3c-4d-5e')!;
    expect(r.octets).toEqual(['00', '1a', '2b', '3c', '4d', '5e']);
    expect(r.formatted).toBe('00:1a:2b:3c:4d:5e');
  });

  it('parses a bare 12-hex-digit address with no separator', () => {
    const r = parseMacAddress('001a2b3c4d5e')!;
    expect(r.octets).toEqual(['00', '1a', '2b', '3c', '4d', '5e']);
    expect(r.formatted).toBe('00:1a:2b:3c:4d:5e');
  });

  it('is case-insensitive and normalizes output to lowercase', () => {
    const r1 = parseMacAddress('AA:BB:CC:DD:EE:FF')!;
    expect(r1.formatted).toBe('aa:bb:cc:dd:ee:ff');
    const r2 = parseMacAddress('Aa-bB-cC-dD-eE-fF')!;
    expect(r2.formatted).toBe('aa:bb:cc:dd:ee:ff');
    const r3 = parseMacAddress('AaBbCcDdEeFf')!;
    expect(r3.formatted).toBe('aa:bb:cc:dd:ee:ff');
  });

  it('trims surrounding whitespace', () => {
    const r = parseMacAddress('  00:1a:2b:3c:4d:5e  ')!;
    expect(r.formatted).toBe('00:1a:2b:3c:4d:5e');
  });
});

describe('parseMacAddress — OUI / NIC-specific split', () => {
  it('splits the first 3 and last 3 octets', () => {
    const r = parseMacAddress('00:1a:2b:3c:4d:5e')!;
    expect(r.oui).toBe('00:1a:2b');
    expect(r.nic).toBe('3c:4d:5e');
  });
});

describe('parseMacAddress — U/L and I/G bit decoding', () => {
  // Four first-octet values covering all 2x2 combinations of the U/L bit
  // (bit 1, 0x02) and the I/G bit (bit 0, 0x01) — pure bit math, not tied to
  // any real-world vendor or protocol assignment.
  it('00 -> universally administered, unicast (both bits 0)', () => {
    const r = parseMacAddress('00:11:22:33:44:55')!;
    expect(r.firstOctetBinary).toBe('00000000');
    expect(r.isUniversallyAdministered).toBe(true);
    expect(r.isLocallyAdministered).toBe(false);
    expect(r.isUnicast).toBe(true);
    expect(r.isMulticast).toBe(false);
  });

  it('01 -> universally administered, multicast (I/G bit set)', () => {
    const r = parseMacAddress('01:11:22:33:44:55')!;
    expect(r.firstOctetBinary).toBe('00000001');
    expect(r.isUniversallyAdministered).toBe(true);
    expect(r.isMulticast).toBe(true);
    expect(r.isUnicast).toBe(false);
  });

  it('02 -> locally administered, unicast (U/L bit set) — constructed test value, not a claimed real vendor prefix', () => {
    const r = parseMacAddress('02:11:22:33:44:55')!;
    expect(r.firstOctetBinary).toBe('00000010');
    expect(r.isLocallyAdministered).toBe(true);
    expect(r.isUniversallyAdministered).toBe(false);
    expect(r.isUnicast).toBe(true);
    expect(r.isMulticast).toBe(false);
  });

  it('03 -> locally administered, multicast (both bits set)', () => {
    const r = parseMacAddress('03:11:22:33:44:55')!;
    expect(r.firstOctetBinary).toBe('00000011');
    expect(r.isLocallyAdministered).toBe(true);
    expect(r.isMulticast).toBe(true);
  });

  it('decodes a manually constructed locally-administered example with an OUI-shaped prefix', () => {
    // d2 = 11010010 — bit 1 (U/L) is set, bit 0 (I/G) is clear. Constructed
    // by hand specifically to exercise this case; not presented anywhere as
    // a real assigned vendor OUI.
    const r = parseMacAddress('d2:1a:2b:3c:4d:5e')!;
    expect(r.firstOctetBinary).toBe('11010010');
    expect(r.isLocallyAdministered).toBe(true);
    expect(r.isUnicast).toBe(true);
  });
});

describe('parseMacAddress — broadcast address', () => {
  it('flags ff:ff:ff:ff:ff:ff as broadcast', () => {
    const r = parseMacAddress('ff:ff:ff:ff:ff:ff')!;
    expect(r.isBroadcast).toBe(true);
    // Broadcast is a special case of multicast (I/G bit set) that is also
    // locally administered by convention (U/L bit set) — both derived bit
    // fields should reflect that, not just the isBroadcast flag.
    expect(r.isMulticast).toBe(true);
    expect(r.isLocallyAdministered).toBe(true);
  });

  it('does not flag a non-broadcast address, even an all-but-one-byte match', () => {
    const r = parseMacAddress('ff:ff:ff:ff:ff:fe')!;
    expect(r.isBroadcast).toBe(false);
  });
});

describe('parseMacAddress — rejects invalid input', () => {
  it('rejects the wrong number of octets', () => {
    expect(parseMacAddress('00:1a:2b:3c:4d')).toBeNull(); // 5 octets
    expect(parseMacAddress('00:1a:2b:3c:4d:5e:6f')).toBeNull(); // 7 octets
    expect(parseMacAddress('001a2b3c4d')).toBeNull(); // 10 hex chars
    expect(parseMacAddress('001a2b3c4d5e6f')).toBeNull(); // 14 hex chars
  });

  it('rejects invalid hex characters', () => {
    expect(parseMacAddress('00:1a:2b:3c:4d:5g')).toBeNull();
    expect(parseMacAddress('zz:1a:2b:3c:4d:5e')).toBeNull();
    expect(parseMacAddress('zz1a2b3c4d5e')).toBeNull();
  });

  it('rejects malformed/mixed separator patterns', () => {
    expect(parseMacAddress('00:1a-2b:3c:4d:5e')).toBeNull(); // mixed : and -
    expect(parseMacAddress('00::1a:2b:3c:4d:5e')).toBeNull(); // double colon
    expect(parseMacAddress('00:1a:2b:3c:4d:5e:')).toBeNull(); // trailing colon
    expect(parseMacAddress(':00:1a:2b:3c:4d:5e')).toBeNull(); // leading colon
    expect(parseMacAddress('00: 1a:2b:3c:4d:5e')).toBeNull(); // internal space
    expect(parseMacAddress('001a:2b:3c:4d:5e')).toBeNull(); // unbalanced groups
  });

  it('rejects empty or whitespace-only input', () => {
    expect(parseMacAddress('')).toBeNull();
    expect(parseMacAddress('   ')).toBeNull();
  });
});
