import { describe, it, expect } from 'vitest';
import {
  parseIPv4,
  formatIPv4,
  parseCidr,
  isSameSubnet,
  prefixForHosts,
  splitEqual,
  rangeToCidrBlocks,
  planVlsm,
  supernetFor,
} from '../src/utils/cidr';

describe('parseIPv4/formatIPv4', () => {
  it('round-trips a normal address', () => {
    expect(formatIPv4(parseIPv4('192.168.1.1')!)).toBe('192.168.1.1');
  });
  it('rejects an out-of-range octet', () => {
    expect(parseIPv4('192.168.1.256')).toBeNull();
  });
  it('rejects a malformed address', () => {
    expect(parseIPv4('192.168.1')).toBeNull();
    expect(parseIPv4('not.an.ip.addr')).toBeNull();
  });
});

describe('parseCidr', () => {
  it('computes a standard /24', () => {
    const r = parseCidr('192.168.1.10/24')!;
    expect(r.network).toBe('192.168.1.0');
    expect(r.broadcast).toBe('192.168.1.255');
    expect(r.netmask).toBe('255.255.255.0');
    expect(r.firstHost).toBe('192.168.1.1');
    expect(r.lastHost).toBe('192.168.1.254');
    expect(r.usableHosts).toBe(254);
    expect(r.totalHosts).toBe(256);
  });

  it('computes a /30', () => {
    const r = parseCidr('10.0.0.0/30')!;
    expect(r.network).toBe('10.0.0.0');
    expect(r.broadcast).toBe('10.0.0.3');
    expect(r.usableHosts).toBe(2);
    expect(r.firstHost).toBe('10.0.0.1');
    expect(r.lastHost).toBe('10.0.0.2');
  });

  it('handles /31 as a point-to-point link (RFC 3021), no broadcast/network split', () => {
    const r = parseCidr('10.0.0.0/31')!;
    expect(r.usableHosts).toBe(2);
    expect(r.firstHost).toBe('10.0.0.0');
    expect(r.lastHost).toBe('10.0.0.1');
  });

  it('handles /32 as a single host', () => {
    const r = parseCidr('10.0.0.5/32')!;
    expect(r.usableHosts).toBe(1);
    expect(r.totalHosts).toBe(1);
    expect(r.network).toBe('10.0.0.5');
    expect(r.broadcast).toBe('10.0.0.5');
  });

  it('handles /0 (default route)', () => {
    const r = parseCidr('0.0.0.0/0')!;
    expect(r.netmask).toBe('0.0.0.0');
    expect(r.totalHosts).toBe(2 ** 32);
  });

  it('rejects a bad prefix', () => {
    expect(parseCidr('10.0.0.0/33')).toBeNull();
    expect(parseCidr('10.0.0.0/-1')).toBeNull();
  });

  it('rejects malformed input', () => {
    expect(parseCidr('10.0.0.0')).toBeNull();
    expect(parseCidr('not-a-cidr')).toBeNull();
  });

  it('normalizes a host address to its network (masks off host bits)', () => {
    const r = parseCidr('192.168.1.200/24')!;
    expect(r.ip).toBe('192.168.1.200');
    expect(r.network).toBe('192.168.1.0');
  });
});

describe('isSameSubnet', () => {
  it('confirms two addresses in the same /24', () => {
    expect(isSameSubnet('192.168.1.10', '192.168.1.250', 24)).toBe(true);
  });
  it('rejects two addresses in different /24s', () => {
    expect(isSameSubnet('192.168.1.10', '192.168.2.10', 24)).toBe(false);
  });
  it('returns false for an unparseable address', () => {
    expect(isSameSubnet('not-an-ip', '192.168.1.1', 24)).toBe(false);
  });
});

describe('prefixForHosts', () => {
  it('finds the smallest block covering common host counts', () => {
    expect(prefixForHosts(1)).toBe(32);
    expect(prefixForHosts(2)).toBe(31);
    expect(prefixForHosts(3)).toBe(29); // /30 only has 2 usable, so 3 needs a /29 (6 usable)
    expect(prefixForHosts(6)).toBe(29);
    expect(prefixForHosts(50)).toBe(26); // /26 = 62 usable
    expect(prefixForHosts(254)).toBe(24);
    expect(prefixForHosts(255)).toBe(23); // one more than a /24 can hold
  });
  it('rejects non-positive or unrepresentable requests', () => {
    expect(prefixForHosts(0)).toBeNull();
    expect(prefixForHosts(-5)).toBeNull();
    expect(prefixForHosts(2 ** 33)).toBeNull();
  });
  it('rounds a fractional request up', () => {
    expect(prefixForHosts(50.2)).toBe(prefixForHosts(51));
  });
});

describe('splitEqual', () => {
  it('splits a /24 into 4 equal /26s', () => {
    const r = splitEqual('192.168.1.0/24', 4)!;
    expect(r.count).toBe(4);
    expect(r.subnetPrefix).toBe(26);
    expect(r.subnets.map((s) => s.network)).toEqual(['192.168.1.0', '192.168.1.64', '192.168.1.128', '192.168.1.192']);
    expect(r.subnets.every((s) => s.usableHosts === 62)).toBe(true);
  });
  it('rounds a non-power-of-two count up (3 -> 4)', () => {
    const r = splitEqual('10.0.0.0/24', 3)!;
    expect(r.requestedCount).toBe(3);
    expect(r.count).toBe(4);
  });
  it('returns null when asked to split past /32', () => {
    expect(splitEqual('10.0.0.0/24', 1000)).toBeNull();
  });
  it('returns null for a bad base network or count', () => {
    expect(splitEqual('not-a-cidr', 4)).toBeNull();
    expect(splitEqual('10.0.0.0/24', 0)).toBeNull();
  });
});

describe('rangeToCidrBlocks', () => {
  it('reduces a single aligned block to one CIDR', () => {
    expect(rangeToCidrBlocks(parseIPv4('10.0.0.0')!, parseIPv4('10.0.0.255')!)).toEqual(['10.0.0.0/24']);
  });
  it('reduces an odd-length range to several blocks', () => {
    // 10.0.0.10 - 10.0.0.20 is not a power-of-two-aligned single block.
    const blocks = rangeToCidrBlocks(parseIPv4('10.0.0.10')!, parseIPv4('10.0.0.20')!);
    expect(blocks.length).toBeGreaterThan(1);
    // Every block's own math should round-trip and the blocks should cover
    // the range exactly, back to back, with no gaps or overlaps.
    let cursor = parseIPv4('10.0.0.10')!;
    for (const b of blocks) {
      const r = parseCidr(b)!;
      expect(parseIPv4(r.network)).toBe(cursor);
      cursor = parseIPv4(r.broadcast)! + 1;
    }
    expect(cursor).toBe(parseIPv4('10.0.0.20')! + 1);
  });
});

describe('planVlsm', () => {
  it('packs descending-size requests with zero fragmentation', () => {
    const plan = planVlsm('10.0.0.0/24', [
      { id: 'a', label: 'Servers', hosts: 100 },
      { id: 'b', label: 'Users', hosts: 50 },
      { id: 'c', label: 'Printers', hosts: 10 },
    ])!;
    expect(plan.overflow).toBe(false);
    const byId = Object.fromEntries(plan.allocations.map((a) => [a.id, a]));
    // Largest (100 hosts -> /25) is placed first at the base network start.
    expect(byId.a.cidr!.network).toBe('10.0.0.0');
    expect(byId.a.cidr!.prefix).toBe(25);
    // Next (50 hosts -> /26) packs immediately after with no gap.
    expect(byId.b.cidr!.network).toBe('10.0.0.128');
    expect(byId.b.cidr!.prefix).toBe(26);
    // Smallest (10 hosts -> /28) packs right after that.
    expect(byId.c.cidr!.network).toBe('10.0.0.192');
    expect(byId.c.cidr!.prefix).toBe(28);
    // Output order matches input order, not allocation (size) order.
    expect(plan.allocations.map((a) => a.id)).toEqual(['a', 'b', 'c']);
  });

  it('reports free space as real CIDR blocks', () => {
    const plan = planVlsm('10.0.0.0/24', [{ id: 'a', label: 'LAN', hosts: 100 }])!;
    // 100 hosts -> /25 (10.0.0.0-127), leaving 10.0.0.128-255 free.
    expect(plan.freeBlocks).toEqual(['10.0.0.128/25']);
    expect(plan.usedAddresses).toBe(128);
    expect(plan.totalAddresses).toBe(256);
  });

  it('flags a request that does not fit, without corrupting the ones that do', () => {
    const plan = planVlsm('10.0.0.0/24', [
      { id: 'huge', label: 'Too big', hosts: 1000 }, // needs a /22, base is only a /24
      { id: 'small', label: 'Fits fine', hosts: 10 },
    ])!;
    expect(plan.overflow).toBe(true);
    const byId = Object.fromEntries(plan.allocations.map((a) => [a.id, a]));
    expect(byId.huge.fits).toBe(false);
    expect(byId.huge.cidr).toBeNull();
    expect(byId.small.fits).toBe(true);
    expect(byId.small.cidr!.network).toBe('10.0.0.0');
  });

  it('returns null for an unparseable base network', () => {
    expect(planVlsm('not-a-cidr', [{ id: 'a', label: 'x', hosts: 10 }])).toBeNull();
  });

  it('handles an empty request list', () => {
    const plan = planVlsm('10.0.0.0/24', [])!;
    expect(plan.allocations).toEqual([]);
    expect(plan.overflow).toBe(false);
    expect(plan.freeBlocks).toEqual(['10.0.0.0/24']);
  });
});

describe('supernetFor', () => {
  it('combines two adjacent /25s into their exact parent /24', () => {
    const a = parseCidr('10.0.0.0/25')!;
    const b = parseCidr('10.0.0.128/25')!;
    const s = supernetFor([a, b]);
    expect(s.network).toBe('10.0.0.0');
    expect(s.prefix).toBe(24);
    expect(s.broadcast).toBe('10.0.0.255');
  });

  it('finds the smallest block covering non-adjacent subnets, even if not tightly packed', () => {
    const a = parseCidr('10.0.0.0/24')!;
    const b = parseCidr('10.0.5.0/24')!;
    const s = supernetFor([a, b]);
    // 10.0.0.0-10.0.5.255 needs at least a /21 (10.0.0.0-10.0.7.255) to be
    // both aligned and cover both inputs.
    expect(s.network).toBe('10.0.0.0');
    expect(s.prefix).toBe(21);
  });

  it('returns the input itself when given a single CIDR', () => {
    const a = parseCidr('192.168.1.0/24')!;
    const s = supernetFor([a]);
    expect(s.network).toBe('192.168.1.0');
    expect(s.prefix).toBe(24);
  });

  it('handles three scattered subnets', () => {
    const cidrs = ['172.16.0.0/24', '172.16.2.0/24', '172.16.3.0/24'].map((c) => parseCidr(c)!);
    const s = supernetFor(cidrs);
    // Covers 172.16.0.0-172.16.3.255 -> smallest aligned block is a /22.
    expect(s.network).toBe('172.16.0.0');
    expect(s.prefix).toBe(22);
  });
});
