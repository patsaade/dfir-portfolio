// CIDR/Subnet Calculator — pure IPv4 CIDR math, no external research needed
// (this is arithmetic defined by the CIDR spec itself, RFC 4632). Every
// function is a pure, side-effect-free transform from a parsed CIDR to its
// derived values, so it's fully unit-testable without a DOM.

export interface CidrResult {
  input: string;
  ip: string;
  prefix: number;
  netmask: string;
  wildcard: string;
  network: string;
  broadcast: string;
  firstHost: string | null;
  lastHost: string | null;
  totalHosts: number;
  usableHosts: number;
}

export function parseIPv4(ip: string): number | null {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v < 0 || v > 255) return null;
    n = (n << 8) | v;
  }
  return n >>> 0;
}

export function formatIPv4(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

// /31 and /32 have no usable-host range in the classic broadcast sense (RFC
// 3021 repurposes /31 for two-host point-to-point links, and /32 is a single
// host) — reflected here rather than a misleading negative count. Shared by
// parseCidr and prefixForHosts so the two can never drift out of sync.
function usableHostsForPrefix(prefix: number): number {
  const total = 2 ** (32 - prefix);
  return prefix >= 31 ? total : Math.max(total - 2, 0);
}

export function parseCidr(input: string): CidrResult | null {
  const trimmed = input.trim();
  const match = trimmed.match(/^([^/]+)\/(\d{1,2})$/);
  if (!match) return null;
  const ip = parseIPv4(match[1]);
  const prefix = Number(match[2]);
  if (ip === null || prefix < 0 || prefix > 32) return null;

  const maskBits = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const wildcardBits = (~maskBits) >>> 0;
  const network = (ip & maskBits) >>> 0;
  const broadcast = (network | wildcardBits) >>> 0;
  const totalHosts = 2 ** (32 - prefix);
  const usableHosts = usableHostsForPrefix(prefix);
  const firstHost = prefix >= 31 ? formatIPv4(network) : totalHosts > 2 ? formatIPv4(network + 1) : null;
  const lastHost = prefix >= 31 ? formatIPv4(broadcast) : totalHosts > 2 ? formatIPv4(broadcast - 1) : null;

  return {
    input: trimmed,
    ip: formatIPv4(ip),
    prefix,
    netmask: formatIPv4(maskBits),
    wildcard: formatIPv4(wildcardBits),
    network: formatIPv4(network),
    broadcast: formatIPv4(broadcast),
    firstHost,
    lastHost,
    totalHosts,
    usableHosts,
  };
}

export function isSameSubnet(a: string, b: string, prefix: number): boolean {
  const ipA = parseIPv4(a);
  const ipB = parseIPv4(b);
  if (ipA === null || ipB === null) return false;
  const maskBits = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipA & maskBits) >>> 0 === (ipB & maskBits) >>> 0;
}

// ── Subnet / VLAN planning (VLSM, RFC 1878) ─────────────────────────────────
// A VLAN ID itself is just an operator-chosen label — nothing here invents or
// computes one. What these functions compute is the IP math underneath it:
// how big a block a given host count actually needs, and how to lay several
// such blocks out inside one base network without overlapping.

// Smallest available prefix (i.e. largest prefix number, smallest block) whose
// usable-host capacity is at least `hosts` — the classic "how big a subnet do
// I need" question. Null for a non-positive or unrepresentable request.
export function prefixForHosts(hosts: number): number | null {
  const h = Math.ceil(hosts);
  if (!Number.isFinite(h) || h <= 0 || h > 2 ** 32) return null;
  for (let prefix = 32; prefix >= 0; prefix--) {
    if (usableHostsForPrefix(prefix) >= h) return prefix;
  }
  return 0;
}

export interface EqualSplitResult {
  base: CidrResult;
  requestedCount: number;
  count: number; // actual count, rounded up to a power of two
  subnetPrefix: number;
  subnets: CidrResult[];
}

// Splits a base network into the smallest power-of-two number of equal
// subnets that is >= requestedCount (subnets can only ever divide evenly into
// powers of two, so asking for e.g. 3 actually yields 4).
export function splitEqual(baseCidrStr: string, requestedCount: number): EqualSplitResult | null {
  const base = parseCidr(baseCidrStr);
  const req = Math.ceil(requestedCount);
  if (!base || !Number.isFinite(req) || req < 1) return null;
  const extraBits = Math.max(Math.ceil(Math.log2(req)), 0);
  const subnetPrefix = base.prefix + extraBits;
  if (subnetPrefix > 32) return null; // more subnets than the base network can hold
  const count = 2 ** extraBits;
  const blockSize = 2 ** (32 - subnetPrefix);
  const baseNetworkInt = parseIPv4(base.network)!;
  const subnets: CidrResult[] = [];
  for (let i = 0; i < count; i++) {
    const netInt = baseNetworkInt + i * blockSize;
    subnets.push(parseCidr(`${formatIPv4(netInt)}/${subnetPrefix}`)!);
  }
  return { base, requestedCount: req, count, subnetPrefix, subnets };
}

// Decomposes an inclusive [startInt, endInt] address range into the minimal
// list of CIDR blocks that cover it exactly (the standard range-to-CIDR
// reduction) — used to describe VLSM leftover space as real, assignable
// blocks instead of just a raw address count.
export function rangeToCidrBlocks(startInt: number, endInt: number): string[] {
  const blocks: string[] = [];
  let start = startInt;
  while (start <= endInt) {
    let bits = 32;
    while (bits > 0) {
      const size = 2 ** bits;
      if (start % size === 0 && start + size - 1 <= endInt) break;
      bits--;
    }
    blocks.push(`${formatIPv4(start)}/${32 - bits}`);
    start += 2 ** bits;
  }
  return blocks;
}

export interface VlsmRequest {
  id: string;
  label: string;
  hosts: number;
}
interface VlsmAllocation {
  id: string;
  label: string;
  hosts: number;
  prefix: number | null;
  cidr: CidrResult | null;
  fits: boolean;
}
export interface VlsmPlanResult {
  base: CidrResult;
  allocations: VlsmAllocation[]; // same order as the input requests
  usedAddresses: number;
  totalAddresses: number;
  freeBlocks: string[];
  overflow: boolean;
}

// Allocates one right-sized block per request inside baseCidrStr. Requests
// are placed largest-block-first: since every smaller power-of-two block
// divides evenly into any larger one, a strictly size-descending placement
// order can never leave an alignment gap between two successfully-placed
// blocks — the only gaps possible are from a request that didn't fit at all,
// and those are reported explicitly (fits: false) rather than silently
// skipped or allowed to corrupt later placements.
// The reverse of VLSM: given several subnets already in use, find the
// smallest single CIDR-aligned block that contains all of them — the
// classic route-summarization/supernetting question. Iterates from the most
// specific prefix (32) down to the least (0), snapping the candidate
// block's start down to the nearest boundary at or below the lowest input
// address, and stopping at the first (most specific) block size whose
// aligned range also reaches the highest input address. If the inputs
// aren't already contiguous/aligned, the result legitimately contains
// address space outside the originals — that's inherent to supernetting,
// not a bug (there's no smaller *single* CIDR block that could cover a
// scattered set).
export function supernetFor(cidrs: CidrResult[]): CidrResult {
  const starts = cidrs.map((c) => parseIPv4(c.network)!);
  const ends = cidrs.map((c) => parseIPv4(c.broadcast)!);
  const minStart = Math.min(...starts);
  const maxEnd = Math.max(...ends);
  for (let prefix = 32; prefix >= 0; prefix--) {
    const blockSize = 2 ** (32 - prefix);
    const alignedStart = Math.floor(minStart / blockSize) * blockSize;
    if (alignedStart + blockSize - 1 >= maxEnd) {
      return parseCidr(`${formatIPv4(alignedStart)}/${prefix}`)!;
    }
  }
  return parseCidr('0.0.0.0/0')!;
}

export function planVlsm(baseCidrStr: string, requests: VlsmRequest[]): VlsmPlanResult | null {
  const base = parseCidr(baseCidrStr);
  if (!base) return null;
  const baseNetworkInt = parseIPv4(base.network)!;
  const baseBroadcastInt = parseIPv4(base.broadcast)!;

  const withPrefix = requests.map((r, i) => ({ ...r, origIndex: i, prefix: prefixForHosts(r.hosts) }));
  const sorted = [...withPrefix].sort((a, b) => {
    if (a.prefix === null && b.prefix === null) return a.origIndex - b.origIndex;
    if (a.prefix === null) return 1;
    if (b.prefix === null) return -1;
    if (a.prefix !== b.prefix) return a.prefix - b.prefix; // smaller prefix number = bigger block, placed first
    return a.origIndex - b.origIndex;
  });

  let cursor = baseNetworkInt;
  const allocById = new Map<string, VlsmAllocation>();
  for (const r of sorted) {
    if (r.prefix === null) {
      allocById.set(r.id, { id: r.id, label: r.label, hosts: r.hosts, prefix: null, cidr: null, fits: false });
      continue;
    }
    const blockSize = 2 ** (32 - r.prefix);
    const aligned = Math.ceil(cursor / blockSize) * blockSize;
    const end = aligned + blockSize - 1;
    if (end > baseBroadcastInt) {
      // Doesn't fit — cursor is left unchanged so a later, smaller request
      // (processed next, since we're going largest-to-smallest) can still
      // try the same remaining gap instead of being blocked by this failure.
      allocById.set(r.id, { id: r.id, label: r.label, hosts: r.hosts, prefix: r.prefix, cidr: null, fits: false });
      continue;
    }
    const cidr = parseCidr(`${formatIPv4(aligned)}/${r.prefix}`)!;
    allocById.set(r.id, { id: r.id, label: r.label, hosts: r.hosts, prefix: r.prefix, cidr, fits: true });
    cursor = aligned + blockSize;
  }

  const allocations = withPrefix.map((r) => allocById.get(r.id)!);
  const usedAddresses = allocations.reduce((sum, a) => sum + (a.cidr ? a.cidr.totalHosts : 0), 0);
  const overflow = allocations.some((a) => !a.fits);
  const freeBlocks = cursor > baseBroadcastInt ? [] : rangeToCidrBlocks(cursor, baseBroadcastInt);

  return { base, allocations, usedAddresses, totalAddresses: base.totalHosts, freeBlocks, overflow };
}
