// IPv6 CIDR arithmetic (RFC 4291 addressing architecture, CIDR notation
// applied to 128-bit addresses per RFC 4632's same underlying idea, RFC 5952
// canonical textual representation). Every address is held internally as a
// 128-bit bigint — JS's Number can't carry that precision, so this
// deliberately does NOT share cidr.ts's plain-number/32-bit-bitwise-operator
// approach; the two families are different enough (no network/broadcast
// split, address counts routinely exceeding Number.MAX_SAFE_INTEGER) that
// mixing them in one file would muddy both.
//
// IPv6 has no "network address" / "broadcast address" reservation the way
// IPv4 does — every address in a subnet, including the all-zero host ID, is
// a real, assignable address. (RFC 4291 §2.6.1 reserves the all-zero
// interface ID as the "Subnet-Router anycast address", but that's a
// convention for routers to answer on, not an off-limits address the way
// IPv4's broadcast is.) So this module reports a network (first) address and
// a last address, never "broadcast" or "usable hosts" — those are IPv4-only
// concepts and this file doesn't pretend otherwise.

import { parseIPv4 as parseIPv4Legacy } from './cidr';

const GROUP_COUNT = 8;
const MAX_128 = (1n << 128n) - 1n;

/** Parses any RFC 4291 textual IPv6 address form: full 8-group, "::"
 *  zero-run compression (at most one "::" per address), and an embedded
 *  IPv4 dotted-quad as the trailing 32 bits (e.g. "::ffff:192.168.1.1",
 *  "64:ff9b::192.168.1.1" — the IPv4-mapped and NAT64 forms). A trailing
 *  "%zone" index (e.g. "fe80::1%eth0") is accepted and stripped, since it
 *  names an interface on the *originating* host, not part of the address
 *  value itself. Returns null for anything malformed — never throws. */
export function parseIPv6(input: string): bigint | null {
  let text = input.trim();
  if (!text) return null;
  text = text.split('%')[0];
  if (text.length === 0) return null;

  const doubleColonCount = (text.match(/::/g) || []).length;
  if (doubleColonCount > 1) return null;

  let headPart = text;
  let tailPart = '';
  const hasDoubleColon = doubleColonCount === 1;
  if (hasDoubleColon) {
    const idx = text.indexOf('::');
    headPart = text.slice(0, idx);
    tailPart = text.slice(idx + 2);
  }

  const splitGroups = (s: string): string[] => (s.length === 0 ? [] : s.split(':'));
  let headGroups = splitGroups(headPart);
  let tailGroups = splitGroups(tailPart);

  // An embedded IPv4 dotted-quad is only valid as the LAST group.
  const expandEmbeddedIPv4 = (groups: string[]): string[] | null => {
    if (groups.length === 0) return groups;
    const last = groups[groups.length - 1];
    if (!last.includes('.')) return groups;
    const v4 = parseIPv4Legacy(last);
    if (v4 === null) return null;
    const hi = ((v4 >>> 16) & 0xffff).toString(16);
    const lo = (v4 & 0xffff).toString(16);
    return [...groups.slice(0, -1), hi, lo];
  };
  const expandedHead = expandEmbeddedIPv4(headGroups);
  const expandedTail = expandEmbeddedIPv4(tailGroups);
  if (expandedHead === null || expandedTail === null) return null;
  headGroups = expandedHead;
  tailGroups = expandedTail;

  const isValidGroup = (g: string) => /^[0-9a-fA-F]{1,4}$/.test(g);
  if (!headGroups.every(isValidGroup) || !tailGroups.every(isValidGroup)) return null;

  let allGroups: string[];
  if (hasDoubleColon) {
    const missing = GROUP_COUNT - headGroups.length - tailGroups.length;
    if (missing < 0) return null; // "::" must actually stand in for at least one group
    allGroups = [...headGroups, ...Array(missing).fill('0'), ...tailGroups];
  } else {
    if (headGroups.length !== GROUP_COUNT) return null;
    allGroups = headGroups;
  }
  if (allGroups.length !== GROUP_COUNT) return null;

  let value = 0n;
  for (const g of allGroups) value = (value << 16n) | BigInt(parseInt(g, 16));
  return value;
}

/** Formats a 128-bit value back to text. Default output is RFC 5952
 *  canonical form (lowercase hex, no leading zeros per group, the single
 *  LONGEST run of consecutive all-zero groups compressed with "::" — the
 *  first such run wins a tie, and a lone zero group is never compressed).
 *  opts.expand renders the full, uncompressed 8-group form instead. */
export function formatIPv6(value: bigint, opts: { expand?: boolean } = {}): string {
  const v = value & MAX_128;
  const groups: string[] = [];
  for (let i = 7; i >= 0; i--) groups.push(((v >> BigInt(i * 16)) & 0xffffn).toString(16));
  if (opts.expand) return groups.map((g) => g.padStart(4, '0')).join(':');

  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < groups.length; i++) {
    if (groups[i] === '0') {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  if (bestLen < 2) return groups.join(':');
  const before = groups.slice(0, bestStart).join(':');
  const after = groups.slice(bestStart + bestLen).join(':');
  return `${before}::${after}`;
}

/** Human-readable address count for a given number of host bits. Below
 *  2^70ish this is still a plausible literal digit string; anything bigger
 *  (e.g. a /32's 2^96 addresses) is genuinely not meaningful as a 29-digit
 *  number to a human, so it's shown as "2^N (~X.XXe+YY)" instead — standard
 *  practice for describing IPv6 address-space sizes. */
function formatAddressCount6(hostBits: number): string {
  if (hostBits <= 0) return '1';
  const exact = 1n << BigInt(hostBits);
  const digits = exact.toString();
  if (digits.length <= 21) return digits;
  const approx = Math.pow(2, hostBits).toExponential(2);
  return `2^${hostBits} (~${approx})`;
}

export interface Cidr6Result {
  input: string;
  ip: string;
  ipExpanded: string;
  prefix: number;
  network: string;
  networkExpanded: string;
  lastAddress: string;
  totalAddressesLabel: string;
}

export function parseCidr6(input: string): Cidr6Result | null {
  const trimmed = input.trim();
  const match = trimmed.match(/^([^/]+)\/(\d{1,3})$/);
  if (!match) return null;
  const ip = parseIPv6(match[1]);
  const prefix = Number(match[2]);
  if (ip === null || prefix < 0 || prefix > 128) return null;

  const hostBits = 128 - prefix;
  const maskBits = (MAX_128 << BigInt(hostBits)) & MAX_128;
  const networkValue = ip & maskBits;
  const wildcardBits = MAX_128 >> BigInt(prefix);
  const lastValue = networkValue | wildcardBits;

  return {
    input: trimmed,
    ip: formatIPv6(ip),
    ipExpanded: formatIPv6(ip, { expand: true }),
    prefix,
    network: formatIPv6(networkValue),
    networkExpanded: formatIPv6(networkValue, { expand: true }),
    lastAddress: formatIPv6(lastValue),
    totalAddressesLabel: formatAddressCount6(hostBits),
  };
}

export function isSameSubnet6(a: string, b: string, prefix: number): boolean {
  const ipA = parseIPv6(a);
  const ipB = parseIPv6(b);
  if (ipA === null || ipB === null || prefix < 0 || prefix > 128) return false;
  const hostBits = 128 - prefix;
  const maskBits = (MAX_128 << BigInt(hostBits)) & MAX_128;
  return (ipA & maskBits) === (ipB & maskBits);
}
