// Public/private IP & CIDR cheat sheet — special-use IPv4/IPv6 address
// blocks that matter for DFIR (recognizing internal vs. external traffic at
// a glance, spotting a fabricated-example address in a report, understanding
// CGNAT/documentation ranges). Every entry here is sourced directly from
// IANA's own special-purpose address registries — the single authoritative
// source for "what is this block reserved for and by which RFC" — not
// second-hand summaries. Re-verify against the registries below if either
// ever adds/changes an entry:
//   https://www.iana.org/assignments/iana-ipv4-special-registry/
//   https://www.iana.org/assignments/iana-ipv6-special-registry/
import type { Reference } from './references';

type IpFamily = 'ipv4' | 'ipv6';
type IpRangeCategory =
  | 'private-use'
  | 'shared-address-space'
  | 'loopback'
  | 'link-local'
  | 'multicast'
  | 'documentation'
  | 'benchmarking'
  | 'translation'
  | 'reserved'
  | 'broadcast'
  | 'unique-local'
  | 'global-unicast';

export interface IpRangeEntry {
  cidr: string;
  name: string;
  family: IpFamily;
  category: IpRangeCategory;
  note: string;
  references: Reference[];
}

const IANA_IPV4: Reference = { name: 'IANA IPv4 Special-Purpose Address Registry', url: 'https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml' };
const IANA_IPV6: Reference = { name: 'IANA IPv6 Special-Purpose Address Registry', url: 'https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml' };
const RFC = (n: number): Reference => ({ name: `RFC ${n}`, url: `https://www.rfc-editor.org/rfc/rfc${n}` });

export const IP_RANGES: IpRangeEntry[] = [
  // ── IPv4 private-use (RFC 1918) ─────────────────────────────────────────
  {
    cidr: '10.0.0.0/8',
    name: 'Private-Use',
    family: 'ipv4',
    category: 'private-use',
    note: 'The largest RFC 1918 block (16.7M addresses) — the default range for most enterprise internal networks.',
    references: [RFC(1918), IANA_IPV4],
  },
  {
    cidr: '172.16.0.0/12',
    name: 'Private-Use',
    family: 'ipv4',
    category: 'private-use',
    note: 'RFC 1918 private range, 1.05M addresses — a common Docker/container-network default.',
    references: [RFC(1918), IANA_IPV4],
  },
  {
    cidr: '192.168.0.0/16',
    name: 'Private-Use',
    family: 'ipv4',
    category: 'private-use',
    note: 'RFC 1918 private range, 65,536 addresses — the default on almost every home/SOHO router.',
    references: [RFC(1918), IANA_IPV4],
  },
  // ── Shared address space (CGNAT) ────────────────────────────────────────
  {
    cidr: '100.64.0.0/10',
    name: 'Shared Address Space',
    family: 'ipv4',
    category: 'shared-address-space',
    note: 'Reserved for carrier-grade NAT (CGNAT) between an ISP’s customer-facing network and its own NAT devices — routable only within that provider’s network, distinct from RFC 1918. Seeing this in a log usually means the traffic traversed an ISP’s CGNAT layer, not a private LAN.',
    references: [RFC(6598), IANA_IPV4],
  },
  // ── Loopback ─────────────────────────────────────────────────────────────
  {
    cidr: '127.0.0.0/8',
    name: 'Loopback',
    family: 'ipv4',
    category: 'loopback',
    note: 'Any address in this whole /8 (not just 127.0.0.1) loops back to the local host — never appears on the wire.',
    references: [RFC(1122), IANA_IPV4],
  },
  // ── Link-local ───────────────────────────────────────────────────────────
  {
    cidr: '169.254.0.0/16',
    name: 'Link Local (APIPA)',
    family: 'ipv4',
    category: 'link-local',
    note: 'Auto-assigned by Windows/most OSes when DHCP fails — seeing this on a host is a strong signal it never reached a DHCP server, not evidence of a specific attack on its own.',
    references: [RFC(3927), IANA_IPV4],
  },
  // ── Multicast ────────────────────────────────────────────────────────────
  {
    cidr: '224.0.0.0/4',
    name: 'Multicast',
    family: 'ipv4',
    category: 'multicast',
    note: 'Class D multicast space — 224.0.0.0/24 specifically is reserved for local-network control traffic (routing protocols, mDNS, etc.) that a router never forwards off-segment.',
    references: [RFC(5771), IANA_IPV4],
  },
  // ── Documentation (RFC 5737 TEST-NETs) ──────────────────────────────────
  {
    cidr: '192.0.2.0/24',
    name: 'Documentation (TEST-NET-1)',
    family: 'ipv4',
    category: 'documentation',
    note: 'Reserved purely for documentation/examples — never routed on the real internet. This site’s own fabricated Email Header Analyzer sample uses this range for exactly that reason.',
    references: [RFC(5737), IANA_IPV4],
  },
  {
    cidr: '198.51.100.0/24',
    name: 'Documentation (TEST-NET-2)',
    family: 'ipv4',
    category: 'documentation',
    note: 'Same purpose as 192.0.2.0/24 — a second documentation block so an example can show two distinct "networks" without using anything real.',
    references: [RFC(5737), IANA_IPV4],
  },
  {
    cidr: '203.0.113.0/24',
    name: 'Documentation (TEST-NET-3)',
    family: 'ipv4',
    category: 'documentation',
    note: 'The third RFC 5737 documentation block, also used throughout this site’s own tool examples (IOC Extractor, Regex Tester) as clearly-fabricated illustrative addresses.',
    references: [RFC(5737), IANA_IPV4],
  },
  // ── Benchmarking ─────────────────────────────────────────────────────────
  {
    cidr: '198.18.0.0/15',
    name: 'Benchmarking',
    family: 'ipv4',
    category: 'benchmarking',
    note: 'Reserved for testing network-interconnect-device throughput in a lab, so a benchmark can’t accidentally flood real internet addresses.',
    references: [RFC(2544), IANA_IPV4],
  },
  // ── "This network" / broadcast ──────────────────────────────────────────
  {
    cidr: '0.0.0.0/8',
    name: 'This Network',
    family: 'ipv4',
    category: 'reserved',
    note: '0.0.0.0 itself shows up as a "no specific address" placeholder (e.g. a default route, or a DHCP client’s source address before it has one).',
    references: [RFC(791), IANA_IPV4],
  },
  {
    cidr: '255.255.255.255/32',
    name: 'Limited Broadcast',
    family: 'ipv4',
    category: 'broadcast',
    note: 'The local-segment broadcast address — routers never forward it. Distinct from a subnet’s own directed broadcast address (e.g. 10.0.0.255 for a 10.0.0.0/24), which this tool’s CIDR & VLAN Calculator computes per-network above.',
    references: [RFC(919), IANA_IPV4],
  },
  {
    cidr: '240.0.0.0/4',
    name: 'Reserved (Class E)',
    family: 'ipv4',
    category: 'reserved',
    note: 'Historically "reserved for future use" and still not assigned for general internet use — seeing it as a real source/destination in traffic is unusual and worth a second look.',
    references: [RFC(1112), IANA_IPV4],
  },

  // ── IPv6 ─────────────────────────────────────────────────────────────────
  {
    cidr: '::1/128',
    name: 'Loopback',
    family: 'ipv6',
    category: 'loopback',
    note: 'IPv6’s single loopback address — the equivalent of IPv4’s whole 127.0.0.0/8, but just one address here.',
    references: [RFC(4291), IANA_IPV6],
  },
  {
    cidr: '::/128',
    name: 'Unspecified Address',
    family: 'ipv6',
    category: 'reserved',
    note: 'The IPv6 equivalent of 0.0.0.0 — a placeholder meaning "no address," e.g. a host that hasn’t configured one yet.',
    references: [RFC(4291), IANA_IPV6],
  },
  {
    cidr: 'fe80::/10',
    name: 'Link-Local Unicast',
    family: 'ipv6',
    category: 'link-local',
    note: 'Every IPv6 interface auto-assigns one of these — routers never forward them off-segment, and they’re always present alongside any other address a host has.',
    references: [RFC(4291), IANA_IPV6],
  },
  {
    cidr: 'fc00::/7',
    name: 'Unique Local Address (ULA)',
    family: 'ipv6',
    category: 'unique-local',
    note: 'IPv6’s rough analogue to RFC 1918 private space — not globally routed, but (unlike IPv4 private ranges) the /48 below it is meant to be pseudo-randomly generated so two organizations’ ULA ranges essentially never collide if networks are later merged.',
    references: [RFC(4193), IANA_IPV6],
  },
  {
    cidr: 'ff00::/8',
    name: 'Multicast',
    family: 'ipv6',
    category: 'multicast',
    note: 'IPv6 has no broadcast at all — anything that would be a broadcast in IPv4 (e.g. "all routers," "all nodes") uses a well-known multicast address in this block instead.',
    references: [RFC(4291), IANA_IPV6],
  },
  {
    cidr: '2000::/3',
    name: 'Global Unicast',
    family: 'ipv6',
    category: 'global-unicast',
    note: 'The block real, internet-routable IPv6 addresses are allocated from — most real-world IPv6 traffic you’ll see in a log starts with "2" or "3".',
    references: [RFC(4291), IANA_IPV6],
  },
  {
    cidr: '::ffff:0:0/96',
    name: 'IPv4-Mapped Address',
    family: 'ipv6',
    category: 'translation',
    note: 'Embeds a real IPv4 address in the low 32 bits (e.g. ::ffff:192.168.1.1) — how a dual-stack socket API represents an IPv4 peer to IPv6-aware code. This tool’s CIDR & VLAN Calculator (IPv6 mode) parses this exact form.',
    references: [RFC(4291), IANA_IPV6],
  },
  {
    cidr: '64:ff9b::/96',
    name: 'NAT64 Well-Known Prefix',
    family: 'ipv6',
    category: 'translation',
    note: 'The standard prefix a NAT64 gateway prepends to an embedded IPv4 address (e.g. 64:ff9b::192.168.1.1) to let an IPv6-only host reach an IPv4-only destination.',
    references: [RFC(6052), IANA_IPV6],
  },
  {
    cidr: '2001:db8::/32',
    name: 'Documentation',
    family: 'ipv6',
    category: 'documentation',
    note: 'The IPv6 equivalent of the RFC 5737 TEST-NETs — this site’s own IPv6 tool examples use addresses from this range.',
    references: [RFC(3849), IANA_IPV6],
  },
  {
    cidr: '3fff::/20',
    name: 'Documentation',
    family: 'ipv6',
    category: 'documentation',
    note: 'A second, newer documentation prefix (allocated 2024) alongside 2001:db8::/32 — added because 2001:db8::/32 examples were increasingly showing up as real-looking addresses in generated/AI-assisted content.',
    references: [RFC(9637), IANA_IPV6],
  },
];

/** Quick-reference CIDR/prefix table for IPv4 — computed directly (pure
 *  arithmetic, RFC 4632), not hand-typed, so it can never drift from the
 *  CIDR & VLAN Calculator's own math above it on the same page. */
export interface CidrQuickRefRow {
  prefix: number;
  netmask: string;
  totalAddresses: number;
  usableHosts: number;
}

function netmaskFor(prefix: number): string {
  const bits = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return [(bits >>> 24) & 255, (bits >>> 16) & 255, (bits >>> 8) & 255, bits & 255].join('.');
}

export const CIDR_QUICK_REF: CidrQuickRefRow[] = Array.from({ length: 25 }, (_, i) => {
  const prefix = i + 8; // /8 through /32 — anything shorter than /8 is never seen as a single assigned subnet in practice
  const total = 2 ** (32 - prefix);
  const usable = prefix >= 31 ? total : Math.max(total - 2, 0);
  return { prefix, netmask: netmaskFor(prefix), totalAddresses: total, usableHosts: usable };
});
