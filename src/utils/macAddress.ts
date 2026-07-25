// MAC Analyzer — pure structural decoding of an IEEE 802
// MAC-48 address (6 bytes / 48 bits), entirely deterministic bit math defined
// by the IEEE 802 address format itself (nothing here is looked up or
// fact-checked against a vendor database — see the header comment in
// MacAddressAnalyzer.astro for why). Every function is a pure, side-effect-free
// transform from a parsed address to its derived bit fields, so it's fully
// unit-testable without a DOM — same shape as src/utils/cidr.ts.
//
// Deliberately does NOT attempt to resolve the first 3 bytes (the OUI) to a
// manufacturer name. That mapping is assigned and maintained by the IEEE
// Registration Authority and changes over time; this file only decodes what
// the address's own bits say about themselves — the OUI/NIC-specific split
// and the two self-describing bits in the first octet.

export interface MacAddressResult {
  /** The original input string, trimmed. */
  input: string;
  /** 6 lowercase hex pairs, e.g. ['00','1a','2b','3c','4d','5e']. */
  octets: string[];
  /** Canonical colon-separated lowercase form, e.g. '00:1a:2b:3c:4d:5e'. */
  formatted: string;
  /** First 3 octets (the OUI), colon-separated — e.g. '00:1a:2b'. */
  oui: string;
  /** Last 3 octets (the NIC-specific portion), colon-separated — e.g. '3c:4d:5e'. */
  nic: string;
  /** The first octet's value, as an 8-bit binary string, e.g. '00000000'. */
  firstOctetBinary: string;
  /** U/L bit (bit 1 of the first octet) === 0: factory-assigned, globally unique per IEEE. */
  isUniversallyAdministered: boolean;
  /** U/L bit (bit 1 of the first octet) === 1: manually/virtually assigned (VMs, VPNs, randomized Wi-Fi MACs, etc.). */
  isLocallyAdministered: boolean;
  /** I/G bit (bit 0 of the first octet) === 0: addresses a single device. */
  isUnicast: boolean;
  /** I/G bit (bit 0 of the first octet) === 1: addresses a group of devices. */
  isMulticast: boolean;
  /** True only for ff:ff:ff:ff:ff:ff, the link-local broadcast address. */
  isBroadcast: boolean;
}

// Three accepted input shapes, checked in order: colon-separated,
// hyphen-separated, and bare 12-hex-digit with no separator at all. A
// pattern must match one of these exactly (after trimming) — no mixed
// separators, no partial groups, no stray whitespace in the middle.
const COLON_FORM = /^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/;
const HYPHEN_FORM = /^([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}$/;
const BARE_FORM = /^[0-9a-fA-F]{12}$/;

export function parseMacAddress(input: string): MacAddressResult | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  let octets: string[];
  if (COLON_FORM.test(trimmed)) {
    octets = trimmed.split(':');
  } else if (HYPHEN_FORM.test(trimmed)) {
    octets = trimmed.split('-');
  } else if (BARE_FORM.test(trimmed)) {
    octets = trimmed.match(/.{2}/g)!;
  } else {
    return null;
  }
  octets = octets.map((o) => o.toLowerCase());

  const firstByte = parseInt(octets[0], 16);
  const isUniversallyAdministered = (firstByte & 0x02) === 0;
  const isUnicast = (firstByte & 0x01) === 0;
  const isBroadcast = octets.every((o) => o === 'ff');

  return {
    input: trimmed,
    octets,
    formatted: octets.join(':'),
    oui: octets.slice(0, 3).join(':'),
    nic: octets.slice(3, 6).join(':'),
    firstOctetBinary: firstByte.toString(2).padStart(8, '0'),
    isUniversallyAdministered,
    isLocallyAdministered: !isUniversallyAdministered,
    isUnicast,
    isMulticast: !isUnicast,
    isBroadcast,
  };
}
