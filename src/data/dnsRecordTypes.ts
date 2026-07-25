// DNS Resource Record (RR) TYPE reference — pure IT-fundamentals framing (what
// each record type IS and does, no investigation/attacker angle; see CLAUDE.md's
// IT vs. DFIR framing rule). Every `typeValue` and `rfc` citation below was
// verified directly against IANA's own "Domain Name System (DNS) Parameters"
// registry, "Resource Record (RR) TYPEs" table:
//   https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
// and cross-checked against each type's defining RFC (RFC 1035 for the seven
// original/core types; RFC 3596 for AAAA; RFC 2782 for SRV; RFC 8659 for CAA,
// which obsoletes the original RFC 6844). Re-verify against the registry above
// if it ever adds/renumbers an entry.
import type { Reference } from './references';

export type DnsRecordCategory = 'address' | 'alias' | 'mail' | 'text' | 'authority' | 'reverse' | 'service' | 'security';

export interface DnsRecordEntry {
  /** The record's mnemonic, e.g. "A", "AAAA", "MX". */
  type: string;
  /** The numeric TYPE value from IANA's RR TYPEs table. */
  typeValue: number;
  category: DnsRecordCategory;
  /** IANA's own one-line "Meaning" for this TYPE, quoted from the registry table. */
  meaning: string;
  /** One-sentence description of what the record does / is used for. */
  purpose: string;
  /** RDATA field names in order, for records with more than one field (omitted for single-field records). */
  fields?: string;
  /** A short illustrative zone-file-style line. IPv4/IPv6 addresses use the
   *  RFC 5737/3849 documentation-only ranges (TEST-NET-1, 2001:DB8::/32) —
   *  the same convention the IP & CIDR Reference page's own copy calls out —
   *  rather than a real, potentially-stale live address. */
  example: string;
  rfc: Reference;
  /** Optional extra accuracy note (e.g. an obsoleted predecessor RFC). */
  note?: string;
}

const RFC = (n: number): Reference => ({ name: `RFC ${n}`, url: `https://www.rfc-editor.org/rfc/rfc${n}` });

export const DNS_RECORD_TYPES: DnsRecordEntry[] = [
  {
    type: 'A',
    typeValue: 1,
    category: 'address',
    meaning: 'a host address',
    purpose: 'Maps a hostname to a 32-bit IPv4 address — the fundamental record type behind ordinary IPv4 name resolution.',
    example: 'example.com.       A       192.0.2.1',
    rfc: RFC(1035),
  },
  {
    type: 'AAAA',
    typeValue: 28,
    category: 'address',
    meaning: 'IP6 Address',
    purpose: "Maps a hostname to a 128-bit IPv6 address — the IPv6 counterpart to the A record, needed because A's RDATA only has room for 32 bits.",
    example: 'example.com.       AAAA    2001:db8::1',
    rfc: RFC(3596),
  },
  {
    type: 'CNAME',
    typeValue: 5,
    category: 'alias',
    meaning: 'the canonical name for an alias',
    purpose: 'Points one name to another canonical name, so every other record for the alias is looked up through the target instead of being duplicated.',
    fields: 'CNAME',
    example: 'www.example.com.   CNAME   example.com.',
    rfc: RFC(1035),
  },
  {
    type: 'MX',
    typeValue: 15,
    category: 'mail',
    meaning: 'mail exchange',
    purpose: 'Identifies a mail server for the domain along with a preference value used to rank it against any other mail servers for the same domain — lower values are preferred.',
    fields: 'PREFERENCE, EXCHANGE',
    example: 'example.com.       MX      10 mail.example.com.',
    rfc: RFC(1035),
  },
  {
    type: 'TXT',
    typeValue: 16,
    category: 'text',
    meaning: 'text strings',
    purpose: "Holds arbitrary text data attached to a name — the RFC leaves the meaning of that text up to whatever's using it, and in practice that's grown to include domain-ownership verification and email-authentication policies such as SPF.",
    fields: 'TXT-DATA',
    example: 'example.com.       TXT     "v=spf1 -all"',
    rfc: RFC(1035),
  },
  {
    type: 'NS',
    typeValue: 2,
    category: 'authority',
    meaning: 'an authoritative name server',
    purpose: 'Delegates a zone (or subdomain) to a specific set of authoritative name servers.',
    fields: 'NSDNAME',
    example: 'example.com.       NS      ns1.example.net.',
    rfc: RFC(1035),
  },
  {
    type: 'SOA',
    typeValue: 6,
    category: 'authority',
    meaning: 'marks the start of a zone of authority',
    purpose: "Marks the start of a zone of authority — one SOA record per zone — and carries its primary name server, admin mailbox, serial number, and the refresh/retry/expire timers secondary servers use to stay in sync.",
    fields: 'MNAME, RNAME, SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM',
    example: 'example.com.       SOA     ns1.example.net. hostmaster.example.com. 2026072200 7200 3600 1209600 3600',
    rfc: RFC(1035),
  },
  {
    type: 'PTR',
    typeValue: 12,
    category: 'reverse',
    meaning: 'a domain name pointer',
    purpose: 'Maps an address back to a hostname — the reverse of an A/AAAA lookup — conventionally served from the in-addr.arpa (IPv4) or ip6.arpa (IPv6) reverse-lookup zones.',
    fields: 'PTRDNAME',
    example: '1.2.0.192.in-addr.arpa.  PTR   example.com.',
    rfc: RFC(1035),
  },
  {
    type: 'SRV',
    typeValue: 33,
    category: 'service',
    meaning: 'Server Selection',
    purpose: 'Publishes the hostname, port, and relative priority/weight for a specific service, addressed via an underscore-prefixed "_service._proto.name" label instead of a plain hostname.',
    fields: 'Priority, Weight, Port, Target',
    example: '_sip._tcp.example.com. SRV   10 60 5060 sipserver.example.com.',
    rfc: RFC(2782),
  },
  {
    type: 'CAA',
    typeValue: 257,
    category: 'security',
    meaning: 'Certification Authority Restriction',
    purpose: 'Restricts which certificate authorities are allowed to issue TLS certificates for the domain, and can name where a CA should report policy violations.',
    fields: 'Flags, Tag, Value',
    example: 'example.com.       CAA     0 issue "letsencrypt.org"',
    rfc: RFC(8659),
    note: 'RFC 8659 obsoletes the original CAA specification, RFC 6844.',
  },
];

export const DNS_CATEGORY_LABEL: Record<DnsRecordCategory, string> = {
  address: 'Address',
  alias: 'Alias',
  mail: 'Mail',
  text: 'Text',
  authority: 'Zone authority',
  reverse: 'Reverse lookup',
  service: 'Service location',
  security: 'Certificate policy',
};

/** Case-insensitive lookup by mnemonic (e.g. "a", "MX") — used by tests and
 *  available for any future page that wants a single-type lookup. */
export function dnsRecordByType(type: string): DnsRecordEntry | undefined {
  const needle = type.trim().toUpperCase();
  return DNS_RECORD_TYPES.find((r) => r.type === needle);
}
