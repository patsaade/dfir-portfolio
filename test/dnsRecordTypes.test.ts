import { describe, it, expect } from 'vitest';
import { DNS_RECORD_TYPES, DNS_CATEGORY_LABEL, dnsRecordByType, type DnsRecordCategory } from '../src/data/dnsRecordTypes';

// Ground-truth TYPE values + defining RFC, taken directly from IANA's DNS
// Parameters registry ("Resource Record (RR) TYPEs" table) on 2026-07-23:
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
// Guards against a future edit silently drifting from the authoritative source.
const IANA_GROUND_TRUTH: Record<string, { typeValue: number; rfc: number }> = {
  A: { typeValue: 1, rfc: 1035 },
  NS: { typeValue: 2, rfc: 1035 },
  CNAME: { typeValue: 5, rfc: 1035 },
  SOA: { typeValue: 6, rfc: 1035 },
  PTR: { typeValue: 12, rfc: 1035 },
  MX: { typeValue: 15, rfc: 1035 },
  TXT: { typeValue: 16, rfc: 1035 },
  AAAA: { typeValue: 28, rfc: 3596 },
  SRV: { typeValue: 33, rfc: 2782 },
  CAA: { typeValue: 257, rfc: 8659 },
};

const REQUIRED_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CAA'];

describe('DNS record type reference', () => {
  it('covers every required record type from the brief', () => {
    const types = new Set(DNS_RECORD_TYPES.map((r) => r.type));
    for (const t of REQUIRED_TYPES) expect(types.has(t), t).toBe(true);
  });

  it('has unique type mnemonics', () => {
    const types = DNS_RECORD_TYPES.map((r) => r.type);
    expect(new Set(types).size).toBe(types.length);
  });

  it('has unique numeric TYPE values', () => {
    const values = DNS_RECORD_TYPES.map((r) => r.typeValue);
    expect(new Set(values).size).toBe(values.length);
  });

  it('matches IANA\'s registered TYPE value and defining RFC for every entry', () => {
    for (const r of DNS_RECORD_TYPES) {
      const truth = IANA_GROUND_TRUTH[r.type];
      expect(truth, `${r.type} missing from ground-truth table`).toBeDefined();
      expect(r.typeValue, `${r.type} TYPE value`).toBe(truth.typeValue);
      expect(r.rfc.url, `${r.type} RFC url`).toBe(`https://www.rfc-editor.org/rfc/rfc${truth.rfc}`);
      expect(r.rfc.name, `${r.type} RFC name`).toBe(`RFC ${truth.rfc}`);
    }
  });

  it('gives every entry non-empty meaning, purpose, and example text', () => {
    for (const r of DNS_RECORD_TYPES) {
      expect(r.meaning.trim().length, `${r.type} meaning`).toBeGreaterThan(0);
      expect(r.purpose.trim().length, `${r.type} purpose`).toBeGreaterThan(0);
      expect(r.example.trim().length, `${r.type} example`).toBeGreaterThan(0);
    }
  });

  it('writes purpose sentences that actually end as sentences', () => {
    for (const r of DNS_RECORD_TYPES) {
      expect(r.purpose.trim().endsWith('.'), r.type).toBe(true);
    }
  });

  it('assigns every entry a known, labeled category', () => {
    for (const r of DNS_RECORD_TYPES) {
      expect(DNS_CATEGORY_LABEL[r.category], r.type).toBeTruthy();
    }
  });

  it('every category constant is actually used by at least one entry', () => {
    const used = new Set(DNS_RECORD_TYPES.map((r) => r.category));
    for (const cat of Object.keys(DNS_CATEGORY_LABEL) as DnsRecordCategory[]) {
      expect(used.has(cat), cat).toBe(true);
    }
  });

  it('uses only RFC 5737/3849 documentation-only addresses in examples, never a real live address', () => {
    for (const r of DNS_RECORD_TYPES) {
      if (r.type === 'A') expect(r.example).toContain('192.0.2.');
      // PTR's example is the reverse-lookup form of the same TEST-NET-1 address (a.b.c.d -> d.c.b.a.in-addr.arpa).
      if (r.type === 'PTR') expect(r.example).toContain('.192.in-addr.arpa.');
      if (r.type === 'AAAA') expect(r.example).toContain('2001:db8::');
    }
  });

  it('MX example encodes a numeric preference with lower-is-preferred semantics documented in purpose', () => {
    const mx = dnsRecordByType('MX')!;
    expect(mx.example).toMatch(/MX\s+\d+\s+\S+/);
    expect(mx.purpose.toLowerCase()).toContain('lower values are preferred');
  });

  it('SOA lists all seven RFC 1035 RDATA fields in order', () => {
    const soa = dnsRecordByType('SOA')!;
    expect(soa.fields).toBe('MNAME, RNAME, SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM');
  });

  it('SRV example follows the _service._proto.name label convention', () => {
    const srv = dnsRecordByType('SRV')!;
    expect(srv.example).toMatch(/^_[a-z]+\._(tcp|udp)\./);
  });

  it('CAA documents that RFC 8659 obsoletes RFC 6844', () => {
    const caa = dnsRecordByType('CAA')!;
    expect(caa.note).toContain('RFC 6844');
  });

  it('dnsRecordByType is a case-insensitive lookup that returns undefined for unknown types', () => {
    expect(dnsRecordByType('mx')?.type).toBe('MX');
    expect(dnsRecordByType('MX')?.type).toBe('MX');
    expect(dnsRecordByType('NOPE')).toBeUndefined();
  });
});
