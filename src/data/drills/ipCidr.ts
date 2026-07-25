// Pure, deterministic question generator for the /drills/ip-cidr/ module.
// Every fact traces to a value COMPUTED at generation time by this site's
// own real CIDR utilities (src/utils/cidr.ts's parseCidr()/prefixForHosts())
// or read directly off the real IANA-sourced range data
// (src/data/ipRanges.ts's IP_RANGES) — nothing here is a hand-typed answer.
//
// Index -> question is a fixed lookup into a small curated question bank,
// not Math.random(), so nextQuestion(0) is byte-identical between this
// page's own build-time frontmatter call and the client script's
// post-hydration re-render (see DrillEngine.astro's header comment on why
// that matters for the no-JS/no-flash contract) and totalQuestions can stay
// a plain constant.
import { parseCidr, parseIPv4, prefixForHosts } from '../../utils/cidr';
import { IP_RANGES } from '../ipRanges';
import type { DrillQuestion } from '../../scripts/drillEngine';

// Same human labels as ip-reference.astro's own page-local `catLabel` map
// (that one is page-scoped, not exported, so this is a deliberate small
// duplication rather than a cross-page import of a private const).
const CATEGORY_LABELS: Record<string, string> = {
  'private-use': 'Private-use',
  'shared-address-space': 'Shared address space (CGNAT)',
  loopback: 'Loopback',
  'link-local': 'Link-local',
  multicast: 'Multicast',
  documentation: 'Documentation',
  benchmarking: 'Benchmarking',
  translation: 'Translation',
  reserved: 'Reserved',
  broadcast: 'Broadcast',
  'unique-local': 'Unique local (ULA)',
  'global-unicast': 'Global unicast',
};

function rangeFor(cidr: string) {
  const entry = IP_RANGES.find((r) => r.cidr === cidr);
  if (!entry) throw new Error(`ipCidr drill: no IP_RANGES entry for ${cidr}`);
  return entry;
}

// Total address count for a bare prefix, via the real parseCidr() math
// (the network address doesn't matter for a total-address count, so 0.0.0.0
// is just a convenient carrier address).
function totalAddressesForPrefix(prefix: number): number {
  return parseCidr(`0.0.0.0/${prefix}`)!.totalHosts;
}

// ── Type (a): CIDR field lookups (network / broadcast / usable hosts) ──────

function networkQuestion(cidrStr: string): DrillQuestion {
  const r = parseCidr(cidrStr)!;
  return {
    prompt: `What is the network address of ${cidrStr}?`,
    explanation: `${r.ip} ANDed with the /${r.prefix} netmask (${r.netmask}) gives the network address ${r.network}.`,
    answerType: 'text',
    correctAnswer: r.network,
    // Compares parsed integer values (via the real parseIPv4()), not raw
    // strings, so e.g. leading zeros or extra whitespace still grade correctly
    // — this IS the exact field under test, so a semantic address compare is
    // the right level of robustness (not a looser fallback).
    grade: (ans) => {
      const n = parseIPv4(ans);
      return n !== null && n === parseIPv4(r.network);
    },
  };
}

function broadcastQuestion(cidrStr: string): DrillQuestion {
  const r = parseCidr(cidrStr)!;
  return {
    prompt: `What is the broadcast address of ${cidrStr}?`,
    explanation: `The /${r.prefix} wildcard mask ${r.wildcard} ORed onto the network address ${r.network} gives the broadcast address ${r.broadcast}.`,
    answerType: 'text',
    correctAnswer: r.broadcast,
    grade: (ans) => {
      const n = parseIPv4(ans);
      return n !== null && n === parseIPv4(r.broadcast);
    },
  };
}

function usableHostsQuestion(cidrStr: string): DrillQuestion {
  const r = parseCidr(cidrStr)!;
  return {
    prompt: `How many usable host addresses does ${cidrStr} provide?`,
    explanation: `A /${r.prefix} block holds ${r.totalHosts.toLocaleString()} total addresses. Subtracting the network and broadcast addresses leaves ${r.usableHosts.toLocaleString()} usable hosts.`,
    answerType: 'text',
    correctAnswer: String(r.usableHosts),
    grade: (ans) => Number(String(ans).replace(/[^0-9]/g, '')) === r.usableHosts,
  };
}

// ── Type (b): special-use range category recognition (real IP_RANGES data) ─

// Lenient category grading: strips parenthetical asides (e.g. "(CGNAT)",
// "(ULA)") and collapses everything else down to lowercase words, so both
// the hyphenated category id ("shared-address-space") and its human label
// ("Shared address space (CGNAT)") normalize to the same string — the
// learner can type either form, with or without hyphens.
function normalizeCategory(s: string): string {
  return s
    .toLowerCase()
    .replace(/\(.*?\)/g, '')
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
}

function categoryQuestion(cidrStr: string, exampleAddr: string): DrillQuestion {
  const r = rangeFor(cidrStr);
  const correctLabel = CATEGORY_LABELS[r.category] ?? r.category;
  const acceptable = new Set([normalizeCategory(r.category), normalizeCategory(correctLabel)]);
  return {
    prompt: `${exampleAddr} falls inside ${r.cidr} (${r.name}). What category does this block belong to?`,
    explanation: r.note,
    referenceHref: r.references[0]?.url,
    referenceLabel: r.references[0]?.name,
    hint: `Answer with the plain-English category name, e.g. "private-use", "multicast", or "loopback" — hyphens or spaces both work.`,
    answerType: 'text',
    correctAnswer: correctLabel,
    grade: (ans) => acceptable.has(normalizeCategory(ans)),
  };
}

// ── Type (c): subnet math (prefixForHosts() / total-address ratios) ────────

function subnetCountQuestion(baseCidrStr: string, subPrefix: number): DrillQuestion {
  const base = parseCidr(baseCidrStr)!;
  const subTotal = totalAddressesForPrefix(subPrefix);
  const count = base.totalHosts / subTotal;
  return {
    prompt: `How many /${subPrefix} subnets fit inside ${baseCidrStr}?`,
    explanation: `A /${base.prefix} block holds ${base.totalHosts.toLocaleString()} addresses; each /${subPrefix} block holds ${subTotal.toLocaleString()}. ${base.totalHosts.toLocaleString()} ÷ ${subTotal.toLocaleString()} = ${count.toLocaleString()}.`,
    answerType: 'text',
    correctAnswer: String(count),
    grade: (ans) => Number(String(ans).replace(/[^0-9]/g, '')) === count,
  };
}

function smallestPrefixQuestion(hosts: number): DrillQuestion {
  const prefix = prefixForHosts(hosts)!;
  const usable = parseCidr(`0.0.0.0/${prefix}`)!.usableHosts;
  return {
    prompt: `What is the smallest CIDR prefix length (e.g. /27) that provides at least ${hosts} usable host addresses?`,
    explanation: `/${prefix} provides ${usable.toLocaleString()} usable hosts — the smallest block (largest prefix number) that still covers ${hosts}. The next-smaller block, /${prefix + 1}, would fall short.`,
    answerType: 'text',
    correctAnswer: `/${prefix}`,
    grade: (ans) => Number(String(ans).replace(/[^0-9]/g, '')) === prefix,
  };
}

const QUESTIONS: DrillQuestion[] = [
  networkQuestion('192.168.4.130/26'),
  categoryQuestion('100.64.0.0/10', '100.64.55.10'),
  broadcastQuestion('10.20.30.0/22'),
  subnetCountQuestion('10.4.0.0/24', 28),
  categoryQuestion('169.254.0.0/16', '169.254.10.5'),
  usableHostsQuestion('172.16.5.0/27'),
  smallestPrefixQuestion(100),
  categoryQuestion('192.0.2.0/24', '192.0.2.55'),
  subnetCountQuestion('10.0.0.0/16', 24),
  networkQuestion('203.0.113.201/28'),
];

export function getIpCidrQuestion(index: number): DrillQuestion {
  return QUESTIONS[((index % QUESTIONS.length) + QUESTIONS.length) % QUESTIONS.length];
}
