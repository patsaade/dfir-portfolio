// CVSS v3.1 Base Score Calculator — pure functions, no DOM dependency (unit
// tested directly in test/cvss.test.ts against FIRST.org's own published
// worked examples; imported into the client bundle by CvssCalculator.astro
// for live scoring as each metric dropdown changes).
//
// Implements ONLY the CVSS v3.1 *Base* metric group and Base Score formula —
// not Temporal or Environmental metrics, and not CVSS v2 or v4. This mirrors
// this codebase's "explicitly-scoped subset, documented, never silently
// guessed" convention (see src/utils/sigma.ts's own header comment for the
// precedent). Every equation, coefficient, and threshold below is taken
// verbatim from FIRST's official CVSS v3.1 Specification Document —
// https://www.first.org/cvss/v3-1/specification-document — Section 7.1 (Base
// Metrics Equations) and Appendix A (Floating Point Rounding / the Roundup
// function). Every metric's numeric weight is drawn from that same
// document's Section 7.4 metric value tables. Do not hand-tune any constant here — a value that
// looks "close enough" is a bug, not an approximation, for a scoring standard
// with published reference answers (see test/cvss.test.ts).

/** Attack Vector — how the vulnerability is reached. */
export type AttackVector = 'N' | 'A' | 'L' | 'P';
/** Attack Complexity — conditions beyond the attacker's control that must
 *  exist for a successful attack. */
export type AttackComplexity = 'L' | 'H';
/** Privileges Required — the access level an attacker must already hold. */
export type PrivilegesRequired = 'N' | 'L' | 'H';
/** User Interaction — whether a human other than the attacker must
 *  participate. */
export type UserInteraction = 'N' | 'R';
/** Scope — whether the exploited vulnerability can affect resources beyond
 *  its own security authority. */
export type Scope = 'U' | 'C';
/** Shared value set for the three Impact metrics (Confidentiality,
 *  Integrity, Availability). */
export type CiaImpact = 'N' | 'L' | 'H';

export interface CvssV31Metrics {
  AV: AttackVector;
  AC: AttackComplexity;
  PR: PrivilegesRequired;
  UI: UserInteraction;
  S: Scope;
  C: CiaImpact;
  I: CiaImpact;
  A: CiaImpact;
}

export type CvssSeverity = 'None' | 'Low' | 'Medium' | 'High' | 'Critical';

export interface CvssV31Result {
  /** 0.0–10.0, rounded to one decimal place via the spec's Roundup function. */
  baseScore: number;
  severity: CvssSeverity;
  /** Impact Sub Score (ISS) — not rounded, exposed for the "how this was
   *  computed" breakdown on the page. */
  impactSubScore: number;
  /** Impact component of the Base Score equation (Scope-dependent). */
  impact: number;
  /** Exploitability component of the Base Score equation. */
  exploitability: number;
}

// ---------------------------------------------------------------------------
// Metric metadata — single source of truth for the calculator's dropdowns
// AND the page's own metric-reference table (same role HASH_ALGORITHMS plays
// in utils/hashes.ts / SIGMA_MODIFIERS plays in utils/sigma.ts).
// ---------------------------------------------------------------------------

export interface CvssMetricOption {
  value: string;
  label: string;
  /** Short, accurate paraphrase of the spec's own definition for this value —
   *  not a verbatim quote (see file header: source is the FIRST v3.1 spec,
   *  Section 7.1). */
  hint: string;
}

export interface CvssMetricDef {
  id: keyof CvssV31Metrics;
  name: string;
  hint: string;
  options: CvssMetricOption[];
}

export const CVSS_METRICS: readonly CvssMetricDef[] = [
  {
    id: 'AV',
    name: 'Attack Vector',
    hint: 'How the vulnerable component is reached.',
    options: [
      { value: 'N', label: 'Network', hint: 'Exploitable remotely, up to and including across the internet.' },
      { value: 'A', label: 'Adjacent', hint: 'Exploitable only from the same physical or logical network segment (e.g. same VLAN, Bluetooth range).' },
      { value: 'L', label: 'Local', hint: 'Requires local access — a shell session, or getting the victim to run/open something.' },
      { value: 'P', label: 'Physical', hint: 'Requires the attacker to physically touch or manipulate the vulnerable device.' },
    ],
  },
  {
    id: 'AC',
    name: 'Attack Complexity',
    hint: "Conditions beyond the attacker's control that must exist first.",
    options: [
      { value: 'L', label: 'Low', hint: 'No special conditions needed — an attacker can expect repeatable success.' },
      { value: 'H', label: 'High', hint: 'Success depends on conditions outside the attacker\'s control (e.g. winning a race condition, prior reconnaissance).' },
    ],
  },
  {
    id: 'PR',
    name: 'Privileges Required',
    hint: 'The access level an attacker must already hold before the attack.',
    options: [
      { value: 'N', label: 'None', hint: 'The attacker is unauthenticated and needs no prior access.' },
      { value: 'L', label: 'Low', hint: 'The attacker needs basic user-level privileges affecting only their own settings/files.' },
      { value: 'H', label: 'High', hint: 'The attacker needs significant privileges (e.g. admin) over the vulnerable component.' },
    ],
  },
  {
    id: 'UI',
    name: 'User Interaction',
    hint: 'Whether a human other than the attacker must take an action.',
    options: [
      { value: 'N', label: 'None', hint: 'The vulnerability can be exploited with no other user involved.' },
      { value: 'R', label: 'Required', hint: 'A user must do something first (open a file, click a link) for exploitation to succeed.' },
    ],
  },
  {
    id: 'S',
    name: 'Scope',
    hint: "Whether the exploit's impact can spread beyond the vulnerable component's own security authority.",
    options: [
      { value: 'U', label: 'Unchanged', hint: 'The impact stays confined to resources managed by the same security authority as the vulnerable component.' },
      { value: 'C', label: 'Changed', hint: 'The impact can reach resources managed by a different security authority (e.g. a guest-VM escape reaching the hypervisor).' },
    ],
  },
  {
    id: 'C',
    name: 'Confidentiality',
    hint: 'Impact to the confidentiality of data the vulnerable component manages.',
    options: [
      { value: 'H', label: 'High', hint: 'Total loss — all protected data in the impacted component is disclosed to the attacker.' },
      { value: 'L', label: 'Low', hint: 'Some loss — restricted data is disclosed, but the attacker has no control over what.' },
      { value: 'N', label: 'None', hint: 'No loss of confidentiality.' },
    ],
  },
  {
    id: 'I',
    name: 'Integrity',
    hint: 'Impact to the trustworthiness of data the vulnerable component manages.',
    options: [
      { value: 'H', label: 'High', hint: 'Total loss — the attacker can modify any/all protected data, or the loss of protection is complete.' },
      { value: 'L', label: 'Low', hint: 'Data modification is possible, but the attacker has no control over the consequence.' },
      { value: 'N', label: 'None', hint: 'No loss of integrity.' },
    ],
  },
  {
    id: 'A',
    name: 'Availability',
    hint: 'Impact to the availability of the vulnerable component itself.',
    options: [
      { value: 'H', label: 'High', hint: "Total loss — the attacker can fully deny access to the component's resources." },
      { value: 'L', label: 'Low', hint: 'Reduced performance or intermittent availability, short of a full denial.' },
      { value: 'N', label: 'None', hint: 'No impact to availability.' },
    ],
  },
] as const;

/** Canonical Base-vector metric order per the spec's own vector string
 *  grammar — used by both buildCvssV31VectorString and
 *  parseCvssV31VectorString. */
export const CVSS_METRIC_ORDER: (keyof CvssV31Metrics)[] = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

/** A reasonable, non-authoritative starting point for the calculator UI —
 *  not a "default" in any CVSS-spec sense, just what renders before a user
 *  changes anything. */
export const DEFAULT_CVSS_METRICS: CvssV31Metrics = {
  AV: 'N',
  AC: 'L',
  PR: 'N',
  UI: 'N',
  S: 'U',
  C: 'N',
  I: 'N',
  A: 'N',
};

// ---------------------------------------------------------------------------
// Numeric weights — CVSS v3.1 Specification Document, Section 7.1.
// ---------------------------------------------------------------------------

const AV_WEIGHTS: Record<AttackVector, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC_WEIGHTS: Record<AttackComplexity, number> = { L: 0.77, H: 0.44 };
// Privileges Required is the one Base metric whose weight itself depends on
// Scope (the spec gives PR two separate tables) — everything else below is
// Scope-independent at the per-metric level.
const PR_WEIGHTS_UNCHANGED: Record<PrivilegesRequired, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_WEIGHTS_CHANGED: Record<PrivilegesRequired, number> = { N: 0.85, L: 0.68, H: 0.5 };
const UI_WEIGHTS: Record<UserInteraction, number> = { N: 0.85, R: 0.62 };
const CIA_WEIGHTS: Record<CiaImpact, number> = { H: 0.56, L: 0.22, N: 0 };

/**
 * The spec's own "Roundup" function (Appendix A): rounds UP to the nearest
 * one decimal place using integer arithmetic on the input scaled by 100,000,
 * specifically to sidestep binary floating-point representation error
 * (0.1 + 0.2 !== 0.3, etc.) that a naive `Math.ceil(x * 10) / 10` can trip
 * over. This is the exact algorithm from FIRST's own reference
 * implementation — do not "simplify" it to a plain ceiling divide.
 */
export function cvssRoundUp(input: number): number {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) {
    return intInput / 100000;
  }
  return (Math.floor(intInput / 10000) + 1) / 10;
}

/** CVSS v3.1 Base severity rating bands — Specification Document, Section 5. */
export function cvssSeverityRating(score: number): CvssSeverity {
  if (score === 0) return 'None';
  if (score < 4.0) return 'Low';
  if (score < 7.0) return 'Medium';
  if (score < 9.0) return 'High';
  return 'Critical';
}

/**
 * The CVSS v3.1 Base Score formula, exactly as published (Section 7.1):
 *
 *   ISS             = 1 - [(1-C) x (1-I) x (1-A)]
 *   Impact          = Scope Unchanged: 6.42 x ISS
 *                      Scope Changed:  7.52 x (ISS-0.029) - 3.25 x (ISS-0.02)^15
 *   Exploitability  = 8.22 x AV x AC x PR x UI
 *   BaseScore       = Impact <= 0            -> 0
 *                      Scope Unchanged        -> Roundup(Min[(Impact+Exploitability), 10])
 *                      Scope Changed           -> Roundup(Min[1.08x(Impact+Exploitability), 10])
 */
export function computeCvssV31BaseScore(metrics: CvssV31Metrics): CvssV31Result {
  const scopeChanged = metrics.S === 'C';

  const iss = 1 - (1 - CIA_WEIGHTS[metrics.C]) * (1 - CIA_WEIGHTS[metrics.I]) * (1 - CIA_WEIGHTS[metrics.A]);

  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;

  const prWeights = scopeChanged ? PR_WEIGHTS_CHANGED : PR_WEIGHTS_UNCHANGED;
  const exploitability = 8.22 * AV_WEIGHTS[metrics.AV] * AC_WEIGHTS[metrics.AC] * prWeights[metrics.PR] * UI_WEIGHTS[metrics.UI];

  let baseScore: number;
  if (impact <= 0) {
    baseScore = 0;
  } else if (scopeChanged) {
    baseScore = cvssRoundUp(Math.min(1.08 * (impact + exploitability), 10));
  } else {
    baseScore = cvssRoundUp(Math.min(impact + exploitability, 10));
  }

  return {
    baseScore,
    severity: cvssSeverityRating(baseScore),
    impactSubScore: iss,
    impact,
    exploitability,
  };
}

/** Builds the standard "CVSS:3.1/AV:.../AC:.../..." Base vector string in
 *  the spec's canonical metric order. */
export function buildCvssV31VectorString(metrics: CvssV31Metrics): string {
  const parts = CVSS_METRIC_ORDER.map((id) => `${id}:${metrics[id]}`);
  return `CVSS:3.1/${parts.join('/')}`;
}

export interface CvssParseSuccess {
  ok: true;
  metrics: CvssV31Metrics;
}
export interface CvssParseFailure {
  ok: false;
  error: string;
}

const VALID_VALUES: Record<keyof CvssV31Metrics, readonly string[]> = {
  AV: ['N', 'A', 'L', 'P'],
  AC: ['L', 'H'],
  PR: ['N', 'L', 'H'],
  UI: ['N', 'R'],
  S: ['U', 'C'],
  C: ['H', 'L', 'N'],
  I: ['H', 'L', 'N'],
  A: ['H', 'L', 'N'],
};

/**
 * Parses a CVSS:3.1 **Base** vector string only — the 8 Base metrics, in the
 * spec's canonical order, prefixed with "CVSS:3.1/". Real-world vector
 * strings (e.g. from NVD) sometimes append Temporal/Environmental metrics
 * (E, RL, RC, CR, IR, AR, MAV, ...) after the Base ones; per this file's
 * documented scope (Base metrics only), those trailing segments are
 * rejected with a specific error rather than silently ignored, so a partial
 * parse never masquerades as a full one.
 */
export function parseCvssV31VectorString(vector: string): CvssParseSuccess | CvssParseFailure {
  const trimmed = vector.trim();
  if (!trimmed) return { ok: false, error: 'Vector string is empty.' };

  const segments = trimmed.split('/');
  if (segments[0] !== 'CVSS:3.1') {
    return { ok: false, error: 'Must start with "CVSS:3.1/" — other CVSS versions are not supported.' };
  }

  const rest = segments.slice(1);
  if (rest.length !== CVSS_METRIC_ORDER.length) {
    return {
      ok: false,
      error: `Expected exactly the 8 Base metrics (${CVSS_METRIC_ORDER.join('/')}) — Temporal/Environmental metrics aren't supported by this tool.`,
    };
  }

  const metrics = {} as CvssV31Metrics;
  for (let i = 0; i < CVSS_METRIC_ORDER.length; i++) {
    const expectedId = CVSS_METRIC_ORDER[i];
    const segment = rest[i];
    const parts = segment.split(':');
    if (parts.length !== 2) {
      return { ok: false, error: `Malformed metric segment "${segment}" — expected exactly one ":" (metric:value), found ${parts.length - 1}.` };
    }
    const [id, value] = parts;
    if (id !== expectedId) {
      return { ok: false, error: `Expected metric "${expectedId}" at position ${i + 1}, found "${id ?? segment}". Metrics must appear in canonical order.` };
    }
    if (!value || !VALID_VALUES[expectedId].includes(value)) {
      return { ok: false, error: `Invalid value "${value ?? ''}" for metric ${expectedId}.` };
    }
    (metrics as unknown as Record<string, string>)[expectedId] = value;
  }

  return { ok: true, metrics };
}
