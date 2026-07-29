// MITRE D3FEND — the defensive counterpart to ATT&CK. Drives the /reference/d3fend/
// map and the per-technique /reference/d3fend/[id]/ pages. The dataset is generated from MITRE's
// official D3FEND ontology + inferred ATT&CK mappings by scripts/gen-d3fend-map.mjs
// → d3fend-techniques.generated.ts (re-run to refresh). Each technique knows the
// ATT&CK techniques it `counters`, which powers the two-way cross-link with the
// MITRE ATT&CK Map (a D3FEND technique lists what it defends against; an ATT&CK
// technique lists the D3FEND countermeasures).
import {
  D3FEND_GENERATED,
  D3FEND_TACTIC_ORDER,
  D3FEND_TACTICS,
  D3FEND_VERSION,
  type D3fendTechnique as GeneratedD3fendTechnique,
} from './d3fend-techniques.generated';
import { D3FEND_OVERLAY, type D3fendOverlay } from './d3fend-overlay';

export { D3FEND_TACTIC_ORDER, D3FEND_TACTICS, D3FEND_VERSION };

// Generated MITRE data enriched with the curated overlay (empty today — see
// d3fend-overlay.ts). Same shape as AttackTechnique in references.ts.
export interface D3fendTechnique extends GeneratedD3fendTechnique, D3fendOverlay {}

export const D3FEND_TECHNIQUES: D3fendTechnique[] = D3FEND_GENERATED.map((t) => {
  const o = D3FEND_OVERLAY[t.id];
  return o ? { ...t, ...o } : t;
});

export const d3fendById = (id: string): D3fendTechnique | undefined =>
  D3FEND_TECHNIQUES.find((t) => t.id === id);

/** D3FEND techniques that counter a given ATT&CK technique id (reverse cross-link). */
export function d3fendCountering(attackId: string): D3fendTechnique[] {
  return D3FEND_TECHNIQUES.filter((t) => t.counters.includes(attackId));
}
