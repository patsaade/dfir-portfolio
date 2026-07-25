// MITRE ATT&CK Groups — the Threat Actor / APT reference. Drives the
// /threat-actors/ index and the per-group /threat-actors/[slug]/ detail
// pages. The dataset is generated from MITRE's official Enterprise ATT&CK
// STIX bundle (scripts/gen-threat-actors.mjs -> threat-actors.generated.ts,
// re-run to refresh) — the same bundle the ATT&CK/D3FEND maps are generated
// from (see the ATT&CK refresh process in CLAUDE.md), so all three stay in
// lockstep on every MITRE release. No hand-maintained overlay exists yet —
// every group renders straight off MITRE's own name/aliases/description
// (the same "generated data, empty overlay" state D3FEND started in; see
// d3fend.ts + d3fend-overlay.ts for the shape to extend into if bespoke
// DFIR framing is ever added for specific groups).
import {
  THREAT_ACTORS_GENERATED,
  THREAT_ACTORS_TOTAL,
  THREAT_ACTORS_ATTACK_VERSION,
  type GeneratedThreatActor,
} from './threat-actors.generated';

export { THREAT_ACTORS_TOTAL, THREAT_ACTORS_ATTACK_VERSION };
export type ThreatActor = GeneratedThreatActor;

/** Every documented group — sorted by MITRE group id (G0001, G0002, …), the
 * generator's own order, which also drives detail-page prev/next. */
export const THREAT_ACTORS: ThreatActor[] = THREAT_ACTORS_GENERATED;

/**
 * URL slug for a group: its name, lowercased and hyphenated (e.g. "APT28" ->
 * "apt28", "admin@338" -> "admin-338"). Verified unique across the dataset by
 * test/threatActors.test.ts — chosen over the MITRE G#### id because the name
 * is what people actually search for ("APT28", not "G0007").
 */
export function threatActorSlug(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

/** O(1) slug lookup, built once at module load — mirrors ATTACK_TECHNIQUE_BY_ID
 * in references.ts / d3fendById in d3fend.ts. File-local: nothing outside this
 * module needs the raw Map, only the `threatActorBySlug` lookup below. */
const THREAT_ACTOR_BY_SLUG: Map<string, ThreatActor> = new Map(
  THREAT_ACTORS.map((a) => [threatActorSlug(a.name), a]),
);

export const threatActorBySlug = (slug: string): ThreatActor | undefined =>
  THREAT_ACTOR_BY_SLUG.get(slug);
