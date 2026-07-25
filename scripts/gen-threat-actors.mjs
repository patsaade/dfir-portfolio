// Regenerate the threat-actor / APT-group dataset from MITRE's official
// Enterprise STIX bundle so names, aliases, IDs, descriptions, and the
// techniques + software each group is documented using stay authoritative —
// never hand-invented. Mirrors gen-attack-map.mjs's structure and helpers.
//
//   node scripts/gen-threat-actors.mjs <path-to-enterprise-attack.json>
//
// Source bundle (≈50 MB, not committed):
//   https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
//
// STIX models a threat actor / APT group as an "intrusion-set" object. Its
// native `aliases` array gives other names the group is known by; `uses`
// relationships to attack-pattern (technique) and malware/tool (software)
// objects give what it's documented doing. Emits:
//   src/data/threat-actors.generated.ts — every non-revoked, non-deprecated
//       intrusion-set with its real MITRE G#### id, aliases, summary,
//       description, technique ids used (capped), and software names used
//       (capped) + the total group count and the ATT&CK version this was
//       generated from. AUTO-GENERATED; do not hand-edit.
import fs from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();
const STIX = process.argv[2] || path.join(ROOT, 'enterprise-attack.json');
const objects = JSON.parse(fs.readFileSync(STIX, 'utf8')).objects || [];

// Caps keep the generated file (and each prerendered page) a sane size.
const MAX_TECHNIQUES = 15;
const MAX_SOFTWARE = 10;

// ── clean MITRE markdown (strip citations, links → text, code/emphasis) ───────
function strip(s) {
  return String(s || '')
    .replace(/\(Citation:[^)]*\)/g, '')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/<\/?code>/g, '')
    .replace(/[*`]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}
// One clean sentence (cards + meta description).
function summarize(desc) {
  const s = strip(desc);
  const parts = s.split(/(?<=\.)\s+/);
  let out = parts[0] || s;
  if (out.length < 60 && parts[1]) out += ' ' + parts[1];
  return out.length > 240 ? out.slice(0, 237).replace(/\s+\S*$/, '') + '…' : out;
}
// Fuller cleaned text, cut at a sentence boundary near `max`.
function trimTo(desc, max) {
  let s = strip(desc);
  if (s.length <= max) return s;
  s = s.slice(0, max);
  const dot = s.lastIndexOf('. ');
  return dot > max * 0.5 ? s.slice(0, dot + 1) : s.replace(/\s+\S*$/, '') + '…';
}
function ref(o) {
  const r = (o.external_references || []).find((x) => x.source_name === 'mitre-attack' && x.external_id);
  return r ? { id: r.external_id, url: r.url } : null;
}

// ── lookups for relationship resolution ───────────────────────────────────────
// Technique STIX id -> its real ATT&CK id (T####[.###]), base + sub-techniques
// alike, skipping revoked/deprecated attack-patterns (so cross-links either
// resolve on-site against ATTACK_TECHNIQUES or fall back to a live MITRE page
// via resolveAttackLink(), never a stale/superseded id).
const techniqueIdByStix = {};
for (const o of objects) {
  if (o.type !== 'attack-pattern' || o.revoked || o.x_mitre_deprecated) continue;
  const r = ref(o);
  if (r) techniqueIdByStix[o.id] = r.id;
}
// Software (malware/tool) STIX id -> its display name, same revoked/deprecated filter.
const softwareNameByStix = {};
for (const o of objects) {
  if ((o.type !== 'malware' && o.type !== 'tool') || o.revoked || o.x_mitre_deprecated) continue;
  if (o.name) softwareNameByStix[o.id] = o.name;
}

// ── intrusion-sets (real, publicly documented threat actor / APT groups) ──────
const groupStixIds = new Set();
const groups = {}; // STIX id -> partial record
for (const o of objects) {
  if (o.type !== 'intrusion-set' || o.revoked || o.x_mitre_deprecated) continue;
  const r = ref(o);
  if (!r) continue;
  groupStixIds.add(o.id);
  groups[o.id] = {
    id: r.id,
    name: o.name,
    aliases: [...new Set((o.aliases || []).filter((a) => a && a.toLowerCase() !== o.name.toLowerCase()))],
    url: r.url,
    summary: o.description ? summarize(o.description) : '',
    description: o.description ? trimTo(o.description, 500) : '',
    techniques: new Set(),
    software: new Set(),
  };
}

// ── relationships: group --uses--> technique, group --uses--> software ────────
for (const o of objects) {
  if (o.type !== 'relationship' || o.revoked || o.relationship_type !== 'uses') continue;
  const g = groups[o.source_ref];
  if (!g) continue;
  const tId = techniqueIdByStix[o.target_ref];
  if (tId) { g.techniques.add(tId); continue; }
  const sName = softwareNameByStix[o.target_ref];
  if (sName) g.software.add(sName);
}

// ── assemble, sorted by id ─────────────────────────────────────────────────────
const out = [];
for (const stixId of [...groupStixIds].sort((a, b) => (groups[a].id < groups[b].id ? -1 : 1))) {
  const g = groups[stixId];
  const allTechniques = [...g.techniques].sort();
  const allSoftware = [...g.software].sort();
  const rec = {
    id: g.id,
    name: g.name,
    aliases: g.aliases,
    url: g.url,
    summary: g.summary,
    description: g.description,
    techniques: allTechniques.slice(0, MAX_TECHNIQUES),
    software: allSoftware.slice(0, MAX_SOFTWARE),
  };
  if (allTechniques.length > MAX_TECHNIQUES) rec.techniquesTotal = allTechniques.length;
  out.push(rec);
}

const attackVer = (objects.find((o) => o.type === 'x-mitre-collection') || {}).x_mitre_version || '?';
const iface =
  'export interface GeneratedThreatActor {\n' +
  '  id: string;\n  name: string;\n' +
  '  /** Other names this group is publicly known by. */\n  aliases: string[];\n' +
  '  url: string;\n' +
  '  /** One-line summary (cards, meta description). */\n  summary: string;\n' +
  '  /** Fuller MITRE description — the detail-page definition. */\n  description: string;\n' +
  '  /** ATT&CK technique ids this group is documented using (a capped sample). */\n  techniques: string[];\n' +
  '  /** Total documented technique uses behind `techniques`, only set when capped. */\n  techniquesTotal?: number;\n' +
  '  /** Malware/tool names this group is documented using (a capped sample). */\n  software: string[];\n' +
  '}\n\n';
const genFile =
  '// AUTO-GENERATED by scripts/gen-threat-actors.mjs from the MITRE ATT&CK Enterprise\n' +
  `// STIX bundle (v${attackVer}). Do not edit by hand — re-run the script to refresh.\n\n` +
  '/** The ATT&CK Enterprise version this dataset was generated from. */\n' +
  `export const THREAT_ACTORS_ATTACK_VERSION = '${attackVer}';\n\n` +
  iface +
  '// Compact one-line array (generated; not meant to be hand-reviewed).\n' +
  'export const THREAT_ACTORS_GENERATED: GeneratedThreatActor[] = ' + JSON.stringify(out) + ';\n\n' +
  '/** Total real, publicly documented groups in the dataset. */\n' +
  'export const THREAT_ACTORS_TOTAL: number = THREAT_ACTORS_GENERATED.length;\n';
fs.writeFileSync(path.join(ROOT, 'src/data/threat-actors.generated.ts'), genFile);

console.log('wrote', out.length, 'threat actors (v' + attackVer + ')');
