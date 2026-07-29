// Vendor threat-actor naming-convention reference — how MITRE ATT&CK,
// Mandiant/Google Threat Intelligence, CrowdStrike, Microsoft, and
// Secureworks Counter Threat Unit (CTU) each derive their own name for the
// same tracked activity. Every scheme's explanation and code -> meaning
// mapping below was independently verified against that vendor's own live
// documentation (see `sourceUrl`) before inclusion — same "confirm before
// adding, drop what can't be confirmed" discipline as src/data/eventIds.ts
// and the MITRE-STIX generation behind src/data/threatActors.ts. This is a
// DIFFERENT category of hand-curated content than THREAT_ACTORS, though:
// these are facts about vendor TAXONOMY (how five separate organizations'
// naming grammars work), not facts about any one specific tracked group, so
// nothing here is derived from or duplicated out of that dataset. Powers
// both the "Naming conventions" explainer on /reference/threat-actors/
// (src/pages/threat-actors.astro) and the namingConvention drill mode in
// src/data/drills/threatActorsDrill.ts — a fact only needs verifying once
// and both surfaces stay in lockstep.
import type { IconName } from '../components/Icon.astro';

interface VendorNameMapping {
  /** The vendor's own short code/qualifier — a G#### format, a category word, an element name, a prefix. */
  code: string;
  /** What that code indicates — a country/nexus, a motivation, a maturity tier. */
  meaning: string;
}

export interface VendorNamingScheme {
  vendor: string;
  icon: IconName;
  /** Plain-English summary of how this vendor derives its own names — see this file's header comment for the verification discipline. */
  explanation: string;
  mappings: VendorNameMapping[];
  sourceUrl: string;
  /** Human-readable label for the citation link text. */
  sourceLabel: string;
}

export const VENDOR_NAMING_SCHEMES: VendorNamingScheme[] = [
  {
    vendor: 'MITRE ATT&CK',
    icon: 'crosshair',
    explanation:
      "Every tracked group gets a permanent, unique G#### identifier when it's added to the ATT&CK knowledge base (Enterprise, Mobile, and ICS groups share one numbering pool) — ids increase over time as new groups are added, though this is an observed pattern, not a formal assignment rule documented on MITRE's own pages. MITRE doesn't do its own primary attribution; it aggregates public threat reporting and captures every other publicly reported name for the same tracked activity — regardless of which vendor coined it — as an \"Associated Group\" on that group's own page (a field MITRE renamed from \"Aliases\"). The name MITRE displays as canonical is often, though this isn't stated as a hard rule either, whichever name became most recognized in public reporting.",
    mappings: [
      { code: 'G####', meaning: 'Permanent, unique id assigned when a group is added to the knowledge base' },
      { code: 'Associated Groups', meaning: 'Every other publicly reported name for the same tracked activity, from any vendor (formerly labeled "Aliases")' },
    ],
    sourceUrl: 'https://attack.mitre.org/groups/',
    sourceLabel: "MITRE ATT&CK's own Groups index",
  },
  {
    vendor: 'Mandiant / Google Threat Intelligence',
    icon: 'search',
    explanation:
      'Mandiant\'s naming reflects a maturity ladder for attribution confidence, not one flat namespace. A newly discovered cluster of related intrusion activity — shared infrastructure, tools, or tradecraft observed across one or more incidents — starts as an "uncategorized" cluster with a sequential UNC#### number, deliberately not yet claiming a motivation or nation-state attribution. As evidence accumulates, often over years, a cluster can be renamed or merged, sometimes pass through an intermediate TEMP.* working name, and eventually "graduate" into a fully classified APT## or FIN## designation once enough evidence supports it.',
    mappings: [
      { code: 'APT##', meaning: 'Assessed, with sufficient confidence, to be affiliated with nation-state-sponsored espionage' },
      { code: 'FIN##', meaning: 'Assessed to be financially motivated (cybercrime), not nation-state espionage' },
      { code: 'UNC####', meaning: 'An "uncategorized" cluster not yet ready to classify — can graduate into APT##/FIN##, merge with, or split from other clusters' },
    ],
    sourceUrl: 'https://cloud.google.com/blog/topics/threat-intelligence/how-mandiant-tracks-uncategorized-threat-actors',
    sourceLabel: 'How Mandiant tracks uncategorized threat actors',
  },
  {
    vendor: 'CrowdStrike',
    icon: 'bug',
    explanation:
      'CrowdStrike assigns every tracked adversary a two-word cryptonym. The first word is a distinguishing qualifier — often influenced by a prominent tool or TTP analysts observed the actor use — unique to that specific adversary. The second word is a shared category term indicating nation-state nexus or motivation: nation-state actors get their attributed country\'s own recognized national animal, while non-nation-state categories get their own dedicated word (eCrime gets "Spider," hacktivism gets "Jackal").',
    mappings: [
      { code: 'Bear', meaning: 'Russia (nation-state)' },
      { code: 'Panda', meaning: 'China (nation-state)' },
      { code: 'Kitten', meaning: 'Iran (nation-state)' },
      { code: 'Chollima', meaning: 'North Korea (nation-state)' },
      { code: 'Buffalo', meaning: 'Vietnam (nation-state)' },
      { code: 'Leopard', meaning: 'Pakistan (nation-state)' },
      { code: 'Tiger', meaning: 'India (nation-state)' },
      { code: 'Wolf', meaning: 'Turkey (nation-state)' },
      { code: 'Crane', meaning: 'South Korea / Republic of Korea (nation-state)' },
      { code: 'Bison', meaning: 'Belarus (nation-state)' },
      { code: 'Spider', meaning: 'eCrime / financially motivated (not nation-state)' },
      { code: 'Jackal', meaning: 'Hacktivism — politically/ideologically motivated disruption (not nation-state or financial)' },
    ],
    sourceUrl: 'https://www.crowdstrike.com/en-us/adversaries/',
    sourceLabel: "CrowdStrike's own Adversary Universe",
  },
  {
    vendor: 'Microsoft',
    icon: 'cloud',
    explanation:
      'Since April 2023, Microsoft assigns every threat actor a weather-themed "family name." For nation-state actors, the family name maps to the actor\'s country/region of attribution (a fixed weather-word-per-country table Microsoft publishes and updates); for non-nation-state activity, the family name instead encodes a motivation or category. Within a family, individual actor groups are distinguished by a unique adjective prefixed to the family name (e.g. "Midnight Blizzard," "Forest Blizzard" — both Russia-attributed but distinct groups sharing the Blizzard family). Newly discovered or not-yet-fully-attributed activity gets a temporary "Storm-####" designation instead of a full family name, converting to a permanent named actor (or merging into an existing one) once Microsoft reaches high confidence on origin/identity. This superseded Microsoft\'s older, pre-2023 chemical-element codenames (e.g. STRONTIUM, NOBELIUM) — both eras\' names are preserved in Microsoft\'s own current-to-legacy mapping table.',
    mappings: [
      { code: 'Typhoon', meaning: 'China (nation-state)' },
      { code: 'Sandstorm', meaning: 'Iran (nation-state)' },
      { code: 'Sleet', meaning: 'North Korea (nation-state)' },
      { code: 'Blizzard', meaning: 'Russia (nation-state)' },
      { code: 'Dust', meaning: 'Türkiye (nation-state)' },
      { code: 'Cyclone', meaning: 'Vietnam (nation-state)' },
      { code: 'Rain', meaning: 'Lebanon (nation-state)' },
      { code: 'Hail', meaning: 'South Korea (nation-state)' },
      { code: 'Tempest', meaning: 'Financially motivated (not nation-state)' },
      { code: 'Tsunami', meaning: 'Private sector offensive actor (PSOA) — commercial spyware/cyberweapon vendors' },
      { code: 'Flood', meaning: 'Influence operations' },
      { code: 'Storm-####', meaning: 'Temporary designation for a newly discovered or still-developing cluster, pending conversion to a permanent named actor or merge into an existing one' },
    ],
    sourceUrl: 'https://learn.microsoft.com/en-us/unified-secops/microsoft-threat-actor-naming',
    sourceLabel: "Microsoft's own threat actor naming reference",
  },
  {
    vendor: 'Secureworks Counter Threat Unit (now part of Sophos)',
    icon: 'lock',
    explanation:
      'Secureworks CTU assigns every threat group a metal/element word plus a distinguishing nickname (e.g. "Bronze Butler"). The element prefix denotes the group\'s attributed country or thematic category, replacing CTU\'s older numeric "Threat Group-####" designations (e.g. TG-3390 became BRONZE UNION) with names CTU says are easier for analysts to remember and discuss.',
    mappings: [
      { code: 'BRONZE', meaning: 'China' },
      { code: 'COBALT', meaning: 'Iran' },
      { code: 'GOLD', meaning: 'Cybercrime / financially motivated' },
      { code: 'IRON', meaning: 'Russia' },
      { code: 'NICKEL', meaning: 'North Korea' },
      { code: 'COPPER', meaning: 'Pakistan' },
      { code: 'PLATINUM', meaning: 'United States' },
      { code: 'ALUMINUM', meaning: 'Palestine' },
      { code: 'LITHIUM', meaning: 'Lebanon' },
      { code: 'SILVER', meaning: 'Singapore' },
      { code: 'STEEL', meaning: 'United Kingdom' },
      { code: 'TIN', meaning: 'Vietnam' },
      { code: 'TUNGSTEN', meaning: 'South Korea' },
      { code: 'ZINC', meaning: 'India' },
      { code: 'RADIUM', meaning: 'Red Team exercises (not a real threat actor)' },
    ],
    sourceUrl: 'https://docs.taegis.secureworks.com/intelligence/threat_groups/',
    sourceLabel: "Secureworks CTU's own Threat Group index",
  },
];

/** Why the same real-world group ends up with names from five unrelated
 *  vendor grammars — condensed from the same verification pass as the
 *  schemes above. See src/pages/threat-actors.astro for where this renders. */
export const WHY_MANY_NAMES =
  "Every major intel vendor discovers new malicious activity independently, through its own visibility — Mandiant through incident-response engagements, CrowdStrike through Falcon telemetry and its own adversary-tracking team, Microsoft through its cloud and endpoint telemetry, Secureworks through CTU research and customer engagements, and MITRE ATT&CK by aggregating public reporting rather than doing primary attribution itself. When a vendor first spots a new cluster of activity — shared C2 infrastructure, a distinctive toolset, a consistent TTP pattern — it has no way of knowing whether anyone else has already seen the same actor from a different angle, so it opens its own working name under its own house convention. Only later, sometimes years later, does correlation happen: shared infrastructure, overlapping malware, an intel-sharing relationship, a leak, or a law-enforcement action establishes that two independently-named clusters are actually the same group, and a cluster \"graduates\" into a named designation, or a temporary one (like a Storm-#### tag) is retired in favor of a permanent name. Occasionally the reverse happens too: a single presumed group turns out to be two distinct clusters that had been conflated, and they get split apart. MITRE sits downstream of all of this — it doesn't attribute activity itself, it aggregates what's already been publicly reported, and lists every other vendor's name for the same cluster as an Associated Group on its own canonical page.";
