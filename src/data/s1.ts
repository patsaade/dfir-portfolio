// SentinelOne PowerQuery Builder — the verified field / event-type / operator
// reference data.
//
// SOURCE DISCIPLINE (stricter here than anywhere else on this site, because
// SentinelOne's own product documentation sits behind a customer login and
// cannot be linked or cited). Nothing in this file was written from memory or
// inferred from a naming pattern. Every field name, event-type value, operator
// and command below had to clear one of two bars before it was allowed in:
//
//   TIER 1 — `source: 'sentinelone'`. The exact spelling appears verbatim in a
//   query SentinelOne itself published on sentinelone.com, or in the
//   SentineLabs (SentinelOne Research) S1QL query repository. These are the
//   vendor's own words.
//
//   TIER 2 — `source: 'corroborated'`. The exact spelling appears in at least
//   TWO independently-authored public sources — the maintained
//   pySigma SentinelOne PowerQuery backend's field-mapping pipeline, Sekoia's
//   and Google Security Operations' published SentinelOne Cloud Funnel field
//   documentation, and independent practitioner query collections.
//
// Anything that cleared neither bar was LEFT OUT, even where it looked obvious
// by symmetry with a field that did clear it. That is deliberate: a
// plausible-looking S1 field name that doesn't exist silently returns zero rows
// and reads as "nothing to find here," which is the worst possible failure mode
// for a hunting query. The tool's own page lists what was cut and why.
//
// Verified 2026-07-28 against:
//   - sentinelone.com/blog/intro-powerqueries/ (the PowerQuery syntax primer —
//     the group/let/sort/filter/limit/columns pipeline and count())
//   - sentinelone.com/blog/powerquery-brings-new-data-analytics-capabilities-to-singularity-xdr/
//     (the command list and the aggregate function names)
//   - sentinelone.com/blog/singularity-operations-center-unified-security-operations-for-rapid-triage/
//   - sentinelone.com/blog/how-sentinelone-secures-the-ai-tools-that-act-like-users/
//   - sentinelone.com/blog/defending-against-sha1-hulud-the-second-coming/
//   - github.com/SentineLabs/S1QL-Queries
//
// This is a SYNTAX BUILDER, not a query engine. Nothing here connects to a
// SentinelOne console, no query is executed, and no event is ever fetched.

/** Coarse type, which decides whether a value is quoted or written bare and
 *  which operators are offered. */
export type S1FieldKind = 'string' | 'numeric';

/** Which bar the exact spelling cleared — see the file header. Surfaced in the
 *  UI so a reader can see the provenance of every name they build against. */
type S1SourceTier = 'sentinelone' | 'corroborated';

export interface S1Field {
  /** Exact field name as published. */
  name: string;
  kind: S1FieldKind;
  /** Picker option-group. */
  group: string;
  hint: string;
  source: S1SourceTier;
}

// ---------------------------------------------------------------------------
// Fields
// ---------------------------------------------------------------------------

export const S1_FIELDS: S1Field[] = [
  // --- Event ---------------------------------------------------------------
  { name: 'event.type', kind: 'string', group: 'Event', source: 'sentinelone', hint: 'What kind of activity the row records — Process Creation, IP Connect, DNS Resolved, and so on.' },
  { name: 'event.time', kind: 'string', group: 'Event', source: 'sentinelone', hint: 'When the agent recorded the event. Usually a column you return rather than one you filter on.' },
  { name: 'event.category', kind: 'string', group: 'Event', source: 'corroborated', hint: 'Broader family the event type belongs to — file, dns, driver, logins, and so on.' },
  { name: 'dataSource.name', kind: 'string', group: 'Event', source: 'sentinelone', hint: "Which product produced the row. Pin it to 'SentinelOne' to exclude third-party data ingested into the same lake." },

  // --- Endpoint ------------------------------------------------------------
  { name: 'endpoint.name', kind: 'string', group: 'Endpoint', source: 'sentinelone', hint: 'Hostname of the agent that recorded the event. Case-sensitive on an exact match.' },
  { name: 'endpoint.os', kind: 'string', group: 'Endpoint', source: 'corroborated', hint: 'Operating system family — windows, linux, or osx.' },

  // --- Acting (source) process --------------------------------------------
  { name: 'src.process.name', kind: 'string', group: 'Acting process (src)', source: 'sentinelone', hint: 'Image name of the process performing the action. On a Process Creation row this is the PARENT.' },
  { name: 'src.process.cmdline', kind: 'string', group: 'Acting process (src)', source: 'sentinelone', hint: 'Full command line of the acting process.' },
  { name: 'src.process.user', kind: 'string', group: 'Acting process (src)', source: 'sentinelone', hint: 'Account the acting process ran as.' },
  { name: 'src.process.image.path', kind: 'string', group: 'Acting process (src)', source: 'corroborated', hint: 'Full on-disk path of the acting process image.' },
  { name: 'src.process.image.sha1', kind: 'string', group: 'Acting process (src)', source: 'corroborated', hint: 'SHA-1 of the acting process image.' },
  { name: 'src.process.integrityLevel', kind: 'string', group: 'Acting process (src)', source: 'corroborated', hint: 'Windows integrity level the acting process held.' },
  { name: 'src.process.storyline.id', kind: 'string', group: 'Acting process (src)', source: 'sentinelone', hint: "SentinelOne's own correlation ID for the whole execution chain — the fastest pivot from one row to the rest of the story." },
  { name: 'src.process.netConnCount', kind: 'numeric', group: 'Acting process (src)', source: 'sentinelone', hint: 'How many network connections the agent attributed to this process.' },
  { name: 'src.process.parent.name', kind: 'string', group: 'Acting process (src)', source: 'sentinelone', hint: 'Image name of the acting process’s own parent — the grandparent on a Process Creation row.' },
  { name: 'src.process.parent.cmdline', kind: 'string', group: 'Acting process (src)', source: 'corroborated', hint: 'Command line of that grandparent process.' },
  { name: 'src.process.parent.image.path', kind: 'string', group: 'Acting process (src)', source: 'corroborated', hint: 'On-disk path of that grandparent process image.' },
  { name: 'src.process.parent.publisher', kind: 'string', group: 'Acting process (src)', source: 'sentinelone', hint: 'Code-signing publisher of that grandparent process image.' },

  // --- Target process ------------------------------------------------------
  { name: 'tgt.process.name', kind: 'string', group: 'Target process (tgt)', source: 'sentinelone', hint: 'Image name of the process being created or acted on — the CHILD on a Process Creation row.' },
  { name: 'tgt.process.cmdline', kind: 'string', group: 'Target process (tgt)', source: 'sentinelone', hint: 'Full command line of the newly created process. The richest single field for execution hunting.' },
  { name: 'tgt.process.publisher', kind: 'string', group: 'Target process (tgt)', source: 'sentinelone', hint: 'Code-signing publisher of the target process image.' },
  { name: 'tgt.process.image.path', kind: 'string', group: 'Target process (tgt)', source: 'corroborated', hint: 'Full on-disk path of the target process image — where the thing that ran actually lives.' },

  // --- Target file ---------------------------------------------------------
  { name: 'tgt.file.path', kind: 'string', group: 'Target file (tgt)', source: 'sentinelone', hint: 'Full path of the file the event touched. Backslashes are doubled inside a quoted value.' },
  { name: 'tgt.file.extension', kind: 'string', group: 'Target file (tgt)', source: 'corroborated', hint: 'File extension without the dot — exe, dll, ps1, zip, and so on.' },
  { name: 'tgt.file.sha1', kind: 'string', group: 'Target file (tgt)', source: 'sentinelone', hint: 'SHA-1 of the file. The field SentinelOne’s own IOC-sweep queries use.' },
  { name: 'tgt.file.size', kind: 'numeric', group: 'Target file (tgt)', source: 'sentinelone', hint: 'File size in bytes.' },

  // --- Registry ------------------------------------------------------------
  { name: 'registry.keyPath', kind: 'string', group: 'Registry', source: 'corroborated', hint: 'Full path of the registry key or value the event applied to.' },
  { name: 'registry.value', kind: 'string', group: 'Registry', source: 'corroborated', hint: 'Data written to the registry value.' },

  // --- Network / DNS / URL -------------------------------------------------
  { name: 'src.ip.address', kind: 'string', group: 'Network', source: 'sentinelone', hint: 'Local address of the connection.' },
  { name: 'dst.ip.address', kind: 'string', group: 'Network', source: 'sentinelone', hint: 'Remote address the endpoint connected to.' },
  { name: 'src.port.number', kind: 'numeric', group: 'Network', source: 'sentinelone', hint: 'Local port.' },
  { name: 'dst.port.number', kind: 'numeric', group: 'Network', source: 'sentinelone', hint: 'Remote port — the one that tells you what the traffic probably is.' },
  { name: 'event.network.direction', kind: 'string', group: 'Network', source: 'sentinelone', hint: 'OUTGOING or INCOMING.' },
  { name: 'event.network.connectionStatus', kind: 'string', group: 'Network', source: 'corroborated', hint: 'SUCCESS or FAILURE for the connection attempt.' },
  { name: 'event.dns.request', kind: 'string', group: 'Network', source: 'corroborated', hint: 'Domain the endpoint looked up.' },
  { name: 'event.dns.response', kind: 'string', group: 'Network', source: 'corroborated', hint: 'What the resolver answered with.' },
  { name: 'url.address', kind: 'string', group: 'Network', source: 'corroborated', hint: 'Full URL for an HTTP event.' },

  // --- Persistence / detections -------------------------------------------
  { name: 'task.name', kind: 'string', group: 'Persistence & detections', source: 'sentinelone', hint: 'Name of a scheduled task involved in the event.' },
  { name: 'indicator.name', kind: 'string', group: 'Persistence & detections', source: 'corroborated', hint: "Name of the behavioural indicator SentinelOne's engine raised on the activity." },
  { name: 'indicator.metadata', kind: 'string', group: 'Persistence & detections', source: 'corroborated', hint: 'Free-text detail attached to that indicator.' },
];

export const S1_FIELD_GROUPS: string[] = S1_FIELDS.reduce<string[]>((groups, f) => {
  if (!groups.includes(f.group)) groups.push(f.group);
  return groups;
}, []);

// ---------------------------------------------------------------------------
// event.type values
// ---------------------------------------------------------------------------

export interface S1EventType {
  value: string;
  hint: string;
  source: S1SourceTier;
}

/** Only the `event.type` values whose exact strings cleared the sourcing bars
 *  in this file's header. SentinelOne records many more; a value's absence here
 *  means it could not be verified from public material, never that it doesn't
 *  exist. */
export const S1_EVENT_TYPES: S1EventType[] = [
  { value: 'Process Creation', source: 'sentinelone', hint: 'A process was created. src.* is the parent, tgt.* is the child.' },
  { value: 'File Creation', source: 'corroborated', hint: 'A file was created on disk.' },
  { value: 'File Modification', source: 'corroborated', hint: 'An existing file was written to.' },
  { value: 'Module Load', source: 'sentinelone', hint: 'A DLL or other module was loaded into a process.' },
  { value: 'IP Connect', source: 'sentinelone', hint: 'A network connection was attempted or established.' },
  { value: 'DNS Resolved', source: 'corroborated', hint: 'A DNS lookup completed.' },
  { value: 'Registry Value Create', source: 'corroborated', hint: 'A registry value was created.' },
  { value: 'Registry Value Modified', source: 'corroborated', hint: 'An existing registry value was changed.' },
];

// ---------------------------------------------------------------------------
// Operators
// ---------------------------------------------------------------------------

/** How the right-hand side is written out.
 *  - `binary` -> `field <symbol> <value>`
 *  - `list`   -> `field in ('a', 'b')` */
type S1OperatorForm = 'binary' | 'list';

export interface S1Operator {
  id: string;
  /** Exact text emitted into the query. */
  symbol: string;
  label: string;
  form: S1OperatorForm;
  kinds: S1FieldKind[];
  hint: string;
}

/** Every operator here appears verbatim in a SentinelOne-published query or in
 *  two independent public collections. Notably absent: a documented
 *  case-SENSITIVE `contains`. `contains` reads as case-insensitive in some
 *  published examples and `contains:anycase` is used explicitly in others, so
 *  both are offered and the tool says plainly that `contains:anycase` is the
 *  one to reach for when case must not matter. */
export const S1_OPERATORS: S1Operator[] = [
  { id: 'eq', symbol: '=', label: 'equals', form: 'binary', kinds: ['string', 'numeric'], hint: 'Exact match. String comparison is case-sensitive — use contains:anycase when case should not matter.' },
  { id: 'neq', symbol: '!=', label: 'not equals', form: 'binary', kinds: ['string', 'numeric'], hint: 'Exact non-match. Reads as an implicit AND NOT against the rest of the expression.' },
  { id: 'contains', symbol: 'contains', label: 'contains', form: 'binary', kinds: ['string'], hint: 'Substring match anywhere in the field.' },
  { id: 'contains_ci', symbol: 'contains:anycase', label: 'contains (ignore case)', form: 'binary', kinds: ['string'], hint: 'Substring match that explicitly ignores case — the durable choice for file names and command lines.' },
  { id: 'in', symbol: 'in', label: 'in list', form: 'list', kinds: ['string', 'numeric'], hint: 'Matches any value in the list. The clean way to express "any of these" without OR grouping.' },
  { id: 'matches', symbol: 'matches', label: 'matches regex', form: 'binary', kinds: ['string'], hint: 'Regular-expression match against the field.' },
  { id: 'gt', symbol: '>', label: 'greater than', form: 'binary', kinds: ['numeric'], hint: 'Numeric comparison.' },
  { id: 'gte', symbol: '>=', label: 'greater than or equal', form: 'binary', kinds: ['numeric'], hint: 'Numeric comparison.' },
  { id: 'lt', symbol: '<', label: 'less than', form: 'binary', kinds: ['numeric'], hint: 'Numeric comparison.' },
  { id: 'lte', symbol: '<=', label: 'less than or equal', form: 'binary', kinds: ['numeric'], hint: 'Numeric comparison.' },
];

// ---------------------------------------------------------------------------
// Aggregate functions for `| group`
// ---------------------------------------------------------------------------

export interface S1Aggregation {
  id: string;
  label: string;
  /** Function name as written in PowerQuery. */
  fn: string;
  /** Default output column name the builder assigns with `<alias> = ...`. */
  alias: string;
  needsField: boolean;
  fieldKinds: S1FieldKind[];
  hint: string;
}

/** The aggregate functions SentinelOne's own PowerQuery material names. */
export const S1_AGGREGATIONS: S1Aggregation[] = [
  { id: 'count', label: 'count() — rows', fn: 'count', alias: 'events', needsField: false, fieldKinds: [], hint: 'Number of events in each group.' },
  { id: 'estimate_distinct', label: 'estimate_distinct() — distinct values', fn: 'estimate_distinct', alias: 'distinct_values', needsField: true, fieldKinds: ['string', 'numeric'], hint: 'Approximate count of distinct values — the go-to for "how many hosts / how many destinations".' },
  { id: 'array_agg_distinct', label: 'array_agg_distinct() — the distinct values themselves', fn: 'array_agg_distinct', alias: 'values', needsField: true, fieldKinds: ['string', 'numeric'], hint: 'Collects the distinct values into a list instead of just counting them.' },
  { id: 'sum', label: 'sum() — total', fn: 'sum', alias: 'total', needsField: true, fieldKinds: ['numeric'], hint: 'Adds up a numeric field across the group.' },
  { id: 'min', label: 'min() — smallest', fn: 'min', alias: 'smallest', needsField: true, fieldKinds: ['numeric'], hint: 'Smallest value in the group.' },
  { id: 'max', label: 'max() — largest', fn: 'max', alias: 'largest', needsField: true, fieldKinds: ['numeric'], hint: 'Largest value in the group.' },
];
