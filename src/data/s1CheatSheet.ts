// SentinelOne PowerQuery (S1QL 2.0) Cheat Sheet — the query shape, operators,
// commands and Deep Visibility field namespace a responder actually types into
// the SentinelOne console.
//
// SOURCE DISCIPLINE, AND AN HONEST SCOPE NOTE.
//
// SentinelOne's full product documentation sits behind a customer login, so —
// unlike the KQL and SPL sheets, which are verified against Microsoft's and
// Splunk's openly published language references — this sheet is built ONLY from
// SentinelOne's own PUBLICLY PUBLISHED material: their engineering/threat-
// research blog posts, each of which ships complete, real, runnable queries.
// Every command, operator, function and field name below appears verbatim in at
// least one of these SentinelOne-authored pages, read on 2026-07-28:
//   - "PowerQuery Brings New Data Analytics Capabilities to Singularity XDR"
//     (the command inventory: filter, columns, group, join, limit, sort,
//     transpose, parse, union, let — plus the group-by function list and the
//     arithmetic/ternary/regex support statement)
//   - "Transform Your Data On The Fly!" and "Adding fit and finish to your
//     PowerQueries reports" (worked group/let/sort/filter/limit/columns and
//     parse-from + ternary examples)
//   - "Summary Calculations with PowerQuery Join and Union Functions" and
//     "Computing Time Deltas with PowerQueries" (join/union subquery syntax)
//   - "Singularity Operations Center", "Defending Against ToolShell",
//     "Defending Against Sha1-Hulud: The Second Coming", "Shadow Agents", and
//     "Protection Against Local Upgrade Technique Described in Aon Research"
//     (real hunting queries — the source of every `event.*` / `endpoint.*` /
//     `src.*` / `tgt.*` / `dst.*` / `task.*` field name here)
// See externalResources.ts's 's1-cheatsheet' entry for the citations, and
// S1_CATEGORY_SOURCES below for the per-section source shown on the page.
//
// WHAT IS DELIBERATELY NOT HERE — gaps, stated rather than padded over:
//   - THE FIELD LIST IS NOT THE SCHEMA. Deep Visibility exposes far more fields
//     than the ~25 below; these are simply the ones SentinelOne has published in
//     a real query. The console's own autocomplete is the authority on the rest.
//   - NO EVENT-TYPE ENUMERATION. Only the `event.type` values that appear in a
//     published query ('Process Creation', 'IP Connect') are named. The full
//     list of event types is not publicly documented and is not guessed at here.
//   - NO S1QL 1.0 SYNTAX. SentinelOne's 2017-era Deep Visibility cheat sheet
//     uses a completely different, PascalCase field namespace (ProcessCmd,
//     ParentProcessName, DstIP, ...). That is the older query language, not
//     PowerQuery/S1QL 2.0, and mixing the two produces queries that silently
//     match nothing — so none of it is reproduced here.
//   - NO `lookup`, NO API/`limit` ceiling claims, NO time-range syntax. The
//     console supplies the time range through its own picker in every published
//     example, so no `earliest`/`latest`-style modifier is documented here.
//
// Category order IS display order (the page groups by first occurrence).

export interface S1SyntaxEntry {
  category: string;
  syntax: string;
  description: string;
  example: string;
}

/** The authoritative SentinelOne-published page each category was verified
 *  against, surfaced under that category's heading on the page. */
export const S1_CATEGORY_SOURCES: Record<string, { name: string; url: string }> = {
  'Query Shape & the Pipeline': {
    name: 'SentinelOne — PowerQuery Brings New Data Analytics Capabilities to Singularity XDR',
    url: 'https://www.sentinelone.com/blog/powerquery-brings-new-data-analytics-capabilities-to-singularity-xdr/',
  },
  'Filtering & Matching': {
    name: 'SentinelOne — Defending Against ToolShell (published hunting queries)',
    url: 'https://www.sentinelone.com/blog/defending-against-toolshell-sharepoints-latest-critical-vulnerability/',
  },
  'Core Event & Endpoint Fields': {
    name: 'SentinelOne — Singularity Operations Center (published hunting queries)',
    url: 'https://www.sentinelone.com/blog/singularity-operations-center-unified-security-operations-for-rapid-triage/',
  },
  'Process, File & Network Fields': {
    name: 'SentinelOne — Shadow Agents (published PowerQuery)',
    url: 'https://www.sentinelone.com/blog/how-sentinelone-secures-the-ai-tools-that-act-like-users/',
  },
  'Aggregation with group': {
    name: 'SentinelOne — Protection Against Local Upgrade Technique (published PowerQuery)',
    url: 'https://www.sentinelone.com/blog/protection-against-local-upgrade-technique-described-in-aon-research/',
  },
  'Shaping & Computing Fields': {
    name: 'SentinelOne — Adding fit and finish to your PowerQueries reports',
    url: 'https://www.sentinelone.com/blog/adding-fit-and-finish-to-your-powerqueries-reports/',
  },
  'Combining Result Sets': {
    name: 'SentinelOne — Summary Calculations with PowerQuery Join and Union Functions',
    url: 'https://www.sentinelone.com/blog/summary-calculations-with-joins-and-unions/',
  },
};

export const S1_CHEAT_SHEET: S1SyntaxEntry[] = [
  // -------------------------------------------------------------------------
  // Query Shape & the Pipeline
  // -------------------------------------------------------------------------
  {
    category: 'Query Shape & the Pipeline',
    syntax: 'filter | command | command',
    description:
      'A PowerQuery starts with a plain Deep Visibility filter expression — no leading pipe — and then chains commands with the pipe character. Everything before the first pipe selects events; everything after it transforms them.',
    example:
      "dataSource.name = 'SentinelOne' and event.type = 'Process Creation' | group count = count() by endpoint.name",
  },
  {
    category: 'Query Shape & the Pipeline',
    syntax: "dataSource.name = 'SentinelOne'",
    description:
      'Scopes a query to SentinelOne agent telemetry rather than any other source feeding the Data Lake. Every SentinelOne-published hunting query opens with it.',
    example:
      "dataSource.name = 'SentinelOne' and event.type = 'Process Creation' and src.process.cmdline contains '--name SHA1HULUD'",
  },
  {
    category: 'Query Shape & the Pipeline',
    syntax: 'filter → group → let → columns → filter',
    description:
      'The shape SentinelOne\'s own published queries follow: select events, aggregate them, compute derived fields from the aggregates, choose the output columns, then filter on what you just computed. A second `filter` after the aggregation is how you threshold a summary.',
    example:
      "| group count = count() by endpoint.name | let ratio = count / 100 | columns endpoint.name, count, ratio | filter ratio > 5",
  },
  {
    category: 'Query Shape & the Pipeline',
    syntax: '| filter <condition>',
    description:
      'Discards records that do not match a condition. Placed after a `group` or `columns` stage, it filters on the fields that stage produced rather than on raw event fields.',
    example: "| filter tgt_process_cmdlines contains 'tasklist' and tgt_process_cmdlines contains 'findstr'",
  },
  {
    category: 'Query Shape & the Pipeline',
    syntax: '| limit N',
    description:
      'Caps the number of records displayed or processed by subsequent commands. Worth setting explicitly on a wide hunt so an aggregation downstream stays bounded.',
    example: '| limit 1600000',
  },
  {
    category: 'Query Shape & the Pipeline',
    syntax: '| sort -field',
    description: 'Determines the order records are displayed in. A leading `-` sorts descending.',
    example: '| sort -error_percent',
  },
  {
    category: 'Query Shape & the Pipeline',
    syntax: '| transpose',
    description: 'Removes columns from a table and creates a new column from their values — for turning a wide summary into a narrow one.',
    example: '| group count = count() by endpoint.name | transpose',
  },

  // -------------------------------------------------------------------------
  // Filtering & Matching
  // -------------------------------------------------------------------------
  {
    category: 'Filtering & Matching',
    syntax: '=',
    description: 'Equality against a literal. String literals are single-quoted (double quotes appear in SentinelOne\'s own queries too).',
    example: "endpoint.os = 'windows' and event.type = 'Process Creation'",
  },
  {
    category: 'Filtering & Matching',
    syntax: 'and / or',
    description: 'Logical conjunction and disjunction. Parenthesise groups when you mix them — SentinelOne\'s own published queries do.',
    example:
      "(tgt.file.path contains '/bun_environment.js' or tgt.file.path contains '\\\\bun_environment.js')",
  },
  {
    category: 'Filtering & Matching',
    syntax: '!( ... )',
    description: 'Negates a whole parenthesised expression — the way to exclude a known-good hash set from an otherwise broad file hunt.',
    example: 'AND !(tgt.file.sha1 in ("3d7570d14d34b0ba137d502f042b27b0f37a59fa"))',
  },
  {
    category: 'Filtering & Matching',
    syntax: 'contains',
    description: 'Substring match. The most-used operator in SentinelOne\'s published hunting queries, because command lines and paths are rarely exact-matchable.',
    example: "src.process.name contains 'w3wp.exe' and src.process.cmdline contains 'SharePoint'",
  },
  {
    category: 'Filtering & Matching',
    syntax: 'contains:anycase',
    description: 'Case-insensitive substring match. Accepts a parenthesised list, in which case any element matching is enough.',
    example: "tgt.process.cmdline contains:anycase ('clawdbot','moltbot','openclaw')",
  },
  {
    category: 'Filtering & Matching',
    syntax: 'contains (a, b, c)',
    description: 'Substring match against several candidates at once — one clause instead of a chain of ORs.',
    example: "| filter tgt_process_cmdlines contains ('sentinelinstaller','sentineloneinstaller')",
  },
  {
    category: 'Filtering & Matching',
    syntax: 'in ( ... )',
    description: 'Exact membership against a list of literals. This is the shape SentinelOne publishes IOC hash sweeps in.',
    example:
      'tgt.file.sha1 in ("3d7570d14d34b0ba137d502f042b27b0f37a59fa","d60ec97eea19fffb4809bc35b91033b52490ca11")',
  },
  {
    category: 'Filtering & Matching',
    syntax: 'in:anycase ( ... )',
    description: 'Case-insensitive membership test — the right operator for Windows process names, whose casing is not consistent in telemetry.',
    example: "tgt.process.name in:anycase ('tasklist.exe')",
  },
  {
    category: 'Filtering & Matching',
    syntax: 'matches "regex"',
    description: 'Regular-expression match against a field. Used inside a filter, and equally inside a ternary to bucket values.',
    example: '(host matches "prod") ? "Prod" : "non-prod"',
  },
  {
    category: 'Filtering & Matching',
    syntax: '>  <  >=  <=',
    description: 'Numeric comparison. Works on raw event fields and on values you computed in an earlier `group` or `let` stage.',
    example: 'tgt.file.size>7000000',
  },
  {
    category: 'Filtering & Matching',
    syntax: '&&',
    description: 'The C-style logical AND, used inside a `filter` expression alongside comparisons.',
    example: '| filter requests >= 500 && error_percent > 1',
  },

  // -------------------------------------------------------------------------
  // Core Event & Endpoint Fields
  // -------------------------------------------------------------------------
  {
    category: 'Core Event & Endpoint Fields',
    syntax: 'event.type',
    description:
      "The event class. SentinelOne's published queries use 'Process Creation' and 'IP Connect'; the console's autocomplete lists the rest, and this sheet does not guess at values that have not been published.",
    example: "event.type = 'IP Connect' and event.network.direction = 'OUTGOING'",
  },
  {
    category: 'Core Event & Endpoint Fields',
    syntax: 'event.time',
    description: 'The event timestamp. Bucket it with `timebucket()` in a `let` before grouping, to turn a raw event stream into a timeline.',
    example: "| let event.time = timebucket(event.time, '10 minutes')",
  },
  {
    category: 'Core Event & Endpoint Fields',
    syntax: 'event.network.direction',
    description: "Direction of a network event. 'OUTGOING' is the value SentinelOne uses in its own egress-hunting example.",
    example:
      "event.type='IP Connect' and event.network.direction = 'OUTGOING' | group count=count() by dst.ip.address",
  },
  {
    category: 'Core Event & Endpoint Fields',
    syntax: 'endpoint.name',
    description: 'The agent hostname. The natural `by` key for almost every summary, and the field you pivot on once a hunt returns a hit.',
    example: "endpoint.name = 'TheBorg-KY3H' and event.type='IP Connect'",
  },
  {
    category: 'Core Event & Endpoint Fields',
    syntax: 'endpoint.os',
    description: "The endpoint operating system — 'windows' in SentinelOne's published Windows-specific hunts.",
    example: "dataSource.name = 'SentinelOne' and endpoint.os = \"windows\"",
  },
  {
    category: 'Core Event & Endpoint Fields',
    syntax: 'dataSource.name',
    description: 'Which product fed the record into the Data Lake. Pin it to SentinelOne when you want agent telemetry rather than an ingested third-party log.',
    example: "dataSource.name = 'SentinelOne'",
  },
  {
    category: 'Core Event & Endpoint Fields',
    syntax: 'task.name',
    description: 'Scheduled-task name. A persistence-hunting field — SentinelOne uses it alongside process and file predicates in the same query.',
    example: "(task.name contains 'OpenClaw')",
  },

  // -------------------------------------------------------------------------
  // Process, File & Network Fields
  // -------------------------------------------------------------------------
  {
    category: 'Process, File & Network Fields',
    syntax: 'src.process.name',
    description:
      'The SOURCE (acting/parent-side) process image name. In SentinelOne telemetry `src.*` is the process that did something and `tgt.*` is what it did it to — getting the two the wrong way round is the most common mistake in an S1 query.',
    example: "event.type = 'Process Creation' and src.process.name contains 'csc.exe'",
  },
  {
    category: 'Process, File & Network Fields',
    syntax: 'src.process.cmdline',
    description: 'Command line of the source process. The highest-signal field on the platform for anything script- or LOLBin-shaped.',
    example: "src.process.cmdline contains '--unattended --token '",
  },
  {
    category: 'Process, File & Network Fields',
    syntax: 'src.process.parent.name',
    description: 'The grandparent in the chain — the process that spawned the source process. This is what turns a single event into a lineage.',
    example: "src.process.parent.name in ('ResistanceIsFutile.exe', '9672B0.exe')",
  },
  {
    category: 'Process, File & Network Fields',
    syntax: 'src.process.parent.cmdline',
    description: 'Command line of that grandparent process. Aggregate it with `array_agg_distinct()` to see every way a parent was invoked.',
    example: '| group list1 = array_agg_distinct(src.process.parent.cmdline) by endpoint.name',
  },
  {
    category: 'Process, File & Network Fields',
    syntax: 'src.process.parent.publisher',
    description: 'Signing publisher of the parent process image — the quick signed/unsigned sanity check on a suspicious chain.',
    example: '| columns src.process.parent.name, src.process.parent.publisher',
  },
  {
    category: 'Process, File & Network Fields',
    syntax: 'src.process.user',
    description: 'The user context the source process ran as. Pair it with the process name to separate service activity from a real interactive user.',
    example: '| columns endpoint.name, src.process.user, src.process.cmdline',
  },
  {
    category: 'Process, File & Network Fields',
    syntax: 'src.process.storyline.id',
    description:
      'The Storyline identifier — SentinelOne\'s correlation key that ties every related process, file, thread and network event together. Copy it out of a hit and query on it to get the whole incident in one shot.',
    example: '| columns event.time, src.process.storyline.id, event.type, endpoint.name',
  },
  {
    category: 'Process, File & Network Fields',
    syntax: 'tgt.process.name',
    description: 'The TARGET process image name — on a Process Creation event, the process that was created.',
    example: "src.process.name contains 'w3wp.exe' and tgt.process.name contains 'cmd.exe'",
  },
  {
    category: 'Process, File & Network Fields',
    syntax: 'tgt.process.cmdline',
    description: 'Command line of the target process. The field to aggregate when you want every distinct way a binary was invoked across the estate.',
    example: '| group cmdlines = array_agg_distinct(tgt.process.cmdline) by endpoint.name',
  },
  {
    category: 'Process, File & Network Fields',
    syntax: 'tgt.process.displayName',
    description:
      'The binary\'s file description string — "Lists the current running tasks" for tasklist.exe. Catches a renamed LOLBin that a name-based filter would miss.',
    example: "tgt.process.displayName contains 'Lists the current running tasks'",
  },
  {
    category: 'Process, File & Network Fields',
    syntax: 'tgt.process.publisher',
    description: 'Signing publisher of the target process image.',
    example: '| columns tgt.process.cmdline, tgt.process.publisher',
  },
  {
    category: 'Process, File & Network Fields',
    syntax: 'tgt.file.path',
    description: 'Full path of the file the event acted on. Remember to cover both path separators when a hunt spans Windows and Unix endpoints.',
    example:
      "tgt.file.path contains 'App_Web_spinstall0.aspx'",
  },
  {
    category: 'Process, File & Network Fields',
    syntax: 'tgt.file.sha1',
    description: 'SHA-1 of the target file. The field SentinelOne publishes its own IOC sweeps against, using `in ( ... )`.',
    example:
      'dataSource.name = \'SentinelOne\' AND tgt.file.sha1 in ("3d7570d14d34b0ba137d502f042b27b0f37a59fa")',
  },
  {
    category: 'Process, File & Network Fields',
    syntax: 'tgt.file.size',
    description: 'Size of the target file in bytes. A size floor is a cheap way to cut a broad filename hunt down to plausible payloads.',
    example: "dataSource.name = 'SentinelOne' AND tgt.file.size>7000000",
  },
  {
    category: 'Process, File & Network Fields',
    syntax: 'src.ip.address / dst.ip.address',
    description: 'Source and destination IP of a network event. Group by the destination to map where a host has been reaching out to.',
    example: '| group count=count() by dst.ip.address | sort -count',
  },
  {
    category: 'Process, File & Network Fields',
    syntax: 'src.port.number / dst.port.number',
    description: 'Source and destination port. A specific port pair is often the cheapest first filter for an agent or C2 you already know the shape of.',
    example: '(src.port.number = 18789 or dst.port.number = 18789)',
  },

  // -------------------------------------------------------------------------
  // Aggregation with group
  // -------------------------------------------------------------------------
  {
    category: 'Aggregation with group',
    syntax: '| group name = func() by field',
    description:
      'Aggregates records, grouping by one or more fields and computing statistics for each group. Comma-separate several aggregates, and several `by` keys.',
    example: '| group count = count() by endpoint.name, src.process.name',
  },
  {
    category: 'Aggregation with group',
    syntax: 'count()',
    description: 'Counts records in the group.',
    example: '| group count = count() by dst.ip.address',
  },
  {
    category: 'Aggregation with group',
    syntax: 'count(<condition>)',
    description:
      'Conditional count — counts only the records satisfying a predicate, so you can put a total and a subset side by side in one pass.',
    example: '| group requests = count(), errors = count(status >= 500) by uriPath',
  },
  {
    category: 'Aggregation with group',
    syntax: 'estimate_distinct(field)',
    description: 'Approximate distinct count over the group. The cardinality signal you threshold on when hunting for spray or enumeration behaviour.',
    example: '| group distinct_count_tgt_process_name = estimate_distinct(tgt.process.name) by endpoint.name',
  },
  {
    category: 'Aggregation with group',
    syntax: 'sum() / min() / max()',
    description:
      'The standard numeric aggregates over a group. SentinelOne documents `percentile()` alongside them; no published example of its argument form was available, so none is invented here.',
    example: '| group mint = min(timestamp), maxt = max(timestamp) by key = "1"',
  },
  {
    category: 'Aggregation with group',
    syntax: 'array_agg_distinct(field)',
    description:
      'Collapses every DISTINCT value in the group into one array cell. This is what turns "1,400 process events on this host" into one readable row listing what actually ran.',
    example: '| group cmdlines = array_agg_distinct(tgt.process.cmdline) by endpoint.name, src.process.name',
  },
  {
    category: 'Aggregation with group',
    syntax: 'timebucket(field, "interval")',
    description:
      'Rounds a timestamp down to an interval. Assign it back over `event.time` in a `let`, then group by it, and you have a per-interval timeline.',
    example:
      "| let event.time = timebucket(event.time, '10 minutes') | group count = count() by event.time, endpoint.name",
  },
  {
    category: 'Aggregation with group',
    syntax: 'array_to_string(array, sep)',
    description:
      'Renders an aggregated array back into a single readable string with a separator — the step that makes an `array_agg_distinct()` column legible in an exported report.',
    example: '| let tgt_process_cmdlines = array_to_string(list3,"\\r\\n")',
  },
  {
    category: 'Aggregation with group',
    syntax: 'by field = <expression>',
    description:
      'The `by` key can be a computed expression, including a constant. A static key (`by key = 1`) collapses everything into one group — the trick SentinelOne publishes for computing a percentage-of-total.',
    example: '| group total_sum = sum(value) by key = 1',
  },

  // -------------------------------------------------------------------------
  // Shaping & Computing Fields
  // -------------------------------------------------------------------------
  {
    category: 'Shaping & Computing Fields',
    syntax: '| columns a, b, c',
    description: 'Chooses which columns appear in the output table, in the order given.',
    example:
      '| columns event.time, endpoint.name, event.type, src.process.user, tgt.process.cmdline, tgt.file.path',
  },
  {
    category: 'Shaping & Computing Fields',
    syntax: '| columns name = <expression>',
    description: 'Defines a new column inline while selecting — including a ternary, which is how you bucket a numeric value into a label.',
    example: '| columns value, host, score = (value > 130000000) ? "high" : "low"',
  },
  {
    category: 'Shaping & Computing Fields',
    syntax: '| let name = <expression>',
    description: 'Defines one or more new fields on the table. Later stages — `columns`, `filter`, `sort` — can then refer to them by name.',
    example: '| let error_percent = errors * 100 / requests',
  },
  {
    category: 'Shaping & Computing Fields',
    syntax: '+  -  *  /  %',
    description: 'Arithmetic operators, plus negation. Available anywhere an expression is — in `let`, in `columns`, and inside a `filter`.',
    example: '| let delta_min = (end.timestamp - start.timestamp)/1000000000/60',
  },
  {
    category: 'Shaping & Computing Fields',
    syntax: '(cond) ? a : b',
    description:
      'Ternary conditional. Chain them for multi-way classification — SentinelOne\'s own example nests one inside the false branch of another.',
    example: '| columns env = (host matches "prod") ? "Prod" : (host matches "sb") ? "sb" : "qa"',
  },
  {
    category: 'Shaping & Computing Fields',
    syntax: 'format("%s %s", a, b)',
    description: 'printf-style string formatting — the way to build one composite field out of several columns before grouping on it.',
    example: '| let cmdline = format("%s %s", tgt.process.name, tgt.process.cmdline)',
  },
  {
    category: 'Shaping & Computing Fields',
    syntax: '| parse "regex" from field',
    description:
      'Extracts new columns inline using a regular expression with named captures, reading from the named field. The captured names become fields the next stage can group on.',
    example: '| parse "$drive$:(\\\\\\\\[^\\\\\\\\]+)+\\\\\\\\$file$\\\\.\\\\w+" from logfile',
  },

  // -------------------------------------------------------------------------
  // Combining Result Sets
  // -------------------------------------------------------------------------
  {
    category: 'Combining Result Sets',
    syntax: '| join a = (...), b = (...) on key',
    description:
      'Runs two or more named subqueries and merges them side by side on a shared key, keeping only records that match. Each subquery is a full query in its own right, pipes included.',
    example:
      "| join start = ((\"START Request\") | columns RequestId, timestamp), end = ((\"END Request\") | columns RequestId, timestamp) on RequestId",
  },
  {
    category: 'Combining Result Sets',
    syntax: 'alias.field',
    description: 'After a join, reference a column from a specific side by its subquery alias. This is how you compute an elapsed time between two event types.',
    example: '| let delta_min = (end.timestamp - start.timestamp)/1000000000/60',
  },
  {
    category: 'Combining Result Sets',
    syntax: '| union (...), (...)',
    description:
      'Runs two or more subqueries and stacks their results as ROWS rather than columns — the way to append a synthetic "all hosts" total row underneath a per-host breakdown.',
    example:
      '| union (| group value = sum(value) by host | sort -value), (| group value = sum(value) | columns value, host = "ALL HOSTS")',
  },
  {
    category: 'Combining Result Sets',
    syntax: 'join ... by key = "1"',
    description:
      'Joining on a statically-assigned constant key pairs every row against a single aggregate row — the documented SentinelOne pattern for percentage-of-total and rate calculations.',
    example:
      '| join (| group sum = sum(value) by host, key = "1"), (| group mint = min(timestamp), maxt = max(timestamp) by key = "1") on key',
  },
];
