// KQL (Kusto Query Language) Cheat Sheet — the operators, functions and schema
// a responder actually types at the keyboard in Microsoft Defender XDR advanced
// hunting and Microsoft Sentinel.
//
// SOURCE DISCIPLINE (same rule as eventIds.ts / kql.ts / networkPorts.ts): every
// operator name, function name, join flavor, data type and table/column name
// below was read off Microsoft's own live documentation before being written
// here — never from memory, never inferred from one page onto another. Verified
// against Microsoft Learn on 2026-07-28:
//   - KQL overview, tabular expression statements, and the KQL quick reference
//   - String operators (the full has/contains/startswith table, verbatim)
//   - summarize, join, union operator pages
//   - Aggregation function types + Scalar function types indexes
//   - Defender XDR "Learn the advanced hunting query language" + the advanced
//     hunting schema-tables index
// See externalResources.ts's 'kql-cheatsheet' entry for the citations, and
// KQL_CATEGORY_SOURCES below for the per-section source shown on the page.
//
// EXPLICITLY-SCOPED SUBSET — documented cuts, not silent gaps:
//   - Every EXAMPLE is written against a table/column pair this repo has
//     already verified in src/data/kql.ts (the KQL Builder's own schema data),
//     so no example can reference a column that doesn't exist.
//   - The function categories Kusto documents for geospatial, series/time-series
//     decomposition, machine-learning plugins, tdigest/hll sketches and units
//     conversion are omitted. They exist and are documented; they are simply not
//     what an incident responder reaches for.
//   - `evaluate <plugin>` and `invoke` are documented KQL operators but are
//     omitted here because a *runnable* example needs a specific plugin/function
//     whose own signature wasn't verified in this pass.
//
// Category order IS display order (the page groups by first occurrence).

export interface KqlSyntaxEntry {
  category: string;
  syntax: string;
  description: string;
  example: string;
}

/** The authoritative page each category was verified against, surfaced under
 *  that category's heading on the page (same credit-the-source convention as
 *  references.ts's CATEGORY_SOURCES). */
export const KQL_CATEGORY_SOURCES: Record<string, { name: string; url: string }> = {
  'Query Shape & Statements': {
    name: 'Microsoft Learn — Kusto Query Language overview',
    url: 'https://learn.microsoft.com/en-us/kusto/query/',
  },
  'Filtering & Searching': {
    name: 'Microsoft Learn — KQL quick reference',
    url: 'https://learn.microsoft.com/en-us/kusto/query/kql-quick-reference',
  },
  'String Matching Operators': {
    name: 'Microsoft Learn — String operators',
    url: 'https://learn.microsoft.com/en-us/kusto/query/datatypes-string-operators',
  },
  'Time Windows': {
    name: 'Microsoft Learn — Scalar function types (DateTime/timespan)',
    url: 'https://learn.microsoft.com/en-us/kusto/query/scalar-functions',
  },
  'Shaping & Ordering Results': {
    name: 'Microsoft Learn — KQL quick reference',
    url: 'https://learn.microsoft.com/en-us/kusto/query/kql-quick-reference',
  },
  Aggregation: {
    name: 'Microsoft Learn — summarize operator & Aggregation function types',
    url: 'https://learn.microsoft.com/en-us/kusto/query/aggregation-functions',
  },
  'Joins, Unions & Lookups': {
    name: 'Microsoft Learn — join operator',
    url: 'https://learn.microsoft.com/en-us/kusto/query/join-operator',
  },
  'Scalar & Parsing Functions': {
    name: 'Microsoft Learn — Scalar function types',
    url: 'https://learn.microsoft.com/en-us/kusto/query/scalar-functions',
  },
  'Tables & Schema': {
    name: 'Microsoft Learn — Advanced hunting schema tables',
    url: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables',
  },
};

export const KQL_CHEAT_SHEET: KqlSyntaxEntry[] = [
  // -------------------------------------------------------------------------
  // Query Shape & Statements
  // -------------------------------------------------------------------------
  {
    category: 'Query Shape & Statements',
    syntax: 'Table | operator | operator',
    description:
      'A query is a tabular data source followed by operators chained with the pipe character. Each operator takes a table in and emits a table out, so order matters for both results and performance.',
    example: 'DeviceProcessEvents | where Timestamp > ago(1d) | count',
  },
  {
    category: 'Query Shape & Statements',
    syntax: '//',
    description:
      'Line comment. Worth putting at the top of anything you intend to save or hand to someone else — Microsoft\'s own sample queries lead with one.',
    example: '// Suspicious PowerShell downloads in the last day — then the query itself on the next line.',
  },
  {
    category: 'Query Shape & Statements',
    syntax: 'let Name = ...;',
    description:
      'Binds a name to a scalar, a tabular expression, or a function definition, for reuse later in the same query. Statements are separated by a semicolon.',
    example: 'let window = 7d; DeviceLogonEvents | where Timestamp > ago(window) | summarize Logons = count() by AccountName',
  },
  {
    category: 'Query Shape & Statements',
    syntax: "['keyword']",
    description:
      'KQL is case-sensitive for everything — table names, column names, operators and functions. A keyword can still be used as an identifier by wrapping it in brackets and quotes.',
    example: "DeviceProcessEvents | project ['where'] = FileName",
  },
  {
    category: 'Query Shape & Statements',
    syntax: 'T | count',
    description: 'Counts the records in the input table. Shorthand for `summarize count()`.',
    example: 'DeviceNetworkEvents | where Timestamp > ago(1h) | count',
  },
  {
    category: 'Query Shape & Statements',
    syntax: 'T | take N',
    description:
      'Returns the specified number of records, with no ordering guarantee. Use it to sanity-check a query cheaply before you widen it. `take` and `limit` are synonyms.',
    example: 'DeviceRegistryEvents | take 10',
  },
  {
    category: 'Query Shape & Statements',
    syntax: 'print Expression',
    description: 'Outputs a single row of one or more scalar expressions — handy for testing a function before you wire it into a query.',
    example: 'print ago(1d)',
  },
  {
    category: 'Query Shape & Statements',
    syntax: 'range Name from A to B step S',
    description: 'Generates a single-column table holding an arithmetic series. Useful as a scaffold to fill gaps in a timeline.',
    example: 'range Slot from 1 to 24 step 1',
  },
  {
    category: 'Query Shape & Statements',
    syntax: 'T | render Visualization',
    description: 'Renders the result set as a chart instead of a table. Purely a presentation step; it does not change the rows.',
    example: 'DeviceNetworkEvents | summarize count() by bin(Timestamp, 1h) | render timechart',
  },

  // -------------------------------------------------------------------------
  // Filtering & Searching
  // -------------------------------------------------------------------------
  {
    category: 'Filtering & Searching',
    syntax: 'T | where Predicate',
    description: 'Filters to the rows satisfying a predicate. Put your time filter first and your most selective predicate next.',
    example: 'DeviceProcessEvents | where FileName == "powershell.exe"',
  },
  {
    category: 'Filtering & Searching',
    syntax: 'and / or',
    description: 'Logical conjunction and disjunction inside a single `where`. Chaining separate `where` clauses is equivalent to `and` and often reads better.',
    example: 'DeviceProcessEvents | where FileName == "cmd.exe" and InitiatingProcessFileName == "winword.exe"',
  },
  {
    category: 'Filtering & Searching',
    syntax: '==  !=  <  <=  >  >=',
    description: 'Comparison operators. On strings `==` and `!=` are case-sensitive; use `=~` / `!~` for the case-insensitive forms.',
    example: 'DeviceNetworkEvents | where RemotePort == 4444',
  },
  {
    category: 'Filtering & Searching',
    syntax: 'in (...) / !in (...)',
    description: 'Equals (or does not equal) any element of a list. Case-sensitive — the `in~` / `!in~` variants are the case-insensitive forms.',
    example: 'DeviceProcessEvents | where FileName in~ ("powershell.exe", "powershell_ise.exe")',
  },
  {
    category: 'Filtering & Searching',
    syntax: 'between (A .. B)',
    description: 'Matches a value inside an inclusive range — the readable way to express a fixed investigation window rather than a rolling one.',
    example:
      'DeviceProcessEvents | where Timestamp between (datetime(2026-02-01) .. datetime(2026-02-08))',
  },
  {
    category: 'Filtering & Searching',
    syntax: 'search "term"',
    description:
      'Searches every column of the table (or of several tables) for a value. Convenient for a first pass on an unfamiliar schema, and far slower than a targeted `where`.',
    example: 'search in (DeviceProcessEvents, DeviceNetworkEvents) "mimikatz"',
  },
  {
    category: 'Filtering & Searching',
    syntax: 'T | distinct Col, Col',
    description: 'Produces the distinct combinations of the named columns — the fastest way to answer "which hosts/accounts/binaries are even involved here?".',
    example: 'DeviceLogonEvents | where ActionType == "LogonFailed" | distinct DeviceName, AccountName',
  },
  {
    category: 'Filtering & Searching',
    syntax: 'isempty() / isnotempty()',
    description: 'True when a string argument is empty or null / neither empty nor null. Guard clauses for columns that are only populated on some event types.',
    example: 'DeviceProcessEvents | where isnotempty(ProcessCommandLine)',
  },
  {
    category: 'Filtering & Searching',
    syntax: 'isnull() / isnotnull()',
    description: 'True when the argument is null / is not null. Use these for non-string columns, where `isempty()` does not apply.',
    example: 'DeviceNetworkEvents | where isnotnull(RemoteIP)',
  },
  {
    category: 'Filtering & Searching',
    syntax: 'ipv4_is_private(IP)',
    description: 'True when an IPv4 string belongs to a private network range. The clean way to strip internal traffic out of an egress hunt.',
    example: 'DeviceNetworkEvents | where isnotempty(RemoteIP) and not(ipv4_is_private(RemoteIP))',
  },
  {
    category: 'Filtering & Searching',
    syntax: 'ipv4_is_in_range(IP, "CIDR")',
    description: 'True when an IPv4 string falls inside a prefix in CIDR notation. Use `ipv4_is_in_any_range()` to test against several prefixes at once.',
    example: 'DeviceNetworkEvents | where ipv4_is_in_range(RemoteIP, "10.10.0.0/16")',
  },
  {
    category: 'Filtering & Searching',
    syntax: 'has_ipv4(Text, "IP")',
    description: 'True when a free-text column contains the given IPv4 address. Index-accelerated, so it beats a regex over a command line or URL.',
    example: 'DeviceProcessEvents | where has_ipv4(ProcessCommandLine, "10.1.2.3")',
  },

  // -------------------------------------------------------------------------
  // String Matching Operators
  // -------------------------------------------------------------------------
  {
    category: 'String Matching Operators',
    syntax: '==',
    description: 'Case-sensitive equality. Prefer it over `=~` when you know the exact casing — the case-sensitive form is the faster one.',
    example: 'DeviceProcessEvents | where FileName == "rundll32.exe"',
  },
  {
    category: 'String Matching Operators',
    syntax: '=~',
    description: 'Case-insensitive equality. Use it when the telemetry casing is inconsistent, which on Windows paths and account names it usually is.',
    example: 'DeviceLogonEvents | where AccountName =~ "Administrator"',
  },
  {
    category: 'String Matching Operators',
    syntax: '!= / !~',
    description: 'Case-sensitive and case-insensitive inequality.',
    example: 'DeviceProcessEvents | where InitiatingProcessFileName !~ "explorer.exe"',
  },
  {
    category: 'String Matching Operators',
    syntax: 'has',
    description:
      'Matches a whole TERM — a maximal alphanumeric sequence of three characters or more — not an arbitrary substring. Term-indexed, so it is the fastest string operator here.',
    example: 'DeviceProcessEvents | where ProcessCommandLine has "DownloadString"',
  },
  {
    category: 'String Matching Operators',
    syntax: 'contains',
    description:
      'Matches an arbitrary substring, case-insensitively. It cannot use the term index, so it scans — reach for `has` first and fall back to `contains` only when the fragment you want is not a whole term.',
    example: 'DeviceProcessEvents | where ProcessCommandLine contains "-enc"',
  },
  {
    category: 'String Matching Operators',
    syntax: 'has_cs / contains_cs',
    description: 'The case-sensitive forms of `has` and `contains`. Faster than their case-insensitive counterparts when the casing is known.',
    example: 'DeviceProcessEvents | where ProcessCommandLine contains_cs "IEX"',
  },
  {
    category: 'String Matching Operators',
    syntax: '!has / !contains',
    description: 'Negated term match and negated substring match — the usual shape of an allow-list exclusion.',
    example: 'DeviceProcessEvents | where FileName == "svchost.exe" | where FolderPath !contains "\\\\Windows\\\\System32\\\\"',
  },
  {
    category: 'String Matching Operators',
    syntax: 'has_any (...)',
    description: 'True when ANY element of the list is a term in the value. One clause instead of a long chain of `or`s.',
    example:
      'DeviceProcessEvents | where ProcessCommandLine has_any("WebClient", "DownloadFile", "DownloadString", "WebRequest")',
  },
  {
    category: 'String Matching Operators',
    syntax: 'has_all (...)',
    description: 'True when EVERY element of the list is a term in the value — for command lines that must contain several markers together.',
    example: 'DeviceProcessEvents | where ProcessCommandLine has_all("powershell", "hidden", "bypass")',
  },
  {
    category: 'String Matching Operators',
    syntax: 'startswith / endswith',
    description: 'Case-insensitive prefix and suffix match on the whole value. `startswith_cs` / `endswith_cs` are the case-sensitive forms.',
    example: 'DeviceFileEvents | where FileName endswith ".ps1"',
  },
  {
    category: 'String Matching Operators',
    syntax: 'hasprefix / hassuffix',
    description:
      'Term-level prefix and suffix match — matches the start or end of any TERM in the value, not just the start or end of the whole string. `_cs` variants are case-sensitive.',
    example: 'DeviceProcessEvents | where FolderPath hasprefix "temp"',
  },
  {
    category: 'String Matching Operators',
    syntax: 'matches regex',
    description:
      'Case-sensitive regular-expression match against the right-hand side. The heaviest option on this list — use it only when nothing term- or substring-based will do.',
    example: 'DeviceProcessEvents | where FileName matches regex "^[a-z]{8}\\\\.exe$"',
  },
  {
    category: 'String Matching Operators',
    syntax: 'in~ (...) / !in~ (...)',
    description: 'Case-insensitive membership test against a list of literals.',
    example: 'DeviceProcessEvents | where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "outlook.exe")',
  },

  // -------------------------------------------------------------------------
  // Time Windows
  // -------------------------------------------------------------------------
  {
    category: 'Time Windows',
    syntax: 'ago(timespan)',
    description:
      'Subtracts a timespan from the current UTC clock. The first filter in almost every hunting query, because scoping the time range is what keeps a query fast and finite.',
    example: 'DeviceProcessEvents | where Timestamp > ago(7d)',
  },
  {
    category: 'Time Windows',
    syntax: 'Timestamp vs TimeGenerated',
    description:
      'Defender XDR advanced hunting tables carry the event time in `Timestamp`; Azure Monitor / Sentinel workspace tables carry it in `TimeGenerated`. Getting this wrong is the most common reason a cross-product query silently returns nothing.',
    example: 'SecurityEvent | where TimeGenerated > ago(1d) | where EventID == 4625',
  },
  {
    category: 'Time Windows',
    syntax: 'd h m s ms',
    description:
      'Timespan literals: a bare number followed by a unit. Combine them with `ago()`, `bin()` and arithmetic on datetime columns.',
    example: 'DeviceNetworkEvents | where Timestamp > ago(90m)',
  },
  {
    category: 'Time Windows',
    syntax: 'now()',
    description: 'The current UTC clock time, optionally offset by a timespan. Kusto time filters are always UTC regardless of your portal timezone setting.',
    example: 'DeviceProcessEvents | extend Age = now() - Timestamp',
  },
  {
    category: 'Time Windows',
    syntax: 'datetime(YYYY-MM-DD)',
    description: 'A datetime literal. Use it for a fixed incident window that must not move as the query is re-run.',
    example:
      'DeviceLogonEvents | where Timestamp between (datetime(2026-02-01 03:00) .. datetime(2026-02-01 06:00))',
  },
  {
    category: 'Time Windows',
    syntax: 'bin(Timestamp, 1h)',
    description:
      'Rounds a value down to a multiple of the bin size. This is how you bucket a timeline — automatic hourly binning of datetime columns is no longer implicit, so bin explicitly.',
    example: 'DeviceNetworkEvents | summarize Connections = count() by bin(Timestamp, 1h)',
  },
  {
    category: 'Time Windows',
    syntax: 'startofday() / endofday()',
    description:
      'Snaps a datetime to the start or end of the containing day, optionally shifted by an offset. `startofweek`, `startofmonth` and `startofyear` follow the same shape.',
    example: 'DeviceLogonEvents | where Timestamp >= startofday(ago(1d)) and Timestamp < startofday(now())',
  },
  {
    category: 'Time Windows',
    syntax: 'datetime_diff(part, A, B)',
    description: 'Returns the difference between two datetimes as an integer count of the named date part.',
    example: 'DeviceProcessEvents | extend MinutesAgo = datetime_diff("minute", now(), Timestamp)',
  },
  {
    category: 'Time Windows',
    syntax: 'format_datetime(dt, fmt)',
    description: 'Formats a datetime against a format pattern — useful when a report has to line up with an external timeline.',
    example: 'DeviceProcessEvents | extend When = format_datetime(Timestamp, "yyyy-MM-dd HH:mm:ss")',
  },
  {
    category: 'Time Windows',
    syntax: 'todatetime(value)',
    description: 'Converts a string or number to a datetime scalar. Needed whenever a timestamp arrived as text in a custom or parsed column.',
    example: 'DeviceEvents | extend Parsed = todatetime("2026-02-01T03:14:15Z")',
  },
  {
    category: 'Time Windows',
    syntax: 'unixtime_seconds_todatetime(n)',
    description:
      'Converts Unix epoch seconds to a UTC datetime. Millisecond, microsecond and nanosecond variants exist under the same naming pattern.',
    example: 'print unixtime_seconds_todatetime(1769904855)',
  },
  {
    category: 'Time Windows',
    syntax: 'hourofday() / dayofweek()',
    description:
      'Extract the hour of the day, or the days elapsed since the preceding Sunday as a timespan. The building blocks of an "activity outside business hours" hunt.',
    example: 'DeviceLogonEvents | summarize Logons = count() by Hour = hourofday(Timestamp) | sort by Hour asc',
  },

  // -------------------------------------------------------------------------
  // Shaping & Ordering Results
  // -------------------------------------------------------------------------
  {
    category: 'Shaping & Ordering Results',
    syntax: 'T | project Col, Col',
    description:
      'Selects the columns to include, in the order given, and can rename or compute them inline. Project early — carrying 60 columns through a pipeline you only need six of costs you.',
    example:
      'DeviceProcessEvents | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine',
  },
  {
    category: 'Shaping & Ordering Results',
    syntax: 'T | project-away Pattern',
    description: 'Drops the named columns (wildcards allowed) and keeps everything else — the inverse of `project` when you only want to lose a few.',
    example: 'DeviceProcessEvents | project-away ReportId, DeviceId',
  },
  {
    category: 'Shaping & Ordering Results',
    syntax: 'T | project-keep Pattern',
    description: 'Keeps the named columns (wildcards allowed) without having to spell out an explicit order.',
    example: 'DeviceProcessEvents | project-keep Timestamp, DeviceName, InitiatingProcess*',
  },
  {
    category: 'Shaping & Ordering Results',
    syntax: 'T | project-rename New = Old',
    description: 'Renames a column in the output while leaving the rest of the schema alone.',
    example: 'DeviceNetworkEvents | project-rename DestinationIP = RemoteIP',
  },
  {
    category: 'Shaping & Ordering Results',
    syntax: 'T | project-reorder Col, Col',
    description: 'Reorders columns in the output without dropping any — the readable way to put the columns you care about on the left.',
    example: 'DeviceProcessEvents | project-reorder Timestamp, DeviceName',
  },
  {
    category: 'Shaping & Ordering Results',
    syntax: 'T | extend New = Expr',
    description: 'Adds a calculated column to the result set, keeping every existing column.',
    example:
      'DeviceProcessEvents | extend CmdLength = strlen(ProcessCommandLine) | where CmdLength > 500',
  },
  {
    category: 'Shaping & Ordering Results',
    syntax: 'T | sort by Col desc',
    description: 'Sorts the rows of the input table by one or more columns, ascending or descending.',
    example: 'DeviceLogonEvents | summarize Failures = count() by AccountName | sort by Failures desc',
  },
  {
    category: 'Shaping & Ordering Results',
    syntax: 'T | top N by Expr',
    description:
      'Returns the first N rows after sorting by the expression. One operator instead of `sort` followed by `take`, and cheaper.',
    example: 'DeviceProcessEvents | where Timestamp > ago(1d) | top 100 by Timestamp',
  },
  {
    category: 'Shaping & Ordering Results',
    syntax: 'T | limit N',
    description: 'Caps the number of rows returned. A synonym for `take`, and no ordering is implied by either.',
    example: 'DeviceFileEvents | where FileName endswith ".zip" | limit 50',
  },

  // -------------------------------------------------------------------------
  // Aggregation
  // -------------------------------------------------------------------------
  {
    category: 'Aggregation',
    syntax: 'T | summarize Agg by Group',
    description:
      'Groups rows by the `by` expressions and computes aggregations over each group. Without a `by` clause you get a single summary row.',
    example: 'DeviceProcessEvents | summarize Executions = count() by DeviceName, FileName',
  },
  {
    category: 'Aggregation',
    syntax: 'count()',
    description: 'Counts rows in the group. Note that it counts nulls too, unlike most other aggregates.',
    example: 'DeviceLogonEvents | summarize Logons = count() by LogonType',
  },
  {
    category: 'Aggregation',
    syntax: 'countif(Predicate)',
    description:
      'Counts only the rows in the group satisfying a predicate — the way to put two competing counts side by side in one pass.',
    example:
      'DeviceLogonEvents | summarize Failed = countif(ActionType == "LogonFailed"), Success = countif(ActionType == "LogonSuccess") by AccountName',
  },
  {
    category: 'Aggregation',
    syntax: 'dcount(Col)',
    description:
      'An approximate distinct count of the group. `dcountif()` takes a predicate; `count_distinct()` is the exact (and more expensive) version.',
    example: 'DeviceNetworkEvents | summarize Destinations = dcount(RemoteIP) by DeviceName',
  },
  {
    category: 'Aggregation',
    syntax: 'sum() / avg() / min() / max()',
    description:
      'The standard statistical aggregates. Each has an `if` variant (`sumif`, `avgif`, `minif`, `maxif`) that takes a predicate. Nulls are ignored.',
    example: 'DeviceFileEvents | summarize Bytes = sum(FileSize) by DeviceName',
  },
  {
    category: 'Aggregation',
    syntax: 'make_set(Col)',
    description:
      'Returns a dynamic array of the DISTINCT values in the group. The fastest way to collapse "everything this host talked to" into one readable cell.',
    example: 'DeviceNetworkEvents | summarize Ports = make_set(RemotePort) by DeviceName',
  },
  {
    category: 'Aggregation',
    syntax: 'make_list(Col)',
    description: 'Returns a dynamic array of ALL values in the group, duplicates included — use it when frequency or order matters.',
    example: 'DeviceProcessEvents | summarize Chain = make_list(FileName) by DeviceName',
  },
  {
    category: 'Aggregation',
    syntax: 'arg_max(Expr, *)',
    description:
      'Returns the whole row (with `*`) where the expression is maximised. This is how you get the LATEST event per host rather than just its timestamp. `arg_min()` is the mirror image.',
    example: 'DeviceLogonEvents | summarize arg_max(Timestamp, *) by DeviceName',
  },
  {
    category: 'Aggregation',
    syntax: 'min() / max() on Timestamp',
    description: 'First-seen and last-seen bounds for a group — the two numbers that turn a pile of events into an activity window.',
    example:
      'DeviceProcessEvents | summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by SHA1',
  },
  {
    category: 'Aggregation',
    syntax: 'percentile(Col, N)',
    description: 'A percentile estimate over the group. `percentiles()` returns several at once.',
    example: 'DeviceProcessEvents | summarize p95 = percentile(FileSize, 95) by FileName',
  },
  {
    category: 'Aggregation',
    syntax: 'take_any(Col)',
    description: 'Returns an arbitrary non-empty value from the group — cheap when you just need one representative sample, not a full set.',
    example: 'DeviceProcessEvents | summarize Sample = take_any(ProcessCommandLine) by FileName',
  },
  {
    category: 'Aggregation',
    syntax: 'summarize ... by bin(Timestamp, 1h)',
    description: 'Groups by a rounded time bucket, producing the row-per-interval shape a timeline or a `render timechart` expects.',
    example:
      'DeviceLogonEvents | where ActionType == "LogonFailed" | summarize Failures = count() by bin(Timestamp, 1h), AccountName',
  },
  {
    category: 'Aggregation',
    syntax: 'T | make-series Agg on Axis',
    description:
      'Builds evenly-spaced series along an axis, filling gaps with a default value — the input shape the time-series and anomaly functions expect.',
    example:
      'DeviceNetworkEvents | make-series Connections = count() default = 0 on Timestamp from ago(1d) to now() step 1h by DeviceName',
  },

  // -------------------------------------------------------------------------
  // Joins, Unions & Lookups
  // -------------------------------------------------------------------------
  {
    category: 'Joins, Unions & Lookups',
    syntax: 'T1 | join kind=inner (T2) on Col',
    description:
      'Merges two tables on matching column values. If the column has the same name on both sides, `on ColumnName` is enough.',
    example:
      'AlertInfo | join kind=inner (AlertEvidence) on AlertId | project Timestamp, Title, Severity, EntityType',
  },
  {
    category: 'Joins, Unions & Lookups',
    syntax: 'on $left.A == $right.B',
    description: 'Join condition when the key columns have different names on each side. Comma-separate several conditions to AND them.',
    example:
      'DeviceProcessEvents | join kind=inner (DeviceNetworkEvents) on $left.DeviceId == $right.DeviceId',
  },
  {
    category: 'Joins, Unions & Lookups',
    syntax: 'kind=innerunique',
    description:
      'The DEFAULT join flavor, and the one that surprises people: it de-duplicates the left side on the join key before matching. Say `kind=inner` explicitly when you want a standard inner join.',
    example: 'DeviceInfo | join kind=innerunique (DeviceNetworkEvents) on DeviceId',
  },
  {
    category: 'Joins, Unions & Lookups',
    syntax: 'kind=leftouter / rightouter / fullouter',
    description: 'Outer joins. Cells with no match on the other side come back null.',
    example: 'DeviceInfo | join kind=leftouter (DeviceLogonEvents) on DeviceId',
  },
  {
    category: 'Joins, Unions & Lookups',
    syntax: 'kind=leftanti',
    description:
      'Returns the left rows that DON\'T match anything on the right, with the left schema only. The workhorse for "which hosts are missing X?" and for baseline subtraction. `anti` and `leftantisemi` are accepted spellings; `rightanti` is the mirror.',
    example: 'DeviceInfo | join kind=leftanti (DeviceProcessEvents | where Timestamp > ago(1d)) on DeviceId',
  },
  {
    category: 'Joins, Unions & Lookups',
    syntax: 'kind=leftsemi / rightsemi',
    description: 'Returns rows from one side that DO have a match on the other, keeping only that side\'s columns — a filter rather than a widening.',
    example: 'DeviceInfo | join kind=leftsemi (AlertEvidence) on DeviceId',
  },
  {
    category: 'Joins, Unions & Lookups',
    syntax: 'union T1, T2',
    description:
      'Returns the rows of two or more tables. `kind=inner` keeps only columns common to all inputs; `kind=outer` (the default) keeps every column.',
    example: 'union DeviceProcessEvents, DeviceNetworkEvents | where Timestamp > ago(7d)',
  },
  {
    category: 'Joins, Unions & Lookups',
    syntax: 'union withsource=Col ...',
    description: 'Adds a column naming the source table each row came from — essential once a union spans more than two tables.',
    example:
      'union withsource=SourceTable kind=outer DeviceFileEvents, DeviceRegistryEvents | where Timestamp > ago(1d) | summarize count() by SourceTable',
  },
  {
    category: 'Joins, Unions & Lookups',
    syntax: 'T1 | lookup (T2) on Col',
    description:
      'Enriches a fact table with columns from a dimension table. Semantically a `leftouter`/`inner` join, but optimised for the small-lookup-table case.',
    example: 'DeviceProcessEvents | lookup kind=leftouter (DeviceInfo) on DeviceId',
  },
  {
    category: 'Joins, Unions & Lookups',
    syntax: 'Put the SMALL table on the left',
    description:
      'Microsoft\'s own performance guidance for `join`: when one side is consistently smaller, make it the left (outer) table. Filter each leg before joining rather than after.',
    example:
      'AlertEvidence | where Timestamp > ago(1d) | join kind=inner (DeviceProcessEvents | where Timestamp > ago(1d)) on DeviceId',
  },

  // -------------------------------------------------------------------------
  // Scalar & Parsing Functions
  // -------------------------------------------------------------------------
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'iff(pred, a, b)',
    description: 'Two-branch conditional — returns the second argument when the predicate is true, otherwise the third.',
    example:
      'DeviceLogonEvents | extend Outcome = iff(ActionType == "LogonSuccess", "success", "failure")',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'case(p1, v1, p2, v2, else)',
    description: 'Multi-branch conditional — returns the value for the first satisfied predicate, else the final fallback.',
    example:
      'DeviceProcessEvents | extend Risk = case(ProcessCommandLine has "-enc", "high", ProcessCommandLine has "bypass", "medium", "low")',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'coalesce(a, b, ...)',
    description: 'Returns the first non-null (or, for strings, non-empty) argument — useful for collapsing two columns that carry the same idea in different tables.',
    example: 'DeviceLogonEvents | extend Actor = coalesce(AccountName, InitiatingProcessAccountName)',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'strcat(a, b, ...)',
    description: 'Concatenates between 1 and 64 arguments. `strcat_delim()` takes a delimiter as its first argument.',
    example: 'DeviceLogonEvents | extend Principal = strcat(AccountDomain, "\\\\", AccountName)',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'split(text, delimiter)',
    description: 'Splits a string on a delimiter into a dynamic array of substrings.',
    example: 'DeviceProcessEvents | extend PathParts = split(FolderPath, "\\\\")',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'substring(text, start, len)',
    description: 'Extracts a substring from a zero-based start index. Omit the length to run to the end of the string.',
    example: 'DeviceProcessEvents | extend ShortHash = substring(SHA1, 0, 12)',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'tolower() / toupper()',
    description: 'Case normalisation. Worth applying before a join or a `summarize by` so that two spellings of the same account do not split into two groups.',
    example: 'DeviceLogonEvents | summarize count() by Account = tolower(AccountName)',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'strlen(text)',
    description: 'Length of a string in characters. A long command line is a cheap, high-signal heuristic for encoded payloads.',
    example: 'DeviceProcessEvents | where strlen(ProcessCommandLine) > 1000',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'indexof(text, lookup)',
    description: 'Zero-based index of the first occurrence of a substring, or -1 when it is absent.',
    example: 'DeviceProcessEvents | extend EncPos = indexof(ProcessCommandLine, "-enc")',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'countof(text, search)',
    description: 'Counts occurrences of a substring (plain matches may overlap) or of a regex (regex matches do not).',
    example: 'DeviceProcessEvents | extend Pipes = countof(ProcessCommandLine, "|")',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'extract(regex, n, text)',
    description:
      'Returns capture group n of the first regex match against the text — the compact alternative to a full `parse` when you want one field.',
    example:
      'DeviceNetworkEvents | extend Host = extract("https?://([^/]+)", 1, RemoteUrl)',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'extract_all(regex, text)',
    description: 'Returns every regex match as a dynamic array, rather than only the first.',
    example:
      'DeviceProcessEvents | extend Ips = extract_all("\\\\d{1,3}(\\\\.\\\\d{1,3}){3}", ProcessCommandLine)',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'replace_string(text, old, new)',
    description: 'Replaces every plain-string match. `replace_regex()` does the same for a pattern; `replace_strings()` takes several pairs at once.',
    example: 'DeviceFileEvents | extend Relative = replace_string(FolderPath, "C:\\\\Users\\\\", "")',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'trim(regex, text)',
    description: 'Removes leading and trailing matches of a regex. `trim_start()` and `trim_end()` do one side only.',
    example: 'DeviceProcessEvents | extend Cleaned = trim("\\\\s+", ProcessCommandLine)',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'parse_command_line(text, parser)',
    description:
      'Parses a command-line string into an array of arguments the way the OS would. Far more reliable than splitting on spaces once quoting is involved.',
    example:
      'DeviceProcessEvents | extend Args = parse_command_line(ProcessCommandLine, "windows")',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'parse_url(text)',
    description: 'Parses an absolute URL into a dynamic object with its scheme, host, path, query parameters and port broken out.',
    example: 'DeviceNetworkEvents | where isnotempty(RemoteUrl) | extend Parts = parse_url(RemoteUrl)',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'url_decode(text)',
    description: 'Converts a percent-encoded URL back to its plain representation. `url_encode()` is the inverse.',
    example: 'DeviceNetworkEvents | extend Decoded = url_decode(RemoteUrl)',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'base64_decode_tostring(text)',
    description:
      'Decodes a base64 string to UTF-8. Note that PowerShell\'s own `-EncodedCommand` is UTF-16LE, so expect interleaved null bytes you still have to strip.',
    example: 'print base64_decode_tostring("SGVsbG8gRElGUg==")',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'parse_json(text) / todynamic()',
    description: 'Interprets a string as JSON and returns it as a `dynamic` value you can index into with dot notation.',
    example: 'DeviceEvents | extend Fields = parse_json(AdditionalFields)',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'tostring() / toint() / tolong()',
    description:
      'Type conversions. Filtering a `dynamic` property usually needs an explicit `tostring()` around it before a string operator will behave.',
    example: 'DeviceEvents | extend Name = tostring(parse_json(AdditionalFields).FileName)',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'array_length(arr)',
    description: 'Number of elements in a dynamic array. `set_has_element()` tests membership; `array_index_of()` returns a position.',
    example:
      'DeviceNetworkEvents | summarize Ports = make_set(RemotePort) by DeviceName | where array_length(Ports) > 20',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'T | mv-expand Col',
    description:
      'Expands a dynamic array into one row per element — the standard way to flatten a `make_set()` result, or an array you just parsed, back into rows.',
    example:
      'DeviceNetworkEvents | summarize Ports = make_set(RemotePort) by DeviceName | mv-expand Ports',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'T | parse Expr with ...',
    description:
      'Parses a string column into new columns against a pattern, in simple, regex or relaxed mode. Use it to structure a free-text field you will be filtering on repeatedly.',
    example:
      'DeviceProcessEvents | parse ProcessCommandLine with * "-Command " Command:string',
  },
  {
    category: 'Scalar & Parsing Functions',
    syntax: 'hash_sha256() / hash_md5()',
    description: 'Hash functions over a scalar value. Useful for building a stable key from several columns, not for re-deriving a file hash from telemetry.',
    example: 'DeviceProcessEvents | extend Key = hash_sha256(strcat(DeviceName, FileName))',
  },

  // -------------------------------------------------------------------------
  // Tables & Schema
  // -------------------------------------------------------------------------
  {
    category: 'Tables & Schema',
    syntax: 'DeviceProcessEvents',
    description:
      'Process creation and related events (Defender XDR). The starting point for parent/child chains and command-line hunting. Note that SHA256 is often unpopulated here — prefer SHA1.',
    example:
      'DeviceProcessEvents | where Timestamp > ago(1d) | where InitiatingProcessFileName =~ "winword.exe" | project Timestamp, DeviceName, FileName, ProcessCommandLine',
  },
  {
    category: 'Tables & Schema',
    syntax: 'DeviceNetworkEvents',
    description: 'Network connection and related events — RemoteIP, RemotePort, RemoteUrl, LocalIP/LocalPort and the initiating process.',
    example:
      'DeviceNetworkEvents | where Timestamp > ago(1d) | where RemotePort in (4444, 8080) | project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName',
  },
  {
    category: 'Tables & Schema',
    syntax: 'DeviceFileEvents',
    description:
      'File creation, modification and other file-system events. Carries FileOriginUrl and FileOriginIP, which is how you attribute a dropped file to its download.',
    example:
      'DeviceFileEvents | where Timestamp > ago(1d) | where FolderPath contains "\\\\Users\\\\Public\\\\" | project Timestamp, DeviceName, FileName, FolderPath, SHA1',
  },
  {
    category: 'Tables & Schema',
    syntax: 'DeviceRegistryEvents',
    description: 'Creation and modification of registry entries — RegistryKey, RegistryValueName, RegistryValueData plus the previous values.',
    example:
      'DeviceRegistryEvents | where Timestamp > ago(7d) | where RegistryKey has "CurrentVersion\\\\Run" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData',
  },
  {
    category: 'Tables & Schema',
    syntax: 'DeviceLogonEvents',
    description:
      'Sign-ins and other authentication events on devices — LogonType, AccountName, RemoteIP, FailureReason and IsLocalAdmin.',
    example:
      'DeviceLogonEvents | where Timestamp > ago(1d) | where ActionType == "LogonFailed" | summarize Attempts = count() by AccountName, RemoteIP | sort by Attempts desc',
  },
  {
    category: 'Tables & Schema',
    syntax: 'DeviceImageLoadEvents',
    description: 'DLL loading events. The table to reach for when you are chasing side-loading or an unsigned module inside a signed host process.',
    example: 'DeviceImageLoadEvents | where Timestamp > ago(1d) | take 10',
  },
  {
    category: 'Tables & Schema',
    syntax: 'DeviceEvents',
    description:
      'A catch-all for many event types, including those raised by security controls such as Defender Antivirus and exploit protection. Filter it by ActionType.',
    example: 'DeviceEvents | where Timestamp > ago(1d) | summarize Events = count() by ActionType | sort by Events desc',
  },
  {
    category: 'Tables & Schema',
    syntax: 'DeviceInfo / DeviceNetworkInfo',
    description:
      'Machine information including OS details, and the network properties of devices — adapters, IP and MAC addresses, connected networks and domains. These are the dimension tables you join a hunt against.',
    example: 'DeviceInfo | summarize arg_max(Timestamp, *) by DeviceId',
  },
  {
    category: 'Tables & Schema',
    syntax: 'AlertInfo / AlertEvidence',
    description:
      'Alerts across Defender for Endpoint, Office 365, Cloud Apps and Identity, with severity and threat categorisation — and the files, IPs, URLs, users and devices attached to each alert.',
    example:
      'AlertInfo | where Timestamp > ago(7d) | join kind=inner (AlertEvidence) on AlertId | project Timestamp, Title, Severity, EntityType',
  },
  {
    category: 'Tables & Schema',
    syntax: 'IdentityLogonEvents',
    description:
      'Authentication events on Active Directory and Microsoft online services. `IdentityDirectoryEvents` covers on-premises domain-controller events, `IdentityQueryEvents` covers AD object queries.',
    example: 'IdentityLogonEvents | where Timestamp > ago(1d) | take 10',
  },
  {
    category: 'Tables & Schema',
    syntax: 'EmailEvents / EmailAttachmentInfo / EmailUrlInfo',
    description:
      'Microsoft 365 email delivery and blocking events, plus the attachments and the URLs found in those messages. `UrlClickEvents` records Safe Links clicks.',
    example: 'EmailEvents | where Timestamp > ago(1d) | take 10',
  },
  {
    category: 'Tables & Schema',
    syntax: 'CloudAppEvents',
    description: 'Events involving accounts and objects in Office 365 and other connected cloud apps and services.',
    example: 'CloudAppEvents | where Timestamp > ago(1d) | take 10',
  },
  {
    category: 'Tables & Schema',
    syntax: 'EntraIdSignInEvents',
    description:
      'Microsoft Entra interactive and non-interactive sign-ins. `EntraIdSpnSignInEvents` covers service-principal and managed-identity sign-ins.',
    example: 'EntraIdSignInEvents | where Timestamp > ago(1d) | take 10',
  },
  {
    category: 'Tables & Schema',
    syntax: 'SecurityEvent (Sentinel)',
    description:
      'The Windows Security log forwarded into a Log Analytics workspace — EventID, Account, LogonType, NewProcessName, CommandLine. A workspace table, so it uses TimeGenerated, not Timestamp.',
    example:
      'SecurityEvent | where TimeGenerated > ago(1d) | where EventID == 4625 | summarize Failures = count() by TargetUserName, IpAddress | sort by Failures desc',
  },
  {
    category: 'Tables & Schema',
    syntax: 'SigninLogs (Sentinel)',
    description:
      'Microsoft Entra ID sign-in logs in a Log Analytics workspace — UserPrincipalName, IPAddress, ResultType, ConditionalAccessStatus, RiskLevelDuringSignIn.',
    example:
      'SigninLogs | where TimeGenerated > ago(1d) | where ResultType != 0 | summarize Failures = count() by UserPrincipalName, IPAddress',
  },
];
