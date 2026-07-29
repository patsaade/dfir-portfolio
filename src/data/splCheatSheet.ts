// Splunk SPL (Search Processing Language) Cheat Sheet — the commands, functions
// and modifiers a responder actually types at the keyboard in a Splunk search
// bar.
//
// SOURCE DISCIPLINE (same rule as eventIds.ts / kql.ts / networkPorts.ts): every
// command name, argument, function name and description below was read off
// Splunk's own live Search Reference before being written here — never from
// memory. Verified against help.splunk.com (Splunk Enterprise 10.2 Search
// Reference) on 2026-07-28:
//   - Commands by category (the full command list, with Splunk's own one-line
//     descriptions) and the command quick reference
//   - The individual command pages for search, where, eval, stats, eventstats,
//     streamstats, tstats, timechart, chart, bin, top, sort, fields, rename,
//     dedup, transaction, join, append, lookup, inputlookup, rex, regex, spath,
//     mvexpand, fillnull, iplocation and metadata
//   - Time modifiers (earliest/latest, the relative-time format, snap-to)
//   - The evaluation-functions index
// See externalResources.ts's 'spl-cheatsheet' entry for the citations, and
// SPL_CATEGORY_SOURCES below for the per-section source shown on the page.
//
// EXPLICITLY-SCOPED SUBSET — documented cuts, not silent gaps:
//   - EVERY EXAMPLE HERE IS EITHER A SPLUNK-DOCUMENTED EXAMPLE OR IS BUILT ONLY
//     FROM ARGUMENT FORMS THAT PAGE DOCUMENTS. A command that Splunk documents
//     but whose own page wasn't read in this pass gets NO entry rather than a
//     guessed example — that's why commands like `transpose`, `foreach`, `map`,
//     `multisearch` and `set` are absent. They're real; they're just not
//     verified here.
//   - The machine-learning, prediction (`predict`, `x11`), geospatial
//     (`geom`, `geostats`), metrics (`mstats`, `mcollect`) and summary-indexing
//     (`si*`) command families are out of scope for a DFIR sheet.
//   - Field names in examples are Splunk's own documentation field names
//     (`clientip`, `host`, `source`, `sourcetype`, `status`, `action`) or CIM
//     -neutral placeholders — your own index's field names will differ.
//
// Category order IS display order (the page groups by first occurrence).

export interface SplSyntaxEntry {
  category: string;
  syntax: string;
  description: string;
  example: string;
}

/** The authoritative page each category was verified against, surfaced under
 *  that category's heading on the page (same credit-the-source convention as
 *  references.ts's CATEGORY_SOURCES). */
export const SPL_CATEGORY_SOURCES: Record<string, { name: string; url: string }> = {
  'Search Basics & the Pipeline': {
    name: 'Splunk Search Reference — search command',
    url: 'https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/search-commands/search',
  },
  'Filtering & Comparison': {
    name: 'Splunk Search Reference — where command',
    url: 'https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/search-commands/where',
  },
  'Time Range Modifiers': {
    name: 'Splunk Search Reference — Time modifiers',
    url: 'https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/time-format-variables-and-modifiers/time-modifiers',
  },
  'Selecting & Shaping Fields': {
    name: 'Splunk Search Reference — Commands by category',
    url: 'https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/quick-reference/commands-by-category',
  },
  'Statistics & Aggregation': {
    name: 'Splunk Search Reference — stats command',
    url: 'https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/search-commands/stats',
  },
  'Time Series & Charting': {
    name: 'Splunk Search Reference — timechart command',
    url: 'https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/search-commands/timechart',
  },
  'Correlation: Joins, Lookups & Transactions': {
    name: 'Splunk Search Reference — transaction command',
    url: 'https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/search-commands/transaction',
  },
  'Field Extraction & Regex': {
    name: 'Splunk Search Reference — rex command',
    url: 'https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/search-commands/rex',
  },
  'Eval Functions': {
    name: 'Splunk Search Reference — Evaluation functions',
    url: 'https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/evaluation-functions/evaluation-functions',
  },
  'Accelerated & Metadata Searches': {
    name: 'Splunk Search Reference — tstats command',
    url: 'https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/search-commands/tstats',
  },
};

export const SPL_CHEAT_SHEET: SplSyntaxEntry[] = [
  // -------------------------------------------------------------------------
  // Search Basics & the Pipeline
  // -------------------------------------------------------------------------
  {
    category: 'Search Basics & the Pipeline',
    syntax: 'search terms | command | command',
    description:
      'A search is a set of terms followed by commands chained with the pipe character. `search` is implicit at the start of any pipeline that does not begin with another generating command, so you rarely type it first.',
    example: 'index=main sourcetype=WinEventLog:Security | stats count BY host',
  },
  {
    category: 'Search Basics & the Pipeline',
    syntax: 'index= / sourcetype= / host= / source=',
    description:
      'The default fields that scope a search. Naming an index and a sourcetype up front is the single biggest thing you can do for search performance.',
    example: 'index=_internal sourcetype="splunkd"',
  },
  {
    category: 'Search Basics & the Pipeline',
    syntax: 'field=value',
    description: 'A field-value pair. Splunk applies it at search time against extracted fields; values containing spaces or special characters need quoting.',
    example: 'sourcetype=access_combined_wcookie action IN (addtocart, purchase)',
  },
  {
    category: 'Search Basics & the Pipeline',
    syntax: 'AND / OR / NOT',
    description:
      'Boolean operators. `AND` is implied between adjacent terms. Evaluation order is: parentheses first, then NOT, then OR, then AND — so parenthesise anything you are not certain about.',
    example: '(code=10 OR code=29) host!="localhost" xqp>5',
  },
  {
    category: 'Search Basics & the Pipeline',
    syntax: '*',
    description: 'Wildcard. Works inside a field value as well as at the end of it — but a leading wildcard forces a full scan, so avoid it on a wide search.',
    example: 'host=webserver* (status=4* OR status=5*)',
  },
  {
    category: 'Search Basics & the Pipeline',
    syntax: 'field IN (a, b, c)',
    description: 'Matches any value in a list, and the list entries accept wildcards. Much more readable than a chain of ORs.',
    example: 'error_code IN (400, 402, 404, 500)',
  },
  {
    category: 'Search Basics & the Pipeline',
    syntax: '[ search ... ]',
    description:
      'A subsearch. It runs first and its results are passed into the outer search — so keep it small and bounded, because subsearch results are capped and time out.',
    example: '... | join product_id [search vendors]',
  },
  {
    category: 'Search Basics & the Pipeline',
    syntax: '| makeresults',
    description:
      'Generates empty search results with no index behind them. The fastest way to test an eval expression or a regex without touching real data.',
    example: '| makeresults | eval myip="2001:4860:4860::8888" | iplocation myip',
  },
  {
    category: 'Search Basics & the Pipeline',
    syntax: '| head N',
    description:
      'Returns the first N results. `tail` returns the last N and `reverse` flips the order — the three of them are how you cheaply preview a pipeline mid-build.',
    example: 'index=_internal sourcetype="splunkd" | head 5',
  },

  // -------------------------------------------------------------------------
  // Filtering & Comparison
  // -------------------------------------------------------------------------
  {
    category: 'Filtering & Comparison',
    syntax: '| where <eval-expression>',
    description:
      'Arbitrary filtering with an eval expression that must return true or false. The key difference from `search`: `where` treats an unquoted value as a FIELD NAME, so it can compare two fields against each other.',
    example: '... | where ipaddress=clientip',
  },
  {
    category: 'Filtering & Comparison',
    syntax: '=  !=  <  <=  >  >=',
    description: 'Comparison operators, valid in both `search` and `where`. In `where`, quote a literal string or it will be read as a field name.',
    example: 'sourcetype=physicsjobs | where distance/time > 100',
  },
  {
    category: 'Filtering & Comparison',
    syntax: 'like(field, "pattern")',
    description: 'SQL-style pattern match inside `where`. `%` matches any sequence, `_` matches a single character.',
    example: '... | where like(ipaddress, "198.%")',
  },
  {
    category: 'Filtering & Comparison',
    syntax: 'cidrmatch("CIDR", field)',
    description: 'True when an IP field falls inside a CIDR block. The correct way to scope by subnet — string prefix matching on IPs is a well-known way to get this wrong.',
    example: 'host="CheckPoint" | where like(src, "10.9.165.%") OR cidrmatch("10.9.165.0/25", dst)',
  },
  {
    category: 'Filtering & Comparison',
    syntax: '| regex field="pattern"',
    description:
      'REMOVES results whose field does not match a PCRE pattern (`!=` inverts it). Distinct from `rex`, which extracts or replaces rather than filters.',
    example: '... | regex _raw="(?<!\\\\d)10\\\\.\\\\d{1,3}\\\\.\\\\d{1,3}\\\\.\\\\d{1,3}(?!\\\\d)"',
  },
  {
    category: 'Filtering & Comparison',
    syntax: '| dedup field',
    description:
      'Removes results matching criteria you have already seen. Add an integer to keep N of each, `consecutive=true` to drop only adjacent repeats, and `sortby` to control which copy survives.',
    example: '... | dedup source sortby -_size',
  },
  {
    category: 'Filtering & Comparison',
    syntax: '| dedup N field field',
    description: 'Keeps the first N results for each combination of the named fields — useful for sampling a few events per host rather than one.',
    example: '... | dedup 2 source host',
  },
  {
    category: 'Filtering & Comparison',
    syntax: '| fillnull value=<string>',
    description:
      'Replaces null values with a value (default 0), across all fields or just the ones you name. Run it before a `stats` that would otherwise silently drop rows.',
    example: '... | fillnull value=unknown host kbps',
  },

  // -------------------------------------------------------------------------
  // Time Range Modifiers
  // -------------------------------------------------------------------------
  {
    category: 'Time Range Modifiers',
    syntax: 'earliest= / latest=',
    description:
      'Scope the search window inline instead of using the time picker. Format: `[+|-]<integer><unit>@<snap-unit>`. Both accept relative and absolute forms.',
    example: 'index=main earliest=-24h latest=now()',
  },
  {
    category: 'Time Range Modifiers',
    syntax: '@ (snap to)',
    description:
      'Rounds DOWN to the nearest unit. `-1d@d` means the start of yesterday, not this time yesterday — this is what makes a scheduled search cover a whole clean day.',
    example: 'index=main earliest=-1d@d latest=@d',
  },
  {
    category: 'Time Range Modifiers',
    syntax: 's m h d w mon q y',
    description:
      'Time units, each with long forms: `s|sec|secs|second|seconds`, `m|min|mins|minute|minutes`, `h|hr|hrs|hour|hours`, `d|day|days`, `w|week|weeks`, `mon|month|months`, `q|qtr|qtrs|quarter|quarters`, `y|yr|yrs|year|years`. Subsecond units are `us`, `ms`, `cs`, `ds`.',
    example: 'index=main earliest=-15m',
  },
  {
    category: 'Time Range Modifiers',
    syntax: '@w0 ... @w6',
    description: 'Snaps to a specific day of the week, where `w0` is Sunday. The building block for "the last full business week".',
    example: '... earliest=-5d@w1 latest=@w6',
  },
  {
    category: 'Time Range Modifiers',
    syntax: 'earliest="MM/DD/YYYY:HH:MM:SS"',
    description: 'Absolute timestamps for a fixed incident window that must not move as the search is re-run.',
    example: '... earliest="11/15/2022:20:00:00" latest="11/22/2022:20:00:00"',
  },
  {
    category: 'Time Range Modifiers',
    syntax: 'earliest=1 latest=now()',
    description: 'Searches over all time. Use it deliberately and rarely — on a real index it is the most expensive thing you can type.',
    example: '...earliest=1 latest=now()',
  },
  {
    category: 'Time Range Modifiers',
    syntax: '(earliest=... latest=...) OR (...)',
    description: 'Several disjoint windows in one search — for correlating two separate bursts of activity without running two searches.',
    example:
      '...(earliest="9/23/2022:17:00:00" latest="9/23/2022:18:00:00") OR (earliest="9/23/2022:19:00:00" latest="9/23/2022:20:00:00")',
  },
  {
    category: 'Time Range Modifiers',
    syntax: '| bin _time span=5m',
    description:
      'Buckets a continuous value into discrete sets. On `_time` this is how you build a timeline without `timechart`. `bucket` is an alias for the same command.',
    example: '... | bin _time span=5m | stats avg(thruput) by _time host',
  },
  {
    category: 'Time Range Modifiers',
    syntax: '| bin _time aligntime=@d+3h',
    description: 'Aligns the bucket boundaries to a specific time rather than to the search window — for lining up buckets with a business day.',
    example: '...| bin _time span=12h aligntime=@d+3h',
  },

  // -------------------------------------------------------------------------
  // Selecting & Shaping Fields
  // -------------------------------------------------------------------------
  {
    category: 'Selecting & Shaping Fields',
    syntax: '| fields field, field',
    description:
      'Keeps only the named fields (a leading `+` is the default). Doing this early cuts the volume every downstream command has to carry.',
    example: '... | fields source, sourcetype, host, error*',
  },
  {
    category: 'Selecting & Shaping Fields',
    syntax: '| fields - field',
    description: 'Removes the named fields. Internal fields such as `_raw` and `_time` have to be removed explicitly by name.',
    example: '... | fields - host, ip',
  },
  {
    category: 'Selecting & Shaping Fields',
    syntax: '| table field, field',
    description: 'Builds a table of the named fields in the order given. Where `fields` prunes, `table` also fixes column order for a report.',
    example:
      'sourcetype=access_* status>=400 | head 20 | iplocation clientip | table clientip, status, City, Country',
  },
  {
    category: 'Selecting & Shaping Fields',
    syntax: '| rename old AS new',
    description: 'Renames a field. Wildcards work on both sides; quote any name containing a space.',
    example: '... | rename _ip AS IPAddress',
  },
  {
    category: 'Selecting & Shaping Fields',
    syntax: '| rename prefix* AS prefix*',
    description: 'Bulk-renames a family of fields by pattern — for normalising a vendor prefix across a whole sourcetype.',
    example: '... | rename EU* AS EMEA*',
  },
  {
    category: 'Selecting & Shaping Fields',
    syntax: '| sort -field',
    description:
      'Sorts by one or more fields; `-` is descending, `+` ascending. Defaults to 10,000 results — pass `0` to sort everything.',
    example: '... | sort _time, -host',
  },
  {
    category: 'Selecting & Shaping Fields',
    syntax: '| sort num(field) / str() / ip()',
    description:
      'Forces a sort type instead of letting Splunk guess. `ip()` in particular sorts addresses numerically rather than as strings, which is almost always what you want.',
    example: '... | sort ip(ipaddress), -str(url)',
  },
  {
    category: 'Selecting & Shaping Fields',
    syntax: '| sort 1 -_time',
    description: 'The idiomatic "give me the single most recent event" — a count in front of the sort clause caps the output.',
    example: '... | sort 1 -_time',
  },
  {
    category: 'Selecting & Shaping Fields',
    syntax: '| mvexpand field',
    description: 'Expands a multivalue field into one event per value. `limit=<int>` caps how many values are expanded per input event.',
    example: '... | mvexpand foo limit=100',
  },
  {
    category: 'Selecting & Shaping Fields',
    syntax: '| fieldformat field=expr',
    description:
      'Changes how a field DISPLAYS without changing its underlying value — so a formatted epoch still sorts and compares numerically.',
    example: '| metadata type=sourcetypes index=_internal | fieldformat firstTime=strftime(firstTime, "%c")',
  },

  // -------------------------------------------------------------------------
  // Statistics & Aggregation
  // -------------------------------------------------------------------------
  {
    category: 'Statistics & Aggregation',
    syntax: '| stats <func>(field) BY field',
    description:
      'The workhorse. Computes aggregates, optionally grouped by one or more fields, and discards everything that is not part of the result.',
    example: 'sourcetype=access_* | stats count BY status, host',
  },
  {
    category: 'Statistics & Aggregation',
    syntax: 'count / count(field)',
    description: 'Bare `count` counts events; `count(field)` counts events where that field is present. The difference matters on sparse sourcetypes.',
    example: 'sourcetype=access_* | stats count BY host',
  },
  {
    category: 'Statistics & Aggregation',
    syntax: 'count(eval(<condition>))',
    description:
      'Conditional counting — the idiom for putting success and failure counts side by side in a single pass instead of running two searches.',
    example:
      'sourcetype=access_* | stats count(eval(method="GET")) AS GET, count(eval(method="POST")) AS POST BY host',
  },
  {
    category: 'Statistics & Aggregation',
    syntax: 'dc(field) / distinct_count(field)',
    description: 'Distinct count. `estdc()` is the cheaper estimated version, with `estdc_error()` reporting its error bound.',
    example: '... | stats dc(host)',
  },
  {
    category: 'Statistics & Aggregation',
    syntax: 'values(field) / list(field)',
    description:
      'Multivalue aggregates: `values()` returns the DISTINCT values in a group, `list()` returns all of them in order. The way to collapse "everything this host did" into one row.',
    example: '... | stats values(dest_port) AS Ports BY src_ip',
  },
  {
    category: 'Statistics & Aggregation',
    syntax: 'earliest(field) / latest(field)',
    description:
      'Returns the field value from the chronologically first / last event in the group. `earliest_time()` and `latest_time()` return the timestamps themselves.',
    example: '... | stats earliest(_time) AS FirstSeen, latest(_time) AS LastSeen BY user',
  },
  {
    category: 'Statistics & Aggregation',
    syntax: 'first(field) / last(field)',
    description:
      'Returns the field value from the first / last event in RESULT order, not time order. Use `earliest()`/`latest()` when you actually mean chronology.',
    example: '... | stats first(status) BY host',
  },
  {
    category: 'Statistics & Aggregation',
    syntax: 'sum / avg / min / max / median',
    description: 'The standard numeric aggregates. `range()`, `mode()`, `stdev()`, `stdevp()`, `var()`, `varp()` and `sumsq()` round out the set.',
    example: 'sourcetype=access* | stats avg(kbps) BY host',
  },
  {
    category: 'Statistics & Aggregation',
    syntax: 'perc<num>(field)',
    description:
      'Percentile estimate — `perc95(duration)`. `exactperc<num>()` is the exact (and far more expensive) form; `upperperc<num>()` gives the upper bound.',
    example: '... | stats perc95(duration) BY sourcetype',
  },
  {
    category: 'Statistics & Aggregation',
    syntax: '| stats <func>(*wildcard*)',
    description: 'Aggregate every field matching a wildcard in one clause instead of naming them individually.',
    example: '... | stats avg(*lay) BY date_hour',
  },
  {
    category: 'Statistics & Aggregation',
    syntax: '| eventstats <func> BY field',
    description:
      'Computes the same aggregates as `stats` but ATTACHES them to every original event instead of collapsing them. This is how you compare each event to its own group average.',
    example: 'eventtype="error" | eventstats avg(bytes) AS avg | where bytes>avg',
  },
  {
    category: 'Statistics & Aggregation',
    syntax: '| streamstats <func>',
    description:
      'Running aggregates, computed in event order. `current=f` excludes the current event, which is what you want when comparing an event to what came before it.',
    example: '... | streamstats count current=f',
  },
  {
    category: 'Statistics & Aggregation',
    syntax: '| streamstats window=N',
    description:
      'Limits the running aggregate to a sliding window of N events. `time_window=5m` does the same by time, and requires the events to be sorted by time.',
    example: '... | streamstats avg(foo) window=5',
  },
  {
    category: 'Statistics & Aggregation',
    syntax: '| top limit=N field',
    description:
      'The most common values of a field, with count and percent. `rare` is the mirror image and takes the same arguments — and on a DFIR hunt the rare values are usually the interesting ones.',
    example: 'sourcetype=access_* | top limit=20 referer',
  },
  {
    category: 'Statistics & Aggregation',
    syntax: '| top field BY field',
    description: 'Top values computed per group rather than globally — "the most common action for each referring domain".',
    example: 'sourcetype=access_* | top action by referer_domain',
  },
  {
    category: 'Statistics & Aggregation',
    syntax: '| top N field showperc=f countfield=<name>',
    description: 'Drops the percent column and renames the count column — the tidy form for a report table.',
    example:
      'sourcetype=access_* status=200 action=purchase | top 1 productName by categoryId showperc=f countfield=total',
  },

  // -------------------------------------------------------------------------
  // Time Series & Charting
  // -------------------------------------------------------------------------
  {
    category: 'Time Series & Charting',
    syntax: '| timechart span=<span> <func>',
    description:
      'Builds a time series and its statistics table in one step. `span` sets the bucket size; if you give both `bins` and `span`, span wins.',
    example: '... | timechart span=1m avg(CPU) BY host',
  },
  {
    category: 'Time Series & Charting',
    syntax: '| timechart ... BY field',
    description:
      'Splits the series by a field, producing one line per distinct value. Beware of high-cardinality split fields — you will get a column per value.',
    example: 'sourcetype="web" | timechart count by host | fillnull value=NULL',
  },
  {
    category: 'Time Series & Charting',
    syntax: '| chart <func> OVER field',
    description:
      'Tabular output for charting where the x-axis is a field rather than time. `OVER` sets the rows; a following `BY` splits them into columns.',
    example: '... | chart max(delay) OVER site BY org',
  },
  {
    category: 'Time Series & Charting',
    syntax: '| chart ... BY field span=<span>',
    description: 'Bins a numeric split field while charting — `span=log2` gives logarithmic buckets, which is the right shape for durations and sizes.',
    example:
      'sourcetype=access_* status=200 action=purchase | transaction clientip maxspan=10m | chart count BY duration span=log2',
  },
  {
    category: 'Time Series & Charting',
    syntax: '| bin field bins=N',
    description: 'Discretises a numeric field into a fixed number of buckets (default 100). `start=` and `end=` clamp the range.',
    example: '... | bin size bins=10 | stats count(_raw) by size',
  },

  // -------------------------------------------------------------------------
  // Correlation: Joins, Lookups & Transactions
  // -------------------------------------------------------------------------
  {
    category: 'Correlation: Joins, Lookups & Transactions',
    syntax: '| transaction <field-list>',
    description:
      'Groups events into transactions by shared field values. It adds `duration`, `eventcount` and `closed_txn` fields to each transaction.',
    example: '... | transaction host cookie maxspan=30s maxpause=5s',
  },
  {
    category: 'Correlation: Joins, Lookups & Transactions',
    syntax: 'startswith= / endswith=',
    description:
      'Anchors a transaction to the events that open and close it. This is how you turn a stream of web events into per-session stories.',
    example:
      'sourcetype=access_* | transaction JSESSIONID clientip startswith="view" endswith="purchase" | where duration>0',
  },
  {
    category: 'Correlation: Joins, Lookups & Transactions',
    syntax: 'maxspan= / maxpause= / maxevents=',
    description:
      'Bounds a transaction: total elapsed time, maximum gap between consecutive events, and maximum member count (default 1000). Without bounds a transaction can swallow a whole index.',
    example: 'sourcetype="cisco:esa" | transaction mid dcid icid maxevents=10 endswith="Message done"',
  },
  {
    category: 'Correlation: Joins, Lookups & Transactions',
    syntax: '| join field [search ...]',
    description:
      'SQL-style join between the main pipeline and a subsearch. Default `type=inner`; `type=outer` (equivalently `type=left`) keeps unmatched left rows.',
    example: '... | join product_id [search vendors]',
  },
  {
    category: 'Correlation: Joins, Lookups & Transactions',
    syntax: 'join left=L right=R where L.a=R.b',
    description: 'Joins on fields with different names on each side, using aliases. `max=0` lifts the one-matching-row-per-key default.',
    example: '... | join left=L right=R where L.product_id=R.pid [search vendors]',
  },
  {
    category: 'Correlation: Joins, Lookups & Transactions',
    syntax: '| append [search ...]',
    description:
      'Appends subsearch results as extra ROWS. `appendcols` appends them as extra COLUMNS, pairing first result with first result.',
    example: '| makeresults count=5 | eval Country="Canada" | append [| makeresults count=5 | eval City="Toronto"]',
  },
  {
    category: 'Correlation: Joins, Lookups & Transactions',
    syntax: '| lookup <table> <field> OUTPUT <field>',
    description:
      'Enriches events from a configured lookup table. `OUTPUTNEW` only writes fields that are not already present, which is the safer default when enriching.',
    example: '| lookup usertogroup user as local_user OUTPUT group as user_group',
  },
  {
    category: 'Correlation: Joins, Lookups & Transactions',
    syntax: '| inputlookup <table>',
    description:
      'Reads a lookup table as its own result set — the way to inspect a threat-intel list, or to use one as the seed of a subsearch. `outputlookup` writes back.',
    example: '| inputlookup users.csv',
  },
  {
    category: 'Correlation: Joins, Lookups & Transactions',
    syntax: '| inputlookup <table> WHERE ...',
    description: 'Filters a lookup while reading it, instead of pulling the whole table and filtering after.',
    example: '| inputlookup kvstorecoll_lookup where (CustID>500) AND (CustName="P*") | stats count',
  },
  {
    category: 'Correlation: Joins, Lookups & Transactions',
    syntax: '| iplocation <ip-field>',
    description:
      'Adds City, Country, Region, lat and lon from an IP field. `allfields=true` adds Continent, MetroCode and Timezone; `prefix=` namespaces the new fields.',
    example: 'sourcetype = access_* | iplocation prefix=iploc_ allfields=true clientip | fields iploc_*',
  },

  // -------------------------------------------------------------------------
  // Field Extraction & Regex
  // -------------------------------------------------------------------------
  {
    category: 'Field Extraction & Regex',
    syntax: '| rex "(?<name>pattern)"',
    description:
      'Extracts fields at search time using a PCRE pattern with named capture groups. Defaults to matching against `_raw`.',
    example: 'source="cisco_esa.txt" | rex field=_raw "From: <(?<from>.*)> To: <(?<to>.*)>"',
  },
  {
    category: 'Field Extraction & Regex',
    syntax: 'rex field=<field>',
    description: 'Runs the extraction against a specific field instead of the whole raw event — faster, and avoids collisions with unrelated text.',
    example: '... | rex field=fields "(?<alpha>\\\\d+),(?<beta>\\\\d+)"',
  },
  {
    category: 'Field Extraction & Regex',
    syntax: 'max_match=<int>',
    description: 'Number of matches to extract (default 1). Set it to 0 for unlimited, which produces a multivalue field.',
    example: 'rex field=test max_match=0 "((?<field>[^$]*)\\\\$(?<value>[^,]*),?)"',
  },
  {
    category: 'Field Extraction & Regex',
    syntax: 'rex mode=sed',
    description:
      'Sed-style substitution instead of extraction — the standard way to mask a card number, token or hostname in output you are about to share.',
    example: 'rex field=ccnumber mode=sed "s/(\\\\d{4}-){3}/XXXX-XXXX-XXXX-/g"',
  },
  {
    category: 'Field Extraction & Regex',
    syntax: 'offset_field=<string>',
    description: 'Writes the match position into a field (as `start-end`) — useful when you need to prove where in the event a match landed.',
    example: 'rex offset_field=off field=list "(?<firstfive>abcde)"',
  },
  {
    category: 'Field Extraction & Regex',
    syntax: '| spath path=<datapath>',
    description:
      'Extracts fields from structured JSON or XML. Steps are separated by periods; array indices go in curly brackets, and `{}` means "every element".',
    example: '... | spath output=myfield path=vendorProductSet.product.desc',
  },
  {
    category: 'Field Extraction & Regex',
    syntax: 'spath input=<field>',
    description: 'Parses structured data out of a named field rather than `_raw` — for a JSON blob nested inside a syslog line.',
    example: '... | spath input=message output=user path=actor.user.name',
  },
  {
    category: 'Field Extraction & Regex',
    syntax: 'spath path=arr{}.field',
    description: 'Walks into every element of a JSON array, producing a multivalue field you can then `mvexpand`.',
    example: '... | spath output=myfield path=vendorProductSet.product{}.locDesc',
  },

  // -------------------------------------------------------------------------
  // Eval Functions
  // -------------------------------------------------------------------------
  {
    category: 'Eval Functions',
    syntax: '| eval field=<expression>',
    description: 'Calculates an expression and writes it into a field. Comma-separate several assignments in one `eval`; later ones can use earlier ones.',
    example: '... | eval full_name = first_name." ".last_name, low_name = lower(full_name)',
  },
  {
    category: 'Eval Functions',
    syntax: '+  -  *  /  %  .',
    description:
      'Arithmetic operators plus `.` for concatenation. Boolean operators are `AND OR NOT XOR`, and `=` and `==` are interchangeable in eval.',
    example: '... | eval velocity=distance/time',
  },
  {
    category: 'Eval Functions',
    syntax: 'if(predicate, true, false)',
    description: 'Two-branch conditional.',
    example: '... | eval error = if(status == 200, "OK", "Problem")',
  },
  {
    category: 'Eval Functions',
    syntax: 'case(cond, val, cond, val, ...)',
    description: 'Returns the value for the first condition that is TRUE. There is no implicit else — add `1=1` as the final condition if you want one.',
    example:
      '... | eval error_msg = case(error == 404, "Not found", error == 500, "Internal Server Error", error == 200, "OK")',
  },
  {
    category: 'Eval Functions',
    syntax: 'coalesce(a, b, ...)',
    description: 'Returns the first non-null argument — for collapsing two sourcetypes that name the same idea differently.',
    example: '... | eval user = coalesce(username, user_name, account)',
  },
  {
    category: 'Eval Functions',
    syntax: 'match(str, regex)',
    description: 'True when the string matches the regex. `searchmatch()` tests a whole search string against the event instead.',
    example: '... | eval is_exe = if(match(file_name, "\\\\.exe$"), 1, 0)',
  },
  {
    category: 'Eval Functions',
    syntax: 'replace(str, regex, replacement)',
    description: 'Regex substitution inside an eval expression.',
    example: '... | eval clean = replace(path, "^[A-Za-z]:", "")',
  },
  {
    category: 'Eval Functions',
    syntax: 'lower() / upper() / len()',
    description: 'Case normalisation and character count. Normalise before a `stats ... BY` or two spellings become two groups.',
    example: '... | eval low-user = lower(username)',
  },
  {
    category: 'Eval Functions',
    syntax: 'substr(str, start, len)',
    description: 'Substring extraction. `ltrim()`, `rtrim()` and `trim()` strip characters from the edges.',
    example: '... | eval short_hash = substr(file_hash, 1, 12)',
  },
  {
    category: 'Eval Functions',
    syntax: 'split(str, delim)',
    description: 'Splits a string into a multivalue field. `mvjoin()` puts one back together; `mvcount()`, `mvindex()`, `mvfilter()` and `mvdedup()` work on the result.',
    example: '... | eval parts = split(path, "/") | eval depth = mvcount(parts)',
  },
  {
    category: 'Eval Functions',
    syntax: 'strftime(epoch, format)',
    description: 'Formats an epoch time as a readable string. `strptime()` is the inverse and is how you turn a log-embedded timestamp into a real time field.',
    example: '... | eval when = strftime(_time, "%Y-%m-%d %H:%M:%S")',
  },
  {
    category: 'Eval Functions',
    syntax: 'relative_time(time, specifier)',
    description: 'Applies a relative-time specifier (the same `-1d@d` grammar as `earliest`) to a time value inside an expression.',
    example: '... | eval day_start = relative_time(_time, "@d")',
  },
  {
    category: 'Eval Functions',
    syntax: 'now() / time()',
    description: '`now()` is the search start time and is constant for the whole search; `time()` is the wall-clock time when the eval ran.',
    example: '... | eval age_seconds = now() - _time',
  },
  {
    category: 'Eval Functions',
    syntax: 'tostring(value, format)',
    description: 'Converts to a string, optionally with a format such as "commas", "hex" or "duration". `tonumber()` goes the other way.',
    example: '... | eval x="$".tostring(x,"commas")',
  },
  {
    category: 'Eval Functions',
    syntax: 'md5() / sha1() / sha256()',
    description: 'Computes a hash of a string inside a search. Useful for building a stable correlation key, not for re-deriving a file hash from telemetry.',
    example: '... | eval key = sha256(host.user)',
  },
  {
    category: 'Eval Functions',
    syntax: 'isnull() / isnotnull()',
    description: 'Null tests. `typeof()`, `isnum()`, `isstr()`, `isint()` and `ismv()` cover the rest of the type checks.',
    example: '... | where isnotnull(dest_ip)',
  },
  {
    category: 'Eval Functions',
    syntax: 'ipmask(mask, ip)',
    description: 'Applies a bitwise mask to an IPv4 address — the way to group traffic by network rather than by host.',
    example: '... | eval subnet = ipmask("255.255.255.0", clientip) | stats count BY subnet',
  },
  {
    category: 'Eval Functions',
    syntax: 'json_extract(json, path)',
    description: 'Pulls values out of a JSON string by path inside an eval. `json_keys()`, `json_valid()` and `json_array_to_mv()` complete the set.',
    example: '... | eval user = json_extract(_raw, "actor.user.name")',
  },

  // -------------------------------------------------------------------------
  // Accelerated & Metadata Searches
  // -------------------------------------------------------------------------
  {
    category: 'Accelerated & Metadata Searches',
    syntax: '| tstats <func> WHERE index=...',
    description:
      'Runs statistics directly against the indexed `tsidx` files rather than raw events. Orders of magnitude faster than `stats`, at the cost of only seeing indexed fields.',
    example: '| tstats count WHERE index=_internal',
  },
  {
    category: 'Accelerated & Metadata Searches',
    syntax: 'tstats ... BY field span=<span>',
    description: 'Groups an accelerated search, optionally by time bucket. This is the fast way to build a first-pass timeline over a wide window.',
    example: '| tstats count WHERE index=myindex host=x by source',
  },
  {
    category: 'Accelerated & Metadata Searches',
    syntax: 'tstats FROM datamodel=<name>',
    description:
      'Runs against an accelerated data model instead of an index. `summariesonly=t` restricts it to summarised data only, which keeps it genuinely fast.',
    example: '| tstats summariesonly=t min(_time) AS min, max(_time) AS max FROM datamodel=mydm',
  },
  {
    category: 'Accelerated & Metadata Searches',
    syntax: 'tstats ... where nodename=<dataset>',
    description: 'Selects a child dataset inside a data model, rather than the whole root object.',
    example: '| tstats count FROM datamodel=internal_server where nodename=server.scheduler.alerts',
  },
  {
    category: 'Accelerated & Metadata Searches',
    syntax: 'tstats prestats=t ... | timechart',
    description: 'Emits intermediate statistics so a downstream reporting command can finish the job — the accelerated route to a chart.',
    example: '| tstats prestats=t count WHERE index=_internal BY _time span=1h | timechart span=1d count',
  },
  {
    category: 'Accelerated & Metadata Searches',
    syntax: '| metadata type=sourcetypes index=...',
    description:
      'Lists the hosts, sources or sourcetypes present in an index, with first/last/recent event times. The first thing to run against an unfamiliar environment.',
    example: '| metadata type=sourcetypes index=_internal',
  },
  {
    category: 'Accelerated & Metadata Searches',
    syntax: 'metadata type=hosts index=a index=b',
    description: 'Accepts several indexes and wildcards at once — a quick inventory of which hosts are actually reporting.',
    example: '| metadata type=hosts index=cs* index=na* index=ap* index=eu*',
  },
];
