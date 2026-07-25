// Reference data for the Timestamp Converter's operator/format table — every
// format the research pass covered, not just the ones wired into the live
// converter (src/utils/timestamps.ts). Where a format is numerically
// identical (or a simple relabeling) of one already in the live converter,
// `linkedFormatId` points at it instead of duplicating a field for it.
//
// Content accuracy: every epoch origin/unit/DFIR-relevance note below came
// from an explicit research + independent adversarial fact-check pass
// (Microsoft Learn, RFC text, Apple/forensic documentation) — see
// src/utils/timestamps.ts's comments for the interactive formats' own
// citations. Don't add a format here without the same rigor.

export interface TimestampFormatRef {
  name: string;
  aliases?: string[];
  epochOrigin: string;
  unit: string;
  whereSeenInDFIR: string;
  /** Id into TIMESTAMP_FORMATS (src/utils/timestamps.ts) if this format has a live, editable field. */
  linkedFormatId?: string;
  /** Why this format has no live field of its own, when it doesn't. */
  note?: string;
}

export const TIMESTAMP_FORMAT_REFERENCE: TimestampFormatRef[] = [
  // ── Unix / platform epochs ────────────────────────────────────────────
  {
    name: 'Unix time (seconds)',
    aliases: ['POSIX time', 'epoch time'],
    epochOrigin: '1970-01-01T00:00:00Z',
    unit: 'seconds',
    whereSeenInDFIR: 'Linux syslog/auditd, most REST APIs, JWT iat/exp/nbf claims, cron, many log formats',
    linkedFormatId: 'unix-s',
  },
  {
    name: 'Unix time (milliseconds)',
    aliases: ['JS timestamp', 'epoch millis'],
    epochOrigin: '1970-01-01T00:00:00Z',
    unit: 'milliseconds',
    whereSeenInDFIR: 'JavaScript Date.now()/getTime(), Java System.currentTimeMillis(), MongoDB, many JSON logs',
    linkedFormatId: 'unix-ms',
  },
  {
    name: 'Unix time (microseconds)',
    aliases: ['epoch micros', 'Firefox PRTime'],
    epochOrigin: '1970-01-01T00:00:00Z',
    unit: 'microseconds',
    whereSeenInDFIR:
      "Python time.time_ns()/1000, PostgreSQL internal timestamps, Firefox/Thunderbird places.sqlite (PRTime, Mozilla's NSPR type — numerically identical to this format)",
    linkedFormatId: 'unix-us',
  },
  {
    name: 'Unix time (nanoseconds)',
    aliases: ['epoch nanos', 'Go time.UnixNano()'],
    epochOrigin: '1970-01-01T00:00:00Z',
    unit: 'nanoseconds',
    whereSeenInDFIR: 'Go time.UnixNano(), Python time.time_ns(), high-resolution tracing/eBPF tooling, APFS inode timestamps',
    linkedFormatId: 'unix-ns',
  },
  {
    name: 'Java / JavaScript epoch time',
    aliases: ['System.currentTimeMillis()', 'Date.now()', 'java.util.Date'],
    epochOrigin: '1970-01-01T00:00:00Z',
    unit: 'milliseconds',
    whereSeenInDFIR: 'JVM/Android application logs, browser console/localStorage artifacts, Node.js logs',
    note: 'Numerically identical to Unix milliseconds above — both are ms since the Unix epoch.',
  },
  {
    name: 'Python epoch conventions',
    aliases: ['time.time()', 'datetime.timestamp()'],
    epochOrigin: '1970-01-01T00:00:00Z',
    unit: 'seconds (float)',
    whereSeenInDFIR: 'Python-based forensic scripts, Volatility/custom tool output, application logs',
    note: 'Same as Unix seconds above, just as a float; time.time_ns() is the nanoseconds field instead.',
  },

  // ── Windows / Microsoft ───────────────────────────────────────────────
  {
    name: 'Windows FILETIME',
    aliases: ['NT time', 'NTFS timestamp', 'Win32 FILETIME'],
    epochOrigin: '1601-01-01T00:00:00Z',
    unit: '100-nanosecond intervals',
    whereSeenInDFIR:
      'NTFS $MFT $STANDARD_INFORMATION/$FILE_NAME MACB timestamps, registry LastWrite, EVTX records, Prefetch, LNK files, Active Directory (lastLogon, pwdLastSet, accountExpires — as "AD/LDAP timestamp")',
    linkedFormatId: 'filetime',
  },
  {
    name: 'Active Directory / LDAP timestamp',
    aliases: ['AD timestamp', 'LDAP generalized FILETIME'],
    epochOrigin: '1601-01-01T00:00:00Z',
    unit: '100-nanosecond intervals',
    whereSeenInDFIR: 'AD attributes pwdLastSet, accountExpires, lastLogon, badPasswordTime, lockoutTime',
    note: 'Identical epoch and unit to Windows FILETIME above — same field, different name in AD/LDAP contexts.',
  },
  {
    name: '.NET / C# DateTime.Ticks',
    aliases: ['.NET ticks', 'TimeSpan ticks'],
    epochOrigin: '0001-01-01T00:00:00',
    unit: '100-nanosecond intervals',
    whereSeenInDFIR: '.NET/C# application databases, PowerShell Get-Date .Ticks — do not confuse with FILETIME (same tick size, different epoch)',
    linkedFormatId: 'net-ticks',
  },
  {
    name: 'OLE Automation Date',
    aliases: ['OADate', 'VB6/VBA Date', 'COM DATE type', 'Excel/Lotus serial date'],
    epochOrigin: '1899-12-30T00:00:00',
    unit: 'days (fractional — integer part is the day, fraction is time-of-day)',
    whereSeenInDFIR:
      'VB6/VBA CDbl(Date), classic ASP, .NET DateTime.ToOADate(), XLS/XLSX cell values, CSV exports from spreadsheets',
    linkedFormatId: 'ole-date',
    note: 'Numerically identical to the classic Excel/Lotus 1900 serial date system for dates on/after 1900-03-01; Excel\'s own "phantom Feb 29, 1900" leap-year bug only affects the 59 serial values before that date.',
  },
  {
    name: 'FAT/FAT32 directory entry timestamp',
    aliases: ['MS-DOS date/time', 'FatDateTime'],
    epochOrigin: '1980-01-01 (packed year offset)',
    unit: 'packed 16-bit date + 16-bit time fields, local time, 2-second resolution',
    whereSeenInDFIR: 'FAT12/16/32 volumes (USB drives, SD cards, embedded/IoT media), some legacy ZIP archive entries',
    linkedFormatId: 'fat-dos',
    note: 'Stored in local time with no offset field of its own — exFAT fixes this by adding an explicit UTC-offset byte.',
  },

  // ── Apple / macOS ─────────────────────────────────────────────────────
  {
    name: 'HFS+ timestamp',
    aliases: ['HFS Plus timestamp', 'Mac OS Extended timestamp'],
    epochOrigin: '1904-01-01T00:00:00Z',
    unit: 'seconds',
    whereSeenInDFIR: 'Mac OS Extended (HFS+) volume catalog timestamps, Time Machine, drives predating the APFS transition (2017)',
    linkedFormatId: 'hfsplus',
  },
  {
    name: 'Classic Mac OS HFS timestamp',
    aliases: ['HFS local timestamp'],
    epochOrigin: '1904-01-01T00:00:00, in LOCAL time',
    unit: 'seconds',
    whereSeenInDFIR: 'Legacy HFS (Mac OS 9 and earlier) volumes — rare today',
    note: 'Same 1904 epoch as HFS+, but stored in local time with no offset — unlike HFS+, which is UTC. No live field given how rarely this specific legacy variant surfaces.',
  },
  {
    name: 'Mac Absolute Time (Cocoa)',
    aliases: ['CFAbsoluteTime', 'Core Data timestamp', 'NSDate reference date'],
    epochOrigin: '2001-01-01T00:00:00Z',
    unit: 'seconds (some newer fields use nanoseconds at the same epoch)',
    whereSeenInDFIR: 'Safari History.db, macOS/iOS plist NSDate fields, Core Data-backed apps (Messages, Notes, Photos.sqlite, Health)',
    linkedFormatId: 'mac-absolute',
  },
  {
    name: 'APFS timestamp',
    aliases: ['Apple File System timestamp'],
    epochOrigin: '1970-01-01T00:00:00Z',
    unit: 'nanoseconds',
    whereSeenInDFIR: 'APFS inode MACB timestamps (macOS 10.13+ / iOS default filesystem), Time Machine on Big Sur+',
    note: 'Numerically identical to Unix nanoseconds above.',
  },

  // ── Linux / ext filesystem ────────────────────────────────────────────
  {
    name: 'ext2/ext3 inode timestamp',
    aliases: ['classic 32-bit Unix mtime/atime/ctime'],
    epochOrigin: '1970-01-01T00:00:00Z',
    unit: 'seconds (signed 32-bit)',
    whereSeenInDFIR: 'ext2 (older Linux, some boot/EFI partitions), ext3 (older distros, embedded Linux/NAS) inode timestamps',
    note: 'Identity-mapped Unix seconds, just stored in a 32-bit field — subject to the year-2038 rollover. No crtime/birth-time field exists on ext2/ext3.',
  },
  {
    name: 'ext4 extended inode timestamp',
    aliases: ['ext4 crtime/birth time'],
    epochOrigin: '1970-01-01T00:00:00Z (extended past 2038 via 2 borrowed epoch bits)',
    unit: '32-bit seconds + a 32-bit extra field (2 epoch-extension bits + 30 nanosecond bits)',
    whereSeenInDFIR: 'ext4 i_mtime/i_atime/i_ctime/i_crtime + their _extra fields — Linux server/container/older-Android forensics, timestomping detection',
    note: 'Bit-packed across two 32-bit fields per timestamp — reference only; not a practical single live-field input.',
  },

  // ── Other forensic-relevant formats ───────────────────────────────────
  {
    name: 'Google/Chrome WebKit timestamp',
    aliases: ['Chromium timestamp'],
    epochOrigin: '1601-01-01T00:00:00Z',
    unit: 'microseconds',
    whereSeenInDFIR: "Chrome/Chromium/Edge/Brave History and Cookies SQLite DBs (visit_time, last_visit_time, creation_utc)",
    linkedFormatId: 'webkit',
    note: 'Shares its epoch with Windows FILETIME — just a microsecond tick instead of 100ns.',
  },
  {
    name: 'UUID version 1 timestamp',
    aliases: ['UUIDv1 timestamp', 'GUID v1 timestamp'],
    epochOrigin: '1582-10-15T00:00:00Z (the Gregorian calendar reform date)',
    unit: '100-nanosecond intervals, packed into a 60-bit field',
    whereSeenInDFIR:
      'Time-based UUIDs (v1, and v6/v7 variants) in application/database records, log correlation IDs — recoverable creation time plus the generating NIC MAC address',
    linkedFormatId: 'uuid-v1',
    note: 'Same 100ns tick size as FILETIME, but a completely different (much earlier) epoch — do not reuse the FILETIME offset.',
  },
  {
    name: 'GPS time',
    aliases: ['GPST'],
    epochOrigin: '1980-01-06T00:00:00 UTC',
    unit: 'seconds (continuous — no leap seconds inserted after the epoch)',
    whereSeenInDFIR: 'GNSS/GPS receiver logs, vehicle telematics, drone/UAV flight logs, NMEA/RTCM/ublox captures',
    linkedFormatId: 'gps',
    note: 'GPS never gets leap seconds, so it drifts further ahead of UTC each time one is added — currently 18s ahead (unchanged since the last leap second, 2016-12-31).',
  },
  {
    name: 'TAI64',
    aliases: ['djb TAI64'],
    epochOrigin: '2^62 represents 1970-01-01T00:00:00 TAI',
    unit: 'whole TAI seconds (no leap seconds), 8-byte big-endian integer',
    whereSeenInDFIR: 'daemontools/djbdns/qmail/s6/runit service logs (the "@" + 24 hex chars in multilog output)',
    linkedFormatId: 'tai64',
    note: 'TAI runs 37s ahead of UTC (as of 2017-01-01, unchanged through 2026) — naive parsers that skip this correction drift by that much.',
  },
  {
    name: 'TAI64N',
    aliases: ['djb TAI64N'],
    epochOrigin: 'Same as TAI64',
    unit: '12-byte format: the TAI64 seconds label plus a 4-byte nanosecond field',
    whereSeenInDFIR: 'Same djb-lineage service logs as TAI64, where sub-second resolution matters',
    note: 'Same seconds handling as TAI64; the extra nanosecond field needs no epoch adjustment of its own. No separate live field — use TAI64 for the seconds portion.',
  },

  // ── Human-readable / text formats ─────────────────────────────────────
  {
    name: 'ISO 8601 / RFC 3339',
    aliases: ['Internet date/time format'],
    epochOrigin: 'n/a — direct calendar representation',
    unit: 'YYYY-MM-DDThh:mm:ss[.fff](Z|±hh:mm)',
    whereSeenInDFIR: 'Cloud audit logs (AWS CloudTrail, Azure Activity Log, GCP Audit Logs), Kubernetes events, JSON APIs, RFC 5424 syslog',
    linkedFormatId: 'iso8601',
    note: 'RFC 3339 is a stricter profile of ISO 8601 (offset always present, no week-dates/ordinal-dates) — RFC 5424 syslog reuses this exact grammar.',
  },
  {
    name: 'RFC 2822 / RFC 5322 Date-Time',
    aliases: ['email Date header', 'RFC 822 date'],
    epochOrigin: 'n/a — direct calendar representation',
    unit: "[day-name,] dd Mon yyyy hh:mm:ss ±zzzz",
    whereSeenInDFIR: "Email 'Date:'/'Received:' headers in .eml/.msg files and mbox archives — core artifact in phishing/BEC investigations",
    linkedFormatId: 'rfc2822',
    note: "2-digit years are windowed per RFC 5322 (00-49 -> 2000s, 50-99 -> 1900s); named zones like 'EST'/'CST' are historically ambiguous and treated as offset 0 unless numeric.",
  },
  {
    name: 'HTTP-date (RFC 7231/9110)',
    aliases: ['IMF-fixdate', 'rfc850-date', 'asctime-date'],
    epochOrigin: 'n/a — direct calendar representation',
    unit: "day-name, dd Mon yyyy hh:mm:ss GMT (IMF-fixdate; two obsolete variants also exist)",
    whereSeenInDFIR: "HTTP 'Date'/'Last-Modified'/'Expires' headers — web/proxy log forensics, C2 beaconing interval analysis",
    linkedFormatId: 'http-date',
    note: 'Always GMT/UTC by definition. The live field parses/emits the modern IMF-fixdate; the two obsolete variants (rfc850-date, asctime-date) are documented here but not separately parsed.',
  },
  {
    name: 'Syslog (RFC 3164, legacy BSD)',
    aliases: ['BSD syslog timestamp'],
    epochOrigin: 'n/a — direct calendar representation',
    unit: 'Mmm dd hh:mm:ss (local time, space- not zero-padded day)',
    whereSeenInDFIR: '/var/log/messages, /var/log/syslog on older rsyslog/sysklogd configs, many network/embedded device logs',
    linkedFormatId: 'syslog-3164',
    note: 'Has NO year and NO timezone field at all — both must come from external context (this tool uses the reference year/offset you set).',
  },
  {
    name: 'Syslog (RFC 5424, modern)',
    aliases: ['modern syslog timestamp'],
    epochOrigin: 'n/a — direct calendar representation',
    unit: 'reuses the RFC 3339 grammar exactly (year and offset are mandatory)',
    whereSeenInDFIR: 'rsyslog/syslog-ng default framing, next-gen firewall/EDR/SIEM syslog exports',
    note: 'Identical grammar to ISO 8601 / RFC 3339 above — use that field. Fixes RFC 3164\'s missing year/offset.',
  },
  {
    name: 'Apache/NCSA Common Log Format',
    aliases: ['Combined Log Format timestamp'],
    epochOrigin: 'n/a — direct calendar representation',
    unit: '[dd/Mmm/yyyy:hh:mm:ss ±zzzz]',
    whereSeenInDFIR: 'Apache/NCSA-lineage web server access logs — web-shell and web-exploitation timeline reconstruction',
    linkedFormatId: 'clf',
    note: 'Always carries an explicit numeric offset, unlike RFC 3164 — the timestamp itself is unambiguous (though which host\'s clock produced it still needs confirming).',
  },
];
