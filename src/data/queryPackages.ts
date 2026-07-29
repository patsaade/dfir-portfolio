// DFIR query packages — prebuilt hunting queries for the three query builders
// on this site (KQL for Microsoft Defender XDR / Sentinel, SPL for Splunk, and
// PowerQuery for SentinelOne Singularity).
//
// A "package" is a starting point for one specific investigation: what it
// finds, what data it needs to find it in, and — where one genuinely applies —
// the MITRE ATT&CK technique it's looking for. None of these are finished
// detections. Every one of them returns benign activity in a real environment
// and has to be tuned against your own baseline before it means anything, which
// is why each carries its own `tuning` line saying where the noise comes from.
//
// TWO RULES THIS FILE IS BUILT AROUND
//
// 1. NO PACKAGE STORES QUERY TEXT. Each package stores a SPEC, and the query is
//    rendered by the same pure builder the interactive tool itself uses
//    (buildKqlQuery / buildSplQuery / buildS1Query). That means a package
//    cannot drift from what the builder would produce, cannot reference a
//    table/column the builder doesn't know, and cannot ship broken syntax — the
//    builders drop anything they can't render correctly and say so. It also
//    means loading a package into the builder is exact: the form ends up in the
//    state that produced the query, ready to keep editing.
//
// 2. EVERY SCHEMA REFERENCE IS VERIFIED, NOT REMEMBERED. KQL tables and columns
//    come from src/data/kql.ts (verified against Microsoft Learn's Defender XDR
//    advanced-hunting and Azure Monitor schema references). SentinelOne fields
//    come from src/data/s1.ts, which carries its own per-field provenance. SPL
//    is the one language with no universal schema — a field name there depends
//    on how the data was onboarded — so every SPL package states its assumed
//    index, sourcetype and add-on in `dataSource` rather than pretending the
//    names are universal. Where the field names come from Sysmon's own event
//    schema they're noted as such, because those are stable; where they come
//    from the Splunk Add-on for Microsoft Windows's parsing of a Security-log
//    message body, that's noted too, because those are not.
//
// ATT&CK ids are checked against ATTACK_TECHNIQUES at test time
// (test/queryPackages.test.ts), so a package can never link to a technique
// page this site doesn't have.

import { buildKqlQuery, type KqlQuerySpec } from '../utils/kql';
import { buildSplQuery, type SplQuerySpec } from '../utils/spl';
import { buildS1Query, type S1QuerySpec } from '../utils/s1';

export type QueryLanguage = 'kql' | 'spl' | 's1';

/** Investigation shape a package belongs to. Drives the grouping on each
 *  builder page and the option-groups in the loader. */
export type PackageTheme =
  | 'Execution & scripting'
  | 'Credential access'
  | 'Lateral movement'
  | 'Persistence'
  | 'Command & control'
  | 'Collection & staging'
  | 'Frequency analysis';

interface QueryPackageBase {
  /** Stable id — also the value of the loader's <option>. */
  id: string;
  title: string;
  /** One line: what this finds. Not what it is, what it finds. */
  finds: string;
  theme: PackageTheme;
  /** The telemetry this needs, named precisely enough to check against your
   *  own environment before you run it. */
  dataSource: string;
  /** Where the false positives come from, and what to do about them. */
  tuning: string;
  /** A technique id that resolves on this site's own ATT&CK map. Omitted where
   *  the package is a hunting method rather than a search for one technique. */
  attack?: string;
}

export interface KqlPackage extends QueryPackageBase {
  language: 'kql';
  spec: KqlQuerySpec;
}
export interface SplPackage extends QueryPackageBase {
  language: 'spl';
  spec: SplQuerySpec;
}
export interface S1Package extends QueryPackageBase {
  language: 's1';
  spec: S1QuerySpec;
}

export type QueryPackage = KqlPackage | SplPackage | S1Package;

// ---------------------------------------------------------------------------
// KQL — Microsoft Defender XDR advanced hunting & Microsoft Sentinel
// ---------------------------------------------------------------------------

const DEFENDER_PROCESS = 'Defender for Endpoint process telemetry (DeviceProcessEvents), queried from the Microsoft Defender portal’s advanced hunting page.';
const DEFENDER_NETWORK = 'Defender for Endpoint network telemetry (DeviceNetworkEvents).';
const DEFENDER_FILE = 'Defender for Endpoint file telemetry (DeviceFileEvents).';
const DEFENDER_LOGON = 'Defender for Endpoint authentication telemetry (DeviceLogonEvents).';
const DEFENDER_REGISTRY = 'Defender for Endpoint registry telemetry (DeviceRegistryEvents).';
const SENTINEL_SECURITY = 'Windows Security auditing events forwarded into a Log Analytics workspace (SecurityEvent). Needs the relevant audit subcategory enabled on the source hosts.';
const SENTINEL_SIGNIN = 'Microsoft Entra ID interactive sign-in logs streamed into a Log Analytics workspace (SigninLogs).';

export const KQL_PACKAGES: KqlPackage[] = [
  {
    id: 'kql-powershell-encoded',
    language: 'kql',
    title: 'Base64-encoded PowerShell',
    theme: 'Execution & scripting',
    finds: 'PowerShell invoked with an encoded command block instead of readable script text.',
    dataSource: DEFENDER_PROCESS,
    tuning:
      'Some management and packaging products encode their own commands. Baseline which parent processes legitimately do this in your estate and exclude those first, rather than the encoded flag itself.',
    attack: 'T1059',
    spec: {
      table: 'DeviceProcessEvents',
      timespan: '7d',
      where: [
        { column: 'FileName', operatorId: 'in_ci', value: 'powershell.exe, pwsh.exe' },
        { column: 'ProcessCommandLine', operatorId: 'has_any', value: 'encodedcommand, frombase64string' },
      ],
      project: ['Timestamp', 'DeviceName', 'AccountName', 'InitiatingProcessFileName', 'ProcessCommandLine'],
      summarize: null,
      sort: { column: 'Timestamp', direction: 'desc' },
      limit: 100,
    },
  },
  {
    id: 'kql-powershell-suppressed',
    language: 'kql',
    title: 'PowerShell run hidden or with policy bypassed',
    theme: 'Execution & scripting',
    finds: 'PowerShell started with a hidden window, an execution-policy bypass, or a suppressed profile.',
    dataSource: DEFENDER_PROCESS,
    tuning:
      'Software installers and login scripts use these flags routinely. The signal is the combination with an unexpected parent, so keep InitiatingProcessFileName in the output and stack on it.',
    attack: 'T1059',
    spec: {
      table: 'DeviceProcessEvents',
      timespan: '7d',
      where: [
        { column: 'FileName', operatorId: 'in_ci', value: 'powershell.exe, pwsh.exe' },
        { column: 'ProcessCommandLine', operatorId: 'has_any', value: 'hidden, bypass, noprofile' },
      ],
      project: ['Timestamp', 'DeviceName', 'AccountName', 'InitiatingProcessFileName', 'ProcessCommandLine'],
      summarize: null,
      sort: { column: 'Timestamp', direction: 'desc' },
      limit: 100,
    },
  },
  {
    id: 'kql-office-spawns-shell',
    language: 'kql',
    title: 'Office application spawning a shell',
    theme: 'Execution & scripting',
    finds: 'Word, Excel, or Outlook starting a command interpreter — the classic macro execution chain.',
    dataSource: DEFENDER_PROCESS,
    tuning:
      'Add-ins and document-automation tooling produce this legitimately. Match on the child command line rather than the pairing alone once you know which add-ins are normal for you.',
    attack: 'T1204',
    spec: {
      table: 'DeviceProcessEvents',
      timespan: '7d',
      where: [
        { column: 'InitiatingProcessFileName', operatorId: 'in_ci', value: 'winword.exe, excel.exe, powerpnt.exe, outlook.exe' },
        { column: 'FileName', operatorId: 'in_ci', value: 'cmd.exe, powershell.exe, pwsh.exe, wscript.exe, cscript.exe, mshta.exe' },
      ],
      project: ['Timestamp', 'DeviceName', 'AccountName', 'InitiatingProcessFileName', 'FileName', 'ProcessCommandLine'],
      summarize: null,
      sort: { column: 'Timestamp', direction: 'desc' },
      limit: 100,
    },
  },
  {
    id: 'kql-lolbin-execution',
    language: 'kql',
    title: 'Signed-binary proxy execution (LOLBins)',
    theme: 'Execution & scripting',
    finds: 'Execution of the signed Microsoft binaries most often used to run attacker code without dropping a new executable.',
    dataSource: DEFENDER_PROCESS,
    tuning:
      'Every one of these binaries has a legitimate job. This is a stack-counting starting point, not an alert — summarize by FileName and command line and work the rare tail.',
    attack: 'T1218',
    spec: {
      table: 'DeviceProcessEvents',
      timespan: '1d',
      where: [
        {
          column: 'FileName',
          operatorId: 'in_ci',
          value: 'rundll32.exe, regsvr32.exe, mshta.exe, certutil.exe, bitsadmin.exe, wmic.exe, msbuild.exe, installutil.exe, regasm.exe, regsvcs.exe, cmstp.exe, forfiles.exe',
        },
      ],
      project: ['Timestamp', 'DeviceName', 'AccountName', 'FileName', 'ProcessCommandLine', 'InitiatingProcessFileName'],
      summarize: null,
      sort: { column: 'Timestamp', direction: 'desc' },
      limit: 200,
    },
  },
  {
    id: 'kql-certutil-transfer',
    language: 'kql',
    title: 'certutil used to fetch or decode a payload',
    theme: 'Execution & scripting',
    finds: 'certutil.exe invoked with the flags that turn a certificate utility into a downloader or a base64 decoder.',
    dataSource: DEFENDER_PROCESS,
    tuning:
      'Genuine certificate work uses certutil too, but rarely with urlcache or decode. Treat any hit outside a PKI administration context as worth reading in full.',
    attack: 'T1105',
    spec: {
      table: 'DeviceProcessEvents',
      timespan: '7d',
      where: [
        { column: 'FileName', operatorId: 'eq_ci', value: 'certutil.exe' },
        { column: 'ProcessCommandLine', operatorId: 'has_any', value: 'urlcache, decode, encode, verifyctl' },
      ],
      project: ['Timestamp', 'DeviceName', 'AccountName', 'ProcessCommandLine', 'InitiatingProcessFileName'],
      summarize: null,
      sort: { column: 'Timestamp', direction: 'desc' },
      limit: 100,
    },
  },
  {
    id: 'kql-execution-from-public',
    language: 'kql',
    title: 'Execution from a world-writable path',
    theme: 'Execution & scripting',
    finds: 'Processes launched out of C:\\Users\\Public, a directory any user can write to.',
    dataSource: DEFENDER_PROCESS,
    tuning:
      'Some vendor installers stage there briefly. Sort by FolderPath and exclude the paths you can attribute to a known product rather than excluding the whole tree.',
    attack: 'T1204',
    spec: {
      table: 'DeviceProcessEvents',
      timespan: '7d',
      where: [{ column: 'FolderPath', operatorId: 'startswith', value: 'C:\\Users\\Public' }],
      project: ['Timestamp', 'DeviceName', 'AccountName', 'FileName', 'FolderPath', 'ProcessCommandLine'],
      summarize: null,
      sort: { column: 'Timestamp', direction: 'desc' },
      limit: 100,
    },
  },
  {
    id: 'kql-lsass-in-command-line',
    language: 'kql',
    title: 'LSASS named on a command line',
    theme: 'Credential access',
    finds: 'Any process invoked with lsass in its arguments — the shape most credential-dumping tooling leaves behind.',
    dataSource: DEFENDER_PROCESS,
    tuning:
      'Legitimate crash-dump and diagnostic tooling can name LSASS. Read the full command line on every hit; there should be few enough that you can.',
    attack: 'T1003.001',
    spec: {
      table: 'DeviceProcessEvents',
      timespan: '30d',
      where: [{ column: 'ProcessCommandLine', operatorId: 'contains', value: 'lsass' }],
      project: ['Timestamp', 'DeviceName', 'AccountName', 'FileName', 'FolderPath', 'ProcessCommandLine', 'InitiatingProcessFileName'],
      summarize: null,
      sort: { column: 'Timestamp', direction: 'desc' },
      limit: 100,
    },
  },
  {
    id: 'kql-comsvcs-minidump',
    language: 'kql',
    title: 'rundll32 driving the comsvcs.dll dump export',
    theme: 'Credential access',
    finds: 'The living-off-the-land process-dumping path that needs no attacker binary on disk at all.',
    dataSource: DEFENDER_PROCESS,
    tuning:
      'There is close to no benign reason for this pairing. Anything returned here is worth escalating rather than tuning away.',
    attack: 'T1003.001',
    spec: {
      table: 'DeviceProcessEvents',
      timespan: '30d',
      where: [
        { column: 'FileName', operatorId: 'eq_ci', value: 'rundll32.exe' },
        { column: 'ProcessCommandLine', operatorId: 'contains', value: 'comsvcs' },
      ],
      project: ['Timestamp', 'DeviceName', 'AccountName', 'ProcessCommandLine', 'InitiatingProcessFileName'],
      summarize: null,
      sort: { column: 'Timestamp', direction: 'desc' },
      limit: 100,
    },
  },
  {
    id: 'kql-failed-logon-spread',
    language: 'kql',
    title: 'One source failing against many accounts',
    theme: 'Credential access',
    finds: 'Source addresses that failed to log on to an unusually wide set of accounts — the password-spraying shape.',
    dataSource: DEFENDER_LOGON,
    tuning:
      'A misconfigured service account or a stale credential on a shared host produces volume against ONE account. The number that matters here is the distinct-account count, not the attempt count.',
    attack: 'T1110',
    spec: {
      table: 'DeviceLogonEvents',
      timespan: '1d',
      where: [{ column: 'ActionType', operatorId: 'eq_ci', value: 'LogonFailed' }],
      project: [],
      summarize: { aggregationId: 'dcount', aggColumn: 'AccountName', by: ['RemoteIP', 'DeviceName'], binColumn: '', binSize: '' },
      sort: { column: 'DistinctCount', direction: 'desc' },
      limit: 50,
    },
  },
  {
    id: 'kql-signin-failures-by-source',
    language: 'kql',
    title: 'Entra ID sign-in failures by source address',
    theme: 'Credential access',
    finds: 'Failed interactive sign-ins grouped by originating IP and account.',
    dataSource: SENTINEL_SIGNIN,
    tuning:
      'ResultType is 0 on success, so anything else is a failure — including expected ones like an expired password. Pivot on ResultType before treating a cluster as an attack.',
    attack: 'T1110',
    spec: {
      table: 'SigninLogs',
      timespan: '1d',
      where: [{ column: 'ResultType', operatorId: 'neq', value: '0' }],
      project: [],
      summarize: { aggregationId: 'count', aggColumn: '', by: ['IPAddress', 'UserPrincipalName'], binColumn: '', binSize: '' },
      sort: { column: 'Count', direction: 'desc' },
      limit: 50,
    },
  },
  {
    id: 'kql-rdp-inbound',
    language: 'kql',
    title: 'Inbound RDP sessions by source',
    theme: 'Lateral movement',
    finds: 'Remote interactive logons, grouped by the device reached and the address they came from.',
    dataSource: DEFENDER_LOGON,
    tuning:
      'Jump hosts and admin workstations dominate the top of this list and should. The interesting rows are the ones near the bottom: a source that reached exactly one host, once.',
    attack: 'T1021',
    spec: {
      table: 'DeviceLogonEvents',
      timespan: '7d',
      where: [{ column: 'LogonType', operatorId: 'eq_ci', value: 'RemoteInteractive' }],
      project: [],
      summarize: { aggregationId: 'count', aggColumn: '', by: ['DeviceName', 'RemoteIP'], binColumn: '', binSize: '' },
      sort: { column: 'Count', direction: 'desc' },
      limit: 100,
    },
  },
  {
    id: 'kql-smb-remote-write',
    language: 'kql',
    title: 'Files written to a host over SMB',
    theme: 'Lateral movement',
    finds: 'File activity a remote machine initiated across a share, with the source address and account that did it.',
    dataSource: DEFENDER_FILE,
    tuning:
      'Backup agents, deployment tooling and roaming profiles all write over SMB. Filter to executable and script extensions, or to shares that should never receive writes.',
    attack: 'T1021',
    spec: {
      table: 'DeviceFileEvents',
      timespan: '7d',
      where: [{ column: 'RequestProtocol', operatorId: 'eq_ci', value: 'SMB' }],
      project: ['Timestamp', 'DeviceName', 'FileName', 'FolderPath', 'ShareName', 'RequestSourceIP', 'RequestAccountName'],
      summarize: null,
      sort: { column: 'Timestamp', direction: 'desc' },
      limit: 200,
    },
  },
  {
    id: 'kql-wmi-spawned',
    language: 'kql',
    title: 'Processes spawned by the WMI provider host',
    theme: 'Lateral movement',
    finds: 'Anything WmiPrvSE.exe started — the endpoint-side trace of remote WMI execution.',
    dataSource: DEFENDER_PROCESS,
    tuning:
      'Monitoring and inventory products drive WMI constantly. Stack the child command lines first; the ones worth reading are the interpreters and the one-offs.',
    attack: 'T1047',
    spec: {
      table: 'DeviceProcessEvents',
      timespan: '7d',
      where: [{ column: 'InitiatingProcessFileName', operatorId: 'eq_ci', value: 'wmiprvse.exe' }],
      project: ['Timestamp', 'DeviceName', 'AccountName', 'FileName', 'ProcessCommandLine'],
      summarize: null,
      sort: { column: 'Timestamp', direction: 'desc' },
      limit: 200,
    },
  },
  {
    id: 'kql-winrm-spawned',
    language: 'kql',
    title: 'Processes spawned by the WinRM host',
    theme: 'Lateral movement',
    finds: 'Anything wsmprovhost.exe started — what remote PowerShell looks like from the receiving end.',
    dataSource: DEFENDER_PROCESS,
    tuning:
      'Legitimate remote administration lands here too. Correlate against who is expected to hold WinRM access to the target host rather than against the command line alone.',
    attack: 'T1021',
    spec: {
      table: 'DeviceProcessEvents',
      timespan: '7d',
      where: [{ column: 'InitiatingProcessFileName', operatorId: 'eq_ci', value: 'wsmprovhost.exe' }],
      project: ['Timestamp', 'DeviceName', 'AccountName', 'FileName', 'ProcessCommandLine'],
      summarize: null,
      sort: { column: 'Timestamp', direction: 'desc' },
      limit: 200,
    },
  },
  {
    id: 'kql-run-key-persistence',
    language: 'kql',
    title: 'Run-key persistence written over time',
    theme: 'Persistence',
    finds: 'Writes under a CurrentVersion\\Run key, bucketed by hour so a burst stands out from steady background churn.',
    dataSource: DEFENDER_REGISTRY,
    tuning:
      'Installers write Run keys legitimately. The hourly bucket is the point — one device writing several in the same hour is a different story from one write a week.',
    attack: 'T1547',
    spec: {
      table: 'DeviceRegistryEvents',
      timespan: '7d',
      where: [{ column: 'RegistryKey', operatorId: 'contains', value: 'CurrentVersion\\Run' }],
      project: [],
      summarize: { aggregationId: 'count', aggColumn: '', by: ['DeviceName'], binColumn: 'Timestamp', binSize: '1h' },
      sort: { column: 'Count', direction: 'desc' },
      limit: 100,
    },
  },
  {
    id: 'kql-scheduled-task-cli',
    language: 'kql',
    title: 'Scheduled tasks created from the command line',
    theme: 'Persistence',
    finds: 'schtasks.exe invoked to create a task, with the full arguments that say what the task will run.',
    dataSource: DEFENDER_PROCESS,
    tuning:
      'Software deployment creates tasks this way. Read the /tr argument on each hit — that is the payload, and it is usually enough to triage in one pass.',
    attack: 'T1053.005',
    spec: {
      table: 'DeviceProcessEvents',
      timespan: '30d',
      where: [
        { column: 'FileName', operatorId: 'eq_ci', value: 'schtasks.exe' },
        { column: 'ProcessCommandLine', operatorId: 'has', value: 'create' },
      ],
      project: ['Timestamp', 'DeviceName', 'AccountName', 'ProcessCommandLine', 'InitiatingProcessFileName'],
      summarize: null,
      sort: { column: 'Timestamp', direction: 'desc' },
      limit: 100,
    },
  },
  {
    id: 'kql-service-installed',
    language: 'kql',
    title: 'New Windows services installed',
    theme: 'Persistence',
    finds: 'Service installations recorded by Windows auditing, with the binary each new service points at.',
    dataSource: SENTINEL_SECURITY,
    tuning:
      'Patch cycles produce clusters of these. The field to read first is ServiceFileName — a service whose binary lives outside a program directory is the one to pull on.',
    attack: 'T1543.003',
    spec: {
      table: 'SecurityEvent',
      timespan: '30d',
      where: [{ column: 'EventID', operatorId: 'eq', value: '4697' }],
      project: ['TimeGenerated', 'Computer', 'SubjectUserName', 'ServiceName', 'ServiceFileName'],
      summarize: null,
      sort: { column: 'TimeGenerated', direction: 'desc' },
      limit: 100,
    },
  },
  {
    id: 'kql-public-destination-fanout',
    language: 'kql',
    title: 'Processes reaching many public destinations',
    theme: 'Command & control',
    finds: 'Processes talking to an unusually wide set of public addresses — scanning behaviour, or an implant inside an ordinary-looking binary.',
    dataSource: DEFENDER_NETWORK,
    tuning:
      'Browsers, updaters and CDN clients top this list by design. Exclude those by name and look at what is left, especially anything running from a user-writable path.',
    attack: 'T1071',
    spec: {
      table: 'DeviceNetworkEvents',
      timespan: '1d',
      where: [{ column: 'RemoteIPType', operatorId: 'eq', value: 'Public' }],
      project: [],
      summarize: { aggregationId: 'dcount', aggColumn: 'RemoteIP', by: ['InitiatingProcessFileName', 'DeviceName'], binColumn: '', binSize: '' },
      sort: { column: 'DistinctCount', direction: 'desc' },
      limit: 50,
    },
  },
  {
    id: 'kql-beacon-hourly',
    language: 'kql',
    title: 'Hourly connection counts per destination',
    theme: 'Command & control',
    finds: 'Connections to each public destination bucketed by the hour, so a flat, evenly-spaced count is visible as a shape.',
    dataSource: DEFENDER_NETWORK,
    tuning:
      "Beaconing shows up as a count that barely varies hour to hour, not as a big number. Sort by the bucket rather than the count once you have a candidate destination, and read it as a series.",
    attack: 'T1071',
    spec: {
      table: 'DeviceNetworkEvents',
      timespan: '1d',
      where: [{ column: 'RemoteIPType', operatorId: 'eq', value: 'Public' }],
      project: [],
      summarize: { aggregationId: 'count', aggColumn: '', by: ['RemoteIP', 'InitiatingProcessFileName'], binColumn: 'Timestamp', binSize: '1h' },
      sort: { column: 'Count', direction: 'desc' },
      limit: 200,
    },
  },
  {
    id: 'kql-downloaded-executables',
    language: 'kql',
    title: 'Executables written with download provenance',
    theme: 'Collection & staging',
    finds: 'Executable files that arrived with a recorded origin URL — what was downloaded, by what, from where.',
    dataSource: DEFENDER_FILE,
    tuning:
      'Ordinary software downloads land here. Group by FileOriginUrl and work the domains you cannot attribute to a known vendor.',
    attack: 'T1105',
    spec: {
      table: 'DeviceFileEvents',
      timespan: '7d',
      where: [
        { column: 'FileName', operatorId: 'endswith', value: '.exe' },
        { column: 'FileOriginUrl', operatorId: 'isnotempty', value: '' },
      ],
      project: ['Timestamp', 'DeviceName', 'FileName', 'FolderPath', 'FileOriginUrl', 'InitiatingProcessFileName'],
      summarize: null,
      sort: { column: 'Timestamp', direction: 'desc' },
      limit: 200,
    },
  },
  {
    id: 'kql-archive-staging',
    language: 'kql',
    title: 'Archive utilities run on an endpoint',
    theme: 'Collection & staging',
    finds: 'Command-line archiving tools — the step that usually comes immediately before data leaves.',
    dataSource: DEFENDER_PROCESS,
    tuning:
      'Developers and backup jobs use these daily. Read the command line for a password flag or an output path under a user profile; those two together are the pattern worth chasing.',
    attack: 'T1560',
    spec: {
      table: 'DeviceProcessEvents',
      timespan: '7d',
      where: [{ column: 'FileName', operatorId: 'in_ci', value: '7z.exe, 7za.exe, rar.exe, winrar.exe, tar.exe, makecab.exe' }],
      project: ['Timestamp', 'DeviceName', 'AccountName', 'FileName', 'FolderPath', 'ProcessCommandLine'],
      summarize: null,
      sort: { column: 'Timestamp', direction: 'desc' },
      limit: 200,
    },
  },
  {
    id: 'kql-rare-executables',
    language: 'kql',
    title: 'Executables seen on very few devices',
    theme: 'Frequency analysis',
    finds: 'Binaries that ran on the smallest number of distinct machines — the long tail where new tooling lives.',
    dataSource: DEFENDER_PROCESS,
    tuning:
      "Rarity is not badness. Almost everything at the top of this list will be a one-off installer or a developer's own build; the value is that the list is short enough to actually read.",
    spec: {
      table: 'DeviceProcessEvents',
      timespan: '30d',
      where: [{ column: 'FileName', operatorId: 'endswith', value: '.exe' }],
      project: [],
      summarize: { aggregationId: 'dcount', aggColumn: 'DeviceName', by: ['FileName'], binColumn: '', binSize: '' },
      sort: { column: 'DistinctCount', direction: 'asc' },
      limit: 100,
    },
  },
  {
    id: 'kql-rare-parent-child',
    language: 'kql',
    title: 'Uncommon parent/child process pairs',
    theme: 'Frequency analysis',
    finds: 'Parent-to-child launch pairings that almost never happen in your environment.',
    dataSource: DEFENDER_PROCESS,
    tuning:
      'Every environment has a stable set of normal pairings; the rare ones are where an unexpected chain shows. Work upward from the bottom of the list and whitelist as you confirm each pairing.',
    spec: {
      table: 'DeviceProcessEvents',
      timespan: '7d',
      where: [{ column: 'FileName', operatorId: 'endswith', value: '.exe' }],
      project: [],
      summarize: { aggregationId: 'count', aggColumn: '', by: ['InitiatingProcessFileName', 'FileName'], binColumn: '', binSize: '' },
      sort: { column: 'Count', direction: 'asc' },
      limit: 100,
    },
  },
];

// ---------------------------------------------------------------------------
// SPL — Splunk
//
// SPL has no universal schema: a field name depends entirely on how the data
// was onboarded. Each package below therefore names the index, sourcetype, and
// add-on it assumes, and each falls into one of two field families:
//
//   - SYSMON packages use Sysmon's OWN event field names (Image, CommandLine,
//     ParentImage, TargetImage, TargetObject, QueryName, ...). Those come from
//     Sysmon's event schema itself and are passed through unchanged by the
//     Splunk Add-on for Sysmon, so they are stable across deployments.
//   - WINDOWS SECURITY packages use the underscore field names the Splunk
//     Add-on for Microsoft Windows extracts from the Security event's message
//     body (Account_Name, Logon_Type, Source_Network_Address, ...). Those
//     depend on the add-on and its version — check them against your own data
//     before trusting a zero-result run.
//
// Every package states which family it is in. None of them assume CIM
// normalization, because a query that silently needs a data model is worse than
// one that says what it needs.
// ---------------------------------------------------------------------------

const SYSMON_SOURCE =
  'Sysmon operational log via the Splunk Add-on for Sysmon (sourcetype XmlWinEventLog:Microsoft-Windows-Sysmon/Operational). Field names are Sysmon’s own, so they hold across deployments — but the event ID has to be enabled in your Sysmon configuration first.';
const WINSEC_SOURCE =
  'Windows Security log via the Splunk Add-on for Microsoft Windows (sourcetype WinEventLog:Security). The underscore field names come from the add-on’s parsing of the event message body — confirm them against your own data before trusting an empty result.';

export const SPL_PACKAGES: SplPackage[] = [
  {
    id: 'spl-encoded-powershell',
    language: 'spl',
    title: 'Base64-encoded PowerShell',
    theme: 'Execution & scripting',
    finds: 'Sysmon process-creation events whose command line carries an encoded PowerShell block.',
    dataSource: SYSMON_SOURCE + ' Needs Sysmon event ID 1.',
    tuning:
      'The wildcard match is deliberately loose so it catches the abbreviated forms of the flag. Expect a handful of management tools; baseline by ParentImage.',
    attack: 'T1059',
    spec: {
      base: {
        index: 'endpoint',
        sourcetype: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
        earliest: '-7d@d',
        latest: 'now',
        filters: [
          { field: 'EventCode', operator: '=', value: '1' },
          { field: 'CommandLine', operator: '=', value: '*-enc*' },
        ],
      },
      commands: [
        { kind: 'table', fields: ['_time', 'host', 'User', 'ParentImage', 'Image', 'CommandLine'] },
        { kind: 'sort', limit: '0', fields: [{ field: '_time', direction: 'desc' }] },
      ],
    },
  },
  {
    id: 'spl-rare-parent-child',
    language: 'spl',
    title: 'Uncommon parent/child process pairs',
    theme: 'Frequency analysis',
    finds: 'Parent-to-child launch pairings that occurred fewer than five times across the whole window.',
    dataSource: SYSMON_SOURCE + ' Needs Sysmon event ID 1.',
    tuning:
      'Raise the threshold on a large estate and lower it on a small one — five is a starting point, not a constant. Confirm each pairing once and exclude it, and the list gets useful fast.',
    spec: {
      base: {
        index: 'endpoint',
        sourcetype: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
        earliest: '-7d@d',
        latest: 'now',
        filters: [{ field: 'EventCode', operator: '=', value: '1' }],
      },
      commands: [
        { kind: 'stats', aggregations: [{ fn: 'count', field: '', alias: '' }, { fn: 'dc', field: 'host', alias: 'hosts' }], by: ['ParentImage', 'Image'] },
        { kind: 'where', left: 'count', operator: '<', right: '5', rightKind: 'number' },
        { kind: 'sort', limit: '0', fields: [{ field: 'count', direction: 'asc' }] },
        { kind: 'table', fields: ['count', 'hosts', 'ParentImage', 'Image'] },
      ],
    },
  },
  {
    id: 'spl-lsass-process-access',
    language: 'spl',
    title: 'Processes opening a handle to LSASS',
    theme: 'Credential access',
    finds: 'Sysmon process-access events targeting lsass.exe, grouped by who asked and what access they asked for.',
    dataSource: SYSMON_SOURCE + ' Needs Sysmon event ID 10, which is off by default and noisy without filters.',
    tuning:
      'Endpoint security products and diagnostics open LSASS constantly. Exclude those SourceImage values, then read the GrantedAccess mask — the memory-read rights are the ones that matter.',
    attack: 'T1003.001',
    spec: {
      base: {
        index: 'endpoint',
        sourcetype: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
        earliest: '-7d@d',
        latest: 'now',
        filters: [
          { field: 'EventCode', operator: '=', value: '10' },
          { field: 'TargetImage', operator: '=', value: '*lsass.exe' },
        ],
      },
      commands: [
        { kind: 'stats', aggregations: [{ fn: 'count', field: '', alias: '' }, { fn: 'dc', field: 'host', alias: 'hosts' }], by: ['SourceImage', 'GrantedAccess'] },
        { kind: 'sort', limit: '0', fields: [{ field: 'count', direction: 'desc' }] },
      ],
    },
  },
  {
    id: 'spl-failed-logons-by-source',
    language: 'spl',
    title: 'Failed logons by source address',
    theme: 'Credential access',
    finds: 'Windows logon failures counted per originating address, with how many distinct accounts each one touched.',
    dataSource: WINSEC_SOURCE + ' Needs event ID 4625, which requires Audit Logon failure auditing.',
    tuning:
      'A single stale credential produces high volume against one account. Read the distinct-account column, not the attempt count — that is what separates a broken service from a spray.',
    attack: 'T1110',
    spec: {
      base: {
        index: 'wineventlog',
        sourcetype: 'WinEventLog:Security',
        earliest: '-24h@h',
        latest: 'now',
        filters: [{ field: 'EventCode', operator: '=', value: '4625' }],
      },
      commands: [
        {
          kind: 'stats',
          aggregations: [
            { fn: 'count', field: '', alias: 'attempts' },
            { fn: 'dc', field: 'Account_Name', alias: 'accounts_tried' },
          ],
          by: ['Source_Network_Address'],
        },
        { kind: 'sort', limit: '20', fields: [{ field: 'accounts_tried', direction: 'desc' }] },
      ],
    },
  },
  {
    id: 'spl-rdp-successful-logons',
    language: 'spl',
    title: 'Successful RDP logons',
    theme: 'Lateral movement',
    finds: 'Logon type 10 successes, grouped by account and source address.',
    dataSource: WINSEC_SOURCE + ' Needs event ID 4624.',
    tuning:
      'Admin jump hosts dominate. The rows worth reading are the pairings you have never seen before, so keep a copy of last month’s result and diff against it.',
    attack: 'T1021',
    spec: {
      base: {
        index: 'wineventlog',
        sourcetype: 'WinEventLog:Security',
        earliest: '-7d@d',
        latest: 'now',
        filters: [
          { field: 'EventCode', operator: '=', value: '4624' },
          { field: 'Logon_Type', operator: '=', value: '10' },
        ],
      },
      commands: [
        { kind: 'stats', aggregations: [{ fn: 'count', field: '', alias: '' }, { fn: 'dc', field: 'host', alias: 'hosts_reached' }], by: ['Account_Name', 'Source_Network_Address'] },
        { kind: 'sort', limit: '50', fields: [{ field: 'count', direction: 'desc' }] },
      ],
    },
  },
  {
    id: 'spl-share-access',
    language: 'spl',
    title: 'Detailed file-share access',
    theme: 'Lateral movement',
    finds: 'Which accounts touched which paths on a share, and from where.',
    dataSource: WINSEC_SOURCE + ' Needs event ID 5145, which requires Audit Detailed File Share auditing — very high volume, enable it deliberately.',
    tuning:
      'This is one of the noisiest events Windows produces. Scope it to a single sensitive share by adding a Share_Name filter before running it anywhere real.',
    attack: 'T1021',
    spec: {
      base: {
        index: 'wineventlog',
        sourcetype: 'WinEventLog:Security',
        earliest: '-24h@h',
        latest: 'now',
        filters: [{ field: 'EventCode', operator: '=', value: '5145' }],
      },
      commands: [
        { kind: 'stats', aggregations: [{ fn: 'count', field: '', alias: '' }, { fn: 'dc', field: 'Relative_Target_Name', alias: 'paths' }], by: ['Account_Name', 'Source_Address', 'Share_Name'] },
        { kind: 'sort', limit: '100', fields: [{ field: 'paths', direction: 'desc' }] },
      ],
    },
  },
  {
    id: 'spl-wmi-remote-exec',
    language: 'spl',
    title: 'Processes spawned by the WMI provider host',
    theme: 'Lateral movement',
    finds: 'Sysmon process creations whose parent is WmiPrvSE.exe — the endpoint trace of remote WMI execution.',
    dataSource: SYSMON_SOURCE + ' Needs Sysmon event ID 1.',
    tuning:
      'Inventory and monitoring agents use WMI heavily. Stack Image first; the interesting rows are interpreters and one-off binaries.',
    attack: 'T1047',
    spec: {
      base: {
        index: 'endpoint',
        sourcetype: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
        earliest: '-7d@d',
        latest: 'now',
        filters: [
          { field: 'EventCode', operator: '=', value: '1' },
          { field: 'ParentImage', operator: '=', value: '*\\WmiPrvSE.exe' },
        ],
      },
      commands: [
        { kind: 'table', fields: ['_time', 'host', 'User', 'Image', 'CommandLine'] },
        { kind: 'sort', limit: '0', fields: [{ field: '_time', direction: 'desc' }] },
      ],
    },
  },
  {
    id: 'spl-run-key-persistence',
    language: 'spl',
    title: 'Registry Run-key writes',
    theme: 'Persistence',
    finds: 'Sysmon registry value-set events under a CurrentVersion\\Run key, with the data that was written.',
    dataSource: SYSMON_SOURCE + ' Needs Sysmon event ID 13 and a configuration that does not exclude the Run keys.',
    tuning:
      'Installers write these legitimately. Details holds the command the key will run — that field, not the key path, is what tells you whether to care.',
    attack: 'T1547',
    spec: {
      base: {
        index: 'endpoint',
        sourcetype: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
        earliest: '-7d@d',
        latest: 'now',
        filters: [
          { field: 'EventCode', operator: '=', value: '13' },
          { field: 'TargetObject', operator: '=', value: '*CurrentVersion\\Run*' },
        ],
      },
      commands: [
        { kind: 'table', fields: ['_time', 'host', 'Image', 'TargetObject', 'Details'] },
        { kind: 'sort', limit: '0', fields: [{ field: '_time', direction: 'desc' }] },
      ],
    },
  },
  {
    id: 'spl-service-installed',
    language: 'spl',
    title: 'New Windows services installed',
    theme: 'Persistence',
    finds: 'Service installation events with the binary each new service is configured to run.',
    dataSource: WINSEC_SOURCE + ' Needs event ID 4697, which requires Audit Security System Extension auditing.',
    tuning:
      'Patch windows produce bursts. Read Service_File_Name — a service binary outside a program directory, or one with arguments, is the row to pull on.',
    attack: 'T1543.003',
    spec: {
      base: {
        index: 'wineventlog',
        sourcetype: 'WinEventLog:Security',
        earliest: '-30d@d',
        latest: 'now',
        filters: [{ field: 'EventCode', operator: '=', value: '4697' }],
      },
      commands: [
        { kind: 'table', fields: ['_time', 'host', 'Account_Name', 'Service_Name', 'Service_File_Name'] },
        { kind: 'sort', limit: '0', fields: [{ field: '_time', direction: 'desc' }] },
      ],
    },
  },
  {
    id: 'spl-scheduled-task-created',
    language: 'spl',
    title: 'Scheduled tasks created',
    theme: 'Persistence',
    finds: 'Task-registration events, newest first.',
    dataSource: WINSEC_SOURCE + ' Needs event ID 4698, which requires Audit Other Object Access Events.',
    tuning:
      'Software deployment creates tasks constantly. The name alone rarely decides it — pull the task content from the raw event once a name looks unfamiliar.',
    attack: 'T1053.005',
    spec: {
      base: {
        index: 'wineventlog',
        sourcetype: 'WinEventLog:Security',
        earliest: '-30d@d',
        latest: 'now',
        filters: [{ field: 'EventCode', operator: '=', value: '4698' }],
      },
      commands: [
        { kind: 'table', fields: ['_time', 'host', 'Account_Name', 'Task_Name'] },
        { kind: 'sort', limit: '0', fields: [{ field: '_time', direction: 'desc' }] },
      ],
    },
  },
  {
    id: 'spl-outbound-fanout',
    language: 'spl',
    title: 'Processes reaching many destinations',
    theme: 'Command & control',
    finds: 'Sysmon network connections aggregated per process, worst fan-out first.',
    dataSource: SYSMON_SOURCE + ' Needs Sysmon event ID 3, which is off by default.',
    tuning:
      'Browsers and updaters own the top of this list. Exclude them by Image and read what remains, especially anything running from a user-writable path.',
    attack: 'T1071',
    spec: {
      base: {
        index: 'endpoint',
        sourcetype: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
        earliest: '-24h@h',
        latest: 'now',
        filters: [{ field: 'EventCode', operator: '=', value: '3' }],
      },
      commands: [
        {
          kind: 'stats',
          aggregations: [
            { fn: 'count', field: '', alias: 'connections' },
            { fn: 'dc', field: 'DestinationIp', alias: 'destinations' },
            { fn: 'dc', field: 'DestinationPort', alias: 'ports' },
          ],
          by: ['Image'],
        },
        { kind: 'sort', limit: '50', fields: [{ field: 'destinations', direction: 'desc' }] },
      ],
    },
  },
  {
    id: 'spl-beacon-candidates',
    language: 'spl',
    title: 'High-volume single-destination talkers',
    theme: 'Command & control',
    finds: 'Process-to-destination pairs with a high connection count and almost no port variety — the beaconing shape.',
    dataSource: SYSMON_SOURCE + ' Needs Sysmon event ID 3.',
    tuning:
      'Volume alone is not beaconing; regularity is. Use this to shortlist candidate pairs, then go back to the raw events for those pairs and look at the interval between connections.',
    attack: 'T1071',
    spec: {
      base: {
        index: 'endpoint',
        sourcetype: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
        earliest: '-24h@h',
        latest: 'now',
        filters: [{ field: 'EventCode', operator: '=', value: '3' }],
      },
      commands: [
        {
          kind: 'stats',
          aggregations: [
            { fn: 'count', field: '', alias: 'connections' },
            { fn: 'dc', field: 'DestinationPort', alias: 'ports' },
          ],
          by: ['host', 'Image', 'DestinationIp'],
        },
        { kind: 'where', left: 'connections', operator: '>', right: '100', rightKind: 'number' },
        { kind: 'sort', limit: '100', fields: [{ field: 'connections', direction: 'desc' }] },
      ],
    },
  },
  {
    id: 'spl-rare-dns-lookups',
    language: 'spl',
    title: 'Domains looked up by very few hosts',
    theme: 'Command & control',
    finds: 'DNS queries whose domain was resolved by fewer than three machines in the window.',
    dataSource: SYSMON_SOURCE + ' Needs Sysmon event ID 22, available on Windows 8.1 and later.',
    tuning:
      'CDN and telemetry hostnames make up most of the tail. Sorting by lookup volume within the rare set surfaces the ones that a single host talked to repeatedly, which is the more interesting half.',
    attack: 'T1071.004',
    spec: {
      base: {
        index: 'endpoint',
        sourcetype: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
        earliest: '-24h@h',
        latest: 'now',
        filters: [{ field: 'EventCode', operator: '=', value: '22' }],
      },
      commands: [
        {
          kind: 'stats',
          aggregations: [
            { fn: 'count', field: '', alias: 'lookups' },
            { fn: 'dc', field: 'host', alias: 'hosts' },
          ],
          by: ['QueryName'],
        },
        { kind: 'where', left: 'hosts', operator: '<', right: '3', rightKind: 'number' },
        { kind: 'sort', limit: '200', fields: [{ field: 'lookups', direction: 'desc' }] },
        { kind: 'table', fields: ['QueryName', 'hosts', 'lookups'] },
      ],
    },
  },
  {
    id: 'spl-archive-staging',
    language: 'spl',
    title: 'Password-protected archive creation',
    theme: 'Collection & staging',
    finds: "Command lines carrying WinRAR's -hp password flag.",
    dataSource: SYSMON_SOURCE + ' Needs Sysmon event ID 1.',
    tuning:
      "Legitimate use exists but is rare enough that the result set stays readable. Look at the output path: a staged "
      + "archive under a user profile or a temp directory is the pattern. Note this catches WinRAR only — 7-Zip spells "
      + "its password switch -p and encrypts file names with -mhe=on, so swap the filter if 7z.exe is what's in your environment.",
    attack: 'T1560',
    spec: {
      base: {
        index: 'endpoint',
        sourcetype: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
        earliest: '-7d@d',
        latest: 'now',
        filters: [
          { field: 'EventCode', operator: '=', value: '1' },
          { field: 'CommandLine', operator: '=', value: '*-hp*' },
        ],
      },
      commands: [
        { kind: 'table', fields: ['_time', 'host', 'User', 'Image', 'CommandLine'] },
        { kind: 'sort', limit: '0', fields: [{ field: '_time', direction: 'desc' }] },
      ],
    },
  },
  {
    id: 'spl-first-seen-binaries',
    language: 'spl',
    title: 'Binaries first seen in this window',
    theme: 'Frequency analysis',
    finds: 'Executables that ran on fewer than three hosts, with the earliest time each one appeared.',
    dataSource: SYSMON_SOURCE + ' Needs Sysmon event ID 1.',
    tuning:
      '"First seen" here only means first seen inside the search window — widen the window and the list shrinks. Run it against a long baseline once, keep the result, and diff.',
    spec: {
      base: {
        index: 'endpoint',
        sourcetype: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
        earliest: '-7d@d',
        latest: 'now',
        filters: [{ field: 'EventCode', operator: '=', value: '1' }],
      },
      commands: [
        {
          kind: 'stats',
          aggregations: [
            { fn: 'min', field: '_time', alias: 'first_seen' },
            { fn: 'count', field: '', alias: 'executions' },
            { fn: 'dc', field: 'host', alias: 'hosts' },
          ],
          by: ['Image'],
        },
        { kind: 'where', left: 'hosts', operator: '<', right: '3', rightKind: 'number' },
        { kind: 'sort', limit: '200', fields: [{ field: 'first_seen', direction: 'desc' }] },
      ],
    },
  },
];

// ---------------------------------------------------------------------------
// SentinelOne PowerQuery
// ---------------------------------------------------------------------------

const S1_SOURCE =
  'SentinelOne agent telemetry in the Singularity Data Lake, run from Event Search / PowerQuery. Set the time range in the console — PowerQuery takes it from the picker, not from the query text.';

export const S1_PACKAGES: S1Package[] = [
  {
    id: 's1-powershell-encoded',
    language: 's1',
    title: 'Base64-encoded PowerShell',
    theme: 'Execution & scripting',
    finds: 'PowerShell launched with an encoded command block rather than readable script text.',
    dataSource: S1_SOURCE,
    tuning:
      'Some management agents encode their own commands. Baseline by src.process.name — the parent — before excluding anything on the child command line.',
    attack: 'T1059',
    spec: {
      filters: [
        { field: 'event.type', operatorId: 'eq', value: 'Process Creation' },
        { field: 'tgt.process.name', operatorId: 'in', value: 'powershell.exe, pwsh.exe' },
        { field: 'tgt.process.cmdline', operatorId: 'contains_ci', value: '-enc' },
      ],
      group: null,
      postFilter: null,
      sort: '',
      limit: 200,
      columns: ['event.time', 'endpoint.name', 'src.process.user', 'src.process.name', 'tgt.process.cmdline'],
    },
  },
  {
    id: 's1-office-spawns-shell',
    language: 's1',
    title: 'Office application spawning a shell',
    theme: 'Execution & scripting',
    finds: 'Word, Excel, PowerPoint or Outlook starting a command interpreter.',
    dataSource: S1_SOURCE,
    tuning:
      'Document-automation add-ins produce this legitimately. Once you know which add-ins are normal, filter on the child command line rather than on the pairing.',
    attack: 'T1204',
    spec: {
      filters: [
        { field: 'event.type', operatorId: 'eq', value: 'Process Creation' },
        { field: 'src.process.name', operatorId: 'in', value: 'winword.exe, excel.exe, powerpnt.exe, outlook.exe' },
        { field: 'tgt.process.name', operatorId: 'in', value: 'cmd.exe, powershell.exe, pwsh.exe, wscript.exe, cscript.exe, mshta.exe' },
      ],
      group: null,
      postFilter: null,
      sort: '',
      limit: 200,
      columns: ['event.time', 'endpoint.name', 'src.process.user', 'src.process.name', 'tgt.process.name', 'tgt.process.cmdline'],
    },
  },
  {
    id: 's1-lolbin-execution',
    language: 's1',
    title: 'Signed-binary proxy execution (LOLBins)',
    theme: 'Execution & scripting',
    finds: 'Execution of the signed Microsoft binaries most often used to run attacker code.',
    dataSource: S1_SOURCE,
    tuning:
      'All of these have legitimate uses. Group by tgt.process.name and src.process.name first and read the rare pairings rather than the raw event list.',
    attack: 'T1218',
    spec: {
      filters: [
        { field: 'event.type', operatorId: 'eq', value: 'Process Creation' },
        {
          field: 'tgt.process.name',
          operatorId: 'in',
          value: 'rundll32.exe, regsvr32.exe, mshta.exe, certutil.exe, bitsadmin.exe, wmic.exe, msbuild.exe, installutil.exe, regasm.exe, regsvcs.exe, cmstp.exe',
        },
      ],
      group: null,
      postFilter: null,
      sort: '',
      limit: 500,
      columns: ['event.time', 'endpoint.name', 'src.process.name', 'tgt.process.name', 'tgt.process.cmdline'],
    },
  },
  {
    id: 's1-execution-from-temp',
    language: 's1',
    title: 'Execution out of a temp directory',
    theme: 'Execution & scripting',
    finds: 'Processes whose image sits under a Temp path — where dropped payloads usually run from first.',
    dataSource: S1_SOURCE,
    tuning:
      'Installers unpack and run from Temp routinely. Correlate with tgt.process.publisher: an unsigned binary running from Temp is a much shorter list.',
    attack: 'T1204',
    spec: {
      filters: [
        { field: 'event.type', operatorId: 'eq', value: 'Process Creation' },
        { field: 'tgt.process.image.path', operatorId: 'contains_ci', value: '\\Temp\\' },
      ],
      group: null,
      postFilter: null,
      sort: '',
      limit: 500,
      columns: ['event.time', 'endpoint.name', 'src.process.name', 'tgt.process.image.path', 'tgt.process.publisher', 'tgt.process.cmdline'],
    },
  },
  {
    id: 's1-lsass-in-command-line',
    language: 's1',
    title: 'LSASS named on a command line',
    theme: 'Credential access',
    finds: 'Any process invoked with lsass in its arguments.',
    dataSource: S1_SOURCE,
    tuning:
      'Crash-dump and diagnostic tooling can legitimately name LSASS. The result set should be small enough to read every command line in full.',
    attack: 'T1003.001',
    spec: {
      filters: [
        { field: 'event.type', operatorId: 'eq', value: 'Process Creation' },
        { field: 'tgt.process.cmdline', operatorId: 'contains_ci', value: 'lsass' },
      ],
      group: null,
      postFilter: null,
      sort: '',
      limit: 200,
      columns: ['event.time', 'endpoint.name', 'src.process.user', 'src.process.name', 'tgt.process.name', 'tgt.process.cmdline'],
    },
  },
  {
    id: 's1-comsvcs-minidump',
    language: 's1',
    title: 'rundll32 driving the comsvcs.dll dump export',
    theme: 'Credential access',
    finds: 'The living-off-the-land process-dumping path that needs no attacker binary on disk.',
    dataSource: S1_SOURCE,
    tuning: 'There is close to no benign use of this pairing. Treat a hit as an escalation, not a tuning exercise.',
    attack: 'T1003.001',
    spec: {
      filters: [
        { field: 'event.type', operatorId: 'eq', value: 'Process Creation' },
        { field: 'tgt.process.name', operatorId: 'contains_ci', value: 'rundll32.exe' },
        { field: 'tgt.process.cmdline', operatorId: 'contains_ci', value: 'comsvcs' },
      ],
      group: null,
      postFilter: null,
      sort: '',
      limit: 100,
      columns: ['event.time', 'endpoint.name', 'src.process.user', 'src.process.name', 'tgt.process.cmdline', 'src.process.storyline.id'],
    },
  },
  {
    id: 's1-run-key-persistence',
    language: 's1',
    title: 'Registry Run-key writes',
    theme: 'Persistence',
    finds: 'Registry values created or changed under a CurrentVersion\\Run key, with the data written.',
    dataSource: S1_SOURCE + ' Windows endpoints only.',
    tuning:
      'Installers write Run keys legitimately. registry.value holds what the key will execute — that is the field that decides whether a row matters.',
    attack: 'T1547',
    spec: {
      filters: [
        { field: 'event.type', operatorId: 'in', value: 'Registry Value Create, Registry Value Modified' },
        { field: 'registry.keyPath', operatorId: 'contains_ci', value: 'CurrentVersion\\Run' },
      ],
      group: null,
      postFilter: null,
      sort: '',
      limit: 200,
      columns: ['event.time', 'endpoint.name', 'src.process.name', 'registry.keyPath', 'registry.value'],
    },
  },
  {
    id: 's1-scheduled-task-cli',
    language: 's1',
    title: 'Scheduled tasks created from the command line',
    theme: 'Persistence',
    finds: 'schtasks.exe invoked to register a task, with the arguments that say what it will run.',
    dataSource: S1_SOURCE + ' Windows endpoints only.',
    tuning:
      'Deployment tooling creates tasks this way. Read the /tr argument — that is the payload, and one pass over it is usually enough to triage.',
    attack: 'T1053.005',
    spec: {
      filters: [
        { field: 'event.type', operatorId: 'eq', value: 'Process Creation' },
        { field: 'tgt.process.name', operatorId: 'contains_ci', value: 'schtasks.exe' },
        { field: 'tgt.process.cmdline', operatorId: 'contains_ci', value: '/create' },
      ],
      group: null,
      postFilter: null,
      sort: '',
      limit: 200,
      columns: ['event.time', 'endpoint.name', 'src.process.user', 'src.process.name', 'tgt.process.cmdline'],
    },
  },
  {
    id: 's1-outbound-fanout',
    language: 's1',
    title: 'Processes reaching many destinations',
    theme: 'Command & control',
    finds: 'Outbound connections aggregated per endpoint and process, widest fan-out first.',
    dataSource: S1_SOURCE,
    tuning:
      'Browsers and updaters top this list by design. Exclude them by src.process.name and read what is left.',
    attack: 'T1071',
    spec: {
      filters: [
        { field: 'event.type', operatorId: 'eq', value: 'IP Connect' },
        { field: 'event.network.direction', operatorId: 'eq', value: 'OUTGOING' },
      ],
      group: {
        aggregations: [
          { aggregationId: 'count', field: '', alias: 'connections' },
          { aggregationId: 'estimate_distinct', field: 'dst.ip.address', alias: 'destinations' },
        ],
        by: ['endpoint.name', 'src.process.name'],
      },
      postFilter: null,
      sort: 'destinations',
      limit: 100,
      columns: [],
    },
  },
  {
    id: 's1-rare-binaries',
    language: 's1',
    title: 'Binaries seen on very few endpoints',
    theme: 'Frequency analysis',
    finds: 'Executables that ran on two or fewer distinct machines across the window.',
    dataSource: S1_SOURCE,
    tuning:
      'Rarity is not badness — most of this will be one-off installers. The value is that the list is short enough to read, and it is where new tooling shows up first.',
    spec: {
      filters: [{ field: 'event.type', operatorId: 'eq', value: 'Process Creation' }],
      group: {
        aggregations: [
          { aggregationId: 'estimate_distinct', field: 'endpoint.name', alias: 'endpoints' },
          { aggregationId: 'count', field: '', alias: 'executions' },
        ],
        by: ['tgt.process.name'],
      },
      postFilter: { column: 'endpoints', operatorId: 'lte', value: '2' },
      sort: 'executions',
      limit: 200,
      columns: [],
    },
  },
  {
    id: 's1-rare-parent-child',
    language: 's1',
    title: 'Uncommon parent/child process pairs',
    theme: 'Frequency analysis',
    finds: 'Parent-to-child launch pairings that happened five times or fewer.',
    dataSource: S1_SOURCE,
    tuning:
      'Raise the threshold on a large estate. Confirm and exclude each pairing once, and the list gets short and stays short.',
    spec: {
      filters: [{ field: 'event.type', operatorId: 'eq', value: 'Process Creation' }],
      group: {
        aggregations: [
          { aggregationId: 'count', field: '', alias: 'launches' },
          { aggregationId: 'estimate_distinct', field: 'endpoint.name', alias: 'endpoints' },
        ],
        by: ['src.process.name', 'tgt.process.name'],
      },
      postFilter: { column: 'launches', operatorId: 'lte', value: '5' },
      sort: 'endpoints',
      limit: 300,
      columns: [],
    },
  },
  {
    id: 's1-archive-staging',
    language: 's1',
    title: 'Archives created on an endpoint',
    theme: 'Collection & staging',
    finds: 'Archive files written to disk — the step that usually comes just before data leaves.',
    dataSource: S1_SOURCE,
    tuning:
      'Backups and software downloads produce archives constantly. Pair this with tgt.file.path to focus on user profiles and temp directories rather than backup targets.',
    attack: 'T1560',
    spec: {
      filters: [
        { field: 'event.type', operatorId: 'eq', value: 'File Creation' },
        { field: 'tgt.file.extension', operatorId: 'in', value: 'zip, 7z, rar, gz, cab' },
      ],
      group: null,
      postFilter: null,
      sort: '',
      limit: 300,
      columns: ['event.time', 'endpoint.name', 'src.process.name', 'tgt.file.path', 'tgt.file.size'],
    },
  },
  {
    id: 's1-executable-dropped',
    language: 's1',
    title: 'Executables and scripts dropped to disk',
    theme: 'Collection & staging',
    finds: 'File creation of executable and script types, with the process that wrote them.',
    dataSource: S1_SOURCE,
    tuning:
      'Software installation dominates. Add a tgt.file.path filter for the directories that should never receive an executable, and this becomes readable immediately.',
    attack: 'T1105',
    spec: {
      filters: [
        { field: 'event.type', operatorId: 'eq', value: 'File Creation' },
        { field: 'tgt.file.extension', operatorId: 'in', value: 'exe, dll, ps1, bat, cmd, js, vbs, hta' },
      ],
      group: null,
      postFilter: null,
      sort: '',
      limit: 500,
      columns: ['event.time', 'endpoint.name', 'src.process.name', 'tgt.file.path', 'tgt.file.sha1'],
    },
  },
];

// ---------------------------------------------------------------------------
// Shared accessors
// ---------------------------------------------------------------------------

export const QUERY_PACKAGES: QueryPackage[] = [...KQL_PACKAGES, ...SPL_PACKAGES, ...S1_PACKAGES];

/** Render a package's query text with the same pure builder the interactive
 *  tool uses — see rule 1 in this file's header. Never a stored string. */
export function queryPackageText(pkg: QueryPackage): string {
  if (pkg.language === 'kql') return buildKqlQuery(pkg.spec).query;
  if (pkg.language === 'spl') return buildSplQuery(pkg.spec);
  return buildS1Query(pkg.spec).query;
}

/** Packages for one language, in declaration order. */
export function packagesFor(language: QueryLanguage): QueryPackage[] {
  return QUERY_PACKAGES.filter((p) => p.language === language);
}

/** Themes present in a language's packages, in the order the packages declare
 *  them — drives the loader's option-groups and the page's own sections. */
export function themesFor(language: QueryLanguage): PackageTheme[] {
  return packagesFor(language).reduce<PackageTheme[]>((themes, p) => {
    if (!themes.includes(p.theme)) themes.push(p.theme);
    return themes;
  }, []);
}
