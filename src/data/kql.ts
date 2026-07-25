// KQL Query Builder — the verified table/column/operator reference data.
//
// SOURCE DISCIPLINE (same rule as eventIds.ts / networkPorts.ts): every table
// name, column name, and column data type below was read off Microsoft's own
// CURRENT live schema documentation before being written here — never from
// memory, and never inferred from one table onto another. Table/column names
// have genuinely churned across product history (Azure AD -> Entra ID
// renames, MDATP -> Defender for Endpoint, the `SHA256`-usually-empty note),
// so each table carries its own `docUrl` and that page is the authority.
// Verified against Microsoft Learn on 2026-07-24:
//   - Defender XDR advanced hunting schema reference (the five Device* tables)
//   - Azure Monitor Logs reference for SecurityEvent and SigninLogs
//   - The Kusto query-language reference for the operators/aggregations
//
// EXPLICITLY-SCOPED SUBSET — documented cuts, not silent gaps:
//   - COLUMNS ARE A CURATED SUBSET. Each table's real schema is larger (some
//     run past 60 columns). What's here is the DFIR-relevant slice; every
//     entry is verified, but "not listed here" never means "not in the real
//     table." Use the in-product schema browser or the linked doc page for
//     the full list.
//   - NO `dynamic`/JSON COLUMNS. Columns typed `dynamic` (SigninLogs'
//     DeviceDetail/LocationDetails/Status, the Device* tables'
//     AdditionalFields) are deliberately excluded from the pickers: filtering
//     them usefully needs `tostring(Col.property)` / `parse_json()` unpacking,
//     and this builder does not generate that. Building a half-correct
//     `where DeviceDetail == "..."` would be worse than omitting them.
//   - NO `join`, `union`, `let`, `extend`, `parse`, `externaldata`, or
//     multi-table correlation. This assembles a single-table pipeline.
//   - SEVEN TABLES, not the whole schema. Both products expose dozens more.
//
// The tool built on this is a SYNTAX BUILDER, not a query engine: nothing
// here connects to a tenant, and no query is ever executed.

export type KqlColumnKind = 'string' | 'numeric' | 'datetime' | 'bool';

export interface KqlColumn {
  /** Exact column name as documented — case matters in KQL. */
  name: string;
  /** The documented KQL data type, spelled as the source doc spells it. */
  type: string;
  /** Coarse grouping that decides which operators are offered and whether a
   *  value gets quoted, treated as a number, or passed through as a KQL
   *  expression. */
  kind: KqlColumnKind;
  /** One-line paraphrase of the documented description (never a verbatim
   *  copy of Microsoft's prose — see CLAUDE.md's copyright rule). */
  hint: string;
}

export interface KqlTable {
  name: string;
  /** Which product surface this table lives in. */
  product: 'Microsoft Defender XDR' | 'Microsoft Sentinel';
  /** Short product-surface label used in the picker's option groups. */
  surface: string;
  /** The column a time filter should be applied to. Defender advanced
   *  hunting tables use `Timestamp`; Azure Monitor / Sentinel workspace
   *  tables use `TimeGenerated`. */
  timeColumn: string;
  blurb: string;
  docUrl: string;
  columns: KqlColumn[];
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

const DEVICE_PROCESS_EVENTS: KqlTable = {
  name: 'DeviceProcessEvents',
  product: 'Microsoft Defender XDR',
  surface: 'Defender XDR — advanced hunting',
  timeColumn: 'Timestamp',
  blurb: 'Process creation and related events from Defender for Endpoint. The starting point for parent/child process chains and command-line hunting.',
  docUrl: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table',
  columns: [
    { name: 'Timestamp', type: 'datetime', kind: 'datetime', hint: 'When the event was recorded (UTC).' },
    { name: 'DeviceId', type: 'string', kind: 'string', hint: 'Service-unique identifier for the device.' },
    { name: 'DeviceName', type: 'string', kind: 'string', hint: 'Fully qualified domain name of the device.' },
    { name: 'ActionType', type: 'string', kind: 'string', hint: 'The activity that triggered the event.' },
    { name: 'FileName', type: 'string', kind: 'string', hint: 'Name of the file the action applied to.' },
    { name: 'FolderPath', type: 'string', kind: 'string', hint: 'Folder containing that file.' },
    { name: 'SHA1', type: 'string', kind: 'string', hint: 'SHA-1 of the file the action applied to.' },
    { name: 'SHA256', type: 'string', kind: 'string', hint: 'SHA-256 of the file — Microsoft notes this is usually not populated; prefer SHA1.' },
    { name: 'MD5', type: 'string', kind: 'string', hint: 'MD5 of the file the action applied to.' },
    { name: 'FileSize', type: 'long', kind: 'numeric', hint: 'Size of the file in bytes.' },
    { name: 'ProcessId', type: 'long', kind: 'numeric', hint: 'PID of the newly created process.' },
    { name: 'ProcessCommandLine', type: 'string', kind: 'string', hint: 'Command line used to create the new process.' },
    { name: 'ProcessIntegrityLevel', type: 'string', kind: 'string', hint: 'Windows integrity level assigned to the new process.' },
    { name: 'ProcessTokenElevation', type: 'string', kind: 'string', hint: 'Token elevation type applied to the new process.' },
    { name: 'ProcessCreationTime', type: 'datetime', kind: 'datetime', hint: 'When the process was created.' },
    { name: 'ProcessUniqueId', type: 'string', kind: 'string', hint: 'Unique process identifier — the Process Start Key on Windows. Immune to PID reuse.' },
    { name: 'AccountName', type: 'string', kind: 'string', hint: 'User name of the account.' },
    { name: 'AccountDomain', type: 'string', kind: 'string', hint: 'Domain of the account.' },
    { name: 'AccountSid', type: 'string', kind: 'string', hint: 'Security identifier of the account.' },
    { name: 'AccountUpn', type: 'string', kind: 'string', hint: 'User principal name of the account.' },
    { name: 'LogonId', type: 'long', kind: 'numeric', hint: 'Logon-session identifier, unique per device between restarts.' },
    { name: 'InitiatingProcessFileName', type: 'string', kind: 'string', hint: 'Name of the process that initiated the event (the parent of the created process).' },
    { name: 'InitiatingProcessFolderPath', type: 'string', kind: 'string', hint: 'Folder containing the initiating process image.' },
    { name: 'InitiatingProcessCommandLine', type: 'string', kind: 'string', hint: 'Command line of the initiating process.' },
    { name: 'InitiatingProcessId', type: 'long', kind: 'numeric', hint: 'PID of the initiating process.' },
    { name: 'InitiatingProcessSHA1', type: 'string', kind: 'string', hint: 'SHA-1 of the initiating process image.' },
    { name: 'InitiatingProcessAccountName', type: 'string', kind: 'string', hint: 'Account that ran the initiating process.' },
    { name: 'InitiatingProcessAccountDomain', type: 'string', kind: 'string', hint: 'Domain of the account that ran the initiating process.' },
    { name: 'InitiatingProcessIntegrityLevel', type: 'string', kind: 'string', hint: 'Integrity level of the initiating process.' },
    { name: 'InitiatingProcessTokenElevation', type: 'string', kind: 'string', hint: 'UAC elevation state of the initiating process.' },
    { name: 'InitiatingProcessParentFileName', type: 'string', kind: 'string', hint: 'Name of the grandparent — the process that spawned the initiating process.' },
    { name: 'InitiatingProcessParentId', type: 'long', kind: 'numeric', hint: 'PID of that grandparent process.' },
    { name: 'InitiatingProcessSignerType', type: 'string', kind: 'string', hint: 'File-signer type of the initiating process image.' },
    { name: 'InitiatingProcessSignatureStatus', type: 'string', kind: 'string', hint: 'Signature status of the initiating process image.' },
    { name: 'IsProcessRemoteSession', type: 'bool', kind: 'bool', hint: 'Whether the created process ran inside an RDP session.' },
    { name: 'ProcessRemoteSessionIP', type: 'string', kind: 'string', hint: 'IP of the remote device that started the created process RDP session.' },
    { name: 'ReportId', type: 'long', kind: 'numeric', hint: 'Repeating event counter — unique only with DeviceName and Timestamp.' },
  ],
};

const DEVICE_NETWORK_EVENTS: KqlTable = {
  name: 'DeviceNetworkEvents',
  product: 'Microsoft Defender XDR',
  surface: 'Defender XDR — advanced hunting',
  timeColumn: 'Timestamp',
  blurb: 'Network connections and related events from Defender for Endpoint. Where beaconing, C2 destinations, and port-scanning behaviour surface.',
  docUrl: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table',
  columns: [
    { name: 'Timestamp', type: 'datetime', kind: 'datetime', hint: 'When the event was recorded (UTC).' },
    { name: 'DeviceId', type: 'string', kind: 'string', hint: 'Service-unique identifier for the device.' },
    { name: 'DeviceName', type: 'string', kind: 'string', hint: 'Fully qualified domain name of the device.' },
    { name: 'ActionType', type: 'string', kind: 'string', hint: 'The activity that triggered the event.' },
    { name: 'RemoteIP', type: 'string', kind: 'string', hint: 'IP address that was being connected to.' },
    { name: 'RemotePort', type: 'int', kind: 'numeric', hint: 'TCP port on the remote device being connected to.' },
    { name: 'RemoteUrl', type: 'string', kind: 'string', hint: 'URL or FQDN that was being connected to.' },
    { name: 'RemoteIPType', type: 'string', kind: 'string', hint: 'Address class of the remote IP — Public, Private, Loopback, and so on.' },
    { name: 'LocalIP', type: 'string', kind: 'string', hint: 'Source IP the communication came from.' },
    { name: 'LocalPort', type: 'int', kind: 'numeric', hint: 'TCP port on the local device used for the communication.' },
    { name: 'LocalIPType', type: 'string', kind: 'string', hint: 'Address class of the local IP.' },
    { name: 'Protocol', type: 'string', kind: 'string', hint: 'Protocol used during the communication.' },
    { name: 'InitiatingProcessFileName', type: 'string', kind: 'string', hint: 'Process that made the connection.' },
    { name: 'InitiatingProcessFolderPath', type: 'string', kind: 'string', hint: 'Folder containing that process image.' },
    { name: 'InitiatingProcessCommandLine', type: 'string', kind: 'string', hint: 'Command line of the connecting process.' },
    { name: 'InitiatingProcessId', type: 'long', kind: 'numeric', hint: 'PID of the connecting process.' },
    { name: 'InitiatingProcessSHA1', type: 'string', kind: 'string', hint: 'SHA-1 of the connecting process image.' },
    { name: 'InitiatingProcessMD5', type: 'string', kind: 'string', hint: 'MD5 of the connecting process image.' },
    { name: 'InitiatingProcessAccountName', type: 'string', kind: 'string', hint: 'Account that ran the connecting process.' },
    { name: 'InitiatingProcessAccountDomain', type: 'string', kind: 'string', hint: 'Domain of that account.' },
    { name: 'InitiatingProcessParentFileName', type: 'string', kind: 'string', hint: 'Parent of the connecting process.' },
    { name: 'InitiatingProcessIntegrityLevel', type: 'string', kind: 'string', hint: 'Integrity level of the connecting process.' },
    { name: 'InitiatingProcessTokenElevation', type: 'string', kind: 'string', hint: 'UAC elevation state of the connecting process.' },
    { name: 'ReportId', type: 'long', kind: 'numeric', hint: 'Repeating event counter — unique only with DeviceName and Timestamp.' },
  ],
};

const DEVICE_FILE_EVENTS: KqlTable = {
  name: 'DeviceFileEvents',
  product: 'Microsoft Defender XDR',
  surface: 'Defender XDR — advanced hunting',
  timeColumn: 'Timestamp',
  blurb: 'File creation, modification, and other file-system events. Carries mark-of-the-web style download provenance and SMB request attribution.',
  docUrl: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table',
  columns: [
    { name: 'Timestamp', type: 'datetime', kind: 'datetime', hint: 'When the event was recorded (UTC).' },
    { name: 'DeviceId', type: 'string', kind: 'string', hint: 'Service-unique identifier for the device.' },
    { name: 'DeviceName', type: 'string', kind: 'string', hint: 'Fully qualified domain name of the device.' },
    { name: 'ActionType', type: 'string', kind: 'string', hint: 'The activity that triggered the event.' },
    { name: 'FileName', type: 'string', kind: 'string', hint: 'Name of the file the action applied to.' },
    { name: 'FolderPath', type: 'string', kind: 'string', hint: 'Folder containing that file.' },
    { name: 'SHA1', type: 'string', kind: 'string', hint: 'SHA-1 of the file.' },
    { name: 'SHA256', type: 'string', kind: 'string', hint: 'SHA-256 of the file — usually not populated; prefer SHA1.' },
    { name: 'MD5', type: 'string', kind: 'string', hint: 'MD5 of the file.' },
    { name: 'FileSize', type: 'long', kind: 'numeric', hint: 'Size of the file in bytes.' },
    { name: 'FileOriginUrl', type: 'string', kind: 'string', hint: 'URL the file was downloaded from.' },
    { name: 'FileOriginReferrerUrl', type: 'string', kind: 'string', hint: 'Page that linked to the downloaded file.' },
    { name: 'FileOriginIP', type: 'string', kind: 'string', hint: 'IP address the file was downloaded from.' },
    { name: 'PreviousFolderPath', type: 'string', kind: 'string', hint: 'Folder the file sat in before the action.' },
    { name: 'PreviousFileName', type: 'string', kind: 'string', hint: 'Original file name before a rename.' },
    { name: 'RequestProtocol', type: 'string', kind: 'string', hint: 'Protocol that initiated the activity — Unknown, Local, SMB, or NFS.' },
    { name: 'RequestSourceIP', type: 'string', kind: 'string', hint: 'IP of the remote device that initiated the activity.' },
    { name: 'RequestSourcePort', type: 'int', kind: 'numeric', hint: 'Source port on that remote device.' },
    { name: 'RequestAccountName', type: 'string', kind: 'string', hint: 'Account used to remotely initiate the activity.' },
    { name: 'RequestAccountDomain', type: 'string', kind: 'string', hint: 'Domain of that account.' },
    { name: 'ShareName', type: 'string', kind: 'string', hint: 'Name of the shared folder containing the file.' },
    { name: 'SensitivityLabel', type: 'string', kind: 'string', hint: 'Information-protection label applied to the content.' },
    { name: 'InitiatingProcessFileName', type: 'string', kind: 'string', hint: 'Process that touched the file.' },
    { name: 'InitiatingProcessFolderPath', type: 'string', kind: 'string', hint: 'Folder containing that process image.' },
    { name: 'InitiatingProcessCommandLine', type: 'string', kind: 'string', hint: 'Command line of that process.' },
    { name: 'InitiatingProcessSHA1', type: 'string', kind: 'string', hint: 'SHA-1 of that process image.' },
    { name: 'InitiatingProcessAccountName', type: 'string', kind: 'string', hint: 'Account that ran the process.' },
    { name: 'InitiatingProcessAccountDomain', type: 'string', kind: 'string', hint: 'Domain of that account.' },
    { name: 'InitiatingProcessParentFileName', type: 'string', kind: 'string', hint: 'Parent of the process that touched the file.' },
    { name: 'ReportId', type: 'long', kind: 'numeric', hint: 'Repeating event counter — unique only with DeviceName and Timestamp.' },
  ],
};

const DEVICE_LOGON_EVENTS: KqlTable = {
  name: 'DeviceLogonEvents',
  product: 'Microsoft Defender XDR',
  surface: 'Defender XDR — advanced hunting',
  timeColumn: 'Timestamp',
  blurb: 'User logons and other authentication events on devices. The endpoint-side view of lateral movement and credential misuse.',
  docUrl: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table',
  columns: [
    { name: 'Timestamp', type: 'datetime', kind: 'datetime', hint: 'When the event was recorded (UTC).' },
    { name: 'DeviceId', type: 'string', kind: 'string', hint: 'Service-unique identifier for the device.' },
    { name: 'DeviceName', type: 'string', kind: 'string', hint: 'Fully qualified domain name of the device.' },
    { name: 'ActionType', type: 'string', kind: 'string', hint: 'The activity that triggered the event, e.g. a failed logon.' },
    { name: 'LogonType', type: 'string', kind: 'string', hint: 'Session type — Interactive, Remote interactive (RDP), Network, Batch, or Service.' },
    { name: 'AccountName', type: 'string', kind: 'string', hint: 'User name of the account.' },
    { name: 'AccountDomain', type: 'string', kind: 'string', hint: 'Domain of the account.' },
    { name: 'AccountSid', type: 'string', kind: 'string', hint: 'Security identifier of the account.' },
    { name: 'Protocol', type: 'string', kind: 'string', hint: 'Protocol used during the communication.' },
    { name: 'FailureReason', type: 'string', kind: 'string', hint: 'Why the recorded action failed.' },
    { name: 'IsLocalAdmin', type: 'boolean', kind: 'bool', hint: 'Whether the user is a local administrator on the device.' },
    { name: 'LogonId', type: 'long', kind: 'numeric', hint: 'Logon-session identifier, unique per device between restarts.' },
    { name: 'RemoteDeviceName', type: 'string', kind: 'string', hint: 'Device that performed the remote operation.' },
    { name: 'RemoteIP', type: 'string', kind: 'string', hint: 'IP the logon attempt came from.' },
    { name: 'RemoteIPType', type: 'string', kind: 'string', hint: 'Address class of that remote IP.' },
    { name: 'RemotePort', type: 'int', kind: 'numeric', hint: 'TCP port on the remote device.' },
    { name: 'InitiatingProcessFileName', type: 'string', kind: 'string', hint: 'Process responsible for the logon event.' },
    { name: 'InitiatingProcessFolderPath', type: 'string', kind: 'string', hint: 'Folder containing that process image.' },
    { name: 'InitiatingProcessCommandLine', type: 'string', kind: 'string', hint: 'Command line of that process.' },
    { name: 'InitiatingProcessAccountName', type: 'string', kind: 'string', hint: 'Account that ran that process.' },
    { name: 'InitiatingProcessAccountDomain', type: 'string', kind: 'string', hint: 'Domain of that account.' },
    { name: 'InitiatingProcessParentFileName', type: 'string', kind: 'string', hint: 'Parent of that process.' },
    { name: 'ReportId', type: 'long', kind: 'numeric', hint: 'Repeating event counter — unique only with DeviceName and Timestamp.' },
  ],
};

const DEVICE_REGISTRY_EVENTS: KqlTable = {
  name: 'DeviceRegistryEvents',
  product: 'Microsoft Defender XDR',
  surface: 'Defender XDR — advanced hunting',
  timeColumn: 'Timestamp',
  blurb: 'Creation and modification of registry entries. Carries the previous key/value alongside the new one, which is what makes persistence hunting tractable.',
  docUrl: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table',
  columns: [
    { name: 'Timestamp', type: 'datetime', kind: 'datetime', hint: 'When the event was recorded (UTC).' },
    { name: 'DeviceId', type: 'string', kind: 'string', hint: 'Service-unique identifier for the device.' },
    { name: 'DeviceName', type: 'string', kind: 'string', hint: 'Fully qualified domain name of the device.' },
    { name: 'ActionType', type: 'string', kind: 'string', hint: 'The activity that triggered the event.' },
    { name: 'RegistryKey', type: 'string', kind: 'string', hint: 'Registry key the action applied to.' },
    { name: 'RegistryValueName', type: 'string', kind: 'string', hint: 'Name of the registry value the action applied to.' },
    { name: 'RegistryValueType', type: 'string', kind: 'string', hint: 'Data type of that value — binary, string, and so on.' },
    { name: 'RegistryValueData', type: 'string', kind: 'string', hint: 'Data held by that registry value.' },
    { name: 'PreviousRegistryKey', type: 'string', kind: 'string', hint: 'Original key before the modification.' },
    { name: 'PreviousRegistryValueName', type: 'string', kind: 'string', hint: 'Original value name before the modification.' },
    { name: 'PreviousRegistryValueData', type: 'string', kind: 'string', hint: 'Original value data before the modification.' },
    { name: 'InitiatingProcessFileName', type: 'string', kind: 'string', hint: 'Process that made the registry change.' },
    { name: 'InitiatingProcessFolderPath', type: 'string', kind: 'string', hint: 'Folder containing that process image.' },
    { name: 'InitiatingProcessCommandLine', type: 'string', kind: 'string', hint: 'Command line of that process.' },
    { name: 'InitiatingProcessId', type: 'long', kind: 'numeric', hint: 'PID of that process.' },
    { name: 'InitiatingProcessSHA1', type: 'string', kind: 'string', hint: 'SHA-1 of that process image.' },
    { name: 'InitiatingProcessAccountName', type: 'string', kind: 'string', hint: 'Account that ran that process.' },
    { name: 'InitiatingProcessAccountDomain', type: 'string', kind: 'string', hint: 'Domain of that account.' },
    { name: 'InitiatingProcessParentFileName', type: 'string', kind: 'string', hint: 'Parent of that process.' },
    { name: 'InitiatingProcessIntegrityLevel', type: 'string', kind: 'string', hint: 'Integrity level of that process.' },
    { name: 'InitiatingProcessTokenElevation', type: 'string', kind: 'string', hint: 'UAC elevation state of that process.' },
    { name: 'ReportId', type: 'long', kind: 'numeric', hint: 'Repeating event counter — unique only with DeviceName and Timestamp.' },
  ],
};

const SECURITY_EVENT: KqlTable = {
  name: 'SecurityEvent',
  product: 'Microsoft Sentinel',
  surface: 'Sentinel / Log Analytics workspace',
  timeColumn: 'TimeGenerated',
  blurb: 'Windows Security auditing events collected from Windows machines into a Log Analytics workspace. The raw Event ID view — 4624, 4625, 4688, 4720, and the rest.',
  docUrl: 'https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent',
  columns: [
    { name: 'TimeGenerated', type: 'datetime', kind: 'datetime', hint: 'When the event was generated on the source computer.' },
    { name: 'Computer', type: 'string', kind: 'string', hint: 'Name of the computer the event occurred on.' },
    { name: 'EventID', type: 'int', kind: 'numeric', hint: 'Windows Event ID — the number the provider used to identify the event.' },
    { name: 'Activity', type: 'string', kind: 'string', hint: 'Descriptive title of the event that occurred.' },
    { name: 'Account', type: 'string', kind: 'string', hint: 'Security context for the user or service.' },
    { name: 'AccountType', type: 'string', kind: 'string', hint: 'Whether the account is a machine account or a user account.' },
    { name: 'Channel', type: 'string', kind: 'string', hint: 'Event log channel the event was written to.' },
    { name: 'SubjectUserName', type: 'string', kind: 'string', hint: 'User account that generated the event.' },
    { name: 'SubjectDomainName', type: 'string', kind: 'string', hint: 'Domain or workgroup of that subject account.' },
    { name: 'SubjectUserSid', type: 'string', kind: 'string', hint: 'SID of the account that generated the event.' },
    { name: 'SubjectLogonId', type: 'string', kind: 'string', hint: 'Logon-session identifier for the subject account.' },
    { name: 'TargetUserName', type: 'string', kind: 'string', hint: 'Name of the user account the event acted on.' },
    { name: 'TargetDomainName', type: 'string', kind: 'string', hint: 'Domain of that target account.' },
    { name: 'TargetUserSid', type: 'string', kind: 'string', hint: 'SID of the user or resource involved in the event.' },
    { name: 'TargetLogonId', type: 'string', kind: 'string', hint: 'Logon-session identifier tied to the event.' },
    { name: 'LogonType', type: 'int', kind: 'numeric', hint: 'Numeric logon type — 2 interactive, 3 network, 10 RemoteInteractive, and so on.' },
    { name: 'LogonTypeName', type: 'string', kind: 'string', hint: 'Text form of the logon type.' },
    { name: 'LogonProcessName', type: 'string', kind: 'string', hint: 'Name of the registered logon process.' },
    { name: 'AuthenticationPackageName', type: 'string', kind: 'string', hint: 'Authentication package loaded for the logon.' },
    { name: 'IpAddress', type: 'string', kind: 'string', hint: 'Network address associated with the event.' },
    { name: 'IpPort', type: 'string', kind: 'string', hint: 'Network port associated with the event.' },
    { name: 'WorkstationName', type: 'string', kind: 'string', hint: 'Machine name the logon attempt came from.' },
    { name: 'Status', type: 'string', kind: 'string', hint: 'Status code explaining why a logon failed.' },
    { name: 'SubStatus', type: 'string', kind: 'string', hint: 'Sub-status code carrying the detailed failure reason.' },
    { name: 'FailureReason', type: 'string', kind: 'string', hint: 'Text explanation of the Status field value.' },
    { name: 'NewProcessName', type: 'string', kind: 'string', hint: 'Full path of the executable for a newly created process.' },
    { name: 'NewProcessId', type: 'string', kind: 'string', hint: 'Hexadecimal PID of the new process — a string, not a number.' },
    { name: 'ParentProcessName', type: 'string', kind: 'string', hint: 'Name of the parent process.' },
    { name: 'CommandLine', type: 'string', kind: 'string', hint: 'Command-line arguments passed to the process.' },
    { name: 'ProcessName', type: 'string', kind: 'string', hint: 'Full path of the executable for the process.' },
    { name: 'ProcessId', type: 'string', kind: 'string', hint: 'Identifier of the process that generated the event.' },
    { name: 'TokenElevationType', type: 'string', kind: 'string', hint: 'Token type assigned to a new process under UAC policy.' },
    { name: 'ElevatedToken', type: 'string', kind: 'string', hint: 'Yes/No flag for whether the session is elevated.' },
    { name: 'ObjectName', type: 'string', kind: 'string', hint: 'Name of the object access was requested for.' },
    { name: 'ObjectType', type: 'string', kind: 'string', hint: 'Type of the object that was accessed.' },
    { name: 'ShareName', type: 'string', kind: 'string', hint: 'Name of the accessed network share.' },
    { name: 'ServiceName', type: 'string', kind: 'string', hint: 'Name of the installed service.' },
    { name: 'ServiceFileName', type: 'string', kind: 'string', hint: 'Service binary registered with the Service Control Manager.' },
    { name: 'PrivilegeList', type: 'string', kind: 'string', hint: 'User, group, or system privileges tied to the event.' },
    { name: 'MemberName', type: 'string', kind: 'string', hint: 'User account involved in a group-membership change.' },
    { name: 'MemberSid', type: 'string', kind: 'string', hint: 'SID of that account.' },
    { name: 'SourceComputerId', type: 'string', kind: 'string', hint: 'Unique identifier assigned to each computer in the domain.' },
  ],
};

const SIGNIN_LOGS: KqlTable = {
  name: 'SigninLogs',
  product: 'Microsoft Sentinel',
  surface: 'Sentinel / Log Analytics workspace',
  timeColumn: 'TimeGenerated',
  blurb: 'Microsoft Entra ID interactive sign-in activity. The identity-side counterpart to DeviceLogonEvents — Conditional Access outcomes, risk state, and source IP.',
  docUrl: 'https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs',
  columns: [
    { name: 'TimeGenerated', type: 'datetime', kind: 'datetime', hint: 'When the record was generated.' },
    { name: 'CreatedDateTime', type: 'datetime', kind: 'datetime', hint: 'When the sign-in was initiated (UTC).' },
    { name: 'UserPrincipalName', type: 'string', kind: 'string', hint: 'UPN of the user.' },
    { name: 'UserDisplayName', type: 'string', kind: 'string', hint: 'Display name of the user.' },
    { name: 'UserId', type: 'string', kind: 'string', hint: 'Identifier of the user.' },
    { name: 'UserType', type: 'string', kind: 'string', hint: 'Whether the user is a member or a guest in the tenant.' },
    { name: 'AlternateSignInName', type: 'string', kind: 'string', hint: 'Identifier the user actually supplied to sign in.' },
    { name: 'SignInIdentifier', type: 'string', kind: 'string', hint: 'Identifier the user provided to sign in.' },
    { name: 'SignInIdentifierType', type: 'string', kind: 'string', hint: 'Kind of sign-in identifier used — UPN, phone number, proxy address, and so on.' },
    { name: 'AppDisplayName', type: 'string', kind: 'string', hint: 'Application name shown in the portal.' },
    { name: 'AppId', type: 'string', kind: 'string', hint: 'Application identifier in Microsoft Entra ID.' },
    { name: 'ResourceDisplayName', type: 'string', kind: 'string', hint: 'Name of the resource the user signed in to.' },
    { name: 'IPAddress', type: 'string', kind: 'string', hint: 'Client IP the sign-in came from.' },
    { name: 'Location', type: 'string', kind: 'string', hint: 'Two-letter country code the sign-in came from.' },
    { name: 'AutonomousSystemNumber', type: 'string', kind: 'string', hint: 'ASN of the network the actor used.' },
    { name: 'ClientAppUsed', type: 'string', kind: 'string', hint: 'Legacy client used for the sign-in — Browser, IMAP, SMTP, POP, and so on.' },
    { name: 'UserAgent', type: 'string', kind: 'string', hint: 'User-agent string tied to the sign-in.' },
    { name: 'ResultType', type: 'string', kind: 'string', hint: 'Sign-in error code — 0 means success, anything else is a failure.' },
    { name: 'ResultDescription', type: 'string', kind: 'string', hint: 'Error message or failure reason for the sign-in.' },
    { name: 'ConditionalAccessStatus', type: 'string', kind: 'string', hint: 'Outcome of the triggered Conditional Access policy — success, failure, or notApplied.' },
    { name: 'AuthenticationRequirement', type: 'string', kind: 'string', hint: 'Highest authentication level required across the sign-in steps.' },
    { name: 'AuthenticationProtocol', type: 'string', kind: 'string', hint: 'Protocol or grant type used — oAuth2, ropc, saml20, deviceCode, and so on.' },
    { name: 'IsInteractive', type: 'bool', kind: 'bool', hint: 'Whether the user supplied an authentication factor themselves.' },
    { name: 'RiskLevelDuringSignIn', type: 'string', kind: 'string', hint: 'Risk level at sign-in time — needs Entra ID P2 or it reads as hidden.' },
    { name: 'RiskLevelAggregated', type: 'string', kind: 'string', hint: 'Aggregated risk level — needs Entra ID P2 or it reads as hidden.' },
    { name: 'RiskState', type: 'string', kind: 'string', hint: 'Risk state — atRisk, confirmedCompromised, remediated, dismissed, and so on.' },
    { name: 'RiskDetail', type: 'string', kind: 'string', hint: 'Reason behind the current risk state.' },
    { name: 'RiskEventTypes_V2', type: 'string', kind: 'string', hint: 'Risk detections tied to the sign-in — unlikelyTravel, leakedCredentials, and so on.' },
    { name: 'IncomingTokenType', type: 'string', kind: 'string', hint: 'Type of token used to sign in — primary refresh token, SAML assertion, and so on.' },
    { name: 'TokenIssuerType', type: 'string', kind: 'string', hint: 'Identity provider type — AzureAD, ADFederationServices, and so on.' },
    { name: 'CrossTenantAccessType', type: 'string', kind: 'string', hint: 'Kind of cross-tenant access the actor used.' },
    { name: 'HomeTenantId', type: 'string', kind: 'string', hint: 'Tenant that homes the signing-in identity.' },
    { name: 'ResourceTenantId', type: 'string', kind: 'string', hint: 'Tenant that owns the resource referenced in the sign-in.' },
    { name: 'ServicePrincipalName', type: 'string', kind: 'string', hint: 'Application name used for sign-in, when signing in as an application.' },
    { name: 'ServicePrincipalId', type: 'string', kind: 'string', hint: 'Application identifier used for sign-in.' },
    { name: 'CorrelationId', type: 'string', kind: 'string', hint: 'Client-sent identifier for correlating a sign-in across records.' },
    { name: 'SessionId', type: 'string', kind: 'string', hint: 'Identifier of the session generated during the sign-in.' },
  ],
};

/** Every table this builder knows about, in picker order. */
export const KQL_TABLES: KqlTable[] = [
  DEVICE_PROCESS_EVENTS,
  DEVICE_NETWORK_EVENTS,
  DEVICE_FILE_EVENTS,
  DEVICE_LOGON_EVENTS,
  DEVICE_REGISTRY_EVENTS,
  SECURITY_EVENT,
  SIGNIN_LOGS,
];

// ---------------------------------------------------------------------------
// Operators
// ---------------------------------------------------------------------------

/** How an operator's right-hand side is written out.
 *  - `binary`   -> `Column <symbol> <value>`
 *  - `list`     -> `Column <symbol> (<v1>, <v2>, ...)`
 *  - `function` -> `<symbol>(Column)` (no value at all) */
export type KqlOperatorForm = 'binary' | 'list' | 'function';

export interface KqlOperator {
  id: string;
  /** Exact KQL text — this is what lands in the generated query. */
  symbol: string;
  label: string;
  form: KqlOperatorForm;
  /** Column kinds this operator is offered for. */
  kinds: KqlColumnKind[];
  /** true = case-sensitive, false = case-insensitive, null = not applicable. */
  caseSensitive: boolean | null;
  hint: string;
}

/** The where-clause operators this builder can emit, all drawn from the Kusto
 *  string-operator reference plus the numeric comparison and null-check
 *  operators. Case sensitivity is copied straight from that table — it is not
 *  guessable, and getting it wrong silently changes what a hunt matches. */
export const KQL_OPERATORS: KqlOperator[] = [
  { id: 'eq', symbol: '==', label: 'equals', form: 'binary', kinds: ['string', 'numeric', 'datetime', 'bool'], caseSensitive: true, hint: 'Exact match. Case-sensitive, and the faster choice over =~.' },
  { id: 'neq', symbol: '!=', label: 'not equals', form: 'binary', kinds: ['string', 'numeric', 'datetime', 'bool'], caseSensitive: true, hint: 'Exact non-match. Case-sensitive.' },
  { id: 'eq_ci', symbol: '=~', label: 'equals (ignore case)', form: 'binary', kinds: ['string'], caseSensitive: false, hint: 'Case-insensitive exact match — the durable choice for file names and command lines.' },
  { id: 'neq_ci', symbol: '!~', label: 'not equals (ignore case)', form: 'binary', kinds: ['string'], caseSensitive: false, hint: 'Case-insensitive exact non-match.' },
  { id: 'has', symbol: 'has', label: 'has term', form: 'binary', kinds: ['string'], caseSensitive: false, hint: 'Matches a whole indexed term, not a substring. Faster than contains.' },
  { id: 'nhas', symbol: '!has', label: 'does not have term', form: 'binary', kinds: ['string'], caseSensitive: false, hint: 'The negation of has.' },
  { id: 'has_cs', symbol: 'has_cs', label: 'has term (case-sensitive)', form: 'binary', kinds: ['string'], caseSensitive: true, hint: 'Case-sensitive whole-term match.' },
  { id: 'has_any', symbol: 'has_any', label: 'has any term', form: 'list', kinds: ['string'], caseSensitive: false, hint: 'Whole-term match against any value in the list.' },
  { id: 'has_all', symbol: 'has_all', label: 'has all terms', form: 'list', kinds: ['string'], caseSensitive: false, hint: 'Whole-term match against every value in the list.' },
  { id: 'contains', symbol: 'contains', label: 'contains', form: 'binary', kinds: ['string'], caseSensitive: false, hint: 'Substring match. Scans rather than using the term index — slower than has.' },
  { id: 'ncontains', symbol: '!contains', label: 'does not contain', form: 'binary', kinds: ['string'], caseSensitive: false, hint: 'The negation of contains.' },
  { id: 'contains_cs', symbol: 'contains_cs', label: 'contains (case-sensitive)', form: 'binary', kinds: ['string'], caseSensitive: true, hint: 'Case-sensitive substring match.' },
  { id: 'startswith', symbol: 'startswith', label: 'starts with', form: 'binary', kinds: ['string'], caseSensitive: false, hint: 'Prefix match, case-insensitive.' },
  { id: 'startswith_cs', symbol: 'startswith_cs', label: 'starts with (case-sensitive)', form: 'binary', kinds: ['string'], caseSensitive: true, hint: 'Prefix match, case-sensitive.' },
  { id: 'endswith', symbol: 'endswith', label: 'ends with', form: 'binary', kinds: ['string'], caseSensitive: false, hint: 'Suffix match, case-insensitive.' },
  { id: 'endswith_cs', symbol: 'endswith_cs', label: 'ends with (case-sensitive)', form: 'binary', kinds: ['string'], caseSensitive: true, hint: 'Suffix match, case-sensitive.' },
  { id: 'in', symbol: 'in', label: 'in list', form: 'list', kinds: ['string', 'numeric'], caseSensitive: true, hint: 'Equals any value in the list. Case-sensitive.' },
  { id: 'in_ci', symbol: 'in~', label: 'in list (ignore case)', form: 'list', kinds: ['string'], caseSensitive: false, hint: 'Equals any value in the list, ignoring case.' },
  { id: 'nin', symbol: '!in', label: 'not in list', form: 'list', kinds: ['string', 'numeric'], caseSensitive: true, hint: 'Equals none of the values in the list. Case-sensitive.' },
  { id: 'matches_regex', symbol: 'matches regex', label: 'matches regex', form: 'binary', kinds: ['string'], caseSensitive: true, hint: 'Regular-expression match. Microsoft recommends parse functions over regex where possible.' },
  { id: 'gt', symbol: '>', label: 'greater than', form: 'binary', kinds: ['numeric', 'datetime'], caseSensitive: null, hint: 'Numeric or datetime comparison.' },
  { id: 'gte', symbol: '>=', label: 'greater than or equal', form: 'binary', kinds: ['numeric', 'datetime'], caseSensitive: null, hint: 'Numeric or datetime comparison.' },
  { id: 'lt', symbol: '<', label: 'less than', form: 'binary', kinds: ['numeric', 'datetime'], caseSensitive: null, hint: 'Numeric or datetime comparison.' },
  { id: 'lte', symbol: '<=', label: 'less than or equal', form: 'binary', kinds: ['numeric', 'datetime'], caseSensitive: null, hint: 'Numeric or datetime comparison.' },
  { id: 'isnotempty', symbol: 'isnotempty', label: 'is not empty', form: 'function', kinds: ['string'], caseSensitive: null, hint: 'The column holds a non-empty string.' },
  { id: 'isempty', symbol: 'isempty', label: 'is empty', form: 'function', kinds: ['string'], caseSensitive: null, hint: 'The column holds an empty string or null.' },
  { id: 'isnotnull', symbol: 'isnotnull', label: 'is not null', form: 'function', kinds: ['string', 'numeric', 'datetime', 'bool'], caseSensitive: null, hint: 'The column has a value. Every other filter returns false against null.' },
  { id: 'isnull', symbol: 'isnull', label: 'is null', form: 'function', kinds: ['string', 'numeric', 'datetime', 'bool'], caseSensitive: null, hint: 'The column has no value at all.' },
];

// ---------------------------------------------------------------------------
// Aggregations and timespans
// ---------------------------------------------------------------------------

export interface KqlAggregation {
  id: string;
  label: string;
  /** Function name as written in KQL. */
  fn: string;
  /** Default output column name the builder assigns with `Alias = ...`. */
  alias: string;
  needsColumn: boolean;
  /** Column kinds the aggregated column may be, when one is required. */
  columnKinds: KqlColumnKind[];
  hint: string;
}

export const KQL_AGGREGATIONS: KqlAggregation[] = [
  { id: 'count', label: 'count() — rows', fn: 'count', alias: 'Count', needsColumn: false, columnKinds: [], hint: 'Number of rows in each group.' },
  { id: 'dcount', label: 'dcount() — distinct values', fn: 'dcount', alias: 'DistinctCount', needsColumn: true, columnKinds: ['string', 'numeric', 'datetime', 'bool'], hint: 'Estimated number of distinct values of a column per group.' },
  { id: 'make_set', label: 'make_set() — distinct values as a list', fn: 'make_set', alias: 'Values', needsColumn: true, columnKinds: ['string', 'numeric', 'datetime', 'bool'], hint: 'Collects the distinct values themselves into an array.' },
  { id: 'min', label: 'min() — earliest / smallest', fn: 'min', alias: 'Min', needsColumn: true, columnKinds: ['numeric', 'datetime', 'string'], hint: 'Smallest value in each group — first-seen time, when applied to a datetime.' },
  { id: 'max', label: 'max() — latest / largest', fn: 'max', alias: 'Max', needsColumn: true, columnKinds: ['numeric', 'datetime', 'string'], hint: 'Largest value in each group — last-seen time, when applied to a datetime.' },
  { id: 'avg', label: 'avg() — mean', fn: 'avg', alias: 'Avg', needsColumn: true, columnKinds: ['numeric'], hint: 'Arithmetic mean. Nulls are ignored rather than counted as zero.' },
  { id: 'sum', label: 'sum() — total', fn: 'sum', alias: 'Sum', needsColumn: true, columnKinds: ['numeric'], hint: 'Total of a numeric column across each group.' },
];

export interface KqlTimespan {
  id: string;
  label: string;
}

/** Timespan literals passed to ago(). Restricted to hour and day units — the
 *  only two suffixes used in the Microsoft examples this data was verified
 *  against. Defender advanced hunting itself only retains 30 days of data
 *  unless it is streamed onward to Sentinel, so 30d is the practical ceiling
 *  for the Device* tables. */
export const KQL_TIMESPANS: KqlTimespan[] = [
  { id: '1h', label: 'Last 1 hour' },
  { id: '4h', label: 'Last 4 hours' },
  { id: '12h', label: 'Last 12 hours' },
  { id: '1d', label: 'Last 24 hours' },
  { id: '7d', label: 'Last 7 days' },
  { id: '30d', label: 'Last 30 days' },
];

/** bin() bucket widths offered for time-bucketed summaries. Same
 *  hour/day-suffix restriction as KQL_TIMESPANS. */
export const KQL_BIN_SIZES: KqlTimespan[] = [
  { id: '1h', label: '1 hour' },
  { id: '6h', label: '6 hours' },
  { id: '1d', label: '1 day' },
];
