// Prerendered site-wide search index, consumed by the ⌘K palette (Search.astro).
// One compact JSON file (cached) covering posts, labs, glossary terms, and key
// pages — so the whole site is searchable client-side with no backend. Mirrors
// the static-CDN model of /glossary/bank.json.
import type { APIRoute } from 'astro';
import { getSortedPosts, getSortedLabs } from '../utils/posts';
import { SECURITY_TERMS } from '../data/securityTerms';
import { ATTACK_TECHNIQUES } from '../data/references';
import { D3FEND_TECHNIQUES } from '../data/d3fend';
import { TOOLS } from '../data/tools';
import { EVENT_IDS } from '../data/eventIds';
import { NETWORK_PORTS } from '../data/networkPorts';
import { THREAT_ACTORS, threatActorSlug } from '../data/threatActors';

export const prerender = true;

// Stable, hand-listed destinations that aren't collection/term pages.
const STATIC_PAGES = [
  { title: 'About', url: '/about/', kind: 'Page', desc: 'Patrick Saade — DFIR-focused security analyst.', keywords: 'about bio experience career work history' },
  { title: 'DFIR', url: '/dfir/', kind: 'Page', desc: 'Every DFIR reference and tool on this site, organized by what you\'re trying to do.', keywords: 'dfir hub overview reference tools frameworks extractors converters parsers query builders' },
  { title: 'IT', url: '/it/', kind: 'Page', desc: 'General IT & networking tools and reference material, kept separate from the DFIR-specific toolkit.', keywords: 'it hub networking subnet cidr vlan planner reference tools' },
  { title: 'Tool Catalog', url: '/tools/', kind: 'Page', desc: 'Free & open-source DFIR tools, grouped by platform.', keywords: 'tools toolkit catalog volatility velociraptor autopsy' },
  { title: 'DFIR Command Cheat Sheet', url: '/tools/cheatsheet/', kind: 'Page', desc: 'Genuinely useful, verified DFIR commands for the toolkit, grouped by platform.', keywords: 'cheat sheet cheatsheet quick reference commands syntax' },
  { title: 'Timestamp Converter', url: '/tools/timestamp-converter/', kind: 'Page', desc: 'Comprehensive bidirectional timestamp/epoch converter — Unix, FILETIME, WebKit, Mac Absolute Time, .NET Ticks, UUID v1, GPS, TAI64, and text/log formats.', keywords: 'timestamp epoch converter filetime webkit unix time uuid gps tai64 date time conversion decoder' },
  { title: 'IOC Extractor', url: '/tools/ioc-extractor/', kind: 'Page', desc: 'Paste a log, alert, or report and extract every IOC it contains — IPs, domains, URLs, emails, hashes, CVE IDs, MITRE ATT&CK IDs, Bitcoin addresses — with a defang/refang toggle.', keywords: 'ioc extractor indicator of compromise defang refang hash ip domain url cve attack bitcoin triage' },
  { title: 'Hash Calculator & Verifier', url: '/tools/hash-calculator/', kind: 'Page', desc: "Compute MD5/SHA-1/SHA-256/SHA-384/SHA-512 for text or a local file, verify against a known hash, and identify a bare hash's likely algorithm with a confidence level — entirely local.", keywords: 'hash calculator verifier md5 sha1 sha256 sha512 checksum file identity ntlm identify confidence local' },
  { title: 'Codec Builder', url: '/tools/deobfuscator/', kind: 'Page', desc: 'Chain Base64/hex/URL encode or decode, ROT13/47, single-byte XOR, and Gzip/Deflate inflate to build or peel back obfuscated loader and dropper payloads — entirely local.', keywords: 'codec builder deobfuscator deobfuscation obfuscator recipe base64 hex xor rot13 rot47 gzip deflate inflate malware loader dropper encode decode' },
  { title: 'Text Diff Tool', url: '/tools/text-diff/', kind: 'Page', desc: 'Compare two logs or text blocks and highlight what changed, line by line — entirely local.', keywords: 'text diff tool compare log file change added removed unified side by side' },
  { title: 'CIDR & VLAN Calculator', url: '/tools/cidr-calculator/', kind: 'Page', desc: 'Compute network/broadcast address, netmask, wildcard mask, and usable host range from CIDR notation, check a same-subnet match, and plan multiple subnets or VLANs (VLSM) against a base network — entirely local.', keywords: 'cidr subnet calculator netmask wildcard mask broadcast network address rfc 4632 ip range vlsm vlan planner subnet planner rfc 1878' },
  { title: 'Number Base Converter', url: '/tools/base-converter/', kind: 'Page', desc: 'Convert a value between binary, octal, decimal, and hexadecimal live as you type, with an ASCII decode of the underlying bytes — entirely local.', keywords: 'number base converter binary octal decimal hexadecimal hex ascii bit byte encoding' },
  { title: 'MAC Analyzer', url: '/tools/mac-address/', kind: 'Page', desc: "Decode a MAC address into its OUI and NIC-specific bytes, and see what the U/L and I/G bits mean — entirely local. Decodes structure only, doesn't identify the manufacturer.", keywords: 'mac address analyzer structure oui nic ethernet hardware address unicast multicast locally administered universally administered' },
  { title: 'PE Header Explorer', url: '/tools/pe-explorer/', kind: 'Page', desc: 'Parse a local EXE/DLL client-side — DOS/NT headers, section table, imports/exports, and a computed imphash.', keywords: 'pe header explorer portable executable dos nt coff optional header section table import export imphash malware static analysis' },
  { title: 'LNK (Shell Link) Forensic Parser', url: '/tools/lnk-parser/', kind: 'Page', desc: 'Parse a Windows .lnk shortcut file per MS-SHLLINK — target timestamps, volume/host info, and the embedded shell item breadcrumb path.', keywords: 'lnk shell link forensic parser shortcut ms-shllink shell item id list recent files jump list' },
  { title: 'MFT & USN Journal Timestomp Analyzer', url: '/tools/mft-usn-analyzer/', kind: 'Page', desc: 'Parse a raw NTFS MFT FILE record or USN journal record, comparing $STANDARD_INFORMATION vs $FILE_NAME timestamps to flag timestomping.', keywords: 'mft usn journal timestomp analyzer ntfs standard information file name filetime anti-forensics timestamp' },
  { title: 'Email Header & Auth-Chain Analyzer', url: '/tools/email-header-analyzer/', kind: 'Page', desc: 'Paste raw email headers to walk the Received chain, read SPF/DKIM/DMARC verdicts, and flag From/Reply-To mismatches — entirely local.', keywords: 'email header analyzer received chain spf dkim dmarc phishing authentication results reply-to return-path' },
  { title: 'DFIR Regex Tester & Pattern Library', url: '/tools/regex-tester/', kind: 'Page', desc: 'Live regex playground with inline match highlighting, capture-group breakdown, and a library of common DFIR patterns (IPs, SIDs, GUIDs, paths).', keywords: 'regex tester pattern library ipv4 ipv6 sid guid windows path registry key base64' },
  { title: 'Regex Syntax Cheat Sheet', url: '/tools/regex-cheatsheet/', kind: 'Page', desc: 'A token-by-token reference for JavaScript/ECMAScript regex syntax — anchors, character classes, quantifiers, groups, lookaround, flags, escapes, replacement tokens, and RegExp/String methods.', keywords: 'regex cheat sheet syntax reference javascript ecmascript anchors character classes quantifiers groups backreferences lookahead lookbehind flags escape sequences replacement patterns regexp methods' },
  { title: 'Sigma Rule Tester & Builder', url: '/tools/sigma-tester/', kind: 'Page', desc: 'Build or paste a Sigma detection rule and test it live against sample log events, with per-condition match highlighting.', keywords: 'sigma rule tester builder detection engineering yaml siem detection as code' },
  { title: 'OSINT Toolkit', url: '/osint/', kind: 'Page', desc: 'Interactive search-operator (dork) builder plus recon recipes and OSINT tools.', keywords: 'osint dork dorking google bing duckduckgo search operators recon attack surface open source intelligence' },
  { title: 'Certifications', url: '/certifications/', kind: 'Page', desc: 'Security certifications — CISSP, CompTIA, the GIAC forensics track.', keywords: 'certifications cissp giac gcfa comptia credly' },
  { title: 'Glossary', url: '/glossary/', kind: 'Page', desc: 'A cybersecurity & DFIR glossary.', keywords: 'glossary terms definitions reference' },
  { title: 'Windows Event ID / Sysmon Reference', url: '/event-ids/', kind: 'Page', desc: 'A comprehensive, fully-cited reference for Windows Security auditing log and Sysmon event IDs that matter for DFIR.', keywords: 'windows event id sysmon security log auditing reference 4624 4688 logon process creation' },
  { title: 'Network Port Reference', url: '/network-ports/', kind: 'Page', desc: 'A comprehensive, fully-cited reference for TCP/UDP ports that matter for DFIR, with confidence levels.', keywords: 'network port reference tcp udp well-known registered ephemeral dynamic iana rdp smb ssh dns c2' },
  { title: 'IP & CIDR Reference', url: '/ip-reference/', kind: 'Page', desc: 'Special-use IPv4/IPv6 address blocks (private, CGNAT, loopback, link-local, multicast, documentation) plus a CIDR quick reference, sourced from IANA.', keywords: 'ip address cidr reference private public rfc 1918 cgnat loopback link-local multicast documentation ula nat64 iana' },
  { title: 'OSI & TCP/IP Model Reference', url: '/osi-model/', kind: 'Page', desc: 'The OSI seven-layer model and the practical four-layer TCP/IP model, what runs at each layer, and the well-known/registered/dynamic port ranges.', keywords: 'osi model tcp ip layers physical data link network transport session presentation application protocol ports well-known registered ephemeral' },
  { title: 'MITRE ATT&CK Coverage Map', url: '/attack-map/', kind: 'Page', desc: 'MITRE ATT&CK techniques covered across the site.', keywords: 'mitre attack techniques tactics coverage matrix' },
  { title: 'MITRE D3FEND map', url: '/d3fend/', kind: 'Page', desc: 'MITRE D3FEND defensive techniques, mapped to ATT&CK.', keywords: 'mitre d3fend defensive techniques tactics countermeasures harden detect isolate' },
  { title: 'Threat Actor / APT Reference', url: '/threat-actors/', kind: 'Page', desc: 'MITRE-documented threat actor / APT groups — aliases, techniques, and known tooling.', keywords: 'threat actor apt group reference mitre attack intrusion set aliases attribution' },
  { title: 'Cyber Kill Chain Reference', url: '/kill-chain/', kind: 'Page', desc: "Lockheed Martin's 7-phase Cyber Kill Chain, phase by phase, mapped to MITRE ATT&CK where it fits.", keywords: 'cyber kill chain lockheed martin reconnaissance weaponization delivery exploitation installation command control actions objectives intrusion' },
  { title: 'Pyramid of Pain', url: '/pyramid-of-pain/', kind: 'Page', desc: "David Bianco's six indicator types, from hash values to TTPs, ranked by cost to the adversary.", keywords: 'pyramid of pain david bianco hash values ip addresses domain names network host artifacts tools ttps indicators' },
  { title: 'JWT Decoder', url: '/tools/jwt-decoder/', kind: 'Page', desc: "Decode a JSON Web Token's header, payload, and claims — entirely in your browser. Signature verification not included.", keywords: 'jwt json web token decoder header payload claims base64url auth bearer token' },
  { title: 'User-Agent String Parser', url: '/tools/user-agent-parser/', kind: 'Page', desc: 'Parse a raw User-Agent header into browser, engine, and OS, with every caveat spelled out — entirely local.', keywords: 'user agent string parser browser engine os chrome firefox safari webkit gecko blink header' },
  { title: 'CVSS Score Calculator', url: '/tools/cvss-calculator/', kind: 'Page', desc: 'Pick the CVSS v3.1 Base metrics — or paste a vector string — and get the score, severity band, and canonical vector back instantly.', keywords: 'cvss score calculator vulnerability severity base metrics vector string attack complexity privileges scope confidentiality integrity availability' },
  { title: 'Recycle Bin ($I) Parser', url: '/tools/recycle-bin-parser/', kind: 'Page', desc: 'Decode a Windows Recycle Bin $I metadata file — original full path, size, and deletion timestamp, both format versions.', keywords: 'recycle bin parser dollar i sinfo file deleted original path timestamp windows forensics artifact' },
  { title: 'Prefetch File Parser', url: '/tools/prefetch-parser/', kind: 'Page', desc: 'Parse a Windows Prefetch (.pf) file — executable name, run count, and last-run timestamps from the uncompressed formats.', keywords: 'prefetch file parser pf windows scca run count last run timestamp execution evidence forensics' },
  { title: 'YARA Rule Tester', url: '/tools/yara-tester/', kind: 'Page', desc: 'Build a YARA rule string by string and scan it live against a pasted sample — real byte-level matching, entirely in your browser.', keywords: 'yara rule tester builder malware signature strings condition ascii wide nocase hex pattern' },
  { title: 'KQL Query Builder', url: '/tools/kql-builder/', kind: 'Page', desc: 'Assemble a Kusto Query Language hunting query for Microsoft Defender XDR or Sentinel against real, documented table columns.', keywords: 'kql kusto query language builder microsoft defender xdr sentinel advanced hunting deviceprocessevents' },
  { title: 'Splunk SPL Query Builder', url: '/tools/spl-builder/', kind: 'Page', desc: 'Compose a Splunk SPL search step by step — base search plus stats, table, sort, where, and eval — entirely in your browser.', keywords: 'splunk spl search processing language query builder stats table sort where eval index sourcetype' },
  { title: 'HTTP Status Code Reference', url: '/http-status-codes/', kind: 'Page', desc: "Every currently-assigned HTTP status code from IANA's registry, grouped by class, with the exact reason phrase.", keywords: 'http status code reference 1xx 2xx 3xx 4xx 5xx reason phrase iana rfc 9110' },
  { title: 'DNS Record Type Reference', url: '/dns-records/', kind: 'Page', desc: 'The common DNS resource record types — A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV, CAA — with TYPE value and purpose.', keywords: 'dns record type reference a aaaa cname mx txt ns soa ptr srv caa resource record iana' },
  { title: 'ASCII Table & Character Encoding Reference', url: '/ascii-table/', kind: 'Page', desc: 'The full 7-bit ASCII table with decimal/hex/octal/binary for every code point, plus how Unicode and UTF-8 relate to it.', keywords: 'ascii table character encoding reference decimal hex octal binary unicode utf-8 code point' },
  { title: 'Cron Expression Parser & Builder', url: '/tools/cron-parser/', kind: 'Page', desc: 'Decode a 5-field crontab(5) cron expression into a plain-English sentence, or assemble one with a guided per-field builder.', keywords: 'cron expression parser builder crontab schedule minute hour day month vixie posix' },
  { title: 'Data Size & Storage Unit Converter', url: '/tools/data-size-converter/', kind: 'Page', desc: "Convert a value between bit, byte, decimal (kB-PB) and binary (KiB-PiB) size units — and see why a '500 GB' drive shows less.", keywords: 'data size storage unit converter bit byte kilobyte megabyte gigabyte kibibyte mebibyte gibibyte decimal binary' },
  { title: 'Blog', url: '/blog/', kind: 'Page', desc: 'DFIR deep dives.', keywords: 'blog posts writeups articles' },
  { title: 'Labs', url: '/labs/', kind: 'Page', desc: 'Lab & CTF writeups.', keywords: 'labs ctf writeups cyberdefenders 13cubed' },
  { title: 'Drills', url: '/drills/', kind: 'Page', desc: 'Short, focused DFIR knowledge-check drills built from the same real data this site\'s own tools and references use.', keywords: 'drills practice quiz knowledge check regex ip cidr hashing attack event id command line' },
  { title: 'RegEx Range Drill', url: '/drills/regex/', kind: 'Page', desc: 'Build a pattern that solves progressively harder challenges.', keywords: 'regex range drill practice pattern matching' },
  { title: 'Subnetting Drill', url: '/drills/ip-cidr/', kind: 'Page', desc: 'Subnet arithmetic and special-use range recognition.', keywords: 'subnetting ip cidr drill practice quiz subnet netmask' },
  { title: 'Hash Identification Drill', url: '/drills/hashing/', kind: 'Page', desc: 'Recognize hash algorithms by format and context.', keywords: 'hash identification drill practice quiz md5 sha1 sha256' },
  { title: 'MITRE ATT&CK Drill', url: '/drills/attack/', kind: 'Page', desc: 'Technique recognition drawn from real ATT&CK data.', keywords: 'mitre attack drill practice quiz technique tactic' },
  { title: 'Windows Event ID Drill', url: '/drills/event-ids/', kind: 'Page', desc: 'Identify Security/Sysmon events from real sample logs.', keywords: 'windows event id drill practice quiz sysmon security log' },
  { title: 'Terminal Commands Drill', url: '/drills/commands/', kind: 'Page', desc: 'Native bash, cmd.exe, and PowerShell commands — the terminal itself, not a tool.', keywords: 'terminal commands drill practice quiz bash cmd powershell shell linux macos windows cli' },
  { title: 'Threat Actor / APT Drill', url: '/drills/threat-actors/', kind: 'Page', desc: 'Identify MITRE-documented threat actor groups from their aliases, techniques, and tooling.', keywords: 'threat actor apt drill practice quiz mitre attack group alias attribution' },
];

export const GET: APIRoute = async () => {
  const [posts, labs] = await Promise.all([getSortedPosts(), getSortedLabs()]);

  const entries = [
    ...posts.map((p) => ({
      title: p.data.title,
      url: `/blog/${p.id}/`,
      kind: 'Post',
      desc: p.data.excerpt,
      keywords: `${p.data.tags.join(' ')} ${p.data.category} ${p.data.tools.join(' ')}`.toLowerCase(),
    })),
    ...labs.map((l) => ({
      title: l.data.title,
      url: `/labs/${l.id}/`,
      kind: 'Lab',
      desc: l.data.excerpt,
      keywords: `${l.data.tags.join(' ')} ${l.data.source} ${l.data.tools.join(' ')}`.toLowerCase(),
    })),
    ...SECURITY_TERMS.map((t) => ({
      title: t.term,
      url: `/glossary/${t.slug}/`,
      kind: 'Term',
      desc: t.short,
      keywords: `${(t.aka ?? []).join(' ')} ${t.category}`.toLowerCase(),
    })),
    ...ATTACK_TECHNIQUES.map((t) => ({
      title: `${t.id} ${t.name}`,
      url: `/attack-map/${t.id}/`,
      kind: 'ATT&CK',
      desc: t.summary ?? '',
      keywords: `${t.tactics.join(' ')} mitre att&ck technique`.toLowerCase(),
    })),
    ...D3FEND_TECHNIQUES.map((t) => ({
      title: `${t.id} ${t.name}`,
      url: `/d3fend/${t.id}/`,
      kind: 'D3FEND',
      desc: t.definition,
      keywords: `${t.tactic} mitre d3fend defensive countermeasure technique`.toLowerCase(),
    })),
    ...TOOLS.map((t) => ({
      title: t.name,
      url: `/tools/${t.slug}/`,
      kind: 'Tool',
      desc: t.use,
      keywords: `${t.fn} ${t.cost} ${t.platform} ${t.tags.join(' ')} dfir tool`.toLowerCase(),
    })),
    ...EVENT_IDS.map((e) => ({
      title: `${e.id} ${e.name}`,
      url: `/event-ids/${e.slug}/`,
      kind: 'Event ID',
      desc: e.category,
      keywords: `${e.channel} ${e.source} windows event id sysmon`.toLowerCase(),
    })),
    ...NETWORK_PORTS.map((p) => ({
      title: `${p.port} ${p.name}`,
      url: `/network-ports/${p.slug}/`,
      kind: 'Port',
      desc: p.category,
      keywords: `${p.protocol} port ${p.port} network`.toLowerCase(),
    })),
    ...THREAT_ACTORS.map((a) => ({
      title: `${a.id} ${a.name}`,
      url: `/threat-actors/${threatActorSlug(a.name)}/`,
      kind: 'Threat Actor',
      desc: a.summary,
      keywords: `${a.aliases.join(' ')} threat actor apt group mitre attack`.toLowerCase(),
    })),
    ...STATIC_PAGES,
  ];

  return new Response(JSON.stringify(entries), {
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
};
