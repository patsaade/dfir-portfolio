// Real, verified external websites/tools that complement each of the site's
// own interactive DFIR tools — researched and WebFetch-verified before
// inclusion (same no-invention discipline as eventIds.ts/tools.ts). Distinct
// from RelatedTools.astro's toolChip, which links to OTHER PAGES ON THIS
// SITE; every resource here is off-site. Keyed by the tool page's own route
// slug (the segment after /tools/, or 'osint' for the OSINT Toolkit).
// 'reference' = an authoritative spec or standards-body source (RFC, FIPS/NIST,
// IEEE, POSIX, an official project spec, Microsoft Learn's own format docs,
// MITRE ATT&CK's own pages) — the same tier of organization CLAUDE.md's
// references.ts already treats as authoritative site-wide. 'recommendation' =
// a community-, individual-, or company-built tool or training resource that
// complements this page and is worth using and crediting — CyberChef,
// VirusTotal, regex101, Eric Zimmerman's EZ Tools, a practice/wargame site,
// etc. ExternalResources.astro renders the two as separate labeled sections
// (only rendering a section that actually has entries) so a reader can tell
// "authoritative source" from "worth crediting/supporting" at a glance.
export interface ExternalResource {
  name: string;
  url: string;
  blurb: string;
  kind: 'reference' | 'recommendation';
}

// Shared by 'cidr-calculator' and the /drills/ip-cidr/ drill module — same
// object reference in both arrays rather than a second copy of the prose,
// per the "reuse, don't duplicate" rule for a resource already verified
// elsewhere in this file.
const RFC_4632_ENTRY: ExternalResource = {
  name: 'RFC 4632 — Classless Inter-domain Routing (CIDR)',
  url: 'https://www.rfc-editor.org/rfc/rfc4632',
  blurb: "The authoritative IETF specification for CIDR notation and address aggregation that this page's own arithmetic implements — worth consulting directly for the full addressing/aggregation rules beyond what a calculator surfaces.",
  kind: 'reference',
};

// Shared by 'hash-calculator' and the /drills/hashing/ drill module — the
// SHA-1/SHA-2 family spec both already cite independently; same "reuse, don't
// duplicate" pattern as RFC_4632_ENTRY above.
const FIPS_180_4_ENTRY: ExternalResource = {
  name: 'FIPS 180-4, Secure Hash Standard (SHS)',
  url: 'https://csrc.nist.gov/pubs/fips/180-4/upd1/final',
  blurb: "NIST's authoritative standard for the SHA-1/SHA-2 hash algorithm family this page computes and identifies.",
  kind: 'reference',
};

// Shared by 'regex-cheatsheet', 'regex-tester', and the /drills/regex/ drill
// module — this site's actual regex engine, verified: src/utils/regexPatterns.ts's
// compileRegexSafely() calls a plain `new RegExp(pattern, flags)`, native
// JavaScript/ECMAScript RegExp — NOT PCRE2, NOT Python's re, NOT POSIX
// BRE/ERE. A previous version of this entry cited PCRE2's own syntax page
// with a blurb claiming it was "the regex flavor this site's Regex Tester
// (and the regex drill) both use" — WebFetch-verified false (PCRE2 supports
// possessive quantifiers, atomic groups, recursive patterns, and
// backtracking-control verbs, none of which plain JS regex has) and
// corrected to this MDN citation instead.
const MDN_JS_REGEX_ENTRY: ExternalResource = {
  name: 'MDN — JavaScript Reference: Regular expressions',
  url: 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Regular_expressions',
  blurb: "MDN's full JavaScript RegExp reference — every flag, named capturing groups, lookbehind assertions, and Unicode property escapes with their exact flag requirements. The authoritative, actively-maintained source for the regex flavor this site's tools actually run.",
  kind: 'reference',
};

export const EXTERNAL_RESOURCES: Record<string, ExternalResource[]> = {
  'spl-builder': [
    {
      name: 'Splunk Search Reference — Command quick reference',
      url: 'https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/quick-reference/command-quick-reference',
      blurb:
        "Splunk's own alphabetical index of every SPL search command, each with a one-line description and a link to its full syntax page. The authoritative answer to \"is there a command for this?\" — and the source every command name and syntax line on this page was verified against.",
      kind: 'reference',
    },
    {
      name: 'Splunk Search Manual — Anatomy of a search',
      url: 'https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.2/use-the-search-app/anatomy-of-a-search',
      blurb:
        "Splunk's own breakdown of how a search is put together — search terms, commands, functions, arguments, clauses — and what the pipe actually does between stages. Worth reading once if the pipeline model this builder is organized around is new to you.",
      kind: 'reference',
    },
    {
      name: 'Splunk Search Reference — Time modifiers',
      url: 'https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/time-format-variables-and-modifiers/time-modifiers',
      blurb:
        'The full specification for earliest/latest, the relative-time format, the snap-to (@) operator, and the complete table of valid time unit abbreviations — including the absolute-timestamp forms this builder passes through verbatim rather than modelling.',
      kind: 'reference',
    },
    {
      name: 'Splunk Boss of the SOC (BOTS) v3 dataset',
      url: 'https://github.com/splunk/botsv3',
      blurb:
        "Splunk's free, CC0-licensed CTF dataset — pre-indexed Windows, Linux, AWS, cloud, and network telemetry from a simulated intrusion. The realistic way to practice the query shapes on this page against data that actually has something to find.",
      kind: 'recommendation',
    },
    {
      name: 'Splunk — Splunk Cheat Sheet: Query, SPL, RegEx, & Commands',
      url: 'https://www.splunk.com/en_us/blog/learn/splunk-cheat-sheet-query-spl-regex-commands.html',
      blurb:
        "Splunk's own practical cheat sheet: the core concepts, the commonly-used commands with worked query examples, eval functions, regex patterns, and time formatting — a faster lookup than the full reference once you know what you're after.",
      kind: 'recommendation',
    },
  ],
  'regex-cheatsheet': [
    {
      name: 'MDN — JavaScript Guide: Regular expressions',
      url: 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions',
      blurb: "MDN's guide-style walkthrough of JavaScript regular expressions — creating patterns, character classes, assertions, groups, quantifiers, and flags — scoped specifically to the ECMAScript RegExp implementation this page documents, not a generic/PCRE-flavored guide.",
      kind: 'reference',
    },
    MDN_JS_REGEX_ENTRY,
    {
      name: 'ECMA-262 — ECMAScript Language Specification',
      url: 'https://tc39.es/ecma262/',
      blurb: "The official ECMAScript Language Specification — its RegExp Objects chapter is the ground-truth source behind every entry above. Worth reaching for exact edge-case semantics beyond what MDN summarizes; MDN stays the better everyday reference.",
      kind: 'reference',
    },
    {
      name: 'regex101',
      url: 'https://regex101.com/?flavor=javascript',
      blurb: "An interactive tester deep-linked to regex101's JavaScript flavor, so a pasted pattern is explained and highlighted using actual JS engine semantics rather than PCRE2's — a useful second opinion alongside this site's own Regex Tester.",
      kind: 'recommendation',
    },
  ],
  'cvss-calculator': [
    {
      name: 'FIRST — CVSS v3.1 Specification Document',
      url: 'https://www.first.org/cvss/v3-1/specification-document',
      blurb: "The authoritative specification this page's calculator implements — the three metric groups (Section 1.1), every Base metric definition and numeric weight, the Base Score equations (Section 7.1), the qualitative severity bands (Section 5), and the Roundup function in Appendix A.",
      kind: 'reference',
    },
    {
      name: 'FIRST — CVSS v3.1 User Guide',
      url: 'https://www.first.org/cvss/v3-1/user-guide',
      blurb: 'The companion document to the specification: visual scoring rubrics for each metric, plus the guidance a spec alone leaves out — how to score vulnerability chains, firewall-protected components, and vulnerabilities in libraries, and how to decide Scope in ambiguous cases.',
      kind: 'reference',
    },
    {
      name: 'FIRST — CVSS v3.1 Examples',
      url: 'https://www.first.org/cvss/v3-1/examples',
      blurb: "FIRST's own 31 worked examples — real CVEs with a full justification for every metric choice, the resulting vector string, and the published score. The source of the worked examples on this page, and the reference answers this site's own test suite checks its implementation against.",
      kind: 'reference',
    },
    {
      name: 'FIRST — CVSS v3.1 Calculator',
      url: 'https://www.first.org/cvss/calculator/3-1',
      blurb: "FIRST's official v3.1 calculator. Worth going to directly for the two metric groups this page deliberately does not implement: Temporal (exploit maturity, remediation level, report confidence) and Environmental (your own C/I/A requirements plus per-metric overrides).",
      kind: 'reference',
    },
    {
      name: 'FIRST — CVSS v4.0 Specification Document',
      url: 'https://www.first.org/cvss/v4-0/specification-document',
      blurb: 'The current major version of the standard, and a substantially different scoring system: new Attack Requirements metric, Passive/Active User Interaction values, impact split across vulnerable and subsequent systems, an optional Supplemental group, and the CVSS-B/BT/BE/BTE nomenclature. This page scores v3.1 only.',
      kind: 'reference',
    },
    {
      name: 'FIRST — EPSS (Exploit Prediction Scoring System)',
      url: 'https://www.first.org/epss/',
      blurb: 'A data-driven model estimating the probability that a published CVE will be exploited in the wild within the next 30 days, published daily as free scores and percentiles. The exploitation-likelihood dimension a CVSS Base Score deliberately does not measure.',
      kind: 'reference',
    },
    {
      name: 'Vulnerability-Lookup (CIRCL)',
      url: 'https://vulnerability.circl.lu/',
      blurb: 'A free, open-source vulnerability platform run by CIRCL, Luxembourg\'s national CERT — correlates advisories across national databases, CSAF providers, and community feeds, and adds real-world "sightings" plus several KEV catalogs, which is the evidence a Base Score alone leaves you needing.',
      kind: 'recommendation',
    },
  ],
  'hash-calculator': [
    FIPS_180_4_ENTRY,
    {
      name: 'CyberChef',
      url: 'https://gchq.github.io/CyberChef/',
      blurb: "GCHQ's browser-based \"Cyber Swiss Army Knife\" runs entirely client-side like this tool, but lets you chain hash generation with dozens of other decoding/encoding operations — useful when the data needs unwrapping (Base64, XOR, etc.) before you can even hash it.",
      kind: 'recommendation',
    },
    {
      name: 'VirusTotal',
      url: 'https://www.virustotal.com/',
      blurb: 'Paste an MD5, SHA-1, or SHA-256 into VirusTotal\'s free search box to check it against 70+ antivirus engines and community reputation data — the natural next step once this tool computes or verifies a hash and you need to know if it matches known malware.',
      kind: 'recommendation',
    },
    {
      name: 'Hashes.com Hash Type Identifier',
      url: 'https://hashes.com/en/tools/hash_identifier',
      blurb: "A free, no-signup complement to this tool's own algorithm-guessing feature, covering a much wider range of hash formats (NTLM, bcrypt, and dozens more) for bare hashes that fall outside the MD5/SHA family this tool checks.",
      kind: 'recommendation',
    },
  ],
  'ioc-extractor': [
    {
      name: 'NVD (National Vulnerability Database)',
      url: 'https://nvd.nist.gov/',
      blurb: "For CVE IDs the extractor flags, NIST's own NVD is the authoritative source behind those identifiers — full descriptions, CVSS severity scores, and affected products for any CVE you search.",
      kind: 'reference',
    },
    {
      name: 'CyberChef',
      url: 'https://gchq.github.io/CyberChef/',
      blurb: "GCHQ's browser-based \"Cyber Swiss Army Knife\" has dedicated Extract IP address/URL/Email operations plus Defang IP Address and Defang URL recipes you can chain after decoding steps (Base64, hex, gzip, etc.) — useful when the IOCs you need aren't sitting in plaintext but buried inside obfuscated or encoded log data first.",
      kind: 'recommendation',
    },
    {
      name: 'VirusTotal',
      url: 'https://www.virustotal.com/',
      blurb: 'The natural next step after extraction: paste an extracted hash, IP, domain, or URL into VirusTotal\'s free lookup to check its reputation against 70+ antivirus engines and blocklists, no account required for a basic search.',
      kind: 'recommendation',
    },
    {
      name: 'Blockchain.com Explorer',
      url: 'https://www.blockchain.com/explorer',
      blurb: 'For Bitcoin addresses pulled out of a ransom note or fraud report, this free block explorer lets you paste the address and instantly see its balance and full transaction history, no signup needed.',
      kind: 'recommendation',
    },
  ],
  'regex-tester': [
    MDN_JS_REGEX_ENTRY,
    {
      name: 'regex101',
      url: 'https://regex101.com/',
      blurb: 'A full-featured online regex debugger supporting PCRE2, Python, Golang, and JavaScript flavors with live match highlighting, a plain-English breakdown of every capture group, and a substitution/unit-test mode — worth reaching for when an investigation needs a specific engine\'s exact behavior or more elaborate testing than this site\'s single-flavor playground offers.',
      kind: 'recommendation',
    },
    {
      name: 'CyberChef',
      url: 'https://gchq.github.io/CyberChef/',
      blurb: "GCHQ's browser-based \"Cyber Swiss Army Knife\" chains regex extraction (via its Find/Replace and Register operations) together with base64/hex decoding, XOR, and hundreds of other transforms — the natural next step when a DFIR pattern match on this site's tester needs to feed into further decoding of obfuscated or encoded artifact data, all still fully client-side.",
      kind: 'recommendation',
    },
    {
      name: 'iHateRegex',
      url: 'https://ihateregex.io/',
      blurb: 'A community-maintained regex cheat sheet with visual railroad-diagram breakdowns and a live testing playground for common general-purpose patterns (IPs, emails, dates, phone numbers) — a useful complement to this site\'s DFIR-specific pattern library (SIDs, GUIDs, Windows paths) when a broader, non-forensics pattern is needed.',
      kind: 'recommendation',
    },
  ],
  deobfuscator: [
    {
      name: 'CyberChef',
      url: 'https://gchq.github.io/CyberChef/',
      blurb: "GCHQ's browser-based \"Cyber Swiss Army Knife\" uses the same drag-and-drop recipe-chaining idea as this tool (Base64, hex, XOR, Gunzip, ROT13…) but with 300+ operations — reach for it when a payload needs a step this tool doesn't have, like AES/RC4 decryption, regex extraction, or hex-dump parsing.",
      kind: 'recommendation',
    },
    {
      name: 'dCode.fr — XOR Cipher',
      url: 'https://www.dcode.fr/xor-cipher',
      blurb: "Adds automatic XOR key bruteforce (1–16 bytes), key-length cryptanalysis, and frequency-analysis attacks for recovering an unknown key — useful when this tool's single-byte XOR step needs a key you don't already have (dCode's companion ROT-13/ROT-47 pages cover the same rotation ciphers this tool implements).",
      kind: 'recommendation',
    },
    {
      name: 'de4js',
      url: 'https://thanhle.io.vn/de4js/',
      blurb: "A dedicated JavaScript deobfuscator/unpacker (eval-based packers, JJencode, AAencode, JSFuck, Dean Edwards' Packer) for droppers whose payload is obfuscated JavaScript source itself rather than Base64/hex/XOR/gzip-wrapped binary data, which is outside this tool's scope.",
      kind: 'recommendation',
    },
  ],
  'email-header-analyzer': [
    {
      name: 'RFC 7208 — Sender Policy Framework (SPF)',
      url: 'https://www.rfc-editor.org/rfc/rfc7208',
      blurb: "The IETF standard defining the SPF DNS TXT-record mechanism this tool's SPF verdicts are read straight out of — how a domain publishes which mail servers are authorized to send on its behalf.",
      kind: 'reference',
    },
    {
      name: 'RFC 6376 — DomainKeys Identified Mail (DKIM) Signatures',
      url: 'https://www.rfc-editor.org/rfc/rfc6376',
      blurb: "The IETF standard for the cryptographic signature this tool's DKIM verdicts are read from — how a receiver verifies a message wasn't altered in transit and was authorized by its claimed signing domain.",
      kind: 'reference',
    },
    {
      name: 'RFC 9989 — DMARC (2026 revision)',
      url: 'https://www.rfc-editor.org/rfc/rfc9989',
      blurb: 'The current DMARC policy specification ("DMARCbis," May 2026 — supersedes the older RFC 7489) this tool\'s DMARC verdicts are read from — how SPF and DKIM results tie to the visible From: domain.',
      kind: 'reference',
    },
    {
      name: 'MxToolbox Email Header Analyzer',
      url: 'https://mxtoolbox.com/EmailHeaders.aspx',
      blurb: "A free web-based alternative that parses the same Received chain and SPF/DKIM/DMARC results, but adds sender-IP blacklist and reputation checks this site's client-side tool doesn't perform.",
      kind: 'recommendation',
    },
    {
      name: 'Google Admin Toolbox Messageheader',
      url: 'https://toolbox.googleapps.com/apps/messageheader/',
      blurb: "Google's free header analyzer visualizes the hop-by-hop delay timeline across the Received chain, useful as a second opinion when triaging Gmail/Workspace-originated mail.",
      kind: 'recommendation',
    },
    {
      name: 'CyberChef',
      url: 'https://gchq.github.io/CyberChef/',
      blurb: "GCHQ's browser-based \"Cyber Swiss Army Knife\" complements the header tool by decoding obfuscated or encoded content (Base64, quoted-printable, URL-encoding) often found in phishing headers and bodies that a header parser alone won't unpack.",
      kind: 'recommendation',
    },
    {
      name: 'VirusTotal',
      url: 'https://www.virustotal.com/gui/home/url',
      blurb: 'The natural next step after this tool flags a Received-chain hop, sending IP, or spoofed domain: look up that indicator\'s reputation across 70+ security engines for free, with no account required for a query.',
      kind: 'recommendation',
    },
  ],
  'jwt-decoder': [
    {
      name: 'RFC 7519 — JSON Web Token (JWT)',
      url: 'https://www.rfc-editor.org/rfc/rfc7519',
      blurb: "The IETF standard defining the JWT claims format this tool decodes — the seven Registered Claim Names (iss, sub, aud, exp, nbf, iat, jti) and the NumericDate format the Expired/Not-yet-valid verdicts are computed from.",
      kind: 'reference',
    },
    {
      name: 'RFC 7515 — JSON Web Signature (JWS)',
      url: 'https://www.rfc-editor.org/rfc/rfc7515',
      blurb: "The IETF standard for the compact serialization format itself — the three base64url segments this tool splits on — and the header's \"alg\" parameter this tool reads back without ever using it to verify anything.",
      kind: 'reference',
    },
    {
      name: 'OWASP — Testing JSON Web Tokens',
      url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens',
      blurb: "OWASP's Web Security Testing Guide chapter on JWT-specific attack classes — algorithm confusion, the \"alg: none\" unsecured-JWS trick, weak HMAC secrets — the exact failure modes that make blindly trusting a decoded-but-unverified token dangerous.",
      kind: 'reference',
    },
    {
      name: 'jwt.io Debugger',
      url: 'https://jwt.io/',
      blurb: "Auth0/Okta's well-known JWT debugger goes a step further than this page: given the signing secret or public key, it can actually verify a token's signature, not just decode its contents — the check this site's client-side tool deliberately never attempts.",
      kind: 'recommendation',
    },
  ],
  'user-agent-parser': [
    {
      name: 'MDN — HTTP User-Agent header',
      url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/User-Agent',
      blurb: "MDN's reference for the header itself: the product/version/comment syntax, the current per-browser string formats for Firefox, Chrome, Edge, Opera and Safari, and the User-Agent reduction that freezes platform and device values. The primary source behind this page's token tables.",
      kind: 'reference',
    },
    {
      name: 'MDN — Browser detection using the user agent',
      url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Browser_detection_using_the_user_agent',
      blurb: 'The guidance page that explains why UA sniffing is unreliable, gives the must-contain/must-not-contain token table this parser\'s check order follows, and names the "Mobi" substring as the least-unreliable mobile signal. Read this before building anything on top of a parsed result.',
      kind: 'reference',
    },
    {
      name: 'MDN — Firefox user agent string reference',
      url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/User-Agent/Firefox',
      blurb: 'Mozilla\'s own breakdown of the Gecko UA format — what the legacy "Mozilla/5.0" compatibility token means, why desktop Firefox hardcodes its gecko-trail to 20100101, and the FxiOS quirk where Firefox on iPad carries no Firefox token at all.',
      kind: 'reference',
    },
    {
      name: 'RFC 9110 §10.1.5 — HTTP Semantics: User-Agent',
      url: 'https://www.rfc-editor.org/rfc/rfc9110#name-user-agent',
      blurb: 'The IETF definition of the field this tool parses, including its ABNF and the standard\'s own warning that user agents generate it with enough detail to be used for fingerprinting — useful when you need to argue from the spec rather than from vendor docs.',
      kind: 'reference',
    },
    {
      name: 'Microsoft Learn — Detecting Microsoft Edge from your website',
      url: 'https://learn.microsoft.com/en-us/microsoft-edge/web-platform/user-agent-guidance',
      blurb: 'Microsoft\'s authoritative source for the Edg / EdgA / EdgiOS token split, why the shortened "Edg" token deliberately differs from legacy EdgeHTML\'s "Edge", and the confirmation that "Windows NT 10.0" was never updated for Windows 11.',
      kind: 'reference',
    },
    {
      name: 'Chromium — User Agent in Chrome for iOS',
      url: 'https://chromium.googlesource.com/chromium/src/+/lkgr/docs/ios/user_agent.md',
      blurb: "The Chromium project's own documentation of the CriOS token and why Chrome on iOS sends an otherwise Mobile-Safari-shaped string — the concrete case for why an iOS browser's engine is WebKit no matter which browser brand the UA claims.",
      kind: 'reference',
    },
    {
      name: 'Chrome for Developers — User-Agent Client Hints',
      url: 'https://developer.chrome.com/docs/privacy-security/user-agent-client-hints',
      blurb: "Google's guide to the Sec-CH-UA-* headers and navigator.userAgentData that are replacing UA-string parsing, plus the reasoning behind User-Agent reduction. Worth reading for what a modern client actually exposes beyond the legacy string this tool reads.",
      kind: 'reference',
    },
    {
      name: 'UAParser.js',
      url: 'https://github.com/faisalman/ua-parser-js',
      blurb: "The widely-used open-source UA detection library, with a far larger maintained pattern set than this page's deliberately small subset — the right tool when you need to parse UA strings in bulk and accept a library dependency (check its licensing, which changed between major versions).",
      kind: 'recommendation',
    },
    {
      name: 'WhatIsMyBrowser — User Agent Parser & database',
      url: 'https://explore.whatismybrowser.com/useragents/parse/',
      blurb: 'A free web-based parser backed by a large searchable database of real-world User-Agent strings — the practical second opinion when a string from a log comes back unrecognized here and you want to know whether anyone else has seen it before.',
      kind: 'recommendation',
    },
  ],
  'pe-explorer': [
    {
      name: 'PE Format — Microsoft Learn',
      url: 'https://learn.microsoft.com/en-us/windows/win32/debug/pe-format',
      blurb: "Microsoft's own official specification for the Portable Executable/COFF file format — the DOS header, NT headers, section table, and import structures this page's own parsing implements — worth consulting directly for a field this tool's summarized output doesn't fully expand.",
      kind: 'reference',
    },
    {
      name: 'PEStudio',
      url: 'https://www.winitor.com/',
      blurb: "A free/freemium Windows-only static PE inspector built specifically for malware initial assessment — it goes deeper than a headers/imports/imphash view by also flagging suspicious strings, checking imports against a blocklist of suspicious API calls, and auto-querying VirusTotal for the file's hash reputation.",
      kind: 'recommendation',
    },
    {
      name: 'VirusTotal',
      url: 'https://www.virustotal.com/',
      blurb: "Free hash/file lookup against 70+ antivirus engines and sandboxes — after computing a file's imphash or other hashes locally with PE Header Explorer, paste the hash into VirusTotal to check reputation and see if the same import-hash cluster has been seen in known malware families.",
      kind: 'recommendation',
    },
    {
      name: 'Detect It Easy (DIE)',
      url: 'https://github.com/horsicq/Detect-It-Easy',
      blurb: 'A free, open-source (MIT) file-type and packer/compiler/cryptor identification tool for PE, ELF, and Mach-O binaries — a natural next step after PE Header Explorer\'s static header parse, since a packed or encrypted section table often explains why imports/exports look sparse or obfuscated.',
      kind: 'recommendation',
    },
    {
      name: 'CFF Explorer (NTCore Explorer Suite)',
      url: 'https://ntcore.com/explorer-suite/',
      blurb: 'A free Windows PE editor/viewer with full PE32/64 and .NET support — where PE Header Explorer is read-only, CFF Explorer lets an analyst interactively edit headers, rebuild the import table, and disassemble sections for deeper manual reverse engineering.',
      kind: 'recommendation',
    },
  ],
  'lnk-parser': [
    {
      name: '[MS-SHLLINK]: Shell Link (.LNK) Binary File Format — Microsoft Learn',
      url: 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943',
      blurb: "Microsoft's own authoritative binary-format spec that this tool's parsing logic implements, worth consulting directly when you need to verify a specific field or dig into a structure (e.g. LinkInfo, the LinkTargetIDList shell-item breadcrumb) beyond what the summarized output shows.",
      kind: 'reference',
    },
    {
      name: "Eric Zimmerman's LECmd (EZ Tools)",
      url: 'https://ericzimmerman.github.io/',
      blurb: 'The de facto industry-standard offline LNK parser (part of the free EZ Tools/KAPE suite used by FBI and Kroll IR teams), useful as a deeper, batch-capable alternative when you need to process an entire evidence set of .lnk files with CSV/timeline output rather than one file at a time in the browser.',
      kind: 'recommendation',
    },
    {
      name: 'ExifTool',
      url: 'https://exiftool.org/',
      blurb: "Phil Harvey's widely used cross-platform metadata utility ships a dedicated LNK module, making it a handy way to cross-check a shortcut's extracted fields as part of a broader multi-format triage workflow spanning many file types at once.",
      kind: 'recommendation',
    },
    {
      name: 'LnkParse3',
      url: 'https://github.com/Matmaus/LnkParse3',
      blurb: 'An actively maintained open-source Python LNK parser with JSON output, useful as a scriptable alternative when you need to batch-process or pipeline many .lnk files programmatically instead of pasting them one at a time into a browser tool.',
      kind: 'recommendation',
    },
  ],
  'recycle-bin-parser': [
    {
      name: 'libyal / dtformats — Windows Recycle.Bin file formats',
      url: 'https://github.com/libyal/dtformats/blob/main/documentation/Windows%20Recycle.Bin%20file%20formats.asciidoc',
      blurb: "Joachim Metz's byte-level documentation of the $I metadata record — the offset tables this tool's parser implements for both format version 1 and version 2. Microsoft publishes no specification for $I, so this format-documentation project (the same effort behind the libyal forensic libraries) is the closest thing to an authoritative reference and is worth reading directly for the raw structures.",
      kind: 'reference',
    },
    {
      name: 'MITRE ATT&CK T1070.004 — Indicator Removal: File Deletion',
      url: 'https://attack.mitre.org/techniques/T1070/004/',
      blurb: "MITRE's authoritative page for the Stealth-tactic technique that makes this artifact matter: an adversary deleting the files their intrusion left behind. Useful for the detection guidance and real-world procedure examples that frame what a recovered $I record actually evidences.",
      kind: 'reference',
    },
    {
      name: "Eric Zimmerman's RBCmd (EZ Tools)",
      url: 'https://ericzimmerman.github.io/',
      blurb: 'The de facto industry-standard offline Recycle Bin parser, listed on this page as an "INFO2/$I" parser — reach for it when you need to process a whole $Recycle.Bin directory into CSV for timeline work, rather than decoding one record at a time in the browser.',
      kind: 'recommendation',
    },
    {
      name: 'rifiuti2',
      url: 'https://github.com/abelcheung/rifiuti2',
      blurb: "Abel Cheung's cross-platform open-source Recycle Bin parser, shipping separate binaries for the pre-Vista INFO2 index and for the modern $Recycle.Bin $I records, with XML/JSON output. A good scriptable second opinion on Linux/macOS, and its source is a useful cross-check on the $I field offsets.",
      kind: 'recommendation',
    },
    {
      name: 'Magnet Forensics — Artifact Profile: Windows Recycle Bin',
      url: 'https://www.magnetforensics.com/blog/artifact-profile-recycle-bin/',
      blurb: 'A vendor-written practitioner overview of the artifact as a whole — where the per-user folders live, how the $I/$R pair works, and what the Recycle Bin does and does not capture. Useful investigative context around the raw fields this tool decodes.',
      kind: 'recommendation',
    },
  ],
  'prefetch-parser': [
    {
      name: '[MS-XCA]: Xpress Compression Algorithm — Microsoft Learn',
      url: 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/a8b7cb0a-92a6-4187-a23b-5e14273b96f8',
      blurb: "Microsoft's own published specification for the LZ77+Huffman variant of Xpress — the algorithm that wraps every Windows 10/11 Prefetch file inside its MAM container, and the reason this browser tool stops at detecting those files instead of decoding them.",
      kind: 'reference',
    },
    {
      name: 'RtlDecompressBufferEx (ntifs.h) — Microsoft Learn',
      url: 'https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldecompressbufferex',
      blurb: 'The Windows API that performs the decompression, documenting COMPRESSION_FORMAT_XPRESS_HUFF as a supported format. This is the function offline Prefetch tools call on a Windows host, which is why several of them require Windows 8 or newer to open a Windows 10 file at all.',
      kind: 'reference',
    },
    {
      name: 'libyal/libscca — Windows Prefetch File (SCCA) format documentation',
      url: 'https://github.com/libyal/libscca',
      blurb: "Joachim Metz's reverse-engineered format specification — the per-version structure tables this parser's offsets come from — plus a C library and the sccainfo command-line tool that reads compressed Windows 10 files this browser tool cannot.",
      kind: 'recommendation',
    },
    {
      name: "Eric Zimmerman's PECmd (EZ Tools)",
      url: 'https://github.com/EricZimmerman/PECmd',
      blurb: 'The de facto industry-standard offline Prefetch parser. It handles the compressed Windows 10/11 format and can write the decompressed bytes back out, so it is the natural next step for any file this tool identifies as a MAM container, and for batch/CSV timeline output across a whole evidence set.',
      kind: 'recommendation',
    },
    {
      name: 'Forensics Wiki — Windows Prefetch File Format',
      url: 'https://forensics.wiki/windows_prefetch_file_format/',
      blurb: "A second, independently maintained write-up of the same header and file-information structures, useful for cross-checking an offset before trusting it — it's the source this tool's own layout constants were verified against.",
      kind: 'recommendation',
    },
    {
      name: 'SANS Internet Storm Center — Forensic Value of Prefetch',
      url: 'https://isc.sans.edu/diary/Forensic+Value+of+Prefetch/29168',
      blurb: 'A practitioner diary on how to actually use the artifact: what the NAME-HASH.pf filename encodes, the eight-timestamp change in Windows 8, and the folder retention limits (128 files on Windows 7 and older, 1,024 on Windows 8 and newer) that shape how much history you can expect to recover.',
      kind: 'recommendation',
    },
  ],
  'mft-usn-analyzer': [
    {
      name: 'MITRE ATT&CK T1070.006 — Timestomp',
      url: 'https://attack.mitre.org/techniques/T1070/006/',
      blurb: "MITRE's authoritative reference for the Stealth-tactic Timestomp technique, including 'double timestomping' (where both $SI and $FN are altered to defeat exactly this kind of comparison) and real-world procedure examples for interpreting what a flagged mismatch actually indicates.",
      kind: 'reference',
    },
    {
      name: "MFTECmd (Eric Zimmerman's EZ Tools)",
      url: 'https://github.com/EricZimmerman/MFTECmd',
      blurb: 'The free, actively-maintained, industry-standard command-line parser for $MFT, $J (USN journal), $LogFile, $Boot and $SDS — run it against a full disk image or extracted $MFT to batch-extract every $SI/$FN timestamp pair at scale, complementing this page\'s single-record deep dive.',
      kind: 'recommendation',
    },
    {
      name: 'USN Journal Viewer & Parser',
      url: 'https://www.usnparser.com/en',
      blurb: 'A free tool that parses a raw $UsnJrnl:$J file entirely client-side in the browser (WebAssembly, nothing uploaded to a server) and can optionally cross-reference an uploaded $MFT to resolve full paths, useful for triaging a full USN journal export before drilling into one record here.',
      kind: 'recommendation',
    },
    {
      name: 'SANS DFIR: Detecting Time Stamp Manipulation',
      url: 'https://www.sans.org/blog/digital-forensics-detecting-time-stamp-manipulation',
      blurb: 'A SANS walkthrough of a real intrusion where comparing $STANDARD_INFORMATION against $FILE_NAME timestamps exposed an attacker disguising a malicious binary as a legitimate system file — the same $SI-vs-$FN detection logic this tool automates, shown against a live case.',
      kind: 'recommendation',
    },
  ],
  'kql-builder': [
    {
      name: 'Kusto Query Language (KQL) overview',
      url: 'https://learn.microsoft.com/en-us/kusto/query/',
      blurb: "Microsoft's own reference landing page for the whole language — the authority on every operator, function, and data type beyond the single-table pipeline this builder assembles.",
      kind: 'reference',
    },
    {
      name: 'Advanced hunting schema reference (Microsoft Defender XDR)',
      url: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables',
      blurb: 'The complete list of advanced hunting tables, each linking to its own per-column schema page. The authority on the full column set this builder only carries a DFIR-relevant subset of.',
      kind: 'reference',
    },
    {
      name: 'Advanced hunting query best practices',
      url: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-best-practices',
      blurb: "Microsoft's documented guidance on writing queries that don't time out — filter early, has beats contains, project selectively — and the source of the performance hints this tool surfaces as you build.",
      kind: 'reference',
    },
    {
      name: 'Kusto string operators reference',
      url: 'https://learn.microsoft.com/en-us/kusto/query/datatypes-string-operators',
      blurb: 'The per-operator table that settles which string comparisons are case-sensitive, plus the explanation of how term indexing makes has fundamentally different from contains.',
      kind: 'reference',
    },
    {
      name: 'Microsoft Sentinel & Defender XDR content repository',
      url: 'https://github.com/Azure/Azure-Sentinel',
      blurb: 'The MIT-licensed, community-contributed repository of real hunting queries, detection rules, workbooks, and parsers for Sentinel and Defender — thousands of working KQL queries to read, adapt, and learn the idioms from.',
      kind: 'recommendation',
    },
    {
      name: 'Must Learn KQL (Rod Trent)',
      url: 'https://github.com/rod-trent/MustLearnKQL',
      blurb: 'A free, MIT-licensed 21-part KQL course with queries, an eBook, workshop material, and companion videos — the resource most people are pointed at when they ask how to actually learn the language.',
      kind: 'recommendation',
    },
  ],
  'sigma-tester': [
    {
      name: 'Sigma Detection Format (sigmahq.io)',
      url: 'https://sigmahq.io/',
      blurb: 'The authoritative Sigma specification and documentation site, the reference to consult for full YAML syntax, field modifiers, and correlation-rule features beyond what this tool\'s built-in builder exposes.',
      kind: 'reference',
    },
    {
      name: 'Uncoder IO (SOC Prime)',
      url: 'https://uncoder.io/',
      blurb: 'A free browser-based IDE that translates Sigma rules into 12+ real SIEM/EDR/XDR query languages (Splunk, Elastic, Microsoft Sentinel, and more) — use it once a rule passes here to actually deploy it in a production platform.',
      kind: 'recommendation',
    },
    {
      name: 'SigmaHQ Rule Repository',
      url: 'https://github.com/SigmaHQ/sigma',
      blurb: 'The official, peer-reviewed collection of thousands of community-maintained Sigma detection rules, a ready source of real-world rules to paste into this tester and validate against your own sample log events.',
      kind: 'recommendation',
    },
    {
      name: 'Chainsaw (WithSecure Labs)',
      url: 'https://github.com/WithSecureLabs/chainsaw',
      blurb: 'A free, actively maintained command-line tool that runs Sigma rules directly against real Windows Event Log (EVTX) artifacts, a next step from this tool\'s sample-event testing when you need to hunt across an actual forensic dataset.',
      kind: 'recommendation',
    },
  ],
  'yara-tester': [
    {
      name: 'Writing YARA rules (official YARA documentation)',
      url: 'https://yara.readthedocs.io/en/stable/writingrules.html',
      blurb: 'The authoritative YARA rule-writing reference — the full string-modifier set, hex-string jumps and alternatives, the complete condition grammar, and the module system. The source this page\'s supported subset was written against, and where to go for everything the subset deliberately leaves out.',
      kind: 'reference',
    },
    {
      name: 'YARA-X documentation (VirusTotal)',
      url: 'https://virustotal.github.io/yara-x/',
      blurb: 'Official docs for YARA-X, VirusTotal\'s Rust rewrite of YARA — roughly rule-compatible with YARA 4.x but stricter about a few constructs the older parser tolerated. Worth reading alongside the YARA docs when a rule behaves differently between the two engines.',
      kind: 'reference',
    },
    {
      name: 'YARAify (abuse.ch / Spamhaus)',
      url: 'https://yaraify.abuse.ch/',
      blurb: 'A free platform for scanning files against a large public collection of YARA rules, and for publishing your own through YARAhub — the natural next step once a rule works here and you want to see how it behaves against real corpus data.',
      kind: 'recommendation',
    },
    {
      name: 'Awesome YARA (InQuest)',
      url: 'https://github.com/InQuest/awesome-yara',
      blurb: 'A large, actively curated index of YARA rule sets, editors, linters, scanning frameworks and style guides. The fastest way to find real published rules to study, or a rule-authoring tool that fits your workflow.',
      kind: 'recommendation',
    },
    {
      name: 'signature-base (Florian Roth)',
      url: 'https://github.com/Neo23x0/signature-base',
      blurb: 'A long-running open collection of YARA rules and IOCs written for low false-positive rates, released under the Detection Rule License. A good corpus of real, production-quality rules to read for authoring conventions.',
      kind: 'recommendation',
    },
  ],
  'timestamp-converter': [
    {
      name: 'DCode (Digital Detective)',
      url: 'https://www.digital-detective.net/dcode/',
      blurb: "A free downloadable Windows forensic utility supporting dozens of timestamp formats decoded directly from raw little/big-endian hex, integers, or floats pulled out of a forensic image — the deeper reference when a value needs decoding straight from a hex dump or a format falls outside this tool's 19.",
      kind: 'recommendation',
    },
    {
      name: 'Epoch Converter',
      url: 'https://www.epochconverter.com/',
      blurb: 'A browser-based converter with dedicated sub-pages for formats like LDAP/Active Directory FILETIME, .NET ticks, and GPS time, handy as a quick second opinion to cross-check a conversion this tool just produced.',
      kind: 'recommendation',
    },
    {
      name: 'CyberChef',
      url: 'https://gchq.github.io/CyberChef/',
      blurb: 'A free, open-source, browser-only "data Swiss Army knife" with dedicated recipe operations such as From UNIX Timestamp and Windows Filetime to UNIX Timestamp, useful when a timestamp has to be pulled out of a larger blob of hex/base64 as one step in a longer decode chain rather than converted on its own.',
      kind: 'recommendation',
    },
  ],
  'cidr-calculator': [
    RFC_4632_ENTRY,
    {
      name: 'RFC 1878 — Variable Length Subnet Table For IPv4',
      url: 'https://www.rfc-editor.org/rfc/rfc1878',
      blurb: "The original VLSM (Variable Length Subnet Masking) reference this page's own \"Custom sizes (VLSM)\" planner mode implements — includes the full subnet-size/host-count table for every prefix length.",
      kind: 'reference',
    },
    {
      name: 'Visual Subnet Calculator',
      url: 'https://www.davidc.net/sites/default/subnets/subnets.html',
      blurb: 'A free interactive tool that visually splits and joins subnets within a base network as you click — useful for cross-checking this page\'s own VLSM planner output, or for exploring "what if" splits before committing to a segmentation plan.',
      kind: 'recommendation',
    },
  ],
  'mac-address': [
    {
      name: 'IEEE Registration Authority — Search for an Assignment',
      url: 'https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries',
      blurb: "The IEEE's own public search tool for OUI/MA-L assignments — paste the OUI this page decodes into its lookup form to find the organization it was actually issued to, the one question this tool deliberately doesn't answer itself.",
      kind: 'reference',
    },
    {
      name: 'IEEE Public OUI Listing (oui.txt)',
      url: 'https://standards-oui.ieee.org/oui/oui.txt',
      blurb: "The Registration Authority's own raw, downloadable listing of every OUI assignment and the organization behind it — the authoritative source behind any vendor-lookup tool, useful for bulk or offline lookups against many OUIs at once rather than one at a time.",
      kind: 'reference',
    },
  ],
  'cron-parser': [
    {
      name: "cronie's crontab(5) man page (man7.org)",
      url: 'https://man7.org/linux/man-pages/man5/crontab.5.html',
      blurb: "The crontab(5) documentation for cronie — the crond most Linux distributions ship — and the actual source this page's field grammar (names, step values, the day-of-month/day-of-week OR rule, the 0–7 day-of-week range, and the 7 '@'-nickname extensions) was verified against.",
      kind: 'reference',
    },
    {
      name: 'The Open Group Base Specifications — crontab utility (POSIX)',
      url: 'https://pubs.opengroup.org/onlinepubs/9699919799/utilities/crontab.html',
      blurb: "The narrower POSIX crontab specification this page contrasts its own (wider, cronie-based) grammar against — numeric-only fields, day-of-week strictly 0–6, and no step values or names at all.",
      kind: 'reference',
    },
    {
      name: 'crontab.guru',
      url: 'https://crontab.guru/',
      blurb: "Cronitor's well-known interactive cron editor — a quick second opinion alongside this page's own parser, plus a library of common schedule examples worth skimming for inspiration.",
      kind: 'recommendation',
    },
  ],
  'base-converter': [
    {
      name: 'Unicode Basic Latin code chart',
      url: 'https://www.unicode.org/charts/PDF/U0000.pdf',
      blurb: "The Unicode Consortium's own official code chart for the Basic Latin block (U+0000–U+007F), listing every control character and printable glyph by exact code point — the authoritative reference behind this page's own printable-ASCII range check (0x20–0x7E).",
      kind: 'reference',
    },
    {
      name: 'CyberChef',
      url: 'https://gchq.github.io/CyberChef/',
      blurb: 'GCHQ\'s browser-based "Cyber Swiss Army Knife" has dedicated To Base/From Base operations (plus Base32/58/62/64/85 for the less common text encodings) — useful when a number needs converting as one step in a longer decode chain, chained together with the dozens of other operations this page doesn\'t attempt.',
      kind: 'recommendation',
    },
  ],
  'data-size-converter': [
    {
      name: "NIST — Definitions of the SI units: The binary prefixes",
      url: 'https://physics.nist.gov/cuu/Units/binary.html',
      blurb: "NIST's own reference distinguishing the decimal SI prefixes (kilo=10^3 through peta=10^15) from the binary IEC prefixes (kibi=2^10 through pebi=2^50), including the exact byte counts (1 MiB = 1,048,576 B, 1 GiB = 1,073,741,824 B) this page's own multiplier table is verified against, and the history of IEC 60027-2/IEC 80000-13 standardizing the binary set in 1998 to resolve the ambiguity.",
      kind: 'reference',
    },
    {
      name: 'Seagate — Why does my hard drive report less capacity than indicated on the label?',
      url: 'https://www.seagate.com/support/kb/why-does-my-hard-drive-report-less-capacity-than-indicated-on-the-drives-label-172191en/',
      blurb: "A drive manufacturer's own support article explaining, with the same 500 GB worked example this page uses, why their decimal (base-10) labeling convention and an OS's binary (base-2) reporting convention produce two different — but equally correct — numbers for the identical physical capacity.",
      kind: 'reference',
    },
  ],
  'ascii-table': [
    {
      name: 'Unicode 17.0 — C0 Controls and Basic Latin code chart',
      url: 'https://www.unicode.org/charts/PDF/U0000.pdf',
      blurb: "The Unicode Consortium's own official code chart for U+0000–U+007F — every mnemonic, full character name, and code point on this page is transcribed directly from it, since ASCII (ANSI X3.4) is normatively equivalent to this exact Unicode range.",
      kind: 'reference',
    },
    {
      name: 'RFC 3629 — UTF-8, a transformation format of ISO 10646',
      url: 'https://www.rfc-editor.org/rfc/rfc3629',
      blurb: "The IETF standard defining UTF-8 — including the rule this page's own explainer cites, that code points U+0000–U+007F (the ASCII range) encode as the identical single bytes 00–7F, making any plain ASCII file automatically valid UTF-8.",
      kind: 'reference',
    },
    {
      name: 'CyberChef',
      url: 'https://gchq.github.io/CyberChef/',
      blurb: 'GCHQ\'s browser-based "Cyber Swiss Army Knife" has dedicated To/From Hex, To/From Charcode, and Encode/Decode text (UTF-8, UTF-16, and dozens of other codepages) operations — useful for converting a whole string rather than looking up one character at a time.',
      kind: 'recommendation',
    },
  ],
  'text-diff': [
    {
      name: 'GNU Diffutils Manual',
      url: 'https://www.gnu.org/software/diffutils/manual/diffutils.html',
      blurb: "The authoritative reference for diff, diff3, sdiff, cmp, and patch — including the unified/context output formats this page's own diff view draws its conventions from, plus three-way and directory comparison this single-page tool doesn't attempt.",
      kind: 'reference',
    },
    {
      name: 'Diffchecker',
      url: 'https://www.diffchecker.com/',
      blurb: 'A free, well-known web-based diff tool that goes beyond plain text — images, PDFs, Excel files, and whole folders — useful when a comparison needs a format this tool doesn\'t handle.',
      kind: 'recommendation',
    },
  ],
  osint: [
    {
      name: 'OSINT Framework',
      url: 'https://osintframework.com/',
      blurb: 'A free, categorized directory of hundreds of OSINT tools and resources (usernames, email, domains, social media, and more) — a good next stop once a dork built here surfaces a lead that needs a specialized lookup tool rather than a search engine.',
      kind: 'recommendation',
    },
    {
      name: 'Google Hacking Database (GHDB)',
      url: 'https://www.exploit-db.com/google-hacking-database',
      blurb: 'Offensive Security\'s maintained archive of thousands of categorized real-world Google dorks (exposed files, login portals, error messages, vulnerable servers) — a library of proven query patterns to pull from or adapt when building custom dorks in this tool.',
      kind: 'recommendation',
    },
    {
      name: 'IntelTechniques Search Tools',
      url: 'https://inteltechniques.com/tools/',
      blurb: "Michael Bazzell's (former FBI cyber investigator) collection of purpose-built search forms that auto-generate multi-source queries for emails, usernames, phone numbers, domains, and more — complements this tool's generic dork builder with pre-built, data-type-specific OSINT search automation.",
      kind: 'recommendation',
    },
  ],
  // The 7 /drills/* knowledge-check modules — same key-by-route-slug
  // convention as the tool pages above (the segment after /drills/).
  regex: [
    {
      name: 'Chapter 9. Regular Expressions — POSIX.1-2017',
      url: 'https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap09.html',
      blurb: "The Open Group / IEEE's authoritative POSIX specification for Basic and Extended Regular Expressions (BRE/ERE) — the base grammar most regex flavors, including this drill's own patterns, build on.",
      kind: 'reference',
    },
    MDN_JS_REGEX_ENTRY,
  ],
  'ip-cidr': [
    RFC_4632_ENTRY,
    {
      name: 'RFC 1918: Address Allocation for Private Internets',
      url: 'https://www.rfc-editor.org/rfc/rfc1918.html',
      blurb: "The IETF's foundational specification for the three private IPv4 address blocks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) this drill's special-use range questions draw from.",
      kind: 'reference',
    },
    {
      name: 'SubnetIPv4.com (IPv4 Subnetting Practice Generator)',
      url: 'https://subnetipv4.com/',
      blurb: "Practical Networking's free, genuinely interactive subnetting trainer: it generates a random target IP/CIDR and auto-checks your computed network ID, first/last host, and broadcast address as you type — the same skill this drill's own questions test, with unlimited fresh problems.",
      kind: 'recommendation',
    },
  ],
  hashing: [
    FIPS_180_4_ENTRY,
    {
      name: 'FIPS 202, SHA-3 Standard',
      url: 'https://csrc.nist.gov/pubs/fips/202/final',
      blurb: "NIST's authoritative standard for SHA-3 (Keccak-based) hash and extendable-output functions, the newest member of the hash family this drill covers.",
      kind: 'reference',
    },
    {
      name: 'Hashcat Wiki: Example Hashes',
      url: 'https://hashcat.net/wiki/doku.php?id=example_hashes',
      blurb: "The Hashcat project's own reference table of a real example hash for essentially every format it supports (MD5, NTLM, bcrypt, Kerberos, and hundreds more) — a free, well-known way to drill format recognition well past the MD5/SHA family this drill's own questions cover.",
      kind: 'recommendation',
    },
  ],
  attack: [
    {
      name: 'Get Started — MITRE ATT&CK',
      url: 'https://attack.mitre.org/resources/',
      blurb: "MITRE's own introduction to the ATT&CK framework — what it is and how it's used for detection, threat intel, and adversary emulation, the context behind this drill's technique-recognition questions.",
      kind: 'reference',
    },
    {
      name: 'Atomic Red Team',
      url: 'https://www.atomicredteam.io/',
      blurb: "Red Canary's free, open-source library of 1,800+ small tests, each mapped to a specific ATT&CK technique — run one in a lab VM to generate the exact telemetry that technique produces, then practice recognizing it yourself, a hands-on step up from this drill's own recall questions.",
      kind: 'recommendation',
    },
  ],
  'event-ids': [
    {
      name: 'Sysmon - Sysinternals',
      url: 'https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon',
      blurb: "Microsoft's own Sysmon documentation, listing every Sysmon event ID and what it records — the authoritative source behind this drill's Sysmon sample-log questions.",
      kind: 'reference',
    },
    {
      name: 'LetsDefend — "Log Analysis With Sysmon" challenge',
      url: 'https://app.letsdefend.io/challenge/log-analysis-with-sysmon',
      blurb: 'A free (account required) hands-on challenge on this blue-team training platform: investigate a real Sysmon capture from a "breached endpoint" — initial access, privilege escalation, defense evasion — a genuine incident to work through beyond this drill\'s own single-event recall questions.',
      kind: 'recommendation',
    },
  ],
  // Split by OS track to match the three dedicated terminal drills at
  // /drills/commands/{bash,cmd,powershell}/ (previously one combined
  // 'commands' key, from when all three shells shared a single quiz page).
  'commands-bash': [
    {
      name: 'GNU Coreutils (online manual)',
      url: 'https://www.gnu.org/software/coreutils/manual/coreutils.html',
      blurb: "The FSF/GNU's full reference manual for the core Linux/macOS command-line utilities this drill covers.",
      kind: 'reference',
    },
    {
      name: 'OverTheWire: Bandit',
      url: 'https://overthewire.org/wargames/bandit/',
      blurb: "The OverTheWire community's free, classic beginner wargame: each level's password is found using real shell commands, then used to SSH into the next level — the definitive hands-on way to build the muscle memory this drill's own command recall only tests in isolation.",
      kind: 'recommendation',
    },
  ],
  'commands-cmd': [
    {
      name: 'Windows commands — Microsoft Learn',
      url: 'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands',
      blurb: "Microsoft's authoritative A-Z reference for the built-in cmd.exe commands this drill covers.",
      kind: 'reference',
    },
    {
      name: 'TryHackMe: "Windows Command Line" room',
      url: 'https://tryhackme.com/room/windowscommandline',
      blurb: 'A free TryHackMe room (account required) that deploys a real Windows VM and walks through native cmd.exe commands — system info, network troubleshooting, file/disk management, process management — with graded questions, hands-on practice beyond this drill\'s own recall format.',
      kind: 'recommendation',
    },
  ],
  'commands-powershell': [
    {
      name: 'PowerShell documentation — Microsoft Learn',
      url: 'https://learn.microsoft.com/en-us/powershell/',
      blurb: "Microsoft's official PowerShell docs — cmdlet reference, the object pipeline, and scripting guides for everything this drill covers.",
      kind: 'reference',
    },
    {
      name: 'PSKoans',
      url: 'https://github.com/vexx32/PSKoans',
      blurb: "Joel Sallow's free, open-source PowerShell module that teaches the language through 635+ \"koans\" — failing Pester tests you make pass by writing real PowerShell — installed straight from the PowerShell Gallery and worked through in your own terminal, a deeper, hands-on complement to this drill's own recall questions.",
      kind: 'recommendation',
    },
  ],
  // Missing until this pass — the Threat Actor / APT reference + drill are
  // the newest addition to the site and hadn't been wired into this file yet.
  // Both entries below are individual/org-community resources rather than a
  // standards-body spec (the model itself has no formal spec to cite) — see
  // this key's own comment in pyramid-of-pain.astro for why both are
  // 'recommendation', not 'reference', despite Bianco's post being the
  // actual primary source this page's content was verified against.
  'pyramid-of-pain': [
    {
      name: 'The Pyramid of Pain — David Bianco',
      url: 'https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html',
      blurb: "David Bianco's own original 2013 post introducing the model (updated 2014 to add the Hash Values level) — the primary source this page's every level and its reasoning was verified against directly.",
      kind: 'recommendation',
    },
    {
      name: 'SANS — The Pyramid of Pain',
      url: 'https://www.sans.org/tools/the-pyramid-of-pain',
      blurb: "SANS's own summary page for the model, crediting Bianco as its creator — a good second reference point alongside his original post.",
      kind: 'recommendation',
    },
  ],
  'threat-actors': [
    {
      name: 'MITRE ATT&CK Groups',
      url: 'https://attack.mitre.org/groups/',
      blurb: "MITRE's own official index of every documented threat actor / intrusion-set group — the authoritative dataset this site's own Threat Actor / APT Reference and drill are both generated from.",
      kind: 'reference',
    },
    {
      name: 'Malpedia',
      url: 'https://malpedia.caad.fkie.fraunhofer.de/',
      blurb: "Fraunhofer FKIE's free, publicly browsable malware-family and threat-actor reference library — actor profiles list aliases, associated malware, and citations to vendor/government reporting (samples and non-public YARA rules require an invite-only account, but the actor/family profiles themselves are open to browse).",
      kind: 'recommendation',
    },
  ],
  'dns-records': [
    {
      name: 'IANA — Domain Name System (DNS) Parameters',
      url: 'https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml',
      blurb: "The registry this page's own TYPE values and every other DNS parameter (CLASSes, OPCODEs, RCODEs, and more) are officially assigned from — the single authoritative source to re-check against if IANA ever adds or renumbers a record type.",
      kind: 'reference',
    },
    {
      name: 'RFC 1035 — Domain Names: Implementation and Specification',
      url: 'https://www.rfc-editor.org/rfc/rfc1035',
      blurb: 'The original core DNS specification — defines the message format and the seven original record types this page covers (A, NS, CNAME, SOA, PTR, MX, TXT) down to the exact RDATA field layout for each.',
      kind: 'reference',
    },
    {
      name: 'RFC 3596 — DNS Extensions to Support IP Version 6',
      url: 'https://www.rfc-editor.org/rfc/rfc3596',
      blurb: 'Defines the AAAA record for IPv6 addresses, added once the original A record\'s 32-bit RDATA had no room left to hold one.',
      kind: 'reference',
    },
    {
      name: 'RFC 2782 — A DNS RR for specifying the location of services (DNS SRV)',
      url: 'https://www.rfc-editor.org/rfc/rfc2782',
      blurb: 'Defines the SRV record — its Priority/Weight/Port/Target fields and the underscore-prefixed _service._proto.name label convention this page\'s SRV example follows.',
      kind: 'reference',
    },
    {
      name: 'RFC 8659 — DNS Certification Authority Authorization (CAA) Resource Record',
      url: 'https://www.rfc-editor.org/rfc/rfc8659',
      blurb: 'The current CAA record specification (it obsoletes the original RFC 6844) — defines the Flags/Tag/Value RDATA format and the standard issue/issuewild/iodef property tags.',
      kind: 'reference',
    },
    {
      name: 'Google Admin Toolbox — Dig',
      url: 'https://toolbox.googleapps.com/apps/dig/',
      blurb: "A free, browser-based dig tool for running a live DNS lookup against any domain — useful for seeing a real record of any type on this page instead of just this page's own illustrative examples.",
      kind: 'recommendation',
    },
  ],
  'kill-chain': [
    {
      name: 'Intelligence-Driven Computer Network Defense (Hutchins, Cloppert & Amin, 2011)',
      url: 'https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf',
      blurb: "Lockheed Martin's original 2011 whitepaper — the primary source that introduced the Cyber Kill Chain and its Courses of Action Matrix, and the source every phase definition on this page was verified against directly.",
      kind: 'reference',
    },
    {
      name: 'Lockheed Martin — Cyber Kill Chain®',
      url: 'https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html',
      blurb: "Lockheed Martin's own current overview page for the framework, situating it inside their broader Intelligence Driven Defense® model.",
      kind: 'reference',
    },
    {
      name: 'MITRE ATT&CK — Frequently Asked Questions',
      url: 'https://attack.mitre.org/resources/faq/',
      blurb: "MITRE's own FAQ, including its direct comparison of ATT&CK's unordered tactics against the Kill Chain's fixed phase sequence — the source this page's own comparison section draws from.",
      kind: 'reference',
    },
    {
      name: 'Unified Kill Chain — Paul Pols',
      url: 'https://www.unifiedkillchain.com/',
      blurb: "Paul Pols' own site for the Unified Kill Chain, the 18-phase model that explicitly fuses the Cyber Kill Chain with ATT&CK and allows phases to repeat, skip, or run out of order — worth a look for the fuller, non-linear treatment this page's own comparison section gestures at.",
      kind: 'recommendation',
    },
  ],
  'http-status-codes': [
    {
      name: 'RFC 9110 — HTTP Semantics',
      url: 'https://www.rfc-editor.org/rfc/rfc9110.html',
      blurb: "The current core HTTP specification (obsoletes RFC 7231) — Section 15 is the authoritative source for every core status code's exact reason phrase and semantics on this page.",
      kind: 'reference',
    },
    {
      name: 'IANA — Hypertext Transfer Protocol (HTTP) Status Code Registry',
      url: 'https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml',
      blurb: "The live, canonical registry of every assigned status code and which RFC defines it — the single source this page's own code list was built and cross-checked against.",
      kind: 'reference',
    },
    {
      name: 'MDN — HTTP response status codes',
      url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Status',
      blurb: "MDN's own status-code reference, with a dedicated page per code covering browser/fetch-specific behavior (caching, redirect handling, CORS implications) beyond what the RFC text alone documents.",
      kind: 'reference',
    },
    {
      name: 'httpbin.org',
      url: 'https://httpbin.org/',
      blurb: 'A free HTTP request/response testing service — its /status/{code} endpoint returns any status code on demand, useful for seeing how a client, proxy, or your own code actually handles a specific one.',
      kind: 'recommendation',
    },
    {
      name: 'HTTP Cats',
      url: 'https://http.cat/',
      blurb: 'A free image for every HTTP status code (https://http.cat/{code}) — a genuinely popular placeholder used in API docs, error pages, and test fixtures across the industry.',
      kind: 'recommendation',
    },
  ],
};
