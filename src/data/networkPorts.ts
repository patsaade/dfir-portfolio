// Network Port Reference — TCP/UDP well-known + registered ports that matter
// for DFIR (single source of truth for /reference/network-ports/ and per-port
// detail pages /reference/network-ports/[slug]/). Same rigor as eventIds.ts: every entry was
// researched, then independently adversarially fact-checked (a second pass
// of skeptics specifically trying to REFUTE each claim, not just confirm it)
// before inclusion — 4 entries were caught making a false claim during that
// pass and corrected rather than silently kept; nothing here is guessed at.
//
// `slug` is `{protocol}-{port}` (e.g. "tcp-443") for a port used on ONLY one
// transport; genuinely dual-protocol services use `port-{port}` (e.g.
// "port-53") instead, since giving DNS two separate tcp-53/udp-53 entries
// would duplicate identical content for no reason. `rangeType` is computed,
// not hand-entered — RFC 6335's three IANA tiers (System/Well-Known 0-1023,
// User/Registered 1024-49151, Dynamic/Private/Ephemeral 49152-65535) applied
// mechanically to `port`. No entry lives in the dynamic range on purpose:
// that range is never assigned to a named service by definition (any host
// picks one transiently per connection), so there's nothing to catalog
// individually there — see the "Understanding port ranges" section on the
// index page for what an analyst should know about it instead.
//
// `confidence` is the DFIR-relevant question "how solid is this port-to-
// service mapping": `iana-registered` means IANA's own registry assigns this
// port to this service; `de-facto-standard` means the port is genuinely,
// overwhelmingly used this way in practice but IANA's registry actually
// assigns it to something else or nothing at all (Squid/3128, Oracle/1521,
// Elasticsearch/9200, and the pcsync-https/8443 mixup are the concrete
// examples below — each says so explicitly in its own `what`); and
// `historical-documented` covers the whole "Malware & C2" category, where
// there is no registration authority at all and the port-to-tool mapping
// rests entirely on historical/vendor/threat-intel documentation, not a
// protocol spec — treat those as a pivot point, never a confirmed finding.
import type { Reference } from './references';

type PortRangeType = 'well-known' | 'registered' | 'dynamic';
export type PortConfidence = 'iana-registered' | 'de-facto-standard' | 'historical-documented';

interface NetworkPortField {
  name: string;
  desc: string;
}

interface RawNetworkPortEntry {
  slug: string;
  port: number;
  protocol: 'tcp' | 'udp' | 'tcp/udp';
  name: string;
  category: string;
  confidence: PortConfidence;
  what: string;
  why: string;
  commonTriggers: string;
  indicators: NetworkPortField[];
  example?: string;
  relatedPorts: string[];
  attackTechniques: string[];
  references: Reference[];
}

export interface NetworkPortEntry extends RawNetworkPortEntry {
  rangeType: PortRangeType;
}

function rangeTypeFor(port: number): PortRangeType {
  if (port < 1024) return 'well-known';
  if (port < 49152) return 'registered';
  return 'dynamic';
}

const RAW_ENTRIES: RawNetworkPortEntry[] = [
  {
    slug: 'tcp-80', port: 80, protocol: 'tcp', name: 'HTTP (Hypertext Transfer Protocol)', category: 'Web & Application', confidence: 'iana-registered',
    what: "HTTP is the application-layer protocol underlying the World Wide Web: a stateless request/response protocol where a client requests a resource by method, path, and headers, and a server returns a status code, headers, and a body. Port 80/tcp is its IANA-registered default, governed by RFC 9110 (HTTP Semantics). Traffic on 80 is plaintext by default, with no confidentiality or integrity protection unless something above the transport adds it.",
    why: "Because it is plaintext, HTTP on port 80 is directly readable in a packet capture or proxy log: full URLs, headers, cookies, and any unencrypted credentials or tokens transiting the wire, making it forensically valuable whenever it turns up in traffic that should otherwise be encrypted. It is also the near-universal fallback: most modern sites use 80 only to redirect to 443, so persistent plaintext traffic on 80 rather than a single redirect can indicate a legacy or misconfigured service, an internal tool, or malware avoiding the overhead of TLS.",
    commonTriggers: "Legitimately: web browsing prior to an HTTPS redirect, internal/legacy web applications, load balancer and health-check probes, package/update mirrors. Anomalously/maliciously: plaintext C2 or exfiltration channels using HTTP to blend with common traffic, webshell interaction over unencrypted HTTP, credential harvesting via a spoofed plaintext login form, or a host serving HTTP where only HTTPS is expected.",
    indicators: [
      { name: 'Full request line in the clear', desc: 'The Host header, URI path, and query string are visible as-is, making them the fastest way to spot beaconing patterns, webshell endpoints, or known-malicious User-Agent strings.' },
      { name: 'Redirect behavior', desc: 'Whether the server issues a 301/308 to HTTPS at all; a live plaintext response instead of a redirect is unusual for a modern public-facing site.' },
    ],
    example: 'A compromised web server accepting POST requests to a webshell over plain port 80 rather than 443 avoids the overhead of a TLS setup, and the commands and output are then fully visible in a packet capture.',
    relatedPorts: ['tcp-443', 'tcp-8080', 'tcp-3128'], attackTechniques: ['T1071.001'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 9110: HTTP Semantics', url: 'https://www.rfc-editor.org/rfc/rfc9110' },
    ],
  },
  {
    slug: 'tcp-443', port: 443, protocol: 'tcp', name: 'HTTPS (HTTP over TLS/SSL)', category: 'Web & Application', confidence: 'iana-registered',
    what: "HTTPS wraps HTTP inside a TLS session, so the TCP handshake is followed by a TLS handshake (certificate exchange, cipher negotiation) before any HTTP request or response is exchanged. Port 443/tcp is IANA's registered default and is referenced from RFC 9110 as the default port for the https URI scheme. It now carries the overwhelming majority of web traffic, including HTTP/2 and, via QUIC over UDP on the same port number, HTTP/3.",
    why: "Because the payload is encrypted, an analyst usually cannot read the request or response directly, so attention shifts to metadata: the TLS handshake (SNI hostname, JA3/JA3S fingerprint, certificate subject/issuer, freshly-issued or self-signed certs), connection timing and volume, and destination IP/ASN reputation. Because 443 is essentially never blocked outbound, it is the single most common port for malware C2 and exfiltration to hide in, so being on 443 is not by itself evidence of legitimacy.",
    commonTriggers: "Legitimately: essentially all modern web browsing, API calls, software updates, cloud service traffic. Anomalously/maliciously: C2 frameworks using HTTPS to blend with normal traffic, domain fronting or fronted-CDN abuse, self-signed or very recently issued certificates on a beaconing destination, or JA3 fingerprints matching known offensive tooling rather than a standard browser.",
    indicators: [
      { name: 'TLS SNI and JA3/JA3S fingerprint', desc: 'The Server Name Indication field is visible even in encrypted traffic and identifies the intended hostname; JA3/JA3S fingerprints can flag TLS stacks belonging to known malware/C2 frameworks rather than a real browser.' },
      { name: 'Certificate metadata', desc: 'Subject, issuer, validity window, and self-signed status; a brand-new, self-signed, or mismatched-CN certificate on an otherwise unremarkable destination is a common C2 tell.' },
      { name: 'Beacon interval and jitter', desc: 'Regular, low-jitter connection timing to the same destination is a classic C2 heartbeat pattern, distinguishable from human browsing behavior.' },
    ],
    relatedPorts: ['tcp-80', 'tcp-8443', 'tcp-3128', 'tcp-1080'], attackTechniques: ['T1071.001'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 9110: HTTP Semantics', url: 'https://www.rfc-editor.org/rfc/rfc9110' },
    ],
  },
  {
    slug: 'tcp-8080', port: 8080, protocol: 'tcp', name: 'HTTP Alternate (http-alt)', category: 'Web & Application', confidence: 'iana-registered',
    what: "Port 8080/tcp carries no protocol of its own: it is registered with IANA simply as http-alt, a designated alternate for port 80, and in practice is used by a wide range of unrelated services: web application servers running without root privileges (which cannot bind to the privileged port 80), reverse proxies, development servers, and device/appliance admin UIs. What is actually spoken on 8080 is ordinary HTTP (or occasionally HTTPS); there is no way to know which without inspecting the traffic.",
    why: "Because 8080 is a catch-all convention rather than a defined service, an analyst cannot assume anything about what is listening there from the port number alone; it has to be fingerprinted. It is also a very common default for admin and management interfaces of self-hosted tools and appliances, so unexpected exposure or traffic on 8080 is worth identifying the actual application behind before treating it as routine.",
    commonTriggers: "Legitimately: non-privileged web/app servers (Node.js, Tomcat, Jenkins, etc.), forward/reverse proxy listeners, local development servers. Anomalously/maliciously: an attacker-planted proxy or C2 listener chosen because 8080 is rarely filtered outbound and is easy to overlook among legitimate proxy traffic, or exposed admin panels scanned and exploited for initial access.",
    indicators: [{ name: 'Actual application banner/response', desc: '8080 must be fingerprinted rather than assumed; the Server header, TLS presence or absence, and response content identify what is really listening.' }],
    relatedPorts: ['tcp-80', 'tcp-8443', 'tcp-3128'], attackTechniques: ['T1071.001'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 9110: HTTP Semantics', url: 'https://www.rfc-editor.org/rfc/rfc9110' },
    ],
  },
  {
    slug: 'tcp-8443', port: 8443, protocol: 'tcp', name: 'HTTPS Alternate (registered as PCsync HTTPS)', category: 'Web & Application', confidence: 'de-facto-standard',
    what: "Port 8443/tcp's IANA registration is literally pcsync-https, registered to Laplink Software for its PCsync file-synchronization product's HTTPS interface, a use that is essentially obsolete today. In current practice 8443 functions the way 8080 does for HTTP: a widely-adopted, unofficial convention as the alternate/non-privileged port for HTTPS, defaulted to by many Java application servers and by network device or appliance admin consoles.",
    why: "The gap between the official registration (a defunct Laplink sync product) and overwhelming real-world usage (a generic HTTPS admin or API endpoint) is exactly the kind of port an analyst has to fingerprint rather than trust by name. Its common role as an admin-console/management port also makes it a frequent scanning and exploitation target; internal tools left exposed on 8443 are a recurring initial-access vector.",
    commonTriggers: "Legitimately: application server SSL connectors, network appliance and device management UIs, alternate HTTPS listeners behind a reverse proxy. Anomalously/maliciously: internet-facing admin consoles left exposed on 8443 and scanned or exploited for default credentials or known CVEs, or an attacker choosing 8443 for a TLS-wrapped C2 listener to resemble a benign management port.",
    indicators: [{ name: 'Certificate CN/SAN and TLS fingerprint', desc: 'The same triage as 443: check the served certificate and JA3/JA3S to identify the actual product or appliance rather than assuming a benign admin panel.' }],
    relatedPorts: ['tcp-443', 'tcp-8080'], attackTechniques: ['T1071.001'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 9110: HTTP Semantics', url: 'https://www.rfc-editor.org/rfc/rfc9110' },
    ],
  },
  {
    slug: 'tcp-3128', port: 3128, protocol: 'tcp', name: 'Squid HTTP Proxy (de facto; registered as ndl-aas)', category: 'Web & Application', confidence: 'de-facto-standard',
    what: "Port 3128/tcp is the long-standing default listening port for the Squid caching web proxy, adopted in the 1990s and still Squid's out-of-the-box http_port default today. Its actual IANA registration, however, is for an unrelated service, ndl-aas (an Active API Server port); 3128 became the proxy convention purely through Squid's own defaults and widespread adoption, never a formal IANA proxy assignment.",
    why: "Traffic to 3128 overwhelmingly means an HTTP forward proxy is in use, which cuts both ways for DFIR: it is how organizations legitimately enforce web filtering and logging, and it is also a common pivot mechanism attackers abuse. An open or misconfigured proxy lets an outside actor relay traffic through it, and an internal host reaching an unauthorized external proxy on 3128 can indicate an attempt to bypass egress or DNS controls.",
    commonTriggers: "Legitimately: corporate or ISP web proxy egress, cached web browsing through a Squid deployment. Anomalously/maliciously: an open or misconfigured Squid proxy abused by outside actors to relay traffic and mask source IP, an internal host configured to reach an unauthorized external proxy to evade filtering, or attacker infrastructure running a proxy on 3128 as part of a redirector chain.",
    indicators: [
      { name: 'CONNECT method usage', desc: 'An HTTP CONNECT request tunneling arbitrary TCP, commonly to port 443, is the key thing to inspect; it reveals the true destination the proxy is relaying to.' },
      { name: 'Proxy-Authorization header', desc: 'Presence and validity of proxy authentication helps distinguish sanctioned use from open-proxy abuse.' },
    ],
    relatedPorts: ['tcp-80', 'tcp-443', 'tcp-1080', 'tcp-8080'], attackTechniques: ['T1090', 'T1071.001'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'Squid http_port configuration directive (default 3128)', url: 'https://www.squid-cache.org/Doc/config/http_port/' },
    ],
  },
  {
    slug: 'tcp-1080', port: 1080, protocol: 'tcp', name: 'SOCKS Proxy', category: 'Web & Application', confidence: 'iana-registered',
    what: "SOCKS is a generic circuit-level proxy protocol that relays arbitrary TCP (and, in SOCKS5, UDP) connections on behalf of a client without understanding the application protocol being tunneled, unlike an HTTP proxy, which works only for HTTP(S). Port 1080/tcp is IANA's registered default, and the current version, SOCKS5, is defined in RFC 1928, with RFC 1929 covering username/password authentication.",
    why: "Because SOCKS is protocol-agnostic, a SOCKS proxy on 1080 can carry literally anything: a legitimate privacy or bypass tool, or an attacker's pivot channel for tunneling C2, lateral movement, or further scanning through a compromised host. Post-exploitation frameworks commonly stand up an ad hoc SOCKS proxy on a compromised machine specifically to relay follow-on traffic through it, so an unexpected listener or outbound connection on 1080 warrants immediate attention.",
    commonTriggers: "Legitimately: privacy or bypass tooling such as SSH dynamic (-D) port forwarding, or Tor's SOCKS interface; enterprise proxy chaining. Anomalously/maliciously: a SOCKS proxy stood up on a compromised host by a post-exploitation framework to relay attacker traffic through the victim network, or a host reaching out to an external SOCKS proxy to evade egress monitoring.",
    indicators: [{ name: 'SOCKS handshake destination', desc: 'The SOCKS CONNECT request specifies the true target host and port being relayed; decoding it reveals what is actually being tunneled, since the proxy connection itself gives no application-layer visibility.' }],
    relatedPorts: ['tcp-3128', 'tcp-443'], attackTechniques: ['T1090'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 1928: SOCKS Protocol Version 5', url: 'https://www.rfc-editor.org/rfc/rfc1928' },
    ],
  },
  {
    slug: 'tcp-25', port: 25, protocol: 'tcp', name: 'SMTP (Simple Mail Transfer Protocol)', category: 'Email', confidence: 'iana-registered',
    what: "SMTP is the protocol mail servers use to relay email between each other (MTA-to-MTA) and, historically, from a client to a server. Port 25/tcp is its IANA-registered default, governed by RFC 5321. Modern deployments largely restrict port 25 to server-to-server relay and inbound mail delivery, pushing client mail submission to dedicated ports (465/587) instead.",
    why: "Port 25 is the backbone of inter-domain email delivery, so its logs, including the SMTP conversation, envelope from/to, and Received header chain, are foundational for tracing a phishing email's true origin and delivery path. It is also a classic outbound-abuse vector: a compromised host or misconfigured relay sending unauthorized outbound mail on 25 is one of the most common signs of a mail server or open relay being abused, which is why many ISPs and cloud providers block outbound 25 by default.",
    commonTriggers: "Legitimately: MTA-to-MTA mail relay and inbound mail delivery to a domain's MX host. Anomalously/maliciously: an open relay or compromised mail server sending unsolicited outbound spam or phishing, a compromised host attempting direct-to-MX SMTP that bypasses an organization's outbound mail gateway, or SMTP used as a simple data-exfiltration channel.",
    indicators: [
      { name: 'Received header chain vs. envelope sender', desc: 'Reconstructing the hop-by-hop Received chain and comparing the SMTP envelope sender to the visible From header is the standard way to spot spoofing or a compromised relay in the path.' },
      { name: 'HELO/EHLO identity vs. source IP', desc: 'A HELO hostname that does not resolve to, or match, the connecting IP is a common spam and spoofing tell.' },
    ],
    relatedPorts: ['tcp-465', 'tcp-587'], attackTechniques: ['T1071.003'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 5321: Simple Mail Transfer Protocol', url: 'https://www.rfc-editor.org/rfc/rfc5321' },
    ],
  },
  {
    slug: 'tcp-465', port: 465, protocol: 'tcp', name: 'SMTPS (Message Submission over implicit TLS)', category: 'Email', confidence: 'iana-registered',
    what: "Port 465/tcp carries SMTP wrapped in TLS from the very start of the connection, implicit TLS, with no STARTTLS negotiation, providing the same message-submission function as port 587 but encrypted before any SMTP command is exchanged. Its history is unusually tangled: 465 was informally used for SMTPS since the 1990s but was never officially sanctioned for that purpose, with its formal IANA registrations covering unrelated services (urd on TCP, igmpv3lite on UDP); RFC 8314 in 2018 finally gave the de facto SMTPS usage an official registration, submissions, formalizing 465 as a recommended implicit-TLS submission port alongside 587.",
    why: "Recognizing 465 tells an analyst this is authenticated client mail submission, not server-to-server relay, so the relevant identity is the authenticating account rather than a domain's MX infrastructure. Because TLS is established immediately, any 465 connection that is not cleanly encrypted from the first bytes is itself anomalous. Threat actors that obtain mailbox credentials frequently use 465/587 directly, rather than a webmail UI, for large-scale automated sending in phishing-from-a-real-account or BEC campaigns.",
    commonTriggers: "Legitimately: mail clients submitting outbound mail with implicit TLS. Anomalously/maliciously: automated mass-mail sending from a compromised mailbox credential (BEC, phishing from a real account), or credential-stuffing/brute-force attempts against a mail submission endpoint.",
    indicators: [{ name: 'Authentication attempts and failures', desc: 'Repeated AUTH failures against a submission endpoint in a short window is classic password-spraying or credential-stuffing behavior targeting mailboxes.' }],
    relatedPorts: ['tcp-25', 'tcp-587', 'tcp-995', 'tcp-993'], attackTechniques: ['T1071.003'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 8314: Cleartext Considered Obsolete: Use of TLS for Email Submission and Access', url: 'https://www.rfc-editor.org/rfc/rfc8314' },
    ],
  },
  {
    slug: 'tcp-587', port: 587, protocol: 'tcp', name: 'SMTP Submission (STARTTLS)', category: 'Email', confidence: 'iana-registered',
    what: "Port 587/tcp is the IANA-registered message submission port, defined in RFC 6409, specifically for mail clients authenticating and submitting outbound mail to their provider's server, distinct from port 25's server-to-server relay role. Unlike 465, a 587 connection starts in plaintext and upgrades to TLS mid-session via the STARTTLS command, so an observer sees the initial handshake before encryption begins.",
    why: "Like 465, seeing 587 identifies client mail submission tied to an authenticated account, making it a key channel for detecting compromised-mailbox abuse and for correlating a user's legitimate mail-sending behavior against anomalies. Because STARTTLS negotiation happens in the clear, a 587 session that never upgrades to TLS, or is downgraded, is itself a detectable anomaly consistent with a STARTTLS-stripping interception attempt.",
    commonTriggers: "Legitimately: mail clients on desktop and mobile submitting outbound mail via STARTTLS. Anomalously/maliciously: mass outbound sending from a compromised mailbox credential, credential-stuffing or brute-force against the submission endpoint, or a STARTTLS-stripping downgrade attack forcing the session to stay in plaintext.",
    indicators: [{ name: 'STARTTLS negotiation outcome', desc: 'Whether the session actually upgrades to TLS after STARTTLS is offered; a session that stays plaintext after negotiation should have started is a downgrade or interception red flag.' }],
    relatedPorts: ['tcp-25', 'tcp-465'], attackTechniques: ['T1071.003'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 6409: Message Submission for Mail', url: 'https://www.rfc-editor.org/rfc/rfc6409' },
    ],
  },
  {
    slug: 'tcp-110', port: 110, protocol: 'tcp', name: 'POP3 (Post Office Protocol v3)', category: 'Email', confidence: 'iana-registered',
    what: "POP3 lets a mail client download messages from a server-side mailbox, traditionally removing them from the server after retrieval, a download-and-delete model in contrast to IMAP's server-resident, multi-device synchronization model. Port 110/tcp is its IANA-registered default, defined in RFC 1939. In its unencrypted form, POP3 authenticates with a plaintext USER/PASS exchange by default.",
    why: "A plaintext POP3 session exposes the account's login credentials and the full content of retrieved mail directly on the wire, making it high-value if seen anywhere outside an isolated or legacy environment. With stolen credentials, POP3 is also a straightforward way for an attacker to bulk-download a victim's mailbox contents for reconnaissance or further attacks without ever touching a webmail UI that might carry additional monitoring or MFA.",
    commonTriggers: "Legitimately: legacy mail clients configured for POP3 download-and-delete retrieval, mail migration or archival tools. Anomalously/maliciously: credential-stuffing or brute-force against a POP3 endpoint, or an attacker with compromised credentials using POP3 to bulk-retrieve a victim's mail for reconnaissance or data theft.",
    indicators: [{ name: 'Plaintext USER/PASS commands', desc: 'If TLS is not in use, the USER and PASS commands carry the account credentials in the clear, directly recoverable from a packet capture.' }],
    relatedPorts: ['tcp-995', 'tcp-143'], attackTechniques: ['T1071.003', 'T1114.002'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 1939: Post Office Protocol - Version 3', url: 'https://www.rfc-editor.org/rfc/rfc1939' },
    ],
  },
  {
    slug: 'tcp-995', port: 995, protocol: 'tcp', name: 'POP3S (POP3 over TLS/SSL)', category: 'Email', confidence: 'iana-registered',
    what: 'Port 995/tcp is POP3 wrapped in implicit TLS from connection start, the encrypted counterpart to port 110. It is IANA-registered as pop3s, with RFC 8314 formalizing implicit TLS as the recommended approach for mail retrieval protocols.',
    why: "Because it is encrypted, 995 traffic itself is not readable, but its presence still confirms mailbox-retrieval activity tied to an authenticated account, relevant for the same reasons as 110 (credential attacks, bulk mailbox access after compromise) without the credentials being visible on the wire. Connection volume, timing, and destination become the useful signals instead of packet content.",
    commonTriggers: "Legitimately: mail clients retrieving mailbox content over encrypted POP3. Anomalously/maliciously: automated bulk mailbox retrieval using stolen credentials, or credential-stuffing attempts against a POP3S endpoint, which remain visible as authentication failures even though the payload is encrypted.",
    indicators: [{ name: 'Authentication failure volume', desc: 'Repeated failed TLS-wrapped authentication attempts in a short window against the same account is visible in server-side mail logs even though the wire traffic is encrypted.' }],
    relatedPorts: ['tcp-110', 'tcp-465', 'tcp-993'], attackTechniques: ['T1071.003', 'T1114.002'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 8314: Cleartext Considered Obsolete: Use of TLS for Email Submission and Access', url: 'https://www.rfc-editor.org/rfc/rfc8314' },
    ],
  },
  {
    slug: 'tcp-143', port: 143, protocol: 'tcp', name: 'IMAP (Internet Message Access Protocol)', category: 'Email', confidence: 'iana-registered',
    what: "IMAP synchronizes a mail client's view of a mailbox with a server-resident copy, supporting multiple folders and flags with simultaneous access from multiple devices, unlike POP3's simple download model. Port 143/tcp is its IANA-registered default; the current protocol version is IMAP4rev2, defined in RFC 9051, which supersedes the long-standing IMAP4rev1 in RFC 3501. Like POP3, plaintext IMAP negotiates STARTTLS to upgrade to encryption, or can be used entirely unencrypted if the client allows it.",
    why: "Because IMAP is the most feature-rich mailbox-access protocol, it is a particularly attractive target for credential-based mailbox abuse: an attacker with valid credentials can browse folder structure, search, and selectively exfiltrate specific mail rather than bulk-downloading everything, which is harder to distinguish from normal usage than a POP3 bulk retrieval. IMAP access is also frequently how post-compromise mailbox persistence plays out in practice — attackers using OAuth-token abuse (XOAUTH2) to maintain IMAP access, often alongside forwarding rules configured through the mail platform's own webmail or admin API rather than IMAP itself, to keep visibility into a victim's mail after the original access vector is remediated.",
    commonTriggers: "Legitimately: standard mail client access on desktop and mobile to a server-resident mailbox, multi-device synchronization. Anomalously/maliciously: credential-stuffing or brute-force against IMAP, or an attacker with compromised credentials or OAuth tokens using IMAP to search and selectively exfiltrate mail, for example searching for invoice or wire-transfer related terms as part of BEC reconnaissance, while leaving most of the mailbox untouched.",
    indicators: [
      { name: 'SEARCH/FETCH command patterns', desc: "Targeted SEARCH queries for financial or credential-related keywords followed by selective FETCH of specific messages is a common BEC and mailbox-reconnaissance pattern, distinct from a normal client's bulk sync behavior." },
      { name: "Login source IP/ASN vs. account's normal pattern", desc: 'A successful IMAP login from an unfamiliar country or ASN immediately after a phishing click is a strong compromised-account indicator.' },
    ],
    relatedPorts: ['tcp-993', 'tcp-110'], attackTechniques: ['T1071.003', 'T1114.002'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 9051: Internet Message Access Protocol (IMAP) - Version 4rev2', url: 'https://www.rfc-editor.org/rfc/rfc9051' },
    ],
  },
  {
    slug: 'tcp-993', port: 993, protocol: 'tcp', name: 'IMAPS (IMAP over TLS/SSL)', category: 'Email', confidence: 'iana-registered',
    what: 'Port 993/tcp is IMAP wrapped in implicit TLS from connection start, registered with IANA as imaps and governed by the same IMAP RFCs (3501/9051) plus RFC 8314 for the implicit-TLS convention.',
    why: 'It carries the same underlying risk profile as port 143, selective mailbox access and exfiltration, persistence via forwarding rules or OAuth tokens, but encrypted on the wire, so detection leans on authentication logs, source IP/geo anomalies, and mailbox-side audit logs such as new inbox rules or OAuth app consents rather than packet content.',
    commonTriggers: 'Legitimately: encrypted mail client access to a server-resident mailbox. Anomalously/maliciously: compromised-account mailbox access for BEC reconnaissance or selective exfiltration, or a new forwarding rule or filter created shortly after an anomalous IMAPS login to maintain visibility into a victim\'s mail after the original access vector is remediated.',
    indicators: [{ name: 'New mailbox rule or forwarding creation', desc: "A forwarding rule or filter created shortly after an anomalous login is one of the most reliable BEC persistence indicators, even though the IMAP session itself is encrypted, since it is visible in the mail platform's own audit log." }],
    relatedPorts: ['tcp-143', 'tcp-995', 'tcp-465'], attackTechniques: ['T1071.003', 'T1114.002'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 8314: Cleartext Considered Obsolete: Use of TLS for Email Submission and Access', url: 'https://www.rfc-editor.org/rfc/rfc8314' },
    ],
  },
  {
    slug: 'port-53', port: 53, protocol: 'tcp/udp', name: 'DNS (Domain Name System)', category: 'Name Resolution & Directory Services', confidence: 'iana-registered',
    what: "DNS resolves human-readable names to IP addresses, and vice versa, plus many other record types, and is defined across RFC 1034 (concepts) and RFC 1035 (implementation and wire format). It genuinely runs over both UDP and TCP on port 53: UDP handles the vast majority of ordinary queries for low overhead, while TCP is required whenever a response exceeds the practical UDP size limit, and always for zone transfers (AXFR, defined in RFC 5936) between authoritative name servers.",
    why: "DNS queries are one of the richest sources of intent in an investigation: the domains a host resolves reveal what it is about to contact, often before any connection to the actual destination is attempted, making DNS logs valuable both for reconstructing a timeline and for detection, such as newly-registered domains, DGA-generated names, or unusual query volume. DNS is also a well-established C2 and exfiltration channel in its own right, tunneling data inside TXT, NULL, or CNAME record queries, and an unauthorized TCP/53 zone transfer is a classic reconnaissance and data-exposure finding.",
    commonTriggers: "Legitimately: ordinary name resolution over UDP, the overwhelming majority of traffic, plus large DNSSEC/TXT responses or zone transfers between authoritative name servers over TCP. Anomalously/maliciously: DNS tunneling for C2 or exfiltration using abnormally long or high-entropy subdomain labels and high query volume to a single domain, queries to algorithmically-generated domains from DGA malware, or an unauthenticated AXFR zone transfer attempt exposing internal hostnames.",
    indicators: [
      { name: 'Query name entropy, length, and record type', desc: 'High-entropy or unusually long subdomain labels, especially with TXT, NULL, or CNAME record types and high query frequency to one apex domain, are the standard DNS-tunneling tell.' },
      { name: 'NXDOMAIN rate and newly-observed domains', desc: 'A host generating a high rate of NXDOMAIN responses against algorithmically-varying names is a strong DGA-malware indicator.' },
      { name: 'Unsolicited AXFR/IXFR requests', desc: 'A zone transfer request from a source that is not a configured secondary name server is a reconnaissance attempt worth flagging on its own.' },
    ],
    example: 'Malware exfiltrating small chunks of stolen data as high-entropy subdomain labels in a steady stream of TXT-record queries to an attacker-controlled domain is a textbook DNS tunneling pattern that packet-content inspection alone would miss on other, encrypted ports.',
    relatedPorts: ['port-88', 'port-389'], attackTechniques: ['T1071.004', 'T1590.002'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 1035: Domain Names - Implementation and Specification', url: 'https://www.rfc-editor.org/rfc/rfc1035' },
      { name: 'RFC 5936: DNS Zone Transfer Protocol (AXFR)', url: 'https://www.rfc-editor.org/rfc/rfc5936' },
    ],
  },
  {
    slug: 'port-389', port: 389, protocol: 'tcp/udp', name: 'LDAP (Lightweight Directory Access Protocol)', category: 'Name Resolution & Directory Services', confidence: 'iana-registered',
    what: "LDAP is the protocol clients use to query and modify a directory service, in a Windows environment, Active Directory's own interface for users, groups, computers, group policy, and schema. Port 389/tcp is its IANA-registered default and is defined by RFC 4511 (part of the RFC 4510 series). It also has a genuine UDP role, connectionless LDAP (CLDAP), which Active Directory domain controllers use to answer lightweight LDAP ping queries from the Windows DC Locator service before a client opens a full TCP LDAP session. Standard LDAP traffic on 389 is unencrypted unless upgraded via STARTTLS.",
    why: "LDAP is the primary interface adversaries use for Active Directory reconnaissance once they have any foothold: enumerating users, group memberships, computer objects, trust relationships, and permissions is almost always done via LDAP queries, directly or through tools like BloodHound, AdFind, or PowerView, so a spike in LDAP query volume from an unusual source, such as a workstation rather than a management host, is one of the strongest AD-recon signals available. Because it is plaintext by default, an unencrypted LDAP simple bind also exposes the querying account's credentials on the wire.",
    commonTriggers: "Legitimately: domain-joined clients and servers querying Active Directory for authentication, group policy, and directory lookups, plus CLDAP LDAP ping traffic from the DC Locator service during logon or domain join. Anomalously/maliciously: bulk or automated directory enumeration from a workstation rather than a management server, plaintext LDAP simple binds exposing credentials, or reconnaissance queries targeting privileged groups and delegation or trust attributes.",
    indicators: [
      { name: 'Query volume and source host role', desc: 'A sudden high volume of LDAP searches from a standard workstation rather than a management or monitoring server is the classic BloodHound/AdFind-style enumeration signal.' },
      { name: 'Search filters targeting privileged attributes', desc: 'Filters querying admin group membership, servicePrincipalName (Kerberoasting setup), userAccountControl flags, or delegation attributes indicate targeted AD reconnaissance rather than routine lookups.' },
    ],
    relatedPorts: ['tcp-636', 'tcp-3268', 'tcp-3269', 'port-88', 'port-464', 'port-53'], attackTechniques: ['T1087.002', 'T1069.002'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 4511: LDAP - The Protocol', url: 'https://www.rfc-editor.org/rfc/rfc4511' },
      { name: 'RFC 4510: LDAP - Technical Specification Road Map', url: 'https://www.rfc-editor.org/rfc/rfc4510' },
    ],
  },
  {
    slug: 'tcp-636', port: 636, protocol: 'tcp', name: 'LDAPS (LDAP over TLS/SSL)', category: 'Name Resolution & Directory Services', confidence: 'iana-registered',
    what: "Port 636/tcp is LDAP wrapped in implicit TLS from connection start, the same directory query and modify functionality as 389, but encrypted before any LDAP operation occurs. It predates the standardized StartTLS extension (RFC 4513) and is not itself part of the core LDAP RFC series; it is a widely-deployed de facto convention that Microsoft and other directory vendors continue to support, and which Active Directory hardening guidance increasingly pushes as the default over unsigned plaintext LDAP.",
    why: "It carries the same reconnaissance risk profile as 389, directory enumeration and privileged-group or attribute targeting, but with credentials and query content protected on the wire, so detection again relies on connection volume and source-host anomalies plus directory-side audit logging rather than packet inspection.",
    commonTriggers: "Legitimately: applications and clients configured to require encrypted directory access, especially after AD hardening that disables unsigned or unencrypted LDAP binds. Anomalously/maliciously: the same enumeration tooling used against 389, such as BloodHound or AdFind, simply configured to use LDAPS, or an attacker probing whether unauthenticated LDAPS binds are permitted.",
    indicators: [{ name: 'Directory-side object access auditing', desc: 'Since the wire content is encrypted, correlating LDAPS connection spikes with directory service access logs, such as Windows Security Event ID 4662, is the practical way to see what was actually queried.' }],
    relatedPorts: ['port-389', 'tcp-3269'], attackTechniques: ['T1087.002', 'T1069.002'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 4513: LDAP - Authentication Methods and Security Mechanisms', url: 'https://www.rfc-editor.org/rfc/rfc4513' },
    ],
  },
  {
    slug: 'tcp-3268', port: 3268, protocol: 'tcp', name: 'Global Catalog LDAP (Microsoft Active Directory)', category: 'Name Resolution & Directory Services', confidence: 'iana-registered',
    what: "Port 3268/tcp is Microsoft's extension of LDAP for Active Directory's Global Catalog: a partial, read-only, forest-wide replica of every domain's directory data, hosted on domain controllers designated as Global Catalog servers. Querying 3268 instead of 389 lets a client search across every domain in the forest in a single query, at the cost of only a subset of each object's attributes being available. It is registered with IANA as msft-gc but is not defined by any IETF RFC; it is Active Directory-specific.",
    why: "Global Catalog queries are especially attractive for forest-wide reconnaissance: an attacker or enumeration tool can search across every domain in a multi-domain forest from a single connection, making 3268 traffic from an unexpected source a stronger recon signal in multi-domain environments than the same activity on 389 alone. It also matters operationally, since Global Catalog availability is required for forest-wide functions like universal group membership resolution and UPN logon, so connection failures here can point to an authentication incident.",
    commonTriggers: "Legitimately: forest-wide directory searches, such as Exchange/Outlook global address list lookups or universal group expansion during logon, in a multi-domain AD forest. Anomalously/maliciously: forest-wide enumeration tooling querying the Global Catalog specifically to map trust and group relationships across every domain rather than just the local one.",
    indicators: [], relatedPorts: ['port-389', 'tcp-3269'], attackTechniques: ['T1087.002', 'T1069.002'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'Microsoft Learn: [MS-ADTS] Active Directory Technical Specification - Ports', url: 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1010e59a-cf64-410c-a05c-a3a6c715261a' },
    ],
  },
  {
    slug: 'tcp-3269', port: 3269, protocol: 'tcp', name: 'Global Catalog LDAP over TLS/SSL', category: 'Name Resolution & Directory Services', confidence: 'iana-registered',
    what: 'Port 3269/tcp is the encrypted counterpart to 3268: forest-wide Global Catalog queries wrapped in implicit TLS. It is registered with IANA as msft-gc-ssl and shares the same Microsoft-specific, non-RFC status as 3268.',
    why: "It carries the same forest-wide reconnaissance value as 3268, but encrypted on the wire, so the practical detection approach again shifts to connection-volume and source anomalies plus Active Directory's own object-access auditing rather than packet content.",
    commonTriggers: 'Legitimately: applications and clients required to use encrypted LDAP configured for forest-wide Global Catalog access. Anomalously/maliciously: the same forest-wide enumeration use case as 3268, run over TLS specifically to avoid plaintext detection.',
    indicators: [], relatedPorts: ['tcp-3268', 'tcp-636', 'port-389'], attackTechniques: ['T1087.002', 'T1069.002'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'Microsoft Learn: [MS-ADTS] Active Directory Technical Specification - Ports', url: 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1010e59a-cf64-410c-a05c-a3a6c715261a' },
    ],
  },
  {
    slug: 'port-88', port: 88, protocol: 'tcp/udp', name: 'Kerberos', category: 'Name Resolution & Directory Services', confidence: 'iana-registered',
    what: "Kerberos is the network authentication protocol Active Directory and other Kerberos realms use to issue and validate tickets proving a principal's identity without repeatedly transmitting a password: a client obtains a Ticket-Granting Ticket (TGT) from the Key Distribution Center's Authentication Service, then uses it to request per-service Ticket-Granting Service (TGS) tickets. Port 88 is IANA-registered and defined by RFC 4120 (The Kerberos Network Authentication Service V5), and it genuinely runs over both UDP and TCP: RFC 4120 requires implementations to support both, with UDP preferred for small messages but TCP required whenever a message exceeds the practical UDP datagram size, which is routine in Active Directory once the Privilege Attribute Certificate is included.",
    why: "Port 88 is the single most consequential authentication port in a modern Windows environment, and well-documented attack techniques revolve entirely around it: Kerberoasting requests TGS tickets for accounts with a Service Principal Name and cracks the returned ticket offline for the account's password, and AS-REP Roasting targets accounts with Kerberos pre-authentication disabled to obtain a crackable AS-REP without any prior credentials at all. Both are visible as distinctive request patterns on 88 well before any offline cracking succeeds.",
    commonTriggers: "Legitimately: normal domain logon and service-ticket requests (AS-REQ/AS-REP, TGS-REQ/TGS-REP) throughout a Windows domain's operation. Anomalously/maliciously: a single account requesting TGS tickets for an unusually large number of distinct SPNs in a short window (Kerberoasting), AS-REQ traffic targeting accounts with pre-authentication disabled (AS-REP Roasting), or forged or replayed tickets presenting inconsistent or implausible lifetimes and encryption types.",
    indicators: [
      { name: 'TGS-REQ volume per account/SPN', desc: 'A single requesting account pulling TGS tickets for many distinct SPNs in a short window is the primary Kerberoasting signal, commonly logged as Windows Event ID 4769.' },
      { name: 'Ticket encryption type (etype)', desc: 'RC4 tickets requested where AES is otherwise the domain norm are frequently a downgrade specifically enabling offline cracking, both for Kerberoasting and for Golden/Silver Ticket forgery.' },
    ],
    example: 'An attacker who has compromised a single low-privileged domain account can request TGS tickets for every account with a registered SPN and attempt to crack the returned ticket data offline, potentially recovering a service account\'s plaintext password without ever triggering a lockout or a logon failure event.',
    relatedPorts: ['port-464', 'port-389', 'port-53'], attackTechniques: ['T1558', 'T1558.003', 'T1558.004'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 4120: The Kerberos Network Authentication Service (V5)', url: 'https://www.rfc-editor.org/rfc/rfc4120' },
    ],
  },
  {
    slug: 'port-464', port: 464, protocol: 'tcp/udp', name: 'Kerberos Change/Set Password (kpasswd)', category: 'Name Resolution & Directory Services', confidence: 'iana-registered',
    what: 'Port 464 carries the Kerberos password-change protocol, allowing a principal to change their own password, or, with sufficient privilege, set another principal\'s password, without a full administrative directory operation. In an Active Directory environment this is what runs when a domain user changes their password interactively. It is defined by RFC 3244, Microsoft Windows 2000 Kerberos Change Password and Set Password Protocols, and, confirmed via the IANA registry, runs over both TCP and UDP.',
    why: 'Password-change events are inherently security-relevant: kpasswd traffic corresponds directly to a credential changing, which matters both defensively, confirming a forced password reset after a compromise actually completed, and offensively, since an attacker who has compromised an account or gained sufficient privilege can use the set-password function to lock out or take over other accounts. Unexpected kpasswd traffic to or from a host that is not a domain controller is not normal and should be investigated.',
    commonTriggers: 'Legitimately: routine end-user password changes and administrative password resets against a domain controller. Anomalously/maliciously: an attacker with elevated or delegated rights using the set-password function to take over another account after abusing a delegated reset permission or a privilege escalation path, or unexpected kpasswd traffic to a non-domain-controller host indicating a rogue KDC or credential-capture attempt.',
    indicators: [], relatedPorts: ['port-88'], attackTechniques: [],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 3244: Microsoft Windows 2000 Kerberos Change Password and Set Password Protocols', url: 'https://www.rfc-editor.org/rfc/rfc3244' },
    ],
  },
  {
    slug: 'udp-137', port: 137, protocol: 'udp', name: 'NetBIOS Name Service', category: 'Name Resolution & Directory Services', confidence: 'iana-registered',
    what: 'NetBIOS Name Service handles registration and resolution of NetBIOS names, the legacy host naming scheme that predates DNS on Windows networks, over UDP broadcast or to a WINS server. It is defined by RFC 1001 (concepts) and RFC 1002 (detailed wire specification) as part of the NetBIOS-over-TCP/IP suite, and while IANA registers the service name on both TCP and UDP, the Name Service function itself operates over UDP in practice, per its RFC 1002 design.',
    why: 'NBT-NS is one of two protocols, alongside LLMNR, targeted by an extremely common credential-theft technique: broadcast name-resolution poisoning. Because NBT-NS has no authentication and any host on the local broadcast segment can answer a name query, a tool like Responder can impersonate the requested host, prompt the querying client to authenticate to it, and capture the resulting NTLMv2 hash for offline cracking or relay. This technique requires no prior foothold beyond network access, and is frequently one of the first things attempted after landing on an internal network.',
    commonTriggers: 'Legitimately: legacy NetBIOS name registration and resolution on networks still relying on it, largely superseded by DNS today but often still enabled by default on Windows. Anomalously/maliciously: NBT-NS and LLMNR poisoning via tools like Responder or Inveigh, visible as a host answering an unusual volume of name queries it has no legitimate authority over, followed by inbound SMB or HTTP authentication attempts to that host.',
    indicators: [
      { name: 'Unsolicited or incorrect name-query responses', desc: 'A host answering NBT-NS queries for names it does not own, especially answering every failed DNS lookup, is the core Responder-style poisoning signature.' },
      { name: 'Resulting NTLMv2 authentication to the poisoning host', desc: 'The actual credential theft happens in the follow-on SMB or HTTP authentication attempt to the spoofing host, which is the higher-value event to alert on.' },
    ],
    example: "A tool like Responder answers every failed DNS lookup on a segment as if it were the requested host, prompting the victim's client to authenticate directly to the attacker over SMB or HTTP and hand over a crackable NTLMv2 hash, all without the attacker needing any prior credentials.",
    relatedPorts: ['udp-138', 'tcp-139', 'port-53'], attackTechniques: ['T1557.001'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 1001: Protocol Standard for a NetBIOS Service on a TCP/UDP Transport - Concepts and Methods', url: 'https://www.rfc-editor.org/rfc/rfc1001' },
      { name: 'RFC 1002: Protocol Standard for a NetBIOS Service on a TCP/UDP Transport - Detailed Specifications', url: 'https://www.rfc-editor.org/rfc/rfc1002' },
    ],
  },
  {
    slug: 'udp-138', port: 138, protocol: 'udp', name: 'NetBIOS Datagram Service', category: 'Name Resolution & Directory Services', confidence: 'iana-registered',
    what: 'NetBIOS Datagram Service provides connectionless datagram delivery between NetBIOS names, including the broadcast mechanisms historically used for browser-service announcements and elections on Windows networks, as part of the same NBT suite defined in RFC 1001/1002. Like the Name Service, IANA registers it on both TCP and UDP, but it operates over UDP in practice.',
    why: 'It is the least individually significant of the three classic NetBIOS ports for modern DFIR, largely a legacy broadcast mechanism rather than an active attack surface on its own, but its presence still confirms NBT is enabled on a segment, which is the precondition for the NBT-NS poisoning risk covered under port 137, and unexpected browser-election traffic can indicate legacy protocols left enabled that are contributing to network noise or misconfiguration.',
    commonTriggers: 'Legitimately: legacy NetBIOS browser service announcements and elections, datagram-based name traffic on networks that have not disabled NBT. Anomalously/maliciously: rarely targeted directly, but its presence alongside port 137 is part of the same broadcast-based name-poisoning attack surface.',
    indicators: [], relatedPorts: ['udp-137', 'tcp-139'], attackTechniques: [],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 1002: Protocol Standard for a NetBIOS Service on a TCP/UDP Transport - Detailed Specifications', url: 'https://www.rfc-editor.org/rfc/rfc1002' },
    ],
  },
  {
    slug: 'tcp-139', port: 139, protocol: 'tcp', name: 'NetBIOS Session Service', category: 'Name Resolution & Directory Services', confidence: 'iana-registered',
    what: 'NetBIOS Session Service provides the connection-oriented session layer NetBIOS applications use to exchange data. Historically this was how SMB file and print sharing operated, carried inside a NetBIOS session on 139, before Windows 2000 introduced direct-hosted SMB over TCP port 445 without a NetBIOS session wrapper. It is defined by RFC 1001/1002 and, per the IANA registry, formally listed on both TCP and UDP, though the session service itself is inherently connection-oriented and runs over TCP.',
    why: "Port 139 matters in DFIR largely as SMB's legacy transport: the same file-share access, authentication, and lateral-movement activity that occurs over 445 can also occur over 139 on networks where NetBIOS has not been disabled, and it is the historical home of unauthenticated null-session enumeration, anonymous IPC$ connections used to enumerate users, shares, and policy without credentials, an old but still occasionally effective misconfiguration to check for.",
    commonTriggers: 'Legitimately: legacy SMB and file-sharing access on networks that have not migrated fully to direct-hosted SMB on 445, NetBIOS-based printer or resource browsing. Anomalously/maliciously: null-session enumeration of users and shares via anonymous IPC$ connections, or lateral movement and file-share abuse riding the legacy NetBIOS transport instead of 445.',
    indicators: [{ name: 'Anonymous/null session (IPC$) connections', desc: 'A session authenticating as ANONYMOUS LOGON to IPC$ is the classic null-session enumeration pattern, historically used to pull user and share lists without any credentials.' }],
    example: 'A legacy or misconfigured host that still permits anonymous IPC$ connections lets an attacker enumerate local user accounts and share names over port 139 without supplying any credentials at all, a technique that predates modern Active Directory hardening but still turns up in older environments.',
    relatedPorts: ['udp-137', 'udp-138'], attackTechniques: ['T1135', 'T1021.002'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 1002: Protocol Standard for a NetBIOS Service on a TCP/UDP Transport - Detailed Specifications', url: 'https://www.rfc-editor.org/rfc/rfc1002' },
    ],
  },
  {
    slug: 'tcp-20', port: 20, protocol: 'tcp', name: 'FTP (File Transfer Protocol) — Data', category: 'File Sharing & Remote Access', confidence: 'iana-registered',
    what: "The secondary channel an FTP session uses to move actual file bytes, separate from the command channel on port 21. In active mode the FTP server initiates this connection back to the client's specified port using the PORT command; in passive mode — the default in virtually all modern clients — the server instead opens a random high port and the client connects out to it, so raw port-20 traffic is actually the less common case today.",
    why: "Because file contents cross this channel in the clear unless the session is wrapped in FTPS, a packet capture of port 20 traffic can hand an analyst the exact bytes an attacker exfiltrated or staged. Its more distinctive DFIR signal is behavioral: a server-initiated inbound connection from port 20 back to a client is what FTP bounce/active-mode abuse and FTP-based port-scanning-through-a-third-party rely on, since it lets an attacker make a target believe scan traffic originated from the FTP server rather than from them.",
    commonTriggers: 'Legitimately: an FTP client in active mode receiving a file, or a server responding to a PORT command. Anomalously/maliciously: malware using an FTP data channel to exfiltrate collected files or pull down a secondary payload, or an attacker abusing the FTP PORT command (the classic "FTP bounce" technique) to relay scan/connection traffic through the FTP server toward a third host.',
    indicators: [{ name: 'Active vs. passive mode', desc: 'A genuine inbound connection sourced from tcp/20 only happens in active mode; passive-mode transfers (the modern default) never touch port 20 at all, so real port-20 traffic on the wire is itself worth a second look.' }],
    relatedPorts: ['tcp-21'], attackTechniques: ['T1071.002'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 959 — File Transfer Protocol', url: 'https://www.rfc-editor.org/rfc/rfc959' },
    ],
  },
  {
    slug: 'tcp-21', port: 21, protocol: 'tcp', name: 'FTP (File Transfer Protocol) — Control', category: 'File Sharing & Remote Access', confidence: 'iana-registered',
    what: 'The command channel of an FTP session: the client authenticates with USER/PASS and issues directory-listing and transfer commands, which the server acknowledges with numeric status replies, per RFC 959. This channel also negotiates the companion data channel (port 20 in active mode, or a server-announced high port in passive mode) that carries the actual file bytes.',
    why: "FTP predates any notion of transport encryption, so a plaintext USER/PASS handshake on this port is a straightforward credential-theft opportunity for anyone who can observe the traffic, and an analyst reviewing a capture can read every command an operator or attacker typed. Internet-facing FTP servers — especially ones permitting anonymous login or writable directories — remain a long-running, low-effort target for credential stuffing and for use as a malware/tooling dead-drop.",
    commonTriggers: 'Legitimately: a user or automated job authenticating and transferring files. Anomalously/maliciously: brute-force or credential-stuffing attempts against an internet-facing FTP server, anonymous-login reconnaissance, or an attacker uploading tooling or exfiltrated data to a writable, internet-exposed FTP directory used as a dead-drop.',
    indicators: [{ name: 'Anonymous / plaintext auth', desc: 'A USER anonymous login or a plaintext, non-FTPS PASS command in a capture is itself worth flagging — credential material that, on a compromised host, is often reused elsewhere.' }],
    relatedPorts: ['tcp-20'], attackTechniques: ['T1071.002'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 959 — File Transfer Protocol', url: 'https://www.rfc-editor.org/rfc/rfc959' },
    ],
  },
  {
    slug: 'tcp-22', port: 22, protocol: 'tcp', name: 'SSH (Secure Shell) / SFTP / SCP', category: 'File Sharing & Remote Access', confidence: 'iana-registered',
    what: 'An encrypted remote-login and command-execution protocol (RFC 4251/4253) that also carries file transfer as SFTP and SCP subsystems over the same authenticated, encrypted session, plus arbitrary TCP port forwarding/tunneling. It is the de facto standard for administering Linux/Unix hosts and network appliances, and is increasingly available on Windows via OpenSSH.',
    why: "SSH is the Unix/Linux/network-device equivalent of RDP for an intruder: a valid password or private key grants an interactive, encrypted shell, and because the session is encrypted end-to-end, network-level DFIR from packet capture is largely limited to metadata (who connected, when, for how long) — the real evidence has to come from host-side authentication logs and, if configured, session logging. SSH's own persistence mechanism, planting a key in ~/.ssh/authorized_keys, is a well-documented technique in its own right.",
    commonTriggers: 'Legitimately: system administration, automated deployment/CI over SFTP or SCP, git-over-SSH. Anomalously/maliciously: internet-facing SSH is one of the most continuously brute-forced services on the open internet; an attacker with any foothold may add their own public key to a user\'s authorized_keys file for persistence, or use SSH\'s built-in dynamic port forwarding (-D) as an improvised SOCKS proxy for further pivoting.',
    indicators: [
      { name: 'sshd authentication log', desc: '"Accepted password"/"Accepted publickey" versus repeated "Failed password" entries in auth.log/secure are the primary host-side record of who authenticated, from where, and by what method.' },
      { name: '~/.ssh/authorized_keys modification', desc: 'An unexpected new key or an unexpected modification time on this file is the classic SSH persistence indicator (ATT&CK T1098.004).' },
    ],
    relatedPorts: [], attackTechniques: ['T1021.004', 'T1098.004'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 4253 — The Secure Shell (SSH) Transport Layer Protocol', url: 'https://www.rfc-editor.org/rfc/rfc4253' },
    ],
  },
  {
    slug: 'tcp-23', port: 23, protocol: 'tcp', name: 'Telnet', category: 'File Sharing & Remote Access', confidence: 'iana-registered',
    what: 'A plaintext remote-terminal protocol (RFC 854) that predates SSH by roughly two decades — it opens an interactive command-line session on the remote host with no encryption and, in its base form, no integrity protection at all.',
    why: 'Every credential and every command sent over Telnet is visible to anyone who can observe the traffic, making it one of the simplest "game over" captures an analyst can encounter — a full interactive session, unencrypted, sitting in a pcap. Its continued real-world relevance is mostly on network gear, legacy industrial/SCADA equipment, and consumer IoT devices that never got SSH support; large IoT botnets (Mirai and its many descendants) specifically scan for and brute-force exposed Telnet using default or hardcoded credentials.',
    commonTriggers: 'Legitimately: administering legacy network devices, embedded systems, or ICS/SCADA equipment that only supports Telnet. Anomalously/maliciously: IoT botnet malware scanning the internet for open port 23 and brute-forcing factory-default credentials, or an attacker capturing cleartext credentials from Telnet traffic via a MITM position or a compromised switch SPAN port.',
    indicators: [{ name: 'Cleartext credentials in capture', desc: 'A Telnet session in a packet capture can simply be reassembled to read the login and every subsequent command in plain text.' }],
    relatedPorts: ['tcp-22'], attackTechniques: ['T1021'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 854 — Telnet Protocol Specification', url: 'https://www.rfc-editor.org/rfc/rfc854' },
    ],
  },
  {
    slug: 'tcp-445', port: 445, protocol: 'tcp', name: 'SMB (Server Message Block) / CIFS', category: 'File Sharing & Remote Access', confidence: 'iana-registered',
    what: "Windows' (and Samba's) native file, printer, and named-pipe sharing protocol. Port 445 is \"direct-hosted\" SMB running straight over TCP without the legacy NetBIOS session service (ports 137-139) that older SMB required. Beyond plain file shares, SMB named pipes also carry a range of other Windows RPC-based administrative protocols such as service control, remote registry, and SAM access.",
    why: "SMB is arguably the single highest-value Windows lateral-movement port from a DFIR standpoint: authenticating to the administrative shares (ADMIN$, C$) is the mechanism behind PsExec-style remote execution and its open-source descendants, and SMB has been the delivery vector for some of the largest worm outbreaks on record — the EternalBlue-based WannaCry and NotPetya campaigns exploited unpatched SMBv1. Ransomware operators routinely enumerate and encrypt every reachable SMB share as one of their final acts.",
    commonTriggers: "Legitimately: file/print sharing, Group Policy retrieval, domain controller replication. Anomalously/maliciously: PsExec or Impacket's psexec.py/wmiexec.py/smbexec.py using ADMIN$/C$ to stage and execute a service binary or command, SMB relay/NTLM-relay attacks, or exploitation of an unpatched, exposed SMBv1 host.",
    example: 'An account with no prior administrative activity authenticates over SMB (Logon Type 3), immediately opens a Tree Connect to ADMIN$ (Event 5140), and a new service appears moments later (Event 7045) — the fingerprint of a PsExec-style remote-execution tool rather than routine file access.',
    indicators: [
      { name: 'Tree Connect to an admin share', desc: 'Events 5140 (share accessed) and 5145 (per-file access check) against ADMIN$, C$, or IPC$ are the core SMB lateral-movement signal.' },
      { name: 'Logon Type 3 + service creation', desc: 'A 4624 Logon Type 3 (Network) on the target immediately followed by a 7045 (new service installed) is the classic PsExec-style remote-execution pattern.' },
      { name: 'SMBv1 still in use', desc: 'Any negotiated SMBv1 dialect on a modern network is itself a finding — it should be disabled, and it is what EternalBlue-class exploits require.' },
    ],
    relatedPorts: ['tcp-135'], attackTechniques: ['T1021.002'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'Microsoft Learn — What is SMB File Sharing for Windows and Windows Server?', url: 'https://learn.microsoft.com/en-us/windows-server/storage/file-server/file-server-smb-overview' },
    ],
  },
  {
    slug: 'port-3389', port: 3389, protocol: 'tcp/udp', name: 'RDP (Remote Desktop Protocol)', category: 'File Sharing & Remote Access', confidence: 'iana-registered',
    what: 'Microsoft\'s remote graphical desktop protocol (MS-RDPBCGR), historically a pure TCP protocol but, since RDP 8.0, able to negotiate an additional UDP transport (MS-RDPEUDP) for the same session — used to improve responsiveness for graphics, input, and audio when available, with TCP always present as the base/fallback channel. IANA registers ms-wbt-server on both TCP and UDP port 3389, and Microsoft\'s own documentation lists "TCP and UDP 3389" as the standard RDP port.',
    why: 'RDP is the single highest-value remote-access port on a Windows network for both legitimate admins and intruders alike: a valid credential over RDP grants a full interactive desktop session. It is central to the modern ransomware playbook — exposed RDP is one of the most common initial-access vectors brute-forced or purchased by initial-access brokers and ransomware affiliates, and RDP is equally a common lateral-movement path once inside a network.',
    commonTriggers: 'Legitimately: help-desk/sysadmin remote support, RDS session hosts, remote work. Anomalously/maliciously: internet-facing RDP brute-force or credential-stuffing (near-constant background noise on any exposed 3389), RDP used as initial access or lateral movement by ransomware operators, or RDP session hijacking via tscon.exe.',
    example: 'A host with no history of legitimate remote-admin RDP activity logs a burst of Logon Type 10 failures (Event 4625) from a single external IP, followed by one success (Event 4624) — a textbook brute-force-then-compromise pattern that should trigger immediate triage of that account and host.',
    indicators: [
      { name: 'Logon Type 10', desc: 'Events 4624 (success) / 4625 (failure) with Logon Type 10 (RemoteInteractive) are the definitive Windows Security-log marker of an RDP logon attempt.' },
      { name: 'Event 1149', desc: 'TerminalServices-RemoteConnectionManager/Operational Event 1149 records an authenticated RDP network connection and persists even if the Security log has since rolled over — useful when the primary log has aged out.' },
    ],
    relatedPorts: [], attackTechniques: ['T1021.001'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'Microsoft Learn — Ports That Are Used by RDS', url: 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/ports-used-by-rds' },
      { name: '[MS-RDPBCGR]: Remote Desktop Protocol — Basic Connectivity and Graphics Remoting', url: 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/5073f4ed-1e93-45e1-b039-6e30c385867c' },
    ],
  },
  {
    slug: 'tcp-5900', port: 5900, protocol: 'tcp', name: 'VNC (Virtual Network Computing) / RFB', category: 'File Sharing & Remote Access', confidence: 'iana-registered',
    what: 'A cross-platform remote-framebuffer protocol (RFC 6143) implemented by numerous independent products (RealVNC, TightVNC, UltraVNC, TigerVNC) rather than being tied to one vendor or OS. Port 5900 corresponds to display :0; additional displays on the same host stack upward (5901 for :1, and so on).',
    why: 'Historically, several VNC implementations have shipped with weak, optional, or outright no authentication, and once a session is established the remote party has the same interactive GUI control as someone sitting at the console — no distinction between a legitimate remote-support session and a full-control backdoor at the protocol level. Internet-exposed, unauthenticated VNC servers are a long-running, low-effort mass-scan target.',
    commonTriggers: 'Legitimately: remote IT support and screen-sharing tools built on VNC. Anomalously/maliciously: mass scanning for and connecting to unauthenticated internet-exposed VNC servers, or malware bundling a VNC server as a secondary remote-access backdoor.',
    indicators: [{ name: 'VNC server process on an unexpected host', desc: 'Process creation for a VNC server binary (e.g. winvnc.exe, tvnserver.exe) on a system with no legitimate remote-support justification is worth investigating as a potential backdoor.' }],
    relatedPorts: [], attackTechniques: ['T1021.005'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 6143 — The Remote Framebuffer Protocol', url: 'https://www.rfc-editor.org/rfc/rfc6143' },
    ],
  },
  {
    slug: 'port-2049', port: 2049, protocol: 'tcp/udp', name: 'NFS (Network File System)', category: 'File Sharing & Remote Access', confidence: 'iana-registered',
    what: 'Unix/Linux\'s native network file-sharing protocol, originally from Sun Microsystems. Older versions (NFSv2/RFC 1094, NFSv3/RFC 1813) could run over either TCP or UDP and relied on the separate rpcbind/portmapper service (port 111) to locate the actual mount/NFS daemon ports; NFSv4 (RFC 7530, and RFC 8881 for minor version 1) consolidated everything onto the single well-known port 2049 and effectively requires TCP.',
    why: 'Classic NFS authorization is host- and UID-based rather than credential-based: a client presenting a given UID over a trusted source IP is generally believed by default unless the export is configured with root-squashing and, ideally, Kerberos (sec=krb5). That means an attacker who can reach an export from a trusted-looking address, or who can assume or spoof a privileged UID, can read or write files with no password at all — a long-standing Unix privilege-escalation and data-exposure vector when exports are misconfigured.',
    commonTriggers: 'Legitimately: enterprise/HPC shared storage, ESXi or Unix backup and build targets. Anomalously/maliciously: mounting a misconfigured export from an untrusted host, exploiting a no_root_squash export to write a setuid binary or an SSH authorized_keys file onto the target, or a client spoofing a trusted UID to read sensitive files.',
    indicators: [
      { name: 'showmount -e enumeration', desc: 'Requests enumerating a server\'s exported shares are a common reconnaissance precursor to exploiting a misconfigured export.' },
      { name: 'no_root_squash exports', desc: 'An export configured with no_root_squash (root on the client maps to root on the server) is a critical finding during any NFS configuration review.' },
    ],
    relatedPorts: ['port-111'], attackTechniques: [],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 7530 — Network File System (NFS) Version 4 Protocol', url: 'https://www.rfc-editor.org/rfc/rfc7530' },
    ],
  },
  {
    slug: 'port-111', port: 111, protocol: 'tcp/udp', name: 'RPCbind (Portmapper) / ONC RPC', category: 'File Sharing & Remote Access', confidence: 'iana-registered',
    what: 'The ONC RPC (Sun RPC) directory service: it maps an RPC program number — such as the NFS mount/nfsd services — to the actual dynamic port that service is listening on, functionally the Unix/Linux counterpart to the Windows MSRPC endpoint mapper on port 135. Current implementations use the rpcbind protocol (RFC 1833); the older, TCP/UDP-specific predecessor was the Port Mapper protocol.',
    why: 'An exposed rpcbind is a reconnaissance goldmine — an rpcinfo -p query against it dumps every RPC service registered on the host along with its live port, effectively mapping the box\'s RPC attack surface for free. UDP port 111 is also a well-documented DDoS reflection/amplification vector: a small spoofed query can trigger a substantially larger response directed at a victim whose address was forged as the source.',
    commonTriggers: 'Legitimately: an NFS server (or other ONC RPC service) registering itself on startup, or a local client resolving an RPC service\'s port. Anomalously/maliciously: rpcinfo -p enumeration of an internet-facing host, or abuse of an open UDP/111 service as a DDoS reflector against a spoofed victim IP.',
    example: 'A burst of small inbound UDP/111 queries followed by disproportionately larger outbound responses toward a third-party IP that never initiated the query is the signature of the host being abused as a DDoS reflector, not a real client lookup.',
    indicators: [
      { name: 'rpcinfo enumeration', desc: 'Unsolicited RPC program-number queries from unfamiliar source IPs are a straightforward reconnaissance signal.' },
      { name: 'Amplification traffic pattern', desc: 'A burst of small inbound UDP/111 queries paired with disproportionately larger outbound responses to a third-party IP indicates the host is being abused as a DDoS reflector.' },
    ],
    relatedPorts: ['port-2049'], attackTechniques: [],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 1833 — Binding Protocols for ONC RPC Version 2', url: 'https://www.rfc-editor.org/rfc/rfc1833' },
    ],
  },
  {
    slug: 'tcp-135', port: 135, protocol: 'tcp', name: 'MSRPC Endpoint Mapper (DCE/RPC)', category: 'Remote Management & Administration', confidence: 'iana-registered',
    what: "Windows' RPC locator service: a client connects to port 135 and asks which dynamic high port (typically 49152-65535 on modern Windows) a specific RPC interface — a WMI provider, a DCOM activation request, a remote service-control call — is actually listening on, then opens a second connection to that port to do the real work. DCOM is itself built on top of this same MSRPC transport.",
    why: "Port 135 is almost always the first hop of Windows RPC-based lateral movement rather than the whole story: DCOM lateral movement (ATT&CK T1021.003) and remote WMI execution both start here before the substantive traffic moves to a dynamic high port, which is why blocking or tightly scoping 135 breaks both techniques outright. It is also a pure information-disclosure surface on its own — enumerating what's registered on the endpoint mapper reveals what RPC-based services a host exposes.",
    commonTriggers: 'Legitimately: normal Windows RPC activity — WMI queries, DCOM activation, remote service management from admin tooling. Anomalously/maliciously: DCOM lateral movement via objects like MMC20.Application or ShellWindows, remote WMI process creation (Win32_Process.Create), or reconnaissance enumerating registered RPC interfaces.',
    example: 'A workstation-to-workstation connection to tcp/135 followed within seconds by a connection to a high dynamic port, with no corresponding helpdesk or admin activity, matches the DCOM lateral-movement pattern documented for objects like MMC20.Application — worth pivoting on the source process on the initiating host.',
    indicators: [
      { name: '135 followed by a high dynamic port', desc: 'A connection to tcp/135 immediately followed by a second connection from the same source to a port in the 49152-65535 range is the signature DCE/RPC two-step, visible in Sysmon Event ID 3 (Network Connection) chains.' },
      { name: 'DCOM errors (10009/10028)', desc: 'System-log events 10009 (older Windows) / 10028 (Windows Server 2016+) — "DCOM was unable to communicate with the computer" — are a byproduct signal of an attempted, if failed or blocked, DCOM/RPC connection, not proof of a successful one.' },
    ],
    relatedPorts: ['tcp-445', 'tcp-5985'], attackTechniques: ['T1021.003', 'T1047'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'Microsoft Learn — Remote Procedure Call (RPC) dynamic port allocation with firewalls', url: 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-rpc-dynamic-port-allocation-with-firewalls' },
    ],
  },
  {
    slug: 'tcp-5985', port: 5985, protocol: 'tcp', name: 'WinRM (Windows Remote Management) — HTTP', category: 'Remote Management & Administration', confidence: 'iana-registered',
    what: "Microsoft's implementation of the WS-Management (WS-Man) standard; it is the transport underneath PowerShell Remoting (Enter-PSSession, Invoke-Command) and WMI-over-WinRM. Port 5985 is the default plaintext-HTTP listener — the SOAP payload itself is typically still protected at the message level by Kerberos/NTLM in a default domain configuration, but the outer HTTP channel is not TLS.",
    why: "WinRM is PowerShell Remoting's transport, making it both a core admin-automation channel and an equally capable lateral-movement path once an attacker has a valid credential — and it is frequently less closely monitored than RDP, since it never presents an interactive desktop. On the target, remote sessions are hosted by wsmprovhost.exe; that process spawning unexpected child processes is a strong lateral-movement signal.",
    commonTriggers: 'Legitimately: PowerShell Remoting for admin scripts, configuration-management tools (Ansible, Puppet, Chef) targeting Windows over WinRM, System Center. Anomalously/maliciously: Invoke-Command/Enter-PSSession used for post-compromise lateral movement, the Evil-WinRM tool, or WMI queries executed over a WinRM session.',
    indicators: [
      { name: 'wsmprovhost.exe as parent process', desc: 'A WinRM/PowerShell-Remoting session hosts the client\'s commands under wsmprovhost.exe on the target — unexpected child processes under it are a strong lateral-movement indicator.' },
      { name: '4624 Logon Type 3 + WinRM operational log', desc: 'Correlating a Network logon (Logon Type 3) with a session-creation entry in the Microsoft-Windows-WinRM/Operational log confirms a remoting session, not just an ordinary network authentication.' },
    ],
    relatedPorts: ['tcp-5986', 'tcp-135'], attackTechniques: ['T1021.006'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'Microsoft Learn — Installation and configuration for Windows Remote Management', url: 'https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management' },
    ],
  },
  {
    slug: 'tcp-5986', port: 5986, protocol: 'tcp', name: 'WinRM (Windows Remote Management) — HTTPS', category: 'Remote Management & Administration', confidence: 'iana-registered',
    what: 'The same WS-Management/PowerShell Remoting service as port 5985, bound instead to a TLS-wrapped HTTPS listener backed by a certificate. It is the encrypted counterpart, commonly required when remoting across an untrusted network segment or to a non-domain-joined/workgroup host where Kerberos isn\'t available.',
    why: 'The DFIR relevance mirrors 5985 — it is the same PowerShell Remoting lateral-movement path — but the TLS wrapping means network-level visibility from packet capture can\'t see into session content at all; evidence has to come from host-side logs (the WinRM operational log, PowerShell Script Block Logging) rather than the wire. An unexpected new HTTPS listener, or one bound to an unexpected certificate, is itself worth investigating.',
    commonTriggers: 'Legitimately: WinRM configured for certificate-based or CredSSP remoting across a DMZ or to non-domain-joined hosts. Anomalously/maliciously: the same lateral-movement tooling as 5985 but over the encrypted listener, or an attacker adding a new WinRM HTTPS listener for covert remote access.',
    indicators: [{ name: 'Unexpected listener creation', desc: "A new entry under winrm enumerate winrm/config/Listener that an admin didn't create, or one bound to a certificate that doesn't trace back to expected PKI issuance, is worth investigating." }],
    relatedPorts: ['tcp-5985'], attackTechniques: ['T1021.006'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'Microsoft Learn — Installation and configuration for Windows Remote Management', url: 'https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management' },
    ],
  },
  {
    slug: 'udp-161', port: 161, protocol: 'udp', name: 'SNMP (Simple Network Management Protocol)', category: 'Remote Management & Administration', confidence: 'iana-registered',
    what: 'The standard protocol for polling and configuring network infrastructure — routers, switches, printers, UPS units, and similar devices — using GET/GETNEXT/GETBULK to read values and SET to write configuration. SNMPv1/v2c authenticate with a plaintext "community string"; SNMPv3 (RFC 3411 and its companion RFCs) adds real user-based authentication and encryption.',
    why: 'Default or weak community strings ("public" for read, "private" for write) are still endemic on network gear, and a readable community string alone hands an attacker a working reconnaissance channel into routing tables, interface state, and running configuration on some devices, while a writable one enables outright reconfiguration. SNMP GetBulk requests are also a documented UDP amplification/reflection DDoS vector.',
    commonTriggers: 'Legitimately: network monitoring platforms (SolarWinds, PRTG, Zabbix, etc.) polling device health and interface counters. Anomalously/maliciously: SNMP sweeps or community-string brute-forcing against network infrastructure, GetBulk-based DDoS reflection abuse, or device reconfiguration via a guessed write community.',
    example: 'A flood of GetBulk requests against a device configured with the default "public" community string, followed by disproportionately large outbound UDP responses toward an address that never previously polled the device, indicates the device is being abused as a DDoS amplifier rather than queried by a legitimate NMS.',
    indicators: [
      { name: 'Default community strings', desc: 'Any successful query using "public" or "private" is an immediate, high-priority finding — those values should never be in production use.' },
      { name: 'SNMPv1/v2c in use at all', desc: 'Plaintext-community SNMP traffic where SNMPv3 is available is itself worth flagging during a configuration review.' },
    ],
    relatedPorts: ['udp-162'], attackTechniques: [],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 3411 — An Architecture for Describing SNMP Management Frameworks', url: 'https://www.rfc-editor.org/rfc/rfc3411' },
    ],
  },
  {
    slug: 'udp-162', port: 162, protocol: 'udp', name: 'SNMP Trap', category: 'Remote Management & Administration', confidence: 'iana-registered',
    what: 'The reverse-direction channel from SNMP polling: instead of being queried, a managed device pushes an unsolicited notification — link down, temperature threshold, cold/warm start, and similar events — to a management station listening on port 162.',
    why: 'Because SNMPv1/v2c traps carry the same plaintext community string as regular SNMP queries, they are equally visible on the wire, and because a receiving station generally trusts whatever arrives on 162, forged or spoofed traps can be used to plant misleading status data in a monitoring system — or, in bulk, to flood and degrade the trap receiver itself.',
    commonTriggers: 'Legitimately: network devices notifying a monitoring platform of state changes such as an interface going down or a device restarting. Anomalously/maliciously: spoofed or forged traps sent to mislead a monitoring system, or trap flooding as a minor denial-of-service against the receiver.',
    indicators: [{ name: 'Traps from unmanaged sources', desc: 'A trap arriving from a source IP with no corresponding managed-device entry in the NMS is inherently suspicious.' }],
    relatedPorts: ['udp-161'], attackTechniques: [],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 3411 — An Architecture for Describing SNMP Management Frameworks', url: 'https://www.rfc-editor.org/rfc/rfc3411' },
    ],
  },
  {
    slug: 'udp-514', port: 514, protocol: 'udp', name: 'Syslog', category: 'Remote Management & Administration', confidence: 'iana-registered',
    what: 'The standard log-transport protocol: a device or host sends log messages — originally the loosely structured BSD format, later formalized by RFC 5424 — to a central collector. RFC 5426 defines the plain UDP transport, which is connectionless, unauthenticated, and unencrypted by design.',
    why: "Syslog over UDP is the backbone of most centralized logging/SIEM pipelines, which makes it essential telemetry and simultaneously a spoofable, lossy one: with no source authentication, forged log entries can be injected to pollute or mislead an investigation, and because delivery is fire-and-forget UDP, messages can silently drop under load — worth keeping in mind whenever a device \"should have\" logged an event and the collector has no record of it.",
    commonTriggers: 'Legitimately: firewalls, switches, and servers forwarding logs to a SIEM or a syslog-ng/rsyslog collector. Anomalously/maliciously: log injection/spoofing via a forged UDP source address, flooding a collector to induce message loss, or an attacker altering a device\'s configured syslog destination to blind or redirect its logging.',
    indicators: [
      { name: 'Source/identity mismatch', desc: "A syslog message whose source IP doesn't match the hostname or device identity claimed in the message body is a spoofing indicator." },
      { name: 'Unexplained log-volume drop', desc: "A sudden drop in log volume from a device that's otherwise still reachable is worth investigating as either lost UDP traffic or deliberate log tampering." },
    ],
    relatedPorts: ['tcp-6514'], attackTechniques: [],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 5426 — Transmission of Syslog Messages over UDP', url: 'https://www.rfc-editor.org/rfc/rfc5426' },
    ],
  },
  {
    slug: 'tcp-6514', port: 6514, protocol: 'tcp', name: 'Syslog over TLS', category: 'Remote Management & Administration', confidence: 'iana-registered',
    what: "RFC 5425's TLS transport mapping for syslog: it wraps the same RFC 5424-structured messages in a TLS session, adding the confidentiality, integrity, and (with mutual TLS) sender authentication that plain UDP/514 lacks. IANA separately registers port 6514 for a DTLS-wrapped variant (RFC 6012) as well, though the TCP/TLS mapping is the one actually seen in real-world deployments.",
    why: "When an environment has deliberately moved log forwarding onto this port, it signals a hardened logging pipeline resistant to the spoofing and eavesdropping weaknesses of plain UDP syslog — which raises an analyst's confidence in the integrity of that log stream. Conversely, a TLS handshake failure or certificate mismatch on this port is itself worth investigating, since it can indicate a misconfigured client or a rogue collector attempting to intercept redirected log traffic.",
    commonTriggers: 'Legitimately: compliance-driven or security-conscious environments (e.g. PCI-DSS-scoped networks) running rsyslog/syslog-ng with TLS-enabled forwarding. Anomalously/maliciously: an attacker standing up a rogue TLS syslog listener to intercept redirected log forwarding, or exploiting a client configured to skip certificate validation.',
    indicators: [{ name: 'Certificate validation failures', desc: 'Self-signed or otherwise unexpected certificates presented by a syslog-tls listener are worth investigating as either misconfiguration or a rogue collector.' }],
    relatedPorts: ['udp-514'], attackTechniques: [],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 5425 — TLS Transport Mapping for Syslog', url: 'https://www.rfc-editor.org/rfc/rfc5425' },
    ],
  },
  {
    slug: 'tcp-1433', port: 1433, protocol: 'tcp', name: 'Microsoft SQL Server', category: 'Databases', confidence: 'iana-registered',
    what: "The default port for Microsoft SQL Server's default database engine instance, carrying the Tabular Data Stream (TDS) protocol that clients use to authenticate and run queries. IANA registers the service name ms-sql-s to port 1433 for both TCP and UDP, but in real deployments the database engine itself listens on TCP; the companion UDP service on port 1434 is the separate SQL Server Browser/Resolution service that helps clients locate named instances using dynamic ports, not the query channel itself.",
    why: "SQL Server exposed to the internet on 1433 is a long-running, high-volume target for brute-forcing the built-in 'sa' account or other weak SQL-authentication credentials — a well-documented initial-access path used by multiple ransomware affiliates to get code execution via xp_cmdshell once inside. It's also one of the first ports scanned to fingerprint a Windows-hosted database tier during network reconnaissance.",
    commonTriggers: "Legitimately: application/ORM connections, SSMS/Azure Data Studio administration, linked-server queries, and SQL Server Agent jobs. Anomalously/maliciously: internet-facing 1433 receiving high-volume authentication attempts (credential stuffing/brute force against sa), a successful login immediately followed by xp_cmdshell or sp_configure changes, or unexpected inbound connections from a non-application host.",
    indicators: [
      { name: 'Repeated failed sa/SQL logins', desc: 'A burst of failed authentication attempts against the sa account or other SQL logins from a single source is the classic precursor to a brute-force compromise.' },
      { name: 'xp_cmdshell enablement', desc: 'sp_configure enabling xp_cmdshell shortly after a new login session is a strong signal the attacker is pivoting from database access to OS command execution.' },
      { name: 'Unexpected inbound source', desc: 'Connections to 1433 from outside the known application server/subnet range warrant checking firewall/NSG rules for accidental internet exposure.' },
    ],
    relatedPorts: [], attackTechniques: ['T1046', 'T1078'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'Microsoft Learn — Configure a Server to Listen on a Specific TCP Port', url: 'https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-a-server-to-listen-on-a-specific-tcp-port?view=sql-server-ver16' },
    ],
  },
  {
    slug: 'tcp-1521', port: 1521, protocol: 'tcp', name: 'Oracle Database (Oracle Net Listener)', category: 'Databases', confidence: 'de-facto-standard',
    what: "The conventional default port for the Oracle Net Listener, the process that brokers incoming client connections and hands them off to an Oracle Database instance over Oracle's TNS (Transparent Network Substrate) protocol. Notably, IANA's registry does not actually assign 1521 to Oracle — it's registered to 'ncube-lm' (nCube License Manager); Oracle's own officially IANA-registered ports are 2483/2484 (plain/TLS), but 1521 remains the overwhelmingly dominant real-world default carried forward from decades of Oracle deployment convention.",
    why: "An exposed listener on 1521 is a reconnaissance goldmine: unauthenticated TNS requests can enumerate configured service names (SIDs) via commands like a TNS PING or version query, and historically weak/default listener configurations (no listener password, or default accounts such as SCOTT/TIGER) have enabled unauthorized database access without ever touching an application. It's a routine pivot point in assessments and real intrusions targeting Oracle-backed ERP/financial systems.",
    commonTriggers: "Legitimately: application connection pools, DBA tools (SQL*Plus, SQL Developer), and Oracle Enterprise Manager reaching the listener. Anomalously/maliciously: TNS enumeration/version-fingerprinting probes, SID brute-forcing, or authentication attempts against default Oracle accounts from unexpected hosts.",
    indicators: [
      { name: 'TNS listener version probes', desc: 'Malformed or version-query TNS packets from scanning tools (e.g. tnscmd10g-style probes) indicate reconnaissance against the listener itself, before any database login is attempted.' },
      { name: 'Default account logon attempts', desc: 'Login attempts using well-known legacy default Oracle accounts (e.g. SCOTT/TIGER, SYSTEM) are a strong sign of an automated or opportunistic attack rather than legitimate application traffic.' },
    ],
    example: 'An externally reachable Oracle listener with no listener password set allows an unauthenticated TNS client to enumerate the instance\'s registered service names, which the attacker then uses to target a specific SID for credential brute-forcing.',
    relatedPorts: [], attackTechniques: ['T1046', 'T1078'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: "Oracle Database Net Services Administrator's Guide — Configuring and Administering Oracle Net Listener", url: 'https://docs.oracle.com/database/122/NETAG/configuring-and-administering-oracle-net-listener.htm' },
    ],
  },
  {
    slug: 'tcp-3306', port: 3306, protocol: 'tcp', name: 'MySQL / MariaDB', category: 'Databases', confidence: 'iana-registered',
    what: 'The IANA-registered default port for the MySQL Client/Server binary protocol, used identically by MariaDB (a MySQL-compatible fork). Clients authenticate and exchange queries/result sets with the server over this single persistent TCP connection; local connections on the same host commonly use a Unix socket instead, bypassing the network port entirely.',
    why: '3306 exposed to the internet is one of the most heavily mass-scanned database ports there is, targeted for weak/blank root passwords, and — depending on server configuration — the FILE privilege combined with INTO OUTFILE/LOAD_DATA can be abused for file read/write on the host. Compromised MySQL instances are a recurring vector for both credential-stuffing campaigns and opportunistic ransom-note/data-wiping attacks against exposed cloud databases.',
    commonTriggers: 'Legitimately: application/ORM connections, replication traffic between primary and replica servers, and administrative tools (MySQL Workbench, mysqldump). Anomalously/maliciously: internet-facing 3306 receiving credential-stuffing traffic, successful root logins from unfamiliar source IPs, or query patterns consistent with SELECT ... INTO OUTFILE used to write a webshell to disk.',
    indicators: [
      { name: 'Root login from unexpected source', desc: 'A successful MySQL root (or other high-privilege account) authentication from an IP outside the known application tier is the single highest-value pivot point in a database compromise timeline.' },
      { name: 'INTO OUTFILE / LOAD_FILE usage', desc: "Queries using INTO OUTFILE or LOAD_FILE() are a classic technique for reading arbitrary server files or writing a webshell when the FILE privilege and secure_file_priv aren't tightly restricted." },
    ],
    relatedPorts: [], attackTechniques: ['T1046', 'T1078'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'MySQL 8.4 Reference Manual — Connecting to the MySQL Server Using Command Options', url: 'https://dev.mysql.com/doc/refman/8.4/en/connecting.html' },
    ],
  },
  {
    slug: 'tcp-5432', port: 5432, protocol: 'tcp', name: 'PostgreSQL', category: 'Databases', confidence: 'iana-registered',
    what: "The IANA-registered default port for the PostgreSQL database server's connection listener, carrying PostgreSQL's own frontend/backend wire protocol. The port choice dates back to the original Berkeley POSTGRES project and has stayed the de facto standard through every subsequent PostgreSQL release.",
    why: 'An exposed 5432 is routinely scanned for weak or trust-based authentication (pg_hba.conf misconfigured to trust connections it shouldn\'t), and a compromised superuser session can reach the OS via features like COPY ... TO/FROM PROGRAM, making database access a direct path to remote code execution. Cloud-hosted PostgreSQL instances left open with default/no passwords have been targeted in the same opportunistic ransom-wipe campaigns that hit other exposed databases.',
    commonTriggers: 'Legitimately: application connection pools, logical/streaming replication between primary and standby servers, and admin tools (psql, pgAdmin). Anomalously/maliciously: authentication attempts against default accounts (e.g. postgres) from unfamiliar hosts, or a session invoking COPY ... TO/FROM PROGRAM shortly after login.',
    indicators: [
      { name: 'COPY ... PROGRAM usage', desc: "The COPY command's PROGRAM option executes an arbitrary shell command on the server — its use by a session is a strong pivot point from database access to OS command execution." },
      { name: 'pg_hba.conf trust/md5 exposure', desc: 'A pg_hba.conf entry trusting a broad network range, or still using the weaker legacy md5 auth method for internet-facing connections, is worth confirming during triage of any suspected compromise.' },
    ],
    relatedPorts: [], attackTechniques: ['T1046', 'T1078'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'PostgreSQL Documentation — Connections and Authentication (port parameter)', url: 'https://www.postgresql.org/docs/current/runtime-config-connection.html' },
    ],
  },
  {
    slug: 'tcp-27017', port: 27017, protocol: 'tcp', name: 'MongoDB', category: 'Databases', confidence: 'iana-registered',
    what: 'The default port for mongod (and mongos router) instances, carrying MongoDB\'s own binary wire protocol used by drivers and the mongosh shell to issue commands and queries. IANA registers this port to MongoDB Inc. specifically for TCP; the UDP variant is reserved/unused.',
    why: 'MongoDB shipped with no authentication enabled by default for many years, and the resulting population of internet-exposed, unauthenticated instances became the target of large, well-documented mass campaigns that connected, dumped or deleted the data, and left a ransom note demanding payment for its return — attacks that required no credentials or exploit at all, just an open 27017. It remains one of the fastest-triggering "why is this database on the internet" findings in any external exposure review.',
    commonTriggers: 'Legitimately: application drivers, replica set/sharded cluster member communication, and admin tools (mongosh, Compass). Anomalously/maliciously: an unauthenticated internet-facing instance receiving connections that immediately drop or rename collections and insert a ransom-note document, or successful auth attempts against default/weak credentials on an instance that does have auth enabled.',
    indicators: [
      { name: 'Ransom-note collection', desc: 'A newly created collection or document containing a ransom demand and a contact address, in an otherwise legitimate database, is the hallmark of the mass Mongo-wiping campaigns and should be treated as a confirmed compromise, not just exposure.' },
      { name: 'No-auth bind to 0.0.0.0', desc: 'Confirming whether --auth/security.authorization was enabled and whether bindIp was left at its permissive default is the first triage step for any internet-facing MongoDB instance.' },
    ],
    example: 'An unauthenticated MongoDB instance left bound to 0.0.0.0:27017 is discovered by an internet-wide scanner within hours, its collections are dropped, and a single new document demanding payment in cryptocurrency is inserted in their place — the entire attack requiring nothing beyond an unauthenticated TCP connection.',
    relatedPorts: [], attackTechniques: ['T1046', 'T1485'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'MongoDB Documentation — Default MongoDB Port', url: 'https://www.mongodb.com/docs/manual/reference/default-mongodb-port/' },
    ],
  },
  {
    slug: 'tcp-6379', port: 6379, protocol: 'tcp', name: 'Redis', category: 'Databases', confidence: 'iana-registered',
    what: 'The default port for the Redis in-memory key-value store\'s connection listener, carrying the RESP (REdis Serialization Protocol) wire protocol. IANA registers this port to Redis for TCP only; classic Redis ships with no authentication by default (a requirepass directive must be set explicitly), and older versions had no ACL system at all.',
    why: 'An unauthenticated, internet-exposed Redis instance is directly abusable for remote code execution without any separate vulnerability: an attacker can use CONFIG SET dir/dbfilename plus SAVE to write an arbitrary file (an SSH authorized_keys entry, a cron job, or a webshell) to a chosen path on disk. This exact technique has been used at scale by cryptomining worms and botnet operators to gain persistence on exposed Linux hosts.',
    commonTriggers: 'Legitimately: application/cache client connections, replica synchronization from a Redis replica, and Sentinel/Cluster peer traffic. Anomalously/maliciously: CONFIG SET commands changing dir/dbfilename immediately followed by a SAVE, or connections from unfamiliar source IPs against an instance with no requirepass configured.',
    indicators: [
      { name: 'CONFIG SET dir/dbfilename + SAVE', desc: 'This exact command sequence is the signature of the well-known unauthenticated-Redis-to-RCE technique — it repurposes Redis\'s own persistence feature to drop a file (SSH key, cron entry, webshell) at an attacker-chosen path.' },
      { name: 'requirepass unset', desc: 'Confirming whether requirepass (or Redis 6+ ACLs) is configured is the first triage step for any Redis instance reachable outside its intended application tier.' },
    ],
    relatedPorts: [], attackTechniques: ['T1046', 'T1053.003'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'Redis Documentation — Install Redis (default port 6379)', url: 'https://redis.io/docs/latest/operate/oss_and_stack/install/archive/install-redis/' },
    ],
  },
  {
    slug: 'tcp-9200', port: 9200, protocol: 'tcp', name: 'Elasticsearch (HTTP REST API)', category: 'Databases', confidence: 'de-facto-standard',
    what: "The default port for Elasticsearch's HTTP interface, over which clients send REST API calls (indexing, search, cluster management) — distinct from port 9300, the transport interface nodes use to talk to each other within a cluster. Notably, IANA's registry does not assign 9200 to Elasticsearch at all — it's officially registered to 'wap-wsp' (WAP connectionless session service), a legacy mobile-carrier protocol; 9200 is purely an Elastic-chosen application default, not an IANA assignment, in the same way 1521 is Oracle's de facto (not official) port.",
    why: "Elasticsearch has historically shipped without authentication enabled by default in many self-managed deployments, and internet-exposed clusters have repeatedly been found, indexed, and either exfiltrated or wiped with a ransom note — the same pattern seen against exposed MongoDB. Because the entire API surface (including deleting indices) is reachable over plain HTTP once auth is off, a DFIR analyst finding 9200 open to the internet should treat it as equivalent to an open, unauthenticated database until proven otherwise.",
    commonTriggers: 'Legitimately: Kibana and application clients issuing REST queries, Logstash/Beats ingest traffic, and cluster health checks. Anomalously/maliciously: unauthenticated requests from the internet enumerating indices (GET /_cat/indices) followed by bulk DELETE calls or a newly created index containing a ransom message.',
    indicators: [
      { name: 'Unauthenticated /_cluster or /_cat access', desc: 'Successful, unauthenticated calls to cluster/index management endpoints from an external IP confirm the instance has no security layer (X-Pack security / xpack.security.enabled) active.' },
      { name: 'Mass index deletion', desc: 'A burst of DELETE requests against multiple indices in quick succession, especially followed by creation of a single new index, matches the pattern of the mass ransom-wipe campaigns targeting exposed Elasticsearch clusters.' },
    ],
    relatedPorts: [], attackTechniques: ['T1046', 'T1485'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'Elasticsearch Reference — Networking settings (http.port)', url: 'https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/networking-settings' },
    ],
  },
  {
    slug: 'udp-67', port: 67, protocol: 'udp', name: 'DHCP Server (BOOTPS)', category: 'Network Infrastructure', confidence: 'iana-registered',
    what: "The port a DHCP (Dynamic Host Configuration Protocol) server listens on for client requests, inherited from the older BOOTP protocol it extends (the IANA service name is still 'bootps'). The server uses it to receive DISCOVER/REQUEST broadcasts and hand out IP leases plus configuration options (gateway, DNS, and — for network-boot setups — a TFTP server address).",
    why: "DHCP has no built-in authentication, so any host on the local broadcast segment can pose as a server: a rogue DHCP server can hand out a malicious default gateway or DNS server to every client that asks, silently putting the attacker in the middle of victims' traffic. It's also one of the oldest, most reliable ways to pivot from a compromised or physically-accessible network segment into broad, low-effort visibility over other hosts on that segment.",
    commonTriggers: 'Legitimately: exactly one authorized DHCP server (or a small, known set in a failover/HA configuration) answering client leases on a subnet. Anomalously/maliciously: a second, unauthorized host answering DHCP DISCOVER broadcasts (a rogue DHCP server), or a flood of DISCOVER messages from spoofed MAC addresses intended to exhaust the legitimate server\'s address pool.',
    indicators: [
      { name: 'Unexpected DHCP server source', desc: 'A DHCP OFFER/ACK from a MAC/IP outside the known, authorized server list is the direct signature of a rogue DHCP server / man-in-the-middle setup and should be investigated immediately.' },
      { name: 'Pool exhaustion / high lease churn', desc: 'An unusually high rate of new DISCOVER requests exhausting the address pool can indicate a DHCP starvation attack, often a precursor to standing up a rogue server once clients fail over to it.' },
    ],
    relatedPorts: ['udp-68', 'udp-69'], attackTechniques: ['T1557.003'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 2131 — Dynamic Host Configuration Protocol', url: 'https://www.rfc-editor.org/rfc/rfc2131.html' },
    ],
  },
  {
    slug: 'udp-68', port: 68, protocol: 'udp', name: 'DHCP Client (BOOTPC)', category: 'Network Infrastructure', confidence: 'iana-registered',
    what: "The port a DHCP client listens on to receive OFFER and ACK replies from a DHCP server, the client-side counterpart to server port 67 (again inheriting the BOOTP-era 'bootpc' service name from IANA). Every DHCP-configured host briefly uses this port during lease acquisition and renewal.",
    why: "This port itself is rarely attacker-controlled, but it's the receiving end of the same DHCP spoofing/rogue-server abuse that makes port 67 significant — a client answering an attacker's OFFER on 68 is the moment a host actually accepts a malicious gateway or DNS server. In packet captures, traffic on 67/68 together is what an analyst reconstructs to determine exactly which configuration a given host received and when.",
    commonTriggers: 'Legitimately: the brief DISCOVER/OFFER/REQUEST/ACK exchange at boot, on network reconnect, or at lease renewal. Anomalously/maliciously: a client accepting an OFFER from an unauthorized server (visible as a 67→68 reply from an unexpected source), which is the concrete evidence a rogue-DHCP attack succeeded against that host.',
    indicators: [], relatedPorts: ['udp-67'], attackTechniques: ['T1557.003'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 2131 — Dynamic Host Configuration Protocol', url: 'https://www.rfc-editor.org/rfc/rfc2131.html' },
    ],
  },
  {
    slug: 'udp-69', port: 69, protocol: 'udp', name: 'TFTP (Trivial File Transfer Protocol)', category: 'Network Infrastructure', confidence: 'iana-registered',
    what: "A minimal, connectionless file-transfer protocol with no authentication and no directory listing — a client sends a read or write request and the server streams the file in fixed-size blocks. It's the standard mechanism for PXE network-boot images and for backing up/restoring configuration on network devices (routers, switches, VoIP phones).",
    why: "Because TFTP has no authentication, anything reachable over it is available to anyone who can reach the port — and it's the textbook transport adversaries use to pull a compromised network device's running configuration (which can contain hashed or plaintext credentials, SNMP community strings, and routing details) off to attacker-controlled infrastructure. Seeing TFTP traffic to or from a router/switch outside a planned maintenance window is a strong signal of device-level compromise, not routine administration.",
    commonTriggers: "Legitimately: scheduled configuration backups, firmware upgrades, and PXE boot of diskless/imaging clients (often handed a TFTP server address via DHCP options 66/67). Anomalously/maliciously: a network device pushing its running-config to an unfamiliar external IP over TFTP, or unsolicited TFTP read requests probing for exposed files.",
    indicators: [
      { name: 'Config file transfer to external host', desc: "A TFTP write/read of a file named like a device config (e.g. 'running-config', 'startup-config') to or from an IP outside the management network is the core signature of the config-exfiltration technique documented in real router-compromise campaigns." },
      { name: 'DHCP option 66/67 tie-in', desc: 'Cross-referencing which TFTP server address a host received via DHCP (option 66 server name / 67 boot filename) confirms whether a given TFTP session was part of an expected PXE boot flow.' },
    ],
    relatedPorts: ['udp-67'], attackTechniques: ['T1602.002'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 1350 — The TFTP Protocol (Revision 2)', url: 'https://www.rfc-editor.org/rfc/rfc1350.html' },
    ],
  },
  {
    slug: 'udp-123', port: 123, protocol: 'udp', name: 'NTP (Network Time Protocol)', category: 'Network Infrastructure', confidence: 'iana-registered',
    what: 'The port NTP servers and clients use to exchange time-synchronization messages, keeping system clocks aligned across a network. NTP is fundamentally UDP-based per its governing RFC; IANA also carries a rarely-used TCP registration for the same service name, but essentially all real-world NTP traffic is UDP.',
    why: "Beyond keeping clocks accurate (itself forensically important — skewed clocks break log/timeline correlation across a case), older NTP daemons exposed a 'monlist' command that returned the last several hundred peers a server had talked to in a single small request, giving attackers a massive traffic-amplification factor for reflected DDoS attacks against a spoofed victim IP. An internet-facing NTP server should be checked for this legacy behavior during any infrastructure review.",
    commonTriggers: 'Legitimately: routine time-sync polling between clients and configured NTP servers/pools. Anomalously/maliciously: a burst of small inbound UDP/123 requests followed by large outbound responses to a third-party IP (classic reflection/amplification abuse of an exposed server), or monlist-style queries probing for the vulnerable behavior.',
    indicators: [
      { name: 'monlist query/response', desc: "An NTP server responding to REQ_MON_GETLIST/'monlist' style control-mode queries confirms it's running an outdated build vulnerable to CVE-2013-5211 amplification abuse and should be patched or have that mode disabled." },
      { name: 'Disproportionate response-to-request size', desc: 'Outbound UDP/123 traffic dramatically larger than the corresponding inbound requests, directed at a single external target, is the signature of a server being used as a reflector in an active DDoS attack.' },
    ],
    relatedPorts: [], attackTechniques: ['T1498.002'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 5905 — Network Time Protocol Version 4', url: 'https://www.rfc-editor.org/rfc/rfc5905.html' },
      { name: 'CISA — NTP Amplification Attacks Using CVE-2013-5211', url: 'https://www.cisa.gov/news-events/alerts/2014/01/13/ntp-amplification-attacks-using-cve-2013-5211' },
    ],
  },
  {
    slug: 'tcp-179', port: 179, protocol: 'tcp', name: 'BGP (Border Gateway Protocol)', category: 'Network Infrastructure', confidence: 'iana-registered',
    what: "The port BGP routers (typically ISP/carrier and large enterprise edge routers) use to establish TCP peering sessions and exchange routing information between autonomous systems. IANA's registry additionally lists UDP and SCTP entries for the 'bgp' service name, but the protocol itself is defined and overwhelmingly deployed over TCP, which BGP relies on for reliable, ordered delivery of routing updates.",
    why: "BGP is almost never seen in a typical enterprise DFIR engagement — it belongs to ISPs, cloud providers, and organizations running their own autonomous systems — but where it is present, an unauthorized or misconfigured peering session is how route hijacking happens: an attacker who can establish or manipulate a BGP session can announce more-specific routes that redirect victim traffic through attacker-controlled infrastructure for interception. Its scope in this reference is narrow but significant for network/infrastructure-focused investigations.",
    commonTriggers: 'Legitimately: a small, explicitly configured set of peer routers exchanging routing updates at the network edge. Anomalously/maliciously: a BGP session negotiation from an unrecognized peer IP, or route announcements inconsistent with the organization\'s actual address allocations (a hallmark of route hijacking).',
    indicators: [], relatedPorts: [], attackTechniques: [],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 4271 — A Border Gateway Protocol 4 (BGP-4)', url: 'https://www.rfc-editor.org/rfc/rfc4271.html' },
    ],
  },
  {
    slug: 'udp-500', port: 500, protocol: 'udp', name: 'IKE / ISAKMP (IPsec Key Exchange)', category: 'Network Infrastructure', confidence: 'iana-registered',
    what: 'The port used by IKE (Internet Key Exchange, built on the ISAKMP framework) to negotiate and establish the Security Associations that IPsec VPNs use to authenticate peers and derive encryption keys — the control-plane handshake that happens before any encrypted ESP traffic flows. IANA also lists a TCP registration for the same service name, reflecting a documented (though far less common) fallback: RFC 8229/9329 define encapsulating IKE and IPsec entirely inside a single TCP connection when UDP negotiation isn\'t possible.',
    why: "IKE/IPsec endpoints are exactly the kind of internet-facing 'front door' that shows up in external attack-surface reviews — VPN gateways are a well-established initial-access vector, and a DFIR analyst investigating a network intrusion should always confirm whether the organization has a site-to-site or remote-access IPsec VPN and whether its gateway has been patched for known IKE-implementation vulnerabilities. Because IKE negotiates the very keys that make subsequent traffic opaque, this handshake is also one of the few places metadata (peer identities, proposed algorithms) is visible at all to network monitoring.",
    commonTriggers: 'Legitimately: site-to-site VPN tunnels and remote-access VPN clients establishing or rekeying IPsec Security Associations with a known peer/gateway. Anomalously/maliciously: IKE negotiation attempts from unrecognized source IPs against an internet-facing VPN gateway, or repeated failed negotiations consistent with scanning/fingerprinting the IKE implementation and version.',
    indicators: [], relatedPorts: ['udp-4500', 'udp-1701', 'tcp-1723'], attackTechniques: ['T1133'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 7296 — Internet Key Exchange Protocol Version 2 (IKEv2)', url: 'https://www.rfc-editor.org/rfc/rfc7296.html' },
    ],
  },
  {
    slug: 'udp-4500', port: 4500, protocol: 'udp', name: 'IPsec NAT-Traversal (NAT-T)', category: 'Network Infrastructure', confidence: 'iana-registered',
    what: "The port IKE/IPsec peers switch to when a NAT device is detected between them, encapsulating both the IKE negotiation and the resulting ESP-protected traffic inside UDP so it can survive NAT translation (plain ESP has no port number for NAT to rewrite, which otherwise breaks it). IANA lists both a TCP and UDP registration for 'ipsec-nat-t' on 4500, but the mechanism it names — UDP encapsulation to solve the NAT/ESP incompatibility — is inherently UDP-based per RFC 3948/RFC 7296.",
    why: 'Seeing 4500 alongside 500 is the normal signature of a remote-access or site-to-site IPsec VPN traversing NAT, which is the common case for most road-warrior and cloud-to-cloud VPN setups — so the same DFIR relevance as port 500 applies (VPN gateways as an initial-access surface), and an analyst should expect 4500 rather than raw ESP (IP protocol 50) whenever a NAT boundary is involved.',
    commonTriggers: 'Legitimately: any IPsec VPN peer pair where one or both sides sit behind NAT, continuing negotiation and then carrying encapsulated ESP traffic over 4500 for the life of the tunnel. Anomalously/maliciously: unexpected 4500 traffic to/from a host that shouldn\'t be operating as a VPN endpoint, which can indicate an unauthorized tunnel or a compromised gateway being used to exfiltrate data inside what looks like routine VPN traffic.',
    indicators: [], relatedPorts: ['udp-500'], attackTechniques: ['T1133'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 3948 — UDP Encapsulation of IPsec ESP Packets', url: 'https://www.rfc-editor.org/rfc/rfc3948.html' },
    ],
  },
  {
    slug: 'udp-1701', port: 1701, protocol: 'udp', name: 'L2TP (Layer 2 Tunneling Protocol)', category: 'Network Infrastructure', confidence: 'iana-registered',
    what: "The port L2TP uses to tunnel PPP frames between a client and server, most commonly paired with IPsec for encryption (L2TP/IPsec) since L2TP itself provides no confidentiality. IANA lists both TCP and UDP registrations for 'l2tp' on 1701, but the protocol as deployed (and as most operating systems' built-in VPN clients implement it) runs over UDP.",
    why: "L2TP/IPsec is one of the legacy 'built into every OS' VPN protocol options, which means it still turns up in DFIR work even though it's not the modern recommendation — and because it depends on IPsec (ports 500/4500) for its actual security, an L2TP tunnel with a weak or well-known pre-shared IPsec key is a well-documented weak point that effectively removes the protocol's confidentiality. As with other tunneling protocols, it's also something an insider or attacker could stand up to move data out through what looks like normal VPN infrastructure.",
    commonTriggers: 'Legitimately: remote-access or site-to-site VPN connections using the OS-native L2TP/IPsec client against a known VPN gateway. Anomalously/maliciously: L2TP traffic to/from a host not provisioned as a VPN endpoint, or authentication against a gateway known to use a weak/default IPsec pre-shared key.',
    indicators: [], relatedPorts: ['udp-500', 'udp-4500', 'tcp-1723'], attackTechniques: ['T1572', 'T1133'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 2661 — Layer Two Tunneling Protocol "L2TP"', url: 'https://www.rfc-editor.org/rfc/rfc2661.html' },
    ],
  },
  {
    slug: 'tcp-1723', port: 1723, protocol: 'tcp', name: 'PPTP (Point-to-Point Tunneling Protocol)', category: 'Network Infrastructure', confidence: 'iana-registered',
    what: "The port PPTP uses for its control connection, which negotiates and manages the tunnel; the actual tunneled PPP data travels separately over GRE (IP protocol 47), not over 1723 itself, so a firewall blocking only TCP 1723 doesn't fully stop a PPTP tunnel, and an analyst investigating one needs to look at GRE traffic between the same two hosts as well.",
    why: "PPTP's authentication (MS-CHAPv2) and encryption (MPPE) have been publicly, comprehensively broken for years, to the point that captured MS-CHAPv2 handshakes can be cracked essentially on demand — so PPTP still in use anywhere is itself a finding, not just a normal VPN protocol to note in passing. Seeing 1723 in traffic or firewall logs should prompt checking whether it's legacy infrastructure nobody decommissioned, since its cryptography no longer provides meaningful confidentiality against a capable attacker.",
    commonTriggers: 'Legitimately: legacy VPN clients (largely deprecated in modern OSes) connecting to an old PPTP VPN server. Anomalously/maliciously: PPTP traffic on infrastructure believed to have been decommissioned, or a threat actor leveraging a still-exposed legacy PPTP service as an easy initial-access foothold given its broken cryptography.',
    indicators: [], relatedPorts: ['udp-1701'], attackTechniques: ['T1572', 'T1133'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 2637 — Point-to-Point Tunneling Protocol (PPTP)', url: 'https://www.rfc-editor.org/rfc/rfc2637.html' },
    ],
  },
  {
    slug: 'port-5060', port: 5060, protocol: 'tcp/udp', name: 'SIP (Session Initiation Protocol)', category: 'Network Infrastructure', confidence: 'iana-registered',
    what: "The signaling port for SIP, the protocol that sets up, modifies, and tears down VoIP calls and other real-time sessions (the actual voice/media then flows separately over RTP on a negotiated port range). IANA registers 5060 to SIP for TCP, UDP, and SCTP alike — it's a genuinely dual/multi-transport service, with UDP historically the most common default for signaling and TCP used especially where SIP-over-TLS (SIPS, typically port 5061) or larger message sizes are involved.",
    why: "Internet-facing SIP endpoints (PBXs, SIP trunks, softphone servers) are relentlessly scanned for weak extension credentials, and a compromised SIP account is directly monetizable through International Revenue Share Fraud / toll fraud — attackers place expensive international calls through the victim's trunk and profit from termination fees, often running up massive bills before anyone notices. It's a financially-motivated attack pattern that's easy to overlook if a DFIR analyst is focused only on data-centric threats.",
    commonTriggers: 'Legitimately: SIP trunk registration/signaling between a PBX and carrier, or softphone/handset registration to an internal call server. Anomalously/maliciously: high-volume REGISTER/INVITE scanning against a range of extensions (SIPVicious-style enumeration), or a sudden spike in outbound international call attempts consistent with toll fraud following a compromised extension.',
    indicators: [
      { name: 'SIPVicious-style enumeration', desc: 'A rapid sequence of REGISTER or OPTIONS requests probing sequential extension numbers is the signature of automated SIP account enumeration tools.' },
      { name: 'Off-hours international call spike', desc: 'A burst of outbound calls to unusual international destinations, especially outside business hours, is the practical, financially visible indicator of successful toll fraud via a compromised SIP account.' },
    ],
    relatedPorts: [], attackTechniques: ['T1046'],
    references: [
      { name: 'IANA Service Name and Transport Protocol Port Number Registry', url: 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml' },
      { name: 'RFC 3261 — SIP: Session Initiation Protocol', url: 'https://www.rfc-editor.org/rfc/rfc3261.html' },
    ],
  },
  {
    slug: 'tcp-4444', port: 4444, protocol: 'tcp', name: 'Metasploit Framework default handler', category: 'Malware & C2 (DFIR-Notable)', confidence: 'historical-documented',
    what: "4444 is the long-standing conventional default LPORT for Metasploit's exploit/multi/handler and for reverse_tcp-family payloads (including Meterpreter) — not a port Metasploit invented or was assigned specifically for this purpose (IANA does register TCP/UDP 4444 to a legacy, largely disused service, krb524, the Kerberos v5-to-v4 ticket translator, unrelated to Metasploit), just the value Metasploit and its documentation have used as the out-of-the-box example for years, to the point that SANS Internet Storm Center's own port reference explicitly labels 4444 as the 'Metasploit default listener.' It is trivially changed with a single LPORT option, and penetration testers and red teams routinely do.",
    why: "Seeing a host make an outbound connection to 4444, or a host on the network start listening on 4444, is a well-known heuristic for 'possible Metasploit/Meterpreter reverse-shell callback' — one of the single most common payload delivery mechanisms in both legitimate penetration tests and real intrusions, since it's the path of least resistance for turning an initial exploit into interactive access. Treat 4444 strictly as a lead: real attackers (and testers) frequently pick a different, less conspicuous LPORT specifically because 4444 is so widely fingerprinted and blocklisted.",
    commonTriggers: 'Legitimately/expected: virtually never outside an authorized, scoped penetration test or red-team engagement, where the tester should have pre-notified the blue team. A red flag in essentially every other context: any unexpected outbound connection to 4444 from an internal host, or an internal host suddenly listening on 4444, warrants immediate triage as a possible reverse-shell callback.',
    indicators: [
      { name: 'Outbound beacon to 4444', desc: 'A host initiating a new outbound TCP connection to port 4444 on an external or unfamiliar IP, especially shortly after suspicious process activity, matches the classic Meterpreter reverse_tcp callback pattern.' },
      { name: 'Process spawned by the connecting parent', desc: 'Correlating the process that opened the 4444 connection (e.g. a script interpreter or an exploited service process) against expected baseline behavior helps confirm whether this is a legitimate test or unauthorized access.' },
    ],
    relatedPorts: [], attackTechniques: ['T1571'],
    references: [
      { name: 'SANS Internet Storm Center — Port 4444 (tcp/udp) Attack Activity', url: 'https://isc.sans.edu/data/port/4444' },
      { name: 'Offensive Security — Metasploit Unleashed: Binary Payloads', url: 'https://www.offsec.com/metasploit-unleashed/binary-payloads/' },
    ],
  },
  {
    slug: 'udp-31337', port: 31337, protocol: 'udp', name: 'Back Orifice (historical)', category: 'Malware & C2 (DFIR-Notable)', confidence: 'historical-documented',
    what: "31337 — read as 'eleet'/'elite' in leetspeak — is the historically documented default UDP port for the original Back Orifice, the remote-administration-tool-turned-Windows-backdoor released by the Cult of the Dead Cow in 1998, one of the most widely publicized early Remote Access Trojans; it communicated over UDP by default (its 2000 successor, BO2K, switched to TCP 54320/UDP 54321). Trend Micro's own trojan-port reference table lists 31337 against Back Orifice by name, and SANS Internet Storm Center covered the port's history and significance in a dedicated Cyber Security Awareness Month write-up.",
    why: "Back Orifice itself is effectively extinct in modern intrusions, but 31337 persists as a widely recognized 'known-bad' port baked into countless IDS signatures, blocklists, and port-reference tables precisely because of this history — and the number's cultural cachet ('leet') means it, and its shorter sibling 1337, still get reused informally by other ad hoc backdoors and CTF/training exploits today. A DFIR analyst finding 31337 in traffic should treat it as a strong pivot point worth investigating, not proof of an actual Back Orifice infection — the port is trivially reconfigurable and any tool can bind to it.",
    commonTriggers: 'Legitimate use: essentially none in a modern enterprise — no mainstream software defaults to 31337. A red flag by default: any listener or outbound connection on 31337 warrants investigation as a potential backdoor, historically Back Orifice specifically but plausibly any tool intentionally choosing the port for its notoriety.',
    indicators: [], relatedPorts: ['tcp-12345', 'tcp-1337'], attackTechniques: ['T1571'],
    references: [
      { name: 'SANS Internet Storm Center — Cyber Security Awareness Month, Day 5: Port 31337', url: 'https://isc.sans.edu/diary/7273' },
      { name: 'Trend Micro — What Are Trojan Ports? (reference table)', url: 'https://docs.trendmicro.com/all/ent/officescan/v10.5/en-us/osce_10.5_olhcl/osce_topics/what_are_trojan_ports_.htm' },
    ],
  },
  {
    slug: 'tcp-12345', port: 12345, protocol: 'tcp', name: 'NetBus (historical)', category: 'Malware & C2 (DFIR-Notable)', confidence: 'historical-documented',
    what: '12345 (often paired with 12346) is the historically documented default listening port for NetBus, a graphical Windows remote-access trojan written by Carl-Fredrik Neikter and released around 1998 — a close contemporary of Back Orifice with similar remote-control capability (file access, registry manipulation, process control). Malaysia\'s national CERT (MyCERT) and Juniper Networks\' threat-signature database both document the 12345/12346 default.',
    why: "Like Back Orifice, NetBus itself is a relic of late-1990s Windows malware and not something a modern DFIR engagement expects to find live, but 12345 remains a fixture in legacy IDS signatures and historical port references specifically because of this association — a low-effort, high-value pattern-match for older detection content that may still be running in an environment. As with every port in this category, treat it as a lead to investigate (what's actually listening, and why) rather than an automatic conclusion that NetBus specifically is present.",
    commonTriggers: 'Legitimate use: essentially none in a modern enterprise. A red flag by default: any unexpected listener or connection on 12345 (particularly paired with matching activity on 12346) warrants investigation as a potential legacy-style backdoor.',
    indicators: [], relatedPorts: ['udp-31337'], attackTechniques: ['T1571'],
    references: [
      { name: 'MyCERT Advisory — NetBus', url: 'https://www.mycert.org.my/portal/advisory?id=MA-007.031999' },
      { name: 'Juniper Networks Threat Labs — TROJAN:NETBUS:SERVER-RES-12345', url: 'https://www.juniper.net/us/en/threatlabs/ips-signatures/detail.TROJAN:NETBUS:SERVER-RES-12345.html' },
    ],
  },
  {
    slug: 'tcp-1337', port: 1337, protocol: 'tcp', name: '"Leet" port (generic backdoor/CTF culture)', category: 'Malware & C2 (DFIR-Notable)', confidence: 'historical-documented',
    what: "1337 — leetspeak for 'elite,' the same wordplay behind 31337 — is IANA-registered for an unrelated legitimate service (menandmice-dns, the Men & Mice DNS Server Controller protocol) and has no single dominant malware family, but it does have a genuine documented history: SANS Internet Storm Center's own port reference lists both that legitimate menandmice-dns registration and the historical Shadyshell trojan against TCP 1337 (with the original Shadyshell source archived on Packet Storm), and the number's hacker-culture cachet has made it a recurring, informal choice for CTF challenges, bind-shell exercises, and various ad hoc backdoors ever since.",
    why: "Unlike 31337 or 12345, 1337 isn't tied to one well-documented historical trojan family — its DFIR value is almost entirely about the port number's cultural significance making it a disproportionately popular arbitrary choice for exactly the kind of informal, hand-rolled bind/reverse shell an attacker (or a penetration tester) sets up on the fly. Treat any listener or connection on 1337 as exactly what this whole category is about: a pivot point worth investigating, never a confirmed finding on its own — legitimate menandmice-dns and CTF/training infrastructure also use this port, so context matters enormously.",
    commonTriggers: "Legitimate use: the registered menandmice-dns service, CTF competition infrastructure, security training labs, and some developer tools/games that lean into the 'leet' naming for fun. A red flag in a production environment with no menandmice deployment: any unexpected listener or outbound connection on 1337 warrants the same triage as any other unfamiliar open port or callback.",
    indicators: [], relatedPorts: ['udp-31337'], attackTechniques: ['T1571'],
    references: [
      { name: 'SANS Internet Storm Center — Port 1337 (tcp/udp) reference data', url: 'https://isc.sans.edu/data/port.html?port=1337' },
      { name: 'Packet Storm — shadyshell.c source', url: 'https://packetstormsecurity.com/files/21978/shadyshell.c.html' },
    ],
  },
  {
    slug: 'tcp-6667', port: 6667, protocol: 'tcp', name: 'IRC (historical botnet C2 channel)', category: 'Malware & C2 (DFIR-Notable)', confidence: 'historical-documented',
    what: "6667 is the conventional default port for IRC (Internet Relay Chat) — a legitimate, decades-old chat protocol in its own right — that became, through the 2000s in particular, one of the most common command-and-control channels for botnets. Malware families like Agobot/Phatbot and Kaiten/Tsunami connected outbound to an attacker-run IRC server/channel to receive commands, a pattern SANS Internet Storm Center documented in a dedicated write-up on whether IRC traffic 'is evil,' and which the nmap project still ships a dedicated NSE script (irc-botnet-channels) to help detect.",
    why: "Unlike the other entries in this category, 6667 is IRC's genuine standard port rather than an arbitrarily chosen one — which means the relevant DFIR judgment call isn't 'is this port suspicious' so much as 'does this environment have any legitimate reason to run IRC at all.' Because modern botnets have largely shifted to HTTP(S)/DNS-based C2 to blend into normal traffic, unexpected outbound 6667 traffic from a workstation or server (as opposed to a dedicated, sanctioned chat client) is a comparatively high-confidence signal worth investigating, even though the technique itself is dated.",
    commonTriggers: 'Legitimate use: sanctioned IRC clients on hosts where chat is an approved business tool (increasingly rare in modern enterprises). A red flag: outbound 6667 connections from servers, workstations without an approved IRC client, or any host exhibiting other signs of compromise, especially with periodic beacon-like reconnection behavior.',
    indicators: [], relatedPorts: [], attackTechniques: ['T1071'],
    references: [
      { name: 'SANS Internet Storm Center — Cyber Security Awareness Month, Day 7: Port 6667/8/9/7000 — IRC: is it evil?', url: 'https://isc.sans.edu/diary/Cyber+Security+Awareness+Month+-+Day+7+-+Port+6667897000+-+IRC+is+it+evil/7285' },
      { name: 'Nmap Scripting Engine — irc-botnet-channels', url: 'https://nmap.org/nsedoc/scripts/irc-botnet-channels.html' },
    ],
  },
  {
    slug: 'tcp-9001', port: 9001, protocol: 'tcp', name: 'Tor ORPort (relay traffic)', category: 'Malware & C2 (DFIR-Notable)', confidence: 'historical-documented',
    what: "9001 is the port the Tor Project's own sample relay configuration (torrc.sample.in) and relay-setup documentation use for the ORPort — the port a Tor relay listens on to carry onion-routed traffic between other relays in the network. It's a documented convention rather than a hardcoded requirement; a relay operator can bind ORPort to any port (443 is also commonly recommended precisely because it blends in on restrictive networks), so 9001 specifically is a strong lead, not a guarantee, when triaging Tor-related traffic.",
    why: "Tor is legitimate anonymity software, but it's also a well-documented technique adversaries use to route C2 traffic through a multi-hop encrypted network that's very difficult to trace back to its source (MITRE ATT&CK's own Multi-hop Proxy technique names Tor explicitly). Seeing a host establish connections consistent with Tor relay/client traffic on an internal server with no legitimate reason to run Tor is worth flagging, both as possible C2 channeling and as a policy violation in most enterprise environments.",
    commonTriggers: 'Legitimate use: an intentionally operated Tor relay/bridge (rare and normally an explicit, known decision in an enterprise) or a user running the Tor Browser for legitimate privacy reasons per policy. Anomalously/maliciously: a server or unexpected workstation exhibiting Tor-consistent connection patterns with no sanctioned business reason, particularly alongside other signs of compromise.',
    indicators: [], relatedPorts: ['tcp-9030'], attackTechniques: ['T1090.003'],
    references: [
      { name: 'The Tor Project — sample torrc (ORPort/DirPort defaults)', url: 'https://gitlab.torproject.org/tpo/core/tor/-/blob/HEAD/src/config/torrc.sample.in' },
      { name: 'The Tor Project — Relay Setup (Technical Setup)', url: 'https://community.torproject.org/relay/setup/' },
    ],
  },
  {
    slug: 'tcp-9030', port: 9030, protocol: 'tcp', name: 'Tor DirPort (directory service)', category: 'Malware & C2 (DFIR-Notable)', confidence: 'historical-documented',
    what: "9030 is the port the Tor Project's own sample relay configuration documents for the optional DirPort, which serves network directory information (the list of known relays and their status) to clients and other relays. Not every relay runs a DirPort — it's an optional role on top of the mandatory ORPort — and like 9001 it's a documented convention rather than an enforced default.",
    why: "The DFIR relevance mirrors port 9001: legitimate directory-authority/relay infrastructure exists, but the same Tor network is a documented technique for anonymizing C2 infrastructure and exfiltration destinations. 9030 specifically is a useful corroborating signal alongside 9001 — a host talking to both is more consistent with genuine Tor relay operation than a single ambiguous connection would be.",
    commonTriggers: 'Legitimate use: a host explicitly configured as a Tor relay with directory mirroring enabled. Anomalously/maliciously: unexpected 9030 traffic on a host with no sanctioned Tor role, especially paired with 9001 activity on the same host.',
    indicators: [], relatedPorts: ['tcp-9001'], attackTechniques: ['T1090.003'],
    references: [
      { name: 'The Tor Project — sample torrc (ORPort/DirPort defaults)', url: 'https://gitlab.torproject.org/tpo/core/tor/-/blob/HEAD/src/config/torrc.sample.in' },
      { name: 'The Tor Project — Relay Setup (Technical Setup)', url: 'https://community.torproject.org/relay/setup/' },
    ],
  },
];

export const NETWORK_PORTS: NetworkPortEntry[] = RAW_ENTRIES.map((e) => ({ ...e, rangeType: rangeTypeFor(e.port) }));

export const networkPortBySlug = (slug: string): NetworkPortEntry | undefined =>
  NETWORK_PORTS.find((p) => p.slug === slug);
