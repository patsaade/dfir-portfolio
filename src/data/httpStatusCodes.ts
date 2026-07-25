// HTTP Status Code Reference — every currently-assigned code in IANA's
// "Hypertext Transfer Protocol (HTTP) Status Code Registry", grouped by class.
// Reason phrases and definitions are verified against RFC 9110 (HTTP
// Semantics, June 2022 — obsoletes RFC 7231 and is the current core spec) for
// the codes it defines, and against each code's own registering RFC for the
// rest (WebDAV's RFC 4918/RFC 5842, and the smaller extension RFCs below).
// Re-verify against the live registry if it ever adds an entry:
//   https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
//
// Deliberately excludes:
//  - Every "Unassigned" range in the registry (105-199, 209-225, 227-299,
//    309-399, 419-420, 427, 430, 432-450, 452-499, 509, 512-599) — there's
//    nothing to document.
//  - 104 "Upload Resumption Supported (TEMPORARY)" — registered against an
//    active IETF draft (draft-ietf-httpbis-resumable-upload), not a
//    published RFC, so its phrase/semantics can still change before this
//    page would notice. Everything else here traces to a finished RFC.
//
// 306 and 418 are real registry entries whose current phrase is literally
// "(Unused)" — both are included (marked `reserved: true`) since a reader
// who sees one in the wild should be able to look it up here too.
import type { Reference } from './references';

export type HttpStatusClass = '1xx' | '2xx' | '3xx' | '4xx' | '5xx';

// Which spec family registered the code — a genuinely useful facet distinct
// from the class grouping (a reader asking "is this a core HTTP code or a
// WebDAV extension I don't need to support?" cuts across all five classes).
type HttpStatusSpec = 'core' | 'webdav' | 'extension';

export interface HttpStatusEntry {
  code: number;
  phrase: string;
  statusClass: HttpStatusClass;
  spec: HttpStatusSpec;
  /** One-sentence (occasionally two, when a rename/history note earns its
   *  place) plain-English description of when a server returns this code. */
  description: string;
  /** True only for the registry's two literal "(Unused)" entries (306, 418) —
   *  reserved and formally excluded from use, not just rare. */
  reserved?: boolean;
  reference: Reference;
}

const RFC9110 = (section: string): Reference => ({
  name: `RFC 9110, §${section}`,
  url: `https://www.rfc-editor.org/rfc/rfc9110.html#section-${section}`,
});
const RFC = (n: number, name?: string): Reference => ({
  name: name ?? `RFC ${n}`,
  url: `https://www.rfc-editor.org/rfc/rfc${n}.html`,
});

export const HTTP_STATUS_CODES: HttpStatusEntry[] = [
  // ── 1xx Informational ────────────────────────────────────────────────
  {
    code: 100,
    phrase: 'Continue',
    statusClass: '1xx',
    spec: 'core',
    description:
      'An interim response telling the client the server has received the request headers and hasn’t rejected them yet, so the client should go ahead and send the request body (typically after the client sent an Expect: 100-continue header).',
    reference: RFC9110('15.2.1'),
  },
  {
    code: 101,
    phrase: 'Switching Protocols',
    statusClass: '1xx',
    spec: 'core',
    description:
      'The server agrees to the protocol change the client asked for in its Upgrade header — for example, upgrading a plain HTTP connection to WebSocket.',
    reference: RFC9110('15.2.2'),
  },
  {
    code: 102,
    phrase: 'Processing',
    statusClass: '1xx',
    spec: 'webdav',
    description:
      'A WebDAV extension telling the client that a long-running request is still being worked on, so the connection isn’t mistaken for having stalled. Originally defined by RFC 2518, which RFC 4918 later obsoleted.',
    reference: RFC(2518, 'RFC 2518 (obsoleted by RFC 4918)'),
  },
  {
    code: 103,
    phrase: 'Early Hints',
    statusClass: '1xx',
    spec: 'extension',
    description:
      'Sent before the final response so the client can start acting on header fields — most commonly preloading resources via a Link header — while the server is still assembling the real reply.',
    reference: RFC(8297),
  },

  // ── 2xx Success ──────────────────────────────────────────────────────
  {
    code: 200,
    phrase: 'OK',
    statusClass: '2xx',
    spec: 'core',
    description: 'The request succeeded, and the response body (if any) is the requested resource or the result of the requested action.',
    reference: RFC9110('15.3.1'),
  },
  {
    code: 201,
    phrase: 'Created',
    statusClass: '2xx',
    spec: 'core',
    description: 'The request succeeded and resulted in one or more new resources being created, usually with a Location header pointing at (one of) the new resource(s).',
    reference: RFC9110('15.3.2'),
  },
  {
    code: 202,
    phrase: 'Accepted',
    statusClass: '2xx',
    spec: 'core',
    description: 'The request has been accepted for processing, but the processing hasn’t completed — and, unlike 200, isn’t guaranteed to eventually succeed.',
    reference: RFC9110('15.3.3'),
  },
  {
    code: 203,
    phrase: 'Non-Authoritative Information',
    statusClass: '2xx',
    spec: 'core',
    description: 'The request succeeded, but the payload was modified in transit by an intermediary (a transforming proxy) rather than delivered exactly as the origin server sent it.',
    reference: RFC9110('15.3.4'),
  },
  {
    code: 204,
    phrase: 'No Content',
    statusClass: '2xx',
    spec: 'core',
    description: 'The request succeeded and there’s deliberately no body to send back — common for a successful DELETE, or a form submission that shouldn’t navigate the client anywhere.',
    reference: RFC9110('15.3.5'),
  },
  {
    code: 205,
    phrase: 'Reset Content',
    statusClass: '2xx',
    spec: 'core',
    description: 'The request succeeded and the server wants the user agent to reset the view that submitted it (e.g. clear a form) rather than navigate away.',
    reference: RFC9110('15.3.6'),
  },
  {
    code: 206,
    phrase: 'Partial Content',
    statusClass: '2xx',
    spec: 'core',
    description: 'The server is fulfilling a range request — returning only the requested byte range of the resource (as named in the client’s Range header) rather than the whole thing.',
    reference: RFC9110('15.3.7'),
  },
  {
    code: 207,
    phrase: 'Multi-Status',
    statusClass: '2xx',
    spec: 'webdav',
    description: 'A WebDAV response covering multiple resources from a single request, where the body itself lists a separate status for each resource instead of one status for the whole request.',
    reference: RFC(4918),
  },
  {
    code: 208,
    phrase: 'Already Reported',
    statusClass: '2xx',
    spec: 'webdav',
    description: 'Used inside a WebDAV multi-status response to avoid re-listing the members of a collection that a previous binding in that same response already enumerated.',
    reference: RFC(5842),
  },
  {
    code: 226,
    phrase: 'IM Used',
    statusClass: '2xx',
    spec: 'extension',
    description: 'The server fulfilled a GET request by applying one or more “instance manipulations” (such as a delta/diff encoding) to the resource, and the response is the result of those manipulations rather than the full representation.',
    reference: RFC(3229),
  },

  // ── 3xx Redirection ──────────────────────────────────────────────────
  {
    code: 300,
    phrase: 'Multiple Choices',
    statusClass: '3xx',
    spec: 'core',
    description: 'The target resource has more than one representation, and the response lets the client (or user) choose a preferred one rather than the server picking automatically.',
    reference: RFC9110('15.4.1'),
  },
  {
    code: 301,
    phrase: 'Moved Permanently',
    statusClass: '3xx',
    spec: 'core',
    description: 'The resource has permanently moved to a new URI, and future requests should go straight to the URI given in the response’s Location header.',
    reference: RFC9110('15.4.2'),
  },
  {
    code: 302,
    phrase: 'Found',
    statusClass: '3xx',
    spec: 'core',
    description: 'The resource is temporarily available at a different URI, but the client should keep using the original request URI for future requests.',
    reference: RFC9110('15.4.3'),
  },
  {
    code: 303,
    phrase: 'See Other',
    statusClass: '3xx',
    spec: 'core',
    description: 'Directs the client to fetch a different resource, normally with a GET, as the result of the request — the standard way to redirect after a POST so a page refresh doesn’t resubmit the form.',
    reference: RFC9110('15.4.4'),
  },
  {
    code: 304,
    phrase: 'Not Modified',
    statusClass: '3xx',
    spec: 'core',
    description: 'A conditional GET request (one carrying an If-Modified-Since/If-None-Match header) found the resource unchanged, so the client’s cached copy is still valid and doesn’t need to be re-downloaded.',
    reference: RFC9110('15.4.5'),
  },
  {
    code: 305,
    phrase: 'Use Proxy',
    statusClass: '3xx',
    spec: 'core',
    description: 'Deprecated: told the client it had to access the requested resource only through the proxy given in the response’s Location header.',
    reference: RFC9110('15.4.6'),
  },
  {
    code: 306,
    phrase: '(Unused)',
    statusClass: '3xx',
    spec: 'core',
    reserved: true,
    description: 'Reserved — the current spec states it must not be used by implementations. An expired 1996 HTTP/1.1 draft had assigned it to a proxy-redirection scheme nicknamed “Switch Proxy,” which was never standardized and was dropped over security concerns.',
    reference: RFC9110('15.4.7'),
  },
  {
    code: 307,
    phrase: 'Temporary Redirect',
    statusClass: '3xx',
    spec: 'core',
    description: 'Like 302, the resource is temporarily at a different URI, but unlike 302 the client must repeat the request with the exact same method and body it originally used.',
    reference: RFC9110('15.4.8'),
  },
  {
    code: 308,
    phrase: 'Permanent Redirect',
    statusClass: '3xx',
    spec: 'core',
    description: 'Like 301, the resource has permanently moved, but unlike 301 the client must repeat the request with the exact same method and body it originally used.',
    reference: RFC9110('15.4.9'),
  },

  // ── 4xx Client Error ─────────────────────────────────────────────────
  {
    code: 400,
    phrase: 'Bad Request',
    statusClass: '4xx',
    spec: 'core',
    description: 'The server can’t or won’t process the request because of something it perceives as a client-side problem — malformed syntax, invalid request framing, or similar — without a more specific 4xx code fitting better.',
    reference: RFC9110('15.5.1'),
  },
  {
    code: 401,
    phrase: 'Unauthorized',
    statusClass: '4xx',
    spec: 'core',
    description: 'The request lacks valid authentication credentials for the target resource; the response’s WWW-Authenticate header tells the client how to authenticate.',
    reference: RFC9110('15.5.2'),
  },
  {
    code: 402,
    phrase: 'Payment Required',
    statusClass: '4xx',
    spec: 'core',
    description: 'Reserved for future use, for a request that has not been applied because payment is required and the client hasn’t made payment — the spec keeps the code number set aside, but no standardized payment scheme has ever been built on top of it.',
    reference: RFC9110('15.5.3'),
  },
  {
    code: 403,
    phrase: 'Forbidden',
    statusClass: '4xx',
    spec: 'core',
    description: 'The server understood the request and refuses to fulfill it — unlike 401, authenticating (again) won’t help; the client simply lacks permission for this resource.',
    reference: RFC9110('15.5.4'),
  },
  {
    code: 404,
    phrase: 'Not Found',
    statusClass: '4xx',
    spec: 'core',
    description: 'The origin server has no current representation for the target resource, and deliberately isn’t saying whether that’s temporary or permanent.',
    reference: RFC9110('15.5.5'),
  },
  {
    code: 405,
    phrase: 'Method Not Allowed',
    statusClass: '4xx',
    spec: 'core',
    description: 'The request’s HTTP method is known to the server but isn’t supported by this particular target resource; the response’s Allow header lists which methods are.',
    reference: RFC9110('15.5.6'),
  },
  {
    code: 406,
    phrase: 'Not Acceptable',
    statusClass: '4xx',
    spec: 'core',
    description: 'The target resource has no representation that would be acceptable given the Accept-family headers the client sent.',
    reference: RFC9110('15.5.7'),
  },
  {
    code: 407,
    phrase: 'Proxy Authentication Required',
    statusClass: '4xx',
    spec: 'core',
    description: 'The same idea as 401, but the client needs to authenticate to a proxy in the request path before that proxy will forward the request onward.',
    reference: RFC9110('15.5.8'),
  },
  {
    code: 408,
    phrase: 'Request Timeout',
    statusClass: '4xx',
    spec: 'core',
    description: 'The server closed the connection because the client didn’t send a complete request within the time the server was prepared to wait.',
    reference: RFC9110('15.5.9'),
  },
  {
    code: 409,
    phrase: 'Conflict',
    statusClass: '4xx',
    spec: 'core',
    description: 'The request conflicts with the current state of the target resource — for example, two concurrent edits to the same resource colliding.',
    reference: RFC9110('15.5.10'),
  },
  {
    code: 410,
    phrase: 'Gone',
    statusClass: '4xx',
    spec: 'core',
    description: 'The target resource used to exist here but is no longer available, and this condition is believed to be permanent — a deliberately stronger statement than a plain 404.',
    reference: RFC9110('15.5.11'),
  },
  {
    code: 411,
    phrase: 'Length Required',
    statusClass: '4xx',
    spec: 'core',
    description: 'The server refuses to accept the request because it was sent without a defined Content-Length.',
    reference: RFC9110('15.5.12'),
  },
  {
    code: 412,
    phrase: 'Precondition Failed',
    statusClass: '4xx',
    spec: 'core',
    description: 'One or more conditional request headers (such as If-Match or If-Unmodified-Since) evaluated to false when tested against the resource’s current state.',
    reference: RFC9110('15.5.13'),
  },
  {
    code: 413,
    phrase: 'Content Too Large',
    statusClass: '4xx',
    spec: 'core',
    description: 'The server refuses to process the request because its content is larger than the server is willing or able to handle. RFC 9110 renamed this from the older “Payload Too Large” phrase, which is still what many implementations display.',
    reference: RFC9110('15.5.14'),
  },
  {
    code: 414,
    phrase: 'URI Too Long',
    statusClass: '4xx',
    spec: 'core',
    description: 'The server refuses to process the request because the target resource’s URI is longer than the server is willing to interpret.',
    reference: RFC9110('15.5.15'),
  },
  {
    code: 415,
    phrase: 'Unsupported Media Type',
    statusClass: '4xx',
    spec: 'core',
    description: 'The origin server refuses to service the request because the request content’s format isn’t supported by this method on this resource.',
    reference: RFC9110('15.5.16'),
  },
  {
    code: 416,
    phrase: 'Range Not Satisfiable',
    statusClass: '4xx',
    spec: 'core',
    description: 'The set of ranges given in the request’s Range header can’t be satisfied against the target resource’s actual content.',
    reference: RFC9110('15.5.17'),
  },
  {
    code: 417,
    phrase: 'Expectation Failed',
    statusClass: '4xx',
    spec: 'core',
    description: 'The expectation stated in the request’s Expect header field couldn’t be met by the server (or by a proxy in the request chain).',
    reference: RFC9110('15.5.18'),
  },
  {
    code: 418,
    phrase: '(Unused)',
    statusClass: '4xx',
    spec: 'core',
    reserved: true,
    description: 'Reserved and formally unassigned. It originated as an April Fools’ joke in 1998’s RFC 2324, “Hyper Text Coffee Pot Control Protocol,” and RFC 9110 later reserved the number outright, in part because the joke had already been implemented so widely.',
    reference: RFC9110('15.5.19'),
  },
  {
    code: 421,
    phrase: 'Misdirected Request',
    statusClass: '4xx',
    spec: 'core',
    description: 'The request was directed at a server that can’t produce an authoritative response for the target URI — the code most commonly surfaces when a client reuses an HTTP/2 connection across origins (connection coalescing) and the server isn’t actually configured for the requested one.',
    reference: RFC9110('15.5.20'),
  },
  {
    code: 422,
    phrase: 'Unprocessable Content',
    statusClass: '4xx',
    spec: 'core',
    description: 'The server understands the request’s content type and syntax but can’t act on the instructions it contains — e.g. a well-formed JSON body that fails validation. Originally a WebDAV-only code named “Unprocessable Entity” (RFC 4918); RFC 9110 folded it into core HTTP semantics under this renamed phrase.',
    reference: RFC9110('15.5.21'),
  },
  {
    code: 423,
    phrase: 'Locked',
    statusClass: '4xx',
    spec: 'webdav',
    description: 'The resource being accessed is locked, and the request can’t proceed without the correct lock token.',
    reference: RFC(4918),
  },
  {
    code: 424,
    phrase: 'Failed Dependency',
    statusClass: '4xx',
    spec: 'webdav',
    description: 'The request failed because it depended on the outcome of another request within the same operation, and that other request failed first.',
    reference: RFC(4918),
  },
  {
    code: 425,
    phrase: 'Too Early',
    statusClass: '4xx',
    spec: 'extension',
    description: 'The server isn’t willing to risk processing a request that arrived as TLS 1.3 “early data” before the full handshake completed, since early data can potentially be captured and replayed by an attacker.',
    reference: RFC(8470),
  },
  {
    code: 426,
    phrase: 'Upgrade Required',
    statusClass: '4xx',
    spec: 'core',
    description: 'The server refuses to complete the request using the current protocol and requires the client to upgrade to a different one, typically paired with an Upgrade header naming the required protocol.',
    reference: RFC9110('15.5.22'),
  },
  {
    code: 428,
    phrase: 'Precondition Required',
    statusClass: '4xx',
    spec: 'extension',
    description: 'The origin server requires the request to be conditional (carry an If-Match-style header), to prevent the “lost update” problem where two clients unknowingly overwrite each other’s changes.',
    reference: RFC(6585),
  },
  {
    code: 429,
    phrase: 'Too Many Requests',
    statusClass: '4xx',
    spec: 'extension',
    description: 'The user has sent too many requests in a given amount of time — the standard status code for rate limiting.',
    reference: RFC(6585),
  },
  {
    code: 431,
    phrase: 'Request Header Fields Too Large',
    statusClass: '4xx',
    spec: 'extension',
    description: 'The server is unwilling to process the request because its header fields, individually or in total, are too large.',
    reference: RFC(6585),
  },
  {
    code: 451,
    phrase: 'Unavailable For Legal Reasons',
    statusClass: '4xx',
    spec: 'extension',
    description: 'The server is denying access to the resource as a consequence of a legal demand, such as a government-ordered takedown or censorship order.',
    reference: RFC(7725),
  },

  // ── 5xx Server Error ─────────────────────────────────────────────────
  {
    code: 500,
    phrase: 'Internal Server Error',
    statusClass: '5xx',
    spec: 'core',
    description: 'The server encountered an unexpected condition that prevented it from fulfilling the request — the generic catch-all for a server-side failure with no more specific code.',
    reference: RFC9110('15.6.1'),
  },
  {
    code: 501,
    phrase: 'Not Implemented',
    statusClass: '5xx',
    spec: 'core',
    description: 'The server doesn’t support the functionality required to fulfill the request, such as an unrecognized request method.',
    reference: RFC9110('15.6.2'),
  },
  {
    code: 502,
    phrase: 'Bad Gateway',
    statusClass: '5xx',
    spec: 'core',
    description: 'The server, while acting as a gateway or proxy, received an invalid response from an inbound server it was trying to fulfill the request through.',
    reference: RFC9110('15.6.3'),
  },
  {
    code: 503,
    phrase: 'Service Unavailable',
    statusClass: '5xx',
    spec: 'core',
    description: 'The server is currently unable to handle the request, typically due to temporary overload or maintenance — often paired with a Retry-After header.',
    reference: RFC9110('15.6.4'),
  },
  {
    code: 504,
    phrase: 'Gateway Timeout',
    statusClass: '5xx',
    spec: 'core',
    description: 'The server, while acting as a gateway or proxy, didn’t receive a timely response from an inbound server it needed to complete the request.',
    reference: RFC9110('15.6.5'),
  },
  {
    code: 505,
    phrase: 'HTTP Version Not Supported',
    statusClass: '5xx',
    spec: 'core',
    description: 'The server doesn’t support the major HTTP version that was used in the request message.',
    reference: RFC9110('15.6.6'),
  },
  {
    code: 506,
    phrase: 'Variant Also Negotiates',
    statusClass: '5xx',
    spec: 'extension',
    description: 'A server misconfiguration: the resource chosen by transparent content negotiation is itself configured to perform content negotiation, so it isn’t a valid negotiation endpoint.',
    reference: RFC(2295),
  },
  {
    code: 507,
    phrase: 'Insufficient Storage',
    statusClass: '5xx',
    spec: 'webdav',
    description: 'The server can’t complete the request because it doesn’t have enough storage space available to fulfill it.',
    reference: RFC(4918),
  },
  {
    code: 508,
    phrase: 'Loop Detected',
    statusClass: '5xx',
    spec: 'webdav',
    description: 'The server terminated the operation because it encountered an infinite loop while processing a WebDAV request with a Depth: infinity header.',
    reference: RFC(5842),
  },
  {
    code: 510,
    phrase: 'Not Extended',
    statusClass: '5xx',
    spec: 'extension',
    description: 'The policy for accessing the resource hadn’t been met by the request, and the server wanted the client to resend it with a required extension the response would describe. Defined by RFC 2774’s HTTP Extension Framework, which never saw meaningful adoption and is now Historic.',
    reference: RFC(2774),
  },
  {
    code: 511,
    phrase: 'Network Authentication Required',
    statusClass: '5xx',
    spec: 'extension',
    description: 'Sent by an intercepting proxy — the canonical example being a captive portal — to indicate the client needs to authenticate for network access before its request can go through.',
    reference: RFC(6585),
  },
];
