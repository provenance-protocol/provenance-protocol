/**
 * provenance-protocol — offline verification
 *
 * Verifies a PROVENANCE.yml declaration without contacting any service.
 * No network, no account, no API key. See SPEC.md § Signing and Verification.
 *
 *   import { verifyDeclaration } from 'provenance-protocol/verify';
 *
 *   const result = await verifyDeclaration(parsedYaml, {
 *     retrievedFrom: 'https://github.com/alice/research-assistant',
 *   });
 *
 * Declarations are YAML. Parse them with whatever library you already use and
 * pass the resulting object — this module stays dependency-free on purpose.
 *
 * Uses the Web Crypto API (crypto.subtle): all modern browsers, Node 18+.
 */

import {
  declarationSigningPayload,
  challengePayload,
  revocationPayload,
  attestationSigningPayload,
  attestationWithdrawalPayload,
  noticeSigningPayload,
} from './canonical.js';

/** Signature algorithm. Ed25519 in every spec version so far. */
const ALGORITHM = 'ed25519';

/**
 * Which spec versions this module knows how to verify a signature for, and what
 * the signature covers in each.
 *
 *   0.1 — signs "<provenance_id>:<public_key>". Proves key control under that
 *         identity. Does NOT cover the rest of the declaration: a constraint can
 *         be deleted and the signature still verifies.
 *   0.2 — signs the canonical form of the whole declaration. Any change to any
 *         field breaks it.
 */
const SIGNATURE_COVERAGE = { '0.1': 'identity', '0.2': 'declaration', '0.3': 'declaration' };

function subtle() {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error('Web Crypto API (crypto.subtle) not available');
  return s;
}

function fromBase64(value) {
  if (typeof value !== 'string' || value.length === 0) throw new Error('not base64');
  // atob is available in browsers and Node 18+; avoids depending on Buffer.
  const binary = atob(value.replace(/\s+/g, ''));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

async function verifyEd25519(publicKeyBase64, signatureBase64, message) {
  const key = await subtle().importKey(
    'spki',
    fromBase64(publicKeyBase64),
    { name: 'Ed25519' },
    false,
    ['verify']
  );
  return subtle().verify(
    'Ed25519',
    key,
    fromBase64(signatureBase64),
    new TextEncoder().encode(message)
  );
}

/**
 * SHA-256 of the raw public key bytes, hex encoded.
 *
 * Use it to detect key rotation: store the fingerprint you saw for a
 * provenance_id, and treat a different one later as a material change rather
 * than a silent update. See SPEC.md § Signing and Verification (Continuity).
 *
 * @param {string} publicKeyBase64  Base64 SPKI DER Ed25519 public key
 * @returns {Promise<string>}
 */
export async function keyFingerprint(publicKeyBase64) {
  const digest = await subtle().digest('SHA-256', fromBase64(publicKeyBase64));
  return toHex(new Uint8Array(digest));
}

/**
 * Where a declaration claims to live, parsed out of its provenance_id.
 *
 * @param {string} provenanceId  e.g. 'provenance:github:alice/agent'
 * @returns {{ platform: string, path: string } | null}
 */
export function parseProvenanceId(provenanceId) {
  if (typeof provenanceId !== 'string') return null;
  const match = /^provenance:([a-z0-9-]+):(.+)$/i.exec(provenanceId.trim());
  if (!match) return null;
  return { platform: match[1].toLowerCase(), path: match[2] };
}

/**
 * Where, on each platform's own hosts, the owner/name that an id names must
 * sit in a URL's path — exactly there, never anywhere else in the path. A
 * function returns the identity segments a URL carries, or null if the URL is
 * not one this platform serves declarations from.
 */
const seg = (u) => u.pathname.split('/').filter(Boolean).map((x) => decodeURIComponent(x).toLowerCase());
const PLATFORM_HOSTS = [
  // github.com/<owner>/<repo>/…, raw.githubusercontent.com/<owner>/<repo>/<ref>/…, api.github.com/repos/<owner>/<repo>/…
  [/^(www\.)?github\.com$/i, 'github', (u) => seg(u).slice(0, 2)],
  [/^raw\.githubusercontent\.com$/i, 'github', (u) => seg(u).slice(0, 2)],
  [/^api\.github\.com$/i, 'github', (u) => (seg(u)[0] === 'repos' ? seg(u).slice(1, 3) : null)],
  // huggingface.co/<owner>/<repo>, or /spaces|datasets|models/<owner>/<repo>
  [/^(www\.)?huggingface\.co$/i, 'huggingface', (u) => (['spaces', 'datasets', 'models'].includes(seg(u)[0]) ? seg(u).slice(1, 3) : seg(u).slice(0, 2))],
  // www.npmjs.com/package/<name> or /package/@scope/<name>; registry.npmjs.org/<name> or /@scope/<name> (or %2f-encoded)
  [/^(www\.)?npmjs\.com$/i, 'npm', (u) => { const s = seg(u); if (s[0] !== 'package') return null; return s[1]?.startsWith('@') ? (s[1].includes('/') ? s[1].split('/') : s.slice(1, 3)) : s.slice(1, 2); }],
  [/^registry\.npmjs\.org$/i, 'npm', (u) => { const s = seg(u); return s[0]?.startsWith('@') ? (s[0].includes('/') ? s[0].split('/') : s.slice(0, 2)) : s.slice(0, 1); }],
  // pypi.org/project/<name>/…
  [/^pypi\.org$/i, 'pypi', (u) => (seg(u)[0] === 'project' ? seg(u).slice(1, 2) : null)],
];

/**
 * Does a retrieval location agree with the declaration's own provenance_id?
 *
 * A declaration served from somewhere other than the location it names was
 * put there by someone else, whatever its signature says. The comparison is
 * structural: the id's owner and name must be exactly where the platform puts
 * them in a URL — a repository that merely contains folders with the right
 * names is someone else's repository.
 *
 * @returns {'match' | 'mismatch' | 'unchecked'}
 */
export function checkLocation(provenanceId, retrievedFrom) {
  const id = parseProvenanceId(provenanceId);
  if (!id || typeof retrievedFrom !== 'string') return 'unchecked';

  let url;
  try {
    url = new URL(retrievedFrom);
  } catch {
    return 'unchecked';
  }

  // provenance:domain:<hostname>[/<path>] — for an agent that runs as a service
  // and has no public repository. Whoever put the file at that address controls it.
  if (id.platform === 'domain') {
    const [declaredHost, ...declaredPath] = id.path.split('/').filter(Boolean);
    if (!declaredHost) return 'unchecked';
    // Exact host match. A subdomain is a different party as far as this is
    // concerned, and treating it as the same would be the whole attack.
    if (url.hostname.toLowerCase() !== declaredHost.toLowerCase()) return 'mismatch';
    if (url.port && url.port !== '443') return 'mismatch';
    if (declaredPath.length === 0) return 'match';
    // The declared path is where the agent lives: the URL must start there.
    const segs = seg(url);
    const want = declaredPath.map((x) => x.toLowerCase());
    return want.every((part, j) => segs[j] === part) ? 'match' : 'mismatch';
  }

  const host = PLATFORM_HOSTS.find(([h]) => h.test(url.hostname));
  if (!host) return 'unchecked';
  const [, platform, identityOf] = host;
  if (platform !== id.platform) return 'mismatch';
  if (url.port && url.port !== '443') return 'mismatch';
  const expected = id.path.toLowerCase().split('/').filter(Boolean);
  if (expected.length === 0) return 'unchecked';
  const got = identityOf(url);
  if (!got || got.length !== expected.length) return 'mismatch';
  return expected.every((part, j) => got[j] === part) ? 'match' : 'mismatch';
}

/**
 * Verify a parsed PROVENANCE.yml declaration offline.
 *
 * Checks the identity signature against the public key inside the file, and —
 * when `retrievedFrom` is given — whether the file was served from the
 * location it claims.
 *
 * What a valid signature proves depends on the spec version, and `coverage`
 * reports which: 'declaration' (0.2) means every field is covered, so any edit
 * breaks it; 'identity' (0.1) means only the identity and key are covered, so
 * the declared capabilities and constraints are NOT protected by it.
 *
 * In neither case does a signature prove who the key holder is, that the
 * declared capabilities are accurate, or that the declaration is current.
 * Revocation and standing cannot be checked offline.
 *
 * @param {object} declaration  Parsed PROVENANCE.yml
 * @param {object} [options]
 * @param {string} [options.retrievedFrom]  URL the declaration was fetched from
 * @returns {Promise<{
 *   signed: boolean,
 *   valid: boolean,
 *   reason: string | null,
 *   provenanceId: string | null,
 *   publicKey: string | null,
 *   fingerprint: string | null,
 *   location: 'match' | 'mismatch' | 'unchecked',
 *   coverage: 'declaration' | 'identity' | null,
 *   trustworthy: boolean
 * }>}
 */
export async function verifyDeclaration(declaration, options = {}) {
  const base = {
    signed: false,
    valid: false,
    reason: null,
    provenanceId: null,
    publicKey: null,
    fingerprint: null,
    location: 'unchecked',
    coverage: null,
    trustworthy: false,
  };

  if (declaration === null || typeof declaration !== 'object') {
    return { ...base, reason: 'Declaration must be a parsed object' };
  }

  const provenanceId =
    typeof declaration.provenance_id === 'string' ? declaration.provenance_id : null;
  const identity =
    declaration.identity !== null && typeof declaration.identity === 'object'
      ? declaration.identity
      : null;
  const publicKey = typeof identity?.public_key === 'string' ? identity.public_key : null;
  const signature = typeof identity?.signature === 'string' ? identity.signature : null;

  const location = options.retrievedFrom
    ? checkLocation(provenanceId, options.retrievedFrom)
    : 'unchecked';

  const result = { ...base, provenanceId, publicKey, location };

  if (!identity) return { ...result, reason: 'No identity block' };
  if (!publicKey) return { ...result, reason: 'identity.public_key is missing' };

  const algorithm = identity.algorithm ?? ALGORITHM;
  if (String(algorithm).toLowerCase() !== ALGORITHM) {
    return { ...result, reason: `Unsupported algorithm: ${algorithm}` };
  }

  try {
    result.fingerprint = await keyFingerprint(publicKey);
  } catch {
    return { ...result, reason: 'identity.public_key is not a valid Ed25519 key' };
  }

  // A key with no signature advertises which key to challenge later. It says
  // nothing about whether this file has been altered.
  if (!signature) {
    return { ...result, reason: 'identity.signature is absent — key advertised, file not attested' };
  }
  result.signed = true;

  const declaredVersion = typeof declaration.provenance === 'string' ? declaration.provenance : '0.1';
  if (!provenanceId && declaredVersion === '0.1') {
    // The 0.1 payload is built from provenance_id, so without it there is
    // nothing to verify. A 0.2 signature covers the whole declaration and does
    // not need it (though the location check still does).
    return { ...result, reason: 'provenance_id is required to verify a 0.1 signature' };
  }

  // What the signature covers depends on the spec version the declaration
  // declares, so the payload is built differently for each.
  const specVersion = typeof declaration.provenance === 'string' ? declaration.provenance : '0.1';
  const coverage = SIGNATURE_COVERAGE[specVersion];
  if (!coverage) {
    return {
      ...result,
      reason: `Spec version ${specVersion} is not known to this verifier — cannot check its signature`,
    };
  }
  result.coverage = coverage;

  let payload;
  try {
    payload =
      coverage === 'declaration'
        ? declarationSigningPayload(declaration)
        : `${provenanceId}:${publicKey}`;
  } catch (e) {
    return { ...result, reason: `Declaration cannot be canonicalised: ${e.message}` };
  }

  let valid;
  try {
    valid = await verifyEd25519(publicKey, signature, payload);
  } catch {
    return { ...result, reason: 'identity.signature is malformed' };
  }

  if (!valid) return { ...result, reason: 'Signature does not verify' };

  return {
    ...result,
    valid: true,
    // Signature proves integrity; location binds it to a project someone
    // controls. Only both together justify treating the file as the owner's.
    trustworthy: location === 'match',
    reason: location === 'match' ? null : 'Signature valid, but retrieval location was not confirmed',
  };
}

/**
 * Verify a live challenge response — domain-separated form.
 *
 * Pair with `signAgentChallenge`. Prefer this over `verifyChallenge`: the legacy
 * payload is the same shape as a revocation, so any public endpoint signing it
 * is a way to revoke the agent's own key.
 *
 * @param {string} publicKeyBase64
 * @param {string} provenanceId
 * @param {string} nonce            Single-use, unpredictable
 * @param {string} signatureBase64
 * @returns {Promise<boolean>}
 */
export async function verifyAgentChallenge(publicKeyBase64, provenanceId, nonce, signatureBase64) {
  try {
    return await verifyEd25519(publicKeyBase64, signatureBase64, challengePayload(provenanceId, nonce));
  } catch {
    return false;
  }
}

/**
 * Verify a revocation — domain-separated form.
 *
 * Confirms it came from the key holder. It does not tell you whether a
 * revocation exists; that requires asking an index.
 *
 * @param {string} publicKeyBase64
 * @param {string} provenanceId
 * @param {string} signatureBase64
 * @returns {Promise<boolean>}
 */
export async function verifyAgentRevocation(publicKeyBase64, provenanceId, signatureBase64) {
  try {
    return await verifyEd25519(publicKeyBase64, signatureBase64, revocationPayload(provenanceId));
  } catch {
    return false;
  }
}

/**
 * Verify a live challenge response offline, against a key you already hold.
 *
 * LEGACY (spec 0.1 payload). Accepts "<provenanceId>:<nonce>", which is the same
 * shape as a revocation with nonce "REVOKE" — so never verify against a peer
 * that exposes this form publicly. Use `verifyAgentChallenge`.
 *
 * The network equivalent in the main SDK looks the key up in the index; this
 * takes the key directly, so a system that already stores keys can verify
 * without contacting anyone.
 *
 * @param {string} publicKeyBase64
 * @param {string} provenanceId
 * @param {string} nonce            Single-use, unpredictable
 * @param {string} signatureBase64
 * @returns {Promise<boolean>}
 */
export async function verifyChallenge(publicKeyBase64, provenanceId, nonce, signatureBase64) {
  try {
    return await verifyEd25519(publicKeyBase64, signatureBase64, `${provenanceId}:${nonce}`);
  } catch {
    return false;
  }
}

/**
 * Verify an owner-signed revocation offline.
 *
 * Confirms the revocation came from the key holder. It does not tell you
 * whether a revocation exists — that requires asking an index.
 *
 * @param {string} publicKeyBase64
 * @param {string} provenanceId
 * @param {string} signatureBase64
 * @returns {Promise<boolean>}
 */
export async function verifyRevocation(publicKeyBase64, provenanceId, signatureBase64) {
  try {
    return await verifyEd25519(publicKeyBase64, signatureBase64, `${provenanceId}:REVOKE`);
  } catch {
    return false;
  }
}

/**
 * Where a declaration is published, derived from its provenance id alone.
 *
 * This is what lets anyone find an agent's declaration without asking an index:
 * the identifier names the location, and the location holds the document.
 *
 *   provenance:domain:<host>[/<path>]  → https://<host>[/<path>]/.well-known/provenance.json
 *   provenance:github:<owner>/<repo>   → PROVENANCE.yml at the default branch
 *
 * Returns null for platforms with no single fetchable location (npm, pypi,
 * huggingface, …). There the caller must be told where the file is.
 *
 * @param {string} provenanceId
 * @returns {string | null}
 */
export function locateDeclaration(provenanceId) {
  const id = parseProvenanceId(provenanceId);
  if (!id) return null;

  if (id.platform === 'domain') {
    const [host, ...path] = id.path.split('/').filter(Boolean);
    if (!host || !/^[a-z0-9.-]+(:\d+)?$/i.test(host)) return null;
    const prefix = path.length ? `/${path.map(encodeURIComponent).join('/')}` : '';
    return `https://${host.toLowerCase()}${prefix}/.well-known/provenance.json`;
  }

  if (id.platform === 'github') {
    const parts = id.path.split('/').filter(Boolean);
    if (parts.length !== 2) return null;
    const [owner, repo] = parts.map(encodeURIComponent);
    return `https://raw.githubusercontent.com/${owner}/${repo}/HEAD/PROVENANCE.yml`;
  }

  return null;
}

/**
 * A stable fingerprint of a declaration's content: SHA-256 of its signing
 * payload, as `sha256:<hex>`.
 *
 * Two declarations that differ only in formatting, comments, key order or
 * signature have the same digest; any change to any field gives a different
 * one. An attestation or a decision records this to say exactly which state of
 * a declaration it was about.
 *
 * @param {object} declaration  Parsed declaration
 * @returns {Promise<string>}
 */
export async function declarationDigest(declaration) {
  const bytes = new TextEncoder().encode(declarationSigningPayload(declaration));
  return `sha256:${toHex(new Uint8Array(await subtle().digest('SHA-256', bytes)))}`;
}

/**
 * Decide whether to accept an agent on the strength of its declaration alone.
 *
 * Offline: the declaration and where it was fetched from are all it uses. It
 * answers "is this genuinely the operator's, and does it promise what I
 * require?" — not "is it currently in good standing", which no document can
 * carry and which comes from whichever attesters the caller chooses to trust.
 *
 * Every refusal names its reason. A declaration that could not be checked is
 * refused, never waved through.
 *
 * @param {object} declaration  Parsed declaration
 * @param {object} [options]
 * @param {string}   [options.retrievedFrom]        URL it was fetched from
 * @param {boolean}  [options.requireSignature=true]
 * @param {boolean}  [options.requireLocation=true] Must be served from where its id says
 * @param {'declaration'|'identity'} [options.requireCoverage='declaration']
 *        'declaration' refuses 0.1 signatures, which do not protect constraints
 * @param {string[]} [options.requireConstraints=[]]
 * @param {string[]} [options.requireCapabilities=[]]
 * @param {string}   [options.expectedFingerprint]  Key seen before; a different one is a rotation
 * @param {object}   [options.affiliation]  For agents whose location cannot be checked publicly
 *        (internal or private services): { attestation, issuerPublicKey, now? } — an
 *        `affiliation` attestation signed by the organisation that operates the agent. When
 *        valid and bound to this agent's id and key, it stands in for the location check.
 * @returns {Promise<{ allowed: boolean, reason: string | null, verification: object, anchor: 'location'|'affiliation'|null }>}
 */
export async function checkDeclaration(declaration, options = {}) {
  const {
    retrievedFrom,
    requireSignature = true,
    requireLocation = true,
    requireCoverage = 'declaration',
    requireConstraints = [],
    requireCapabilities = [],
    expectedFingerprint,
  } = options;

  const verification = await verifyDeclaration(declaration, { retrievedFrom });
  const refuse = (reason) => ({ allowed: false, reason, verification, anchor: null });

  if (requireSignature) {
    if (!verification.valid) return refuse(verification.reason ?? 'Signature did not verify');
    if (requireCoverage === 'declaration' && verification.coverage !== 'declaration') {
      return refuse('Signature covers only the identity (spec 0.1), so the declared constraints are not protected');
    }
  }

  // What ties the declaration to its operator: where it was published, or —
  // for a service nobody outside can reach — the operator's organisation
  // vouching for this exact id and key.
  let anchor = verification.location === 'match' ? 'location' : null;
  if (!anchor && options.affiliation) {
    const why = await checkAffiliation(options.affiliation, verification);
    if (why) return refuse(why);
    anchor = 'affiliation';
  }

  if (requireLocation && !anchor) {
    return refuse(
      !retrievedFrom
        ? 'Retrieval location not given, so the declaration cannot be tied to its operator'
        : verification.location === 'mismatch'
          ? 'Declaration was not served from the location its provenance id names'
          : 'Retrieval location could not be interpreted for this provenance id'
    );
  }

  if (expectedFingerprint && verification.fingerprint !== expectedFingerprint) {
    return refuse('Declaration is signed with a different key than previously seen — a key rotation');
  }

  const constraints = Array.isArray(declaration?.constraints) ? declaration.constraints : [];
  for (const c of requireConstraints) {
    if (!constraints.includes(c)) return refuse(`Agent has not committed to constraint: ${c}`);
  }
  const capabilities = Array.isArray(declaration?.capabilities) ? declaration.capabilities : [];
  for (const c of requireCapabilities) {
    if (!capabilities.includes(c)) return refuse(`Agent does not declare capability: ${c}`);
  }
  if (options.requirePinned) {
    const loose = (Array.isArray(declaration?.dependencies) ? declaration.dependencies : []).filter((d) => !isPinned(d));
    if (loose.length) return refuse(`Dependencies not pinned to an exact version: ${loose.map((d) => d.provenance_id ?? d.url).join(', ')}`);
  }

  return { allowed: true, reason: null, verification, anchor };
}

async function checkAffiliation({ attestation, issuerPublicKey, now } = {}, verification) {
  const r = await verifyAttestation(attestation, { issuerPublicKey, now });
  if (!r.valid) return `Affiliation ${r.status}: ${r.reason}`;
  if (r.kind !== 'affiliation') return `Attestation is a ${r.kind}, not an affiliation`;
  if (r.subject?.provenance_id !== verification.provenanceId) {
    return 'Affiliation is for a different agent';
  }
  if (!verification.valid) return 'An affiliation covers a signed declaration only';
  if (attestation.claims?.subject_key_fingerprint !== verification.fingerprint) {
    return 'Affiliation vouches for a different key than this declaration uses';
  }
  return null;
}

/** Attestation format versions this verifier understands. */
const ATTESTATION_VERSIONS = new Set(['0.1']);

/** Tolerated clock difference between issuer and verifier. */
const CLOCK_SKEW_MS = 5 * 60 * 1000;

function parseTime(value) {
  if (typeof value !== 'string') return null;
  // RFC 3339 with an explicit offset; a bare local time means different
  // instants to different verifiers.
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(value)) return null;
  const t = Date.parse(value);
  return Number.isNaN(t) ? null : t;
}

/**
 * Verify an attestation offline: a signed statement by a third party (the
 * issuer) about an agent (the subject).
 *
 * The caller supplies the issuer's public key — normally taken from the
 * issuer's own verified declaration, and pinned. Nothing is fetched.
 *
 * `status` keeps apart outcomes that must never be confused:
 *   'valid'          genuine, and inside its validity window
 *   'expired'        genuine, but past valid_until — stale, not forged
 *   'not_yet_valid'  genuine, but issued_at is in the future
 *   'invalid'        not genuine, malformed, or signed by another key
 *   'unchecked'      could not be checked (no issuer key, unknown version)
 *
 * A valid attestation proves the issuer said this, when, about which state of
 * the subject. It does not prove the issuer is right, and it does not prove the
 * issuer has not withdrawn it since — that is what `status_url` is for.
 *
 * @param {object} attestation
 * @param {object} options
 * @param {string} options.issuerPublicKey  Base64 SPKI DER Ed25519 key of the issuer
 * @param {Date|number} [options.now]       Defaults to the current time
 * @returns {Promise<{
 *   status: 'valid'|'expired'|'not_yet_valid'|'invalid'|'unchecked',
 *   valid: boolean,
 *   reason: string | null,
 *   kind: string | null,
 *   issuer: string | null,
 *   subject: object | null,
 *   validUntil: string | null
 * }>}
 */
export async function verifyAttestation(attestation, options = {}) {
  const out = (status, reason, extra = {}) => ({
    status,
    valid: status === 'valid',
    reason,
    kind: null,
    issuer: null,
    subject: null,
    validUntil: null,
    ...extra,
  });

  if (attestation === null || typeof attestation !== 'object' || Array.isArray(attestation)) {
    return out('invalid', 'Attestation must be a parsed object');
  }

  const a = attestation;
  const facts = {
    kind: typeof a.kind === 'string' ? a.kind : null,
    issuer: typeof a.issuer?.provenance_id === 'string' ? a.issuer.provenance_id : null,
    subject: a.subject && typeof a.subject === 'object' ? a.subject : null,
    validUntil: typeof a.valid_until === 'string' ? a.valid_until : null,
  };

  if (!ATTESTATION_VERSIONS.has(a.attestation)) {
    return out('unchecked', `Attestation version ${a.attestation ?? '(missing)'} is not known to this verifier`, facts);
  }

  const missing = [];
  if (typeof a.id !== 'string' || !a.id) missing.push('id');
  if (!facts.kind) missing.push('kind');
  if (!facts.issuer) missing.push('issuer.provenance_id');
  if (typeof a.issuer?.key_fingerprint !== 'string') missing.push('issuer.key_fingerprint');
  if (!facts.subject || (typeof facts.subject.provenance_id !== 'string' && typeof facts.subject.url !== 'string')) {
    missing.push('subject.provenance_id or subject.url');
  }
  if (typeof a.scope !== 'string' || !a.scope) missing.push('scope');
  if (!a.claims || typeof a.claims !== 'object' || Array.isArray(a.claims)) missing.push('claims');
  if (typeof a.signature !== 'string' || !a.signature) missing.push('signature');
  if (missing.length) return out('invalid', `Missing or malformed: ${missing.join(', ')}`, facts);

  const issuedAt = parseTime(a.issued_at);
  const validUntil = parseTime(a.valid_until);
  if (issuedAt === null || validUntil === null) {
    return out('invalid', 'issued_at and valid_until must be RFC 3339 timestamps with an offset', facts);
  }
  if (validUntil <= issuedAt) return out('invalid', 'valid_until is not after issued_at', facts);

  const { issuerPublicKey } = options;
  if (typeof issuerPublicKey !== 'string' || !issuerPublicKey) {
    return out('unchecked', 'No issuer public key supplied — the signature was not checked', facts);
  }

  let fingerprint;
  try {
    fingerprint = await keyFingerprint(issuerPublicKey);
  } catch {
    return out('unchecked', 'Issuer public key is not valid base64', facts);
  }
  if (fingerprint !== a.issuer.key_fingerprint) {
    return out('invalid', 'Attestation names a different issuer key than the one supplied', facts);
  }

  let genuine;
  try {
    genuine = await verifyEd25519(issuerPublicKey, a.signature, attestationSigningPayload(a));
  } catch (e) {
    return out('invalid', `Signature could not be checked: ${e.message}`, facts);
  }
  if (!genuine) return out('invalid', 'Signature does not verify', facts);

  // Only now are the dates meaningful: an attacker can write any date, so a
  // forged attestation must read as forged, never as merely expired.
  const now = options.now === undefined ? Date.now() : Number(options.now);
  if (issuedAt > now + CLOCK_SKEW_MS) return out('not_yet_valid', 'issued_at is in the future', facts);
  if (now > validUntil) return out('expired', `Expired at ${a.valid_until}`, facts);

  return out('valid', null, facts);
}

/**
 * Verify an issuer's withdrawal of one of its attestations.
 *
 * Confirms the withdrawal is genuine. Whether one has been issued is learned
 * from the attestation's `status_url`, not from the attestation itself.
 *
 * @param {string} issuerPublicKey
 * @param {string} issuerId        issuer.provenance_id of the attestation
 * @param {string} attestationId   id of the attestation
 * @param {string} signatureBase64
 * @returns {Promise<boolean>}
 */
export async function verifyAttestationWithdrawal(issuerPublicKey, issuerId, attestationId, signatureBase64) {
  try {
    return await verifyEd25519(issuerPublicKey, signatureBase64, attestationWithdrawalPayload(issuerId, attestationId));
  } catch {
    return false;
  }
}

const NOTICE_VERSIONS = new Set(['0.1', '0.2']);
const NOTICE_EVENTS = new Set(['declaration-published', 'release', 'key-rotation', 'incident']);

/**
 * Verify a notice offline: a signed statement by an agent's operator about the
 * agent itself.
 *
 * Pass the public key you already hold for the agent — normally from its
 * verified declaration, or the key you pinned. For a `key-rotation` notice
 * that is the OLD key: a valid rotation notice is the old key vouching for
 * the new one, whose fingerprint is then in `newKeyFingerprint`.
 *
 * `status` is 'valid', 'invalid' (forged, altered, malformed, wrong key) or
 * 'unchecked' (no key supplied, unknown version) — never confused.
 *
 * @param {object} notice
 * @param {object} options
 * @param {string} options.publicKey  Base64 SPKI DER key of the agent (the old key, for a rotation)
 * @returns {Promise<{
 *   status: 'valid'|'invalid'|'unchecked',
 *   valid: boolean,
 *   reason: string | null,
 *   event: string | null,
 *   provenanceId: string | null,
 *   newKeyFingerprint: string | null
 * }>}
 */
export async function verifyNotice(notice, options = {}) {
  const out = (status, reason, extra = {}) => ({
    status, valid: status === 'valid', reason, event: null, provenanceId: null, newKeyFingerprint: null, ...extra,
  });
  if (notice === null || typeof notice !== 'object' || Array.isArray(notice)) {
    return out('invalid', 'Notice must be a parsed object');
  }
  const n = notice;
  const facts = {
    event: typeof n.event === 'string' ? n.event : null,
    provenanceId: typeof n.provenance_id === 'string' ? n.provenance_id : null,
  };
  if (!NOTICE_VERSIONS.has(n.notice)) {
    return out('unchecked', `Notice version ${n.notice ?? '(missing)'} is not known to this verifier`, facts);
  }

  const missing = [];
  if (typeof n.id !== 'string' || !n.id) missing.push('id');
  if (!facts.event || !NOTICE_EVENTS.has(facts.event)) missing.push('event');
  if (!facts.provenanceId) missing.push('provenance_id');
  if (typeof n.key_fingerprint !== 'string') missing.push('key_fingerprint');
  if (parseTime(n.issued_at) === null) missing.push('issued_at');
  if (!n.claims || typeof n.claims !== 'object' || Array.isArray(n.claims)) missing.push('claims');
  if (typeof n.signature !== 'string' || !n.signature) missing.push('signature');
  if (facts.event === 'key-rotation' && typeof n.claims?.new_public_key !== 'string') missing.push('claims.new_public_key');
  if (missing.length) return out('invalid', `Missing or malformed: ${missing.join(', ')}`, facts);

  const { publicKey } = options;
  if (typeof publicKey !== 'string' || !publicKey) {
    return out('unchecked', 'No public key supplied — the signature was not checked', facts);
  }
  let fingerprint;
  try {
    fingerprint = await keyFingerprint(publicKey);
  } catch {
    return out('unchecked', 'Public key is not valid base64', facts);
  }
  if (fingerprint !== n.key_fingerprint) {
    return out('invalid', 'Notice names a different signing key than the one supplied', facts);
  }

  let genuine;
  try {
    genuine = await verifyEd25519(publicKey, n.signature, noticeSigningPayload(n));
  } catch (e) {
    return out('invalid', `Signature could not be checked: ${e.message}`, facts);
  }
  if (!genuine) return out('invalid', 'Signature does not verify', facts);

  if (facts.event === 'key-rotation') {
    let newKeyFingerprint;
    try {
      newKeyFingerprint = await keyFingerprint(n.claims.new_public_key);
    } catch {
      return out('invalid', 'claims.new_public_key is not valid base64', facts);
    }
    if (n.claims.new_key_fingerprint && n.claims.new_key_fingerprint !== newKeyFingerprint) {
      return out('invalid', 'claims.new_key_fingerprint does not match claims.new_public_key', facts);
    }
    return out('valid', null, { ...facts, newKeyFingerprint });
  }
  return out('valid', null, facts);
}

/**
 * Whether a declaration's links to an A2A Agent Card and an MCP Registry entry
 * are confirmed by shared control, or merely claimed. Offline; see SPEC.md,
 * "Linking with A2A and MCP".
 *
 *   confirmed  the identifiers share control (host, registry namespace or GitHub account),
 *              computed from the identifiers alone; the listing is not fetched, and it may
 *              describe other software from the same party. Never merge subjects on this alone.
 *   claimed    the declaration names it, but control is not shown to match
 *   none       no link declared
 *
 * @param {object} declaration  Parsed declaration
 * @returns {{ a2a: 'confirmed'|'claimed'|'none', mcp: 'confirmed'|'claimed'|'none' }}
 */
export function checkInteropLinks(declaration) {
  const id = parseProvenanceId(declaration?.provenance_id);
  const interop = declaration?.interop ?? {};
  const host = id?.platform === 'domain' ? id.path.split('/')[0].toLowerCase() : null;

  let a2a = 'none';
  if (typeof interop.a2a_agent_card === 'string') {
    a2a = 'claimed';
    try {
      const url = new URL(interop.a2a_agent_card);
      if (host && url.protocol === 'https:' && url.hostname.toLowerCase() === host) a2a = 'confirmed';
    } catch {}
  }

  let mcp = 'none';
  if (typeof interop.mcp_registry === 'string') {
    mcp = 'claimed';
    const namespace = interop.mcp_registry.split('/')[0].toLowerCase();
    const labels = namespace.split('.');
    if (host && labels.length >= 2 && labels.slice().reverse().join('.') === host) {
      mcp = 'confirmed';
    } else if (id?.platform === 'github' && labels[0] === 'io' && labels[1] === 'github' && labels.length === 3) {
      const owner = id.path.split('/')[0].toLowerCase();
      if (labels[2] === owner) mcp = 'confirmed';
    }
  }

  return { a2a, mcp };
}

/**
 * Open a declaration delivered inside a notice — how an internal or private
 * service, which no watcher can fetch, hands over its declaration.
 *
 * Checks, offline, that the declaration inside verifies, that its digest is
 * the one the notice names, and that the notice was signed by the same key.
 * That proves the notice and declaration belong together. It does NOT prove
 * who operates the agent: nobody outside can check an internal location, so
 * pass the returned declaration to `checkDeclaration` with an `affiliation`
 * from the operating organisation.
 *
 * @param {object} notice  A declaration-published notice carrying claims.declaration
 * @returns {Promise<{ valid: boolean, reason: string | null, declaration: object | null }>}
 */
export async function openDeliveredDeclaration(notice) {
  const fail = (reason) => ({ valid: false, reason, declaration: null });
  if (notice?.event !== 'declaration-published') return fail('Not a declaration-published notice');
  const declaration = notice?.claims?.declaration;
  if (!declaration || typeof declaration !== 'object') return fail('Notice does not carry a declaration');

  const v = await verifyDeclaration(declaration);
  if (!v.valid) return fail(`Delivered declaration did not verify: ${v.reason}`);
  if (v.coverage !== 'declaration') return fail('Delivered declaration must be spec 0.2, signed in full');
  if (v.provenanceId !== notice.provenance_id) return fail('Notice and declaration name different agents');

  let digest;
  try {
    digest = await declarationDigest(declaration);
  } catch (e) {
    return fail(`Delivered declaration cannot be digested: ${e.message}`);
  }
  if (digest !== notice.claims.declaration_digest) return fail('Delivered declaration does not match the digest the notice names');

  const n = await verifyNotice(notice, { publicKey: v.publicKey });
  if (!n.valid) return fail(`Notice ${n.status}: ${n.reason}`);
  return { valid: true, reason: null, declaration };
}

// ---------------------------------------------------------------- pins (0.3)

const PIN_FIELDS = ['version', 'integrity', 'commit', 'declaration_digest'];
function isPinned(dep) {
  return dep && typeof dep.pin === 'object' && dep.pin !== null && PIN_FIELDS.some((f) => typeof dep.pin[f] === 'string');
}
const depKey = (d) => d?.provenance_id ?? d?.url;

/**
 * Compare what a build actually resolved (the `resolved` claim of a verified
 * release or declaration-published notice, format 0.2) with the declaration's
 * pins. Offline; verify the notice first with verifyNotice.
 *
 * For each dependency: 'match' when every pinned field equals what was
 * resolved; 'mismatch' when any pinned field differs — the pin was declared
 * and something else shipped; 'unpinned' when something shipped that the
 * declaration names but does not pin, or does not name at all; 'not_reported'
 * when a pinned dependency is missing from what was resolved.
 *
 * @param {object} declaration
 * @param {object} notice
 * @returns {{ dependency: string, result: 'match'|'mismatch'|'unpinned'|'not_reported', differs?: string[] }[]}
 */
export function checkPins(declaration, notice) {
  const deps = Array.isArray(declaration?.dependencies) ? declaration.dependencies : [];
  const resolved = Array.isArray(notice?.claims?.resolved) ? notice.claims.resolved : [];
  const byKey = new Map(resolved.filter((r) => depKey(r)).map((r) => [depKey(r), r]));
  const out = [];
  for (const d of deps) {
    const key = depKey(d);
    if (!key) continue;
    const r = byKey.get(key);
    byKey.delete(key);
    if (!isPinned(d)) { if (r) out.push({ dependency: key, result: 'unpinned' }); continue; }
    if (!r) { out.push({ dependency: key, result: 'not_reported' }); continue; }
    const differs = PIN_FIELDS.filter((f) => typeof d.pin[f] === 'string' && r[f] !== d.pin[f]);
    out.push(differs.length ? { dependency: key, result: 'mismatch', differs } : { dependency: key, result: 'match' });
  }
  for (const key of byKey.keys()) out.push({ dependency: key, result: 'unpinned' });
  return out;
}

// ---------------------------------------------------------- site index (0.1)

const INDEX_MAX = 1000;
const ID_PATTERN = /^provenance:(github|npm|pypi|huggingface|clawmarket|domain):.+$/;

/**
 * Where a site's index of declarations lives: one fixed address per host, so a
 * watcher that knows only a website can discover every passport it publishes
 * without fetching any other page.
 *
 * @param {string} host  e.g. "example.com"
 * @returns {string|null}
 */
export function locateIndex(host) {
  if (typeof host !== 'string' || !/^[a-z0-9.-]+(:\d+)?$/i.test(host.trim())) return null;
  return `https://${host.trim().toLowerCase()}/.well-known/provenance/index.json`;
}

/**
 * Read a site index. A pointer, never proof: every entry must still be
 * verified at its own location, and an entry off this site is only what the
 * site claims it publishes. Refuses an index whose `site` is not the host it
 * was fetched from.
 *
 * @param {object} index           parsed index.json
 * @param {object} options
 * @param {string} options.fetchedFrom  URL the index was fetched from
 * @returns {{ valid: boolean, reason: string|null, site: string|null, operator: string|null,
 *             agents: { provenanceId: string, name: string|null, onSite: boolean }[] }}
 */
export function readIndex(index, { fetchedFrom } = {}) {
  const bad = (reason) => ({ valid: false, reason, site: null, operator: null, agents: [] });
  if (index === null || typeof index !== 'object' || Array.isArray(index)) return bad('Index must be an object');
  if (index.provenance_index !== '0.1') return bad(`Index version ${JSON.stringify(index.provenance_index ?? null)} is not known to this reader`);
  let host;
  try { host = new URL(fetchedFrom).host.toLowerCase(); } catch { return bad('fetchedFrom must be the URL the index came from'); }
  if (typeof index.site !== 'string' || index.site.toLowerCase() !== host) {
    return bad(`Index names site ${JSON.stringify(index.site ?? null)} but was fetched from ${host}`);
  }
  if (!Array.isArray(index.agents)) return bad('Index has no agents list');
  const seen = new Set();
  const agents = [];
  for (const entry of index.agents.slice(0, INDEX_MAX)) {
    const id = entry?.provenance_id;
    if (typeof id !== 'string' || !ID_PATTERN.test(id) || seen.has(id)) continue;
    seen.add(id);
    const parsed = parseProvenanceId(id);
    const onSite = parsed?.platform === 'domain' && parsed.path.split('/')[0].toLowerCase() === host;
    agents.push({ provenanceId: id, name: typeof entry.name === 'string' ? entry.name.slice(0, 200) : null, onSite });
  }
  return { valid: true, reason: null, site: host, operator: typeof index.operator === 'string' ? index.operator : null, agents };
}
