/**
 * provenance-protocol — offline verification (TypeScript definitions)
 *
 * Verifies a PROVENANCE.yml declaration without contacting any service.
 * Works anywhere the Web Crypto API exists: modern browsers, Node 18+.
 */

/** Whether a declaration was served from the location its provenance_id names. */
export type LocationCheck = 'match' | 'mismatch' | 'unchecked';

/** What a signature was found to cover, per the declaration's spec version. */
export type SignatureCoverage = 'declaration' | 'identity';

export interface VerificationResult {
  /** An identity.signature was present to check. */
  signed: boolean;
  /** The signature verified against identity.public_key. */
  valid: boolean;
  /** Why the result is not a clean pass, or null when it is. */
  reason: string | null;
  provenanceId: string | null;
  publicKey: string | null;
  /** SHA-256 of the public key, hex. Store it to detect key rotation. */
  fingerprint: string | null;
  location: LocationCheck;
  /**
   * 'declaration' (spec 0.2) — every field is covered; any edit breaks it.
   * 'identity' (spec 0.1) — only the identity and key are covered, so the
   * declared capabilities and constraints are NOT protected by the signature.
   * null when no signature was checked.
   */
  coverage: SignatureCoverage | null;
  /**
   * Signature valid AND retrieval location confirmed. Only both together
   * justify treating the declaration as the named project owner's.
   */
  trustworthy: boolean;
}

export interface VerifyOptions {
  /** URL the declaration was fetched from, for the location check. */
  retrievedFrom?: string;
}

/**
 * Verify a parsed PROVENANCE.yml declaration offline.
 *
 * Declarations are YAML — parse with your own library and pass the object;
 * this module is dependency-free by design.
 *
 * A valid signature proves the declaration came from the holder of that
 * private key and is unaltered. It does not prove who that holder is, that
 * the declared capabilities are accurate, or that the declaration is current.
 * Revocation and standing cannot be checked offline.
 */
export function verifyDeclaration(
  declaration: unknown,
  options?: VerifyOptions
): Promise<VerificationResult>;

/** SHA-256 of the raw public key bytes, hex encoded. Use it to detect key rotation. */
export function keyFingerprint(publicKeyBase64: string): Promise<string>;

/** Split a provenance id into its platform and path, or null if malformed. */
export function parseProvenanceId(
  provenanceId: string
): { platform: string; path: string } | null;

/**
 * Does a retrieval location agree with the declaration's own provenance_id?
 * Returns 'unchecked' when the location cannot be interpreted, so an unknown
 * host is never reported as agreement.
 */
export function checkLocation(provenanceId: string, retrievedFrom: string): LocationCheck;

/**
 * Verify a live challenge response against a key you already hold.
 * The nonce must be single-use and unpredictable.
 */
export function verifyChallenge(
  publicKeyBase64: string,
  provenanceId: string,
  nonce: string,
  signatureBase64: string
): Promise<boolean>;

/**
 * Verify an owner-signed revocation. Confirms it came from the key holder;
 * it does not tell you whether a revocation exists.
 */
export function verifyRevocation(
  publicKeyBase64: string,
  provenanceId: string,
  signatureBase64: string
): Promise<boolean>;

/**
 * Verify a live challenge response — domain-separated form. Prefer this over
 * `verifyChallenge`, whose payload is indistinguishable from a revocation.
 */
export function verifyAgentChallenge(
  publicKeyBase64: string, provenanceId: string, nonce: string, signatureBase64: string
): Promise<boolean>;

/** Verify a revocation — domain-separated form. */
export function verifyAgentRevocation(
  publicKeyBase64: string, provenanceId: string, signatureBase64: string
): Promise<boolean>;

/**
 * Where a declaration is published, derived from its provenance id alone:
 * domain ids → https://<host>[/<path>]/.well-known/provenance.json,
 * github ids → PROVENANCE.yml on the default branch. null where the platform
 * has no single fetchable location.
 */
export function locateDeclaration(provenanceId: string): string | null;

/**
 * SHA-256 of a declaration's signing payload, as `sha256:<hex>`. Unchanged by
 * formatting, comments, key order or signature; changed by any field.
 */
export function declarationDigest(declaration: object): Promise<string>;

export interface CheckDeclarationOptions {
  retrievedFrom?: string;
  /** Default true. */
  requireSignature?: boolean;
  /** Default true: must be served from the location its id names. */
  requireLocation?: boolean;
  /** Default 'declaration': refuses 0.1 signatures, which do not protect constraints. */
  requireCoverage?: SignatureCoverage;
  requireConstraints?: string[];
  requireCapabilities?: string[];
  /** Key fingerprint seen before; a different one is refused as a rotation. */
  expectedFingerprint?: string;
  /**
   * For an internal agent: its operator's affiliation attestation and the
   * operator's public key (from the operator's own verified declaration).
   * Stands in for the location check when the location does not match.
   */
  affiliation?: { attestation: unknown; issuerPublicKey: string; now?: Date | number };
}

export interface CheckDeclarationResult {
  allowed: boolean;
  reason: string | null;
  verification: VerificationResult;
  /** What tied the declaration to its operator, when allowed. */
  anchor: 'location' | 'affiliation' | null;
}

/**
 * Accept or refuse an agent on the strength of its declaration alone, offline.
 * Answers "is this genuinely the operator's, and does it promise what I
 * require?" — not current standing, which comes from attesters you choose.
 */
export function checkDeclaration(
  declaration: unknown,
  options?: CheckDeclarationOptions
): Promise<CheckDeclarationResult>;

export type AttestationStatus = 'valid' | 'expired' | 'not_yet_valid' | 'invalid' | 'unchecked';

export interface AttestationVerification {
  /**
   * 'expired' is genuine but stale; 'invalid' is forged or malformed;
   * 'unchecked' means it could not be checked at all. Never treat them alike.
   */
  status: AttestationStatus;
  valid: boolean;
  reason: string | null;
  kind: string | null;
  issuer: string | null;
  subject: { provenance_id?: string; url?: string; declaration_digest?: string } | null;
  validUntil: string | null;
}

/**
 * Verify an attestation offline against the issuer's public key, which the
 * caller supplies (normally from the issuer's own verified declaration).
 */
export function verifyAttestation(
  attestation: unknown,
  options: { issuerPublicKey: string; now?: Date | number }
): Promise<AttestationVerification>;

/** Verify an issuer's withdrawal of one of its attestations. */
export function verifyAttestationWithdrawal(
  issuerPublicKey: string, issuerId: string, attestationId: string, signatureBase64: string
): Promise<boolean>;

export interface NoticeVerification {
  /** 'invalid' is forged, altered or signed by another key; 'unchecked' could not be checked. */
  status: 'valid' | 'invalid' | 'unchecked';
  valid: boolean;
  reason: string | null;
  event: 'declaration-published' | 'release' | 'key-rotation' | 'incident' | null;
  provenanceId: string | null;
  /** For a valid key-rotation: the fingerprint to pin from now on. */
  newKeyFingerprint: string | null;
}

/**
 * Verify a notice — a statement by an agent's operator about the agent,
 * signed with the agent's key. For key-rotation, pass the OLD key.
 */
export function verifyNotice(notice: unknown, options: { publicKey: string }): Promise<NoticeVerification>;

/**
 * Whether a declaration's links to an A2A Agent Card and an MCP Registry
 * entry are confirmed by shared control or merely claimed.
 */
export function checkInteropLinks(declaration: object): {
  a2a: 'confirmed' | 'claimed' | 'none';
  mcp: 'confirmed' | 'claimed' | 'none';
};

/**
 * Open a declaration delivered inside a declaration-published notice (internal
 * or private services). Proves the notice and declaration belong together;
 * pair with an affiliation in checkDeclaration to prove who operates it.
 */
export function openDeliveredDeclaration(notice: unknown): Promise<{
  valid: boolean;
  reason: string | null;
  declaration: object | null;
}>;
