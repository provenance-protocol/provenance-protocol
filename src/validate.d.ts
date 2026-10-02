/**
 * provenance-protocol/validate — schema validation, offline. Node-only.
 * Structure only; signatures are checked by provenance-protocol/verify.
 */

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/** Validate a parsed declaration against the schema for its `provenance` version. */
export function validateDeclaration(declaration: unknown): ValidationResult;

/** Validate a parsed attestation against the schema for its `attestation` version. */
export function validateAttestation(attestation: unknown): ValidationResult;

/** Validate a parsed notice against the schema for its `notice` version. */
export function validateNotice(notice: unknown): ValidationResult;

/** Validate a parsed site index (format 0.1). */
export function validateIndex(index: unknown): ValidationResult;
