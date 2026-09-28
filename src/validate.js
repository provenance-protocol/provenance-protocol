/**
 * provenance-protocol/validate — check documents against the published schemas
 *
 * Offline. Validates a parsed declaration or attestation against the JSON
 * Schema shipped in this package for its declared version. Structure only:
 * signatures are checked by ./verify.js.
 *
 *   import { validateDeclaration } from 'provenance-protocol/validate';
 *   const { valid, errors, warnings } = validateDeclaration(YAML.parse(text));
 *
 * Node-only (reads the schema files from this package). Implements the subset
 * of JSON Schema draft-07 the published schemas use, and throws on any keyword
 * outside it — a validator that silently skipped a rule would pass files the
 * schema rejects.
 */

import { readFileSync } from 'node:fs';

const load = (name) => JSON.parse(readFileSync(new URL(`../schema/${name}`, import.meta.url), 'utf8'));
const cache = new Map();
const schema = (name) => {
  if (!cache.has(name)) cache.set(name, load(name));
  return cache.get(name);
};

const DECLARATION_SCHEMAS = { '0.1': 'provenance-0.1.json', '0.2': 'provenance-0.2.json', '0.3': 'provenance-0.3.json' };
const ATTESTATION_SCHEMAS = { '0.1': 'attestation-0.1.json' };
const NOTICE_SCHEMAS = { '0.1': 'notice-0.1.json', '0.2': 'notice-0.2.json' };

const KNOWN = new Set([
  '$schema', '$id', '$comment', 'title', 'description',
  'type', 'required', 'properties', 'additionalProperties', 'enum', 'const',
  'pattern', 'minLength', 'maxLength', 'minimum', 'items', 'uniqueItems', 'format',
  'anyOf', 'allOf', 'if', 'then',
]);

const FORMATS = {
  uri: (v) => { try { return Boolean(new URL(v).protocol); } catch { return false; } },
  email: (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v),
  'date-time': (v) => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(v) && !Number.isNaN(Date.parse(v)),
};

function typeOf(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (typeof v === 'number') return Number.isInteger(v) ? 'integer' : 'number';
  return typeof v;
}

function check(s, v, path, errors) {
  if (s === true || s === undefined) return;
  if (s === false) { errors.push(`${path}: not allowed`); return; }

  for (const k of Object.keys(s)) {
    if (!KNOWN.has(k)) throw new Error(`Schema keyword "${k}" at ${path} is not supported by this validator`);
  }

  const t = typeOf(v);
  if (s.type) {
    const ok = s.type === t || (s.type === 'number' && t === 'integer');
    if (!ok) { errors.push(`${path}: must be ${s.type}`); return; }
  }
  if ('const' in s && v !== s.const) errors.push(`${path}: must be ${JSON.stringify(s.const)}`);
  if (s.enum && !s.enum.includes(v)) errors.push(`${path}: must be one of ${s.enum.join(', ')}`);

  if ((t === 'number' || t === 'integer') && s.minimum !== undefined && v < s.minimum) {
    errors.push(`${path}: must be at least ${s.minimum}`);
  }

  if (t === 'string') {
    if (s.minLength !== undefined && v.length < s.minLength) errors.push(`${path}: too short`);
    if (s.maxLength !== undefined && v.length > s.maxLength) errors.push(`${path}: too long (max ${s.maxLength})`);
    if (s.pattern && !new RegExp(s.pattern).test(v)) errors.push(`${path}: "${v}" does not match ${s.pattern}`);
    if (s.format) {
      const f = FORMATS[s.format];
      if (!f) throw new Error(`Format "${s.format}" is not supported by this validator`);
      if (!f(v)) errors.push(`${path}: not a valid ${s.format}`);
    }
  }

  if (t === 'array') {
    if (s.items) v.forEach((item, i) => check(s.items, item, `${path}[${i}]`, errors));
    if (s.uniqueItems) {
      const seen = new Set(v.map((x) => JSON.stringify(x)));
      if (seen.size !== v.length) errors.push(`${path}: contains duplicates`);
    }
  }

  if (t === 'object') {
    for (const r of s.required ?? []) if (!(r in v)) errors.push(`${path}.${r}: required`);
    const props = s.properties ?? {};
    for (const [k, val] of Object.entries(v)) {
      if (k in props) check(props[k], val, `${path}.${k}`, errors);
      else if (s.additionalProperties === false) errors.push(`${path}.${k}: unknown field`);
    }
  }

  if (s.anyOf) {
    const passes = s.anyOf.some((sub) => { const e = []; check(sub, v, path, e); return e.length === 0; });
    if (!passes) errors.push(`${path}: does not satisfy any allowed form`);
  }
  for (const sub of s.allOf ?? []) check(sub, v, path, errors);
  if (s.if) {
    const e = [];
    check(s.if, v, path, e);
    if (e.length === 0) check(s.then, v, path, errors);
  }
}

function run(doc, versionField, table, label) {
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) {
    return { valid: false, errors: [`${label} must be an object`], warnings: [] };
  }
  const version = doc[versionField];
  const file = table[version];
  if (!file) {
    return {
      valid: false,
      errors: [`${versionField}: version ${JSON.stringify(version ?? null)} is not known to this validator (known: ${Object.keys(table).join(', ')})`],
      warnings: [],
    };
  }
  const errors = [];
  check(schema(file), doc, '$', errors);
  return { valid: errors.length === 0, errors, warnings: [] };
}

/**
 * Validate a parsed declaration against the schema for its `provenance` version.
 *
 * @param {object} declaration
 * @returns {{ valid: boolean, errors: string[], warnings: string[] }}
 */
export function validateDeclaration(declaration) {
  const result = run(declaration, 'provenance', DECLARATION_SCHEMAS, 'Declaration');
  if (declaration?.provenance === '0.1' && declaration?.identity?.signature) {
    result.warnings.push(
      'Spec 0.1 signatures cover only provenance_id and public_key — the declared capabilities and constraints are not protected. Sign with 0.2.'
    );
  }
  if (declaration?.identity?.signature && !declaration?.provenance_id) {
    result.warnings.push('Signed but no provenance_id: nobody can tie this declaration to a location, so it cannot be verified as its operator\'s.');
  }
  return result;
}

/**
 * Validate a parsed attestation against the schema for its `attestation` version.
 *
 * @param {object} attestation
 * @returns {{ valid: boolean, errors: string[], warnings: string[] }}
 */
export function validateAttestation(attestation) {
  return run(attestation, 'attestation', ATTESTATION_SCHEMAS, 'Attestation');
}

/**
 * Validate a parsed notice against the schema for its `notice` version.
 *
 * @param {object} notice
 * @returns {{ valid: boolean, errors: string[], warnings: string[] }}
 */
export function validateNotice(notice) {
  return run(notice, 'notice', NOTICE_SCHEMAS, 'Notice');
}
