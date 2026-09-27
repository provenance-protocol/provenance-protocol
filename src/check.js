/**
 * provenance-protocol — `provenance check`
 *
 * Compares a declaration with the project it describes, so a passport does
 * not quietly go out of date as the code changes. Runs where the code is — the
 * developer's machine or their own CI — and makes no network connections:
 * the code is read locally and nothing is sent anywhere.
 *
 * Findings come in three kinds, handled differently on purpose:
 *
 *   certain    facts the project states outright — its version, the AI
 *              provider's official library, servers listed in MCP settings.
 *              Safe to apply automatically.
 *   likely     inferences — "an email library, so it probably sends email".
 *              Offered for a person to confirm; never applied unasked, because
 *              a wrong guess would be published under the vendor's signature.
 *   conflicts  the code now does something a promise rules out. Never
 *              resolved automatically: dropping a promise is a public
 *              weakening, and only a person may decide it.
 *
 * Node-only.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import YAML from 'yaml';
import { detectProject } from './init.js';

/** Where a project lists findings it has reviewed and wants left alone. */
export const IGNORE_FILE = '.provenance-ignore';

/**
 * Keys in the ignore file, one per line:
 *   capabilities:read:database
 *   model.model_id
 *   dependencies:https://mcp.example/sse
 * Lines starting with # are comments.
 */
export function readIgnore(dir) {
  const path = join(dir, IGNORE_FILE);
  if (!existsSync(path)) return new Set();
  return new Set(
    readFileSync(path, 'utf8')
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'))
  );
}

const depKey = (d) => d?.provenance_id ?? d?.url;

/**
 * What the project shows that the declaration does not say.
 *
 * @param {string} dir          Project root
 * @param {object} declaration  Parsed declaration
 * @param {object} [options]
 * @param {Set<string>|string[]} [options.ignore]  Keys to leave alone (defaults to the ignore file)
 * @returns {{ inSync: boolean, certain: object[], likely: object[], conflicts: object[], ignored: number }}
 */
export function checkProject(dir, declaration, options = {}) {
  if (!declaration || typeof declaration !== 'object') throw new TypeError('declaration must be a parsed object');
  const ignore = new Set(options.ignore ?? readIgnore(dir));
  const found = detectProject(dir);
  const certain = [];
  const likely = [];
  const conflicts = [];
  let ignored = 0;
  const push = (list, item) => {
    if (ignore.has(item.key)) { ignored++; return; }
    list.push(item);
  };

  if (found.version && declaration.version !== undefined && String(declaration.version) !== String(found.version)) {
    push(certain, { key: 'version', field: 'version', change: 'modified', from: declaration.version, value: String(found.version), reason: `${found.source} says ${found.version}` });
  }

  if (found.model?.provider && declaration.model?.provider !== found.model.provider) {
    push(certain, {
      key: 'model.provider', field: 'model.provider', change: declaration.model?.provider ? 'modified' : 'added',
      from: declaration.model?.provider, value: found.model.provider, reason: 'the project uses that provider\'s official library',
    });
  }
  if (found.model?.model_id && declaration.model?.model_id && declaration.model.model_id !== found.model.model_id) {
    push(likely, { key: 'model.model_id', field: 'model.model_id', change: 'modified', from: declaration.model.model_id, value: found.model.model_id, reason: 'the only model id found in the source' });
  }

  const declaredDeps = new Set((declaration.dependencies ?? []).map(depKey));
  for (const d of found.dependencies) {
    if (!declaredDeps.has(depKey(d))) {
      push(certain, { key: `dependencies:${depKey(d)}`, field: 'dependencies', change: 'added', value: d, reason: 'listed in the project\'s MCP settings' });
    }
  }

  const declaredCaps = new Set(declaration.capabilities ?? []);
  const promises = new Set(declaration.constraints ?? []);
  for (const c of found.capabilities) {
    if (promises.has(`no:${c.capability}`)) {
      // Reported even if ignored as a capability: a clash with a promise is
      // never something to silence by accident.
      conflicts.push({ key: `constraints:no:${c.capability}`, promise: `no:${c.capability}`, capability: c.capability, reason: c.reason });
    } else if (!declaredCaps.has(c.capability)) {
      push(likely, { key: `capabilities:${c.capability}`, field: 'capabilities', change: 'added', value: c.capability, reason: c.reason });
    }
  }

  return { inSync: !certain.length && !likely.length && !conflicts.length, certain, likely, conflicts, ignored };
}

/**
 * Apply findings to a declaration. Returns a new object without a signature;
 * sign it afterwards. Conflicts are not findings and cannot be applied.
 *
 * @param {object} declaration
 * @param {object[]} findings  Items from checkProject's certain or likely lists
 */
export function applyFindings(declaration, findings) {
  const d = structuredClone(declaration);
  for (const f of findings) {
    if (f.field === 'version') d.version = f.value;
    else if (f.field === 'model.provider') d.model = { ...(d.model ?? {}), provider: f.value };
    else if (f.field === 'model.model_id') d.model = { ...(d.model ?? {}), model_id: f.value };
    else if (f.field === 'dependencies') d.dependencies = [...(d.dependencies ?? []), f.value];
    else if (f.field === 'capabilities') d.capabilities = [...new Set([...(d.capabilities ?? []), f.value])];
    else throw new Error(`Cannot apply a finding for ${f.field}`);
  }
  if (d.identity) delete d.identity.signature;
  return d;
}

/**
 * Apply findings to the text of a declaration file, keeping its comments and
 * layout, and removing the now-stale signature. Returns the new text, unsigned:
 * sign it where the key lives — at start-up by provenance-middleware, or on the
 * developer's machine with `provenance sign`. Nothing here needs a key.
 *
 * @param {string} text        The file's current contents
 * @param {object[]} findings  Items from checkProject's certain or likely lists
 * @param {object} [options]
 * @param {boolean} [options.json]  The file is JSON rather than YAML
 * @returns {{ text: string, declaration: object }}
 */
export function updateDeclarationText(text, findings, { json = false } = {}) {
  if (json) {
    const updated = applyFindings(JSON.parse(text), findings);
    return { text: JSON.stringify(updated, null, 2) + '\n', declaration: updated };
  }
  const doc = YAML.parseDocument(text);
  if (doc.errors.length) throw new Error(doc.errors[0].message);
  const updated = applyFindings(doc.toJS(), findings);
  for (const field of new Set(findings.map((f) => f.field.split('.')[0]))) {
    doc.setIn([field], doc.createNode(updated[field]));
  }
  if (doc.hasIn(['identity', 'signature'])) doc.deleteIn(['identity', 'signature']);
  return { text: doc.toString(), declaration: updated };
}
