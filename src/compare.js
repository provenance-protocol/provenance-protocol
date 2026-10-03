/**
 * provenance-protocol — compare two states of a declaration
 *
 * Lists what changed between two parsed declarations, field by field, and
 * classifies each change as weakening, strengthening or neutral for someone
 * relying on the agent. Deterministic, offline, dependency-free: any two
 * watchers given the same declarations report the same changes.
 *
 *   import { compareDeclarations } from 'provenance-protocol';
 *   const changes = compareDeclarations(before, after);
 *   changes.filter((c) => c.direction === 'weakened');
 *
 * The rules are in SPEC.md, "Comparing declarations".
 */

const TRAINING_ORDER = ['none', 'opt_in', 'opt_out', 'yes'];
const IGNORED = new Set(['identity.signature']);

function isObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function same(a, b) {
  return JSON.stringify(canon(a)) === JSON.stringify(canon(b));
}

function canon(v) {
  if (Array.isArray(v)) return v.map(canon);
  if (isObject(v)) return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])]));
  return v;
}

/** Approximate length of an ISO 8601 duration in days, or null. */
export function durationDays(value) {
  if (value === 'none') return 0;
  if (typeof value !== 'string') return null;
  const m = /^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/.exec(value);
  if (!m || value === 'P' || value.endsWith('T')) return null;
  const [, y, mo, w, d, h, mi, s] = m.map((x) => Number(x ?? 0));
  return y * 365 + mo * 30 + w * 7 + d + h / 24 + mi / 1440 + s / 86400;
}

// Keys that identify an item in a list of objects, so an edited entry reads
// as "modified" rather than as one removal plus one addition.
const LIST_KEYS = {
  subprocessors: (x) => x?.name,
  dependencies: (x) => x?.provenance_id ?? x?.url,
  limits: (x) => (x?.applies_to && x?.unit ? `${x.applies_to}|${x.unit}|${x.per ?? ''}` : undefined),
  certifications: (x) => x?.standard,
  delegates: (x) => x?.provenance_id,
  skills: (x) => x?.id,
};

// Direction for list items being added or removed, by field.
//   'more-is-weaker'  adding weakens (more power, more parties, more data)
//   'more-is-stronger' adding strengthens (more promises, more checks)
const LIST_DIRECTION = {
  constraints: 'more-is-stronger',
  capabilities: 'more-is-weaker',
  'data.categories': 'more-is-weaker',
  'data.regions': 'more-is-weaker',
  subprocessors: 'more-is-weaker',
  dependencies: 'more-is-weaker',
  delegates: 'more-is-weaker',
  skills: 'more-is-weaker',
  'oversight.approval_required': 'more-is-stronger',
  limits: 'more-is-stronger',
  certifications: 'more-is-stronger',
};

// Removing a region or a dependency narrows exposure but promises nothing, so
// it is recorded as neutral rather than as a strengthening.
const REMOVAL_NEUTRAL = new Set(['data.regions', 'dependencies']);

function listDirection(field, change) {
  const rule = LIST_DIRECTION[field];
  if (!rule) return 'neutral';
  if (change === 'removed' && REMOVAL_NEUTRAL.has(field)) return 'neutral';
  const adding = change === 'added';
  return (rule === 'more-is-weaker') === adding ? 'weakened' : 'strengthened';
}

function scalarDirection(field, from, to) {
  switch (field) {
    case 'data.retention': {
      const a = durationDays(from), b = durationDays(to);
      if (a === null || b === null) return 'neutral';
      return b > a ? 'weakened' : b < a ? 'strengthened' : 'neutral';
    }
    case 'data.training_use': {
      const a = TRAINING_ORDER.indexOf(from), b = TRAINING_ORDER.indexOf(to);
      if (a < 0 || b < 0) return 'neutral';
      return b > a ? 'weakened' : b < a ? 'strengthened' : 'neutral';
    }
    case 'oversight.pausable_by_customer':
      return from === true && to !== true ? 'weakened' : to === true && from !== true ? 'strengthened' : 'neutral';
    case 'changes.notice_period': {
      const a = durationDays(from) ?? 0, b = durationDays(to) ?? 0;
      return b < a ? 'weakened' : b > a ? 'strengthened' : 'neutral';
    }
    case 'identity.public_key':
    case 'provenance_id':
      // Not a promise changing, but everything rests on it: a changed key is a
      // rotation or an impostor until a rotation notice says which.
      return 'weakened';
    default:
      return 'neutral';
  }
}

function limitDirection(from, to) {
  if (typeof from?.max === 'number' && typeof to?.max === 'number') {
    return to.max > from.max ? 'weakened' : to.max < from.max ? 'strengthened' : 'neutral';
  }
  return 'neutral';
}

// A dependency losing its pin is looser than before; gaining one is tighter;
// moving a pin to another version is normal, and reported, but neutral.
function pinDirection(from, to) {
  const had = from?.pin && typeof from.pin === 'object', has = to?.pin && typeof to.pin === 'object';
  return had && !has ? 'weakened' : !had && has ? 'strengthened' : 'neutral';
}

function subprocessorDirection(from, to) {
  const before = new Set([...(from?.regions ?? []), ...(from?.data_categories ?? [])]);
  const after = [...(to?.regions ?? []), ...(to?.data_categories ?? [])];
  return after.some((x) => !before.has(x)) ? 'weakened' : 'neutral';
}

function compareLists(field, a = [], b = [], out) {
  const keyOf = LIST_KEYS[field];
  if (keyOf && [...a, ...b].every((x) => isObject(x) && keyOf(x) !== undefined)) {
    const before = new Map(a.map((x) => [keyOf(x), x]));
    const after = new Map(b.map((x) => [keyOf(x), x]));
    for (const [k, x] of before) {
      if (!after.has(k)) out.push({ field, change: 'removed', value: x, direction: listDirection(field, 'removed') });
    }
    for (const [k, x] of after) {
      if (!before.has(k)) {
        out.push({ field, change: 'added', value: x, direction: listDirection(field, 'added') });
      } else if (!same(before.get(k), x)) {
        const direction =
          field === 'limits' ? limitDirection(before.get(k), x)
          : field === 'subprocessors' ? subprocessorDirection(before.get(k), x)
          : field === 'dependencies' ? pinDirection(before.get(k), x)
          : 'neutral';
        out.push({ field, change: 'modified', from: before.get(k), to: x, direction });
      }
    }
    return;
  }

  const before = a.map((x) => JSON.stringify(canon(x)));
  const after = b.map((x) => JSON.stringify(canon(x)));
  a.forEach((x, i) => {
    // Every region withdrawn at once leaves where data goes unstated: a weakening, not a narrowing.
    const withdrawn = field === 'data.regions' && after.length === 0;
    if (!after.includes(before[i])) out.push({ field, change: 'removed', value: x, direction: withdrawn ? 'weakened' : listDirection(field, 'removed') });
  });
  b.forEach((x, i) => {
    if (!before.includes(after[i])) out.push({ field, change: 'added', value: x, direction: listDirection(field, 'added') });
  });
}

function walk(path, a, b, out) {
  if (IGNORED.has(path) || same(a, b)) return;

  if (Array.isArray(a) || Array.isArray(b)) {
    if ((a === undefined || Array.isArray(a)) && (b === undefined || Array.isArray(b))) {
      compareLists(path, a ?? [], b ?? [], out);
      return;
    }
  }

  if ((a === undefined || isObject(a)) && (b === undefined || isObject(b)) && (isObject(a) || isObject(b))) {
    const keys = new Set([...Object.keys(a ?? {}), ...Object.keys(b ?? {})]);
    for (const k of [...keys].sort()) walk(path ? `${path}.${k}` : k, a?.[k], b?.[k], out);
    return;
  }

  if (a === undefined) {
    out.push({ field: path, change: 'added', value: b, direction: addedScalarDirection(path, b) });
  } else if (b === undefined) {
    out.push({ field: path, change: 'removed', value: a, direction: removedScalarDirection(path, a) });
  } else {
    out.push({ field: path, change: 'modified', from: a, to: b, direction: scalarDirection(path, a, b) });
  }
}

// A commitment that disappears entirely is a weakening — what was promised is
// now unknown — and one that appears is a strengthening. Everything else added
// or removed as a whole is neutral.
function removedScalarDirection(path, value) {
  if (path === 'changes.notice_period' || (path === 'oversight.pausable_by_customer' && value === true)) return 'weakened';
  // Any stated limit on training or retention, withdrawn, leaves the customer with no promise at all.
  if (path === 'data.training_use' && value !== 'yes') return 'weakened';
  if (path === 'data.retention') return 'weakened';
  if (path === 'identity.public_key' || path === 'provenance_id') return 'weakened';
  return 'neutral';
}

function addedScalarDirection(path, value) {
  if (path === 'changes.notice_period' || (path === 'oversight.pausable_by_customer' && value === true)) return 'strengthened';
  if (path === 'data.training_use' && value !== 'yes') return 'strengthened';
  if (path === 'data.retention') return 'strengthened';
  return 'neutral';
}

function announced(change, before) {
  const pending = before?.changes?.pending;
  if (!Array.isArray(pending)) return false;
  return pending.some(
    (p) =>
      p?.field === change.field &&
      p?.change === change.change &&
      (p.value === undefined || same(p.value, change.value ?? change.to))
  );
}

/**
 * Every difference between two parsed declarations.
 *
 * Each change is { field, change, value | from/to, direction, announced }:
 *   field      dotted path, e.g. 'constraints' or 'data.retention'
 *   change     'added' | 'removed' | 'modified'
 *   direction  'weakened' | 'strengthened' | 'neutral' — for someone relying on the agent
 *   announced  true when `before.changes.pending` listed it in advance
 *
 * The signature is ignored: it changes whenever anything else does. The
 * `changes.pending` list itself is compared like any other field.
 *
 * @param {object} before
 * @param {object} after
 * @returns {Array<object>}
 */
export function compareDeclarations(before, after) {
  if (!isObject(before) || !isObject(after)) throw new TypeError('Both declarations must be parsed objects');
  const out = [];
  walk('', before, after, out);
  return out.map((c) => ({ ...c, announced: c.direction === 'weakened' ? announced(c, before) : false }));
}
