import { checkDecisionBasis, declarationDigest } from '../src/verify.js';

let pass = 0, fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `  ${detail}`}`);
  ok ? pass++ : fail++;
};
const throws = async (fn, re) => { try { await fn(); return false; } catch (e) { return re.test(e.message); } };

const id = 'provenance:domain:agent.example';
const before = { provenance: '0.2', name: 'A', provenance_id: id, capabilities: ['read:web'], constraints: ['no:pii'],
  data: { categories: ['customer_content'], retention: 'P30D' }, identity: { public_key: 'K', signature: 'S' } };
const after = { ...before, data: { ...before.data, retention: 'P90D' } };
const decision = async (decl) => ({ kind: 'decision', subject: { provenance_id: id, declaration_digest: await declarationDigest(decl) },
  claims: { outcome: 'approved', use: 'support inbox triage', decided_at: '2026-09-01T10:00:00Z' } });

const d = await decision(before);
const cur = await checkDecisionBasis(d, before);
check(cur.basis === 'current' && cur.weakened.length === 0, 'unchanged declaration → current', JSON.stringify(cur));
check((await checkDecisionBasis(d, { ...before, identity: { public_key: 'K', signature: 'other' } })).basis === 'current', 'a new signature alone is not a new basis');

const sup = await checkDecisionBasis(d, after);
check(sup.basis === 'superseded' && sup.changes === null && sup.weakened === null, 'changed, basis not held → superseded, no changes listed', JSON.stringify(sup));
const full = await checkDecisionBasis(d, after, before);
check(full.basis === 'superseded' && full.weakened.join() === 'data.retention', 'basis held → lists what weakened since', JSON.stringify(full));
check(full.changes.some((c) => c.field === 'data.retention' && c.direction === 'weakened'), 'the changes are compareDeclarations\' own');

check((await checkDecisionBasis(d, null)).basis === 'unknown', 'no current declaration → unknown');
check((await checkDecisionBasis({ kind: 'decision', subject: { provenance_id: id } }, after)).basis === 'unknown', 'no digest → unknown');
check(await throws(() => checkDecisionBasis(d, after, after), /not the one the attestation names/), 'a basis declaration that is not the named one is refused, never compared');
check(await throws(() => checkDecisionBasis(d, { ...after, provenance_id: 'provenance:domain:other.example' }), /not the attestation's subject/), 'another agent\'s declaration is refused');

// A correctly hashed earlier declaration of another agent is not this agent's history (audit PP-BASIS-01).
const other = { ...before, provenance_id: 'provenance:domain:other.example' };
const crossed = { ...d, subject: { ...d.subject, declaration_digest: await declarationDigest(other) } };
check(await throws(() => checkDecisionBasis(crossed, after, other), /basis declaration is for provenance:domain:other.example/), 'a correctly hashed basis for another agent is refused');
console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
