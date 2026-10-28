import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

const V = JSON.parse(readFileSync(new URL('../test-vectors/attestations-0.1.json', import.meta.url), 'utf8'));
const cli = new URL('../src/cli.js', import.meta.url).pathname;
const dir = mkdtempSync(join(tmpdir(), 'va-'));
let pass = 0, fail = 0;
const t = (name, ok, d = '') => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  ' + d}`); ok ? pass++ : fail++; };
const run = (file, key) => {
  try { return { code: 0, out: execFileSync('node', [cli, 'verify-attestation', file, '--issuer-key', key], { encoding: 'utf8' }) }; }
  catch (e) { return { code: e.status, out: String(e.stdout) + String(e.stderr) }; }
};

// A valid vector is only valid at its own `now`; outside the window it must read as expired, never invalid.
const genuine = join(dir, 'a.json'); writeFileSync(genuine, JSON.stringify(V.vectors.find((v) => v.id === 'attestation-valid').attestation));
let r = run(genuine, V.issuer.public_key);
t('a genuine stamp reads as genuine (valid or, past its date, expired — never invalid)', r.code === 0 && /valid|expired/.test(r.out), r.out);
const altered = join(dir, 'b.json'); writeFileSync(altered, JSON.stringify(V.vectors.find((v) => v.id === 'attestation-claims-tampered').attestation));
r = run(altered, V.issuer.public_key);
t('an altered stamp is INVALID and fails', r.code === 1 && /INVALID/.test(r.out), r.out);
r = run(genuine, V.other_key.public_key);
t('checked against the wrong key it is INVALID', r.code === 1 && /INVALID/.test(r.out), r.out);
// A decision's basis is reported beside the result and never changes it: a subject that cannot be reached reads "unknown".
const { signAttestation } = await import('../src/keygen.js');
const { generateProvenanceKeyPair } = await import('../src/keygen.js');
const { keyFingerprint } = await import('../src/verify.js');
const kp = generateProvenanceKeyPair();
const now = new Date();
const dec = { attestation: '0.1', id: 'dec-1', kind: 'decision',
  issuer: { provenance_id: 'provenance:domain:buyer.invalid', key_fingerprint: await keyFingerprint(kp.publicKey) },
  subject: { provenance_id: 'provenance:domain:agent.invalid', declaration_digest: 'sha256:' + '0'.repeat(64) },
  issued_at: new Date(now - 60_000).toISOString().replace(/\.\d{3}Z$/, 'Z'), valid_until: new Date(+now + 86_400_000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
  scope: 'An approval for one use, made against the stated declaration.', claims: { outcome: 'approved', use: 'triage', decided_at: now.toISOString(), decided_by: 'A buyer' } };
dec.signature = signAttestation(kp.privateKey, dec);
const decFile = join(dir, 'd.json'); writeFileSync(decFile, JSON.stringify(dec));
r = run(decFile, kp.publicKey);
t('a decision whose subject cannot be reached is valid, with its basis "unknown"', r.code === 0 && /valid/.test(r.out) && /Basis:\s+unknown/.test(r.out.replace(/\x1b\[[0-9;]*m/g, "")), r.out);
// The basis lookup is bounded (audit PP-BASIS-02), and a 0.1 identity-only signature is not a basis (audit PP-BASIS-03).
const preload = new URL('./fixtures/basis-fetch.mjs', import.meta.url).href;
const runWith = (env) => {
  const started = Date.now();
  try { return { code: 0, ms: Date.now() - started, out: execFileSync('node', ['--import', preload, cli, 'verify-attestation', decFile, '--issuer-key', kp.publicKey],
    { encoding: 'utf8', timeout: 15_000, env: { ...process.env, PROVENANCE_BASIS_TIMEOUT_MS: '500', ...env } }).replace(/\x1b\[[0-9;]*m/g, '') }; }
  catch (e) { return { code: e.status, ms: Date.now() - started, out: String(e.stdout) + String(e.stderr) + (e.signal ? ` signal ${e.signal}` : '') }; }
};
for (const mode of ['stall', 'stall-body']) {
  r = runWith({ BASIS_FETCH: mode });
  t(`a subject lookup that ${mode === 'stall' ? 'never answers' : 'never finishes its body'} ends as valid, basis unknown, and the command exits`,
    r.code === 0 && /Result:\s+valid/.test(r.out) && /Basis:\s+unknown — .*no complete answer/.test(r.out), r.out);
}
const legacyKp = generateProvenanceKeyPair();
const { signForProvenance } = await import('../src/keygen.js');
const { declarationDigest } = await import('../src/verify.js');
const legacy = { provenance: '0.1', name: 'Legacy', provenance_id: 'provenance:domain:agent.invalid', capabilities: ['read:web'],
  identity: { public_key: legacyKp.publicKey, algorithm: 'ed25519' } };
legacy.identity.signature = signForProvenance(legacyKp.privateKey, legacy.provenance_id, legacyKp.publicKey);
const pinned = { ...dec, id: 'dec-2', subject: { ...dec.subject, declaration_digest: await declarationDigest(legacy) } };
delete pinned.signature; pinned.signature = signAttestation(kp.privateKey, pinned);
writeFileSync(decFile, JSON.stringify(pinned));
r = runWith({ BASIS_FETCH: 'json', BASIS_FETCH_BODY: JSON.stringify(legacy) });
t('a current declaration signed for its identity only (0.1) gives basis unknown, never current', r.code === 0 && /Result:\s+valid/.test(r.out) && /Basis:\s+unknown — .*identity only/.test(r.out), r.out);
console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
