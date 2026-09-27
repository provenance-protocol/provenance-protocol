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
console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
