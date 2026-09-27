import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { generateProvenanceKeyPair, signDeclaration } from '../src/keygen.js';

const cli = new URL('../src/cli.js', import.meta.url).pathname;
const dir = mkdtempSync(join(tmpdir(), 'vaf-'));
let pass = 0, fail = 0;
const t = (name, ok, d = '') => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  ' + d}`); ok ? pass++ : fail++; };
const run = (args, env = {}) => {
  try { return { code: 0, out: execFileSync('node', [cli, ...args], { encoding: 'utf8', cwd: dir, env: { ...process.env, ...env } }) }; }
  catch (e) { return { code: e.status, out: String(e.stdout) + String(e.stderr) }; }
};

const org = generateProvenanceKeyPair();
const agent = generateProvenanceKeyPair();
const decl = { provenance: '0.2', name: 'HR Assistant', description: 'Answers staff questions.', provenance_id: 'provenance:domain:hr.corp.internal',
  identity: { public_key: agent.publicKey, algorithm: 'ed25519' } };
decl.identity.signature = signDeclaration(agent.privateKey, decl);
writeFileSync(join(dir, 'decl.json'), JSON.stringify(decl));

let r = run(['affiliate', 'decl.json', '--org', 'provenance:domain:corp.example', '--unit', 'HR', '--out', 'aff.json'], { PROVENANCE_ORG_PRIVATE_KEY: org.privateKey });
t('the organisation signs an affiliation', r.code === 0, r.out);

r = run(['verify', 'decl.json', '--from', 'https://nymbrink.example/delivered/hr.json', '--affiliation', 'aff.json', '--org-key', org.publicKey]);
t('served from elsewhere, an internal agent verifies through its operator’s affiliation', r.code === 0 && /vouched for by provenance:domain:corp.example \(HR\)/.test(r.out), r.out);

r = run(['verify', 'decl.json', '--from', 'https://nymbrink.example/delivered/hr.json', '--affiliation', 'aff.json', '--org-key', generateProvenanceKeyPair().publicKey]);
t('checked against another organisation’s key it fails', r.code === 1 && /does NOT check out/.test(r.out), r.out);

r = run(['verify', 'decl.json', '--from', 'https://nymbrink.example/delivered/hr.json']);
t('without the affiliation the wrong location still fails', r.code === 1, r.out);

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
