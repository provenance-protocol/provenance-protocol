import { checkPins, checkDeclaration, compareDeclarations, verifyDeclaration, verifyNotice, keyFingerprint } from '../src/index.js';
import { validateDeclaration, validateNotice } from '../src/validate.js';
import { generateProvenanceKeyPair, signDeclaration, signNotice } from '../src/keygen.js';

let pass = 0, fail = 0;
const t = (name, ok, d = '') => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  ' + d}`); ok ? pass++ : fail++; };

const k = generateProvenanceKeyPair();
const dep = { kind: 'mcp_server', url: 'https://www.npmjs.com/package/postmark-mcp', pin: { version: '1.0.15', integrity: 'sha512-3u4AbC==' } };
const decl = { provenance: '0.3', name: 'Mailer', description: 'Sends receipts.', provenance_id: 'provenance:domain:mail.example.com',
  dependencies: [dep, { kind: 'agent', provenance_id: 'provenance:domain:search.example.com' }],
  identity: { public_key: k.publicKey, algorithm: 'ed25519' } };
decl.identity.signature = signDeclaration(k.privateKey, decl);

t('a 0.3 declaration with pins is valid', validateDeclaration(decl).valid, JSON.stringify(validateDeclaration(decl).errors));
t('and its signature covers the whole declaration', (await verifyDeclaration(decl)).coverage === 'declaration');
t('a range is not a pin field: unknown pin keys are refused', !validateDeclaration({ ...decl, dependencies: [{ ...dep, pin: { range: '^1.0.0' } }] }).valid);
t('a 0.2 declaration may not carry a pin', !validateDeclaration({ ...decl, provenance: '0.2' }).valid);

const notice = { notice: '0.2', id: 'n-1', event: 'release', provenance_id: decl.provenance_id, key_fingerprint: await keyFingerprint(k.publicKey),
  issued_at: '2026-09-28T10:00:00Z', claims: { version: '4.2.0', declaration_digest: 'sha256:' + '0'.repeat(64),
    resolved: [{ url: dep.url, version: '1.0.16', integrity: 'sha512-3u4AbC==' }, { url: 'https://www.npmjs.com/package/left-pad', version: '1.3.0' }] } };
notice.signature = signNotice(k.privateKey, notice);
t('a 0.2 release notice with resolved is valid', validateNotice(notice).valid, JSON.stringify(validateNotice(notice).errors));
t('and verifies', (await verifyNotice(notice, { publicKey: k.publicKey })).valid);

const r = checkPins(decl, notice);
const by = Object.fromEntries(r.map((x) => [x.dependency, x]));
t('a shipped version other than the pin is a mismatch, naming the field', by[dep.url].result === 'mismatch' && by[dep.url].differs.join() === 'version', JSON.stringify(r));
t('something shipped but not declared is unpinned', by['https://www.npmjs.com/package/left-pad'].result === 'unpinned');
t('an unpinned declared dependency that was not reported is not listed', !by['provenance:domain:search.example.com']);
const ok2 = checkPins(decl, { claims: { resolved: [{ url: dep.url, version: '1.0.15', integrity: 'sha512-3u4AbC==' }] } });
t('what was pinned and shipped matches', ok2.find((x) => x.dependency === dep.url).result === 'match');
t('a pinned dependency missing from the build report is not_reported', checkPins(decl, { claims: { resolved: [] } })[0].result === 'not_reported');

const c = await checkDeclaration(decl, { requireLocation: false, requirePinned: true });
t('requirePinned refuses a declaration with an unpinned dependency', !c.allowed && /search\.example\.com/.test(c.reason), c.reason);

const unpin = { ...decl, dependencies: [{ ...dep, pin: undefined }, decl.dependencies[1]] };
delete unpin.dependencies[0].pin;
const ch = compareDeclarations(decl, unpin);
t('removing a pin is a weakening', ch.some((x) => x.field === 'dependencies' && x.change === 'modified' && x.direction === 'weakened'), JSON.stringify(ch));
t('adding a pin is a strengthening', compareDeclarations(unpin, decl).some((x) => x.direction === 'strengthened'));
const moved = { ...decl, dependencies: [{ ...dep, pin: { version: '1.0.16' } }, decl.dependencies[1]] };
t('moving a pin is reported, neutral', compareDeclarations(decl, moved).some((x) => x.field === 'dependencies' && x.direction === 'neutral'));

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
