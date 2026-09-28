#!/usr/bin/env node
/**
 * provenance — Provenance Protocol CLI (the `provenance` bin of provenance-protocol)
 *
 * Offline — no service involved:
 *   provenance init [--domain <host>] [--yes]
 *   provenance check [file] [--update] [--strict]
 *   provenance keygen
 *   provenance sign [file]
 *   provenance verify <file | url | provenance_id> [--from <url>] [--affiliation <file | url>]
 *   provenance validate [file]
 *   provenance verify-attestation <file | url> [--issuer-key <base64>]
 *   provenance affiliate <declaration> --org <org_provenance_id> [--unit <name>]
 *
 * Against an index you name (--index <url> or PROVENANCE_INDEX_URL):
 *   provenance register --id <id> --url <url> [options]
 *   provenance status <id>
 *   provenance revoke --id <id> [--private-key <key>]
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as nodeSign } from 'crypto';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import { createRequire } from 'module';
import YAML from 'yaml';
import { verifyDeclaration, checkDeclaration, locateDeclaration, keyFingerprint, verifyAttestation } from './verify.js';
import { validateDeclaration } from './validate.js';
import { signDeclaration, signAttestation } from './keygen.js';
import { detectProject, runInit } from './init.js';
import { checkProject, updateDeclarationText, IGNORE_FILE } from './check.js';
import { createInterface } from 'readline/promises';

const VERSION = createRequire(import.meta.url)('../package.json').version;

// ── Colours ───────────────────────────────────────────────────────────────────

const c = {
  reset: '\x1b[0m', dim: '\x1b[2m', bold: '\x1b[1m',
  green: '\x1b[32m', amber: '\x1b[33m', red: '\x1b[31m', white: '\x1b[97m',
};
const ok  = s => `${c.green}✓${c.reset} ${s}`;
const err = s => `${c.red}✗${c.reset} ${s}`;
const dim = s => `${c.dim}${s}${c.reset}`;
const hi  = s => `${c.white}${c.bold}${s}${c.reset}`;
const amb = s => `${c.amber}${s}${c.reset}`;

// ── Arg parsing ───────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = { _: [] };
  let i = 0;
  while (i < argv.length) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith('--')) { args[key] = next; i += 2; }
      else { args[key] = true; i++; }
    } else { args._.push(a); i++; }
  }
  return args;
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

function generateKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return {
    publicKey:  Buffer.from(publicKey).toString('base64'),
    privateKey: Buffer.from(privateKey).toString('base64'),
  };
}

function signMessage(privateKeyBase64, message) {
  const key = createPrivateKey({ key: Buffer.from(privateKeyBase64, 'base64'), format: 'der', type: 'pkcs8' });
  return nodeSign(null, Buffer.from(message, 'utf8'), key).toString('base64');
}

function derivePublicKey(privateKeyBase64) {
  const priv = createPrivateKey({ key: Buffer.from(privateKeyBase64, 'base64'), format: 'der', type: 'pkcs8' });
  return Buffer.from(createPublicKey(priv).export({ type: 'spki', format: 'der' })).toString('base64');
}

// An index is one application of the standard, not part of it. Which one to
// trust is the user's decision, so there is no default.
function indexUrl(args) {
  const url = args.index || process.env.PROVENANCE_INDEX_URL || process.env.PROVENANCE_API_URL;
  if (!url || url === true) {
    console.error(err('This command talks to an index. Name the one you use with --index <url> or PROVENANCE_INDEX_URL.'));
    console.error(dim('Nothing was sent. keygen, sign, verify and validate need no index.'));
    process.exit(2);
  }
  return String(url).replace(/\/$/, '');
}

function readDocument(file) {
  const path = resolve(process.cwd(), file);
  if (!existsSync(path)) { console.error(err(`File not found: ${path}`)); process.exit(2); }
  const text = readFileSync(path, 'utf8');
  const json = /\.json$/i.test(path);
  try {
    return { path, text, json, doc: json ? null : YAML.parseDocument(text), value: json ? JSON.parse(text) : parseYaml(text) };
  } catch (e) {
    console.error(err(`${file} could not be parsed: ${e.message}`));
    process.exit(1);
  }
}

// Plain JSON values only: a YAML timestamp parsed as a Date would make the
// signature depend on how the Date is serialised, so dates stay strings.
function parseYaml(text) {
  const doc = YAML.parseDocument(text, { schema: 'core' });
  if (doc.errors.length) throw new Error(doc.errors[0].message);
  return doc.toJS();
}

// ── Commands ──────────────────────────────────────────────────────────────────

async function cmdKeygen() {
  console.log(`\n${amb('Generating Ed25519 keypair...')}\n`);
  const { publicKey, privateKey } = generateKeyPair();

  console.log(`${hi('Public key')} ${dim('(add to PROVENANCE.yml identity.public_key)')}`);
  console.log(`${c.green}${publicKey}${c.reset}\n`);
  console.log(`${hi('Private key')} ${dim('(store as PROVENANCE_PRIVATE_KEY — never commit)')}`);
  console.log(`${c.amber}${privateKey}${c.reset}\n`);
  console.log(dim('─'.repeat(60)));
  console.log(dim('Add to your environment:'));
  console.log(`  PROVENANCE_PRIVATE_KEY=${privateKey}\n`);
  console.log(dim('Add to PROVENANCE.yml:'));
  console.log(`  identity:`);
  console.log(`    public_key: "${publicKey}"`);
  console.log(`    algorithm: ed25519\n`);
}

async function cmdInit(args) {
  const dir = process.cwd();
  const domain = typeof args.domain === 'string' ? args.domain : undefined;
  const yes = args.yes === true;

  const found = detectProject(dir, { domain });
  console.log(`\n${amb('Reading your project')} ${dim('(nothing leaves this machine)')}\n`);
  console.log(`  ${dim('name:')}          ${found.name ?? dim('—')}`);
  console.log(`  ${dim('identifier:')}    ${found.provenanceId ?? dim('— (you will be asked)')}`);
  console.log(`  ${dim('AI provider:')}   ${found.model ? `${found.model.provider}${found.model.model_id ? ' · ' + found.model.model_id : ''}` : dim('none detected')}`);
  if (found.modelIdsSeen.length > 1) console.log(`  ${dim('models seen:')}   ${found.modelIdsSeen.join(', ')} ${dim('(add the one you use to model.model_id)')}`);
  for (const c of found.capabilities) console.log(`  ${dim('can:')}           ${c.capability} ${dim('— ' + c.reason)}`);
  for (const d of found.dependencies) console.log(`  ${dim('depends on:')}    ${d.url} ${dim('— ' + d.purpose)}`);
  console.log();

  let rl;
  const ask = yes ? undefined : async (question) => {
    rl ??= createInterface({ input: process.stdin, output: process.stdout });
    return rl.question(`  ${question}`);
  };
  if (!yes && !process.stdin.isTTY) {
    console.error(err('init asks a few questions. Run it in a terminal, or pass --yes to fill in only what your project shows.'));
    process.exit(2);
  }

  let result;
  try {
    result = await runInit(dir, { ask, yes, domain, force: args.force === true });
  } catch (e) {
    rl?.close();
    console.error(err(e.message));
    process.exit(1);
  }
  rl?.close();

  const d = result.declaration;
  console.log(`\n${ok('PROVENANCE.yml written and signed — the signature covers every field')}`);
  if (d.constraints?.length) console.log(`  ${dim('promises:')} ${d.constraints.join(', ')}`);
  if (result.keyCreated) {
    console.log(`\n${ok('New key saved to .provenance-key (added to .gitignore)')}`);
    console.log(`  ${dim('Keep it safe. Your service signs with it: set PROVENANCE_PRIVATE_KEY to its contents.')}`);
  }
  if (result.notStated.length) {
    console.log(`\n${amb('Not stated yet')} ${dim('(optional — add when a buyer asks, then run `provenance sign`):')}`);
    for (const n of result.notStated) console.log(`  ${dim('·')} ${n}`);
    if (yes && result.suggestions.promises.length) {
      console.log(`  ${dim('Promises your code would support:')} ${result.suggestions.promises.map((p) => p.constraint).join(', ')}`);
    }
  }
  console.log(`\n${amb('Next — pick one way to publish it:')}`);
  if (d.provenance_id?.startsWith('provenance:github:')) {
    console.log(`  ${dim('·')} commit PROVENANCE.yml to the repository root`);
  }
  console.log(`  ${dim('·')} or serve it from your service: ${hi("app.use(provenance({ declaration: './PROVENANCE.yml' }))")} ${dim('(npm i provenance-middleware)')}`);
  console.log(`\n${amb('Keep it honest on every build')} ${dim('(.github/workflows/provenance.yml):')}`);
  console.log(dim('  - uses: provenance-protocol/provenance-action@v1'));
  console.log();
}

// The key used to sign: the environment, or the file init creates.
function findPrivateKey(args) {
  if (typeof args['private-key'] === 'string') return args['private-key'];
  if (process.env.PROVENANCE_PRIVATE_KEY) return process.env.PROVENANCE_PRIVATE_KEY;
  const f = resolve(process.cwd(), '.provenance-key');
  return existsSync(f) ? readFileSync(f, 'utf8').trim() : null;
}

async function cmdCheck(args) {
  const file = args._[1] || 'PROVENANCE.yml';
  const { path, json, doc, value } = readDocument(file);
  const r = checkProject(process.cwd(), value);
  const show = (f) => {
    const what = f.field === 'dependencies' ? (f.value.provenance_id ?? f.value.url) : f.value;
    return `${f.field}: ${f.change === 'modified' ? `${f.from} → ` : '+ '}${what}  ${dim('(' + f.reason + ')')}`;
  };

  console.log(`\n${amb('Checking')} ${hi(file)} ${dim('against this project — read locally, nothing is sent anywhere')}\n`);
  for (const c of r.conflicts) {
    console.log(`${err(`Your code conflicts with a promise: ${c.promise}`)} ${dim('— ' + c.reason)}`);
    console.log(`  ${dim('Either change the code, or remove the promise yourself and re-sign. Buyers are told when a promise is dropped.')}`);
  }
  if (r.inSync) {
    console.log(ok('Passport matches the project'));
    if (r.ignored) console.log(dim(`  (${r.ignored} finding(s) ignored via ${IGNORE_FILE})`));
    console.log();
    return;
  }

  if (!args.update) {
    for (const f of r.certain) console.log(`  ${amb('update:')}  ${show(f)}`);
    for (const f of r.likely) console.log(`  ${amb('confirm:')} ${show(f)}`);
    if (r.certain.length || r.likely.length) {
      console.log(`\n  ${dim('Run')} ${hi('npx provenance-protocol check --update')} ${dim('to apply, or list a finding in ' + IGNORE_FILE + ' to leave it alone.')}`);
    }
    console.log();
    if (args.strict) process.exit(1);
    return;
  }

  // --update: certain facts are applied; each likely one is asked about.
  const accepted = [...r.certain];
  const ignoreNew = [];
  if (r.likely.length) {
    if (!process.stdin.isTTY) {
      for (const f of r.likely) console.log(`  ${amb('not applied (needs a person):')} ${show(f)}`);
    } else {
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      for (const f of r.likely) {
        const a = (await rl.question(`  ${show(f)}\n  Add it? [y]es / [n]o / [i]gnore from now on: `)).trim().toLowerCase();
        if (a === 'y' || a === 'yes') accepted.push(f);
        else if (a === 'i' || a === 'ignore') ignoreNew.push(f.key);
      }
      rl.close();
    }
  }
  if (ignoreNew.length) {
    const ig = resolve(process.cwd(), IGNORE_FILE);
    const prev = existsSync(ig) ? readFileSync(ig, 'utf8') : '# Findings from `provenance check` reviewed and left alone\n';
    writeFileSync(ig, prev + (prev.endsWith('\n') ? '' : '\n') + ignoreNew.join('\n') + '\n');
    console.log(ok(`${ignoreNew.length} finding(s) added to ${IGNORE_FILE}`));
  }
  if (!accepted.length) { console.log(dim('\n  Nothing applied.\n')); if (args.strict && r.conflicts.length) process.exit(1); return; }

  const key = findPrivateKey(args);
  if (!key) { console.error(err('No key to sign with: set PROVENANCE_PRIVATE_KEY, or keep .provenance-key here')); process.exit(2); }
  const { text: newText, declaration: updated } = updateDeclarationText(readFileSync(path, 'utf8'), accepted, { json });
  if (updated.identity?.public_key && derivePublicKey(key) !== updated.identity.public_key) {
    console.error(err('This key does not match identity.public_key — nothing was changed.'));
    process.exit(1);
  }
  const signature = signDeclaration(key, updated);
  if (json) {
    writeFileSync(path, JSON.stringify({ ...updated, identity: { ...updated.identity, signature } }, null, 2) + '\n');
  } else {
    const d2 = YAML.parseDocument(newText);
    d2.setIn(['identity', 'signature'], signature);
    writeFileSync(path, d2.toString());
  }
  const back = await verifyDeclaration(readDocument(file).value);
  if (!back.valid) { console.error(err(`Wrote ${file} but it does not verify: ${back.reason}`)); process.exit(1); }
  for (const f of accepted) console.log(ok(show(f)));
  console.log(ok(`${file} updated and signed\n`));
  if (args.strict && r.conflicts.length) process.exit(1);
}

async function cmdSign(args) {
  const file = args._[1] || 'PROVENANCE.yml';
  const privateKey = args['private-key'] || process.env.PROVENANCE_PRIVATE_KEY;
  if (!privateKey) { console.error(err('PROVENANCE_PRIVATE_KEY (or --private-key) is required to sign')); process.exit(2); }

  const { path, json, doc, value } = readDocument(file);
  if (value?.provenance !== '0.2' && value?.provenance !== '0.3') {
    console.error(err(`Only spec 0.2 and 0.3 declarations are signed here (this one says ${JSON.stringify(value?.provenance ?? null)}).`));
    console.error(dim('0.1 signatures do not cover capabilities or constraints. Set provenance: "0.2" and run again.'));
    process.exit(1);
  }

  let publicKey;
  try { publicKey = derivePublicKey(privateKey); }
  catch { console.error(err('Private key is not a base64 PKCS8 Ed25519 key')); process.exit(2); }

  const declared = value.identity?.public_key;
  if (declared && declared !== publicKey) {
    console.error(err('identity.public_key in the file does not belong to this private key.'));
    console.error(dim('Refusing to sign: the result would never verify. If you are rotating keys, replace public_key first.'));
    process.exit(1);
  }

  const identity = { ...(value.identity ?? {}), public_key: publicKey, algorithm: 'ed25519' };
  delete identity.signature;
  const unsigned = { ...value, identity };
  const signature = signDeclaration(privateKey, unsigned);

  if (json) {
    writeFileSync(path, JSON.stringify({ ...unsigned, identity: { ...identity, signature } }, null, 2) + '\n');
  } else {
    // Edit the document in place so comments and layout survive.
    doc.setIn(['identity', 'public_key'], publicKey);
    doc.setIn(['identity', 'algorithm'], 'ed25519');
    doc.setIn(['identity', 'signature'], signature);
    writeFileSync(path, doc.toString());
  }

  // Read back what was written and verify it, so a write that went wrong
  // cannot be reported as a success.
  const check = await verifyDeclaration(readDocument(file).value);
  if (!check.valid) { console.error(err(`Wrote ${file}, but it does not verify: ${check.reason}`)); process.exit(1); }
  console.log(ok(`Signed ${file} — covers the whole declaration`));
  console.log(`  ${dim('key fingerprint:')} ${check.fingerprint}\n`);
}

async function cmdVerify(args) {
  const target = args._[1] || 'PROVENANCE.yml';
  let value, retrievedFrom = typeof args.from === 'string' ? args.from : undefined;

  if (/^provenance:/.test(target) || /^https?:\/\//.test(target)) {
    const url = /^provenance:/.test(target) ? locateDeclaration(target) : target;
    if (!url) {
      console.error(err(`No standard location for ${target}. Pass the declaration's URL instead.`));
      process.exit(2);
    }
    let text;
    try {
      const res = await fetch(url, { redirect: 'error' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      text = await res.text();
    } catch (e) {
      console.error(err(`Could not fetch ${url}: ${e.message}`));
      console.error(dim('Nothing was verified. This is not a verification failure.'));
      process.exit(2);
    }
    try { value = /\.json($|\?)/i.test(url) ? JSON.parse(text) : parseYaml(text); }
    catch (e) { console.error(err(`${url} could not be parsed: ${e.message}`)); process.exit(1); }
    retrievedFrom = url;
  } else {
    value = readDocument(target).value;
  }

  const r = await verifyDeclaration(value, { retrievedFrom });

  // An internal agent's operator vouches for it instead of a public location.
  let vouched = null;
  if (typeof args.affiliation === 'string') {
    let text;
    try {
      if (/^https?:\/\//.test(args.affiliation)) {
        const res = await fetch(args.affiliation, { redirect: 'error' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        text = await res.text();
      } else text = readFileSync(resolve(process.cwd(), args.affiliation), 'utf8');
    } catch (e) { console.error(err(`Could not read the affiliation ${args.affiliation}: ${e.message}`)); process.exit(2); }
    let att;
    try { att = JSON.parse(text); } catch { console.error(err('The affiliation is not JSON')); process.exit(1); }
    const org = typeof args['org-key'] === 'string' ? { key: args['org-key'] } : await issuerKey(att?.issuer?.provenance_id);
    const chk = await checkDeclaration(value, { retrievedFrom, affiliation: { attestation: att, issuerPublicKey: org.key } });
    // Served from its own location, the affiliation is not needed; otherwise it must hold on its own.
    if (chk.anchor !== 'location') {
      vouched = chk.anchor === 'affiliation' ? { org: att.issuer.provenance_id, unit: att.claims?.unit ?? null }
        : { error: chk.reason ?? 'the affiliation does not cover this declaration' };
    }
  }

  console.log();
  console.log(`${dim('Provenance id:')}  ${r.provenanceId ?? dim('none')}`);
  console.log(`${dim('Signature:')}      ${r.valid ? c.green + 'valid' : r.signed ? c.red + 'INVALID' : c.amber + 'none'}${c.reset}`);
  console.log(`${dim('Covers:')}         ${r.coverage === 'declaration' ? 'the whole declaration' : r.coverage === 'identity' ? c.amber + 'identity only (0.1) — constraints not protected' + c.reset : dim('—')}`);
  console.log(`${dim('Location:')}       ${r.location === 'match' ? c.green + 'matches its id' : r.location === 'mismatch' ? c.red + 'does NOT match its id' : c.amber + (retrievedFrom ? 'could not be checked' : 'not checked (local file; pass --from <url>)')}${c.reset}`);
  if (r.fingerprint) console.log(`${dim('Key fingerprint:')} ${r.fingerprint}`);
  if (vouched) console.log(`${dim('Operator:')}       ${vouched.error ? c.red + 'affiliation does NOT check out: ' + vouched.error : c.green + 'vouched for by ' + vouched.org + (vouched.unit ? ` (${vouched.unit})` : '') + c.reset + dim(' — stands in for the location check')}${c.reset}`);
  if (r.reason) console.log(`\n${dim(r.reason)}`);
  console.log();

  if (!r.valid) process.exit(1);
  if (vouched) process.exit(vouched.error ? 1 : 0);
  if (r.location === 'mismatch') process.exit(1);
}

/** An organisation's or issuer's key, from its own declaration, verified at its own location. */
async function issuerKey(issuer) {
  const url = issuer ? locateDeclaration(issuer) : null;
  if (!url) { console.error(err(`Cannot locate the declaration for ${issuer ?? '(no issuer)'}`)); process.exit(2); }
  let decl;
  try {
    const res = await fetch(url, { redirect: 'error' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = await res.text();
    decl = /\.json($|\?)/.test(url) ? JSON.parse(body) : parseYaml(body);
  } catch (e) { console.error(err(`Could not fetch ${issuer}'s declaration at ${url}: ${e.message}`)); process.exit(2); }
  const v = await verifyDeclaration(decl, { retrievedFrom: url });
  if (!v.valid || v.location !== 'match' || v.provenanceId !== issuer) {
    console.error(err(`${issuer}'s own declaration does not check out (${v.reason ?? 'location or id mismatch'}) — its key cannot be trusted.`));
    process.exit(1);
  }
  console.log(ok(`${issuer}: declaration genuine, key ${v.fingerprint.slice(0, 16)}…`));
  return { key: v.publicKey, fingerprint: v.fingerprint };
}

// An organisation vouching for one of its own agents: "we operate this
// agent, with this key". For internal services nobody outside can reach,
// this stands in for the location check. Signed with the organisation's key,
// never the agent's.
async function cmdAffiliate(args) {
  const file = args._[1];
  const org = typeof args.org === 'string' ? args.org : process.env.PROVENANCE_ORG_ID;
  const orgKey = args['org-private-key'] || process.env.PROVENANCE_ORG_PRIVATE_KEY;
  const days = Number(args['valid-days'] ?? 365);
  if (!file) { console.error(err('Usage: provenance affiliate <declaration> --org <org_provenance_id> [--unit <name>]')); process.exit(1); }
  if (!org) { console.error(err('--org (or PROVENANCE_ORG_ID) is required: the organisation\'s own provenance id')); process.exit(2); }
  if (!orgKey) { console.error(err('PROVENANCE_ORG_PRIVATE_KEY (or --org-private-key) is required — the organisation\'s key, not the agent\'s')); process.exit(2); }
  if (!Number.isFinite(days) || days <= 0 || days > 3650) { console.error(err('--valid-days must be between 1 and 3650')); process.exit(1); }

  const { value } = readDocument(file);
  const v = await verifyDeclaration(value);
  if (!v.valid || v.coverage !== 'declaration') {
    console.error(err(`Refusing to vouch for a declaration that does not verify in full: ${v.reason ?? 'spec 0.1 signature'}`));
    process.exit(1);
  }

  let orgPublic;
  try { orgPublic = derivePublicKey(orgKey); }
  catch { console.error(err('Organisation key is not a base64 PKCS8 Ed25519 key')); process.exit(2); }

  const now = new Date();
  const stamp = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');
  const attestation = {
    attestation: '0.1',
    id: `affiliation-${v.fingerprint.slice(0, 16)}-${now.getTime().toString(36)}`,
    kind: 'affiliation',
    issuer: { provenance_id: org, key_fingerprint: await keyFingerprint(orgPublic) },
    subject: { provenance_id: v.provenanceId },
    issued_at: stamp(now),
    valid_until: stamp(new Date(now.getTime() + days * 86400000)),
    scope: `${org} operates this agent with the key named here. Not an assessment of its behaviour.`,
    claims: {
      relationship: 'operated_by',
      ...(typeof args.unit === 'string' ? { unit: args.unit } : {}),
      subject_key_fingerprint: v.fingerprint,
    },
  };
  attestation.signature = signAttestation(orgKey, attestation);

  const out = JSON.stringify(attestation, null, 2) + '\n';
  if (typeof args.out === 'string') {
    writeFileSync(resolve(process.cwd(), args.out), out);
    console.log(ok(`Affiliation for ${v.provenanceId} written to ${args.out} (valid ${days} days)`));
  } else {
    process.stdout.write(out);
  }
}

// Check a stamp without trusting whoever issued it: the issuer's key is taken
// from the issuer's own declaration, verified at the location its id names —
// or supplied directly with --issuer-key for a fully offline check.
async function cmdVerifyAttestation(args) {
  const target = args._[1];
  if (!target) { console.error(err('Usage: provenance verify-attestation <file | url> [--issuer-key <base64>]')); process.exit(1); }
  let text;
  if (/^https?:\/\//.test(target)) {
    try {
      const res = await fetch(target, { redirect: 'error' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      text = await res.text();
    } catch (e) { console.error(err(`Could not fetch ${target}: ${e.message}`)); process.exit(2); }
  } else {
    const path = resolve(process.cwd(), target);
    if (!existsSync(path)) { console.error(err(`File not found: ${path}`)); process.exit(2); }
    text = readFileSync(path, 'utf8');
  }
  let att;
  try { att = JSON.parse(text); } catch { console.error(err('Not an attestation: expected JSON')); process.exit(1); }

  let key = typeof args['issuer-key'] === 'string' ? args['issuer-key'] : null;
  const issuer = att?.issuer?.provenance_id;
  if (!key) {
    const url = issuer ? locateDeclaration(issuer) : null;
    if (!url) { console.error(err(`Cannot locate the issuer's declaration for ${issuer ?? '(no issuer)'}; pass --issuer-key`)); process.exit(2); }
    let decl;
    try {
      const res = await fetch(url, { redirect: 'error' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.text();
      decl = /\.json($|\?)/.test(url) ? JSON.parse(body) : parseYaml(body);
    } catch (e) { console.error(err(`Could not fetch the issuer's declaration at ${url}: ${e.message}`)); process.exit(2); }
    const v = await verifyDeclaration(decl, { retrievedFrom: url });
    if (!v.valid || v.location !== 'match' || v.provenanceId !== issuer) {
      console.error(err(`The issuer's own declaration does not check out (${v.reason ?? 'location or id mismatch'}) — its key cannot be trusted.`));
      process.exit(1);
    }
    key = v.publicKey;
    console.log(ok(`Issuer ${issuer}: declaration genuine, key ${v.fingerprint.slice(0, 16)}…`));
  }

  const r = await verifyAttestation(att, { issuerPublicKey: key });
  const word = { valid: c.green + 'valid', expired: c.amber + 'expired (genuine, but stale)', not_yet_valid: c.amber + 'not yet valid', invalid: c.red + 'INVALID', unchecked: c.amber + 'could not be checked' }[r.status];
  console.log(`\n${dim('Attestation:')} ${att.id ?? '?'} ${dim('(' + (att.kind ?? '?') + ')')}`);
  console.log(`${dim('Subject:')}     ${att.subject?.provenance_id ?? att.subject?.url ?? '?'}`);
  console.log(`${dim('Result:')}      ${word}${c.reset}`);
  if (r.reason) console.log(dim(r.reason));
  if (att.scope) console.log(`\n${dim('Scope:')} ${att.scope}`);
  console.log();
  if (r.status === 'invalid') process.exit(1);
  if (r.status === 'unchecked') process.exit(2);
}

async function cmdRegister(args) {
  const id          = args.id;
  const url         = args.url;
  const name        = args.name;
  const description = args.description || args.desc;
  const caps        = args.capabilities ? args.capabilities.split(',').map(s => s.trim()) : [];
  const cons        = args.constraints  ? args.constraints.split(',').map(s => s.trim())  : [];
  const model       = args.model;
  const modelId     = args['model-id'];
  const ajpEndpoint = args['ajp-endpoint'];
  const privateKey  = args['private-key'] || process.env.PROVENANCE_PRIVATE_KEY;

  if (!id)  { console.error(err('--id required'));  process.exit(1); }
  if (!url) { console.error(err('--url required')); process.exit(1); }
  const API = indexUrl(args);

  console.log(`\n${amb('Registering')} ${hi(id)}...\n`);

  let pubKey, signedChallenge;
  if (privateKey) {
    pubKey          = args['public-key'] || process.env.PROVENANCE_PUBLIC_KEY || derivePublicKey(privateKey);
    signedChallenge = signMessage(privateKey, `${id}:REGISTER`);
    console.log(ok('Signing with private key'));
  }

  const body = {
    provenance_id: id, url,
    ...(name        && { name }),
    ...(description && { description }),
    ...(caps.length && { capabilities: caps }),
    ...(cons.length && { constraints: cons }),
    ...(model       && { model_provider: model }),
    ...(modelId     && { model_id: modelId }),
    ...(ajpEndpoint && { ajp_endpoint: ajpEndpoint }),
    ...(pubKey      && { public_key: pubKey }),
    ...(signedChallenge && { signed_challenge: signedChallenge }),
  };

  const res  = await fetch(`${API}/api/agents/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  const data = await res.json();

  if (!res.ok) { console.error(err(data.error || `HTTP ${res.status}`)); process.exit(1); }

  const agent = data.agent || data;
  console.log(ok(data.created ? 'Agent registered' : 'Agent updated'));
  console.log(`  ${dim('confidence:')}      ${c.green}${agent.confidence}${c.reset}`);
  console.log(`  ${dim('identity_verified:')} ${agent.identity_verified ? c.green + 'true' : c.amber + 'false'}${c.reset}`);
  if (ajpEndpoint) console.log(`  ${dim('ajp_endpoint:')}    ${ajpEndpoint}`);
  if (!agent.identity_verified)
    console.log(`\n${c.amber}Tip:${c.reset} Run with ${hi('--private-key')} to get identity_verified status`);
  console.log();
}

async function cmdStatus(args) {
  const id = args._[1];
  if (!id) { console.error(err('Usage: provenance status <provenance_id>')); process.exit(1); }
  const API = indexUrl(args);

  console.log(`\n${amb('Checking')} ${hi(id)}...\n`);

  const res  = await fetch(`${API}/api/agent/${id.replace('provenance:', '').replace(':', '/')}`);
  const data = await res.json();

  if (!res.ok || data.error) { console.error(err(data.error || 'Not found')); process.exit(1); }

  const trust      = Math.round((data.confidence || 0) * 100);
  const trustColor = trust >= 80 ? c.green : trust >= 50 ? c.amber : c.red;

  console.log(`${hi(data.name || id)}`);
  console.log(`${dim(data.provenance_id)}\n`);
  console.log(`${dim('Trust score:')}       ${trustColor}${trust}/100${c.reset}`);
  console.log(`${dim('Declared:')}          ${data.declared ? c.green + 'yes' : c.amber + 'no'}${c.reset}`);
  console.log(`${dim('Identity verified:')} ${data.identity_verified ? c.green + 'yes' : c.amber + 'no'}${c.reset}`);
  console.log(`${dim('AJP endpoint:')}      ${data.ajp?.endpoint ? c.green + data.ajp.endpoint : c.dim + 'not set'}${c.reset}`);
  console.log(`${dim('Incidents:')}         ${(data.incident_count || 0) === 0 ? c.green + '0' : c.red + data.incident_count}${c.reset}`);
  if (data.capabilities?.length) console.log(`${dim('Capabilities:')}      ${data.capabilities.join(', ')}`);
  if (data.constraints?.length)  console.log(`${dim('Constraints:')}       ${data.constraints.join(', ')}`);

  console.log();
  for (const [pass, label] of [
    [data.declared,                'PROVENANCE.yml declared'],
    [data.identity_verified,       'Identity verified (Ed25519)'],
    [!!data.ajp?.endpoint,         'AJP endpoint configured'],
    [(data.incident_count||0)===0, 'No open incidents'],
  ]) console.log(`  ${pass ? ok(label) : dim('○ ' + label)}`);
  console.log();
}

async function cmdValidate(args) {
  const file = args._[1] || 'PROVENANCE.yml';
  console.log(`\n${amb('Validating')} ${hi(file)}...\n`);
  const { value } = readDocument(file);

  const result = validateDeclaration(value);
  // A signature that is present but does not verify is a broken file, not a
  // style note — someone edited it after signing.
  if (value?.identity?.signature) {
    const sig = await verifyDeclaration(value);
    if (!sig.valid) { result.valid = false; result.errors.push(`identity.signature: ${sig.reason}`); }
  }

  if (result.valid) console.log(ok('Valid PROVENANCE.yml'));
  else { console.log(err('Validation failed')); for (const e of result.errors) console.log(`  ${c.red}✗${c.reset} ${e}`); }
  for (const w of result.warnings) console.log(`  ${c.amber}⚠${c.reset} ${w}`);
  console.log();

  // Non-zero on an invalid file so this can gate a pipeline.
  if (!result.valid) process.exit(1);
}

async function cmdRevoke(args) {
  const id         = args.id;
  const privateKey = args['private-key'] || process.env.PROVENANCE_PRIVATE_KEY;
  if (!id)         { console.error(err('--id required')); process.exit(1); }
  if (!privateKey) { console.error(err('--private-key or PROVENANCE_PRIVATE_KEY required')); process.exit(1); }
  const API = indexUrl(args);

  console.log(`\n${c.red}Revoking identity for${c.reset} ${hi(id)}...\n`);

  const res  = await fetch(`${API}/api/agents/revoke`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ provenance_id: id, signed_challenge: signMessage(privateKey, `${id}:REVOKE`) }),
  });
  const data = await res.json();
  if (!res.ok || !data.success) { console.error(err(data.error || `HTTP ${res.status}`)); process.exit(1); }

  console.log(ok('Identity revoked'));
  console.log(dim('Run `provenance register` with a new keypair to re-establish.\n'));
}

function cmdHelp() {
  console.log(`
${hi('provenance')} ${dim(`v${VERSION}`)} — Provenance Protocol CLI

${amb('Offline — no service involved:')}
  ${hi('init')}      [--domain <host>] [--yes]  Write and sign your first declaration (about 5 minutes)
  ${hi('check')}     [file] [--update] [--strict] Compare the passport with the project; --update applies facts
  ${hi('keygen')}                              Generate an Ed25519 keypair
  ${hi('sign')}      [file]                     Sign a 0.2 declaration in place (default: ./PROVENANCE.yml)
  ${hi('verify')}    <file | url | id>          Verify a declaration's signature and location
                 [--affiliation <file | url>]  …or, for an internal agent, its operator's affiliation
                 [--org-key <base64>]          the operator's key, instead of fetching its declaration
               [--from <url>]            where a local file was published
  ${hi('validate')}  [file]                     Check a declaration against the schema
  ${hi('verify-attestation')} <file | url>     Check a stamp against its issuer's own published key
  ${hi('affiliate')} <declaration>              Vouch, as an organisation, for an agent you operate
               --org <org_provenance_id> [--unit <name>] [--valid-days 365] [--out file]

${amb('Against an index you choose')} ${dim('(--index <url> or PROVENANCE_INDEX_URL):')}
  ${hi('register')}  --id <id> --url <url>     Register or update your agent in that index
               [--name <name>]
               [--description <text>]
               [--capabilities read:web,write:code]
               [--constraints no:pii,no:financial:transact]
               [--model anthropic] [--model-id claude-sonnet-4-6]
               [--ajp-endpoint <url>]
               [--private-key <key>]
  ${hi('status')}    <provenance_id>            What that index says about an agent
  ${hi('revoke')}    --id <id>                  Tell that index your key is revoked
               [--private-key <key>]

${amb('Exit codes:')}
  0 ok   1 checked and failed   2 could not check (nothing was verified)

${amb('Environment variables:')}
  PROVENANCE_PRIVATE_KEY  Your Ed25519 private key (base64 PKCS8 DER)
  PROVENANCE_ORG_PRIVATE_KEY  Your organisation's key, for affiliate
  PROVENANCE_INDEX_URL    Index for register, status and revoke

${amb('For AJP job delegation:')}
  ${dim('npx @ilucky21c/ajp-cli hire <id> --instruction "..."')}

${amb('Examples:')}
  provenance init
  provenance sign
  provenance verify provenance:domain:agent.example.com
  provenance validate
`);
}

// ── Main ──────────────────────────────────────────────────────────────────────

const argv = process.argv.slice(2);
const args = parseArgs(argv);
const cmd  = args._[0];

try {
  if (!cmd || cmd === 'help' || args.help) cmdHelp();
  else if (cmd === 'init')     await cmdInit(args);
  else if (cmd === 'check')    await cmdCheck(args);
  else if (cmd === 'keygen')   await cmdKeygen();
  else if (cmd === 'sign')     await cmdSign(args);
  else if (cmd === 'verify')   await cmdVerify(args);
  else if (cmd === 'affiliate') await cmdAffiliate(args);
  else if (cmd === 'verify-attestation') await cmdVerifyAttestation(args);
  else if (cmd === 'register') await cmdRegister(args);
  else if (cmd === 'status')   await cmdStatus(args);
  else if (cmd === 'validate') await cmdValidate(args);
  else if (cmd === 'revoke')   await cmdRevoke(args);
  else { console.error(err(`Unknown command: ${cmd}\nRun \`provenance help\` for usage.`)); process.exit(1); }
} catch (e) {
  console.error(err(e.message));
  process.exit(1);
}
