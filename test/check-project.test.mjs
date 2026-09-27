import { mkdtempSync, writeFileSync, readFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import net from 'node:net';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import YAML from 'yaml';
import { checkProject, applyFindings } from '../src/check.js';
import { runInit } from '../src/init.js';
import { verifyDeclaration } from '../src/verify.js';

let pass = 0, fail = 0;
const t = (name, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  ${JSON.stringify(detail)}`}`);
  ok ? pass++ : fail++;
};
delete process.env.PROVENANCE_PRIVATE_KEY;

// Any attempt to reach the network during the check is recorded and refused.
const attempts = [];
const refuse = (what) => (...a) => { attempts.push(what); throw new Error(`network refused: ${what}`); };
globalThis.fetch = refuse('fetch');
net.Socket.prototype.connect = refuse('socket');
dns.lookup = refuse('dns');
http.request = refuse('http'); https.request = refuse('https');

const dir = mkdtempSync(join(tmpdir(), 'check-'));
const write = (f, body) => { mkdirSync(join(dir, f, '..'), { recursive: true }); writeFileSync(join(dir, f), typeof body === 'string' ? body : JSON.stringify(body)); };
write('package.json', { name: 'support-agent', description: 'Answers tickets.', version: '1.0.0', dependencies: { '@anthropic-ai/sdk': '1' } });

const ask = async (q) => (/never send email/.test(q) ? 'y' : '');
await runInit(dir, { ask });
const read = () => YAML.parse(readFileSync(join(dir, 'PROVENANCE.yml'), 'utf8'));
let decl = read();
t('a fresh passport is in sync with its project', checkProject(dir, decl).inSync, checkProject(dir, decl));

// The code changes.
write('package.json', { name: 'support-agent', description: 'Answers tickets.', version: '1.1.0',
  dependencies: { openai: '4', nodemailer: '6', '@prisma/client': '5' } });
write('.mcp.json', { mcpServers: { search: { url: 'https://mcp.search.example/sse' } } });

let r = checkProject(dir, decl);
t('version change is a certain fact', r.certain.some((f) => f.field === 'version' && f.value === '1.1.0'), r.certain);
t('provider change is a certain fact', r.certain.some((f) => f.field === 'model.provider' && f.value === 'openai'), r.certain);
t('a new MCP server is a certain fact', r.certain.some((f) => f.field === 'dependencies' && f.value.url === 'https://mcp.search.example/sse'), r.certain);
t('a capability inferred from a library is only likely', r.likely.some((f) => f.value === 'read:database') && !r.certain.some((f) => f.field === 'capabilities'), r.likely);
t('code that clashes with a promise is a conflict, never a finding', r.conflicts.some((c) => c.promise === 'no:write:email') && ![...r.certain, ...r.likely].some((f) => f.value === 'write:email'), r);
t('the check made no network connection', attempts.length === 0, attempts);

// Applying certain facts keeps the promise and verifies once signed.
const updated = applyFindings(decl, r.certain);
t('applying facts never removes a promise', updated.constraints.includes('no:write:email'));
t('applied facts are present', updated.version === '1.1.0' && updated.model.provider === 'openai' && updated.dependencies.length === 1);
t('the stale signature is removed so it must be re-signed', !updated.identity.signature);

// Ignoring a reviewed finding.
write('.provenance-ignore', '# reviewed\ncapabilities:read:database\n');
r = checkProject(dir, decl);
t('an ignored finding stays quiet', !r.likely.some((f) => f.value === 'read:database') && r.ignored === 1, r);
t('but a promise conflict cannot be ignored away', r.conflicts.length === 1);

// CLI end to end: --update applies certain facts, signs, and still reports the conflict.
const out = execFileSync('node', [new URL('../src/cli.js', import.meta.url).pathname, 'check', '--update'], { cwd: dir, encoding: 'utf8' });
decl = read();
t('--update writes the facts and signs', decl.version === '1.1.0' && decl.model.provider === 'openai' && (await verifyDeclaration(decl)).valid, out);
t('--update leaves the promise and says so', decl.constraints.includes('no:write:email') && /conflicts with a promise/.test(out));
let strictFailed = false;
try { execFileSync('node', [new URL('../src/cli.js', import.meta.url).pathname, 'check', '--strict'], { cwd: dir, encoding: 'utf8', stdio: 'pipe' }); } catch { strictFailed = true; }
t('--strict fails the build while a promise conflict remains', strictFailed);

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
