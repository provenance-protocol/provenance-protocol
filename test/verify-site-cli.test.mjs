import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { execFile } from 'node:child_process';

const V = JSON.parse(readFileSync(new URL('../test-vectors/declarations-0.2.json', import.meta.url), 'utf8'));
const decl = V.vectors.find((v) => v.id === 'declaration-signature-valid').declaration;
const cli = new URL('../src/cli.js', import.meta.url).pathname;
let pass = 0, fail = 0;
const t = (name, ok, d = '') => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  ' + d}`); ok ? pass++ : fail++; };
const run = (target) => new Promise((ok) => execFile('node', [cli, 'verify', target], { encoding: 'utf8' },
  (e, out, errOut) => ok({ code: e ? e.code : 0, out: (out + errOut).replace(/\x1b\[[0-9;]*m/g, '') })));

// One site serving a web page at its root and, optionally, a declaration at the standard location.
const serve = (withDecl) => new Promise((ok) => {
  const seen = [];
  const s = createServer((req, res) => {
    seen.push(req.url);
    if (req.url === '/.well-known/provenance.json' && withDecl) return res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(decl));
    if (req.url === '/' || req.url === '/about') return res.writeHead(200, { 'content-type': 'text/html' }).end('<!doctype html><html><body>Home: x</body></html>');
    res.writeHead(404).end();
  }).listen(0, '127.0.0.1', () => ok({ base: `http://127.0.0.1:${s.address().port}`, seen, close: () => s.close() }));
});

let site = await serve(true);
for (const target of [site.base, `${site.base}/`]) {
  const r = await run(target);
  t(`a bare site address (${target.endsWith('/') ? 'with' : 'without'} slash) is checked at the standard location`,
    /Signature:\s+valid/.test(r.out) && !/INVALID/.test(r.out) && /standard location/.test(r.out), r.out);
}
t('…the site\'s own page was never read as a declaration', !site.seen.includes('/'), JSON.stringify(site.seen));
let r = await run(`${site.base}/about`);
t('a page address is fetched as given, and a web page is reported as not a declaration', r.code === 2 && /returned a web page/.test(r.out) && /Nothing was verified/.test(r.out), r.out);
site.close();

site = await serve(false);
r = await run(site.base);
t('a site with no declaration says nothing was verified, not that it is invalid', r.code === 2 && /HTTP 404/.test(r.out) && /Nothing was verified/.test(r.out) && !/INVALID/.test(r.out), r.out);
site.close();

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
