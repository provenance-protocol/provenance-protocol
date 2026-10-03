import { checkLocation } from '../src/verify.js';

let pass = 0, fail = 0;
const t = (name, ok, extra = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  ' + extra}`);
  ok ? pass++ : fail++;
};

const cases = [
  ['hosted service at its own domain', 'provenance:domain:agent.example.com',
    'https://agent.example.com/.well-known/provenance.json', 'match'],
  ['served from someone else\'s domain', 'provenance:domain:agent.example.com',
    'https://evil.example.com/.well-known/provenance.json', 'mismatch'],
  ['a subdomain is NOT the parent domain', 'provenance:domain:example.com',
    'https://agent.example.com/provenance.json', 'mismatch'],
  ['and the parent is not the subdomain', 'provenance:domain:agent.example.com',
    'https://example.com/provenance.json', 'mismatch'],
  ['hostname comparison is case-insensitive', 'provenance:domain:AGENT.Example.COM',
    'https://agent.example.com/provenance.json', 'match'],
  ['several agents under one domain', 'provenance:domain:example.com/agents/research',
    'https://example.com/agents/research/provenance.json', 'match'],
  ['the wrong agent under the right domain', 'provenance:domain:example.com/agents/research',
    'https://example.com/agents/billing/provenance.json', 'mismatch'],
  ['repo identifiers still work', 'provenance:github:alice/agent',
    'https://github.com/alice/agent', 'match'],
  ['raw file URLs under a repo still work', 'provenance:github:alice/agent',
    'https://raw.githubusercontent.com/alice/agent/main/PROVENANCE.yml', 'match'],
  ['a repo id served from a bare domain is unchecked, not a match', 'provenance:github:alice/agent',
    'https://agent.example.com/.well-known/provenance.json', 'unchecked'],
  // Audit, 3 October 2026: the owner/name must sit exactly where the platform puts it.
  ['a victim name nested in an attacker repo is not a match', 'provenance:github:victim/agent',
    'https://raw.githubusercontent.com/attacker/project/main/victim/agent/PROVENANCE.yml', 'mismatch'],
  ['…nor on github.com', 'provenance:github:victim/agent',
    'https://github.com/attacker/project/blob/main/victim/agent/PROVENANCE.yml', 'mismatch'],
  ['api.github.com repository contents match', 'provenance:github:alice/agent',
    'https://api.github.com/repos/alice/agent/contents/PROVENANCE.yml', 'match'],
  ['other GitHub hosts are not repositories', 'provenance:github:alice/agent',
    'https://objects.githubusercontent.com/alice/agent/x', 'unchecked'],
  ['a domain path must start where the id says', 'provenance:domain:example.com/agents/research',
    'https://example.com/attacker/agents/research/provenance.json', 'mismatch'],
  ['an unexpected port is not the site', 'provenance:domain:example.com',
    'https://example.com:8443/.well-known/provenance.json', 'mismatch'],
  ['npm package page', 'provenance:npm:left-pad', 'https://www.npmjs.com/package/left-pad', 'match'],
  ['npm: another package containing the name', 'provenance:npm:left-pad', 'https://www.npmjs.com/package/evil/left-pad', 'mismatch'],
  ['scoped npm package', 'provenance:npm:@acme/agent', 'https://registry.npmjs.org/@acme%2fagent', 'match'],
  ['pypi project', 'provenance:pypi:agent-kit', 'https://pypi.org/project/agent-kit/', 'match'],
  ['hugging face space', 'provenance:huggingface:alice/agent', 'https://huggingface.co/spaces/alice/agent/raw/main/PROVENANCE.yml', 'match'],
  ['hugging face: nested name', 'provenance:huggingface:alice/agent', 'https://huggingface.co/bob/x/raw/main/alice/agent/PROVENANCE.yml', 'mismatch'],
  ['malformed identifier', 'not-a-provenance-id', 'https://example.com/x', 'unchecked'],
  ['malformed url', 'provenance:domain:example.com', 'not a url', 'unchecked'],
  ['empty host in identifier', 'provenance:domain:/', 'https://example.com/x', 'unchecked'],
];

for (const [name, id, url, want] of cases) {
  const got = checkLocation(id, url);
  t(name, got === want, `got '${got}', want '${want}'`);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
