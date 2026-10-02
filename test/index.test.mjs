import { locateIndex, readIndex } from '../src/index.js';
import { validateIndex } from '../src/validate.js';

let pass = 0, fail = 0;
const t = (name, ok, d = '') => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  ' + d}`); ok ? pass++ : fail++; };

const index = { provenance_index: '0.1', site: 'example.com', operator: 'provenance:domain:example.com', agents: [
  { provenance_id: 'provenance:domain:example.com/agents/support', name: 'Support Agent' },
  { provenance_id: 'provenance:github:example/research-agent' },
  { provenance_id: 'provenance:domain:example.com/agents/support' },
  { provenance_id: 'not an id' },
] };
t('the index has one fixed address per host', locateIndex('Example.com') === 'https://example.com/.well-known/provenance/index.json');
t('a bad host has no index address', locateIndex('not a host/') === null);
const r = readIndex(index, { fetchedFrom: 'https://example.com/.well-known/provenance/index.json' });
t('a valid index lists its agents, once each, skipping malformed ids', r.valid && r.agents.length === 2, JSON.stringify(r));
t('an on-site entry is marked on-site', r.agents[0].onSite === true && r.agents[0].name === 'Support Agent');
t('an off-site entry is only what the site claims', r.agents[1].onSite === false);
t('an index naming another site is refused', !readIndex(index, { fetchedFrom: 'https://evil.example/.well-known/provenance/index.json' }).valid);
t('an unknown version is refused', !readIndex({ ...index, provenance_index: '9' }, { fetchedFrom: 'https://example.com/x' }).valid);
const clean = { ...index, agents: index.agents.slice(0, 2) };
t('a clean index passes the schema', validateIndex(clean).valid, JSON.stringify(validateIndex(clean).errors));
t('an extra field is refused by the schema', !validateIndex({ ...clean, extra: 1 }).valid);

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
