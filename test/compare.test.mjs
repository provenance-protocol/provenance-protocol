import { compareDeclarations, durationDays } from '../src/compare.js';

let pass = 0, fail = 0;
const t = (name, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  ${JSON.stringify(detail)}`}`);
  ok ? pass++ : fail++;
};
const find = (changes, field, change) => changes.find((c) => c.field === field && c.change === change);

const base = {
  provenance: '0.2', name: 'A', description: 'B',
  capabilities: ['read:web', 'financial:transact'],
  constraints: ['no:pii', 'no:write:external'],
  data: { categories: ['customer_content'], retention: 'P30D', training_use: 'none', regions: ['EU'] },
  subprocessors: [{ name: 'ModelCo', role: 'model_provider', regions: ['US'] }],
  oversight: { approval_required: ['financial:transact'], pausable_by_customer: true },
  limits: [{ applies_to: 'financial:transact', max: 500, unit: 'USD', per: 'P1D' }],
  dependencies: [{ provenance_id: 'provenance:domain:tool.example', kind: 'mcp_server' }],
  certifications: [{ standard: 'ISO/IEC 42001' }],
  changes: { notice_period: 'P30D', pending: [{ field: 'constraints', change: 'removed', value: 'no:write:external', effective: '2026-11-01' }] },
  identity: { public_key: 'K1', signature: 'S1' },
};
const clone = (x) => JSON.parse(JSON.stringify(x));

t('identical declarations → no changes', compareDeclarations(base, clone(base)).length === 0);
t('signature alone changing is ignored', compareDeclarations(base, { ...clone(base), identity: { public_key: 'K1', signature: 'S2' } }).length === 0);

let after = clone(base);
after.constraints = ['no:pii'];
let c = find(compareDeclarations(base, after), 'constraints', 'removed');
t('constraint removed → weakened', c?.direction === 'weakened', c);
t('…and announced, because it was pending', c?.announced === true, c);

after = clone(base); after.constraints = [];
c = find(compareDeclarations(base, after), 'constraints', 'removed');
t('unannounced removal is marked unannounced', compareDeclarations(base, after).some((x) => x.value === 'no:pii' && x.announced === false));

after = clone(base); after.capabilities.push('write:email');
t('capability added → weakened', find(compareDeclarations(base, after), 'capabilities', 'added')?.direction === 'weakened');

after = clone(base); after.data.retention = 'P1Y';
t('longer retention → weakened', find(compareDeclarations(base, after), 'data.retention', 'modified')?.direction === 'weakened');
after = clone(base); after.data.retention = 'P7D';
t('shorter retention → strengthened', find(compareDeclarations(base, after), 'data.retention', 'modified')?.direction === 'strengthened');

after = clone(base); after.data.training_use = 'opt_out';
t('training use loosened → weakened', find(compareDeclarations(base, after), 'data.training_use', 'modified')?.direction === 'weakened');

after = clone(base); after.data.regions = ['EU', 'US'];
t('region added → weakened', find(compareDeclarations(base, after), 'data.regions', 'added')?.direction === 'weakened');

after = clone(base); after.subprocessors.push({ name: 'HostCo', role: 'hosting' });
t('subprocessor added → weakened', find(compareDeclarations(base, after), 'subprocessors', 'added')?.direction === 'weakened');
after = clone(base); after.subprocessors[0].regions = ['US', 'CN'];
c = find(compareDeclarations(base, after), 'subprocessors', 'modified');
t('subprocessor gains a region → modified, weakened', c?.direction === 'weakened', c);

after = clone(base); after.oversight.approval_required = [];
t('human approval removed → weakened', find(compareDeclarations(base, after), 'oversight.approval_required', 'removed')?.direction === 'weakened');
after = clone(base); after.oversight.pausable_by_customer = false;
t('no longer pausable → weakened', find(compareDeclarations(base, after), 'oversight.pausable_by_customer', 'modified')?.direction === 'weakened');

after = clone(base); after.limits[0].max = 5000;
c = find(compareDeclarations(base, after), 'limits', 'modified');
t('limit raised → weakened, as one modification', c?.direction === 'weakened' && compareDeclarations(base, after).length === 1, compareDeclarations(base, after));
after = clone(base); after.limits = [];
t('limit removed → weakened', find(compareDeclarations(base, after), 'limits', 'removed')?.direction === 'weakened');

after = clone(base); after.dependencies.push({ url: 'https://api.pay.example', kind: 'api' });
t('dependency added → weakened', find(compareDeclarations(base, after), 'dependencies', 'added')?.direction === 'weakened');

after = clone(base); after.certifications = [];
t('certification dropped → weakened', find(compareDeclarations(base, after), 'certifications', 'removed')?.direction === 'weakened');

after = clone(base); after.changes.notice_period = 'P7D';
t('shorter notice period → weakened', find(compareDeclarations(base, after), 'changes.notice_period', 'modified')?.direction === 'weakened');
after = clone(base); delete after.changes.notice_period;
t('notice period removed → weakened', find(compareDeclarations(base, after), 'changes.notice_period', 'removed')?.direction === 'weakened');

after = clone(base); after.identity.public_key = 'K2';
t('key changed → weakened until a rotation notice explains it', find(compareDeclarations(base, after), 'identity.public_key', 'modified')?.direction === 'weakened');

after = clone(base); after.description = 'C';
t('description edit → neutral', find(compareDeclarations(base, after), 'description', 'modified')?.direction === 'neutral');

// A promise withdrawn entirely leaves nothing promised: a weakening (audit, 3 October 2026).
after = clone(base); after.data = { ...after.data }; delete after.data.retention;
t('finite retention promise withdrawn → weakened', find(compareDeclarations(base, after), 'data.retention', 'removed')?.direction === 'weakened');
const optIn = clone(base); optIn.data = { ...optIn.data, training_use: 'opt_in' };
after = clone(optIn); delete after.data.training_use;
t('opt-in-only training promise withdrawn → weakened', find(compareDeclarations(optIn, after), 'data.training_use', 'removed')?.direction === 'weakened');
const withRegions = clone(base); withRegions.data = { ...withRegions.data, regions: ['EU'] };
after = clone(withRegions); after.data.regions = [];
t('every region withdrawn → weakened', find(compareDeclarations(withRegions, after), 'data.regions', 'removed')?.direction === 'weakened');
after = clone(withRegions); after.data.regions = ['EU', 'US']; const twoRegions = clone(after); after.data.regions = ['EU'];
t('one of several regions dropped → still neutral', find(compareDeclarations(twoRegions, after), 'data.regions', 'removed')?.direction === 'neutral');

t('durations: P1Y > P30D > P1W', durationDays('P1Y') > durationDays('P30D') && durationDays('P30D') > durationDays('P1W'));
t('durations: malformed → null', durationDays('30 days') === null && durationDays('P') === null);

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
