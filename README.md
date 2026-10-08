# provenance-protocol

The Provenance Protocol: an open standard for declaring and verifying AI agent
identity — and a reference implementation of it.

An agent publishes a signed **declaration**: what it is, what it can do, what it
will never do, who answers for it, and — optionally — what happens to data,
who else touches it, what needs a human, and what it depends on. Third parties publish signed
**attestations** about it: what they observed, what was reported, what they
approved. Both verify **offline** — no account, no API key, and no call to any
service. Nothing here depends on any particular company, this one included.

```bash
npm install provenance-protocol
```

## The standard

| | |
|---|---|
| [**SPEC.md**](./SPEC.md) | The specification: declarations, where they live, signing and verification, attestations, conformance. |
| [**schema/**](./schema/) | JSON Schemas for declarations (0.1, 0.2) and attestations (0.1). |
| [**test-vectors/**](./test-vectors/) | Normative vectors. Pass these and you interoperate. |

Licensed under Apache 2.0. Implement it in any language, for any purpose, without permission
or notification. Indexes, monitors and attesters are applications built on the
standard, not part of it.

---

## Accept an agent on the strength of its declaration

```js
import { checkDeclaration, locateDeclaration } from 'provenance-protocol';

const url = locateDeclaration('provenance:domain:agent.example.com');
// → https://agent.example.com/.well-known/provenance.json

const declaration = await (await fetch(url, { redirect: 'error' })).json();

const { allowed, reason } = await checkDeclaration(declaration, {
  retrievedFrom: url,
  requireConstraints: ['no:financial:transact'],   // example — use your own
});

if (!allowed) throw new Error(reason);
```

`checkDeclaration` refuses unless the signature covers the whole declaration,
the file was served from the location its id names, and it promises what you
require. Every refusal says why. It answers *is this genuinely the operator's,
and does it promise what I need?* — not *is it in good standing today*, which
no document can carry and which comes from attesters you choose to trust.

GitHub-hosted declarations are YAML; parse them with any YAML library and pass
the object.

## Verify, in detail

```js
import { verifyDeclaration } from 'provenance-protocol';

const result = await verifyDeclaration(declaration, { retrievedFrom: url });

result.valid        // the signature verifies against the key in the file
result.coverage     // 'declaration' (0.2) | 'identity' (0.1)
result.location     // 'match' | 'mismatch' | 'unchecked'
result.trustworthy  // valid AND served from the location it claims: about the file, not the agent's conduct
result.fingerprint  // SHA-256 of the key — pin it to detect rotation
```

Under spec **0.2** the signature covers every field, so deleting a constraint
breaks it. Under **0.1** it covered only the identity and key; a valid 0.1
signature says nothing about whether the constraints were edited.

## Attestations

A signed statement by a third party about an agent. Verify it against the
issuer's public key — normally from the issuer's own verified declaration.

```js
import { verifyAttestation } from 'provenance-protocol';

const r = await verifyAttestation(attestation, { issuerPublicKey });

r.status  // 'valid' | 'expired' | 'not_yet_valid' | 'invalid' | 'unchecked'
```

`expired` means genuine but stale; `invalid` means forged or altered. They are
never confused: the signature is checked before the dates.

Issuing one (Node):

```js
import { signAttestation } from 'provenance-protocol/keygen';
import { keyFingerprint, declarationDigest } from 'provenance-protocol';

const attestation = {
  attestation: '0.1',
  id: 'att-0001',
  kind: 'declaration-check',
  issuer: { provenance_id: 'provenance:domain:attester.example', key_fingerprint: await keyFingerprint(myPublicKey) },
  subject: { provenance_id: declaration.provenance_id, declaration_digest: await declarationDigest(declaration) },
  issued_at: '2026-09-21T09:00:00Z',
  valid_until: '2026-09-24T09:00:00Z',
  scope: 'Covers the declaration as retrieved at the stated time and location only.',
  claims: { retrieved_from: url, retrieved_at: '2026-09-21T08:59:12Z', signature: 'declaration', location: 'match' },
};
attestation.signature = signAttestation(myPrivateKey, attestation);
```

## What changed, and does it matter?

```js
import { compareDeclarations } from 'provenance-protocol';

for (const c of compareDeclarations(before, after)) {
  // { field: 'data.retention', change: 'modified', from: 'P30D', to: 'P1Y',
  //   direction: 'weakened', announced: false }
}
```

Every watcher applying the spec's rules reports the same changes and agrees on
which weaken the agent's promises: a constraint removed, retention lengthened, a
subprocessor or region added, human approval dropped, a limit raised. A
weakening the operator listed in advance under `changes.pending` is marked
`announced`.

## Notices — the operator's own signed updates

```js
import { verifyNotice } from 'provenance-protocol';
const r = await verifyNotice(notice, { publicKey });   // for key-rotation: the OLD key
r.status            // 'valid' | 'invalid' | 'unchecked'
r.newKeyFingerprint // after a valid key-rotation, pin this
```

Events: `declaration-published`, `release`, `key-rotation` (signed by the old
key, so a new key arrives vouched for), `incident`. Operators sign them with
`signNotice` from `provenance-protocol/keygen`;
[`provenance-middleware`](https://github.com/provenance-protocol/provenance-middleware)
publishes them for you.

## Links to A2A and MCP

```js
import { checkInteropLinks } from 'provenance-protocol';
checkInteropLinks(declaration);   // { a2a: 'confirmed' | 'claimed' | 'none', mcp: … }
```

A declaration can point to the same agent's A2A Agent Card and MCP Registry
entry. A link is *confirmed* only when the same party provably controls both
ends; otherwise it is *claimed*, so nobody can attach their declaration to a
well-known agent.

## Pinned dependencies (spec 0.3)

A declaration can pin what it relies on to an exact version, and a release can
report what it actually resolved — so a dependency that changes silently, or a
pin that was never honoured, is visible:

```yaml
provenance: "0.3"
dependencies:
  - url: https://www.npmjs.com/package/postmark-mcp
    kind: mcp_server
    pin: { version: 1.0.15, integrity: sha512-3u4… }
```

```js
import { checkPins } from 'provenance-protocol';
checkPins(declaration, releaseNotice);   // [{ dependency, result: 'match' | 'mismatch' | 'unpinned' | 'not_reported' }]
```

## Every passport a site publishes

A site with several agents can list them at one fixed address, so anyone who
knows only the website can find them all with a single request:

```js
import { locateIndex, readIndex } from 'provenance-protocol';
const url = locateIndex('example.com');          // https://example.com/.well-known/provenance/index.json
const { agents } = readIndex(await (await fetch(url)).json(), { fetchedFrom: url });
// Each entry is a pointer: verify every declaration at its own location.
```

## Internal agents

A company's own agents, on hosts nobody outside can reach, deliver their
declaration inside a signed notice, and the company vouches for them with an
`affiliation` signed by its own key:

```bash
PROVENANCE_ORG_PRIVATE_KEY=… npx provenance-protocol affiliate PROVENANCE.yml \
  --org provenance:domain:corp.example --unit "Human Resources" --out affiliation.json
```

```js
import { openDeliveredDeclaration, checkDeclaration } from 'provenance-protocol';

const { declaration } = await openDeliveredDeclaration(notice);
const r = await checkDeclaration(declaration, {
  affiliation: { attestation: affiliation, issuerPublicKey: orgPublicKey },
});
r.anchor   // 'affiliation' — tied to the organisation, not to a location
```

Anyone the company shares the two files with can check them the same way:

```bash
npx provenance-protocol verify PROVENANCE.json --affiliation affiliation.json
```

It fetches the company's own declaration from its public domain, checks it is
genuine, and verifies the affiliation against the key inside it.

## Your first declaration, in about five minutes

```bash
npx provenance-protocol init
```

It reads your project on your machine — name, version, repository, which AI
provider you use, which libraries imply which capabilities, which MCP servers you
connect to — suggests the promises your code supports, asks two policy questions,
creates a key kept out of git, and signs. Nothing leaves your machine. With
`--yes` it fills in only what your project shows and makes no promises for you:
a promise has to be a decision.

## Keep it true as the code changes

```bash
npx provenance-protocol check            # what changed in the project that the passport doesn't say
npx provenance-protocol check --update   # apply the facts, confirm the guesses, re-sign
```

It reads the project on your machine — nothing is sent anywhere, and a test in
this repository proves it makes no network connection. Facts the project states
outright (version, the AI provider's library, servers in your MCP settings) are
applied; inferences ("an email library, so it probably sends email") are asked
about; code that clashes with a promise is reported and **never** resolved for
you, because dropping a promise is a public weakening. List a reviewed finding in
`.provenance-ignore` to leave it alone. In CI, `provenance-action` runs the same
check on every build.

## Sign your own declaration

From the command line — no service involved:

```bash
npx provenance-protocol keygen            # once; keep the private key in your env
PROVENANCE_PRIVATE_KEY=… npx provenance-protocol sign PROVENANCE.yml
npx provenance-protocol verify provenance:domain:agent.example.com
npx provenance-protocol validate
```

Check a stamp someone issued, against the issuer's own published key:

```bash
npx provenance-protocol verify-attestation stamp.json
```

`sign` edits the file in place, keeps your comments, and reads the result back
to confirm it verifies. For a hosted service,
[`provenance-middleware`](https://github.com/provenance-protocol/provenance-middleware)
serves and signs the declaration at startup instead.

Or in code:

```js
import { generateProvenanceKeyPair, signDeclaration } from 'provenance-protocol/keygen';
declaration.identity.signature = signDeclaration(privateKey, declaration);
```

Exit codes: `0` ok, `1` checked and failed, `2` could not check. "Could not
check" is never reported as a failure, or as a pass.

## Entry points

| Import | Runs in | What |
|---|---|---|
| `provenance-protocol` | anywhere with Web Crypto | verify, check, locate, compare, attestations, notices |
| `provenance-protocol/keygen` | Node | keys, signing declarations, challenges, attestations, notices |
| `provenance-protocol/validate` | Node | schema validation for declarations, attestations and notices |
| `provenance-protocol/index-client` | anywhere | client for an index service you choose (below) |

The main entry has no dependencies. `yaml` is used only by the CLI.

## Live proof of key control

A signed file proves where the declaration came from. To check that the service
answering you right now holds the key, send it a single-use nonce:

```js
import { verifyAgentChallenge } from 'provenance-protocol';
const ok = await verifyAgentChallenge(publicKey, provenanceId, nonce, signature);
```

The agent answers with `signAgentChallenge` (or `provenance-middleware` does it
for them).

## Index client (optional)

An index is a service that crawls or accepts registrations and answers
questions about current standing — open incidents, revocation, age. It is an
application of the standard, not part of it. You must name the one you trust;
there is no default.

```js
import { Provenance } from 'provenance-protocol/index-client';

const index = new Provenance({ apiUrl: 'https://index.example.com', onApiError: 'deny' });
const result = await index.gate(provenanceId, { requireConstraints: ['no:pii'] });
```

The CLI's `register`, `status` and `revoke` commands likewise need
`--index <url>` or `PROVENANCE_INDEX_URL`.

## Upgrading from 0.5

- The main entry is now offline. `Provenance` moved to
  `provenance-protocol/index-client` and requires `apiUrl`; the default
  `provenance` instance is gone.
- The index client's `verifySignature` and `gate({ requireSignedProof })` now
  expect the domain-separated challenge (`signAgentChallenge`), matching
  `provenance-middleware`.
- `provenance validate` runs locally against the bundled schema.
- The schemas accept `provenance:domain:` identifiers and ignore unknown
  top-level fields, as the conformance rules always required.

## Related

| Package | Purpose |
|---|---|
| [`provenance-middleware`](https://github.com/provenance-protocol/provenance-middleware) | One line that makes a service serve and sign its own declaration |
| [`provenance-action`](https://github.com/provenance-protocol/provenance-action) | Verify a declaration in CI |
| [`ajp-protocol`](https://github.com/provenance-protocol/ajp-protocol) | Agent Job Protocol — agent-to-agent job delegation |

## License

Apache License 2.0 — see [LICENSE](./LICENSE). Versions before 0.11.1 were released under MIT.
