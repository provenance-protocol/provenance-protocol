# Provenance Protocol Specification
**Declarations 0.1, 0.2 and 0.3 · Attestations 0.1 · Notices 0.1 and 0.2**

---

## What is PROVENANCE.yml?

`PROVENANCE.yml` is a single file that lives in the root of any AI agent's
repository. It tells the world — in a structured, machine-readable,
human-readable way — what this agent is, what it can do, what it will
never do, and who is responsible for it.

Think of it as the agent's public identity card.
Voluntary. Simple. Five minutes to add. Zero friction.

The filename is unambiguous by design. No existing project will already
have a file called `PROVENANCE.yml` for any other purpose. When you see
this file in a repository you know exactly what it is and why it exists.

---

## Why does this exist?

The agent internet is growing faster than the infrastructure to understand it.
Thousands of agents exist publicly — on GitHub, HuggingFace, npm, PyPI,
ClawMarket — but there is no standard way to answer basic questions:

- What does this agent actually do?
- What can it access? What will it never touch?
- Who built it and how do I reach them if something goes wrong?
- What model powers it, and has that changed recently?
- Has this agent's behavior been consistent over time?

`PROVENANCE.yml` makes these questions answerable — automatically, at scale,
without anyone needing to manually curate anything.

It is the `robots.txt` of the agent internet. A simple convention that
benefits everyone: builders state what their agent is once and every system
can read it; receiving systems can check it without asking anyone; the
ecosystem gets a shared foundation that no single service owns.

The standard has two documents:

- a **declaration** — what an agent says about itself, published and signed by
  whoever is answerable for it; and
- an **attestation** — what a third party says about an agent, signed by that
  third party.

Both verify offline. Nothing in this specification requires contacting any
particular service.

---

## The File

Place a file named exactly `PROVENANCE.yml` in the root of your repository,
or serve the declaration from your own domain — see
[Where a declaration lives](#where-a-declaration-lives).

### Minimal valid PROVENANCE.yml

```yaml
provenance: "0.2"
name: "Research Assistant"
description: "Searches the web and summarizes academic papers on a given topic."
```

Three lines. That is the minimum. Everything else is optional but valuable.

---

### Complete PROVENANCE.yml

```yaml
# PROVENANCE.yml
# Provenance Protocol 0.2
# https://github.com/provenance-protocol/provenance-protocol/blob/main/SPEC.md

provenance: "0.2"

# ── Identity ──────────────────────────────────────────────────────────────────

name: "Research Assistant"
version: "1.4.2"
description: >
  Searches the web, retrieves academic papers, and produces structured
  summaries with citations. Designed for researchers and analysts.

# ── Intelligence ──────────────────────────────────────────────────────────────
# A change here is a material change: anyone watching the declaration sees it

model:
  provider: "anthropic"
  model_id: "claude-sonnet-4-5"

# ── Capabilities — what this agent CAN do ─────────────────────────────────────

capabilities:
  - read:web
  - read:pdf
  - read:arxiv
  - write:summaries

# ── Constraints — what this agent will NEVER do ───────────────────────────────
# These are public commitments. The signature makes deleting one detectable.

constraints:
  - no:write:external
  - no:financial:transact
  - no:pii
  - no:delegate:agents

# ── Runtime ───────────────────────────────────────────────────────────────────

runtime:
  type: "task"              # task | persistent | scheduled
  trigger: "api"            # api | webhook | schedule | event

# ── Contact ───────────────────────────────────────────────────────────────────

contact:
  name: "Alice Chen"
  url: "https://alice.dev"
  email: "agent-issues@alice.dev"

# ── Skills ────────────────────────────────────────────────────────────────────
# External skills this agent depends on

skills:
  - id: "web-search-001"
    source: "skillsmp"
    url: "https://skillsmp.com/skills/web-search-001"

# ── Provenance ID ─────────────────────────────────────────────────────────────
# Names where this declaration is published. See Provenance IDs.

provenance_id: "provenance:github:alice/research-assistant"

# ── Identity — optional, makes this file tamper-evident ───────────────────────
# In 0.2 the signature covers every field above. Generate it with
# `npx provenance-protocol sign`. See Signing and Verification.

identity:
  public_key: "MCowBQYDK2VwAyEA..."
  signature: "3n8Kd0vQ..."
  algorithm: "ed25519"
```

---

## Field Reference

### Required

| Field | Type | Description |
|---|---|---|
| `provenance` | string | Spec version: `"0.2"` for new declarations, `"0.3"` when a dependency carries a `pin`, `"0.1"` legacy |
| `name` | string | Human-readable name for this agent |
| `description` | string | What this agent does, in plain language |

### Recommended

| Field | Type | Description |
|---|---|---|
| `version` | string | Semantic version of the agent |
| `model.provider` | string | `anthropic` `openai` `google` `mistral` `meta` `local` `other` |
| `model.model_id` | string | Specific model e.g. `claude-sonnet-4-5` |
| `capabilities` | list | What this agent can do |
| `constraints` | list | What this agent will never do — public commitment |
| `contact.name` | string | Who is responsible for this agent |
| `contact.url` | string | Where to learn more |
| `runtime.type` | string | `task` `persistent` `scheduled` |

### Optional

| Field | Type | Description |
|---|---|---|
| `contact.email` | string | Contact for issues or abuse reports |
| `skills` | list | SkillsMP or other skills this agent depends on |
| `delegates` | list | Sub-agents this orchestrator spawns |
| `provenance_id` | string | Names where this declaration is published — see Provenance IDs |
| `runtime.trigger` | string | `api` `webhook` `schedule` `event` |
| `identity.public_key` | string | Base64 SPKI DER Ed25519 public key |
| `identity.signature` | string | Base64 Ed25519 signature. In 0.2 over the whole declaration; in 0.1 over `<provenance_id>:<public_key>` only. Optional — see Signing and Verification |
| `identity.algorithm` | string | Always `ed25519` |
| `ajp.endpoint` | string | Where this agent accepts jobs under the Agent Job Protocol |

### Operational sections

Optional sections a risk or procurement reviewer asks about first. They are
part of spec 0.2: a declaration that omits them is exactly as valid as before,
and a verifier that predates them still verifies the signature, because
unknown top-level fields are ignored (Conformance, point 3) and the signing
rule is unchanged. Every value is structured — controlled words, ISO codes,
ISO 8601 durations — so they can be compared mechanically.

These are the operator's own signed statements. Their value is that they are
signed, versioned and comparable: a change is provable, dated and attributable.

**`operator`** — the legal party answerable for the agent.

```yaml
operator:
  legal_name: "Acme Robotics Ltd"
  jurisdiction: "GB"                 # ISO 3166-1 alpha-2
  registration: "GB-COH:12345678"    # optional, scheme:number
  security_contact: "https://acme.example/.well-known/security.txt"
```

**`data`** — what happens to data the agent is given.

```yaml
data:
  categories: [customer_content, personal]   # customer_content | personal | special_category | financial | credentials
  retention: "P30D"                          # ISO 8601 duration, or none
  training_use: none                         # none | opt_in | opt_out | yes
  regions: [EU]                              # ISO 3166-1 alpha-2, or EU / EEA
```

**`subprocessors`** — other parties that touch the data. The model provider is
one of them.

```yaml
subprocessors:
  - name: "ModelCo"
    role: model_provider         # model_provider | hosting | storage | tool | other
    regions: [US]
    data_categories: [customer_content]
    provenance_id: null          # when the subprocessor has one
```

**`oversight`** — what needs a human.

```yaml
oversight:
  approval_required: [financial:transact, write:email]   # capabilities used only with per-use approval
  pausable_by_customer: true
```

**`limits`** — hard ceilings.

```yaml
limits:
  - applies_to: financial:transact
    max: 500
    unit: USD                    # ISO 4217, or actions
    per: "P1D"                   # omit for a per-action limit
```

**`dependencies`** — what the agent relies on. Supersedes `skills` and
`delegates`, which remain valid. A dependency with a `provenance_id` has its own
declaration, so a watcher can follow the chain.

```yaml
dependencies:
  - provenance_id: "provenance:domain:search-tool.example"
    kind: mcp_server             # mcp_server | agent | api | package
    purpose: "web search"
  - url: "https://api.payments.example"
    kind: api
```

*Spec 0.3.* A dependency may carry a **`pin`**: the exact version the operator
intends to run, signed with the rest of the declaration. It has at least one
of `version` (exact, as the registry names it — never a range), `integrity`
(a Subresource-Integrity hash: `sha256-`, `sha384-` or `sha512-` and base64),
`commit` (a full git commit id) and `declaration_digest` (for a dependency with
its own declaration: the digest of the declaration relied on).

```yaml
provenance: "0.3"
dependencies:
  - url: "https://www.npmjs.com/package/postmark-mcp"
    kind: mcp_server
    pin: { version: "1.0.15", integrity: "sha512-3u4…" }
  - provenance_id: "provenance:domain:search-tool.example"
    kind: agent
    pin: { declaration_digest: "sha256:9f2c…" }
```

A pin says what should run; a `release` notice's `resolved` claim says what
did ([Notices](#notices)). `checkPins` compares the two: **match**,
**mismatch** (a pin was declared and something else shipped), **unpinned** or
**not reported**. A pin does not make a dependency safe; it makes the choice
explicit, signed and comparable, so a silent change is visible.

**`certifications`** — pointers only. A certification is proven by the
certifier's signed [attestation](#attestations), which `attestation_url`
points to; the declaration naming it proves nothing on its own.

```yaml
certifications:
  - standard: "ISO/IEC 42001"
    attestation_url: "https://certifier.example/att/abc123.json"
```

**`changes`** — advance notice. The operator commits to a minimum notice period
before a weakening change and lists pending changes while they are pending.

```yaml
changes:
  notice_period: "P30D"
  pending:
    - field: constraints
      change: removed
      value: no:write:external
      effective: "2026-11-01"
      reason: "adding CRM sync"
```

**`interop`** — the same agent in other ecosystems. See
[Linking with A2A and MCP](#linking-with-a2a-and-mcp).

```yaml
interop:
  a2a_agent_card: "https://agent.example.com/.well-known/agent-card.json"
  mcp_registry: "com.example/research-server"
```

---

## Capability Vocabulary

Standard capability strings. Using them lets any receiving system filter on
them without a translation table. The same list is published machine-readably
as `vocabulary.json`.
Custom capabilities allowed — prefix with your domain: `acme:custom-capability`

### Read
```
read:web          fetch public web content
read:files        read local files
read:database     query databases
read:email        read email (requires auth)
read:calendar     read calendar (requires auth)
read:code         read code repositories
read:pdf          parse PDF documents
read:images       process images
read:audio        process audio
```

### Write
```
write:files       write local files
write:database    write to databases
write:email       send email
write:code        modify code
write:summaries   generate written content
write:external    any external system write
```

### Execute
```
execute:code      run code in a sandbox
execute:terminal  run terminal commands
execute:browser   control a browser
```

### Financial
```
financial:read       read financial data
financial:transact   initiate financial transactions
```

### Delegation
```
delegate:agents   can spawn or hire sub-agents
delegate:humans   can request human approval
```

### Constraints (no: prefix)

Any capability prefixed with `no:` is a public constraint.
A commitment that this agent will never exercise that capability.

```yaml
constraints:
  - no:financial:transact    # will never initiate transactions
  - no:write:external        # will never write to external systems
  - no:delegate:agents       # will never spawn sub-agents
  - no:pii                   # will never collect personal data
```

**Constraints are the most powerful field in PROVENANCE.yml.**
A receiving system that requires `no:financial:transact` can filter for it.
Under 0.2 the constraint is covered by the signature, so it cannot be quietly
deleted, and a party that sees it broken can say so in a signed
[attestation](#attestations) naming the constraint. The commitment is real.

---

## Provenance IDs

Every agent has a stable identifier derived from where its declaration is
published. No registration required — the ID is computed deterministically
from the public location, and only whoever controls that location can publish
there.

```
provenance:github:owner/repo
provenance:npm:@scope/package-name
provenance:pypi:package-name
provenance:huggingface:owner/space-name
provenance:clawmarket:listing-id
provenance:domain:agent.example.com
provenance:domain:example.com/agents/research
```

### Domain identifiers

`provenance:domain:<hostname>` is for an agent that runs as a service and has no
public repository — which is most commercial agents. Control is proven exactly as
it is for a repository: the declaration is served from the location the
identifier names, and only someone with write access to that location could have
put it there.

The hostname must match exactly. A subdomain is a different party for this
purpose, and treating `agent.example.com` as covered by `example.com` would be
the whole attack.

Optional path segments allow several agents under one domain — those segments
must appear in the retrieval path.

Without this form, a hosted service serving its own declaration could never be
verified as its operator's: the signature would check out while the location
check reported `unchecked`, so no verifier could conclude the declaration was
genuinely theirs.

Add `provenance_id` to your PROVENANCE.yml so any verifier can tie the file
to the location it names.

---

## Where a declaration lives

Anyone holding a provenance id can find the declaration without asking an
index. The identifier names the location:

| Identifier | Declaration is published at |
|---|---|
| `provenance:domain:<host>` | `https://<host>/.well-known/provenance.json` |
| `provenance:domain:<host>/<path>` | `https://<host>/<path>/.well-known/provenance.json` |
| `provenance:github:<owner>/<repo>` | `PROVENANCE.yml` at the root of the default branch |
| other platforms | inside the published package or repository; the location must be supplied |

A declaration served from a domain is JSON — the same fields as the YAML file,
so the same signature verifies either form. It MUST be served over HTTPS, and a
verifier SHOULD NOT follow a redirect to another host: the location check is
what ties the document to its operator.

The location check is structural. For a domain id, the URL's host must equal
the id's host exactly, on the standard port, and the URL's path must **begin**
with the id's path. For a platform id, the owner and name must sit exactly
where that platform puts them — `github.com/<owner>/<repo>/…`,
`raw.githubusercontent.com/<owner>/<repo>/…`, `api.github.com/repos/<owner>/<repo>/…`,
`huggingface.co[/spaces|datasets|models]/<owner>/<repo>/…`,
`npmjs.com/package/<name>`, `registry.npmjs.org/<name>`, `pypi.org/project/<name>/…`.
A repository that merely contains folders with the right names is someone
else's repository, and does not match.

### Finding every passport a site publishes

A host can hold only one declaration at `/.well-known/provenance.json`. A site
that publishes more — agents under paths, or in its repositories — MAY list them
in a **site index** at:

```
https://<host>/.well-known/provenance/index.json
```

```json
{
  "provenance_index": "0.1",
  "site": "example.com",
  "operator": "provenance:domain:example.com",
  "agents": [
    { "provenance_id": "provenance:domain:example.com/agents/support", "name": "Support Agent" },
    { "provenance_id": "provenance:github:example/research-agent" }
  ]
}
```

`site` MUST equal the host the index was fetched from; at most 1,000 entries
are read; `name` is a display hint only. The index is a pointer, never proof:
every listed declaration is verified at its own location exactly as if it had
been found any other way, and an entry off the site is only what the site
claims to publish. A watcher that knows only a host fetches at most these two
files — the declaration and the index — and no other page. Schema:
`schema/index-0.1.json`; reference functions `locateIndex` and `readIndex`.

The agent MAY also expose a live challenge endpoint at
`https://<host>/.well-known/provenance/challenge` (see
[Live proof of key control](#live-proof-of-key-control)).

Services that crawl, index or monitor declarations are applications of the
standard. They may add a great deal — search, history, alerts — but a
declaration's meaning never depends on them.

---

## Signing and Verification

A `PROVENANCE.yml` file is readable by anyone, which also means it is
editable by anyone who re-hosts it. The optional `identity` block makes a
declaration **tamper-evident**: it proves the file was produced by whoever
holds a particular private key, and that nobody has altered it since.

Verification requires no network access and no account. Any implementation
can perform it offline.

### The identity block

```yaml
provenance_id: "provenance:github:alice/research-assistant"

identity:
  public_key: "MCowBQYDK2VwAyEA..."   # base64 of SPKI DER Ed25519 public key
  signature: "3n8Kd0vQ..."            # base64 of raw 64-byte Ed25519 signature
  algorithm: "ed25519"                # always ed25519 in v0.1
```

`public_key` is required when `identity` is present. `algorithm` is optional
and defaults to `ed25519`; no other value is valid.

`signature` is optional, and its presence changes what the block means:

- **`public_key` alone** advertises the key this agent will use to prove
  control live, through the challenge-response below. The declaration itself
  is not tamper-evident. This is the path for an agent with no public
  repository, where there is no stable location to sign against.
- **`public_key` with `signature`** additionally makes the declaration
  tamper-evident. This requires `provenance_id`, since the identity is part
  of what gets signed.

Prefer the signed form wherever the agent has a public location. A verifier
that finds a key with no signature has learned which key to challenge, and
nothing about whether the file has been altered.

### What gets signed — and this differs by version

The `provenance` field selects the rule. A verifier MUST use the rule for the
version the declaration declares, and MUST refuse to guess for a version it does
not know.

#### 0.2 — the whole declaration (use this)

The signed message is the UTF-8 encoding of:

```
provenance-declaration-v1:<canonical JSON of the declaration>
```

The canonical JSON is the **JSON Canonicalization Scheme (JCS, RFC 8785)**
applied to the **parsed** declaration with `identity.signature` removed — it
cannot cover itself. In short: object keys sorted by their UTF-16 code units at
every depth, no insignificant whitespace, and strings and numbers serialised as
ECMAScript `JSON.stringify` does. Using a published scheme means any existing
JCS library produces the same bytes; the same scheme is used to sign A2A Agent
Cards.

Every signature format in this specification — declarations, attestations,
withdrawals — uses this canonical form.

Because canonicalisation applies to the parsed value rather than the file's
bytes, comments, indentation, quoting style and key order do not affect the
signature. A declaration can be reformatted without re-signing. Only JSON
representable values may be signed; a parser that yields dates or other
non-plain objects must be made to yield strings instead.

Every field is covered, so deleting a constraint or adding a capability breaks
the signature. `provenance_id` is not required to verify a 0.2 signature, though
the location check still needs it.

#### 0.1 — the identity only (legacy)

The signed message is the UTF-8 encoding of:

```
<provenance_id>:<public_key>
```

This binds the key to the identity, so a key lifted from one declaration cannot
be replayed under a different `provenance_id`, and it requires `provenance_id`
to be present.

**It does not cover any other field.** A 0.1 declaration's capabilities and
constraints are not protected by its signature: someone with write access to the
location can delete a declared constraint and the signature still verifies.
Location and write access are the only controls there.

0.1 declarations remain readable and verifiable — nothing published stops
working — but new declarations SHOULD use 0.2, and a verifier SHOULD report
which coverage it checked so a reader is not misled about what was proven.

### How to verify

1. Read the `provenance` version, `provenance_id` and the `identity` block.
2. Build the signed message for that version — refuse an unknown version:
   - **0.2:** `provenance-declaration-v1:` + the canonical JSON of the parsed
     declaration with `identity.signature` removed.
   - **0.1:** `<provenance_id>:<public_key>`.
3. Import `public_key` as an Ed25519 SPKI DER key.
4. Verify `signature` over the message bytes.
5. Check that the declaration was retrieved from the location its
   `provenance_id` names. A valid signature at the wrong location is
   unverified.

Ed25519 is deterministic (RFC 8032), so a correct implementation produces
byte-identical signatures for the same key and message. The test vectors in
`test-vectors/` let you confirm this without contacting anyone.

### What verification proves — and what it does not

A valid signature proves the declaration was produced by the holder of that
private key, and:

- under **0.2**, that no field of the declaration has changed since;
- under **0.1**, only that `provenance_id` and `public_key` have not changed —
  everything else is unprotected.

A valid signature does **not** prove:

- that the key belongs to any particular person or organisation, or
- that the declared capabilities or constraints are accurate, or
- that the declaration is still current.

Binding a key to a real-world identity is a separate step. Two mechanisms
are available, and they compose:

**Location.** A declaration fetched from the repository named by its own
`provenance_id` was placed there by someone with write access to it. A
declaration whose `provenance_id` does not match where it was found should
be treated as unverified regardless of its signature — this is the
re-hosting case the substituted-key test vector covers.

**Continuity.** Once a key has been seen for a `provenance_id`, a later
declaration signed by a different key is a key rotation and must be treated
as a material change, not a silent update.

This is the same division of labour as a machine-readable passport: the
document proves its own integrity offline, while identity binding and
current standing are looked up.

### Every signed payload is domain-separated

An agent's key signs several different things. Each payload MUST carry the
prefix for its purpose, so that a signature obtained for one purpose can never
be presented as another:

| Purpose | Signed payload |
|---|---|
| Declaration (0.2) | `provenance-declaration-v1:<canonical JSON>` |
| Live proof of key control | `provenance-challenge-v1:<provenance_id>:<nonce>` |
| Revocation | `provenance-revocation-v1:<provenance_id>` |
| Attestation | `provenance-attestation-v1:<canonical JSON>` |
| Attestation withdrawal | `provenance-attestation-withdrawal-v1:<canonical JSON of {attestation_id, issuer}>` |
| Notice | `provenance-notice-v1:<canonical JSON>` |

This is not a precaution against something hypothetical. In 0.1 a challenge was
signed as `<provenance_id>:<nonce>` and a revocation as
`<provenance_id>:REVOKE` — **the same payload with a chosen nonce.** Any
publicly reachable endpoint that signs a caller-supplied nonce in the 0.1 form
therefore hands out valid revocation signatures for its own key, and a stranger
can revoke the agent. Supplying the public key as the nonce likewise reproduces
the 0.1 declaration signature.

An endpoint that signs a caller-supplied value MUST use the separated challenge
form, and MUST NOT sign the 0.1 payload. Verifiers SHOULD require the separated
form from any agent that exposes a public challenge endpoint.

The 0.1 payloads remain defined so existing deployments keep working, but they
are unsafe to expose and are superseded.

### Live proof of key control

A signature on a file proves the file's origin. It does not prove that the
agent running right now controls that key. For that, a receiving system issues
a nonce and the agent returns a signature over
`provenance-challenge-v1:<provenance_id>:<nonce>`.

Nonces must be single-use and unpredictable. The receiving system verifies the
signature against the public key it already holds for that `provenance_id`.

### Revocation

A key holder revokes a `provenance_id` by signing
`provenance-revocation-v1:<provenance_id>`. The payload contains no
caller-supplied input, so it cannot be produced by a challenge endpoint however
that endpoint is called.

Revocation is the one operation that cannot be verified offline — a verifier
has no way to know a revocation has been issued without asking. Implementations
that cache public keys should re-check revocation status on the same cadence
they would re-check any other freshness signal.

---

## Attestations

A declaration is what an agent says about itself. An **attestation** is what
someone else says about it: a monitor recording what it observed, a platform
recording a report it received, a reviewer recording an approval. The issuer
signs it with its own key, and anyone can verify it offline without asking the
issuer.

Anyone may issue attestations. The standard defines the envelope and how to
verify it; it does not decide whose attestations to trust. That is each
verifier's choice, the same way each border decides which stamps it honours.

### The envelope

```json
{
  "attestation": "0.1",
  "id": "att-0001",
  "kind": "declaration-check",
  "issuer": {
    "provenance_id": "provenance:domain:attester.example",
    "key_fingerprint": "9f2c…64 hex…"
  },
  "subject": {
    "provenance_id": "provenance:github:example/research-agent",
    "declaration_digest": "sha256:4be1…"
  },
  "issued_at": "2026-09-21T09:00:00Z",
  "valid_until": "2026-09-24T09:00:00Z",
  "scope": "Covers the declaration as retrieved at the stated time and location only. Not an assessment of the agent's behaviour.",
  "status_url": "https://attester.example/.well-known/provenance/withdrawals",
  "claims": { "…": "kind-specific" },
  "signature": "base64…"
}
```

| Field | Required | Meaning |
|---|---|---|
| `attestation` | yes | Format version. A verifier MUST refuse to guess at one it does not know. |
| `id` | yes | Unique among this issuer's attestations. |
| `kind` | yes | `declaration-check`, `report`, `decision`, or a custom kind prefixed with the issuer's domain (`example.com:pen-test`). |
| `issuer.provenance_id` | yes | The issuer is an agent like any other: its own declaration publishes its public key. |
| `issuer.key_fingerprint` | yes | SHA-256 of the issuer's public key (SPKI DER), hex. Names which key signed, so a rotation is visible. |
| `subject.provenance_id` / `subject.url` | one of | The agent the attestation is about. `url` is for an agent observed without a declaration. |
| `subject.declaration_digest` | per kind | Which state of the subject's declaration it is about: `sha256:` + hex SHA-256 of the declaration's 0.2 signing payload. Unchanged by formatting or signature; changed by any field. |
| `issued_at`, `valid_until` | yes | RFC 3339 with an explicit offset. |
| `scope` | yes | What this covers and does not, in plain language. It travels with the attestation. |
| `status_url` | no | Where the issuer publishes withdrawals. |
| `claims` | yes | Kind-specific content. |
| `signature` | yes | Base64 Ed25519 over `provenance-attestation-v1:` + the canonical JSON of the attestation with `signature` removed — the same canonicalisation as a 0.2 declaration. |

The schema is `schema/attestation-0.1.json`.

### Core kinds

**`declaration-check`** — the issuer fetched the subject's declaration and
records what it found: `retrieved_from`, `retrieved_at`, `signature`
(`declaration` / `identity` / `none` / `invalid`), `location`
(`match` / `mismatch` / `unchecked`), the subject's `key_fingerprint`, and
optionally `changes` since the `previous_digest` it saw. Requires
`subject.declaration_digest`.

**`report`** — an identified party reported something about the subject. The
issuer attests **that the report was made**, by whom and when — not that it is
true. `reporter` (with `disclosed: false` when the issuer holds the reporter's
identity but does not publish it), `reported_at`, `category`, `relates_to`
(the declared constraints or capabilities concerned, in the standard
vocabulary), `summary`, `state` (`received` / `responded` / `disputed` /
`withdrawn` / `resolved`) and the subject's `response`.

**`affiliation`** — an organisation states that it operates the subject agent,
with a specific key: `relationship` (`operated_by`), `unit` (the department or
team, optional) and `subject_key_fingerprint`. Requires
`subject.provenance_id`. It covers that key only; a new key needs a new
affiliation. See [Private and internal agents](#private-and-internal-agents).

**`decision`** — someone approved the subject for a use, or withdrew that
approval: `outcome` (`approved` / `withdrawn`), `use`, `decided_at`,
`decided_by`. Requires `subject.declaration_digest`, so the decision is pinned
to the exact declared state it was made against — and a later change to the
declaration is visibly a change to the basis of the decision.

### Validity and expiry

Every attestation expires. Absence of news cannot be carried in a document, so
a short validity window is what makes staleness visible: when the issuer stops
looking, its attestations stop being current.

An issuer SHOULD NOT issue a window longer than it can honour — typically no
more than twice the interval at which it re-checks. A window renewed many times
within its own life can never lapse, and expiry then means nothing.

A verifier MUST keep these outcomes apart:

| Status | Meaning |
|---|---|
| `valid` | genuine, and inside its validity window |
| `expired` | genuine, past `valid_until` — stale, not forged |
| `not_yet_valid` | genuine, `issued_at` in the future (beyond clock tolerance) |
| `invalid` | forged, altered, malformed, or signed by a key other than the one named |
| `unchecked` | could not be checked — no issuer key, unknown version |

The signature is checked **before** the dates. Anyone can write a date, so a
forgery must always read as `invalid`, never as merely `expired`.

### Finding the issuer's key

The verifier needs the issuer's public key. The normal source is the issuer's
own declaration, verified like any other and located from
`issuer.provenance_id`. A verifier SHOULD pin the issuer's key fingerprint, and
treat an attestation naming a different fingerprint as a key rotation by the
issuer — to be accepted deliberately, not silently.

### Withdrawal

An issuer withdraws an attestation before it expires by signing
`provenance-attestation-withdrawal-v1:` + the canonical JSON of
`{"attestation_id": …, "issuer": …}` and publishing it at the attestation's
`status_url`. Like key revocation, a withdrawal cannot be discovered offline;
expiry is what bounds how long a withdrawn attestation can go unnoticed.

### What an attestation proves

A valid attestation proves that the issuer said this, when, and about which
state of the subject. It does not prove the issuer is right. Issuers SHOULD
attest facts they observed rather than conclusions about fitness, and say so
in `scope`.

---

## Notices

An attestation is what someone else says about an agent. A **notice** is what
the operator says about its own agent as things happen, signed with the
agent's own key. Notices let a watcher learn of a change when it happens
instead of on its next scheduled check.

```json
{
  "notice": "0.1",
  "id": "n-2026-09-24-001",
  "event": "declaration-published",
  "provenance_id": "provenance:domain:agent.example.com",
  "key_fingerprint": "…64 hex…",
  "issued_at": "2026-09-24T10:00:00Z",
  "claims": {
    "declaration_url": "https://agent.example.com/.well-known/provenance.json",
    "declaration_digest": "sha256:…",
    "running_version": "4.2.0"
  },
  "signature": "base64…"
}
```

The signature is Ed25519 over `provenance-notice-v1:` + the canonical JSON of the
notice without `signature`. `key_fingerprint` names the signing key. The schema
is `schema/notice-0.1.json`.

| Event | Claims | Sent when |
|---|---|---|
| `declaration-published` | `declaration_url`, `declaration_digest`, `running_version`, and optionally the full `declaration` | the service starts, or the declaration changes |
| `release` | `version`, `commit`, `declaration_digest`, and from format 0.2 optionally `resolved` | CI ships a release — ties promises to a build |
| `key-rotation` | `new_public_key`, `reason` | the operator replaces its key |
| `incident` | `severity`, `summary`, `started_at`, `resolved_at`, `relates_to` | the operator discloses its own incident |

**Notice format 0.2** (`"notice": "0.2"`) is 0.1 plus an optional `resolved`
claim on `release` and `declaration-published`: what the build actually
resolved, one entry per dependency, each naming it by `provenance_id` or `url`
with any of `version`, `integrity`, `commit` or `declaration_digest`. Signed by
the agent's key like every notice, it is what pins are checked against.

**Key rotation is signed by the old key.** The notice is the old key vouching
for the new one. A verifier that pinned the old key accepts the new key as a
continuation, not as an impostor. A rotation signed by the new key proves
nothing, and a verifier MUST NOT accept it as continuity. If the old key is
lost or compromised, there is no continuity to prove: the operator publishes a
new declaration, and watchers treat it as a new key, which is the truth.

### Delivery

A notice is signed, so how it travels needs no trust:

- **Pull.** The operator MAY publish recent notices, newest first, as a JSON
  array at `https://<host>/.well-known/provenance/notices` for domain ids. Any
  watcher can read them without asking permission.
- **Push.** The operator MAY send each notice by HTTPS `POST`, as
  `application/json`, to watchers it chooses. A watcher MUST verify it and MUST
  NOT treat an unverifiable notice as a change.

No particular watcher is part of the standard. An operator picks any, several or
none.

A notice is the operator's own statement. It is evidence of what they said and
when, like a declaration — not proof that it is true.

---

## Private and internal agents

Many agents are never exposed to the internet: a company's own assistants in
HR, finance or support, running on internal hosts. They use the same
declarations, notices and attestations, with two differences.

**Delivery instead of fetching.** A watcher outside the network cannot fetch
the declaration, so the agent delivers it: a `declaration-published` notice
carrying the full signed `declaration` in its claims, sent to watchers the
operator chooses. A receiver MUST check that the declaration verifies in full
(spec 0.2), that its digest equals `declaration_digest`, and that the notice is
signed by the declaration's own key. That proves the notice and the declaration
belong together. It does not prove who operates the agent. The watcher never
needs access to the network, credentials, or the agent's key.

**Affiliation instead of location.** An internal hostname proves nothing to an
outsider, so the location check cannot tie the declaration to its operator.
Instead the operating organisation signs an `affiliation` attestation with its
own key: this agent id, with this key, is operated by us (and, optionally, by
this unit). The organisation's key is published in its own declaration at its
public domain — `provenance:domain:corp.example` — and verified like any other.

A verifier MAY accept an affiliation in place of the location check when it is
valid, of kind `affiliation`, names the declaration's `provenance_id`, and its
`subject_key_fingerprint` equals the declaration's key. Nothing else stands in
for location. There is still no central authority: each organisation vouches
only for its own agents.

Internal declarations and attestations need not be published anywhere. They are
shared with whoever the organisation chooses.

---

## Comparing declarations

Two watchers looking at the same two versions of a declaration should report
the same changes and agree on which ones matter. This section fixes how.

Compare the parsed declarations field by field, ignoring `identity.signature`.
List items are matched by identity where they have one (a subprocessor by
`name`, a dependency by `provenance_id` or `url`, a limit by `applies_to`,
`unit` and `per`, a certification by `standard`), so an edited entry is one
modification rather than a removal and an addition.

Each change is classified for someone relying on the agent:

| Weakened | Strengthened |
|---|---|
| a constraint removed | a constraint added |
| a stated `retention`, a `training_use` other than `yes`, or every `region` withdrawn (the promise becomes unknown) | a `retention` or a `training_use` other than `yes` stated where none was |
| a capability added | a capability removed |
| a data category, region or subprocessor added; a subprocessor gaining a region or data category | a certification added |
| retention lengthened; `training_use` moving towards `yes` | retention shortened; `training_use` moving towards `none` |
| a capability no longer needing human approval; no longer pausable by the customer | a capability newly needing approval |
| a limit raised or removed | a limit lowered or added |
| a dependency added; a dependency's `pin` removed | a dependency's `pin` added |
| a certification removed | |
| the notice period shortened or removed | a notice period lengthened or added |
| `identity.public_key` or `provenance_id` changed | |

Everything else is neutral — including a `pin` moved to another version, which
is reported so a watcher can judge the new target. A weakening is **announced** when the previous
version listed it in `changes.pending`. A weakening that took effect without
having been pending for the declared `notice_period` breaks the operator's own
promise, which a watcher with the history can show.

A changed key is classified as weakened until a valid `key-rotation` notice
signed by the previous key explains it.

The reference implementation is `compareDeclarations` in this package.

---

## Linking with A2A and MCP

The same agent may also publish an A2A Agent Card or an entry in the MCP
Registry. The Provenance declaration adds what those do not carry — explicit
constraints, the operational sections, stamps from third parties — and links
to them rather than replacing them.

A link is **confirmed** when both ends are controlled by the same party:

- **A2A.** A declaration with a `provenance:domain:<host>` id and an Agent Card
  at `https://<host>/.well-known/agent-card.json` on the same host are linked by
  location: whoever controls the host published both. `interop.a2a_agent_card`
  names the card explicitly; when it points to a different host, the link is
  **claimed**, not confirmed, unless that card links back.
- **MCP.** The MCP Registry verifies namespace ownership by domain: a server
  named `com.example/…` was published by whoever controls `example.com`. A
  declaration with id `provenance:domain:example.com` naming that server in
  `interop.mcp_registry` is confirmed by the same domain control. Likewise a
  server named `io.github.<owner>/…`, which the registry ties to that GitHub
  account, is confirmed for a `provenance:github:<owner>/…` declaration. Any other
  pairing — including a subdomain, which on shared hosting is often a
  different party — is claimed.

A watcher MUST report a claimed link as claimed. Treating a link as confirmed
without matching control would let anyone attach their declaration to a
well-known agent.

An agent that has only an A2A card or an MCP entry can still be the subject of
an attestation, named by `subject.url`. When it later publishes a declaration,
the history accumulated about that URL carries over.

---

## Conformance

An implementation of this specification is conformant if it:

1. Accepts every file that validates against the schema for its declared
   version — `schema/provenance-0.1.json`, `schema/provenance-0.2.json` or
   `schema/provenance-0.3.json`.
2. Treats `provenance`, `name` and `description` as required and everything
   else as optional.
3. Ignores unrecognised top-level fields rather than rejecting the file.
   Future spec versions add fields; a `0.1` reader must not break on them.
4. Treats `identity.signature` as optional, and an unsigned `identity`
   block as advertising a key rather than attesting the file.
5. Applies the signing rule for the version the declaration declares, refuses
   to guess for an unknown version, and reports which coverage it checked —
   a reader must not be left thinking a 0.1 signature protected the
   declared constraints.
6. Reproduces every signature in `test-vectors/signatures-0.1.json` and every
   declaration in `test-vectors/declarations-0.2.json` marked `valid`, and
   refuses every one marked `invalid`.
7. Treats a declaration whose `provenance_id` does not match its retrieval
   location as unverified.
8. For attestations: refuses unknown `attestation` versions, checks the
   signature before the validity window, keeps `valid`, `expired`,
   `not_yet_valid`, `invalid` and `unchecked` distinct, and reproduces every
   outcome in `test-vectors/attestations-0.1.json`.
9. For notices: refuses unknown `notice` versions, accepts a key rotation only
   when signed by the previous key, and reproduces every outcome in
   `test-vectors/notices-0.1.json`.
10. Accepts an affiliation in place of the location check only when it binds
    the declaration's exact `provenance_id` and key fingerprint.

Points 6 to 10 are what make independent implementations agree. An
implementation that passes the test vectors interoperates with every other
one that does, with no reference to any particular service.

A reference implementation ships in this repository as the `provenance-protocol`
package: verification, attestations and declaration location work offline in
any JavaScript runtime with Web Crypto, and signing and schema validation in
Node. It is one implementation, not the definition — the vectors are the
definition.

---

## Implementing this specification

This specification, its JSON Schema and its test vectors are published under
the Apache License, Version 2.0. You may implement them in any language, for any purpose,
commercial or otherwise, without permission, notification or fee.

Nothing in this specification requires contacting any particular service. A
conformant implementation can read, validate and cryptographically verify a
declaration entirely offline. Services built on this protocol — indexes,
monitors, attesters — are applications of the standard, not part of it.

---

## Versioning

The `provenance` field records which spec version you are using, and it is what
a reader uses to decide how to interpret the file.

We commit to backwards compatibility: a `0.1` file will always be readable and
verifiable, whatever later versions say. Fields are never removed.

Usually a new version only adds fields. Version 0.2 is the exception so far — it
changed what an existing field *covers*, because `identity.signature` in 0.1
protected only the identity and left the declared capabilities and constraints
unprotected, which was weaker than readers assumed. Rather than redefine 0.1
under declarations already published, 0.2 defines the stronger rule and the
`provenance` field keeps the two apart. A verifier implements both and applies
the one the declaration asks for.

Where a version changes the meaning of an existing field, it will always do so
by declaring a new version, never by reinterpreting an old one.

Version 0.3 only adds: the `pin` on a dependency. It signs exactly as 0.2. It is
a new version rather than a quiet addition because 0.2's schema refuses fields
it does not know, so a 0.2 validator would reject a pinned declaration; the
`provenance` field tells a reader which rules to apply. Notices likewise gain
format 0.2 for the `resolved` claim.

---

## FAQ

**Do I have to register anywhere?**
No. Publish the declaration at the location your provenance id names and it
can be found and verified by anyone. Indexes may list you; none is required.

**What if my agent has no public repository?**
Serve the declaration from your own domain at
`/.well-known/provenance.json` and use a `provenance:domain:` id. That is the
path for most hosted services.

**What if my constraints are inaccurate?**
Constraints are public commitments. Be honest. Under 0.2 they are covered by
your signature, and anyone who sees one broken can publish a signed report
naming it.

**Can I use custom capability strings?**
Yes. Prefix with your domain: `acme:internal-tool`. Standard vocabulary
recommended for interoperability.

**What happens when I change my model?**
Change the declaration and sign it again. Anyone watching it sees exactly which
field changed. Transparency is the point.

**Who decides whose attestations count?**
Each verifier. The standard makes every attestation checkable; trusting a
particular issuer is a decision the standard deliberately leaves to the reader.

---

*Provenance Protocol — Apache License 2.0*
*https://github.com/provenance-protocol/provenance-protocol*
