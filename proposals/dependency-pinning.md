# Proposal: Pinning dependencies

Status: **adopted** in spec 0.3 and notice format 0.2 — `pin`, change rules, `resolved`, `checkPins` and `requirePinned` are in provenance-protocol 0.14.0. Not yet built: `provenance-action` writing `resolved` from the lockfile, and `provenance check` comparing a lockfile with pins.
Decisions on the open questions: `integrity` accepts SRI only (a PyPI sha256 hex digest is written in SRI form); unpinned dependencies are reported only on request (`requirePinned`); `resolved` is allowed on `declaration-published` as well as `release`.
Date: 28 September 2026

## Problem

A declaration can say what an agent relies on (`dependencies`), but not *which
exact version* of it. That leaves a gap that 2026's incidents walked straight
through:

- **A dependency turns malicious between versions.** The `postmark-mcp` server
  shipped fifteen clean releases, then one that quietly copied every email to
  an outside address. An agent that depended on "postmark-mcp" was declaring
  the same thing before and after.
- **A pin that is never checked.** In *Plugin4Shell* (disclosed 17 September
  2026), four major coding agents pinned plugins to a commit but never verified
  that the checkout resolved to it; an attacker controlling the plugin's
  repository could serve other code while the pin still looked honoured.

A watcher today can see that an agent depends on something. It cannot see
whether the agent committed to a specific version, nor notice when what runs is
not what was committed to.

## Proposal

### 1. An optional `pin` on each dependency

```yaml
dependencies:
  - kind: mcp_server
    url: https://www.npmjs.com/package/postmark-mcp
    purpose: send transactional email
    pin:
      version: 1.0.15
      integrity: sha512-3u4…            # the package's published integrity hash (SRI form)
  - kind: agent
    provenance_id: provenance:domain:search.example.com
    pin:
      declaration_digest: sha256:9f2c…   # the exact declaration relied on
  - kind: package
    url: https://github.com/acme/plugin
    pin:
      commit: 4e1d0a7c9b…                # full git commit
```

`pin` is an object with at least one of:

| Field | Meaning |
|---|---|
| `version` | Exact version string as the registry names it. Not a range. |
| `integrity` | Subresource-Integrity-style hash of the artifact: `sha256-`, `sha384-` or `sha512-` followed by base64. |
| `commit` | Full hexadecimal commit id (40 or 64 characters). |
| `declaration_digest` | For a dependency with a `provenance_id`: the `declarationDigest()` of the declaration relied on. |

A pin is a statement about what the operator *intends* to run. It is signed
with the rest of the declaration, so it cannot be edited without breaking the
signature.

### 2. Change rules

In `compareDeclarations`:

- a pin **removed** from a dependency is `weakened` (looser than before);
- a pin **added** is `strengthened`;
- a pin **modified** is `neutral` — upgrading is normal — but is reported, so a
  watcher can decide whether the new target is acceptable.

### 3. What was actually resolved: a `resolved` claim on `release` notices

A pin says what should run. To catch the Plugin4Shell pattern — a pin that
*looks* honoured — the build that ships must say what it actually got. The
`release` notice gains an optional claim:

```json
"claims": {
  "version": "4.2.0",
  "commit": "a1b2c3d…",
  "declaration_digest": "sha256:…",
  "resolved": [
    { "url": "https://www.npmjs.com/package/postmark-mcp", "version": "1.0.15", "integrity": "sha512-3u4…" }
  ]
}
```

Signed by the agent's key, like every notice. A verifier compares each
`resolved` entry with the matching `pin`:

- **match** — what shipped is what was pinned;
- **mismatch** — a pin was declared and something else shipped;
- **unpinned** — something shipped that the declaration does not pin.

`provenance-action` can produce `resolved` from the lockfile at build time, with
no key in CI (the service signs, as today).

### 4. SDK

- `checkPins(declaration, releaseNotice)` → `{ dependency, result: 'match' | 'mismatch' | 'unpinned' }[]`, offline.
- `checkDeclaration(…, { requirePinned: true })` refuses a declaration whose
  dependencies are not all pinned.
- `provenance check` warns when a lockfile's resolved version differs from a
  declared pin.

## What it does not do

It does not detect malicious code. A pinned version can itself be malicious; the
pin makes the choice explicit, signed and comparable, and makes a silent change
visible. Deciding whether a version is safe stays with the operator and its
customers.

## Compatibility

Dependency items are `additionalProperties: false` in schema 0.2, so a 0.2
validator would reject a declaration carrying `pin`. The field therefore lands
in **spec 0.3** (`provenance: "0.3"`), with 0.2 declarations remaining valid
unchanged. The signing payload and canonical form are unaffected. Once
published, the field names are fixed — which is why this is a proposal first.

## Open questions

1. Should `integrity` accept only SRI, or also registry-specific forms (npm's
   `sha512-…` is already SRI; PyPI publishes sha256 hex)?
2. Should an unpinned dependency be reported by default, or only on request
   (`requirePinned`)? Reporting by default is noisier but closer to the lesson
   of 2026.
3. Should `resolved` also be allowed on `declaration-published` notices, for
   services without a CI release step?

## For watchers (non-normative)

A monitoring service can alert when a watched agent's pin is removed, when a
release notice reports a mismatch, and — for a `declaration_digest` pin — when
the pinned dependency's current declaration no longer has that digest.
