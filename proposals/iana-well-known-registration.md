# Registering this standard's well-known URIs with IANA

Status: **not pursued for now** — kept for when registering is worth the effort; the names are in use regardless.
Date: 1 October 2026

## Why

Names under `/.well-known/` are shared by every site on the internet. RFC 8615
keeps a public registry of them at IANA so that two standards never claim the
same name. This standard already uses two:

- `provenance.json` — where a domain's declaration lives;
- `provenance/` — a prefix for the live challenge, notices, withdrawals and
  (proposed) the site index.

Neither is registered yet. "Provenance" is a common word; registering reserves
the names for this use before another project picks them.

## How (RFC 8615, section 3.1)

- Send each request below to **wellknown-uri-review@ietf.org**. A designated
  expert reviews it, usually within a few weeks, and IANA records it.
- **No fee.** Registration is free.
- "Provisional" status needs only a stable, public description; "permanent"
  needs a published specification the expert judges sufficient. SPEC.md is
  public and versioned, so we request **permanent**, and accept provisional if
  the expert prefers.
- The expert may ask for changes; answer on the list. Approval is likely but not
  guaranteed.

## Request 1

```
Subject: Well-known URI registration request: provenance.json

URI suffix: provenance.json

Change controller: The Provenance Protocol project
  (https://github.com/provenance-protocol), <CONTACT EMAIL>

Specification document(s): The Provenance Protocol specification, section
  "Where a declaration lives":
  https://github.com/provenance-protocol/provenance-protocol/blob/main/SPEC.md#where-a-declaration-lives

Status: permanent

Related information: Serves a JSON document — an AI agent's signed
  declaration of its identity, capabilities, constraints and data handling —
  for the agent identified by provenance:domain:<host>. The document is signed
  with Ed25519 over a canonical JSON form (RFC 8785), so any party can verify
  it offline. Served over HTTPS only; verifiers do not follow redirects to
  another host, since the location is what ties the declaration to the site's
  operator. Open-source reference implementation (Apache-2.0):
  https://github.com/provenance-protocol/provenance-protocol
```

## Request 2

```
Subject: Well-known URI registration request: provenance

URI suffix: provenance

Change controller: The Provenance Protocol project
  (https://github.com/provenance-protocol), <CONTACT EMAIL>

Specification document(s): The Provenance Protocol specification:
  https://github.com/provenance-protocol/provenance-protocol/blob/main/SPEC.md
  (sections "Live proof of key control", "Notices" and "Attestations")

Status: permanent

Related information: A prefix for resources that accompany an agent's
  declaration at the same origin:
  - /.well-known/provenance/challenge  (POST) a live proof that the service
    holds the declared key, signed over a domain-separated payload
  - /.well-known/provenance/notices    (GET) the operator's recent signed
    notices about its agent (new version, release, key rotation, incident)
  - /.well-known/provenance/withdrawals (GET) an attester's signed
    withdrawals of attestations it issued
  - /.well-known/provenance/index.json (GET, proposed) a list of the
    declarations a site publishes
```

## Before sending

1. Fill in `<CONTACT EMAIL>` — an address that will keep working for years
   (for example a standard-specific address, not a person's).
2. Send from that address, so the expert's questions reach it.
3. Once registered, add the IANA registry entries to SPEC.md.
