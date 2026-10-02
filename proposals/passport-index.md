# Proposal: A site index of passports

Status: **adopted** — index format 0.1 is in SPEC.md ("Finding every passport a site publishes"); `locateIndex`, `readIndex` and `validateIndex` are in provenance-protocol 0.15.0, and provenance-middleware 0.6.0 can serve an index. Open questions left for later: signing the index, and digests per entry.
Date: 1 October 2026

## Problem

A domain's declaration lives at one fixed address,
`https://<host>/.well-known/provenance.json`, so a watcher can find it with a
single request — no crawling. But a domain can hold only one declaration there.
Everything else is invisible to anyone who does not already know where to look:

- **several agents on one site**, published under paths
  (`provenance:domain:example.com/agents/support` →
  `https://example.com/agents/support/.well-known/provenance.json`);
- **agents the same company publishes elsewhere**, typically in GitHub
  repositories (`provenance:github:example/research-agent`).

A buyer who knows only the company's website, or a watcher that observed the
company's A2A card before it published any declaration, has no way to learn
that these passports exist.

Path-based locations have a second weakness: RFC 8615 defines well-known URIs
only at the root of an origin. `https://<host>/<path>/.well-known/…` is a
convention of this standard, not a well-known URI in RFC 8615's sense. A
root-level index gives every passport on a site, wherever it lives, one
discovery point that is.

## Proposal

### 1. The index document

At `https://<host>/.well-known/provenance/index.json`, a site MAY publish:

```json
{
  "provenance_index": "0.1",
  "site": "example.com",
  "updated_at": "2026-10-01T09:00:00Z",
  "operator": "provenance:domain:example.com",
  "agents": [
    { "provenance_id": "provenance:domain:example.com/agents/support", "name": "Support Agent" },
    { "provenance_id": "provenance:domain:example.com/agents/billing" },
    { "provenance_id": "provenance:github:example/research-agent", "name": "Research Agent" }
  ]
}
```

| Field | Meaning |
|---|---|
| `provenance_index` | Format version, `"0.1"`. Required. |
| `site` | The host serving the index. Required; MUST equal the host it was fetched from. |
| `updated_at` | When the list last changed. Optional. |
| `operator` | The site operator's own provenance id, if it has one (the key it vouches for internal agents with). Optional. |
| `agents` | Required. Each entry has a `provenance_id` and MAY have a `name`, purely as a display hint. At most 1,000 entries. |

The index is **not signed** and needs no key: it is published at the site's own
address, which is what it speaks for, and it proves nothing about the
declarations it lists (see 2).

### 2. A pointer, never proof

- Every listed declaration is fetched from **its own** location and verified
  exactly as if it had been found any other way: signature, and location
  matching its id. The index adds nothing to that result.
- A listed declaration that does not verify is reported as it is — not genuine,
  or could not be checked — never hidden or excused by the index.
- An entry may point off-site (a GitHub repository, another domain). That says
  the site's operator claims to publish it; it does not make the off-site
  declaration the site's. A watcher MAY show such a link as **claimed**, and as
  **confirmed** only when the off-site declaration names the same `operator`
  and verifies with a key the operator vouches for (for example by an
  `affiliation` attestation). This follows the confirmed/claimed rule already
  used for A2A and MCP links.

### 3. Discovery order

A watcher that knows only a host SHOULD request, at most daily:

1. `https://<host>/.well-known/provenance.json` — the site's own declaration;
2. `https://<host>/.well-known/provenance/index.json` — the index, if any.

A 404 for either is not an error; it means the site publishes none. Neither
request involves fetching any other page of the site.

### 4. SDK

- `locateIndex(host)` → the index URL.
- `readIndex(document, { fetchedFrom })` → validated entries, refusing an
  index whose `site` differs from the host it came from.
- Schema `schema/index-0.1.json`, and `validateIndex` in `/validate`.
- The middleware MAY serve the index for a service that hosts several
  declarations.

## What it does not do

It does not register anything with anyone, and it is optional: a site with one
agent at the root needs no index. It makes no declaration more trustworthy. It
only lets a watcher find, with one request, the passports a site says it
publishes.

## Privacy

Publishing an index lists the site's agents publicly. That is the operator's
choice; internal agents should not be listed (they are delivered to the
watchers the operator chooses, not published).

## Compatibility

A new document type with its own version; declarations, notices and
attestations are unchanged. The path lives under `/.well-known/provenance/`,
the prefix this standard already uses for challenges, notices and withdrawals
(see the registration request in `iana-well-known-registration.md`).

## Open questions

1. Should the index be signable (optional `signature` by the `operator` key),
   so a copy kept elsewhere stays attributable? Not needed for discovery.
2. Should entries carry the declaration's last known digest, so a watcher can
   skip unchanged ones? Saves requests, but goes stale easily.
