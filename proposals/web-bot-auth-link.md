# Proposal: Linking a declaration to Web Bot Auth

Status: **draft for discussion — held** until Web Bot Auth is final at the IETF; its directory location and key format may still change, and a field in this standard cannot be taken back once published.
Date: 28 September 2026

## Problem

Websites are starting to decide, request by request, which agents they let in.
In September 2026 Amazon blocked a major assistant's agent from its store;
Shopify signs and authenticates agents for higher rate limits; Cloudflare's
**Web Bot Auth** (HTTP Message Signatures, in IETF standardisation) and Visa's
Trusted Agent Protocol let an agent prove *who is knocking* with a signature on
each request.

Those answer "is this request from agent X?". They do not answer what agent X
promised, who answers for it, or whether that changed — which is what a
Provenance declaration records. A site that verifies a Web Bot Auth signature
has no standard way to find the agent's declaration, and a watcher of a
declaration has no standard way to know it belongs to the agent sending those
requests.

The declaration already links to the same agent in two other ecosystems
(`interop.a2a_agent_card`, `interop.mcp_registry`), with a rule that a link is
**confirmed** only when the same party provably controls both ends, and
**claimed** otherwise. This proposal adds the third.

## Proposal

### 1. A new interop field

```yaml
interop:
  a2a_agent_card: https://agent.example.com/.well-known/agent-card.json
  mcp_registry: com.example/agent
  web_bot_auth: https://agent.example.com/.well-known/http-message-signatures-directory
```

`web_bot_auth` is the HTTPS URL of the agent's Web Bot Auth key directory — the
signed JSON Web Key Set that sites fetch to verify its request signatures.

### 2. When the link is confirmed

`checkInteropLinks(declaration)` gains `webBotAuth: 'confirmed' | 'claimed' | 'none'`:

- **confirmed (same key)** — the directory contains an Ed25519 JWK whose key
  equals the declaration's `identity.public_key`. Strongest: one key, two uses.
- **confirmed (same controller)** — the declaration is a `provenance:domain:`
  id and the directory is served from that exact host (not a subdomain), as for
  A2A cards today.
- **claimed** — anything else. Shown, never trusted.

Confirming the "same key" case needs a fetch; `checkInteropLinks` stays offline
and reports the host rule, and a new `confirmWebBotAuth(declaration, directory)`
checks the key match given the fetched directory.

### 3. The other direction: finding the declaration from a request

A site that has verified a Web Bot Auth signature knows the directory's origin
(the `Signature-Agent` header). It can then look for a declaration at that
origin's standard address — `https://<host>/.well-known/provenance.json` — and
apply the confirmation rule above. No new header is needed; the standard
locations meet.

## What it does not do

It does not replace request signatures, and it does not make a declaration a
credential for access. A site still decides for itself what to let in; this lets
it base that decision on the agent's signed promises and their history, not
only on its name.

## Compatibility

`interop` is `additionalProperties: false` in schema 0.2, so the field lands in
**spec 0.3**. Additive; 0.2 declarations are unchanged. Once published the
field name is fixed, so this is a proposal first.

## Open questions

1. Should reusing the declaration key as a Web Bot Auth key be recommended, or
   only recognised? Reuse gives the strongest link but couples key rotation for
   both purposes; a `key-rotation` notice would then have to cover both.
2. Should Visa's Trusted Agent Protocol and similar attestation schemes get
   their own interop fields, or one generic `request_signing` list?

## For watchers (non-normative)

A monitoring service can show the link as confirmed or claimed exactly as the
SDK reports it, and alert when a confirmed link becomes claimed — for example,
when the directory stops containing the declared key.
