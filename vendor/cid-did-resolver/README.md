# @thisdid/cid-did-resolver

[`did:cid`](https://github.com/archetech/archon) resolution for the DIF
[`did-resolver`](https://www.npmjs.com/package/did-resolver) interface — as a
**resolution-only Archon Gatekeeper**, not a proxy.

Instead of trusting a Gatekeeper's answer, this driver fetches the DID's
accepted operation history (`POST {gatekeeper}/dids/export`) and re-derives
the document itself, verifying every operation before applying it:

- the DID suffix must equal the CIDv1 (JSON codec · SHA-256 · base32) of the
  JCS-canonicalized genesis operation, and every event must target the DID;
- every proof must be a well-formed legacy `EcdsaSecp256k1Signature2019` or
  `DataIntegrityProof` / `archon-ecdsa-secp256k1-jcs-2026` proof (which also
  signs its proof configuration), verified, low-S, under the key its
  `verificationMethod` names;
- agent operations are authorized by the predecessor document (key rotation
  honored); asset operations by their owner agent, selected at the
  operation's chain position when its receipt and the owner's history are
  chain-anchored, otherwise at `proof.created`;
- operations must link to their predecessor (`previd`), follow the state
  transition rules (controllers, registration replacement, unique method ids)
  and never extend a deletion; resolution returns the most recent
  *confirmed* version, with DID Core metadata only.

Only event **discovery** is delegated: the Gatekeeper can withhold the tail
of a chain or misreport receipts, but cannot forge, alter, or reorder signed
state — any operation that does not verify fails the resolution.

Normative target: the did:cid Method Specification,
[`archetech/didcid-specs@e8aace4`](https://github.com/archetech/didcid-specs/tree/e8aace4d79542aed0ea58b4e252f260f176a70e3).
Port source: [`@didcid/gatekeeper`](https://www.npmjs.com/package/@didcid/gatekeeper)
0.8.0 (MIT, archon commit `9924993`), `resolveDIDAt` with `confirm` and
`verify` as Archon's conformant `/1.0/identifiers` surface runs it.
[REFERENCE-MAP.md](REFERENCE-MAP.md) maps every function and check to both,
lists where the specification overrides the code, and the open questions.
The resolution options `versionTime` and `versionSequence` are honored.

```ts
import { Resolver } from "did-resolver";
import { getResolver } from "@thisdid/cid-did-resolver";

const resolver = new Resolver(
  getResolver({ gatekeeperUrl: "https://archon.technology/api/v1" }),
);
const result = await resolver.resolve(
  "did:cid:bagaaieraoqzjgi6537vyu3h3rtetki5g4bk6stzyqplcmwpqgqxp7fewowcq",
);
```

### Resource budgets

One resolution fetches at most `maxDids` distinct DID histories (default 32:
the DID plus the owners and transferees its operations name, within a
Worker's subrequest budget) and finishes within `deadlineMs` (default 7000 ms,
below the ThisDID gateway's 8 s step timeout); every Gatekeeper request is
also bounded by `timeoutMs` (default 6000 ms) and each history by `maxEvents`
(default 1024). Exceeding `maxDids` or `deadlineMs` fails closed with the
registered DID Resolution error `internalError`. An owner's history is
verified once per resolution and its states reused by every asset operation
it authorizes, so the cost grows with the sum of the histories, not their
product.

Runs anywhere `fetch`, `TextEncoder`, and `atob` exist — including Cloudflare
Workers. Dependencies are pure JS: `@noble/curves`, `@noble/hashes`,
`multiformats`.

## Command line

The package ships a standalone resolver command, `thisdid-resolve-cid`, that
needs nothing but Node 20+ — no resolver service, no Worker:

```sh
npx thisdid-resolve-cid did:cid:bagaaieraoqzjgi6537vyu3h3rtetki5g4bk6stzyqplcmwpqgqxp7fewowcq
# from a checkout: node lib/bin.js <did>
```

It prints the DIF resolution result as JSON on stdout and exits 0 when the
DID resolved, 1 when the resolver reported an error
(`didResolutionMetadata.error`), 2 on a usage or configuration error.
`--version-time <iso>` and `--version-sequence <n>` select a version (the
resolution options of resolution.md); `--version-id <id>` is passed through but
ignored, since `versionId` is not a resolution selector for did:cid
(resolution.md L20). `--compact` prints single-line JSON, `--help` prints the
full reference. Host options are read from the environment, under the same names the ThisDID
Worker uses, so one `.dev.vars` file drives both:

| Variable | Effect |
| --- | --- |
| `CID_GATEKEEPER_URL` | Archon Gatekeeper base URL (`gatekeeperUrl`; default: the public deployment) |
| `CID_TIMEOUT_MS` | per-request bound in ms (`timeoutMs`) |
| `CID_MAX_EVENTS` | bound on the operation chain length (`maxEvents`) |
| `CID_DEADLINE_MS` | bound on one whole resolution in ms (`deadlineMs`, default 7000) |
| `CID_MAX_DIDS` | bound on distinct DID histories one resolution fetches (`maxDids`, default 32) |
