# Reference map — @thisdid/cid-did-resolver ⇔ did:cid specification and Archon Gatekeeper

| role                      | what                                                                                                                                                                                                                                                             |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Normative target**      | did:cid Method Specification, [`archetech/didcid-specs@e8aace4`](https://github.com/archetech/didcid-specs/tree/e8aace4d79542aed0ea58b4e252f260f176a70e3) (HEAD on 2026-11-17; normative since 2026-10-05). Decides wherever it and the code disagree.            |
| **Port source**           | `@didcid/gatekeeper` **0.8.0** (MIT), npm `gitHead` [`archetech/archon@9924993`](https://github.com/archetech/archon/tree/9924993167db8ab3230224565cae62e31e1aacea). Ported function by function where it agrees with the specification.                         |
| Cross-check               | The Rust port at the same commit: `rust/services/gatekeeper/src/{resolver,authorization,proofs}.rs`.                                                                                                                                                             |
| Behavioral-parity target  | `https://archon.technology` (reported 0.14.1, commit `4fd5322`, on 2026-11-17): its conformant `GET /1.0/identifiers/<did>` is what the live vectors are compared with.                                                                                          |

Abbreviations below: **GK** = `packages/gatekeeper/src/gatekeeper.ts`, **EP** =
`event-policy.ts`, **HV** = `history-view.ts` (same folder), **IR** =
`services/gatekeeper/server/src/identifiers-router.ts`; spec files are under
`markdown/`. Line numbers refer to the pinned commits.

## What is ported, and what is not

The driver ports **verified resolution of an accepted history**: GK
`resolveDIDAt` with `confirm: true, verify: true`, which is exactly what both
reference conformant surfaces run (IR L220-247; Rust `api.rs`
`resolve_conformant` L1430-1480), followed by IR `normalizeDidDocumentMetadata`
(L171-186). The history comes from GK `exportDID` (L1553), which returns the
node's accepted history (`db.getEvents`). Every operation in it is authorized
against its predecessor before it is applied, and any operation that does not
verify fails the resolution.

Not ported:

- **import-time evidence selection** (`importEventOnce` GK L1926,
  `compareSuccessors` GK L139, `rebuildHistories`): see open question 1;
- the block **`timestamp`** enrichment (needs a registry block database; it is
  registration provenance, not DID Core metadata — resolution.md L48);
- **dereferencing** of `/data` and `/registration`, and **representation
  negotiation** (resolution.md L66-87) — the driver returns the JSON-LD
  representation, the specification's default;
- **retrieval aliases** learned from IPFS content (protocol-rules.md L13): a
  resolution-only driver holds no content store, so an unknown `previd`
  reference stays unresolved and the resolution fails.

## Function map

| Driver (`src/`)                          | Reference @9924993                                     | Specification @e8aace4                                                     |
| ---------------------------------------- | ------------------------------------------------------ | -------------------------------------------------------------------------- |
| `operations.ts` `canonicalizeJSON`       | cipher-base.ts `canonicalizeJSON` L182 (`canonicalize`) | security-considerations.md L69 (JCS before CID and signing)                 |
| `operations.ts` `generateCID`            | ipfs/src/utils.ts `encodeJSON` L40, `generateCID` L61; GK L534 | protocol-rules.md L11 (CIDv1, 0x0200, SHA-256, JCS of the signed op); did-format.md L15 |
| `operations.ts` `legacyNumericCid`       | GK `normalizeEvent` L1655-1673                         | protocol-rules.md L13 (TypeScript numeric-key reference, content-derived)  |
| `operations.ts` `generateDID`            | GK `generateDID` L569                                  | protocol-rules.md L11; creation.md L67, L124                               |
| `operations.ts` `base64urlDecode`        | Rust `URL_SAFE_NO_PAD`; TS multiformats `base64url` also strips `=` (divergence 1 below) | proof-verification.md L53 (unpadded base64url)        |
| `operations.ts` `isWellFormedSecp256k1Jwk` | GK L45                                               | creation.md L25 (publicJwk)                                                |
| `operations.ts` `timestampMillis`        | GK L84                                                 | protocol-rules.md L45 (time bounds)                                        |
| `operations.ts` `verifyDateFormat`       | GK L794                                                | protocol-rules.md L32 ("accepted RFC 3339 string grammar")                 |
| `operations.ts` `standardDatetime`       | GK `generateStandardDatetime` L1230                    | resolution.md L59 (second-precision metadata)                              |
| `operations.ts` `isValidRegistryName`    | GK L129                                                | protocol-rules.md L15                                                      |
| `operations.ts` `isOperationProofType`   | GK L121                                                | proof-verification.md L48-51; security-considerations.md L75               |
| `operations.ts` `verifyProofFormat`      | GK L825                                                | proof-verification.md L55 (created, named method, purpose, signature)      |
| `operations.ts` `absoluteKeyId`          | GK L113                                                | protocol-rules.md L28 (relative fragments resolved against the DID)        |
| `operations.ts` `operationDigest`        | GK `operationSigningBytes` L737 + cipher-node.ts `verifyMessage` L15 (SHA-256) | proof-verification.md L50-53                         |
| `operations.ts` `verifySignature`        | cipher-node.ts `verifyMessage` L15-19 (compact, `hasHighS` → false) | proof-verification.md L53 ("verifier's low-S requirement")    |
| `operations.ts` `operationKey`           | GK L759 (archon #1130, PR #1132)                       | protocol-rules.md L30, L38 (named method; no relationship membership)      |
| `operations.ts` `verifyCreateOperation`  | GK L865                                                | creation.md L17-31, L77-92; protocol-rules.md L15, L21-22                   |
| `operations.ts` `verifyUpdateOperation`  | GK L959                                                | update.md L75; revocation.md L38; protocol-rules.md L26                    |
| `operations.ts` `validRegistration`      | GK L592                                                | protocol-rules.md L15, L24, L32; Change Status L109 (archon#1466)          |
| `operations.ts` `isUnanchoredRegistry` / `isLocallyStampedRegistry` | EP L9, L14                  | protocol-rules.md L43, L69                                                 |
| `operations.ts` `hasChainMetadata`       | EP L88 (`batch = false`)                               | protocol-rules.md L51-53                                                   |
| `operations.ts` `compareOrdinals`        | common/src/utils.ts L5                                 | protocol-rules.md L53; resolution.md L97                                   |
| `operations.ts` `normalizeEventTime`     | EP L18                                                 | protocol-rules.md L45; resolution.md L33                                   |
| `operations.ts` `verifyEventShape`       | GK `verifyEvent` L2134 (shape part); Rust `verify_event_shape` | protocol-rules.md L11, L17, L51-53; resolution.md L31                |
| `operations.ts` `eventTarget`            | GK L1648                                               | protocol-rules.md L11 (envelope `did` must match the target)               |
| `operations.ts` `historyEntries`         | HV L20 (+ `registryAfter` L6)                          | protocol-rules.md L25; archon-extensions.md L35                            |
| `operations.ts` `hasAnchoredPrefix`      | HV L32                                                 | protocol-rules.md L41-42                                                   |
| `operations.ts` `applyComponents`        | HV L44                                                 | protocol-rules.md L23, L26; revocation.md L5                               |
| `operations.ts` `generateDoc`            | GK L1078                                               | did-document.md L25-80 (incl. `capabilityInvocation`)                      |
| `resolver.ts` `loadChain`                | GK `verifyEvent` L2134, `normalizeEvent` L1655, `eventTarget` L1648 | resolution.md L30-31                                        |
| `resolver.ts` `isSelfControlledAgent`    | GK L606                                                | protocol-rules.md L21-22                                                   |
| `resolver.ts` `isAnchored`               | GK L720                                                | protocol-rules.md L41-43                                                   |
| `resolver.ts` `controllerAt`             | GK `resolveDIDAt` as called by authorization (`confirm: true`) | protocol-rules.md L38-43                                           |
| `resolver.ts` `controllerForEvent`       | GK L703 (archon #1131, PR #1134); Rust `authorization.rs` L50 | protocol-rules.md L38-47; security-considerations.md L101            |
| `resolver.ts` `validatePredecessor`      | GK L615 (+ `canonicalReference` L1675)                 | protocol-rules.md L13, L36                                                 |
| `resolver.ts` `authorizeCreateOperation` | GK L672                                                | protocol-rules.md L21-22                                                   |
| `resolver.ts` `authorizeOperation`       | GK L624; Rust `authorization.rs` L193                  | protocol-rules.md L21-30, L38                                              |
| `resolver.ts` `resolveAt`                | GK `resolveDIDAt` L1179 (cutoffs of the walk L1297-1395), `verify: true` | resolution.md L24-36; did-document.md L20                 |
| `resolver.ts` `stateAt`                  | GK `resolveDIDAt` walk L1297-1395 (authorize, then `applyComponents`), built incrementally | resolution.md L36 (a cached projection consistent with replay) |
| `resolver.ts` `sequenceOption`           | IR L234-239 (`parseInt`, NaN ignored)                  | resolution.md L15                                                          |
| `resolver.ts` `conformantMetadata`       | IR `normalizeDidDocumentMetadata` L171; Rust `api.rs` L1584 | resolution.md L46-48; did-document.md L155-168                        |
| `resolver.ts` `cid` (entry)              | IR `resolveConformant` L220 (`confirm: true, verify: true`) | resolution.md L18, L34, L87 (confirmed, verified state)               |

## Where this port follows the specification instead of the code

1. **Proof `@context`.** proof-verification.md L53: "remove `proofValue` from
   the proof configuration and include the secured document's `@context` when
   present … A proof context that disagrees with the document is invalid."
   `operationDigest` applies it literally: a document `@context` is added to a
   configuration that has none before hashing; a proof `@context` that differs
   from the document's, or is present without one, is invalid; with neither,
   the configuration is the proof as given. GK `operationSigningBytes`
   (L737-751) and Rust `operation_message_hash` (proofs.rs L339) hash the proof
   as given and compare nothing, so for an operation that declares `@context`
   the two sides compute different digests. No live or reference operation
   declares one, so no accepted history changes.
2. **Explicit `null` document replacement.** protocol-rules.md L17: explicit
   null is not "a valid registration or document replacement". GK L639
   (`operation.doc?.didDocument ?? current.didDocument`) falls back to the
   predecessor and then applies `null` (HV L48); the Rust port refuses
   (`authorization.rs` L258). The driver refuses.
3. **`versionId` as an input.** resolution.md L20: "it is not an input selector
   on this surface". IR L230-232 and Rust `api.rs` L1444 accept it. The driver
   does not select by it (see open question 3 for what it does instead).

The legacy behaviours the specification keeps are kept: the legacy proof does
not bind its configuration (proof-verification.md L40, L50), and all three
historical purposes are accepted without relationship membership
(proof-verification.md L55; protocol-rules.md L30; archon issue #1156, open).

## Divergences between the reference ports (for the specification's authors)

1. **Padded base64url.** The TypeScript reference decodes `proofValue` and JWK
   coordinates with multiformats `base64url`, which strips trailing `=`
   (verified against multiformats 13.4.2: `"AQ=="` decodes like `"AQ"`); the
   Rust port (`URL_SAFE_NO_PAD`) refuses padding. The specification says
   unpadded (proof-verification.md L53); the driver refuses padding, like
   Rust. Both refuse non-zero trailing bits.
2. **Update components** — see open question 4.
3. **Explicit `null` document replacement** — see spec-over-code 2.

## Open questions (not decided here)

1. **Competing successors in an export.** The specification has resolvers
   select among valid competing successors by expected-chain confirmation,
   ordinal, then canonical CID (protocol-rules.md L63-71; resolution.md L26,
   L32; did-document.md L20). The reference does that when it *accepts
   evidence* (GK `importEventOnce` L1926 with `compareSuccessors` L139) and
   *resolves* by walking the stored accepted history, failing on any operation
   that does not verify (GK L1297-1395; Rust `resolver.rs` L233-276). The
   export the driver reads is that accepted history (GK L1553-1557), which
   never holds two successors of one predecessor. The specification does not
   address a resolver that verifies another node's accepted history, and says
   the conformant surface does not delegate to peers (resolution.md L36, L91).
   Options: (a) verified resolution of the export as the accepted history
   (current behaviour, the reference's resolution path: siblings, invalid
   operations and reordering all fail closed); (b) re-run evidence selection
   over the export (the reference's import path: invalid operations are
   dropped rather than failing, siblings are chosen by protocol-rules.md
   L67-69, export order stops mattering). Recommendation: (a), because the
   export is a claimed accepted history and (b) would let a Gatekeeper serve a
   silently truncated document where (a) refuses; ask the specification's
   authors to state which applies to export-based resolvers. The Archon
   `cycle` controller vector exercises (b) and is not used.
2. **Trust in the Gatekeeper's receipts.** "Only locally trusted registry
   mediators supply confirmation … Peer-relayed chain claims become unconfirmed
   Hyperswarm hints" (protocol-rules.md L59). The driver takes the configured
   Gatekeeper's receipts (registry, time, ordinal, registration) as reported,
   which decides `confirmed`, version cutoffs and chain-position authority.
   Options: (a) treat the configured Gatekeeper as the trusted source (current;
   unchanged from before); (b) treat its chain receipts as hints, which would
   make every chain-registry DID unconfirmed and disable chain-position
   authority. Recommendation: (a), documented, since the operator chooses the
   Gatekeeper; the specification should say how a resolution-only client
   should treat a Gatekeeper's export.
3. **A requested `versionId`.** The specification excludes it as a selector
   (resolution.md L20) but does not say whether a resolver should ignore it or
   report an error. The driver ignores it (unchanged); the ThisDID Worker
   contract still forwards it. Options: ignore, or return an error such as
   `invalidOptions`. No recommendation without the authors.
4. **An update that supplies no component**, or only falsy ones. update.md L11
   requires `doc`; neither it nor protocol-rules.md requires a component. GK
   `verifyEvent` L2206 refuses unless a component is truthy; Rust
   `verify_event_shape` refuses unless one is present. The driver follows the
   TypeScript reference (the port source); the two ports differ for
   `""`/`0`/`false` data.
5. **Error codes.** The specification says only "the appropriate resolution
   error" (resolution.md L91). The reference conformant surfaces report a
   chain that does not verify as `notFound` (Rust `resolver.rs` L83-110); the
   driver keeps `invalidDidDocument` (unchanged), `notFound` for an empty
   export, `invalidDid` for syntax, `networkError` for transport, and the
   registered `internalError` for an exceeded resolution budget.
6. **Owner that migrated off-chain.** protocol-rules.md L41 applies chain
   position to "a controller whose confirmed prefix is chain-anchored". GK
   `isAnchored` (L720-728) also requires the owner's registry at the cutoff to
   be a chain registry, so an owner that moved from a chain to Hyperswarm falls
   back to proof time although its confirmed prefix holds chain anchors. The
   driver follows the reference (pinned by a test); whether "chain-anchored"
   covers that owner should be confirmed by the authors.

## Bounds and hardening (not reference behaviour)

Per resolution: at most `maxDids` distinct DID histories fetched (default 32,
`CID_MAX_DIDS`) and one overall deadline `deadlineMs` (default 7000 ms,
`CID_DEADLINE_MS`; below the gateway's 8 s step timeout), which also caps each
request's own `timeoutMs` (default 6000 ms) and is checked before every
request and every operation verified. Exceeding either fails closed with the
registered DID Resolution error `internalError`. Per history: response ≤ 2 MiB,
events ≤ `maxEvents` (1024), DID suffix ≤ 128 characters; controller recursion
depth ≤ 3. An owner whose genesis is not an agent is refused from its genesis
alone (it can never be a self-controlled agent, GK L606), so asset graphs are
never walked recursively. Each DID's verified states are built once per
resolution and shared by every lookup (`stateAt`), so an asset of N operations
over an owner of M costs N + M verifications rather than about N·M replayed
operations; finding each lookup's cutoff remains a linear scan of precomputed
times. Measured on a 1000-operation asset over a 1000-operation owner: 1.34 s
CPU against 0.72 s for the owner alone (the reviewer measured 2.1 s against
0.65 s before), the remainder being the 2002 signature verifications.

## Evidence

- Live (`src/__tests__/live.test.ts`, `fixture.ts`; provenance in
  `src/__tests__/vectors/NOTICE`): the legacy canary, a new-suite agent with two
  rotations, a hyperswarm → BTC:mainnet migration with chain receipts, and a
  new-suite asset with its owner — each reproduces Archon's conformant
  `didDocument` and `didDocumentMetadata` field for field.
- Reference (`src/__tests__/archon.test.ts`): Archon's proof, canonicalization,
  numeric-predecessor, controller-rules, history-recovery and
  registration-transition vectors, and the specification's signed examples
  (including its post-revocation result, compared whole).
- Synthetic (`src/__tests__/synthetic.test.ts`, `rules.test.ts`,
  `resolver.test.ts`): the new suite and its `@context` rule, key selection,
  chain-position authority (same-block ordinal order, ordinals only on the
  cutoff's registry, proof time for unanchored receipts, unconfirmed suffixes,
  owners migrated off-chain), creation, receipt and confirmation rules,
  ownership rules and fail-closed cases.
- Budgets (`src/__tests__/budget.test.ts`): fan-out cap, deadline (in and
  between requests), and the memoization effect (each operation applied once).
- Mutation sweep (2026-11-18): 50 checks, each reverted alone with the whole
  suite run — 49 fail at least one test. The survivor, dropping the
  `deactivated` term of `isSelfControlledAgent`, is equivalent here: a deletion
  clears the document to its `id`, so a deactivated owner has no key and
  verification refuses anyway. The local-creation time rule of
  `normalizeEventTime` is caught only by its unit test: a genesis event's time
  feeds nothing in resolution.
