/**
 * did:cid resolver for the DIF `did-resolver` interface.
 *
 * A RESOLUTION-ONLY Archon Gatekeeper: instead of proxying a Gatekeeper's
 * answer, this driver fetches the DID's accepted operation history
 * (`POST {gatekeeper}/dids/export`) and re-derives the document itself,
 * verifying every operation in-process before it is applied:
 *
 *  - the DID suffix must equal the CIDv1 (JSON codec, SHA-256, base32) of the
 *    JCS-canonicalized genesis operation, and every envelope must target the
 *    DID;
 *  - every operation proof must be a well-formed `EcdsaSecp256k1Signature2019`
 *    or `DataIntegrityProof` / `archon-ecdsa-secp256k1-jcs-2026` proof, whose
 *    signature verifies under the key its `verificationMethod` names;
 *  - an agent operation is authorized by the predecessor document; an asset
 *    operation by its owner agent, selected at the operation's chain position
 *    when the receipt and the owner's history are chain-anchored, otherwise at
 *    `proof.created`;
 *  - every update/delete links to its predecessor (`previd`), satisfies the
 *    state-transition rules (controllers, registration replacement, unique
 *    method ids) and never extends a deletion.
 *
 * Specification: the did:cid Method Specification, archetech/didcid-specs
 * e8aace4d79542aed0ea58b4e252f260f176a70e3 (normative since 2026-10-05).
 * Reference: `@didcid/gatekeeper` 0.8.0 (MIT), archon commit
 * 9924993167db8ab3230224565cae62e31e1aacea — this file ports `resolveDIDAt`
 * with `confirm: true, verify: true` (the conformant `/1.0/identifiers`
 * surface, services/gatekeeper/server/src/identifiers-router.ts), with
 * `authorizeOperation`, `authorizeCreateOperation`, `controllerForEvent`,
 * `isAnchored`, `isSelfControlledAgent` and `validatePredecessor`.
 * REFERENCE-MAP.md maps each function and check to both, and lists where
 * this port follows the specification instead of the code.
 *
 * Only discovery is delegated to the Gatekeeper: the export is the
 * Gatekeeper's accepted history, and its receipts (registry, time, ordinal)
 * are taken as that Gatekeeper reports them. A lying Gatekeeper can withhold
 * the tail of a chain or misreport receipts, but cannot forge, alter or
 * reorder signed state without failing a signature or a CID link; any
 * operation in the export that does not verify fails the resolution (fail
 * closed). The blockchain `timestamp` enrichment is omitted (it requires a
 * registry block database).
 */
import type { ResolverRegistry } from "did-resolver";
export interface CidResolverOptions {
    /** Archon Gatekeeper API base (e.g. `https://archon.technology/api/v1`). */
    gatekeeperUrl?: string;
    /** Per-request wall-clock bound. Default 6000 ms. */
    timeoutMs?: number;
    /** Upper bound on events accepted per DID chain. Default 1024. */
    maxEvents?: number;
    /**
     * Wall-clock bound for one whole resolution, every Gatekeeper request and
     * all verification included. Default 7000 ms (below the ThisDID gateway's
     * 8 s step timeout). Exceeding it fails with `internalError`.
     */
    deadlineMs?: number;
    /**
     * Upper bound on distinct DID histories one resolution may fetch (the DID
     * plus the owners and transferees its operations name). Default 32, within
     * a Worker's subrequest budget. Exceeding it fails with `internalError`.
     */
    maxDids?: number;
}
export declare function getResolver(options?: CidResolverOptions): ResolverRegistry;
//# sourceMappingURL=resolver.d.ts.map