export interface OperationProof {
    type?: string;
    cryptosuite?: string;
    created?: string;
    verificationMethod?: string;
    proofPurpose?: string;
    proofValue?: string;
    "@context"?: unknown;
    [member: string]: unknown;
}
export interface Registration {
    version?: unknown;
    type?: unknown;
    registry?: unknown;
    prefix?: unknown;
    validUntil?: unknown;
    [member: string]: unknown;
}
export interface VerificationMethod {
    id?: unknown;
    controller?: unknown;
    type?: unknown;
    publicKeyJwk?: unknown;
    [member: string]: unknown;
}
export interface DidDocument {
    id?: unknown;
    controller?: unknown;
    verificationMethod?: unknown;
    [member: string]: unknown;
}
export interface Operation {
    type?: unknown;
    created?: unknown;
    did?: unknown;
    previd?: unknown;
    publicJwk?: unknown;
    registration?: Registration;
    controller?: unknown;
    data?: unknown;
    doc?: {
        didDocument?: DidDocument | null;
        didDocumentData?: unknown;
        didDocumentRegistration?: unknown;
        [member: string]: unknown;
    };
    proof?: OperationProof;
    "@context"?: unknown;
    [member: string]: unknown;
}
export interface GatekeeperEvent {
    registry?: unknown;
    time?: unknown;
    ordinal?: unknown;
    registration?: unknown;
    did?: unknown;
    opid?: unknown;
    operation?: Operation;
    [member: string]: unknown;
}
export interface DocumentMetadata {
    created?: string;
    updated?: string;
    deleted?: string;
    deactivated?: boolean;
    canonicalId?: string;
    versionId?: string;
    versionSequence?: string;
    confirmed?: boolean;
}
/** The reference's DidCidDocument, plus the DID's genesis type (`creationType`). */
export interface DidCidDocument {
    didDocument: DidDocument;
    didDocumentMetadata: DocumentMetadata;
    didDocumentData?: unknown;
    didDocumentRegistration?: Registration;
    creationType?: string;
}
/** The reference's `InvalidOperationError`: a rule failure, never a crash. */
export declare class OperationError extends Error {
}
export declare const DID_PREFIX = "did:cid";
export declare const ARCHON_SECP256K1_CRYPTOSUITE = "archon-ecdsa-secp256k1-jcs-2026";
export declare const LEGACY_PROOF_TYPE = "EcdsaSecp256k1Signature2019";
export declare const OPERATION_PROOF_PURPOSES: string[];
/**
 * Version-1 operation size: 65,536 UTF-16 code units of compact JSON
 * (protocol-rules.md, Identity and admission; reference `maxOpBytes`).
 */
export declare const MAX_OPERATION_SIZE: number;
/**
 * RFC 8785 (JCS), as the reference's `canonicalize` package produces it for
 * values that come from JSON.parse: keys sorted by UTF-16 code units,
 * ECMAScript number serialization, JSON.stringify string escaping.
 */
export declare function canonicalizeJSON(value: unknown): string;
/**
 * `generateCID(operation, { canonical: true })`: the operation ID — CIDv1,
 * JSON multicodec 0x0200, SHA-256, lowercase base32, over the JCS bytes of the
 * complete signed operation (protocol-rules.md, Identity and admission).
 */
export declare function generateCID(value: unknown): Promise<string>;
/**
 * The historical TypeScript numeric-key reference (`normalizeEvent`): the CID
 * of `JSON.stringify(JSON.parse(JCS(operation)))`, which moves integer-like
 * keys first. Derived from content only, never from a claimed opid; undefined
 * when it equals the canonical CID (protocol-rules.md, Identity and admission).
 */
export declare function legacyNumericCid(value: unknown): Promise<string | undefined>;
/** `generateDID`: `${registration.prefix || didPrefix}:${cid}`. */
export declare function generateDID(operation: Operation): Promise<string>;
/**
 * Unpadded base64url, as the specification prescribes for `proofValue`
 * (proof-verification.md, DID operation proofs) and as the Rust port decodes
 * (URL_SAFE_NO_PAD): no padding, no stray characters, no leftover non-zero
 * bits. The TypeScript reference's multiformats decoder also strips trailing
 * `=` padding, so it accepts a padded `proofValue` or JWK coordinate that
 * this port and the Rust port refuse (a TS/Rust divergence, REFERENCE-MAP.md).
 */
export declare function base64urlDecode(encoded: string): Uint8Array | undefined;
/** `isWellFormedSecp256k1Jwk`: kty EC, crv secp256k1, 32-byte x and y. */
export declare function isWellFormedSecp256k1Jwk(jwk: unknown): boolean;
/** `timestampMillis`: event-time comparison with chrono's leap-second instant. */
export declare function timestampMillis(time: string): number;
/** `verifyDateFormat`: the RFC 3339 grammar both reference ports accept. */
export declare function verifyDateFormat(time?: unknown): boolean;
/** `generateStandardDatetime` (resolveDIDAt): second precision, Z suffix. */
export declare function standardDatetime(time: unknown): string;
/** `isValidRegistryName`: 1–128 chars of `[A-Za-z0-9][A-Za-z0-9:_-]*`. */
export declare function isValidRegistryName(registry: unknown): registry is string;
/** `isOperationProofType`: the legacy type or the Archon Data Integrity suite. */
export declare function isOperationProofType(proof: OperationProof): boolean;
/**
 * `verifyProofFormat`: a supported type, RFC 3339 `created`, a supported
 * purpose, a named `verificationMethod`, and a `proofValue`
 * (proof-verification.md, DID operation proofs). Purpose membership in the
 * named relationship is deliberately not checked (protocol-rules.md, State
 * transitions: "it does not enforce membership in capabilityInvocation").
 */
export declare function verifyProofFormat(proof?: unknown): proof is OperationProof;
/** `absoluteKeyId`: compare key references as DID URLs, not strings. */
export declare function absoluteKeyId(ref: unknown, did: unknown): string | undefined;
/**
 * The 32-byte digest an operation proof signs (`operationSigningBytes`, then
 * `verifyMessage`'s SHA-256):
 *  - legacy: SHA-256(JCS(operation − proof));
 *  - Archon suite: SHA-256(SHA-256(JCS(config)) || SHA-256(JCS(operation −
 *    proof))).
 * The configuration is built as proof-verification.md (DID operation proofs)
 * prescribes: "remove `proofValue` from the proof configuration and include
 * the secured document's `@context` when present", and "a proof context that
 * disagrees with the document is invalid". So a document `@context` is added
 * to a configuration that has none, a proof `@context` that differs from the
 * document's (or is present without one) is refused, and with neither the
 * configuration is the proof as given. The reference hashes the proof as
 * given and compares nothing (see REFERENCE-MAP.md, spec-over-code).
 */
export declare function operationDigest(operation: Operation): Uint8Array;
/**
 * `verifyMessage`: compact 64-byte `r || s` (unpadded base64url), low-S
 * required, verified against the compressed key.
 */
export declare function verifySignature(operation: Operation, publicJwk: Record<string, unknown>): boolean;
/**
 * `operationKey`: the key the proof names, matched as a DID URL against the
 * authorizing document — not the first key (archon #1130/#1132;
 * protocol-rules.md, State transitions). Undefined when the document does not
 * list it; a listed key that is not secp256k1 is refused.
 */
export declare function operationKey(doc: DidCidDocument, proof: OperationProof): Record<string, unknown> | undefined;
/**
 * `verifyCreateOperation`: structure, registration, proof format, and the
 * signature — by `publicJwk` for an agent, by the named key of the supplied
 * controller document for an asset.
 */
export declare function verifyCreateOperation(operation: Operation, controllerDoc?: DidCidDocument): boolean;
/**
 * `verifyUpdateOperation`: proof format, a live authorizing document, and the
 * signature by the key the proof names.
 */
export declare function verifyUpdateOperation(operation: Operation, doc: DidCidDocument): boolean;
/**
 * `validRegistration`: a whole-component registration — version 1, a subject
 * type, a valid registry name, an RFC 3339 `validUntil` if any; a replacement
 * keeps genesis version, type and prefix, and cannot add `validUntil` to a
 * DID whose predecessor registration has none (protocol-rules.md, State
 * transitions; Change Status, archon#1466).
 */
export declare function validRegistration(value: unknown, genesis?: Registration, previous?: Registration): boolean;
/** `isLocallyStampedRegistry`. */
export declare function isLocallyStampedRegistry(registry: unknown): boolean;
/** `isUnanchoredRegistry`: pin, local and hyperswarm have no chain clock. */
export declare function isUnanchoredRegistry(registry: unknown): boolean;
/**
 * `hasChainMetadata`: a chain receipt's ordinal `[height, index, …, opidx]`
 * agrees with complete `registration` metadata (protocol-rules.md, Chain
 * receipts and anchored batches).
 */
export declare function hasChainMetadata(ordinal: unknown, registration: unknown): boolean;
/** `compareOrdinals` (common/utils.ts): lexicographic, longer is greater. */
export declare function compareOrdinals(a: number[], b: number[]): -1 | 0 | 1;
/**
 * `normalizeEventTime`: unanchored receipts use intrinsic time — a local
 * creation its operation `created`, every other local/Hyperswarm/pin receipt
 * its `proof.created`; chain receipts keep block time (protocol-rules.md,
 * Operation Authorization; resolution.md, Resolution Algorithm step 4).
 */
export declare function normalizeEventTime(event: GatekeeperEvent): void;
/**
 * `verifyEvent` (shape): a valid registry name, a receipt shape that fits it,
 * an RFC 3339 time, a bounded operation with a well-formed proof, and the
 * structure its type requires.
 */
export declare function verifyEventShape(event: GatekeeperEvent): boolean;
/**
 * `eventTarget`: a creation targets its content-derived DID, an update or
 * deletion its signed `did`; an envelope `did`, when supplied, must match
 * (protocol-rules.md, Identity and admission).
 */
export declare function eventTarget(event: GatekeeperEvent): Promise<string | undefined>;
/**
 * `historyEntries`: each event with the registry expected to confirm it — the
 * predecessor's registration (the old registry confirms a migration) — and
 * whether the confirmed prefix still holds (protocol-rules.md, State
 * transitions).
 */
export declare function historyEntries(events: GatekeeperEvent[]): Generator<{
    event: GatekeeperEvent;
    index: number;
    expectedRegistry: unknown;
    confirmed: boolean;
}>;
/**
 * `hasAnchoredPrefix`: the confirmed prefix carries chain positions on its
 * expected chain registry (protocol-rules.md, Operation Authorization).
 */
export declare function hasAnchoredPrefix(events: GatekeeperEvent[]): boolean;
/**
 * `applyComponents`: supplied components replace whole components, omitted
 * ones are kept; a deletion clears the document to its id and the data to {}
 * and keeps the registration (protocol-rules.md, State transitions).
 */
export declare function applyComponents(doc: DidCidDocument, operation: Operation, did: string): void;
/**
 * `generateDoc`: the initial document set of a genesis operation. An agent
 * document grants `capabilityInvocation` with `#key-1` (did-document.md,
 * Agent DID Document; gatekeeper >= 0.7.0).
 */
export declare function generateDoc(anchor: Operation, did: string): DidCidDocument;
//# sourceMappingURL=operations.d.ts.map