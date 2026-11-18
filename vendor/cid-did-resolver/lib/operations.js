/**
 * did:cid operation-level rules: identity, canonicalization, proof formats,
 * signature verification, event shape and envelope policy.
 *
 * A clean-room port of the operation-level functions of `@didcid/gatekeeper`
 * 0.8.0 (MIT; archon commit 9924993167db8ab3230224565cae62e31e1aacea:
 * packages/gatekeeper/src/gatekeeper.ts, event-policy.ts, history-view.ts;
 * packages/cipher/src/cipher-base.ts, cipher-node.ts; packages/ipfs/src/utils.ts),
 * checked against the normative did:cid Method Specification
 * (archetech/didcid-specs e8aace4d79542aed0ea58b4e252f260f176a70e3).
 * Function names follow the reference so the two can be read side by side;
 * REFERENCE-MAP.md maps every function to its source lines and spec section,
 * and lists where this port follows the specification instead of the code.
 *
 * Everything here is pure: no network, no resolution. Rule failures that the
 * reference reports by throwing `InvalidOperationError` throw `OperationError`
 * here; failures it reports as `false` return `false`. Both refuse the
 * operation.
 */
import { CID } from "multiformats/cid";
import * as jsonCodec from "multiformats/codecs/json";
import { sha256 as cidHasher } from "multiformats/hashes/sha2";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
/** The reference's `InvalidOperationError`: a rule failure, never a crash. */
export class OperationError extends Error {
}
// ── Constants (gatekeeper.ts) ──────────────────────────────────────────────
export const DID_PREFIX = "did:cid";
export const ARCHON_SECP256K1_CRYPTOSUITE = "archon-ecdsa-secp256k1-jcs-2026";
export const LEGACY_PROOF_TYPE = "EcdsaSecp256k1Signature2019";
export const OPERATION_PROOF_PURPOSES = [
    "capabilityInvocation",
    "authentication",
    "assertionMethod",
];
const VALID_VERSIONS = [1];
const VALID_TYPES = ["agent", "asset"];
/**
 * Version-1 operation size: 65,536 UTF-16 code units of compact JSON
 * (protocol-rules.md, Identity and admission; reference `maxOpBytes`).
 */
export const MAX_OPERATION_SIZE = 64 * 1024;
const isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
// ── Canonicalization and identity (ipfs/utils.ts, cipher-base.ts) ──────────
/**
 * RFC 8785 (JCS), as the reference's `canonicalize` package produces it for
 * values that come from JSON.parse: keys sorted by UTF-16 code units,
 * ECMAScript number serialization, JSON.stringify string escaping.
 */
export function canonicalizeJSON(value) {
    if (typeof value === "number" && !Number.isFinite(value)) {
        throw new OperationError("number has no JSON serialization");
    }
    if (value === null || typeof value !== "object")
        return JSON.stringify(value);
    if (Array.isArray(value)) {
        return ("[" +
            value
                .map((item) => canonicalizeJSON(item === undefined ? null : item))
                .join(",") +
            "]");
    }
    const record = value;
    return ("{" +
        Object.keys(record)
            .sort()
            .filter((key) => record[key] !== undefined)
            .map((key) => JSON.stringify(key) + ":" + canonicalizeJSON(record[key]))
            .join(",") +
        "}");
}
/** `encodeJSON` (canonical): RFC 8785 requires well-formed Unicode. */
function validateUnicode(value) {
    if (typeof value === "string" && /[\uD800-\uDFFF]/u.test(value)) {
        throw new OperationError("RFC 8785 requires well-formed Unicode");
    }
    if (value && typeof value === "object") {
        for (const key of Object.keys(value)) {
            validateUnicode(key);
            validateUnicode(value[key]);
        }
    }
}
async function jsonCid(bytes) {
    const digest = await cidHasher.digest(bytes);
    return CID.createV1(jsonCodec.code, digest).toString();
}
/**
 * `generateCID(operation, { canonical: true })`: the operation ID — CIDv1,
 * JSON multicodec 0x0200, SHA-256, lowercase base32, over the JCS bytes of the
 * complete signed operation (protocol-rules.md, Identity and admission).
 */
export async function generateCID(value) {
    validateUnicode(value);
    return jsonCid(new TextEncoder().encode(canonicalizeJSON(value)));
}
/**
 * The historical TypeScript numeric-key reference (`normalizeEvent`): the CID
 * of `JSON.stringify(JSON.parse(JCS(operation)))`, which moves integer-like
 * keys first. Derived from content only, never from a claimed opid; undefined
 * when it equals the canonical CID (protocol-rules.md, Identity and admission).
 */
export async function legacyNumericCid(value) {
    const canonical = canonicalizeJSON(value);
    const legacy = JSON.stringify(JSON.parse(canonical));
    if (legacy === canonical)
        return undefined;
    return jsonCid(jsonCodec.encode(JSON.parse(canonical)));
}
/** `generateDID`: `${registration.prefix || didPrefix}:${cid}`. */
export async function generateDID(operation) {
    const cid = await generateCID(operation);
    const prefix = operation.registration?.prefix || DID_PREFIX;
    return `${String(prefix)}:${cid}`;
}
/** `hashMessage` / `hashJSON`: SHA-256 of the JCS bytes. */
function hashJSON(value) {
    return sha256(new TextEncoder().encode(canonicalizeJSON(value)));
}
// ── Encodings ──────────────────────────────────────────────────────────────
const BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/**
 * Unpadded base64url, as the specification prescribes for `proofValue`
 * (proof-verification.md, DID operation proofs) and as the Rust port decodes
 * (URL_SAFE_NO_PAD): no padding, no stray characters, no leftover non-zero
 * bits. The TypeScript reference's multiformats decoder also strips trailing
 * `=` padding, so it accepts a padded `proofValue` or JWK coordinate that
 * this port and the Rust port refuse (a TS/Rust divergence, REFERENCE-MAP.md).
 */
export function base64urlDecode(encoded) {
    if (typeof encoded !== "string" || encoded.length % 4 === 1)
        return undefined;
    const out = new Uint8Array(Math.floor((encoded.length * 6) / 8));
    let bits = 0;
    let buffer = 0;
    let written = 0;
    for (const char of encoded) {
        const value = BASE64URL.indexOf(char);
        if (value < 0)
            return undefined;
        buffer = ((buffer << 6) | value) & 0xffff;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[written++] = (buffer >> bits) & 0xff;
        }
    }
    if (bits >= 6 || (buffer & ((1 << bits) - 1)) !== 0)
        return undefined;
    return out;
}
// ── Formats (gatekeeper.ts) ────────────────────────────────────────────────
/** `isWellFormedSecp256k1Jwk`: kty EC, crv secp256k1, 32-byte x and y. */
export function isWellFormedSecp256k1Jwk(jwk) {
    if (!isRecord(jwk) || jwk.kty !== "EC" || jwk.crv !== "secp256k1") {
        return false;
    }
    for (const coordinate of [jwk.x, jwk.y]) {
        if (typeof coordinate !== "string")
            return false;
        if (base64urlDecode(coordinate)?.length !== 32)
            return false;
    }
    return true;
}
const LEAP_SECOND = /:60(?=[.Zz+-])/;
/** `timestampMillis`: event-time comparison with chrono's leap-second instant. */
export function timestampMillis(time) {
    return (Date.parse(time.replace(LEAP_SECOND, ":59")) +
        (LEAP_SECOND.test(time) ? 1000 : 0));
}
const MONTH_LENGTHS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
function daysInMonth(year, month) {
    if (month !== 2)
        return MONTH_LENGTHS[month - 1];
    const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
    return leap ? 29 : 28;
}
/** `verifyDateFormat`: the RFC 3339 grammar both reference ports accept. */
export function verifyDateFormat(time) {
    if (typeof time !== "string" || !time)
        return false;
    const match = /^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[Zz]|[+-](\d{2}):(\d{2}))$/.exec(time);
    if (!match)
        return false;
    const [, year, month, day, hour, minute, second, offsetHour, offsetMinute] = match.map(Number);
    if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)) {
        return false;
    }
    if (hour > 23 || minute > 59 || second > 60)
        return false;
    return !(offsetHour > 23 || offsetMinute > 59);
}
/** `generateStandardDatetime` (resolveDIDAt): second precision, Z suffix. */
export function standardDatetime(time) {
    const text = String(time);
    if (LEAP_SECOND.test(text)) {
        return standardDatetime(text.replace(LEAP_SECOND, ":59")).replace(/:59Z$/, ":60Z");
    }
    return new Date(text).toISOString().replace(/\.\d{3}Z$/, "Z");
}
/** `isValidRegistryName`: 1–128 chars of `[A-Za-z0-9][A-Za-z0-9:_-]*`. */
export function isValidRegistryName(registry) {
    return (typeof registry === "string" &&
        registry.length > 0 &&
        registry.length <= 128 &&
        /^[A-Za-z0-9][A-Za-z0-9:_-]*$/.test(registry));
}
/** `verifyDIDFormat`. */
function verifyDIDFormat(did) {
    return did.startsWith("did:");
}
/** `isOperationProofType`: the legacy type or the Archon Data Integrity suite. */
export function isOperationProofType(proof) {
    if (proof.type === LEGACY_PROOF_TYPE)
        return true;
    return (proof.type === "DataIntegrityProof" &&
        proof.cryptosuite === ARCHON_SECP256K1_CRYPTOSUITE);
}
/**
 * `verifyProofFormat`: a supported type, RFC 3339 `created`, a supported
 * purpose, a named `verificationMethod`, and a `proofValue`
 * (proof-verification.md, DID operation proofs). Purpose membership in the
 * named relationship is deliberately not checked (protocol-rules.md, State
 * transitions: "it does not enforce membership in capabilityInvocation").
 */
export function verifyProofFormat(proof) {
    if (!isRecord(proof))
        return false;
    if (!isOperationProofType(proof))
        return false;
    if (!verifyDateFormat(proof.created))
        return false;
    if (typeof proof.proofPurpose !== "string" ||
        !OPERATION_PROOF_PURPOSES.includes(proof.proofPurpose)) {
        return false;
    }
    if (typeof proof.verificationMethod !== "string" ||
        !proof.verificationMethod.includes("#")) {
        return false;
    }
    const [did] = proof.verificationMethod.split("#");
    if (did !== "" && !verifyDIDFormat(did))
        return false;
    return Boolean(proof.proofValue && typeof proof.proofValue === "string");
}
/** `absoluteKeyId`: compare key references as DID URLs, not strings. */
export function absoluteKeyId(ref, did) {
    if (typeof ref !== "string" || !ref)
        return undefined;
    return ref.startsWith("#")
        ? `${typeof did === "string" ? did : ""}${ref}`
        : ref;
}
// ── Signatures (gatekeeper.ts, cipher-node.ts) ─────────────────────────────
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
export function operationDigest(operation) {
    const proof = operation.proof;
    const unsecured = { ...operation };
    delete unsecured.proof;
    if (proof.type === LEGACY_PROOF_TYPE)
        return hashJSON(unsecured);
    const config = { ...proof };
    delete config.proofValue;
    const documentHasContext = Object.hasOwn(operation, "@context");
    if (Object.hasOwn(proof, "@context")) {
        if (!documentHasContext ||
            canonicalizeJSON(proof["@context"]) !==
                canonicalizeJSON(operation["@context"])) {
            throw new OperationError("proof @context disagrees with the document");
        }
    }
    else if (documentHasContext) {
        config["@context"] = operation["@context"];
    }
    const digests = new Uint8Array(64);
    digests.set(hashJSON(config), 0);
    digests.set(hashJSON(unsecured), 32);
    return sha256(digests);
}
/** `convertJwkToCompressedBytes`: x plus y parity, exactly as the reference. */
function compressedKey(jwk) {
    const x = base64urlDecode(jwk.x);
    const y = base64urlDecode(jwk.y);
    const point = new Uint8Array(33);
    point[0] = y[y.length - 1] % 2 === 0 ? 0x02 : 0x03;
    point.set(x, 1);
    return point;
}
/**
 * `verifyMessage`: compact 64-byte `r || s` (unpadded base64url), low-S
 * required, verified against the compressed key.
 */
export function verifySignature(operation, publicJwk) {
    const signature = base64urlDecode(String(operation.proof?.proofValue));
    if (signature?.length !== 64) {
        throw new OperationError("proofValue is not a compact signature");
    }
    const digest = operationDigest(operation);
    try {
        // The digest is already the message hash (prehash: false); low-S is the
        // reference verifier's rule (cipher-node.ts `hasHighS`).
        return secp256k1.verify(signature, digest, compressedKey(publicJwk), {
            prehash: false,
            lowS: true,
            format: "compact",
        });
    }
    catch {
        return false;
    }
}
/**
 * `operationKey`: the key the proof names, matched as a DID URL against the
 * authorizing document — not the first key (archon #1130/#1132;
 * protocol-rules.md, State transitions). Undefined when the document does not
 * list it; a listed key that is not secp256k1 is refused.
 */
export function operationKey(doc, proof) {
    const did = doc.didDocument?.id;
    const methods = Array.isArray(doc.didDocument?.verificationMethod)
        ? doc.didDocument.verificationMethod
        : [];
    const target = absoluteKeyId(proof.verificationMethod, did);
    const method = methods.find((candidate) => absoluteKeyId(candidate?.id, did) === target);
    if (!method?.publicKeyJwk)
        return undefined;
    if (!isWellFormedSecp256k1Jwk(method.publicKeyJwk)) {
        throw new OperationError("verification key is not a secp256k1 key");
    }
    return method.publicKeyJwk;
}
function exceedsOperationSize(operation) {
    return JSON.stringify(operation).length > MAX_OPERATION_SIZE;
}
/**
 * `verifyCreateOperation`: structure, registration, proof format, and the
 * signature — by `publicJwk` for an agent, by the named key of the supplied
 * controller document for an asset.
 */
export function verifyCreateOperation(operation, controllerDoc) {
    if (exceedsOperationSize(operation))
        throw new OperationError("size");
    if (operation.type !== "create") {
        throw new OperationError(`type=${String(operation.type)}`);
    }
    if (!verifyDateFormat(operation.created)) {
        throw new OperationError("created");
    }
    const registration = operation.registration;
    if (!registration)
        throw new OperationError("registration");
    if (!VALID_VERSIONS.includes(registration.version)) {
        throw new OperationError("registration.version");
    }
    if (!VALID_TYPES.includes(registration.type)) {
        throw new OperationError("registration.type");
    }
    if (!isValidRegistryName(registration.registry)) {
        throw new OperationError("registration.registry");
    }
    if (!verifyProofFormat(operation.proof))
        throw new OperationError("proof");
    const proof = operation.proof;
    if (registration.type === "agent" && proof.verificationMethod !== "#key-1") {
        throw new OperationError("proof.verificationMethod must be #key-1 for agent create");
    }
    if (typeof registration.validUntil === "string" &&
        !verifyDateFormat(registration.validUntil)) {
        throw new OperationError("registration.validUntil");
    }
    if (registration.type === "agent") {
        if (!isWellFormedSecp256k1Jwk(operation.publicJwk)) {
            throw new OperationError("publicJwk");
        }
        return verifySignature(operation, operation.publicJwk);
    }
    // asset
    const [controllerDid] = String(proof.verificationMethod).split("#");
    if (operation.controller !== controllerDid) {
        throw new OperationError("signer is not controller");
    }
    const doc = controllerDoc;
    if (doc?.didDocumentRegistration &&
        doc.didDocumentRegistration.registry === "local" &&
        registration.registry !== "local") {
        throw new OperationError(`non-local registry=${String(registration.registry)}`);
    }
    if (!doc?.didDocument?.verificationMethod) {
        throw new OperationError("didDocument missing verificationMethod");
    }
    const publicJwk = operationKey(doc, proof);
    if (!publicJwk)
        return false;
    return verifySignature(operation, publicJwk);
}
/**
 * `verifyUpdateOperation`: proof format, a live authorizing document, and the
 * signature by the key the proof names.
 */
export function verifyUpdateOperation(operation, doc) {
    if (exceedsOperationSize(operation))
        throw new OperationError("size");
    if (!verifyProofFormat(operation.proof))
        throw new OperationError("proof");
    if (!doc?.didDocument)
        throw new OperationError("doc.didDocument");
    if (doc.didDocumentMetadata?.deactivated) {
        throw new OperationError("DID deactivated");
    }
    if (!doc.didDocument.verificationMethod) {
        throw new OperationError("doc.didDocument.verificationMethod");
    }
    const publicJwk = operationKey(doc, operation.proof);
    if (!publicJwk)
        return false;
    return verifySignature(operation, publicJwk);
}
/**
 * `validRegistration`: a whole-component registration — version 1, a subject
 * type, a valid registry name, an RFC 3339 `validUntil` if any; a replacement
 * keeps genesis version, type and prefix, and cannot add `validUntil` to a
 * DID whose predecessor registration has none (protocol-rules.md, State
 * transitions; Change Status, archon#1466).
 */
export function validRegistration(value, genesis, previous) {
    if (!isRecord(value))
        return false;
    const registration = value;
    if (registration.version !== 1 ||
        !VALID_TYPES.includes(registration.type) ||
        !isValidRegistryName(registration.registry)) {
        return false;
    }
    if (registration.validUntil !== undefined &&
        (typeof registration.validUntil !== "string" ||
            !verifyDateFormat(registration.validUntil))) {
        return false;
    }
    if (registration.validUntil !== undefined &&
        previous &&
        previous.validUntil === undefined) {
        return false;
    }
    return (!genesis ||
        (registration.version === genesis.version &&
            registration.type === genesis.type &&
            registration.prefix === genesis.prefix));
}
// ── Event envelopes (event-policy.ts, gatekeeper.ts verifyEvent) ───────────
/** `isLocallyStampedRegistry`. */
export function isLocallyStampedRegistry(registry) {
    return registry === "local" || registry === "hyperswarm";
}
/** `isUnanchoredRegistry`: pin, local and hyperswarm have no chain clock. */
export function isUnanchoredRegistry(registry) {
    return registry === "pin" || isLocallyStampedRegistry(registry);
}
function hasValidOrdinalComponents(ordinal, allowEmpty) {
    if (!Array.isArray(ordinal) || (!allowEmpty && ordinal.length === 0)) {
        return false;
    }
    return ordinal.every((value) => Number.isSafeInteger(value) && value >= 0);
}
/**
 * `hasChainMetadata`: a chain receipt's ordinal `[height, index, …, opidx]`
 * agrees with complete `registration` metadata (protocol-rules.md, Chain
 * receipts and anchored batches).
 */
export function hasChainMetadata(ordinal, registration) {
    if (!hasValidOrdinalComponents(ordinal, false) || ordinal.length < 3) {
        return false;
    }
    if (!isRecord(registration))
        return false;
    return (registration.height === ordinal[0] &&
        registration.index === ordinal[1] &&
        typeof registration.txid === "string" &&
        registration.txid.length > 0 &&
        typeof registration.batch === "string" &&
        registration.batch.length > 0 &&
        registration.opidx === ordinal[ordinal.length - 1]);
}
/** `compareOrdinals` (common/utils.ts): lexicographic, longer is greater. */
export function compareOrdinals(a, b) {
    const minLength = Math.min(a.length, b.length);
    for (let i = 0; i < minLength; i++) {
        if (a[i] < b[i])
            return -1;
        if (a[i] > b[i])
            return 1;
    }
    if (a.length < b.length)
        return -1;
    if (a.length > b.length)
        return 1;
    return 0;
}
/**
 * `normalizeEventTime`: unanchored receipts use intrinsic time — a local
 * creation its operation `created`, every other local/Hyperswarm/pin receipt
 * its `proof.created`; chain receipts keep block time (protocol-rules.md,
 * Operation Authorization; resolution.md, Resolution Algorithm step 4).
 */
export function normalizeEventTime(event) {
    const operation = event.operation;
    if (event.registry === "local" &&
        operation.type === "create" &&
        operation.created) {
        event.time = operation.created;
    }
    else if (isUnanchoredRegistry(event.registry) && operation.proof) {
        event.time = operation.proof.created;
    }
}
/**
 * `verifyEvent` (shape): a valid registry name, a receipt shape that fits it,
 * an RFC 3339 time, a bounded operation with a well-formed proof, and the
 * structure its type requires.
 */
export function verifyEventShape(event) {
    if (!isValidRegistryName(event.registry) || !event.time || !event.operation) {
        return false;
    }
    const ordinalValid = isUnanchoredRegistry(event.registry)
        ? event.ordinal === undefined ||
            hasValidOrdinalComponents(event.ordinal, true)
        : hasChainMetadata(event.ordinal, event.registration);
    if (!ordinalValid)
        return false;
    if (!verifyDateFormat(event.time))
        return false;
    const operation = event.operation;
    if (!isRecord(operation))
        return false;
    if (exceedsOperationSize(operation))
        return false;
    if (!verifyProofFormat(operation.proof))
        return false;
    if (operation.type === "create") {
        const registration = operation.registration;
        if (!operation.created || !registration)
            return false;
        if (!VALID_VERSIONS.includes(registration.version))
            return false;
        if (!VALID_TYPES.includes(registration.type))
            return false;
        if (!isValidRegistryName(registration.registry))
            return false;
        if (registration.type === "agent" && !operation.publicJwk)
            return false;
        if (registration.type === "asset") {
            const [controllerDid] = String(operation.proof.verificationMethod).split("#");
            if (operation.controller !== controllerDid)
                return false;
        }
        return true;
    }
    if (operation.type === "update") {
        const doc = operation.doc;
        if (!isRecord(doc) ||
            (!doc.didDocument && !doc.didDocumentData && !doc.didDocumentRegistration)) {
            return false;
        }
        const docId = isRecord(doc.didDocument) ? doc.didDocument.id : undefined;
        if (docId && operation.did && docId !== operation.did)
            return false;
        return Boolean(operation.did);
    }
    if (operation.type === "delete")
        return Boolean(operation.did);
    return false;
}
/**
 * `eventTarget`: a creation targets its content-derived DID, an update or
 * deletion its signed `did`; an envelope `did`, when supplied, must match
 * (protocol-rules.md, Identity and admission).
 */
export async function eventTarget(event) {
    const operation = event.operation;
    const did = operation.type === "create" ? await generateDID(operation) : operation.did;
    return typeof did === "string" &&
        did.length > 0 &&
        (event.did === undefined || event.did === did)
        ? did
        : undefined;
}
// ── History view (history-view.ts) ─────────────────────────────────────────
function registryAfter(registry, operation) {
    if (operation.type !== "update")
        return registry;
    const replacement = operation.doc?.didDocumentRegistration;
    return (isRecord(replacement) ? replacement.registry : undefined) ?? registry;
}
/**
 * `historyEntries`: each event with the registry expected to confirm it — the
 * predecessor's registration (the old registry confirms a migration) — and
 * whether the confirmed prefix still holds (protocol-rules.md, State
 * transitions).
 */
export function* historyEntries(events) {
    let expectedRegistry = events[0]?.operation?.registration?.registry;
    let confirmed = true;
    for (const [index, event] of events.entries()) {
        if (index > 0)
            confirmed = confirmed && event.registry === expectedRegistry;
        yield { event, index, expectedRegistry, confirmed };
        expectedRegistry = registryAfter(expectedRegistry, event.operation);
    }
}
/**
 * `hasAnchoredPrefix`: the confirmed prefix carries chain positions on its
 * expected chain registry (protocol-rules.md, Operation Authorization).
 */
export function hasAnchoredPrefix(events) {
    let anchored = false;
    for (const { event, expectedRegistry, confirmed } of historyEntries(events)) {
        if (!confirmed)
            break;
        if (event.registry === expectedRegistry &&
            !isUnanchoredRegistry(event.registry)) {
            if (!hasChainMetadata(event.ordinal, event.registration))
                return false;
            anchored = true;
        }
    }
    return anchored;
}
/**
 * `applyComponents`: supplied components replace whole components, omitted
 * ones are kept; a deletion clears the document to its id and the data to {}
 * and keeps the registration (protocol-rules.md, State transitions).
 */
export function applyComponents(doc, operation, did) {
    if (operation.type === "update") {
        const next = operation.doc ?? {};
        if (next.didDocument !== undefined) {
            doc.didDocument = next.didDocument;
        }
        if (next.didDocumentData !== undefined) {
            doc.didDocumentData = next.didDocumentData;
        }
        if (next.didDocumentRegistration !== undefined) {
            doc.didDocumentRegistration =
                next.didDocumentRegistration;
        }
    }
    else if (operation.type === "delete") {
        doc.didDocument = { id: did };
        doc.didDocumentData = {};
    }
}
/**
 * `generateDoc`: the initial document set of a genesis operation. An agent
 * document grants `capabilityInvocation` with `#key-1` (did-document.md,
 * Agent DID Document; gatekeeper >= 0.7.0).
 */
export function generateDoc(anchor, did) {
    const registration = anchor.registration;
    const metadata = { created: anchor.created };
    if (registration.prefix)
        metadata.canonicalId = did;
    if (registration.type === "agent") {
        return {
            didDocument: {
                "@context": ["https://www.w3.org/ns/did/v1"],
                id: did,
                verificationMethod: [
                    {
                        id: "#key-1",
                        controller: did,
                        type: "EcdsaSecp256k1VerificationKey2019",
                        publicKeyJwk: anchor.publicJwk,
                    },
                ],
                authentication: ["#key-1"],
                assertionMethod: ["#key-1"],
                capabilityInvocation: ["#key-1"],
            },
            didDocumentMetadata: metadata,
            didDocumentData: {},
            didDocumentRegistration: registration,
            creationType: "agent",
        };
    }
    return {
        didDocument: {
            "@context": ["https://www.w3.org/ns/did/v1"],
            id: did,
            controller: anchor.controller,
        },
        didDocumentMetadata: metadata,
        didDocumentData: anchor.data,
        didDocumentRegistration: registration,
        creationType: "asset",
    };
}
//# sourceMappingURL=operations.js.map