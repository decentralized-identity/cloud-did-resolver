import { CID } from "multiformats/cid";
import { OperationError, applyComponents, compareOrdinals, eventTarget, generateCID, generateDoc, hasAnchoredPrefix, hasChainMetadata, historyEntries, isUnanchoredRegistry, legacyNumericCid, normalizeEventTime, standardDatetime, timestampMillis, validRegistration, verifyCreateOperation, verifyEventShape, verifyProofFormat, verifyUpdateOperation, absoluteKeyId, } from "./operations.js";
const DEFAULT_GATEKEEPER_URL = "https://archon.technology/api/v1";
const DEFAULT_TIMEOUT_MS = 6000;
const DEFAULT_MAX_EVENTS = 1024;
const DEFAULT_DEADLINE_MS = 7000;
const DEFAULT_MAX_DIDS = 32;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
/** DID suffix is a base32 CIDv1 — bound before parsing. */
const MAX_SUFFIX_CHARS = 128;
/** Owners are agents, which authorize themselves; bound recursion anyway. */
const MAX_CONTROLLER_DEPTH = 3;
/** A resolution failure — reported as a result, never thrown upward. */
class ChainError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.code = code;
    }
}
function errorResult(error, message) {
    return {
        didResolutionMetadata: { error, ...(message ? { message } : {}) },
        didDocument: null,
        didDocumentMetadata: {},
    };
}
const isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
function validDidSyntax(did) {
    if (typeof did !== "string")
        return false;
    const segments = did.split(":");
    if (segments.length !== 3 ||
        segments[0] !== "did" ||
        segments[1] !== "cid" ||
        segments[2].length === 0 ||
        segments[2].length > MAX_SUFFIX_CHARS) {
        return false;
    }
    try {
        CID.parse(segments[2]);
        return true;
    }
    catch {
        return false;
    }
}
/**
 * The conformant surface's `normalizeDidDocumentMetadata`: DID Core metadata
 * only — `confirmed` and `timestamp` are registration provenance, not
 * document metadata (resolution.md, Resolution Result).
 */
function conformantMetadata(metadata) {
    const standard = {};
    if (metadata.deactivated)
        standard.deactivated = true;
    if (metadata.created !== undefined)
        standard.created = metadata.created;
    if (metadata.updated !== undefined)
        standard.updated = metadata.updated;
    if (metadata.deleted !== undefined)
        standard.deleted = metadata.deleted;
    if (metadata.canonicalId !== undefined) {
        standard.canonicalId = metadata.canonicalId;
    }
    if (metadata.versionId !== undefined)
        standard.versionId = metadata.versionId;
    if (metadata.versionSequence !== undefined) {
        standard.versionSequence = metadata.versionSequence;
    }
    return standard;
}
export function getResolver(options) {
    const base = (options?.gatekeeperUrl ?? DEFAULT_GATEKEEPER_URL).replace(/\/+$/, "");
    const timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const maxEvents = options?.maxEvents ?? DEFAULT_MAX_EVENTS;
    const deadlineMs = options?.deadlineMs ?? DEFAULT_DEADLINE_MS;
    const maxDids = options?.maxDids ?? DEFAULT_MAX_DIDS;
    async function readBounded(response) {
        if (Number(response.headers.get("content-length") ?? 0) > MAX_RESPONSE_BYTES) {
            return null;
        }
        if (!response.body)
            return "";
        const reader = response.body.getReader();
        const chunks = [];
        let total = 0;
        try {
            for (;;) {
                const { done, value } = await reader.read();
                if (done)
                    break;
                total += value.byteLength;
                if (total > MAX_RESPONSE_BYTES) {
                    await reader.cancel();
                    return null;
                }
                chunks.push(value);
            }
        }
        finally {
            reader.releaseLock();
        }
        const bytes = new Uint8Array(total);
        let offset = 0;
        for (const chunk of chunks) {
            bytes.set(chunk, offset);
            offset += chunk.byteLength;
        }
        return new TextDecoder().decode(bytes);
    }
    /**
     * Fetch a DID's accepted history from the Gatekeeper, bounded by the
     * per-request timeout and by what is left of the resolution's deadline.
     */
    async function fetchEvents(did, session) {
        session.checkDeadline();
        const remaining = session.deadline - Date.now();
        const deadlineBound = remaining <= timeoutMs;
        let response;
        let text;
        try {
            response = await fetch(`${base}/dids/export`, {
                method: "POST",
                headers: {
                    "content-type": "application/json",
                    accept: "application/json",
                },
                body: JSON.stringify({ dids: [did] }),
                signal: AbortSignal.timeout(Math.max(1, Math.min(timeoutMs, remaining))),
            });
            if (!response.ok) {
                throw new ChainError("networkError", `gatekeeper HTTP ${response.status}`);
            }
            text = await readBounded(response);
        }
        catch (cause) {
            if (deadlineBound &&
                !(cause instanceof ChainError) &&
                Date.now() >= session.deadline - 1) {
                throw session.deadlineError();
            }
            throw cause;
        }
        if (text === null) {
            throw new ChainError("networkError", "response exceeds size bound");
        }
        const body = JSON.parse(text);
        const events = Array.isArray(body) ? body[0] : null;
        if (!Array.isArray(events) || events.length === 0)
            return null;
        if (events.length > maxEvents) {
            throw new ChainError("invalidDidDocument", "event chain exceeds bound");
        }
        return events;
    }
    /**
     * Validate one export before any of it is used: every envelope well-formed
     * (`verifyEvent`), its time normalized (`normalizeEventTime`), its target
     * the DID (`eventTarget`), the genesis first and only there. Operation ids
     * are recomputed from content (`normalizeEvent`); the envelope `opid` is
     * never trusted.
     */
    async function loadChain(did, session) {
        const fetched = await fetchEvents(did, session);
        if (!fetched)
            return null;
        const events = JSON.parse(JSON.stringify(fetched));
        const versionIds = [];
        const legacyIds = [];
        for (const [index, event] of events.entries()) {
            if (!isRecord(event) || !verifyEventShape(event)) {
                throw new ChainError("invalidDidDocument", `malformed event ${index}`);
            }
            normalizeEventTime(event);
            const operation = event.operation;
            if (index === 0 && operation.type !== "create") {
                throw new ChainError("invalidDidDocument", "chain does not start with create");
            }
            if (index > 0 && operation.type === "create") {
                throw new ChainError("invalidDidDocument", "create after genesis");
            }
            try {
                if ((await eventTarget(event)) !== did) {
                    throw new ChainError("invalidDidDocument", index === 0
                        ? "DID does not match the CID of its genesis operation"
                        : `event ${index} targets another DID`);
                }
                versionIds.push(await generateCID(operation));
                legacyIds.push(await legacyNumericCid(operation));
            }
            catch (cause) {
                if (cause instanceof OperationError) {
                    throw new ChainError("invalidDidDocument", cause.message);
                }
                throw cause;
            }
        }
        const times = events.map((event) => timestampMillis(String(event.time)));
        const confirmed = [...historyEntries(events)].map((entry) => entry.confirmed);
        return { did, events, versionIds, legacyIds, times, confirmed };
    }
    /**
     * Per-resolution state and budget: one export per DID (at most `maxDids`),
     * one deadline, and each DID's verified document after each of its
     * operations — built once, in order, and shared by every lookup.
     */
    class Session {
        deadline = Date.now() + deadlineMs;
        chains = new Map();
        states = new Map();
        deadlineError() {
            return new ChainError("internalError", `resolution exceeded its ${deadlineMs} ms deadline`);
        }
        checkDeadline() {
            if (Date.now() > this.deadline)
                throw this.deadlineError();
        }
        async chain(did) {
            let chain = this.chains.get(did);
            if (!chain) {
                if (this.chains.size >= maxDids) {
                    throw new ChainError("internalError", `resolution needs more than ${maxDids} DID histories`);
                }
                chain = loadChain(did, this);
                this.chains.set(did, chain);
            }
            return chain;
        }
    }
    /** `isSelfControlledAgent`: an agent genesis, no foreign controller, live. */
    function isSelfControlledAgent(doc) {
        const id = doc.didDocument?.id;
        const controller = doc.didDocument?.controller;
        return (doc.creationType === "agent" &&
            !!id &&
            (controller === undefined || controller === id) &&
            !doc.didDocumentMetadata?.deactivated);
    }
    /** `isAnchored`: the DID's confirmed prefix carries chain positions. */
    async function isAnchored(did, registry, session) {
        if (!registry || isUnanchoredRegistry(registry))
            return false;
        const chain = await session.chain(did);
        return chain ? hasAnchoredPrefix(chain.events) : false;
    }
    /**
     * A controller document, as the reference's `resolveDIDAt` returns it to
     * authorization: undefined when the DID does not resolve (no registration),
     * and for an asset — which can never be a self-controlled agent owner — its
     * genesis alone, without walking its own controller graph.
     */
    async function controllerAt(did, opts, session, depth) {
        if (!validDidSyntax(did))
            return undefined;
        const chain = await session.chain(did);
        if (!chain)
            return undefined;
        const genesis = chain.events[0].operation;
        if (genesis.registration?.type !== "agent") {
            return {
                didDocument: { id: did, controller: genesis.controller },
                didDocumentMetadata: {},
                didDocumentRegistration: genesis.registration,
                creationType: String(genesis.registration?.type),
            };
        }
        return resolveAt(did, opts, session, depth + 1);
    }
    /**
     * `controllerForEvent`: the owner document that authorizes an asset
     * operation. With a chain receipt and an owner whose confirmed prefix is
     * chain-anchored, the owner's events on the receipt's registry must precede
     * its ordinal and events on other registries its block time; otherwise the
     * owner at the operation's `proof.created` (protocol-rules.md, Operation
     * Authorization; archon #1131, #1134).
     */
    async function controllerForEvent(controllerDid, operation, event, session, depth) {
        if (!isUnanchoredRegistry(event.registry) &&
            hasChainMetadata(event.ordinal, event.registration)) {
            const doc = await controllerAt(controllerDid, {
                confirm: true,
                versionTime: String(event.time),
                versionOrdinal: {
                    registry: event.registry,
                    ordinal: event.ordinal,
                },
            }, session, depth);
            if (doc &&
                typeof controllerDid === "string" &&
                (await isAnchored(controllerDid, doc.didDocumentRegistration?.registry, session))) {
                return doc;
            }
        }
        return controllerAt(controllerDid, { confirm: true, versionTime: operation.proof?.created }, session, depth);
    }
    /**
     * `validatePredecessor`: `previd` names the complete predecessor operation
     * — its canonical id or the content-derived TypeScript numeric-key id
     * (protocol-rules.md, Identity and admission; Operation Authorization).
     */
    function validatePredecessor(chain, index, operation, previous) {
        const reference = operation.previd;
        const versionId = previous.didDocumentMetadata?.versionId;
        if (!versionId ||
            typeof reference !== "string" ||
            !reference ||
            (reference !== versionId && reference !== chain.legacyIds[index - 1])) {
            throw new OperationError("previd");
        }
    }
    /** `authorizeCreateOperation`. */
    async function authorizeCreateOperation(operation, event, session, depth) {
        const controller = operation.registration?.type === "asset" &&
            operation.controller &&
            verifyProofFormat(operation.proof)
            ? await controllerForEvent(operation.controller, operation, event, session, depth)
            : undefined;
        if (controller?.didDocumentRegistration &&
            !isSelfControlledAgent(controller)) {
            return false;
        }
        const valid = verifyCreateOperation(operation, controller);
        if (!valid || !validRegistration(operation.registration))
            return false;
        if (operation.registration?.type === "agent") {
            return operation.controller === undefined;
        }
        return !!controller && isSelfControlledAgent(controller);
    }
    /**
     * `authorizeOperation`: select the authorizing document once, then verify
     * the proof against it (protocol-rules.md, State transitions; Operation
     * Authorization).
     */
    async function authorizeOperation(chain, index, operation, current, event, session, depth) {
        if (operation.type === "create") {
            return authorizeCreateOperation(operation, event, session, depth);
        }
        if (operation.type !== "update" && operation.type !== "delete") {
            return false;
        }
        if (!current)
            throw new OperationError("predecessor");
        validatePredecessor(chain, index, operation, current);
        const genesis = chain.events[0].operation.registration;
        const type = genesis?.type;
        if (!verifyProofFormat(operation.proof))
            throw new OperationError("proof");
        if (!type || current.didDocumentMetadata?.deactivated) {
            return verifyUpdateOperation(operation, current);
        }
        if (operation.doc?.didDocumentRegistration !== undefined &&
            !validRegistration(operation.doc.didDocumentRegistration, genesis, current.didDocumentRegistration)) {
            return false;
        }
        // An explicit null is not a document replacement (protocol-rules.md,
        // Identity and admission); the reference's `??` would fall back to the
        // predecessor here, the Rust port refuses (see REFERENCE-MAP.md).
        const next = operation.doc?.didDocument !== undefined
            ? operation.doc.didDocument
            : current.didDocument;
        if (!isRecord(next) || next.id !== operation.did)
            return false;
        const methods = next.verificationMethod;
        if (Array.isArray(methods)) {
            const ids = methods
                .map((method) => isRecord(method) && typeof method.id === "string"
                ? absoluteKeyId(method.id, next.id)
                : undefined)
                .filter((id) => id !== undefined);
            if (new Set(ids).size !== ids.length)
                return false;
        }
        let authority;
        if (type === "agent") {
            if (!isSelfControlledAgent(current) ||
                (next.controller !== undefined && next.controller !== operation.did)) {
                return false;
            }
            authority = current;
        }
        else if (type === "asset") {
            const controller = current.didDocument?.controller;
            if (!controller || !next.controller)
                return false;
            const owner = await controllerForEvent(controller, operation, event, session, depth);
            if (!owner?.didDocumentRegistration) {
                throw new OperationError("controller not found");
            }
            if (!isSelfControlledAgent(owner))
                return false;
            if (next.controller !== controller) {
                const transferee = await controllerForEvent(next.controller, operation, event, session, depth);
                if (!transferee?.didDocumentRegistration) {
                    throw new OperationError("controller not found");
                }
                if (!isSelfControlledAgent(transferee))
                    return false;
            }
            authority = owner;
        }
        else {
            return false;
        }
        return verifyUpdateOperation(operation, authority);
    }
    /** Authorize one operation; refuse closed. */
    async function authorize(chain, index, current, event, session, depth) {
        let valid;
        try {
            valid = await authorizeOperation(chain, index, event.operation, current, event, session, depth);
        }
        catch (cause) {
            if (cause instanceof OperationError) {
                throw new ChainError("invalidDidDocument", `operation ${index} refused: ${cause.message}`);
            }
            throw cause;
        }
        if (!valid) {
            throw new ChainError("invalidDidDocument", `operation ${index} signature or authorization invalid`);
        }
    }
    /**
     * The verified document after operation `stop`, built incrementally: each
     * operation is authorized against the document before it, exactly once per
     * resolution, and every lookup of the DID (one per asset operation it owns)
     * reuses the states already built instead of replaying the history.
     */
    async function stateAt(chain, stop, session, depth) {
        const did = chain.did;
        let states = session.states.get(did);
        if (!states) {
            states = [];
            session.states.set(did, states);
        }
        while (states.length <= stop) {
            session.checkDeadline();
            const index = states.length;
            const event = chain.events[index];
            const operation = event.operation;
            const versionId = chain.versionIds[index];
            if (index === 0) {
                await authorize(chain, 0, undefined, event, session, depth);
                const doc = generateDoc(operation, did);
                const canonicalId = doc.didDocumentMetadata.canonicalId;
                doc.didDocumentMetadata = {
                    created: standardDatetime(doc.didDocumentMetadata.created),
                    ...(canonicalId ? { canonicalId } : {}),
                    versionId,
                    versionSequence: "1",
                    confirmed: true,
                };
                states.push(doc);
                continue;
            }
            const previous = states[index - 1];
            await authorize(chain, index, previous, event, session, depth);
            const { created, canonicalId } = previous.didDocumentMetadata;
            const updated = standardDatetime(event.time);
            const next = { ...previous };
            applyComponents(next, operation, did);
            next.didDocumentMetadata =
                operation.type === "update"
                    ? {
                        created,
                        updated,
                        ...(canonicalId ? { canonicalId } : {}),
                        versionId,
                        versionSequence: String(index + 1),
                        confirmed: chain.confirmed[index],
                    }
                    : {
                        deactivated: true,
                        created,
                        deleted: updated,
                        ...(canonicalId ? { canonicalId } : {}),
                        versionId,
                        versionSequence: String(index + 1),
                        confirmed: chain.confirmed[index],
                    };
            states.push(next);
        }
        return states[stop];
    }
    /**
     * `resolveDIDAt` with `verify: true`: apply the accepted history up to the
     * requested bound — the ordinal for events on the cutoff's registry, the
     * time for others — or the requested sequence, or, with `confirm`, the
     * first operation not confirmed on its expected registry; nothing past the
     * bound is verified or applied (resolution.md, Resolution Algorithm).
     */
    async function resolveAt(did, opts, session, depth) {
        if (depth > MAX_CONTROLLER_DEPTH) {
            throw new ChainError("invalidDidDocument", "controller chain too deep");
        }
        const chain = await session.chain(did);
        if (!chain)
            throw new ChainError("notFound", "no events for DID");
        const timeBound = opts.versionTime === undefined
            ? undefined
            : timestampMillis(opts.versionTime);
        let stop = 0;
        for (let index = 1; index < chain.events.length; index++) {
            const event = chain.events[index];
            if (opts.versionOrdinal &&
                event.registry === opts.versionOrdinal.registry) {
                if (Array.isArray(event.ordinal) &&
                    compareOrdinals(event.ordinal, opts.versionOrdinal.ordinal) >= 0) {
                    break;
                }
            }
            else if (timeBound !== undefined && chain.times[index] > timeBound) {
                break;
            }
            // Before operation `index`, `index` versions have been applied.
            if (opts.versionSequence && index === opts.versionSequence)
                break;
            if (opts.confirm && !chain.confirmed[index])
                break;
            stop = index;
        }
        return stateAt(chain, stop, session, depth);
    }
    /** `versionSequence` as the reference router parses it (parseInt, no NaN). */
    function sequenceOption(value) {
        if (typeof value === "number")
            return value;
        if (typeof value === "string") {
            const parsed = parseInt(value, 10);
            return Number.isNaN(parsed) ? undefined : parsed;
        }
        return undefined;
    }
    const cid = async (did, _parsed, _resolver, resolutionOptions) => {
        try {
            if (!validDidSyntax(did)) {
                throw new ChainError("invalidDid", "malformed did:cid identifier");
            }
            // The conformant surface: confirmed, verified state; versionTime and
            // versionSequence select a version (resolution.md, Resolution Options).
            const state = await resolveAt(did, {
                confirm: true,
                versionTime: typeof resolutionOptions?.versionTime === "string"
                    ? resolutionOptions.versionTime
                    : undefined,
                versionSequence: sequenceOption(resolutionOptions?.versionSequence),
            }, new Session(), 0);
            return {
                didResolutionMetadata: { contentType: "application/did+ld+json" },
                didDocument: JSON.parse(JSON.stringify(state.didDocument)),
                didDocumentMetadata: conformantMetadata(state.didDocumentMetadata),
            };
        }
        catch (cause) {
            if (cause instanceof ChainError) {
                return errorResult(cause.code, cause.message);
            }
            return errorResult("networkError", cause instanceof Error ? cause.message.slice(0, 200) : undefined);
        }
    };
    return { cid };
}
//# sourceMappingURL=resolver.js.map