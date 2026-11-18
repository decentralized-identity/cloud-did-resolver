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
import type { DIDResolutionResult, ResolverRegistry } from "did-resolver";
import { CID } from "multiformats/cid";
import {
  OperationError,
  applyComponents,
  compareOrdinals,
  eventTarget,
  generateCID,
  generateDoc,
  hasAnchoredPrefix,
  hasChainMetadata,
  historyEntries,
  isUnanchoredRegistry,
  legacyNumericCid,
  normalizeEventTime,
  standardDatetime,
  timestampMillis,
  validRegistration,
  verifyCreateOperation,
  verifyEventShape,
  verifyProofFormat,
  verifyUpdateOperation,
  absoluteKeyId,
  type DidCidDocument,
  type DidDocument,
  type DocumentMetadata,
  type GatekeeperEvent,
  type Operation,
} from "./operations.js";

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
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

function errorResult(error: string, message?: string): DIDResolutionResult {
  return {
    didResolutionMetadata: { error, ...(message ? { message } : {}) },
    didDocument: null,
    didDocumentMetadata: {},
  };
}

/** The resolveDIDAt options this port uses (verify is always on). */
interface ResolveAtOptions {
  versionTime?: string;
  versionSequence?: number;
  /** Chain-position cutoff — internal, for asset authorization only. */
  versionOrdinal?: { registry: unknown; ordinal: number[] };
  confirm: boolean;
}

/** One DID's validated export: normalized events and their operation ids. */
interface Chain {
  did: string;
  events: GatekeeperEvent[];
  versionIds: string[];
  /** Content-derived TypeScript numeric-key id, where it differs. */
  legacyIds: (string | undefined)[];
  /** `timestampMillis` of each normalized event time. */
  times: number[];
  /** `historyEntries` confirmation of each event. */
  confirmed: boolean[];
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

function validDidSyntax(did: unknown): did is string {
  if (typeof did !== "string") return false;
  const segments = did.split(":");
  if (
    segments.length !== 3 ||
    segments[0] !== "did" ||
    segments[1] !== "cid" ||
    segments[2].length === 0 ||
    segments[2].length > MAX_SUFFIX_CHARS
  ) {
    return false;
  }
  try {
    CID.parse(segments[2]);
    return true;
  } catch {
    return false;
  }
}

/**
 * The conformant surface's `normalizeDidDocumentMetadata`: DID Core metadata
 * only — `confirmed` and `timestamp` are registration provenance, not
 * document metadata (resolution.md, Resolution Result).
 */
function conformantMetadata(metadata: DocumentMetadata): DocumentMetadata {
  const standard: DocumentMetadata = {};
  if (metadata.deactivated) standard.deactivated = true;
  if (metadata.created !== undefined) standard.created = metadata.created;
  if (metadata.updated !== undefined) standard.updated = metadata.updated;
  if (metadata.deleted !== undefined) standard.deleted = metadata.deleted;
  if (metadata.canonicalId !== undefined) {
    standard.canonicalId = metadata.canonicalId;
  }
  if (metadata.versionId !== undefined) standard.versionId = metadata.versionId;
  if (metadata.versionSequence !== undefined) {
    standard.versionSequence = metadata.versionSequence;
  }
  return standard;
}

export function getResolver(options?: CidResolverOptions): ResolverRegistry {
  const base = (options?.gatekeeperUrl ?? DEFAULT_GATEKEEPER_URL).replace(
    /\/+$/,
    "",
  );
  const timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxEvents = options?.maxEvents ?? DEFAULT_MAX_EVENTS;
  const deadlineMs = options?.deadlineMs ?? DEFAULT_DEADLINE_MS;
  const maxDids = options?.maxDids ?? DEFAULT_MAX_DIDS;

  async function readBounded(response: Response): Promise<string | null> {
    if (
      Number(response.headers.get("content-length") ?? 0) > MAX_RESPONSE_BYTES
    ) {
      return null;
    }
    if (!response.body) return "";
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > MAX_RESPONSE_BYTES) {
          await reader.cancel();
          return null;
        }
        chunks.push(value);
      }
    } finally {
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
  async function fetchEvents(
    did: string,
    session: Session,
  ): Promise<GatekeeperEvent[] | null> {
    session.checkDeadline();
    const remaining = session.deadline - Date.now();
    const deadlineBound = remaining <= timeoutMs;
    let response: Response;
    let text: string | null;
    try {
      response = await fetch(`${base}/dids/export`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify({ dids: [did] }),
        signal: AbortSignal.timeout(
          Math.max(1, Math.min(timeoutMs, remaining)),
        ),
      });
      if (!response.ok) {
        throw new ChainError(
          "networkError",
          `gatekeeper HTTP ${response.status}`,
        );
      }
      text = await readBounded(response);
    } catch (cause) {
      if (
        deadlineBound &&
        !(cause instanceof ChainError) &&
        Date.now() >= session.deadline - 1
      ) {
        throw session.deadlineError();
      }
      throw cause;
    }
    if (text === null) {
      throw new ChainError("networkError", "response exceeds size bound");
    }
    const body = JSON.parse(text) as unknown;
    const events = Array.isArray(body) ? (body[0] as unknown) : null;
    if (!Array.isArray(events) || events.length === 0) return null;
    if (events.length > maxEvents) {
      throw new ChainError("invalidDidDocument", "event chain exceeds bound");
    }
    return events as GatekeeperEvent[];
  }

  /**
   * Validate one export before any of it is used: every envelope well-formed
   * (`verifyEvent`), its time normalized (`normalizeEventTime`), its target
   * the DID (`eventTarget`), the genesis first and only there. Operation ids
   * are recomputed from content (`normalizeEvent`); the envelope `opid` is
   * never trusted.
   */
  async function loadChain(
    did: string,
    session: Session,
  ): Promise<Chain | null> {
    const fetched = await fetchEvents(did, session);
    if (!fetched) return null;
    const events = JSON.parse(JSON.stringify(fetched)) as GatekeeperEvent[];
    const versionIds: string[] = [];
    const legacyIds: (string | undefined)[] = [];
    for (const [index, event] of events.entries()) {
      if (!isRecord(event) || !verifyEventShape(event)) {
        throw new ChainError("invalidDidDocument", `malformed event ${index}`);
      }
      normalizeEventTime(event);
      const operation = event.operation as Operation;
      if (index === 0 && operation.type !== "create") {
        throw new ChainError(
          "invalidDidDocument",
          "chain does not start with create",
        );
      }
      if (index > 0 && operation.type === "create") {
        throw new ChainError("invalidDidDocument", "create after genesis");
      }
      try {
        if ((await eventTarget(event)) !== did) {
          throw new ChainError(
            "invalidDidDocument",
            index === 0
              ? "DID does not match the CID of its genesis operation"
              : `event ${index} targets another DID`,
          );
        }
        versionIds.push(await generateCID(operation));
        legacyIds.push(await legacyNumericCid(operation));
      } catch (cause) {
        if (cause instanceof OperationError) {
          throw new ChainError("invalidDidDocument", cause.message);
        }
        throw cause;
      }
    }
    const times = events.map((event) => timestampMillis(String(event.time)));
    const confirmed = [...historyEntries(events)].map(
      (entry) => entry.confirmed,
    );
    return { did, events, versionIds, legacyIds, times, confirmed };
  }

  /**
   * Per-resolution state and budget: one export per DID (at most `maxDids`),
   * one deadline, and each DID's verified document after each of its
   * operations — built once, in order, and shared by every lookup.
   */
  class Session {
    readonly deadline = Date.now() + deadlineMs;
    private readonly chains = new Map<string, Promise<Chain | null>>();
    readonly states = new Map<string, DidCidDocument[]>();

    deadlineError(): ChainError {
      return new ChainError(
        "internalError",
        `resolution exceeded its ${deadlineMs} ms deadline`,
      );
    }

    checkDeadline(): void {
      if (Date.now() > this.deadline) throw this.deadlineError();
    }

    async chain(did: string): Promise<Chain | null> {
      let chain = this.chains.get(did);
      if (!chain) {
        if (this.chains.size >= maxDids) {
          throw new ChainError(
            "internalError",
            `resolution needs more than ${maxDids} DID histories`,
          );
        }
        chain = loadChain(did, this);
        this.chains.set(did, chain);
      }
      return chain;
    }
  }

  /** `isSelfControlledAgent`: an agent genesis, no foreign controller, live. */
  function isSelfControlledAgent(doc: DidCidDocument): boolean {
    const id = doc.didDocument?.id;
    const controller = doc.didDocument?.controller;
    return (
      doc.creationType === "agent" &&
      !!id &&
      (controller === undefined || controller === id) &&
      !doc.didDocumentMetadata?.deactivated
    );
  }

  /** `isAnchored`: the DID's confirmed prefix carries chain positions. */
  async function isAnchored(
    did: string,
    registry: unknown,
    session: Session,
  ): Promise<boolean> {
    if (!registry || isUnanchoredRegistry(registry)) return false;
    const chain = await session.chain(did);
    return chain ? hasAnchoredPrefix(chain.events) : false;
  }

  /**
   * A controller document, as the reference's `resolveDIDAt` returns it to
   * authorization: undefined when the DID does not resolve (no registration),
   * and for an asset — which can never be a self-controlled agent owner — its
   * genesis alone, without walking its own controller graph.
   */
  async function controllerAt(
    did: unknown,
    opts: ResolveAtOptions,
    session: Session,
    depth: number,
  ): Promise<DidCidDocument | undefined> {
    if (!validDidSyntax(did)) return undefined;
    const chain = await session.chain(did);
    if (!chain) return undefined;
    const genesis = chain.events[0].operation as Operation;
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
  async function controllerForEvent(
    controllerDid: unknown,
    operation: Operation,
    event: GatekeeperEvent,
    session: Session,
    depth: number,
  ): Promise<DidCidDocument | undefined> {
    if (
      !isUnanchoredRegistry(event.registry) &&
      hasChainMetadata(event.ordinal, event.registration)
    ) {
      const doc = await controllerAt(
        controllerDid,
        {
          confirm: true,
          versionTime: String(event.time),
          versionOrdinal: {
            registry: event.registry,
            ordinal: event.ordinal as number[],
          },
        },
        session,
        depth,
      );
      if (
        doc &&
        typeof controllerDid === "string" &&
        (await isAnchored(
          controllerDid,
          doc.didDocumentRegistration?.registry,
          session,
        ))
      ) {
        return doc;
      }
    }
    return controllerAt(
      controllerDid,
      { confirm: true, versionTime: operation.proof?.created },
      session,
      depth,
    );
  }

  /**
   * `validatePredecessor`: `previd` names the complete predecessor operation
   * — its canonical id or the content-derived TypeScript numeric-key id
   * (protocol-rules.md, Identity and admission; Operation Authorization).
   */
  function validatePredecessor(
    chain: Chain,
    index: number,
    operation: Operation,
    previous: DidCidDocument,
  ): void {
    const reference = operation.previd;
    const versionId = previous.didDocumentMetadata?.versionId;
    if (
      !versionId ||
      typeof reference !== "string" ||
      !reference ||
      (reference !== versionId && reference !== chain.legacyIds[index - 1])
    ) {
      throw new OperationError("previd");
    }
  }

  /** `authorizeCreateOperation`. */
  async function authorizeCreateOperation(
    operation: Operation,
    event: GatekeeperEvent,
    session: Session,
    depth: number,
  ): Promise<boolean> {
    const controller =
      operation.registration?.type === "asset" &&
      operation.controller &&
      verifyProofFormat(operation.proof)
        ? await controllerForEvent(
            operation.controller,
            operation,
            event,
            session,
            depth,
          )
        : undefined;
    if (
      controller?.didDocumentRegistration &&
      !isSelfControlledAgent(controller)
    ) {
      return false;
    }
    const valid = verifyCreateOperation(operation, controller);
    if (!valid || !validRegistration(operation.registration)) return false;
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
  async function authorizeOperation(
    chain: Chain,
    index: number,
    operation: Operation,
    current: DidCidDocument | undefined,
    event: GatekeeperEvent,
    session: Session,
    depth: number,
  ): Promise<boolean> {
    if (operation.type === "create") {
      return authorizeCreateOperation(operation, event, session, depth);
    }
    if (operation.type !== "update" && operation.type !== "delete") {
      return false;
    }
    if (!current) throw new OperationError("predecessor");
    validatePredecessor(chain, index, operation, current);
    const genesis = (chain.events[0].operation as Operation).registration;
    const type = genesis?.type;
    if (!verifyProofFormat(operation.proof)) throw new OperationError("proof");
    if (!type || current.didDocumentMetadata?.deactivated) {
      return verifyUpdateOperation(operation, current);
    }
    if (
      operation.doc?.didDocumentRegistration !== undefined &&
      !validRegistration(
        operation.doc.didDocumentRegistration,
        genesis,
        current.didDocumentRegistration,
      )
    ) {
      return false;
    }
    // An explicit null is not a document replacement (protocol-rules.md,
    // Identity and admission); the reference's `??` would fall back to the
    // predecessor here, the Rust port refuses (see REFERENCE-MAP.md).
    const next =
      operation.doc?.didDocument !== undefined
        ? operation.doc.didDocument
        : current.didDocument;
    if (!isRecord(next) || next.id !== operation.did) return false;
    const methods = (next as DidDocument).verificationMethod;
    if (Array.isArray(methods)) {
      const ids = methods
        .map((method) =>
          isRecord(method) && typeof method.id === "string"
            ? absoluteKeyId(method.id, next.id)
            : undefined,
        )
        .filter((id) => id !== undefined);
      if (new Set(ids).size !== ids.length) return false;
    }

    let authority: DidCidDocument;
    if (type === "agent") {
      if (
        !isSelfControlledAgent(current) ||
        (next.controller !== undefined && next.controller !== operation.did)
      ) {
        return false;
      }
      authority = current;
    } else if (type === "asset") {
      const controller = current.didDocument?.controller;
      if (!controller || !next.controller) return false;
      const owner = await controllerForEvent(
        controller,
        operation,
        event,
        session,
        depth,
      );
      if (!owner?.didDocumentRegistration) {
        throw new OperationError("controller not found");
      }
      if (!isSelfControlledAgent(owner)) return false;
      if (next.controller !== controller) {
        const transferee = await controllerForEvent(
          next.controller,
          operation,
          event,
          session,
          depth,
        );
        if (!transferee?.didDocumentRegistration) {
          throw new OperationError("controller not found");
        }
        if (!isSelfControlledAgent(transferee)) return false;
      }
      authority = owner;
    } else {
      return false;
    }
    return verifyUpdateOperation(operation, authority);
  }

  /** Authorize one operation; refuse closed. */
  async function authorize(
    chain: Chain,
    index: number,
    current: DidCidDocument | undefined,
    event: GatekeeperEvent,
    session: Session,
    depth: number,
  ): Promise<void> {
    let valid: boolean;
    try {
      valid = await authorizeOperation(
        chain,
        index,
        event.operation as Operation,
        current,
        event,
        session,
        depth,
      );
    } catch (cause) {
      if (cause instanceof OperationError) {
        throw new ChainError(
          "invalidDidDocument",
          `operation ${index} refused: ${cause.message}`,
        );
      }
      throw cause;
    }
    if (!valid) {
      throw new ChainError(
        "invalidDidDocument",
        `operation ${index} signature or authorization invalid`,
      );
    }
  }

  /**
   * The verified document after operation `stop`, built incrementally: each
   * operation is authorized against the document before it, exactly once per
   * resolution, and every lookup of the DID (one per asset operation it owns)
   * reuses the states already built instead of replaying the history.
   */
  async function stateAt(
    chain: Chain,
    stop: number,
    session: Session,
    depth: number,
  ): Promise<DidCidDocument> {
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
      const operation = event.operation as Operation;
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
      const next: DidCidDocument = { ...previous };
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
  async function resolveAt(
    did: string,
    opts: ResolveAtOptions,
    session: Session,
    depth: number,
  ): Promise<DidCidDocument> {
    if (depth > MAX_CONTROLLER_DEPTH) {
      throw new ChainError("invalidDidDocument", "controller chain too deep");
    }
    const chain = await session.chain(did);
    if (!chain) throw new ChainError("notFound", "no events for DID");

    const timeBound =
      opts.versionTime === undefined
        ? undefined
        : timestampMillis(opts.versionTime);
    let stop = 0;
    for (let index = 1; index < chain.events.length; index++) {
      const event = chain.events[index];
      if (
        opts.versionOrdinal &&
        event.registry === opts.versionOrdinal.registry
      ) {
        if (
          Array.isArray(event.ordinal) &&
          compareOrdinals(event.ordinal, opts.versionOrdinal.ordinal) >= 0
        ) {
          break;
        }
      } else if (timeBound !== undefined && chain.times[index] > timeBound) {
        break;
      }
      // Before operation `index`, `index` versions have been applied.
      if (opts.versionSequence && index === opts.versionSequence) break;
      if (opts.confirm && !chain.confirmed[index]) break;
      stop = index;
    }
    return stateAt(chain, stop, session, depth);
  }

  /** `versionSequence` as the reference router parses it (parseInt, no NaN). */
  function sequenceOption(value: unknown): number | undefined {
    if (typeof value === "number") return value;
    if (typeof value === "string") {
      const parsed = parseInt(value, 10);
      return Number.isNaN(parsed) ? undefined : parsed;
    }
    return undefined;
  }

  const cid = async (
    did: string,
    _parsed?: unknown,
    _resolver?: unknown,
    resolutionOptions?: Record<string, unknown>,
  ): Promise<DIDResolutionResult> => {
    try {
      if (!validDidSyntax(did)) {
        throw new ChainError("invalidDid", "malformed did:cid identifier");
      }
      // The conformant surface: confirmed, verified state; versionTime and
      // versionSequence select a version (resolution.md, Resolution Options).
      const state = await resolveAt(
        did,
        {
          confirm: true,
          versionTime:
            typeof resolutionOptions?.versionTime === "string"
              ? resolutionOptions.versionTime
              : undefined,
          versionSequence: sequenceOption(resolutionOptions?.versionSequence),
        },
        new Session(),
        0,
      );
      return {
        didResolutionMetadata: { contentType: "application/did+ld+json" },
        didDocument: JSON.parse(
          JSON.stringify(state.didDocument),
        ) as DIDResolutionResult["didDocument"],
        didDocumentMetadata: conformantMetadata(state.didDocumentMetadata),
      };
    } catch (cause) {
      if (cause instanceof ChainError) {
        return errorResult(cause.code, cause.message);
      }
      return errorResult(
        "networkError",
        cause instanceof Error ? cause.message.slice(0, 200) : undefined,
      );
    }
  };

  return { cid } as unknown as ResolverRegistry;
}
