import { afterEach, describe, expect, it, vi } from "vitest";
import { ARCHON_NODE_DID, FIXTURE } from "./fixture.js";
import {
  agentDocument,
  clone,
  hyperswarm,
  jwkFor,
  key,
  opCid,
  resolve,
  signLegacy,
  stubExport,
  type Op,
} from "./helpers.js";

const liveEvents = () => clone(FIXTURE.events) as Record<string, unknown>[];

afterEach(() => vi.unstubAllGlobals());

// ── Live-chain regression ───────────────────────────────────────────────────

describe("did:cid resolution-only gatekeeper — live chain", () => {
  it("independently verifies the 18-event archon.technology chain", async () => {
    stubExport({ [ARCHON_NODE_DID]: liveEvents() });
    const result = await resolve(ARCHON_NODE_DID);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument).toEqual(FIXTURE.expected.didDocument);
    expect(result.didDocumentMetadata).toEqual(
      FIXTURE.expected.didDocumentMetadata,
    );
  });

  // protocol-rules.md, Operation Authorization: Hyperswarm envelope times are
  // normalized to the operation's proof.created. The 2026-08-19 export carried
  // receipt times (2026-05-18T17:36:19Z); the result must not depend on them.
  it("normalizes Hyperswarm receipt times to proof time", async () => {
    const events = liveEvents();
    for (const event of events) event.time = "2026-05-18T17:36:19.766Z";
    stubExport({ [ARCHON_NODE_DID]: events });
    const result = await resolve(ARCHON_NODE_DID);
    expect(result.didDocumentMetadata).toEqual(
      FIXTURE.expected.didDocumentMetadata,
    );
  });

  it("rejects a chain whose genesis does not hash to the DID", async () => {
    const events = liveEvents();
    (events[0].operation as Op).created = "2027-01-01T00:00:00.000Z";
    stubExport({ [ARCHON_NODE_DID]: events });
    const result = await resolve(ARCHON_NODE_DID);
    expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
    expect(result.didResolutionMetadata.message).toContain("genesis");
  });

  it("rejects a tampered update operation (broken signature)", async () => {
    const events = liveEvents();
    ((events[5].operation as Op).doc as Op).didDocumentData = { forged: true };
    stubExport({ [ARCHON_NODE_DID]: events });
    const result = await resolve(ARCHON_NODE_DID);
    expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
    expect(result.didResolutionMetadata.message).toContain("signature");
  });

  it("rejects a reordered chain (broken previd link)", async () => {
    const events = liveEvents();
    [events[3], events[4]] = [events[4], events[3]];
    stubExport({ [ARCHON_NODE_DID]: events });
    const result = await resolve(ARCHON_NODE_DID);
    expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
    expect(result.didResolutionMetadata.message).toContain("previd");
  });

  it("rejects a withheld genesis (chain starting mid-way)", async () => {
    stubExport({ [ARCHON_NODE_DID]: liveEvents().slice(1) });
    const result = await resolve(ARCHON_NODE_DID);
    expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
  });
});

// ── Synthetic chains: rotation, deletion, assets (legacy proofs) ────────────

const KEY_A = key(7);
const KEY_B = key(9);

async function legacyAgent(
  priv: Uint8Array,
  created = "2026-02-01T00:00:00.000Z",
): Promise<{ did: string; op: Op }> {
  const op = signLegacy(
    {
      created,
      publicJwk: jwkFor(priv),
      registration: { registry: "hyperswarm", type: "agent", version: 1 },
      type: "create",
    },
    priv,
    "#key-1",
    created,
  );
  return { did: `did:cid:${await opCid(op)}`, op };
}

describe("did:cid resolution-only gatekeeper — synthetic chains", () => {
  it("honors key rotation: later updates verify against the rotated key", async () => {
    const { did, op: genesis } = await legacyAgent(KEY_A);
    const rotate = signLegacy(
      {
        did,
        doc: {
          didDocument: agentDocument(did, [{ id: "#key-2", priv: KEY_B }]),
        },
        previd: await opCid(genesis),
        type: "update",
      },
      KEY_A, // authorized by the then-current key
      `${did}#key-1`,
      "2026-02-02T00:00:00.000Z",
    );
    const afterRotate = signLegacy(
      {
        did,
        doc: { didDocumentData: { note: "signed by the new key" } },
        previd: await opCid(rotate),
        type: "update",
      },
      KEY_B, // must verify against the ROTATED key
      `${did}#key-2`,
      "2026-02-03T00:00:00.000Z",
    );
    stubExport({
      [did]: [genesis, rotate, afterRotate].map(hyperswarm),
    });
    const result = await resolve(did);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument?.verificationMethod?.[0]?.id).toBe("#key-2");
    expect(result.didDocumentMetadata.versionSequence).toBe("3");

    // The OLD key must no longer authorize updates.
    const forged = signLegacy(
      {
        did,
        doc: { didDocumentData: { forged: true } },
        previd: await opCid(afterRotate),
        type: "update",
      },
      KEY_A,
      `${did}#key-1`,
      "2026-02-04T00:00:00.000Z",
    );
    stubExport({
      [did]: [genesis, rotate, afterRotate, forged].map(hyperswarm),
    });
    const rejected = await resolve(did);
    expect(rejected.didResolutionMetadata.error).toBe("invalidDidDocument");
  });

  it("resolves a delete operation to a deactivated tombstone", async () => {
    const { did, op: genesis } = await legacyAgent(KEY_A);
    const remove = signLegacy(
      { did, previd: await opCid(genesis), type: "delete" },
      KEY_A,
      `${did}#key-1`,
      "2026-02-05T12:00:00.000Z",
    );
    stubExport({ [did]: [genesis, remove].map(hyperswarm) });
    const result = await resolve(did);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata.deactivated).toBe(true);
    expect(result.didDocumentMetadata.deleted).toBe("2026-02-05T12:00:00Z");
    expect(result.didDocumentMetadata.updated).toBeUndefined();
    expect(result.didDocument).toEqual({ id: did });
  });

  it("rejects an operation that extends a deletion", async () => {
    const { did, op: genesis } = await legacyAgent(KEY_A);
    const remove = signLegacy(
      { did, previd: await opCid(genesis), type: "delete" },
      KEY_A,
      `${did}#key-1`,
      "2026-02-05T00:00:00.000Z",
    );
    const revive = signLegacy(
      {
        did,
        doc: { didDocumentData: { revived: true } },
        previd: await opCid(remove),
        type: "update",
      },
      KEY_A,
      `${did}#key-1`,
      "2026-02-06T00:00:00.000Z",
    );
    stubExport({ [did]: [genesis, remove, revive].map(hyperswarm) });
    const result = await resolve(did);
    expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
    expect(result.didResolutionMetadata.message).toContain("deactivated");
  });

  it("resolves an asset DID by verifying against its controller's chain", async () => {
    const { did: controllerDid, op: controllerGenesis } =
      await legacyAgent(KEY_A);
    const assetOp = signLegacy(
      {
        controller: controllerDid,
        created: "2026-02-02T00:00:00.000Z",
        data: { title: "verifiable asset" },
        registration: { registry: "hyperswarm", type: "asset", version: 1 },
        type: "create",
      },
      KEY_A,
      `${controllerDid}#key-1`,
      "2026-02-02T00:00:00.000Z",
    );
    const assetDid = `did:cid:${await opCid(assetOp)}`;
    stubExport({
      [controllerDid]: [hyperswarm(controllerGenesis)],
      [assetDid]: [hyperswarm(assetOp)],
    });
    const result = await resolve(assetDid);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument?.id).toBe(assetDid);
    expect(result.didDocument?.controller).toBe(controllerDid);
  });
});

// ── Transport & input handling ──────────────────────────────────────────────

describe("did:cid resolution-only gatekeeper — transport and input", () => {
  it("rejects malformed identifiers offline", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    for (const did of [
      "did:cid:not-a-cid!",
      "did:cid:" + "b".repeat(200),
      "did:cid:abc:extra",
    ]) {
      const result = await resolve(did);
      expect(result.didResolutionMetadata.error).toBe("invalidDid");
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("maps an empty export to notFound", async () => {
    stubExport({});
    const result = await resolve(ARCHON_NODE_DID);
    expect(result.didResolutionMetadata.error).toBe("notFound");
  });

  it("maps gatekeeper transport failures to networkError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("boom", { status: 503 })),
    );
    const result = await resolve(ARCHON_NODE_DID);
    expect(result.didResolutionMetadata.error).toBe("networkError");
  });

  it("rejects an oversized export before parsing it", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("[".repeat(3 * 1024 * 1024))),
    );
    const result = await resolve(ARCHON_NODE_DID);
    expect(result.didResolutionMetadata.error).toBe("networkError");
    expect(result.didResolutionMetadata.message).toContain("size bound");
  });
});
