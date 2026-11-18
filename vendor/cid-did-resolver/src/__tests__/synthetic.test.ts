/**
 * Synthetic chains signed with @noble/curves (test keys only) for the rules
 * the live and reference vectors do not isolate. Each case names the
 * specification text it pins (archetech/didcid-specs e8aace4).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  agentDocument,
  agentGenesis,
  b64u,
  chainReceipt,
  clone,
  hyperswarm,
  jwkFor,
  key,
  opCid,
  resolve,
  signLegacy,
  signSuite,
  stubExport,
  type Event,
  type Op,
} from "./helpers.js";

afterEach(() => vi.unstubAllGlobals());

const KEY_A = key(0x11);
const KEY_B = key(0x22);
const KEY_C = key(0x33);
const T0 = "2026-10-01T00:00:00.000Z";
const T1 = "2026-10-02T00:00:00.000Z";
const T2 = "2026-10-03T00:00:00.000Z";
const T3 = "2026-10-04T00:00:00.000Z";

async function update(
  did: string,
  previous: Op,
  doc: Op,
  priv: Uint8Array,
  verificationMethod: string,
  created: string,
): Promise<Op> {
  return signSuite(
    { type: "update", did, previd: await opCid(previous), doc },
    priv,
    verificationMethod,
    created,
  );
}

async function expectRefused(did: string, fragment?: string) {
  const result = await resolve(did);
  expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
  if (fragment)
    expect(result.didResolutionMetadata.message).toContain(fragment);
}

/** An agent whose document lists #key-1 (KEY_A) and #key-2 (KEY_B). */
async function twoKeyAgent() {
  const { did, op: genesis } = await agentGenesis(KEY_A, T0);
  const addKey = await update(
    did,
    genesis,
    {
      didDocument: agentDocument(did, [
        { id: "#key-1", priv: KEY_A },
        { id: "#key-2", priv: KEY_B },
      ]),
    },
    KEY_A,
    `${did}#key-1`,
    T1,
  );
  return { did, genesis, addKey };
}

describe("archon-ecdsa-secp256k1-jcs-2026 (proof-verification.md, DID operation proofs)", () => {
  it("verifies a chain signed entirely with the new suite", async () => {
    const { did, op: genesis } = await agentGenesis(KEY_A, T0);
    const data = await update(
      did,
      genesis,
      { didDocumentData: { n: 1 } },
      KEY_A,
      `${did}#key-1`,
      T1,
    );
    stubExport({ [did]: [genesis, data].map(hyperswarm) });
    const result = await resolve(did);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata).toEqual({
      created: "2026-10-01T00:00:00Z",
      updated: "2026-10-02T00:00:00Z",
      versionId: await opCid(data),
      versionSequence: "2",
    });
  });

  it.each([
    ["created", "2026-10-02T00:00:01.000Z"],
    ["proofPurpose", "authentication"],
    ["verificationMethod", "#key-1"],
  ])(
    "refuses an altered proof configuration member: %s",
    async (member, value) => {
      const { did, op: genesis } = await agentGenesis(KEY_A, T0);
      const data = await update(
        did,
        genesis,
        { didDocumentData: { n: 1 } },
        KEY_A,
        `${did}#key-1`,
        T1,
      );
      (data.proof as Op)[member] = value;
      stubExport({ [did]: [genesis, data].map(hyperswarm) });
      await expectRefused(did, "operation 1");
    },
  );

  it("refuses a tampered signature and a tampered body", async () => {
    const { did, op: genesis } = await agentGenesis(KEY_A, T0);
    const data = await update(
      did,
      genesis,
      { didDocumentData: { n: 1 } },
      KEY_A,
      `${did}#key-1`,
      T1,
    );
    const badSig = clone(data);
    const sig = Buffer.from(
      String((badSig.proof as Op).proofValue),
      "base64url",
    );
    sig[10] ^= 1;
    (badSig.proof as Op).proofValue = b64u(sig);
    stubExport({ [did]: [genesis, badSig].map(hyperswarm) });
    await expectRefused(did, "operation 1");
    const badBody = clone(data);
    (badBody.doc as Op).didDocumentData = { n: 2 };
    stubExport({ [did]: [genesis, badBody].map(hyperswarm) });
    await expectRefused(did, "operation 1");
  });

  it("refuses a high-S signature under either proof type", async () => {
    const N = secp256k1.Point.CURVE().n;
    const highS = (operation: Op) => {
      const sig = Buffer.from(
        String((operation.proof as Op).proofValue),
        "base64url",
      );
      const s = BigInt("0x" + sig.subarray(32).toString("hex"));
      sig.set(Buffer.from((N - s).toString(16).padStart(64, "0"), "hex"), 32);
      return {
        ...operation,
        proof: { ...(operation.proof as Op), proofValue: b64u(sig) },
      };
    };
    const { did, op: genesis } = await agentGenesis(KEY_A, T0);
    const modern = await update(
      did,
      genesis,
      { didDocumentData: { n: 1 } },
      KEY_A,
      `${did}#key-1`,
      T1,
    );
    stubExport({ [did]: [genesis, highS(modern)].map(hyperswarm) });
    await expectRefused(did, "operation 1");
    const legacy = signLegacy(
      {
        type: "update",
        did,
        previd: await opCid(genesis),
        doc: { didDocumentData: { n: 1 } },
      },
      KEY_A,
      `${did}#key-1`,
      T1,
    );
    stubExport({ [did]: [genesis, legacy].map(hyperswarm) });
    expect((await resolve(did)).didResolutionMetadata.error).toBeUndefined();
    stubExport({ [did]: [genesis, highS(legacy)].map(hyperswarm) });
    await expectRefused(did, "operation 1");
  });

  it("refuses a proof @context that disagrees with the operation", async () => {
    // "A proof context that disagrees with the document is invalid." The
    // signature covers the configuration as given, so it is otherwise valid.
    const { did, op: genesis } = await agentGenesis(KEY_A, T0);
    const op = signSuite(
      {
        type: "update",
        did,
        previd: await opCid(genesis),
        doc: { didDocumentData: { n: 1 } },
      },
      KEY_A,
      `${did}#key-1`,
      T1,
      { "@context": ["https://w3id.org/security/data-integrity/v2"] },
    );
    stubExport({ [did]: [genesis, op].map(hyperswarm) });
    await expectRefused(did, "@context");
  });

  // proof-verification.md L53: "remove proofValue from the proof
  // configuration and include the secured document's @context when present".
  // The reference hashes the proof as given (gatekeeper.ts L737-751).
  describe("an operation that declares @context", () => {
    const CONTEXT = ["https://www.w3.org/ns/did/v1"];
    async function contextual(
      proofContext: unknown,
      transmit: "with" | "without",
    ) {
      const { did, op: genesis } = await agentGenesis(KEY_A, T0);
      const op = signSuite(
        {
          "@context": CONTEXT,
          type: "update",
          did,
          previd: await opCid(genesis),
          doc: { didDocumentData: { n: 1 } },
        },
        KEY_A,
        `${did}#key-1`,
        T1,
        proofContext === undefined ? {} : { "@context": proofContext },
      );
      if (transmit === "without") delete (op.proof as Op)["@context"];
      stubExport({ [did]: [genesis, op].map(hyperswarm) });
      return resolve(did);
    }

    it("adds the document's @context to a configuration that has none", async () => {
      // Signed over a configuration carrying the document's @context; the
      // transmitted proof omits it.
      const result = await contextual(CONTEXT, "without");
      expect(result.didResolutionMetadata.error).toBeUndefined();
      expect(result.didDocumentMetadata.versionSequence).toBe("2");
    });

    it("accepts a proof that carries the same @context", async () => {
      const result = await contextual(CONTEXT, "with");
      expect(result.didResolutionMetadata.error).toBeUndefined();
    });

    it("refuses a proof that carries a different @context", async () => {
      const result = await contextual(
        ["https://w3id.org/security/data-integrity/v2"],
        "with",
      );
      expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
      expect(result.didResolutionMetadata.message).toContain("@context");
    });

    it("refuses a signature over a configuration without the document's @context", async () => {
      // What a signer hashing the proof as given (the reference) produces.
      const result = await contextual(undefined, "without");
      expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
    });
  });

  it("accepts the historical purposes and refuses others", async () => {
    // "New operations emit capabilityInvocation; version 1 also accepts
    // historical authentication and assertionMethod purposes."
    const { did, op: genesis } = await agentGenesis(KEY_A, T0);
    for (const [proofPurpose, ok] of [
      ["authentication", true],
      ["assertionMethod", true],
      ["keyAgreement", false],
      ["capabilityDelegation", false],
    ] as const) {
      const op = signSuite(
        {
          type: "update",
          did,
          previd: await opCid(genesis),
          doc: { didDocumentData: { n: 1 } },
        },
        KEY_A,
        `${did}#key-1`,
        T1,
        { proofPurpose },
      );
      stubExport({ [did]: [genesis, op].map(hyperswarm) });
      const result = await resolve(did);
      expect(result.didResolutionMetadata.error, proofPurpose).toBe(
        ok ? undefined : "invalidDidDocument",
      );
    }
  });
});

describe("key selection by proof.verificationMethod (protocol-rules.md, State transitions)", () => {
  it("authorizes with a non-first key the document lists", async () => {
    const { did, genesis, addKey } = await twoKeyAgent();
    const bySecond = await update(
      did,
      addKey,
      { didDocumentData: { by: 2 } },
      KEY_B,
      `${did}#key-2`,
      T2,
    );
    stubExport({ [did]: [genesis, addKey, bySecond].map(hyperswarm) });
    const result = await resolve(did);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata.versionSequence).toBe("3");
  });

  it("does not enforce relationship membership for the named key", async () => {
    // "it does not enforce membership in capabilityInvocation" (archon#1156
    // is open): #key-2 is listed only under verificationMethod.
    const { did, genesis, addKey } = await twoKeyAgent();
    const doc = (addKey.doc as Op).didDocument as Op;
    expect(doc.capabilityInvocation).toEqual(["#key-1"]);
    const relative = await update(
      did,
      addKey,
      { didDocumentData: { by: 2 } },
      KEY_B,
      "#key-2",
      T2,
    );
    stubExport({ [did]: [genesis, addKey, relative].map(hyperswarm) });
    expect((await resolve(did)).didResolutionMetadata.error).toBeUndefined();
  });

  it("refuses a proof naming a key other than the signer's, or an unlisted key", async () => {
    const { did, genesis, addKey } = await twoKeyAgent();
    for (const verificationMethod of [`${did}#key-1`, `${did}#key-9`]) {
      const op = await update(
        did,
        addKey,
        { didDocumentData: { by: 2 } },
        KEY_B,
        verificationMethod,
        T2,
      );
      stubExport({ [did]: [genesis, addKey, op].map(hyperswarm) });
      await expectRefused(did, "operation 2");
    }
  });

  it("refuses a named method that is not a secp256k1 key", async () => {
    const { did, op: genesis } = await agentGenesis(KEY_A, T0);
    const doc = agentDocument(did, [{ id: "#key-1", priv: KEY_A }]);
    (doc.verificationMethod as Op[]).push({
      id: "#key-x",
      controller: did,
      type: "JsonWebKey2020",
      publicKeyJwk: {
        kty: "OKP",
        crv: "X25519",
        x: b64u(new Uint8Array(32).fill(5)),
      },
    });
    const add = await update(
      did,
      genesis,
      { didDocument: doc },
      KEY_A,
      `${did}#key-1`,
      T1,
    );
    const byX = await update(
      did,
      add,
      { didDocumentData: { n: 1 } },
      KEY_A,
      `${did}#key-x`,
      T2,
    );
    stubExport({ [did]: [genesis, add, byX].map(hyperswarm) });
    await expectRefused(did, "not a secp256k1 key");
  });

  it("refuses duplicate method ids after resolving relative fragments", async () => {
    const { did, op: genesis } = await agentGenesis(KEY_A, T0);
    const doc = agentDocument(did, [{ id: "#key-1", priv: KEY_A }]);
    (doc.verificationMethod as Op[]).push({
      id: `${did}#key-1`,
      controller: did,
      type: "EcdsaSecp256k1VerificationKey2019",
      publicKeyJwk: jwkFor(KEY_A),
    });
    const dup = await update(
      did,
      genesis,
      { didDocument: doc },
      KEY_A,
      `${did}#key-1`,
      T1,
    );
    stubExport({ [did]: [genesis, dup].map(hyperswarm) });
    await expectRefused(did, "operation 1");
  });
});

describe("asset authority by chain position (protocol-rules.md, Operation Authorization)", () => {
  const REG = "BTC:signet";
  const time = (h: number) =>
    new Date(Date.UTC(2026, 9, 1) + h * 60_000).toISOString();

  /** Owner on `ownerRegistry`: genesis, then a rotation KEY_A -> KEY_B. */
  async function setup(ownerRegistry: string, rotationAt: (op: Op) => Event) {
    const { did: owner, op: ownerGenesis } = await agentGenesis(
      KEY_A,
      T0,
      ownerRegistry,
    );
    const rotation = await update(
      owner,
      ownerGenesis,
      { didDocument: agentDocument(owner, [{ id: "#key-1", priv: KEY_B }]) },
      KEY_A,
      `${owner}#key-1`,
      time(20),
    );
    const assetGenesis = signSuite(
      {
        type: "create",
        created: time(2),
        registration: { version: 1, type: "asset", registry: REG },
        controller: owner,
        data: { v: 0 },
      },
      KEY_A,
      `${owner}#key-1`,
      time(2),
    );
    const asset = `did:cid:${await opCid(assetGenesis)}`;
    // Signed by the retired KEY_A, claiming a proof time before the rotation.
    const backdated = signSuite(
      {
        type: "update",
        did: asset,
        previd: await opCid(assetGenesis),
        doc: { didDocumentData: { v: 1 } },
      },
      KEY_A,
      `${owner}#key-1`,
      time(10),
    );
    const ownerEvents =
      ownerRegistry === REG
        ? [chainReceipt(ownerGenesis, REG, 1, time(1)), rotationAt(rotation)]
        : [hyperswarm(ownerGenesis), hyperswarm(rotation)];
    return { owner, asset, assetGenesis, backdated, ownerEvents };
  }

  it("refuses a retired key at a chain position after the owner's rotation", async () => {
    const s = await setup(REG, (op) => chainReceipt(op, REG, 20, time(20)));
    stubExport({
      [s.owner]: s.ownerEvents,
      [s.asset]: [
        chainReceipt(s.assetGenesis, REG, 2, time(2)),
        chainReceipt(s.backdated, REG, 30, time(30)),
      ],
    });
    await expectRefused(s.asset, "operation 1");
  });

  it("orders a rotation and an operation in the same block by ordinal", async () => {
    // Same block time; the rotation is at index 0, the operation at index 1.
    const s = await setup(REG, (op) => ({
      ...chainReceipt(op, REG, 20, time(30)),
      ordinal: [20, 0, 0],
      registration: {
        height: 20,
        index: 0,
        opidx: 0,
        txid: "tx20",
        batch: "b20",
      },
    }));
    const after = {
      ...chainReceipt(s.backdated, REG, 20, time(30)),
      ordinal: [20, 1, 0],
      registration: {
        height: 20,
        index: 1,
        opidx: 0,
        txid: "tx20b",
        batch: "b20b",
      },
    };
    stubExport({
      [s.owner]: s.ownerEvents,
      [s.asset]: [chainReceipt(s.assetGenesis, REG, 2, time(2)), after],
    });
    await expectRefused(s.asset, "operation 1");
    // One position earlier, before the rotation, the same key is authorized.
    const before = {
      ...after,
      ordinal: [19, 1, 0],
      registration: { ...after.registration, height: 19 },
    };
    stubExport({
      [s.owner]: s.ownerEvents,
      [s.asset]: [chainReceipt(s.assetGenesis, REG, 2, time(2)), before],
    });
    expect(
      (await resolve(s.asset)).didResolutionMetadata.error,
    ).toBeUndefined();
  });

  it("authorizes the rotated key at that chain position", async () => {
    const s = await setup(REG, (op) => chainReceipt(op, REG, 20, time(20)));
    const fresh = signSuite(
      {
        type: "update",
        did: s.asset,
        previd: await opCid(s.assetGenesis),
        doc: { didDocumentData: { v: 1 } },
      },
      KEY_B,
      `${s.owner}#key-1`,
      time(10), // proof time before the rotation: chain position decides
    );
    stubExport({
      [s.owner]: s.ownerEvents,
      [s.asset]: [
        chainReceipt(s.assetGenesis, REG, 2, time(2)),
        chainReceipt(fresh, REG, 30, time(30)),
      ],
    });
    expect(
      (await resolve(s.asset)).didResolutionMetadata.error,
    ).toBeUndefined();
  });

  it("falls back to proof time when the owner's history is not chain-anchored", async () => {
    // "Without qualifying chain evidence, select controller history at the
    // operation's proof.created" — a Hyperswarm owner has no chain clock.
    const s = await setup("hyperswarm", (op) => hyperswarm(op));
    stubExport({
      [s.owner]: s.ownerEvents,
      [s.asset]: [
        chainReceipt(s.assetGenesis, REG, 2, time(2)),
        chainReceipt(s.backdated, REG, 30, time(30)),
      ],
    });
    expect(
      (await resolve(s.asset)).didResolutionMetadata.error,
    ).toBeUndefined();
  });
});

describe("asset ownership (protocol-rules.md, State transitions)", () => {
  async function asset(owner: string, registry: string, created: string) {
    const op = signSuite(
      {
        type: "create",
        created,
        registration: { version: 1, type: "asset", registry },
        controller: owner,
        data: { v: 0 },
      },
      KEY_A,
      `${owner}#key-1`,
      created,
    );
    return { did: `did:cid:${await opCid(op)}`, op };
  }

  it("refuses a non-local asset created by a local-only owner", async () => {
    // "A local-only controller cannot create a non-local asset."
    const { did: owner, op: ownerGenesis } = await agentGenesis(
      KEY_A,
      T0,
      "local",
    );
    const local = { registry: "local", time: T0, operation: ownerGenesis };
    const ok = await asset(owner, "local", T1);
    const bad = await asset(owner, "hyperswarm", T1);
    stubExport({
      [owner]: [local],
      [ok.did]: [{ registry: "local", time: T1, operation: ok.op }],
      [bad.did]: [hyperswarm(bad.op)],
    });
    expect((await resolve(ok.did)).didResolutionMetadata.error).toBeUndefined();
    await expectRefused(bad.did, "non-local registry");
  });

  it("refuses an asset created by a deactivated owner", async () => {
    const { did: owner, op: ownerGenesis } = await agentGenesis(KEY_A, T0);
    const remove = signSuite(
      { type: "delete", did: owner, previd: await opCid(ownerGenesis) },
      KEY_A,
      `${owner}#key-1`,
      T1,
    );
    const late = await asset(owner, "hyperswarm", T2);
    stubExport({
      [owner]: [ownerGenesis, remove].map(hyperswarm),
      [late.did]: [hyperswarm(late.op)],
    });
    await expectRefused(late.did, "operation 0");
  });
});

describe("history linkage and envelopes (fail closed)", () => {
  async function threeOps() {
    const { did, op: genesis } = await agentGenesis(KEY_A, T0);
    const one = await update(
      did,
      genesis,
      { didDocumentData: { n: 1 } },
      KEY_A,
      `${did}#key-1`,
      T1,
    );
    const two = await update(
      did,
      one,
      { didDocumentData: { n: 2 } },
      KEY_A,
      `${did}#key-1`,
      T2,
    );
    return { did, genesis, one, two };
  }

  it("refuses a reordered chain", async () => {
    const { did, genesis, one, two } = await threeOps();
    stubExport({ [did]: [genesis, two, one].map(hyperswarm) });
    await expectRefused(did, "previd");
  });

  it("refuses an export with competing successors of one predecessor", async () => {
    // Sibling selection happens where Archon accepts evidence; the export is
    // the accepted history, which never holds two successors of one
    // predecessor. See REFERENCE-MAP.md, open questions.
    const { did, genesis, one } = await threeOps();
    const sibling = await update(
      did,
      genesis,
      { didDocumentData: { n: 9 } },
      KEY_A,
      `${did}#key-1`,
      T3,
    );
    for (const order of [
      [one, sibling],
      [sibling, one],
    ]) {
      stubExport({ [did]: [genesis, ...order].map(hyperswarm) });
      await expectRefused(did, "previd");
    }
  });

  it("refuses an envelope that names another DID", async () => {
    const { did, genesis, one } = await threeOps();
    const other = (await agentGenesis(KEY_C, T0)).did;
    stubExport({
      [did]: [hyperswarm(genesis), { ...hyperswarm(one), did: other }],
    });
    await expectRefused(did, "event 1 targets another DID");
  });

  it("refuses an operation whose signed did is another DID", async () => {
    const { did, genesis } = await threeOps();
    const other = (await agentGenesis(KEY_C, T0)).did;
    const misdirected = signSuite(
      {
        type: "update",
        did: other,
        previd: await opCid(genesis),
        doc: { didDocumentData: { n: 1 } },
      },
      KEY_A,
      `${did}#key-1`,
      T1,
    );
    stubExport({ [did]: [genesis, misdirected].map(hyperswarm) });
    await expectRefused(did, "targets another DID");
  });

  it("refuses an operation over the 65,536 code-unit size", async () => {
    const { did, op: genesis } = await agentGenesis(KEY_A, T0);
    const big = await update(
      did,
      genesis,
      { didDocumentData: { blob: "x".repeat(65_536) } },
      KEY_A,
      `${did}#key-1`,
      T1,
    );
    stubExport({ [did]: [genesis, big].map(hyperswarm) });
    await expectRefused(did, "malformed event 1");
  });

  it("refuses ill-formed Unicode, which has no RFC 8785 encoding", async () => {
    const { did, op: genesis } = await agentGenesis(KEY_A, T0);
    const bad = await update(
      did,
      genesis,
      { didDocumentData: { s: "\ud800" } },
      KEY_A,
      `${did}#key-1`,
      T1,
    );
    stubExport({ [did]: [genesis, bad].map(hyperswarm) });
    await expectRefused(did, "Unicode");
  });

  it("refuses an explicit null document replacement", async () => {
    // "this does not make explicit null a valid registration or document
    // replacement" (protocol-rules.md, Identity and admission).
    const { did, op: genesis } = await agentGenesis(KEY_A, T0);
    const nulled = await update(
      did,
      genesis,
      { didDocument: null, didDocumentData: { n: 1 } },
      KEY_A,
      `${did}#key-1`,
      T1,
    );
    stubExport({ [did]: [genesis, nulled].map(hyperswarm) });
    await expectRefused(did, "operation 1");
  });

  it("applies versionSequence and versionTime to the verified prefix only", async () => {
    const { did, genesis, one, two } = await threeOps();
    const forged = clone(two);
    (forged.doc as Op).didDocumentData = { forged: true };
    stubExport({ [did]: [genesis, one, forged].map(hyperswarm) });
    // Nothing past the bound is applied, so nothing past it is verified
    // (resolveDIDAt breaks before authorizing).
    const bySequence = await resolve(did, { versionSequence: "2" });
    expect(bySequence.didDocumentMetadata.versionId).toBe(await opCid(one));
    const byTime = await resolve(did, { versionTime: T1 });
    expect(byTime.didDocumentMetadata.versionId).toBe(await opCid(one));
    await expectRefused(did, "operation 2");
  });
});
