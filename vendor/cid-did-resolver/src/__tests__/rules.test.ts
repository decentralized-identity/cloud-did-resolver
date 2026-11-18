/**
 * One synthetic test per rule an independent review found unguarded (each
 * check could be reverted with the suite still passing). Spec citations are
 * archetech/didcid-specs e8aace4; reference citations archon 9924993.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import r7rExport from "./vectors/live/bagaaierar7r-export.json";
import r7rResult from "./vectors/live/bagaaierar7r-conformant.json";
import { normalizeEventTime, type GatekeeperEvent } from "../operations.js";
import {
  agentDocument,
  agentGenesis,
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

const KEY_A = key(0x71);
const KEY_B = key(0x72);
const BTC = "BTC:signet";
const t = (m: number) =>
  new Date(Date.UTC(2026, 9, 1) + m * 60_000).toISOString();

async function expectRefused(did: string, fragment?: string) {
  const result = await resolve(did);
  expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
  if (fragment) {
    expect(result.didResolutionMetadata.message).toContain(fragment);
  }
}
const expectResolved = async (did: string, sequence?: string) => {
  const result = await resolve(did);
  expect(result.didResolutionMetadata.error).toBeUndefined();
  if (sequence)
    expect(result.didDocumentMetadata.versionSequence).toBe(sequence);
};

const update = async (
  did: string,
  previous: Op,
  doc: Op,
  priv: Uint8Array,
  signer: string,
  created: string,
) =>
  signSuite(
    { type: "update", did, previd: await opCid(previous), doc },
    priv,
    `${signer}#key-1`,
    created,
  );

/** A data-only asset update signed by `priv` claiming proof time `created`. */
const assetUpdate = async (
  asset: string,
  previous: Op,
  owner: string,
  priv: Uint8Array,
  created: string,
) =>
  update(asset, previous, { didDocumentData: { v: 1 } }, priv, owner, created);

async function assetGenesis(owner: string, registry: string, created: string) {
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

const rotateTo = (owner: string, priv: Uint8Array) => ({
  didDocument: agentDocument(owner, [{ id: "#key-1", priv }]),
});

describe("creation rules (protocol-rules.md L21; creation.md L30)", () => {
  it("refuses an agent creation that names a key other than #key-1", async () => {
    const op = signSuite(
      {
        type: "create",
        created: t(0),
        registration: { version: 1, type: "agent", registry: "hyperswarm" },
        publicJwk: jwkFor(KEY_A),
      },
      KEY_A,
      "#key-2",
      t(0),
    );
    const did = `did:cid:${await opCid(op)}`;
    stubExport({ [did]: [hyperswarm(op)] });
    await expectRefused(did, "#key-1");
  });

  it("refuses an agent publicJwk without kty and crv (archon #1140)", async () => {
    const { x, y } = jwkFor(KEY_A);
    const op = signSuite(
      {
        type: "create",
        created: t(0),
        registration: { version: 1, type: "agent", registry: "hyperswarm" },
        publicJwk: { x, y },
      },
      KEY_A,
      "#key-1",
      t(0),
    );
    const did = `did:cid:${await opCid(op)}`;
    stubExport({ [did]: [hyperswarm(op)] });
    await expectRefused(did, "publicJwk");
  });

  it("refuses a second create later in the export", async () => {
    // A duplicated genesis must not re-enter the walk and rewrite metadata.
    const { did, op: genesis } = await agentGenesis(KEY_A, t(0));
    const data = await update(
      did,
      genesis,
      { didDocumentData: { n: 1 } },
      KEY_A,
      did,
      t(1),
    );
    stubExport({ [did]: [genesis, data, genesis].map(hyperswarm) });
    await expectRefused(did, "create after genesis");
  });
});

describe("update and proof rules", () => {
  it("refuses a document replacement that drops its id (protocol-rules.md L24)", async () => {
    const { did, op: genesis } = await agentGenesis(KEY_A, t(0));
    const doc = agentDocument(did, [{ id: "#key-1", priv: KEY_A }]);
    delete doc.id;
    const anonymous = await update(
      did,
      genesis,
      { didDocument: doc },
      KEY_A,
      did,
      t(1),
    );
    stubExport({ [did]: [genesis, anonymous].map(hyperswarm) });
    await expectRefused(did, "operation 1");
  });

  it("refuses a proof whose created is not an RFC 3339 time (proof-verification.md L55)", async () => {
    // On a chain registry, so the bad value is not also the event time; the
    // legacy proof leaves `created` unsigned, so only the format check stops it.
    const genesis = signSuite(
      {
        type: "create",
        created: t(0),
        registration: { version: 1, type: "agent", registry: BTC },
        publicJwk: jwkFor(KEY_A),
      },
      KEY_A,
      "#key-1",
      t(0),
    );
    const did = `did:cid:${await opCid(genesis)}`;
    const op = signLegacy(
      {
        type: "update",
        did,
        previd: await opCid(genesis),
        doc: { didDocumentData: { n: 1 } },
      },
      KEY_A,
      `${did}#key-1`,
      "not-a-date",
    );
    stubExport({
      [did]: [
        chainReceipt(genesis, BTC, 1, t(0)),
        chainReceipt(op, BTC, 2, t(1)),
      ],
    });
    await expectRefused(did, "malformed event 1");
    (op.proof as Op).created = t(1);
    stubExport({
      [did]: [
        chainReceipt(genesis, BTC, 1, t(0)),
        chainReceipt(op, BTC, 2, t(1)),
      ],
    });
    await expectResolved(did, "2");
  });
});

describe("receipts and confirmation (protocol-rules.md L25, L51-53)", () => {
  it("refuses a chain receipt whose opidx is not the ordinal's last component", async () => {
    const chain = clone((r7rExport as unknown as Event[][])[0]);
    (chain[3].registration as Op).opidx = 2; // ordinal [941189, 1891, 1]
    stubExport({
      [(r7rResult as { didDocument: { id: string } }).didDocument.id]: chain,
    });
    await expectRefused(
      (r7rResult as { didDocument: { id: string } }).didDocument.id,
      "malformed event 3",
    );
  });

  it("confirms the genesis unconditionally, whatever its receipt", async () => {
    // A chain-registry DID created through gossip (creation.md L5; lifecycle.md
    // L7: creation does not wait for a chain anchor), then anchored updates.
    const genesis = signSuite(
      {
        type: "create",
        created: t(0),
        registration: { version: 1, type: "agent", registry: BTC },
        publicJwk: jwkFor(KEY_A),
      },
      KEY_A,
      "#key-1",
      t(0),
    );
    const did = `did:cid:${await opCid(genesis)}`;
    const data = await update(
      did,
      genesis,
      { didDocumentData: { n: 1 } },
      KEY_A,
      did,
      t(1),
    );
    stubExport({
      [did]: [hyperswarm(genesis), chainReceipt(data, BTC, 5, t(2))],
    });
    await expectResolved(did, "2");
  });

  it("normalizes a local creation to its created time, other unanchored receipts to proof time", () => {
    const operation = (type: string) => ({
      type,
      created: "2026-01-01T00:00:00.000Z",
      proof: { created: "2026-01-02T00:00:00.000Z" },
    });
    const time = (registry: string, type: string) => {
      const event = {
        registry,
        time: "2030-01-01T00:00:00Z",
        operation: operation(type),
      };
      normalizeEventTime(event as GatekeeperEvent);
      return event.time;
    };
    expect(time("local", "create")).toBe("2026-01-01T00:00:00.000Z");
    expect(time("local", "update")).toBe("2026-01-02T00:00:00.000Z");
    expect(time("hyperswarm", "create")).toBe("2026-01-02T00:00:00.000Z");
    expect(time("pin", "update")).toBe("2026-01-02T00:00:00.000Z");
    expect(time(BTC, "update")).toBe("2030-01-01T00:00:00Z");
  });
});

describe("asset authority selection (protocol-rules.md L38-43)", () => {
  it("compares ordinals only on the cutoff's own registry (L41)", async () => {
    // Owner on ETH:sepolia with a large height; asset on BTC:signet. The
    // owner's rotation precedes the asset operation by block time; comparing
    // its ETH ordinal with the BTC one would wrongly exclude it.
    const ETH = "ETH:sepolia";
    const { did: owner, op: ownerGenesis } = await agentGenesis(
      KEY_A,
      t(0),
      ETH,
    );
    const rotation = await update(
      owner,
      ownerGenesis,
      rotateTo(owner, KEY_B),
      KEY_A,
      owner,
      t(20),
    );
    const asset = await assetGenesis(owner, BTC, t(2));
    const ownerChain = [
      chainReceipt(ownerGenesis, ETH, 1, t(1)),
      chainReceipt(rotation, ETH, 900, t(20)),
    ];
    const retired = await assetUpdate(asset.did, asset.op, owner, KEY_A, t(10));
    stubExport({
      [owner]: ownerChain,
      [asset.did]: [
        chainReceipt(asset.op, BTC, 2, t(2)),
        chainReceipt(retired, BTC, 30, t(30)),
      ],
    });
    await expectRefused(asset.did, "operation 1");
    const current = await assetUpdate(asset.did, asset.op, owner, KEY_B, t(10));
    stubExport({
      [owner]: ownerChain,
      [asset.did]: [
        chainReceipt(asset.op, BTC, 2, t(2)),
        chainReceipt(current, BTC, 30, t(30)),
      ],
    });
    await expectResolved(asset.did, "2");
  });

  /**
   * Owner: Hyperswarm genesis (KEY_A), rotation to KEY_B at t10 and migration
   * to BTC:signet at t11 (both Hyperswarm), then `tail`.
   */
  async function migratingOwner(
    tail: (owner: string, migration: Op) => Promise<Event[]>,
  ) {
    const { did: owner, op: ownerGenesis } = await agentGenesis(KEY_A, t(0));
    const rotation = await update(
      owner,
      ownerGenesis,
      rotateTo(owner, KEY_B),
      KEY_A,
      owner,
      t(10),
    );
    const migration = await update(
      owner,
      rotation,
      { didDocumentRegistration: { version: 1, type: "agent", registry: BTC } },
      KEY_B,
      owner,
      t(11),
    );
    return {
      owner,
      events: [
        hyperswarm(ownerGenesis),
        { ...hyperswarm(rotation), ordinal: [3] },
        { ...hyperswarm(migration), ordinal: [4] },
        ...(await tail(owner, migration)),
      ],
    };
  }

  it("uses proof time for a Hyperswarm receipt even when it carries chain metadata (L43)", async () => {
    const { owner, events } = await migratingOwner(async (o, migration) => [
      chainReceipt(
        await update(
          o,
          migration,
          { didDocumentData: { n: 1 } },
          KEY_B,
          o,
          t(12),
        ),
        BTC,
        50,
        t(12),
      ),
    ]);
    const asset = await assetGenesis(owner, "hyperswarm", t(2));
    const disguised = (op: Op): Event => ({
      ...hyperswarm(op),
      ordinal: [10, 0, 0],
      registration: {
        height: 10,
        index: 0,
        opidx: 0,
        txid: "tx10",
        batch: "b10",
      },
    });
    // At proof time t5 the owner still holds KEY_A.
    const early = await assetUpdate(asset.did, asset.op, owner, KEY_B, t(5));
    stubExport({
      [owner]: events,
      [asset.did]: [hyperswarm(asset.op), disguised(early)],
    });
    await expectRefused(asset.did, "operation 1");
    const proofTime = await assetUpdate(
      asset.did,
      asset.op,
      owner,
      KEY_A,
      t(5),
    );
    stubExport({
      [owner]: events,
      [asset.did]: [hyperswarm(asset.op), disguised(proofTime)],
    });
    await expectResolved(asset.did, "2");
  });

  it("does not count an unconfirmed suffix as chain anchoring (L42)", async () => {
    // After the migration, BTC:signet confirms; the Hyperswarm event at t12
    // breaks the confirmed prefix, so the anchored BTC event after it cannot
    // make the owner chain-anchored, and proof time (t5, KEY_A) applies.
    const { owner, events } = await migratingOwner(async (o, migration) => {
      const hint = await update(
        o,
        migration,
        { didDocumentData: { n: 1 } },
        KEY_B,
        o,
        t(12),
      );
      const anchored = await update(
        o,
        hint,
        { didDocumentData: { n: 2 } },
        KEY_B,
        o,
        t(13),
      );
      return [hyperswarm(hint), chainReceipt(anchored, BTC, 50, t(13))];
    });
    const asset = await assetGenesis(owner, BTC, t(1));
    const backdated = await assetUpdate(
      asset.did,
      asset.op,
      owner,
      KEY_A,
      t(5),
    );
    stubExport({
      [owner]: events,
      [asset.did]: [
        chainReceipt(asset.op, BTC, 2, t(1)),
        chainReceipt(backdated, BTC, 30, t(30)),
      ],
    });
    await expectResolved(asset.did, "2");
  });

  it("falls back to proof time when the owner has migrated to an unanchored registry (GK L720)", async () => {
    // The reference's isAnchored: an owner whose registry at the cutoff is
    // Hyperswarm has no chain clock, even with anchored history before it.
    const { did: owner, op: ownerGenesis } = await agentGenesis(
      KEY_A,
      t(0),
      BTC,
    );
    const rotation = await update(
      owner,
      ownerGenesis,
      rotateTo(owner, KEY_B),
      KEY_A,
      owner,
      t(20),
    );
    const migration = await update(
      owner,
      rotation,
      {
        didDocumentRegistration: {
          version: 1,
          type: "agent",
          registry: "hyperswarm",
        },
      },
      KEY_B,
      owner,
      t(21),
    );
    const asset = await assetGenesis(owner, BTC, t(2));
    const backdated = await assetUpdate(
      asset.did,
      asset.op,
      owner,
      KEY_A,
      t(5),
    );
    stubExport({
      [owner]: [
        chainReceipt(ownerGenesis, BTC, 1, t(1)),
        chainReceipt(rotation, BTC, 20, t(20)),
        chainReceipt(migration, BTC, 21, t(21)),
      ],
      [asset.did]: [
        chainReceipt(asset.op, BTC, 2, t(2)),
        chainReceipt(backdated, BTC, 30, t(30)),
      ],
    });
    await expectResolved(asset.did, "2");
  });
});
