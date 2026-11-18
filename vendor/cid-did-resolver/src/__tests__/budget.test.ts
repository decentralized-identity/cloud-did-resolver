/**
 * Resource budgets of one resolution: distinct DID histories fetched
 * (`maxDids`), one overall deadline (`deadlineMs`), and incremental replay of
 * owner histories (each owner state built once, however many asset
 * operations it authorizes). Exceeding a budget fails closed with the
 * registered DID Resolution error `internalError`.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { applyComponents } from "../operations.js";
import { getResolver, type CidResolverOptions } from "../resolver.js";
import {
  GATEKEEPER,
  agentGenesis,
  hyperswarm,
  key,
  opCid,
  signSuite,
  stubExport,
  type Op,
} from "./helpers.js";

// Count document transitions: each one is a replayed operation.
vi.mock("../operations.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../operations.js")>();
  return { ...actual, applyComponents: vi.fn(actual.applyComponents) };
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.mocked(applyComponents).mockClear();
});

const resolveWith = (did: string, options: CidResolverOptions) =>
  getResolver({ gatekeeperUrl: GATEKEEPER, ...options }).cid(
    did,
    null as never,
    null as never,
    {},
  );

const at = (minutes: number) =>
  new Date(Date.UTC(2026, 9, 1) + minutes * 60_000).toISOString();

const KEYS = [key(0x51), key(0x52), key(0x53), key(0x54)];

/** An asset passed from agent 0 to agent 1 to agent 2 (4 DIDs in all). */
async function transferredAsset() {
  const agents = await Promise.all(
    KEYS.slice(0, 3).map((priv, i) => agentGenesis(priv, at(i))),
  );
  const genesis = signSuite(
    {
      type: "create",
      created: at(10),
      registration: { version: 1, type: "asset", registry: "hyperswarm" },
      controller: agents[0].did,
      data: { v: 0 },
    },
    KEYS[0],
    `${agents[0].did}#key-1`,
    at(10),
  );
  const asset = `did:cid:${await opCid(genesis)}`;
  const ops: Op[] = [genesis];
  for (const owner of [1, 2]) {
    ops.push(
      signSuite(
        {
          type: "update",
          did: asset,
          previd: await opCid(ops.at(-1)!),
          doc: {
            didDocument: {
              "@context": ["https://www.w3.org/ns/did/v1"],
              id: asset,
              controller: agents[owner].did,
            },
          },
        },
        KEYS[owner - 1],
        `${agents[owner - 1].did}#key-1`,
        at(10 + owner),
      ),
    );
  }
  const chains: Record<string, unknown[]> = { [asset]: ops.map(hyperswarm) };
  for (const agent of agents) chains[agent.did] = [hyperswarm(agent.op)];
  return { asset, chains };
}

describe("fan-out budget (maxDids)", () => {
  it("fails closed with internalError past the cap, before fetching more", async () => {
    const { asset, chains } = await transferredAsset();
    const fetchMock = stubExport(chains);
    const capped = await resolveWith(asset, { maxDids: 3 });
    expect(capped.didResolutionMetadata).toEqual({
      error: "internalError",
      message: "resolution needs more than 3 DID histories",
    });
    expect(fetchMock).toHaveBeenCalledTimes(3);
    fetchMock.mockClear();
    const enough = await resolveWith(asset, { maxDids: 4 });
    expect(enough.didResolutionMetadata.error).toBeUndefined();
    expect(enough.didDocumentMetadata.versionSequence).toBe("3");
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it("fetches each DID once per resolution (default cap 32)", async () => {
    const { asset, chains } = await transferredAsset();
    const fetchMock = stubExport(chains);
    const result = await resolveWith(asset, {});
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });
});

describe("deadline budget (deadlineMs)", () => {
  /** A Gatekeeper that answers only when aborted. */
  const hangingFetch = () =>
    vi.fn(
      (_input: RequestInfo | URL, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () =>
            reject(init.signal?.reason),
          );
        }),
    );

  it("aborts a request at the resolution deadline with internalError", async () => {
    vi.stubGlobal("fetch", hangingFetch());
    const { asset } = await transferredAsset();
    const result = await resolveWith(asset, { deadlineMs: 40 });
    expect(result.didResolutionMetadata).toEqual({
      error: "internalError",
      message: "resolution exceeded its 40 ms deadline",
    });
  });

  it("keeps a per-request timeout inside the deadline a networkError", async () => {
    vi.stubGlobal("fetch", hangingFetch());
    const { asset } = await transferredAsset();
    const result = await resolveWith(asset, {
      timeoutMs: 20,
      deadlineMs: 5000,
    });
    expect(result.didResolutionMetadata.error).toBe("networkError");
  });

  it("stops between requests once the deadline has passed", async () => {
    const { asset, chains } = await transferredAsset();
    const exported = stubExport(chains);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        await new Promise((resolve) => setTimeout(resolve, 25));
        return exported(input, init);
      }),
    );
    const result = await resolveWith(asset, { deadlineMs: 60 });
    expect(result.didResolutionMetadata.error).toBe("internalError");
    expect(result.didResolutionMetadata.message).toContain("deadline");
  });
});

describe("owner histories are replayed once per resolution", () => {
  it("builds each owner state once, not once per asset operation", async () => {
    const M = 30;
    const N = 30;
    const { did: owner, op: ownerGenesis } = await agentGenesis(KEYS[3], at(0));
    const ownerOps: Op[] = [ownerGenesis];
    for (let i = 1; i <= M; i++) {
      ownerOps.push(
        signSuite(
          {
            type: "update",
            did: owner,
            previd: await opCid(ownerOps.at(-1)!),
            doc: { didDocumentData: { n: i } },
          },
          KEYS[3],
          `${owner}#key-1`,
          at(i),
        ),
      );
    }
    const assetGenesis = signSuite(
      {
        type: "create",
        created: at(M + 1),
        registration: { version: 1, type: "asset", registry: "hyperswarm" },
        controller: owner,
        data: { v: 0 },
      },
      KEYS[3],
      `${owner}#key-1`,
      at(M + 1),
    );
    const asset = `did:cid:${await opCid(assetGenesis)}`;
    const assetOps: Op[] = [assetGenesis];
    for (let i = 1; i <= N; i++) {
      assetOps.push(
        signSuite(
          {
            type: "update",
            did: asset,
            previd: await opCid(assetOps.at(-1)!),
            doc: { didDocumentData: { v: i } },
          },
          KEYS[3],
          `${owner}#key-1`,
          at(M + 1 + i),
        ),
      );
    }
    stubExport({
      [owner]: ownerOps.map(hyperswarm),
      [asset]: assetOps.map(hyperswarm),
    });
    const result = await resolveWith(asset, {});
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata.versionSequence).toBe(String(N + 1));
    // Every operation of either history is applied exactly once; a replay
    // per asset operation would apply the owner's M updates N + 1 times.
    expect(vi.mocked(applyComponents)).toHaveBeenCalledTimes(M + N);
  });
});
