import { afterEach, expect, it, vi } from "vitest";
import { fold, probeOne, probeZone } from "./index";
import { OUTBOUND_CANARIES } from "../../src/outbound-canaries";

type ProbeEnv = Parameters<typeof probeOne>[1];

afterEach(() => vi.unstubAllGlobals());

it("trips a provider down after three all-failed probe rounds and recovers on success", () => {
  const failed = [
    {
      step: "archon" as const,
      did: "did:iden3:test",
      ok: false,
      ms: 8000,
      error: "timeout",
    },
  ];
  const one = fold(null, failed, 1);
  const two = fold(one, failed, 2);
  const three = fold(two, failed, 3);
  expect(three.providers.archon?.status).toBe("down");
  const recovered = fold(
    three,
    [{ ...failed[0], ok: true, ms: 100, error: null }],
    4,
  );
  expect(recovered.providers.archon?.status).toBe("up");
  expect(recovered.providers.archon?.consecutiveFails).toBe(0);
});

it("probes Godiddy via the health endpoint, never the resolver API", async () => {
  const fetchMock = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(String(input)).toBe("https://health.test/health");
      // The probe authenticates exactly like live resolution traffic.
      expect(
        (init?.headers as Record<string, string> | undefined)?.authorization,
      ).toBe("Bearer probe-key");
      return new Response("OK");
    },
  );
  vi.stubGlobal("fetch", fetchMock);
  const result = await probeOne({ step: "godiddy", did: "health:godiddy" }, {
    GODIDDY_HEALTH: "https://health.test/health",
    GODIDDY_API_KEY: "probe-key",
  } as ProbeEnv);
  expect(result.ok).toBe(true);
  expect(result.error).toBeNull();
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

it("counts a throttled (429) Godiddy as up, flagged rateLimited", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response("slow down", { status: 429 })),
  );
  const result = await probeOne(
    { step: "godiddy", did: "health:godiddy" },
    {} as ProbeEnv,
  );
  expect(result.ok).toBe(true);
  expect(result.error).toBe("rateLimited");
});

it("counts a failing Godiddy health endpoint as a miss", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response("boom", { status: 503 })),
  );
  const result = await probeOne(
    { step: "godiddy", did: "health:godiddy" },
    {} as ProbeEnv,
  );
  expect(result.ok).toBe(false);
  expect(result.error).toBe("miss");
});

it("probes did:cid canaries against Archon's Gatekeeper base", async () => {
  const CID_DID = "did:cid:bagaaieraexample";
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    expect(String(input)).toBe(
      `https://gatekeeper.test/api/v1/did/${encodeURIComponent(CID_DID)}`,
    );
    return Response.json({
      didDocument: { id: CID_DID },
      didDocumentMetadata: {},
      didResolutionMetadata: {},
    });
  });
  vi.stubGlobal("fetch", fetchMock);
  const result = await probeOne({ step: "archon", did: CID_DID }, {
    ARCHON_RESOLVER: "https://archon.test",
    ARCHON_CID_RESOLVER: "https://gatekeeper.test/api/v1/did",
  } as ProbeEnv);
  expect(result.ok).toBe(true);
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

it("counts a rate-limited canary resolution as up for any upstream", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response("slow down", { status: 429 })),
  );
  const result = await probeOne({ step: "archon", did: "did:iden3:test" }, {
    ARCHON_RESOLVER: "https://archon.test",
  } as ProbeEnv);
  expect(result.ok).toBe(true);
  expect(result.error).toBe("rateLimited");
});

it("skips the zone check when no public origin is configured", async () => {
  const fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
  expect(await probeZone({} as ProbeEnv)).toEqual([]);
  expect(fetchMock).not.toHaveBeenCalled();
});

it("checks the resolver through the public origin and records zone:<method>", async () => {
  const [cid, plc] = OUTBOUND_CANARIES;
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    expect(String(input)).toBe("https://resolver.test/health/outbound");
    return Response.json(
      {
        ok: false,
        checkedTs: 1,
        checks: [
          {
            did: cid,
            method: "cid",
            ok: false,
            ms: 300,
            error: "notFound",
            attempts: [
              { step: "local", error: "networkError" },
              { step: "archon", error: "upstreamError", status: 525 },
            ],
          },
          {
            did: plc,
            method: "plc",
            ok: true,
            ms: 120,
            error: null,
            attempts: [],
          },
        ],
      },
      { status: 503 },
    );
  });
  vi.stubGlobal("fetch", fetchMock);
  const results = await probeZone({
    PUBLIC_RESOLVER_URL: "https://resolver.test/",
  } as ProbeEnv);
  expect(results).toEqual([
    {
      step: "zone",
      healthKey: "zone:cid",
      did: cid,
      ok: false,
      ms: 300,
      error: "local:networkError,archon:525",
    },
    {
      step: "zone",
      healthKey: "zone:plc",
      did: plc,
      ok: true,
      ms: 120,
      error: null,
    },
  ]);
  // Three failed rounds trip the zone key down, like any provider.
  const one = fold(null, results, 1);
  const three = fold(fold(one, results, 2), results, 3);
  expect(three.providers["zone:cid"]?.status).toBe("down");
  expect(three.providers["zone:plc"]?.status).toBe("up");
});

it("fails every zone canary when the public origin is unreachable", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      throw new Error("connect failed");
    }),
  );
  const results = await probeZone({
    PUBLIC_RESOLVER_URL: "https://resolver.test",
  } as ProbeEnv);
  expect(results.map((r) => [r.healthKey, r.ok, r.error])).toEqual(
    OUTBOUND_CANARIES.map((did) => [
      `zone:${did.split(":")[1]}`,
      false,
      "error",
    ]),
  );
});

it("counts a throttled zone check as up, flagged rateLimited", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response("", { status: 429 })),
  );
  const results = await probeZone({
    PUBLIC_RESOLVER_URL: "https://resolver.test",
  } as ProbeEnv);
  expect(results.every((r) => r.ok && r.error === "rateLimited")).toBe(true);
});
