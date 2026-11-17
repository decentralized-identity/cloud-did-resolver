import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Env } from "./types";

const resolveDid = vi.fn();
vi.mock("./resolve", () => ({ resolveDid }));

const {
  OUTBOUND_CANARIES,
  OUTBOUND_CACHE_MS,
  checkOutbound,
  resetOutboundCache,
} = await import("./outbound-health");
const { default: app } = await import("./index");

const ok = {
  didResolutionMetadata: { provider: "ThisDID" },
  didDocument: { id: "did:x:y" },
  didDocumentMetadata: {},
};
const failed525 = {
  didResolutionMetadata: {
    error: "notFound",
    attempts: [
      { step: "local", error: "networkError" },
      { step: "archon", error: "upstreamError", status: 525 },
    ],
  },
  didDocument: null,
  didDocumentMetadata: {},
};

beforeEach(() => {
  resetOutboundCache();
  resolveDid.mockReset();
});

describe("checkOutbound", () => {
  it("resolves every canary and reports ok when all resolve", async () => {
    resolveDid.mockResolvedValue(ok);
    const report = await checkOutbound({} as Env, 1000);
    expect(report.ok).toBe(true);
    expect(report.checks.map((c) => c.did)).toEqual([...OUTBOUND_CANARIES]);
    expect(report.checks.every((c) => c.ok && c.error === null)).toBe(true);
  });

  it("reports a failing canary with its per-step failures, without documents", async () => {
    resolveDid.mockImplementation(async (did: string) =>
      did.startsWith("did:cid:") ? failed525 : ok,
    );
    const report = await checkOutbound({} as Env, 1000);
    expect(report.ok).toBe(false);
    const cid = report.checks.find((c) => c.method === "cid");
    expect(cid).toMatchObject({
      ok: false,
      error: "notFound",
      attempts: [
        { step: "local", error: "networkError" },
        { step: "archon", error: "upstreamError", status: 525 },
      ],
    });
    expect(JSON.stringify(report)).not.toContain("didDocument");
  });

  it("reuses a report for a minute, then checks again", async () => {
    resolveDid.mockResolvedValue(ok);
    await checkOutbound({} as Env, 1000);
    await checkOutbound({} as Env, 1000 + OUTBOUND_CACHE_MS - 1);
    expect(resolveDid).toHaveBeenCalledTimes(OUTBOUND_CANARIES.length);
    await checkOutbound({} as Env, 1000 + OUTBOUND_CACHE_MS);
    expect(resolveDid).toHaveBeenCalledTimes(2 * OUTBOUND_CANARIES.length);
  });

  it("shares one check between concurrent callers", async () => {
    resolveDid.mockResolvedValue(ok);
    await Promise.all([
      checkOutbound({} as Env, 1000),
      checkOutbound({} as Env, 1000),
    ]);
    expect(resolveDid).toHaveBeenCalledTimes(OUTBOUND_CANARIES.length);
  });
});

describe("GET /health/outbound", () => {
  async function request() {
    const inserts: string[] = [];
    const pending: Promise<unknown>[] = [];
    const env = {
      RESOLVER_LABEL: "test",
      ASSETS: { fetch: async () => new Response("asset") },
      DB: {
        prepare: (sql: string) => {
          if (sql.includes("INSERT")) inserts.push(sql);
          const stmt = {
            bind: () => stmt,
            run: async () => ({}),
            all: async () => ({ results: [] }),
          };
          return stmt;
        },
      },
    } as unknown as Env;
    const res = await app.request("/health/outbound", {}, env, {
      waitUntil: (p: Promise<unknown>) => void pending.push(p),
      passThroughOnException: () => {},
      props: {},
    });
    await Promise.all(pending);
    return { res, inserts };
  }

  it("answers 200 with the report when every canary resolves, and records nothing", async () => {
    resolveDid.mockResolvedValue(ok);
    const { res, inserts } = await request();
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(((await res.json()) as { ok: boolean }).ok).toBe(true);
    expect(inserts).toEqual([]);
  });

  it("answers 503 when a canary fails", async () => {
    resolveDid.mockResolvedValue(failed525);
    const { res } = await request();
    expect(res.status).toBe(503);
    expect(((await res.json()) as { ok: boolean }).ok).toBe(false);
  });
});
