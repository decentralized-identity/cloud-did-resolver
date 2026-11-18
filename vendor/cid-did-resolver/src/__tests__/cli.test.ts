import { afterEach, describe, expect, it, vi } from "vitest";
import {
  COMMAND,
  USAGE,
  main,
  optionsFromEnv,
  parseArgs,
  type CliIo,
} from "../cli.js";
import {
  GATEKEEPER,
  agentGenesis,
  hyperswarm,
  key,
  opCid,
  signSuite,
  stubExport,
} from "./helpers.js";

function capture(): { out: string[]; err: string[]; io: CliIo } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    io: {
      stdout: (text) => {
        out.push(text);
      },
      stderr: (text) => {
        err.push(text);
      },
    },
  };
}

const ENV = {};

afterEach(() => vi.unstubAllGlobals());

// Every case here is offline: malformed and foreign identifiers are rejected
// by did-resolver before the driver would touch the network.
describe(COMMAND, () => {
  it("prints usage and exits 0 on --help", async () => {
    const c = capture();
    expect(await main(["--help"], ENV, c.io)).toBe(0);
    expect(c.out.join("")).toBe(USAGE);
    expect(c.err).toEqual([]);
  });

  it("exits 2 with usage on stderr when no DID is given", async () => {
    const c = capture();
    expect(await main([], ENV, c.io)).toBe(2);
    expect(c.err.join("")).toContain("missing <did>");
    expect(c.err.join("")).toContain("Usage:");
    expect(c.out).toEqual([]);
  });

  it("rejects unknown options, stray arguments and valueless flags", () => {
    expect(parseArgs(["did:cid:x", "--nope"]).error).toBe(
      "unknown option --nope",
    );
    expect(parseArgs(["did:cid:x", "extra"]).error).toBe(
      "unexpected argument extra",
    );
    expect(parseArgs(["did:cid:x", "--version-id"]).error).toBe(
      "--version-id requires a value",
    );
    expect(parseArgs(["did:cid:x", "--version-time", "--compact"]).error).toBe(
      "--version-time requires a value",
    );
    expect(parseArgs(["did:cid:x", "--version-sequence"]).error).toBe(
      "--version-sequence requires a value",
    );
  });

  it("passes resolution options and --compact through", () => {
    const parsed = parseArgs([
      "--version-id",
      "3",
      "did:cid:x",
      "--version-time",
      "2026-01-01T00:00:00Z",
      "--version-sequence",
      "2",
      "--compact",
    ]);
    expect(parsed.error).toBeUndefined();
    expect(parsed.did).toBe("did:cid:x");
    expect(parsed.compact).toBe(true);
    expect(parsed.resolutionOptions).toEqual({
      versionId: "3",
      versionTime: "2026-01-01T00:00:00Z",
      versionSequence: "2",
    });
  });

  it("documents versionId as ignored and versionSequence as a selector", () => {
    expect(USAGE).toContain("--version-sequence <n>");
    expect(USAGE).toMatch(/--version-id <id>\s+passed through but ignored/);
    expect(USAGE).toContain("resolution.md L20");
  });

  it("resolves the version --version-sequence names", async () => {
    const { did, op: genesis } = await agentGenesis(key(0x44));
    const update = signSuite(
      {
        type: "update",
        did,
        previd: await opCid(genesis),
        doc: { didDocumentData: { n: 1 } },
      },
      key(0x44),
      `${did}#key-1`,
      "2026-10-02T00:00:00.000Z",
    );
    stubExport({ [did]: [genesis, update].map(hyperswarm) });
    const env = { CID_GATEKEEPER_URL: GATEKEEPER };
    for (const [sequence, expected] of [
      ["1", await opCid(genesis)],
      ["2", await opCid(update)],
    ]) {
      const c = capture();
      expect(await main([did, "--version-sequence", sequence], env, c.io)).toBe(
        0,
      );
      const result = JSON.parse(c.out.join(""));
      expect(result.didDocumentMetadata.versionSequence).toBe(sequence);
      expect(result.didDocumentMetadata.versionId).toBe(expected);
    }
  });

  it("reports a malformed DID as invalidDid JSON with exit 1", async () => {
    const c = capture();
    expect(await main(["did:cid:"], ENV, c.io)).toBe(1);
    const result = JSON.parse(c.out.join(""));
    expect(result.didResolutionMetadata.error).toBe("invalidDid");
    expect(result.didDocument).toBeNull();
  });

  it("reports a foreign method as unsupportedDidMethod with exit 1", async () => {
    const c = capture();
    expect(await main(["did:example:123", "--compact"], ENV, c.io)).toBe(1);
    expect(c.out.join("")).not.toContain("\n  ");
    expect(JSON.parse(c.out.join("")).didResolutionMetadata.error).toBe(
      "unsupportedDidMethod",
    );
  });

  it("maps the documented environment variables onto resolver options", () => {
    expect(optionsFromEnv({})).toEqual({});
    expect(
      optionsFromEnv({
        CID_GATEKEEPER_URL: "https://gatekeeper.example/api/v1/did",
        CID_TIMEOUT_MS: "4000",
        CID_MAX_EVENTS: "50",
        CID_DEADLINE_MS: "5000",
        CID_MAX_DIDS: "8",
      }),
    ).toEqual({
      gatekeeperUrl: "https://gatekeeper.example/api/v1/did",
      maxEvents: 50,
      timeoutMs: 4000,
      deadlineMs: 5000,
      maxDids: 8,
    });
  });

  it("exits 2 on a malformed environment value without resolving", async () => {
    for (const env of [
      { CID_GATEKEEPER_URL: "ftp://gatekeeper.example" },
      { CID_MAX_EVENTS: "many" },
      { CID_DEADLINE_MS: "7s" },
      { CID_MAX_DIDS: "-1" },
    ]) {
      const c = capture();
      expect(await main(["did:cid:x"], { ...{}, ...env }, c.io)).toBe(2);
      expect(c.err.join("")).toContain(Object.keys(env)[0]);
      expect(c.out).toEqual([]);
    }
  });
});
