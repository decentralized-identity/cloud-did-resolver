/**
 * Live chains exported from https://archon.technology on 2026-11-17T23:57Z
 * (Archon 0.14.1, commit 4fd5322), each with Archon's own conformant
 * resolution (GET /1.0/identifiers/<did>) as the expected result.
 * Provenance: vectors/NOTICE.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import oneExport from "./vectors/live/bagaaieraone-export.json";
import oneResult from "./vectors/live/bagaaieraone-conformant.json";
import r7rExport from "./vectors/live/bagaaierar7r-export.json";
import r7rResult from "./vectors/live/bagaaierar7r-conformant.json";
import etsExport from "./vectors/live/bagaaieraets-export.json";
import etsResult from "./vectors/live/bagaaieraets-conformant.json";
import fgqExport from "./vectors/live/bagaaierafgq-export.json";
import fgqResult from "./vectors/live/bagaaierafgq-conformant.json";
import { SUITE, clone, resolve, stubExport, type Op } from "./helpers.js";

afterEach(() => vi.unstubAllGlobals());

type Result = { didDocument: { id: string }; didDocumentMetadata: unknown };
const events = (exported: unknown) =>
  clone((exported as unknown[][])[0]) as Op[];
const didOf = (result: unknown) => (result as Result).didDocument.id;
const suites = (chain: Op[]) =>
  chain.map(
    (e) => (e.operation as { proof: Op }).proof.cryptosuite ?? "legacy",
  );

const ROTATED = didOf(oneResult);
const MIGRATED = didOf(r7rResult);
const ASSET = didOf(etsResult);
const OWNER = didOf(fgqResult);

const allLive = () => ({
  [ROTATED]: events(oneExport),
  [MIGRATED]: events(r7rExport),
  [ASSET]: events(etsExport),
  [OWNER]: events(fgqExport),
});

async function expectArchonResult(did: string, expected: unknown) {
  const result = await resolve(did);
  expect(result.didResolutionMetadata).toEqual({
    contentType: "application/did+ld+json",
  });
  expect(result.didDocument).toEqual((expected as Result).didDocument);
  expect(result.didDocumentMetadata).toEqual(
    (expected as Result).didDocumentMetadata,
  );
}

describe("live archon.technology chains (Archon v0.13+ wallets)", () => {
  it("captures what they claim: the new suite, rotation, migration", () => {
    const rotated = events(oneExport);
    expect(suites(rotated).slice(19)).toEqual(Array(6).fill(SUITE));
    expect(suites(rotated).slice(0, 19)).toEqual(Array(19).fill("legacy"));
    const signers = rotated.map(
      (e) => (e.operation as { proof: Op }).proof.verificationMethod,
    );
    expect(new Set(signers.map((s) => String(s).split("#")[1]))).toEqual(
      new Set(["key-1", "key-2", "key-3"]),
    );
    const migrated = events(r7rExport);
    expect(migrated.map((e) => e.registry)).toEqual([
      ...Array(3).fill("hyperswarm"),
      ...Array(5).fill("BTC:mainnet"),
    ]);
    expect(suites(migrated).at(-1)).toBe(SUITE);
    expect(suites(events(etsExport))).toEqual([SUITE, SUITE]);
  });

  it("verifies a new-suite agent across two key rotations", async () => {
    stubExport(allLive());
    await expectArchonResult(ROTATED, oneResult);
  });

  it("verifies a registry migration to BTC:mainnet with chain receipts", async () => {
    stubExport(allLive());
    await expectArchonResult(MIGRATED, r7rResult);
  });

  it("verifies a new-suite asset against its owner's chain", async () => {
    stubExport(allLive());
    await expectArchonResult(ASSET, etsResult);
    await expectArchonResult(OWNER, fgqResult);
  });

  it("refuses the new-suite rotation when its proof configuration is altered", async () => {
    for (const [member, value] of [
      ["created", "2026-09-23T20:35:14.596Z"],
      ["proofPurpose", "authentication"],
      ["verificationMethod", `${ROTATED}#key-2`],
    ]) {
      const chain = events(oneExport);
      (chain[19].operation as { proof: Op }).proof[member] = value;
      stubExport({ ...allLive(), [ROTATED]: chain });
      const result = await resolve(ROTATED);
      expect(result.didResolutionMetadata.error, member).toBe(
        "invalidDidDocument",
      );
    }
  });

  it("refuses an asset operation when the owner's chain is withheld", async () => {
    stubExport({ ...allLive(), [OWNER]: [] });
    const result = await resolve(ASSET);
    expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
  });

  it("refuses a chain receipt with incomplete registration metadata", async () => {
    const chain = events(r7rExport);
    delete (chain[3].registration as Op).txid;
    stubExport({ ...allLive(), [MIGRATED]: chain });
    const result = await resolve(MIGRATED);
    expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
    expect(result.didResolutionMetadata.message).toContain("malformed event 3");
  });

  it("stops at the confirmed prefix when a successor sits on the wrong registry", async () => {
    // After the migration, BTC:mainnet confirms successors; a Hyperswarm hint
    // is not a confirmation (protocol-rules.md, State transitions;
    // resolution.md: the default result is the most recent confirmed version).
    const chain = events(r7rExport);
    const tail = chain[7];
    tail.registry = "hyperswarm";
    delete tail.ordinal;
    delete tail.registration;
    stubExport({ ...allLive(), [MIGRATED]: chain });
    const result = await resolve(MIGRATED);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata.versionSequence).toBe("7");
  });

  it("honors versionTime and versionSequence", async () => {
    stubExport(allLive());
    const bySequence = await resolve(ROTATED, { versionSequence: 20 });
    expect(bySequence.didDocumentMetadata.versionSequence).toBe("20");
    expect(bySequence.didDocument?.verificationMethod?.[0]?.id).toBe("#key-2");
    const byTime = await resolve(ROTATED, {
      versionTime: "2026-09-23T20:35:40Z",
    });
    expect(byTime.didDocumentMetadata.versionSequence).toBe("20");
    expect(byTime.didDocumentMetadata.updated).toBe("2026-09-23T20:35:14Z");
  });
});
