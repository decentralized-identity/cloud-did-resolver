/**
 * Golden vectors from the reference implementation and the specification:
 * Archon tests/gatekeeper/*-vectors.json at 9924993 (@didcid/gatekeeper
 * 0.8.0; MIT, vectors/archon/LICENSE) and the did:cid specification's signed
 * examples at e8aace4. Provenance and hashes: vectors/NOTICE.
 *
 * The driver resolves an exported accepted history, so a vector the reference
 * accepts must resolve with it applied, and a vector the reference rejects
 * must make an export that contains it fail closed — while the export without
 * it (the reference's accepted history) still resolves.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import proofVectors from "./vectors/archon/proof-vectors.json";
import canonicalVectors from "./vectors/archon/canonicalization-vectors.json";
import numericVectors from "./vectors/archon/numeric-predecessor-vectors.json";
import controllerRules from "./vectors/archon/controller-rules-vectors.json";
import historyRecovery from "./vectors/archon/history-recovery-vectors.json";
import registrationVectors from "./vectors/archon/registration-transition-v1-vectors.json";
import specExamples from "./vectors/spec-examples.json";
import {
  canonicalizeJSON,
  generateCID,
  generateDID,
  legacyNumericCid,
  verifyCreateOperation,
  verifyProofFormat,
  verifyUpdateOperation,
  type DidCidDocument,
  type Operation,
} from "../operations.js";
import {
  clone,
  hyperswarm,
  opCid,
  resolve,
  stubExport,
  type Op,
} from "./helpers.js";

afterEach(() => vi.unstubAllGlobals());

const op = (value: unknown) => clone(value) as Operation;

/** The reference refuses either by throwing or by returning false. */
function verifies(check: () => boolean): boolean {
  try {
    return check();
  } catch {
    return false;
  }
}

// ── proof-vectors.json (operation-proofs.test.ts) ───────────────────────────

describe("Archon proof-vectors.json", () => {
  const legacy = () => op(proofVectors.agentCreateValid.operation);
  const modern = () => op(proofVectors.agentCreateValidDataIntegrity.operation);

  it("accepts the legacy proof and the Archon Data Integrity suite", () => {
    expect(verifyProofFormat(legacy().proof)).toBe(true);
    expect(verifyCreateOperation(legacy())).toBe(true);
    expect(verifyProofFormat(modern().proof)).toBe(true);
    expect(verifyCreateOperation(modern())).toBe(true);
  });

  it("rejects the invalid legacy proof", () => {
    expect(
      verifies(() =>
        verifyCreateOperation(
          op(proofVectors.agentCreateInvalidProof.operation),
        ),
      ),
    ).toBe(false);
  });

  it("refuses a cryptosuite it does not implement", () => {
    const operation = modern();
    operation.proof!.cryptosuite = "ecdsa-jcs-2019";
    expect(verifyProofFormat(operation.proof)).toBe(false);
  });

  it.each([
    ["created", "2026-04-12T12:00:00Z"],
    ["proofPurpose", "assertionMethod"],
    ["verificationMethod", "#key-2"],
  ])("binds %s in the Archon suite", (member, value) => {
    const operation = modern();
    operation.proof![member] = value;
    expect(verifies(() => verifyCreateOperation(operation))).toBe(false);
  });

  it("does not bind created on the legacy proof (unchanged by design)", () => {
    const operation = legacy();
    operation.proof!.created = "2026-04-12T12:00:00Z";
    expect(verifyCreateOperation(operation)).toBe(true);
  });

  it("still rejects a tampered operation body", () => {
    const operation = modern();
    operation.registration!.registry = "hyperswarm";
    expect(verifyCreateOperation(operation)).toBe(false);
  });

  it.each(["capabilityInvocation", "authentication", "assertionMethod"])(
    "accepts proof purpose %s",
    (proofPurpose) => {
      expect(verifyProofFormat({ ...modern().proof, proofPurpose })).toBe(true);
    },
  );

  it.each(["keyAgreement", "capabilityDelegation", ""])(
    "refuses proof purpose %j",
    (proofPurpose) => {
      expect(verifyProofFormat({ ...modern().proof, proofPurpose })).toBe(
        false,
      );
    },
  );

  it("verifies the update vectors against their authorizing document", () => {
    const doc = clone(proofVectors.agentUpdateValid.doc) as DidCidDocument;
    expect(
      verifyUpdateOperation(op(proofVectors.agentUpdateValid.operation), doc),
    ).toBe(true);
    expect(
      verifies(() =>
        verifyUpdateOperation(
          op(proofVectors.agentUpdateInvalidProof.operation),
          clone(proofVectors.agentUpdateInvalidProof.doc) as DidCidDocument,
        ),
      ),
    ).toBe(false);
  });
});

// ── canonicalization-vectors.json ───────────────────────────────────────────

describe("Archon canonicalization-vectors.json", () => {
  it.each(canonicalVectors.bytes)(
    "RFC 8785 bytes and JSON CID: $name",
    async ({ input, canonical, cid }) => {
      const value = JSON.parse(input) as unknown;
      expect(canonicalizeJSON(value)).toBe(canonical);
      expect(await generateCID(value)).toBe(cid);
    },
  );

  it.each(canonicalVectors.signed)(
    "signed JCS chain (modern=$modern) resolves and deactivates",
    async (vector) => {
      const [agent, asset, update, deletion] = vector.operations as Op[];
      for (const [i, operation] of (vector.operations as Op[]).entries()) {
        expect(await generateCID(operation)).toBe(vector.cids[i]);
      }
      stubExport({
        [vector.controller]: [hyperswarm(agent)],
        [vector.did]: [asset, update].map(hyperswarm),
      });
      const live = await resolve(vector.did);
      expect(live.didResolutionMetadata.error).toBeUndefined();
      expect(live.didDocumentMetadata.versionId).toBe(vector.cids[2]);
      stubExport({
        [vector.controller]: [hyperswarm(agent)],
        [vector.did]: [asset, update, deletion].map(hyperswarm),
      });
      const deleted = await resolve(vector.did);
      expect(deleted.didDocumentMetadata.deactivated).toBe(true);
      expect(deleted.didDocumentMetadata.versionId).toBe(vector.cids[3]);
    },
  );
});

// ── numeric-predecessor-vectors.json ────────────────────────────────────────

describe("Archon numeric-predecessor-vectors.json", () => {
  const v = numericVectors as unknown as {
    agent: Op;
    update: Op;
    successor: Op;
    did: string;
    cids: Record<string, { rust: string; typescript: string }>;
  };

  it("derives canonical ids and the TypeScript numeric-key alias from content", async () => {
    for (const name of ["agent", "update", "successor"] as const) {
      expect(await generateCID(v[name])).toBe(v.cids[name].rust);
    }
    expect(await generateDID(v.agent as Operation)).toBe(v.did);
    expect(await legacyNumericCid(v.update)).toBe(v.cids.update.typescript);
    expect(await legacyNumericCid(v.agent)).toBeUndefined();
  });

  it("accepts a successor whose previd is the legacy numeric-key id", async () => {
    expect(v.successor.previd).toBe(v.cids.update.typescript);
    stubExport({ [v.did]: [v.agent, v.update, v.successor].map(hyperswarm) });
    const result = await resolve(v.did);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata.versionSequence).toBe("3");
    expect(result.didDocumentMetadata.versionId).toBe(v.cids.successor.rust);
  });
});

// ── controller-rules-vectors.json (State transitions) ───────────────────────

describe("Archon controller-rules-vectors.json", () => {
  type V = { did: string; operation: Op };
  const base = controllerRules.base as unknown as V[];
  const genesisOf = (did: string) => base.find((e) => e.did === did);

  it.each(
    controllerRules.cases as unknown as {
      name: string;
      accepted: boolean;
      setup: V[];
      event: V;
    }[],
  )("$name → accepted=$accepted", async ({ accepted, setup, event }) => {
    const exports: Record<string, unknown[]> = {};
    for (const genesis of base) exports[genesis.did] = [genesis];
    for (const extra of setup) exports[extra.did].push(extra);
    const isCreate = event.operation.type === "create";
    if (isCreate) exports[event.did] = [event];
    else exports[event.did] = [...exports[event.did], event];
    stubExport(exports);
    const result = await resolve(event.did);
    if (accepted) {
      expect(result.didResolutionMetadata.error).toBeUndefined();
      expect(result.didDocumentMetadata.versionId).toBe(
        await opCid(event.operation),
      );
    } else {
      expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
      if (!isCreate) {
        // The reference's accepted history (without the rejected operation).
        exports[event.did] = exports[event.did].slice(0, -1);
        stubExport(exports);
        expect(genesisOf(event.did)).toBeDefined();
        const prefix = await resolve(event.did);
        expect(prefix.didResolutionMetadata.error).toBeUndefined();
      }
    }
  });
});

// ── history-recovery-vectors.json (asset authority by chain position) ───────

describe("Archon history-recovery-vectors.json", () => {
  type E = {
    did: string;
    operation: Op;
    time: string;
    ordinal: number[];
    registration: unknown;
  };
  type Vector = Record<string, E | E[] | string> & {
    registry: string;
    controller: string;
    asset: string;
    child: string;
  };
  const scenarios = [
    // [scenario, accepted]: the reference's expected outcome per scenario.
    ["new-key", true],
    ["early", true],
    ["retired", false],
    ["migration", false],
    ["deletion", false],
    ["create", false],
    ["delegation", false],
  ] as const;

  it.each(
    (historyRecovery as unknown as Vector[]).flatMap((vector) =>
      scenarios.map(([scenario, accepted]) => ({ vector, scenario, accepted })),
    ),
  )(
    "$vector.registry $scenario → accepted=$accepted",
    async ({ vector, scenario, accepted }) => {
      const [controllerCreate, assetCreate] = vector.base as E[];
      const rotation = (
        scenario === "migration" ? vector.migrationRotation : vector.rotation
      ) as E;
      const exports: Record<string, unknown[]> = {
        [vector.controller]: [
          controllerCreate,
          ...(scenario === "migration" ? [vector.migration as E] : []),
          rotation,
        ],
        [vector.asset]: [assetCreate],
      };
      let target = vector.asset;
      if (scenario === "create") {
        const old = vector.old as E;
        exports[vector.asset] = [
          {
            ...assetCreate,
            time: old.time,
            ordinal: old.ordinal,
            registration: old.registration,
          },
        ];
      } else if (scenario === "delegation") {
        const [otherCreate, childCreate, transfer] = vector.delegation as E[];
        exports[otherCreate.did] = [otherCreate];
        exports[vector.child] = [childCreate, transfer, vector.delegated as E];
        target = vector.child;
      } else {
        const tail =
          scenario === "deletion"
            ? [vector.deletion]
            : scenario === "retired"
              ? [vector.old, vector.oldNext]
              : scenario === "early"
                ? [vector.early]
                : [vector.fresh, vector.freshNext];
        exports[vector.asset] = [assetCreate, ...(tail as E[])];
      }
      // Every operation here claims proof.created = 2026-01-01T00:00:00Z,
      // before the rotation: only chain-position authority tells them apart.
      stubExport(exports);
      const result = await resolve(target);
      if (accepted) {
        expect(result.didResolutionMetadata.error).toBeUndefined();
        const last = exports[target].at(-1) as E;
        expect(result.didDocumentMetadata.versionId).toBe(
          await opCid(last.operation),
        );
      } else {
        expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
      }
    },
  );
});

// ── registration-transition-v1-vectors.json (archon#1466, spec Change Status) ─

describe("Archon registration-transition-v1-vectors.json", () => {
  const v = registrationVectors as unknown as {
    agent: Op;
    did: string;
    unsupportedGenesis: Op;
    invalidGenesis: Op[];
    cases: {
      name: string;
      agent?: Op;
      did?: string;
      prior?: Op;
      operation: Op;
      accepted: boolean;
    }[];
  };

  it.each(v.cases)(
    "$name → accepted=$accepted",
    async ({ agent = v.agent, did = v.did, prior, operation, accepted }) => {
      const history = [agent, ...(prior ? [prior] : [])];
      stubExport({ [did]: [...history, operation].map(hyperswarm) });
      const result = await resolve(did);
      if (accepted) {
        expect(result.didResolutionMetadata.error).toBeUndefined();
        expect(result.didDocumentMetadata.versionSequence).toBe(
          String(history.length + 1),
        );
      } else {
        expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
        stubExport({ [did]: history.map(hyperswarm) });
        expect(
          (await resolve(did)).didResolutionMetadata.error,
        ).toBeUndefined();
      }
    },
  );

  it("refuses a version-2 genesis and malformed genesis expiry", async () => {
    for (const genesis of [v.unsupportedGenesis, ...v.invalidGenesis]) {
      const did = `did:cid:${await opCid(genesis)}`;
      stubExport({ [did]: [hyperswarm(genesis)] });
      const result = await resolve(did);
      expect(result.didResolutionMetadata.error).toBe("invalidDidDocument");
    }
  });
});

// ── The specification's signed examples (creation, update, revocation) ──────

describe("did:cid specification examples (e8aace4)", () => {
  const { agent, asset, rotation, deletion, deletedResult } =
    specExamples as unknown as Record<string, Op>;
  const AGENT =
    "did:cid:bagaaiera7apdjgpe7jleguoioddew7oqqxn2iqlsowktnbnqksf7bpzuntka";
  const ASSET =
    "did:cid:bagaaierancfl35mj7m4gejwewe2no335bkl527gjlz22dwba5sgybdvevt4q";

  it("derives the DIDs the specification states", async () => {
    expect(await generateDID(agent as Operation)).toBe(AGENT);
    expect(await generateDID(asset as Operation)).toBe(ASSET);
  });

  it("verifies the rotation (signed by #key-1, installs #key-2)", async () => {
    stubExport({ [AGENT]: [agent, rotation].map(hyperswarm) });
    const result = await resolve(AGENT);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument).toEqual((rotation.doc as Op).didDocument);
    expect(result.didDocumentMetadata).toEqual({
      created: "2026-09-22T00:00:00Z",
      updated: "2026-09-22T00:00:02Z",
      versionId: await opCid(rotation),
      versionSequence: "2",
    });
  });

  it("reproduces the post-revocation resolution result", async () => {
    // The deletion is signed by the owner's rotated #key-2, at proof time
    // after the rotation (Hyperswarm: no chain position).
    stubExport({
      [AGENT]: [agent, rotation].map(hyperswarm),
      [ASSET]: [asset, deletion].map(hyperswarm),
    });
    const result = await resolve(ASSET);
    expect(result).toEqual(deletedResult);
  });
});
