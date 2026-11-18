/**
 * Test helpers: an independent JCS / CID / signing implementation (not the
 * driver's), so synthetic chains check the driver rather than echo it, and a
 * mock of the Gatekeeper export endpoint.
 */
import { expect, vi } from "vitest";
import { CID } from "multiformats/cid";
import * as jsonCodec from "multiformats/codecs/json";
import { sha256 as cidHasher } from "multiformats/hashes/sha2";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { getResolver } from "../resolver.js";

export type Op = Record<string, unknown>;
export type Event = Record<string, unknown>;

export const GATEKEEPER = "https://gatekeeper.test/api/v1";
export const SUITE = "archon-ecdsa-secp256k1-jcs-2026";

export const resolve = (did: string, options: Record<string, unknown> = {}) =>
  getResolver({ gatekeeperUrl: GATEKEEPER }).cid(
    did,
    null as never,
    null as never,
    options,
  );

/** Mock the export endpoint: one accepted history per DID, DIF batch shape. */
export function stubExport(chains: Record<string, unknown[]>) {
  const fetchMock = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(String(input)).toBe(`${GATEKEEPER}/dids/export`);
      const { dids } = JSON.parse(String(init?.body)) as { dids: string[] };
      return Response.json(dids.map((d) => chains[d] ?? []));
    },
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

export const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

export function jcs(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(jcs).join(",") + "]";
  const record = value as Record<string, unknown>;
  return (
    "{" +
    Object.keys(record)
      .sort()
      .map((k) => JSON.stringify(k) + ":" + jcs(record[k]))
      .join(",") +
    "}"
  );
}

export const b64u = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString("base64url");

export async function opCid(op: Op): Promise<string> {
  const digest = await cidHasher.digest(new TextEncoder().encode(jcs(op)));
  return CID.createV1(jsonCodec.code, digest).toString();
}

export function jwkFor(priv: Uint8Array): Record<string, string> {
  const pub = secp256k1.getPublicKey(priv, false);
  return {
    kty: "EC",
    crv: "secp256k1",
    x: b64u(pub.slice(1, 33)),
    y: b64u(pub.slice(33, 65)),
  };
}

const hash = (text: string) => sha256(new TextEncoder().encode(text));

/** Legacy proof: SHA-256(JCS(op)) signed, configuration unsigned. */
export function signLegacy(
  op: Op,
  priv: Uint8Array,
  verificationMethod: string,
  created: string,
  proofPurpose = "authentication",
): Op {
  return {
    ...op,
    proof: {
      type: "EcdsaSecp256k1Signature2019",
      created,
      verificationMethod,
      proofPurpose,
      proofValue: b64u(secp256k1.sign(hash(jcs(op)), priv, { prehash: false })),
    },
  };
}

/** The Archon suite: SHA-256(SHA-256(JCS(config)) || SHA-256(JCS(op))). */
export function signSuite(
  op: Op,
  priv: Uint8Array,
  verificationMethod: string,
  created: string,
  extra: Record<string, unknown> = {},
): Op {
  const config = {
    type: "DataIntegrityProof",
    cryptosuite: SUITE,
    created,
    verificationMethod,
    proofPurpose: "capabilityInvocation",
    ...extra,
  };
  const both = new Uint8Array(64);
  both.set(hash(jcs(config)), 0);
  both.set(hash(jcs(op)), 32);
  const digest = sha256(both);
  return {
    ...op,
    proof: {
      ...config,
      proofValue: b64u(secp256k1.sign(digest, priv, { prehash: false })),
    },
  };
}

/** A Hyperswarm receipt; its time is the proof time, as Archon exports it. */
export const hyperswarm = (operation: Op): Event => ({
  registry: "hyperswarm",
  time: (operation.proof as Op).created,
  operation,
});

/** A complete chain receipt `[height, index, opidx]` on `registry`. */
export const chainReceipt = (
  operation: Op,
  registry: string,
  height: number,
  time: string,
): Event => ({
  registry,
  time,
  ordinal: [height, 0, 0],
  registration: {
    height,
    index: 0,
    opidx: 0,
    txid: `tx${height}`,
    batch: `batch${height}`,
  },
  operation,
});

export const key = (fill: number) => new Uint8Array(32).fill(fill);

export function agentDocument(
  did: string,
  methods: { id: string; priv: Uint8Array }[],
): Op {
  return {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: did,
    verificationMethod: methods.map(({ id, priv }) => ({
      id,
      controller: did,
      type: "EcdsaSecp256k1VerificationKey2019",
      publicKeyJwk: jwkFor(priv),
    })),
    authentication: [methods[0].id],
    assertionMethod: [methods[0].id],
    capabilityInvocation: [methods[0].id],
  };
}

/** A new-suite agent genesis on `registry`. */
export async function agentGenesis(
  priv: Uint8Array,
  created = "2026-10-01T00:00:00.000Z",
  registry = "hyperswarm",
): Promise<{ did: string; op: Op }> {
  const op = signSuite(
    {
      type: "create",
      created,
      registration: { version: 1, type: "agent", registry },
      publicJwk: jwkFor(priv),
    },
    priv,
    "#key-1",
    created,
  );
  return { did: `did:cid:${await opCid(op)}`, op };
}
