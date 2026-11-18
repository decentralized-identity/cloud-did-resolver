import type { ResolverRegistry } from "did-resolver";
import { getResolver, optionsFromEnv } from "@thisdid/cid-did-resolver";
import { createDriverWorker } from "../runtime";

/**
 * did:cid through the vendored `@thisdid/cid-did-resolver` — a
 * resolution-only Archon Gatekeeper: the signed operation chain is fetched
 * from the configured Gatekeeper and fully verified in this Worker (genesis
 * CID, per-operation signatures with key rotation, previd hash links), per
 * the did:cid Method Specification and `@didcid/gatekeeper` 0.8.0.
 */

/**
 * The CID_* settings, from wrangler.jsonc `vars` or secrets — the same names
 * the package's CLI reads from its environment. Unset or empty values take
 * the package defaults; a malformed value makes the registry throw, so the
 * Worker answers internalError instead of resolving under an unintended
 * policy.
 */
type CidEnv = {
  /** Archon Gatekeeper API base. Defaults to archon.technology/api/v1. */
  CID_GATEKEEPER_URL?: string;
  /** Bound on events in one history. */
  CID_MAX_EVENTS?: string;
  /** Bound on one Gatekeeper request, in ms. */
  CID_TIMEOUT_MS?: string;
  /** Bound on one whole resolution, in ms (default 7000, under the gateway's 8 s step). */
  CID_DEADLINE_MS?: string;
  /** Bound on distinct DID histories fetched for one resolution (default 32). */
  CID_MAX_DIDS?: string;
};

export default createDriverWorker<CidEnv>({
  method: "cid",
  packageName: "@thisdid/cid-did-resolver",
  packageVersion: "1.0.0",
  registry: (env) =>
    getResolver(optionsFromEnv(env)) as unknown as ResolverRegistry,
});
