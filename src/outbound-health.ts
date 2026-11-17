/**
 * Outbound health, checked from inside the thisdid.com zone.
 *
 * Zone settings apply to the Workers' outgoing requests. A setting can break
 * TLS to every origin outside Cloudflare while the same code keeps working
 * outside the zone. On 2026-10/11 the zone's post-quantum encryption to
 * origin made every request to Archon, Godiddy, Alchemy and plc.directory fail
 * with HTTP 525: all did:cid DIDs returned 404, yet the probe kept passing,
 * because it runs on a cron with no zone context.
 *
 * GET /health/outbound resolves fixed canaries in the zone's own request
 * context. The probe calls it through the public origin every round and
 * records the result under the `zone:<method>` health keys.
 */
import {
  OUTBOUND_CANARIES,
  type OutboundCheck,
  type OutboundReport,
} from "./outbound-canaries";
import { resolveDid } from "./resolve";
import type { Env } from "./types";

export { OUTBOUND_CANARIES };
export type { OutboundCheck, OutboundReport };

/**
 * A report is reused for a minute per isolate, and concurrent requests share
 * one check, so the public route cannot be used to multiply traffic to the
 * upstreams.
 */
export const OUTBOUND_CACHE_MS = 60_000;
let cached: OutboundReport | null = null;
let inflight: Promise<OutboundReport> | null = null;

async function checkOne(did: string, env: Env): Promise<OutboundCheck> {
  const started = Date.now();
  const method = did.split(":")[1] ?? "";
  try {
    const r = await resolveDid(did, env);
    const m = r.didResolutionMetadata;
    return {
      did,
      method,
      ok: Boolean(r.didDocument) && !m.error,
      ms: Date.now() - started,
      error: m.error ?? null,
      attempts: (m.attempts ?? []).map(({ step, error, status }) =>
        status == null ? { step, error } : { step, error, status },
      ),
    };
  } catch {
    return {
      did,
      method,
      ok: false,
      ms: Date.now() - started,
      error: "internalError",
      attempts: [],
    };
  }
}

export async function checkOutbound(
  env: Env,
  now = Date.now(),
): Promise<OutboundReport> {
  if (cached && now - cached.checkedTs < OUTBOUND_CACHE_MS) return cached;
  if (inflight) return inflight;
  inflight = (async () => {
    const checks = await Promise.all(
      OUTBOUND_CANARIES.map((did) => checkOne(did, env)),
    );
    cached = { ok: checks.every((c) => c.ok), checkedTs: now, checks };
    return cached;
  })();
  try {
    return await inflight;
  } finally {
    inflight = null;
  }
}

/** Test hook: forget the cached report. */
export function resetOutboundCache(): void {
  cached = null;
  inflight = null;
}
