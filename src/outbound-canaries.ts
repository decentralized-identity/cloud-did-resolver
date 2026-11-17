/**
 * Canaries and report shape for GET /health/outbound (src/outbound-health.ts).
 * Kept separate so the probe Worker can import them without bundling the
 * resolver.
 */

/** Each canary's routes reach origins outside Cloudflare. */
export const OUTBOUND_CANARIES = [
  // local driver → Archon's Gatekeeper; verifier and fallbacks → Archon, Godiddy
  "did:cid:bagaaieraoqzjgi6537vyu3h3rtetki5g4bk6stzyqplcmwpqgqxp7fewowcq",
  // local driver → plc.directory
  "did:plc:z72i7hdynmk6r22z27h6tvur",
] as const;

export interface OutboundCheck {
  did: string;
  method: string;
  ok: boolean;
  ms: number;
  error: string | null;
  /** Per-step failures, as the resolver reports them (no documents). */
  attempts: Array<{ step: string; error: string; status?: number }>;
}

export interface OutboundReport {
  ok: boolean;
  checkedTs: number;
  checks: OutboundCheck[];
}
