/**
 * Pedersen commitments and 64-bit Bulletproofs range proofs (Stap 7b).
 * Thin, typed adapters over wasm/rout-zk (pedersen.rs, bulletproofs.rs); all
 * mathematics happens in the pinned engine. Reachable only through the crypto
 * worker ops "pedersen.commit", "bulletproofs.prove_range" and
 * "bulletproofs.verify_range".
 *
 *   commitment = v·g + r·h  (48 octets, compressed G1)
 *   proof      = 928 octets, proves v ∈ [0, 2^64 - 1] for the commitment,
 *                bound to a caller context (e.g. the booking or slot id)
 *
 * Values are bigint in [0, 2^64 - 1]; blinding factors are 32 octets
 * big-endian (< q). The blinding is the secret opening: callers own and wipe it.
 */
import { wipe } from "@/lib/crypto/wipe";
import { withZkFrame, zkCheck, ZkEngineError } from "./zk-engine";

export const COMMITMENT_BYTES = 48;
export const BLINDING_BYTES = 32;
export const RANGE_PROOF_BYTES = 928;
export const RANGE_BITS = 64;
export const MAX_RANGE_CONTEXT_BYTES = 1024;
const MAX_VALUE = (1n << 64n) - 1n;

/** 0 <= v <= 2^64 - 1 as a 32-octet big-endian scalar; anything else is refused here and again in the engine. */
export function encodeRangeValue(value: bigint): Uint8Array {
  if (typeof value !== "bigint" || value < 0n || value > MAX_VALUE) throw new ZkEngineError("zk_invalid_input");
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 24; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function need(bytes: unknown, len: number): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== len) throw new ZkEngineError("zk_invalid_input");
  return bytes;
}

function context(bytes: unknown): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > MAX_RANGE_CONTEXT_BYTES) throw new ZkEngineError("zk_invalid_input");
  return bytes;
}

/** C = v·g + r·h. Without a blinding, a fresh one is drawn inside the engine and returned. */
export async function pedersenCommit(value: bigint, blinding?: Uint8Array): Promise<{ commitment: Uint8Array; blinding: Uint8Array }> {
  const v = encodeRangeValue(value);
  try {
    if (blinding !== undefined) need(blinding, BLINDING_BYTES);
    return await withZkFrame((f) => {
      const pv = f.put(v);
      const out = f.reserve(COMMITMENT_BYTES);
      if (blinding !== undefined) {
        zkCheck(f.ex.rout_zk_pedersen_commit(pv, f.put(blinding), out));
        return { commitment: f.take(out, COMMITMENT_BYTES), blinding: blinding.slice() };
      }
      const pb = f.reserve(BLINDING_BYTES);
      zkCheck(f.ex.rout_zk_pedersen_commit_fresh(pv, pb, out));
      return { commitment: f.take(out, COMMITMENT_BYTES), blinding: f.take(pb, BLINDING_BYTES) };
    });
  } finally {
    wipe(v);
  }
}

/** Commitment to `value` under `blinding` plus a proof that value ∈ [0, 2^64 - 1], bound to `ctx`. */
export async function proveRange(value: bigint, blinding: Uint8Array, ctx: Uint8Array): Promise<{ commitment: Uint8Array; proof: Uint8Array }> {
  const v = encodeRangeValue(value);
  try {
    need(blinding, BLINDING_BYTES);
    context(ctx);
    return await withZkFrame((f) => {
      const pv = f.put(v);
      const pb = f.put(blinding);
      const pc = f.put(ctx);
      const oc = f.reserve(COMMITMENT_BYTES);
      const op = f.reserve(RANGE_PROOF_BYTES);
      const len = zkCheck(f.ex.rout_zk_range_prove(pv, pb, pc, ctx.byteLength, oc, op));
      if (len !== RANGE_PROOF_BYTES) throw new ZkEngineError("zk_engine_integrity");
      return { commitment: f.take(oc, COMMITMENT_BYTES), proof: f.take(op, RANGE_PROOF_BYTES) };
    });
  } finally {
    wipe(v);
  }
}

/** True only if `proof` shows that `commitment` hides a value in [0, 2^64 - 1] for `ctx`. */
export async function verifyRange(commitment: Uint8Array, proof: Uint8Array, ctx: Uint8Array): Promise<boolean> {
  need(commitment, COMMITMENT_BYTES);
  need(proof, RANGE_PROOF_BYTES);
  context(ctx);
  try {
    return await withZkFrame((f) => {
      const rc = f.ex.rout_zk_range_verify(f.put(commitment), f.put(ctx), ctx.byteLength, f.put(proof), RANGE_PROOF_BYTES);
      // -1 (a point or scalar that fails decoding) and -2 (equation fails) are both "not valid".
      if (rc === -1 || rc === -2) return false;
      zkCheck(rc);
      return true;
    });
  } catch (e) {
    if (e instanceof ZkEngineError && e.code === "zk_rejected") return false;
    throw e;
  }
}
