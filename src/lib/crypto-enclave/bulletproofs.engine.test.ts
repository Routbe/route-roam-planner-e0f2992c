// @vitest-environment node
/**
 * Stap 7b end to end through the worker ops against a locally built rout-zk
 * module. The committed pin stays null; this file substitutes a test pin for
 * the bytes at ROUT_ZK_DEV_WASM and is skipped when that variable is unset
 * (it is set once CI builds the pinned module, or by hand:
 *   ROUT_ZK_DEV_WASM=/path/rout_zk.wasm bunx vitest run bulletproofs.engine).
 */
import "fake-indexeddb/auto";
import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";

const dev = vi.hoisted(() => {
  const path = process.env.ROUT_ZK_DEV_WASM;
  if (!path) return null;
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { createHash } = require("node:crypto") as typeof import("node:crypto");
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const bytes = (require("node:fs") as typeof import("node:fs")).readFileSync(path);
  return { base64: bytes.toString("base64"), sha384: createHash("sha384").update(bytes).digest("hex") };
});

vi.mock("./zk-wasm-pin", () => ({ ROUT_ZK_WASM_SHA384: dev?.sha384 ?? null }));
vi.mock("./zk-wasm-bytes", () => ({ ROUT_ZK_WASM_BASE64: dev?.base64 ?? null }));

import { COMMITMENT_BYTES, RANGE_PROOF_BYTES } from "./bulletproofs";
import { runEnclaveOp } from "./enclave-core";
import { lastZkMemoryForTest, ZK_ENGINE_PAGES } from "./zk-engine";

const enc = new TextEncoder();
const allZero = () => lastZkMemoryForTest()!.every((b) => b === 0);

async function ok<T>(p: Promise<{ ok: boolean; result?: unknown; code?: string }>): Promise<T> {
  const r = await p;
  if (!r.ok) throw new Error(String(r.code));
  return r.result as T;
}

describe.skipIf(!dev)("rout-zk 7b through the crypto worker (local build)", () => {
  it("imports one fixed memory of the expected size and contains no memory.grow", async () => {
    const bytes = readFileSync(process.env.ROUT_ZK_DEV_WASM!);
    const mod = await WebAssembly.compile(bytes);
    expect(WebAssembly.Module.imports(mod).map((i) => `${i.module}.${i.name}:${i.kind}`).sort()).toEqual(["env.memory:memory", "env.rout_random:function"]);
    const wabt = await (await import("wabt")).default();
    const text = wabt.readWasm(bytes, { readDebugNames: false }).toText({});
    expect(text).not.toMatch(/memory\.grow/);
    expect(text).toMatch(new RegExp(`\\(import "env" "memory" \\(memory \\(;0;\\) ${ZK_ENGINE_PAGES} ${ZK_ENGINE_PAGES}\\)\\)`));
  });

  it("proves and verifies v in [0, 2^64-1] and wipes engine memory after each call", async () => {
    // The worker zero-fills every request buffer after the op, so each call gets its own copy.
    const ctx = () => enc.encode("slot-42/booking-1");
    for (const value of [0n, 1n, 9n, (1n << 64n) - 1n]) {
      const { blinding } = await ok<{ commitment: Uint8Array; blinding: Uint8Array }>(runEnclaveOp("pedersen.commit", { value }));
      expect(allZero()).toBe(true);
      const keep = blinding.slice();
      const { commitment, proof } = await ok<{ commitment: Uint8Array; proof: Uint8Array }>(runEnclaveOp("bulletproofs.prove_range", { value, blinding, context: ctx() }));
      expect(allZero()).toBe(true);
      expect(blinding.every((b) => b === 0)).toBe(true); // the worker wiped its copy
      expect(commitment).toHaveLength(COMMITMENT_BYTES);
      expect(proof).toHaveLength(RANGE_PROOF_BYTES);
      const again = await ok<{ commitment: Uint8Array }>(runEnclaveOp("pedersen.commit", { value, blinding: keep.slice() }));
      expect(Buffer.from(again.commitment).equals(Buffer.from(commitment))).toBe(true);
      expect(await ok(runEnclaveOp("bulletproofs.verify_range", { commitment, proof, context: ctx() }))).toEqual({ valid: true });
      expect(allZero()).toBe(true);
    }
  }, 120_000);

  it("rejects a wrong context, a tampered proof and another commitment", async () => {
    const ctx = () => enc.encode("slot-1");
    const blinding = crypto.getRandomValues(new Uint8Array(32));
    blinding[0] &= 0x3f; // < q
    const { commitment, proof } = await ok<{ commitment: Uint8Array; proof: Uint8Array }>(runEnclaveOp("bulletproofs.prove_range", { value: 3n, blinding: blinding.slice(), context: ctx() }));
    expect(await ok(runEnclaveOp("bulletproofs.verify_range", { commitment, proof, context: enc.encode("slot-2") }))).toEqual({ valid: false });
    const bad = proof.slice();
    bad[RANGE_PROOF_BYTES - 1] ^= 1;
    expect(await ok(runEnclaveOp("bulletproofs.verify_range", { commitment, proof: bad, context: ctx() }))).toEqual({ valid: false });
    const other = await ok<{ commitment: Uint8Array }>(runEnclaveOp("pedersen.commit", { value: 4n, blinding: blinding.slice() }));
    expect(await ok(runEnclaveOp("bulletproofs.verify_range", { commitment: other.commitment, proof, context: ctx() }))).toEqual({ valid: false });
  }, 120_000);

  it("refuses a non-canonical blinding (>= q) inside the engine", async () => {
    const r = await runEnclaveOp("bulletproofs.prove_range", { value: 1n, blinding: new Uint8Array(32).fill(0xff), context: new Uint8Array(0) });
    expect(r).toEqual({ ok: false, code: "invalid_input" });
    expect(allZero()).toBe(true);
  });
});
