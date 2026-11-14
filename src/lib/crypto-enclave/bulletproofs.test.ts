// @vitest-environment node
/**
 * Stap 7b worker ops while rout-zk has no reproducible pin: the loader must
 * refuse (no fallback), inputs are validated before the engine and secret
 * inputs are wiped either way.
 */
import "fake-indexeddb/auto";
import { describe, expect, it } from "vitest";
import { encodeRangeValue, RANGE_PROOF_BYTES } from "./bulletproofs";
import { runEnclaveOp } from "./enclave-core";
import { zkEngineModule } from "./zk-engine";
import { ROUT_ZK_WASM_BASE64 } from "./zk-wasm-bytes";
import { ROUT_ZK_WASM_SHA384 } from "./zk-wasm-pin";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("rout-zk loader without a pin", () => {
  it("has no pin and no bytes yet, and refuses before compiling", async () => {
    expect(ROUT_ZK_WASM_SHA384).toBeNull();
    expect(ROUT_ZK_WASM_BASE64).toBeNull();
    await expect(zkEngineModule()).rejects.toMatchObject({ code: "zk_engine_unpinned" });
  });

  it("every 7b op answers enclave_unavailable and wipes the blinding", async () => {
    const blinding = new Uint8Array(32).fill(7);
    const r1 = await runEnclaveOp("bulletproofs.prove_range", { value: 5n, blinding, context: new Uint8Array(4) });
    expect(r1).toEqual({ ok: false, code: "enclave_unavailable" });
    expect(blinding.every((b) => b === 0)).toBe(true);
    const b2 = new Uint8Array(32).fill(3);
    expect(await runEnclaveOp("pedersen.commit", { value: 1n, blinding: b2 })).toEqual({ ok: false, code: "enclave_unavailable" });
    expect(b2.every((b) => b === 0)).toBe(true);
    expect(await runEnclaveOp("pedersen.commit", { value: 1n })).toEqual({ ok: false, code: "enclave_unavailable" });
    const v = await runEnclaveOp("bulletproofs.verify_range", { commitment: new Uint8Array(48), proof: new Uint8Array(RANGE_PROOF_BYTES), context: new Uint8Array(0) });
    expect(v).toEqual({ ok: false, code: "enclave_unavailable" });
  });
});

describe("input rules (checked before the engine)", () => {
  it("encodes 0..2^64-1 as a 32-octet big-endian scalar", () => {
    expect(hex(encodeRangeValue(0n))).toBe("00".repeat(32));
    expect(hex(encodeRangeValue(258n))).toBe("00".repeat(30) + "0102");
    expect(hex(encodeRangeValue((1n << 64n) - 1n))).toBe("00".repeat(24) + "ff".repeat(8));
  });

  it("refuses v < 0 and v >= 2^64", () => {
    for (const v of [-1n, -(1n << 64n), 1n << 64n, (1n << 64n) + 1n, 1n << 255n]) {
      expect(() => encodeRangeValue(v)).toThrow(/zk_invalid_input/);
    }
    expect(() => encodeRangeValue(5 as unknown as bigint)).toThrow(/zk_invalid_input/);
  });

  it("out-of-range values and wrong buffer sizes are invalid_input, and the blinding is still wiped", async () => {
    const blinding = new Uint8Array(32).fill(9);
    expect(await runEnclaveOp("bulletproofs.prove_range", { value: 1n << 64n, blinding, context: new Uint8Array(1) })).toEqual({ ok: false, code: "invalid_input" });
    expect(blinding.every((b) => b === 0)).toBe(true);
    expect(await runEnclaveOp("bulletproofs.prove_range", { value: -1n, blinding: new Uint8Array(32), context: new Uint8Array(1) })).toEqual({ ok: false, code: "invalid_input" });
    expect(await runEnclaveOp("pedersen.commit", { value: 1n, blinding: new Uint8Array(31) })).toEqual({ ok: false, code: "invalid_input" });
    expect(await runEnclaveOp("bulletproofs.verify_range", { commitment: new Uint8Array(47), proof: new Uint8Array(RANGE_PROOF_BYTES), context: new Uint8Array(0) })).toEqual({ ok: false, code: "invalid_input" });
    expect(await runEnclaveOp("bulletproofs.verify_range", { commitment: new Uint8Array(48), proof: new Uint8Array(RANGE_PROOF_BYTES - 1), context: new Uint8Array(0) })).toEqual({ ok: false, code: "invalid_input" });
  });
});
