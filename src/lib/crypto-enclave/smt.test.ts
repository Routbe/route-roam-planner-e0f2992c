// @vitest-environment node
/**
 * Stap 7c worker ops while rout-zk has no reproducible pin: refusal without a
 * device key, refusal of the unpinned engine (no fallback), input validation
 * before the engine, the root-signing key derivation and the worker's
 * rollback/fork high-water mark.
 */
import "fake-indexeddb/auto";
import { readFileSync } from "node:fs";
import { expand } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";
import { runEnclaveOp } from "./enclave-core";
import { PSEUDONYM_INFO } from "./pseudonyms";
import { RootWatermarks, SMT_EMPTY_ROOT_HEX, SMT_SIBLINGS_BYTES, smtSignerKeyMaterial, type SignedRoot } from "./smt";

const USER = "00000000-0000-4000-8000-0000000007c1";
const TREE = "host:00000000-0000-4000-8000-0000000000aa/slot:1";

const root = (epoch: number, fill: number, treeId = TREE): SignedRoot => ({
  treeId,
  epoch,
  root: new Uint8Array(32).fill(fill),
  publicKey: new Uint8Array(96).fill(1),
  signature: new Uint8Array(80).fill(2),
});

async function withDeviceKey(userId: string) {
  const g = await runEnclaveOp("masterKey.generate", {});
  if (!g.ok) throw new Error(g.code);
  const c = await runEnclaveOp("masterKey.commitPending", { handle: (g.result as { handle: string }).handle, userId });
  if (!c.ok) throw new Error(c.code);
}

describe("nullifier SMT ops without a pinned engine", () => {
  it("refuses before a device key exists", async () => {
    const other = "00000000-0000-4000-8000-0000000007c9";
    expect(await runEnclaveOp("smt.genesis", { userId: other, treeId: TREE })).toEqual({ ok: false, code: "no_device_key" });
  });

  it("answers enclave_unavailable once a device key exists (no fallback)", async () => {
    await withDeviceKey(USER);
    expect(await runEnclaveOp("smt.genesis", { userId: USER, treeId: TREE })).toEqual({ ok: false, code: "enclave_unavailable" });
    const args = { userId: USER, signedRoot: root(0, 3), nullifier: new Uint8Array(32), siblings: new Uint8Array(SMT_SIBLINGS_BYTES) };
    expect(await runEnclaveOp("smt.insert_nullifier", args)).toEqual({ ok: false, code: "enclave_unavailable" });
    expect(await runEnclaveOp("smt.verify_non_membership", { ...args, signedRoot: root(0, 3) })).toEqual({ ok: false, code: "enclave_unavailable" });
    expect(await runEnclaveOp("smt.verify_signed_root", { userId: USER, signedRoot: root(0, 3) })).toEqual({ ok: false, code: "enclave_unavailable" });
  });

  it("refuses malformed roots, nullifiers and sibling lists before the engine", async () => {
    const ok = { userId: USER, nullifier: new Uint8Array(32), siblings: new Uint8Array(SMT_SIBLINGS_BYTES) };
    const bad: Partial<SignedRoot>[] = [
      { root: new Uint8Array(31) },
      { publicKey: new Uint8Array(48) },
      { signature: new Uint8Array(79) },
      { epoch: -1 },
      { epoch: 1.5 },
      { epoch: Number.MAX_SAFE_INTEGER + 1 },
      { treeId: "" },
      { treeId: "x".repeat(257) },
    ];
    for (const b of bad) {
      expect(await runEnclaveOp("smt.verify_signed_root", { userId: USER, signedRoot: { ...root(0, 1), ...b } })).toEqual({ ok: false, code: "invalid_input" });
    }
    expect(await runEnclaveOp("smt.insert_nullifier", { ...ok, signedRoot: root(0, 1), nullifier: new Uint8Array(31) })).toEqual({ ok: false, code: "invalid_input" });
    expect(await runEnclaveOp("smt.insert_nullifier", { ...ok, signedRoot: root(0, 1), siblings: new Uint8Array(SMT_SIBLINGS_BYTES - 32) })).toEqual({ ok: false, code: "invalid_input" });
    expect(await runEnclaveOp("smt.genesis", { userId: USER, treeId: "y".repeat(257) })).toEqual({ ok: false, code: "invalid_input" });
  });
});

describe("root-signing key material", () => {
  it("is 32 octets, deterministic per seed and separated from the pseudonym key", () => {
    const seed = new Uint8Array(32).fill(5);
    const a = smtSignerKeyMaterial(seed);
    expect(a).toHaveLength(32);
    expect(Buffer.from(smtSignerKeyMaterial(seed)).equals(Buffer.from(a))).toBe(true);
    expect(Buffer.from(smtSignerKeyMaterial(new Uint8Array(32).fill(6))).equals(Buffer.from(a))).toBe(false);
    const pseudonymKey = expand(sha256, seed, new TextEncoder().encode(PSEUDONYM_INFO), 32);
    expect(Buffer.from(pseudonymKey).equals(Buffer.from(a))).toBe(false);
    expect(() => smtSignerKeyMaterial(new Uint8Array(31))).toThrow(/zk_invalid_input/);
  });
});

describe("high-water mark against rollback and forks", () => {
  it("refuses an older epoch and a different root at the seen epoch", () => {
    const m = new RootWatermarks();
    expect(m.admissible("a", root(0, 1))).toBe(true);
    m.observe("a", root(3, 9));
    expect(m.admissible("a", root(2, 1))).toBe(false); // rollback to before spent nullifiers
    expect(m.admissible("a", root(0, 1))).toBe(false); // back to genesis
    expect(m.admissible("a", root(3, 8))).toBe(false); // fork at the same epoch
    expect(m.admissible("a", root(3, 9))).toBe(true);
    expect(m.admissible("a", root(4, 7))).toBe(true); // newer, e.g. from another session
    m.observe("a", root(2, 1)); // never lowers the mark
    expect(m.admissible("a", root(2, 1))).toBe(false);
  });

  it("keeps marks per member and per tree", () => {
    const m = new RootWatermarks();
    m.observe("a", root(5, 1));
    expect(m.admissible("b", root(0, 1))).toBe(true);
    expect(m.admissible("a", root(0, 1, "host:x/slot:2"))).toBe(true);
    expect(m.has("a", TREE)).toBe(true);
    expect(m.has("b", TREE)).toBe(false);
  });
});

it("the empty root constant equals the Rust fixture", () => {
  const hex = readFileSync(new URL("../../../wasm/rout-zk/tests/fixtures/smt/empty_root.hex", import.meta.url), "utf8").trim();
  expect(SMT_EMPTY_ROOT_HEX).toBe(hex);
});
