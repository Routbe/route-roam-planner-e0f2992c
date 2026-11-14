// @vitest-environment node
/**
 * Stap 7c end to end through the worker ops against a locally built rout-zk
 * module. The committed pin stays null; this file substitutes a test pin for
 * the bytes at ROUT_ZK_DEV_WASM and is skipped when that variable is unset
 * (ROUT_ZK_DEV_WASM=/path/rout_zk.wasm bunx vitest run smt.engine).
 */
import "fake-indexeddb/auto";
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

import { runEnclaveOp } from "./enclave-core";
import { SMT_DEPTH, SMT_EMPTY_ROOT_HEX, SMT_NODE_BYTES, SMT_PATH_BYTES, smtEmptyPath, type SignedRoot } from "./smt";
import { lastZkMemoryForTest } from "./zk-engine";

const ALICE = "00000000-0000-4000-8000-0000000007a1";
const MALLORY = "00000000-0000-4000-8000-0000000007a2";
const TREE = "host:00000000-0000-4000-8000-0000000000aa/slot:2026-11-20T10:00Z";
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const allZero = () => lastZkMemoryForTest()!.every((b) => b === 0);
const copy = (s: SignedRoot): SignedRoot => ({ ...s, root: s.root.slice(), publicKey: s.publicKey.slice(), signature: s.signature.slice() });

async function ok<T>(p: Promise<{ ok: boolean; result?: unknown; code?: string }>): Promise<T> {
  const r = await p;
  if (!r.ok) throw new Error(String(r.code));
  return r.result as T;
}

async function withDeviceKey(userId: string) {
  const { handle } = await ok<{ handle: string }>(runEnclaveOp("masterKey.generate", {}));
  await ok(runEnclaveOp("masterKey.commitPending", { handle, userId }));
}

/** The untrusted node store (later: the database), as plain bytes. */
class Store {
  nodes = new Map<string, Uint8Array>();
  constructor(readonly empty: Uint8Array) {}
  private prefix(n: Uint8Array, h: number) {
    const p = n.slice();
    for (let i = 0; i < h; i++) p[31 - (i >> 3)] &= ~(1 << (i & 7));
    return p;
  }
  private get(h: number, p: Uint8Array) {
    return this.nodes.get(`${h}:${hex(p)}`) ?? this.empty.subarray(h * SMT_NODE_BYTES, (h + 1) * SMT_NODE_BYTES);
  }
  siblings(n: Uint8Array) {
    const out = new Uint8Array(SMT_DEPTH * SMT_NODE_BYTES);
    for (let h = 0; h < SMT_DEPTH; h++) {
      const p = this.prefix(n, h);
      p[31 - (h >> 3)] ^= 1 << (h & 7);
      out.set(this.get(h, p), h * SMT_NODE_BYTES);
    }
    return out;
  }
  apply(n: Uint8Array, path: Uint8Array) {
    for (let h = 0; h <= SMT_DEPTH; h++) this.nodes.set(`${h}:${hex(this.prefix(n, h))}`, path.slice(h * SMT_NODE_BYTES, (h + 1) * SMT_NODE_BYTES));
  }
  root() {
    return this.get(SMT_DEPTH, new Uint8Array(32));
  }
}

const nf = (i: number) => {
  const n = new Uint8Array(32);
  for (let j = 0; j < 32; j++) n[j] = (i * 41 + j * 7 + 3) & 0xff;
  return n;
};

type Inserted = { inserted: true; signedRoot: SignedRoot; path: Uint8Array } | { inserted: false };

describe.skipIf(!dev)("rout-zk 7c through the crypto worker (local build)", () => {
  it("spends nullifiers once, proves NonExist for unspent ones and wipes engine memory", async () => {
    await withDeviceKey(ALICE);
    const empty = await smtEmptyPath();
    expect(empty).toHaveLength(SMT_PATH_BYTES);
    expect(hex(empty.subarray(SMT_DEPTH * SMT_NODE_BYTES))).toBe(SMT_EMPTY_ROOT_HEX);
    const store = new Store(empty);

    const { signedRoot: genesis } = await ok<{ signedRoot: SignedRoot }>(runEnclaveOp("smt.genesis", { userId: ALICE, treeId: TREE }));
    expect(allZero()).toBe(true);
    expect(genesis.epoch).toBe(0);
    expect(hex(genesis.root)).toBe(SMT_EMPTY_ROOT_HEX);
    expect(await ok(runEnclaveOp("smt.verify_signed_root", { userId: ALICE, signedRoot: copy(genesis) }))).toEqual({ valid: true });

    let cur = genesis;
    for (let i = 0; i < 3; i++) {
      const r = await ok<Inserted>(runEnclaveOp("smt.insert_nullifier", { userId: ALICE, signedRoot: copy(cur), nullifier: nf(i), siblings: store.siblings(nf(i)) }));
      expect(allZero()).toBe(true);
      if (!r.inserted) throw new Error("insert refused");
      store.apply(nf(i), r.path);
      expect(hex(store.root())).toBe(hex(r.signedRoot.root));
      expect(r.signedRoot.epoch).toBe(i + 1);
      cur = r.signedRoot;
    }

    // Unspent: valid NonExist. Spent: not.
    expect(await ok(runEnclaveOp("smt.verify_non_membership", { userId: ALICE, signedRoot: copy(cur), nullifier: nf(7), siblings: store.siblings(nf(7)) }))).toEqual({ valid: true });
    expect(await ok(runEnclaveOp("smt.verify_non_membership", { userId: ALICE, signedRoot: copy(cur), nullifier: nf(1), siblings: store.siblings(nf(1)) }))).toEqual({ valid: false });
    // Double spend.
    expect(await ok(runEnclaveOp("smt.insert_nullifier", { userId: ALICE, signedRoot: copy(cur), nullifier: nf(1), siblings: store.siblings(nf(1)) }))).toEqual({ inserted: false });
    expect(allZero()).toBe(true);

    // Rollback: the genuine genesis root (no spent nullifiers) is refused after newer roots were seen.
    expect(await ok(runEnclaveOp("smt.insert_nullifier", { userId: ALICE, signedRoot: copy(genesis), nullifier: nf(1), siblings: new Store(empty).siblings(nf(1)) }))).toEqual({ inserted: false });
    expect(await ok(runEnclaveOp("smt.verify_signed_root", { userId: ALICE, signedRoot: copy(genesis) }))).toEqual({ valid: false });
    expect(await runEnclaveOp("smt.genesis", { userId: ALICE, treeId: TREE })).toEqual({ ok: false, code: "invalid_input" });
  }, 120_000);

  it("refuses roots edited or signed by a database admin", async () => {
    await withDeviceKey(MALLORY);
    const empty = await smtEmptyPath();
    const tree = `${TREE}/admin-test`;
    const { signedRoot: g } = await ok<{ signedRoot: SignedRoot }>(runEnclaveOp("smt.genesis", { userId: ALICE, treeId: tree }));
    const store = new Store(empty);
    const r = await ok<Inserted>(runEnclaveOp("smt.insert_nullifier", { userId: ALICE, signedRoot: copy(g), nullifier: nf(1), siblings: store.siblings(nf(1)) }));
    if (!r.inserted) throw new Error("insert refused");
    store.apply(nf(1), r.path);
    const cur = r.signedRoot;

    const flippedRoot = copy(cur);
    flippedRoot.root[31] ^= 1;
    const flippedSig = copy(cur);
    flippedSig.signature[79] ^= 1;
    const otherEpoch = { ...copy(cur), epoch: cur.epoch + 5 };
    const otherTree = { ...copy(cur), treeId: "host:other/slot:x" };
    for (const s of [flippedRoot, flippedSig, otherEpoch]) {
      expect(await ok(runEnclaveOp("smt.verify_signed_root", { userId: ALICE, signedRoot: s }))).toEqual({ valid: false });
    }
    expect(await ok(runEnclaveOp("smt.verify_signed_root", { userId: ALICE, signedRoot: otherTree }))).toEqual({ valid: false });

    // The admin builds a fresh empty tree under their own key and swaps it in.
    const { signedRoot: forged } = await ok<{ signedRoot: SignedRoot }>(runEnclaveOp("smt.genesis", { userId: MALLORY, treeId: `${tree}-forged` }));
    const swapped = { ...copy(forged), treeId: tree, epoch: cur.epoch + 1 };
    expect(await ok(runEnclaveOp("smt.verify_signed_root", { userId: ALICE, signedRoot: swapped }))).toEqual({ valid: false });
    expect(await ok(runEnclaveOp("smt.verify_non_membership", { userId: ALICE, signedRoot: copy(swapped), nullifier: nf(1), siblings: new Store(empty).siblings(nf(1)) }))).toEqual({ valid: false });
    expect(await ok(runEnclaveOp("smt.insert_nullifier", { userId: ALICE, signedRoot: copy(swapped), nullifier: nf(1), siblings: new Store(empty).siblings(nf(1)) }))).toEqual({ inserted: false });
    // Alice's genuine state is unaffected.
    expect(await ok(runEnclaveOp("smt.verify_signed_root", { userId: ALICE, signedRoot: copy(cur) }))).toEqual({ valid: true });
    expect(allZero()).toBe(true);
  }, 120_000);
});
