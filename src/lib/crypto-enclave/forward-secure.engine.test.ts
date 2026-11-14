// @vitest-environment node
/**
 * Stap 7d end to end through the worker ops against a locally built rout-zk
 * module. The committed pin stays null; this file substitutes a test pin for
 * the bytes at ROUT_ZK_DEV_WASM and is skipped when that variable is unset
 * (ROUT_ZK_DEV_WASM=/path/rout_zk.wasm bunx vitest run forward-secure.engine).
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
import { hostKeys, packHashedMessages, type EpochLink, type HostKeyAnchor } from "./forward-secure";
import { lastZkMemoryForTest, withZkFrame } from "./zk-engine";

const HOST = "00000000-0000-4000-8000-0000000007d3";
const OTHER = "00000000-0000-4000-8000-0000000007d4";
const GUEST_HOST = "00000000-0000-4000-8000-0000000007d5";
const KEY = "host:00000000-0000-4000-8000-0000000000aa/key:1";
const allZero = () => lastZkMemoryForTest()!.every((b) => b === 0);
const enc = new TextEncoder();
const msgs = () => [enc.encode("slot:2026-11-20T10:00Z"), enc.encode("seats:1")];

async function ok<T>(p: Promise<{ ok: boolean; result?: unknown; code?: string }>): Promise<T> {
  const r = await p;
  if (!r.ok) throw new Error(String(r.code));
  return r.result as T;
}

async function withDeviceKey(userId: string) {
  const { handle } = await ok<{ handle: string }>(runEnclaveOp("masterKey.generate", {}));
  await ok(runEnclaveOp("masterKey.commitPending", { handle, userId }));
}

type Chain = { anchor: HostKeyAnchor; epoch: number; publicKey: Uint8Array; links: EpochLink[] };
type Signed = { epoch: number; publicKey: Uint8Array; signature: Uint8Array };

// The worker wipes every request after it ran (as over postMessage), so each call gets copies.
const copyChain = (c: Chain) => ({
  anchor: { keyId: c.anchor.keyId, publicKey: c.anchor.publicKey.slice() },
  links: c.links.map((l) => ({ ...l, publicKey: l.publicKey.slice(), signature: l.signature.slice() })),
});
const verify = (chain: Chain, epoch: number, signature: Uint8Array, extra: Record<string, unknown> = {}) =>
  ok<{ valid: boolean }>(runEnclaveOp("host_key.verify_epoch_credential", { ...copyChain(chain), epoch, signature: signature.slice(), messages: msgs(), ...extra })).then((r) => r.valid);

/** A guest commitment through the raw engine export (Blind BBS Commit). */
async function commit(values: Uint8Array[]) {
  const packed = packHashedMessages(values, 16);
  return withZkFrame((f) => {
    const ex = f.ex as unknown as { rout_zk_commit(m: number, ml: number, out: number, cap: number, blind: number): number };
    const out = f.reserve(1024);
    const pb = f.reserve(32);
    const n = ex.rout_zk_commit(f.put(packed), packed.byteLength, out, 1024, pb);
    if (n < 0) throw new Error("commit failed");
    return { cwp: f.take(out, n), proverBlind: f.take(pb, 32) };
  });
}

describe.skipIf(!dev)("forward-secure host keys through the worker (local rout-zk build)", () => {
  it("ratchets, erases the old state, and binds credentials to their epoch", async () => {
    await withDeviceKey(HOST);
    const init = await ok<{ anchor: HostKeyAnchor; epoch: number }>(runEnclaveOp("host_key.init", { userId: HOST, keyId: KEY }));
    expect(init.epoch).toBe(0);
    expect(allZero()).toBe(true);
    expect((await runEnclaveOp("host_key.init", { userId: HOST, keyId: KEY })).ok).toBe(false);

    const s0 = await ok<Signed>(runEnclaveOp("host_key.sign_credential", { userId: HOST, keyId: KEY, epoch: 0, messages: msgs() }));
    expect(allZero()).toBe(true);

    const held = hostKeys.get(HOST, KEY)!.state;
    const before = held.slice();
    const a1 = await ok<{ epoch: number; link: EpochLink }>(runEnclaveOp("host_key.advance_epoch", { userId: HOST, keyId: KEY, toEpoch: 1 }));
    expect(allZero()).toBe(true);
    expect(hostKeys.get(HOST, KEY)!.state).toBe(held); // same bytes, overwritten in place
    expect(Buffer.from(held).equals(Buffer.from(before))).toBe(false);
    await ok(runEnclaveOp("host_key.advance_epoch", { userId: HOST, keyId: KEY, toEpoch: 3 }));
    expect(a1.link.from).toBe(0);

    // Only the current epoch signs.
    expect(await runEnclaveOp("host_key.sign_credential", { userId: HOST, keyId: KEY, epoch: 1, messages: msgs() })).toEqual({ ok: false, code: "invalid_input" });
    expect(await runEnclaveOp("host_key.advance_epoch", { userId: HOST, keyId: KEY, toEpoch: 3 })).toEqual({ ok: false, code: "invalid_input" });
    const s3 = await ok<Signed>(runEnclaveOp("host_key.sign_credential", { userId: HOST, keyId: KEY, epoch: 3, messages: msgs() }));
    expect(s3.epoch).toBe(3);

    const chain = await ok<Chain>(runEnclaveOp("host_key.chain", { userId: HOST, keyId: KEY }));
    expect(chain.epoch).toBe(3);
    expect(chain.links.map((l) => [l.from, l.to])).toEqual([[0, 1], [1, 3]]);
    expect(Buffer.from(chain.publicKey).equals(Buffer.from(s3.publicKey))).toBe(true);

    expect(await verify(chain, 3, s3.signature)).toBe(true);
    expect(allZero()).toBe(true);
    expect(await verify(chain, 0, s0.signature)).toBe(true);
    // Signed with the expired epoch-0 key, presented for epoch 3; or epoch 3 claimed as 0.
    expect(await verify(chain, 3, s0.signature)).toBe(false);
    expect(await verify(chain, 0, s3.signature)).toBe(false);
    // Epoch 2 was skipped: it has no key at all.
    expect(await verify(chain, 2, s3.signature)).toBe(false);
    // Expired by the verifier's own window.
    expect(await verify(chain, 0, s0.signature, { minEpoch: 1 })).toBe(false);
    // Edited message, edited link, another host's anchor.
    expect(await ok<{ valid: boolean }>(runEnclaveOp("host_key.verify_epoch_credential", { ...copyChain(chain), epoch: 3, signature: s3.signature.slice(), messages: [enc.encode("x")] })).then((r) => r.valid)).toBe(false);
    const bent = chain.links.map((l) => ({ ...l, publicKey: l.publicKey.slice(), signature: l.signature.slice() }));
    bent[1]!.signature[10] ^= 1;
    expect(await verify({ ...chain, links: bent }, 3, s3.signature)).toBe(false);
    await withDeviceKey(OTHER);
    const foreign = await ok<{ anchor: HostKeyAnchor }>(runEnclaveOp("host_key.init", { userId: OTHER, keyId: KEY }));
    expect(await verify({ ...chain, anchor: foreign.anchor }, 3, s3.signature)).toBe(false);

    // secure.wipe erases the held state.
    await ok(runEnclaveOp("secure.wipe", {}));
    expect(held.every((b) => b === 0)).toBe(true);
    expect(hostKeys.has(HOST, KEY)).toBe(false);
  }, 120_000);

  it("issues blind credentials that open only with the guest's blind", async () => {
    await withDeviceKey(GUEST_HOST);
    const key = `${KEY}/blind`;
    await ok(runEnclaveOp("host_key.init", { userId: GUEST_HOST, keyId: key }));
    await ok(runEnclaveOp("host_key.advance_epoch", { userId: GUEST_HOST, keyId: key, toEpoch: 2 }));
    const committed = [enc.encode("guest pseudonym"), enc.encode("guest secret")];
    const { cwp, proverBlind } = await commit(committed);
    const s = await ok<Signed>(runEnclaveOp("host_key.sign_credential", { userId: GUEST_HOST, keyId: key, epoch: 2, messages: msgs(), commitmentWithProof: cwp }));
    const chain = await ok<Chain>(runEnclaveOp("host_key.chain", { userId: GUEST_HOST, keyId: key }));
    expect(await verify(chain, 2, s.signature, { committedMessages: committed.map((m) => m.slice()), proverBlind: proverBlind.slice() })).toBe(true);
    expect(await verify(chain, 2, s.signature, { committedMessages: committed.map((m) => m.slice()) })).toBe(false);
    expect(await verify(chain, 2, s.signature)).toBe(false);
    expect(allZero()).toBe(true);
  }, 120_000);
});
