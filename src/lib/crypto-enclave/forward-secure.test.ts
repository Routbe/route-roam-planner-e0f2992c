// @vitest-environment node
/**
 * Stap 7d worker ops while rout-zk has no reproducible pin: refusal without a
 * device key, refusal of the unpinned engine (no fallback, no key held),
 * input checks before the engine, in-place state replacement and wiping in
 * the worker store, and the verifier's chain cache.
 */
import "fake-indexeddb/auto";
import { describe, expect, it } from "vitest";
import { runEnclaveOp } from "./enclave-core";
import { checkCommitment, EpochChainCache, HostKeyStore, packHashedMessages, type EpochLink } from "./forward-secure";

const USER = "00000000-0000-4000-8000-0000000007d1";
const KEY = "host:00000000-0000-4000-8000-0000000000aa/key:1";

const link = (from: number, to: number, fill: number): EpochLink => ({
  from,
  to,
  publicKey: new Uint8Array(96).fill(fill),
  signature: new Uint8Array(80).fill(fill + 1),
});
const anchor = { keyId: KEY, publicKey: new Uint8Array(96).fill(9) };

async function withDeviceKey(userId: string) {
  const g = await runEnclaveOp("masterKey.generate", {});
  if (!g.ok) throw new Error(g.code);
  const c = await runEnclaveOp("masterKey.commitPending", { handle: (g.result as { handle: string }).handle, userId });
  if (!c.ok) throw new Error(c.code);
}

describe("host key ops without a pinned engine", () => {
  it("refuses before a device key exists", async () => {
    expect(await runEnclaveOp("host_key.init", { userId: "00000000-0000-4000-8000-0000000007d9", keyId: KEY })).toEqual({ ok: false, code: "no_device_key" });
  });

  it("refuses the unpinned engine and holds no key afterwards", async () => {
    await withDeviceKey(USER);
    expect(await runEnclaveOp("host_key.init", { userId: USER, keyId: KEY })).toEqual({ ok: false, code: "enclave_unavailable" });
    expect(await runEnclaveOp("host_key.advance_epoch", { userId: USER, keyId: KEY, toEpoch: 1 })).toEqual({ ok: false, code: "invalid_input" });
    expect(await runEnclaveOp("host_key.sign_credential", { userId: USER, keyId: KEY, epoch: 0, messages: [] })).toEqual({ ok: false, code: "invalid_input" });
    expect(await runEnclaveOp("host_key.chain", { userId: USER, keyId: KEY })).toEqual({ ok: false, code: "invalid_input" });
  });

  it("checks key ids and verification input before the engine", async () => {
    expect(await runEnclaveOp("host_key.init", { userId: USER, keyId: "" })).toEqual({ ok: false, code: "invalid_input" });
    expect(await runEnclaveOp("host_key.init", { userId: USER, keyId: "é".repeat(129) })).toEqual({ ok: false, code: "invalid_input" });
    const base = { anchor, links: [link(0, 1, 3)], epoch: 1, signature: new Uint8Array(80), messages: [] };
    expect(await runEnclaveOp("host_key.verify_epoch_credential", { ...base, anchor: { keyId: KEY, publicKey: new Uint8Array(95) } })).toEqual({ ok: false, code: "invalid_input" });
    expect(await runEnclaveOp("host_key.verify_epoch_credential", { ...base, links: [link(1, 1, 3)] })).toEqual({ ok: false, code: "invalid_input" });
    expect(await runEnclaveOp("host_key.verify_epoch_credential", { ...base, epoch: -1 })).toEqual({ ok: false, code: "invalid_input" });
    expect(await runEnclaveOp("host_key.verify_epoch_credential", { ...base, messages: Array.from({ length: 31 }, () => new Uint8Array(1)) })).toEqual({ ok: false, code: "invalid_input" });
    // Decided without the engine: an expired epoch, a gap in the chain, an epoch with no key.
    expect(await runEnclaveOp("host_key.verify_epoch_credential", { ...base, minEpoch: 2 })).toEqual({ ok: true, result: { valid: false } });
    expect(await runEnclaveOp("host_key.verify_epoch_credential", { ...base, links: [link(0, 1, 3), link(2, 3, 4)] })).toEqual({ ok: true, result: { valid: false } });
    expect(await runEnclaveOp("host_key.verify_epoch_credential", { ...base, links: [link(1, 2, 3)] })).toEqual({ ok: true, result: { valid: false } });
  });
});

describe("HostKeyStore", () => {
  it("overwrites the held state in place and wipes the incoming copy", () => {
    const store = new HostKeyStore();
    const held = new Uint8Array(32).fill(0xaa);
    store.create(USER, KEY, held, new Uint8Array(96).fill(1));
    const next = new Uint8Array(32).fill(0xbb);
    store.advance(USER, KEY, next, link(0, 3, 5));
    const slot = store.get(USER, KEY)!;
    expect(slot.state).toBe(held); // same buffer: no second copy of the old state
    expect(Array.from(held)).toEqual(Array(32).fill(0xbb));
    expect(next.every((b) => b === 0)).toBe(true);
    expect(slot.epoch).toBe(3);
    expect(slot.links).toHaveLength(1);
  });

  it("refuses a link that does not start at the held epoch, still wiping the copy", () => {
    const store = new HostKeyStore();
    const held = new Uint8Array(32).fill(0xaa);
    store.create(USER, KEY, held, new Uint8Array(96).fill(1));
    const next = new Uint8Array(32).fill(0xbb);
    expect(() => store.advance(USER, KEY, next, link(1, 2, 5))).toThrow();
    expect(Array.from(held)).toEqual(Array(32).fill(0xaa));
    expect(next.every((b) => b === 0)).toBe(true);
    expect(() => store.create(USER, KEY, new Uint8Array(32), new Uint8Array(96))).toThrow();
  });

  it("wipeAll zero-fills every held state", () => {
    const store = new HostKeyStore();
    const a = new Uint8Array(32).fill(7);
    const b = new Uint8Array(32).fill(8);
    store.create(USER, "a", a, new Uint8Array(96));
    store.create(USER, "b", b, new Uint8Array(96));
    expect(store.wipeAll()).toBe(2);
    expect(a.every((x) => x === 0) && b.every((x) => x === 0)).toBe(true);
    expect(store.has(USER, "a")).toBe(false);
  });
});

describe("EpochChainCache", () => {
  it("skips verified links and flags a fork", () => {
    const cache = new EpochChainCache();
    const chain = [link(0, 1, 3), link(1, 2, 4)];
    expect(cache.verifiedPrefix(anchor, chain)).toBe(0);
    cache.remember(anchor, chain);
    chain[0]!.publicKey.fill(0); // the cache kept its own copy
    expect(cache.verifiedPrefix(anchor, [link(0, 1, 3), link(1, 2, 4), link(2, 5, 6)])).toBe(2);
    expect(cache.verifiedPrefix(anchor, [link(0, 1, 3), link(1, 2, 7)])).toBe(-1);
    expect(cache.verifiedPrefix({ keyId: KEY, publicKey: new Uint8Array(96).fill(1) }, chain)).toBe(0);
  });
});

describe("encodings", () => {
  it("packs HASH messages and bounds commitments", () => {
    expect(Array.from(packHashedMessages([new Uint8Array([1, 2]), new Uint8Array(0)], 30))).toEqual([0, 2, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0]);
    expect(() => packHashedMessages([new Uint8Array(1025)], 30)).toThrow();
    expect(checkCommitment(undefined).byteLength).toBe(0);
    expect(checkCommitment(new Uint8Array(48 + 2 * 32)).byteLength).toBe(112);
    expect(() => checkCommitment(new Uint8Array(48 + 32))).toThrow();
    expect(() => checkCommitment(new Uint8Array(48 + 19 * 32))).toThrow();
  });
});
