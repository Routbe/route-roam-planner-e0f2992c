/**
 * Host side of the anonymous booking engine (wasm/rout-zk). Runs only in the
 * crypto worker; never on the UI thread.
 *
 * Same discipline as the password engine (opaque-engine.ts):
 *   - the loader refuses while no pin exists and refuses bytes whose SHA-384
 *     differs from the pin, before compiling;
 *   - every operation gets its own WebAssembly.Memory with initial == maximum
 *     (the module has no allocator and no memory.grow);
 *   - inputs are copied in, outputs copied out, and the whole linear memory is
 *     zero-filled in `finally`, on success, error and trap alike.
 */
import { sha384 } from "@noble/hashes/sha2.js";
import { ROUT_ZK_WASM_BASE64 } from "./zk-wasm-bytes";
import { ROUT_ZK_WASM_SHA384 } from "./zk-wasm-pin";

export class ZkEngineError extends Error {
  constructor(readonly code: "zk_engine_unpinned" | "zk_engine_integrity" | "zk_engine_unavailable" | "zk_invalid_input" | "zk_rejected") {
    super(code);
    this.name = "ZkEngineError";
  }
}

export type ZkExports = {
  rout_zk_abi_version(): number;
  rout_zk_heap_base(): number;
  rout_zk_pedersen_commit(value: number, blind: number, out: number): number;
  rout_zk_pedersen_commit_fresh(value: number, outBlind: number, out: number): number;
  rout_zk_range_prove(value: number, blind: number, ctx: number, ctxLen: number, outCommit: number, outProof: number): number;
  rout_zk_range_verify(commit: number, ctx: number, ctxLen: number, proof: number, proofLen: number): number;
  rout_zk_smt_empty_path(out: number): number;
  rout_zk_smt_signer_pk(km: number, kmLen: number, outPk: number): number;
  rout_zk_smt_genesis(km: number, kmLen: number, tree: number, treeLen: number, outRoot: number, outSig: number): number;
  rout_zk_smt_verify_root(pk: number, tree: number, treeLen: number, root: number, epoch: bigint, sig: number): number;
  rout_zk_smt_verify(pk: number, tree: number, treeLen: number, root: number, epoch: bigint, sig: number, nf: number, siblings: number, member: number): number;
  rout_zk_smt_insert(
    km: number, kmLen: number, tree: number, treeLen: number, root: number, epoch: bigint, sig: number, nf: number, siblings: number,
    outRoot: number, outSig: number, outPath: number,
  ): number;
  rout_zk_hostkey_init(kid: number, kidLen: number, outState: number, outPk: number): number;
  rout_zk_hostkey_public_key(state: number, epoch: bigint, kid: number, kidLen: number, outPk: number): number;
  rout_zk_hostkey_advance(state: number, epoch: bigint, to: bigint, kid: number, kidLen: number, outPk: number, outSig: number): number;
  rout_zk_hostkey_sign(state: number, epoch: bigint, kid: number, kidLen: number, cwp: number, cwpLen: number, msgs: number, msgsLen: number, outSig: number): number;
  rout_zk_hostkey_verify_link(pkFrom: number, kid: number, kidLen: number, from: bigint, to: bigint, pkTo: number, sig: number): number;
  rout_zk_hostkey_verify_credential(
    pk: number, kid: number, kidLen: number, epoch: bigint, sig: number, msgs: number, msgsLen: number, bmsgs: number, bmsgsLen: number, proverBlind: number,
  ): number;
};

/** ABI 4 = BBS / Blind BBS / pseudonym (7a) + Pedersen and range proofs (7b) + Poseidon SMT with signed roots (7c) + forward-secure host keys (7d). */
export const ZK_ENGINE_ABI = 4;
/** Linked as --initial-memory = --max-memory = 2 MiB (1 MiB stack first). */
export const ZK_ENGINE_PAGES = 32;
const PAGE = 65_536;
const SCRATCH = 64 * 1024;

let compiled: Promise<WebAssembly.Module> | null = null;
const live = new Set<WebAssembly.Memory>();

function hexOf(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function decodeBase64(text: string): Uint8Array {
  const raw = atob(text);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

/** Refuses without a pin, verifies the pinned SHA-384, then compiles once per context. */
export function zkEngineModule(): Promise<WebAssembly.Module> {
  if (!compiled) {
    compiled = (async () => {
      const pin = ROUT_ZK_WASM_SHA384;
      const base64 = ROUT_ZK_WASM_BASE64;
      if (!pin || !base64) throw new ZkEngineError("zk_engine_unpinned");
      if (typeof WebAssembly === "undefined") throw new ZkEngineError("zk_engine_unavailable");
      const bytes = decodeBase64(base64);
      if (hexOf(sha384(bytes)) !== pin) throw new ZkEngineError("zk_engine_integrity");
      try {
        return await WebAssembly.compile(bytes as BufferSource);
      } catch {
        throw new ZkEngineError("zk_engine_unavailable");
      }
    })();
    compiled.catch(() => {
      compiled = null;
    });
  }
  return compiled;
}

/** Zero-fills every engine memory that is still alive (worker teardown / lock). Returns how many. */
export function wipeZkEngineMemory(): number {
  let n = 0;
  for (const memory of live) {
    new Uint8Array(memory.buffer).fill(0);
    n++;
  }
  return n;
}

let lastMemory: WebAssembly.Memory | null = null;
/** Test hook: the memory of the last finished operation must read back as zeros. */
export function lastZkMemoryForTest(): Uint8Array | null {
  return lastMemory ? new Uint8Array(lastMemory.buffer) : null;
}

export type ZkFrame = {
  ex: ZkExports;
  put(bytes: Uint8Array): number;
  reserve(len: number): number;
  take(ptr: number, len: number): Uint8Array;
};

export async function withZkFrame<T>(fn: (f: ZkFrame) => T): Promise<T> {
  const module = await zkEngineModule();
  const memory = new WebAssembly.Memory({ initial: ZK_ENGINE_PAGES, maximum: ZK_ENGINE_PAGES });
  live.add(memory);
  lastMemory = memory;
  try {
    const instance = await WebAssembly.instantiate(module, {
      env: {
        memory,
        rout_random(ptr: number, len: number) {
          crypto.getRandomValues(new Uint8Array(memory.buffer, ptr, len));
        },
      },
    });
    const ex = instance.exports as unknown as ZkExports;
    if (ex.rout_zk_abi_version() !== ZK_ENGINE_ABI) throw new ZkEngineError("zk_engine_integrity");
    const base = (ex.rout_zk_heap_base() + 63) & ~63;
    const end = base + SCRATCH;
    if (end > ZK_ENGINE_PAGES * PAGE) throw new ZkEngineError("zk_engine_integrity");
    let cursor = base;
    const reserve = (len: number) => {
      const at = (cursor + 7) & ~7;
      if (at + len > end) throw new ZkEngineError("zk_invalid_input");
      cursor = at + len;
      return at;
    };
    return fn({
      ex,
      reserve,
      put(bytes) {
        const at = reserve(Math.max(bytes.length, 1));
        new Uint8Array(memory.buffer, at, bytes.length).set(bytes);
        return at;
      },
      take(ptr, len) {
        return new Uint8Array(memory.buffer, ptr, len).slice();
      },
    });
  } catch (e) {
    if (e instanceof ZkEngineError) throw e;
    // A trap (unreachable) or link error: no detail, no oracle.
    throw new ZkEngineError("zk_engine_unavailable");
  } finally {
    new Uint8Array(memory.buffer).fill(0);
    live.delete(memory);
  }
}

/** Maps an engine return code: >= 0 ok, -2 rejected, anything else invalid. */
export function zkCheck(rc: number): number {
  if (rc >= 0) return rc;
  if (rc === -2) throw new ZkEngineError("zk_rejected");
  throw new ZkEngineError("zk_invalid_input");
}
