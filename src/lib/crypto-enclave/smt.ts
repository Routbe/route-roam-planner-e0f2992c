/**
 * Nullifier Sparse Merkle Tree with enclave-signed roots (Stap 7c). Thin,
 * typed adapters over wasm/rout-zk (poseidon.rs, smt.rs); all hashing,
 * signing and proof checks happen in the pinned engine. Reachable only
 * through the crypto worker ops "smt.genesis", "smt.insert_nullifier",
 * "smt.verify_non_membership" and "smt.verify_signed_root".
 *
 *   tree      256 levels, Poseidon (BLS12-381 scalar field, x^5, t = 3) nodes,
 *             one leaf per 32-octet nullifier (empty = 0)
 *   proof     256 sibling nodes from the leaf up, 8192 octets (fixed size)
 *   signed    BBS signature (80) of the member's root-signing key (public key
 *             96) over [tree id, root, I2OSP(epoch, 8)]
 *
 * The signing key is KeyGen(HKDF-SHA256(device seed, salt SMT_SIGNER_SALT))
 * inside the engine; the key material is wiped here, the secret key never
 * leaves the engine call. Roots are only accepted when signed by the caller's
 * own key, so a database admin can neither edit a root nor sign one.
 *
 * Rollback: replaying an *older* genuine signed root (dropping spent
 * nullifiers) is not detectable from a signature. RootWatermarks keeps the
 * highest (epoch, root) seen per member and tree inside this worker and
 * refuses anything older or a different root at the same epoch (a fork). The
 * mark is volatile: it starts empty after a reload, so lasting protection
 * needs the planned external anchoring of roots (booking-engine/AGENTS.md,
 * "Ledger anchoring").
 */
import { extract, expand } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { wipe } from "@/lib/crypto/wipe";
import { equalBytes } from "./pseudonyms";
import { withZkFrame, zkCheck, ZkEngineError } from "./zk-engine";

export const SMT_DEPTH = 256;
export const SMT_NODE_BYTES = 32;
export const NULLIFIER_BYTES = 32;
export const SMT_SIBLINGS_BYTES = SMT_DEPTH * SMT_NODE_BYTES;
export const SMT_PATH_BYTES = (SMT_DEPTH + 1) * SMT_NODE_BYTES;
export const ROOT_SIGNATURE_BYTES = 80;
export const ROOT_PUBLIC_KEY_BYTES = 96;
export const MAX_TREE_ID_BYTES = 256;
export const SMT_KEY_MATERIAL_BYTES = 32;
export const SMT_SIGNER_SALT = "rout.v1.smt.root-signer";
/** Root of the empty tree; equal to wasm/rout-zk/tests/fixtures/smt/empty_root.hex. */
export const SMT_EMPTY_ROOT_HEX = "46cb7f6a1a639693f80c2afddb77288ff88ff08ad19943a595c4c92633ec9505";

export type SignedRoot = {
  treeId: string;
  epoch: number;
  root: Uint8Array;
  publicKey: Uint8Array;
  signature: Uint8Array;
};

const enc = new TextEncoder();

function need(bytes: unknown, len: number): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== len) throw new ZkEngineError("zk_invalid_input");
  return bytes;
}

/** Tree id as UTF-8, 1..256 octets (e.g. "host:<id>/slot:<id>"). */
export function treeIdBytes(treeId: unknown): Uint8Array {
  if (typeof treeId !== "string") throw new ZkEngineError("zk_invalid_input");
  const b = enc.encode(treeId);
  if (b.byteLength === 0 || b.byteLength > MAX_TREE_ID_BYTES) throw new ZkEngineError("zk_invalid_input");
  return b;
}

/** Shape check of a signed root from an untrusted store. */
export function checkSignedRoot(s: unknown): SignedRoot {
  if (typeof s !== "object" || s === null) throw new ZkEngineError("zk_invalid_input");
  const r = s as Record<string, unknown>;
  treeIdBytes(r.treeId);
  if (typeof r.epoch !== "number" || !Number.isSafeInteger(r.epoch) || r.epoch < 0) throw new ZkEngineError("zk_invalid_input");
  need(r.root, SMT_NODE_BYTES);
  need(r.publicKey, ROOT_PUBLIC_KEY_BYTES);
  need(r.signature, ROOT_SIGNATURE_BYTES);
  return r as unknown as SignedRoot;
}

/** Root-signing key material from the member's device seed (domain-separated HKDF-SHA256). */
export function smtSignerKeyMaterial(deviceSeed: Uint8Array): Uint8Array {
  need(deviceSeed, 32);
  const prk = extract(sha256, deviceSeed, enc.encode(SMT_SIGNER_SALT));
  try {
    return expand(sha256, prk, enc.encode("root-signing-key"), SMT_KEY_MATERIAL_BYTES);
  } finally {
    wipe(prk);
  }
}

/** The 257 empty-subtree values, leaf level (0) first; public constants for the node store. */
export async function smtEmptyPath(): Promise<Uint8Array> {
  return withZkFrame((f) => {
    const out = f.reserve(SMT_PATH_BYTES);
    zkCheck(f.ex.rout_zk_smt_empty_path(out));
    return f.take(out, SMT_PATH_BYTES);
  });
}

export async function smtSignerPublicKey(keyMaterial: Uint8Array): Promise<Uint8Array> {
  need(keyMaterial, SMT_KEY_MATERIAL_BYTES);
  return withZkFrame((f) => {
    const out = f.reserve(ROOT_PUBLIC_KEY_BYTES);
    zkCheck(f.ex.rout_zk_smt_signer_pk(f.put(keyMaterial), SMT_KEY_MATERIAL_BYTES, out));
    return f.take(out, ROOT_PUBLIC_KEY_BYTES);
  });
}

/** The empty root signed at epoch 0 for `treeId`. */
export async function smtGenesis(keyMaterial: Uint8Array, treeId: string): Promise<SignedRoot> {
  need(keyMaterial, SMT_KEY_MATERIAL_BYTES);
  const tree = treeIdBytes(treeId);
  return withZkFrame((f) => {
    const km = f.put(keyMaterial);
    const pk = f.reserve(ROOT_PUBLIC_KEY_BYTES);
    const root = f.reserve(SMT_NODE_BYTES);
    const sig = f.reserve(ROOT_SIGNATURE_BYTES);
    zkCheck(f.ex.rout_zk_smt_signer_pk(km, SMT_KEY_MATERIAL_BYTES, pk));
    zkCheck(f.ex.rout_zk_smt_genesis(km, SMT_KEY_MATERIAL_BYTES, f.put(tree), tree.byteLength, root, sig));
    return { treeId, epoch: 0, root: f.take(root, SMT_NODE_BYTES), publicKey: f.take(pk, ROOT_PUBLIC_KEY_BYTES), signature: f.take(sig, ROOT_SIGNATURE_BYTES) };
  });
}

/** True only if `signed` carries `trustedPublicKey` and its signature verifies. */
export async function smtVerifySignedRoot(signed: SignedRoot, trustedPublicKey: Uint8Array): Promise<boolean> {
  const s = checkSignedRoot(signed);
  need(trustedPublicKey, ROOT_PUBLIC_KEY_BYTES);
  if (!equalBytes(s.publicKey, trustedPublicKey)) return false;
  const tree = treeIdBytes(s.treeId);
  return withZkFrame((f) => {
    const rc = f.ex.rout_zk_smt_verify_root(f.put(trustedPublicKey), f.put(tree), tree.byteLength, f.put(s.root), BigInt(s.epoch), f.put(s.signature));
    return verdict(rc);
  });
}

/** Signed root under `trustedPublicKey`, then NonExist (member = false) or Exist of `nullifier`. */
export async function smtVerifyNullifier(signed: SignedRoot, trustedPublicKey: Uint8Array, nullifier: Uint8Array, siblings: Uint8Array, member = false): Promise<boolean> {
  const s = checkSignedRoot(signed);
  need(trustedPublicKey, ROOT_PUBLIC_KEY_BYTES);
  need(nullifier, NULLIFIER_BYTES);
  need(siblings, SMT_SIBLINGS_BYTES);
  if (!equalBytes(s.publicKey, trustedPublicKey)) return false;
  const tree = treeIdBytes(s.treeId);
  return withZkFrame((f) => {
    const rc = f.ex.rout_zk_smt_verify(
      f.put(trustedPublicKey), f.put(tree), tree.byteLength, f.put(s.root), BigInt(s.epoch), f.put(s.signature),
      f.put(nullifier), f.put(siblings), member ? 1 : 0,
    );
    return verdict(rc);
  });
}

/**
 * Verifies the old signed root under the caller's key, proves NonExist,
 * occupies the leaf and signs (R', epoch + 1). null = rejected (spent
 * nullifier, wrong siblings, foreign or edited root); no reason is given.
 * `path` holds the new leaf and every ancestor (leaf first, root last) for the
 * untrusted node store.
 */
export async function smtInsert(keyMaterial: Uint8Array, signed: SignedRoot, nullifier: Uint8Array, siblings: Uint8Array): Promise<{ signedRoot: SignedRoot; path: Uint8Array } | null> {
  need(keyMaterial, SMT_KEY_MATERIAL_BYTES);
  const s = checkSignedRoot(signed);
  need(nullifier, NULLIFIER_BYTES);
  need(siblings, SMT_SIBLINGS_BYTES);
  if (s.epoch >= Number.MAX_SAFE_INTEGER) throw new ZkEngineError("zk_invalid_input");
  const tree = treeIdBytes(s.treeId);
  return withZkFrame((f) => {
    const km = f.put(keyMaterial);
    const pk = f.reserve(ROOT_PUBLIC_KEY_BYTES);
    zkCheck(f.ex.rout_zk_smt_signer_pk(km, SMT_KEY_MATERIAL_BYTES, pk));
    // The root must name this signer; the engine checks the signature under it again.
    if (!equalBytes(f.take(pk, ROOT_PUBLIC_KEY_BYTES), s.publicKey)) return null;
    const root = f.reserve(SMT_NODE_BYTES);
    const sig = f.reserve(ROOT_SIGNATURE_BYTES);
    const path = f.reserve(SMT_PATH_BYTES);
    const rc = f.ex.rout_zk_smt_insert(
      km, SMT_KEY_MATERIAL_BYTES, f.put(tree), tree.byteLength, f.put(s.root), BigInt(s.epoch), f.put(s.signature),
      f.put(nullifier), f.put(siblings), root, sig, path,
    );
    if (!verdict(rc)) return null;
    return {
      signedRoot: { treeId: s.treeId, epoch: s.epoch + 1, root: f.take(root, SMT_NODE_BYTES), publicKey: f.take(pk, ROOT_PUBLIC_KEY_BYTES), signature: f.take(sig, ROOT_SIGNATURE_BYTES) },
      path: f.take(path, SMT_PATH_BYTES),
    };
  });
}

/** 0 = valid; -1 (malformed point/scalar) and -2 (does not verify) = not valid; anything else throws. */
function verdict(rc: number): boolean {
  if (rc === -1 || rc === -2) return false;
  zkCheck(rc);
  return true;
}

/**
 * Highest signed root seen per (member, tree) in this worker. Public data, so
 * nothing to wipe; keyed by member so another account never shares a mark.
 */
export class RootWatermarks {
  private marks = new Map<string, { epoch: number; root: Uint8Array }>();

  private key(owner: string, treeId: string) {
    return `${owner}\u0000${treeId}`;
  }

  has(owner: string, treeId: string): boolean {
    return this.marks.has(this.key(owner, treeId));
  }

  /** False for an older epoch than seen, or another root at the seen epoch. */
  admissible(owner: string, s: SignedRoot): boolean {
    const m = this.marks.get(this.key(owner, s.treeId));
    if (!m) return true;
    if (s.epoch < m.epoch) return false;
    if (s.epoch === m.epoch) return equalBytes(s.root, m.root);
    return true;
  }

  /** Records a verified root if it is newer than the mark. */
  observe(owner: string, s: SignedRoot): void {
    const k = this.key(owner, s.treeId);
    const m = this.marks.get(k);
    if (!m || s.epoch > m.epoch) this.marks.set(k, { epoch: s.epoch, root: s.root.slice() });
  }

  clear(): void {
    this.marks.clear();
  }
}
