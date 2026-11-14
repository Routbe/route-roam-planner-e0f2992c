/**
 * Recovery v4 (Stap 6): dynamic 2-of-3 → 3-of-4 recovery vault, following
 * formal/recovery-v4/RecoveryV4.tla.
 *
 *   2of3  user_kek + server + paper          (member without a ROUT Card)
 *   3of4  user_kek + server + paper + card   (after the card is linked)
 *
 * Shares (factors):
 *   user_kek  32-byte secret from the passkey PRF or the OPAQUE export key (kekFactorSecret)
 *   server    ROUT's share, sealed to the server factor key; ROUT opens only this one
 *   paper     24 BIP39 words kept offline
 *   card      the ROUT Card's #rk1 secret, read from the tap URL fragment (never sent to a server)
 *
 * Per ceremony (setup, upgrade, downgrade, rotate) a FRESH 32-byte generation
 * key G is drawn and split with Shamir over GF(2^8) inside the pinned Wasm
 * engine (opaque-engine sssSplit, constant time, SHA-256 commitment per share).
 * G seals the vault root (the Master Key the workspace key derives from) with
 * XChaCha20-Poly1305; the AAD binds member, ceremony, generation, policy and
 * every share commitment, so a swapped commitment or policy no longer opens.
 *
 * Commit gating (model finding 1): a staged ceremony's sealed root is wrapped
 * once more to ROUT's server factor (`pendingRoot`). Only the server's commit
 * step removes that layer (commitPendingRoot), so the shares of a staged,
 * uncommitted ceremony (e.g. a 2-of-3 downgrade) cannot open the live vault.
 *
 * Every share travels only as an RVE1 `mpc` envelope (holder shard_factor,
 * hybrid ML-KEM-1024 + X25519) bound to member, ceremony, generation and factor.
 *
 * Compromised shares: `exclude` lists factors the caller must not use (the
 * server sets it when its share was released without a step-up); such a share
 * is refused, never silently skipped.
 *
 * Zeroization: G, shares, opened envelopes and the root copy are owned buffers
 * wiped in `finally`; the Wasm memory is zero-filled by the engine. JS cannot
 * erase engine/GC copies; `__ownedAuditForTest` lets tests read back every owned
 * buffer of the last operation as zeros.
 */
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { generateRecipientKeys, keyId, openEnvelope, sealEnvelope, type RecipientKeys } from "./pqc-envelope";
import { SSS_COMMIT_LEN, sssCombine, sssSplit, type SssShare } from "./opaque-engine";

export const V4_FACTORS = ["user_kek", "server", "paper", "card"] as const;
export type V4Factor = (typeof V4_FACTORS)[number];
export const V4_POLICIES = ["2of3", "3of4"] as const;
export type V4Policy = (typeof V4_POLICIES)[number];
export const POLICY_FACTORS: Readonly<Record<V4Policy, readonly V4Factor[]>> = Object.freeze({
  "2of3": Object.freeze(["user_kek", "server", "paper"] as const),
  "3of4": Object.freeze(["user_kek", "server", "paper", "card"] as const),
});
export const POLICY_THRESHOLD: Readonly<Record<V4Policy, number>> = Object.freeze({ "2of3": 2, "3of4": 3 });
export const ROOT_BYTES = 32;
const GEN_BYTES = 32;
const NONCE_BYTES = 24;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CEREMONY_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** One error for every recovery failure: no oracle on which share was wrong. */
export class RecoveryV4Error extends Error {
  constructor(readonly code: "recovery_failed" | "factor_compromised" | "below_threshold" = "recovery_failed") {
    super(code);
    this.name = "RecoveryV4Error";
  }
}

const enc = new TextEncoder();
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

// ---------------------------------------------------------------- zeroization audit

let lastOwned: Uint8Array[] = [];
/** Test hook: every buffer the last operation owned; all must read back as zeros. */
export const __ownedAuditForTest = (): readonly Uint8Array[] => lastOwned;
function scope() {
  const owned: Uint8Array[] = [];
  return {
    own<T extends Uint8Array>(b: T): T {
      owned.push(b);
      return b;
    },
    wipe() {
      for (const b of owned) b.fill(0);
      lastOwned = owned;
    },
  };
}

// ---------------------------------------------------------------- contexts

function checkIds(memberId: string, ceremonyId: string, generation: number) {
  if (!UUID_RE.test(memberId)) throw new TypeError("member_id_invalid");
  if (!CEREMONY_RE.test(ceremonyId)) throw new TypeError("ceremony_id_invalid");
  if (!Number.isSafeInteger(generation) || generation < 1) throw new TypeError("generation_invalid");
}
export const sssContextV4 = (memberId: string, ceremonyId: string, generation: number, policy: V4Policy) =>
  `rout.recovery.v4.sss|${memberId}|${ceremonyId}|g=${generation}|${policy}`;
export const shardContextV4 = (memberId: string, ceremonyId: string, generation: number, factor: V4Factor) =>
  `rout.recovery.v4.shard|${memberId}|${ceremonyId}|g=${generation}|${factor}`;
export const pendingContextV4 = (memberId: string, ceremonyId: string, generation: number) =>
  `rout.recovery.v4.pending-root|${memberId}|${ceremonyId}|g=${generation}`;

function rootAad(memberId: string, ceremonyId: string, generation: number, policy: V4Policy, commitments: Readonly<Partial<Record<V4Factor, Uint8Array>>>): Uint8Array {
  const parts = POLICY_FACTORS[policy].map((f) => `${f}=${hex(commitments[f] ?? new Uint8Array(0))}`);
  return enc.encode(`rout.recovery.v4.root|${memberId}|${ceremonyId}|g=${generation}|${policy}|t=${POLICY_THRESHOLD[policy]}|${parts.join(",")}`);
}

// ---------------------------------------------------------------- factor keys

/** Deterministic RVE1 recipient keys of one v4 factor from its 32-byte secret. */
export function v4FactorKeys(factor: V4Factor, secret: Uint8Array, memberId: string): RecipientKeys {
  if (!UUID_RE.test(memberId)) throw new TypeError("member_id_invalid");
  if (!(secret instanceof Uint8Array) || secret.length !== 32) throw new TypeError("factor_secret_must_be_32_bytes");
  const seed = hkdf(sha256, secret, enc.encode("rout.recovery.v4.factor"), enc.encode(`${factor}|${memberId}`), 32);
  try {
    return generateRecipientKeys("shard_factor", seed);
  } finally {
    seed.fill(0);
  }
}

/** The user_kek factor secret from a passkey PRF output (32 B) or an OPAQUE export key (64 B). Caller wipes `raw`. */
export function kekFactorSecret(source: "prf" | "opaque", raw: Uint8Array): Uint8Array {
  if (!(raw instanceof Uint8Array) || (source === "prf" ? raw.length !== 32 : raw.length !== 64)) throw new TypeError("kek_source_invalid");
  return hkdf(sha256, raw, enc.encode("rout.recovery.v4.kek"), enc.encode(source), 32);
}

/** A new paper factor: 24 words and its keys. */
export function createPaperV4(memberId: string): { mnemonic: string; keys: RecipientKeys } {
  const entropy = randomBytes(32);
  try {
    return { mnemonic: entropyToMnemonic(entropy, wordlist), keys: v4FactorKeys("paper", entropy, memberId) };
  } finally {
    entropy.fill(0);
  }
}

export function paperKeysV4(mnemonic: string, memberId: string): RecipientKeys {
  const normalized = mnemonic.trim().toLowerCase().split(/\s+/).join(" ");
  if (normalized.split(" ").length !== 24 || !validateMnemonic(normalized, wordlist)) throw new RecoveryV4Error();
  const entropy = mnemonicToEntropy(normalized, wordlist);
  try {
    return v4FactorKeys("paper", entropy, memberId);
  } finally {
    entropy.fill(0);
  }
}

// ---------------------------------------------------------------- ceremony

/** What the client uploads at BEGIN (all ciphertext or public). */
export type StagedCeremonyV4 = {
  v: 4;
  memberId: string;
  ceremonyId: string;
  generation: number;
  policy: V4Policy;
  /** Sealed root, wrapped once more to ROUT's server factor until commit. */
  pendingRoot: Uint8Array;
  shards: Readonly<Partial<Record<V4Factor, Uint8Array>>>;
  commitments: Readonly<Partial<Record<V4Factor, Uint8Array>>>;
};

/** An active ceremony: the server removed the commit layer. */
export type ActiveCeremonyV4 = Omit<StagedCeremonyV4, "pendingRoot"> & { sealedRoot: Uint8Array };

function exactFactors<T>(policy: V4Policy, rec: Readonly<Partial<Record<V4Factor, T>>>, ok: (v: T) => boolean): boolean {
  const want = POLICY_FACTORS[policy];
  for (const f of V4_FACTORS) {
    const has = rec[f] !== undefined;
    if (has !== want.includes(f)) return false;
    if (has && !ok(rec[f] as T)) return false;
  }
  return true;
}

/**
 * Stages a ceremony: fresh generation key, Shamir split in Wasm, one sealed
 * share per factor, the root sealed under G and wrapped to the server factor.
 */
export async function stageCeremonyV4(input: {
  memberId: string;
  ceremonyId: string;
  generation: number;
  policy: V4Policy;
  vaultRoot: Uint8Array;
  factorPublicKeys: Readonly<Partial<Record<V4Factor, Uint8Array>>>;
}): Promise<StagedCeremonyV4> {
  const { memberId, ceremonyId, generation, policy, vaultRoot, factorPublicKeys } = input;
  checkIds(memberId, ceremonyId, generation);
  if (!V4_POLICIES.includes(policy)) throw new TypeError("policy_invalid");
  if (!(vaultRoot instanceof Uint8Array) || vaultRoot.length !== ROOT_BYTES) throw new TypeError("root_must_be_32_bytes");
  if (!exactFactors(policy, factorPublicKeys, (k) => k instanceof Uint8Array && k.length > 0)) throw new TypeError(policy === "3of4" ? "card_factor_required" : "factor_set_invalid");
  const factors = POLICY_FACTORS[policy];
  const ids = factors.map((f) => hex(keyId(factorPublicKeys[f]!)));
  if (new Set(ids).size !== ids.length) throw new TypeError("factor_keys_must_differ");

  const s = scope();
  try {
    const g = s.own(randomBytes(GEN_BYTES));
    const { shares, commitments } = await sssSplit(g, POLICY_THRESHOLD[policy], factors.length, sssContextV4(memberId, ceremonyId, generation, policy));
    for (const sh of shares) s.own(sh.y);
    const commit: Partial<Record<V4Factor, Uint8Array>> = {};
    const shards: Partial<Record<V4Factor, Uint8Array>> = {};
    factors.forEach((f, i) => {
      const sh = shares[i]!;
      const plain = s.own(new Uint8Array(1 + sh.y.length));
      plain[0] = sh.x;
      plain.set(sh.y, 1);
      shards[f] = sealEnvelope({ kind: "mpc", holder: "shard_factor", recipientPublicKey: factorPublicKeys[f]!, plaintext: plain, context: shardContextV4(memberId, ceremonyId, generation, f) });
      commit[f] = commitments[i]!;
    });
    const nonce = randomBytes(NONCE_BYTES);
    const body = xchacha20poly1305(g, nonce, rootAad(memberId, ceremonyId, generation, policy, commit)).encrypt(vaultRoot);
    const sealedRoot = s.own(new Uint8Array(NONCE_BYTES + body.length));
    sealedRoot.set(nonce);
    sealedRoot.set(body, NONCE_BYTES);
    const pendingRoot = sealEnvelope({ kind: "mpc", holder: "shard_factor", recipientPublicKey: factorPublicKeys.server!, plaintext: sealedRoot, context: pendingContextV4(memberId, ceremonyId, generation) });
    return { v: 4, memberId, ceremonyId, generation, policy, pendingRoot, shards: Object.freeze(shards), commitments: Object.freeze(commit) };
  } finally {
    s.wipe();
  }
}

/** Server commit step: removes the commit layer with ROUT's server factor secret key. */
export function commitPendingRoot(staged: StagedCeremonyV4, serverSecretKey: Uint8Array): ActiveCeremonyV4 {
  try {
    const sealedRoot = openEnvelope({
      envelope: staged.pendingRoot,
      expectedKind: "mpc",
      holder: "shard_factor",
      secretKey: serverSecretKey,
      context: pendingContextV4(staged.memberId, staged.ceremonyId, staged.generation),
    });
    const { pendingRoot: _drop, ...rest } = staged;
    return { ...rest, sealedRoot };
  } catch {
    throw new RecoveryV4Error();
  }
}

/** Opens one factor's shard (the server, for its own factor). Returns x || y; caller wipes. */
export function openShardV4(c: ActiveCeremonyV4 | StagedCeremonyV4, factor: V4Factor, secretKey: Uint8Array): Uint8Array {
  const env = c.shards[factor];
  if (!env) throw new RecoveryV4Error();
  try {
    return openEnvelope({ envelope: env, expectedKind: "mpc", holder: "shard_factor", secretKey, context: shardContextV4(c.memberId, c.ceremonyId, c.generation, factor) });
  } catch {
    throw new RecoveryV4Error();
  }
}

/**
 * Rebuilds the vault root from at least the policy's threshold of factors.
 * `factorSecretKeys` opens shards here; `openedShares` (x || y, e.g. ROUT's
 * own, opened server-side) is wiped here. Factors in `exclude` are refused.
 */
export async function recoverRootV4(input: {
  ceremony: ActiveCeremonyV4;
  memberId: string;
  factorSecretKeys?: Readonly<Partial<Record<V4Factor, Uint8Array>>>;
  openedShares?: Partial<Record<V4Factor, Uint8Array>>;
  exclude?: readonly V4Factor[];
}): Promise<Uint8Array> {
  const { ceremony: c, memberId } = input;
  const keys = input.factorSecretKeys ?? {};
  const opened = input.openedShares ?? {};
  const s = scope();
  for (const v of Object.values(opened)) if (v) s.own(v);
  try {
    if (c.v !== 4 || c.memberId !== memberId || !V4_POLICIES.includes(c.policy)) throw new RecoveryV4Error();
    checkIds(memberId, c.ceremonyId, c.generation);
    const allowed = POLICY_FACTORS[c.policy];
    // Commitments: exactly the policy's factors. Shards: a subset (the member's copy never holds ROUT's).
    if (!exactFactors(c.policy, c.commitments, (x) => x instanceof Uint8Array && x.length === SSS_COMMIT_LEN)) throw new RecoveryV4Error();
    if (V4_FACTORS.some((f) => c.shards[f] !== undefined && (!allowed.includes(f) || !(c.shards[f] instanceof Uint8Array)))) throw new RecoveryV4Error();
    const used = V4_FACTORS.filter((f) => keys[f] !== undefined || opened[f] !== undefined);
    if (used.some((f) => !allowed.includes(f))) throw new RecoveryV4Error();
    if (used.some((f) => input.exclude?.includes(f))) throw new RecoveryV4Error("factor_compromised");
    const k = POLICY_THRESHOLD[c.policy];
    if (used.length < k) throw new RecoveryV4Error("below_threshold");

    const shares: SssShare[] = [];
    const commits: Uint8Array[] = [];
    for (const f of used) {
      const raw = opened[f] ?? s.own(openShardV4(c, f, keys[f]!));
      if (raw.length < 2) throw new RecoveryV4Error();
      shares.push({ x: raw[0]!, y: s.own(raw.slice(1)) });
      commits.push(c.commitments[f]!);
    }
    let g: Uint8Array;
    try {
      g = s.own(await sssCombine(shares, commits, k, sssContextV4(memberId, c.ceremonyId, c.generation, c.policy)));
    } catch {
      throw new RecoveryV4Error();
    }
    if (c.sealedRoot.length <= NONCE_BYTES) throw new RecoveryV4Error();
    let view: Uint8Array;
    try {
      view = s.own(
        xchacha20poly1305(g, c.sealedRoot.subarray(0, NONCE_BYTES), rootAad(memberId, c.ceremonyId, c.generation, c.policy, c.commitments)).decrypt(c.sealedRoot.subarray(NONCE_BYTES)),
      );
    } catch {
      throw new RecoveryV4Error();
    }
    if (view.length !== ROOT_BYTES) throw new RecoveryV4Error();
    return view.slice();
  } finally {
    s.wipe();
  }
}

/** Which factors a ceremony of `policy` needs public keys for; the card only at 3of4. */
export const factorsFor = (policy: V4Policy): readonly V4Factor[] => POLICY_FACTORS[policy];

/** Policy after linking (upgrade) or unlinking-and-downgrading a card. */
export const policyForCard = (hasCard: boolean): V4Policy => (hasCard ? "3of4" : "2of3");
