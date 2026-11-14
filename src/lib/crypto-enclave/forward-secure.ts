/**
 * Forward-secure host keys per epoch (Stap 7d). Thin, typed adapters over
 * wasm/rout-zk (forward_secure.rs); every ratchet step, key derivation,
 * signature and check happens in the pinned engine. Reachable only through
 * the crypto worker ops "host_key.init", "host_key.advance_epoch",
 * "host_key.sign_credential", "host_key.chain" and
 * "host_key.verify_epoch_credential".
 *
 *   state     SK_t, 32 octets; SK_t = HKDF-SHA256(SK_{t-1} || I2OSP(t, 8));
 *             SK_0 from a fresh engine-side random seed, never from a stored key
 *   key       x_t = KeyGen(SK_t, info || t || key id), PK_t (96) = x_t·BP2
 *   link      BBS signature (80) of x_t over [key id, t, t', PK_t'], made
 *             before SK_t is overwritten; verifiers walk the links from the
 *             anchor PK_0
 *   credential Blind BBS signature (80) of x_t over [key id, t, messages..]
 *
 * The state lives only in this worker (HostKeyStore): on every advance the
 * held buffer is zero-filled and overwritten in place, and secure.wipe /
 * worker termination erases it. It is deliberately not persisted: a stored
 * copy of an older state (a backup, a database row) would undo forward
 * security, so how a host keeps its chain across reloads is an open decision
 * (see docs/HANDOVER.md, Stap 7d).
 */
import { wipe } from "@/lib/crypto/wipe";
import { equalBytes } from "./pseudonyms";
import { withZkFrame, zkCheck, ZkEngineError } from "./zk-engine";

export const HOST_STATE_BYTES = 32;
export const HOST_PUBLIC_KEY_BYTES = 96;
export const HOST_SIGNATURE_BYTES = 80;
export const MAX_HOST_KEY_ID_BYTES = 256;
/** Largest jump of one advance (the engine ratchets through every step). */
export const MAX_EPOCH_ADVANCE = 65_536;
/** Links one chain may hold / one verification may walk. */
export const MAX_CHAIN_LINKS = 1024;
/** 32 BBS messages minus the two the engine binds (key id, epoch). */
export const MAX_CREDENTIAL_MESSAGES = 30;
export const MAX_COMMITTED_MESSAGES = 16;
export const MAX_CREDENTIAL_MESSAGE_BYTES = 1024;
export const PROVER_BLIND_BYTES = 32;

export type HostKeyAnchor = { keyId: string; publicKey: Uint8Array };
export type EpochLink = { from: number; to: number; publicKey: Uint8Array; signature: Uint8Array };

const enc = new TextEncoder();

function need(bytes: unknown, len: number): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== len) throw new ZkEngineError("zk_invalid_input");
  return bytes;
}

function epochOf(v: unknown): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) throw new ZkEngineError("zk_invalid_input");
  return v;
}

/** Key id as UTF-8, 1..256 octets (e.g. "host:<id>/key:<n>"). */
export function hostKeyIdBytes(keyId: unknown): Uint8Array {
  if (typeof keyId !== "string") throw new ZkEngineError("zk_invalid_input");
  const b = enc.encode(keyId);
  if (b.byteLength === 0 || b.byteLength > MAX_HOST_KEY_ID_BYTES) throw new ZkEngineError("zk_invalid_input");
  return b;
}

/** Packs HASH messages for the engine: 0x00 || u32 LE length || bytes, per message. */
export function packHashedMessages(messages: unknown, max: number): Uint8Array {
  if (!Array.isArray(messages) || messages.length > max) throw new ZkEngineError("zk_invalid_input");
  let total = 0;
  for (const m of messages) {
    if (!(m instanceof Uint8Array) || m.byteLength > MAX_CREDENTIAL_MESSAGE_BYTES) throw new ZkEngineError("zk_invalid_input");
    total += 5 + m.byteLength;
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const m of messages as Uint8Array[]) {
    out[at] = 0;
    new DataView(out.buffer).setUint32(at + 1, m.byteLength, true);
    out.set(m, at + 5);
    at += 5 + m.byteLength;
  }
  return out;
}

/** commitment_with_proof: empty, or C (48) || 2..18 scalars (0..16 committed messages). */
export function checkCommitment(cwp: unknown): Uint8Array {
  if (cwp === undefined) return new Uint8Array(0);
  if (!(cwp instanceof Uint8Array)) throw new ZkEngineError("zk_invalid_input");
  if (cwp.byteLength === 0) return cwp;
  const k = (cwp.byteLength - 48) / 32;
  if (!Number.isInteger(k) || k < 2 || k > MAX_COMMITTED_MESSAGES + 2) throw new ZkEngineError("zk_invalid_input");
  return cwp;
}

/** Shape check of an epoch link from an untrusted source. */
export function checkLink(v: unknown): EpochLink {
  if (typeof v !== "object" || v === null) throw new ZkEngineError("zk_invalid_input");
  const l = v as Record<string, unknown>;
  const from = epochOf(l.from);
  const to = epochOf(l.to);
  if (to <= from) throw new ZkEngineError("zk_invalid_input");
  return { from, to, publicKey: need(l.publicKey, HOST_PUBLIC_KEY_BYTES), signature: need(l.signature, HOST_SIGNATURE_BYTES) };
}

export function checkAnchor(v: unknown): HostKeyAnchor {
  if (typeof v !== "object" || v === null) throw new ZkEngineError("zk_invalid_input");
  const a = v as Record<string, unknown>;
  hostKeyIdBytes(a.keyId);
  return { keyId: a.keyId as string, publicKey: need(a.publicKey, HOST_PUBLIC_KEY_BYTES) };
}

export const copyLink = (l: EpochLink): EpochLink => ({ from: l.from, to: l.to, publicKey: l.publicKey.slice(), signature: l.signature.slice() });

/** 0 = valid; -1 (malformed) and -2 (does not verify) = not valid; anything else throws. */
function verdict(rc: number): boolean {
  if (rc === -1 || rc === -2) return false;
  zkCheck(rc);
  return true;
}

// ---- Engine calls ---------------------------------------------------------

/** SK_0 and PK_0 for `keyId`; the seed is drawn and wiped inside the engine. */
export async function hostKeyInit(keyId: string): Promise<{ state: Uint8Array; publicKey: Uint8Array }> {
  const kid = hostKeyIdBytes(keyId);
  return withZkFrame((f) => {
    const st = f.reserve(HOST_STATE_BYTES);
    const pk = f.reserve(HOST_PUBLIC_KEY_BYTES);
    zkCheck(f.ex.rout_zk_hostkey_init(f.put(kid), kid.byteLength, st, pk));
    return { state: f.take(st, HOST_STATE_BYTES), publicKey: f.take(pk, HOST_PUBLIC_KEY_BYTES) };
  });
}

export async function hostKeyPublicKey(state: Uint8Array, epoch: number, keyId: string): Promise<Uint8Array> {
  need(state, HOST_STATE_BYTES);
  const kid = hostKeyIdBytes(keyId);
  return withZkFrame((f) => {
    const pk = f.reserve(HOST_PUBLIC_KEY_BYTES);
    zkCheck(f.ex.rout_zk_hostkey_public_key(f.put(state), BigInt(epochOf(epoch)), f.put(kid), kid.byteLength, pk));
    return f.take(pk, HOST_PUBLIC_KEY_BYTES);
  });
}

/** SK_to (fresh buffer), PK_to and the link signed by the epoch-`epoch` key. */
export async function hostKeyAdvance(state: Uint8Array, epoch: number, to: number, keyId: string): Promise<{ state: Uint8Array; link: EpochLink }> {
  need(state, HOST_STATE_BYTES);
  const from = epochOf(epoch);
  if (epochOf(to) <= from || to - from > MAX_EPOCH_ADVANCE) throw new ZkEngineError("zk_invalid_input");
  const kid = hostKeyIdBytes(keyId);
  return withZkFrame((f) => {
    const st = f.put(state);
    const pk = f.reserve(HOST_PUBLIC_KEY_BYTES);
    const sig = f.reserve(HOST_SIGNATURE_BYTES);
    zkCheck(f.ex.rout_zk_hostkey_advance(st, BigInt(from), BigInt(to), f.put(kid), kid.byteLength, pk, sig));
    return {
      state: f.take(st, HOST_STATE_BYTES),
      link: { from, to, publicKey: f.take(pk, HOST_PUBLIC_KEY_BYTES), signature: f.take(sig, HOST_SIGNATURE_BYTES) },
    };
  });
}

/** Credential of epoch `epoch`; blind when `commitment` (a guest's commitment_with_proof) is not empty. */
export async function hostKeySign(state: Uint8Array, epoch: number, keyId: string, messages: Uint8Array[], commitment?: Uint8Array): Promise<Uint8Array> {
  need(state, HOST_STATE_BYTES);
  const e = epochOf(epoch);
  const kid = hostKeyIdBytes(keyId);
  const cwp = checkCommitment(commitment);
  const packed = packHashedMessages(messages, MAX_CREDENTIAL_MESSAGES);
  try {
    return await withZkFrame((f) => {
      const sig = f.reserve(HOST_SIGNATURE_BYTES);
      zkCheck(f.ex.rout_zk_hostkey_sign(f.put(state), BigInt(e), f.put(kid), kid.byteLength, f.put(cwp), cwp.byteLength, f.put(packed), packed.byteLength, sig));
      return f.take(sig, HOST_SIGNATURE_BYTES);
    });
  } finally {
    wipe(packed);
  }
}

export async function hostKeyVerifyLink(publicKeyFrom: Uint8Array, keyId: string, link: EpochLink): Promise<boolean> {
  need(publicKeyFrom, HOST_PUBLIC_KEY_BYTES);
  const l = checkLink(link);
  const kid = hostKeyIdBytes(keyId);
  return withZkFrame((f) =>
    verdict(f.ex.rout_zk_hostkey_verify_link(f.put(publicKeyFrom), f.put(kid), kid.byteLength, BigInt(l.from), BigInt(l.to), f.put(l.publicKey), f.put(l.signature))),
  );
}

export type CredentialCheck = {
  epoch: number;
  signature: Uint8Array;
  messages: Uint8Array[];
  committedMessages?: Uint8Array[];
  proverBlind?: Uint8Array;
};

export async function hostKeyVerifyCredential(publicKey: Uint8Array, keyId: string, c: CredentialCheck): Promise<boolean> {
  need(publicKey, HOST_PUBLIC_KEY_BYTES);
  const kid = hostKeyIdBytes(keyId);
  const e = epochOf(c.epoch);
  need(c.signature, HOST_SIGNATURE_BYTES);
  const blind = c.proverBlind === undefined ? new Uint8Array(PROVER_BLIND_BYTES) : need(c.proverBlind, PROVER_BLIND_BYTES);
  const packed = packHashedMessages(c.messages, MAX_CREDENTIAL_MESSAGES);
  const committed = packHashedMessages(c.committedMessages ?? [], MAX_COMMITTED_MESSAGES);
  try {
    return await withZkFrame((f) =>
      verdict(
        f.ex.rout_zk_hostkey_verify_credential(
          f.put(publicKey), f.put(kid), kid.byteLength, BigInt(e), f.put(c.signature),
          f.put(packed), packed.byteLength, f.put(committed), committed.byteLength, f.put(blind),
        ),
      ),
    );
  } finally {
    wipe(packed, committed);
    if (c.proverBlind === undefined) wipe(blind);
  }
}

// ---- Worker-held state ----------------------------------------------------

type HostKeySlot = { state: Uint8Array; epoch: number; anchor: Uint8Array; publicKey: Uint8Array; links: EpochLink[] };

/**
 * Ratchet states per (member, key id), only in this worker. advance()
 * zero-fills the held buffer and writes the next state into the same bytes,
 * so no copy of SK_{t-1} survives the transition here; wipeAll() erases all.
 */
export class HostKeyStore {
  private slots = new Map<string, HostKeySlot>();

  private key(owner: string, keyId: string) {
    return `${owner}\u0000${keyId}`;
  }

  has(owner: string, keyId: string): boolean {
    return this.slots.has(this.key(owner, keyId));
  }

  get(owner: string, keyId: string): HostKeySlot | undefined {
    return this.slots.get(this.key(owner, keyId));
  }

  /** Takes ownership of `state` (the store keeps this very buffer). */
  create(owner: string, keyId: string, state: Uint8Array, publicKey: Uint8Array): void {
    const k = this.key(owner, keyId);
    if (this.slots.has(k)) throw new ZkEngineError("zk_invalid_input");
    this.slots.set(k, { state, epoch: 0, anchor: publicKey.slice(), publicKey: publicKey.slice(), links: [] });
  }

  /** Overwrites the held state with `next` in place and wipes `next`. */
  advance(owner: string, keyId: string, next: Uint8Array, link: EpochLink): void {
    const slot = this.get(owner, keyId);
    try {
      if (!slot || next.byteLength !== HOST_STATE_BYTES || link.from !== slot.epoch) throw new ZkEngineError("zk_invalid_input");
      slot.state.fill(0);
      slot.state.set(next);
      slot.epoch = link.to;
      slot.publicKey = link.publicKey.slice();
      slot.links.push(copyLink(link));
    } finally {
      wipe(next);
    }
  }

  /** Zero-fills every held state and forgets every chain. Returns how many. */
  wipeAll(): number {
    let n = 0;
    for (const slot of this.slots.values()) {
      wipe(slot.state);
      n++;
    }
    this.slots.clear();
    return n;
  }
}

/**
 * Chains a verifier already checked, per anchor (public data). A request
 * whose links agree with the cached prefix only has its new links checked; a
 * different link where a verified one exists is a fork and is refused.
 */
export class EpochChainCache {
  private chains = new Map<string, EpochLink[]>();
  constructor(private readonly maxChains = 256) {}

  private key(a: HostKeyAnchor) {
    return `${a.keyId}\u0000${Array.from(a.publicKey, (b) => b.toString(16).padStart(2, "0")).join("")}`;
  }

  /** Leading links equal to verified ones; -1 when one differs (fork). */
  verifiedPrefix(a: HostKeyAnchor, links: EpochLink[]): number {
    const known = this.chains.get(this.key(a)) ?? [];
    const n = Math.min(known.length, links.length);
    for (let i = 0; i < n; i++) {
      const x = known[i]!;
      const y = links[i]!;
      if (x.from !== y.from || x.to !== y.to || !equalBytes(x.publicKey, y.publicKey) || !equalBytes(x.signature, y.signature)) return -1;
    }
    return n;
  }

  remember(a: HostKeyAnchor, links: EpochLink[]): void {
    const k = this.key(a);
    const known = this.chains.get(k);
    if (known && known.length >= links.length) return;
    this.chains.delete(k);
    if (this.chains.size >= this.maxChains) {
      const oldest = this.chains.keys().next().value;
      if (oldest !== undefined) this.chains.delete(oldest);
    }
    this.chains.set(k, links.map(copyLink));
  }

  clear(): void {
    this.chains.clear();
  }
}

/** Host key chains of this worker (wiped by secure.wipe). */
export const hostKeys = new HostKeyStore();
/** Chains this worker verified as a guest (public). */
export const epochChains = new EpochChainCache();

/**
 * PK of `epoch` if every link from the anchor verifies, else null. Links must
 * start at 0 and be contiguous (each `from` is the previous `to`); epochs a
 * host skipped have no key.
 */
export async function epochPublicKey(anchor: HostKeyAnchor, links: EpochLink[], epoch: number, cache: EpochChainCache = epochChains): Promise<Uint8Array | null> {
  const a = checkAnchor(anchor);
  if (!Array.isArray(links) || links.length > MAX_CHAIN_LINKS) throw new ZkEngineError("zk_invalid_input");
  const chain = links.map(checkLink);
  const e = epochOf(epoch);
  let at = 0;
  for (const l of chain) {
    if (l.from !== at) return null;
    at = l.to;
  }
  const verified = cache.verifiedPrefix(a, chain);
  if (verified < 0) return null;
  for (let i = verified; i < chain.length; i++) {
    const from = i === 0 ? a.publicKey : chain[i - 1]!.publicKey;
    if (!(await hostKeyVerifyLink(from, a.keyId, chain[i]!))) return null;
  }
  cache.remember(a, chain);
  if (e === 0) return a.publicKey.slice();
  const hit = chain.find((l) => l.to === e);
  return hit ? hit.publicKey.slice() : null;
}

/**
 * A guest's check of a credential: the chain reaches `c.epoch` from the
 * anchor, the epoch is not older than `minEpoch` (expired), and the signature
 * verifies under exactly that epoch's key with key id and epoch bound in.
 */
export async function verifyEpochCredential(anchor: HostKeyAnchor, links: EpochLink[], c: CredentialCheck & { minEpoch?: number }, cache: EpochChainCache = epochChains): Promise<boolean> {
  const e = epochOf(c.epoch);
  if (c.minEpoch !== undefined && e < epochOf(c.minEpoch)) return false;
  const pk = await epochPublicKey(anchor, links, e, cache);
  if (!pk) return false;
  return hostKeyVerifyCredential(pk, anchor.keyId, c);
}
