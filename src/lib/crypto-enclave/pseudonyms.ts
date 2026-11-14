/**
 * Per-booking guest pseudonym (Stap 7a). Runs only inside the crypto worker
 * (op "pseudonym.derive"); the same rule is implemented in Rust in
 * wasm/rout-zk/src/pseudonym.rs and both are pinned to one shared vector.
 *
 *   derived_seed = HKDF-Expand(PRK = master_seed, info = "rout.v1.booking.pseudonym", L = 32)
 *   pseudonym    = HMAC-SHA256(derived_seed, host_id || booking_nonce)
 *
 * booking_nonce is exactly 32 random bytes, so `host_id || booking_nonce`
 * is unambiguous for any host id. A fresh nonce per booking makes two
 * bookings of one guest at one host unlinkable without the master seed.
 * Every derived byte view is zero-filled before returning.
 */
import { expand } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { wipe } from "@/lib/crypto/wipe";

export const PSEUDONYM_INFO = "rout.v1.booking.pseudonym";
export const PSEUDONYM_SEED_BYTES = 32;
export const BOOKING_NONCE_BYTES = 32;
export const PSEUDONYM_BYTES = 32;
export const MAX_HOST_ID_BYTES = 256;

const enc = new TextEncoder();

export class PseudonymInputError extends Error {
  constructor() {
    super("invalid pseudonym input");
  }
}

/** A fresh booking nonce from the platform CSPRNG. */
export function newBookingNonce(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(BOOKING_NONCE_BYTES));
}

export function derivePseudonym(masterSeed: Uint8Array, hostId: string, bookingNonce: Uint8Array): Uint8Array {
  const host = enc.encode(hostId);
  if (masterSeed.byteLength !== PSEUDONYM_SEED_BYTES || bookingNonce.byteLength !== BOOKING_NONCE_BYTES || host.byteLength === 0 || host.byteLength > MAX_HOST_ID_BYTES) {
    wipe(host);
    throw new PseudonymInputError();
  }
  const seed = expand(sha256, masterSeed, enc.encode(PSEUDONYM_INFO), 32);
  const input = new Uint8Array(host.byteLength + BOOKING_NONCE_BYTES);
  try {
    input.set(host, 0);
    input.set(bookingNonce, host.byteLength);
    return hmac(sha256, seed, input);
  } finally {
    wipe(seed, input, host);
  }
}

/** Constant-time comparison of two equal-length byte strings. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let d = 0;
  for (let i = 0; i < a.byteLength; i++) d |= a[i] ^ b[i];
  return d === 0;
}
