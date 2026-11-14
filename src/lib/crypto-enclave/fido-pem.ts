/** PEM helpers for the pinned FIDO trust anchors (sync, workerd-safe). */
import { sha256 } from "@noble/hashes/sha2.js";

export function pemToDer(pem: string): Uint8Array {
  const body = pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(body)) throw new Error("pem_invalid");
  return Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
}

export function pemSha256Hex(pem: string): string {
  let s = "";
  for (const b of sha256(pemToDer(pem))) s += b.toString(16).padStart(2, "0");
  return s;
}
