// @vitest-environment node
import "fake-indexeddb/auto";
import { describe, expect, it } from "vitest";
import { runEnclaveOp } from "./enclave-core";
import { derivePseudonym, newBookingNonce } from "./pseudonyms";

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const fill = (n: number) => new Uint8Array(32).fill(n);

async function derive(seed: Uint8Array, hostId: string, nonce: Uint8Array) {
  const r = await runEnclaveOp("pseudonym.derive", { masterSeed: seed, hostId, bookingNonce: nonce });
  if (!r.ok) throw new Error(r.code);
  return (r.result as { pseudonym: Uint8Array }).pseudonym;
}

describe("per-booking pseudonym", () => {
  it("matches the vector shared with the Rust engine", () => {
    expect(hex(derivePseudonym(fill(7), "host-1", fill(1)))).toBe("0e80bd98bcb57b6e5c68f3f48ea94b5b1a9e1087520083bf1ee2f8855719140c");
  });

  it("gives two bookings of the same guest at the same host different pseudonyms", async () => {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const a = await derive(seed.slice(), "host-a", newBookingNonce());
    const b = await derive(seed.slice(), "host-a", newBookingNonce());
    expect(a).toHaveLength(32);
    expect(hex(a)).not.toBe(hex(b));
  });

  it("is stable for the same booking and differs per host", async () => {
    const nonce = newBookingNonce();
    const a = await derive(fill(3), "host-a", nonce.slice());
    const again = await derive(fill(3), "host-a", nonce.slice());
    const other = await derive(fill(3), "host-b", nonce.slice());
    expect(hex(a)).toBe(hex(again));
    expect(hex(a)).not.toBe(hex(other));
  });

  it("wipes the seed and nonce it was handed", async () => {
    const seed = fill(9);
    const nonce = fill(4);
    await derive(seed, "host-a", nonce);
    expect(seed.every((x) => x === 0)).toBe(true);
    expect(nonce.every((x) => x === 0)).toBe(true);
  });

  it("refuses wrong sizes", async () => {
    for (const [s, h, n] of [[new Uint8Array(31), "h", fill(1)], [fill(1), "h", new Uint8Array(31)], [fill(1), "", fill(1)]] as const) {
      const r = await runEnclaveOp("pseudonym.derive", { masterSeed: s, hostId: h, bookingNonce: n });
      expect(r).toEqual({ ok: false, code: "invalid_input" });
    }
  });
});
