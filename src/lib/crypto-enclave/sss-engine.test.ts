// @vitest-environment node
/**
 * Stap 6: Shamir over GF(2^8) in the pinned Wasm engine. Cross-checked against
 * the independent, audited shamir-secret-sharing library (same field, AES
 * polynomial 0x11b): shares from the engine combine there and vice versa.
 */
import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { combine as libCombine, split as libSplit } from "shamir-secret-sharing";
import { lastEngineMemoryForTest, SssError, sssCombine, sssSplit, wipeEngineMemory } from "./opaque-engine";

const CTX = "rout.test.sss|member|ceremony";
const subsets = <T,>(xs: T[], k: number): T[][] => (k === 0 ? [[]] : xs.flatMap((x, i) => subsets(xs.slice(i + 1), k - 1).map((r) => [x, ...r])));
const allZero = (b: Uint8Array | null) => !!b && b.every((x) => x === 0);

describe("Stap 6: Shamir in the Wasm engine", () => {
  it("every 3-of-4 subset rebuilds the secret; every 2-of-4 subset is refused", async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shares, commitments } = await sssSplit(secret, 3, 4, CTX);
    expect(allZero(lastEngineMemoryForTest())).toBe(true);
    const idx = [0, 1, 2, 3];
    for (const s of [...subsets(idx, 3), ...subsets(idx, 4)]) {
      const got = await sssCombine(s.map((i) => shares[i]!), s.map((i) => commitments[i]!), 3, CTX);
      expect(Buffer.from(got).equals(Buffer.from(secret))).toBe(true);
      expect(allZero(lastEngineMemoryForTest())).toBe(true);
    }
    for (const s of subsets(idx, 2)) {
      await expect(sssCombine(s.map((i) => shares[i]!), s.map((i) => commitments[i]!), 3, CTX)).rejects.toMatchObject({ code: "sss_below_threshold" });
      expect(allZero(lastEngineMemoryForTest())).toBe(true);
    }
  });

  it("2-of-3 works the same way", async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shares, commitments } = await sssSplit(secret, 2, 3, CTX);
    for (const s of subsets([0, 1, 2], 2)) {
      const got = await sssCombine(s.map((i) => shares[i]!), s.map((i) => commitments[i]!), 2, CTX);
      expect(Buffer.from(got).equals(Buffer.from(secret))).toBe(true);
    }
  });

  it("a flipped bit, a swapped share or another context fails the commitment", async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { shares, commitments } = await sssSplit(secret, 3, 4, CTX);
    const three = shares.slice(0, 3);
    const c3 = commitments.slice(0, 3);
    for (let bit = 0; bit < 8 * 32; bit += 37) {
      const bad = three.map((s, i) => (i === 1 ? { x: s.x, y: s.y.slice() } : s));
      bad[1]!.y[bit >> 3]! ^= 1 << (bit & 7);
      await expect(sssCombine(bad, c3, 3, CTX)).rejects.toMatchObject({ code: "sss_bad_commitment" });
    }
    await expect(sssCombine(three, [c3[1]!, c3[0]!, c3[2]!], 3, CTX)).rejects.toMatchObject({ code: "sss_bad_commitment" });
    await expect(sssCombine(three, c3, 3, CTX + "x")).rejects.toMatchObject({ code: "sss_bad_commitment" });
    expect(allZero(lastEngineMemoryForTest())).toBe(true);
  });

  it("refuses duplicate or zero x and bad parameters", async () => {
    const secret = new Uint8Array(32).fill(7);
    const { shares, commitments } = await sssSplit(secret, 3, 4, CTX);
    await expect(sssCombine([shares[0]!, shares[0]!, shares[1]!], [commitments[0]!, commitments[0]!, commitments[1]!], 3, CTX)).rejects.toBeInstanceOf(SssError);
    await expect(sssSplit(secret, 1, 4, CTX)).rejects.toBeInstanceOf(SssError);
    await expect(sssSplit(secret, 5, 4, CTX)).rejects.toBeInstanceOf(SssError);
    await expect(sssSplit(new Uint8Array(65), 3, 4, CTX)).rejects.toBeInstanceOf(SssError);
    await expect(sssSplit(secret, 3, 4, "")).rejects.toBeInstanceOf(SssError);
  });

  it("is the same field as the audited library: shares interoperate both ways", async () => {
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ minLength: 1, maxLength: 64 }), fc.integer({ min: 2, max: 4 }), async (secret, k) => {
        const n = 4;
        const { shares } = await sssSplit(secret, k, n, CTX);
        // Library format: y || x.
        const asLib = shares.slice(0, k).map((s) => Uint8Array.from([...s.y, s.x]));
        expect(Buffer.from(await libCombine(asLib)).equals(Buffer.from(secret))).toBe(true);
        const lib = await libSplit(secret, n, k);
        const back = lib.slice(0, k).map((b) => ({ x: b[b.length - 1]!, y: b.slice(0, -1) }));
        // Library shares carry no commitment: build ours over them, then combine in the engine.
        const { sha256 } = await import("@noble/hashes/sha2.js");
        const ctx = new TextEncoder().encode(CTX);
        const commit = (x: number, y: Uint8Array) => sha256(Uint8Array.from([...new TextEncoder().encode("rout.sss.commit.v1"), ctx.length, ...ctx, x, ...y]));
        const got = await sssCombine(back, back.map((s) => commit(s.x, s.y)), k, CTX);
        expect(Buffer.from(got).equals(Buffer.from(secret))).toBe(true);
      }),
      { numRuns: 60 },
    );
  });

  it("below the threshold the shares reveal nothing about a chosen byte (distribution check)", async () => {
    // For a fixed 1-byte secret, share 1's y over many splits is uniform: each of 256 values ~ N/256.
    const counts = new Map<number, number>();
    const N = 2048;
    for (let i = 0; i < N; i++) {
      const { shares } = await sssSplit(Uint8Array.of(0x42), 3, 4, CTX);
      const y = shares[0]!.y[0]!;
      counts.set(y, (counts.get(y) ?? 0) + 1);
    }
    expect(counts.size).toBeGreaterThan(240);
    expect(Math.max(...counts.values())).toBeLessThan(30);
  }, 60_000);

  it("teardown wipe leaves no live engine memory", () => {
    expect(wipeEngineMemory()).toBe(0);
  });
});
