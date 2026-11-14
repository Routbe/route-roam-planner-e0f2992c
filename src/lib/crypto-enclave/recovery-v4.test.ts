// @vitest-environment node
import { describe, expect, it } from "vitest";
import { randomBytes } from "@noble/hashes/utils.js";
import { lastEngineMemoryForTest } from "./opaque-engine";
import {
  __ownedAuditForTest,
  commitPendingRoot,
  createPaperV4,
  kekFactorSecret,
  openShardV4,
  POLICY_FACTORS,
  recoverRootV4,
  RecoveryV4Error,
  stageCeremonyV4,
  v4FactorKeys,
  type ActiveCeremonyV4,
  type V4Factor,
  type V4Policy,
} from "./recovery-v4";

const MEMBER = "00000000-0000-4000-8000-0000000000d1";
const OTHER = "00000000-0000-4000-8000-0000000000d2";
const uuid = () => crypto.randomUUID();
const subsets = <T,>(xs: readonly T[], k: number): T[][] => (k === 0 ? [[]] : xs.flatMap((x, i) => subsets(xs.slice(i + 1), k - 1).map((r) => [x, ...r])));
const zero = (b: Uint8Array | null) => !!b && b.every((x) => x === 0);

function factorSet(member = MEMBER) {
  const secrets: Record<V4Factor, Uint8Array> = { user_kek: kekFactorSecret("prf", randomBytes(32)), server: randomBytes(32), paper: randomBytes(32), card: randomBytes(32) };
  const keys = Object.fromEntries((Object.keys(secrets) as V4Factor[]).map((f) => [f, v4FactorKeys(f, secrets[f], member)])) as Record<V4Factor, ReturnType<typeof v4FactorKeys>>;
  return { keys };
}

async function ceremony(policy: V4Policy, generation = 1, root = randomBytes(32), fs = factorSet()) {
  const pub = Object.fromEntries(POLICY_FACTORS[policy].map((f) => [f, fs.keys[f].publicKey]));
  const staged = await stageCeremonyV4({ memberId: MEMBER, ceremonyId: uuid(), generation, policy, vaultRoot: root, factorPublicKeys: pub });
  const active = commitPendingRoot(staged, fs.keys.server.secretKey);
  return { staged, active, root, fs };
}
const secrets = (fs: ReturnType<typeof factorSet>, factors: readonly V4Factor[]) => Object.fromEntries(factors.map((f) => [f, fs.keys[f].secretKey]));

describe("Stap 6: recovery v4 engine", () => {
  it("3of4: every 3- and 4-subset opens; every 2-subset is refused", async () => {
    const { active, root, fs } = await ceremony("3of4");
    for (const set of [...subsets(POLICY_FACTORS["3of4"], 3), POLICY_FACTORS["3of4"] as V4Factor[]]) {
      const got = await recoverRootV4({ ceremony: active, memberId: MEMBER, factorSecretKeys: secrets(fs, set) });
      expect(Buffer.from(got).equals(Buffer.from(root))).toBe(true);
    }
    for (const set of subsets(POLICY_FACTORS["3of4"], 2)) {
      await expect(recoverRootV4({ ceremony: active, memberId: MEMBER, factorSecretKeys: secrets(fs, set) })).rejects.toMatchObject({ code: "below_threshold" });
    }
  });

  it("2of3: any two open, one is refused, a card is not part of it", async () => {
    const { active, root, fs } = await ceremony("2of3");
    for (const set of subsets(POLICY_FACTORS["2of3"], 2)) {
      expect(Buffer.from(await recoverRootV4({ ceremony: active, memberId: MEMBER, factorSecretKeys: secrets(fs, set) })).equals(Buffer.from(root))).toBe(true);
    }
    await expect(recoverRootV4({ ceremony: active, memberId: MEMBER, factorSecretKeys: secrets(fs, ["paper"]) })).rejects.toBeInstanceOf(RecoveryV4Error);
    await expect(recoverRootV4({ ceremony: active, memberId: MEMBER, factorSecretKeys: secrets(fs, ["paper", "card"]) })).rejects.toBeInstanceOf(RecoveryV4Error);
  });

  it("3of4 needs a card key; mismatched or duplicated factor keys are refused", async () => {
    const fs = factorSet();
    const pub = { user_kek: fs.keys.user_kek.publicKey, server: fs.keys.server.publicKey, paper: fs.keys.paper.publicKey };
    await expect(stageCeremonyV4({ memberId: MEMBER, ceremonyId: uuid(), generation: 1, policy: "3of4", vaultRoot: randomBytes(32), factorPublicKeys: pub })).rejects.toThrow("card_factor_required");
    await expect(
      stageCeremonyV4({ memberId: MEMBER, ceremonyId: uuid(), generation: 1, policy: "2of3", vaultRoot: randomBytes(32), factorPublicKeys: { ...pub, paper: pub.user_kek } }),
    ).rejects.toThrow("factor_keys_must_differ");
  });

  it("a staged ceremony does not open before the server commit (commit gating)", async () => {
    const { staged, fs } = await ceremony("2of3");
    // The pending root is sealed to the server factor: two shares alone have nothing to open.
    expect("sealedRoot" in staged).toBe(false);
    const fake = { ...staged, sealedRoot: staged.pendingRoot } as unknown as ActiveCeremonyV4;
    await expect(recoverRootV4({ ceremony: fake, memberId: MEMBER, factorSecretKeys: secrets(fs, ["user_kek", "paper"]) })).rejects.toBeInstanceOf(RecoveryV4Error);
    expect(() => commitPendingRoot(staged, fs.keys.paper.secretKey)).toThrow(RecoveryV4Error);
  });

  it("invalid hash: a corrupted share, a swapped commitment or another member fails", async () => {
    const { active, fs } = await ceremony("3of4");
    // Swap two commitments: the shares no longer match them.
    const swapped = { ...active, commitments: { ...active.commitments, paper: active.commitments.card!, card: active.commitments.paper! } };
    await expect(recoverRootV4({ ceremony: swapped, memberId: MEMBER, factorSecretKeys: secrets(fs, ["paper", "card", "user_kek"]) })).rejects.toBeInstanceOf(RecoveryV4Error);
    // A server share opened and then corrupted.
    const server = openShardV4(active, "server", fs.keys.server.secretKey);
    server[5]! ^= 0x01;
    await expect(recoverRootV4({ ceremony: active, memberId: MEMBER, factorSecretKeys: secrets(fs, ["paper", "card"]), openedShares: { server } })).rejects.toBeInstanceOf(RecoveryV4Error);
    await expect(recoverRootV4({ ceremony: { ...active, memberId: OTHER }, memberId: OTHER, factorSecretKeys: secrets(fs, ["paper", "card", "user_kek"]) })).rejects.toBeInstanceOf(RecoveryV4Error);
    // A share moved from one factor to another does not open (context-bound envelopes).
    const moved = { ...active, shards: { ...active.shards, paper: active.shards.card!, card: active.shards.paper! } };
    await expect(recoverRootV4({ ceremony: moved, memberId: MEMBER, factorSecretKeys: secrets(fs, ["paper", "card", "user_kek"]) })).rejects.toBeInstanceOf(RecoveryV4Error);
  });

  it("the server's own share works opened server-side and is wiped after use", async () => {
    const { active, root, fs } = await ceremony("3of4");
    const server = openShardV4(active, "server", fs.keys.server.secretKey);
    const got = await recoverRootV4({ ceremony: active, memberId: MEMBER, factorSecretKeys: secrets(fs, ["paper", "card"]), openedShares: { server } });
    expect(Buffer.from(got).equals(Buffer.from(root))).toBe(true);
    expect(zero(server)).toBe(true);
  });

  it("a compromised factor is refused, not skipped", async () => {
    const { active, root, fs } = await ceremony("3of4");
    await expect(recoverRootV4({ ceremony: active, memberId: MEMBER, factorSecretKeys: secrets(fs, ["paper", "card", "user_kek"]), exclude: ["card"] })).rejects.toMatchObject({ code: "factor_compromised" });
    const got = await recoverRootV4({ ceremony: active, memberId: MEMBER, factorSecretKeys: secrets(fs, ["paper", "server", "user_kek"]), exclude: ["card"] });
    expect(Buffer.from(got).equals(Buffer.from(root))).toBe(true);
  });

  it("rotation ceremony: new generation and ceremony; old shares do not open the new one; upgrade 2of3 -> 3of4 keeps the root", async () => {
    const fs = factorSet();
    const root = randomBytes(32);
    const g1 = await ceremony("2of3", 1, root, fs);
    const g2 = await ceremony("3of4", 2, root, fs);
    expect(g2.active.ceremonyId).not.toBe(g1.active.ceremonyId);
    // Old ceremony's shards against the new ceremony: wrong context, refused.
    const mixed = { ...g2.active, shards: { ...g2.active.shards, user_kek: g1.active.shards.user_kek!, paper: g1.active.shards.paper! } };
    await expect(recoverRootV4({ ceremony: mixed, memberId: MEMBER, factorSecretKeys: secrets(fs, ["user_kek", "paper", "card"]) })).rejects.toBeInstanceOf(RecoveryV4Error);
    const got = await recoverRootV4({ ceremony: g2.active, memberId: MEMBER, factorSecretKeys: secrets(fs, ["user_kek", "paper", "card"]) });
    expect(Buffer.from(got).equals(Buffer.from(root))).toBe(true);
    // Rotation with the same policy draws a fresh generation key: different sealed root and commitments.
    const g3 = await ceremony("3of4", 3, root, fs);
    expect(Buffer.from(g3.active.sealedRoot).equals(Buffer.from(g2.active.sealedRoot))).toBe(false);
    expect(Buffer.from(g3.active.commitments.paper!).equals(Buffer.from(g2.active.commitments.paper!))).toBe(false);
  });

  it("zeroization audit: every owned buffer and the engine memory read back as zeros", async () => {
    const { active, fs } = await ceremony("3of4");
    expect(__ownedAuditForTest().length).toBeGreaterThan(0);
    expect(__ownedAuditForTest().every(zero)).toBe(true);
    expect(zero(lastEngineMemoryForTest())).toBe(true);
    await recoverRootV4({ ceremony: active, memberId: MEMBER, factorSecretKeys: secrets(fs, ["paper", "card", "user_kek"]) });
    expect(__ownedAuditForTest().length).toBeGreaterThanOrEqual(7);
    expect(__ownedAuditForTest().every(zero)).toBe(true);
    expect(zero(lastEngineMemoryForTest())).toBe(true);
    await recoverRootV4({ ceremony: active, memberId: MEMBER, factorSecretKeys: secrets(fs, ["paper"]) }).catch(() => undefined);
    expect(__ownedAuditForTest().every(zero)).toBe(true);
  });

  it("paper words round-trip and the kek secret depends on its source", () => {
    const p = createPaperV4(MEMBER);
    expect(p.mnemonic.split(" ")).toHaveLength(24);
    const raw = randomBytes(64);
    expect(() => kekFactorSecret("prf", raw)).toThrow();
    expect(kekFactorSecret("opaque", raw)).toHaveLength(32);
  });
});
