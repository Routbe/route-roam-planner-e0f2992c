// @vitest-environment node
/**
 * db/0272 (Stap 6, dynamic recovery v4; live on Neon 2026-11-14) and its
 * rollback (db-pending/), on PGlite over a replay of every migration in db/
 * before 0272. Drives the real v4 engine
 * (Wasm Shamir, RVE1 shards) and the real store as rout_app, step by step as
 * in formal/recovery-v4/RecoveryV4.tla. Nothing here touches Neon.
 */
import { PGlite } from "@electric-sql/pglite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "@noble/hashes/utils.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { listMigrationFiles, planMigrations } from "../../scripts/migration-plan";
import { migrationDefinerGuardSql, migrationDefinerViolations } from "../../scripts/security-definer-policy";
import { kekFactorSecret, POLICY_FACTORS, recoverRootV4, stageCeremonyV4, v4FactorKeys, type ActiveCeremonyV4, type V4Factor, type V4Policy } from "@/lib/crypto-enclave/recovery-v4";
import { RecoveryV4Store } from "@/lib/recovery/recovery-v4-store.server";
import { serverFactorV4PublicKey } from "@/lib/recovery/server-factor.server";
import type { VaultSqlExecutor } from "@/lib/vault/vault-port.server";

const ROOT = join(__dirname, "..", "..");
const FILE = "0272_dynamic_recovery_v4.sql";
const SQL = readFileSync(join(ROOT, "db", FILE), "utf8");
const ROLLBACK = readFileSync(join(ROOT, "db-pending", "0272_dynamic_recovery_v4_rollback.sql"), "utf8");
const SERVER_SECRET = "S".repeat(64);
const MEMBER = "00000000-0000-4000-8000-0000000000d1";
const OTHER = "00000000-0000-4000-8000-0000000000d2";
const AUTH = "00000000-0000-4000-8000-0000000000a1";
const AUTH2 = "00000000-0000-4000-8000-0000000000a2";
const CARD = "00000000-0000-4000-8000-0000000000c1";
const CARD2 = "00000000-0000-4000-8000-0000000000c2";
const idem = () => crypto.randomUUID().replace(/-/g, "");
const hexOf = (n: number) => Array.from(randomBytes(n), (b) => b.toString(16).padStart(2, "0")).join("");

describe("0272 dynamic recovery v4 on a replay of db/", () => {
  let db: PGlite;
  const exec: VaultSqlExecutor = async (userId, query, params) => {
    await db.exec("begin");
    try {
      await db.exec("set local role rout_app");
      await db.query("select set_config('rout.current_user_id', $1, true)", [userId]);
      const r = await db.query<Record<string, unknown>>(query, [...params]);
      await db.exec("commit");
      return r.rows;
    } catch (e) {
      await db.exec("rollback");
      throw e;
    }
  };
  const store = new RecoveryV4Store(exec, SERVER_SECRET);
  const root = randomBytes(32);
  const keys = Object.fromEntries((["user_kek", "paper", "card"] as const).map((f) => [f, v4FactorKeys(f, f === "user_kek" ? kekFactorSecret("prf", randomBytes(32)) : randomBytes(32), MEMBER)])) as Record<Exclude<V4Factor, "server">, ReturnType<typeof v4FactorKeys>>;

  const proof = async (user = MEMBER, ageSeconds = 0) => {
    const id = crypto.randomUUID();
    await db.query(`insert into vault_enclave.step_up_proofs (proof_id, user_id, method, verified_at) values ($1, $2, 'passkey', clock_timestamp() - make_interval(secs => $3))`, [id, user, ageSeconds]);
    return id;
  };
  const tap = async (card = CARD) => {
    const ref = `tap_${hexOf(32)}`;
    await db.query(`insert into vault_enclave.sdm_tap_grants (grant_digest, card_id, created_at, expires_at) values (sha256(convert_to($1, 'UTF8')), $2, clock_timestamp(), clock_timestamp() + interval '2 minutes')`, [ref, card]);
    return ref;
  };
  const stage = async (policy: V4Policy) => {
    const st = await store.status(MEMBER);
    const pub: Partial<Record<V4Factor, Uint8Array>> = { server: serverFactorV4PublicKey(MEMBER, SERVER_SECRET) };
    for (const f of POLICY_FACTORS[policy]) if (f !== "server") pub[f] = keys[f].publicKey;
    return { st: st!, staged: await stageCeremonyV4({ memberId: MEMBER, ceremonyId: crypto.randomUUID(), generation: st!.nextGeneration, policy, vaultRoot: root, factorPublicKeys: pub }) };
  };
  const active = async () => {
    const m = (await store.material(MEMBER, false))!;
    return { ...m, sealedRoot: m.sealedRoot! } as ActiveCeremonyV4;
  };
  const recover = async (factors: Exclude<V4Factor, "server">[], server?: Uint8Array, exclude?: V4Factor[]) =>
    recoverRootV4({ ceremony: await active(), memberId: MEMBER, factorSecretKeys: Object.fromEntries(factors.map((f) => [f, keys[f].secretKey])), openedShares: server ? { server } : {}, exclude });
  const same = (a: Uint8Array) => Buffer.from(a).equals(Buffer.from(root));
  const ageCeremony = (id: string) =>
    db.query("update vault_enclave.recovery_v4_ceremonies set created_at = created_at - interval '11 minutes', expires_at = expires_at - interval '11 minutes' where ceremony_id = $1", [id]);

  beforeAll(async () => {
    const { btree_gist } = await import("@electric-sql/pglite/contrib/btree_gist");
    const { pgcrypto } = await import("@electric-sql/pglite/contrib/pgcrypto");
    db = await PGlite.create({ extensions: { pgcrypto, btree_gist } });
    const dir = join(ROOT, "db");
    for (const step of planMigrations(listMigrationFiles(dir), new Set())) {
      if (step.action === "run" && step.file !== FILE) await db.exec(`begin;\n${readFileSync(join(dir, step.file), "utf8")}\n;commit;`);
    }
    await db.query(`insert into neon_auth."user" (id, name, email, "emailVerified", "createdAt", "updatedAt") values ($1,'m','m@example.test',true,now(),now()), ($2,'o','o@example.test',true,now(),now())`, [AUTH, AUTH2]);
    await db.query("insert into public.users (id, email, auth_user_id) values ($1, 'm@example.test', $2), ($3, 'o@example.test', $4)", [MEMBER, AUTH, OTHER, AUTH2]);
    // Two cards of MEMBER (no fleet/batch rows needed for this dry run: FK triggers off while seeding).
    await db.exec("set session_replication_role = replica");
    await db.query(`insert into vault_enclave.sdm_batch_cards (card_id, batch_id, uid_hash, owner_user_id) values ($1, gen_random_uuid(), sha256('a'), $3), ($2, gen_random_uuid(), sha256('b'), $3)`, [CARD, CARD2, MEMBER]);
    await db.exec("set session_replication_role = origin");
  }, 300_000);
  afterAll(async () => db?.close());

  it("0272 and its rollback apply cleanly on an empty install; rout_app reaches no table or helper", async () => {
    expect(migrationDefinerViolations(FILE, SQL)).toEqual([]);
    await db.exec(`begin;\n${SQL}\n;commit;`);
    await db.exec(`begin;\n${ROLLBACK}\n;commit;`);
    expect((await db.query<{ r: string | null }>("select to_regclass('vault_enclave.recovery_v4_vaults')::text as r")).rows[0]!.r).toBeNull();
    await db.exec(`begin;\n${SQL}\n;\n${migrationDefinerGuardSql(FILE)};\ncommit;`);
    const t = await db.query<{ s: boolean; i: boolean }>("select has_table_privilege('rout_app', 'vault_enclave.recovery_v4_ceremonies', 'select') as s, has_table_privilege('rout_app', 'vault_enclave.recovery_v4_vaults', 'insert') as i");
    expect(t.rows[0]).toEqual({ s: false, i: false });
    const h = await db.query<{ e: boolean; p: boolean }>("select has_function_privilege('rout_app', 'vault_enclave.recovery_v4_lock(uuid)', 'execute') as e, has_function_privilege('public', 'vault_enclave.recovery_v4_status()', 'execute') as p");
    expect(h.rows[0]).toEqual({ e: false, p: false });
    await expect(exec(MEMBER, "select * from vault_enclave.recovery_v4_ceremonies", [])).rejects.toThrow(/permission/);
  });

  it("no caller: every step answers no_caller", async () => {
    expect((await store.abort("", idem(), crypto.randomUUID())).why).toBe("no_caller");
    expect(await store.status("")).toBeNull();
  });

  it("setup 2of3 needs a fresh step-up; commit opens with any two factors", async () => {
    const { st, staged } = await stage("2of3");
    expect(st.level).toBe("none");
    expect((await store.begin(MEMBER, idem(), { ver: st.ver, kind: "setup", proofId: null, staged })).why).toBe("stepup");
    expect((await store.begin(MEMBER, idem(), { ver: st.ver, kind: "setup", proofId: await proof(MEMBER, 400), staged })).why).toBe("stepup");
    expect((await store.begin(MEMBER, idem(), { ver: st.ver, kind: "setup", proofId: await proof(OTHER), staged })).why).toBe("stepup");
    const b = await store.begin(MEMBER, idem(), { ver: st.ver, kind: "setup", proofId: await proof(), staged });
    expect(b).toMatchObject({ ok: true, why: "ok", cid: staged.ceremonyId, ver: st.ver + 1, level: "none" });
    expect(await store.material(MEMBER, false)).toBeNull();
    const c = await store.commit(MEMBER, idem(), b.ver!, staged.ceremonyId, null);
    expect(c).toMatchObject({ ok: true, level: "2of3", act: staged.ceremonyId, pend: null });
    expect(same(await recover(["user_kek", "paper"]))).toBe(true);
    const rel = await store.releaseServerShare(MEMBER, null);
    expect(rel.granted).toBe(true);
    if (rel.granted) expect(same(await recover(["paper"], rel.share, rel.exclude))).toBe(true);
    await expect(recover(["paper"])).rejects.toThrow();
  });

  it("idempotency: a repeated key returns the stored answer once; another request under it is refused", async () => {
    const st = (await store.status(MEMBER))!;
    const key = idem();
    const a = await store.reportCompromise(MEMBER, key, "user_kek");
    const again = await store.reportCompromise(MEMBER, key, "user_kek");
    expect(again).toEqual(a);
    expect((await store.status(MEMBER))!.ver).toBe(st.ver + 1);
    expect((await store.reportCompromise(MEMBER, key, "paper")).why).toBe("idem_mismatch");
    expect((await store.status(MEMBER))!.compromised).toEqual(["user_kek"]);
  });

  it("2of3 with a compromised share: ROUT's share only with a fresh step-up", async () => {
    const denied = await store.releaseServerShare(MEMBER, null);
    expect(denied).toMatchObject({ granted: false, reason: "step_up_required" });
    const ok = await store.releaseServerShare(MEMBER, await proof());
    expect(ok.granted).toBe(true);
    if (ok.granted) {
      expect(ok.exclude).toEqual([]);
      await expect(recover(["user_kek"], ok.share, ["user_kek"])).rejects.toMatchObject({ code: "factor_compromised" });
    }
  });

  it("upgrade to 3of4: CAS, busy, card confirmation, then three open and the old ceremony is shredded", async () => {
    const { st, staged } = await stage("3of4");
    const oldId = st.activeId!;
    expect((await store.begin(MEMBER, idem(), { ver: st.ver - 1, kind: "upgrade", proofId: await proof(), staged })).why).toBe("conflict");
    expect((await store.begin(MEMBER, idem(), { ver: st.ver, kind: "downgrade", proofId: await proof(), staged })).why).toBe("invalid");
    const b = await store.begin(MEMBER, idem(), { ver: st.ver, kind: "upgrade", proofId: await proof(), staged });
    expect(b.ok).toBe(true);
    const second = await stage("2of3");
    expect((await store.begin(MEMBER, idem(), { ver: b.ver!, kind: "rotate", proofId: await proof(), staged: second.staged })).why).toBe("busy");
    expect((await store.commit(MEMBER, idem(), b.ver!, staged.ceremonyId, null)).why).toBe("card");
    expect((await store.confirmCard(MEMBER, idem(), b.ver!, staged.ceremonyId, `tap_${hexOf(32)}`)).why).toBe("card");
    const cf = await store.confirmCard(MEMBER, idem(), b.ver!, staged.ceremonyId, await tap());
    expect(cf.ok).toBe(true);
    const c = await store.commit(MEMBER, idem(), cf.ver!, staged.ceremonyId, null);
    expect(c).toMatchObject({ ok: true, level: "3of4" });
    expect((await store.status(MEMBER))!.compromised).toEqual([]);
    const old = await db.query<{ status: string; s: boolean }>("select status, shard_server is null and shard_paper is null and sealed_root is null as s from vault_enclave.recovery_v4_ceremonies where ceremony_id = $1", [oldId]);
    expect(old.rows[0]).toEqual({ status: "revoked", s: true });
    expect(same(await recover(["user_kek", "paper", "card"]))).toBe(true);
    const rel = await store.releaseServerShare(MEMBER, null);
    if (!rel.granted) throw new Error("server share expected");
    expect(same(await recover(["paper", "card"], rel.share))).toBe(true);
    await expect(recover(["paper", "card"])).rejects.toMatchObject({ code: "below_threshold" });
  });

  it("3of4 with a lost card: excluded without step-up; a second loss needs one", async () => {
    expect((await store.reportCompromise(MEMBER, idem(), "card")).ok).toBe(true);
    const rel = await store.releaseServerShare(MEMBER, null);
    expect(rel.granted).toBe(true);
    if (rel.granted) {
      expect(rel.exclude).toEqual(["card"]);
      await expect(recover(["paper", "card"], rel.share.slice(), rel.exclude)).rejects.toMatchObject({ code: "factor_compromised" });
      expect(same(await recover(["paper", "user_kek"], rel.share, rel.exclude))).toBe(true);
    }
    expect((await store.reportCompromise(MEMBER, idem(), "paper")).ok).toBe(true);
    expect(await store.releaseServerShare(MEMBER, null)).toMatchObject({ granted: false, reason: "step_up_required" });
  });

  it("rotation clears the compromise set; a revoked confirmed card resets the confirmation", async () => {
    const { st, staged } = await stage("3of4");
    const b = await store.begin(MEMBER, idem(), { ver: st.ver, kind: "rotate", proofId: await proof(), staged });
    const cf = await store.confirmCard(MEMBER, idem(), b.ver!, staged.ceremonyId, await tap(CARD2));
    expect(cf.ok).toBe(true);
    await db.query("update vault_enclave.sdm_batch_cards set revoked_at = clock_timestamp() where card_id = $1", [CARD2]);
    expect((await store.commit(MEMBER, idem(), cf.ver!, staged.ceremonyId, null)).why).toBe("card");
    expect((await store.status(MEMBER))!.pending!.cardConfirmed).toBe(false);
    const cf2 = await store.confirmCard(MEMBER, idem(), cf.ver!, staged.ceremonyId, await tap(CARD));
    const c = await store.commit(MEMBER, idem(), cf2.ver!, staged.ceremonyId, null);
    expect(c.ok).toBe(true);
    const now = (await store.status(MEMBER))!;
    expect(now.compromised).toEqual([]);
    expect(now.generation).toBe(staged.generation);
    expect(same(await recover(["user_kek", "paper", "card"]))).toBe(true);
  });

  it("downgrade to 2of3 commits only with a second fresh step-up", async () => {
    const { st, staged } = await stage("2of3");
    const p = await proof();
    const b = await store.begin(MEMBER, idem(), { ver: st.ver, kind: "downgrade", proofId: p, staged });
    expect(b.ok).toBe(true);
    expect((await store.commit(MEMBER, idem(), b.ver!, staged.ceremonyId, p)).why).toBe("stepup");
    expect((await store.commit(MEMBER, idem(), b.ver!, staged.ceremonyId, null)).why).toBe("stepup");
    const c = await store.commit(MEMBER, idem(), b.ver!, staged.ceremonyId, await proof());
    expect(c).toMatchObject({ ok: true, level: "2of3" });
    expect(same(await recover(["user_kek", "paper"]))).toBe(true);
  });

  it("a pending ceremony ends after 10 minutes on the database clock and is shredded; the cron does the same", async () => {
    const one = await stage("2of3");
    const b = await store.begin(MEMBER, idem(), { ver: one.st.ver, kind: "rotate", proofId: await proof(), staged: one.staged });
    expect(b.ok).toBe(true);
    await ageCeremony(one.staged.ceremonyId);
    const st = (await store.status(MEMBER))!;
    expect(st.pending).toBeNull();
    expect(st.ver).toBe(b.ver! + 1);
    expect((await store.commit(MEMBER, idem(), st.ver, one.staged.ceremonyId, null)).why).toBe("gone");
    const row = await db.query<{ status: string; s: boolean }>("select status, pending_root is null and shard_server is null as s from vault_enclave.recovery_v4_ceremonies where ceremony_id = $1", [one.staged.ceremonyId]);
    expect(row.rows[0]).toEqual({ status: "aborted", s: true });

    const two = await stage("2of3");
    const b2 = await store.begin(MEMBER, idem(), { ver: st.ver, kind: "rotate", proofId: await proof(), staged: two.staged });
    expect(b2.ok).toBe(true);
    await ageCeremony(two.staged.ceremonyId);
    expect(await store.expireDue()).toBe(1);
    expect(same(await recover(["user_kek", "paper"]))).toBe(true);
  });

  it("abort ends a pending ceremony; remove needs a step-up and shreds everything", async () => {
    const { st, staged } = await stage("2of3");
    const b = await store.begin(MEMBER, idem(), { ver: st.ver, kind: "rotate", proofId: await proof(), staged });
    expect((await store.abort(MEMBER, idem(), crypto.randomUUID())).why).toBe("gone");
    expect((await store.abort(MEMBER, idem(), staged.ceremonyId)).ok).toBe(true);
    const now = (await store.status(MEMBER))!;
    expect(now.ver).toBe(b.ver! + 1);
    expect((await store.remove(MEMBER, idem(), now.ver, null)).why).toBe("stepup");
    const r = await store.remove(MEMBER, idem(), now.ver, await proof());
    expect(r).toMatchObject({ ok: true, level: "none" });
    const left = await db.query<{ n: number }>("select count(*)::int as n from vault_enclave.recovery_v4_ceremonies where user_id = $1 and (shard_server is not null or sealed_root is not null or pending_root is not null)", [MEMBER]);
    expect(left.rows[0]!.n).toBe(0);
    expect(await store.releaseServerShare(MEMBER, null)).toMatchObject({ granted: false, reason: "no_vault" });
  });

  it("another member never sees this member's material; the audit chain holds every step", async () => {
    expect(await store.material(OTHER, false)).toBeNull();
    expect((await store.status(OTHER))!.level).toBe("none");
    const a = await db.query<{ n: number; ok: boolean }>("select count(*)::int as n, vault_enclave.verify_audit_chain() as ok from vault_enclave.audit_logs where action like 'recovery_v4_%'");
    expect(a.rows[0]!.n).toBeGreaterThan(20);
    expect(a.rows[0]!.ok).toBe(true);
  });

  it("the rollback refuses once recovery data or audit entries exist", async () => {
    await expect(db.exec(`begin;\n${ROLLBACK}\n;commit;`)).rejects.toThrow(/not empty|immutable/);
    await db.exec("rollback").catch(() => undefined);
  });
});
