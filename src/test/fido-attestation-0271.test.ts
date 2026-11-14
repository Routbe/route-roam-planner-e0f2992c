// @vitest-environment node
/**
 * db/0271 (Stap 5, FIDO MDS3 passkey attestation; live on Neon 2026-11-14) and
 * its rollback (db-pending/), replayed on PGlite over every migration in db/ before 0271. Drives the real
 * vault adapter as rout_app and the real RVE1 pak sealing under a test KEK.
 */
import { PGlite } from "@electric-sql/pglite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { listMigrationFiles, planMigrations } from "../../scripts/migration-plan";
import { deriveVaultKek } from "@/lib/vault/server-kek";
import { openPasskeyAttestation, sealPasskeyAttestation } from "@/lib/vault/server-vault.server";
import { LocalPostgresVaultAdapter, type VaultSqlExecutor } from "@/lib/vault/vault-port.server";
import { recordVerdict } from "@/lib/auth/passkey-attestation-record.server";

const ROOT = join(__dirname, "..", "..");
const FILE_0271 = "0271_fido_mds3_attestation.sql";
const SQL = readFileSync(join(ROOT, "db", FILE_0271), "utf8");
const ROLLBACK = readFileSync(join(ROOT, "db-pending", "0271_fido_mds3_attestation_rollback.sql"), "utf8");
const MEMBER = "00000000-0000-4000-8000-0000000000d1";
const AUTH = "00000000-0000-4000-8000-0000000000a1";
const OTHER = "00000000-0000-4000-8000-0000000000a2";
const CRED = "credential_AAAAAAAAAAAAAAAAAAAA";
const OLD_CRED = "credential_OLDOLDOLDOLDOLDOLDOL";
const OTHER_CRED = "credential_OTHEROTHEROTHEROTHER";
const verdict = { attested: true as const, fmt: "packed" as const, aaguid: "01020304-0506-0708-090a-0b0c0d0e0f10", description: "Key", certification: { fips140: 3, fipsPhysical: 3, ccEal: null, fido: "FIDO_CERTIFIED_L2" as const }, statusSafe: true, certifiedL3: true, mdsNo: 1 };

describe("0271 passkey attestation on a replay of db/", () => {
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
  const port = new LocalPostgresVaultAdapter(exec);
  const kek = deriveVaultKek("a".repeat(64));
  const seal = (c: { userId: string }, id: string, p: Uint8Array) => sealPasskeyAttestation(c, id, p, { port, kek });

  beforeAll(async () => {
    const { btree_gist } = await import("@electric-sql/pglite/contrib/btree_gist");
    const { pgcrypto } = await import("@electric-sql/pglite/contrib/pgcrypto");
    db = await PGlite.create({ extensions: { pgcrypto, btree_gist } });
    const dir = join(ROOT, "db");
    for (const step of planMigrations(listMigrationFiles(dir), new Set())) {
      if (step.action === "run" && step.file !== FILE_0271) await db.exec(`begin;\n${readFileSync(join(dir, step.file), "utf8")}\n;commit;`);
    }
    await db.query(`insert into neon_auth."user" (id, name, email, "emailVerified", "createdAt", "updatedAt") values ($1,'m','m@example.test',true,now(),now()), ($2,'o','o@example.test',true,now(),now())`, [AUTH, OTHER]);
    await db.query("insert into public.users (id, email, auth_user_id) values ($1, 'm@example.test', $2)", [MEMBER, AUTH]);
    const pk = `insert into neon_auth.passkey (id, name, "publicKey", "userId", "credentialID", counter, "deviceType", "backedUp", transports, "createdAt", aaguid) values ($1, 'k', 'pk', $2, $3, 0, 'singleDevice', false, 'usb', $4, null)`;
    await db.query(pk, ["p1", AUTH, CRED, new Date()]);
    await db.query(pk, ["p2", AUTH, OLD_CRED, new Date(Date.now() - 3600_000)]);
    await db.query(pk, ["p3", OTHER, OTHER_CRED, new Date()]);
  }, 300_000);
  afterAll(async () => db?.close());

  it("before 0271 the feature is unavailable and recording is a no-op", async () => {
    expect(await port.passkeyAttestationAvailable()).toBe(false);
    expect(await recordVerdict(MEMBER, CRED, verdict, { port, seal })).toBe("unavailable");
  });

  it("0271 applies and rout_app reaches no table", async () => {
    await db.exec(`begin;\n${SQL}\n;commit;`);
    expect(await port.passkeyAttestationAvailable()).toBe(true);
    const r = await db.query<{ s: boolean }>("select has_table_privilege('rout_app', 'vault_enclave.passkey_attestations', 'select') as s");
    expect(r.rows[0]!.s).toBe(false);
  });

  it("records once for the caller's own fresh passkey, as member or as auth identity", async () => {
    expect(await recordVerdict(MEMBER, CRED, verdict, { port, seal })).toBe("recorded");
    expect(await recordVerdict(MEMBER, CRED, verdict, { port, seal })).toBe("denied");
    expect(await port.passkeyAttestationFlags({ userId: MEMBER })).toEqual([{ credentialId: CRED, fmt: "packed", attested: true, statusSafe: true, certifiedL3: true }]);
    expect(await port.passkeyAttestationFlags({ userId: AUTH })).toHaveLength(1);
  });

  it("refuses another member's passkey and an old passkey; never shows another member's rows", async () => {
    expect(await recordVerdict(MEMBER, OTHER_CRED, verdict, { port, seal })).toBe("denied");
    expect(await recordVerdict(MEMBER, OLD_CRED, verdict, { port, seal })).toBe("denied");
    expect(await port.passkeyAttestationFlags({ userId: OTHER })).toEqual([]);
  });

  it("the envelope opens only for its own credential", async () => {
    const r = await db.query<{ envelope: Uint8Array }>("select envelope from vault_enclave.passkey_attestations where credential_id = $1", [CRED]);
    const env = r.rows[0]!.envelope;
    const plain = JSON.parse(new TextDecoder().decode(await openPasskeyAttestation(CRED, env, { port, kek })));
    expect(plain.verdict.certifiedL3).toBe(true);
    await expect(openPasskeyAttestation(OLD_CRED, env, { port, kek })).rejects.toThrow();
  });

  it("rows are immutable and certified needs attested + safe", async () => {
    await expect(db.exec(`update vault_enclave.passkey_attestations set certified_l3 = false`)).rejects.toThrow();
  });

  it("rollback refuses while verdicts exist", async () => {
    await expect(db.exec(`begin;\n${ROLLBACK}\n;commit;`)).rejects.toThrow(/not empty|immutable/);
    await db.exec("rollback").catch(() => undefined);
  });
});
