/**
 * Server side of recovery v4 (Stap 6): one call per step of
 * formal/recovery-v4/RecoveryV4.tla, each a single vault_enclave transaction
 * (db-pending/0272). The caller is always the signed-in member (`userId`);
 * the database takes it from the transaction context.
 *
 * Only two things here touch a key, both ROUT's own server factor:
 *   - commit: removes ROUT's commit layer from the pending root (the root stays
 *     sealed under the ceremony's generation key, which ROUT never holds);
 *   - releaseServerShare: opens ROUT's one share, after the database decided
 *     the release is safe or a fresh passkey step-up was consumed.
 */
import { wipe } from "@/lib/crypto/wipe";
import {
  commitPendingRoot,
  openShardV4,
  V4_FACTORS,
  type ActiveCeremonyV4,
  type StagedCeremonyV4,
  type V4Factor,
  type V4Policy,
} from "@/lib/crypto-enclave/recovery-v4";
import type { VaultSqlExecutor } from "@/lib/vault/vault-port.server";
import { withServerFactorV4SecretKey } from "./server-factor.server";

export type V4Why = "ok" | "conflict" | "busy" | "invalid" | "stepup" | "card" | "gone" | "malformed" | "idem_mismatch" | "no_caller";
export type V4Answer = { op: string; ok: boolean; why: V4Why; cid: string | null; ver: number | null; level: "none" | V4Policy | null; pend: string | null; act: string | null };
export type V4Status = {
  level: "none" | V4Policy;
  ver: number;
  generation: number;
  nextGeneration: number;
  compromised: V4Factor[];
  pending: { id: string; policy: V4Policy; expiresAt: string; cardConfirmed: boolean } | null;
  activeId: string | null;
};
export type V4Material = Omit<ActiveCeremonyV4, "sealedRoot"> & { kind: string; sealedRoot: Uint8Array | null; pendingRoot: Uint8Array | null };

const IDEM_RE = /^[A-Za-z0-9_-]{16,64}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const hx = (b: Uint8Array | null | undefined) => (b ? Buffer.from(b).toString("hex") : null);
const bx = (h: unknown) => (typeof h === "string" ? new Uint8Array(Buffer.from(h, "hex")) : null);

function answer(rows: readonly Record<string, unknown>[]): V4Answer {
  const a = rows[0]?.["a"] as V4Answer | undefined;
  if (!a || typeof a.ok !== "boolean") throw new Error("recovery_v4_no_answer");
  return { ...a, ver: a.ver === null ? null : Number(a.ver) };
}
function checkIdem(k: string) {
  if (!IDEM_RE.test(k)) throw new TypeError("idempotency_key_invalid");
}

export class RecoveryV4Store {
  constructor(private readonly exec: VaultSqlExecutor, private readonly serverSecret?: string) {}

  async status(userId: string): Promise<V4Status | null> {
    const rows = await this.exec(userId,
      "select level, ver::text as ver, generation, next_generation, compromised, pending_id::text as pending_id, pending_policy, to_json(pending_expires_at)#>>'{}' as pending_expires_at, pending_card_confirmed, active_id::text as active_id from vault_enclave.recovery_v4_status()", []);
    const r = rows[0];
    if (!r) return null;
    return {
      level: r["level"] as V4Status["level"],
      ver: Number(r["ver"]),
      generation: Number(r["generation"]),
      nextGeneration: Number(r["next_generation"]),
      compromised: (r["compromised"] as V4Factor[]) ?? [],
      pending: r["pending_id"] ? { id: String(r["pending_id"]), policy: r["pending_policy"] as V4Policy, expiresAt: String(r["pending_expires_at"]), cardConfirmed: Boolean(r["pending_card_confirmed"]) } : null,
      activeId: (r["active_id"] as string | null) ?? null,
    };
  }

  async begin(userId: string, idem: string, input: { ver: number; kind: "setup" | "upgrade" | "downgrade" | "rotate"; proofId: string | null; staged: StagedCeremonyV4 }): Promise<V4Answer> {
    checkIdem(idem);
    const s = input.staged;
    if (s.memberId !== userId) throw new TypeError("member_mismatch");
    return answer(await this.exec(userId,
      `select vault_enclave.recovery_v4_begin($1, $2::bigint, $3, $4, $5::uuid, $6::uuid, $7::int, decode($8, 'hex'),
         decode($9, 'hex'), decode($10, 'hex'), decode($11, 'hex'), decode($12, 'hex'),
         decode($13, 'hex'), decode($14, 'hex'), decode($15, 'hex'), decode($16, 'hex')) as a`,
      [idem, String(input.ver), input.kind, s.policy, input.proofId, s.ceremonyId, s.generation, hx(s.pendingRoot),
       hx(s.shards.user_kek), hx(s.shards.server), hx(s.shards.paper), hx(s.shards.card),
       hx(s.commitments.user_kek), hx(s.commitments.server), hx(s.commitments.paper), hx(s.commitments.card)]));
  }

  async confirmCard(userId: string, idem: string, ver: number, ceremonyId: string, tapRef: string): Promise<V4Answer> {
    checkIdem(idem);
    return answer(await this.exec(userId, "select vault_enclave.recovery_v4_confirm_card($1, $2::bigint, $3::uuid, $4) as a", [idem, String(ver), ceremonyId, tapRef]));
  }

  /** Removes ROUT's commit layer from the caller's pending root, then commits. */
  async commit(userId: string, idem: string, ver: number, ceremonyId: string, proofId: string | null): Promise<V4Answer> {
    checkIdem(idem);
    if (!UUID_RE.test(ceremonyId)) throw new TypeError("ceremony_id_invalid");
    const pending = await this.material(userId, true);
    let sealed: Uint8Array | null = null;
    if (pending && pending.ceremonyId === ceremonyId && pending.pendingRoot) {
      const staged = { v: 4, memberId: userId, ceremonyId, generation: pending.generation, policy: pending.policy, pendingRoot: pending.pendingRoot, shards: {}, commitments: {} } as StagedCeremonyV4;
      try {
        sealed = await withServerFactorV4SecretKey(userId, (sk) => commitPendingRoot(staged, sk).sealedRoot, this.serverSecret);
      } catch {
        sealed = null;
      }
    }
    try {
      return answer(await this.exec(userId, "select vault_enclave.recovery_v4_commit($1, $2::bigint, $3::uuid, $4::uuid, decode($5, 'hex')) as a", [idem, String(ver), ceremonyId, proofId, hx(sealed)]));
    } finally {
      wipe(sealed);
    }
  }

  async abort(userId: string, idem: string, ceremonyId: string): Promise<V4Answer> {
    checkIdem(idem);
    return answer(await this.exec(userId, "select vault_enclave.recovery_v4_abort($1, $2::uuid) as a", [idem, ceremonyId]));
  }

  async remove(userId: string, idem: string, ver: number, proofId: string | null): Promise<V4Answer> {
    checkIdem(idem);
    return answer(await this.exec(userId, "select vault_enclave.recovery_v4_remove($1, $2::bigint, $3::uuid) as a", [idem, String(ver), proofId]));
  }

  async reportCompromise(userId: string, idem: string, factor: Exclude<V4Factor, "server">): Promise<V4Answer> {
    checkIdem(idem);
    return answer(await this.exec(userId, "select vault_enclave.recovery_v4_report_compromise($1, $2) as a", [idem, factor]));
  }

  /** The caller's ceremony material (ciphertext and public values; never ROUT's share). */
  async material(userId: string, pending: boolean): Promise<V4Material | null> {
    const rows = await this.exec(userId,
      `select ceremony_id::text as id, kind, policy, generation, encode(sealed_root, 'hex') as sealed, encode(pending_root, 'hex') as pending,
              encode(shard_user_kek, 'hex') as s_user_kek, encode(shard_paper, 'hex') as s_paper, encode(shard_card, 'hex') as s_card,
              encode(commit_user_kek, 'hex') as c_user_kek, encode(commit_server, 'hex') as c_server, encode(commit_paper, 'hex') as c_paper, encode(commit_card, 'hex') as c_card
         from vault_enclave.recovery_v4_material($1)`, [pending]);
    const r = rows[0];
    if (!r) return null;
    const shards: Partial<Record<V4Factor, Uint8Array>> = {};
    const commitments: Partial<Record<V4Factor, Uint8Array>> = {};
    for (const f of V4_FACTORS) {
      const sh = bx(r[`s_${f}`]);
      const c = bx(r[`c_${f}`]);
      if (sh) shards[f] = sh;
      if (c) commitments[f] = c;
    }
    return { v: 4, memberId: userId, ceremonyId: String(r["id"]), kind: String(r["kind"]), policy: r["policy"] as V4Policy, generation: Number(r["generation"]), sealedRoot: bx(r["sealed"]), pendingRoot: bx(r["pending"]), shards, commitments };
  }

  /**
   * ROUT's share of the active ceremony for a server-assisted recovery
   * (x || y, caller wipes), or a refusal. `exclude` are the shares the client
   * must not combine with it.
   */
  async releaseServerShare(userId: string, proofId: string | null): Promise<{ granted: true; ceremonyId: string; share: Uint8Array; exclude: V4Factor[] } | { granted: false; reason: string; exclude: V4Factor[] }> {
    const rows = await this.exec(userId, "select granted, reason, ceremony_id::text as id, generation, policy, encode(shard, 'hex') as shard, exclude from vault_enclave.recovery_v4_server_share($1::uuid)", [proofId]);
    const r = rows[0];
    const exclude = ((r?.["exclude"] as V4Factor[] | null) ?? []).slice();
    if (!r || r["granted"] !== true) return { granted: false, reason: String(r?.["reason"] ?? "denied"), exclude };
    const env = bx(r["shard"]);
    if (!env) return { granted: false, reason: "denied", exclude };
    const c = { v: 4, memberId: userId, ceremonyId: String(r["id"]), generation: Number(r["generation"]), policy: r["policy"] as V4Policy, shards: { server: env }, commitments: {}, sealedRoot: new Uint8Array(0) } as ActiveCeremonyV4;
    const share = await withServerFactorV4SecretKey(userId, (sk) => openShardV4(c, "server", sk), this.serverSecret);
    return { granted: true, ceremonyId: c.ceremonyId, share, exclude };
  }

  /** Cron: ends pending ceremonies past their TTL. */
  async expireDue(): Promise<number> {
    const rows = await this.exec("", "select vault_enclave.recovery_v4_expire_due() as n", []);
    return Number(rows[0]?.["n"] ?? 0);
  }
}
