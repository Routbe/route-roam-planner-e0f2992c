/**
 * Glue between the auth route and the Stap 5 attestation engine. Every step is
 * best effort: a failure is logged (codes only, never key material) and the
 * registration that already succeeded stays untouched.
 */
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { PASSKEY_ATTESTATION_FORMATS, type IVaultPort } from "@/lib/vault/vault-port.server";
import type { AttestationVerdict } from "./passkey-attestation.server";

export const ATTESTATION_BUDGET_MS = 8_000;

type Fmt = (typeof PASSKEY_ATTESTATION_FORMATS)[number];
const fmtOf = (f: string): Fmt => ((PASSKEY_ATTESTATION_FORMATS as readonly string[]).includes(f) ? (f as Fmt) : "unknown");

/** Runs the engine within a time budget; a slow MDS3 download becomes "mds_unavailable". */
export async function verdictWithinBudget(response: RegistrationResponseJSON, budgetMs = ATTESTATION_BUDGET_MS): Promise<AttestationVerdict> {
  const { verifyPasskeyAttestation } = await import("./passkey-attestation.server");
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<AttestationVerdict>((resolve) => {
    timer = setTimeout(() => resolve({ attested: false, fmt: "unknown", aaguid: null, reason: "mds_unavailable", statusSafe: null }), budgetMs);
  });
  try {
    return await Promise.race([verifyPasskeyAttestation(response), timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/** Seals the verdict (RVE1 pak) and records it for the caller's own fresh passkey. */
export async function recordVerdict(
  callerId: string,
  credentialId: string,
  verdict: AttestationVerdict,
  deps: { port?: IVaultPort; seal?: (caller: { userId: string }, credentialId: string, plaintext: Uint8Array) => Promise<Uint8Array> } = {},
): Promise<"recorded" | "unavailable" | "no_kek" | "denied" | "error"> {
  const plaintext = new TextEncoder().encode(JSON.stringify({ v: 1, verdict }));
  try {
    const { vaultPort } = await import("@/lib/vault/vault-port.server");
    const port = deps.port ?? vaultPort();
    if (!(await port.passkeyAttestationAvailable())) return "unavailable";
    let envelope: Uint8Array;
    try {
      const seal = deps.seal ?? (await import("@/lib/vault/server-vault.server")).sealPasskeyAttestation;
      envelope = await seal({ userId: callerId }, credentialId, plaintext);
    } catch (err) {
      if (err instanceof Error && err.name === "VaultKekMissingError") return "no_kek";
      throw err;
    }
    const ok = await port.recordPasskeyAttestation({ userId: callerId }, {
      credentialId,
      fmt: fmtOf(verdict.fmt),
      attested: verdict.attested,
      statusSafe: verdict.statusSafe,
      certifiedL3: verdict.attested ? verdict.certifiedL3 : false,
      envelope,
    });
    return ok ? "recorded" : "denied";
  } catch (err) {
    console.error("[attestation] record failed", err instanceof Error ? err.name : "error");
    return "error";
  } finally {
    plaintext.fill(0);
  }
}
