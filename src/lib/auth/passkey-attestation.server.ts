/**
 * Stap 5 — hardware attestation engine for WebAuthn passkey registrations.
 *
 * Input: the browser's RegistrationResponseJSON as received, before Better Auth
 * sees it. Output: a strict verdict; this module NEVER throws to the caller and
 * never rejects a registration (owner invariant "niemand blokkeren"). The
 * registration itself is verified independently by @better-auth/passkey on the
 * same clientDataJSON, so challenge, origin and RP ID binding stay enforced there;
 * a verdict is only persisted when that verification succeeded.
 *
 * What counts as hardware_attested (all must hold):
 *  1. fmt is packed with x5c (self attestation never counts), tpm, apple or
 *     android-key; the statement signature over authData || SHA-256(clientDataJSON)
 *     verifies (simplewebauthn's per-format verifiers: TCG SAN 2.23.133.2.1/2/3 and
 *     AIK EKU 2.23.133.8.3 for TPM, AAGUID cert extension 1.3.6.1.4.1.45724.1.1.4 for
 *     packed, nonce extension for Apple, key description challenge for Android).
 *  2. The x5c chain validates to a trust anchor: the MDS3 statement's own
 *     attestationRootCertificates (packed, tpm, android-key with a statement), or a
 *     pinned root (Apple WebAuthn Root CA; Google Hardware Attestation Roots).
 *  3. packed / tpm need an MDS3 entry for the AAGUID whose keyProtection names
 *     hardware / secure_element / tee and never software.
 *  4. android-key additionally needs its KeyDescription security levels and
 *     RootOfTrust checked; that parser is not wired yet, so android-key reports
 *     `android_levels_unverified` and is never attested (honest, not blocking).
 *
 * statusSafe: false as soon as MDS3 lists any compromise or revocation for the
 * AAGUID. A later report does not clear it: it cannot prove this device got the fix.
 *
 * certification: exact FIPS 140-3 (CMVP) and CC EAL levels from the MDS3
 * authenticatorGetInfo.certifications member (CTAP 2.2), and the FIDO level from
 * the latest FIDO_CERTIFIED_* report. certifiedL3 = attested AND statusSafe AND
 * (FIPS 140-3 level >= 3 OR CC EAL >= 6). Unknown is never "certified".
 */
import { z } from "zod";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { lookupAaguid, mds3, type Mds3Cache, type Mds3Entry, type Mds3Snapshot, type Mds3StatusReport } from "@/lib/crypto-enclave/fido-mds3";

export const ZERO_AAGUID = "00000000-0000-0000-0000-000000000000";
export const ATTESTED_FORMATS = ["packed", "tpm", "apple", "android-key"] as const;
export type AttestedFormat = (typeof ATTESTED_FORMATS)[number];

/** MDS3 statuses that make an authenticator unsafe (FIDO MDS3 §3.1.4). */
export const UNSAFE_STATUSES = new Set([
  "REVOKED",
  "USER_VERIFICATION_BYPASS",
  "ATTESTATION_KEY_COMPROMISE",
  "USER_KEY_REMOTE_COMPROMISE",
  "USER_KEY_PHYSICAL_COMPROMISE",
]);
const FIDO_LEVELS = ["FIDO_CERTIFIED_L1", "FIDO_CERTIFIED_L1plus", "FIDO_CERTIFIED_L2", "FIDO_CERTIFIED_L2plus", "FIDO_CERTIFIED_L3", "FIDO_CERTIFIED_L3plus"] as const;
const HW_PROTECTION = new Set(["hardware", "secure_element", "tee"]);

export const CertificationSchema = z.object({
  fips140: z.number().int().min(1).max(4).nullable(),
  fipsPhysical: z.number().int().min(1).max(4).nullable(),
  ccEal: z.number().int().min(1).max(7).nullable(),
  fido: z.enum(FIDO_LEVELS).nullable(),
});
export type Certification = z.infer<typeof CertificationSchema>;

export const AttestationVerdictSchema = z.discriminatedUnion("attested", [
  z.object({
    attested: z.literal(true),
    fmt: z.enum(ATTESTED_FORMATS),
    aaguid: z.string().regex(/^[0-9a-f-]{36}$/),
    description: z.string().max(200).nullable(),
    certification: CertificationSchema,
    statusSafe: z.boolean(),
    certifiedL3: z.boolean(),
    mdsNo: z.number().int().nullable(),
  }),
  z.object({
    attested: z.literal(false),
    fmt: z.string().max(32),
    aaguid: z.string().max(36).nullable(),
    reason: z.enum([
      "no_attestation",
      "self_attestation",
      "unsupported_format",
      "zero_aaguid",
      "mds_unavailable",
      "unknown_aaguid",
      "software_key",
      "android_levels_unverified",
      "verification_failed",
      "malformed",
    ]),
    statusSafe: z.boolean().nullable(),
  }),
]);
export type AttestationVerdict = z.infer<typeof AttestationVerdictSchema>;

/** Latest-first is irrelevant for safety: any unsafe report marks the AAGUID unsafe. */
export function statusSafe(reports: readonly Mds3StatusReport[]): boolean {
  return !reports.some((r) => UNSAFE_STATUSES.has(r.status));
}

function latestFidoLevel(reports: readonly Mds3StatusReport[]): Certification["fido"] {
  const dated = reports
    .filter((r): r is Mds3StatusReport & { status: (typeof FIDO_LEVELS)[number] } => (FIDO_LEVELS as readonly string[]).includes(r.status))
    .map((r) => ({ r, t: r.effectiveDate ? Date.parse(r.effectiveDate) : 0 }))
    .sort((a, b) => b.t - a.t);
  return dated[0]?.r.status ?? null;
}

const lvl = (v: unknown, max: number): number | null => (typeof v === "number" && Number.isInteger(v) && v >= 1 && v <= max ? v : null);

/** Exact levels from MDS3; absent fields stay null (never assumed). */
export function certificationOf(entry: Mds3Entry | null): Certification {
  const c = entry?.statement.authenticatorGetInfo?.certifications ?? {};
  const fips = Math.max(lvl(c["FIPS-CMVP-3"], 4) ?? 0, lvl(c["FIPS-CMVP-2"], 4) ?? 0);
  const phys = Math.max(lvl(c["FIPS-CMVP-3-PHY"], 4) ?? 0, lvl(c["FIPS-CMVP-2-PHY"], 4) ?? 0);
  return {
    fips140: fips || null,
    fipsPhysical: phys || null,
    ccEal: lvl(c["CC-EAL"], 7),
    fido: entry ? latestFidoLevel(entry.statusReports) : null,
  };
}

export function isCertifiedL3(c: Certification): boolean {
  return (c.fips140 ?? 0) >= 3 || (c.ccEal ?? 0) >= 6;
}

function hardwareProtected(entry: Mds3Entry): boolean {
  const kp = entry.statement.keyProtection ?? [];
  return kp.length > 0 && !kp.includes("software") && kp.some((k) => HW_PROTECTION.has(k));
}

type Decoded = { fmt: string; hasX5c: boolean; aaguid: string | null };

async function decode(response: RegistrationResponseJSON): Promise<Decoded | null> {
  try {
    const { decodeAttestationObject, parseAuthenticatorData, isoBase64URL, convertAAGUIDToString } = await import("@simplewebauthn/server/helpers");
    const att = decodeAttestationObject(isoBase64URL.toBuffer(response.response.attestationObject));
    const fmt = att.get("fmt");
    const stmt = att.get("attStmt");
    const auth = parseAuthenticatorData(att.get("authData"));
    if (typeof fmt !== "string") return null;
    return { fmt, hasX5c: Array.isArray(stmt?.get("x5c")) && stmt.get("x5c")!.length > 0, aaguid: auth.aaguid ? convertAAGUIDToString(auth.aaguid) : null };
  } catch {
    return null;
  }
}

let metadataForNo: number | null = null;
async function loadMetadata(snapshot: Mds3Snapshot): Promise<void> {
  if (metadataForNo === snapshot.no) return;
  const { MetadataService } = await import("@simplewebauthn/server");
  // Statements only (already verified by fido-mds3); no network fetch by the library.
  await MetadataService.initialize({ mdsServers: [], statements: snapshot.statements as never, verificationMode: "permissive" });
  metadataForNo = snapshot.no;
}

export type AttestationDeps = { cache?: Mds3Cache; snapshot?: Mds3Snapshot | null };

/** Never throws; every failure is a not-attested verdict. */
export async function verifyPasskeyAttestation(response: RegistrationResponseJSON, deps: AttestationDeps = {}): Promise<AttestationVerdict> {
  const d = await decode(response);
  if (!d) return { attested: false, fmt: "unknown", aaguid: null, reason: "malformed", statusSafe: null };
  const base = { fmt: d.fmt.slice(0, 32), aaguid: d.aaguid };
  if (d.fmt === "none") return { attested: false, ...base, reason: "no_attestation", statusSafe: null };
  if (!(ATTESTED_FORMATS as readonly string[]).includes(d.fmt)) return { attested: false, ...base, reason: "unsupported_format", statusSafe: null };
  const fmt = d.fmt as AttestedFormat;
  if (fmt === "packed" && !d.hasX5c) return { attested: false, ...base, reason: "self_attestation", statusSafe: null };
  if (!d.aaguid || d.aaguid === ZERO_AAGUID) {
    if (fmt !== "apple") return { attested: false, ...base, reason: "zero_aaguid", statusSafe: null };
  }

  let snapshot: Mds3Snapshot | null;
  try {
    snapshot = deps.snapshot !== undefined ? deps.snapshot : await (deps.cache ?? mds3()).current();
  } catch {
    snapshot = null;
  }
  // Apple anonymous attestation is not in MDS3: it rests on the pinned Apple root only.
  if (!snapshot && fmt !== "apple") return { attested: false, ...base, reason: "mds_unavailable", statusSafe: null };
  const entry = d.aaguid && d.aaguid !== ZERO_AAGUID ? lookupAaguid(snapshot, d.aaguid) : null;
  const safe = entry ? statusSafe(entry.statusReports) : null;
  if ((fmt === "packed" || fmt === "tpm") && !entry) return { attested: false, ...base, reason: "unknown_aaguid", statusSafe: safe };
  if (entry && (fmt === "packed" || fmt === "tpm") && !hardwareProtected(entry)) return { attested: false, ...base, reason: "software_key", statusSafe: safe };

  try {
    const { installPinnedAttestationRoots } = await import("@/lib/crypto-enclave/fido-root-pins");
    installPinnedAttestationRoots();
    if (snapshot) await loadMetadata(snapshot);
    const { verifyRegistrationResponse } = await import("@simplewebauthn/server");
    const { decodeClientDataJSON } = await import("@simplewebauthn/server/helpers");
    const origin = decodeClientDataJSON(response.response.clientDataJSON).origin;
    const result = await verifyRegistrationResponse({
      response,
      // Binding is enforced by Better Auth on this same clientDataJSON; here only the statement counts.
      expectedChallenge: () => true,
      expectedOrigin: origin,
      requireUserVerification: false,
    });
    if (!result.verified) return { attested: false, ...base, reason: "verification_failed", statusSafe: safe };
  } catch {
    return { attested: false, ...base, reason: "verification_failed", statusSafe: safe };
  }
  if (fmt === "android-key") return { attested: false, ...base, reason: "android_levels_unverified", statusSafe: safe };

  const certification = certificationOf(entry);
  const isSafe = safe ?? true;
  const verdict: AttestationVerdict = {
    attested: true,
    fmt,
    aaguid: (d.aaguid ?? ZERO_AAGUID).toLowerCase(),
    description: typeof entry?.statement.description === "string" ? entry.statement.description.slice(0, 200) : null,
    certification,
    statusSafe: isSafe,
    certifiedL3: isSafe && isCertifiedL3(certification),
    mdsNo: snapshot?.no ?? null,
  };
  return AttestationVerdictSchema.parse(verdict);
}

/** Same registration with the statement removed (fmt none), so Better Auth's own check can never fail on it. */
export async function stripAttestation(response: RegistrationResponseJSON): Promise<RegistrationResponseJSON | null> {
  try {
    const { decodeAttestationObject, isoBase64URL, isoCBOR } = await import("@simplewebauthn/server/helpers");
    const att = decodeAttestationObject(isoBase64URL.toBuffer(response.response.attestationObject));
    const authData = att.get("authData");
    if (!(authData instanceof Uint8Array)) return null;
    const none = new Map<string, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]);
    const encoded = isoCBOR.encode(none as never);
    return { ...response, response: { ...response.response, attestationObject: isoBase64URL.fromBuffer(encoded) } };
  } catch {
    return null;
  }
}
