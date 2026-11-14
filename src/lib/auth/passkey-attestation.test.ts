import { describe, expect, it } from "vitest";
import { isoBase64URL, isoCBOR } from "@simplewebauthn/server/helpers";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { certificationOf, isCertifiedL3, statusSafe, stripAttestation, verifyPasskeyAttestation } from "./passkey-attestation.server";
import type { Mds3Entry } from "@/lib/crypto-enclave/fido-mds3";
import { installPinnedAttestationRoots, ROOT_PINS, PINNED_ROOTS } from "@/lib/crypto-enclave/fido-root-pins";
import { pemSha256Hex } from "@/lib/crypto-enclave/fido-pem";
import { checkBlobHeader, verifyMds3Blob } from "@/lib/crypto-enclave/fido-mds3";

const AAGUID = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
function authData(aaguid = AAGUID): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(32 + 1 + 4 + 16 + 2 + 16 + 1);
  out[32] = 0x45; // UP | UV | AT
  out.set(aaguid, 37);
  out[54] = 16;
  out.set(new Uint8Array(16).fill(9), 55);
  out[71] = 0xa0; // empty COSE map, enough for decoding fmt/aaguid
  return out;
}
function reg(fmt: string, attStmt: Map<string, unknown>, ad = authData()): RegistrationResponseJSON {
  const obj = isoCBOR.encode(new Map<string, unknown>([["fmt", fmt], ["attStmt", attStmt], ["authData", ad]]) as never);
  return {
    id: "AAAAAAAAAAAAAAAAAAAAAA",
    rawId: "AAAAAAAAAAAAAAAAAAAAAA",
    type: "public-key",
    clientExtensionResults: {},
    response: { clientDataJSON: isoBase64URL.fromUTF8String('{"type":"webauthn.create","challenge":"x","origin":"https://rout.be"}'), attestationObject: isoBase64URL.fromBuffer(obj) },
  };
}
const entry = (over: Partial<Mds3Entry["statement"]>, reports: Mds3Entry["statusReports"] = []): Mds3Entry => ({ aaguid: "x", statement: { keyProtection: ["hardware", "secure_element"], ...over }, statusReports: reports });

describe("Stap 5: attestation verdicts never block and never over-claim", () => {
  it("fmt none (iCloud/Google sync) is not attested", async () => {
    const v = await verifyPasskeyAttestation(reg("none", new Map()), { snapshot: null });
    expect(v).toMatchObject({ attested: false, reason: "no_attestation" });
  });
  it("packed self attestation (no x5c) never counts", async () => {
    const v = await verifyPasskeyAttestation(reg("packed", new Map<string, unknown>([["alg", -7], ["sig", new Uint8Array(8)]])), { snapshot: null });
    expect(v).toMatchObject({ attested: false, reason: "self_attestation" });
  });
  it("packed with x5c but MDS3 unavailable is not attested", async () => {
    const v = await verifyPasskeyAttestation(reg("packed", new Map<string, unknown>([["alg", -7], ["sig", new Uint8Array(8)], ["x5c", [new Uint8Array(4)]]])), { snapshot: null });
    expect(v).toMatchObject({ attested: false, reason: "mds_unavailable" });
  });
  it("unknown formats and garbage are not attested", async () => {
    expect(await verifyPasskeyAttestation(reg("fido-u2f", new Map()), { snapshot: null })).toMatchObject({ attested: false, reason: "unsupported_format" });
    const bad = reg("none", new Map());
    expect(await verifyPasskeyAttestation({ ...bad, response: { ...bad.response, attestationObject: "AAAA" } })).toMatchObject({ attested: false, reason: "malformed" });
  });
  it("a forged packed statement with an MDS3 entry fails verification instead of passing", async () => {
    const aaguid = "01020304-0506-0708-090a-0b0c0d0e0f10";
    const e = { ...entry({ aaguid, attestationTypes: ["basic_full"], attestationRootCertificates: [] }), aaguid };
    const snapshot = { no: 1, nextUpdate: "2099-01-01", verifiedAt: 0, entries: new Map([[aaguid, e]]), statements: [e.statement] };
    const v = await verifyPasskeyAttestation(reg("packed", new Map<string, unknown>([["alg", -7], ["sig", new Uint8Array(8)], ["x5c", [new Uint8Array(4)]]])), { snapshot });
    expect(v).toMatchObject({ attested: false, reason: "verification_failed" });
  });
  it("stripAttestation keeps authData byte for byte and sets fmt none", async () => {
    const r = reg("packed", new Map<string, unknown>([["alg", -7], ["x5c", [new Uint8Array(4)]]]));
    const s = (await stripAttestation(r))!;
    const { decodeAttestationObject } = await import("@simplewebauthn/server/helpers");
    const a = decodeAttestationObject(isoBase64URL.toBuffer(s.response.attestationObject));
    expect(a.get("fmt")).toBe("none");
    expect([...(a.get("attStmt") as unknown as Map<string, unknown>).keys()]).toEqual([]);
    expect(isoBase64URL.fromBuffer(new Uint8Array(a.get("authData")))).toBe(isoBase64URL.fromBuffer(new Uint8Array(authData())));
    expect(s.response.clientDataJSON).toBe(r.response.clientDataJSON);
  });
});

describe("Stap 5: MDS3 status and certification", () => {
  it("any compromise or revocation is unsafe, even when a later report follows", () => {
    expect(statusSafe([{ status: "FIDO_CERTIFIED_L2" }])).toBe(true);
    for (const s of ["REVOKED", "USER_VERIFICATION_BYPASS", "ATTESTATION_KEY_COMPROMISE", "USER_KEY_REMOTE_COMPROMISE", "USER_KEY_PHYSICAL_COMPROMISE"])
      expect(statusSafe([{ status: s }, { status: "UPDATE_AVAILABLE" }])).toBe(false);
  });
  it("certified L3 needs FIPS 140-3 level >= 3 or CC EAL >= 6; unknown is never certified", () => {
    expect(isCertifiedL3(certificationOf(entry({ authenticatorGetInfo: { certifications: { "FIPS-CMVP-3": 3 } } })))).toBe(true);
    expect(isCertifiedL3(certificationOf(entry({ authenticatorGetInfo: { certifications: { "CC-EAL": 6 } } })))).toBe(true);
    expect(isCertifiedL3(certificationOf(entry({ authenticatorGetInfo: { certifications: { "FIPS-CMVP-3": 2, "CC-EAL": 5 } } })))).toBe(false);
    expect(isCertifiedL3(certificationOf(entry({})))).toBe(false);
    expect(isCertifiedL3(certificationOf(null))).toBe(false);
  });
  it("the FIDO level is the latest certification report", () => {
    const c = certificationOf(entry({}, [{ status: "FIDO_CERTIFIED_L1", effectiveDate: "2020-01-01" }, { status: "FIDO_CERTIFIED_L2", effectiveDate: "2022-01-01" }]));
    expect(c.fido).toBe("FIDO_CERTIFIED_L2");
  });
});

describe("Stap 5: pinned trust anchors", () => {
  it("every pinned root hashes to its pin and installs", () => {
    for (const id of ["mds", "apple", "android-key"] as const) expect(PINNED_ROOTS[id].map(pemSha256Hex).sort()).toEqual([...ROOT_PINS[id]].sort());
    expect(() => installPinnedAttestationRoots()).not.toThrow();
  });
  it("an MDS3 BLOB under a swapped root is refused", async () => {
    await expect(verifyMds3Blob("a.b.c", { rootSha256: "00".repeat(32) })).rejects.toThrow();
  });
  it("the BLOB header refuses alg none and HS256", () => {
    const h = (o: object) => `${isoBase64URL.fromUTF8String(JSON.stringify(o))}.e30.sig`;
    expect(() => checkBlobHeader(h({ alg: "none", x5c: ["a"] }))).toThrow();
    expect(() => checkBlobHeader(h({ alg: "HS256", x5c: ["a"] }))).toThrow();
  });
});
