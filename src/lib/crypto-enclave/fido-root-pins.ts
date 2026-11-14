/**
 * SHA-256 pins (DER) of every trust anchor Stap 5 accepts outside MDS3, and
 * the one place that installs them into @simplewebauthn/server's
 * SettingsService. A root whose bytes do not hash to its pin is refused, so a
 * dependency update can never swap a trust anchor silently.
 */
import { SettingsService } from "@simplewebauthn/server";
import { Apple_WebAuthn_Root_CA, Google_Hardware_Attestation_Roots, GlobalSign_Root_CA_R3 } from "./fido-mds3-roots";
import { pemSha256Hex } from "./fido-pem";

export const ROOT_PINS = Object.freeze({
  mds: ["cbb522d7b7f127ad6a0113865bdf1cd4102e7d0759af635a7cf4720dc963c53b"],
  apple: ["0915dd5c07a28db549d1f677bb5a75d4bfbe9561a773424327762e9e02f9bb29"],
  "android-key": [
    "c1984a3ef45c1e2a918551de10603c86f7051b2249c4891cae3230eabd0c97d5",
    "1ef1a04b8ba58ab94589ac498c8982a783f24ea7307e0159a0c3a73b377d87cc",
    "ab6641178a36e179aa0c1cdddf9a16eb45fa20943e2b8cd7c7c05c26cf8b487a",
    "cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc",
  ],
} as const);

export const PINNED_ROOTS = Object.freeze({
  mds: [GlobalSign_Root_CA_R3],
  apple: [Apple_WebAuthn_Root_CA],
  "android-key": [...Google_Hardware_Attestation_Roots],
});

export class RootPinError extends Error {
  constructor(public readonly identifier: string) {
    super(`root_pin_mismatch:${identifier}`);
    this.name = "RootPinError";
  }
}

/** Verifies every pinned root against its pin, then installs exactly those roots. */
export function installPinnedAttestationRoots(): void {
  for (const id of ["mds", "apple", "android-key"] as const) {
    const pems = PINNED_ROOTS[id];
    const hashes = pems.map(pemSha256Hex).sort();
    const pins = [...ROOT_PINS[id]].sort();
    if (hashes.length !== pins.length || hashes.some((h, i) => h !== pins[i])) throw new RootPinError(id);
    SettingsService.setRootCertificates({ identifier: id, certificates: [...pems] });
  }
  // No generic roots for packed / tpm / fido-u2f: those chain only to the MDS3 statement's own roots.
  for (const id of ["packed", "tpm", "fido-u2f", "android-safetynet"] as const) SettingsService.setRootCertificates({ identifier: id, certificates: [] });
}
