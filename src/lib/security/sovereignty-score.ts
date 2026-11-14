/**
 * Veiligheidsschild (Sovereignty Health Score): the member's own protection level,
 * computed from the factors that actually exist right now. Pure, so every rule is
 * testable and nothing is stored that could drift from the real factors.
 *
 * Informational only: no access decision may ever read this score. Step-up proofs
 * stay the sole gate for sensitive actions.
 *
 * Owner decisions (2026-11-14):
 *  - Level 3 needs an active ROUT Card AND a passkey (decision A). A card next to
 *    only a password stays level 1, with a hint to add a passkey.
 *  - A frozen card suspends level 3 (decision B): back to 2 (or 1) with a notice.
 *  - Stap 5 (owner decision 2026-11-14, Level 9): level 3 needs an active card AND a
 *    passkey whose FIDO MDS3 attestation proves certified hardware (FIPS 140-3 L3+ or
 *    CC EAL6+) and that MDS3 does not list as compromised. An attested but uncertified
 *    key, or no attestation at all (iCloud/Google sync), stays level 2 and keeps working.
 *  - A key MDS3 lists as compromised is shown as unsafe; it never blocks anything.
 */

export type ShieldLevel = 1 | 2 | 3;

/** Lifecycle state of the member's root card serial; null = no root card to check. */
export type CardShieldState = "active" | "frozen" | "blocked" | "unavailable" | null;

/** Raw facts; null means the lookup failed and the fact is unknown. */
export interface SovereigntyFacts {
  /** OPAQUE registration in vault_enclave.pake_registrations. */
  password: boolean | null;
  /** neon_auth.passkey rows of this member. */
  passkeys: { count: number; deviceBound: boolean; synced: boolean } | null;
  /** Activated, unrevoked physical ROUT Card (vault_enclave.member_card_factor). */
  card: boolean | null;
  cardState: CardShieldState;
  /** Stap 5 verdict per passkey (oldest first); null = lookup failed. */
  passkeyMarks: readonly PasskeyMark[] | null;
}

/** certified = attested + safe + FIPS 140-3 L3+/CC EAL6+; unsafe = listed as compromised by MDS3. */
export type KeyMark = "certified" | "attested" | "unsafe" | "unattested";
export type PasskeyMark = { name: string | null; mark: KeyMark };

export type ShieldNotice = "card_frozen" | "card_needs_passkey" | "card_status_unknown" | "card_needs_certified_key" | "key_unsafe" | "key_status_unknown";
export type ShieldNextStep = "add_passkey" | "add_card" | "unfreeze_card" | "add_certified_key";
export type PasskeyStorage = "device" | "synced" | "mixed";

export interface SovereigntyHealthScore {
  /** null = unknown: the shield claims no level at all. */
  level: ShieldLevel | null;
  factors: { password: boolean | null; passkey: boolean | null; card: "active" | "frozen" | "none" | "unknown" };
  passkeyStorage: PasskeyStorage | null;
  notices: ShieldNotice[];
  nextStep: ShieldNextStep | null;
  /** Per-passkey hardware marks for the panel; null = unknown. */
  keyMarks: readonly PasskeyMark[] | null;
}

function storageOf(p: NonNullable<SovereigntyFacts["passkeys"]>): PasskeyStorage | null {
  if (p.count <= 0) return null;
  if (p.deviceBound && p.synced) return "mixed";
  if (p.synced) return "synced";
  return p.deviceBound ? "device" : null;
}

export function getSovereigntyHealthScore(facts: SovereigntyFacts): SovereigntyHealthScore {
  const passkey = facts.passkeys === null ? null : facts.passkeys.count > 0;
  const owned = facts.card === true;
  const cardActive = owned && facts.cardState === "active";
  // A blocked card is revoked in the vault too; if a race still reports it, it counts as suspended.
  const cardSuspended = owned && (facts.cardState === "frozen" || facts.cardState === "blocked");
  const cardUnknown = facts.card === null || (owned && (facts.cardState === "unavailable" || facts.cardState === null));
  const card: SovereigntyHealthScore["factors"]["card"] = cardActive ? "active" : cardSuspended ? "frozen" : cardUnknown ? "unknown" : "none";

  const marks = passkey === true ? facts.passkeyMarks : passkey === false ? [] : null;
  const certifiedKey = marks?.some((m) => m.mark === "certified") === true;

  let level: ShieldLevel | null = null;
  if (passkey === true && cardActive && certifiedKey) level = 3;
  else if (passkey === true) level = 2;
  else if (passkey === false && facts.password === true) level = 1;

  const notices: ShieldNotice[] = [];
  if (level !== null) {
    if (owned && facts.cardState === "frozen") notices.push("card_frozen");
    if (cardActive && passkey === false) notices.push("card_needs_passkey");
    if (cardUnknown && level < 3) notices.push("card_status_unknown");
    if (cardActive && passkey === true && marks !== null && !certifiedKey) notices.push("card_needs_certified_key");
    if (passkey === true && marks === null) notices.push("key_status_unknown");
    if (marks?.some((m) => m.mark === "unsafe")) notices.push("key_unsafe");
  }

  let nextStep: ShieldNextStep | null = null;
  if (level === 1) nextStep = "add_passkey";
  else if (level === 2) {
    nextStep = card === "frozen" && facts.cardState === "frozen" ? "unfreeze_card"
      : card === "none" ? "add_card"
      : cardActive && marks !== null && !certifiedKey ? "add_certified_key"
      : null;
  }

  return {
    level,
    factors: { password: facts.password, passkey, card },
    passkeyStorage: facts.passkeys ? storageOf(facts.passkeys) : null,
    notices,
    nextStep,
    keyMarks: marks,
  };
}

export type ShieldChangeReason = "passkey_removed" | "card_frozen" | "card_removed" | "factor_removed";

/** Maps one stored verdict to its mark; no verdict is "unattested", never more. */
export function keyMarkOf(flags: { attested: boolean; statusSafe: boolean | null; certifiedL3: boolean } | null): KeyMark {
  if (!flags) return "unattested";
  if (flags.statusSafe === false) return "unsafe";
  if (!flags.attested) return "unattested";
  return flags.certifiedL3 && flags.statusSafe === true ? "certified" : "attested";
}
export type ShieldChange = { direction: "up"; level: ShieldLevel } | { direction: "down"; level: ShieldLevel; reason: ShieldChangeReason };

/** What changed between two readings of the same member; null when the level did not move or is unknown. */
export function shieldChange(prev: SovereigntyHealthScore, next: SovereigntyHealthScore): ShieldChange | null {
  if (prev.level === null || next.level === null || prev.level === next.level) return null;
  if (next.level > prev.level) return { direction: "up", level: next.level };
  let reason: ShieldChangeReason = "factor_removed";
  if (prev.factors.passkey === true && next.factors.passkey === false) reason = "passkey_removed";
  else if (prev.factors.card === "active" && next.factors.card === "frozen") reason = "card_frozen";
  else if (prev.factors.card === "active" && next.factors.card === "none") reason = "card_removed";
  return { direction: "down", level: next.level, reason };
}
