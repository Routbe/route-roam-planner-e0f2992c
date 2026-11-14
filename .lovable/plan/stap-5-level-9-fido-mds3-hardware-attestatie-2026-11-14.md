# Stap 5 (Level 9) — FIDO MDS3 hardware-attestatie

Doel: bij het registreren van een passkey cryptografisch bewijzen of die uit echte, niet-gecompromitteerde en gecertificeerde hardware komt, zonder ooit iemand te weigeren. Migraties komen alleen in `db-pending/`. Er gaat niets naar Neon zonder jouw aparte GO.

## Wat ik al gecontroleerd heb
- `@better-auth/passkey` zet vast `attestationType: "none"`. De browser stuurt nu dus nooit een attestatie mee.
- De plugin geeft het volledige `verification`-object (attestationObject, fmt, aaguid) door aan onze `registration.afterVerification` in `better-auth.server.ts`. Daar haken we in.
- `neon_auth.passkey` op Neon heeft geen attestatiekolommen.
- `sovereignty-shield.server.ts` geeft altijd `attestedKey: false`. `sovereignty-score.ts` geeft nu niveau 3 bij passkey plus (actieve kaart **of** attestatie).
- In het project zitten al `@simplewebauthn/server` 13 en de ASN.1/X.509-bibliotheken `@peculiar/asn1-schema`, `asn1-x509` en `asn1-android`. De TPM-controle van simplewebauthn gebruikt de TCG-OID's 2.23.133.2.1, 2 en 3 en de EKU 2.23.133.8.3.

## Aanpassingen op jouw Level-9-opdracht (met eerlijke kanttekeningen)
1. **Niveau 3 = gecertificeerde, geattesteerde hardware-passkey ÉN een actieve NXP ROUT Card**, zoals jij vraagt. Dit vervangt de huidige "kaart **of** attestatie". Gevolg: wie nu alleen een kaart heeft, zakt naar niveau 2 tot er een geattesteerde sleutel bij komt. Dat zie je als melding met een knop. Ook dit blokkeert niemand. Bevroren kaart (besluit B) blijft gelden.
2. **Fabrikant-roots komen uit MDS3, niet uit een eigen lijst.** Elke MDS3-entry bevat de `attestationRootCertificates` van die fabrikant (Yubico, Infineon, Nuvoton, STMicro, Feitian…), ondertekend via de FIDO-root. Een vaste lijst in de code veroudert en kan niet worden ingetrokken.
   - Apple (anonymous) en Google (Android Key/hardware attestation) staan niet in MDS3. Hun officiële roots pin ik met SHA-256 in de code, met bron en datum, en een test die faalt als een pin verloopt.
3. **TPM-OID:** 2.5.4.86 is geen TCG-TPM-extensie. Ik gebruik de OID's die de WebAuthn-spec voorschrijft: SAN-attributen 2.23.133.2.1/2/3 (fabrikant, model, versie), EKU 2.23.133.8.3 (AIK) en basicConstraints CA=false. De fabrikant wordt gecontroleerd tegen de TCG-vendorlijst.
4. **Android Key Description (1.3.6.1.4.1.11129.2.1.17):** we eisen `attestationSecurityLevel` en `keymasterSecurityLevel` = TrustedEnvironment of StrongBox (StrongBox apart gemarkeerd), RootOfTrust met deviceLocked=true en verifiedBootState=Verified, en geen `allApplications`. De challenge-hash moet kloppen.
5. **ASN.1/DER:** geen zelfgeschreven parser, maar de reeds aanwezige `@peculiar/asn1-*` (strikte DER, lengte- en diepte-limieten). Zelf DER parsen voor beveiligingskritieke code is juist het grootste risico. Staan deze pakketten alleen indirect in het project, dan vraag ik eerst je OK om ze als directe, vastgepinde dependency op te nemen.
6. **Opslag in vault_enclave als RVE1 onder de Master KEK.** De volledige metadata komt als `pak_`-envelop in een nieuwe tabel. Daarnaast komt één niet-geheime vlag (attested ja/nee + certificeringsniveau) per passkey, zodat het schild ook werkt zonder te ontsleutelen. Kanttekening: Neon heeft nu 0 serversleutels (`ROUT_VAULT_KEK` is nog niet actief). Tot dat zo is, slaat de code niets op, logt dat, en blijft iedereen "niet geattesteerd".

## Onderdelen

1. **MDS3-client** (`src/lib/crypto-enclave/fido-mds3.ts`)
   - Haalt de blob op van `mds3.fidoalliance.org` met een time-out en een groottelimiet.
   - JWT-controle:
     - `alg` alleen RS256/ES256;
     - de `x5c`-keten tot de vastgepinde FIDO-root (GlobalSign Root R3, SHA-256-pin);
     - geldigheidsdata, CRL-controle van de tussencertificaten, handtekening en een `no`-serienummer dat niet daalt.
   - Cache van 24 uur in het geheugen met verversing. Bij een fout blijft de vorige lijst maximaal 7 dagen bruikbaar. Daarna wordt het resultaat "onbekend", nooit "geattesteerd".

2. **Attestatie-engine** (`src/lib/auth/passkey-attestation.server.ts`)
   - Formaten: packed (x5c; self-attestation telt niet als hardware), tpm, apple en android-key.
   - Elke keten tot de root uit MDS3 of de pin, met geldigheid, padlengte, keyUsage en algoritmebinding.
   - De AAGUID uit authData moet gelijk zijn aan die in het certificaat (OID 1.3.6.1.4.1.45724.1.1.4).
   - StatusReports:
     - `REVOKED`, `USER_VERIFICATION_BYPASS`, `ATTESTATION_KEY_COMPROMISE`, `USER_KEY_REMOTE_COMPROMISE` en `USER_KEY_PHYSICAL_COMPROMISE` geven "onveilig" (zichtbaar in het schild, nooit blokkerend);
     - de meest recente melding telt, inclusief eventuele latere `UPDATE_AVAILABLE`/`FIDO_CERTIFIED`.
   - Certificering wordt exact toegekend: FIPS 140-3 L1 t/m L4, CC EAL4+/EAL5+/EAL6+ en FIDO L1 t/m L3+.
   - Uitkomst als strikte Zod-union: `{attested:true, fmt, aaguid, certification, statusSafe}` of `{attested:false, reason}`. De engine gooit nooit een fout naar de registratie.
   - De registratie-opties krijgen `attestation: "direct"` via onze `/api/auth/$`-route. Alleen dat veld verandert, de challenge blijft gelijk.
     - Afweging: sommige browsers vragen dan "mag deze site je merk en model zien?". Bij nee wordt het `attested:false`, niveau 2.
   - Eerst een test die bewijst dat de interne `verifyRegistrationResponse` van de plugin geen registratie weigert bij een onbekende root of AAGUID. Faalt die test, dan stop ik en leg ik je een alternatief voor.

3. **Migratie** (`db-pending/0271_fido_mds3_attestation.sql` + rollback)
   - Tabel `vault_enclave.passkey_attestations`:
     - kolommen: passkey_id, user, envelop, attested, cert_level, checked_at;
     - deny_all RLS en geen tabelrechten voor rout_app.
   - SECURITY DEFINER-functies `record_passkey_attestation` en `my_passkey_attestation_flags`:
     - search_path = pg_catalog, pg_temp;
     - de aanroeper komt uit de transactiecontext en het moet de eigen passkey zijn;
     - de envelop moet met `RVE1` beginnen;
     - elke uitkomst gaat naar het audit-log, met de nieuwe acties in `audit_logs_action_check`.
   - Expliciete revoke en grant, en een DO-blok als bewaker.
   - De rollback stopt als er al attestaties zijn.
   - Controles vooraf (alleen-lezen) en een PGlite-replay van db/ + 0271 + rollback + 0271. `CODE_SCHEMA_LEVEL` blijft 0270 tot jouw GO.

4. **Veiligheidsschild**
   - Nieuwe niveauregel uit punt 1, met tests per combinatie.
   - Per passkey toont het paneel: "Gecertificeerd (FIPS 140-3 L3)", "Hardware geattesteerd", "Onveilig apparaat (melding fabrikant)" of "Niet geattesteerd".
   - In NL/EN/FR/DE, met AAA-contrast en knoppen van minstens 44 px. De AGENTS-regels voor het schild worden bijgewerkt.

5. **Tests**
   - Echte fixtures voor elk formaat: YubiKey packed, Windows Hello TPM, Apple anonymous en Android Key.
   - Vervalste ketens, een verkeerde root, een verlopen root, een verlopen tussencertificaat, een AAGUID die niet klopt, een gemanipuleerde TPM-SAN, een Android Key met softwarelevel of ontgrendelde bootloader, en self-attestation.
   - MDS3: een gemanipuleerde handtekening, een dalend serienummer, een verlopen TTL en terugval op de vorige lijst.
   - Elke compromitterende statusReport, ook na een latere update.
   - Niemand blokkeren: elke ongeldige variant registreert nog steeds, als niveau 2.
   - Daarna de volledige `bunx vitest run` en `bunx tsgo -b --noEmit`, tot 0 rood en 0 typefouten.

6. **Documentatie**: regels in `src/lib/security/AGENTS.md` en `booking-engine/AGENTS.md`, plus de roadmap en een bijlage bij HANDOVER.

## Eerlijke grenzen
- iCloud-sleutelhanger en Google Password Manager geven meestal "none" of AAGUID 0. Die blijven niveau 2 en kunnen niveau 3 alleen bereiken met een extra hardwaresleutel.
- Attestatie bewijst het apparaat bij de registratie, niet bij elk later gebruik.
- Een cache per worker-instance: een koude start haalt de lijst opnieuw op.
- Een echte test met jouw YubiKey of TPM-laptop en de ROUT Card blijft nodig voor een afgevinkte productiestatus.

## Oplevering
Je krijgt de code, de testresultaten, de volledige SQL van 0271 en de rollback, de replay-uitkomst en de controles vooraf (alleen SELECT). Neon wordt pas gewijzigd na je GO.
