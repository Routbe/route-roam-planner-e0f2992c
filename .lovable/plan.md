# Stap 7 — Anonieme boekingsmotor, deel 7a (fundament)

Bevestiging: CODE_SCHEMA_LEVEL is 0272 en Neon staat op 0272. Een migratie 0273 komt alleen in db-pending/, met een rollback ernaast. Op Neon gebeurt niets zonder jouw GO. Alles blijft op je eigen infrastructuur.

## Wat er nu echt staat (nagekeken)
- wasm/rout-zk heeft Cargo.toml, rust-toolchain.toml (1.95.0) en een lib.rs met alleen `#![no_std]`. Er is nog geen logica.
- De Cargo.toml bevat bls12_381 0.8.0, sha2 en zeroize. **`subtle` staat er niet in**, anders dan het dossier zegt.
- In de repo staan **geen bestanden met BBS- of Poseidon-testvectoren**. Ze moeten nog worden toegevoegd uit de officiële IETF-draft.
- In src/lib/crypto-enclave bestaan nog geen bestanden voor pseudoniemen, BBS of Bulletproofs.
- db-pending/ bevat 0265_booking_ledger.sql (nog niet uitgevoerd) en vier rollbacks. Er is nog geen 0273.
- **Twee correcties op het dossier:**
  - De recovery-v4-tabellen op Neon heten recovery_v4_vaults, recovery_v4_ceremonies en recovery_v4_idempotency, niet *_v4-ceremonies/shards/audit.
  - Hosting: de bouwinstelling bouwt nu standaard voor Cloudflare, terwijl het dossier Vercel noemt.
- De rustc in de sandbox is 1.95.0, maar "built from a source tarball". De build.sh van rout-opaque weigert zo'n build. Een gepinde .wasm-build met hash kan hier dus niet; die moet via jouw CI (wasm-reproducible.yml) of lokaal met rustup.

## Voorstel: Stap 7 opdelen
Stap 7 is te groot voor één keer: BBS, Bulletproofs, Poseidon-SMT, forward-secure sleutels, migratie, adapters en tests. Ik stel voor om eerst **7a** te bouwen en te laten nakijken.

### 7a — wat ik bouw
1. **Geheugensandbox in rout-zk:** een vaste werkruimte, geen allocator, geen memory.grow. Ze wordt na elke operatie in een finally gewist met volatile zeroize. Ik gebruik hetzelfde patroon als rout-opaque.
2. **Pseudoniem per boeking:** `HMAC-SHA256(guest_master_seed, host_id || booking_nonce)` in Rust. De TypeScript-kant komt in `crypto-enclave/pseudonyms.ts`, alleen via de crypto-worker.
3. **BBS-kern (IETF BBS, BLS12-381-SHA-256):** sleutels maken, tekenen, verifiëren en een bewijs maken en controleren. Dit wordt getoetst aan de officiële fixtures, die ik als testbestanden in de repo zet.
4. **Blind BBS (draft-05):** een commitment van de gast, blind tekenen door de host en verifiëren. Ook dit wordt getoetst aan de officiële fixtures.
5. **Tests:** Rust-unit-tests met de fixtures (cargo test, native). Daarnaast Vitest-tests voor de pseudoniemregel: twee boekingen van dezelfde gast bij dezelfde host geven verschillende pseudoniemen.
6. **Documentatie:** roadmap.md bijwerken en alleen een appendix toevoegen aan HANDOVER.md, met de correcties hierboven.

### Later, apart, elk met eigen goedkeuring
- **7b:** Pedersen-capaciteit en Bulletproofs-range-proofs.
- **7c:** Poseidon-SMT-nullifiers en een door de enclave ondertekende root per epoch.
- **7d:** forward-secure hostsleutels (SK_t = H(SK_{t-1})).
- **7e:** `db-pending/0273_anonymous_booking_engine.sql` met rollback en een PGlite-replaytest. Daarbij RLS zonder policies, REVOKE voor public en rout_app, en alleen SECURITY DEFINER met `pg_catalog, pg_temp`. De migratie wordt **niet** uitgevoerd.
- **7f:** de koppeling met 0265_booking_ledger. Die moet ook nog beslist worden.

## Technische details
- **Pin en hash:** de pin in een `zk-wasm-pin.ts` blijft leeg of geweigerd tot jouw CI de reproduceerbare build levert. De loader weigert elke ongepinde binary, dus er is geen terugval.
- **Waar de code draait:** de TypeScript-adapters roepen rout-zk alleen in de crypto-worker aan, met getypeerde verzoeken en overgedragen buffers, net als de RVE1-ops.
- **Constant-time:** constant-time vergelijkingen via bls12_381/`subtle`. `subtle` wordt expliciet toegevoegd.
- **Grenzen van de verificatie:** ik kan hier `vitest run` en `tsgo` draaien. De reproduceerbare Wasm-hash en de timingtests (dudect) kan ik hier niet aantonen. Dat zeg ik er dan ook eerlijk bij.

## Wat ik van jou nodig heb
- GO voor 7a met deze afbakening.
- Bevestiging dat de .wasm-build met hash via jouw CI of lokaal gebeurt.
