# Held-back migrations

CONTRACT steps that remove legacy access. They stay out of `db/` (every file
there is replayed by the runners) until the deployed app uses the matching
EXPAND functions. Move a file into `db/` only when production runs that code
(the public health probe reports `schema` at or above the EXPAND number).


Applied and moved into `db/`: 0230, 0231, 0233, 0235, 0237 (production reported 0236).
- 0239 and 0241 applied (Nov 2026); no legacy rout_server access remains.
- 0262 applied on Neon (2026-11-13) and moved into `db/`.
- 0263 and 0264 applied on Neon (2026-11-13, production reported 0263); 0264 moved into `db/`. 

- 0265_booking_ledger.sql: held back (EXPAND, not yet applied on Neon); greatest/least unqualified. Moves to db/ with CODE_SCHEMA_LEVEL 0265 after the owner's GO.
- 0266_recovery_card_factor.sql: applied on Neon (2026-11-13 21:45) and moved into `db/`; CODE_SCHEMA_LEVEL is 0266.
- 0267_card_recovery_factor_tap.sql: applied on Neon (2026-11-14 12:12 UTC, owner's GO) and moved into `db/`; CODE_SCHEMA_LEVEL is 0267. Its rollback stays here (`0267_card_recovery_factor_tap_rollback.sql`, refuses while recovery_factor grants exist).
- 0272_dynamic_recovery_v4.sql: applied on Neon (2026-11-14 18:18 UTC, owner's GO) and moved into `db/`; CODE_SCHEMA_LEVEL is 0272. Its rollback stays here (`0272_dynamic_recovery_v4_rollback.sql`, refuses once a ceremony or recovery_v4 audit entry exists).
- 0268/0269 (recovery v3 drafts, never applied): moved to `db-archive/` (owner, 2026-11-14); recovery v4 (0272) replaces them.
- 0273_anonymous_booking_engine.sql (Stap 7e): held back, NOT applied on Neon; CODE_SCHEMA_LEVEL stays 0272. Rollback `0273_anonymous_booking_engine_rollback.sql` is idempotent and refuses once any anon_* table holds a row or an anon_* audit entry exists. Dry run: src/test/anonymous-booking-0273.test.ts. Before moving into db/: classify the anon_* tables in account merge/purge and refresh the schema snapshot.
