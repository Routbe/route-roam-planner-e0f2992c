-- Rollback of 0273 (anonymous booking engine). Separate GO required.
-- Idempotent: a second run (or a run on a database without 0273) changes nothing.
-- Refuses while any anonymous booking table holds a row or the audit log holds
-- an anon_* entry: a sealed host state or a spent nullifier must never vanish
-- silently, and audit entries are immutable, so their action values must stay
-- allowed. Restores the audit action check of db/0272 exactly.

do $$
declare
  t text;
  v_has boolean;
begin
  foreach t in array array['anon_host_keys', 'anon_host_key_states', 'anon_epoch_links', 'anon_smt_trees',
                           'anon_smt_roots', 'anon_booking_tokens', 'anon_pseudonym_invalidations'] loop
    if pg_catalog.to_regclass('vault_enclave.' || t) is not null then
      execute pg_catalog.format('select exists (select 1 from vault_enclave.%I)', t) into v_has;
      if v_has then raise exception '0273 rollback: vault_enclave.% is not empty', t; end if;
    end if;
  end loop;
  if exists (select 1 from vault_enclave.audit_logs where action like 'anon\_%') then
    raise exception '0273 rollback: audit log already holds anon entries (immutable)';
  end if;
end $$;

drop function if exists vault_enclave.anon_host_chain(text);
drop function if exists vault_enclave.anon_pseudonym_invalidate(text, bytea, text);
drop function if exists vault_enclave.anon_booking_check(text, bytea);
drop function if exists vault_enclave.anon_booking_record(text, bigint, bytea, bytea, bytea, bytea, bigint, bytea);
drop function if exists vault_enclave.anon_host_key_retire(uuid, text);
drop function if exists vault_enclave.anon_host_key_state(text);
drop function if exists vault_enclave.anon_host_key_advance(text, bigint, bigint, bigint, bytea, bytea, bytea);
drop function if exists vault_enclave.anon_host_key_init(uuid, text, bytea, bytea, bytea, bytea, text, bytea, bytea);
drop function if exists vault_enclave.anon_stepup(uuid, uuid);
drop function if exists vault_enclave.anon_caller();
drop table if exists vault_enclave.anon_pseudonym_invalidations;
drop table if exists vault_enclave.anon_booking_tokens;
drop table if exists vault_enclave.anon_smt_roots;
drop table if exists vault_enclave.anon_smt_trees;
drop table if exists vault_enclave.anon_epoch_links;
drop table if exists vault_enclave.anon_host_key_states;
drop table if exists vault_enclave.anon_host_keys;
drop function if exists vault_enclave.anon_append_only();
drop function if exists vault_enclave.anon_answer(text, boolean, text, bigint, bigint);
drop function if exists vault_enclave.anon_id_ok(text, text);
drop function if exists vault_enclave.anon_len(bytea, integer);
drop function if exists vault_enclave.anon_is_proof(bytea);
drop function if exists vault_enclave.anon_is_hsk(bytea);

alter table vault_enclave.audit_logs drop constraint if exists audit_logs_action_check;
alter table vault_enclave.audit_logs add constraint audit_logs_action_check
  check (action in ('step_up_register', 'token_store', 'token_retrieve', 'server_key_register',
                    'sdm_card_register', 'sdm_recovery_retrieve', 'sdm_recovery_confirm',
                    'sdm_fleet_register', 'sdm_batch_register', 'sdm_batch_cards_register',
                    'sdm_tap_begin', 'sdm_tap_confirm', 'sdm_tap_consume',
                    'sdm_card_activate', 'sdm_batch_list', 'sdm_batch_export',
                    'sdm_station_register', 'sdm_station_list', 'sdm_station_retire',
                    'card_step_up_begin', 'card_step_up_complete', 'card_step_up_claim',
                    'sdm_card_revoke',
                    'pake_setup_register', 'pake_register', 'pake_signup_register',
                    'pake_unregister', 'pake_login',
                    'passkey_attestation_record',
                    'recovery_v4_begin', 'recovery_v4_confirm', 'recovery_v4_commit',
                    'recovery_v4_abort', 'recovery_v4_remove', 'recovery_v4_expire',
                    'recovery_v4_replay', 'recovery_v4_compromise', 'recovery_v4_server_share'));

do $$
begin
  if exists (select 1 from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace
              where n.nspname = 'vault_enclave' and c.relname like 'anon\_%')
     or exists (select 1 from pg_catalog.pg_proc p join pg_catalog.pg_namespace n on n.oid = p.pronamespace
                 where n.nspname = 'vault_enclave' and p.proname like 'anon\_%') then
    raise exception '0273 rollback incomplete';
  end if;
end $$;
