-- Rollback of 0272 (dynamic recovery v4). Separate GO required.
-- Refuses while any recovery ceremony or recovery_v4 audit entry exists:
-- dropping sealed shares would lock members out, and audit entries are
-- immutable, so their action values must stay allowed. Restores the audit
-- action check of db/0271 exactly.

do $$
begin
  if exists (select 1 from vault_enclave.recovery_v4_ceremonies) then
    raise exception '0272 rollback: recovery_v4_ceremonies is not empty';
  end if;
  if exists (select 1 from vault_enclave.audit_logs where action like 'recovery\_v4\_%') then
    raise exception '0272 rollback: audit log already holds recovery_v4 entries (immutable)';
  end if;
end $$;

drop function vault_enclave.recovery_v4_expire_due();
drop function vault_enclave.recovery_v4_material(boolean);
drop function vault_enclave.recovery_v4_status();
drop function vault_enclave.recovery_v4_server_share(uuid);
drop function vault_enclave.recovery_v4_report_compromise(text, text);
drop function vault_enclave.recovery_v4_remove(text, bigint, uuid);
drop function vault_enclave.recovery_v4_abort(text, uuid);
drop function vault_enclave.recovery_v4_commit(text, bigint, uuid, uuid, bytea);
drop function vault_enclave.recovery_v4_confirm_card(text, bigint, uuid, text);
drop function vault_enclave.recovery_v4_begin(text, bigint, text, text, uuid, uuid, integer, bytea, bytea, bytea, bytea, bytea, bytea, bytea, bytea, bytea);
drop function vault_enclave.recovery_v4_key_ok(text);
drop function vault_enclave.recovery_v4_digest(text[]);
drop function vault_enclave.recovery_v4_ids(uuid);
drop function vault_enclave.recovery_v4_store(uuid, text, text, bytea, jsonb);
drop function vault_enclave.recovery_v4_replay(uuid, text, text, bytea);
drop function vault_enclave.recovery_v4_lock(uuid);
drop function vault_enclave.recovery_v4_end(uuid, text);
drop function vault_enclave.recovery_v4_consume(uuid, uuid);
drop function vault_enclave.recovery_v4_fresh(uuid, uuid);
drop function vault_enclave.recovery_v4_answer(text, boolean, text, uuid, bigint, text, uuid, uuid);
drop function vault_enclave.recovery_v4_begin_ok(text, text, text);
drop function vault_enclave.recovery_v4_factors(text);
drop function vault_enclave.recovery_v4_k(text);
drop table vault_enclave.recovery_v4_idempotency;
drop table vault_enclave.recovery_v4_ceremonies;
drop table vault_enclave.recovery_v4_vaults;
drop function vault_enclave.recovery_v4_is_mpc(bytea, integer);

alter table vault_enclave.audit_logs drop constraint audit_logs_action_check;
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
                    'passkey_attestation_record'));

do $$
begin
  if to_regclass('vault_enclave.recovery_v4_vaults') is not null
     or to_regclass('vault_enclave.recovery_v4_ceremonies') is not null
     or exists (select 1 from pg_catalog.pg_proc p join pg_catalog.pg_namespace n on n.oid = p.pronamespace
                 where n.nspname = 'vault_enclave' and p.proname like 'recovery\_v4\_%') then
    raise exception '0272 rollback incomplete';
  end if;
end $$;
