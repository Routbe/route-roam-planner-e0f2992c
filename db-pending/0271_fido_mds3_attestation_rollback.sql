-- Rollback of 0271 (FIDO MDS3 passkey attestation). Separate GO required.
-- Refuses to run while any verdict is stored, so no attestation history is
-- dropped by accident; delete those rows deliberately first if that is the
-- owner's decision. Restores the audit action check of db/0270 exactly.

do $$
begin
  if exists (select 1 from vault_enclave.passkey_attestations) then
    raise exception '0271 rollback: passkey_attestations is not empty';
  end if;
  if exists (select 1 from vault_enclave.audit_logs where action = 'passkey_attestation_record') then
    raise exception '0271 rollback: audit log already holds passkey_attestation_record entries (immutable)';
  end if;
end $$;

drop function vault_enclave.my_passkey_attestations();
drop function vault_enclave.record_passkey_attestation(text, text, boolean, boolean, boolean, bytea);
drop function vault_enclave.passkey_attestation_identity(uuid);
drop table vault_enclave.passkey_attestations;
drop function vault_enclave.passkey_attestations_guard();

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
                    'pake_unregister', 'pake_login'));

do $$
begin
  if to_regclass('vault_enclave.passkey_attestations') is not null
     or to_regprocedure('vault_enclave.record_passkey_attestation(text, text, boolean, boolean, boolean, bytea)') is not null then
    raise exception '0271 rollback incomplete';
  end if;
end $$;
