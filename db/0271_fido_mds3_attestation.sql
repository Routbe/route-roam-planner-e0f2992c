-- 0271 — FIDO MDS3 hardware attestation per passkey (Stap 5).
-- EXPAND only: one new deny-all table in vault_enclave, two SECURITY DEFINER
-- entry points and a wider audit action check. Nothing existing changes
-- behaviour; neon_auth.passkey is not altered. Held in db-pending/ until the
-- owner's GO.
--
--   passkey_attestations  one verdict per WebAuthn credential, written once:
--                         the full verdict (format, AAGUID, certification,
--                         MDS3 serial) only as an RVE1 envelope (kind pak = 8,
--                         holder server vault, sealed to a server key whose seed
--                         is wrapped under the Master KEK), plus the non-secret
--                         flags the Veiligheidsschild needs without opening it.
--
-- Invariant "niemand blokkeren": nothing here is consulted for sign-in or
-- registration. A missing row means "not attested". Denials return false and
-- commit their audit row; nothing raises at runtime.

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

create table vault_enclave.passkey_attestations (
  credential_id text primary key,
  auth_user_id uuid not null references neon_auth."user"(id) on delete cascade,
  fmt text not null,
  attested boolean not null,
  status_safe boolean,
  certified_l3 boolean not null,
  envelope bytea not null,
  recorded_at timestamptz not null default pg_catalog.clock_timestamp(),
  constraint passkey_attestations_credential check (credential_id ~ '^[A-Za-z0-9_-]+$' and length(credential_id) between 16 and 1366),
  constraint passkey_attestations_fmt check (fmt in ('none', 'packed', 'tpm', 'apple', 'android-key', 'fido-u2f', 'android-safetynet', 'unknown')),
  -- Certified only when attested and not listed as compromised.
  constraint passkey_attestations_certified check (not certified_l3 or (attested and status_safe is true)),
  constraint passkey_attestations_attested_fmt check (not attested or fmt in ('packed', 'tpm', 'apple', 'android-key')),
  -- RVE1 header: magic, suite 1, kind pak (8), holder server vault (1).
  constraint passkey_attestations_envelope_header check (
    substring(envelope from 1 for 4) = '\x52564531'::bytea
    and pg_catalog.get_byte(envelope, 4) = 1
    and pg_catalog.get_byte(envelope, 5) = 8
    and pg_catalog.get_byte(envelope, 6) = 1),
  constraint passkey_attestations_envelope_len check (octet_length(envelope) between 1663 and 8192)
);
create index passkey_attestations_user_idx on vault_enclave.passkey_attestations (auth_user_id);

revoke all on table vault_enclave.passkey_attestations from public, rout_app;
alter table vault_enclave.passkey_attestations enable row level security;

-- A verdict is written once and never changes; only the passkey owner's cascade removes it.
create function vault_enclave.passkey_attestations_guard() returns trigger
language plpgsql set search_path = pg_catalog, pg_temp as $$
begin
  raise exception 'vault_enclave.passkey_attestations rows are immutable';
end $$;
create trigger passkey_attestations_guard before update on vault_enclave.passkey_attestations
  for each row execute function vault_enclave.passkey_attestations_guard();
revoke all on function vault_enclave.passkey_attestations_guard() from public, rout_app;

-- The member (public.users id) or, during first enrolment, the Better Auth identity itself.
create function vault_enclave.passkey_attestation_identity(p_caller uuid) returns uuid
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select coalesce(
    (select u.auth_user_id from public.users u where u.id = p_caller),
    (select au.id from neon_auth."user" au where au.id = p_caller))
$$;
revoke all on function vault_enclave.passkey_attestation_identity(uuid) from public, rout_app;

-- Records a verdict for the caller's own passkey, created at most 10 minutes ago, once.
create function vault_enclave.record_passkey_attestation(
  p_credential_id text, p_fmt text, p_attested boolean, p_status_safe boolean, p_certified_l3 boolean, p_envelope bytea)
returns boolean language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v_auth uuid;
  v_rows integer;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'passkey_attestation_record', 'denied', 'no_caller', null); return false;
  end if;
  v_auth := vault_enclave.passkey_attestation_identity(v_caller);
  if v_auth is null then
    perform vault_enclave.append_audit(v_caller, 'passkey_attestation_record', 'denied', 'no_identity', null); return false;
  end if;
  if not exists (
    select 1 from neon_auth.passkey p
     where p."credentialID" = p_credential_id and p."userId" = v_auth::text
       and p."createdAt" > pg_catalog.clock_timestamp() - interval '10 minutes'
       and p."createdAt" <= pg_catalog.clock_timestamp() + interval '5 seconds') then
    perform vault_enclave.append_audit(v_caller, 'passkey_attestation_record', 'denied', 'not_own_fresh_passkey', null); return false;
  end if;
  begin
    insert into vault_enclave.passkey_attestations (credential_id, auth_user_id, fmt, attested, status_safe, certified_l3, envelope)
    values (p_credential_id, v_auth, p_fmt, p_attested, p_status_safe, p_certified_l3, p_envelope)
    on conflict (credential_id) do nothing;
    get diagnostics v_rows = row_count;
  exception when check_violation or not_null_violation then
    perform vault_enclave.append_audit(v_caller, 'passkey_attestation_record', 'denied', 'malformed', null); return false;
  end;
  if v_rows = 0 then
    perform vault_enclave.append_audit(v_caller, 'passkey_attestation_record', 'denied', 'already_recorded', null); return false;
  end if;
  perform vault_enclave.append_audit(v_caller, 'passkey_attestation_record', 'granted',
    case when p_certified_l3 then 'certified_l3' when p_attested then 'attested' else 'not_attested' end, null);
  return true;
end $$;

-- The caller's own non-secret flags; never the envelope, never another member's rows.
create function vault_enclave.my_passkey_attestations()
returns table (credential_id text, fmt text, attested boolean, status_safe boolean, certified_l3 boolean)
language plpgsql stable security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_auth uuid := vault_enclave.passkey_attestation_identity(vault_enclave.caller_user_id());
begin
  if v_auth is null then return; end if;
  return query
    select a.credential_id, a.fmt, a.attested, a.status_safe, a.certified_l3
      from vault_enclave.passkey_attestations a
      join neon_auth.passkey p on p."credentialID" = a.credential_id and p."userId" = v_auth::text
     where a.auth_user_id = v_auth
     order by a.recorded_at;
end $$;

revoke all on function vault_enclave.record_passkey_attestation(text, text, boolean, boolean, boolean, bytea) from public;
revoke all on function vault_enclave.my_passkey_attestations() from public;
grant execute on function vault_enclave.record_passkey_attestation(text, text, boolean, boolean, boolean, bytea) to rout_app;
grant execute on function vault_enclave.my_passkey_attestations() to rout_app;

-- In-transaction checks: rout_app reaches no new table, every new definer is
-- pinned, PUBLIC executes none of them, the internal helper is closed to rout_app.
do $$
declare v_bad text;
begin
  if pg_catalog.has_table_privilege('rout_app', 'vault_enclave.passkey_attestations', 'select')
     or pg_catalog.has_table_privilege('rout_app', 'vault_enclave.passkey_attestations', 'insert')
     or pg_catalog.has_table_privilege('rout_app', 'vault_enclave.passkey_attestations', 'update')
     or pg_catalog.has_table_privilege('rout_app', 'vault_enclave.passkey_attestations', 'delete')
     or not (select c.relrowsecurity from pg_catalog.pg_class c where c.oid = 'vault_enclave.passkey_attestations'::regclass) then
    raise exception '0271: rout_app can reach vault_enclave.passkey_attestations';
  end if;
  select string_agg(p.proname, ', ') into v_bad from pg_catalog.pg_proc p
   join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'vault_enclave' and p.prosecdef
     and p.proname in ('record_passkey_attestation', 'my_passkey_attestations', 'passkey_attestation_identity')
     and (p.proconfig is null or not ('search_path=pg_catalog, pg_temp' = any (p.proconfig))
       or pg_catalog.has_function_privilege('public', p.oid, 'execute'));
  if v_bad is not null then raise exception '0271: unpinned or public definer %', v_bad; end if;
  if pg_catalog.has_function_privilege('rout_app', 'vault_enclave.passkey_attestation_identity(uuid)', 'execute') then
    raise exception '0271: rout_app can execute the internal identity helper';
  end if;
end $$;
