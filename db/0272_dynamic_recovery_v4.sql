-- 0272 — EXPAND: dynamic recovery v4 (Stap 6), the SQL side of
-- formal/recovery-v4/RecoveryV4.tla. Independent of the v3 drafts 0268/0269
-- (left untouched; archiving them is the owner's call). Held in db-pending/
-- until the owner's GO.
--
-- One master row per member (vault_enclave.recovery_v4_vaults) and its
-- ceremonies. Every entry point is ONE self-contained transaction:
--   SELECT .. FOR UPDATE on the master row, lazy TTL expiry on the database
--   clock, idempotency key (a repeated key returns the stored answer), version
--   compare-and-swap, then the write. No session variables, advisory locks or
--   temp tables survive a step (Neon / PgBouncer pooling). The caller is taken
--   from the transaction context (vault_enclave.caller_user_id), never from a
--   parameter.
--
--   model action      function                                   answer.why on refusal
--   SBegin            recovery_v4_begin                          conflict busy invalid stepup malformed
--   SConfirm          recovery_v4_confirm_card                   conflict gone invalid card
--   SCommit           recovery_v4_commit                         conflict gone card stepup malformed
--   SAbort            recovery_v4_abort                          gone
--   SRemove           recovery_v4_remove                         conflict invalid stepup
--   ExpirePending     lazy in every step + recovery_v4_expire_due
--   Replay            idempotency table                          idem_mismatch (same key, other request)
--   ReportCompromise  recovery_v4_report_compromise              invalid
--   ReleaseServer     recovery_v4_server_share                   step_up_required
--
-- Levels: none, 2of3 (user_kek + server + paper), 3of4 (+ card). Threshold
-- K = 2 / 3. Owner decisions 2026-11-14: 2-of-3 until a card is linked;
-- pending TTL 10 minutes; a compromised share is excluded and ROUT's server
-- share is released without a fresh passkey step-up only while the
-- compromised shares plus the server share stay below K (CompromiseContained);
-- any commit or remove clears the compromise set (forced rotation).
--
-- Stored data are ciphertext or public only: RVE1 `mpc` envelopes (kind 3,
-- holder shard_factor 3), the sealed root (XChaCha20-Poly1305 under the
-- ceremony's generation key, opened only in the member's browser) and the
-- SHA-256 share commitments. Revoked and aborted ceremonies are shredded
-- (every blob set to NULL) in the same transaction.

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
                    'passkey_attestation_record',
                    'recovery_v4_begin', 'recovery_v4_confirm', 'recovery_v4_commit',
                    'recovery_v4_abort', 'recovery_v4_remove', 'recovery_v4_expire',
                    'recovery_v4_replay', 'recovery_v4_compromise', 'recovery_v4_server_share'));

-- RVE1 `mpc` envelope of exactly the size v4 writes: header magic, suite 1,
-- kind mpc (3), holder shard_factor (3); 1663 bytes of envelope overhead plus
-- a 33-byte share (x || 32-byte y) or the 72-byte sealed root.
create function vault_enclave.recovery_v4_is_mpc(p_env bytea, p_plain integer) returns boolean
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select p_env is not null and octet_length(p_env) = 1663 + p_plain
     and substring(p_env from 1 for 4) = '\x52564531'::bytea
     and pg_catalog.get_byte(p_env, 4) = 1 and pg_catalog.get_byte(p_env, 5) = 3 and pg_catalog.get_byte(p_env, 6) = 3
$$;
revoke all on function vault_enclave.recovery_v4_is_mpc(bytea, integer) from public, rout_app;

create table vault_enclave.recovery_v4_vaults (
  user_id uuid primary key references public.users(id) on delete cascade,
  level text not null default 'none',
  ver bigint not null default 0,
  generation integer not null default 0,
  next_generation integer not null default 1,
  compromised text[] not null default '{}',
  updated_at timestamptz not null default pg_catalog.clock_timestamp(),
  constraint recovery_v4_vaults_level check (level in ('none', '2of3', '3of4')),
  constraint recovery_v4_vaults_gen check ((level = 'none') = (generation = 0) and generation >= 0 and next_generation > generation),
  constraint recovery_v4_vaults_comp check (compromised <@ array['user_kek', 'paper', 'card']::text[]
                                           and (level <> 'none' or compromised = '{}')
                                           and (level = '3of4' or not ('card' = any (compromised))))
);

create table vault_enclave.recovery_v4_ceremonies (
  ceremony_id uuid primary key,
  user_id uuid not null references vault_enclave.recovery_v4_vaults(user_id) on delete cascade,
  kind text not null,
  policy text not null,
  generation integer not null,
  status text not null,
  card_id uuid,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  expires_at timestamptz not null,
  ended_at timestamptz,
  pending_root bytea,
  sealed_root bytea,
  shard_user_kek bytea, shard_server bytea, shard_paper bytea, shard_card bytea,
  commit_user_kek bytea, commit_server bytea, commit_paper bytea, commit_card bytea,
  constraint recovery_v4_cer_kind check (kind in ('setup', 'upgrade', 'downgrade', 'rotate')),
  constraint recovery_v4_cer_policy check (policy in ('2of3', '3of4')),
  constraint recovery_v4_cer_status check (status in ('pending', 'active', 'revoked', 'aborted')),
  constraint recovery_v4_cer_gen check (generation >= 1),
  constraint recovery_v4_cer_ttl check (expires_at = created_at + interval '10 minutes'),
  constraint recovery_v4_cer_ended check ((status in ('pending', 'active')) = (ended_at is null)),
  -- NoHalfOpen: an active 3of4 ceremony had its card proven by a tap.
  constraint recovery_v4_cer_card check (policy = '3of4' or card_id is null),
  constraint recovery_v4_cer_halfopen check (status <> 'active' or policy <> '3of4' or card_id is not null),
  -- Shapes per status; revoked/aborted ceremonies are shredded.
  constraint recovery_v4_cer_shape check (
    case status
      when 'pending' then pending_root is not null and sealed_root is null
      when 'active' then pending_root is null and sealed_root is not null
      else pending_root is null and sealed_root is null and shard_user_kek is null and shard_server is null
           and shard_paper is null and shard_card is null
    end),
  constraint recovery_v4_cer_shards check (
    status in ('revoked', 'aborted') or (
      shard_user_kek is not null and shard_server is not null and shard_paper is not null
      and (shard_card is not null) = (policy = '3of4')
      and commit_user_kek is not null and commit_server is not null and commit_paper is not null
      and (commit_card is not null) = (policy = '3of4'))),
  constraint recovery_v4_cer_commit_len check (
    coalesce(octet_length(commit_user_kek), 32) = 32 and coalesce(octet_length(commit_server), 32) = 32
    and coalesce(octet_length(commit_paper), 32) = 32 and coalesce(octet_length(commit_card), 32) = 32),
  constraint recovery_v4_cer_sealed_len check (sealed_root is null or octet_length(sealed_root) = 72),
  constraint recovery_v4_cer_envelopes check (
    (shard_user_kek is null or vault_enclave.recovery_v4_is_mpc(shard_user_kek, 33))
    and (shard_server is null or vault_enclave.recovery_v4_is_mpc(shard_server, 33))
    and (shard_paper is null or vault_enclave.recovery_v4_is_mpc(shard_paper, 33))
    and (shard_card is null or vault_enclave.recovery_v4_is_mpc(shard_card, 33))
    and (pending_root is null or vault_enclave.recovery_v4_is_mpc(pending_root, 72)))
);

-- Exclusivity (model invariant): at most one active and one pending ceremony per member.
create unique index recovery_v4_one_active on vault_enclave.recovery_v4_ceremonies (user_id) where status = 'active';
create unique index recovery_v4_one_pending on vault_enclave.recovery_v4_ceremonies (user_id) where status = 'pending';
create index recovery_v4_pending_due on vault_enclave.recovery_v4_ceremonies (expires_at) where status = 'pending';

create table vault_enclave.recovery_v4_idempotency (
  user_id uuid not null references vault_enclave.recovery_v4_vaults(user_id) on delete cascade,
  idem_key text not null,
  op text not null,
  request_digest bytea not null,
  answer jsonb not null,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  primary key (user_id, idem_key),
  constraint recovery_v4_idem_key check (idem_key ~ '^[A-Za-z0-9_-]+$' and length(idem_key) between 16 and 64),
  constraint recovery_v4_idem_digest check (octet_length(request_digest) = 32)
);

revoke all on table vault_enclave.recovery_v4_vaults, vault_enclave.recovery_v4_ceremonies,
  vault_enclave.recovery_v4_idempotency from public, rout_app;
alter table vault_enclave.recovery_v4_vaults enable row level security;
alter table vault_enclave.recovery_v4_ceremonies enable row level security;
alter table vault_enclave.recovery_v4_idempotency enable row level security;
-- deny_all: RLS on without any policy; only the definers below (table owner) touch the rows.

-- ---------------------------------------------------------------- internal helpers

create function vault_enclave.recovery_v4_k(p_level text) returns integer
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select case p_level when '3of4' then 3 when '2of3' then 2 else 0 end
$$;

create function vault_enclave.recovery_v4_factors(p_policy text) returns text[]
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select case p_policy when '3of4' then array['user_kek', 'server', 'paper', 'card']
                       when '2of3' then array['user_kek', 'server', 'paper'] else '{}'::text[] end
$$;

-- BeginKinds(level) of the model.
create function vault_enclave.recovery_v4_begin_ok(p_level text, p_kind text, p_policy text) returns boolean
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select case p_level
    when 'none' then p_kind = 'setup' and p_policy in ('2of3', '3of4')
    when '2of3' then (p_kind, p_policy) in (('upgrade', '3of4'), ('rotate', '2of3'))
    when '3of4' then (p_kind, p_policy) in (('downgrade', '2of3'), ('rotate', '3of4'))
    else false end
$$;

create function vault_enclave.recovery_v4_answer(
  p_op text, p_ok boolean, p_why text, p_cid uuid, p_ver bigint, p_level text, p_pend uuid, p_act uuid)
returns jsonb language sql immutable set search_path = pg_catalog, pg_temp as $$
  select pg_catalog.jsonb_build_object('op', p_op, 'ok', p_ok, 'why', p_why, 'cid', p_cid, 'ver', p_ver,
                                       'level', p_level, 'pend', p_pend, 'act', p_act)
$$;

-- Fresh(p): the caller's own passkey proof, unconsumed, verified within 300 s on the database clock.
create function vault_enclave.recovery_v4_fresh(p_caller uuid, p_proof uuid) returns boolean
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select p_proof is not null and exists (
    select 1 from vault_enclave.step_up_proofs s
     where s.proof_id = p_proof and s.user_id = p_caller and s.method = 'passkey' and s.consumed_at is null
       and s.verified_at >= pg_catalog.clock_timestamp() - interval '300 seconds'
       and s.verified_at <= pg_catalog.clock_timestamp())
$$;

-- Consume(p): marks a fresh proof used; a no-op otherwise.
create function vault_enclave.recovery_v4_consume(p_caller uuid, p_proof uuid) returns void
language sql security definer set search_path = pg_catalog, pg_temp as $$
  update vault_enclave.step_up_proofs s set consumed_at = pg_catalog.clock_timestamp()
   where s.proof_id = p_proof and s.user_id = p_caller and s.consumed_at is null
     and s.verified_at >= pg_catalog.clock_timestamp() - interval '300 seconds'
$$;

-- Ends a ceremony: shreds every blob in the same statement.
create function vault_enclave.recovery_v4_end(p_ceremony uuid, p_status text) returns void
language sql security definer set search_path = pg_catalog, pg_temp as $$
  update vault_enclave.recovery_v4_ceremonies c
     set status = p_status, ended_at = pg_catalog.clock_timestamp(),
         pending_root = null, sealed_root = null,
         shard_user_kek = null, shard_server = null, shard_paper = null, shard_card = null
   where c.ceremony_id = p_ceremony
$$;

-- Locks (creating if needed) the caller's master row, applies the TTL on the
-- database clock (ExpirePending: pending -> aborted, ver + 1) and prunes
-- idempotency rows older than one day. Returns the locked row.
create function vault_enclave.recovery_v4_lock(p_caller uuid) returns vault_enclave.recovery_v4_vaults
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v vault_enclave.recovery_v4_vaults%rowtype;
  v_due uuid;
begin
  insert into vault_enclave.recovery_v4_vaults (user_id) values (p_caller) on conflict (user_id) do nothing;
  select * into v from vault_enclave.recovery_v4_vaults where user_id = p_caller for update;
  select c.ceremony_id into v_due from vault_enclave.recovery_v4_ceremonies c
   where c.user_id = p_caller and c.status = 'pending' and c.expires_at <= pg_catalog.clock_timestamp();
  if v_due is not null then
    perform vault_enclave.recovery_v4_end(v_due, 'aborted');
    update vault_enclave.recovery_v4_vaults set ver = ver + 1, updated_at = pg_catalog.clock_timestamp()
     where user_id = p_caller returning * into v;
    perform vault_enclave.append_audit(p_caller, 'recovery_v4_expire', 'granted', 'ttl', null);
  end if;
  delete from vault_enclave.recovery_v4_idempotency i
   where i.user_id = p_caller and i.created_at < pg_catalog.clock_timestamp() - interval '1 day';
  return v;
end $$;

-- Replay: the stored answer for the same key and request; 'idem_mismatch' for another request.
create function vault_enclave.recovery_v4_replay(p_caller uuid, p_key text, p_op text, p_digest bytea) returns jsonb
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare r vault_enclave.recovery_v4_idempotency%rowtype;
begin
  select * into r from vault_enclave.recovery_v4_idempotency i where i.user_id = p_caller and i.idem_key = p_key;
  if not found then return null; end if;
  if r.op <> p_op or r.request_digest <> p_digest then
    perform vault_enclave.append_audit(p_caller, 'recovery_v4_replay', 'denied', 'idem_mismatch', null);
    return vault_enclave.recovery_v4_answer(p_op, false, 'idem_mismatch', null, null, null, null, null);
  end if;
  perform vault_enclave.append_audit(p_caller, 'recovery_v4_replay', 'granted', p_op, null);
  return r.answer;
end $$;

create function vault_enclave.recovery_v4_store(p_caller uuid, p_key text, p_op text, p_digest bytea, p_answer jsonb) returns jsonb
language sql security definer set search_path = pg_catalog, pg_temp as $$
  insert into vault_enclave.recovery_v4_idempotency (user_id, idem_key, op, request_digest, answer)
  values (p_caller, p_key, p_op, p_digest, p_answer) returning answer
$$;

create function vault_enclave.recovery_v4_ids(p_caller uuid, out p_pend uuid, out p_act uuid)
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select (select c.ceremony_id from vault_enclave.recovery_v4_ceremonies c where c.user_id = p_caller and c.status = 'pending'),
         (select c.ceremony_id from vault_enclave.recovery_v4_ceremonies c where c.user_id = p_caller and c.status = 'active')
$$;

create function vault_enclave.recovery_v4_digest(p_parts text[]) returns bytea
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.array_to_string(p_parts, '|', '~'), 'UTF8'))
$$;

create function vault_enclave.recovery_v4_key_ok(p_key text) returns boolean
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select p_key is not null and p_key ~ '^[A-Za-z0-9_-]+$' and length(p_key) between 16 and 64
$$;

-- ---------------------------------------------------------------- SBegin

create function vault_enclave.recovery_v4_begin(
  p_idem text, p_ver bigint, p_kind text, p_policy text, p_proof uuid,
  p_ceremony uuid, p_generation integer, p_pending_root bytea,
  p_shard_user_kek bytea, p_shard_server bytea, p_shard_paper bytea, p_shard_card bytea,
  p_commit_user_kek bytea, p_commit_server bytea, p_commit_paper bytea, p_commit_card bytea)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v vault_enclave.recovery_v4_vaults%rowtype;
  v_ids record;
  v_digest bytea;
  v_prev jsonb;
  v_why text;
  v_ans jsonb;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'recovery_v4_begin', 'denied', 'no_caller', null);
    return vault_enclave.recovery_v4_answer('begin', false, 'no_caller', null, null, null, null, null);
  end if;
  if not vault_enclave.recovery_v4_key_ok(p_idem) then
    perform vault_enclave.append_audit(v_caller, 'recovery_v4_begin', 'denied', 'bad_key', null);
    return vault_enclave.recovery_v4_answer('begin', false, 'malformed', null, null, null, null, null);
  end if;
  v := vault_enclave.recovery_v4_lock(v_caller);
  v_digest := vault_enclave.recovery_v4_digest(array['begin', p_ver::text, p_kind, p_policy, p_proof::text, p_ceremony::text,
    p_generation::text, pg_catalog.encode(pg_catalog.sha256(coalesce(p_pending_root, '')), 'hex'),
    pg_catalog.encode(pg_catalog.sha256(coalesce(p_shard_user_kek, '') || coalesce(p_shard_server, '') || coalesce(p_shard_paper, '')
      || coalesce(p_shard_card, '') || coalesce(p_commit_user_kek, '') || coalesce(p_commit_server, '')
      || coalesce(p_commit_paper, '') || coalesce(p_commit_card, '')), 'hex')]);
  v_prev := vault_enclave.recovery_v4_replay(v_caller, p_idem, 'begin', v_digest);
  if v_prev is not null then return v_prev; end if;
  select * into v_ids from vault_enclave.recovery_v4_ids(v_caller);

  v_why := case
    when p_ver is distinct from v.ver then 'conflict'
    when v_ids.p_pend is not null then 'busy'
    when not vault_enclave.recovery_v4_begin_ok(v.level, p_kind, p_policy) then 'invalid'
    when not vault_enclave.recovery_v4_fresh(v_caller, p_proof) then 'stepup'
    when p_ceremony is null or p_generation is distinct from v.next_generation
      or exists (select 1 from vault_enclave.recovery_v4_ceremonies c where c.ceremony_id = p_ceremony)
      or not vault_enclave.recovery_v4_is_mpc(p_pending_root, 72)
      or not vault_enclave.recovery_v4_is_mpc(p_shard_user_kek, 33)
      or not vault_enclave.recovery_v4_is_mpc(p_shard_server, 33)
      or not vault_enclave.recovery_v4_is_mpc(p_shard_paper, 33)
      or (p_policy = '3of4') <> (p_shard_card is not null)
      or (p_shard_card is not null and not vault_enclave.recovery_v4_is_mpc(p_shard_card, 33))
      or coalesce(octet_length(p_commit_user_kek), 0) <> 32 or coalesce(octet_length(p_commit_server), 0) <> 32
      or coalesce(octet_length(p_commit_paper), 0) <> 32
      or (p_policy = '3of4') <> (p_commit_card is not null) or coalesce(octet_length(p_commit_card), 32) <> 32
      then 'malformed'
    else 'ok' end;
  if v_why <> 'ok' then
    v_ans := vault_enclave.recovery_v4_answer('begin', false, v_why, null, v.ver, v.level, v_ids.p_pend, v_ids.p_act);
    perform vault_enclave.append_audit(v_caller, 'recovery_v4_begin', 'denied', v_why, null);
    return vault_enclave.recovery_v4_store(v_caller, p_idem, 'begin', v_digest, v_ans);
  end if;

  insert into vault_enclave.recovery_v4_ceremonies (ceremony_id, user_id, kind, policy, generation, status, created_at, expires_at,
    pending_root, shard_user_kek, shard_server, shard_paper, shard_card, commit_user_kek, commit_server, commit_paper, commit_card)
  select p_ceremony, v_caller, p_kind, p_policy, p_generation, 'pending', t.now, t.now + interval '10 minutes',
    p_pending_root, p_shard_user_kek, p_shard_server, p_shard_paper, p_shard_card,
    p_commit_user_kek, p_commit_server, p_commit_paper, p_commit_card
  from (select pg_catalog.clock_timestamp() as now) t;
  update vault_enclave.recovery_v4_vaults set ver = ver + 1, next_generation = next_generation + 1,
         updated_at = pg_catalog.clock_timestamp() where user_id = v_caller returning * into v;
  perform vault_enclave.recovery_v4_consume(v_caller, p_proof);
  v_ans := vault_enclave.recovery_v4_answer('begin', true, 'ok', p_ceremony, v.ver, v.level, p_ceremony, v_ids.p_act);
  perform vault_enclave.append_audit(v_caller, 'recovery_v4_begin', 'granted', p_kind || ':' || p_policy, null);
  return vault_enclave.recovery_v4_store(v_caller, p_idem, 'begin', v_digest, v_ans);
end $$;

-- ---------------------------------------------------------------- SConfirm

-- The tap grant (purpose recovery_factor, db/0267) proves the caller's own,
-- unrevoked card during this ceremony; the card id is kept and re-checked at commit.
create function vault_enclave.recovery_v4_confirm_card(p_idem text, p_ver bigint, p_ceremony uuid, p_tap_ref text)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v vault_enclave.recovery_v4_vaults%rowtype;
  c vault_enclave.recovery_v4_ceremonies%rowtype;
  v_ids record;
  v_digest bytea;
  v_prev jsonb;
  v_why text;
  v_card uuid;
  v_ok boolean := false;
  v_ans jsonb;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'recovery_v4_confirm', 'denied', 'no_caller', null);
    return vault_enclave.recovery_v4_answer('confirm', false, 'no_caller', null, null, null, null, null);
  end if;
  if not vault_enclave.recovery_v4_key_ok(p_idem) then
    return vault_enclave.recovery_v4_answer('confirm', false, 'malformed', null, null, null, null, null);
  end if;
  v := vault_enclave.recovery_v4_lock(v_caller);
  v_digest := vault_enclave.recovery_v4_digest(array['confirm', p_ver::text, p_ceremony::text,
    pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(coalesce(p_tap_ref, ''), 'UTF8')), 'hex')]);
  v_prev := vault_enclave.recovery_v4_replay(v_caller, p_idem, 'confirm', v_digest);
  if v_prev is not null then return v_prev; end if;
  select * into v_ids from vault_enclave.recovery_v4_ids(v_caller);
  select * into c from vault_enclave.recovery_v4_ceremonies x
   where x.ceremony_id = p_ceremony and x.user_id = v_caller and x.status = 'pending';

  v_why := case
    when p_ver is distinct from v.ver then 'conflict'
    when c.ceremony_id is null then 'gone'
    when c.policy <> '3of4' then 'invalid'
    else null end;
  if v_why is null then
    if p_tap_ref is not null and p_tap_ref ~ '^tap_[0-9a-f]{64}$' then
      select g.card_id into v_card from vault_enclave.sdm_tap_grants g
       where g.grant_digest = pg_catalog.sha256(pg_catalog.convert_to(p_tap_ref, 'UTF8'));
      select t.granted into v_ok from vault_enclave.consume_sdm_tap(p_tap_ref, 'recovery_factor') t;
    end if;
    v_why := case when coalesce(v_ok, false) and v_card is not null then 'ok' else 'card' end;
  end if;
  if v_why <> 'ok' then
    v_ans := vault_enclave.recovery_v4_answer('confirm', false, v_why, p_ceremony, v.ver, v.level, v_ids.p_pend, v_ids.p_act);
    perform vault_enclave.append_audit(v_caller, 'recovery_v4_confirm', 'denied', v_why, null);
    return vault_enclave.recovery_v4_store(v_caller, p_idem, 'confirm', v_digest, v_ans);
  end if;
  update vault_enclave.recovery_v4_ceremonies set card_id = v_card where ceremony_id = p_ceremony;
  update vault_enclave.recovery_v4_vaults set ver = ver + 1, updated_at = pg_catalog.clock_timestamp()
   where user_id = v_caller returning * into v;
  v_ans := vault_enclave.recovery_v4_answer('confirm', true, 'ok', p_ceremony, v.ver, v.level, v_ids.p_pend, v_ids.p_act);
  perform vault_enclave.append_audit(v_caller, 'recovery_v4_confirm', 'granted', 'ok', null);
  return vault_enclave.recovery_v4_store(v_caller, p_idem, 'confirm', v_digest, v_ans);
end $$;

-- ---------------------------------------------------------------- SCommit

-- p_sealed_root: the pending root with ROUT's commit layer removed by the
-- server (the server opens only its own layer; the root stays sealed under
-- the generation key). A commit that lowers K consumes a fresh step-up here.
create function vault_enclave.recovery_v4_commit(p_idem text, p_ver bigint, p_ceremony uuid, p_proof uuid, p_sealed_root bytea)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v vault_enclave.recovery_v4_vaults%rowtype;
  c vault_enclave.recovery_v4_ceremonies%rowtype;
  v_ids record;
  v_digest bytea;
  v_prev jsonb;
  v_why text;
  v_card_ok boolean;
  v_ans jsonb;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'recovery_v4_commit', 'denied', 'no_caller', null);
    return vault_enclave.recovery_v4_answer('commit', false, 'no_caller', null, null, null, null, null);
  end if;
  if not vault_enclave.recovery_v4_key_ok(p_idem) then
    return vault_enclave.recovery_v4_answer('commit', false, 'malformed', null, null, null, null, null);
  end if;
  v := vault_enclave.recovery_v4_lock(v_caller);
  v_digest := vault_enclave.recovery_v4_digest(array['commit', p_ver::text, p_ceremony::text, p_proof::text,
    pg_catalog.encode(pg_catalog.sha256(coalesce(p_sealed_root, '')), 'hex')]);
  v_prev := vault_enclave.recovery_v4_replay(v_caller, p_idem, 'commit', v_digest);
  if v_prev is not null then return v_prev; end if;
  select * into v_ids from vault_enclave.recovery_v4_ids(v_caller);
  select * into c from vault_enclave.recovery_v4_ceremonies x
   where x.ceremony_id = p_ceremony and x.user_id = v_caller and x.status = 'pending' for update;
  -- A card unlinked (revoked) or moved since the tap resets the confirmation (model CardUnlink).
  if c.ceremony_id is not null and c.card_id is not null then
    select exists (select 1 from vault_enclave.sdm_batch_cards k
                    where k.card_id = c.card_id and k.revoked_at is null and k.owner_user_id = v_caller) into v_card_ok;
    if not v_card_ok then
      update vault_enclave.recovery_v4_ceremonies set card_id = null where ceremony_id = c.ceremony_id;
      c.card_id := null;
    end if;
  end if;

  v_why := case
    when p_ver is distinct from v.ver then 'conflict'
    when c.ceremony_id is null then 'gone'
    when c.policy = '3of4' and c.card_id is null then 'card'
    when vault_enclave.recovery_v4_k(c.policy) < vault_enclave.recovery_v4_k(v.level)
      and not vault_enclave.recovery_v4_fresh(v_caller, p_proof) then 'stepup'
    when p_sealed_root is null or octet_length(p_sealed_root) <> 72 then 'malformed'
    else 'ok' end;
  if v_why <> 'ok' then
    v_ans := vault_enclave.recovery_v4_answer('commit', false, v_why, p_ceremony, v.ver, v.level, v_ids.p_pend, v_ids.p_act);
    perform vault_enclave.append_audit(v_caller, 'recovery_v4_commit', 'denied', v_why, null);
    return vault_enclave.recovery_v4_store(v_caller, p_idem, 'commit', v_digest, v_ans);
  end if;
  if v_ids.p_act is not null then
    perform vault_enclave.recovery_v4_end(v_ids.p_act, 'revoked');
  end if;
  update vault_enclave.recovery_v4_ceremonies set status = 'active', pending_root = null, sealed_root = p_sealed_root
   where ceremony_id = p_ceremony;
  update vault_enclave.recovery_v4_vaults set level = c.policy, generation = c.generation, compromised = '{}',
         ver = ver + 1, updated_at = pg_catalog.clock_timestamp()
   where user_id = v_caller returning * into v;
  perform vault_enclave.recovery_v4_consume(v_caller, p_proof);
  v_ans := vault_enclave.recovery_v4_answer('commit', true, 'ok', p_ceremony, v.ver, v.level, null, p_ceremony);
  perform vault_enclave.append_audit(v_caller, 'recovery_v4_commit', 'granted', c.kind || ':' || c.policy, null);
  return vault_enclave.recovery_v4_store(v_caller, p_idem, 'commit', v_digest, v_ans);
end $$;

-- ---------------------------------------------------------------- SAbort

create function vault_enclave.recovery_v4_abort(p_idem text, p_ceremony uuid)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v vault_enclave.recovery_v4_vaults%rowtype;
  v_ids record;
  v_digest bytea;
  v_prev jsonb;
  v_ans jsonb;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'recovery_v4_abort', 'denied', 'no_caller', null);
    return vault_enclave.recovery_v4_answer('abort', false, 'no_caller', null, null, null, null, null);
  end if;
  if not vault_enclave.recovery_v4_key_ok(p_idem) then
    return vault_enclave.recovery_v4_answer('abort', false, 'malformed', null, null, null, null, null);
  end if;
  v := vault_enclave.recovery_v4_lock(v_caller);
  v_digest := vault_enclave.recovery_v4_digest(array['abort', p_ceremony::text]);
  v_prev := vault_enclave.recovery_v4_replay(v_caller, p_idem, 'abort', v_digest);
  if v_prev is not null then return v_prev; end if;
  select * into v_ids from vault_enclave.recovery_v4_ids(v_caller);
  if p_ceremony is null or v_ids.p_pend is distinct from p_ceremony then
    v_ans := vault_enclave.recovery_v4_answer('abort', false, 'gone', p_ceremony, v.ver, v.level, v_ids.p_pend, v_ids.p_act);
    perform vault_enclave.append_audit(v_caller, 'recovery_v4_abort', 'denied', 'gone', null);
    return vault_enclave.recovery_v4_store(v_caller, p_idem, 'abort', v_digest, v_ans);
  end if;
  perform vault_enclave.recovery_v4_end(p_ceremony, 'aborted');
  update vault_enclave.recovery_v4_vaults set ver = ver + 1, updated_at = pg_catalog.clock_timestamp()
   where user_id = v_caller returning * into v;
  v_ans := vault_enclave.recovery_v4_answer('abort', true, 'ok', p_ceremony, v.ver, v.level, null, v_ids.p_act);
  perform vault_enclave.append_audit(v_caller, 'recovery_v4_abort', 'granted', 'ok', null);
  return vault_enclave.recovery_v4_store(v_caller, p_idem, 'abort', v_digest, v_ans);
end $$;

-- ---------------------------------------------------------------- SRemove

create function vault_enclave.recovery_v4_remove(p_idem text, p_ver bigint, p_proof uuid)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v vault_enclave.recovery_v4_vaults%rowtype;
  v_ids record;
  v_digest bytea;
  v_prev jsonb;
  v_why text;
  v_ans jsonb;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'recovery_v4_remove', 'denied', 'no_caller', null);
    return vault_enclave.recovery_v4_answer('remove', false, 'no_caller', null, null, null, null, null);
  end if;
  if not vault_enclave.recovery_v4_key_ok(p_idem) then
    return vault_enclave.recovery_v4_answer('remove', false, 'malformed', null, null, null, null, null);
  end if;
  v := vault_enclave.recovery_v4_lock(v_caller);
  v_digest := vault_enclave.recovery_v4_digest(array['remove', p_ver::text, p_proof::text]);
  v_prev := vault_enclave.recovery_v4_replay(v_caller, p_idem, 'remove', v_digest);
  if v_prev is not null then return v_prev; end if;
  select * into v_ids from vault_enclave.recovery_v4_ids(v_caller);
  v_why := case
    when p_ver is distinct from v.ver then 'conflict'
    when v.level = 'none' then 'invalid'
    when not vault_enclave.recovery_v4_fresh(v_caller, p_proof) then 'stepup'
    else 'ok' end;
  if v_why <> 'ok' then
    v_ans := vault_enclave.recovery_v4_answer('remove', false, v_why, null, v.ver, v.level, v_ids.p_pend, v_ids.p_act);
    perform vault_enclave.append_audit(v_caller, 'recovery_v4_remove', 'denied', v_why, null);
    return vault_enclave.recovery_v4_store(v_caller, p_idem, 'remove', v_digest, v_ans);
  end if;
  if v_ids.p_act is not null then perform vault_enclave.recovery_v4_end(v_ids.p_act, 'revoked'); end if;
  if v_ids.p_pend is not null then perform vault_enclave.recovery_v4_end(v_ids.p_pend, 'aborted'); end if;
  update vault_enclave.recovery_v4_vaults set level = 'none', generation = 0, compromised = '{}',
         ver = ver + 1, updated_at = pg_catalog.clock_timestamp()
   where user_id = v_caller returning * into v;
  perform vault_enclave.recovery_v4_consume(v_caller, p_proof);
  v_ans := vault_enclave.recovery_v4_answer('remove', true, 'ok', null, v.ver, 'none', null, null);
  perform vault_enclave.append_audit(v_caller, 'recovery_v4_remove', 'granted', 'ok', null);
  return vault_enclave.recovery_v4_store(v_caller, p_idem, 'remove', v_digest, v_ans);
end $$;

-- ---------------------------------------------------------------- ReportCompromise

create function vault_enclave.recovery_v4_report_compromise(p_idem text, p_factor text)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v vault_enclave.recovery_v4_vaults%rowtype;
  v_ids record;
  v_digest bytea;
  v_prev jsonb;
  v_ans jsonb;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'recovery_v4_compromise', 'denied', 'no_caller', null);
    return vault_enclave.recovery_v4_answer('compromise', false, 'no_caller', null, null, null, null, null);
  end if;
  if not vault_enclave.recovery_v4_key_ok(p_idem) then
    return vault_enclave.recovery_v4_answer('compromise', false, 'malformed', null, null, null, null, null);
  end if;
  v := vault_enclave.recovery_v4_lock(v_caller);
  v_digest := vault_enclave.recovery_v4_digest(array['compromise', p_factor]);
  v_prev := vault_enclave.recovery_v4_replay(v_caller, p_idem, 'compromise', v_digest);
  if v_prev is not null then return v_prev; end if;
  select * into v_ids from vault_enclave.recovery_v4_ids(v_caller);
  if v.level = 'none' or p_factor is null or p_factor = 'server'
     or not (p_factor = any (vault_enclave.recovery_v4_factors(v.level))) or p_factor = any (v.compromised) then
    v_ans := vault_enclave.recovery_v4_answer('compromise', false, 'invalid', null, v.ver, v.level, v_ids.p_pend, v_ids.p_act);
    perform vault_enclave.append_audit(v_caller, 'recovery_v4_compromise', 'denied', 'invalid', null);
    return vault_enclave.recovery_v4_store(v_caller, p_idem, 'compromise', v_digest, v_ans);
  end if;
  update vault_enclave.recovery_v4_vaults set compromised = compromised || p_factor, ver = ver + 1,
         updated_at = pg_catalog.clock_timestamp() where user_id = v_caller returning * into v;
  v_ans := vault_enclave.recovery_v4_answer('compromise', true, 'ok', null, v.ver, v.level, v_ids.p_pend, v_ids.p_act);
  perform vault_enclave.append_audit(v_caller, 'recovery_v4_compromise', 'granted', p_factor, null);
  return vault_enclave.recovery_v4_store(v_caller, p_idem, 'compromise', v_digest, v_ans);
end $$;

-- ---------------------------------------------------------------- ReleaseServer

-- The server's own share envelope of the active ceremony, for ROUT to open
-- with its server factor key. The active card counts as compromised once it
-- is revoked or no longer the caller's (model CardUnlink). If the compromised
-- shares plus the server share would reach K, only a fresh passkey step-up
-- (consumed here) releases it; `exclude` lists the shares the client must not
-- use in a server-assisted recovery. Denials return granted = false.
create function vault_enclave.recovery_v4_server_share(p_proof uuid)
returns table (granted boolean, reason text, ceremony_id uuid, generation integer, policy text, shard bytea, exclude text[])
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v vault_enclave.recovery_v4_vaults%rowtype;
  c vault_enclave.recovery_v4_ceremonies%rowtype;
  v_comp text[];
  v_danger boolean;
  v_step boolean := false;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'recovery_v4_server_share', 'denied', 'no_caller', null);
    return query select false, 'no_caller'::text, null::uuid, null::integer, null::text, null::bytea, null::text[]; return;
  end if;
  v := vault_enclave.recovery_v4_lock(v_caller);
  select * into c from vault_enclave.recovery_v4_ceremonies x where x.user_id = v_caller and x.status = 'active';
  if c.ceremony_id is null then
    perform vault_enclave.append_audit(v_caller, 'recovery_v4_server_share', 'denied', 'no_vault', null);
    return query select false, 'no_vault'::text, null::uuid, null::integer, null::text, null::bytea, null::text[]; return;
  end if;
  v_comp := v.compromised;
  if c.policy = '3of4' and not ('card' = any (v_comp)) and not exists (
       select 1 from vault_enclave.sdm_batch_cards k where k.card_id = c.card_id and k.revoked_at is null and k.owner_user_id = v_caller) then
    v_comp := v_comp || 'card'::text;
  end if;
  v_danger := pg_catalog.cardinality(v_comp) + 1 >= vault_enclave.recovery_v4_k(c.policy);
  if v_danger then
    v_step := vault_enclave.recovery_v4_fresh(v_caller, p_proof);
    if not v_step then
      perform vault_enclave.append_audit(v_caller, 'recovery_v4_server_share', 'denied', 'step_up_required', null);
      return query select false, 'step_up_required'::text, c.ceremony_id, c.generation, c.policy, null::bytea, v_comp; return;
    end if;
    perform vault_enclave.recovery_v4_consume(v_caller, p_proof);
  end if;
  perform vault_enclave.append_audit(v_caller, 'recovery_v4_server_share', 'granted',
    case when v_step then 'step_up' when pg_catalog.cardinality(v_comp) > 0 then 'excluding' else 'ok' end, null);
  return query select true, 'ok'::text, c.ceremony_id, c.generation, c.policy, c.shard_server,
    case when v_step then '{}'::text[] else v_comp end;
end $$;

-- ---------------------------------------------------------------- reads (ciphertext / public only)

-- Status of the caller's vault; never a blob.
create function vault_enclave.recovery_v4_status()
returns table (level text, ver bigint, generation integer, next_generation integer, compromised text[],
               pending_id uuid, pending_policy text, pending_expires_at timestamptz, pending_card_confirmed boolean,
               active_id uuid)
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v vault_enclave.recovery_v4_vaults%rowtype;
begin
  if v_caller is null then return; end if;
  v := vault_enclave.recovery_v4_lock(v_caller);
  return query
    select v.level, v.ver, v.generation, v.next_generation, v.compromised,
           p.ceremony_id, p.policy, p.expires_at, p.card_id is not null, a.ceremony_id
      from (select 1) one
      left join vault_enclave.recovery_v4_ceremonies p on p.user_id = v_caller and p.status = 'pending'
      left join vault_enclave.recovery_v4_ceremonies a on a.user_id = v_caller and a.status = 'active';
end $$;

-- The caller's own ceremony material: the active one, or (p_pending) the
-- pending one so the client can verify its own card share before confirming.
-- The server share is never returned here.
create function vault_enclave.recovery_v4_material(p_pending boolean)
returns table (ceremony_id uuid, kind text, policy text, generation integer, sealed_root bytea, pending_root bytea,
               shard_user_kek bytea, shard_paper bytea, shard_card bytea,
               commit_user_kek bytea, commit_server bytea, commit_paper bytea, commit_card bytea)
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v vault_enclave.recovery_v4_vaults%rowtype;
begin
  if v_caller is null then return; end if;
  v := vault_enclave.recovery_v4_lock(v_caller);
  return query
    select c.ceremony_id, c.kind, c.policy, c.generation, c.sealed_root, c.pending_root,
           c.shard_user_kek, c.shard_paper, c.shard_card, c.commit_user_kek, c.commit_server, c.commit_paper, c.commit_card
      from vault_enclave.recovery_v4_ceremonies c
     where c.user_id = v_caller and c.status = case when coalesce(p_pending, false) then 'pending' else 'active' end;
end $$;

-- Cron: ends every pending ceremony past its TTL (no caller; returns how many).
create function vault_enclave.recovery_v4_expire_due() returns integer
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  r record;
  n integer := 0;
begin
  for r in select c.ceremony_id, c.user_id from vault_enclave.recovery_v4_ceremonies c
            where c.status = 'pending' and c.expires_at <= pg_catalog.clock_timestamp()
            order by c.expires_at limit 500 loop
    perform 1 from vault_enclave.recovery_v4_vaults v where v.user_id = r.user_id for update skip locked;
    if found then
      perform vault_enclave.recovery_v4_end(r.ceremony_id, 'aborted');
      update vault_enclave.recovery_v4_vaults set ver = ver + 1, updated_at = pg_catalog.clock_timestamp() where user_id = r.user_id;
      perform vault_enclave.append_audit(r.user_id, 'recovery_v4_expire', 'granted', 'ttl', null);
      n := n + 1;
    end if;
  end loop;
  return n;
end $$;

-- ---------------------------------------------------------------- rights

revoke all on function vault_enclave.recovery_v4_k(text) from public, rout_app;
revoke all on function vault_enclave.recovery_v4_factors(text) from public, rout_app;
revoke all on function vault_enclave.recovery_v4_begin_ok(text, text, text) from public, rout_app;
revoke all on function vault_enclave.recovery_v4_answer(text, boolean, text, uuid, bigint, text, uuid, uuid) from public, rout_app;
revoke all on function vault_enclave.recovery_v4_fresh(uuid, uuid) from public, rout_app;
revoke all on function vault_enclave.recovery_v4_consume(uuid, uuid) from public, rout_app;
revoke all on function vault_enclave.recovery_v4_end(uuid, text) from public, rout_app;
revoke all on function vault_enclave.recovery_v4_lock(uuid) from public, rout_app;
revoke all on function vault_enclave.recovery_v4_replay(uuid, text, text, bytea) from public, rout_app;
revoke all on function vault_enclave.recovery_v4_store(uuid, text, text, bytea, jsonb) from public, rout_app;
revoke all on function vault_enclave.recovery_v4_ids(uuid) from public, rout_app;
revoke all on function vault_enclave.recovery_v4_digest(text[]) from public, rout_app;
revoke all on function vault_enclave.recovery_v4_key_ok(text) from public, rout_app;

revoke all on function vault_enclave.recovery_v4_begin(text, bigint, text, text, uuid, uuid, integer, bytea, bytea, bytea, bytea, bytea, bytea, bytea, bytea, bytea) from public;
revoke all on function vault_enclave.recovery_v4_confirm_card(text, bigint, uuid, text) from public;
revoke all on function vault_enclave.recovery_v4_commit(text, bigint, uuid, uuid, bytea) from public;
revoke all on function vault_enclave.recovery_v4_abort(text, uuid) from public;
revoke all on function vault_enclave.recovery_v4_remove(text, bigint, uuid) from public;
revoke all on function vault_enclave.recovery_v4_report_compromise(text, text) from public;
revoke all on function vault_enclave.recovery_v4_server_share(uuid) from public;
revoke all on function vault_enclave.recovery_v4_status() from public;
revoke all on function vault_enclave.recovery_v4_material(boolean) from public;
revoke all on function vault_enclave.recovery_v4_expire_due() from public;
grant execute on function vault_enclave.recovery_v4_begin(text, bigint, text, text, uuid, uuid, integer, bytea, bytea, bytea, bytea, bytea, bytea, bytea, bytea, bytea) to rout_app;
grant execute on function vault_enclave.recovery_v4_confirm_card(text, bigint, uuid, text) to rout_app;
grant execute on function vault_enclave.recovery_v4_commit(text, bigint, uuid, uuid, bytea) to rout_app;
grant execute on function vault_enclave.recovery_v4_abort(text, uuid) to rout_app;
grant execute on function vault_enclave.recovery_v4_remove(text, bigint, uuid) to rout_app;
grant execute on function vault_enclave.recovery_v4_report_compromise(text, text) to rout_app;
grant execute on function vault_enclave.recovery_v4_server_share(uuid) to rout_app;
grant execute on function vault_enclave.recovery_v4_status() to rout_app;
grant execute on function vault_enclave.recovery_v4_material(boolean) to rout_app;
grant execute on function vault_enclave.recovery_v4_expire_due() to rout_app;

-- In-transaction proof: rout_app and PUBLIC reach no new table, every new
-- function is pinned and closed to PUBLIC, internal helpers are closed to rout_app.
do $$
declare v_bad text;
begin
  select string_agg(t, ', ') into v_bad from unnest(array['vault_enclave.recovery_v4_vaults',
    'vault_enclave.recovery_v4_ceremonies', 'vault_enclave.recovery_v4_idempotency']) t
   where pg_catalog.has_table_privilege('rout_app', t, 'select') or pg_catalog.has_table_privilege('rout_app', t, 'insert')
      or pg_catalog.has_table_privilege('rout_app', t, 'update') or pg_catalog.has_table_privilege('rout_app', t, 'delete')
      or pg_catalog.has_table_privilege('public', t, 'select')
      or not (select c.relrowsecurity from pg_catalog.pg_class c where c.oid = t::regclass)
      or exists (select 1 from pg_catalog.pg_policy p where p.polrelid = t::regclass);
  if v_bad is not null then raise exception '0272: reachable or policy-bearing table %', v_bad; end if;
  select string_agg(p.proname, ', ') into v_bad from pg_catalog.pg_proc p
   join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'vault_enclave' and p.proname like 'recovery\_v4\_%'
     and (not ('search_path=pg_catalog, pg_temp' = any (coalesce(p.proconfig, '{}')))
          or pg_catalog.has_function_privilege('public', p.oid, 'execute'));
  if v_bad is not null then raise exception '0272: unpinned or public function %', v_bad; end if;
  select string_agg(p.proname, ', ') into v_bad from pg_catalog.pg_proc p
   join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'vault_enclave' and p.proname = any (array['recovery_v4_is_mpc', 'recovery_v4_k', 'recovery_v4_factors',
     'recovery_v4_begin_ok', 'recovery_v4_answer', 'recovery_v4_fresh', 'recovery_v4_consume', 'recovery_v4_end',
     'recovery_v4_lock', 'recovery_v4_replay', 'recovery_v4_store', 'recovery_v4_ids', 'recovery_v4_digest', 'recovery_v4_key_ok'])
     and pg_catalog.has_function_privilege('rout_app', p.oid, 'execute');
  if v_bad is not null then raise exception '0272: rout_app can execute internal helper %', v_bad; end if;
end $$;
