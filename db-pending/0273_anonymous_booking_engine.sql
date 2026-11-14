-- 0273 — EXPAND: anonymous booking engine (Stap 7e), the SQL side of the
-- wasm/rout-zk engine from steps 7a-7d. HELD IN db-pending/: not applied on
-- Neon, not in db/, CODE_SCHEMA_LEVEL stays 0272 until the owner's GO.
--
-- What is stored (all of it public material or ciphertext; no guest identity):
--   anon_host_keys               one forward-secure chain per host: anchor PK_0
--                                (bound to the host row and signed by the
--                                enclave), current epoch and PK_t
--   anon_host_key_states         the current ratchet state SK_t, only as an
--                                RVE1 envelope (kind 9 hsk, holder 1 server
--                                vault, owner decision 2026-11-14); replaced
--                                in place on every advance, never kept twice
--   anon_epoch_links             PK_t -> PK_t' links signed by the old epoch key
--   anon_smt_trees / _roots      the nullifier tree of a chain and its signed
--                                root per tree epoch (one row per insertion)
--   anon_booking_tokens          a spent nullifier, the host-scoped pseudonym,
--                                the credential epoch and the BBS presentation
--   anon_pseudonym_invalidations pseudonyms a host has invalidated
--
-- The database cannot run pairings: it does NOT verify BBS signatures or
-- proofs. It enforces what it can prove itself: the caller from the
-- transaction context (vault_enclave.caller_user_id, never a parameter),
-- ownership, exact byte sizes, one linear history per chain and per tree
-- (compare-and-swap on ver / head epoch under FOR UPDATE), nullifier and
-- pseudonym uniqueness, credential epochs that have a published key, append-only
-- history rows, a fresh passkey step-up for creating or retiring a chain, and an
-- audit row for every call. Signature and proof checks happen in the crypto
-- worker (forward-secure.ts, smt.ts) before and after these calls.
--
-- Every new table: no rights for PUBLIC or rout_app, RLS on with one
-- restrictive deny_all policy. rout_app reaches the data only through the
-- SECURITY DEFINER entry points below (search_path = pg_catalog, pg_temp).
-- Denials return ok = false instead of raising, so their audit row commits.

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
                    'recovery_v4_replay', 'recovery_v4_compromise', 'recovery_v4_server_share',
                    'anon_host_key_init', 'anon_host_key_advance', 'anon_host_key_retire',
                    'anon_host_state_read', 'anon_booking_record', 'anon_booking_check',
                    'anon_pseudonym_invalidate'));

-- ---------------------------------------------------------------- shape helpers

-- RVE1 envelope of the ratchet state: magic, suite 1, kind 9 (hsk), holder 1
-- (server vault); 1663 bytes of envelope overhead + the 32-byte state.
create function vault_enclave.anon_is_hsk(p_env bytea) returns boolean
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select p_env is not null and octet_length(p_env) = 1695
     and substring(p_env from 1 for 4) = '\x52564531'::bytea
     and pg_catalog.get_byte(p_env, 4) = 1 and pg_catalog.get_byte(p_env, 5) = 9 and pg_catalog.get_byte(p_env, 6) = 1
$$;

-- BBS presentation (core_bbs PROOF_MIN_LEN 272 + 32 per undisclosed message,
-- at most MAX_MESSAGES = 49 of them).
create function vault_enclave.anon_is_proof(p bytea) returns boolean
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select p is not null and octet_length(p) between 272 and 1840 and (octet_length(p) - 272) % 32 = 0
$$;

create function vault_enclave.anon_len(p bytea, n integer) returns boolean
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select p is not null and octet_length(p) = n
$$;

-- Opaque random ids: hk_ (host chain) and st_ (nullifier tree), 256 bits hex.
create function vault_enclave.anon_id_ok(p_id text, p_prefix text) returns boolean
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select p_id is not null and p_id ~ ('^' || p_prefix || '_[0-9a-f]{64}$')
$$;

create function vault_enclave.anon_answer(p_op text, p_ok boolean, p_why text, p_epoch bigint, p_ver bigint)
returns jsonb language sql immutable set search_path = pg_catalog, pg_temp as $$
  select pg_catalog.jsonb_build_object('op', p_op, 'ok', p_ok, 'why', p_why, 'epoch', p_epoch, 'ver', p_ver)
$$;

-- ---------------------------------------------------------------- tables

create table vault_enclave.anon_host_keys (
  key_id text primary key,
  host_user_id uuid not null references public.users(id) on delete cascade,
  anchor_pk bytea not null,
  anchor_signer_pk bytea not null,
  anchor_sig bytea not null,
  epoch bigint not null default 0,
  current_pk bytea not null,
  ver bigint not null default 0,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  updated_at timestamptz not null default pg_catalog.clock_timestamp(),
  retired_at timestamptz,
  constraint anon_host_keys_id check (vault_enclave.anon_id_ok(key_id, 'hk')),
  constraint anon_host_keys_len check (octet_length(anchor_pk) = 96 and octet_length(anchor_signer_pk) = 96
                                       and octet_length(anchor_sig) = 80 and octet_length(current_pk) = 96),
  constraint anon_host_keys_epoch check (epoch between 0 and 9007199254740991 and ver >= 0
                                         and (epoch <> 0 or current_pk = anchor_pk))
);
-- One live chain per host.
create unique index anon_host_keys_one_active on vault_enclave.anon_host_keys (host_user_id) where retired_at is null;

create table vault_enclave.anon_host_key_states (
  key_id text primary key references vault_enclave.anon_host_keys(key_id) on delete cascade,
  state_envelope bytea not null,
  updated_at timestamptz not null default pg_catalog.clock_timestamp(),
  constraint anon_host_key_states_env check (vault_enclave.anon_is_hsk(state_envelope))
);

create table vault_enclave.anon_epoch_links (
  key_id text not null references vault_enclave.anon_host_keys(key_id) on delete cascade,
  from_epoch bigint not null,
  to_epoch bigint not null,
  next_pk bytea not null,
  link_sig bytea not null,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  primary key (key_id, to_epoch),
  constraint anon_epoch_links_from unique (key_id, from_epoch),
  -- forward_secure.rs MAX_ADVANCE = 65536; epochs stay exact in JavaScript.
  constraint anon_epoch_links_step check (from_epoch >= 0 and to_epoch > from_epoch
                                          and to_epoch - from_epoch <= 65536 and to_epoch <= 9007199254740991),
  constraint anon_epoch_links_len check (octet_length(next_pk) = 96 and octet_length(link_sig) = 80)
);

create table vault_enclave.anon_smt_trees (
  tree_id text primary key,
  key_id text not null unique references vault_enclave.anon_host_keys(key_id) on delete cascade,
  root_signer_pk bytea not null,
  head_epoch bigint not null default 0,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  constraint anon_smt_trees_id check (vault_enclave.anon_id_ok(tree_id, 'st')),
  constraint anon_smt_trees_len check (octet_length(root_signer_pk) = 96),
  constraint anon_smt_trees_head check (head_epoch >= 0)
);

create table vault_enclave.anon_smt_roots (
  tree_id text not null references vault_enclave.anon_smt_trees(tree_id) on delete cascade,
  epoch bigint not null,
  root bytea not null,
  root_sig bytea not null,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  primary key (tree_id, epoch),
  constraint anon_smt_roots_len check (octet_length(root) = 32 and octet_length(root_sig) = 80),
  -- Genesis is the empty 256-level Poseidon tree (smt.ts SMT_EMPTY_ROOT_HEX).
  constraint anon_smt_roots_genesis check (epoch >= 0 and (epoch <> 0
    or root = '\x46cb7f6a1a639693f80c2afddb77288ff88ff08ad19943a595c4c92633ec9505'::bytea))
);

create table vault_enclave.anon_booking_tokens (
  token_id uuid primary key default pg_catalog.gen_random_uuid(),
  tree_id text not null,
  root_epoch bigint not null,
  nullifier bytea not null,
  pseudonym bytea not null,
  credential_epoch bigint not null,
  presentation bytea not null,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  constraint anon_booking_tokens_root foreign key (tree_id, root_epoch)
    references vault_enclave.anon_smt_roots(tree_id, epoch) on delete cascade,
  -- A nullifier is spent once per tree; each insertion is exactly one root step.
  constraint anon_booking_tokens_nullifier unique (tree_id, nullifier),
  constraint anon_booking_tokens_pseudonym unique (tree_id, pseudonym),
  constraint anon_booking_tokens_step unique (tree_id, root_epoch),
  constraint anon_booking_tokens_shape check (root_epoch >= 1 and octet_length(nullifier) = 32
    and octet_length(pseudonym) = 32 and credential_epoch >= 0 and vault_enclave.anon_is_proof(presentation))
);

create table vault_enclave.anon_pseudonym_invalidations (
  tree_id text not null,
  pseudonym bytea not null,
  reason text not null,
  invalidated_at timestamptz not null default pg_catalog.clock_timestamp(),
  primary key (tree_id, pseudonym),
  constraint anon_pseudonym_invalidations_token foreign key (tree_id, pseudonym)
    references vault_enclave.anon_booking_tokens(tree_id, pseudonym) on delete cascade,
  constraint anon_pseudonym_invalidations_reason check (reason in ('cancelled', 'no_show', 'abuse', 'guest_request'))
);

-- History rows are append-only: no UPDATE, no direct DELETE or TRUNCATE. A
-- delete cascading from the host's account (trigger depth > 1) still passes.
create function vault_enclave.anon_append_only() returns trigger
language plpgsql set search_path = pg_catalog, pg_temp as $$
begin
  if tg_op = 'DELETE' and pg_catalog.pg_trigger_depth() > 1 then return old; end if;
  raise exception 'anon_append_only' using errcode = '42501';
end $$;

create trigger anon_epoch_links_append_only before update or delete on vault_enclave.anon_epoch_links
  for each row execute function vault_enclave.anon_append_only();
create trigger anon_epoch_links_no_truncate before truncate on vault_enclave.anon_epoch_links
  for each statement execute function vault_enclave.anon_append_only();
create trigger anon_smt_roots_append_only before update or delete on vault_enclave.anon_smt_roots
  for each row execute function vault_enclave.anon_append_only();
create trigger anon_smt_roots_no_truncate before truncate on vault_enclave.anon_smt_roots
  for each statement execute function vault_enclave.anon_append_only();
create trigger anon_booking_tokens_append_only before update or delete on vault_enclave.anon_booking_tokens
  for each row execute function vault_enclave.anon_append_only();
create trigger anon_booking_tokens_no_truncate before truncate on vault_enclave.anon_booking_tokens
  for each statement execute function vault_enclave.anon_append_only();
create trigger anon_pseudonym_invalidations_append_only before update or delete on vault_enclave.anon_pseudonym_invalidations
  for each row execute function vault_enclave.anon_append_only();
create trigger anon_pseudonym_invalidations_no_truncate before truncate on vault_enclave.anon_pseudonym_invalidations
  for each statement execute function vault_enclave.anon_append_only();

-- No rights for anyone but the owner, on every table of the schema.
revoke all on all tables in schema vault_enclave from public, rout_app;
alter table vault_enclave.anon_host_keys enable row level security;
alter table vault_enclave.anon_host_key_states enable row level security;
alter table vault_enclave.anon_epoch_links enable row level security;
alter table vault_enclave.anon_smt_trees enable row level security;
alter table vault_enclave.anon_smt_roots enable row level security;
alter table vault_enclave.anon_booking_tokens enable row level security;
alter table vault_enclave.anon_pseudonym_invalidations enable row level security;
create policy deny_all on vault_enclave.anon_host_keys as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.anon_host_key_states as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.anon_epoch_links as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.anon_smt_trees as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.anon_smt_roots as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.anon_booking_tokens as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.anon_pseudonym_invalidations as restrictive for all to public using (false) with check (false);

-- ---------------------------------------------------------------- internal helpers

-- The signed-in member from the transaction context, only if the member exists.
create function vault_enclave.anon_caller() returns uuid
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select u.id from public.users u where u.id = vault_enclave.caller_user_id()
$$;

-- Spends the caller's own passkey proof if it is unused and at most 300 s old
-- on the database clock; one statement, so a proof is spent at most once.
create function vault_enclave.anon_stepup(p_caller uuid, p_proof uuid) returns boolean
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
begin
  if p_proof is null then return false; end if;
  update vault_enclave.step_up_proofs s set consumed_at = pg_catalog.clock_timestamp()
   where s.proof_id = p_proof and s.user_id = p_caller and s.method = 'passkey' and s.consumed_at is null
     and s.verified_at >= pg_catalog.clock_timestamp() - interval '300 seconds'
     and s.verified_at <= pg_catalog.clock_timestamp() + interval '5 seconds';
  return found;
end $$;

-- ---------------------------------------------------------------- entry points

-- Creates the caller's chain: anchor PK_0 (epoch 0), the sealed SK_0 state,
-- the nullifier tree and its signed genesis root, in one transaction.
create function vault_enclave.anon_host_key_init(
  p_proof uuid, p_key_id text, p_anchor_pk bytea, p_anchor_signer_pk bytea, p_anchor_sig bytea,
  p_state bytea, p_tree_id text, p_root_signer_pk bytea, p_genesis_sig bytea)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.anon_caller();
  v_why text := 'ok';
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'anon_host_key_init', 'denied', 'no_caller', null);
    return vault_enclave.anon_answer('init', false, 'no_caller', null, null);
  end if;
  -- One init per host at a time (released at commit).
  perform pg_catalog.pg_advisory_xact_lock(273, pg_catalog.hashtext(v_caller::text));
  if not vault_enclave.anon_id_ok(p_key_id, 'hk') or not vault_enclave.anon_id_ok(p_tree_id, 'st')
     or not vault_enclave.anon_len(p_anchor_pk, 96) or not vault_enclave.anon_len(p_anchor_signer_pk, 96)
     or not vault_enclave.anon_len(p_anchor_sig, 80) or not vault_enclave.anon_len(p_root_signer_pk, 96)
     or not vault_enclave.anon_len(p_genesis_sig, 80) or not vault_enclave.anon_is_hsk(p_state) then
    v_why := 'malformed';
  elsif exists (select 1 from vault_enclave.anon_host_keys k where k.host_user_id = v_caller and k.retired_at is null) then
    v_why := 'busy';
  elsif exists (select 1 from vault_enclave.anon_host_keys k where k.key_id = p_key_id)
     or exists (select 1 from vault_enclave.anon_smt_trees t where t.tree_id = p_tree_id) then
    v_why := 'taken';
  elsif not vault_enclave.anon_stepup(v_caller, p_proof) then
    v_why := 'stepup';
  end if;
  if v_why <> 'ok' then
    perform vault_enclave.append_audit(v_caller, 'anon_host_key_init', 'denied', v_why, null);
    return vault_enclave.anon_answer('init', false, v_why, null, null);
  end if;
  insert into vault_enclave.anon_host_keys (key_id, host_user_id, anchor_pk, anchor_signer_pk, anchor_sig, current_pk)
  values (p_key_id, v_caller, p_anchor_pk, p_anchor_signer_pk, p_anchor_sig, p_anchor_pk);
  insert into vault_enclave.anon_host_key_states (key_id, state_envelope) values (p_key_id, p_state);
  insert into vault_enclave.anon_smt_trees (tree_id, key_id, root_signer_pk) values (p_tree_id, p_key_id, p_root_signer_pk);
  insert into vault_enclave.anon_smt_roots (tree_id, epoch, root, root_sig)
  values (p_tree_id, 0, '\x46cb7f6a1a639693f80c2afddb77288ff88ff08ad19943a595c4c92633ec9505'::bytea, p_genesis_sig);
  perform vault_enclave.append_audit(v_caller, 'anon_host_key_init', 'granted', 'ok', null);
  return vault_enclave.anon_answer('init', true, 'ok', 0, 0);
end $$;

-- Epoch transition t -> t': CAS on ver and epoch, one signed link, the new
-- PK_t' and the new sealed state replace the old ones in the same row.
create function vault_enclave.anon_host_key_advance(
  p_key_id text, p_ver bigint, p_from bigint, p_to bigint, p_next_pk bytea, p_link_sig bytea, p_state bytea)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.anon_caller();
  k vault_enclave.anon_host_keys%rowtype;
  v_why text := 'ok';
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'anon_host_key_advance', 'denied', 'no_caller', null);
    return vault_enclave.anon_answer('advance', false, 'no_caller', null, null);
  end if;
  select * into k from vault_enclave.anon_host_keys h where h.key_id = p_key_id and h.host_user_id = v_caller for update;
  if not found then
    v_why := 'unknown';
  elsif k.retired_at is not null then
    v_why := 'retired';
  elsif p_ver = k.ver - 1 and p_to = k.epoch and exists (select 1 from vault_enclave.anon_epoch_links l
          where l.key_id = k.key_id and l.from_epoch = p_from and l.to_epoch = p_to
            and l.next_pk = p_next_pk and l.link_sig = p_link_sig) then
    -- The same transition again (a retried request): its stored answer.
    perform vault_enclave.append_audit(v_caller, 'anon_host_key_advance', 'granted', 'replay', null);
    return vault_enclave.anon_answer('advance', true, 'replay', k.epoch, k.ver);
  elsif p_from is null or p_to is null or p_from < 0 or p_to <= p_from or p_to - p_from > 65536
     or p_to > 9007199254740991 or not vault_enclave.anon_len(p_next_pk, 96)
     or not vault_enclave.anon_len(p_link_sig, 80) or not vault_enclave.anon_is_hsk(p_state)
     or p_next_pk = k.current_pk then
    v_why := 'malformed';
  elsif p_ver is distinct from k.ver or p_from is distinct from k.epoch then
    v_why := 'conflict';
  elsif (select pg_catalog.count(*) from vault_enclave.anon_epoch_links l where l.key_id = k.key_id) >= 1024 then
    -- forward-secure.ts MAX_CHAIN_LINKS: a longer chain no guest could verify.
    v_why := 'chain_full';
  end if;
  if v_why <> 'ok' then
    perform vault_enclave.append_audit(v_caller, 'anon_host_key_advance', 'denied', v_why, null);
    return vault_enclave.anon_answer('advance', false, v_why, k.epoch, k.ver);
  end if;
  insert into vault_enclave.anon_epoch_links (key_id, from_epoch, to_epoch, next_pk, link_sig)
  values (k.key_id, p_from, p_to, p_next_pk, p_link_sig);
  update vault_enclave.anon_host_keys set epoch = p_to, current_pk = p_next_pk, ver = ver + 1,
         updated_at = pg_catalog.clock_timestamp() where key_id = k.key_id returning * into k;
  update vault_enclave.anon_host_key_states set state_envelope = p_state, updated_at = pg_catalog.clock_timestamp()
   where key_id = k.key_id;
  perform vault_enclave.append_audit(v_caller, 'anon_host_key_advance', 'granted', 'ok', null);
  return vault_enclave.anon_answer('advance', true, 'ok', k.epoch, k.ver);
end $$;

-- The caller's own sealed SK_t (never another member's, never a retired chain's).
create function vault_enclave.anon_host_key_state(p_key_id text)
returns table (granted boolean, epoch bigint, ver bigint, state_envelope bytea)
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.anon_caller();
  r record;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'anon_host_state_read', 'denied', 'no_caller', null);
    return query select false, null::bigint, null::bigint, null::bytea; return;
  end if;
  select k.epoch as e, k.ver as v, s.state_envelope as env into r
    from vault_enclave.anon_host_keys k join vault_enclave.anon_host_key_states s on s.key_id = k.key_id
   where k.key_id = p_key_id and k.host_user_id = v_caller and k.retired_at is null;
  if not found then
    perform vault_enclave.append_audit(v_caller, 'anon_host_state_read', 'denied', 'unknown', null);
    return query select false, null::bigint, null::bigint, null::bytea; return;
  end if;
  perform vault_enclave.append_audit(v_caller, 'anon_host_state_read', 'granted', 'ok', null);
  return query select true, r.e, r.v, r.env;
end $$;

-- Ends the caller's chain (fresh step-up): the sealed state is deleted; the
-- public chain, tree and tokens stay for verification of earlier bookings.
create function vault_enclave.anon_host_key_retire(p_proof uuid, p_key_id text)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.anon_caller();
  k vault_enclave.anon_host_keys%rowtype;
  v_why text := 'ok';
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'anon_host_key_retire', 'denied', 'no_caller', null);
    return vault_enclave.anon_answer('retire', false, 'no_caller', null, null);
  end if;
  select * into k from vault_enclave.anon_host_keys h where h.key_id = p_key_id and h.host_user_id = v_caller for update;
  if not found then
    v_why := 'unknown';
  elsif k.retired_at is not null then
    v_why := 'retired';
  elsif not vault_enclave.anon_stepup(v_caller, p_proof) then
    v_why := 'stepup';
  end if;
  if v_why <> 'ok' then
    perform vault_enclave.append_audit(v_caller, 'anon_host_key_retire', 'denied', v_why, null);
    return vault_enclave.anon_answer('retire', false, v_why, k.epoch, k.ver);
  end if;
  delete from vault_enclave.anon_host_key_states s where s.key_id = k.key_id;
  update vault_enclave.anon_host_keys set retired_at = pg_catalog.clock_timestamp(), ver = ver + 1,
         updated_at = pg_catalog.clock_timestamp() where key_id = k.key_id returning * into k;
  perform vault_enclave.append_audit(v_caller, 'anon_host_key_retire', 'granted', 'ok', null);
  return vault_enclave.anon_answer('retire', true, 'ok', k.epoch, k.ver);
end $$;

-- Records one anonymous booking on the caller's tree: the nullifier, the
-- host-scoped pseudonym and the presentation, plus the new signed root at
-- head + 1. Order of refusals: unknown, retired, malformed, (replay), spent,
-- pseudonym_taken, epoch (credential epoch without a published key or in the
-- future), conflict (stale head).
create function vault_enclave.anon_booking_record(
  p_tree_id text, p_head bigint, p_root bytea, p_root_sig bytea, p_nullifier bytea, p_pseudonym bytea,
  p_credential_epoch bigint, p_presentation bytea)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.anon_caller();
  t vault_enclave.anon_smt_trees%rowtype;
  k vault_enclave.anon_host_keys%rowtype;
  v_why text := 'ok';
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'anon_booking_record', 'denied', 'no_caller', null);
    return vault_enclave.anon_answer('record', false, 'no_caller', null, null);
  end if;
  select tr.* into t from vault_enclave.anon_smt_trees tr join vault_enclave.anon_host_keys h on h.key_id = tr.key_id
   where tr.tree_id = p_tree_id and h.host_user_id = v_caller for update of tr;
  if found then
    select * into k from vault_enclave.anon_host_keys h where h.key_id = t.key_id;
  end if;
  if t.tree_id is null then
    v_why := 'unknown';
  elsif k.retired_at is not null then
    v_why := 'retired';
  elsif p_head is null or p_head < 0 or not vault_enclave.anon_len(p_root, 32) or not vault_enclave.anon_len(p_root_sig, 80)
     or not vault_enclave.anon_len(p_nullifier, 32) or not vault_enclave.anon_len(p_pseudonym, 32)
     or p_credential_epoch is null or p_credential_epoch < 0 or not vault_enclave.anon_is_proof(p_presentation) then
    v_why := 'malformed';
  elsif exists (select 1 from vault_enclave.anon_booking_tokens b join vault_enclave.anon_smt_roots r
                  on r.tree_id = b.tree_id and r.epoch = b.root_epoch
                 where b.tree_id = t.tree_id and b.nullifier = p_nullifier and b.root_epoch = p_head + 1
                   and b.pseudonym = p_pseudonym and b.credential_epoch = p_credential_epoch
                   and b.presentation = p_presentation and r.root = p_root and r.root_sig = p_root_sig) then
    perform vault_enclave.append_audit(v_caller, 'anon_booking_record', 'granted', 'replay', null);
    return vault_enclave.anon_answer('record', true, 'replay', p_head + 1, null);
  elsif exists (select 1 from vault_enclave.anon_booking_tokens b where b.tree_id = t.tree_id and b.nullifier = p_nullifier) then
    v_why := 'spent';
  elsif exists (select 1 from vault_enclave.anon_booking_tokens b where b.tree_id = t.tree_id and b.pseudonym = p_pseudonym) then
    v_why := 'pseudonym_taken';
  elsif p_credential_epoch > k.epoch or (p_credential_epoch <> 0 and not exists (
          select 1 from vault_enclave.anon_epoch_links l where l.key_id = k.key_id and l.to_epoch = p_credential_epoch)) then
    v_why := 'epoch';
  elsif p_head <> t.head_epoch then
    v_why := 'conflict';
  end if;
  if v_why <> 'ok' then
    perform vault_enclave.append_audit(v_caller, 'anon_booking_record', 'denied', v_why, null);
    return vault_enclave.anon_answer('record', false, v_why, t.head_epoch, null);
  end if;
  insert into vault_enclave.anon_smt_roots (tree_id, epoch, root, root_sig) values (t.tree_id, p_head + 1, p_root, p_root_sig);
  insert into vault_enclave.anon_booking_tokens (tree_id, root_epoch, nullifier, pseudonym, credential_epoch, presentation)
  values (t.tree_id, p_head + 1, p_nullifier, p_pseudonym, p_credential_epoch, p_presentation);
  update vault_enclave.anon_smt_trees set head_epoch = p_head + 1 where tree_id = t.tree_id;
  perform vault_enclave.append_audit(v_caller, 'anon_booking_record', 'granted', 'ok', null);
  return vault_enclave.anon_answer('record', true, 'ok', p_head + 1, null);
end $$;

-- Whether a nullifier is spent on the caller's tree, and whether its
-- pseudonym was invalidated; also returns the head epoch.
create function vault_enclave.anon_booking_check(p_tree_id text, p_nullifier bytea)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.anon_caller();
  v_head bigint;
  v_spent boolean;
  v_invalid boolean;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'anon_booking_check', 'denied', 'no_caller', null);
    return vault_enclave.anon_answer('check', false, 'no_caller', null, null);
  end if;
  select tr.head_epoch into v_head from vault_enclave.anon_smt_trees tr
    join vault_enclave.anon_host_keys h on h.key_id = tr.key_id where tr.tree_id = p_tree_id and h.host_user_id = v_caller;
  if not found then
    perform vault_enclave.append_audit(v_caller, 'anon_booking_check', 'denied', 'unknown', null);
    return vault_enclave.anon_answer('check', false, 'unknown', null, null);
  end if;
  if not vault_enclave.anon_len(p_nullifier, 32) then
    perform vault_enclave.append_audit(v_caller, 'anon_booking_check', 'denied', 'malformed', null);
    return vault_enclave.anon_answer('check', false, 'malformed', v_head, null);
  end if;
  select true, exists (select 1 from vault_enclave.anon_pseudonym_invalidations i
                        where i.tree_id = b.tree_id and i.pseudonym = b.pseudonym)
    into v_spent, v_invalid
    from vault_enclave.anon_booking_tokens b where b.tree_id = p_tree_id and b.nullifier = p_nullifier;
  perform vault_enclave.append_audit(v_caller, 'anon_booking_check', 'granted', 'ok', null);
  return vault_enclave.anon_answer('check', true, 'ok', v_head, null)
    || pg_catalog.jsonb_build_object('spent', coalesce(v_spent, false), 'invalidated', coalesce(v_invalid, false));
end $$;

-- Invalidates a pseudonym recorded on the caller's tree (idempotent).
create function vault_enclave.anon_pseudonym_invalidate(p_tree_id text, p_pseudonym bytea, p_reason text)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.anon_caller();
  v_tree text;
  v_why text := 'ok';
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'anon_pseudonym_invalidate', 'denied', 'no_caller', null);
    return vault_enclave.anon_answer('invalidate', false, 'no_caller', null, null);
  end if;
  select tr.tree_id into v_tree from vault_enclave.anon_smt_trees tr
    join vault_enclave.anon_host_keys h on h.key_id = tr.key_id where tr.tree_id = p_tree_id and h.host_user_id = v_caller;
  if v_tree is null then
    v_why := 'unknown';
  elsif not vault_enclave.anon_len(p_pseudonym, 32) or p_reason is null
     or p_reason not in ('cancelled', 'no_show', 'abuse', 'guest_request') then
    v_why := 'malformed';
  elsif not exists (select 1 from vault_enclave.anon_booking_tokens b where b.tree_id = v_tree and b.pseudonym = p_pseudonym) then
    v_why := 'unknown';
  end if;
  if v_why <> 'ok' then
    perform vault_enclave.append_audit(v_caller, 'anon_pseudonym_invalidate', 'denied', v_why, null);
    return vault_enclave.anon_answer('invalidate', false, v_why, null, null);
  end if;
  insert into vault_enclave.anon_pseudonym_invalidations (tree_id, pseudonym, reason)
  values (v_tree, p_pseudonym, p_reason) on conflict (tree_id, pseudonym) do nothing;
  if not found then
    perform vault_enclave.append_audit(v_caller, 'anon_pseudonym_invalidate', 'granted', 'already', null);
    return vault_enclave.anon_answer('invalidate', true, 'already', null, null);
  end if;
  perform vault_enclave.append_audit(v_caller, 'anon_pseudonym_invalidate', 'granted', 'ok', null);
  return vault_enclave.anon_answer('invalidate', true, 'ok', null, null);
end $$;

-- Public, read-only: the anchor and every signed link of one chain, so an
-- anonymous guest can verify an epoch key without signing in. Only public
-- keys and signatures (hex); never the host id, the state or any token.
-- Not audited: it reads nothing private and would flood the audit chain.
create function vault_enclave.anon_host_chain(p_key_id text) returns jsonb
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select case when k.key_id is null then pg_catalog.jsonb_build_object('found', false)
  else pg_catalog.jsonb_build_object(
    'found', true, 'keyId', k.key_id, 'epoch', k.epoch, 'retired', k.retired_at is not null,
    'anchorPublicKey', pg_catalog.encode(k.anchor_pk, 'hex'),
    'anchorSignerPublicKey', pg_catalog.encode(k.anchor_signer_pk, 'hex'),
    'anchorSignature', pg_catalog.encode(k.anchor_sig, 'hex'),
    'currentPublicKey', pg_catalog.encode(k.current_pk, 'hex'),
    'links', coalesce((select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'from', l.from_epoch, 'to', l.to_epoch,
        'publicKey', pg_catalog.encode(l.next_pk, 'hex'), 'signature', pg_catalog.encode(l.link_sig, 'hex'))
        order by l.from_epoch)
      from vault_enclave.anon_epoch_links l where l.key_id = k.key_id), '[]'::jsonb)) end
  from (select 1) d left join vault_enclave.anon_host_keys k on k.key_id = p_key_id
$$;

-- ---------------------------------------------------------------- rights

revoke all on function vault_enclave.anon_is_hsk(bytea) from public, rout_app;
revoke all on function vault_enclave.anon_is_proof(bytea) from public, rout_app;
revoke all on function vault_enclave.anon_len(bytea, integer) from public, rout_app;
revoke all on function vault_enclave.anon_id_ok(text, text) from public, rout_app;
revoke all on function vault_enclave.anon_answer(text, boolean, text, bigint, bigint) from public, rout_app;
revoke all on function vault_enclave.anon_append_only() from public, rout_app;
revoke all on function vault_enclave.anon_caller() from public, rout_app;
revoke all on function vault_enclave.anon_stepup(uuid, uuid) from public, rout_app;

revoke all on function vault_enclave.anon_host_key_init(uuid, text, bytea, bytea, bytea, bytea, text, bytea, bytea) from public;
revoke all on function vault_enclave.anon_host_key_advance(text, bigint, bigint, bigint, bytea, bytea, bytea) from public;
revoke all on function vault_enclave.anon_host_key_state(text) from public;
revoke all on function vault_enclave.anon_host_key_retire(uuid, text) from public;
revoke all on function vault_enclave.anon_booking_record(text, bigint, bytea, bytea, bytea, bytea, bigint, bytea) from public;
revoke all on function vault_enclave.anon_booking_check(text, bytea) from public;
revoke all on function vault_enclave.anon_pseudonym_invalidate(text, bytea, text) from public;
revoke all on function vault_enclave.anon_host_chain(text) from public;
grant execute on function vault_enclave.anon_host_key_init(uuid, text, bytea, bytea, bytea, bytea, text, bytea, bytea) to rout_app;
grant execute on function vault_enclave.anon_host_key_advance(text, bigint, bigint, bigint, bytea, bytea, bytea) to rout_app;
grant execute on function vault_enclave.anon_host_key_state(text) to rout_app;
grant execute on function vault_enclave.anon_host_key_retire(uuid, text) to rout_app;
grant execute on function vault_enclave.anon_booking_record(text, bigint, bytea, bytea, bytea, bytea, bigint, bytea) to rout_app;
grant execute on function vault_enclave.anon_booking_check(text, bytea) to rout_app;
grant execute on function vault_enclave.anon_pseudonym_invalidate(text, bytea, text) to rout_app;
grant execute on function vault_enclave.anon_host_chain(text) to rout_app;

-- In-transaction proof: no new table is reachable by rout_app or PUBLIC, each
-- has RLS on with exactly the restrictive deny_all policy, every new function
-- is pinned and closed to PUBLIC, and internal helpers are closed to rout_app.
do $$
declare v_bad text;
begin
  select string_agg(t, ', ') into v_bad from unnest(array['vault_enclave.anon_host_keys',
    'vault_enclave.anon_host_key_states', 'vault_enclave.anon_epoch_links', 'vault_enclave.anon_smt_trees',
    'vault_enclave.anon_smt_roots', 'vault_enclave.anon_booking_tokens', 'vault_enclave.anon_pseudonym_invalidations']) t
   where pg_catalog.has_table_privilege('rout_app', t, 'select') or pg_catalog.has_table_privilege('rout_app', t, 'insert')
      or pg_catalog.has_table_privilege('rout_app', t, 'update') or pg_catalog.has_table_privilege('rout_app', t, 'delete')
      or pg_catalog.has_table_privilege('public', t, 'select') or pg_catalog.has_table_privilege('public', t, 'insert')
      or not (select c.relrowsecurity from pg_catalog.pg_class c where c.oid = t::regclass)
      or (select pg_catalog.count(*) from pg_catalog.pg_policy p where p.polrelid = t::regclass) <> 1
      or not exists (select 1 from pg_catalog.pg_policy p where p.polrelid = t::regclass and p.polname = 'deny_all'
                       and not p.polpermissive and p.polcmd = '*'
                       and pg_catalog.pg_get_expr(p.polqual, p.polrelid) = 'false'
                       and pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) = 'false');
  if v_bad is not null then raise exception '0273: reachable or wrongly guarded table %', v_bad; end if;
  select string_agg(c.relname, ', ') into v_bad from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
   where n.nspname = 'vault_enclave' and c.relkind in ('r', 'p', 'v', 'm')
     and (pg_catalog.has_table_privilege('rout_app', c.oid, 'select') or pg_catalog.has_table_privilege('public', c.oid, 'select'));
  if v_bad is not null then raise exception '0273: vault_enclave table readable by rout_app or PUBLIC: %', v_bad; end if;
  select string_agg(p.proname, ', ') into v_bad from pg_catalog.pg_proc p
   join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'vault_enclave' and p.proname like 'anon\_%'
     and (not ('search_path=pg_catalog, pg_temp' = any (coalesce(p.proconfig, '{}')))
          or pg_catalog.has_function_privilege('public', p.oid, 'execute'));
  if v_bad is not null then raise exception '0273: unpinned or public function %', v_bad; end if;
  select string_agg(p.proname, ', ') into v_bad from pg_catalog.pg_proc p
   join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'vault_enclave' and p.proname = any (array['anon_is_hsk', 'anon_is_proof', 'anon_len', 'anon_id_ok',
     'anon_answer', 'anon_append_only', 'anon_caller', 'anon_stepup'])
     and pg_catalog.has_function_privilege('rout_app', p.oid, 'execute');
  if v_bad is not null then raise exception '0273: rout_app can execute internal helper %', v_bad; end if;
end $$;
