-- FairShift baseline role and row-level access controls.
-- Run in the Supabase SQL editor after creating the first Auth users.

create extension if not exists pgcrypto;
create schema if not exists app_private;
revoke all on schema app_private from public, anon;
grant usage on schema app_private to authenticated;

create table if not exists public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  organization_id uuid not null references public.organizations(id),
  full_name text not null,
  employee_id text,
  must_change_password boolean not null default false,
  temp_password_expires_at timestamptz,
  temp_password_issued_at timestamptz,
  role text not null check (role in ('worker','manager','admin')),
  unique (id, organization_id),
  created_at timestamptz not null default now()
);

alter table public.profiles add column if not exists employee_id text;
alter table public.profiles add column if not exists must_change_password boolean not null default false;
alter table public.profiles add column if not exists temp_password_expires_at timestamptz;
alter table public.profiles add column if not exists temp_password_issued_at timestamptz;
create unique index if not exists profiles_org_employee_id_unique on public.profiles(organization_id, employee_id) where employee_id is not null;
create unique index if not exists profiles_employee_id_global_unique on public.profiles(employee_id) where employee_id is not null;

create table if not exists public.shifts (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id),
  worker_id uuid not null,
  site text not null,
  starts_at timestamptz not null,
  ends_at timestamptz not null,
  status text not null default 'scheduled' check (status in ('scheduled','checked_in','completed','cancelled')),
  created_at timestamptz not null default now(),
  check (ends_at > starts_at),
  foreign key (worker_id, organization_id) references public.profiles(id, organization_id)
);
create index if not exists shifts_worker_start_idx on public.shifts(worker_id, starts_at);
create index if not exists shifts_org_start_idx on public.shifts(organization_id, starts_at);

create table if not exists public.pay_statements (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id),
  worker_id uuid not null,
  period_start date not null,
  period_end date not null,
  currency text not null default 'INR',
  regular_hours numeric(7,2) not null default 0,
  overtime_hours numeric(7,2) not null default 0,
  gross_amount numeric(12,2) not null,
  deductions numeric(12,2) not null default 0,
  created_at timestamptz not null default now(),
  check (period_end >= period_start),
  check (regular_hours >= 0 and overtime_hours >= 0 and gross_amount >= 0 and deductions >= 0),
  foreign key (worker_id, organization_id) references public.profiles(id, organization_id)
);
create index if not exists pay_statements_worker_period_idx on public.pay_statements(worker_id, period_end desc);

-- Deliberately has no reporter/user id: the report contents aren't linked to an account.
create table if not exists public.safety_reports (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id),
  site text not null check (length(site) between 1 and 120),
  description text not null check (length(description) between 3 and 4000),
  status text not null default 'open' check (status in ('open','in_review','resolved')),
  created_at timestamptz not null default now(),
  resolved_at timestamptz
);
create index if not exists safety_reports_org_status_idx on public.safety_reports(organization_id, status, created_at desc);

create or replace function app_private.current_role()
returns text language sql stable security definer set search_path = pg_catalog
as $$ select p.role from public.profiles p where p.id = (select auth.uid()) $$;
create or replace function app_private.worker_ready()
returns boolean language sql stable security definer set search_path = pg_catalog
as $$ select coalesce((select not p.must_change_password from public.profiles p where p.id = (select auth.uid())), false) $$;
create or replace function app_private.current_org()
returns uuid language sql stable security definer set search_path = pg_catalog
as $$ select p.organization_id from public.profiles p where p.id = (select auth.uid()) $$;
revoke all on function app_private.current_role() from public, anon;
revoke all on function app_private.current_org() from public, anon;
revoke all on function app_private.worker_ready() from public, anon;
grant execute on function app_private.current_role() to authenticated;
grant execute on function app_private.current_org() to authenticated;
grant execute on function app_private.worker_ready() to authenticated;

alter table public.organizations enable row level security;
alter table public.profiles enable row level security;
alter table public.shifts enable row level security;
alter table public.pay_statements enable row level security;
alter table public.safety_reports enable row level security;

revoke all on public.organizations, public.profiles, public.shifts, public.pay_statements, public.safety_reports from anon, authenticated;
grant select on public.organizations, public.profiles, public.shifts, public.pay_statements, public.safety_reports to authenticated;
grant insert on public.safety_reports to authenticated;
grant update(status,resolved_at) on public.safety_reports to authenticated;
grant insert, update, delete on public.shifts to authenticated;

create policy org_read_same_org on public.organizations for select to authenticated
  using (id = (select app_private.current_org()));
create policy profile_read_self_or_org_admin on public.profiles for select to authenticated
  using (id = (select auth.uid()) or
    (organization_id = (select app_private.current_org()) and (select app_private.current_role()) = 'admin' and (select auth.jwt()->>'aal') = 'aal2'));

create policy shifts_worker_or_org_manager_read on public.shifts for select to authenticated
  using ((worker_id = (select auth.uid()) and (select app_private.worker_ready())) or
    (organization_id = (select app_private.current_org()) and (select app_private.current_role()) in ('manager','admin') and ((select app_private.current_role()) <> 'admin' or (select auth.jwt()->>'aal') = 'aal2')));
create policy shifts_manager_write_same_org on public.shifts for insert to authenticated
  with check (organization_id = (select app_private.current_org()) and (select app_private.current_role()) in ('manager','admin') and ((select app_private.current_role()) <> 'admin' or (select auth.jwt()->>'aal') = 'aal2'));
create policy shifts_manager_update_same_org on public.shifts for update to authenticated
  using (organization_id = (select app_private.current_org()) and (select app_private.current_role()) in ('manager','admin') and ((select app_private.current_role()) <> 'admin' or (select auth.jwt()->>'aal') = 'aal2'))
  with check (organization_id = (select app_private.current_org()) and (select app_private.current_role()) in ('manager','admin') and ((select app_private.current_role()) <> 'admin' or (select auth.jwt()->>'aal') = 'aal2'));
create policy shifts_manager_delete_same_org on public.shifts for delete to authenticated
  using (organization_id = (select app_private.current_org()) and (select app_private.current_role()) in ('manager','admin') and ((select app_private.current_role()) <> 'admin' or (select auth.jwt()->>'aal') = 'aal2'));

create policy pay_read_worker_or_mfa_admin on public.pay_statements for select to authenticated
  using ((worker_id = (select auth.uid()) and (select app_private.worker_ready())) or
    (organization_id = (select app_private.current_org()) and (select app_private.current_role()) = 'admin' and (select auth.jwt()->>'aal') = 'aal2'));

create policy safety_worker_submit_org on public.safety_reports for insert to authenticated
  with check (organization_id = (select app_private.current_org()) and (select app_private.current_role()) = 'worker' and (select app_private.worker_ready()) and status = 'open');
create policy safety_manager_read_org on public.safety_reports for select to authenticated
  using (organization_id = (select app_private.current_org()) and (select app_private.current_role()) in ('manager','admin') and ((select app_private.current_role()) <> 'admin' or (select auth.jwt()->>'aal') = 'aal2'));
create policy safety_manager_update_org on public.safety_reports for update to authenticated
  using (organization_id = (select app_private.current_org()) and (select app_private.current_role()) in ('manager','admin') and ((select app_private.current_role()) <> 'admin' or (select auth.jwt()->>'aal') = 'aal2'))
  with check (organization_id = (select app_private.current_org()) and (select app_private.current_role()) in ('manager','admin') and ((select app_private.current_role()) <> 'admin' or (select auth.jwt()->>'aal') = 'aal2'));

-- Provision users out-of-band: create the Auth user in Supabase, then insert a profile
-- with that Auth user UUID, the organization's UUID, and one of the allowed roles.
-- Never let a signed-in user insert/update their own role or organization.
