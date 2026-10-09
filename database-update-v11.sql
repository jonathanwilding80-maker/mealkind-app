-- MealKind v11: simple Care Circle (menu list + calendar + password per group)
-- Run once in Supabase > SQL Editor > New query > Run.

create extension if not exists pgcrypto with schema extensions;

alter table public.families
  add column if not exists menu jsonb not null default '[]'::jsonb,
  add column if not exists passcode_hash text;

-- Who may see a circle: the family (organizer code) or anyone with the group password
create or replace function public._mk_can_view(f public.families, p_code text, p_token uuid)
returns boolean language sql stable set search_path to '' as $$
  select (p_token is not null and f.family_token = p_token)
      or (f.passcode_hash is not null and p_code is not null
          and extensions.crypt(btrim(p_code), f.passcode_hash) = f.passcode_hash)
$$;
revoke execute on function public._mk_can_view(public.families,text,uuid) from public, anon, authenticated;

-- Family sets / changes the group password (4-8 digits)
create or replace function public.mk_set_passcode(p_slug text, p_family_token uuid, p_code text)
returns jsonb language plpgsql security definer set search_path to '' as $$
declare f public.families;
begin
  select * into f from public.families where slug = p_slug for update;
  if not found or f.family_token is distinct from p_family_token then raise exception 'not_family'; end if;
  if btrim(coalesce(p_code,'')) !~ '^\d{4,8}$' then raise exception 'bad_code_format'; end if;
  update public.families set passcode_hash = extensions.crypt(btrim(p_code), extensions.gen_salt('bf')) where id = f.id;
  return jsonb_build_object('ok',true);
end $$;

-- Family sends the chosen recipes to the circle (replaces the list)
create or replace function public.mk_set_menu(p_slug text, p_family_token uuid, p_items jsonb)
returns jsonb language plpgsql security definer set search_path to '' as $$
declare f public.families;
begin
  select * into f from public.families where slug = p_slug for update;
  if not found or f.family_token is distinct from p_family_token then raise exception 'not_family'; end if;
  if jsonb_typeof(p_items) <> 'array' or jsonb_array_length(p_items) > 150 then raise exception 'bad_items'; end if;
  update public.families set menu = coalesce((
      select jsonb_agg(jsonb_build_object('name',left(x->>'name',160),'course',lower(left(coalesce(x->>'course','dinner'),20))))
      from jsonb_array_elements(p_items) x where coalesce(btrim(x->>'name'),'') <> ''),'[]'::jsonb)
   where id = f.id;
  return jsonb_build_object('ok',true);
end $$;

-- The circle page (password or family code required)
create or replace function public.mk_get_circle(p_slug text, p_code text default null, p_family_token uuid default null)
returns jsonb language plpgsql stable security definer set search_path to '' as $$
declare f public.families;
begin
  select * into f from public.families where slug = p_slug;
  if not found then raise exception 'not_found'; end if;
  if f.passcode_hash is null and (p_family_token is null or f.family_token is distinct from p_family_token) then raise exception 'no_password_yet'; end if;
  if not public._mk_can_view(f, p_code, p_family_token) then raise exception 'bad_code'; end if;
  return jsonb_build_object(
    'slug', f.slug, 'display_name', f.display_name, 'recipient_name', f.recipient_name, 'story', f.story,
    'photo_url', f.photo_url, 'drop_off_window', f.drop_off_window,
    'allergy_flags', f.allergy_flags, 'dietary_flags', f.dietary_flags, 'treatment_dates', f.treatment_dates,
    'gofundme_url', f.gofundme_url, 'amazon_url', f.amazon_url, 'menu', f.menu,
    'is_family', (p_family_token is not null and f.family_token = p_family_token),
    'has_password', f.passcode_hash is not null,
    'meals', coalesce((select jsonb_agg(jsonb_build_object('id',i.id,'date',i.date_slot,'course',coalesce(i.time_window,lower(i.task_type),'dinner'),
                          'recipe',coalesce(i.claim_note,i.title),'who',i.claimed_by_name,'status',i.status) order by i.date_slot, i.created_at)
                       from public.care_circle_items i where i.family_id = f.id and i.kind = 'meal' and i.status <> 'open'
                         and i.date_slot >= current_date - 1), '[]'::jsonb));
end $$;

-- A friend signs up to bring a recipe on a day
create or replace function public.mk_join_meal(p_slug text, p_code text, p_date date, p_course text, p_recipe text,
  p_name text, p_phone text default null, p_email text default null, p_reminders text[] default '{2 days before,Morning of}', p_family_token uuid default null)
returns jsonb language plpgsql security definer set search_path to '' as $$
declare f public.families; v_id uuid; v_token uuid := gen_random_uuid();
  v_name text := nullif(left(btrim(coalesce(p_name,'')),80),'');
  v_phone text := public._mk_phone(p_phone); v_email text := public._mk_email(p_email);
  v_course text := case when lower(coalesce(p_course,'')) in ('breakfast','lunch','dinner','snack','dessert') then lower(p_course) else 'dinner' end;
  v_prefs text[] := array(select x from unnest(coalesce(p_reminders,'{}')) x where x in ('2 days before','Morning of','Email too'));
begin
  select * into f from public.families where slug = p_slug;
  if not found then raise exception 'not_found'; end if;
  if not public._mk_can_view(f, p_code, p_family_token) then raise exception 'bad_code'; end if;
  if v_name is null then raise exception 'missing_name'; end if;
  if nullif(btrim(coalesce(p_recipe,'')),'') is null then raise exception 'missing_recipe'; end if;
  if p_date is null or p_date < current_date or p_date > current_date + 120 then raise exception 'bad_date'; end if;
  if (select count(*) from public.care_circle_items where family_id=f.id and created_at > now() - interval '1 hour') > 60 then raise exception 'slow_down'; end if;
  insert into public.care_circle_items(family_id,kind,task_type,title,date_slot,time_window,status,claimed_by_name,claimed_by_phone,claimed_by_email,claim_note,reminder_prefs,claim_token)
  values (f.id,'meal',initcap(v_course),left(btrim(p_recipe),160),p_date,v_course,'claimed',v_name,v_phone,v_email,left(btrim(p_recipe),160),v_prefs,v_token)
  returning id into v_id;
  perform public._mk_queue_reminders(v_id, p_date, v_prefs, v_phone, v_email);
  return jsonb_build_object('ok',true,'id',v_id,'claim_token',v_token,'drop_off_window',f.drop_off_window,'drop_off_note',f.drop_off_note);
end $$;

-- Family marks / unmarks a treatment day
create or replace function public.mk_toggle_treatment(p_slug text, p_family_token uuid, p_date date)
returns jsonb language plpgsql security definer set search_path to '' as $$
declare f public.families;
begin
  select * into f from public.families where slug = p_slug for update;
  if not found or f.family_token is distinct from p_family_token then raise exception 'not_family'; end if;
  update public.families set treatment_dates = case when p_date = any(treatment_dates)
      then array_remove(treatment_dates, p_date) else array_append(treatment_dates, p_date) end where id = f.id;
  return jsonb_build_object('ok',true);
end $$;

grant execute on function public.mk_set_passcode(text,uuid,text), public.mk_set_menu(text,uuid,jsonb),
  public.mk_get_circle(text,text,uuid), public.mk_join_meal(text,text,date,text,text,text,text,text,text[],uuid),
  public.mk_toggle_treatment(text,uuid,date) to anon, authenticated;

-- The old open page functions are replaced by the password-protected ones above
revoke execute on function public.mk_get_page(text) from anon, authenticated, public;
revoke execute on function public.mk_claim_slot(text,uuid,text,text,text,text,text[]) from anon, authenticated, public;
revoke execute on function public.mk_offer_help(text,text,date,text,text,text,text,text[]) from anon, authenticated, public;
revoke execute on function public.mk_post_message(text,text,text,text,boolean) from anon, authenticated, public;

-- Close direct table access (everything goes through the functions above)
drop policy if exists "care circle items insertable" on public.care_circle_items;
drop policy if exists "care circle items updatable (claiming, status changes)" on public.care_circle_items;
drop policy if exists "care circle items readable" on public.care_circle_items;
drop policy if exists "families insertable (family creates their own board)" on public.families;
drop policy if exists "families readable by slug" on public.families;
drop policy if exists "messages readable" on public.messages_photos;
drop policy if exists "messages insertable" on public.messages_photos;
