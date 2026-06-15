-- ============================================================
-- sowers サークル予約アプリ 本番版 データベース設計
-- Supabase (PostgreSQL) 用 / 作成: メイ 2026-06-14
-- 使い方: Supabase ダッシュボード → SQL Editor に貼り付けて実行
-- ============================================================

-- ---------- 役割判定のヘルパー関数 ----------
create or replace function public.is_admin() returns boolean
  language sql stable security definer as $$
  select coalesce((select role = 'admin' from public.profiles where id = auth.uid()), false);
$$;

create or replace function public.is_staff_or_admin() returns boolean
  language sql stable security definer as $$
  select coalesce((select role in ('staff','admin') from public.profiles where id = auth.uid()), false);
$$;

-- ============================================================
-- 1. 会員 (profiles)  ※ auth.users と 1:1
-- ============================================================
create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  nickname    text not null,
  name        text,
  phone       text,
  email       text,                          -- 管理者が確認できる
  password    text,                           -- ご要望により管理者が確認できる（平文・小規模運用判断）
  role        text not null default 'participant' check (role in ('participant','staff','admin')),
  icon        text default 'a1',              -- 顔絵文字キー
  image       text,                           -- アイコン写真(URL)
  birth       date,                           -- 生年月日（保険加入者は必須）
  insurance   boolean not null default false, -- スポーツ保険 加入するか（登録時に決定）
  address     text,                           -- 住所（保険加入者は必須）
  insurance_enrolled_at timestamptz,          -- 加入が成立した日時（自動記録・手で変更不可。補償開始の目安）
  withdrawn   boolean not null default false, -- 管理者による強制退会（ソフト。復帰可能）
  created_at  timestamptz not null default now()
);

alter table public.profiles enable row level security;

-- 本人 または 管理者 のみ全項目を閲覧（メール・パスワード・住所を含む）
create policy "profiles_select_self_or_admin" on public.profiles
  for select using (id = auth.uid() or public.is_admin());
-- 本人 または 管理者 が更新
create policy "profiles_update_self_or_admin" on public.profiles
  for update using (id = auth.uid() or public.is_admin());
-- サインアップ時に本人の行を作成
create policy "profiles_insert_self" on public.profiles
  for insert with check (id = auth.uid());

-- 参加者一覧などで「名前・アイコン等の安全な項目だけ」を全員に見せるための公開ビュー
-- （メール・パスワード・住所・電話は含めない）
create or replace view public.member_directory
  with (security_invoker = false) as
  select id, nickname, name, icon, image, role, birth, insurance, withdrawn
  from public.profiles;
grant select on public.member_directory to anon, authenticated;

-- ---------- 保険「加入成立日」の自動記録（後出し防止） ----------
-- 加入(insurance=true)かつ 住所・生年月日が揃ったら、その時点を加入成立日として自動記録。
-- アプリ側からは値を指定できず、ここで上書きされる（過去日付の手入力＝後出しを防ぐ）。
-- 加入を取り消す/情報が欠けると null（＝補償対象外）に戻る。再加入すると新しい日付になる。
create or replace function public.stamp_insurance() returns trigger
  language plpgsql as $$
begin
  if NEW.insurance = true and NEW.birth is not null and NEW.address is not null then
    if NEW.insurance_enrolled_at is null then
      NEW.insurance_enrolled_at := now();
    end if;
  else
    NEW.insurance_enrolled_at := null;
  end if;
  return NEW;
end;
$$;
drop trigger if exists trg_stamp_insurance on public.profiles;
create trigger trg_stamp_insurance before insert or update on public.profiles
  for each row execute function public.stamp_insurance();

-- ============================================================
-- 2. イベント (events)
-- ============================================================
create table if not exists public.events (
  id         uuid primary key default gen_random_uuid(),
  date       date not null,
  sport      text not null,
  "time"     text not null,           -- 例: 20:00-22:00
  place      text not null,
  capacity   integer not null default 0,
  created_by uuid references public.profiles(id),
  created_at timestamptz not null default now()
);
alter table public.events enable row level security;
create policy "events_select_all" on public.events for select using (auth.role() = 'authenticated');
create policy "events_write_staff" on public.events for all
  using (public.is_staff_or_admin()) with check (public.is_staff_or_admin());

-- ============================================================
-- 3. 予約 (bookings)  ※ 友達(未登録)予約は user_id = null
-- ============================================================
create table if not exists public.bookings (
  id          uuid primary key default gen_random_uuid(),
  event_id    uuid not null references public.events(id) on delete cascade,
  user_id     uuid references public.profiles(id) on delete cascade,
  booked_by   uuid references public.profiles(id) on delete set null, -- 友達予約を入れた会員（友達の予約をキャンセルできる）
  friend_nick text,                    -- 未登録の友達の表示名
  friend_phone text,                   -- 未登録の友達の電話
  status      text not null default 'booked' check (status in ('booked','waitlist')),
  created_at  timestamptz not null default now()
);
alter table public.bookings enable row level security;
create policy "bookings_select_all" on public.bookings for select using (auth.role() = 'authenticated');
create policy "bookings_insert_auth" on public.bookings for insert
  with check (auth.role() = 'authenticated');
-- 本人の予約／自分が入れた友達予約／スタッフ・管理者 が変更・削除できる
create policy "bookings_modify_owner_or_staff" on public.bookings for update
  using (user_id = auth.uid() or booked_by = auth.uid() or public.is_staff_or_admin());
create policy "bookings_delete_owner_or_staff" on public.bookings for delete
  using (user_id = auth.uid() or booked_by = auth.uid() or public.is_staff_or_admin());

-- ---------- キャンセル待ちの自動繰り上げ ----------
-- 予約(booked)が削除され、定員に空きができたら、キャンセル待ちの先頭(古い順)を1件 booked に繰り上げる。
-- security definer なので、参加者本人のキャンセルでも他人のwaitlist行を繰り上げできる（RLSに依存しない）。
create or replace function public.promote_waitlist() returns trigger
  language plpgsql security definer as $$
declare
  cap int;
  booked_count int;
  next_id uuid;
begin
  if OLD.status = 'booked' then
    select capacity into cap from public.events where id = OLD.event_id;
    select count(*) into booked_count from public.bookings
      where event_id = OLD.event_id and status = 'booked';
    if cap is not null and booked_count < cap then
      select id into next_id from public.bookings
        where event_id = OLD.event_id and status = 'waitlist'
        order by created_at asc limit 1;
      if next_id is not null then
        update public.bookings set status = 'booked' where id = next_id;
      end if;
    end if;
  end if;
  return OLD;
end;
$$;
drop trigger if exists trg_promote_waitlist on public.bookings;
create trigger trg_promote_waitlist after delete on public.bookings
  for each row execute function public.promote_waitlist();

-- ============================================================
-- 4. 出欠 (attendance)
-- ============================================================
create table if not exists public.attendance (
  id        uuid primary key default gen_random_uuid(),
  event_id  uuid not null references public.events(id) on delete cascade,
  user_id   uuid references public.profiles(id) on delete cascade,
  phone     text,
  attended  boolean not null default true,
  created_at timestamptz not null default now(),
  unique (event_id, user_id)
);
alter table public.attendance enable row level security;
create policy "attendance_select_all" on public.attendance for select using (auth.role() = 'authenticated');
create policy "attendance_write_staff" on public.attendance for all
  using (public.is_staff_or_admin()) with check (public.is_staff_or_admin());

-- ============================================================
-- 5. 投票 (votes)  ※ ログは管理者のみ閲覧
-- ============================================================
create table if not exists public.votes (
  id         uuid primary key default gen_random_uuid(),
  event_id   uuid not null references public.events(id) on delete cascade,
  voter_id   uuid not null references public.profiles(id) on delete cascade,
  target_id  uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  unique (event_id, voter_id, target_id)
);
alter table public.votes enable row level security;
-- 自分の投票 または 管理者 が閲覧
create policy "votes_select_self_or_admin" on public.votes for select
  using (voter_id = auth.uid() or public.is_admin());
create policy "votes_insert_self" on public.votes for insert with check (voter_id = auth.uid());
create policy "votes_delete_self" on public.votes for delete using (voter_id = auth.uid());

-- 貢献ポイント（被投票数）を数えるための集計ビュー
create or replace view public.vote_points as
  select target_id as user_id, count(*)::int as points
  from public.votes group by target_id;
grant select on public.vote_points to authenticated;

-- ============================================================
-- 6. 電子チケット (tickets)
-- ============================================================
create table if not exists public.tickets (
  id        uuid primary key default gen_random_uuid(),
  user_id   uuid not null references public.profiles(id) on delete cascade,
  title     text not null default '無料参加チケット',
  used      boolean not null default false,
  used_at   timestamptz,
  issued_at timestamptz not null default now()
);
alter table public.tickets enable row level security;
create policy "tickets_select_self_or_admin" on public.tickets for select
  using (user_id = auth.uid() or public.is_admin());
-- 発行は管理者
create policy "tickets_insert_admin" on public.tickets for insert with check (public.is_admin());
-- 使用(更新)は本人 または 管理者
create policy "tickets_update_owner_or_admin" on public.tickets for update
  using (user_id = auth.uid() or public.is_admin());

-- ============================================================
-- 7. 場所と料金 (places) / 全体設定 (app_settings)
-- ============================================================
create table if not exists public.places (
  id       uuid primary key default gen_random_uuid(),
  name     text not null,
  per_hour integer not null default 0   -- 1時間あたりの場所代
);
alter table public.places enable row level security;
create policy "places_select_all" on public.places for select using (auth.role() = 'authenticated');
create policy "places_write_admin" on public.places for all
  using (public.is_admin()) with check (public.is_admin());

create table if not exists public.app_settings (
  id             integer primary key default 1 check (id = 1),  -- 単一行
  labor_per_hour integer not null default 1500,  -- 人件費(時給)
  fee            integer not null default 500     -- 参加費(1人)
);
alter table public.app_settings enable row level security;
create policy "settings_select_all" on public.app_settings for select using (auth.role() = 'authenticated');
create policy "settings_write_admin" on public.app_settings for all
  using (public.is_admin()) with check (public.is_admin());
insert into public.app_settings (id) values (1) on conflict (id) do nothing;

-- ============================================================
-- 8. 友達 (friends)
-- ============================================================
create table if not exists public.friends (
  id        uuid primary key default gen_random_uuid(),
  owner_id  uuid not null references public.profiles(id) on delete cascade,
  nick      text not null,
  phone     text not null
);
alter table public.friends enable row level security;
create policy "friends_owner_all" on public.friends for all
  using (owner_id = auth.uid()) with check (owner_id = auth.uid());

-- ============================================================
-- 9. メッセージ (messages)  ※ 管理者 → 会員 への直接連絡
-- ============================================================
create table if not exists public.messages (
  id         uuid primary key default gen_random_uuid(),
  to_user    uuid not null references public.profiles(id) on delete cascade,
  from_user  uuid references public.profiles(id) on delete set null,
  body       text not null,
  created_at timestamptz not null default now()
);
alter table public.messages enable row level security;
-- 受信者本人 または 管理者 が閲覧
create policy "messages_select_recipient_or_admin" on public.messages for select
  using (to_user = auth.uid() or public.is_admin());
-- 送信は管理者のみ
create policy "messages_insert_admin" on public.messages for insert
  with check (public.is_admin());
create policy "messages_delete_admin" on public.messages for delete using (public.is_admin());

-- ============================================================
-- 初期データ（場所のサンプル）
-- ============================================================
insert into public.places (name, per_hour) values
  ('沖洲インドアパーク', 2500),
  ('徳島市立体育館', 3300),
  ('スポセン', 3500)
on conflict do nothing;

-- ============================================================
-- 補足:
-- ・最初に登録したユーザーを管理者にするには、登録後に SQL Editor で:
--     update public.profiles set role='admin' where email='（あなたのメール）';
-- ・サインアップ後、アプリ側から profiles に本人の行を作成（保険の加入有無・住所・生年月日もこの時に保存）。
-- ============================================================
