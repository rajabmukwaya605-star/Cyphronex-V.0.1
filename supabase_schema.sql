-- ==============================================================================
-- Cyphronex-Bluevane Supabase Database Schema & Security Policies
-- End-to-End Encrypted Architecture with Real-Time Capabilities
-- ==============================================================================

-- 1. Profiles Table
create table if not exists public.profiles (
  id uuid references auth.users on delete cascade primary key,
  username text unique,
  display_name text,
  cyphron_tag text unique,
  avatar_url text,
  bio text default 'Secured by Cyphronex-Bluevane E2EE',
  public_key text, -- Base64 ECDH P-256 Public Key for E2EE key agreement
  key_fingerprint text, -- 60-digit or 12-block safety number fingerprint
  status text default 'online',
  theme_preference jsonb default '{"id":"stealth","accent":"#00f0ff"}'::jsonb,
  last_seen timestamptz default timezone('utc'::text, now()) not null,
  created_at timestamptz default timezone('utc'::text, now()) not null
);

-- Enable RLS for Profiles
alter table public.profiles enable row level security;

create policy "Public profiles are viewable by authenticated users"
  on public.profiles for select
  to authenticated
  using (true);

create policy "Users can insert their own profile"
  on public.profiles for insert
  to authenticated
  with check (auth.uid() = id);

create policy "Users can update their own profile"
  on public.profiles for update
  to authenticated
  using (auth.uid() = id);

-- 2. Contacts Table (Individual contact adding & verification)
create table if not exists public.contacts (
  id uuid default gen_random_uuid() primary key,
  user_id uuid references public.profiles(id) on delete cascade not null,
  contact_user_id uuid references public.profiles(id) on delete cascade not null,
  status text check (status in ('pending', 'accepted', 'blocked')) default 'pending',
  nickname text,
  safety_number_verified boolean default false,
  created_at timestamptz default timezone('utc'::text, now()) not null,
  unique (user_id, contact_user_id)
);

alter table public.contacts enable row level security;

create policy "Users can see their own contacts"
  on public.contacts for select
  to authenticated
  using (auth.uid() = user_id or auth.uid() = contact_user_id);

create policy "Users can add contacts"
  on public.contacts for insert
  to authenticated
  with check (auth.uid() = user_id);

create policy "Users can update their own contacts"
  on public.contacts for update
  to authenticated
  using (auth.uid() = user_id or auth.uid() = contact_user_id);

create policy "Users can delete their own contacts"
  on public.contacts for delete
  to authenticated
  using (auth.uid() = user_id or auth.uid() = contact_user_id);

-- 3. Conversations Table
create table if not exists public.conversations (
  id uuid default gen_random_uuid() primary key,
  type text check (type in ('direct', 'group')) default 'direct',
  name text,
  created_at timestamptz default timezone('utc'::text, now()) not null,
  updated_at timestamptz default timezone('utc'::text, now()) not null
);

alter table public.conversations enable row level security;

-- 4. Conversation Participants
create table if not exists public.conversation_participants (
  conversation_id uuid references public.conversations(id) on delete cascade not null,
  user_id uuid references public.profiles(id) on delete cascade not null,
  joined_at timestamptz default timezone('utc'::text, now()) not null,
  primary key (conversation_id, user_id)
);

alter table public.conversation_participants enable row level security;

create policy "Participants can view their conversation memberships"
  on public.conversation_participants for select
  to authenticated
  using (auth.uid() = user_id or exists (
    select 1 from public.conversation_participants cp
    where cp.conversation_id = conversation_participants.conversation_id
    and cp.user_id = auth.uid()
  ));

create policy "Users can join conversations"
  on public.conversation_participants for insert
  to authenticated
  with check (auth.uid() = user_id);

create policy "Conversations viewable by participants"
  on public.conversations for select
  to authenticated
  using (
    exists (
      select 1 from public.conversation_participants cp
      where cp.conversation_id = conversations.id
      and cp.user_id = auth.uid()
    )
  );

create policy "Authenticated users can create conversations"
  on public.conversations for insert
  to authenticated
  with check (true);

-- 5. Messages Table (Zero-Knowledge E2EE Storage)
-- Notice: encrypted_content and iv contain AES-256-GCM encrypted payload. The server cannot read it.
create table if not exists public.messages (
  id uuid default gen_random_uuid() primary key,
  conversation_id uuid references public.conversations(id) on delete cascade not null,
  sender_id uuid references public.profiles(id) on delete cascade not null,
  encrypted_content text not null, -- Base64 AES-GCM Ciphertext
  iv text not null,                -- Base64 12-byte initialization vector
  message_type text check (message_type in ('text', 'file', 'image', 'audio', 'link', 'system')) default 'text',
  attachment_meta jsonb default null, -- Encrypted file info (encrypted key, storage path, mime type, size, name)
  reactions jsonb default '{}'::jsonb,
  is_read boolean default false,
  created_at timestamptz default timezone('utc'::text, now()) not null
);

alter table public.messages enable row level security;

create policy "Participants can view messages"
  on public.messages for select
  to authenticated
  using (
    exists (
      select 1 from public.conversation_participants cp
      where cp.conversation_id = messages.conversation_id
      and cp.user_id = auth.uid()
    )
  );

create policy "Participants can insert messages"
  on public.messages for insert
  to authenticated
  with check (
    auth.uid() = sender_id and
    exists (
      select 1 from public.conversation_participants cp
      where cp.conversation_id = messages.conversation_id
      and cp.user_id = auth.uid()
    )
  );

create policy "Users can update their own messages or reactions"
  on public.messages for update
  to authenticated
  using (
    exists (
      select 1 from public.conversation_participants cp
      where cp.conversation_id = messages.conversation_id
      and cp.user_id = auth.uid()
    )
  );

-- 6. Enable Supabase Realtime for Messages & Statuses
alter publication supabase_realtime add table public.messages;
alter publication supabase_realtime add table public.contacts;
alter publication supabase_realtime add table public.profiles;

-- 7. Automated profile creation on Auth Sign-Up
create or replace function public.handle_new_user()
returns trigger as $$
declare
  gen_tag text;
begin
  gen_tag := 'CYPH-' || upper(substr(md5(random()::text), 1, 4)) || '-' || upper(substr(md5(random()::text), 5, 4));
  
  insert into public.profiles (id, username, display_name, cyphron_tag, avatar_url)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'username', split_part(new.email, '@', 1)),
    coalesce(new.raw_user_meta_data->>'display_name', split_part(new.email, '@', 1)),
    gen_tag,
    coalesce(new.raw_user_meta_data->>'avatar_url', 'https://api.dicebear.com/7.x/bottts/svg?seed=' || new.id)
  );
  return new;
end;
$$ language plpgsql security definer;

-- Trigger for auth.users
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();
