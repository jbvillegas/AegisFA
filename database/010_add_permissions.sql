-- 1) Ensure the org exists (safe no-op if already present)
insert into organizations (id, name)
values ('org-id', 'org-name')
on conflict (id) do nothing;

-- 2) Provision your app user with write access
insert into users (id, org_id, email, role)
values (
  'id',
  'org-id',
  'email',
  'role'
)
on conflict (id) do update
set
  org_id = excluded.org_id,
  email = excluded.email,
  role = excluded.role;

-- 3) Verify
select id, org_id, email, role
from users
where id = 'id';