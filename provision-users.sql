-- Provision only the first organisation and initial administrator here.
-- Create the admin account in Supabase Authentication using the admin email
-- privately provided by the organisation owner. Never put credentials in Git.

-- Create the organisation once and keep its returned UUID:
-- insert into public.organizations (name) values ('Your Organisation') returning id;

-- After creating the Auth user in the Supabase dashboard, assign its UUID:
-- insert into public.profiles (id, organization_id, full_name, role)
-- values ('AUTH_USER_UUID', 'ORGANIZATION_UUID', 'Admin Name', 'admin');
-- Admin enrolls an authenticator on first FairShift sign-in.
