# FairShift — role-based login and worker access

FairShift has separate login paths for workers and employers/admins. The selected path is only a convenience; the role stored in `profiles` decides access. There is no public sign-up or client-side role assignment.

## Worker accounts without email

An admin signs in with the organisation's admin email and authenticator. In **Worker accounts and access**, the admin enters a worker name and creates or assigns a globally unique worker ID. FairShift generates a one-time starter password. The admin gives the ID and starter password to the worker in person; no worker email address is requested and no invite email is sent. The starter password expires after 24 hours. On first sign-in, the worker must choose a private password of at least 12 characters before the app will allow access to worker data. Admins can reset a lost password; the new starter password is shown once.

Workers sign in using their worker ID and password. Supabase Auth stores an internal, non-deliverable identifier derived from the worker ID because its password login uses email or phone identifiers. Workers never see or need that identifier, and the app does not send email to it. The admin's actual email stays in the Supabase Auth account and is not written into the app or this repository.

## Quick local demo

Open `index.html` directly from the `outputs` folder. When opened as a local file with no Supabase project configured, FairShift provides a local-only demo login:

- Admin ID `admin`, password `FairShiftDemo26!`
- Worker ID `FS-1001`, password `WorkerDemo26!`
- Worker ID `FS-1002`, password `WorkerDemo27!`

The admin demo can add more demo workers; their accounts are saved in this browser only. This mode is for presentations and sample data, not real staff or payroll. For a public GitHub Pages preview, add `?demo=1` to the site URL (for example, `https://ACCOUNT.github.io/fairshift/?demo=1`). Demo data stays in each visitor’s browser and is not a real account system. Do not use this mode for real workers or payroll.

## Required setup

1. Create a Supabase project. Enable email/password for admin sign-in, TOTP MFA, and set the minimum password length to at least 12 characters. Public account sign-up should remain disabled.
2. Run `schema.sql` in the Supabase SQL editor. It creates organizations, protected roles, worker IDs, temporary-password state, shift/pay/report tables, restricted grants, and row-level security. Worker data access is blocked until a worker replaces the starter password. Admin-only data requires an AAL2 authenticator session.
3. Add the project URL and publishable key to `supabase-config.js`. The publishable key is expected to be public. Never put a Supabase secret or `service_role` key in the browser or Git.
4. Create an organisation row and the first admin Auth account privately in Supabase. Use `provision-users.sql` to assign its UUID the `admin` role. Do not put the admin email or password in this repository.
5. Deploy the worker account function from the folder containing `supabase/config.toml`:

   ```text
   supabase functions deploy manage-worker --project-ref YOUR_PROJECT_REF
   supabase secrets set APP_ORIGIN=https://YOUR_CLOUD_RUN_HOST
   ```

   The function requires a valid signed-in user JWT, checks the caller's admin role and AAL2 claim on the server, and creates/resets accounts using Supabase's server-only Auth Admin API. It is configured with `verify_jwt = true`.
6. Add the Cloud Run URL to Supabase Auth's allowed redirect URLs for the admin password reset flow. The worker starter-password flow does not use email.
7. Build and deploy the `outputs` folder to Cloud Run. The Dockerfile serves only the app files; the server config adds security headers and blocks public access to the Supabase function source. Use HTTPS.

## Security behavior

- Only admins with MFA can create a worker account or reset its starter password. The Edge Function checks role and MFA itself; hiding the form in the browser is not the security boundary.
- Worker IDs are globally unique. The temporary password is generated server-side, returned once to the admin, never saved in the app, and expires in 24 hours.
- Workers must sign in with the current temporary password before they can set a private password. RLS blocks shifts, pay, and reports until activation is complete. Lost passwords are reset by an admin and handed to the worker in person.
- Profile roles cannot be changed by signed-in users. Supabase RLS scopes access by worker and organisation.
- Sessions are stored in tab-scoped `sessionStorage`. JavaScript can access browser-stored tokens; HTTP-only server sessions would be stronger for sensitive production use.
- Safety reports do not store a reporter ID. Site, details, or timing may still let an employer infer who reported. Avoid names and sensitive personal details.

## Prototype limits

The schedule, pay example, and workforce metrics are still sample data. Worker directory and safety reports use protected Supabase tables. Do not enter real payroll or worker data until the project, database policies, account recovery, backups, and incident response are reviewed.

There are no default credentials. A live login cannot be used until your Supabase project is configured and the admin profile is provisioned.

## Before launch

- Confirm no service-role key appears in the client config, deployed HTML, or Git history.
- Test worker, manager, and admin access; cross-organisation isolation; starter-password expiry; first-password change; admin password reset; and MFA enforcement.
- Configure Auth settings, email reset redirects, session expiry, and account recovery.
- Ask workers to review the translated copy and the in-person credential handoff process.

This is an implementation scaffold, not a security certification.
