import { withSupabase } from "npm:@supabase/server@1";

type Body = { action?: unknown; name?: unknown; workerId?: unknown; password?: unknown };
const json = (body: unknown, status = 200) => Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function makeTemporaryPassword(): string {
  const random = crypto.getRandomValues(new Uint8Array(20));
  const chars = Array.from(random, byte => alphabet[byte & 31]);
  return chars.join("").match(/.{1,5}/g)!.join("-");
}
const makeAuthEmail = (workerId: string) => `${workerId.toLowerCase()}@workers.fairshift.invalid`;

export default {
  fetch: withSupabase({ auth: "user" }, async (request, context) => {
    if (request.method !== "POST") return json({ ok: false, error: "Method not allowed" }, 405);
    let expectedOrigin: string;
    try { expectedOrigin = new URL(Deno.env.get("APP_ORIGIN") ?? "").origin; }
    catch { return json({ ok: false, error: "Worker accounts are not configured" }, 503); }
    if (!expectedOrigin || request.headers.get("origin") !== expectedOrigin) return json({ ok: false, error: "Request origin is not allowed" }, 403);
    if (Number(request.headers.get("content-length") ?? "0") > 4096) return json({ ok: false, error: "Request is too large" }, 413);
    if (!context.userClaims?.sub || !context.jwtClaims?.sub) return json({ ok: false, error: "Sign-in is required" }, 401);

    let body: Body;
    try { body = await request.json(); } catch { return json({ ok: false, error: "Invalid request body" }, 400); }
    const action = body.action;

    if (action === "complete-password") {
      const { data: worker, error } = await context.supabase.from("profiles")
        .select("id,organization_id,role,must_change_password,temp_password_expires_at,temp_password_issued_at")
        .eq("id", context.userClaims.sub).maybeSingle();
      if (error || !worker || worker.role !== "worker" || !worker.must_change_password) return json({ ok: false, error: "Worker password setup is not available" }, 403);
      const expiresAt = worker.temp_password_expires_at ? Date.parse(worker.temp_password_expires_at) : 0;
      if (!expiresAt || expiresAt < Date.now()) return json({ ok: false, error: "Temporary password expired. Ask your admin for a new one." }, 410);
      const issuedAt = worker.temp_password_issued_at ? Math.floor(Date.parse(worker.temp_password_issued_at) / 1000) : 0;
      if (Number(context.jwtClaims.auth_time ?? 0) < issuedAt) return json({ ok: false, error: "Sign out and sign in with the current temporary password first." }, 403);
      const password = typeof body.password === "string" ? body.password : "";
      if (password.length < 12 || password.length > 128) return json({ ok: false, error: "Choose a password with 12 to 128 characters" }, 400);
      const { error: passwordError } = await context.supabaseAdmin.auth.admin.updateUserById(worker.id, { password });
      if (passwordError) return json({ ok: false, error: "Could not set the password. Try again." }, 400);
      const { error: profileError } = await context.supabaseAdmin.from("profiles").update({
        must_change_password: false, temp_password_expires_at: null, temp_password_issued_at: null,
      }).eq("id", worker.id).eq("organization_id", worker.organization_id);
      if (profileError) return json({ ok: false, error: "Password changed; ask your admin to finish account activation." }, 500);
      return json({ ok: true });
    }

    if (context.jwtClaims.aal !== "aal2") return json({ ok: false, error: "Admin multi-factor sign-in is required" }, 403);
    const { data: admin, error: adminError } = await context.supabase.from("profiles")
      .select("organization_id,role").eq("id", context.userClaims.sub).maybeSingle();
    if (adminError || !admin || admin.role !== "admin") return json({ ok: false, error: "Admin access is required" }, 403);

    if (action === "create") {
      const name = typeof body.name === "string" ? body.name.trim() : "";
      const workerId = typeof body.workerId === "string" ? body.workerId.trim().toUpperCase() : "";
      if (name.length < 2 || name.length > 100 || /[\u0000-\u001f<>]/.test(name)) return json({ ok: false, error: "Invalid worker name" }, 400);
      if (!/^[A-Z0-9][A-Z0-9-]{3,23}$/.test(workerId)) return json({ ok: false, error: "Invalid worker ID" }, 400);
      const { data: duplicate } = await context.supabaseAdmin.from("profiles").select("id")
        .eq("employee_id", workerId).maybeSingle();
      if (duplicate) return json({ ok: false, error: "Worker ID already exists" }, 409);
      const temporaryPassword = makeTemporaryPassword();
      const { data: created, error: createError } = await context.supabaseAdmin.auth.admin.createUser({
        email: makeAuthEmail(workerId), password: temporaryPassword, email_confirm: true,
        user_metadata: { full_name: name, employee_id: workerId },
      });
      if (createError || !created.user) return json({ ok: false, error: "Could not create the worker account. Check the ID and try again." }, 409);
      const { error: profileError } = await context.supabaseAdmin.from("profiles").insert({
        id: created.user.id, organization_id: admin.organization_id, full_name: name,
        employee_id: workerId, role: "worker", must_change_password: true,
        temp_password_issued_at: new Date().toISOString(), temp_password_expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      });
      if (profileError) {
        await context.supabaseAdmin.auth.admin.deleteUser(created.user.id);
        return json({ ok: false, error: "Could not finish worker setup. No account was kept; try again." }, 500);
      }
      return json({ ok: true, workerId, temporaryPassword, expiresInHours: 24 });
    }

    if (action === "reset") {
      const workerId = typeof body.workerId === "string" ? body.workerId.trim().toUpperCase() : "";
      if (!/^[A-Z0-9][A-Z0-9-]{3,23}$/.test(workerId)) return json({ ok: false, error: "Invalid worker ID" }, 400);
      const { data: worker } = await context.supabaseAdmin.from("profiles").select("id,full_name")
        .eq("organization_id", admin.organization_id).eq("employee_id", workerId).eq("role", "worker").maybeSingle();
      if (!worker) return json({ ok: false, error: "Worker not found" }, 404);
      const temporaryPassword = makeTemporaryPassword();
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
      const issuedAt = new Date().toISOString();
      const { error: profileError } = await context.supabaseAdmin.from("profiles").update({
        must_change_password: true, temp_password_expires_at: expiresAt, temp_password_issued_at: issuedAt,
      }).eq("id", worker.id).eq("organization_id", admin.organization_id);
      if (profileError) return json({ ok: false, error: "Could not reset worker access. Try again." }, 500);
      const { error: passwordError } = await context.supabaseAdmin.auth.admin.updateUserById(worker.id, { password: temporaryPassword });
      if (passwordError) return json({ ok: false, error: "Access was paused, but the temporary password could not be set. Retry the reset." }, 500);
      return json({ ok: true, workerId, name: worker.full_name, temporaryPassword, expiresInHours: 24 });
    }
    return json({ ok: false, error: "Unknown action" }, 400);
  }),
};
