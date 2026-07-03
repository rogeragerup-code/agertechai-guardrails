// Deliberately-insecure fixture — proves supabase/functions/ (edge functions,
// a prime service-role-key location) is scanned. Never shipped.
declare const Deno: any;

const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

export function handler() {
  // secret-in-log
  console.log("using key", serviceRoleKey);
  return new Response("ok");
}
