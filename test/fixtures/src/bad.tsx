"use client";
// Deliberately-insecure fixture — every line here should trip a guardrails rule.
// This file is NEVER shipped; it exists only to prove the checker catches things.

export async function bad(supabase: any, comment: string, nextParam: string) {
  // select-star
  const rows = await supabase.from("orders").select("*");

  // service-role-client (this is a "use client" file)
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

  // weak-redirect (no strong regex anywhere in this file)
  const safe = nextParam.startsWith("//") ? "/" : nextParam;

  // dangerous-html
  const el = <div dangerouslySetInnerHTML={{ __html: comment }} />;

  // cors-wildcard
  const headers = { "Access-Control-Allow-Origin": "*" };

  return { rows, key, safe, el, headers };
}
