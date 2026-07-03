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

  // secret-in-log (uses an api key, not the service-role one, so only this rule fires)
  console.log("boot", process.env.ANTHROPIC_API_KEY);

  // JSX-form marker above the line must suppress (regression test, 2026-07-03):
  {/* guardrails-allow: dangerous-html */}
  const ok = <div dangerouslySetInnerHTML={{ __html: "<b>static</b>" }} />;

  return { rows, key, safe, el, headers, ok };
}
