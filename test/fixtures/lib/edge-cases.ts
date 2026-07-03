// Deliberately-insecure fixture — proves lib/ is scanned and the regex
// hardenings of 2026-07-03 catch the realistic variants. Never shipped.

export async function edgeCases(supabase: any, res: any) {
  // select-star — embedded-resource form (leading * followed by a comma)
  const joined = await supabase.from("orders").select("*, profiles(*)");

  // cors-wildcard — lowercase header name (the fetch/undici normalized form)
  const h1 = { "access-control-allow-origin": "*" };

  // cors-wildcard — backtick-quoted
  res.headers.set(`Access-Control-Allow-Origin`, `*`);

  // An inline marker covers only its own line — the line after it must still
  // fire select-star (over-suppression regression test).
  const a = await supabase.from("x").select("*"); // guardrails-allow: select-star
  const b = await supabase.from("y").select("*");

  // A standalone marker comment above the line still suppresses:
  // guardrails-allow: select-star
  const c = await supabase.from("z").select("*");

  return { joined, h1, a, b, c };
}
