// Fixture — the missing-csp suppression path. Here the CSP deliberately lives
// in next.config headers (static marketing site), so the marker below is the
// human taking responsibility for the exception.
// guardrails-allow: missing-csp
export function middleware() {
  return new Response("ok");
}
