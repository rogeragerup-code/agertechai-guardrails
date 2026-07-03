// Fixture — Report-Only alone must NOT satisfy missing-csp; the security
// floor requires an ENFORCING CSP in production.
export function middleware() {
  const res = new Response("ok");
  res.headers.set("Content-Security-Policy-Report-Only", "default-src 'self'");
  return res;
}
