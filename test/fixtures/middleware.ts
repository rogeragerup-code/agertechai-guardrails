// missing-csp: this middleware sets no CSP header, so the rule must flag it.
export function middleware() {
  return new Response("ok");
}
