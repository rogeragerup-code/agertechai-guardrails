// Fixture: the CSP header appears ONLY in comments. Rule 7 must still fire
// missing-csp — a comment is not a header.
import { NextResponse } from "next/server";

/**
 * Old version set:
 *   response.headers.set("Content-Security-Policy", csp);
 * (kept here for reference — a block comment must not satisfy the rule)
 */
export function proxy() {
  const response = NextResponse.next();
  // response.headers.set("Content-Security-Policy", csp);
  return response;
}
