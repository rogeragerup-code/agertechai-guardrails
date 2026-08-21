// Next 16-konvensjonen MED nonce-CSP — dette er formen som skal være ren.
import { NextResponse, type NextRequest } from "next/server";

export default function proxy(request: NextRequest) {
  const nonce = crypto.randomUUID();
  const res = NextResponse.next({ request });
  res.headers.set("Content-Security-Policy", `script-src 'nonce-${nonce}' 'strict-dynamic'`);
  return res;
}
