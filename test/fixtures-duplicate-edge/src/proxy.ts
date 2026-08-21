import { NextResponse } from "next/server";
export default function proxy() {
  const res = NextResponse.next();
  res.headers.set("Content-Security-Policy", "default-src 'self'");
  return res;
}
