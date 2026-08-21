// Proxy uten CSP noe sted — skal være en HARD feil, ikke en advarsel.
import { type NextRequest } from "next/server";
import { updateSession } from "@/lib/supabase/middleware";

export default async function proxy(request: NextRequest) {
  return await updateSession(request);
}
