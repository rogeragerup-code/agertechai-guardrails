// Proxy uten CSP, men next.config setter en statisk en: den dokumenterte
// unntaket for en statisk markedsføringsflate. Skal ADVARE, ikke felle.
import { type NextRequest } from "next/server";

export default function proxy(_request: NextRequest) {}
