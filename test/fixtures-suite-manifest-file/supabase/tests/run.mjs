import { readdir, readFile } from "node:fs/promises";
const forventet = (await readFile("MANIFEST", "utf8"))
  .split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
const files = (await readdir(".")).filter((f) => f.endsWith("_test.sql")).sort();
if (forventet.some((f) => !files.includes(f))) process.exit(1);
if (files.some((f) => !forventet.includes(f))) process.exit(1);
