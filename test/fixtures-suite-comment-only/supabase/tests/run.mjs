import { readdir } from "node:fs/promises";
// We expect 01_alpha_test.sql and 02_beta_test.sql to be present.
/* Historically 01_alpha_test.sql was the first suite added. */
const files = (await readdir(".")).filter((f) => f.endsWith("_test.sql")).sort();
console.log(files.length);
