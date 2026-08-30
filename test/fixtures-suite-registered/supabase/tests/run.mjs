import { readdir } from "node:fs/promises";
const FORVENTEDE = ["01_alpha_test.sql", "02_beta_test.sql"];
const files = (await readdir(".")).filter((f) => f.endsWith("_test.sql")).sort();
const mangler = FORVENTEDE.filter((f) => !files.includes(f));
const ukjente = files.filter((f) => !FORVENTEDE.includes(f));
if (mangler.length || ukjente.length) process.exit(1);
