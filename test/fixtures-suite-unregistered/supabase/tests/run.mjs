import { readdir } from "node:fs/promises";
const files = (await readdir(".")).filter((f) => f.endsWith("_test.sql")).sort();
if (files.length === 0) process.exit(1);
console.log(files.length);
