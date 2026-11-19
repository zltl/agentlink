// t544: browser term emulator is retired — dashboard must not ship createTerm.
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const here = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(here, "../src/dashboard.html"), "utf8");
if (html.includes("createTerm") || html.includes("/v1/web") || html.includes("new WebSocket")) {
  console.error("dashboard still embeds browser controller surfaces");
  process.exit(1);
}
if (!html.includes("not available in the browser")) {
  console.error("dashboard missing sealed-client boundary copy");
  process.exit(1);
}
console.log("ok: management-only dashboard");
