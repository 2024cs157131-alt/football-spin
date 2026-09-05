/* Renders the admin panel exactly as the server does and parses its script.
 * `node --check api/admin.js` does NOT cover code inside the PANEL_HTML
 * template literal, which is how a broken escape shipped unnoticed.
 * Run:  node check-panel.js
 */
const fs = require("fs");
const src = fs.readFileSync(__dirname + "/api/admin.js", "utf8");
const start = src.indexOf("const PANEL_HTML = `");
if (start < 0) { console.error("PANEL_HTML not found"); process.exit(1); }
const lit = src.slice(start + "const PANEL_HTML = ".length);
const html = eval(lit.slice(0, lit.lastIndexOf("`;") + 1));
const m = html.match(/<script>([\s\S]*?)<\/script>/);
if (!m) { console.error("No <script> block in panel"); process.exit(1); }
try {
  new Function(m[1]);
  console.log("panel script OK");
} catch (e) {
  console.error("PANEL SCRIPT SYNTAX ERROR: " + e.message);
  m[1].split("\n").forEach((l, i) => {
    let n = 0;
    for (let j = 0; j < l.length; j++) if (l[j] === '"' && l[j - 1] !== "\\") n++;
    if (n % 2 === 1) console.error("  line " + (i + 1) + ": " + l.trim().slice(0, 110));
  });
  process.exit(1);
}
