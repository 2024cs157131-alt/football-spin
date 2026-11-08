/* Renders the admin panel exactly as the server does, parses its script, and
 * checks that every element the script reaches for actually exists in the
 * markup. `node --check api/admin.js` does NOT cover code inside the
 * PANEL_HTML template literal, which is how a broken escape shipped unnoticed,
 * and nothing at all used to catch an id that a redesign renamed or dropped.
 * Run:  node api/check-panel.js
 */
const fs = require("fs");
const path = require("path");

const candidates = [
  path.join(__dirname, "admin.js"),
  path.join(__dirname, "api", "admin.js"),
];
const file = candidates.find(fs.existsSync);
if (!file) { console.error("admin.js not found next to this script"); process.exit(1); }

const src = fs.readFileSync(file, "utf8");
const start = src.indexOf("const PANEL_HTML = `");
if (start < 0) { console.error("PANEL_HTML not found"); process.exit(1); }
const lit = src.slice(start + "const PANEL_HTML = ".length);
const html = eval(lit.slice(0, lit.lastIndexOf("`;") + 1));

const m = html.match(/<script>([\s\S]*?)<\/script>/);
if (!m) { console.error("No <script> block in panel"); process.exit(1); }
const script = m[1];

let bad = 0;

/* 1. the panel script must parse the way the browser will parse it */
try {
  new Function(script);
  console.log("PASS  panel script parses");
} catch (e) {
  bad++;
  console.error("FAIL  panel script syntax error: " + e.message);
  // an unterminated string is the usual cause — point at the odd-quote lines
  script.split("\n").forEach((l, i) => {
    let n = 0;
    for (let j = 0; j < l.length; j++) if (l[j] === '"' && l[j - 1] !== "\\") n++;
    if (n % 2 === 1) console.error("      line " + (i + 1) + ": " + l.trim().slice(0, 110));
  });
}

/* 2. every getElementById target must exist in the markup */
const present = new Set();
for (const mm of html.matchAll(/\bid="([^"]+)"/g)) present.add(mm[1]);

const wanted = new Set();
for (const mm of script.matchAll(/getElementById\(\s*"([^"]+)"\s*\)/g)) wanted.add(mm[1]);
// ids reached through the array-of-names helpers, e.g. ["daily","players"].forEach(...)
for (const mm of script.matchAll(/\[([^\]]*?)\]\s*\n?\s*\.?\s*forEach\(\s*(labelCells|function)/g)) {
  for (const q of mm[1].matchAll(/"([A-Za-z][\w-]*)"/g)) wanted.add(q[1]);
}

const missing = [...wanted].filter(id => !present.has(id)).sort();
if (missing.length) {
  bad++;
  console.error("FAIL  script reaches for ids that are not in the markup:");
  missing.forEach(id => console.error("      #" + id));
} else {
  console.log("PASS  all " + wanted.size + " referenced ids exist");
}

/* 3. tables the responsive labeller walks need a thead and a tbody */
for (const mm of html.matchAll(/<table id="([^"]+)"([^>]*)>([\s\S]*?)<\/table>/g)) {
  const [, id, attrs, inner] = mm;
  if (!/<thead/.test(inner) || !/<tbody/.test(inner)) {
    bad++;
    console.error("FAIL  table #" + id + " is missing a thead or tbody");
  }
  if (/class="[^"]*\bresp\b/.test(attrs)) {
    const heads = (inner.match(/<th[\s>]/g) || []).length;
    if (!heads) { bad++; console.error("FAIL  responsive table #" + id + " has no header cells"); }
  }
}

/* 4. each tab button must have a matching page, and vice versa */
const tabs = [...html.matchAll(/data-p="([^"]+)"/g)].map(x => x[1]);
const pages = [...html.matchAll(/class="page[^"]*" id="p-([^"]+)"/g)].map(x => x[1]);
const tabGaps = tabs.filter(t => !pages.includes(t));
const pageGaps = pages.filter(p => !tabs.includes(p));
if (tabGaps.length || pageGaps.length) {
  bad++;
  tabGaps.forEach(t => console.error("FAIL  tab '" + t + "' has no #p-" + t + " page"));
  pageGaps.forEach(p => console.error("FAIL  page #p-" + p + " has no tab"));
} else if (tabs.length) {
  console.log("PASS  " + tabs.length + " tabs each match a page");
}

/* 5. no stray template-literal interpolation left in the panel */
if (/\$\{/.test(html)) {
  bad++;
  console.error("FAIL  unresolved ${...} in the rendered panel");
}

console.log(bad ? "\n" + bad + " CHECK(S) FAILED" : "\nall panel checks passed");
process.exit(bad ? 1 : 0);
