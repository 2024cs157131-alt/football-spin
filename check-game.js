/* Static checks for public/index.html.
 *
 * The game is one HTML file with one inline script, so a mistyped or deleted
 * element id fails only at runtime, in whichever code path happens to touch
 * it. That is how a sheet got deleted by an over-greedy edit and the page
 * stopped booting. These checks run in a second and catch it at the source.
 *
 * Run:  node check-game.js
 */
const fs = require("fs");
const path = require("path");

const file = path.join(__dirname, "public", "index.html");
const html = fs.readFileSync(file, "utf8");

let bad = 0;
const fail = (msg, detail) => {
  bad++;
  console.error("FAIL  " + msg);
  if (detail) String(detail).split("\n").forEach(l => console.error("      " + l));
};
const pass = msg => console.log("PASS  " + msg);

/* ---- 1. the inline script must parse ---- */
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
if (!scripts.length) fail("no inline <script> found");
scripts.forEach((src, i) => {
  try { new Function(src); } catch (e) { fail("script block " + i + " does not parse", e.message); }
});
if (!bad) pass("inline script parses");

/* ---- 2. every element the script reaches for must exist ---- */
const markup = html.slice(0, html.indexOf("<script>"));
const present = new Set([...markup.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]));
// ids the script creates at runtime rather than finding in the markup
const RUNTIME_PREFIXES = ["bet-", "amt-", "res-", "del-"];

const src = scripts.join("\n");
const wanted = new Map();
for (const m of src.matchAll(/\$\(\s*"([^"]+)"\s*\)/g)) wanted.set(m[1], "$(...)");
for (const m of src.matchAll(/getElementById\(\s*"([^"]+)"\s*\)/g)) wanted.set(m[1], "getElementById");

const missing = [...wanted.keys()]
  .filter(id => !present.has(id) && !RUNTIME_PREFIXES.some(p => id.startsWith(p)))
  .sort();
if (missing.length) fail("script reaches for ids that are not in the markup:", missing.map(i => "#" + i).join("\n"));
else pass("all " + wanted.size + " referenced ids exist");

/* ---- 3. no literal \uXXXX left in the markup ----
   These are JavaScript escapes. In HTML they render as the raw characters
   "…", which is what players actually saw on the loading screen. */
const litEsc = [...markup.matchAll(/\\u[0-9A-Fa-f]{4}/g)];
if (litEsc.length) {
  fail("literal \\uXXXX escapes in the markup (they only work inside <script>):",
    litEsc.map(m => markup.slice(Math.max(0, m.index - 50), m.index + 6).replace(/\n/g, " ")).join("\n"));
} else pass("no literal escapes in the markup");

/* ---- 4. tags balance, so a bad edit cannot swallow later markup ---- */
const opens = (markup.match(/<div\b/g) || []).length;
const closes = (markup.match(/<\/div>/g) || []).length;
if (opens !== closes) fail("unbalanced <div> tags in the markup: " + opens + " open, " + closes + " closing");
else pass("div tags balance (" + opens + ")");
if (/^\s*\/\w+>/m.test(markup)) fail("a stray half-closed tag is present in the markup");

/* ---- 5. the wheel and the bet board must agree with each other ---- */
const grab = (name) => {
  const m = src.match(new RegExp("const " + name + "\\s*=\\s*(\\[[\\s\\S]*?\\]);"));
  return m ? eval(m[1]) : null;
};
const WHEEL = grab("WHEEL"), BETTABLE = grab("BETTABLE"), BOARD = grab("BOARD");
const ANIM = (() => {
  const m = src.match(/const ANIMALS\s*=\s*(\{[\s\S]*?\n\});/);
  return m ? eval("(" + m[1] + ")") : null;
})();
if (!WHEEL || !BETTABLE || !BOARD || !ANIM) fail("could not read WHEEL / BETTABLE / BOARD / ANIMALS");
else {
  const unknown = WHEEL.filter(k => !ANIM[k]);
  if (unknown.length) fail("WHEEL uses symbols with no ANIMALS entry: " + [...new Set(unknown)].join(", "));
  const offBoard = BETTABLE.filter(k => !BOARD.includes(k));
  if (offBoard.length) fail("BETTABLE symbols with no tile on the board: " + offBoard.join(", "));
  const unreachable = BETTABLE.filter(k => !WHEEL.includes(k));
  if (unreachable.length) fail("bettable symbols that never appear on the wheel: " + unreachable.join(", "));
  if (WHEEL.length !== 24) fail("the wheel has " + WHEEL.length + " slots, expected 24");
  if (!bad) pass("wheel, board and symbol table agree (" + WHEEL.length + " slots, " + BETTABLE.length + " bets)");
}

/* ---- 6. the chip values must all clear the server's minimum ---- */
const chips = grab("CHIP_VALUES");
const serverSrc = fs.readFileSync(path.join(__dirname, "api", "index.js"), "utf8");
const minBet = (serverSrc.match(/const MIN_BET\s*=\s*(\d+)\s*\*\s*100/) || [])[1];
if (chips && minBet) {
  const tooSmall = chips.filter(c => c < Number(minBet));
  if (tooSmall.length)
    fail("chips below the server minimum of KSh " + minBet + ": " + tooSmall.join(", "));
  else pass("smallest chip (KSh " + Math.min(...chips) + ") meets the server minimum (KSh " + minBet + ")");
}

console.log(bad ? "\n" + bad + " CHECK(S) FAILED" : "\nall game checks passed");
process.exit(bad ? 1 : 0);
