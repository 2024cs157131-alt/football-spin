/* The M-Pesa name almost never equals the signup name. Too strict and honest
 * players are locked out of their own money; too loose and the number/name
 * check stops catching anyone. These cases are the line we are drawing. */
const fs = require("fs"), path = require("path");
const src = fs.readFileSync(path.join(__dirname, "api", "index.js"), "utf8");
const i = src.indexOf("function nameParts");
const j = src.indexOf("const msisdn =");
const { nameMatches } = new Function(src.slice(i, j) + "; return { nameMatches };")();

const SHOULD_MATCH = [
  ["Victor Langat",              "VICTOR LANGAT"],
  ["Victor Kipngetich Langat",   "VICTOR LANGAT"],              // middle name only on one side
  ["Victor Langat",              "LANGAT VICTOR"],              // reversed order
  ["Victor Kipngetich Langat",   "LANGAT KIPNGETICH VICTOR"],   // reversed, full
  ["victor langat",              "VICTOR LANGAT"],              // case
  ["Victor  Langat",             "VICTOR LANGAT"],              // double space
  ["Mary-Ann Wanjiku",           "MARY ANN WANJIKU"],           // punctuation
  ["Joseph Kiprono Too",         "JOSEPH KIPRONO"],             // short surname dropped
  ["Mohamed Abdi Hassan",        "MOHAMED HASSAN ABDI"],        // reordered three
  ["Anne Wairimu Kamau",         "ANN WAIRIMU KAMAU"],          // one-letter spelling drift
  ["Fredrick Omondi",            "FREDERICK OMONDI"],           // common spelling variant
  ["Jane Nyambura",              "JANE W NYAMBURA"],            // initial inserted
];

const SHOULD_NOT_MATCH = [
  ["Victor Langat",              "PETER KAMAU"],                // different person
  ["Victor Langat",              "VICTOR KAMAU"],               // only first name shared
  ["Victor Langat",              "JOHN LANGAT"],                // only surname shared
  ["Victor Kipngetich Langat",   "MARY WANJIKU NJOROGE"],
  ["Victor Langat",              ""],                           // no name returned
  ["",                           "VICTOR LANGAT"],              // nothing registered
  ["Victor Langat",              "V L"],                        // initials only
  ["Grace Akinyi",               "GRACE OTIENO"],
];

let fails = 0;
console.log("names that MUST be accepted");
for (const [reg, mp] of SHOULD_MATCH) {
  const r = nameMatches(reg, mp);
  if (!r.ok) fails++;
  console.log("  " + (r.ok ? "PASS" : "FAIL") + "  " + reg.padEnd(26) + " ~ " +
              (mp || "(empty)").padEnd(26) + " matched " + r.matched + "/" + r.of);
}
console.log("\nnames that MUST be rejected");
for (const [reg, mp] of SHOULD_NOT_MATCH) {
  const r = nameMatches(reg, mp);
  if (r.ok) fails++;
  console.log("  " + (!r.ok ? "PASS" : "FAIL") + "  " + reg.padEnd(26) + " ~ " +
              (mp || "(empty)").padEnd(26) + " matched " + r.matched + "/" + r.of);
}
console.log(fails ? "\n" + fails + " CASE(S) FAILED" : "\nall name-matching cases passed");
process.exit(fails ? 1 : 0);
