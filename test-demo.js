/* How often does a player actually see a win, live vs demo? */
const crypto = require("crypto"), fs = require("fs"), path = require("path");
const src = fs.readFileSync(path.join(__dirname, "api", "index.js"), "utf8");
const grab = (a, b) => src.slice(src.indexOf(a), src.indexOf(b));
const defs = [
  grab("const WHEEL = [", "/* Weights are derived"),
  grab("const BASE = [", "function buildOutcomes"),
  grab("function buildOutcomes", "function rtpOf"),
  grab("function drawOutcome", "function visualSlot"),
  grab("function payFor", "async function settle"),
].join("\n");
const G = new Function("crypto", "DEFAULT_RTP", defs +
  "; return { buildOutcomes, drawOutcome, payFor, EXTRA_MIN, EXTRA_MAX, SYMBOL_KEYS, MAX_DEMO_RTP };")(crypto, 32);

function run(rtp, max, bets, spins) {
  const outcomes = G.buildOutcomes(rtp, max);
  const pool = outcomes.filter(o => G.SYMBOL_KEYS.has(o.key));
  const stake = Object.values(bets).reduce((a, b) => a + b, 0);
  let wins = 0, longestDry = 0, dry = 0, staked = 0, paid = 0;
  for (let i = 0; i < spins; i++) {
    staked += stake;
    let won = 0, free = true, guard = 0;
    while (free && guard++ < 50) {
      free = false;
      const hit = G.drawOutcome(outcomes);
      if (hit.key === "bonus") {
        const n = G.EXTRA_MIN + crypto.randomInt(G.EXTRA_MAX - G.EXTRA_MIN + 1);
        for (let e = 0; e < n; e++) { const pk = G.drawOutcome(pool); won += G.payFor(pk.key, pk.odds, bets); }
      } else if (hit.key === "respin") free = true;
      else won += G.payFor(hit.key, hit.odds, bets);
    }
    paid += won;
    if (won > 0) { wins++; if (dry > longestDry) longestDry = dry; dry = 0; } else dry++;
  }
  if (dry > longestDry) longestDry = dry;
  return { hit: 100 * wins / spins, rtp: 100 * paid / staked, longestDry };
}

const ONE  = { zebra: 2000 };
const TWO  = { zebra: 1000, lion: 1000 };
const FOUR = { zebra: 500, lion: 500, elephant: 500, giraffe: 500 };
const ALL  = { star:250, elephant:250, rhino:250, lion:250, buffalo:250, leopard:250, giraffe:250, zebra:250 };
const N = 200000;
const M = G.MAX_DEMO_RTP;
console.log("                          win rate   return   longest losing run");
const show = (label, r) => console.log("  " + label.padEnd(24) +
  r.hit.toFixed(1).padStart(6) + "%" + r.rtp.toFixed(0).padStart(8) + "%" +
  String(r.longestDry).padStart(14));
const live = {}, demo = {};
for (const [name, bets] of [["one animal",ONE],["two animals",TWO],["four animals",FOUR],["all eight",ALL]]) {
  live[name] = run(32, 90, bets, N);
  demo[name] = run(150, M, bets, N);
}
console.log(" LIVE 32%");
for (const k in live) show("   " + k, live[k]);
console.log(" DEMO 150%");
for (const k in demo) show("   " + k, demo[k]);

let fails = 0;
const check = (ok, msg) => { if (!ok) fails++; console.log("  " + (ok ? "PASS" : "FAIL") + "  " + msg); };
console.log();
/* Thresholds are what the wheel can actually deliver: a one-animal bettor is
   capped by that animal's share of the symbol block, so "regularly" means
   roughly every third spin, not every other one. */
check(demo["one animal"].hit > 30,  "one animal wins on >30% of demo spins (" + demo["one animal"].hit.toFixed(1) + "%)");
check(demo["two animals"].hit > 38, "two animals wins on >38% of demo spins (" + demo["two animals"].hit.toFixed(1) + "%)");
check(demo["all eight"].hit > 85,   "all eight wins on >85% of demo spins (" + demo["all eight"].hit.toFixed(1) + "%)");
check(demo["one animal"].longestDry < 35, "no demo losing run past 35 spins (worst " + demo["one animal"].longestDry + ")");
check(demo["one animal"].hit > live["one animal"].hit * 3, "demo wins at least 3x as often as live");
check(Math.abs(live["one animal"].rtp - 30) < 2, "live return unchanged at ~30% (" + live["one animal"].rtp.toFixed(1) + "%)");
console.log(fails ? "\n" + fails + " FAILED" : "\nall demo checks passed");
process.exit(fails ? 1 : 0);
