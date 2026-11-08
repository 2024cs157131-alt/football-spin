/* Monte-Carlo the REAL settle maths from api/index.js: every bet shape must
   return the same RTP, and that RTP must match the configured target. */
const crypto = require("crypto");
const fs = require("fs");
const src = fs.readFileSync(require("path").join(__dirname, "api", "index.js"), "utf8");

// lift the pure game maths out of the server file
function grab(name, endMarker) {
  const i = src.indexOf(name);
  if (i < 0) throw new Error("not found: " + name);
  const j = src.indexOf(endMarker, i);
  return src.slice(i, j);
}
const defs = [
  grab("const WHEEL = [", "/* Weights are derived"),
  grab("const BASE = [", "function buildOutcomes"),
  grab("function buildOutcomes", "function rtpOf"),
  grab("function rtpOf", "const BETTABLE"),
  grab("function drawOutcome", "function visualSlot"),
  grab("function payFor", "async function settle"),
].join("\n");
const sandbox = new Function("crypto", "DEFAULT_RTP", defs + `
  return { buildOutcomes, rtpOf, drawOutcome, payFor,
           EXTRA_MIN, EXTRA_MAX, SYMBOL_KEYS, BONUS_EV, EXTRA_EV_EACH, BASE_DIRECT };`);
const G = sandbox(crypto, 32);

function simulate(bets, targetRtp, spins) {
  const outcomes = G.buildOutcomes(targetRtp);
  const pool = outcomes.filter(o => G.SYMBOL_KEYS.has(o.key));
  const stake = Object.values(bets).reduce((a, b) => a + b, 0);
  let staked = 0, paid = 0;
  for (let i = 0; i < spins; i++) {
    let free = true, guard = 0;
    staked += stake;
    while (free && guard++ < 50) {
      free = false;
      const hit = G.drawOutcome(outcomes);
      if (hit.key === "bonus") {
        const n = G.EXTRA_MIN + crypto.randomInt(G.EXTRA_MAX - G.EXTRA_MIN + 1);
        for (let e = 0; e < n; e++) {
          const pick = G.drawOutcome(pool);
          paid += G.payFor(pick.key, pick.odds, bets);
        }
      } else if (hit.key === "respin") {
        free = true;                       // a free spin: no extra stake charged
      } else if (hit.key === "jackpot") {
        paid += 0;                         // jackpot pool is accounted separately
      } else {
        paid += G.payFor(hit.key, hit.odds, bets);
      }
    }
  }
  return 100 * paid / staked;
}

const JACKPOT_CUT = 2;   // 2% of stakes diverted to the pool, counted as player return

/* Exact expected return per unit staked, straight from the weights. This is
   the real proof that no bet shape is a better deal than another; the
   simulation below is only a sanity check that the code matches the maths. */
function exactRtp(bets, targetRtp) {
  const outcomes = G.buildOutcomes(targetRtp);
  const T = outcomes.reduce((s, o) => s + o.w, 0);
  const pool = outcomes.filter(o => G.SYMBOL_KEYS.has(o.key));
  const W = pool.reduce((s, o) => s + o.w, 0);
  const S = Object.values(bets).reduce((a, b) => a + b, 0);
  const payOf = (o, share) => share * (o.key === "allprize"
    ? o.odds * S
    : (bets[o.key] ? o.odds * bets[o.key] : 0));

  let direct = 0;
  for (const o of outcomes) if (G.SYMBOL_KEYS.has(o.key)) direct += payOf(o, o.w / T);

  let perExtra = 0;
  for (const o of pool) perExtra += payOf(o, o.w / W);
  const nBar = (G.EXTRA_MIN + G.EXTRA_MAX) / 2;
  const pBonus = (outcomes.find(o => o.key === "bonus").w) / T;
  const bonus = pBonus * nBar * perExtra;

  const pRespin = (outcomes.find(o => o.key === "respin").w) / T;
  return 100 * ((direct + bonus) / S + JACKPOT_CUT / 100) / (1 - pRespin);
}

const SHAPES = {
  "zebra only":              { zebra: 10000 },
  "lion only":               { lion: 10000 },
  "star only":               { star: 10000 },
  "elephant only":           { elephant: 10000 },
  "giraffe only":            { giraffe: 10000 },
  "rhino only":              { rhino: 10000 },
  "buffalo only":            { buffalo: 10000 },
  "leopard only":            { leopard: 10000 },
  "all eight, spread":       { star:1250, elephant:1250, rhino:1250, lion:1250,
                               buffalo:1250, leopard:1250, giraffe:1250, zebra:1250 },
  "two animals, uneven":     { rhino: 7000, zebra: 3000 },
  "one animal, tiny stake":  { zebra: 1000 },
};
let fails = 0;

console.log("EXACT expected return by bet shape");
for (const target of [8, 32, 50, 68, 90]) {
  const got = Object.entries(SHAPES).map(([n, b]) => [n, exactRtp(b, target)]);
  const spread = Math.max(...got.map(x => x[1])) - Math.min(...got.map(x => x[1]));
  const avg = got.reduce((s, x) => s + x[1], 0) / got.length;
  const offTarget = Math.abs(avg - target);
  /* Weights are integers (Math.round(w*k)), so bet shapes can differ by a
     hair. 0.15pt is ~15 shillings per 10,000 staked - far below any player's
     ability to exploit it, and it predates the diamond change. */
  const okSpread = spread < 0.15;
  const okTarget = offTarget < 0.35;       // integer weight rounding only
  if (!okSpread) fails++;
  if (!okTarget) fails++;
  console.log("\n  target " + String(target).padStart(2) + "%   " +
    (okSpread ? "PASS" : "FAIL") + " spread " + spread.toFixed(4) + " pts   " +
    (okTarget ? "PASS" : "FAIL") + " mean " + avg.toFixed(3) + "%");
  if (!okSpread || !okTarget)
    got.forEach(([n, r]) => console.log("        " + n.padEnd(24) + r.toFixed(4) + "%"));
}

console.log("\nSIMULATION sanity check (400k spins, target 32%)");
for (const [name, bets] of Object.entries({ "zebra only": SHAPES["zebra only"],
    "all eight, spread": SHAPES["all eight, spread"] })) {
  const want = exactRtp(bets, 32) - JACKPOT_CUT;
  const r = simulate(bets, 32, 400000);
  const ok = Math.abs(r - want) < 1.5;
  if (!ok) fails++;
  console.log("  " + (ok ? "PASS" : "FAIL") + "  " + name.padEnd(22) +
              r.toFixed(2) + "%  (expected " + want.toFixed(2) + "%)");
}

console.log("\nEXTRA_EV_EACH=" + G.EXTRA_EV_EACH.toFixed(4) +
            "  BONUS_EV=" + G.BONUS_EV.toFixed(4) + "  BASE_DIRECT=" + G.BASE_DIRECT.toFixed(4));
console.log(fails ? "\n" + fails + " CHECK(S) FAILED" : "\nall RTP checks passed");
process.exit(fails ? 1 : 0);
