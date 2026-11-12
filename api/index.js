/**
 * Safari Spin — Postgres backend for Vercel
 *
 * DEPOSITS   : your own M-Pesa paybill via Daraja (STK push + direct C2B).
 * WITHDRAWALS: Daraja B2C from the same paybill to the player's registered
 *              M-Pesa number. No third-party payment processor is involved.
 *
 * Env: DATABASE_URL, APP_SECRET, BASE_URL, CALLBACK_TOKEN,
 *      MPESA_ENV, MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET,
 *      MPESA_SHORTCODE, MPESA_PASSKEY,
 *      MPESA_INITIATOR, MPESA_SECURITY_CREDENTIAL (B2C payouts),
 *      ADMIN_PATH, ADMIN_PASSWORD, ADMIN_TOTP_SECRET
 */
const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");

const {
  DATABASE_URL, APP_SECRET, BASE_URL, CALLBACK_TOKEN,
  MPESA_ENV = "sandbox", MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET,
  MPESA_SHORTCODE, MPESA_PASSKEY,
  MPESA_INITIATOR, MPESA_SECURITY_CREDENTIAL,
} = process.env;

const DARAJA = MPESA_ENV === "production"
  ? "https://api.safaricom.co.ke"
  : "https://sandbox.safaricom.co.ke";

/* Neon presents a certificate from a public CA, so the connection is fully
 * verified. Put `sslmode=verify-full` in DATABASE_URL to match — `require`
 * still works today but will mean "encrypt without checking the certificate"
 * in a future pg release, which is not what we want for player data. */
const pool = new Pool({
  connectionString: DATABASE_URL,
  max: 3,
  connectionTimeoutMillis: 8000,
  idleTimeoutMillis: 10000,
  ssl: { rejectUnauthorized: true },
});
pool.on("error", (e) => console.error("pg pool error:", e.message));

let ready = null;
async function init() {
  if (ready) return ready;
  ready = (async () => {
    const statements = [
      `CREATE TABLE IF NOT EXISTS users(
        id SERIAL PRIMARY KEY, email TEXT UNIQUE, salt TEXT, hash TEXT,
        balance BIGINT DEFAULT 0, created BIGINT)`,
      `CREATE TABLE IF NOT EXISTS spins(
        id SERIAL PRIMARY KEY, user_id INT, bets TEXT, slot INT,
        stake BIGINT, payout BIGINT, created BIGINT)`,
      `CREATE TABLE IF NOT EXISTS tx(
        id SERIAL PRIMARY KEY, user_id INT, kind TEXT, amount BIGINT,
        ref TEXT UNIQUE, status TEXT, phone TEXT, created BIGINT)`,
      `CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT)`,
      `INSERT INTO settings(key,value) VALUES
         ('live_mode','true'),('withdrawals_enabled','true'),
         ('wht_enabled','true'),('wht_rate','20'),('wht_threshold','0'),
         ('excise_rate','15'),('betting_tax_rate','15'),('corp_tax_rate','30'),
         ('target_rtp','32'),('target_net','30'),
         ('min_deposit','20'),('max_deposit','100000'),
         ('demo_rtp','150'),('kyc_review_limit','20000')
        ON CONFLICT DO NOTHING`,
      `CREATE TABLE IF NOT EXISTS expenses(
        id SERIAL PRIMARY KEY, category TEXT, amount BIGINT, note TEXT, created BIGINT)`,
      `CREATE TABLE IF NOT EXISTS settings_audit(
        id SERIAL PRIMARY KEY, key TEXT, old_value TEXT, new_value TEXT, created BIGINT)`,
      `CREATE TABLE IF NOT EXISTS admin_attempts(id SERIAL PRIMARY KEY, ts BIGINT)`,
      `ALTER TABLE admin_attempts ADD COLUMN IF NOT EXISTS ip TEXT`,
      `CREATE TABLE IF NOT EXISTS jackpot(id INT PRIMARY KEY DEFAULT 1, pool BIGINT DEFAULT 500000)`,
      `INSERT INTO jackpot(id) VALUES(1) ON CONFLICT DO NOTHING`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS demo_balance BIGINT DEFAULT 100000`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS winnings BIGINT DEFAULT 0`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS demo_winnings BIGINT DEFAULT 0`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT UNIQUE`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name TEXT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS id_number TEXT UNIQUE`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS id_verified BOOLEAN DEFAULT false`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verified BOOLEAN DEFAULT false`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended BOOLEAN DEFAULT false`,
      `ALTER TABLE spins ADD COLUMN IF NOT EXISTS demo BOOLEAN DEFAULT false`,
      `ALTER TABLE spins ADD COLUMN IF NOT EXISTS jackpot BIGINT DEFAULT 0`,
      `ALTER TABLE spins ADD COLUMN IF NOT EXISTS tax BIGINT DEFAULT 0`,
      `ALTER TABLE spins ADD COLUMN IF NOT EXISTS kind TEXT DEFAULT 'spin'`,
      `ALTER TABLE tx ADD COLUMN IF NOT EXISTS bank TEXT`,
      `ALTER TABLE tx ADD COLUMN IF NOT EXISTS account TEXT`,
      `ALTER TABLE tx ADD COLUMN IF NOT EXISTS alt BOOLEAN DEFAULT false`,
      `ALTER TABLE tx ADD COLUMN IF NOT EXISTS from_win BIGINT DEFAULT 0`,
      `ALTER TABLE tx ADD COLUMN IF NOT EXISTS from_bal BIGINT DEFAULT 0`,
      `ALTER TABLE tx ADD COLUMN IF NOT EXISTS note TEXT`,
      `ALTER TABLE tx ADD COLUMN IF NOT EXISTS payer_name TEXT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS mpesa_name TEXT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS name_verified BOOLEAN DEFAULT false`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS name_mismatch BOOLEAN DEFAULT false`,
    ];
    for (const sql of statements) await pool.query(sql);
  })().catch((e) => { ready = null; throw e; });
  return ready;
}

const app = express();
app.use(express.json());
app.use(async (_req, res, next) => {
  try { await init(); next(); }
  catch (e) {
    console.error("DB init failed:", e.message);
    res.status(500).json({ error: "Server temporarily unavailable. Try again in a moment." });
  }
});

/* ---------- helpers ---------- */
const scrypt = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString("hex");
const sign = p => {
  const b = Buffer.from(JSON.stringify(p)).toString("base64url");
  return b + "." + crypto.createHmac("sha256", APP_SECRET).update(b).digest("base64url");
};
const verify = t => {
  if (!t) return null;
  const [b, m] = t.split(".");
  const e = crypto.createHmac("sha256", APP_SECRET).update(b || "").digest("base64url");
  try { return crypto.timingSafeEqual(Buffer.from(m), Buffer.from(e))
    ? JSON.parse(Buffer.from(b, "base64url").toString()) : null; } catch { return null; }
};
async function auth(req, res, next) {
  const u = verify((req.headers.authorization || "").replace("Bearer ", ""));
  if (!u) return res.status(401).json({ error: "Please log in again." });
  const r = await pool.query("SELECT * FROM users WHERE id=$1", [u.id]);
  if (!r.rows[0]) return res.status(401).json({ error: "Account not found." });
  req.user = r.rows[0]; req.user.balance = Number(req.user.balance);
  next();
}
/* ---------- matching an M-Pesa name to the registered name ----------
 * M-Pesa returns the name on the SIM registration, which rarely matches what
 * someone typed at signup: the order differs ("LANGAT VICTOR" vs "Victor
 * Langat"), a middle name appears on one side only, and spellings drift.
 * Demanding an exact string would lock out most honest players, so this
 * compares name parts and asks for enough overlap to identify the person.
 */
function nameParts(raw) {
  return String(raw || "")
    .toUpperCase()
    .replace(/[^A-Z\s]/g, " ")       // drop punctuation, digits, titles' dots
    .split(/\s+/)
    .filter(w => w.length > 1);      // single initials carry no signal
}

/* Levenshtein, capped: we only care whether two parts are within one or two
 * edits, so there is no point computing a large distance exactly. */
function editDistance(a, b) {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > 2) return 99;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1,
                        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[b.length];
}

/* Two parts count as the same name if they are equal, within one edit for
 * short names or two for long ones, or one is a prefix of the other at least
 * four letters long (M-Pesa truncates some names). */
function partsMatch(a, b) {
  if (a === b) return true;
  const tol = Math.min(a.length, b.length) >= 6 ? 2 : 1;
  if (editDistance(a, b) <= tol) return true;
  const short = a.length < b.length ? a : b, long = a.length < b.length ? b : a;
  return short.length >= 4 && long.startsWith(short);
}

/* Returns { ok, matched, of } — ok when enough parts line up to be confident
 * this is the same person. Two matching parts is the bar; where the shorter
 * name has only one usable part, that one part must match. */
function nameMatches(registered, mpesa) {
  const A = nameParts(registered), B = nameParts(mpesa);
  if (!A.length || !B.length) return { ok: false, matched: 0, of: 0, reason: "missing" };
  const used = new Set();
  let matched = 0;
  for (const a of A) {
    for (let i = 0; i < B.length; i++) {
      if (used.has(i)) continue;
      if (partsMatch(a, B[i])) { used.add(i); matched++; break; }
    }
  }
  const need = Math.min(2, Math.min(A.length, B.length));
  return { ok: matched >= need, matched, of: Math.min(A.length, B.length) };
}

const msisdn = raw => {
  const p = String(raw || "").replace(/\D/g, "").replace(/^0/, "254");
  return /^254(7|1)\d{8}$/.test(p) ? p : null;
};

const BOOL_KEYS = ["live_mode", "withdrawals_enabled", "wht_enabled"];
const DEFAULT_RTP = 32;
async function getSettings() {
  const r = await pool.query("SELECT key,value FROM settings");
  const o = {};
  r.rows.forEach(x => { o[x.key] = BOOL_KEYS.includes(x.key) ? x.value === "true" : Number(x.value); });
  return o;
}

/* ---------- withholding tax ----------
 * Kenyan WHT on winnings is deducted from the player's win at payout and
 * remitted to KRA. It is NOT operator revenue — every deduction is recorded
 * in spins.tax for your KRA returns. Rate / threshold / on-off are set in the
 * admin console so you can match the law as it changes. Switching it off when
 * the law requires withholding is tax evasion.
 */
function applyWHT(grossPayout, stake, st) {
  if (!st.wht_enabled || grossPayout <= 0) return { net: grossPayout, tax: 0 };
  const winnings = Math.max(0, grossPayout - stake);   // tax the winnings, not the stake
  if (winnings <= (st.wht_threshold || 0)) return { net: grossPayout, tax: 0 };
  const tax = Math.floor(winnings * (st.wht_rate || 0) / 100);
  return { net: grossPayout - tax, tax };
}

/* ---------- Daraja auth token (cached) ---------- */
let darajaCache = { v: null, exp: 0 };
async function darajaToken() {
  if (darajaCache.v && Date.now() < darajaCache.exp) return darajaCache.v;
  const basic = Buffer.from(`${MPESA_CONSUMER_KEY}:${MPESA_CONSUMER_SECRET}`).toString("base64");
  const r = await fetch(`${DARAJA}/oauth/v1/generate?grant_type=client_credentials`, {
    headers: { Authorization: `Basic ${basic}` } }).then(x => x.json());
  if (!r.access_token) throw new Error("Daraja auth failed");
  darajaCache = { v: r.access_token, exp: Date.now() + 50 * 60 * 1000 };
  return r.access_token;
}

/* ---------- game definition ----------
 * Wildlife theme (no trademarks). The 24-slot WHEEL is animation only;
 * real odds live in the weighted OUTCOMES table.
 *
 * Player return 32% (68% gross margin) on EVERY bet type:
 *   direct animal/all-prize wins + 2% jackpot + the diamond's extra landings
 *   + free respins.
 * 68% gross is roughly 30% net after excise 15% of stakes, betting tax 15% of
 * GGR and corporate tax 30% — plug live rates into the admin tax calculator.
 */
/* Slots 0 and 1 (top of the wheel) are the STAR — a special symbol, not an
 * animal — paying 50x and 100x. The rest are the Big Five plus two commons. */
/* 24 display slots: two star, two all-prize, two diamond, and eighteen animal
 * positions. Most losing spins now land on an animal that simply isn't the
 * one the player backed, rather than on a dead diamond. */
const WHEEL = ["star","star","allprize","zebra","giraffe","leopard","buffalo","diamond",
  "zebra","lion","rhino","elephant","giraffe","leopard","buffalo","zebra","lion","rhino",
  "elephant","diamond","giraffe","leopard","buffalo","allprize"];
/* Weights are derived from the target RTP set in the admin console, so the
 * payout rate can be tuned without editing code. Base table = 32% RTP; every
 * animal/all-prize weight scales by k, and `diamond` absorbs the difference,
 * which keeps all bet types at identical RTP. Every change is written to
 * settings_audit for your regulator. */
/* BIG FIVE (rhino, elephant, lion, buffalo, leopard) carry the top
 * multipliers; cheetah, giraffe and zebra are the common, low-paying animals.
 * Weights are set so EVERY animal returns the same RTP — a bigger multiplier
 * simply lands more rarely, so no bet is better than another. */
/* A player loses whenever the wheel misses THEIR pick, not only on diamond —
 * so most of the old dead weight has been moved onto the animals. The wheel now
 * lands on a real symbol ~42% of the time instead of ~17%, and a single-animal
 * bettor wins about twice as often. Every bet still returns identical RTP; the
 * price of the livelier wheel is lower top multipliers. */
/* A player loses whenever the wheel misses THEIR pick, so nearly all of the old
 * dead diamond weight now sits on the animals: the wheel lands on a real symbol
 * ~70% of the time and diamond needs only two slots. Every bet still returns the
 * identical RTP. The unavoidable price is lower multipliers — at 32% RTP, a bet's
 * win rate times its payout is fixed, so winning more often means winning less. */
/* Headline multipliers, minimum 5x. Every bet still returns the identical RTP,
 * so a bigger multiplier simply lands more rarely. At the default 32% payout
 * this means ~83% of spins are dead — raise the payout rate in the admin
 * console to trade margin for a livelier wheel (50% payout -> 72% dead,
 * 60% -> 66%). Players can stack several chips on one animal, and can back
 * several animals at once, which raises their chance of hitting on any spin. */
const BASE = [
  { key: "star",     odds: 50,  w: 374,   scale: true },  // STAR — top two slots
  { key: "star",     odds: 100, w: 40,    scale: true },  // STAR — top prize
  { key: "elephant", odds: 30,  w: 756,   scale: true },  // Big Five
  { key: "rhino",    odds: 25,  w: 907,   scale: true },  // Big Five
  { key: "lion",     odds: 20,  w: 1134,  scale: true },  // Big Five
  { key: "buffalo",  odds: 15,  w: 1512,  scale: true },  // Big Five
  { key: "leopard",  odds: 12,  w: 1890,  scale: true },  // Big Five
  { key: "giraffe",  odds: 8,   w: 2835,  scale: true },
  { key: "zebra",    odds: 5,   w: 4536,  scale: true },
  { key: "allprize", odds: 2,   w: 1500,  scale: true },
  { key: "jackpot",  odds: 0,   w: 5 },      // ~1 in 20,000
  { key: "bonus",    odds: 0,   w: 900 },    // DIAMOND: 2-3 extra landings
  { key: "respin",   odds: 0,   w: 1000 },   // DIAMOND RESPIN: one free spin
];
const POOL_W = 100000;
const BONUS_W = 900;          // must match the `bonus` row in BASE above
const JACKPOT_CUT = 0.02;
const JACKPOT_SEED = 5000 * 100;
/* Every symbol in BASE is tuned to the same odds x weight product, so a
 * player's direct return is the same however they split their stake. Deriving
 * these from the table instead of hardcoding them keeps that true if the table
 * is ever retuned. */
const SCALABLE_W = BASE.filter(o => o.scale).reduce((s, o) => s + o.w, 0);
/* A zebra-only bettor's return per unit staked, in weight units: the zebra
 * line plus all-prize, which pays on the whole board. */
const DIRECT_UNITS = BASE.filter(o => o.key === "zebra" || o.key === "allprize")
                         .reduce((s, o) => s + o.odds * o.w, 0);
const BASE_DIRECT = DIRECT_UNITS / POOL_W;   // direct RTP of the scaled block at k = 1

/* DIAMOND (the blue slot): instead of an overlay, the wheel lands 2-3 more
 * times on real symbols and pays whichever of those the player backed. Each
 * extra landing is drawn from the symbol block alone, so its expected return
 * is DIRECT_UNITS / SCALABLE_W per unit staked - a constant that does not
 * depend on k and does not depend on how the player split their bets. That is
 * what keeps every bet type at an identical RTP. */
const EXTRA_MIN = 2, EXTRA_MAX = 3;
const EXTRA_EV_EACH = DIRECT_UNITS / SCALABLE_W;
const BONUS_EV = EXTRA_EV_EACH * (EXTRA_MIN + EXTRA_MAX) / 2;
const SYMBOL_KEYS = new Set(
  ["star", "elephant", "rhino", "lion", "buffalo", "leopard", "giraffe", "zebra", "allprize"]);

/* The wheel must always keep some losing slots, or there is nothing to lose
 * on and the chase has no tension. This floor also stops a very generous
 * demo rate from overflowing the weight pool. */
const DIAMOND_MIN_W = 6000;
const MAX_LIVE_RTP = 90;
/* Demo money is not real, so demo may be set far more generous than the live
 * game - up to the point where the wheel still has losing slots. */
const MAX_DEMO_RTP = 160;

function buildOutcomes(targetRtpPct, maxPct) {
  const hi = Math.max(MAX_LIVE_RTP, Number(maxPct) || MAX_LIVE_RTP);
  const R = Math.min(hi, Math.max(8, Number(targetRtpPct) || DEFAULT_RTP)) / 100;
  const pRespin = 1000 / POOL_W;
  const bonusRtp = (BONUS_W / POOL_W) * BONUS_EV;
  const specialW = BASE.filter(o => !o.scale).reduce((a, o) => a + o.w, 0);
  const kMax = (POOL_W - DIAMOND_MIN_W - specialW) / SCALABLE_W;
  const k = Math.min(kMax,
    Math.max(0.05, (R * (1 - pRespin) - bonusRtp - JACKPOT_CUT) / BASE_DIRECT));
  const out = BASE.map(o => ({ key: o.key, odds: o.odds,
    w: o.scale ? Math.max(1, Math.round(o.w * k)) : o.w }));
  const used = out.reduce((s, o) => s + o.w, 0);
  out.push({ key: "diamond", odds: 0, w: Math.max(1, POOL_W - used) });
  return out;
}
function rtpOf(outcomes) {
  const T = outcomes.reduce((s, o) => s + o.w, 0);
  const pRespin = (outcomes.find(o => o.key === "respin")?.w || 0) / T;
  const bonus = ((outcomes.find(o => o.key === "bonus")?.w || 0) / T) * BONUS_EV;
  let direct = 0;
  for (const o of outcomes) if (o.key === "zebra" || o.key === "allprize") direct += o.odds * o.w / T;
  return (direct + bonus + JACKPOT_CUT) / (1 - pRespin);
}
const BETTABLE = ["star","elephant","rhino","lion","buffalo","leopard","giraffe","zebra"];
const MIN_BET = 10 * 100, MAX_STAKE = 10000 * 100;

/* Withdrawal rules */
const WD_MIN = 100, WD_MAX_MPESA = 70000, WD_DAILY_LIMIT = 3;

function drawOutcome(outcomes) {
  const total = outcomes.reduce((s, o) => s + o.w, 0);
  let roll = crypto.randomInt(total);
  for (const o of outcomes) { if (roll < o.w) return o; roll -= o.w; }
  return outcomes[outcomes.length - 1];
}
function visualSlot(key, odds) {
  if (key === "star") return odds === 100 ? 1 : 0;   // the two top slots
  const visKey = (key === "jackpot" || key === "bonus" || key === "respin") ? "diamond" : key;
  const cands = WHEEL.map((k, i) => (k === visKey ? i : -1)).filter(i => i >= 0);
  return cands[crypto.randomInt(cands.length)];
}

/* ---------- accounts ---------- */
app.post("/api/register", async (req, res) => {
  const { email, password, phone, full_name, id_number, over18 } = req.body || {};
  if (!over18) return res.status(400).json({ error: "You must confirm you are 18 or older." });
  if (!email || !password || password.length < 8)
    return res.status(400).json({ error: "Valid email and password (8+ chars) required." });
  const ph = msisdn(phone);
  if (!ph) return res.status(400).json({ error: "Enter a valid Safaricom number, e.g. 07XX XXX XXX." });
  const name = String(full_name || "").trim().replace(/\s+/g, " ");
  if (name.split(" ").length < 2 || name.length < 5 || !/^[a-zA-Z' .-]+$/.test(name))
    return res.status(400).json({ error: "Enter your full name as it appears on your ID." });
  const idn = String(id_number || "").replace(/\D/g, "");
  if (idn.length < 6 || idn.length > 9)
    return res.status(400).json({ error: "Enter a valid national ID number." });
  const salt = crypto.randomBytes(16).toString("hex");
  try {
    const r = await pool.query(
      "INSERT INTO users(email,salt,hash,phone,full_name,id_number,created) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id",
      [email.toLowerCase().trim(), salt, scrypt(password, salt), ph, name, idn, Date.now()]);
    res.json({ token: sign({ id: r.rows[0].id }), balance: 0 });
  } catch { res.status(400).json({ error: "That email, phone, or ID number is already registered." }); }
});

/* Sign in with the M-Pesa number. Email is still accepted so older accounts
 * and support cases keep working. */
app.post("/api/login", async (req, res) => {
  const { phone, email, password } = req.body || {};
  const raw = String(phone || email || "").trim();
  if (!raw || !password)
    return res.status(400).json({ error: "Enter your phone number and password." });

  const ph = msisdn(raw);
  const r = ph
    ? await pool.query("SELECT * FROM users WHERE phone=$1", [ph])
    : await pool.query("SELECT * FROM users WHERE email=$1", [raw.toLowerCase()]);

  const u = r.rows[0];
  if (!u || scrypt(password, u.salt) !== u.hash)
    return res.status(401).json({ error: "Wrong phone number or password." });
  res.json({ token: sign({ id: u.id }), balance: Number(u.balance) });
});

app.get("/api/me", auth, async (req, res) => {
  const st = await getSettings();
  res.json({ id: req.user.id, email: req.user.email,
    phone: req.user.phone, phone_verified: !!req.user.phone_verified,
    id_verified: !!req.user.id_verified,
    balance: st.live_mode ? req.user.balance : Number(req.user.demo_balance),
    winnings: Number(st.live_mode ? req.user.winnings : req.user.demo_winnings) || 0,
    live: st.live_mode, withdrawals: st.withdrawals_enabled,
    wht: st.wht_enabled ? st.wht_rate : 0,
    wd_max: WD_MAX_MPESA, wd_daily: WD_DAILY_LIMIT,
    min_deposit: Number(st.min_deposit) || 20,
    max_deposit: Number(st.max_deposit) || 100000 });
});

/* ---------- deposit: STK push to your paybill ---------- */
app.post("/api/deposit/init", auth, async (req, res) => {
  const st = await getSettings();
  if (!st.live_mode) return res.status(403).json({ error: "Demo mode is on — deposits are paused." });
  if (req.user.suspended) return res.status(403).json({ error: "Account under review. Contact support." });
  const amountKes = Math.floor(Number(req.body.amount));
  /* The prompt goes to the number on the account and nowhere else. Accepting
     a number from the request let one person fund another person's wallet,
     which is the standard route for laundering a stolen M-Pesa PIN and also
     breaks the "withdraw only to your own number" guarantee. */
  const phone = req.user.phone;
  const asked = req.body.phone ? msisdn(req.body.phone) : null;
  if (asked && asked !== phone)
    return res.status(400).json({
      error: "Deposits must come from the M-Pesa number registered on this account ("
             + (phone ? "0" + phone.slice(3) : "none on file")
             + "). Contact support to change it." });
  const minDep = Number(st.min_deposit) || 20, maxDep = Number(st.max_deposit) || 100000;
  if (!amountKes || amountKes < minDep)
    return res.status(400).json({ error: `Minimum deposit is KSh ${minDep.toLocaleString()}.` });
  if (amountKes > maxDep)
    return res.status(400).json({ error: `Maximum deposit is KSh ${maxDep.toLocaleString()}.` });
  if (!phone) return res.status(400).json({ error: "Enter a valid Safaricom number, e.g. 07XX XXX XXX." });

  const ts = new Date().toISOString().replace(/[-:TZ.]/g, "").slice(0, 14);
  const password = Buffer.from(MPESA_SHORTCODE + MPESA_PASSKEY + ts).toString("base64");
  let r;
  try {
    r = await fetch(`${DARAJA}/mpesa/stkpush/v1/processrequest`, {
      method: "POST",
      headers: { Authorization: `Bearer ${await darajaToken()}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        BusinessShortCode: MPESA_SHORTCODE, Password: password, Timestamp: ts,
        TransactionType: "CustomerPayBillOnline", Amount: amountKes,
        PartyA: phone, PartyB: MPESA_SHORTCODE, PhoneNumber: phone,
        CallBackURL: `${BASE_URL}/api/mpesa/stk/${CALLBACK_TOKEN}`,
        AccountReference: "SPIN" + req.user.id, TransactionDesc: "Wallet deposit",
      }),
    }).then(x => x.json());
  } catch (e) { return res.status(502).json({ error: "Could not reach M-Pesa. Try again." }); }

  if (!r || r.ResponseCode !== "0")
    return res.status(502).json({ error: (r && r.errorMessage) || "Could not send the M-Pesa prompt. Try again." });

  await pool.query(
    "INSERT INTO tx(user_id,kind,amount,ref,status,phone,created) VALUES($1,'deposit',$2,$3,'pending',$4,$5)",
    [req.user.id, amountKes * 100, r.CheckoutRequestID, phone, Date.now()]);
  res.json({ ok: true, message: "Check your phone and enter your M-Pesa PIN." });
});

/* STK result callback — wallets are only credited from here. */
app.post("/api/mpesa/stk/:token", async (req, res) => {
  if (req.params.token !== CALLBACK_TOKEN) return res.sendStatus(403);
  const cb = req.body && req.body.Body && req.body.Body.stkCallback;
  if (!cb) return res.sendStatus(400);
  const t = (await pool.query(
    "SELECT * FROM tx WHERE ref=$1 AND status='pending'", [cb.CheckoutRequestID])).rows[0];
  if (t) {
    if (cb.ResultCode === 0) {
      const item = cb.CallbackMetadata && cb.CallbackMetadata.Item;
      const paid = item && item.find(i => i.Name === "Amount");
      const cents = paid ? Math.round(Number(paid.Value) * 100) : Number(t.amount);
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const upd = await client.query(
          "UPDATE tx SET status='success', amount=$2 WHERE id=$1 AND status='pending'", [t.id, cents]);
        if (!upd.rowCount) throw new Error("already");
        await client.query("UPDATE users SET balance=balance+$2 WHERE id=$1", [t.user_id, cents]);
        await client.query(
          "UPDATE users SET phone_verified=true WHERE id=$1 AND phone=$2 AND phone_verified=false",
          [t.user_id, t.phone]);
        await client.query("COMMIT");
      } catch (e) { await client.query("ROLLBACK"); } finally { client.release(); }
    } else {
      await pool.query("UPDATE tx SET status='failed' WHERE id=$1", [t.id]);
    }
  }
  res.json({ ResultCode: 0, ResultDesc: "Accepted" });
});

/* ---------- C2B: paying the paybill directly from the M-Pesa menu ----------
 * Account number is SPIN<user id>. Register once per environment:
 *   GET /api/mpesa/c2b/register/<CALLBACK_TOKEN>
 */
app.get("/api/mpesa/c2b/register/:token", async (req, res) => {
  if (req.params.token !== CALLBACK_TOKEN) return res.sendStatus(403);
  const r = await fetch(`${DARAJA}/mpesa/c2b/v2/registerurl`, {
    method: "POST",
    headers: { Authorization: `Bearer ${await darajaToken()}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      ShortCode: MPESA_SHORTCODE, ResponseType: "Completed",
      ConfirmationURL: `${BASE_URL}/api/mpesa/c2b/confirm/${CALLBACK_TOKEN}`,
      ValidationURL: `${BASE_URL}/api/mpesa/c2b/validate/${CALLBACK_TOKEN}`,
    }),
  }).then(x => x.json());
  res.json(r);
});

app.post("/api/mpesa/c2b/validate/:token", async (req, res) => {
  if (req.params.token !== CALLBACK_TOKEN) return res.sendStatus(403);
  const userId = parseInt(String((req.body || {}).BillRefNumber || "").replace(/\D/g, ""), 10);
  const amt = Number((req.body || {}).TransAmount || 0);
  const cst = await getSettings();
  const cMin = Number(cst.min_deposit) || 20, cMax = Number(cst.max_deposit) || 100000;
  const u = userId
    ? (await pool.query("SELECT id, phone FROM users WHERE id=$1", [userId])).rows[0]
    : null;
  if (!u) return res.json({ ResultCode: "C2B00012", ResultDesc: "Rejected" });
  if (amt < cMin || amt > cMax) return res.json({ ResultCode: "C2B00013", ResultDesc: "Rejected" });
  /* Turn the payment away at the till rather than take it and argue later.
     C2B00011 is Safaricom's "invalid MSISDN" rejection. */
  const payer = msisdn((req.body || {}).MSISDN);
  if (u.phone && payer && payer !== u.phone)
    return res.json({ ResultCode: "C2B00011", ResultDesc: "Rejected" });
  res.json({ ResultCode: 0, ResultDesc: "Accepted" });
});

app.post("/api/mpesa/c2b/confirm/:token", async (req, res) => {
  if (req.params.token !== CALLBACK_TOKEN) return res.sendStatus(403);
  const b = req.body || {};
  const userId = parseInt(String(b.BillRefNumber || "").replace(/\D/g, ""), 10);
  const cents = Math.round(Number(b.TransAmount) * 100);
  if (userId && cents > 0 && b.TransID) {
    const u = (await pool.query(
      "SELECT id, phone, full_name, name_verified FROM users WHERE id=$1", [userId])).rows[0];
    if (u) {
      /* External validation has to be switched on by Safaricom and is not
         always live, so the same checks are repeated here, where the money has
         already arrived. A payment that fails them is recorded and held for
         the operator rather than credited or silently swallowed. */
      const payer = msisdn(b.MSISDN);
      const payerName = [b.FirstName, b.MiddleName, b.LastName]
        .filter(Boolean).join(" ").trim();
      const nm = nameMatches(u.full_name, payerName);

      let hold = null;
      if (u.phone && payer && payer !== u.phone)
        hold = "Paid from 0" + payer.slice(3) + ", not the number on the account.";
      else if (payerName && u.full_name && !nm.ok)
        hold = "M-Pesa name \"" + payerName + "\" does not match \"" + u.full_name + "\".";

      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const ins = await client.query(
          `INSERT INTO tx(user_id,kind,amount,ref,status,phone,payer_name,note,created)
           VALUES($1,'deposit',$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (ref) DO NOTHING`,
          [userId, cents, b.TransID, hold ? "review" : "success",
           String(b.MSISDN || ""), payerName || null, hold, Date.now()]);
        if (ins.rowCount && !hold) {           // idempotent on Safaricom's TransID
          await client.query("UPDATE users SET balance=balance+$2 WHERE id=$1", [userId, cents]);
          if (payer) await client.query(
            "UPDATE users SET phone_verified=true WHERE id=$1 AND phone=$2 AND phone_verified=false",
            [userId, payer]);
          /* The paybill is the only place the real M-Pesa name is visible, so
             this is where a player's name gets confirmed for good. */
          if (payerName && nm.ok) await client.query(
            "UPDATE users SET mpesa_name=$2, name_verified=true, name_mismatch=false WHERE id=$1",
            [userId, payerName]);
        } else if (ins.rowCount && payerName) {
          await client.query(
            "UPDATE users SET mpesa_name=COALESCE(mpesa_name,$2), name_mismatch=true WHERE id=$1",
            [userId, payerName]);
        }
        await client.query("COMMIT");
      } catch (e) { await client.query("ROLLBACK"); } finally { client.release(); }
    }
  }
  res.json({ ResultCode: 0, ResultDesc: "Accepted" });
});

/* ---------- refund a withdrawal, restoring the exact pots it came from ------
 * A payout can be funded partly from winnings and partly from playable credit.
 * Returning the whole amount to winnings leaves the player whole in total but
 * silently converts their credit into winnings, so the split is recorded on
 * the tx row and replayed here. Rows written before that column existed fall
 * back to winnings, which matches how they were taken.
 * Returns true only if THIS call performed the refund (never double-credits). */
async function refundWithdrawal(t) {
  const amount = Number(t.amount);
  let fw = Number(t.from_win || 0), fb = Number(t.from_bal || 0);
  if (fw + fb !== amount) { fw = amount; fb = 0; }   // legacy or inconsistent row
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const upd = await client.query(
      "UPDATE tx SET status='failed' WHERE id=$1 AND status IN ('pending','sending','review')",
      [t.id]);
    if (!upd.rowCount) { await client.query("ROLLBACK"); client.release(); return false; }
    await client.query(
      "UPDATE users SET winnings=winnings+$2, balance=balance+$3 WHERE id=$1",
      [t.user_id, fw, fb]);
    await client.query("COMMIT");
  } catch (e) {
    try { await client.query("ROLLBACK"); } catch (e2) {}
    client.release();
    return false;
  }
  client.release();
  return true;
}

/* ---------- B2C payout helper (also used by the admin payout queue) ----------
 * Sends money from your paybill straight to the player's M-Pesa. Returns
 * {ok:true} or {ok:false,error}; it never touches balances — the caller has
 * already debited and is responsible for refunding on failure. */
async function sendTransfer({ name, phone, cents, ref }) {
  const amountKes = Math.round(Number(cents) / 100);
  if (!(amountKes > 0)) return { ok: false, error: "Invalid payout amount." };
  if (!MPESA_INITIATOR || !MPESA_SECURITY_CREDENTIAL)
    return { ok: false, error: "B2C is not configured: set MPESA_INITIATOR and MPESA_SECURITY_CREDENTIAL." };

  let token;
  try { token = await darajaToken(); }
  catch (e) { return { ok: false, error: "Could not reach M-Pesa. Try again." }; }

  let r;
  try {
    r = await fetch(`${DARAJA}/mpesa/b2c/v3/paymentrequest`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        OriginatorConversationID: ref,
        InitiatorName: MPESA_INITIATOR,
        SecurityCredential: MPESA_SECURITY_CREDENTIAL,
        CommandID: "BusinessPayment",
        Amount: amountKes,
        PartyA: MPESA_SHORTCODE,
        PartyB: phone,
        Remarks: "Winnings withdrawal",
        Occasion: "Withdrawal",
        QueueTimeOutURL: `${BASE_URL}/api/mpesa/b2c/${CALLBACK_TOKEN}`,
        ResultURL: `${BASE_URL}/api/mpesa/b2c/${CALLBACK_TOKEN}`,
      }),
    }).then(x => x.json());
  } catch (e) { return { ok: false, error: "Could not reach M-Pesa. Try again." }; }

  if (!r || r.ResponseCode !== "0") {
    const msg = (r && (r.errorMessage || r.ResponseDescription)) || "Payout failed.";
    // the usual production cause: the paybill's B2C/utility balance is empty
    return { ok: false, error: msg };
  }
  return { ok: true };
}

/* ---------- Daraja B2C result / timeout callback ----------
 * Safaricom confirms delivery here. Until it arrives the payout stays
 * "pending" for the player and in the admin payout queue. */
app.post("/api/mpesa/b2c/:token", async (req, res) => {
  if (req.params.token !== CALLBACK_TOKEN) return res.sendStatus(403);
  const rslt = req.body && req.body.Result;
  if (rslt) {
    const ref = rslt.OriginatorConversationID;
    const t = (await pool.query(
      "SELECT * FROM tx WHERE ref=$1 AND kind='withdraw'", [ref])).rows[0];
    if (t && (t.status === "pending" || t.status === "sending")) {
      if (rslt.ResultCode === 0) {
        /* The payout result carries the name M-Pesa holds for the receiving
           number. This is the one place a withdrawal can confirm, or
           contradict, the name the player registered with. */
        const params = (rslt.ResultParameters && rslt.ResultParameters.ResultParameter) || [];
        const got = [].concat(params).find(x => x && x.Key === "ReceiverPartyPublicName");
        const raw = got ? String(got.Value || "") : "";
        // Safaricom formats this as "2547XXXXXXXX - FIRST LAST"
        const payeeName = raw.includes("-") ? raw.split("-").slice(1).join("-").trim() : raw.trim();
        if (payeeName) {
          const u = (await pool.query(
            "SELECT full_name FROM users WHERE id=$1", [t.user_id])).rows[0];
          const nm = nameMatches(u && u.full_name, payeeName);
          await pool.query(
            `UPDATE users SET mpesa_name=$2, name_verified=$3, name_mismatch=$4 WHERE id=$1`,
            [t.user_id, payeeName, nm.ok, !nm.ok]);
          await pool.query("UPDATE tx SET payer_name=$2 WHERE id=$1", [t.id, payeeName]);
          if (!nm.ok) await pool.query(
            `UPDATE tx SET note=$2 WHERE id=$1`,
            [t.id, "Paid out to \"" + payeeName + "\", registered as \"" +
                   ((u && u.full_name) || "?") + "\" - review this account."]);
        }
        await pool.query("UPDATE tx SET status='success' WHERE id=$1", [t.id]);
      } else {
        // failed or timed out — put the money back in the pots it came from
        await refundWithdrawal(t);
      }
    }
  }
  res.json({ ResultCode: 0, ResultDesc: "Accepted" });
});

/* ---------- move winnings into playable credit ----------
 * Winnings only become stakeable when the player asks for it, so a win is
 * never quietly fed back into the next spin. */
app.post("/api/move", auth, async (req, res) => {
  const st = await getSettings();
  const live = st.live_mode;
  const balCol = live ? "balance" : "demo_balance";
  const winCol = live ? "winnings" : "demo_winnings";
  const held = Number(live ? req.user.winnings : req.user.demo_winnings) || 0;

  // no amount given means move everything
  const cents = req.body.amount == null ? held : Math.floor(Number(req.body.amount) * 100);
  if (!(cents > 0)) return res.status(400).json({ error: "Nothing to move." });
  if (cents > held) return res.status(400).json({ error: "You don't have that much in winnings." });

  const r = await pool.query(
    `UPDATE users SET ${winCol}=${winCol}-$2, ${balCol}=${balCol}+$2
     WHERE id=$1 AND ${winCol}>=$2 RETURNING ${balCol} AS b, ${winCol} AS w`,
    [req.user.id, cents]);
  if (!r.rowCount) return res.status(400).json({ error: "You don't have that much in winnings." });

  res.json({ ok: true, balance: Number(r.rows[0].b), winnings: Number(r.rows[0].w),
             message: "Moved to credit — ready to stake." });
});

/* ---------- withdrawals ---------- */
async function withdrawalsToday(userId) {
  const start = new Date(); start.setHours(0, 0, 0, 0);
  const r = await pool.query(
    `SELECT COUNT(*) c FROM tx WHERE user_id=$1 AND kind IN ('withdraw','pesalink')
     AND status IN ('pending','sending','success','requested','review') AND created >= $2`,
    [userId, start.getTime()]);
  return Number(r.rows[0].c);
}

app.post("/api/withdraw", auth, async (req, res) => {
  const st = await getSettings();
  if (!st.live_mode) return res.status(403).json({ error: "Demo mode is on — withdrawals are paused." });
  if (!st.withdrawals_enabled) return res.status(403).json({ error: "Withdrawals are briefly paused for maintenance. Your balance is safe." });
  if (req.user.suspended) return res.status(403).json({ error: "Account under review. Contact support." });

  const amountKes = Math.floor(Number(req.body.amount));
  const cents = amountKes * 100;
  // Winnings always go to the M-Pesa number on the account. Locking the
  // destination removes the main account-takeover cashout route and means no
  // manual approval is needed for ordinary withdrawals.
  const phone = req.user.phone;
  if (!phone) return res.status(400).json({ error: "No M-Pesa number on your account. Contact support." });

  if (!amountKes || amountKes < WD_MIN) return res.status(400).json({ error: `Minimum withdrawal is KSh ${WD_MIN}.` });
  if (amountKes > WD_MAX_MPESA)
    return res.status(400).json({ pesalink: true,
      error: `M-Pesa withdrawals are capped at KSh ${WD_MAX_MPESA.toLocaleString()}. Use PesaLink for larger amounts.` });
  if (!req.user.phone_verified)
    return res.status(403).json({ error: "Verify your account with one deposit before withdrawing." });
  if (await withdrawalsToday(req.user.id) >= WD_DAILY_LIMIT)
    return res.status(429).json({ error: `Daily limit reached (${WD_DAILY_LIMIT} withdrawals). Try again tomorrow.` });
  // A second tap used to slip past the balance check while the first request
  // was still in flight: one would succeed and the other would report
  // "insufficient balance", so the player saw an error AND got the money.
  // The row lock below makes the check and the debit a single atomic step.
  const inflight = await pool.query(
    `SELECT 1 FROM tx WHERE user_id=$1 AND kind IN ('withdraw','pesalink')
     AND status='sending' AND created > $2 LIMIT 1`,
    [req.user.id, Date.now() - 120000]);
  if (inflight.rowCount)
    return res.status(409).json({ error: "A withdrawal is already being processed. Give it a moment." });
  const held = await pool.query(
    `SELECT 1 FROM tx WHERE user_id=$1 AND kind='withdraw' AND status='review' LIMIT 1`,
    [req.user.id]);
  if (held.rowCount)
    return res.status(409).json({
      error: "You already have a withdrawal being checked. It will be sent once approved." });

  const ref = "wd_" + crypto.randomBytes(10).toString("hex");
  let fromWin = 0, fromBal = 0;
  const lockClient = await pool.connect();
  try {
    await lockClient.query("BEGIN");
    // FOR UPDATE: no other request can read this row until we commit
    const me = await lockClient.query(
      "SELECT balance, winnings FROM users WHERE id=$1 FOR UPDATE", [req.user.id]);
    const bal = Number(me.rows[0].balance), held = Number(me.rows[0].winnings) || 0;
    if (cents > bal + held) {
      await lockClient.query("ROLLBACK");
      lockClient.release();
      return res.status(400).json({ error: "Insufficient balance." });
    }
    fromWin = Math.min(held, cents);
    fromBal = cents - fromWin;
    await lockClient.query(
      "UPDATE users SET winnings=winnings-$2, balance=balance-$3 WHERE id=$1",
      [req.user.id, fromWin, fromBal]);
    await lockClient.query(
      `INSERT INTO tx(user_id,kind,amount,ref,status,phone,from_win,from_bal,created)
       VALUES($1,'withdraw',$2,$3,'sending',$4,$5,$6,$7)`,
      [req.user.id, cents, ref, phone, fromWin, fromBal, Date.now()]);
    await lockClient.query("COMMIT");
  } catch (e) {
    try { await lockClient.query("ROLLBACK"); } catch (e2) {}
    lockClient.release();
    return res.status(500).json({ error: "Could not start the withdrawal. Your balance was not charged." });
  }
  lockClient.release();

  /* Above the review limit the money has already left the player's wallet but
     is not sent until the operator approves it in the console. A flagged name
     is held at any amount: that is exactly the case a person should look at. */
  const reviewLimit = Number(st.kyc_review_limit) || 20000;
  if (amountKes > reviewLimit || req.user.name_mismatch) {
    await pool.query("UPDATE tx SET status='review', note=$2 WHERE ref=$1",
      [ref, req.user.name_mismatch
        ? "Name on M-Pesa does not match the registered name."
        : "Above the KSh " + reviewLimit.toLocaleString() + " automatic limit."]);
    const u0 = await pool.query("SELECT balance, winnings FROM users WHERE id=$1", [req.user.id]);
    return res.json({ ok: true, review: true,
      balance: Number(u0.rows[0].balance), winnings: Number(u0.rows[0].winnings),
      message: "Withdrawal received and being checked. Large payouts are reviewed by our "
             + "team before they are sent, usually within a few hours." });
  }

  const out = await sendTransfer({ name: req.user.full_name, phone: phone, cents: cents, ref: ref });
  if (!out.ok) {
    const row = (await pool.query("SELECT * FROM tx WHERE ref=$1", [ref])).rows[0];
    if (row) await refundWithdrawal(row);
    return res.status(502).json({ error: out.error + " Your balance was not charged." });
  }
  await pool.query("UPDATE tx SET status='pending' WHERE ref=$1", [ref]);
  const u = await pool.query("SELECT balance, winnings FROM users WHERE id=$1", [req.user.id]);
  res.json({ ok: true, balance: Number(u.rows[0].balance), winnings: Number(u.rows[0].winnings),
             message: "Sent — you'll get the M-Pesa SMS shortly." });
});

/* PesaLink: large withdrawals, bank-to-bank. Queued for manual settlement —
 * you pay from your bank portal and mark it paid in the admin console. */
app.post("/api/withdraw/pesalink", auth, async (req, res) => {
  const st = await getSettings();
  if (!st.live_mode) return res.status(403).json({ error: "Demo mode is on — withdrawals are paused." });
  if (!st.withdrawals_enabled) return res.status(403).json({ error: "Withdrawals are briefly paused for maintenance. Your balance is safe." });
  if (req.user.suspended) return res.status(403).json({ error: "Account under review. Contact support." });
  const amountKes = Math.floor(Number(req.body.amount));
  const cents = amountKes * 100;
  const bank = String(req.body.bank || "").trim();
  const account = String(req.body.account || "").replace(/\s/g, "");
  if (!amountKes || amountKes <= WD_MAX_MPESA)
    return res.status(400).json({ error: `PesaLink is for amounts above KSh ${WD_MAX_MPESA.toLocaleString()}. Use M-Pesa below that.` });
  if (bank.length < 3) return res.status(400).json({ error: "Enter your bank name." });
  if (!/^\d{6,20}$/.test(account)) return res.status(400).json({ error: "Enter a valid bank account number." });
  if (!req.user.phone_verified)
    return res.status(403).json({ error: "Verify your number with one deposit before withdrawing." });
  if (!req.user.id_verified)
    return res.status(403).json({ error: "Large withdrawals need ID verification. Contact support to verify your ID." });
  if (await withdrawalsToday(req.user.id) >= WD_DAILY_LIMIT)
    return res.status(429).json({ error: `Daily limit reached (${WD_DAILY_LIMIT} withdrawals). Try again tomorrow.` });
  const plHeld = Number(req.user.winnings) || 0;
  if (cents > plHeld + req.user.balance) return res.status(400).json({ error: "Insufficient balance." });

  // winnings first, then playable credit
  const plFromWin = Math.min(plHeld, cents);
  const plFromBal = cents - plFromWin;
  const deb = await pool.query(
    `UPDATE users SET winnings=winnings-$2, balance=balance-$3
     WHERE id=$1 AND winnings>=$2 AND balance>=$3`,
    [req.user.id, plFromWin, plFromBal]);
  if (!deb.rowCount) return res.status(400).json({ error: "Insufficient balance." });
  const ref = "pl_" + crypto.randomBytes(10).toString("hex");
  await pool.query(
    `INSERT INTO tx(user_id,kind,amount,ref,status,phone,bank,account,from_win,from_bal,created)
     VALUES($1,'pesalink',$2,$3,'requested',$4,$5,$6,$7,$8,$9)`,
    [req.user.id, cents, ref, req.user.phone, bank, account, plFromWin, plFromBal, Date.now()]);
  const u = await pool.query("SELECT balance, winnings FROM users WHERE id=$1", [req.user.id]);
  res.json({ ok: true, balance: Number(u.rows[0].balance), winnings: Number(u.rows[0].winnings),
    message: "PesaLink request received. Bank transfers are processed within one business day." });
});

/* ---------- settle one spin (shared by spin and free respin) ---------- */
/* What one landing pays, given what the player staked. ALL PRIZE pays every
 * stake on the board; any other symbol pays only the stake sitting on it. */
function payFor(key, odds, bets) {
  if (key === "allprize") {
    let p = 0;
    for (const v of Object.values(bets)) p += Math.floor(Number(v)) * odds;
    return p;
  }
  return bets[key] ? Math.floor(Number(bets[key])) * odds : 0;
}

async function settle(user, bets, stake, live, st, freeSpin) {
  /* Demo plays the same game at a far friendlier rate: the point of the demo
     is to show how the wheel works, and a player who loses 8 spins running
     never gets that far. Live play is untouched. */
  const outcomes = live
    ? buildOutcomes(st.target_rtp)
    : buildOutcomes(st.demo_rtp || 150, MAX_DEMO_RTP);
  const hit = drawOutcome(outcomes);
  let gross = 0, jackpotWin = 0, respin = false, extras = null;

  if (hit.key === "bonus") {
    /* The blue diamond: the wheel lands 2-3 more times on real symbols and
     * each landing is settled exactly as an ordinary spin would be. Drawing
     * from the symbol block alone means an extra landing always shows a real
     * animal, and because the block is tuned to equal odds x weight, the
     * expected return per landing is the same whatever the player backed. */
    const pool = outcomes.filter(o => SYMBOL_KEYS.has(o.key));
    const n = EXTRA_MIN + crypto.randomInt(EXTRA_MAX - EXTRA_MIN + 1);
    extras = [];
    for (let i = 0; i < n; i++) {
      const pick = drawOutcome(pool);
      const pay = payFor(pick.key, pick.odds, bets);
      gross += pay;
      extras.push({ key: pick.key, odds: pick.odds,
                    slot: visualSlot(pick.key, pick.odds), payout: pay });
    }
  } else if (hit.key === "respin") {
    respin = true;
  } else {
    gross = payFor(hit.key, hit.odds, bets);
  }

  const slot = visualSlot(hit.key, hit.odds);
  const contribution = live && !freeSpin ? Math.floor(stake * JACKPOT_CUT) : 0;
  const chargeStake = freeSpin ? 0 : stake;

  const client = await pool.connect();
  let taxTaken = 0, netPayout = 0;
  try {
    await client.query("BEGIN");
    if (hit.key === "jackpot") {
      // Demo plays identically to the real game: the player still "wins" the
      // displayed pool in demo credit, but the real pool is never touched.
      const j = await client.query("SELECT pool FROM jackpot WHERE id=1" + (live ? " FOR UPDATE" : ""));
      jackpotWin = Number(j.rows[0].pool) + contribution;
      gross += jackpotWin;
      if (live) await client.query("UPDATE jackpot SET pool=$1 WHERE id=1", [JACKPOT_SEED]);
    } else if (live) {
      await client.query("UPDATE jackpot SET pool=pool+$1 WHERE id=1", [contribution]);
    }
    const t = live ? applyWHT(gross, chargeStake, st) : { net: gross, tax: 0 };
    netPayout = t.net; taxTaken = t.tax;

    // Stakes come out of playable credit; winnings are parked in a separate
    // pot so they are never silently staked again. The player moves them
    // across deliberately, or withdraws them.
    const balCol = live ? "balance" : "demo_balance";
    const winCol = live ? "winnings" : "demo_winnings";
    const d = await client.query(
      `UPDATE users SET ${balCol}=${balCol}-$2, ${winCol}=${winCol}+$3
       WHERE id=$1 AND ${balCol}>=$2`,
      [user.id, chargeStake, netPayout]);
    if (!d.rowCount) throw new Error("balance");
    await client.query(
      `INSERT INTO spins(user_id,bets,slot,stake,payout,demo,jackpot,tax,kind,created)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [user.id, JSON.stringify(bets), slot, chargeStake, netPayout, !live, jackpotWin, taxTaken,
       freeSpin ? "respin" : "spin", Date.now()]);
    await client.query("COMMIT");
  } catch (e) {
    await client.query("ROLLBACK"); client.release();
    throw new Error(live ? "Insufficient balance. Deposit to play."
                         : "Not enough demo credit for that stake.");
  }
  client.release();
  return { key: hit.key, slot, payout: netPayout, tax: taxTaken,
           jackpot: jackpotWin, extras, respin };
}

/* ---------- the spin ---------- */
app.post("/api/spin", auth, async (req, res) => {
  const bets = req.body.bets || {};
  let stake = 0;
  for (const [k, v] of Object.entries(bets)) {
    if (!BETTABLE.includes(k)) return res.status(400).json({ error: "Unknown bet." });
    const amt = Math.floor(Number(v));
    if (amt < MIN_BET)
      return res.status(400).json({ error: "Minimum KSh " + (MIN_BET / 100) + " per symbol." });
    stake += amt;
  }
  if (!stake) return res.status(400).json({ error: "Place at least one bet." });
  if (stake > MAX_STAKE) return res.status(400).json({ error: "Max total stake is KSh 10,000." });

  const st = await getSettings();
  const live = st.live_mode;
  if (req.user.suspended && live) return res.status(403).json({ error: "Account under review. Contact support." });
  const DEMO_BANKROLL = 200000; // KSh 2,000 of demo credit
  if (!live && Number(req.user.demo_balance) < stake) {
    await pool.query("UPDATE users SET demo_balance=$2 WHERE id=$1", [req.user.id, DEMO_BANKROLL]);
    req.user.demo_balance = DEMO_BANKROLL;
  }
  const curBal = live ? req.user.balance : Number(req.user.demo_balance);
  if (stake > curBal) return res.status(400).json({
    error: live ? "Insufficient balance. Deposit to play."
                : "Not enough demo credit for that stake." });

  let out;
  try { out = await settle(req.user, bets, stake, live, st, false); }
  catch (e) { return res.status(400).json({ error: e.message }); }

  // a free respin resolves immediately, server-side
  let respinResult = null;
  if (out.respin) {
    const fresh = (await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id])).rows[0];
    fresh.balance = Number(fresh.balance);
    try { respinResult = await settle(fresh, bets, stake, live, st, true); } catch (e) { respinResult = null; }
  }

  const balCol = live ? "balance" : "demo_balance";
  const winCol = live ? "winnings" : "demo_winnings";
  const u = await pool.query(
    `SELECT ${balCol} AS b, ${winCol} AS w FROM users WHERE id=$1`, [req.user.id]);
  const jp = await pool.query("SELECT pool FROM jackpot WHERE id=1");
  res.json({
    key: out.key, slot: out.slot, payout: out.payout, tax: out.tax, jackpot: out.jackpot,
    extras: out.extras,
    respin: respinResult ? {
      key: respinResult.key, slot: respinResult.slot, payout: respinResult.payout,
      tax: respinResult.tax, jackpot: respinResult.jackpot,
      extras: respinResult.extras,
    } : null,
    pool: Number(jp.rows[0].pool), balance: Number(u.rows[0].b),
    winnings: Number(u.rows[0].w), live,
  });
});

const BIG_WIN_MIN = 1000 * 100;

app.get("/api/winners", async (_req, res) => {
  const r = await pool.query(`
    SELECT s.payout, s.jackpot, s.kind, s.created, u.full_name, u.id AS uid
    FROM spins s JOIN users u ON u.id = s.user_id
    WHERE s.demo = false AND (s.payout >= $1 OR s.jackpot > 0)
    ORDER BY s.id DESC LIMIT 12`, [BIG_WIN_MIN]);
  res.json(r.rows.map(x => {
    const parts = String(x.full_name || "").trim().split(/\s+/);
    const name = parts[0] ? parts[0] + (parts[1] ? " " + parts[1][0] + "." : "") : "Player " + x.uid;
    return { name: name, amount: Number(x.payout), jackpot: Number(x.jackpot) > 0,
             bonus: x.kind === "bonus", at: Number(x.created) };
  }));
});

app.get("/api/jackpot", async (_req, res) => {
  const r = await pool.query("SELECT pool FROM jackpot WHERE id=1");
  res.json({ pool: Number(r.rows[0]?.pool || 0) });
});

require("./admin.js")(app, pool, sign, verify,
  { sendTransfer: sendTransfer, refundWithdrawal: refundWithdrawal });

/* Where each payout stands, for the player's own screen. */
app.get("/api/withdrawals", auth, async (req, res) => {
  const r = await pool.query(
    `SELECT kind, amount, status, phone, bank, created
     FROM tx WHERE user_id=$1 AND kind IN ('withdraw','pesalink')
     ORDER BY id DESC LIMIT 10`, [req.user.id]);
  const label = st => st === "success" ? "Paid"
    : st === "failed" ? "Failed — refunded"
    : st === "review" ? "Under review"
    : "Pending";
  res.json(r.rows.map(x => ({
    amount: Number(x.amount), status: x.status, label: label(x.status),
    method: x.kind === "pesalink" ? "Bank (PesaLink)" : "M-Pesa",
    at: Number(x.created),
  })));
});

app.get("/api/history", auth, async (req, res) => {
  const spins = await pool.query(
    "SELECT slot,stake,payout,tax,kind,created FROM spins WHERE user_id=$1 ORDER BY id DESC LIMIT 20", [req.user.id]);
  const tx = await pool.query(
    "SELECT kind,amount,status,created FROM tx WHERE user_id=$1 ORDER BY id DESC LIMIT 20", [req.user.id]);
  res.json({ spins: spins.rows, tx: tx.rows });
});

/* Any error escaping a route returns JSON rather than leaving the request to
 * hang — a hanging request is what shows up in the UI as "nothing happened". */
app.use((err, _req, res, _next) => {
  console.error("unhandled route error:", err && err.stack || err);
  if (!res.headersSent)
    res.status(500).json({ error: "Server error: " + (err && err.message || "unknown") });
});

module.exports = app;
