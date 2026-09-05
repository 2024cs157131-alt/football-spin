/**
 * Safari Spin — Paystack (KES / M-Pesa) + Postgres backend for Vercel
 *
 * Collections use Paystack's Transaction API (mobile money + card); payouts use
 * Paystack Transfers to M-Pesa. Paystack signs its webhooks, so wallet credits
 * only ever happen from a verified webhook or a server-side verify call.
 *
 * Env: DATABASE_URL, APP_SECRET, BASE_URL,
 *      PAYSTACK_SECRET  (sk_test_... then sk_live_...)
 *      ADMIN_PATH, ADMIN_PASSWORD, ADMIN_TOTP_SECRET
 */
const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");

const { DATABASE_URL, APP_SECRET, BASE_URL, PAYSTACK_SECRET } = process.env;

const PS = "https://api.paystack.co";
const psHeaders = {
  Authorization: `Bearer ${PAYSTACK_SECRET}`,
  "Content-Type": "application/json",
};

const pool = new Pool({
  connectionString: DATABASE_URL,
  max: 3,
  connectionTimeoutMillis: 8000,
  idleTimeoutMillis: 10000,
  ssl: { rejectUnauthorized: false },
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
         ('target_rtp','32')
        ON CONFLICT DO NOTHING`,
      `CREATE TABLE IF NOT EXISTS expenses(
        id SERIAL PRIMARY KEY, category TEXT, amount BIGINT, note TEXT, created BIGINT)`,
      `CREATE TABLE IF NOT EXISTS settings_audit(
        id SERIAL PRIMARY KEY, key TEXT, old_value TEXT, new_value TEXT, created BIGINT)`,
      `CREATE TABLE IF NOT EXISTS admin_attempts(id SERIAL PRIMARY KEY, ts BIGINT)`,
      `CREATE TABLE IF NOT EXISTS jackpot(id INT PRIMARY KEY DEFAULT 1, pool BIGINT DEFAULT 500000)`,
      `INSERT INTO jackpot(id) VALUES(1) ON CONFLICT DO NOTHING`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS demo_balance BIGINT DEFAULT 100000`,
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
    ];
    for (const sql of statements) await pool.query(sql);
  })().catch((e) => { ready = null; throw e; });
  return ready;
}

const app = express();
// Paystack signs the raw body — this route must see it unparsed
app.use("/api/paystack/webhook", express.raw({ type: "*/*" }));
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

/* ---------- game definition ----------
 * Wildlife theme (no trademarks). The 24-slot WHEEL is animation only;
 * real odds live in the weighted OUTCOMES table.
 *
 * Player return 32% (68% gross margin) on EVERY bet type:
 *   direct animal/all-prize wins + 2% jackpot + ~4% bonus pick-3 + free respins.
 * 68% gross is roughly 30% net after excise 15% of stakes, betting tax 15% of
 * GGR and corporate tax 30% — plug live rates into the admin tax calculator.
 */
/* Slots 0 and 1 (top of the wheel) are the STAR — a special symbol, not an
 * animal — paying 50x and 100x. The rest are the Big Five plus two commons. */
const WHEEL = ["star","star","allprize","zebra","lion","leopard","leopard","diamond",
  "zebra","buffalo","buffalo","giraffe","elephant","elephant","giraffe","lion","lion","rhino",
  "rhino","diamond","zebra","giraffe","buffalo","leopard"];
/* Weights are derived from the target RTP set in the admin console, so the
 * payout rate can be tuned without editing code. Base table = 32% RTP; every
 * animal/all-prize weight scales by k, and `diamond` absorbs the difference,
 * which keeps all bet types at identical RTP. Every change is written to
 * settings_audit for your regulator. */
/* BIG FIVE (rhino, elephant, lion, buffalo, leopard) carry the top
 * multipliers; cheetah, giraffe and zebra are the common, low-paying animals.
 * Weights are set so EVERY animal returns the same RTP — a bigger multiplier
 * simply lands more rarely, so no bet is better than another. */
const BASE = [
  { key: "star",     odds: 50,  w: 374,  scale: true },   // STAR — top two slots
  { key: "star",     odds: 100, w: 40,   scale: true },   // STAR — top prize
  { key: "elephant", odds: 30,  w: 756,  scale: true },   // Big Five
  { key: "rhino",    odds: 25,  w: 907,  scale: true },   // Big Five
  { key: "lion",     odds: 20,  w: 1134, scale: true },   // Big Five
  { key: "buffalo",  odds: 15,  w: 1512, scale: true },   // Big Five
  { key: "leopard",  odds: 12,  w: 1890, scale: true },   // Big Five
  { key: "giraffe",  odds: 8,   w: 2835, scale: true },
  { key: "zebra",    odds: 5,   w: 4536, scale: true },
  { key: "allprize", odds: 2,   w: 1500, scale: true },
  { key: "jackpot",  odds: 0,   w: 5 },      // ~1 in 20,000
  { key: "bonus",    odds: 0,   w: 462 },    // DIAMOND BONUS: pick 3 of 9
  { key: "respin",   odds: 0,   w: 1000 },   // DIAMOND RESPIN: one free spin
];
const POOL_W = 100000;
const JACKPOT_CUT = 0.02;
const JACKPOT_SEED = 5000 * 100;
const BASE_DIRECT = 0.2568;   // direct RTP of the scaled block at k = 1
const BONUS_EV = 8.6667;      // average bonus payout, x total stake

function buildOutcomes(targetRtpPct) {
  const R = Math.min(90, Math.max(8, Number(targetRtpPct) || DEFAULT_RTP)) / 100;
  const pRespin = 1000 / POOL_W;
  const bonusRtp = (462 / POOL_W) * BONUS_EV;
  const k = Math.max(0.05, (R * (1 - pRespin) - bonusRtp - JACKPOT_CUT) / BASE_DIRECT);
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
const MIN_BET = 20 * 100, MAX_STAKE = 10000 * 100;

/* Bonus pick-3: nine tiles, each a multiplier of TOTAL stake. Average total 8.667x. */
const BONUS_TILES = [1, 1, 1, 2, 2, 3, 3, 5, 8];

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

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};
  const r = await pool.query("SELECT * FROM users WHERE email=$1", [(email || "").toLowerCase().trim()]);
  const u = r.rows[0];
  if (!u || scrypt(password || "", u.salt) !== u.hash)
    return res.status(401).json({ error: "Wrong email or password." });
  res.json({ token: sign({ id: u.id }), balance: Number(u.balance) });
});

app.get("/api/me", auth, async (req, res) => {
  const st = await getSettings();
  res.json({ id: req.user.id, email: req.user.email,
    phone: req.user.phone, phone_verified: !!req.user.phone_verified,
    id_verified: !!req.user.id_verified,
    balance: st.live_mode ? req.user.balance : Number(req.user.demo_balance),
    live: st.live_mode, withdrawals: st.withdrawals_enabled,
    wht: st.wht_enabled ? st.wht_rate : 0,
    wd_max: WD_MAX_MPESA, wd_daily: WD_DAILY_LIMIT });
});

/* ---------- deposit: Paystack transaction (M-Pesa / card) ---------- */
app.post("/api/deposit/init", auth, async (req, res) => {
  const st = await getSettings();
  if (!st.live_mode) return res.status(403).json({ error: "Demo mode is on — deposits are paused." });
  if (req.user.suspended) return res.status(403).json({ error: "Account under review. Contact support." });
  const amountKes = Math.floor(Number(req.body.amount));
  if (!amountKes || amountKes < 100) return res.status(400).json({ error: "Minimum deposit is KSh 100." });
  if (amountKes > 100000) return res.status(400).json({ error: "Maximum deposit is KSh 100,000." });

  const reference = "dep_" + crypto.randomBytes(10).toString("hex");
  let r;
  try {
    r = await fetch(`${PS}/transaction/initialize`, {
      method: "POST", headers: psHeaders,
      body: JSON.stringify({
        email: req.user.email,
        amount: amountKes * 100,            // Paystack expects the minor unit
        currency: "KES",
        reference: reference,
        channels: ["mobile_money", "card"], // mobile_money drives the M-Pesa prompt in Kenya
        callback_url: `${BASE_URL}/`,
        metadata: { user_id: req.user.id, phone: req.user.phone },
      }),
    }).then(x => x.json());
  } catch (e) { return res.status(502).json({ error: "Could not reach Paystack. Try again." }); }

  if (!r || !r.status || !r.data)
    return res.status(502).json({ error: (r && r.message) || "Could not start the payment. Try again." });

  await pool.query(
    "INSERT INTO tx(user_id,kind,amount,ref,status,phone,created) VALUES($1,'deposit',$2,$3,'pending',$4,$5)",
    [req.user.id, amountKes * 100, r.data.reference, req.user.phone, Date.now()]);
  res.json({ ok: true, authorization_url: r.data.authorization_url, reference: r.data.reference,
             message: "Finish the payment in the Paystack window, then approve the M-Pesa prompt." });
});

/* Credit the wallet. Shared by the webhook and the verify fallback, and
 * guarded so a transaction can never be credited twice. */
async function creditDeposit(reference, paidMinor) {
  const t = (await pool.query(
    "SELECT * FROM tx WHERE ref=$1 AND kind='deposit' AND status='pending'", [reference])).rows[0];
  if (!t) return false;
  const cents = Number(paidMinor) || Number(t.amount);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const upd = await client.query(
      "UPDATE tx SET status='success', amount=$2 WHERE id=$1 AND status='pending'", [t.id, cents]);
    if (!upd.rowCount) throw new Error("already");
    await client.query("UPDATE users SET balance=balance+$2 WHERE id=$1", [t.user_id, cents]);
    // a completed payment confirms the account holder controls the payment method
    await client.query(
      "UPDATE users SET phone_verified=true WHERE id=$1 AND phone_verified=false", [t.user_id]);
    await client.query("COMMIT");
  } catch (e) { await client.query("ROLLBACK"); client.release(); return false; }
  client.release();
  return true;
}

/* ---------- Paystack webhook (HMAC-SHA512 over the raw body) ---------- */
app.post("/api/paystack/webhook", async (req, res) => {
  const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.from(JSON.stringify(req.body || {}));
  const expected = crypto.createHmac("sha512", PAYSTACK_SECRET || "").update(raw).digest("hex");
  const got = String(req.headers["x-paystack-signature"] || "");
  let ok = false;
  try { ok = crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(got)); } catch (e) { ok = false; }
  if (!ok) return res.sendStatus(401);

  let ev; try { ev = JSON.parse(raw.toString()); } catch (e) { return res.sendStatus(400); }
  const d = ev.data || {};

  if (ev.event === "charge.success") await creditDeposit(d.reference, d.amount);

  if (ev.event === "transfer.success")
    await pool.query("UPDATE tx SET status='success' WHERE ref=$1 AND kind='withdraw'", [d.reference]);

  if (ev.event === "transfer.failed" || ev.event === "transfer.reversed") {
    const t = (await pool.query(
      "SELECT * FROM tx WHERE ref=$1 AND kind='withdraw' AND status IN ('pending','sending')",
      [d.reference])).rows[0];
    if (t) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const upd = await client.query(
          "UPDATE tx SET status='failed' WHERE id=$1 AND status IN ('pending','sending')", [t.id]);
        if (upd.rowCount)                          // refund exactly once
          await client.query("UPDATE users SET balance=balance+$2 WHERE id=$1",
            [t.user_id, Number(t.amount)]);
        await client.query("COMMIT");
      } catch (e) { await client.query("ROLLBACK"); } finally { client.release(); }
    }
  }
  res.sendStatus(200);
});

/* Fallback for when the player returns from checkout — still confirmed
 * server-side against Paystack. The webhook remains the primary path. */
app.get("/api/deposit/verify/:ref", auth, async (req, res) => {
  const t = (await pool.query(
    "SELECT * FROM tx WHERE ref=$1 AND user_id=$2", [req.params.ref, req.user.id])).rows[0];
  if (!t) return res.status(404).json({ error: "Unknown transaction." });
  try {
    const r = await fetch(`${PS}/transaction/verify/${encodeURIComponent(req.params.ref)}`,
      { headers: psHeaders }).then(x => x.json());
    if (r && r.status && r.data && r.data.status === "success")
      await creditDeposit(req.params.ref, r.data.amount);
  } catch (e) { /* fall through and just return the balance */ }
  const u = await pool.query("SELECT balance FROM users WHERE id=$1", [req.user.id]);
  res.json({ balance: Number(u.rows[0].balance) });
});

/* ---------- Paystack payout helper (shared with admin approvals) ----------
 * Returns {ok:true} or {ok:false, error}. Never touches balances — the caller
 * has already debited and is responsible for refunding on failure. */
async function sendTransfer({ name, phone, cents, ref }) {
  let rcp;
  try {
    rcp = await fetch(`${PS}/transferrecipient`, {
      method: "POST", headers: psHeaders,
      body: JSON.stringify({ type: "mobile_money", name: name || "Player",
        account_number: phone, bank_code: "MPESA", currency: "KES" }),
    }).then(x => x.json());
  } catch (e) { return { ok: false, error: "Could not reach Paystack." }; }
  if (!rcp || !rcp.status || !rcp.data)
    return { ok: false, error: (rcp && rcp.message) || "Could not register that M-Pesa number." };

  let tr;
  try {
    tr = await fetch(`${PS}/transfer`, {
      method: "POST", headers: psHeaders,
      body: JSON.stringify({ source: "balance", amount: cents,
        recipient: rcp.data.recipient_code, reference: ref, currency: "KES",
        reason: "Winnings withdrawal" }),
    }).then(x => x.json());
  } catch (e) { return { ok: false, error: "Could not reach Paystack." }; }

  if (!tr || !tr.status) return { ok: false, error: (tr && tr.message) || "Payout failed." };
  if (tr.data && tr.data.status === "otp")
    return { ok: false, error: "Payouts need OTP approval. Disable transfer OTP in your Paystack dashboard." };
  return { ok: true };
}

/* ---------- withdrawals ---------- */
async function withdrawalsToday(userId) {
  const start = new Date(); start.setHours(0, 0, 0, 0);
  const r = await pool.query(
    `SELECT COUNT(*) c FROM tx WHERE user_id=$1 AND kind IN ('withdraw','pesalink')
     AND status IN ('pending','sending','success','requested') AND created >= $2`,
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
  if (cents > req.user.balance) return res.status(400).json({ error: "Insufficient balance." });

  const deb = await pool.query(
    "UPDATE users SET balance=balance-$2 WHERE id=$1 AND balance>=$2", [req.user.id, cents]);
  if (!deb.rowCount) return res.status(400).json({ error: "Insufficient balance." });
  const ref = "wd_" + crypto.randomBytes(10).toString("hex");
  await pool.query(
    "INSERT INTO tx(user_id,kind,amount,ref,status,phone,created) VALUES($1,'withdraw',$2,$3,'sending',$4,$5)",
    [req.user.id, cents, ref, phone, Date.now()]);

  const out = await sendTransfer({ name: req.user.full_name, phone: phone, cents: cents, ref: ref });
  if (!out.ok) {
    await pool.query("UPDATE tx SET status='failed' WHERE ref=$1", [ref]);
    await pool.query("UPDATE users SET balance=balance+$2 WHERE id=$1", [req.user.id, cents]);
    return res.status(502).json({ error: out.error + " Your balance was not charged." });
  }
  await pool.query("UPDATE tx SET status='pending' WHERE ref=$1", [ref]);
  const u = await pool.query("SELECT balance FROM users WHERE id=$1", [req.user.id]);
  res.json({ ok: true, balance: Number(u.rows[0].balance),
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
  if (cents > req.user.balance) return res.status(400).json({ error: "Insufficient balance." });

  const deb = await pool.query(
    "UPDATE users SET balance=balance-$2 WHERE id=$1 AND balance>=$2", [req.user.id, cents]);
  if (!deb.rowCount) return res.status(400).json({ error: "Insufficient balance." });
  const ref = "pl_" + crypto.randomBytes(10).toString("hex");
  await pool.query(
    `INSERT INTO tx(user_id,kind,amount,ref,status,phone,bank,account,created)
     VALUES($1,'pesalink',$2,$3,'requested',$4,$5,$6,$7)`,
    [req.user.id, cents, ref, req.user.phone, bank, account, Date.now()]);
  const u = await pool.query("SELECT balance FROM users WHERE id=$1", [req.user.id]);
  res.json({ ok: true, balance: Number(u.rows[0].balance),
    message: "PesaLink request received. Bank transfers are processed within one business day." });
});

/* ---------- settle one spin (shared by spin and free respin) ---------- */
async function settle(user, bets, stake, live, st, freeSpin) {
  const hit = drawOutcome(buildOutcomes(st.target_rtp));
  let gross = 0, jackpotWin = 0, bonusToken = null, respin = false;

  if (hit.key === "allprize") {
    for (const v of Object.values(bets)) gross += Math.floor(Number(v)) * hit.odds;
  } else if (hit.key === "bonus") {
    const tiles = BONUS_TILES.slice();
    for (let i = tiles.length - 1; i > 0; i--) {          // Fisher-Yates with CSPRNG
      const j = crypto.randomInt(i + 1); const t = tiles[i]; tiles[i] = tiles[j]; tiles[j] = t;
    }
    bonusToken = sign({ uid: user.id, stake, tiles, live, exp: Date.now() + 10 * 60 * 1000,
                        n: crypto.randomBytes(6).toString("hex") });
  } else if (hit.key === "respin") {
    respin = true;
  } else if (bets[hit.key]) {
    gross = Math.floor(Number(bets[hit.key])) * hit.odds;
  }

  const slot = visualSlot(hit.key, hit.odds);
  const contribution = live && !freeSpin ? Math.floor(stake * JACKPOT_CUT) : 0;
  const chargeStake = freeSpin ? 0 : stake;

  const client = await pool.connect();
  let taxTaken = 0, netPayout = 0;
  try {
    await client.query("BEGIN");
    if (hit.key === "jackpot" && live) {
      const j = await client.query("SELECT pool FROM jackpot WHERE id=1 FOR UPDATE");
      jackpotWin = Number(j.rows[0].pool) + contribution;
      gross += jackpotWin;
      await client.query("UPDATE jackpot SET pool=$1 WHERE id=1", [JACKPOT_SEED]);
    } else if (live) {
      await client.query("UPDATE jackpot SET pool=pool+$1 WHERE id=1", [contribution]);
    }
    const t = live ? applyWHT(gross, chargeStake, st) : { net: gross, tax: 0 };
    netPayout = t.net; taxTaken = t.tax;

    const balCol = live ? "balance" : "demo_balance";
    const d = await client.query(
      `UPDATE users SET ${balCol}=${balCol}-$2+$3 WHERE id=$1 AND ${balCol}>=$2`,
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
    throw new Error("Insufficient balance. Deposit to play.");
  }
  client.release();
  return { key: hit.key, slot, payout: netPayout, tax: taxTaken,
           jackpot: jackpotWin, bonusToken, respin };
}

/* ---------- the spin ---------- */
app.post("/api/spin", auth, async (req, res) => {
  const bets = req.body.bets || {};
  let stake = 0;
  for (const [k, v] of Object.entries(bets)) {
    if (!BETTABLE.includes(k)) return res.status(400).json({ error: "Unknown bet." });
    const amt = Math.floor(Number(v));
    if (amt < MIN_BET) return res.status(400).json({ error: "Minimum KSh 20 per symbol." });
    stake += amt;
  }
  if (!stake) return res.status(400).json({ error: "Place at least one bet." });
  if (stake > MAX_STAKE) return res.status(400).json({ error: "Max total stake is KSh 10,000." });

  const st = await getSettings();
  const live = st.live_mode;
  if (req.user.suspended && live) return res.status(403).json({ error: "Account under review. Contact support." });
  if (!live && Number(req.user.demo_balance) < stake) {
    await pool.query("UPDATE users SET demo_balance=100000 WHERE id=$1", [req.user.id]);
    req.user.demo_balance = 100000;
  }
  const curBal = live ? req.user.balance : Number(req.user.demo_balance);
  if (stake > curBal) return res.status(400).json({ error: "Insufficient balance. Deposit to play." });

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
  const u = await pool.query(`SELECT ${balCol} AS b FROM users WHERE id=$1`, [req.user.id]);
  const jp = await pool.query("SELECT pool FROM jackpot WHERE id=1");
  res.json({
    key: out.key, slot: out.slot, payout: out.payout, tax: out.tax, jackpot: out.jackpot,
    bonus: out.bonusToken ? { token: out.bonusToken } : null,
    respin: respinResult ? {
      key: respinResult.key, slot: respinResult.slot, payout: respinResult.payout,
      tax: respinResult.tax, jackpot: respinResult.jackpot,
      bonus: respinResult.bonusToken ? { token: respinResult.bonusToken } : null,
    } : null,
    pool: Number(jp.rows[0].pool), balance: Number(u.rows[0].b), live,
  });
});

/* ---------- diamond bonus: pick 3 of 9 ---------- */
app.post("/api/bonus/pick", auth, async (req, res) => {
  const t = verify(String(req.body.token || ""));
  if (!t || t.uid !== req.user.id || t.exp < Date.now())
    return res.status(400).json({ error: "Bonus expired." });
  const picks = Array.isArray(req.body.picks) ? req.body.picks.map(Number) : [];
  if (picks.length !== 3 || new Set(picks).size !== 3 || picks.some(i => !(i >= 0 && i < 9)))
    return res.status(400).json({ error: "Pick exactly three tiles." });

  const st = await getSettings();
  const gross = picks.reduce((s, i) => s + t.tiles[i] * t.stake, 0);
  const taxed = t.live ? applyWHT(gross, 0, st) : { net: gross, tax: 0 };
  const balCol = t.live ? "balance" : "demo_balance";

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // the token nonce doubles as a unique ref, so a replayed request can't pay twice
    const ins = await client.query(
      `INSERT INTO tx(user_id,kind,amount,ref,status,created)
       VALUES($1,'bonus',$2,$3,'success',$4) ON CONFLICT (ref) DO NOTHING`,
      [req.user.id, taxed.net, "bonus_" + t.n, Date.now()]);
    if (!ins.rowCount) throw new Error("dup");
    await client.query(`UPDATE users SET ${balCol}=${balCol}+$2 WHERE id=$1`, [req.user.id, taxed.net]);
    await client.query(
      `INSERT INTO spins(user_id,bets,slot,stake,payout,demo,jackpot,tax,kind,created)
       VALUES($1,'{}',0,0,$2,$3,0,$4,'bonus',$5)`,
      [req.user.id, taxed.net, !t.live, taxed.tax, Date.now()]);
    await client.query("COMMIT");
  } catch (e) {
    await client.query("ROLLBACK"); client.release();
    return res.status(400).json({ error: "This bonus was already claimed." });
  }
  client.release();
  const u = await pool.query(`SELECT ${balCol} AS b FROM users WHERE id=$1`, [req.user.id]);
  res.json({
    revealed: picks.map(i => ({ i: i, mult: t.tiles[i] })),
    all: t.tiles, payout: taxed.net, tax: taxed.tax, balance: Number(u.rows[0].b),
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

require("./admin.js")(app, pool, sign, verify, { sendTransfer: sendTransfer });

app.get("/api/history", auth, async (req, res) => {
  const spins = await pool.query(
    "SELECT slot,stake,payout,tax,kind,created FROM spins WHERE user_id=$1 ORDER BY id DESC LIMIT 20", [req.user.id]);
  const tx = await pool.query(
    "SELECT kind,amount,status,created FROM tx WHERE user_id=$1 ORDER BY id DESC LIMIT 20", [req.user.id]);
  res.json({ spins: spins.rows, tx: tx.rows });
});

module.exports = app;
