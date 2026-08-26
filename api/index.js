/**
 * Football Spin — Daraja (M-Pesa) + Postgres backend for Vercel
 *
 * Env vars (Vercel → Settings → Environment Variables):
 *   DATABASE_URL              Postgres connection string (Neon)
 *   APP_SECRET                long random string (session signing) — must stay constant
 *   CALLBACK_TOKEN            random string used in callback URLs (Daraja doesn't sign callbacks)
 *   BASE_URL                  https://yourdomain.vercel.app
 *   MPESA_ENV                 "sandbox" or "production"
 *   MPESA_CONSUMER_KEY / MPESA_CONSUMER_SECRET   from your Daraja app
 *   MPESA_SHORTCODE           your paybill number
 *   MPESA_PASSKEY             Lipa na M-Pesa online passkey (STK push)
 *   MPESA_INITIATOR           B2C initiator name
 *   MPESA_SECURITY_CREDENTIAL encrypted initiator password (generate in Daraja portal)
 */
const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");

const {
  DATABASE_URL, APP_SECRET, CALLBACK_TOKEN, BASE_URL,
  MPESA_ENV = "sandbox", MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET,
  MPESA_SHORTCODE, MPESA_PASSKEY, MPESA_INITIATOR, MPESA_SECURITY_CREDENTIAL,
} = process.env;

const DARAJA = MPESA_ENV === "production"
  ? "https://api.safaricom.co.ke"
  : "https://sandbox.safaricom.co.ke";

const pool = new Pool({ connectionString: DATABASE_URL, max: 3 });
let ready;
function init() {
  ready ??= pool.query(`
    CREATE TABLE IF NOT EXISTS users(
      id SERIAL PRIMARY KEY, email TEXT UNIQUE, salt TEXT, hash TEXT,
      balance BIGINT DEFAULT 0, created BIGINT);
    CREATE TABLE IF NOT EXISTS tx(
      id SERIAL PRIMARY KEY, user_id INT, kind TEXT, amount BIGINT,
      ref TEXT UNIQUE, status TEXT, phone TEXT, created BIGINT);
    CREATE TABLE IF NOT EXISTS settings(
      key TEXT PRIMARY KEY, value TEXT);
    INSERT INTO settings(key,value) VALUES('live_mode','true'),('withdrawals_enabled','true')
      ON CONFLICT DO NOTHING;
    CREATE TABLE IF NOT EXISTS admin_attempts(id SERIAL PRIMARY KEY, ts BIGINT);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS demo_balance BIGINT DEFAULT 100000;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT UNIQUE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS id_number TEXT UNIQUE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS id_verified BOOLEAN DEFAULT false;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verified BOOLEAN DEFAULT false;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended BOOLEAN DEFAULT false;
    ALTER TABLE spins ADD COLUMN IF NOT EXISTS demo BOOLEAN DEFAULT false;
    ALTER TABLE spins ADD COLUMN IF NOT EXISTS jackpot BIGINT DEFAULT 0;
    CREATE TABLE IF NOT EXISTS jackpot(
      id INT PRIMARY KEY DEFAULT 1, pool BIGINT DEFAULT 500000);
    INSERT INTO jackpot(id) VALUES(1) ON CONFLICT DO NOTHING;
    CREATE TABLE IF NOT EXISTS spins(
      id SERIAL PRIMARY KEY, user_id INT, bets TEXT, slot INT,
      stake BIGINT, payout BIGINT, created BIGINT);
  `);
  return ready;
}

const app = express();
app.use(express.json());
app.use(async (_req, _res, next) => { await init(); next(); });

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

async function getSettings() {
  const r = await pool.query("SELECT key,value FROM settings");
  const o = {}; r.rows.forEach(x => o[x.key] = x.value === "true");
  return o;
}

/* ---------- Daraja auth token (cached) ---------- */
let tokenCache = { v: null, exp: 0 };
async function darajaToken() {
  if (tokenCache.v && Date.now() < tokenCache.exp) return tokenCache.v;
  const basic = Buffer.from(`${MPESA_CONSUMER_KEY}:${MPESA_CONSUMER_SECRET}`).toString("base64");
  const r = await fetch(`${DARAJA}/oauth/v1/generate?grant_type=client_credentials`, {
    headers: { Authorization: `Basic ${basic}` } }).then(r => r.json());
  if (!r.access_token) throw new Error("Daraja auth failed");
  tokenCache = { v: r.access_token, exp: Date.now() + 50 * 60 * 1000 };
  return r.access_token;
}

/* ---------- game definition (see README: 30% RTP / 70% margin) ---------- */
const WHEEL = ["leicester","leicester","allprize","norwich","liverpool","arsenal","arsenal","diamond",
  "norwich","stoke","stoke","real","manu","manu","norwich","liverpool","liverpool","chelsea",
  "chelsea","diamond","norwich","real","real","stoke"];
/* Base game 28% RTP + 2% jackpot contribution = 30% total player return (70% margin).
 * Jackpot: JACKPOT_CUT of every stake feeds the pool; a 1-in-20,000 weighted
 * trigger pays the whole pool to the spinning player, then the pool resets to
 * JACKPOT_SEED (the seed is the only house cost — a few thousand shillings per hit). */
const OUTCOMES = [
  { key: "leicester", odds: 50,  w: 373 },
  { key: "leicester", odds: 100, w: 56 },
  { key: "manu",      odds: 25,  w: 971 },
  { key: "chelsea",   odds: 25,  w: 971 },
  { key: "arsenal",   odds: 25,  w: 971 },
  { key: "real",      odds: 12,  w: 2023 },
  { key: "liverpool", odds: 12,  w: 2023 },
  { key: "stoke",     odds: 12,  w: 2023 },
  { key: "norwich",   odds: 5,   w: 4853 },
  { key: "allprize",  odds: 2,   w: 1867 },
  { key: "jackpot",   odds: 0,   w: 5 },      // ~1 in 20,000 spins
  { key: "diamond",   odds: 0,   w: 83864 },
];
const JACKPOT_CUT = 0.02;              // share of every stake into the pool
const JACKPOT_SEED = 5000 * 100;       // KSh 5,000 reset value (cents)
const TOTAL_W = OUTCOMES.reduce((s, o) => s + o.w, 0);
const BETTABLE = ["leicester","manu","chelsea","arsenal","real","liverpool","stoke","norwich"];
const MIN_BET = 20 * 100, MAX_STAKE = 10000 * 100; // KES cents

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
    balance: st.live_mode ? req.user.balance : Number(req.user.demo_balance),
    live: st.live_mode, withdrawals: st.withdrawals_enabled });
});

app.get("/api/config", async (_req, res) => {
  const st = await getSettings();
  res.json({ live: st.live_mode, withdrawals: st.withdrawals_enabled });
});

/* ---------- deposit: STK push to your paybill ---------- */
app.post("/api/deposit/init", auth, async (req, res) => {
  const st = await getSettings();
  if (!st.live_mode) return res.status(403).json({ error: "Demo mode is on — deposits are paused." });
  if (req.user.suspended) return res.status(403).json({ error: "Account under review. Contact support." });
  const amountKes = Math.floor(Number(req.body.amount)); // whole shillings for Daraja
  const phone = req.body.phone ? msisdn(req.body.phone) : req.user.phone;
  if (!amountKes || amountKes < 100) return res.status(400).json({ error: "Minimum deposit is KSh 100." });
  if (amountKes > 100000) return res.status(400).json({ error: "Maximum deposit is KSh 100,000." });
  if (!phone) return res.status(400).json({ error: "Enter a valid Safaricom number, e.g. 07XX XXX XXX." });

  const ts = new Date().toISOString().replace(/[-:TZ.]/g, "").slice(0, 14);
  const password = Buffer.from(MPESA_SHORTCODE + MPESA_PASSKEY + ts).toString("base64");
  const r = await fetch(`${DARAJA}/mpesa/stkpush/v1/processrequest`, {
    method: "POST",
    headers: { Authorization: `Bearer ${await darajaToken()}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      BusinessShortCode: MPESA_SHORTCODE, Password: password, Timestamp: ts,
      TransactionType: "CustomerPayBillOnline", Amount: amountKes,
      PartyA: phone, PartyB: MPESA_SHORTCODE, PhoneNumber: phone,
      CallBackURL: `${BASE_URL}/api/mpesa/stk/${CALLBACK_TOKEN}`,
      AccountReference: "SPIN" + req.user.id, TransactionDesc: "Wallet deposit",
    }),
  }).then(r => r.json());

  if (r.ResponseCode !== "0")
    return res.status(502).json({ error: r.errorMessage || "Could not send the M-Pesa prompt. Try again." });
  await pool.query(
    "INSERT INTO tx(user_id,kind,amount,ref,status,phone,created) VALUES($1,'deposit',$2,$3,'pending',$4,$5)",
    [req.user.id, amountKes * 100, r.CheckoutRequestID, phone, Date.now()]);
  res.json({ ok: true, message: "Check your phone and enter your M-Pesa PIN." });
});

// STK result callback (credit only here, after Safaricom confirms)
app.post("/api/mpesa/stk/:token", async (req, res) => {
  if (req.params.token !== CALLBACK_TOKEN) return res.sendStatus(403);
  const cb = req.body?.Body?.stkCallback;
  if (!cb) return res.sendStatus(400);
  const t = (await pool.query("SELECT * FROM tx WHERE ref=$1 AND status='pending'", [cb.CheckoutRequestID])).rows[0];
  if (t) {
    if (cb.ResultCode === 0) {
      const paid = cb.CallbackMetadata?.Item?.find(i => i.Name === "Amount")?.Value;
      const cents = Math.round(Number(paid) * 100) || Number(t.amount);
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query("UPDATE tx SET status='success', amount=$2 WHERE id=$1", [t.id, cents]);
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

/* ---------- C2B: direct paybill payments auto-credit ----------
 * Players can also pay the paybill directly from the M-Pesa menu using
 * account number SPIN<user id>. Register the URLs once per environment:
 * GET /api/mpesa/c2b/register/<CALLBACK_TOKEN>
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
  }).then(r => r.json());
  res.json(r);
});

// Validation: reject payments whose account reference doesn't match a player
app.post("/api/mpesa/c2b/validate/:token", async (req, res) => {
  if (req.params.token !== CALLBACK_TOKEN) return res.sendStatus(403);
  const userId = parseInt(String(req.body?.BillRefNumber || "").replace(/\D/g, ""), 10);
  const amt = Number(req.body?.TransAmount || 0);
  const u = userId ? (await pool.query("SELECT id FROM users WHERE id=$1", [userId])).rows[0] : null;
  if (!u) return res.json({ ResultCode: "C2B00012", ResultDesc: "Rejected" }); // invalid account number
  if (amt < 100 || amt > 100000)
    return res.json({ ResultCode: "C2B00013", ResultDesc: "Rejected" }); // invalid amount
  res.json({ ResultCode: 0, ResultDesc: "Accepted" });
});

// Confirmation: credit the wallet (idempotent on TransID)
app.post("/api/mpesa/c2b/confirm/:token", async (req, res) => {
  if (req.params.token !== CALLBACK_TOKEN) return res.sendStatus(403);
  const b = req.body || {};
  const userId = parseInt(String(b.BillRefNumber || "").replace(/\D/g, ""), 10);
  const cents = Math.round(Number(b.TransAmount) * 100);
  if (userId && cents > 0 && b.TransID) {
    const u = (await pool.query("SELECT id FROM users WHERE id=$1", [userId])).rows[0];
    if (u) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const ins = await client.query(
          `INSERT INTO tx(user_id,kind,amount,ref,status,phone,created)
           VALUES($1,'deposit',$2,$3,'success',$4,$5) ON CONFLICT (ref) DO NOTHING`,
          [userId, cents, b.TransID, String(b.MSISDN || ""), Date.now()]);
        if (ins.rowCount) { // only credit if this TransID wasn't already processed
          await client.query("UPDATE users SET balance=balance+$2 WHERE id=$1", [userId, cents]);
          const payer = msisdn(b.MSISDN);
          if (payer) await client.query(
            "UPDATE users SET phone_verified=true WHERE id=$1 AND phone=$2 AND phone_verified=false",
            [userId, payer]);
        }
        await client.query("COMMIT");
      } catch (e) { await client.query("ROLLBACK"); } finally { client.release(); }
    }
  }
  res.json({ ResultCode: 0, ResultDesc: "Accepted" });
});

/* ---------- withdrawal: B2C from your paybill ---------- */
app.post("/api/withdraw", auth, async (req, res) => {
  const st = await getSettings();
  if (!st.live_mode) return res.status(403).json({ error: "Demo mode is on — withdrawals are paused." });
  if (!st.withdrawals_enabled) return res.status(403).json({ error: "Withdrawals are briefly paused for maintenance. Your balance is safe." });
  if (req.user.suspended) return res.status(403).json({ error: "Account under review. Contact support." });
  const amountKes = Math.floor(Number(req.body.amount));
  const phone = req.user.phone;
  const cents = amountKes * 100;
  if (!amountKes || amountKes < 100) return res.status(400).json({ error: "Minimum withdrawal is KSh 100." });
  if (!req.user.phone_verified)
    return res.status(403).json({ error: "Verify your number first: make one deposit from " +
      "0" + String(phone).slice(3) + " and withdrawals unlock automatically." });
  if (cents > req.user.balance) return res.status(400).json({ error: "Insufficient balance." });

  // debit first; refund on failure via result callback or immediate error
  const deb = await pool.query(
    "UPDATE users SET balance=balance-$2 WHERE id=$1 AND balance>=$2", [req.user.id, cents]);
  if (!deb.rowCount) return res.status(400).json({ error: "Insufficient balance." });
  const ref = "wd_" + crypto.randomBytes(10).toString("hex");
  await pool.query(
    "INSERT INTO tx(user_id,kind,amount,ref,status,phone,created) VALUES($1,'withdraw',$2,$3,'sending',$4,$5)",
    [req.user.id, cents, ref, phone, Date.now()]);

  const r = await fetch(`${DARAJA}/mpesa/b2c/v3/paymentrequest`, {
    method: "POST",
    headers: { Authorization: `Bearer ${await darajaToken()}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      OriginatorConversationID: ref,
      InitiatorName: MPESA_INITIATOR, SecurityCredential: MPESA_SECURITY_CREDENTIAL,
      CommandID: "BusinessPayment", Amount: amountKes,
      PartyA: MPESA_SHORTCODE, PartyB: phone,
      Remarks: "Winnings", Occasion: "Withdrawal",
      QueueTimeOutURL: `${BASE_URL}/api/mpesa/b2c/${CALLBACK_TOKEN}`,
      ResultURL: `${BASE_URL}/api/mpesa/b2c/${CALLBACK_TOKEN}`,
    }),
  }).then(r => r.json()).catch(() => ({}));

  if (r.ResponseCode !== "0") {
    await pool.query("UPDATE tx SET status='failed' WHERE ref=$1", [ref]);
    await pool.query("UPDATE users SET balance=balance+$2 WHERE id=$1", [req.user.id, cents]);
    return res.status(502).json({ error: r.errorMessage || "Payout failed. Your balance was not charged." });
  }
  await pool.query("UPDATE tx SET status='pending' WHERE ref=$1", [ref]);
  const u = await pool.query("SELECT balance FROM users WHERE id=$1", [req.user.id]);
  res.json({ ok: true, balance: Number(u.rows[0].balance), message: "Sent — you'll get the M-Pesa SMS shortly." });
});

// B2C result / timeout callback
app.post("/api/mpesa/b2c/:token", async (req, res) => {
  if (req.params.token !== CALLBACK_TOKEN) return res.sendStatus(403);
  const rslt = req.body?.Result;
  if (rslt) {
    const ref = rslt.OriginatorConversationID;
    const t = (await pool.query("SELECT * FROM tx WHERE ref=$1 AND kind='withdraw'", [ref])).rows[0];
    if (t && t.status === "pending") {
      if (rslt.ResultCode === 0) {
        await pool.query("UPDATE tx SET status='success' WHERE id=$1", [t.id]);
      } else {
        // refund failed payout
        const client = await pool.connect();
        try {
          await client.query("BEGIN");
          await client.query("UPDATE tx SET status='failed' WHERE id=$1", [t.id]);
          await client.query("UPDATE users SET balance=balance+$2 WHERE id=$1", [t.user_id, Number(t.amount)]);
          await client.query("COMMIT");
        } catch (e) { await client.query("ROLLBACK"); } finally { client.release(); }
      }
    }
  }
  res.json({ ResultCode: 0, ResultDesc: "Accepted" });
});

/* ---------- the spin (weighted CSPRNG, audited) ---------- */
app.post("/api/spin", auth, async (req, res) => {
  const bets = req.body.bets || {};
  let stake = 0;
  for (const [k, v] of Object.entries(bets)) {
    if (!BETTABLE.includes(k)) return res.status(400).json({ error: "Unknown bet." });
    const amt = Math.floor(Number(v));
    if (amt < MIN_BET) return res.status(400).json({ error: "Minimum KSh 20 per team." });
    stake += amt;
  }
  if (!stake) return res.status(400).json({ error: "Place at least one bet." });
  if (stake > MAX_STAKE) return res.status(400).json({ error: "Max total stake is KSh 10,000." });
  const st = await getSettings();
  const live = st.live_mode;
  if (req.user.suspended && live) return res.status(403).json({ error: "Account under review. Contact support." });
  if (!live && Number(req.user.demo_balance) < stake) {
    await pool.query("UPDATE users SET demo_balance=100000 WHERE id=$1", [req.user.id]); // demo auto-refill KSh 1,000
    req.user.demo_balance = 100000;
  }
  const balCol = live ? "balance" : "demo_balance";
  const curBal = live ? req.user.balance : Number(req.user.demo_balance);
  if (stake > curBal) return res.status(400).json({ error: "Insufficient balance. Deposit to play." });

  let roll = crypto.randomInt(TOTAL_W), hit = OUTCOMES[OUTCOMES.length - 1];
  for (const o of OUTCOMES) { if (roll < o.w) { hit = o; break; } roll -= o.w; }

  let payout = 0, jackpotWin = 0;
  if (hit.key === "allprize") {
    for (const v of Object.values(bets)) payout += Math.floor(Number(v)) * hit.odds;
  } else if (bets[hit.key]) {
    payout = Math.floor(Number(bets[hit.key])) * hit.odds;
  }
  const visKey = hit.key === "jackpot" ? "allprize" : hit.key;
  const candidates = WHEEL.map((k, i) => (k === visKey ? i : -1)).filter(i => i >= 0);
  let slot = candidates[crypto.randomInt(candidates.length)];
  if (hit.key === "leicester") slot = hit.odds === 100 ? 1 : 0;

  const contribution = live ? Math.floor(stake * JACKPOT_CUT) : 0;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    if (hit.key === "jackpot" && live) {
      const j = await client.query("SELECT pool FROM jackpot WHERE id=1 FOR UPDATE");
      jackpotWin = Number(j.rows[0].pool) + contribution;
      payout += jackpotWin;
      await client.query("UPDATE jackpot SET pool=$1 WHERE id=1", [JACKPOT_SEED]);
    } else if (live) {
      await client.query("UPDATE jackpot SET pool=pool+$1 WHERE id=1", [contribution]);
    }
    const d = await client.query(
      `UPDATE users SET ${balCol}=${balCol}-$2+$3 WHERE id=$1 AND ${balCol}>=$2`,
      [req.user.id, stake, payout]);
    if (!d.rowCount) throw new Error("balance");
    await client.query(
      "INSERT INTO spins(user_id,bets,slot,stake,payout,demo,jackpot,created) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
      [req.user.id, JSON.stringify(bets), slot, stake, payout, !live, jackpotWin, Date.now()]);
    await client.query("COMMIT");
  } catch (e) {
    await client.query("ROLLBACK"); client.release();
    return res.status(400).json({ error: "Insufficient balance. Deposit to play." });
  }
  client.release();
  const u = await pool.query(`SELECT ${balCol} AS b FROM users WHERE id=$1`, [req.user.id]);
  const jp = await pool.query("SELECT pool FROM jackpot WHERE id=1");
  res.json({ slot, payout, jackpot: jackpotWin, pool: Number(jp.rows[0].pool),
             balance: Number(u.rows[0].b), live });
});

const BIG_WIN_MIN = 1000 * 100; // wins of KSh 1,000+ appear in the public feed

app.get("/api/winners", async (_req, res) => {
  const r = await pool.query(`
    SELECT s.payout, s.jackpot, s.created, u.full_name, u.id AS uid
    FROM spins s JOIN users u ON u.id = s.user_id
    WHERE s.demo = false AND (s.payout >= $1 OR s.jackpot > 0)
    ORDER BY s.id DESC LIMIT 12`, [BIG_WIN_MIN]);
  res.json(r.rows.map(x => {
    const parts = String(x.full_name || "").trim().split(/\s+/);
    const name = parts[0] ? parts[0] + (parts[1] ? " " + parts[1][0] + "." : "") : "Player " + x.uid;
    return { name, amount: Number(x.payout), jackpot: Number(x.jackpot) > 0, at: Number(x.created) };
  }));
});

app.get("/api/jackpot", async (_req, res) => {
  const r = await pool.query("SELECT pool FROM jackpot WHERE id=1");
  res.json({ pool: Number(r.rows[0]?.pool || 0) });
});

require("./admin.js")(app, pool, sign, verify);

app.get("/api/history", auth, async (req, res) => {
  const spins = await pool.query(
    "SELECT slot,stake,payout,created FROM spins WHERE user_id=$1 ORDER BY id DESC LIMIT 20", [req.user.id]);
  const tx = await pool.query(
    "SELECT kind,amount,status,created FROM tx WHERE user_id=$1 ORDER BY id DESC LIMIT 20", [req.user.id]);
  res.json({ spins: spins.rows, tx: tx.rows });
});

module.exports = app;
