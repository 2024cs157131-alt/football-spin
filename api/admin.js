/**
 * Admin panel — mounted by api/index.js.
 * Security layers:
 *  1. Secret URL slug (ADMIN_PATH env) — the panel is not linked or discoverable anywhere.
 *  2. Password (constant-time compare) + TOTP 2FA from an authenticator app.
 *  3. Login rate limiting stored in Postgres (works across serverless instances).
 *  4. Short-lived signed admin sessions (60 min).
 * Env: ADMIN_PATH, ADMIN_PASSWORD, ADMIN_TOTP_SECRET (base32)
 */
const crypto = require("crypto");

module.exports = function mountAdmin(app, pool, sign, verify, payouts) {
  const { ADMIN_PATH, ADMIN_PASSWORD, ADMIN_TOTP_SECRET } = process.env;

  /* TEMPORARY 2FA BYPASS — recovery only.
   * Set ADMIN_TOTP_DISABLED=true to sign in with the password alone, e.g. when
   * the authenticator secret has been lost. This leaves the console protected
   * by one factor and a secret URL, so it is materially weaker: set a new
   * ADMIN_TOTP_SECRET, re-add it to your authenticator, then DELETE this
   * variable. The lockout window is also tightened while it is on. */
  const TOTP_DISABLED = ["true", "1", "yes", "on"]
    .includes(String(process.env.ADMIN_TOTP_DISABLED || "").trim().toLowerCase());

  if (!ADMIN_PATH || !ADMIN_PASSWORD || (!ADMIN_TOTP_SECRET && !TOTP_DISABLED)) {
    console.warn("Admin panel disabled: set ADMIN_PATH, ADMIN_PASSWORD, ADMIN_TOTP_SECRET " +
                 "(or ADMIN_TOTP_DISABLED=true for temporary password-only recovery)");
    return;
  }
  if (TOTP_DISABLED)
    console.warn("SECURITY: admin 2FA is DISABLED (ADMIN_TOTP_DISABLED=true). " +
                 "Restore ADMIN_TOTP_SECRET and remove this variable as soon as you can.");

  /* ----- TOTP (RFC 6238, no dependencies) ----- */
  function b32decode(str) {
    const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "", out = [];
    for (const c of str.toUpperCase().replace(/=+$/, "")) {
      const v = A.indexOf(c); if (v < 0) continue;
      bits += v.toString(2).padStart(5, "0");
    }
    for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
    return Buffer.from(out);
  }
  function totp(secret, offset = 0) {
    const counter = Math.floor(Date.now() / 30000) + offset;
    const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(counter));
    const h = crypto.createHmac("sha1", b32decode(secret)).update(buf).digest();
    const o = h[h.length - 1] & 0xf;
    const code = ((h[o] & 0x7f) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1e6;
    return String(code).padStart(6, "0");
  }
  // +/- 2 steps = 60s either side. Phone clocks drift; a tighter window is the
  // usual reason a correct-looking code is rejected.
  const totpOk = code => TOTP_DISABLED ? true : [-2, -1, 0, 1, 2].some(w => {
    try {
      return crypto.timingSafeEqual(
        Buffer.from(totp(ADMIN_TOTP_SECRET, w)),
        Buffer.from(String(code || "").replace(/\D/g, "").padStart(6, "0")));
    } catch (e) { return false; }
  });
  const pwOk = pw => {
    const a = crypto.createHash("sha256").update(String(pw || "")).digest();
    const b = crypto.createHash("sha256").update(ADMIN_PASSWORD).digest();
    return crypto.timingSafeEqual(a, b);
  };

  /* ----- rate limiting (DB-backed, survives serverless cold starts) -----
   * Counted per client IP, not globally: one bot probing the URL should not be
   * able to lock the real operator out. Cleared on every successful login. */
  // fewer tries allowed while the second factor is off
  const MAX_ATTEMPTS = TOTP_DISABLED ? 4 : 8, WINDOW_MS = 10 * 60 * 1000;
  const clientIp = req =>
    String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
    (req.socket && req.socket.remoteAddress) || "unknown";

  let hasIpColumn = null;                    // probed once per cold start
  async function ipColumnExists() {
    if (hasIpColumn !== null) return hasIpColumn;
    try {
      const r = await pool.query(
        `SELECT 1 FROM information_schema.columns
         WHERE table_name='admin_attempts' AND column_name='ip' LIMIT 1`);
      hasIpColumn = r.rowCount > 0;
    } catch (e) { hasIpColumn = false; }
    return hasIpColumn;
  }

  /* Rate limiting must never be the reason a login fails outright: if the
   * counter itself errors, we let the attempt through and log it. */
  async function attemptsFor(ip) {
    try {
      const cutoff = Date.now() - WINDOW_MS;
      await pool.query("DELETE FROM admin_attempts WHERE ts < $1", [cutoff]);
      if (await ipColumnExists()) {
        const r = await pool.query(
          "SELECT COUNT(*) c FROM admin_attempts WHERE ts >= $1 AND ip = $2", [cutoff, ip]);
        return Number(r.rows[0].c);
      }
      const r = await pool.query(
        "SELECT COUNT(*) c FROM admin_attempts WHERE ts >= $1", [cutoff]);
      return Number(r.rows[0].c);
    } catch (e) {
      console.error("admin rate-limit check failed (allowing attempt):", e.message);
      return 0;
    }
  }

  async function recordAttempt(ip) {
    try {
      if (await ipColumnExists())
        await pool.query("INSERT INTO admin_attempts(ts,ip) VALUES($1,$2)", [Date.now(), ip]);
      else
        await pool.query("INSERT INTO admin_attempts(ts) VALUES($1)", [Date.now()]);
    } catch (e) { console.error("admin attempt log failed:", e.message); }
  }

  async function clearAttempts(ip) {
    try {
      if (await ipColumnExists())
        await pool.query("DELETE FROM admin_attempts WHERE ip = $1", [ip]);
      else
        await pool.query("DELETE FROM admin_attempts");
    } catch (e) { console.error("admin attempt clear failed:", e.message); }
  }

  /* Wrap async handlers so a thrown error returns JSON instead of leaving the
   * request hanging — Express 4 does not catch async rejections by itself. */
  const wrap = fn => (req, res) => Promise.resolve(fn(req, res)).catch(err => {
    console.error("admin route error:", err && err.stack || err);
    if (!res.headersSent)
      res.status(500).json({ error: "Server error: " + (err && err.message || "unknown") });
  });

  function adminAuth(req, res, next) {
    const t = verify((req.headers.authorization || "").replace("Bearer ", ""));
    if (!t || t.role !== "admin" || t.exp < Date.now())
      return res.status(401).json({ error: "Session expired. Log in again." });
    next();
  }

  const P = `/api/admin/${ADMIN_PATH}`;

  /* ----- login ----- */
  app.post(`${P}/login`, wrap(async (req, res) => {
    const ip = clientIp(req);
    const used = await attemptsFor(ip);
    if (used >= MAX_ATTEMPTS)
      return res.status(429).json({ error: "Too many attempts. Wait 10 minutes and try again." });

    const { password, code } = req.body || {};
    const okPw = pwOk(password), okCode = totpOk(code);

    if (!okPw || !okCode) {
      await recordAttempt(ip);
      // Which factor failed is logged for you but never returned to the client.
      console.warn("Admin login failed from " + ip +
        " — password " + (okPw ? "ok" : "WRONG") + ", code " + (okCode ? "ok" : "WRONG"));
      const left = MAX_ATTEMPTS - (used + 1);
      return res.status(401).json({
        error: "Wrong password or authenticator code." +
               (left > 0 ? ` ${left} attempt${left === 1 ? "" : "s"} left.` : " Locked for 10 minutes."),
      });
    }

    if (!process.env.APP_SECRET)
      return res.status(500).json({
        error: "APP_SECRET is not set on the server, so no session can be created. " +
               "Add it in Vercel → Environment Variables and redeploy." });

    // A good login clears the slate, so earlier typos can't lock you out later.
    await clearAttempts(ip);
    const ttl = TOTP_DISABLED ? 15 * 60 * 1000 : 60 * 60 * 1000;
    res.json({ token: sign({ role: "admin", exp: Date.now() + ttl }) });
  }));

  /* Clock check: compare your phone against the server so drift is obvious.
   * Returns no secrets and needs no auth. */
  /* Diagnostics — reports configuration state and DB health without ever
   * revealing a secret value. Safe to open in a browser while debugging. */
  app.get(`${P}/diag`, async (_req, res) => {
    const out = {
      admin_path_set: !!ADMIN_PATH,
      admin_password_set: !!ADMIN_PASSWORD,
      admin_password_length: ADMIN_PASSWORD ? String(ADMIN_PASSWORD).length : 0,
      totp_secret_set: !!ADMIN_TOTP_SECRET,
      totp_disabled: TOTP_DISABLED,
      app_secret_set: !!process.env.APP_SECRET,
      app_secret_length: process.env.APP_SECRET ? String(process.env.APP_SECRET).length : 0,
      database_url_set: !!process.env.DATABASE_URL,
      server_time: new Date().toISOString(),
    };
    // can we sign a token? this is the step that silently killed logins when
    // APP_SECRET was missing
    try { sign({ test: 1 }); out.token_signing = "ok"; }
    catch (e) { out.token_signing = "FAILED: " + e.message; }
    // is the database reachable, and does the attempts table exist?
    try {
      await pool.query("SELECT 1");
      out.database = "ok";
      const t = await pool.query(
        `SELECT column_name FROM information_schema.columns WHERE table_name='admin_attempts'`);
      out.admin_attempts_columns = t.rows.map(r => r.column_name);
    } catch (e) { out.database = "FAILED: " + e.message; }

    out.verdict = (!out.admin_password_set ? "ADMIN_PASSWORD is not set — login cannot succeed."
      : !out.app_secret_set ? "APP_SECRET is not set — login cannot issue a session."
      : out.token_signing !== "ok" ? "Token signing is broken — see token_signing."
      : String(out.database).startsWith("FAILED") ? "Database unreachable — see database."
      : "Configuration looks complete. If login still fails, the password is wrong.");
    res.json(out);
  });

  app.get(`${P}/time`, (_req, res) => {
    res.json({ server_time: new Date().toISOString(), epoch_ms: Date.now(),
               totp_step: Math.floor(Date.now() / 30000), totp_disabled: TOTP_DISABLED });
  });

  /* ----- dashboard stats ----- */
  app.get(`${P}/stats`, adminAuth, async (_req, res) => {
    const [users, dep, wd, daily, jack, st, pend, taxq, plq, expDaily, expAll] = await Promise.all([
      pool.query(`SELECT COUNT(*) c, COALESCE(SUM(balance),0)+COALESCE(SUM(winnings),0) bal,
                         COALESCE(SUM(balance),0) credit, COALESCE(SUM(winnings),0) winnings FROM users`),
      pool.query("SELECT COALESCE(SUM(amount),0) s, COUNT(*) c FROM tx WHERE kind='deposit' AND status='success'"),
      pool.query("SELECT COALESCE(SUM(amount),0) s, COUNT(*) c FROM tx WHERE kind='withdraw' AND status='success'"),
      pool.query(`SELECT to_char(to_timestamp(created/1000),'YYYY-MM-DD') d,
        COALESCE(SUM(stake),0) staked, COALESCE(SUM(payout),0) paid, COUNT(*) spins
        FROM spins WHERE demo=false GROUP BY d ORDER BY d DESC LIMIT 14`),
      pool.query("SELECT pool FROM jackpot WHERE id=1"),
      pool.query("SELECT key,value FROM settings"),
      pool.query("SELECT COUNT(*) c, COALESCE(SUM(amount),0) s FROM tx WHERE kind='withdraw' AND status IN ('pending','sending')"),
      pool.query("SELECT COALESCE(SUM(tax),0) t FROM spins WHERE demo=false"),
      pool.query("SELECT COUNT(*) c, COALESCE(SUM(amount),0) s FROM tx WHERE kind='pesalink' AND status='requested'"),
      pool.query(`SELECT to_char(to_timestamp(created/1000),'YYYY-MM-DD') d, COALESCE(SUM(amount),0) s
                  FROM expenses GROUP BY d ORDER BY d DESC LIMIT 30`),
      pool.query("SELECT COALESCE(SUM(amount),0) s FROM expenses"),
    ]);
    const BK = ["live_mode","withdrawals_enabled","wht_enabled"];
    const settings = {}; st.rows.forEach(x => settings[x.key] = BK.includes(x.key) ? x.value === "true" : Number(x.value));
    res.json({
      players: Number(users.rows[0].c),
      player_balances: Number(users.rows[0].bal),        // your liability to players
      player_credit: Number(users.rows[0].credit),       // stakeable pot
      player_winnings: Number(users.rows[0].winnings),   // won, not yet moved across
      deposits: { total: Number(dep.rows[0].s), count: Number(dep.rows[0].c) },
      withdrawals: { total: Number(wd.rows[0].s), count: Number(wd.rows[0].c) },
      pending_withdrawals: { count: Number(pend.rows[0].c), total: Number(pend.rows[0].s) },
      daily: (function () {
        const spend = {}; expDaily.rows.forEach(r => spend[r.d] = Number(r.s));
        return daily.rows.map(r => {
          const gross = Number(r.staked) - Number(r.paid);
          const mk = spend[r.d] || 0;
          return { date: r.d, staked: Number(r.staked), paid: Number(r.paid),
            profit: gross, marketing: mk, net: gross - mk, spins: Number(r.spins) };
        });
      })(),
      expenses_total: Number(expAll.rows[0].s),
      jackpot_pool: Number(jack.rows[0]?.pool || 0),
      wht_collected: Number(taxq.rows[0].t),
      pesalink_pending: { count: Number(plq.rows[0].c), total: Number(plq.rows[0].s) },
      settings,
    });
  });

  /* ----- players ----- */
  app.get(`${P}/players`, adminAuth, async (req, res) => {
    const q = String(req.query.q || "").trim();
    const r = await pool.query(`
      SELECT u.id, u.email, u.full_name, u.id_number, u.id_verified, u.phone, u.phone_verified,
        u.balance, u.winnings, u.suspended, u.created,
        COALESCE((SELECT SUM(amount) FROM tx WHERE user_id=u.id AND kind='deposit' AND status='success'),0) deposited,
        COALESCE((SELECT SUM(amount) FROM tx WHERE user_id=u.id AND kind='withdraw' AND status='success'),0) withdrawn,
        COALESCE((SELECT SUM(stake)-SUM(payout) FROM spins WHERE user_id=u.id AND demo=false),0) net_lost
      FROM users u ${q ? "WHERE u.email ILIKE $1 OR u.phone ILIKE $1 OR u.full_name ILIKE $1 OR u.id_number ILIKE $1" : ""}
      ORDER BY u.id DESC LIMIT 100`, q ? [`%${q}%`] : []);
    /* `winnings` is the separate pot a player must move across before staking.
       It used to be left out of this query, so credited wins looked missing. */
    res.json(r.rows.map(x => ({ ...x, balance: Number(x.balance), winnings: Number(x.winnings || 0),
      deposited: Number(x.deposited), withdrawn: Number(x.withdrawn), net_lost: Number(x.net_lost) })));
  });

  app.post(`${P}/players/:id/suspend`, adminAuth, async (req, res) => {
    await pool.query("UPDATE users SET suspended=$2 WHERE id=$1", [req.params.id, !!req.body.suspended]);
    res.json({ ok: true });
  });

  app.post(`${P}/players/:id/idverify`, adminAuth, async (req, res) => {
    await pool.query("UPDATE users SET id_verified=$2 WHERE id=$1", [req.params.id, !!req.body.verified]);
    res.json({ ok: true });
  });

  /* ----- switches ----- */
  const BOOL_KEYS = ["live_mode", "withdrawals_enabled", "wht_enabled"];
  const NUM_KEYS = ["wht_rate", "wht_threshold", "excise_rate", "betting_tax_rate", "corp_tax_rate", "target_rtp", "target_net", "min_deposit", "max_deposit"];

  app.post(`${P}/settings`, adminAuth, async (req, res) => {
    for (const k of BOOL_KEYS) {
      if (k in (req.body || {}))
        await pool.query("UPDATE settings SET value=$2 WHERE key=$1", [k, String(!!req.body[k])]);
    }
    for (const k of NUM_KEYS) {
      if (k in (req.body || {})) {
        const v = Number(req.body[k]);
        if (!(v >= 0)) return res.status(400).json({ error: "Rates must be zero or higher." });
        if (k === "target_rtp" && (v < 8 || v > 90))
          return res.status(400).json({ error: "Payout rate must be between 8% and 90%." });
        const prev = (await pool.query("SELECT value FROM settings WHERE key=$1", [k])).rows[0];
        if (!prev || prev.value !== String(v)) {
          await pool.query("UPDATE settings SET value=$2 WHERE key=$1", [k, String(v)]);
          await pool.query(
            "INSERT INTO settings_audit(key,old_value,new_value,created) VALUES($1,$2,$3,$4)",
            [k, prev ? prev.value : null, String(v), Date.now()]);
        }
      }
    }
    const r = await pool.query("SELECT key,value FROM settings");
    const o = {}; r.rows.forEach(x => o[x.key] = BOOL_KEYS.includes(x.key) ? x.value === "true" : Number(x.value));
    res.json(o);
  });

  /* ----- solve for the payout rate that yields a target NET profit -----
   * Per KSh 100 staked:  net = (ggr - excise - bettingTax*ggr/100) * (1 - corp/100)
   * Rearranged:          ggr = (net/(1-corp/100) + excise) / (1 - bettingTax/100)
   * RTP = 100 - ggr. Withholding tax is excluded: it comes out of the player's
   * winnings and is remitted to KRA, so it is not operator revenue. */
  function solveRtp(netTarget, ex, bt, ct) {
    const corp = Math.min(99, Math.max(0, ct)) / 100;
    const ggr = (netTarget / (1 - corp) + ex) / (1 - Math.min(99, Math.max(0, bt)) / 100);
    return { ggr: ggr, rtp: 100 - ggr };
  }

  app.post(`${P}/solve-margin`, adminAuth, async (req, res) => {
    const r = await pool.query("SELECT key,value FROM settings");
    const st = {}; r.rows.forEach(x => st[x.key] = x.value);
    const netTarget = Number(req.body.target_net != null ? req.body.target_net : st.target_net);
    const out = solveRtp(netTarget, Number(st.excise_rate), Number(st.betting_tax_rate), Number(st.corp_tax_rate));
    if (!(out.rtp >= 8 && out.rtp <= 90))
      return res.status(400).json({
        error: `A ${netTarget}% net profit would need a ${out.ggr.toFixed(1)}% house margin ` +
               `(payout ${out.rtp.toFixed(1)}%), which is outside the allowed 8–90% payout range. ` +
               `Lower the target or check your tax rates.`,
        ggr: out.ggr, rtp: out.rtp });

    if (req.body.apply) {
      const rtp = Math.round(out.rtp * 10) / 10;
      const prev = (await pool.query("SELECT value FROM settings WHERE key='target_rtp'")).rows[0];
      await pool.query("UPDATE settings SET value=$1 WHERE key='target_rtp'", [String(rtp)]);
      await pool.query("UPDATE settings SET value=$1 WHERE key='target_net'", [String(netTarget)]);
      await pool.query(
        "INSERT INTO settings_audit(key,old_value,new_value,created) VALUES($1,$2,$3,$4)",
        ["target_rtp", prev ? prev.value : null, String(rtp), Date.now()]);
    }
    res.json({ ok: true, target_net: netTarget, ggr: out.ggr, rtp: out.rtp });
  });

  /* ----- marketing & other spend ----- */
  app.get(`${P}/expenses`, adminAuth, async (_req, res) => {
    const [rows, totals, month] = await Promise.all([
      pool.query("SELECT * FROM expenses ORDER BY id DESC LIMIT 50"),
      pool.query("SELECT category, COALESCE(SUM(amount),0) s FROM expenses GROUP BY category"),
      pool.query("SELECT COALESCE(SUM(amount),0) s FROM expenses WHERE created >= $1",
        [Date.now() - 30 * 864e5]),
    ]);
    res.json({
      rows: rows.rows.map(x => ({ ...x, amount: Number(x.amount) })),
      by_category: totals.rows.map(x => ({ category: x.category, total: Number(x.s) })),
      last_30_days: Number(month.rows[0].s),
    });
  });

  app.post(`${P}/expenses`, adminAuth, async (req, res) => {
    const cents = Math.round(Number(req.body.amount) * 100);
    const category = String(req.body.category || "marketing").slice(0, 40);
    const note = String(req.body.note || "").slice(0, 200);
    if (!(cents > 0)) return res.status(400).json({ error: "Enter an amount." });
    await pool.query("INSERT INTO expenses(category,amount,note,created) VALUES($1,$2,$3,$4)",
      [category, cents, note, Date.now()]);
    res.json({ ok: true });
  });

  app.post(`${P}/expenses/:id/delete`, adminAuth, async (req, res) => {
    await pool.query("DELETE FROM expenses WHERE id=$1", [req.params.id]);
    res.json({ ok: true });
  });

  app.get(`${P}/audit`, adminAuth, async (_req, res) => {
    const r = await pool.query("SELECT * FROM settings_audit ORDER BY id DESC LIMIT 30");
    res.json(r.rows);
  });

  /* ----- payout queue: pending / stuck / failed M-Pesa withdrawals ----- */
  app.get(`${P}/payouts`, adminAuth, async (_req, res) => {
    const r = await pool.query(
      `SELECT t.id, t.user_id, t.amount, t.ref, t.status, t.phone, t.created,
              u.full_name, u.id_number
       FROM tx t JOIN users u ON u.id=t.user_id
       WHERE t.kind='withdraw'
       ORDER BY (t.status IN ('sending','pending')) DESC, t.id DESC LIMIT 60`);
    res.json(r.rows.map(x => ({ ...x, amount: Number(x.amount) })));
  });

  /* Manual settlement. "paid" is for money you sent by hand (or that Safaricom
   * delivered without a callback reaching us); "refund" returns it to the
   * player; "retry" sends the M-Pesa B2C payout again. */
  app.post(`${P}/payouts/:ref`, adminAuth, wrap(async (req, res) => {
    const action = String(req.body.action || "");
    const t = (await pool.query(
      "SELECT * FROM tx WHERE ref=$1 AND kind='withdraw'", [req.params.ref])).rows[0];
    if (!t) return res.status(404).json({ error: "Payout not found." });
    if (t.status === "success" && action !== "note")
      return res.status(400).json({ error: "Already marked paid." });

    if (action === "paid") {
      await pool.query("UPDATE tx SET status='success' WHERE id=$1", [t.id]);
      return res.json({ ok: true, message: "Marked paid." });
    }

    if (action === "refund") {
      const done = payouts && payouts.refundWithdrawal
        ? await payouts.refundWithdrawal(t)
        : false;
      if (!done) return res.status(400).json({ error: "Already settled — nothing to refund." });
      return res.json({ ok: true, message: "Refunded to the player." });
    }

    if (action === "retry") {
      if (!payouts || !payouts.sendTransfer)
        return res.status(500).json({ error: "Payout helper unavailable." });
      const u = (await pool.query("SELECT full_name FROM users WHERE id=$1", [t.user_id])).rows[0];
      const newRef = t.ref + "_r" + Date.now().toString(36);
      await pool.query("UPDATE tx SET status='sending', ref=$2 WHERE id=$1", [t.id, newRef]);
      const out = await payouts.sendTransfer({
        name: u && u.full_name, phone: t.phone, cents: Number(t.amount), ref: newRef });
      if (!out.ok) {
        await pool.query("UPDATE tx SET status='pending' WHERE id=$1", [t.id]);
        return res.status(502).json({ error: out.error });
      }
      await pool.query("UPDATE tx SET status='pending' WHERE id=$1", [t.id]);
      return res.json({ ok: true, message: "Payout re-sent." });
    }
    res.status(400).json({ error: "Unknown action." });
  }));

  /* ----- PesaLink queue (large withdrawals, paid manually from your bank) ----- */
  app.get(`${P}/pesalink`, adminAuth, async (_req, res) => {
    const r = await pool.query(
      `SELECT t.id, t.user_id, t.amount, t.ref, t.status, t.phone, t.bank, t.account, t.created,
              u.full_name, u.id_number
       FROM tx t JOIN users u ON u.id=t.user_id
       WHERE t.kind='pesalink' ORDER BY (t.status='requested') DESC, t.id DESC LIMIT 50`);
    res.json(r.rows.map(x => ({ ...x, amount: Number(x.amount) })));
  });

  app.post(`${P}/pesalink/:ref`, adminAuth, async (req, res) => {
    const action = String(req.body.action || "");
    const t = (await pool.query("SELECT * FROM tx WHERE ref=$1 AND kind='pesalink'", [req.params.ref])).rows[0];
    if (!t || t.status !== "requested") return res.status(400).json({ error: "Request already handled." });
    if (action === "paid") {
      await pool.query("UPDATE tx SET status='success' WHERE id=$1", [t.id]);
    } else if (action === "reject") {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query("UPDATE tx SET status='failed' WHERE id=$1", [t.id]);
        await client.query("UPDATE users SET winnings=winnings+$2 WHERE id=$1", [t.user_id, Number(t.amount)]);
        await client.query("COMMIT");
      } catch (e) { await client.query("ROLLBACK"); } finally { client.release(); }
    } else return res.status(400).json({ error: "Unknown action." });
    res.json({ ok: true });
  });

  app.post(`${P}/jackpot`, adminAuth, async (req, res) => {
    const cents = Math.floor(Number(req.body.pool));
    if (!(cents >= 0)) return res.status(400).json({ error: "Invalid amount." });
    await pool.query("UPDATE jackpot SET pool=$1 WHERE id=1", [cents]);
    res.json({ ok: true, pool: cents });
  });

  /* ----- transactions ----- */
  app.get(`${P}/tx`, adminAuth, async (_req, res) => {
    const r = await pool.query(`SELECT t.id, t.user_id, u.email, t.kind, t.amount, t.status, t.phone, t.created
      FROM tx t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC LIMIT 100`);
    res.json(r.rows.map(x => ({ ...x, amount: Number(x.amount) })));
  });

  /* ----- CSV export: every transaction for every player ----- */
  app.get(`${P}/tx/export`, adminAuth, async (_req, res) => {
    const r = await pool.query(`SELECT t.id, t.user_id, u.email, u.full_name, u.id_number, t.kind, t.amount, t.status, t.phone, t.ref, t.created
      FROM tx t JOIN users u ON u.id=t.user_id ORDER BY t.id`);
    const esc = v => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const rows = ["id,player_id,email,full_name,national_id,kind,amount_kes,status,phone,mpesa_ref,date"];
    for (const x of r.rows) {
      rows.push([x.id, x.user_id, esc(x.email), esc(x.full_name), esc(x.id_number), x.kind, (Number(x.amount) / 100).toFixed(2),
        x.status, esc(x.phone), esc(x.ref),
        new Date(Number(x.created)).toISOString()].join(","));
    }
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition",
      `attachment; filename="transactions-${new Date().toISOString().slice(0, 10)}.csv"`);
    res.send(rows.join("\r\n"));
  });

  /* ----- the panel itself (served only at the secret URL) ----- */
  app.get(`${P}/panel`, (_req, res) => {
    res.setHeader("X-Robots-Tag", "noindex, nofollow");
    let html = PANEL_HTML.replaceAll("__BASE__", P);
    if (TOTP_DISABLED) {
      // render the login form without the authenticator field at all
      html = html.replace(
        '<input id="code" inputmode="numeric" placeholder="Authenticator code" maxlength="6">',
        '<input id="code" type="hidden" value="">');
    }
    res.setHeader("Cache-Control", "no-store");   // never serve a stale panel
    res.type("html").send(html);
  });
};

const PANEL_HTML = `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Operator console</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
/* A treasury desk, not a dashboard. Money is right-aligned and tabular so
   columns compare at a glance; brass is spent only on live state and the one
   primary action in view; everything else is hairlines and quiet slate. */
:root{
  --ink:#101722; --panel:#18202d; --panel2:#1e2736; --panel3:#131b26;
  --line:#2a3545; --line2:#3a475c;
  --text:#e9eef6; --dim:#8b9ab0; --faint:#66748a;
  --brass:#d6a44c; --brass-d:#8a6821;
  --up:#3ac07a; --down:#ff6058; --warn:#e8a33d; --focus:#5b94ff;
  --sans:'IBM Plex Sans',ui-sans-serif,system-ui,-apple-system,'Segoe UI',sans-serif;
  --mono:'IBM Plex Mono',ui-monospace,'SF Mono',Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{font-family:var(--sans);background:var(--ink);color:var(--text);margin:0;
  font-size:14px;line-height:1.5;
  font-variant-numeric:tabular-nums;font-feature-settings:"tnum" 1}
.wrap{max-width:1320px;margin:0 auto;padding:0 20px 64px}

/* ---- top bar: brand, live state, sign out ---- */
.bar{position:sticky;top:0;z-index:20;background:rgba(16,23,34,.94);
  backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}
.bar-in{max-width:1320px;margin:0 auto;padding:12px 20px;
  display:flex;align-items:center;gap:14px}
.brand{display:flex;align-items:baseline;gap:10px;font-weight:600;font-size:15px;
  letter-spacing:-.01em;padding-left:11px;position:relative}
.brand::before{content:"";position:absolute;left:0;top:1px;bottom:1px;width:3px;
  background:var(--brass);border-radius:2px}
.brand span{color:var(--faint);font-weight:400;font-size:13px}
.bar .sp{flex:1}

/* ---- state pills ---- */
.badge{font-size:12px;padding:3px 10px;border-radius:4px;background:var(--panel2);
  border:1px solid var(--line2);color:var(--dim);white-space:nowrap}
.badge.live{background:rgba(58,192,122,.12);border-color:rgba(58,192,122,.45);color:var(--up)}
.badge.demo{background:rgba(214,164,76,.12);border-color:var(--brass-d);color:var(--brass)}
.badge.off{background:rgba(255,96,88,.12);border-color:rgba(255,96,88,.4);color:var(--down)}

/* ---- tab rail ---- */
.tabs{display:flex;gap:2px;overflow-x:auto;scrollbar-width:none;
  border-bottom:1px solid var(--line);margin:0 0 24px}
.tabs::-webkit-scrollbar{display:none}
.tabs button{background:none;border:0;border-bottom:2px solid transparent;
  color:var(--dim);font:inherit;font-size:13.5px;padding:11px 14px;cursor:pointer;
  white-space:nowrap;border-radius:0}
.tabs button:hover{color:var(--text)}
.tabs button[aria-selected=true]{color:var(--text);border-bottom-color:var(--brass)}
.tabs button .n{margin-left:6px;font-size:11px;color:var(--ink);background:var(--warn);
  padding:1px 5px;border-radius:999px;font-weight:600;display:none}
.tabs button .n.show{display:inline}
.page{display:none}.page.on{display:block}

/* ---- figure board: grouped by meaning, not ten identical tiles ---- */
.board{display:grid;gap:1px;background:var(--line);border:1px solid var(--line);
  grid-template-columns:repeat(auto-fit,minmax(248px,1fr));margin-bottom:26px}
.fg{background:var(--panel);padding:16px 18px 18px}
.fg h3{margin:0 0 12px;font-size:13px;font-weight:500;color:var(--dim)}
@media (min-width:1080px){.board{grid-template-columns:1.35fr 1fr 1fr 1fr}}
.lead dl.rows dt{white-space:nowrap}
.big{font-family:var(--sans);font-size:clamp(28px,4.4vw,38px);font-weight:600;
  letter-spacing:-.02em;margin:0 0 2px;line-height:1.05}
.big-sub{font-size:12.5px;color:var(--faint);margin:0 0 14px}
dl.rows{margin:0;display:grid;gap:7px}
dl.rows>div{display:flex;align-items:baseline;gap:10px;justify-content:space-between}
dl.rows dt{color:var(--dim);font-size:12.5px;margin:0;min-width:0}
dl.rows dd{margin:0;font-size:13.5px;font-weight:500;text-align:right;white-space:nowrap}
dl.rows>div.sum{border-top:1px solid var(--line2);padding-top:7px;margin-top:1px}
dl.rows>div.sum dt{color:var(--text)}
dl.rows>div.sum dd{font-size:15px;font-weight:600}
.lead dl.rows{grid-template-columns:1fr 1fr;gap:7px 18px}

/* ---- sections ---- */
section.blk{border:1px solid var(--line);background:var(--panel);margin-bottom:20px}
section.blk>header{padding:13px 18px;border-bottom:1px solid var(--line);
  display:flex;align-items:center;gap:12px;flex-wrap:wrap}
section.blk>header h2{margin:0;font-size:14.5px;font-weight:600;letter-spacing:-.01em}
section.blk>header .sp{flex:1}
.body{padding:16px 18px}
.note{color:var(--faint);font-size:12.5px;margin:12px 0 0;max-width:72ch}
.note b{color:var(--dim);font-weight:500}

/* ---- controls ---- */
.row{display:flex;gap:9px;flex-wrap:wrap;align-items:flex-end}
.row+.row{margin-top:12px}
label.f{display:flex;flex-direction:column;gap:5px;font-size:12.5px;color:var(--dim)}
button{background:var(--panel2);color:var(--text);border:1px solid var(--line2);
  border-radius:4px;padding:8px 14px;cursor:pointer;font:inherit;font-size:13px;
  transition:background .12s,border-color .12s}
button:hover{background:#263141;border-color:#4a5a73}
button.on{background:var(--brass);border-color:var(--brass);color:#2a1e05;font-weight:600}
button.on:hover{background:#e2b460;border-color:#e2b460}
button.danger{background:transparent;border-color:rgba(255,96,88,.5);color:var(--down)}
button.danger:hover{background:rgba(255,96,88,.12);border-color:var(--down)}
button.sm{padding:5px 10px;font-size:12px}
button.state{background:rgba(58,192,122,.1);border-color:rgba(58,192,122,.4);
  color:var(--up);cursor:default}
button.state:hover{background:rgba(58,192,122,.1);border-color:rgba(58,192,122,.4)}
/* a toggle that is currently on: reads as a state, still clickable */
button.live{background:rgba(58,192,122,.1);border-color:rgba(58,192,122,.45);color:var(--up)}
button.live:hover{background:rgba(58,192,122,.18);border-color:var(--up)}
button:disabled{opacity:.45;cursor:default}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
input,select{background:var(--panel3);color:var(--text);border:1px solid var(--line2);
  border-radius:4px;padding:8px 10px;width:100%;font:inherit;font-size:13px;
  font-variant-numeric:tabular-nums}
input:focus,select:focus{border-color:var(--focus);outline:none}
input[type=number]{font-family:var(--mono)}
.out{font-size:12.5px;color:var(--dim);align-self:center}

/* ---- tables: hairlines, sticky head, right-aligned money ---- */
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch;
  background:
    linear-gradient(to right,var(--panel),rgba(24,32,45,0)) left center,
    linear-gradient(to left,var(--panel),rgba(24,32,45,0)) right center,
    radial-gradient(farthest-side at 0 50%,rgba(0,0,0,.45),rgba(0,0,0,0)) left center,
    radial-gradient(farthest-side at 100% 50%,rgba(0,0,0,.45),rgba(0,0,0,0)) right center;
  background-repeat:no-repeat;
  background-size:34px 100%,34px 100%,13px 100%,13px 100%;
  background-attachment:local,local,scroll,scroll}
table{width:100%;border-collapse:collapse;font-size:13px;background:var(--panel)}
td,th{padding:9px 11px;text-align:left;white-space:nowrap;
  border-bottom:1px solid var(--line)}
th{color:var(--dim);font-size:12px;font-weight:500;background:var(--panel3);
  position:sticky;top:0;border-bottom:1px solid var(--line2)}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:rgba(255,255,255,.022)}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
td.ref{font-family:var(--mono);font-size:12px;color:var(--dim)}
td.trunc{max-width:210px;overflow:hidden;text-overflow:ellipsis}
.scroll{position:relative}
.pos{color:var(--up)}.neg{color:var(--down)}
.empty{padding:26px 18px;color:var(--faint);font-size:13px;text-align:center}

/* ---- status pills in tables ---- */
.st{font-size:11.5px;padding:2px 8px;border-radius:3px;border:1px solid var(--line2);
  background:var(--panel2);color:var(--dim)}
.st.ok{background:rgba(58,192,122,.12);border-color:rgba(58,192,122,.4);color:var(--up)}
.st.bad{background:rgba(255,96,88,.12);border-color:rgba(255,96,88,.4);color:var(--down)}
.st.wait{background:rgba(232,163,61,.12);border-color:var(--brass-d);color:var(--warn)}

/* ---- sign in ---- */
#login{max-width:368px;margin:11vh auto 0;padding:0 20px}
#login .box{border:1px solid var(--line);background:var(--panel);padding:26px 24px}
#login h1{margin:0 0 4px;font-size:19px;font-weight:600;letter-spacing:-.015em;
  padding-left:11px;position:relative}
#login h1::before{content:"";position:absolute;left:0;top:3px;bottom:3px;width:3px;
  background:var(--brass);border-radius:2px}
#login p.sub{margin:0 0 20px;color:var(--faint);font-size:13px;padding-left:11px}
#login label.f{margin-bottom:12px}
#login .box>button{width:100%}
.err{color:var(--down);font-size:12.5px;min-height:18px;margin:2px 0 8px}
.warn-box{font-size:12.5px;color:var(--warn);background:rgba(232,163,61,.09);
  border:1px solid var(--brass-d);border-radius:4px;padding:10px 12px;margin-bottom:14px}
.alert{font-size:13px;background:rgba(255,96,88,.1);border:1px solid rgba(255,96,88,.45);
  border-left:3px solid var(--down);padding:11px 14px;margin:16px 0 0}
.alert b{color:var(--text)}
pre#diagOut{display:none;white-space:pre-wrap;word-break:break-word;font-size:11.5px;
  font-family:var(--mono);background:var(--panel3);border:1px solid var(--line);
  border-radius:4px;padding:11px;margin-top:10px;max-height:260px;overflow:auto;color:var(--dim)}

@media (max-width:760px){
  .wrap{padding:0 12px 48px}
  .bar-in{padding:10px 12px;gap:8px}
  .brand{font-size:14px}.brand span{display:none}
  .board{grid-template-columns:1fr}
  .lead dl.rows{grid-template-columns:1fr 1fr}
  .body{padding:14px}
  section.blk>header{padding:12px 14px}
  input,select{font-size:16px}            /* stops iOS zooming on focus */
  .row>label.f{flex:1 1 44%;min-width:0}
  .row>button,.row>.out{flex:1 1 auto}
  /* each table row becomes its own block, with the header as a prefix */
  table.resp thead{display:none}
  table.resp tr{display:block;border:1px solid var(--line);
    margin-bottom:9px;padding:8px 11px;background:var(--panel3)}
  table.resp tr:hover{background:var(--panel3)}
  .scroll{background:none}
  table.resp td{display:flex;justify-content:space-between;gap:12px;
    border:0;padding:4px 0;white-space:normal;text-align:right}
  table.resp td.num{text-align:right}
  table.resp td::before{content:attr(data-l);color:var(--faint);font-size:12px;
    text-align:left;flex:0 0 42%}
  table.resp td:empty{display:none}
}
@media (prefers-reduced-motion:reduce){*{transition:none !important;animation:none !important}}
</style></head><body>
<div id="login">
  <div class="box">
    <h1>Operator console</h1>
    <p class="sub">Spin &middot; Kenya</p>
    <div id="clockWarn" class="warn-box" style="display:none"></div>
    <label class="f">Password
      <input id="pw" type="password" autocomplete="current-password"></label>
    <label class="f" id="codeField">Authenticator code
      <input id="code" inputmode="numeric" maxlength="6" autocomplete="one-time-code"></label>
    <div class="err" id="lerr"></div>
    <button class="on" id="loginBtn">Sign in</button>
    <button id="diagBtn" class="sm" style="width:100%;margin-top:9px">Run diagnostics</button>
    <pre id="diagOut"></pre>
  </div>
</div>
<div id="panel" style="display:none">
<div class="bar"><div class="bar-in">
  <div class="brand">Spin <span>Operator console</span></div>
  <span class="sp"></span>
  <span class="badge" id="modeBadge"></span>
  <span class="badge" id="wdBadge"></span>
  <button id="logoutBtn" class="sm">Sign out</button>
</div></div>

<div class="wrap">
  <div id="notices"></div>

  <nav class="tabs" id="tabs" role="tablist">
    <button role="tab" data-p="overview" aria-selected="true">Overview</button>
    <button role="tab" data-p="payouts">Payouts<span class="n" id="nPay"></span></button>
    <button role="tab" data-p="players">Players</button>
    <button role="tab" data-p="rate">Payout rate</button>
    <button role="tab" data-p="risk">Risk &amp; limits</button>
    <button role="tab" data-p="books">Books</button>
  </nav>

  <!-- ============ OVERVIEW ============ -->
  <div class="page on" id="p-overview">
    <div class="board">
      <article class="fg lead">
        <h3>Today</h3>
        <p class="big" id="fToday">&mdash;</p>
        <p class="big-sub" id="fTodaySub">&nbsp;</p>
        <dl class="rows">
          <div><dt>Spins</dt><dd id="fSpins">&mdash;</dd></div>
          <div><dt>Staked</dt><dd id="fStaked">&mdash;</dd></div>
          <div><dt>Paid out</dt><dd id="fPaid">&mdash;</dd></div>
          <div><dt>Margin</dt><dd id="fMargin">&mdash;</dd></div>
        </dl>
      </article>
      <article class="fg">
        <h3>Player funds you are holding</h3>
        <dl class="rows">
          <div><dt>Credit &mdash; can be staked</dt><dd id="fCredit">&mdash;</dd></div>
          <div><dt>Winnings &mdash; not yet moved</dt><dd id="fWinnings">&mdash;</dd></div>
          <div class="sum"><dt>Total you owe players</dt><dd id="fLiab">&mdash;</dd></div>
          <div><dt>Jackpot pool</dt><dd id="fJackpot">&mdash;</dd></div>
        </dl>
      </article>
      <article class="fg">
        <h3>Outstanding</h3>
        <dl class="rows">
          <div><dt>Withholding tax owed to KRA</dt><dd id="fWht">&mdash;</dd></div>
          <div><dt>M-Pesa payouts in flight</dt><dd id="fPend">&mdash;</dd></div>
          <div><dt>PesaLink requests</dt><dd id="fPl">&mdash;</dd></div>
          <div><dt>Marketing &amp; expenses</dt><dd id="fExp">&mdash;</dd></div>
        </dl>
      </article>
      <article class="fg">
        <h3>All time</h3>
        <dl class="rows">
          <div><dt>Registered players</dt><dd id="fPlayers">&mdash;</dd></div>
          <div><dt>Deposits in</dt><dd id="fDep">&mdash;</dd></div>
          <div><dt>Withdrawals out</dt><dd id="fWd">&mdash;</dd></div>
          <div class="sum"><dt>Cash held</dt><dd id="fCash">&mdash;</dd></div>
        </dl>
      </article>
    </div>

    <section class="blk">
      <header><h2>Profit per day</h2><span class="sp"></span>
        <span class="out">Live spins only &mdash; demo play is excluded</span></header>
      <div class="scroll"><table id="daily" class="resp"><thead><tr>
        <th>Date</th><th class="num">Spins</th><th class="num">Staked</th><th class="num">Paid out</th>
        <th class="num">Gross profit</th><th class="num">Marketing</th><th class="num">After spend</th>
        <th class="num">Margin</th></tr></thead><tbody></tbody></table></div>
    </section>
  </div>

  <!-- ============ PAYOUTS ============ -->
  <div class="page" id="p-payouts">
    <section class="blk">
      <header><h2>M-Pesa payouts</h2></header>
      <div class="scroll"><table id="payouts" class="resp"><thead><tr>
        <th>Ref</th><th>Player</th><th>Phone</th><th class="num">Amount</th>
        <th>Status</th><th>When</th><th></th>
      </tr></thead><tbody></tbody></table></div>
      <div class="body" style="border-top:1px solid var(--line)">
        <p class="note" style="margin:0"><b>Pending</b> means M-Pesa accepted the payout but
        Safaricom has not confirmed delivery yet. <b>Mark paid</b> if you settled it by hand,
        <b>Retry</b> to send again, or <b>Refund</b> to return the money to the player's wallet.
        A payout that failed because the B2C float was empty can simply be retried once the
        paybill is topped up.</p>
      </div>
    </section>

    <section class="blk">
      <header><h2>PesaLink requests</h2><span class="sp"></span>
        <span class="out">Pay from your bank, then mark paid</span></header>
      <div class="scroll"><table id="pl" class="resp"><thead><tr>
        <th>Ref</th><th>Player</th><th>Nat. ID</th><th class="num">Amount</th>
        <th>Bank</th><th>Account</th><th>Status</th><th></th>
      </tr></thead><tbody></tbody></table></div>
    </section>
  </div>

  <!-- ============ PLAYERS ============ -->
  <div class="page" id="p-players">
    <section class="blk">
      <header><h2>Players</h2><span class="sp"></span>
        <span style="display:flex;gap:8px;min-width:240px;flex:1;max-width:380px">
          <input id="q" placeholder="Name, email, phone or ID number">
          <button id="searchBtn">Search</button></span></header>
      <div class="scroll"><table id="players" class="resp"><thead><tr>
        <th>ID</th><th>Name</th><th>Nat. ID</th><th>Email</th><th>Phone</th>
        <th class="num">Credit</th><th class="num">Winnings</th><th class="num">Deposited</th>
        <th class="num">Withdrawn</th><th class="num">Net lost</th><th></th>
      </tr></thead><tbody></tbody></table></div>
      <div class="body" style="border-top:1px solid var(--line)">
        <p class="note" style="margin:0"><b>Credit</b> is what the player can stake.
        <b>Winnings</b> is what they have won and not yet moved across &mdash; you owe both.
        <b>Net lost</b> is stakes minus payouts: positive is your gross win from that player.</p>
      </div>
    </section>
  </div>

  <!-- ============ PAYOUT RATE ============ -->
  <div class="page" id="p-rate">
    <section class="blk">
      <header><h2>Payout rate</h2><span class="sp"></span>
        <span class="out" id="rtpMargin"></span></header>
      <div class="body">
        <div class="row">
          <label class="f" style="max-width:150px">Player payout (RTP) %
            <input id="rtpInput" type="number" step="0.5" min="8" max="90"></label>
          <button id="rtpSave" class="on">Apply</button>
          <button id="auditBtn">Change log</button>
        </div>
        <div class="row">
          <label class="f" style="max-width:210px">…or target net profit after tax %
            <input id="netTarget" type="number" step="0.5"></label>
          <button id="netSolve">Calculate</button>
          <button id="netApply">Calculate &amp; apply</button>
          <span id="netOut" class="out"></span>
        </div>
        <p class="note">Takes effect on the next spin. All bet types stay at the same RTP, so no
        symbol is a better deal than another. Every change is timestamped in the change log &mdash;
        BCLB audits declared payout rates, so keep this matching your licence.</p>
        <div class="scroll" id="auditWrap" style="display:none;margin-top:14px;border:1px solid var(--line)">
          <table id="audit" class="resp"><thead><tr>
            <th>When</th><th>Setting</th><th>From</th><th>To</th>
          </tr></thead><tbody></tbody></table></div>
      </div>
    </section>

    <section class="blk">
      <header><h2>Where KSh 100 of stakes goes</h2></header>
      <div class="body" id="marginCalc"></div>
    </section>
  </div>

  <!-- ============ RISK & LIMITS ============ -->
  <div class="page" id="p-risk">
    <section class="blk">
      <header><h2>Trading switches</h2></header>
      <div class="body">
        <div class="row">
          <button id="btnMode"></button>
          <button id="btnWd"></button>
        </div>
        <p class="note">Pausing withdrawals stops payouts only &mdash; deposits and play continue
        and every balance is safe. Demo mode pauses all real money: players get free credits and
        deposit and withdraw are hidden from them.</p>
      </div>
    </section>

    <section class="blk">
      <header><h2>Deposit limits</h2></header>
      <div class="body">
        <div class="row">
          <label class="f" style="max-width:150px">Minimum KSh
            <input id="minDep" type="number" min="1"></label>
          <label class="f" style="max-width:150px">Maximum KSh
            <input id="maxDep" type="number" min="1"></label>
          <button id="depSave" class="on">Save limits</button>
          <span id="depOut" class="out"></span>
        </div>
      </div>
    </section>

    <section class="blk">
      <header><h2>Jackpot pool</h2></header>
      <div class="body">
        <div class="row">
          <label class="f" style="max-width:170px">Set pool to KSh
            <input id="jp" type="number"></label>
          <button id="jpBtn">Set jackpot</button>
        </div>
        <p class="note">The pool grows on its own from a slice of every live stake. Set it by hand
        only to seed a launch figure or to correct an error.</p>
      </div>
    </section>
  </div>

  <!-- ============ BOOKS ============ -->
  <div class="page" id="p-books">
    <section class="blk">
      <header><h2>Tax rates</h2><span class="sp"></span><button id="btnWht"></button></header>
      <div class="body">
        <div class="row">
          <label class="f" style="max-width:130px">Withholding %
            <input id="whtRate" type="number" step="0.5"></label>
          <label class="f" style="max-width:150px">Excise % of stakes
            <input id="exRate" type="number" step="0.5"></label>
          <label class="f" style="max-width:160px">Betting tax % of GGR
            <input id="btRate" type="number" step="0.5"></label>
          <label class="f" style="max-width:130px">Corporate %
            <input id="ctRate" type="number" step="0.5"></label>
          <button id="taxSave" class="on">Save rates</button>
        </div>
        <p class="note">Withholding tax is deducted from the player's winnings and remitted to
        KRA &mdash; it is never your revenue. Rates change; confirm the current figures with your
        accountant. Turning withholding off while the law requires it is tax evasion.</p>
      </div>
    </section>

    <section class="blk">
      <header><h2>Marketing &amp; expenses</h2></header>
      <div class="body">
        <div class="row">
          <label class="f" style="max-width:170px">Category
            <select id="expCat">
              <option value="marketing">Marketing</option>
              <option value="bonuses">Player bonuses</option>
              <option value="hosting">Hosting / tech</option>
              <option value="licensing">Licensing / legal</option>
              <option value="other">Other</option>
            </select></label>
          <label class="f" style="max-width:140px">Amount KSh
            <input id="expAmt" type="number"></label>
          <label class="f" style="flex:1;min-width:180px">Note
            <input id="expNote" placeholder="e.g. Facebook campaign"></label>
          <button id="expAdd" class="on">Record spend</button>
        </div>
      </div>
      <div class="scroll" style="border-top:1px solid var(--line)">
        <table id="exp" class="resp"><thead><tr>
          <th>Date</th><th>Category</th><th class="num">Amount</th><th>Note</th><th></th>
        </tr></thead><tbody></tbody></table></div>
    </section>

    <section class="blk">
      <header><h2>Transactions</h2><span class="sp"></span>
        <button id="exportBtn">Download all (CSV)</button></header>
      <div class="scroll"><table id="tx" class="resp"><thead><tr>
        <th>ID</th><th>Player</th><th>Kind</th><th class="num">Amount</th>
        <th>Status</th><th>Phone</th><th>When</th>
      </tr></thead><tbody></tbody></table></div>
    </section>
  </div>
</div>
</div>
<script>
/* Nothing should ever fail invisibly on this screen. */
window.addEventListener("error", function(ev){ showFatal(ev.message + (ev.filename?" ("+ev.lineno+")":"")); });
window.addEventListener("unhandledrejection", function(ev){
  showFatal("Unhandled: " + ((ev.reason && ev.reason.message) || ev.reason));
});
function showFatal(msg){
  var box = document.getElementById("lerr");
  if(box){ box.textContent = "Script error: " + msg; }
}
const B="__BASE__"; let T=sessionStorage.getItem("adm")||null; let S={};
const K=c=>"KSh "+(c/100).toLocaleString("en-KE");
/* One vocabulary for status everywhere: green settled, red failed, amber in
   flight. Reading a queue should not mean reading each word. */
const ST=function(st){
  var s=String(st||"").toLowerCase();
  var c=(s==="success"||s==="paid")?"ok"
       :(s==="failed"||s==="rejected"||s==="refunded")?"bad"
       :(s==="pending"||s==="sending"||s==="requested"||s==="review")?"wait":"";
  return '<span class="st '+c+'">'+st+"</span>";
};
const EMPTY=function(cols,msg){
  return '<tr><td colspan="'+cols+'" class="empty">'+msg+"</td></tr>";
};
const api=async(p,b)=>{
  const ctrl=new AbortController();
  const timer=setTimeout(()=>ctrl.abort(),20000);   // never sit silent forever
  let r;
  try{
    r=await fetch(B+p,{method:b?"POST":"GET",
      headers:{"Content-Type":"application/json",Authorization:"Bearer "+T},
      body:b?JSON.stringify(b):undefined, signal:ctrl.signal});
  }catch(err){
    clearTimeout(timer);
    throw new Error(err.name==="AbortError"
      ? "The server did not respond in 20s. It may be starting up \u2014 try again."
      : "Network error: could not reach the server.");
  }
  clearTimeout(timer);
  const text=await r.text();
  let d=null; try{ d=text?JSON.parse(text):null; }catch(e){ d=null; }
  if(!r.ok){
    if(r.status===401){ logout("Your session expired. Please sign in again."); throw new Error("Session expired."); }
    if(d&&d.error) throw new Error(d.error);
    if(r.status===404) throw new Error("404 \u2014 admin path not found. Check ADMIN_PATH matches the URL.");
    throw new Error("Server returned "+r.status+(text?" \u2014 "+text.slice(0,120):""));
  }
  if(d===null) throw new Error("Unexpected response from server (not JSON).");
  return d;
};

async function login(){
  const btn=document.getElementById("loginBtn"), err=document.getElementById("lerr");
  btn.disabled=true; btn.textContent="Signing in\u2026"; err.textContent="";
  try{
    const d=await api("/login",{password:document.getElementById("pw").value,
      code:document.getElementById("code").value});
    T=d.token;sessionStorage.setItem("adm",T);show();
  }catch(e){
    err.textContent=e.message||"Login failed (no details returned).";
    checkClock();                       // a wrong-looking code is often clock drift
    document.getElementById("code").value="";
  }finally{
    btn.disabled=false; btn.textContent="Sign in";
  }
}

/* If this device's clock is off, authenticator codes fail even when they look
 * right on screen. Compare against the server and say so plainly. */
/* Ask the server whether 2FA is currently bypassed, and reflect that in the UI
   so the state is never a surprise. */
async function checkMode(){
  try{
    const r=await fetch(B+"/time").then(x=>x.json());
    if(r.totp_disabled){
      // hide the whole field, not just the box, or the label is left dangling
      var cf=document.getElementById("codeField");
      if(cf) cf.style.display="none"; else document.getElementById("code").style.display="none";
      const w=document.getElementById("clockWarn");
      w.innerHTML="<b>Two-factor authentication is OFF.</b> This console is protected by the "+
        "password and secret URL only. Set a new ADMIN_TOTP_SECRET, add it to your authenticator, "+
        "then remove ADMIN_TOTP_DISABLED.";
      w.style.display="block";
    }
  }catch(e){}
}

async function checkClock(){
  try{
    const r=await fetch(B+"/time").then(x=>x.json());
    if(r.totp_disabled) return;          // no code required, so drift is irrelevant
    const skew=Math.abs(Date.now()-r.epoch_ms)/1000;
    if(skew>20){
      document.getElementById("clockWarn").innerHTML=
        "This device's clock is off by about "+Math.round(skew)+
        " seconds. Authenticator codes are time-based \u2014 enable automatic date &amp; time on the phone generating the code, then try again.";
      document.getElementById("clockWarn").style.display="block";
    }
  }catch(e){}
}

/* Return cleanly to the login form. Without this an expired session left the
   panel on screen with dead data and no way back except a fresh browser. */
function logout(msg){
  T = null;
  try{ sessionStorage.removeItem("adm"); }catch(e){}
  if(refreshTimer){ clearInterval(refreshTimer); refreshTimer = null; }
  const panel = document.getElementById("panel");
  panel.style.display = "none";
  // drop any stale rows so nothing from the old session lingers
  ["daily","players","tx","exp","pl","audit"].forEach(function(id){
    const t = document.getElementById(id);
    if(t && t.tBodies && t.tBodies[0]) t.tBodies[0].innerHTML = "";
  });
  ["fToday","fTodaySub","fSpins","fStaked","fPaid","fMargin","fCredit","fWinnings",
   "fLiab","fJackpot","fWht","fPend","fPl","fExp","fPlayers","fDep","fWd","fCash"]
    .forEach(function(id){ var e=document.getElementById(id); if(e) e.textContent="—"; });
  const nt = document.getElementById("notices"); if(nt) nt.innerHTML = "";
  document.getElementById("login").style.display = "block";
  document.getElementById("lerr").textContent = msg || "";
  document.getElementById("pw").value = "";
  const c = document.getElementById("code"); if(c) c.value = "";
}

let refreshTimer = null;

async function show(){
  document.getElementById("login").style.display="none";
  document.getElementById("panel").style.display="block";
  try{
    const t=await fetch(B+"/time").then(x=>x.json());
    if(t.totp_disabled){
      const b=document.createElement("div");
      b.className="alert";
      b.innerHTML="<b>Two-factor authentication is off.</b> This console is protected by the "+
        "secret URL and the password alone. Sessions last 15 minutes. Set ADMIN_TOTP_SECRET "+
        "again and delete ADMIN_TOTP_DISABLED to turn it back on.";
      document.getElementById("notices").appendChild(b);
    }
  }catch(e){}
  await refresh();
  await Promise.all([loadPlayers(),loadTx(),loadPesalink(),loadExpenses(),loadPayouts()]);
  labelAll();
}

async function refresh(){
  const s=await api("/stats");S=s.settings;
  const today=s.daily[0]||{staked:0,paid:0,profit:0,spins:0};
  /* The board is grouped by what each figure means to you, so the numbers that
     belong together are read together — in particular credit + winnings, which
     are both money you owe and which used to be collapsed into one total. */
  var put=function(id,v,cls){
    var el=document.getElementById(id); if(!el) return;
    el.textContent=v; el.className=cls||"";
  };
  var sign=function(c){ return c>=0?"pos":"neg"; };
  put("fToday",K(today.profit),"big "+sign(today.profit));
  document.getElementById("fTodaySub").textContent =
    today.spins ? (today.profit>=0?"ahead on ":"behind on ")+today.spins+
      (today.spins===1?" live spin":" live spins")
    : "no live spins yet today";
  put("fSpins",today.spins);
  put("fStaked",K(today.staked));
  put("fPaid",K(today.paid));
  put("fMargin",today.staked?Math.round(100*today.profit/today.staked)+"%":"—",
      today.staked?sign(today.profit):"");

  put("fCredit",K(s.player_credit!=null?s.player_credit:s.player_balances));
  put("fWinnings",K(s.player_winnings||0));
  put("fLiab",K(s.player_balances));
  put("fJackpot",K(s.jackpot_pool));

  put("fWht",K(s.wht_collected));
  put("fPend",s.pending_withdrawals.count+" · "+K(s.pending_withdrawals.total),
      s.pending_withdrawals.count?"neg":"");
  put("fPl",s.pesalink_pending.count+" · "+K(s.pesalink_pending.total),
      s.pesalink_pending.count?"neg":"");
  put("fExp",K(s.expenses_total));

  put("fPlayers",s.players);
  put("fDep",K(s.deposits.total));
  put("fWd",K(s.withdrawals.total));
  put("fCash",K(s.deposits.total-s.withdrawals.total));

  var pendN=s.pending_withdrawals.count+s.pesalink_pending.count;
  var nPay=document.getElementById("nPay");
  if(nPay){ nPay.textContent=pendN; nPay.className="n"+(pendN?" show":""); }

  document.getElementById("daily").tBodies[0].innerHTML=s.daily.length?s.daily.map(function(d){
    return "<tr><td>"+d.date+'</td><td class="num">'+d.spins+'</td><td class="num">'+K(d.staked)+
      '</td><td class="num">'+K(d.paid)+
      '</td><td class="num '+sign(d.profit)+'">'+K(d.profit)+"</td>"+
      '<td class="num">'+(d.marketing?K(d.marketing):"—")+"</td>"+
      '<td class="num '+sign(d.net)+'">'+K(d.net)+'</td><td class="num">'+
      (d.staked?Math.round(100*d.profit/d.staked)+"%":"—")+"</td></tr>";
  }).join(""):'<tr><td colspan="8" class="empty">No live spins recorded yet.</td></tr>';

  document.getElementById("modeBadge").textContent=S.live_mode?"LIVE":"DEMO";
  document.getElementById("modeBadge").className="badge "+(S.live_mode?"live":"demo");
  var wb=document.getElementById("wdBadge");
  wb.textContent=S.withdrawals_enabled?"Withdrawals on":"Withdrawals paused";
  wb.className="badge"+(S.withdrawals_enabled?"":" off");
  var btnMode=document.getElementById("btnMode");
  btnMode.textContent=S.live_mode?"Switch to DEMO mode":"Switch to LIVE mode";
  btnMode.className=S.live_mode?"":"on";
  var btnWd=document.getElementById("btnWd");
  btnWd.textContent=S.withdrawals_enabled?"Pause withdrawals":"Resume withdrawals";
  btnWd.className=S.withdrawals_enabled?"danger":"on";

  var btnWht=document.getElementById("btnWht");
  btnWht.textContent=S.wht_enabled?"Withholding is on":"Withholding is off";
  btnWht.className=S.wht_enabled?"live":"danger";
  var mn=document.getElementById("minDep"), mx=document.getElementById("maxDep");
  if(document.activeElement!==mn) mn.value=S.min_deposit;
  if(document.activeElement!==mx) mx.value=S.max_deposit;
  document.getElementById("whtRate").value=S.wht_rate;
  document.getElementById("exRate").value=S.excise_rate;
  document.getElementById("btRate").value=S.betting_tax_rate;
  document.getElementById("ctRate").value=S.corp_tax_rate;
  var rtpEl=document.getElementById("rtpInput");
  if(document.activeElement!==rtpEl) rtpEl.value=S.target_rtp;
  var netEl=document.getElementById("netTarget");
  if(document.activeElement!==netEl) netEl.value=S.target_net;
  /* Gross margin alone is not the signal: excise is charged on stakes, so a
     positive gross margin can still be a net loss. Colour follows the net. */
  var hm=100-Number(S.target_rtp);
  var preTax=hm-(Number(S.excise_rate)||0)-(Number(S.betting_tax_rate)||0)*hm/100;
  document.getElementById("rtpMargin").innerHTML=
    "House margin <b class='"+(preTax>0?"pos":"neg")+"'>"+hm.toFixed(1)+"%</b>"+
    (preTax<=0?" <span class='neg'>&mdash; a net loss after tax</span>":"");
  drawMargin(s);
}


function drawMargin(s){
  var ex=Number(S.excise_rate)||0, bt=Number(S.betting_tax_rate)||0, ct=Number(S.corp_tax_rate)||0;
  var ggr=100-Number(S.target_rtp);
  var exAmt=ex;                 // per KSh 100 staked, excise is charged on the stake
  var btAmt=bt*ggr/100;
  var pre=ggr-exAmt-btAmt;
  /* A loss owes no corporate tax. Treating it as a credit flattered the net
     figure and made a loss-making payout rate look less bad than it is. */
  var ctAmt=pre>0?pre*ct/100:0;
  var net=pre-ctAmt;
  var realised=s.daily[0]&&s.daily[0].staked?Math.round(100*s.daily[0].profit/s.daily[0].staked):null;
  /* A waterfall down to net, so it is obvious which line is eating the margin. */
  var line=function(label,amount,cls){
    return '<div><dt>'+label+'</dt><dd class="'+(cls||"")+'">KSh '+amount.toFixed(2)+'</dd></div>';
  };
  document.getElementById("marginCalc").innerHTML=
    '<dl class="rows" style="max-width:460px">'+
    line("Gross gaming revenue at "+ggr.toFixed(1)+"% margin",ggr,ggr>=0?"":"neg")+
    line("Excise on stakes ("+ex+"%)",-exAmt)+
    line("Betting tax ("+bt+"% of gross)",-btAmt)+
    '<div class="sum"><dt>Pre-tax profit</dt><dd class="'+(pre>=0?"pos":"neg")+
      '">KSh '+pre.toFixed(2)+'</dd></div>'+
    line("Corporate tax ("+ct+"%)",-ctAmt)+
    '<div class="sum"><dt>Net profit per KSh 100 staked</dt><dd class="'+(net>=0?"pos":"neg")+
      '">KSh '+net.toFixed(2)+' &middot; '+net.toFixed(1)+'%</dd></div>'+
    '</dl>'+
    (realised!==null?'<p class="note">Realised gross margin on the most recent trading day: <b>'+
      realised+'%</b>. A figure far from the '+ggr.toFixed(1)+
      '% target just means too few spins have been played to average out yet.</p>':"")+
    (net<0?'<p class="note" style="color:var(--down)">At this payout rate you lose money on '+
      'every stake. Raise the house margin on the payout rate tab.</p>':"");
}

async function saveTax(){
  await api("/settings",{
    wht_rate:Number(document.getElementById("whtRate").value),
    excise_rate:Number(document.getElementById("exRate").value),
    betting_tax_rate:Number(document.getElementById("btRate").value),
    corp_tax_rate:Number(document.getElementById("ctRate").value)});
  refresh();
}

async function saveRtp(){
  var v=Number(document.getElementById("rtpInput").value);
  if(!(v>=8&&v<=90)){alert("Payout rate must be between 8% and 90%.");return}
  if(!confirm("Set player payout to "+v+"% (house margin "+(100-v).toFixed(1)+"%)?\\n\\nThis changes the odds from the next spin and is recorded in the change log."))return;
  await api("/settings",{target_rtp:v});refresh();loadAudit();
}
async function solveMargin(apply){
  try{
    var d=await api("/solve-margin",{target_net:Number(document.getElementById("netTarget").value),apply:!!apply});
    document.getElementById("netOut").innerHTML=
      "needs <b>"+d.ggr.toFixed(1)+"%</b> house margin \u2192 payout <b>"+d.rtp.toFixed(1)+"%</b>"+
      (apply?" <span class='pos'>applied</span>":"");
    if(apply){ refresh(); loadAudit(); }
  }catch(e){ document.getElementById("netOut").innerHTML="<span class='neg'>"+e.message+"</span>"; }
}
async function loadAudit(){
  var a=await api("/audit");
  document.getElementById("audit").tBodies[0].innerHTML=a.map(function(x){
    return "<tr><td>"+new Date(Number(x.created)).toLocaleString()+"</td><td>"+x.key+
      "</td><td>"+(x.old_value===null?"—":x.old_value)+"</td><td>"+x.new_value+"</td></tr>";
  }).join("") || EMPTY(4,"No changes recorded yet.");
}
async function loadExpenses(){
  var e=await api("/expenses");
  document.getElementById("exp").tBodies[0].innerHTML=e.rows.map(function(x){
    return "<tr><td>"+new Date(Number(x.created)).toLocaleDateString()+"</td><td>"+x.category+
      '</td><td class="num">'+K(x.amount)+"</td><td>"+(x.note||"")+
      '</td><td><button class="expdel sm" data-id="'+x.id+'">Delete</button></td></tr>';
  }).join("") || EMPTY(5,"No spend recorded yet.");
  labelCells("exp");
  document.querySelectorAll(".expdel").forEach(function(b){
    b.onclick=async function(){ if(!confirm("Delete this entry?"))return;
      await api("/expenses/"+b.dataset.id+"/delete",{});loadExpenses();refresh(); };
  });
}
async function addExpense(){
  var amt=Number(document.getElementById("expAmt").value);
  if(!(amt>0)){alert("Enter an amount.");return}
  await api("/expenses",{amount:amt,category:document.getElementById("expCat").value,
    note:document.getElementById("expNote").value});
  document.getElementById("expAmt").value="";document.getElementById("expNote").value="";
  loadExpenses();refresh();
}
/* On phones each row becomes a card, and every cell shows its column name.
   Deriving the labels from <thead> keeps them correct for every table. */
function labelCells(id){
  var t=document.getElementById(id); if(!t) return;
  var hs=[].map.call(t.tHead.rows[0].cells, function(th){ return th.textContent.trim(); });
  [].forEach.call(t.tBodies[0].rows, function(tr){
    [].forEach.call(tr.cells, function(td,i){
      // an empty-state row spans every column; a header prefix would be nonsense
      if(td.classList.contains("empty")) return;
      if(!td.dataset.l) td.dataset.l = hs[i]||"";
    });
  });
}
function labelAll(){ ["daily","players","tx","exp","pl","audit","payouts"].forEach(labelCells); }

async function loadPayouts(){
  var p=await api("/payouts");
  document.getElementById("payouts").tBodies[0].innerHTML=p.map(function(x){
    var act = x.status==="success" ? "" :
      '<button class="pobtn sm on" data-ref="'+x.ref+'" data-a="paid">Mark paid</button> '+
      '<button class="pobtn sm" data-ref="'+x.ref+'" data-a="retry">Retry</button> '+
      '<button class="pobtn sm danger" data-ref="'+x.ref+'" data-a="refund">Refund</button>';
    return "<tr>"+
      '<td data-l="Ref">'+x.ref.slice(0,10)+"</td>"+
      '<td data-l="Player">'+(x.full_name||"\u2014")+"</td>"+
      '<td data-l="Phone">'+(x.phone?"0"+String(x.phone).slice(3):"\u2014")+"</td>"+
      '<td data-l="Amount" class="num">'+K(x.amount)+"</td>"+
      '<td data-l="Status">'+ST(x.status)+"</td>"+
      '<td data-l="When">'+new Date(Number(x.created)).toLocaleString()+"</td>"+
      '<td data-l="">'+act+"</td></tr>";
  }).join("") || EMPTY(7,"No payouts yet.");
  labelCells("payouts");
  document.querySelectorAll(".pobtn").forEach(function(b){
    b.onclick=async function(){
      var a=b.dataset.a;
      var msg = a==="refund" ? "Refund this payout to the player?"
        : a==="retry" ? "Send this payout again?"
        : "Mark this payout as paid? Only do this if the money really reached them.";
      if(!confirm(msg)) return;
      b.disabled=true;
      try{ var r=await api("/payouts/"+b.dataset.ref,{action:a}); alert(r.message||"Done"); }
      catch(e){ alert(e.message); }
      b.disabled=false; await loadPayouts(); refresh().then(labelAll);
    };
  });
}
async function loadPesalink(){
  var p=await api("/pesalink");
  document.getElementById("pl").tBodies[0].innerHTML=p.map(function(x){
    var act=x.status==="requested"
      ? '<button class="plbtn on" data-ref="'+x.ref+'" data-a="paid">Mark paid</button> '+
        '<button class="plbtn danger" data-ref="'+x.ref+'" data-a="reject">Reject &amp; refund</button>'
      : "";
    return '<tr><td class="ref">'+x.ref.slice(0,10)+"</td><td>"+(x.full_name||"—")+"</td><td>"+(x.id_number||"—")+
      '</td><td class="num">'+K(x.amount)+"</td><td>"+(x.bank||"")+"</td><td>"+(x.account||"")+
      "</td><td>"+ST(x.status)+"</td><td>"+act+"</td></tr>";
  }).join("") || EMPTY(8,"No PesaLink requests. Payouts above KSh 70,000 arrive here.");
  labelCells("pl");
  document.querySelectorAll(".plbtn").forEach(function(b){
    b.onclick=async function(){
      if(b.dataset.a==="reject"&&!confirm("Reject and refund this request?"))return;
      await api("/pesalink/"+b.dataset.ref,{action:b.dataset.a});
      loadPesalink();refresh();
    };
  });
}

async function toggle(k){
  if(k==="live_mode"&&!confirm(S.live_mode?"Switch everyone to DEMO (free) mode?":"Go LIVE with real money?"))return;
  if(k==="withdrawals_enabled"&&S.withdrawals_enabled&&!confirm("Pause all withdrawals?"))return;
  var body={};body[k]=!S[k];
  await api("/settings",body);refresh();
}

async function setJackpot(){
  var jp=document.getElementById("jp");
  await api("/jackpot",{pool:Number(jp.value)*100});jp.value="";refresh();
}

async function loadPlayers(){
  var q=document.getElementById("q").value||"";
  var p=await api("/players?q="+encodeURIComponent(q));
  document.getElementById("players").tBodies[0].innerHTML=p.map(function(u){
    return "<tr><td>"+u.id+"</td><td>"+(u.full_name||"—")+"</td>"+
      "<td>"+(u.id_number||"—")+' <button class="idvbtn sm'+(u.id_verified?" state":"")+'" data-id="'+u.id+'" data-v="'+(!u.id_verified)+'">'+(u.id_verified?"ID \u2713":"Mark verified")+"</button></td>"+
      '<td class="trunc" title="'+u.email+'">'+u.email+"</td><td>"+(u.phone?"0"+u.phone.slice(3):"—")+
      (u.phone_verified?' <span class="st ok">verified</span>':' <span class="st">unverified</span>')+"</td>"+
      /* both pots: winnings are money you owe just as much as credit is, and
         leaving this column out is what made credited wins look missing */
      '<td class="num">'+K(u.balance)+'</td>'+
      '<td class="num'+(u.winnings>0?" pos":"")+'">'+K(u.winnings||0)+'</td>'+
      '<td class="num">'+K(u.deposited)+'</td><td class="num">'+K(u.withdrawn)+"</td>"+
      '<td class="num '+(u.net_lost>=0?"pos":"neg")+'">'+K(u.net_lost)+"</td>"+
      '<td><button class="suspbtn sm'+(u.suspended?" danger":"")+'" data-id="'+u.id+'" data-v="'+(!u.suspended)+'">'+(u.suspended?"Unsuspend":"Suspend")+"</button></td></tr>";
  }).join("") || '<tr><td colspan="11" class="empty">No players match that search.</td></tr>';
  labelCells("players");
  document.querySelectorAll(".idvbtn").forEach(function(b){
    b.onclick=function(){idv(Number(b.dataset.id), b.dataset.v==="true");};
  });
  document.querySelectorAll(".suspbtn").forEach(function(b){
    b.onclick=function(){susp(Number(b.dataset.id), b.dataset.v==="true");};
  });
}

async function susp(id,v){await api("/players/"+id+"/suspend",{suspended:v});loadPlayers();}
async function idv(id,v){await api("/players/"+id+"/idverify",{verified:v});loadPlayers();}

async function exportTx(){
  const r=await fetch(B+"/tx/export",{headers:{Authorization:"Bearer "+T}});
  if(!r.ok){alert("Export failed — log in again.");return}
  const blob=await r.blob();const a=document.createElement("a");
  a.href=URL.createObjectURL(blob);
  a.download="transactions-"+new Date().toISOString().slice(0,10)+".csv";
  a.click();URL.revokeObjectURL(a.href);
}

async function loadTx(){
  const t=await api("/tx");
  document.getElementById("tx").tBodies[0].innerHTML=t.map(function(x){
    return "<tr><td>"+x.id+'</td><td class="trunc" title="'+x.email+'">'+x.email+"</td><td>"+x.kind+
      '</td><td class="num">'+K(x.amount)+"</td><td>"+ST(x.status)+"</td><td>"+(x.phone||"")+
      "</td><td>"+new Date(Number(x.created)).toLocaleString()+"</td></tr>";
  }).join("") || EMPTY(7,"No transactions yet.");
}

checkMode();
document.getElementById("loginBtn").onclick=login;
document.getElementById("logoutBtn").onclick=function(){ logout("Signed out."); };
document.getElementById("diagBtn").onclick=async function(){
  var out=document.getElementById("diagOut");
  out.style.display="block"; out.textContent="Checking\u2026";
  try{
    var r=await fetch(B+"/diag");
    var txt=await r.text();
    try{
      var d=JSON.parse(txt);
      out.textContent = "VERDICT: " + d.verdict + "\\n\\n" + JSON.stringify(d,null,2);
    }catch(e){
      out.textContent = "Server returned non-JSON (HTTP "+r.status+"):\\n\\n"+txt.slice(0,600);
    }
  }catch(e){
    out.textContent = "Could not reach the server: " + e.message +
      "\\n\\nCheck the admin path in the URL matches ADMIN_PATH exactly.";
  }
};
["pw","code"].forEach(function(id){
  document.getElementById(id).addEventListener("keydown",function(e){ if(e.key==="Enter") login(); });
});
document.getElementById("btnMode").onclick=function(){toggle("live_mode")};
document.getElementById("btnWd").onclick=function(){toggle("withdrawals_enabled")};
document.getElementById("btnWht").onclick=function(){
  if(S.wht_enabled&&!confirm("Stop deducting withholding tax?\\n\\nOnly do this if the law no longer requires it — withholding when required is a legal obligation."))return;
  api("/settings",{wht_enabled:!S.wht_enabled}).then(refresh);
};
document.getElementById("taxSave").onclick=saveTax;
document.getElementById("depSave").onclick=async function(){
  var mn=Number(document.getElementById("minDep").value);
  var mx=Number(document.getElementById("maxDep").value);
  if(!(mn>0)||!(mx>mn)){ document.getElementById("depOut").textContent="Max must be above min."; return; }
  try{ await api("/settings",{min_deposit:mn,max_deposit:mx});
    document.getElementById("depOut").textContent="Saved."; refresh();
  }catch(e){ document.getElementById("depOut").textContent=e.message; }
};

document.getElementById("rtpSave").onclick=saveRtp;
document.getElementById("netSolve").onclick=function(){solveMargin(false)};
document.getElementById("netApply").onclick=function(){
  if(!confirm("Set the payout rate to hit this net profit target?\\n\\nThis changes the odds from the next spin and is recorded in the change log."))return;
  solveMargin(true);
};
document.getElementById("expAdd").onclick=addExpense;
document.getElementById("auditBtn").onclick=function(){
  var w=document.getElementById("auditWrap");
  if(w.style.display==="none"){w.style.display="block";loadAudit();}else{w.style.display="none";}
};
document.getElementById("jpBtn").onclick=setJackpot;
document.getElementById("searchBtn").onclick=loadPlayers;
document.getElementById("q").addEventListener("keydown",function(e){if(e.key==="Enter")loadPlayers();});
document.getElementById("exportBtn").onclick=exportTx;

/* Tabs: the console is too big for one scroll, and the operator usually wants
   one job at a time. The choice survives a reload so a refresh does not throw
   you back to the overview mid-task. */
(function(){
  var rail=document.getElementById("tabs");
  var open=function(name){
    var found=false;
    [].forEach.call(rail.querySelectorAll("button"),function(b){
      var on=b.dataset.p===name;
      b.setAttribute("aria-selected",on?"true":"false");
      if(on) found=true;
    });
    if(!found) return open("overview");
    [].forEach.call(document.querySelectorAll(".page"),function(pg){
      pg.classList.toggle("on",pg.id==="p-"+name);
    });
    try{ sessionStorage.setItem("admTab",name); }catch(e){}
  };
  rail.addEventListener("click",function(e){
    var b=e.target.closest("button[data-p]"); if(b) open(b.dataset.p);
  });
  var saved=null; try{ saved=sessionStorage.getItem("admTab"); }catch(e){}
  open(saved||"overview");
})();

if(T)show();
refreshTimer = setInterval(function(){
  if(T && document.getElementById("panel").style.display!=="none"){
    refresh().then(labelAll).catch(function(){});   // 401s are handled inside api()
  }
},30000);
</script></body></html>`;
