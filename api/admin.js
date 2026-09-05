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

module.exports = function mountAdmin(app, pool, sign, verify) {
  const { ADMIN_PATH, ADMIN_PASSWORD, ADMIN_TOTP_SECRET } = process.env;

  /* TEMPORARY 2FA BYPASS — recovery only.
   * Set ADMIN_TOTP_DISABLED=true to sign in with the password alone, e.g. when
   * the authenticator secret has been lost. This leaves the console protected
   * by one factor and a secret URL, so it is materially weaker: set a new
   * ADMIN_TOTP_SECRET, re-add it to your authenticator, then DELETE this
   * variable. The lockout window is also tightened while it is on. */
  const TOTP_DISABLED = String(process.env.ADMIN_TOTP_DISABLED || "").toLowerCase() === "true";

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

    // A good login clears the slate, so earlier typos can't lock you out later.
    await clearAttempts(ip);
    const ttl = TOTP_DISABLED ? 15 * 60 * 1000 : 60 * 60 * 1000;
    res.json({ token: sign({ role: "admin", exp: Date.now() + ttl }) });
  }));

  /* Clock check: compare your phone against the server so drift is obvious.
   * Returns no secrets and needs no auth. */
  app.get(`${P}/time`, (_req, res) => {
    res.json({ server_time: new Date().toISOString(), epoch_ms: Date.now(),
               totp_step: Math.floor(Date.now() / 30000), totp_disabled: TOTP_DISABLED });
  });

  /* ----- dashboard stats ----- */
  app.get(`${P}/stats`, adminAuth, async (_req, res) => {
    const [users, dep, wd, daily, jack, st, pend, taxq, plq, expDaily, expAll] = await Promise.all([
      pool.query("SELECT COUNT(*) c, COALESCE(SUM(balance),0) bal FROM users"),
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
      SELECT u.id, u.email, u.full_name, u.id_number, u.id_verified, u.phone, u.phone_verified, u.balance, u.suspended, u.created,
        COALESCE((SELECT SUM(amount) FROM tx WHERE user_id=u.id AND kind='deposit' AND status='success'),0) deposited,
        COALESCE((SELECT SUM(amount) FROM tx WHERE user_id=u.id AND kind='withdraw' AND status='success'),0) withdrawn,
        COALESCE((SELECT SUM(stake)-SUM(payout) FROM spins WHERE user_id=u.id AND demo=false),0) net_lost
      FROM users u ${q ? "WHERE u.email ILIKE $1 OR u.phone ILIKE $1 OR u.full_name ILIKE $1 OR u.id_number ILIKE $1" : ""}
      ORDER BY u.id DESC LIMIT 100`, q ? [`%${q}%`] : []);
    res.json(r.rows.map(x => ({ ...x, balance: Number(x.balance), deposited: Number(x.deposited),
      withdrawn: Number(x.withdrawn), net_lost: Number(x.net_lost) })));
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
  const NUM_KEYS = ["wht_rate", "wht_threshold", "excise_rate", "betting_tax_rate", "corp_tax_rate", "target_rtp", "target_net"];

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
        await client.query("UPDATE users SET balance=balance+$2 WHERE id=$1", [t.user_id, Number(t.amount)]);
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
    res.type("html").send(PANEL_HTML.replaceAll("__BASE__", P));
  });
};

const PANEL_HTML = `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Console</title><style>
body{font-family:system-ui;background:#0d1117;color:#e6edf3;margin:0;padding:16px;max-width:1000px;margin:auto}
h1{font-size:18px}h2{font-size:14px;color:#7d8590;margin:22px 0 8px;text-transform:uppercase;letter-spacing:1px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:12px}
.card small{color:#7d8590;font-size:11px;display:block}.card b{font-size:18px}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{padding:7px 8px;border-bottom:1px solid #21262d;text-align:left;white-space:nowrap}
th{color:#7d8590;font-size:11px;text-transform:uppercase}
.pos{color:#3fb950}.neg{color:#f85149}
button{background:#21262d;color:#e6edf3;border:1px solid #30363d;border-radius:8px;padding:8px 14px;cursor:pointer}
button.on{background:#1f6feb;border-color:#1f6feb}button.danger{background:#da3633;border-color:#da3633}
input{background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:8px;padding:9px;width:100%;box-sizing:border-box;margin:4px 0}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
#login{max-width:320px;margin:80px auto}
.scroll{overflow-x:auto}.err{color:#f85149;font-size:13px;min-height:16px}
.badge{font-size:10px;padding:2px 8px;border-radius:999px;background:#21262d}
.badge.live{background:#238636}.badge.demo{background:#9e6a03}
</style></head><body>
<div id="login">
  <h1>Operator console</h1>
  <input id="pw" type="password" placeholder="Password" autocomplete="current-password">
  <input id="code" inputmode="numeric" placeholder="Authenticator code" maxlength="6">
  <div class="err" id="lerr"></div>
  <div id="clockWarn" style="display:none;font-size:12px;color:#d29922;background:#1c1500;border:1px solid #4a3800;border-radius:8px;padding:8px;margin-bottom:8px"></div>
  <button class="on" style="width:100%" id="loginBtn">Sign in</button>
</div>
<div id="panel" style="display:none">
  <div class="row" style="justify-content:space-between"><h1>Operator console</h1>
    <span><span class="badge" id="modeBadge"></span> <span class="badge" id="wdBadge"></span></span></div>

  <h2>Today & totals</h2><div class="cards" id="cards"></div>

  <h2>Controls</h2>
  <div class="row">
    <button id="btnMode"></button>
    <button id="btnWd"></button>
    <span style="flex:1"></span>
    <input id="jp" type="number" placeholder="Jackpot KSh" style="width:130px">
    <button id="jpBtn">Set jackpot</button>
  </div>
  <p style="color:#7d8590;font-size:12px">Pause withdrawals during a glitch — deposits and play continue, balances are safe. Demo mode pauses all real money; players get free credits.</p>

  <h2>Payout rate (house margin)</h2>
  <div class="row">
    <label style="font-size:12px;color:#7d8590">Player payout (RTP) %
      <input id="rtpInput" type="number" step="0.5" min="8" max="90" style="width:90px"></label>
    <span id="rtpMargin" style="font-family:system-ui;font-size:15px"></span>
    <button id="rtpSave" class="on">Apply</button>
    <button id="auditBtn">Change log</button>
  </div>
  <div class="row" style="margin-top:8px">
    <label style="font-size:12px;color:#7d8590">…or target NET profit after tax %
      <input id="netTarget" type="number" step="0.5" style="width:90px"></label>
    <button id="netSolve">Calculate payout rate</button>
    <button id="netApply" class="on">Calculate &amp; apply</button>
    <span id="netOut" style="font-size:13px"></span>
  </div>
  <p style="color:#7d8590;font-size:12px">Takes effect on the next spin. All bet types stay at the same RTP. Every change is timestamped in the change log — BCLB audits declared payout rates, so keep this matching your licence.</p>
  <div class="scroll" id="auditWrap" style="display:none;margin-top:8px"><table id="audit"><thead><tr><th>When</th><th>Setting</th><th>From</th><th>To</th></tr></thead><tbody></tbody></table></div>

  <h2>Marketing &amp; expenses</h2>
  <div class="row">
    <select id="expCat" style="background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:8px;padding:9px">
      <option value="marketing">Marketing</option>
      <option value="bonuses">Player bonuses</option>
      <option value="hosting">Hosting / tech</option>
      <option value="licensing">Licensing / legal</option>
      <option value="other">Other</option>
    </select>
    <input id="expAmt" type="number" placeholder="Amount KSh" style="width:130px">
    <input id="expNote" placeholder="Note (e.g. Facebook campaign)" style="flex:1;min-width:160px">
    <button id="expAdd" class="on">Record spend</button>
  </div>
  <div class="scroll" style="margin-top:8px"><table id="exp"><thead><tr><th>Date</th><th>Category</th><th>Amount</th><th>Note</th><th></th></tr></thead><tbody></tbody></table></div>

  <h2>Tax &amp; margin</h2>
  <div class="row">
    <button id="btnWht"></button>
    <label style="font-size:12px;color:#7d8590">WHT rate %<input id="whtRate" type="number" step="0.5" style="width:80px"></label>
    <label style="font-size:12px;color:#7d8590">Excise % of stakes<input id="exRate" type="number" step="0.5" style="width:80px"></label>
    <label style="font-size:12px;color:#7d8590">Betting tax % of GGR<input id="btRate" type="number" step="0.5" style="width:80px"></label>
    <label style="font-size:12px;color:#7d8590">Corporate tax %<input id="ctRate" type="number" step="0.5" style="width:80px"></label>
    <button id="taxSave">Save rates</button>
  </div>
  <div class="card" id="marginCalc" style="margin-top:10px"></div>
  <p style="color:#7d8590;font-size:12px">Withholding tax is deducted from the player's winnings and remitted to KRA — it is not your revenue. Rates change; confirm current figures with your accountant. Turning WHT off while the law requires it is tax evasion.</p>

  <h2 class="row" style="justify-content:space-between">PesaLink requests (pay from your bank, then mark paid)</h2>
  <div class="scroll"><table id="pl"><thead><tr><th>Ref</th><th>Player</th><th>Nat. ID</th><th>Amount</th><th>Bank</th><th>Account</th><th>Status</th><th></th></tr></thead><tbody></tbody></table></div>

  <h2>Profit per day (live spins only)</h2>
  <div class="scroll"><table id="daily"><thead><tr><th>Date</th><th>Spins</th><th>Staked</th><th>Paid out</th><th>Gross profit</th><th>Marketing</th><th>After spend</th><th>Margin</th></tr></thead><tbody></tbody></table></div>

  <h2>Players</h2>
  <div class="row"><input id="q" placeholder="Search email" style="flex:1"><button id="searchBtn">Search</button></div>
  <div class="scroll"><table id="players"><thead><tr><th>ID</th><th>Name</th><th>Nat. ID</th><th>Email</th><th>Phone</th><th>Balance</th><th>Deposited</th><th>Withdrawn</th><th>Net lost</th><th></th></tr></thead><tbody></tbody></table></div>

  <h2 class="row" style="justify-content:space-between">Recent transactions
    <button id="exportBtn">Download all (CSV)</button></h2>
  <div class="scroll"><table id="tx"><thead><tr><th>ID</th><th>Player</th><th>Kind</th><th>Amount</th><th>Status</th><th>Phone</th><th>When</th></tr></thead><tbody></tbody></table></div>
</div>
<script>
const B="__BASE__"; let T=sessionStorage.getItem("adm")||null; let S={};
const K=c=>"KSh "+(c/100).toLocaleString("en-KE");
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
    if(d&&d.error) throw new Error(d.error);
    if(r.status===404) throw new Error("404 \u2014 admin path not found. Check ADMIN_PATH matches the URL.");
    if(r.status===401) throw new Error("Not authorised. Sign in again.");
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
      document.getElementById("code").style.display="none";
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

async function show(){
  document.getElementById("login").style.display="none";
  document.getElementById("panel").style.display="block";
  try{
    const t=await fetch(B+"/time").then(x=>x.json());
    if(t.totp_disabled){
      const b=document.createElement("div");
      b.style.cssText="background:#5a1d1d;border:1px solid #da3633;border-radius:8px;"+
        "padding:10px;margin-bottom:12px;font-size:13px";
      b.innerHTML="\u26A0\uFE0F <b>2FA is disabled</b> \u2014 password-only access. "+
        "Sessions last 15 minutes. Restore ADMIN_TOTP_SECRET and delete ADMIN_TOTP_DISABLED.";
      const p=document.getElementById("panel");
      p.insertBefore(b,p.firstChild);
    }
  }catch(e){}
  await refresh();loadPlayers();loadTx();loadPesalink();loadExpenses();
}

async function refresh(){
  const s=await api("/stats");S=s.settings;
  const today=s.daily[0]||{staked:0,paid:0,profit:0,spins:0};
  document.getElementById("cards").innerHTML=[
    ["Profit today",K(today.profit),today.profit>=0?"pos":"neg"],
    ["Spins today",today.spins],
    ["Players",s.players],
    ["Deposits (all-time)",K(s.deposits.total)],
    ["Withdrawals (all-time)",K(s.withdrawals.total)],
    ["Player balances (liability)",K(s.player_balances)],
    ["Pending payouts",s.pending_withdrawals.count+" / "+K(s.pending_withdrawals.total)],
    ["Jackpot pool",K(s.jackpot_pool)],
    ["WHT collected (owed to KRA)",K(s.wht_collected)],
    ["PesaLink pending",s.pesalink_pending.count+" / "+K(s.pesalink_pending.total)],
    ["Marketing & expenses",K(s.expenses_total)]
  ].map(function(row){
    var l=row[0],v=row[1],c=row[2];
    return '<div class="card"><small>'+l+'</small><b class="'+(c||"")+'">'+v+"</b></div>";
  }).join("");

  document.getElementById("daily").tBodies[0].innerHTML=s.daily.map(function(d){
    return "<tr><td>"+d.date+"</td><td>"+d.spins+"</td><td>"+K(d.staked)+"</td><td>"+K(d.paid)+
      '</td><td class="'+(d.profit>=0?"pos":"neg")+'">'+K(d.profit)+"</td>"+
      "<td>"+(d.marketing?K(d.marketing):"—")+"</td>"+
      '<td class="'+(d.net>=0?"pos":"neg")+'">'+K(d.net)+"</td><td>"+
      (d.staked?Math.round(100*d.profit/d.staked)+"%":"—")+"</td></tr>";
  }).join("");

  document.getElementById("modeBadge").textContent=S.live_mode?"LIVE":"DEMO";
  document.getElementById("modeBadge").className="badge "+(S.live_mode?"live":"demo");
  document.getElementById("wdBadge").textContent=S.withdrawals_enabled?"Withdrawals ON":"Withdrawals PAUSED";
  var btnMode=document.getElementById("btnMode");
  btnMode.textContent=S.live_mode?"Switch to DEMO mode":"Switch to LIVE mode";
  btnMode.className=S.live_mode?"":"on";
  var btnWd=document.getElementById("btnWd");
  btnWd.textContent=S.withdrawals_enabled?"Pause withdrawals":"Resume withdrawals";
  btnWd.className=S.withdrawals_enabled?"danger":"on";

  var btnWht=document.getElementById("btnWht");
  btnWht.textContent=S.wht_enabled?"WHT ON — charging":"WHT OFF — not charging";
  btnWht.className=S.wht_enabled?"on":"danger";
  document.getElementById("whtRate").value=S.wht_rate;
  document.getElementById("exRate").value=S.excise_rate;
  document.getElementById("btRate").value=S.betting_tax_rate;
  document.getElementById("ctRate").value=S.corp_tax_rate;
  var rtpEl=document.getElementById("rtpInput");
  if(document.activeElement!==rtpEl) rtpEl.value=S.target_rtp;
  var netEl=document.getElementById("netTarget");
  if(document.activeElement!==netEl) netEl.value=S.target_net;
  document.getElementById("rtpMargin").innerHTML=
    "= house margin <b class='pos'>"+(100-Number(S.target_rtp)).toFixed(1)+"%</b>";
  drawMargin(s);
}


function drawMargin(s){
  var ex=Number(S.excise_rate)||0, bt=Number(S.betting_tax_rate)||0, ct=Number(S.corp_tax_rate)||0;
  var ggr=100-Number(S.target_rtp);
  var exAmt=ex;                 // per KSh 100 staked, excise is charged on the stake
  var btAmt=bt*ggr/100;
  var pre=ggr-exAmt-btAmt;
  var net=pre*(1-ct/100);
  var realised=s.daily[0]&&s.daily[0].staked?Math.round(100*s.daily[0].profit/s.daily[0].staked):null;
  document.getElementById("marginCalc").innerHTML=
    "<small>Per KSh 100 staked, at "+ggr+"% gross margin</small>"+
    "<div style='font-size:13px;line-height:1.9;margin-top:6px'>"+
    "Gross gaming revenue: <b>KSh "+ggr.toFixed(2)+"</b><br>"+
    "&minus; excise on stakes ("+ex+"%): KSh "+exAmt.toFixed(2)+"<br>"+
    "&minus; betting tax ("+bt+"% of GGR): KSh "+btAmt.toFixed(2)+"<br>"+
    "= pre-tax profit: KSh "+pre.toFixed(2)+"<br>"+
    "&minus; corporate tax ("+ct+"%): KSh "+(pre*ct/100).toFixed(2)+"<br>"+
    "<b class='"+(net>=30?"pos":"neg")+"' style='font-size:16px'>Net profit: KSh "+net.toFixed(2)+" ("+net.toFixed(1)+"%)</b>"+
    (realised!==null?"<br><small style='color:#7d8590'>Today's realised gross margin: "+realised+"%</small>":"")+
    "</div>";
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
  if(!confirm("Set player payout to "+v+"% (house margin "+(100-v).toFixed(1)+"%)?\n\nThis changes the odds from the next spin and is recorded in the change log."))return;
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
  }).join("");
}
async function loadExpenses(){
  var e=await api("/expenses");
  document.getElementById("exp").tBodies[0].innerHTML=e.rows.map(function(x){
    return "<tr><td>"+new Date(Number(x.created)).toLocaleDateString()+"</td><td>"+x.category+
      "</td><td>"+K(x.amount)+"</td><td>"+(x.note||"")+
      '</td><td><button class="expdel" data-id="'+x.id+'">Delete</button></td></tr>';
  }).join("");
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
async function loadPesalink(){
  var p=await api("/pesalink");
  document.getElementById("pl").tBodies[0].innerHTML=p.map(function(x){
    var act=x.status==="requested"
      ? '<button class="plbtn on" data-ref="'+x.ref+'" data-a="paid">Mark paid</button> '+
        '<button class="plbtn danger" data-ref="'+x.ref+'" data-a="reject">Reject &amp; refund</button>'
      : "";
    return "<tr><td>"+x.ref.slice(0,10)+"</td><td>"+(x.full_name||"—")+"</td><td>"+(x.id_number||"—")+
      "</td><td>"+K(x.amount)+"</td><td>"+(x.bank||"")+"</td><td>"+(x.account||"")+
      "</td><td>"+x.status+"</td><td>"+act+"</td></tr>";
  }).join("");
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
      "<td>"+(u.id_number||"—")+' <button class="idvbtn'+(u.id_verified?" on":"")+'" data-id="'+u.id+'" data-v="'+(!u.id_verified)+'">'+(u.id_verified?"ID \u2713":"Mark ID \u2713")+"</button></td>"+
      "<td>"+u.email+"</td><td>"+(u.phone?"0"+u.phone.slice(3):"—")+(u.phone_verified?" \u2713":" \u2717")+"</td>"+
      "<td>"+K(u.balance)+"</td><td>"+K(u.deposited)+"</td><td>"+K(u.withdrawn)+"</td>"+
      '<td class="'+(u.net_lost>=0?"pos":"neg")+'">'+K(u.net_lost)+"</td>"+
      '<td><button class="suspbtn'+(u.suspended?" on":"")+'" data-id="'+u.id+'" data-v="'+(!u.suspended)+'">'+(u.suspended?"Unsuspend":"Suspend")+"</button></td></tr>";
  }).join("");
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
    return "<tr><td>"+x.id+"</td><td>"+x.email+"</td><td>"+x.kind+"</td><td>"+K(x.amount)+"</td><td>"+x.status+"</td><td>"+(x.phone||"")+"</td><td>"+new Date(Number(x.created)).toLocaleString()+"</td></tr>";
  }).join("");
}

checkMode();
document.getElementById("loginBtn").onclick=login;
["pw","code"].forEach(function(id){
  document.getElementById(id).addEventListener("keydown",function(e){ if(e.key==="Enter") login(); });
});
document.getElementById("btnMode").onclick=function(){toggle("live_mode")};
document.getElementById("btnWd").onclick=function(){toggle("withdrawals_enabled")};
document.getElementById("btnWht").onclick=function(){
  if(S.wht_enabled&&!confirm("Stop deducting withholding tax?\n\nOnly do this if the law no longer requires it — withholding when required is a legal obligation."))return;
  api("/settings",{wht_enabled:!S.wht_enabled}).then(refresh);
};
document.getElementById("taxSave").onclick=saveTax;

document.getElementById("rtpSave").onclick=saveRtp;
document.getElementById("netSolve").onclick=function(){solveMargin(false)};
document.getElementById("netApply").onclick=function(){
  if(!confirm("Set the payout rate to hit this net profit target?\n\nThis changes the odds from the next spin and is recorded in the change log."))return;
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

if(T)show();
setInterval(function(){
  if(T&&document.getElementById("panel").style.display!=="none")refresh();
},30000);
</script></body></html>`;
