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
  if (!ADMIN_PATH || !ADMIN_PASSWORD || !ADMIN_TOTP_SECRET) {
    console.warn("Admin panel disabled: set ADMIN_PATH, ADMIN_PASSWORD, ADMIN_TOTP_SECRET");
    return;
  }

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
  const totpOk = code => [-1, 0, 1].some(w => {
    try { return crypto.timingSafeEqual(Buffer.from(totp(ADMIN_TOTP_SECRET, w)), Buffer.from(String(code || "").padStart(6, "0"))); }
    catch { return false; }
  });
  const pwOk = pw => {
    const a = crypto.createHash("sha256").update(String(pw || "")).digest();
    const b = crypto.createHash("sha256").update(ADMIN_PASSWORD).digest();
    return crypto.timingSafeEqual(a, b);
  };

  /* ----- rate limiting (DB-backed, survives serverless cold starts) ----- */
  async function throttled() {
    const cutoff = Date.now() - 10 * 60 * 1000;
    await pool.query("DELETE FROM admin_attempts WHERE ts < $1", [cutoff]);
    const r = await pool.query("SELECT COUNT(*) c FROM admin_attempts WHERE ts >= $1", [cutoff]);
    return Number(r.rows[0].c) >= 8; // max 8 attempts per 10 minutes, global
  }

  function adminAuth(req, res, next) {
    const t = verify((req.headers.authorization || "").replace("Bearer ", ""));
    if (!t || t.role !== "admin" || t.exp < Date.now())
      return res.status(401).json({ error: "Session expired. Log in again." });
    next();
  }

  const P = `/api/admin/${ADMIN_PATH}`;

  /* ----- login ----- */
  app.post(`${P}/login`, async (req, res) => {
    if (await throttled()) return res.status(429).json({ error: "Too many attempts. Wait 10 minutes." });
    const { password, code } = req.body || {};
    if (!pwOk(password) || !totpOk(code)) {
      await pool.query("INSERT INTO admin_attempts(ts) VALUES($1)", [Date.now()]);
      return res.status(401).json({ error: "Wrong password or code." });
    }
    res.json({ token: sign({ role: "admin", exp: Date.now() + 60 * 60 * 1000 }) });
  });

  /* ----- dashboard stats ----- */
  app.get(`${P}/stats`, adminAuth, async (_req, res) => {
    const [users, dep, wd, daily, jack, st, pend] = await Promise.all([
      pool.query("SELECT COUNT(*) c, COALESCE(SUM(balance),0) bal FROM users"),
      pool.query("SELECT COALESCE(SUM(amount),0) s, COUNT(*) c FROM tx WHERE kind='deposit' AND status='success'"),
      pool.query("SELECT COALESCE(SUM(amount),0) s, COUNT(*) c FROM tx WHERE kind='withdraw' AND status='success'"),
      pool.query(`SELECT to_char(to_timestamp(created/1000),'YYYY-MM-DD') d,
        COALESCE(SUM(stake),0) staked, COALESCE(SUM(payout),0) paid, COUNT(*) spins
        FROM spins WHERE demo=false GROUP BY d ORDER BY d DESC LIMIT 14`),
      pool.query("SELECT pool FROM jackpot WHERE id=1"),
      pool.query("SELECT key,value FROM settings"),
      pool.query("SELECT COUNT(*) c, COALESCE(SUM(amount),0) s FROM tx WHERE kind='withdraw' AND status IN ('pending','sending')"),
    ]);
    const settings = {}; st.rows.forEach(x => settings[x.key] = x.value === "true");
    res.json({
      players: Number(users.rows[0].c),
      player_balances: Number(users.rows[0].bal),        // your liability to players
      deposits: { total: Number(dep.rows[0].s), count: Number(dep.rows[0].c) },
      withdrawals: { total: Number(wd.rows[0].s), count: Number(wd.rows[0].c) },
      pending_withdrawals: { count: Number(pend.rows[0].c), total: Number(pend.rows[0].s) },
      daily: daily.rows.map(r => ({ date: r.d, staked: Number(r.staked), paid: Number(r.paid),
        profit: Number(r.staked) - Number(r.paid), spins: Number(r.spins) })),
      jackpot_pool: Number(jack.rows[0]?.pool || 0),
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
  app.post(`${P}/settings`, adminAuth, async (req, res) => {
    for (const k of ["live_mode", "withdrawals_enabled"]) {
      if (k in (req.body || {}))
        await pool.query("UPDATE settings SET value=$2 WHERE key=$1", [k, String(!!req.body[k])]);
    }
    const r = await pool.query("SELECT key,value FROM settings");
    const o = {}; r.rows.forEach(x => o[x.key] = x.value === "true");
    res.json(o);
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
  <div class="err" id="lerr"></div><button class="on" style="width:100%" id="loginBtn">Sign in</button>
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

  <h2>Profit per day (live spins only)</h2>
  <div class="scroll"><table id="daily"><thead><tr><th>Date</th><th>Spins</th><th>Staked</th><th>Paid out</th><th>Profit</th><th>Margin</th></tr></thead><tbody></tbody></table></div>

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
const api=async(p,b)=>{const r=await fetch(B+p,{method:b?"POST":"GET",headers:{"Content-Type":"application/json",Authorization:"Bearer "+T},body:b?JSON.stringify(b):undefined});const d=await r.json();if(!r.ok)throw new Error(d.error||"Error");return d};

async function login(){
  try{const d=await api("/login",{password:document.getElementById("pw").value,code:document.getElementById("code").value});
    T=d.token;sessionStorage.setItem("adm",T);show();
  }catch(e){document.getElementById("lerr").textContent=e.message}
}

async function show(){
  document.getElementById("login").style.display="none";
  document.getElementById("panel").style.display="block";
  await refresh();loadPlayers();loadTx();
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
    ["Jackpot pool",K(s.jackpot_pool)]
  ].map(function(row){
    var l=row[0],v=row[1],c=row[2];
    return '<div class="card"><small>'+l+'</small><b class="'+(c||"")+'">'+v+"</b></div>";
  }).join("");

  document.getElementById("daily").tBodies[0].innerHTML=s.daily.map(function(d){
    return "<tr><td>"+d.date+"</td><td>"+d.spins+"</td><td>"+K(d.staked)+"</td><td>"+K(d.paid)+
      '</td><td class="'+(d.profit>=0?"pos":"neg")+'">'+K(d.profit)+"</td><td>"+
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

document.getElementById("loginBtn").onclick=login;
document.getElementById("btnMode").onclick=function(){toggle("live_mode")};
document.getElementById("btnWd").onclick=function(){toggle("withdrawals_enabled")};
document.getElementById("jpBtn").onclick=setJackpot;
document.getElementById("searchBtn").onclick=loadPlayers;
document.getElementById("q").addEventListener("keydown",function(e){if(e.key==="Enter")loadPlayers();});
document.getElementById("exportBtn").onclick=exportTx;

if(T)show();
setInterval(function(){
  if(T&&document.getElementById("panel").style.display!=="none")refresh();
},30000);
</script></body></html>`;
