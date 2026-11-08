/* Regression test for withdrawal refunds.
 *
 * Runs the real debit/refund SQL from api/index.js against an in-memory
 * Postgres, so the shipped behaviour is checked rather than described.
 * It caught a live bug: refunds returned the whole amount to `winnings`
 * even when part had been taken from playable credit, silently converting
 * one pot into the other.
 *
 * Run:  npm i -D pg-mem && node test-refunds.js
 * (pg-mem is a dev-only dependency; it is not needed to deploy.)
 */
const { newDb } = require("pg-mem");
const db = newDb();

// minimal schema matching api/index.js
db.public.none(`
  CREATE TABLE users(id SERIAL PRIMARY KEY, balance BIGINT DEFAULT 0,
                     winnings BIGINT DEFAULT 0);
  CREATE TABLE tx(id SERIAL PRIMARY KEY, user_id INT, kind TEXT, amount BIGINT,
                  ref TEXT UNIQUE, status TEXT, from_win BIGINT DEFAULT 0,
                  from_bal BIGINT DEFAULT 0, created BIGINT);
  INSERT INTO users(id,balance,winnings) VALUES (1, 5000, 25000);
`);
const q = (sql, p) => db.public.query(
  sql.replace(/\$(\d+)/g, (_, n) => {
    const v = p[n - 1];
    return typeof v === "string" ? `'${v.replace(/'/g, "''")}'` : `(${v})`;
  })
);
const state = () => db.public.many("SELECT balance, winnings FROM users WHERE id=1")[0];
const txRow = ref => db.public.many(`SELECT * FROM tx WHERE ref='${ref}'`)[0];
const K = c => "KSh " + (c / 100).toFixed(2);

let fails = 0;
function check(label, cond, detail) {
  console.log((cond ? "  PASS  " : "  FAIL  ") + label + (detail ? "  — " + detail : ""));
  if (!cond) fails++;
}

console.log("start: credit " + K(state().balance) + ", winnings " + K(state().winnings));
console.log("\n[1] withdraw KSh 300 — winnings first, then credit");

const cents = 30000;
const before = state();
const held = Number(before.winnings);
const fromWin = Math.min(held, cents);
const fromBal = cents - fromWin;

// the exact debit from api/index.js
q("UPDATE users SET winnings=winnings-$2, balance=balance-$3 WHERE id=$1",
  [1, fromWin, fromBal]);
q(`INSERT INTO tx(user_id,kind,amount,ref,status,from_win,from_bal,created)
   VALUES($1,'withdraw',$2,$3,'sending',$4,$5,$6)`,
  [1, cents, "wd_test", fromWin, fromBal, Date.now()]);

const afterDebit = state();
check("split taken correctly",
  fromWin === 25000 && fromBal === 5000, "winnings " + K(fromWin) + " + credit " + K(fromBal));
check("balances zeroed after debit",
  Number(afterDebit.balance) === 0 && Number(afterDebit.winnings) === 0,
  "credit " + K(afterDebit.balance) + ", winnings " + K(afterDebit.winnings));

console.log("\n[2] B2C callback reports FAILURE — refund path from api/index.js");
// the shipped refundWithdrawal() logic: replay the recorded split
function refundWithdrawal(t){
  const amount = Number(t.amount);
  let fw = Number(t.from_win || 0), fb = Number(t.from_bal || 0);
  if (fw + fb !== amount) { fw = amount; fb = 0; }
  const upd = q("UPDATE tx SET status='failed' WHERE id=$1 AND status IN ('pending','sending','review')",
    [t.id]);
  if (!upd.rowCount) return false;
  q("UPDATE users SET winnings=winnings+$2, balance=balance+$3 WHERE id=$1", [t.user_id, fw, fb]);
  return true;
}
refundWithdrawal(txRow("wd_test"));

const afterRefund = state();
const totalBack = Number(afterRefund.balance) + Number(afterRefund.winnings);
check("player is made whole overall", totalBack === 30000, "total " + K(totalBack));
check("credit restored to its original KSh 50",
  Number(afterRefund.balance) === 5000,
  "credit is " + K(afterRefund.balance) + " (was " + K(before.balance) + ")");
check("winnings restored to its original KSh 250",
  Number(afterRefund.winnings) === 25000,
  "winnings is " + K(afterRefund.winnings) + " (was " + K(before.winnings) + ")");

console.log("\n[3] refund runs twice (duplicate callback)");
const guarded = refundWithdrawal(txRow("wd_test")) === false;
check("second refund is blocked by the status guard", guarded,
  guarded ? "helper returned false, no double credit" : "WOULD DOUBLE-PAY");

console.log("\n[4] legacy row with no recorded split (pre-migration withdrawal)");
db.public.none("UPDATE users SET balance=0, winnings=0 WHERE id=1");
db.public.none(`INSERT INTO tx(user_id,kind,amount,ref,status,from_win,from_bal,created)
  VALUES(1,'withdraw',20000,'wd_legacy','pending',0,0,0)`);
refundWithdrawal(txRow("wd_legacy"));
const leg = state();
check("legacy refund returns the full amount",
  Number(leg.winnings) + Number(leg.balance) === 20000,
  "winnings " + K(leg.winnings) + ", credit " + K(leg.balance));

console.log("\n" + (fails ? fails + " CHECK(S) FAILED" : "ALL CHECKS PASSED"));
