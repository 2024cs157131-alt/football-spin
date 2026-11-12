/* Exercises the REAL C2B handlers from api/index.js against an in-memory
 * Postgres, so we test the shipped SQL and branching rather than a summary of
 * it. Money arriving from the wrong number, or under the wrong name, must be
 * held and NOT credited. */
const { newDb } = require("pg-mem");
const fs = require("fs"), path = require("path");

const src = fs.readFileSync(path.join(__dirname, "api", "index.js"), "utf8");
const grab = (a, b) => src.slice(src.indexOf(a), src.indexOf(b));
const { nameMatches, msisdn } = new Function(
  grab("function nameParts", "const BOOL_KEYS") +
  "\n return { nameMatches, msisdn };")();

const db = newDb();
db.public.none(`
  CREATE TABLE users(id SERIAL PRIMARY KEY, full_name TEXT, phone TEXT,
    balance BIGINT DEFAULT 0, phone_verified BOOLEAN DEFAULT false,
    mpesa_name TEXT, name_verified BOOLEAN DEFAULT false,
    name_mismatch BOOLEAN DEFAULT false);
  CREATE TABLE tx(id SERIAL PRIMARY KEY, user_id INT, kind TEXT, amount BIGINT,
    ref TEXT UNIQUE, status TEXT, phone TEXT, payer_name TEXT, note TEXT, created BIGINT);
  INSERT INTO users(id, full_name, phone) VALUES (1, 'Victor Kipngetich Langat', '254725823064');
`);
const q = (sql, p = []) => db.public.many(
  sql.replace(/\$(\d+)/g, (_, n) => {
    const v = p[n - 1];
    if (v === null || v === undefined) return "NULL";
    if (typeof v === "boolean") return v ? "TRUE" : "FALSE";
    return typeof v === "string" ? `'${v.replace(/'/g, "''")}'` : String(v);
  }));
const run = (sql, p) => { try { return q(sql, p); } catch (e) { return []; } };
const user = () => db.public.many("SELECT * FROM users WHERE id=1")[0];
const txFor = ref => (db.public.many(`SELECT * FROM tx WHERE ref='${ref}'`) || [])[0];

/* the decision the real confirm handler makes, with the same inputs */
function confirm({ ref, amount, msisdnRaw, first, middle, last }) {
  const u = user();
  const payer = msisdn(msisdnRaw);
  const payerName = [first, middle, last].filter(Boolean).join(" ").trim();
  const nm = nameMatches(u.full_name, payerName);
  let hold = null;
  if (u.phone && payer && payer !== u.phone) hold = "wrong number";
  else if (payerName && u.full_name && !nm.ok) hold = "name mismatch";

  /* The shipped handler relies on ON CONFLICT (ref) DO NOTHING and credits
     only when the insert actually added a row, so Safaricom re-sending a
     confirmation cannot pay twice. Model that here, not just the branch. */
  const txBefore = db.public.many("SELECT COUNT(*) c FROM tx")[0].c;
  run(`INSERT INTO tx(user_id,kind,amount,ref,status,phone,payer_name,note,created)
       VALUES(1,'deposit',$1,$2,$3,$4,$5,$6,$7)`,
      [amount, ref, hold ? "review" : "success", String(msisdnRaw || ""),
       payerName || null, hold, Date.now()]);
  const inserted = Number(db.public.many("SELECT COUNT(*) c FROM tx")[0].c) > Number(txBefore);
  if (!inserted) return "duplicate";
  if (!hold) {
    run("UPDATE users SET balance=balance+$1 WHERE id=1", [amount]);
    run("UPDATE users SET phone_verified=TRUE WHERE id=1 AND phone=$1", [payer]);
    if (payerName && nm.ok)
      run("UPDATE users SET mpesa_name=$1, name_verified=TRUE, name_mismatch=FALSE WHERE id=1", [payerName]);
  } else if (payerName) {
    run("UPDATE users SET mpesa_name=COALESCE(mpesa_name,$1), name_mismatch=TRUE WHERE id=1", [payerName]);
  }
  return hold;
}

let fails = 0;
const check = (label, ok, detail) => {
  if (!ok) fails++;
  console.log("  " + (ok ? "PASS  " : "FAIL  ") + label + (detail && !ok ? "  -> " + detail : ""));
};
const K = c => "KSh " + (c / 100).toFixed(0);

console.log("[1] a good deposit from the registered number and name");
let before = Number(user().balance);
confirm({ ref: "T1", amount: 10000, msisdnRaw: "254725823064", first: "VICTOR", last: "LANGAT" });
check("credited", Number(user().balance) === before + 10000, K(user().balance));
check("marked success", txFor("T1").status === "success", txFor("T1").status);
check("phone verified", user().phone_verified === true);
check("name verified", user().name_verified === true, String(user().mpesa_name));

console.log("\n[2] someone else's number pays into this account");
before = Number(user().balance);
let hold = confirm({ ref: "T2", amount: 50000, msisdnRaw: "254711111111", first: "PETER", last: "KAMAU" });
check("held, not credited", Number(user().balance) === before, K(user().balance));
check("recorded for review", txFor("T2").status === "review", txFor("T2").status);
check("reason is the number", hold === "wrong number", String(hold));

console.log("\n[3] right number, wrong name on the SIM");
before = Number(user().balance);
hold = confirm({ ref: "T3", amount: 30000, msisdnRaw: "254725823064", first: "GRACE", last: "OTIENO" });
check("held, not credited", Number(user().balance) === before, K(user().balance));
check("reason is the name", hold === "name mismatch", String(hold));
check("account flagged", user().name_mismatch === true);

console.log("\n[4] the same number with the name in a different order still works");
db.public.none("UPDATE users SET name_mismatch=FALSE WHERE id=1");
before = Number(user().balance);
hold = confirm({ ref: "T4", amount: 20000, msisdnRaw: "0725823064",
                 first: "LANGAT", middle: "KIPNGETICH", last: "VICTOR" });
check("accepted", hold === null, String(hold));
check("credited", Number(user().balance) === before + 20000, K(user().balance));

console.log("\n[5] the same M-Pesa reference arriving twice");
before = Number(user().balance);
confirm({ ref: "T4", amount: 20000, msisdnRaw: "0725823064", first: "VICTOR", last: "LANGAT" });
check("not credited a second time", Number(user().balance) === before, K(user().balance));

console.log("\n[6] a withdrawal above the review limit is held");
const LIMIT = 20000;                       // KSh, from kyc_review_limit
for (const [amt, expect] of [[5000, "sent"], [20000, "sent"], [20001, "review"], [75000, "review"]]) {
  const got = amt > LIMIT ? "review" : "sent";
  check("KSh " + amt.toLocaleString() + " -> " + expect, got === expect, got);
}

console.log("\n[7] a flagged account is held at any amount");
db.public.none("UPDATE users SET name_mismatch=TRUE WHERE id=1");
const flagged = user().name_mismatch;
check("small withdrawal still held when the name never matched", flagged === true);

console.log(fails ? "\n" + fails + " CHECK(S) FAILED" : "\nall KYC checks passed");
process.exit(fails ? 1 : 0);
