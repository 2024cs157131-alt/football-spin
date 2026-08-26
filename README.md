# Football Spin — Daraja (M-Pesa paybill) + Vercel

Deposits: STK push to **your own paybill** (Daraja / Lipa na M-Pesa Online). Withdrawals: **B2C** from your paybill to the player's Safaricom number. Database: Postgres (Neon). Hosting: Vercel.

## Project layout
```
api/index.js        ← all backend routes (Vercel serverless function)
public/index.html   ← the game
public/logos/       ← optional team logo PNGs (see "Club logos")
vercel.json
package.json
```

## 1. Daraja setup (developer.safaricom.co.ke)
1. Create an app on the Daraja portal → note the **Consumer Key** and **Consumer Secret**.
2. **STK Push (deposits)**: you need your paybill **shortcode** and the **Lipa na M-Pesa Online passkey**. In sandbox, use shortcode `174379` with the public test passkey. In production, Safaricom issues the passkey when you complete **Go-Live** for Lipa na M-Pesa Online.
3. **B2C (withdrawals)**: request the B2C product in Go-Live. You'll get an **Initiator name** and set an initiator password; generate the **Security Credential** (encrypted password) with the portal's *Generate Security Credential* tool using the production certificate. B2C pays from your paybill's **Utility/B2C balance**, not your collections balance — keep it funded (your bank or Safaricom can set up auto-transfer between the two).
4. Callbacks land at `/api/mpesa/stk/<CALLBACK_TOKEN>` and `/api/mpesa/b2c/<CALLBACK_TOKEN>`. Daraja doesn't sign callbacks, so the random token in the URL is your protection — keep it secret. Callback URLs must be HTTPS (Vercel is) and match what you whitelist during Go-Live.

## 2. Database (Neon — 2 minutes)
On vercel.com → Storage → Create Database → **Neon Postgres** (or neon.tech directly). Copy the connection string. Tables are created automatically on first request.

## 3. Deploy to Vercel
1. Push this folder to GitHub.
2. vercel.com → Add New → Project → import the repo. Framework preset: **Other**. No build command needed.
3. Settings → Environment Variables:

| Variable | Value |
|---|---|
| `DATABASE_URL` | Neon connection string |
| `APP_SECRET` | long random string (`openssl rand -hex 32`) — never change it or all logins invalidate |
| `CALLBACK_TOKEN` | another long random string |
| `BASE_URL` | `https://your-project.vercel.app` (or your domain) |
| `MPESA_ENV` | `sandbox`, then `production` |
| `MPESA_CONSUMER_KEY` / `MPESA_CONSUMER_SECRET` | from your Daraja app |
| `MPESA_SHORTCODE` | your paybill (sandbox: `174379`) |
| `MPESA_PASSKEY` | Lipa na M-Pesa Online passkey |
| `MPESA_INITIATOR` | B2C initiator name |
| `MPESA_SECURITY_CREDENTIAL` | encrypted initiator password from the portal tool |

4. Deploy. Test the full loop in sandbox first (sandbox simulates STK prompts and B2C results to your callbacks), then switch `MPESA_ENV`, shortcode, and keys to production after Go-Live.

Vercel note: serverless functions are stateless — that's why all state lives in Postgres and sessions are signed tokens. Safaricom's callbacks wake the function on demand; nothing needs to run 24/7.

## 4. How money moves
- **Deposit (STK push)**: player enters phone + amount → server sends STK push → player enters M-Pesa PIN → Safaricom hits the STK callback → wallet credited (only from the callback, with the amount Safaricom reports).
- **Deposit (direct paybill / C2B)**: player pays your paybill from the M-Pesa menu with account number `SPIN<their id>` (shown in the deposit screen) → Safaricom hits the C2B confirmation URL → wallet auto-credits. Payments with an invalid account number are rejected at validation. Idempotent on Safaricom's TransID, so retried callbacks can't double-credit.
  **One-time setup per environment**: after deploying, visit `https://yourdomain/api/mpesa/c2b/register/<CALLBACK_TOKEN>` once to register the validation/confirmation URLs with Safaricom (production requires external validation enabled on your shortcode — ask Safaricom, otherwise validation is skipped and only confirmation fires, which still credits correctly).
- **Withdraw (B2C, fully automatic)**: balance debited first, B2C request sent → Safaricom hits the B2C result callback → success marks the tx complete; failure or timeout automatically refunds the balance. No manual approval step.
- Every transaction and spin is stored for reconciliation and regulator audit.

## 5. Game math — 70% margin (with progressive jackpot)
The visual wheel is animation only; the real odds are the weighted `OUTCOMES` table in `api/index.js`. Player return is split: **28% base game + 2% jackpot contribution = 30% RTP total, 70% margin** on every bet type (verified). The jackpot is a progressive pool: 2% of every stake feeds it, it's displayed live in the UI, and a ~1-in-20,000 weighted trigger pays the entire pool to the spinning player, after which it resets to the KSh 5,000 seed (`JACKPOT_SEED` — the seed is the only house cost, a few thousand shillings per hit). Tune `JACKPOT_CUT`, `JACKPOT_SEED`, and the `jackpot` weight to change the feel; the pool payout is transactional (`FOR UPDATE`) so two simultaneous spins can't both win it. **Check the total RTP against your BCLB licence** — declared payout rates are audited, and BCLB requires RNG certification by an accredited test house (GLI, BMM, iTech Labs); outcomes use Node's `crypto.randomInt`, a CSPRNG with rejection sampling (no modulo bias), and the `spins` table is your audit trail.

## 6. Club logos
Drop `manu.png`, `chelsea.png`, `arsenal.png`, `real.png`, `liverpool.png`, `stoke.png`, `norwich.png`, `leicester.png` into `public/logos/` and the wheel and bet buttons use them automatically; otherwise the colour badges show. Club crests are trademarks — only use them with commercial licensing from the rights holders.

## 7. Admin panel (operator console)
The console lives at a **secret URL** that appears nowhere in the app:
```
https://yourdomain/api/admin/<ADMIN_PATH>/panel
```

### Setup — three more environment variables
| Variable | Value |
|---|---|
| `ADMIN_PATH` | long random slug, e.g. `openssl rand -hex 16` → this becomes part of the URL |
| `ADMIN_PASSWORD` | strong password (16+ chars) |
| `ADMIN_TOTP_SECRET` | base32 secret for 2FA, e.g. `openssl rand -hex 10 \| xxd -r -p \| base32` |

Then add the TOTP secret to Google Authenticator / Authy: tap "Enter setup key", account name anything, key = your `ADMIN_TOTP_SECRET`, time-based. Logging in requires password **and** the 6-digit code.

### What it does
- **Dashboard**: profit today, spins today, total players, all-time deposits/withdrawals, **player balances (your liability)**, pending payouts, jackpot pool — refreshes every 30s.
- **Profit per day**: last 14 days of staked / paid out / profit / realised margin (live spins only; demo play is excluded).
- **Pause withdrawals**: one button for the app-glitch scenario — B2C payouts stop instantly with a friendly "briefly paused for maintenance" message, while deposits and play continue and balances stay intact. Resume with the same button.
- **Demo ↔ Live mode**: demo mode pauses all real money — deposits and withdrawals are disabled, spins run on free demo credits (auto-refilled to KSh 1,000), the game shows a DEMO badge, and demo spins are excluded from profit stats and the jackpot. Perfect for launch testing or licence inspection demos.
- **Players**: searchable list with balance, total deposited, total withdrawn, and net lost per player; **Suspend** blocks a player's deposits, withdrawals, and live play (e.g. suspected fraud) without touching their balance.
- **Transactions**: last 100 deposits/withdrawals with status and phone, for reconciliation against your M-Pesa statements.
- **Set jackpot**: correct the pool manually if ever needed.

### Security honestly stated
No internet-facing page is truly "hacker-proof"; this one is defended in layers: (1) the URL slug is a secret — it's served only at that path, marked noindex, and linked from nowhere; (2) login needs password **and** authenticator-app 2FA, compared in constant time; (3) login attempts are rate-limited (8 per 10 min, stored in Postgres so serverless restarts don't reset it); (4) sessions are signed and expire after 60 minutes. For an even harder shell, put Cloudflare in front and add an Access rule (or Vercel's IP allowlisting on Pro) restricting `/api/admin/*` to your own IP — that makes the panel unreachable at the network level. Never share the URL, and rotate `ADMIN_PATH` if you ever suspect it leaked.

## 8. Before going live (compliance)
- BCLB licence: declared RTP must match the game, RNG must be certified, and the paybill must be registered to the licensed entity.
- KYC before withdrawal (BCLB requires it) — an ID-verification provider like Smile ID slots into `/api/withdraw`.
- Responsible gambling: the 18+ gate ships in the UI; add deposit limits and self-exclusion, which BCLB expects.
