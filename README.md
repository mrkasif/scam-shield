# ScamShield — Indian Digital Scam Intelligence & Prevention System

ScamShield is a static, explainable threat-analysis system for suspicious
digital payment and messaging artifacts. It inspects structure — never
content behind the link — and tells the user exactly why something looks
dangerous. Built as an Aavishkar project: Python/FastAPI backend, static
HTML/CSS/vanilla-JS frontend, deployable to Vercel, no paid services.

## Problem

In the Indian digital ecosystem, everyday users constantly face:

* **Suspicious URLs** — phishing login pages, fake KYC portals, prize-scam
  links shared over SMS, WhatsApp, and email.
* **Suspicious messages** — scam instructions and lure text that carry no
  link but still cause fraud.
* **QR codes** — stickers and images that hide a payment request or a
  phishing link behind pixels the victim cannot read.
* **UPI payment requests** — collect requests and QR stickers that pressure
  victims into paying scammers, sometimes impersonating banks, officials,
  or refund agents.

Victims cannot tell a real payee ID from a fake one, or a real domain from
a look-alike, by inspection alone.

## Solution

ScamShield performs **static, explainable threat analysis** on submitted
artifacts and produces, for every analysis:

* risk score **0–100**
* safety zone **GREEN (0–29) / YELLOW (30–69) / RED (70–100)**
* threat **category** (e.g. brand impersonation, credential phishing,
  invalid payee, reward lure)
* human-readable **reasons** explaining every point of the score
* machine-readable **detected indicators**
* a concrete **recommended safety action**

Analysis is rule-based and deterministic: the same input always yields the
same verdict, with every point traceable to a named detector.

## Core capabilities

| Capability | Endpoint | Description |
|---|---|---|
| URL scanner | `POST /api/analyze` | 15 static detectors (IP hosts, `@` tricks, punycode, lure keywords, brand impersonation, dangerous extensions, …) |
| UPI analyzer | `POST /api/analyze/upi` | Payee/amount/currency validation plus KYC, impersonation, urgency, and reward-lure language detection |
| QR analyzer | `POST /api/analyze/qr` | OpenCV decode → classify URL/UPI/text → existing analyzer; never opens anything |
| Smart Scanner | `POST /api/scan` | Auto-detects URL / UPI / text / QR image and routes to the right analyzer |
| Scan History | `GET /api/history`, `GET /api/history/stats`, `DELETE /api/history` | Sanitized metadata only (newest 500) |
| Security Dashboard | (frontend) | Totals, risk/input distributions, recent scans from the history API |
| Local intelligence | (in `/api/scan`) | Offline demo matcher: exact hostname, registrable domain, exact UPI handle |
| Optional URLhaus | (in `/api/scan`, key-gated) | One fail-safe lookup per URL scan; evidence-only, never changes the score |
| Evaluation Lab | `python -m evaluation` | 128-case offline corpus with JSON + Markdown reports |

Health/status: `GET /api/health`, `GET /api/status`.

## Architecture

```text
User Input (URL / UPI / text / QR image)
  ↓
Input Detection (deterministic router)
  ↓
URL / UPI / QR Analysis (existing analyzers; QR decodes first)
  ↓
Detectors (15 URL rules, 14 UPI rules — pure string analysis)
  ↓
Scoring (0–100, capped, every point explained)
  ↓
Risk Zone (GREEN 0–29 / YELLOW 30–69 / RED 70–100)
  ↓
Explainability (reasons + indicators + category)
  ↓
Safety Actions (verify independently / do not pay / report)
```

Optional side paths (never alter the score):

```text
Threat Intelligence  →  local matcher (+ URLhaus when configured)
Evaluation           →  offline lab measuring the analyzers above
History              →  sanitized metadata for the dashboard
```

## Security model

* **No destination fetching** — submitted URLs are never opened, redirected,
  DNS-resolved, or downloaded. The sole exception is the explicitly
  documented, key-gated URLhaus API request (threat-intel lookup only).
* **No payments** — UPI URIs are parsed, never initiated or verified.
* **No credential collection** — nothing to log into; history stores no
  passwords, tokens, full query values, payee names/notes, or QR images.
* **Input hardening** — 1 MB JSON / 10 MB upload caps with clean
  413/422/415 rejections (never truncated, never stack traces), chunked
  upload reads, image dimension caps, JSON content-type enforcement.
* **Headers** — `nosniff`, `SAMEORIGIN`, `no-referrer`, strict same-origin
  CSP (function + `vercel.json` static copy); same-origin CORS by default.
* **Frontend** — `textContent`-only rendering, no inline scripts/handlers,
  no `alert()`, no secrets.
* **External intelligence is optional** — missing key means
  `configured: false`; failures degrade to `available: false` and never
  fail a scan nor imply safety.

## Evaluation

Offline lab (`src/scamshield/evaluation/`, 128 synthetic cases: 107 URL,
15 UPI, 6 QR). Latest verified run:

* Cases: **128**, passed **104/128**
* Detection rate: **58.5%** (flagged ÷ planted threats)
* Precision: **93.9%** (threats ÷ flagged)
* Recall: **58.5%** (= detection rate by construction)
* False-positive rate: **2.7%** (flagged ÷ benign)
* TP **31**, TN **72**, FP **2**, FN **22**, explainability failures **0**

These four rates are distinct — 80% detection is **not** "80% accuracy".
The corpus is synthetic and not prevalence-representative. Residual risk
is documented per case: lone weak signals can score below the YELLOW
threshold (6 misses); keyword-heavy legitimate subdomains can over-trigger
(1 false alarm). Reports: `evaluation/results.json`, `evaluation/report.md`.

## Limitations

* Synthetic, relatively small evaluation corpus.
* Threshold-calibration findings above are by design (not patched to look better).
* Naive registrable-domain (last-two-labels) matching in local intelligence.
* URLhaus intelligence is optional and unconfigured by default.
* Vercel serverless filesystem is ephemeral: history resets on cold starts
  there (reported via the `persistent` flag); local SQLite persists.
* No authentication, no accounts, no ML — out of scope by design.

## Run locally

```powershell
pip install -r requirements.txt
uvicorn api.index:app --port 8000
# open http://localhost:8000
```

Scan a URL:

```powershell
curl -Method POST http://localhost:8000/api/analyze `
  -ContentType "application/json" `
  -Body '{"url":"https://example.com"}'
```

Optional URLhaus key (never commit one; see `.env.example`):

```powershell
$env:SCAMSHIELD_URLHAUS_AUTH_KEY="your-key-here"
```

## Run evaluation

```powershell
python -m evaluation   # from the project root
```

Regenerates `evaluation/results.json` + `evaluation/report.md`, exits
non-zero only if the evaluator itself fails. Fully offline.

## Tests

```powershell
pytest -q
```

147 tests covering analyzers, API, QR, UPI, Smart Scanner,
history, intelligence (local + mocked URLhaus), evaluation, security
regression, and presentation. No network access during tests.

## Deploy to Vercel

```powershell
vercel deploy
```

`vercel.json` routes `/api/*` to the Python function and serves `public/`
as the static site with matching security headers. No API keys or external
services required; set `SCAMSHIELD_URLHAUS_AUTH_KEY` in the Vercel project
environment only if external intelligence is wanted.
