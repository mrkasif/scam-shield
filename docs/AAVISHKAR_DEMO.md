# ScamShield — Aavishkar Live Demo Guide (5–7 minutes)

All inputs below are synthetic and verified against the current build.
Speak in accurate terms: "static threat analysis", "rule-based
intelligence", "explainable risk scoring", "optional external threat
intelligence", "offline-capable analysis". Never claim 100% protection,
detection of every scam, or that any result guarantees safety.

Prep (30 s before judges arrive): start the app, open the page, and
generate two QR fixtures:

```powershell
uvicorn api.index:app --port 8000
python -c "import qrcode; qrcode.make('https://example.com').save('demo-url.png')"
python -c "import qrcode; qrcode.make('upi://pay?pa=shop@paytm&am=50').save('demo-upi.png')"
```

## Demo 1 — Benign URL (30 s)

* Click **Scanner**. Paste `https://example.com`. **Scan**.
* Point at: **0 / GREEN · Minimal Threat**, category benign.
* Concept: baseline — a clean structure scores near zero.
* Do NOT claim: that GREEN means "guaranteed safe".

## Demo 2 — Suspicious URL (60 s)

* Paste `http://paypal-secure-login.evil-example.tk/verify`. **Scan**.
* Point at: **61 / YELLOW · Risk Detected**, brand impersonation, the
  reason list (HTTP, hyphens, lure words, fake brand, risky query) and
  indicator chips.
* Concept: Detect → Explain → Protect; every point is named.
* Do NOT claim: the site was visited (it never is).

## Demo 3 — UPI (60 s)

* Paste `upi://pay?pa=shop@paytm&am=50` → **0 / GREEN**, parsed payee shown.
* Paste `upi://pay?pa=x@ybl&tn=Complete%20KYC%20now` → **YELLOW**,
  KYC/authority language flagged.
* Concept: the destination is analyzed without initiating any payment.
* Do NOT claim: the payee account was verified (it never is).

## Demo 4 — QR (45 s)

* In Scanner, upload `demo-url.png` → decoded payload + GREEN analysis.
* Upload `demo-upi.png` → decoded URI + payment analysis.
* Concept: pixels → text → the same analyzers; destinations never opened.
* Do NOT claim: QR scanning makes a code trustworthy.

## Demo 5 — Intelligence (30 s)

* Scan `https://malicious.example/x`: low structural score **and** a Local
  Intelligence match (`malicious.example`, demo dataset).
* Concept: intelligence is separate evidence, shown beside the score —
  it never silently changes it.
* Do NOT claim: a non-match means safe.

## Demo 6 — Dashboard/History (30 s)

* Click **Dashboard**: totals, GREEN/YELLOW/RED bars, input mix, recent
  scans table; click a row for sanitized detail.
* Concept: only metadata + sanitized previews are stored — no passwords,
  no query values, no images.

## Demo 7 — Evaluation (30 s)

* Click **Evidence**: 128 cases, 104/128, detection 58.5%, precision 93.9%,
  recall 58.5%, FP 2, FN 22, 0 explainability failures.
* Say: synthetic corpus, transparent misses, `python -m evaluation`
  reproduces it offline.
* Do NOT call it accuracy or compare against other products.

## If something fails live

* API error box: read the message aloud — errors are clean by design.
* Backend down: `GET /api/health` in a second tab; restart uvicorn.
* Fallback: `evaluation/report.md` and this guide stand alone as evidence.
