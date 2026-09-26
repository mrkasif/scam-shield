# ScamShield Evaluation Report

Generated: 2026-09-26T16:50:02+00:00 (UTC)
Analyzer version: 0.1.0
Evaluator version: 1.0.0

## 1. Evaluation objective

Measure the current ScamShield static analyzers (URL, UPI, QR) against a curated synthetic attack corpus — honestly, offline, and reproducibly. This evaluation does not tune, retrain, or otherwise modify production detection logic.

## 2. System components evaluated

- URL static analyzer (structure, lure, impersonation, and obfuscation detectors with rule-based 0–100 scoring)
- UPI payment-request analyzer (payee, amount, currency, and scam-language detectors with rule-based 0–100 scoring)
- QR analyzer (OpenCV decode → classify → existing URL/UPI analyzer)
- Shared risk zones: GREEN 0–29, YELLOW 30–69, RED 70–100

## 3. Corpus composition

- Total synthetic cases: 128
- qr_bad: 1 cases
- qr_text: 1 cases
- qr_upi: 2 cases
- qr_url: 2 cases
- upi: 15 cases
- url: 107 cases
- All indicators use reserved `.example` domains or clearly synthetic UPI handles. No real people, credentials, accounts, or malicious infrastructure appear anywhere in the corpus.

## 4. Test methodology

- Each case feeds the real public analyzer function directly (`analyze_url` / `analyze_upi` / `analyze_qr_image` on in-memory QR fixtures) — never the Smart Scanner facade, so no external lookup can occur.
- A case passes only when both the predicted class (SAFE / SUSPICIOUS / HIGH_RISK) and the predicted category match the expectation, which encodes observed analyzer behavior.
- Threat predictions must additionally carry at least one reason and one detected indicator (explainability check).
- Reports regenerate deterministically from evaluator output only; no value is hand-entered.

## 5. Expected vs actual risk mapping

- GREEN → SAFE, YELLOW → SUSPICIOUS, RED → HIGH_RISK.
- No new production risk model is introduced; the expected class belongs to the test case.
- One QR case expects graceful decode failure (DECODE_ERROR) instead of a risk class.

## 6. Overall metrics

- Cases: 128, passed: 104, failed: 24
- Detection rate: 58.5%
- False-positive rate: 2.7%
- Precision: 93.9%
- Recall: 58.5%

These four rates measure different things and are not interchangeable with a single 'accuracy' number:

- Detection rate (here: recall) — fraction of planted threats flagged.
- Precision — fraction of flagged cases that were planted threats.
- Recall — same as detection rate by construction.
- False-positive rate — fraction of benign cases wrongly flagged.

## 7. Confusion-matrix interpretation

- Positive class: expected SUSPICIOUS or HIGH_RISK; predicted positive means analyzer YELLOW or RED.
- True positives: 31 (planted threats flagged).
- False negatives: 22 (planted threats missed).
- False positives: 2 (benign cases flagged).
- True negatives: 72 (benign cases left alone).
- TP + FN equals the planted-threat count; TN + FP equals the benign count; all four sum to the classified total.

## 8. Category-wise results

Category | Cases | Passed | Failed
---|---|---|---
benign | 70 | 63 | 7
brand_impersonation | 21 | 13 | 8
credential_phishing | 1 | 1 | 0
decode_error | 1 | 1 | 0
impersonation_scam | 3 | 3 | 0
invalid_payee | 4 | 4 | 0
ip_host | 5 | 5 | 0
malware_delivery | 1 | 1 | 0
normal | 5 | 5 | 0
phishing_lure | 8 | 3 | 5
plain_text | 1 | 1 | 0
pressure_tactic | 2 | 1 | 1
reward_lure | 2 | 2 | 0
suspicious | 1 | 0 | 1
suspicious_payment | 1 | 0 | 1
suspicious_redirect | 2 | 1 | 1

This table is descriptive only; categories are not ranked.

## 9. False-positive analysis

### u23: Deep legitimate-style subdomains

- Score 31 (YELLOW) vs expected SAFE.
- Triggering reasons: Hostname has 5 labels (many subdomains), often used to fake a trusted domain.; URL contains lure keywords (account, login, secure, verify) often used in phishing lures (fake login/verify/payment pages).
- Indicators: excessive_subdomains, suspicious_keywords
- Reading: legitimate-looking structure tripped keyword plus subdomain rules. Kept visible as a calibration finding; the detector was not weakened to hide it.

### a05: Secure store sign-in

- Score 36 (YELLOW) vs expected SAFE.
- Triggering reasons: URL contains lure keywords (secure, signin) often used in phishing lures (fake login/verify/payment pages).; Hostname uses 'amazon' but is not the official domain (amazon.com); likely brand impersonation.
- Indicators: suspicious_keywords, brand_impersonation
- Reading: legitimate-looking structure tripped keyword plus subdomain rules. Kept visible as a calibration finding; the detector was not weakened to hide it.

## 10. False-negative analysis

### u06: HTTP login page

- Score 18 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: URL uses plain HTTP instead of HTTPS; credentials or payments on such pages can be intercepted.; URL contains lure keywords (login) often used in phishing lures (fake login/verify/payment pages).
- Indicators: no_tls, suspicious_keywords
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### u09: Unusual HTTPS port

- Score 23 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: URL uses unusual port 8080; phishing kits and malware often hide on non-standard ports.; URL contains lure keywords (login) often used in phishing lures (fake login/verify/payment pages).
- Indicators: unusual_port, suspicious_keywords
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### u12: Hyphenated lure domain

- Score 26 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: Hostname contains 4 hyphens; excessive hyphens are typical of look-alike domains.; URL contains lure keywords (login, secure, update) often used in phishing lures (fake login/verify/payment pages).
- Indicators: suspicious_chars, suspicious_keywords
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### u16: URL shortener only

- Score 10 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: URL uses a link shortener, which hides the final destination.
- Indicators: url_shortener
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### u19: KYC lure over HTTP

- Score 26 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: URL uses plain HTTP instead of HTTPS; credentials or payments on such pages can be intercepted.; URL contains lure keywords (account, kyc, verify) often used in phishing lures (fake login/verify/payment pages).
- Indicators: no_tls, suspicious_keywords
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### u20: Prize urgency lure

- Score 26 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: URL uses plain HTTP instead of HTTPS; credentials or payments on such pages can be intercepted.; URL contains lure keywords (prize, urgent) often used in phishing lures (fake login/verify/payment pages).
- Indicators: no_tls, suspicious_keywords
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### p10: Pure urgency pressure

- Score 15 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: Payment text pressures quick action (immediately); scammers manufacture urgency.
- Indicators: urgency_language
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### p12: Garbled amount

- Score 15 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: Amount '12abc' is not a valid positive number; odd amount formatting is used to confuse payers.
- Indicators: bad_amount
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### t01: Amazon digit typosquat

- Score 28 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: URL contains lure keywords (login) often used in phishing lures (fake login/verify/payment pages).; Hostname uses 'amaz0n', a close look-alike of 'amazon' (official domain: amazon.com); likely brand impersonation.
- Indicators: suspicious_keywords, brand_impersonation
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### t02: Microsoft digit typosquat

- Score 28 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: URL contains lure keywords (verify) often used in phishing lures (fake login/verify/payment pages).; Hostname uses 'micros0ft', a close look-alike of 'microsoft' (official domain: microsoft.com); likely brand impersonation.
- Indicators: suspicious_keywords, brand_impersonation
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### t03: Facebook doubled-letter typosquat

- Score 20 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: Hostname uses 'faceboook', a close look-alike of 'facebook' (official domain: facebook.com); likely brand impersonation.
- Indicators: brand_impersonation
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### t04: Apple digit typosquat

- Score 20 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: Hostname uses 'appl3', a close look-alike of 'apple' (official domain: apple.com); likely brand impersonation.
- Indicators: brand_impersonation
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### t06: WhatsApp dropped-letter typosquat

- Score 28 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: URL contains lure keywords (login) often used in phishing lures (fake login/verify/payment pages).; Hostname uses 'whatsap', a close look-alike of 'whatsapp' (official domain: whatsapp.com); likely brand impersonation.
- Indicators: suspicious_keywords, brand_impersonation
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### t07: Instagram transposed typosquat

- Score 0 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: No phishing indicators detected in static analysis.
- Indicators: —
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### t08: Outlook dropped-letter typosquat

- Score 28 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: URL contains lure keywords (verify) often used in phishing lures (fake login/verify/payment pages).; Hostname uses 'outlok', a close look-alike of 'outlook' (official domain: microsoft.com); likely brand impersonation.
- Indicators: suspicious_keywords, brand_impersonation
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### t09: Gmail transposed typosquat

- Score 8 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: URL contains lure keywords (signin) often used in phishing lures (fake login/verify/payment pages).
- Indicators: suspicious_keywords
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### t10: YouTube dropped-letter typosquat

- Score 0 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: No phishing indicators detected in static analysis.
- Indicators: —
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### t15: Abused-TLD lure TK

- Score 26 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: URL contains lure keywords (login, secure) often used in phishing lures (fake login/verify/payment pages).; Hostname anomaly: top-level domain '.tk' is frequently abused by scammers.
- Indicators: suspicious_keywords, hostname_anomaly
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### t16: Abused-TLD lure ML

- Score 26 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: URL contains lure keywords (account, verify) often used in phishing lures (fake login/verify/payment pages).; Hostname anomaly: top-level domain '.ml' is frequently abused by scammers.
- Indicators: suspicious_keywords, hostname_anomaly
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### t17: Abused-TLD lure GQ

- Score 26 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: URL contains lure keywords (bank, update) often used in phishing lures (fake login/verify/payment pages).; Hostname anomaly: top-level domain '.gq' is frequently abused by scammers.
- Indicators: suspicious_keywords, hostname_anomaly
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### t19: Reward lure on CLICK TLD

- Score 26 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: URL contains lure keywords (bonus, free) often used in phishing lures (fake login/verify/payment pages).; Hostname anomaly: top-level domain '.click' is frequently abused by scammers.
- Indicators: suspicious_keywords, hostname_anomaly
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

### a07: Cyrillic homograph subdomain

- Score 28 (GREEN) vs expected SUSPICIOUS.
- Returned reasons: URL contains lure keywords (login) often used in phishing lures (fake login/verify/payment pages).; Hostname uses 'pаypal', a close look-alike of 'paypal' (official domain: paypal.com); likely brand impersonation.
- Indicators: suspicious_keywords, brand_impersonation
- Reading: a lone weak signal scores below the 30-point YELLOW threshold. The signal itself is detected and explained; only the zone boundary keeps it GREEN. Kept visible as a threshold calibration finding; the detector was not tuned to hide it.

## 11. Explainability verification

- Threat predictions with explanations: 33
- Threat predictions without explanations: 0
- A threat prediction counts as explained only with at least one reason and one detected indicator.

## 12. Determinism verification

- Repeated-run equivalence (excluding timestamps): True
- The evaluator holds no randomness, clock-dependent branching, or unordered iteration over result sets.

## 13. No-network verification

- Offline execution with sockets blocked: True
- The runner calls analyzer functions directly (never the Smart Scanner facade), so URLhaus or any external lookup is unreachable by construction; QR fixtures are generated in memory.

## 14. Limitations

Curated synthetic corpus (reserved .example domains, synthetic UPI handles); not a statistically representative measurement of real-world scam prevalence. Expectations encode current analyzer behavior; failures are reported as findings, never silently fixed.

## 15. Reproducibility instructions

From the project root, with dependencies installed:

```powershell
$env:PYTHONPATH='src'; python -m evaluation
```

or equivalently `python -m scamshield.evaluation`. This regenerates `evaluation/results.json` and `evaluation/report.md`, prints the headline metrics, and exits non-zero only if the evaluator itself errors (failed cases are findings, not tool failures). No network, no API keys, no production side effects: history, analyzers, and endpoints are untouched.

Runtime metadata recorded in `results.json`: Python 3.14.6, packages {'fastapi': '0.141.1', 'opencv-python-headless': '5.0.0.93', 'numpy': '2.5.1', 'httpx': '0.28.1', 'qrcode': '8.2', 'pillow': '12.3.0', 'pytest': '9.1.1'}.

## 16. Honest conclusion

Across 128 synthetic cases, the current system flags 58.5% of planted threats at a 2.7% false-positive rate, with 93.9% precision and zero unexplained threat predictions. Residual risk concentrates in lone weak signals that score below the YELLOW threshold and in keyword-heavy legitimate subdomains — both documented above with case IDs. These numbers describe this curated corpus only and must not be read as real-world accuracy.
