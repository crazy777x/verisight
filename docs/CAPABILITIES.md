# VeriSight v6: verification capabilities and limits

## What a result means
| Status | Meaning in this prototype |
|---|---|
| VERIFIED | Needs ALL of: trusted signature (pinned key), pinned issuer, live status ACTIVE from an *authoritative* provider, valid printed dates, consistent fields, fields confirmed by the operator, known document type. Without a connected issuer API this status cannot be reached. |
| INVALID | A reliable check fails: signature does not match payload, or the dates are impossible. |
| EXPIRED | Printed expiry passed (or an authoritative source says so). Date-only expiry = end of that day, in the permit's time zone (IST assumed and reported when absent). |
| REVOKED / SUSPENDED | Only when an authoritative issuer provider says so. A non-authoritative provider is ignored. |
| REVIEW REQUIRED | Mismatch between QR and print, several different QR codes, malformed QR, not-yet-valid permit, duplicate *indicator*, movement-rule violation, review-level forensic indicator, unconfirmed fields. |
| UNVERIFIABLE | Default. Nothing found wrong, but nothing proves authenticity either. Shows **LIVE ISSUER STATUS NOT VERIFIED**. |

Each check (extraction, QR, QR-vs-print, signature, issuer trust, dates, live status, movement, duplicates, forensics) is reported separately and marked
PASSED / FAILED / ATTENTION / INFO / NOT APPLICABLE / NOT AVAILABLE. NOT APPLICABLE is never a failure.

## Real
- Purpose + document-type selection, per-type applicability table (`lib/purposes.ts`).
- Date / validity / daily-window / permitted-day / single-entry / entry-point rules (`lib/permit.ts`).
- QR payload parsing (JSON, key=value, link, VSP1 demo envelope), truncation / ambiguity detection, QR-vs-print comparison.
- For PAN cards, recognizable fields in a decoded QR are compared with OCR-read PAN/name. This does not validate an official PAN QR format or prove issuer authenticity; a match does not lower review risk.
- For non-Aadhaar/PAN travel documents, supported passport TD1/TD3 and 44-character MRV-A visa MRZ check digits are checked when OCR/manual extraction supplies the MRZ. A matching MRZ is not issuer authentication.
- Vehicle registration numbers receive a broad Indian state/RTO shape check; chassis/VIN and engine values receive plausibility-only checks. Cargo HSN digit length (4/6/8), quantity and value receive structural checks only; no VAHAN, manufacturer, tariff, customs, or issuer records are queried.
- Permit expiry/issue date ranges, QR/barcode decoding, QR-to-field comparisons, PDF signature integrity, and image ELA/noise/copy-move/metadata heuristics are available in the permit and triage workflows. Detected forensic regions are shown in the tamper viewer; no region is fabricated when none is detected.
- ECDSA P-256 signature check for the **VSP1 demo envelope**, with a pinned-key trust list.
- QR links are never opened; private / metadata / credentialed / punycode URLs are flagged.
- File validation by size, type and magic bytes (`lib/upload.ts`).
- Existing: OCR (Tesseract), QR (BarcodeDetector / jsQR / ZXing), Aadhaar Verhoeff + Secure-QR signature, MRZ checksum, ELA / noise / copy-move, metadata, PDF signature, risk policy.

## NOT real / not connected (never simulated)
- No government or issuer API (UIDAI, Sarathi, VAHAN, customs, forest, border authority). Live status is always "not verified".
- **VSP1 is a VeriSight demo format, not an official border-pass QR specification.** No official format is assumed. Real permits will usually be reported as "unsupported format" or "unsigned".
- Duplicate checks compare only with records saved in this browser. No cross-checkpoint or national duplicate detection.
- Government-ID, visa, border-pass, corporate-access and certificate layout authenticity is not established by generic OCR or a visually plausible field shape. Issuer-specific templates, approved model weights, training data and authorised status/signature sources are not configured.
- Local movement records are browser storage, not tamper-proof, not official.
- Several QR codes on one page can be told apart only where the browser has BarcodeDetector (Chrome / Edge / Android); elsewhere only the first code is read and the UI says so.
- Analysis still runs in the browser (see CHANGES.md v5): the server cannot re-check a risk number.
- PAN / Voter ID / DL have no public checksum or issuer signature here: PAN format and generic QR-field comparisons only.
- Photograph comparison is the existing Biometric tab; no new face model was added.
- Forensics are heuristics: recompression, screenshots and scans can trigger them, and missing metadata is never evidence.
