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
- ECDSA P-256 signature check for the **VSP1 demo envelope**, with a pinned-key trust list.
- QR links are never opened; private / metadata / credentialed / punycode URLs are flagged.
- File validation by size, type and magic bytes (`lib/upload.ts`).
- Existing: OCR (Tesseract), QR (BarcodeDetector / jsQR / ZXing), Aadhaar Verhoeff + Secure-QR signature, MRZ checksum, ELA / noise / copy-move, metadata, PDF signature, risk policy.

## NOT real / not connected (never simulated)
- No government or issuer API (UIDAI, Sarathi, VAHAN, customs, forest, border authority). Live status is always "not verified".
- **VSP1 is a VeriSight demo format, not an official border-pass QR specification.** No official format is assumed. Real permits will usually be reported as "unsupported format" or "unsigned".
- Duplicate checks compare only with records saved in this browser. No cross-checkpoint or national duplicate detection.
- Local movement records are browser storage, not tamper-proof, not official.
- Several QR codes on one page can be told apart only where the browser has BarcodeDetector (Chrome / Edge / Android); elsewhere only the first code is read and the UI says so.
- Analysis still runs in the browser (see CHANGES.md v5): the server cannot re-check a risk number.
- PAN / Voter ID / DL have no public checksum or issuer signature here: PAN format and generic QR-field comparisons only.
- Photograph comparison is the existing Biometric tab; no new face model was added.
- Forensics are heuristics: recompression, screenshots and scans can trigger them, and missing metadata is never evidence.
