# VeriSight v6: purpose / document-type workflow + Border Pass & Permit module

Built on v5 (nothing rebuilt, no framework or library replaced, no Supabase, no new dependency). All v5 behaviour and tests are kept.

## Added
- **Select Verification Purpose** (14 purposes) and **Select Document Type** (26 types + auto-detect + other) at the top of Document Triage and the new tab. Auto-detect only *suggests*; the operator confirms. Types adapt to the purpose, every other type stays reachable. Changing either keeps the uploaded file.
- **Border Pass & Permit** tab: upload, OCR field extraction (labelled lines only, ambiguous readings flagged, nothing guessed), operator confirmation of fields, QR / signature / issuer / dates / movement / duplicates / forensics as independent rows, final status, evidence, limits, timestamp, local movement record.
- New files: `lib/purposes.ts`, `lib/permit.ts`, `lib/upload.ts`, `lib/qrmulti.ts`, `components/verisight/{selection-panel,permit-panel}.tsx`, `tests/permit.test.ts`, `docs/CAPABILITIES.md`.

## Existing problems found and fixed
1. Upload checked only the file name / MIME type: a renamed or corrupted file got into the pipeline. Now size + type + magic bytes (`lib/upload.ts`), used by Triage and the permit tab.
2. One hard-wired document dropdown in Triage that ignored purpose. Replaced by the shared selector; Triage maps identity types to its existing engine and points other types to the permit tab.
3. Existing QR scanner stops at the first code, so "two different QR codes" could never be noticed. Added `scanQrMulti` (extra codes only where BarcodeDetector exists; the UI says when it cannot).

## Known, NOT changed
- Login / IP throttle reads `x-forwarded-for`, which a client can forge unless a trusted proxy overwrites it. The per-account lockout still holds.
- `data/*.json` storage, browser-side analysis, CDN-loaded OCR/QR libraries (see v5 notes).

# VeriSight v5: fixes from the security review

| # | Review finding | What was done | Status |
|---|---|---|---|
| 1 | Login accepted any ID + 8 chars | Real server-side login (`/api/auth/login`): scrypt-hashed passphrases in `data/users.json`, role comes from the user record (the role picker is gone), HMAC-signed httpOnly SameSite=Strict cookie, 8 h expiry, 5-failure lockout per account and per IP, origin check on every POST | Fixed (needs `npm run create-user`) |
| 1b | Admin / investigator rights only in the UI | `/api/audit` and `/api/queue` (read) refuse officers; `/api/queue/resolve` is investigator/admin only; every rule is re-checked on the server | Fixed |
| 2 | Any certificate accepted as "UIDAI" | Certificate must be on a pinned SHA-256 trust list (`NEXT_PUBLIC_UIDAI_TRUSTED_SHA256`), valid today. Otherwise the result is **"valid-untrusted"** and the card is never shown as UIDAI VERIFIED | Fixed (you must configure the pin) |
| 3 | Risk policy inconsistent | One explicit table in `lib/policy.ts` (code + severity -> forced minimum risk). Only a trusted-signature failure and a declared AI marker can LOCK alone; QR mismatch / broken PDF signature / bad checksum force REVIEW; ELA and metadata are supporting only | Fixed, 20 policy tests |
| 4 | PDF trust chain missing | Embedded chain is verified certificate by certificate up to a pinned root (`NEXT_PUBLIC_PDF_TRUSTED_ROOTS_SHA256`). Valid signature + untrusted signer is never "authentic". Revocation (CRL/OCSP) is NOT checked | Partly fixed |
| 5 | ELA limits | ELA/noise are supporting evidence only (cap 35 on a camera JPEG, 8 on screenshots) and can never review/lock alone | Fixed in logic; **precision / recall still need your dataset** |
| 6 | Audit in localStorage | Audit log and review queue now live on the server: append-only, SHA-256 hash chain, server timestamps, actor taken from the session, chain verified on every read (a tampered file is detected) | Fixed for a single server; use a real DB for production |

Overrides on the server: investigator/admin only, written reason (10+ chars), personal PIN (3 wrong tries = 15 min lock), no self-approval, SAFE-LOCK (risk >= 70) can never be released, one decision per entry, every refusal logged.

Found by the new tests: a lock-in-lock deadlock in the first server draft (fixed).

## Still NOT solved (do not claim otherwise)
- **Analysis runs in the browser, so the risk number is reported by the browser.** The server enforces who may do what, but cannot re-check the analysis. Real production needs server-side analysis.
- No real genuine/forged dataset was available: detection accuracy is untested on real forgeries.
- Face matching reliability is untested; PAN / DL / Voter ID have no public checksum.
- OCR / QR / face libraries still load from a CDN on first run.
- Passwords reset = delete the user in `data/users.json` and re-run `create-user`.

# VeriSight v4: what changed (fixes after real-document testing)

## Why your genuine e-Aadhaar screenshot was marked "LIKELY FORGED" (risk 75)
1. **Fake "MRZ checksum FAILED (4 fields)"** – the OCR ran a letters-only pass over the address text ("At Prabhat Patan Post...") and the old MRZ finder accepted *any* 30-char line containing "<". Fixed in `lib/analysis.ts`: an MRZ must now have the exact ICAO structure (44 / 30 chars, digits only at fixed slots, "<<" name separator). An Indian ID (Aadhaar / PAN / DL / Voter) is never searched for an MRZ at all. Tested: the address text from your screenshot is rejected, real ICAO TD3 / TD1 samples are still detected and checksummed.
2. **"4 edited areas" were the Aadhaar logo and the scissor icon** – vector artwork always differs in compression/noise from text. `lib/tamper.ts` now drops regions that are flat, strongly coloured artwork.
3. **Screenshot treated as an "original JPEG"** – ELA/noise now count as strong evidence only for an untouched camera/scanner JPEG (new `lib/metadata.ts`). On screenshots, exports, PDF renders and re-saved images they are advisory, capped at 8 risk points, and can never lock a document alone.
4. **"No QR" on a small screenshot was scored like a forgery** – a QR that is too small to decode (< ~300 px) is now "cannot verify, upload original PDF", not "fake". A big, clearly visible QR that still decodes to nothing stays CRITICAL.
Result for your screenshot: risk ~35 (below review), headline "NOT PROVEN GENUINE · NO FORGERY EVIDENCE", with the reason and the fix (upload the original PDF).

## How a genuine document is now proven (trust ladder)
1. PDF input: embedded CMS digital signature (hash + signer RSA) is verified.
2. Aadhaar Secure QR is decoded and its **RSA signature is checked with the UIDAI certificate** (load it once from uidai.gov.in; used everywhere).
3. QR data is compared with the printed name / DOB / gender / pincode.
4. Face on the card vs face in the QR / reference photo (Biometric tab).
5. Only when 2 is verified does the headline become **"AUTHENTIC · UIDAI SIGNATURE VERIFIED"**.
Tested offline with a synthetic signed QR: valid cert -> verified, wrong cert -> invalid.

## New: metadata, AI-generated and editing checks
`lib/metadata.ts` + new panel "Metadata · Source · AI-generation check": camera/scanner EXIF, software tag, PDF producer/creator, creation vs modification date, number of saved revisions, C2PA content credentials, and declared AI markers (IPTC AI source type, Midjourney / Stable Diffusion / DALL·E / Firefly / OpenAI tags). A declared AI marker is CRITICAL (locks). Editor names only count when they sit in the metadata fields. Missing metadata is never used as evidence.

## Other fixes
- **No more automatic page jumping.** The countdown is gone; a "Next: ..." button appears and you decide when to move. Step ticks for QR are only set when a QR was really checked.
- Aadhaar is recognised from keywords (UIDAI / Aadhaar) even when the 12-digit number cannot be read.
- The header no longer claims "AIR-GAP VERIFIED": files stay in your browser (LOCAL PROCESSING), but OCR/QR/face libraries load from a CDN on first run, so the first run needs internet.
- Deleted stale compiled `lib/*.js` copies (duplicates of the .ts files).
- New look: ink-navy theme, tricolour header strip, Manrope + JetBrains Mono, rounder panels, sentence-case headings.

## Honest limits (read before submitting)
- A **screenshot or JPG can never prove an Aadhaar is genuine**: it has no PDF signature and its QR is usually too small. Use the original e-Aadhaar PDF (password: first 4 letters of name in CAPITALS + birth year) for real verification.
- PAN / DL / Voter ID have no public checksum or signature: a pass means "format possible", not "genuine".
- Trust chain of the PDF signer to a root CA is not checked offline.
- Thresholds are heuristics (`lib/tamper.ts` TUNE, `lib/verdict.ts` points). Test on your own genuine and forged samples.
- Safe-Lock is client-side (localStorage); a real deployment needs a server database.


## Your reported bugs
1. **Name OCR gave garbage ("AIT AATETT ALY ggdaTA") / "not read"**
   - e-Aadhaar PDFs now use the **PDF text layer** (exact text, no OCR guessing). OCR only fills gaps.
   - Single-word names ("Sumit") are accepted when they sit above DOB / gender.
   - Every OCR name is re-read on its own line (tight crop, letters only) and must pass a plausibility test. Garbage is **rejected and shown as "not read"** instead of a wrong name. (lib/docs.ts `plausibleName`, lib/analysis.ts `reReadNameLine`)
2. **Elon Musk fake card: "No QR"** – a new detector (lib/qrpattern.ts) finds the three QR finder squares.
   The card now says **"QR-shaped picture present but contains NO readable data"** (CRITICAL, +45) instead of a vague "No QR".
   Decoder also tries rotated pages (±6…24°), tolerates offline CDN failure.
   Result for that card: risk 99, LIKELY FORGED, SAFE-LOCKED.
3. **Auto page flow** – Triage → QR & Signature → Biometric → Case Records move on by themselves
   (4–6 s countdown, "Stay here" / "Go now" buttons). Step bar under the tabs shows progress.
   A failed QR check pauses auto-advance. (components/verisight/workflow.tsx)
4. **QR tab redesign** – UIDAI certificate, QR image / triage QR and raw payload are now ONE "Verification Inputs" panel
   and ONE "Verification Checklist" report. Loading the certificate re-verifies instantly. The certificate is shared with
   Document Triage (load once, used everywhere), and expiry is checked.
5. **Anti-bribery Safe-Lock**
   - risk ≥ 70: decision locked by the system. Override button disabled for **every role incl. admin**. Only "Lock & Detain" remains.
   - risk 40–69: goes to the queue as REVIEW; Investigator / Admin may override with PIN + written justification (logged).
   - Enforced inside the store (`resolve`), not only in the UI. Records carry a tamper-evident seal; if localStorage is edited
     (risk lowered, status set to approved) the lock is forced back and `SEAL_BROKEN_FORCED_LOCK` is written to the audit chain.
   - Demo PIN hint removed from the screen; set `NEXT_PUBLIC_OVERRIDE_PIN` (see .env.example).

## New document support (PAN and others)
- **PAN**: format AAAAA9999A, valid holder-type letter (4th), 5th letter vs surname, OCR O/0 I/1 S/5 B/8 repair.
- **Driving licence**: SS-RR-YYYY-NNNNNNN, real state code, issue year not in the future.
- **Voter ID (EPIC)**: 3 letters + 7 digits, dummy-serial check.
- **All documents**: impossible / future DOB, editing-software fingerprints, ELA / noise / copy-move localisation, PDF signature check.
- Document type is auto-detected, or pick it manually.

## Honest limits (please read)
- PAN / DL / EPIC have **no public checksum**. A pass means "format is possible", never "genuine".
- Only an **Aadhaar Secure QR verified with the UIDAI certificate** is cryptographic proof. Load the certificate from uidai.gov.in.
- A genuine card whose QR is too small / blurry can look like "unreadable QR": re-scan before rejecting. The text says so.
- Safe-Lock is client-side (localStorage). It stops officers using the UI and makes edits visible, but a determined person with
  devtools can still wipe the browser data. For real deployment move queue + audit + PIN check to a server database.
- Thresholds are heuristics (TUNE in lib/tamper.ts). Calibrate on your own genuine + forged samples.
