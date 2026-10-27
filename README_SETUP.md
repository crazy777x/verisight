# VeriSight: setup

```
cd verisight-v6                    # when starting from the repository folder
npm install
cp .env.example .env.local          # Windows: copy .env.example .env.local
# 1. put a random 32+ char value in SESSION_SECRET
# 2. create your own accounts (bundled demo login is listed below):
node scripts/create-user.mjs OFF-0001 officer      "a-long-passphrase-123"
node scripts/create-user.mjs INV-0001 investigator "another-long-pass-456" 123456
node scripts/create-user.mjs ADM-0001 admin        "third-long-pass-789"   654321
# 3. (to get "UIDAI VERIFIED") download the UIDAI certificate, confirm it from a source you trust, then:
node scripts/fingerprint.mjs uidai.cer uidai
# 4. To trust a specific Aadhaar PDF signer, obtain its certificate from an authoritative source and confirm it:
node scripts/fingerprint.mjs aadhaar-pdf-signer.cer aadhaar-pdf-signer
# Or pin a verified CCA root/intermediate instead:
node scripts/fingerprint.mjs cca-root.cer pdf-root
# Pin the certificate DER or public-key SPKI SHA-256 fingerprint shown above in .env.local.
# Restart/rebuild the app after changing environment variables.
npm run dev                                 # http://localhost:3000
npm test                                    # 104 automated tests
```
The web app runs at `http://localhost:3000`. The `/api/verify-document` route forwards authenticated uploads to the Python service. To use it, install `backend/requirements.txt` from the repository folder, configure the AWS S3 environment variables required by `backend/services/s3_service.py`, then start `backend/app.py` in a second terminal. The default backend URL is `http://127.0.0.1:5000`; set `VERISIGHT_BACKEND_URL` in `.env.local` if it is hosted elsewhere. If the Python service is stopped, the route returns a clear `503` instead of a `404`.
Do not trust a certificate based only on its displayed name or because it is embedded in the PDF. PDF CA roots are pinned by certificate DER or public-key SPKI SHA-256 fingerprint; an Aadhaar PDF signer pin applies only to Aadhaar PDFs. Without an applicable verified fingerprint, a valid PDF signature remains untrusted.
For image uploads, OCR, QR discovery, metadata markers and pixel-forensics checks run on supported JPEG, PNG, WEBP and TIFF files, including images with missing EXIF. UIDAI certificate verification applies only to Aadhaar Secure QR codes. Pixel/metadata checks are indicators for review, not a guarantee that an image is original: AI/editing metadata can be removed, and recompression or camera processing can resemble edits. An AI metadata marker triggers review, not an automatic rejection.
Investigator / admin accounts have a personal override PIN (the last argument). Officers have none.
Users, queue and audit log are stored in `./data` (git-ignored). Back it up; delete `data/` to reset.

## Workflow (v6)
1. Select verification purpose, 2. select document type (or let auto-detect *suggest* one), 3. upload, 4. review and confirm the extracted fields,
5. run the applicable checks, 6. read the report. Identity documents go through **Document Triage**; passes and permits through **Border Pass & Permit**.
Changing purpose or type keeps the uploaded file. See `docs/CAPABILITIES.md` for what is and is not verified.
After a non-Aadhaar document check, an optional Aadhaar cross-check is available. The existing UIDAI key, signature verification, Aadhaar QR-to-print checks, and Aadhaar verdict logic are reused unchanged; the Aadhaar result is trusted as a comparison source only if that existing verdict reports UIDAI verification. Only common readable identity fields are compared, and a cross-document match does not prove that the other document was issued by its authority.

## Demo login
The bundled demo account is **ID `OFF1` / password `officer2006`**. It is an officer account and works with normal login; `DEMO_MODE` does not need to be enabled.

## Open demo mode (no database needed)
Alternatively, setting `DEMO_MODE=true` (hosting environment variables, plus `SESSION_SECRET` in production) allows **any operator ID + any passphrase to log in**.
- ID starting with `OFF` = officer, starting with `INV` = investigator, anything else = admin (e.g. `ADMIN` / `1234`).
- For overrides, any PIN of 4+ characters works.

**DEMO_MODE is completely open. Never set it in a real deployment. The bundled demo account is also public; use only with sample data.**

## Going live (client / government)
Do not set `DEMO_MODE`. The client's developer replaces `loadUsers()` in `lib/server/auth.ts` (and the file read/write calls in `queue.ts` / `audit.ts`) with their database or SSO.
Roles, lockout, PIN rules and sessions stay unchanged.
