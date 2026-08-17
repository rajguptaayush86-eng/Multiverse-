The Multiverse Portal — free full-stack build
This folder adds a real Node/Express backend to the cinematic portal.
Run locally
Install Node.js 20+.
Open this folder in Terminal.
Run npm install.
Copy .env.example to .env and set JWT_SECRET to a long random value.
Run npm start.
Open http://localhost:3000.
The SQLite database is created automatically in data/multiverse.db. Uploaded image/video/audio files go to uploads/.
Backend included
Account registration/login/logout using bcrypt password hashing.
HttpOnly JWT session cookie.
Server-side universe storage in SQLite.
Public/unlisted/private/invite/password visibility fields.
Owner/editor checks for universe updates.
Version snapshots and audit log APIs.
Media upload endpoint for image/video/audio.
External-universe URL records can be stored and opened by the frontend.
Helmet security headers and upload size/type checks.
Health endpoint.
Important production note
This is a free local/deployable starter, not a claim that every production requirement from the master prompt is magically solved by one package. For a public production deployment, use HTTPS, a strong secret, secure cookies, a managed database/object store, rate limiting, CSRF/origin protections where appropriate, email verification, password-reset flow, passkeys/WebAuthn, moderation, backups, and a proper real-time collaboration layer (WebSocket/CRDT). Do not put database credentials in browser code.
