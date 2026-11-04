# SecureChat (core build)
## Run
1. `cp .env.example server/.env` and fill in values; start MongoDB.
2. `cd server && npm i && npm run dev`
3. `cd client && npm i && npm run dev` → http://localhost:5173 (set `VITE_API_URL` if the API is elsewhere)

## Encryption architecture
Each user generates an ECDH P-256 key pair in the browser (Web Crypto). The private key is non-extractable and kept in IndexedDB; only the public JWK is sent to the server.
Per conversation, ECDH yields an AES-256-GCM key; every message uses a random 96-bit IV. The server stores and relays only `encryptedPayload` + `nonce`.
A safety number (SHA-256 of both public keys) is shown in each chat.

## Known limitations (read before relying on this)
- NOT the Signal Protocol: no prekeys, no double ratchet, **no forward secrecy**. Static-key ECDH. Not security-reviewed.
- Single device only; clearing browser storage loses your key and history. No key rotation or key-change warnings yet.
- Not yet built: media/voice, reactions, edit/delete/forward, contacts/blocking, password reset, settings page, light mode, tests.
