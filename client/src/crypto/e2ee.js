// Web Crypto only (no custom primitives). ECDH P-256 -> AES-256-GCM.
// NOTE: static-key ECDH: NO forward secrecy, NOT the Signal Protocol. See README limitations.
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const db = () => new Promise((res, rej) => { const r = indexedDB.open('securechat', 1);
  r.onupgradeneeded = () => r.result.createObjectStore('keys'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
const idb = async (mode, fn) => { const d = await db(); return new Promise((res, rej) => { const t = d.transaction('keys', mode); const q = fn(t.objectStore('keys')); t.oncomplete = () => res(q?.result); t.onerror = () => rej(t.error); }); };

// Private key is non-extractable and stays in this browser's IndexedDB; never sent anywhere.
export async function createIdentity(userTag) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey']);
  await idb('readwrite', (s) => s.put(kp.privateKey, 'priv:' + userTag));
  return crypto.subtle.exportKey('jwk', kp.publicKey);
}
export const hasIdentity = async (userTag) => !!(await idb('readonly', (s) => s.get('priv:' + userTag)));
const cache = new Map();
async function sharedKey(myTag, peerJwk) {
  const k = myTag + peerJwk.x + peerJwk.y; if (cache.has(k)) return cache.get(k);
  const priv = await idb('readonly', (s) => s.get('priv:' + myTag));
  if (!priv) throw new Error('No private key on this device');
  const peer = await crypto.subtle.importKey('jwk', peerJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const key = await crypto.subtle.deriveKey({ name: 'ECDH', public: peer }, priv, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  cache.set(k, key); return key;
}
export async function encrypt(myTag, peerJwk, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await sharedKey(myTag, peerJwk), enc.encode(text));
  return { encryptedPayload: b64(ct), nonce: b64(iv) };
}
export async function decrypt(myTag, peerJwk, { encryptedPayload, nonce }) {
  try { return dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(nonce) }, await sharedKey(myTag, peerJwk), unb64(encryptedPayload))); }
  catch { return '🔒 Unable to decrypt (tampered or wrong key)'; }
}
// Safety number: SHA-256 over both public keys in canonical order, shown as digit groups.
export async function safetyNumber(a, b) {
  const [x, y] = [a.x + a.y, b.x + b.y].sort();
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(x + y)));
  return Array.from(h.slice(0, 15), (n) => String(n).padStart(3, '0')).join('').match(/.{1,5}/g).join(' ');
}
