// Recover letter.txt from letter.enc.json with the passphrase (the reverse of encrypt.js).
// Usage:  node tools/decrypt.js "the passphrase"      -> writes letter.txt next to letter.enc.json
// Works from a fresh clone: git clone https://github.com/noaboa07/one-month && cd one-month && node tools/decrypt.js "..."
const fs = require('fs'), path = require('path');
const { webcrypto: crypto } = require('crypto');

const pass = process.argv[2];
if (!pass) { console.error('usage: node tools/decrypt.js "passphrase"'); process.exit(1); }
const norm = s => s.toLowerCase().replace(/\s+/g, '');
const b64 = s => new Uint8Array(Buffer.from(s, 'base64'));

(async () => {
  const root = path.join(__dirname, '..');
  const enc = JSON.parse(fs.readFileSync(path.join(root, 'letter.enc.json'), 'utf8'));
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(norm(pass)), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64(enc.salt), iterations: 200000, hash: 'SHA-256' }, km, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  try {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(enc.iv) }, key, b64(enc.data));
    fs.writeFileSync(path.join(root, 'letter.txt'), Buffer.from(plain));
    console.log(`decrypted ${plain.byteLength} bytes -> letter.txt`);
  } catch (_) {
    console.error('wrong passphrase'); process.exit(2);
  }
})();
