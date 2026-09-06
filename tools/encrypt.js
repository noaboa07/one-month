// Encrypt letter.txt -> letter.enc.json with a passphrase (PBKDF2 + AES-256-GCM).
// Usage:  node tools/encrypt.js "the passphrase"
// The passphrase is normalized (lowercased, spaces removed) the same way the page normalizes what she types.
// letter.txt itself is git-ignored; only letter.enc.json is committed.
const fs = require('fs'), path = require('path');
const { webcrypto: crypto } = require('crypto');

const pass = process.argv[2];
if (!pass) { console.error('usage: node tools/encrypt.js "passphrase"'); process.exit(1); }
const norm = s => s.toLowerCase().replace(/\s+/g, '');

(async () => {
  const root = path.join(__dirname, '..');
  const plain = fs.readFileSync(path.join(root, 'letter.txt'));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(norm(pass)), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' }, km, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const data = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain));
  const b64 = u8 => Buffer.from(u8).toString('base64');
  fs.writeFileSync(path.join(root, 'letter.enc.json'), JSON.stringify({ v: 1, salt: b64(salt), iv: b64(iv), data: b64(data) }));
  console.log(`encrypted ${plain.length} bytes of letter.txt -> letter.enc.json (${data.length} bytes ciphertext)`);
})();
