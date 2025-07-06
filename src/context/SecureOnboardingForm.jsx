import React, { useState } from 'react';
const BASEURL = "https://automatic-system-7gxjpj54qqjv5-8000.app.github.dev"

// Utility helpers
const toBase64 = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));
const fromBase64 = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

async function exportPublicKeyToPEM(key) {
  const spki = await window.crypto.subtle.exportKey('spki', key);
  const b64 = toBase64(spki);
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
}

async function signPayload(privateKey, data) {
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-384' }, privateKey, data);
  return toBase64(sig);
}

async function deriveSessionKey(privateKey, peerPublicKey) {
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerPublicKey },
    privateKey,
    384
  );
  return crypto.subtle.importKey('raw', sharedSecret.slice(0, 32), { name: 'AES-GCM' }, false, ['encrypt']);
}

async function encryptPayload(key, data) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { ciphertext: toBase64(encrypted), iv: toBase64(iv) };
}

export default function SecureOnboardingForm() {
  const [status, setStatus] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setStatus("Submitting...");

    try {
      // 1. Prepare mock data
      const userData = {
        username: "demo_user",
        email: "demo@example.com",
        phone: "1234567890"
      };
      const txBytes = new TextEncoder().encode(JSON.stringify(userData));

      // 2. ECDSA keypair
      const ecdsaKey = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify']);
      const q_p = await exportPublicKeyToPEM(ecdsaKey.publicKey);
      const sig_p = await signPayload(ecdsaKey.privateKey, txBytes);

      // 3. Get middleware pubkey
        const res = await fetch(`{BASEURL}/api/middleware/public-key`);
      const { public_key } = await res.json();
      const raw = fromBase64(public_key.replace(/-----.*?-----/g, '').replace(/\s+/g, ''));
      const serverPubKey = await crypto.subtle.importKey('spki', raw.buffer, { name: 'ECDH', namedCurve: 'P-384' }, true, []);

      // 4. Ephemeral ECDH keypair
      const ephKey = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveBits']);
      const ephPubSPKI = await crypto.subtle.exportKey('spki', ephKey.publicKey);

      // 5. Derive AES session key
      const sessionKey = await deriveSessionKey(ephKey.privateKey, serverPubKey);

      // 6. Encrypt payload
      const payload = { target: "registration", tx: userData, sig_p, q_p };
      const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
      const { ciphertext, iv } = await encryptPayload(sessionKey, payloadBytes);

      // 7. Send to middleware
      const response = await fetch(`{BASEURL}/api/secure/gateway`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ephemeral_pubkey: toBase64(ephPubSPKI),
          ciphertext,
          iv
        })
      });

      const result = await response.json();
      setStatus(result.status || JSON.stringify(result));
    } catch (err) {
      console.error(err);
      setStatus("Error: " + err.message);
    }
  };

  return (
    <div className="max-w-md mx-auto p-6 bg-white rounded-xl shadow-md mt-10">
      <h2 className="text-xl font-semibold mb-4">SecureCipher: Mock Onboarding</h2>
      <form onSubmit={handleSubmit}>
        <button
          type="submit"
          className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
        >
          Submit Secure Request
        </button>
      </form>
      {status && <p className="mt-4 text-gray-700">🔐 Server Response: <b>{status}</b></p>}
    </div>
  );
}
