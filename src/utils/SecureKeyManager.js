// SecureKeyManager.js
// Handles ECDSA key generation, encryption, and secure storage in IndexedDB

const DB_NAME = 'secure-cipher-bank';
const STORE_NAME = 'keys';
const KEY_ID = 'user-private-key';

export const SecureKeyManager = {
  async generateKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign', 'verify']
    );
    return keyPair;
  },

  async exportPublicKey(key) {
    const spki = await window.crypto.subtle.exportKey('spki', key);
    return btoa(String.fromCharCode(...new Uint8Array(spki)));
  },

  async exportPrivateKey(key) {
    const pkcs8 = await window.crypto.subtle.exportKey('pkcs8', key);
    return pkcs8;
  },

  async deriveEncryptionKey(pin, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(pin),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );
    return window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: 100000,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  async encryptPrivateKey(privateKey, pin) {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const key = await this.deriveEncryptionKey(pin, salt);
    const pkcs8 = await this.exportPrivateKey(privateKey);
    const encrypted = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      pkcs8
    );
    return { encrypted, salt, iv };
  },

  async decryptPrivateKey(encrypted, pin, salt, iv) {
    const key = await this.deriveEncryptionKey(pin, salt);
    const pkcs8 = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      encrypted
    );
    return window.crypto.subtle.importKey(
      'pkcs8',
      pkcs8,
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign']
    );
  },

  async storeEncryptedKey({ encrypted, salt, iv }) {
    return new Promise((resolve, reject) => {
      const open = window.indexedDB.open(DB_NAME, 1);
      open.onupgradeneeded = () => {
        open.result.createObjectStore(STORE_NAME);
      };
      open.onsuccess = () => {
        const db = open.result;
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        store.put({ encrypted, salt, iv }, KEY_ID);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      };
      open.onerror = () => reject(open.error);
    });
  },

  async getEncryptedKey() {
    return new Promise((resolve, reject) => {
      const open = window.indexedDB.open(DB_NAME, 1);
      open.onupgradeneeded = () => {
        open.result.createObjectStore(STORE_NAME);
      };
      open.onsuccess = () => {
        const db = open.result;
        const tx = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);
        const req = store.get(KEY_ID);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      };
      open.onerror = () => reject(open.error);
    });
  },

  async signData(privateKey, data) {
    const enc = new TextEncoder();
    const signature = await window.crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-384' },
      privateKey,
      enc.encode(data)
    );
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
  }
};
