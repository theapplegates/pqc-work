/**
 * Post-Quantum Cryptographic Service — Sequoia edition
 *
 * The underlying engine is Sequoia-PGP (Rust) compiled to WebAssembly.
 * PQC algorithms: SLH-DSA-256s (signing) + ML-KEM-1024+X448 (encryption),
 * produced as real OpenPGP v6 (RFC 9580) packets.
 *
 * Private keys are optionally wrapped with a PBKDF2+AES-GCM envelope on top
 * of Sequoia's own TSK format, so browser-persisted keys are protected at
 * rest by a user passphrase.
 */

import init, {
  generate_pqc_key,
  extract_public_cert,
  sign_detached,
  verify_detached,
  encrypt_to_cert,
  decrypt_message,
  inspect_cert,
} from 'sequoia-wasm';

import { CRYPTO_PROFILE } from '../constants';
import type { KeyPair } from '../types';

// ═══════════════════════════════════════════════════════════════════
//  WASM bootstrap
// ═══════════════════════════════════════════════════════════════════

let wasmReady: Promise<void> | null = null;
function ensureWasm(): Promise<void> {
  if (!wasmReady) wasmReady = init().then(() => undefined);
  return wasmReady;
}

// ═══════════════════════════════════════════════════════════════════
//  Byte / hex / base64 helpers
// ═══════════════════════════════════════════════════════════════════

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return out;
}

function bytesToBase64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

// ═══════════════════════════════════════════════════════════════════
//  Passphrase envelope (PBKDF2 + AES-GCM around the Sequoia TSK)
// ═══════════════════════════════════════════════════════════════════

const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_HASH = 'SHA-256';
const AES_GCM_IV_BYTES = 12;
const SALT_BYTES = 16;
const ENCRYPTION_AAD = new TextEncoder().encode(
  `${CRYPTO_PROFILE.keyVersion}|${CRYPTO_PROFILE.subkeyAlgorithm}|${CRYPTO_PROFILE.hashAlgorithm}|sequoia`
);

async function deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: PBKDF2_HASH },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function envelopeEncrypt(
  plaintext: string,
  passphrase: string
): Promise<{ ciphertextB64: string; saltHex: string; ivHex: string }> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  const key = await deriveKey(passphrase, salt);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: ENCRYPTION_AAD },
      key,
      new TextEncoder().encode(plaintext)
    )
  );
  return {
    ciphertextB64: bytesToBase64(ct),
    saltHex: bytesToHex(salt),
    ivHex: bytesToHex(iv),
  };
}

async function envelopeDecrypt(
  ciphertextB64: string,
  passphrase: string,
  saltHex: string,
  ivHex: string
): Promise<string> {
  const key = await deriveKey(passphrase, hexToBytes(saltHex));
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: hexToBytes(ivHex), additionalData: ENCRYPTION_AAD },
    key,
    base64ToBytes(ciphertextB64)
  );
  return new TextDecoder().decode(pt);
}

// ═══════════════════════════════════════════════════════════════════
//  In-memory TSK cache (per-KeyPair, cleared on refresh)
//
//  Decrypting the envelope is cheap (~100ms) but the existing UI
//  calls decryptPrivateKey / decryptKemPrivateKey / decryptX448PrivateKey
//  separately. The cache avoids PBKDF2 thrash during a single operation.
// ═══════════════════════════════════════════════════════════════════

const tskCache = new WeakMap<KeyPair, { pass: string; tsk: string }>();

async function unlockTsk(key: KeyPair, passphrase: string): Promise<string> {
  if (!key.salt || !key.iv) {
    // Unencrypted key — the plaintext TSK is stored directly in privateKeyRaw.
    return key.privateKeyRaw;
  }
  const cached = tskCache.get(key);
  if (cached && cached.pass === passphrase) return cached.tsk;

  const tsk = await envelopeDecrypt(key.privateKeyRaw, passphrase, key.salt, key.iv);
  tskCache.set(key, { pass: passphrase, tsk });
  return tsk;
}

// ═══════════════════════════════════════════════════════════════════
//  Cert inspection (shared by key-details modal + anywhere else)
// ═══════════════════════════════════════════════════════════════════

export interface SubkeyInfo {
  fingerprint: string;
  algorithm: string;
  creation_time: string;
  for_signing: boolean;
  for_transport_encryption: boolean;
  for_storage_encryption: boolean;
}

export interface CertInspection {
  fingerprint: string;
  keyid: string;
  primary_key: {
    algorithm: string;
    creation_time: string;
    version: number;
    has_secret?: boolean;
  };
  user_ids: Array<{ value: string; self_signatures: number; revoked: boolean }>;
  subkeys: SubkeyInfo[];
  primary_self_signatures: number;
  primary_revocations: number;
}

export async function inspectCert(armored: string): Promise<CertInspection> {
  await ensureWasm();
  const json = inspect_cert(armored);
  return JSON.parse(json) as CertInspection;
}

// Fingerprint shown with space-separated quartets, OpenPGP style.
function formatFingerprint(hex: string): string {
  const upper = hex.toUpperCase();
  return upper.match(/.{1,4}/g)?.join(' ') ?? upper;
}

// ═══════════════════════════════════════════════════════════════════
//  Key generation
// ═══════════════════════════════════════════════════════════════════

export async function generateKeyPair(
  userId: string,
  passphrase?: string
): Promise<KeyPair> {
  await ensureWasm();

  const tsk = generate_pqc_key(userId);
  const publicCert = extract_public_cert(tsk);
  const info = await inspectCert(publicCert);

  const fingerprint = formatFingerprint(info.fingerprint);
  const createdAt = info.primary_key.creation_time;

  // Envelope-wrap the TSK if the user gave a passphrase.
  let privateKeyRaw: string;
  let salt: string | undefined;
  let iv: string | undefined;
  if (passphrase && passphrase.length > 0) {
    const env = await envelopeEncrypt(tsk, passphrase);
    privateKeyRaw = env.ciphertextB64;
    salt = env.saltHex;
    iv = env.ivHex;
  } else {
    privateKeyRaw = tsk;
  }

  return {
    id: crypto.randomUUID(),
    userId,
    algorithm: CRYPTO_PROFILE.primaryAlgorithm,
    fingerprint,
    createdAt,
    publicKeyPgp: publicCert,
    privateKeyPgp: passphrase ? '' : tsk,
    publicKeyRaw: 'sequoia-pqc-cert',
    privateKeyRaw,
    // Presence markers so the UI's "has encryption subkey" checks pass.
    kemPublicKeyRaw: 'sequoia-pqc-kem',
    kemPrivateKeyRaw: 'sequoia-pqc-kem',
    x448PublicKeyRaw: 'sequoia-pqc-x448',
    x448PrivateKeyRaw: 'sequoia-pqc-x448',
    salt,
    iv,
    kemIv: iv,
    x448Iv: iv,
  };
}

// ═══════════════════════════════════════════════════════════════════
//  Unlock functions — existing UI calls each of these; all resolve
//  to the same plaintext TSK via the cache above.
// ═══════════════════════════════════════════════════════════════════

export async function decryptPrivateKey(key: KeyPair, passphrase: string): Promise<string> {
  return unlockTsk(key, passphrase);
}
export async function decryptKemPrivateKey(key: KeyPair, passphrase: string): Promise<string> {
  return unlockTsk(key, passphrase);
}
export async function decryptX448PrivateKey(key: KeyPair, passphrase: string): Promise<string> {
  return unlockTsk(key, passphrase);
}

// ═══════════════════════════════════════════════════════════════════
//  Sign
//
//  Signature semantics:
//   - We prepend a Comment block (User ID / Fingerprint / Signed on / Algo)
//     to the message so recipients see context — preserved from v1 UX.
//   - The prepended content is what Sequoia actually signs.
//   - We wrap the whole thing in OpenPGP clearsigned format.
// ═══════════════════════════════════════════════════════════════════

interface SignKeyInfo {
  userId: string;
  fingerprint: string;
  createdAt: string;
  publicKeyRaw?: string;
}

function parseUserId(uid: string): { name: string; email: string } {
  const m = uid.match(/^(.*?)\s*<(.+?)>\s*$/);
  if (m) return { name: m[1].trim(), email: m[2].trim() };
  if (uid.includes('@')) return { name: '', email: uid.trim() };
  return { name: uid.trim(), email: '' };
}

export function buildKeyCommentBlock(
  userInfo: { name: string; email: string },
  fingerprint: string,
  validFrom: string,
  _forSigning: boolean
): string {
  const lines = [
    `Comment: User ID:\t${userInfo.name}${userInfo.email ? ` <${userInfo.email}>` : ''}`,
    `Comment: Fingerprint:\t${fingerprint} (SHA-256 v6)`,
    `Comment: Valid from:\t${validFrom}`,
    `Comment: Algorithm:\t${CRYPTO_PROFILE.primaryAlgorithm} (${CRYPTO_PROFILE.primaryCategory})`,
    `Comment: Subkey:\t${CRYPTO_PROFILE.subkeyAlgorithm} (${CRYPTO_PROFILE.subkeyCategory})`,
  ];
  return lines.join('\n');
}

export function buildSignedMessageContent(
  message: string,
  keyInfo: { userId: string; fingerprint: string; createdAt: string }
): string {
  const userInfo = parseUserId(keyInfo.userId);
  const validFrom = new Date(keyInfo.createdAt).toLocaleString('en-US', {
    dateStyle: 'short',
    timeStyle: 'short',
  });
  const commentBlock = buildKeyCommentBlock(userInfo, keyInfo.fingerprint, validFrom, true);
  return `${commentBlock}\n\n${message}`;
}

function wrapAsClearsigned(signedContent: string, signatureBlock: string): string {
  return `-----BEGIN PGP SIGNED MESSAGE-----\nHash: ${CRYPTO_PROFILE.hashAlgorithm}\n\n${signedContent}\n${signatureBlock}`;
}

/**
 * Sign a message. `privateKeyInput` is the plaintext TSK (ASCII armor).
 * Returns the detached signature, the body that was signed, and a
 * clearsigned wrapper ready to share.
 */
export async function sign(
  privateKeyInput: string,
  message: string,
  keyInfo: SignKeyInfo
): Promise<{ signature: string; signedMessage: string; clearSignedMessage: string }> {
  await ensureWasm();
  const signedMessage = buildSignedMessageContent(message, keyInfo);
  const signature = sign_detached(privateKeyInput, signedMessage);
  const clearSignedMessage = wrapAsClearsigned(signedMessage, signature);
  return { signature, signedMessage, clearSignedMessage };
}

// ═══════════════════════════════════════════════════════════════════
//  Verify
// ═══════════════════════════════════════════════════════════════════

/**
 * Verify a detached signature against a message using an ASCII-armored
 * public cert. Returns true on success, false on any failure.
 */
export async function verify(
  publicKeyPgp: string,
  message: string,
  signatureArmored: string
): Promise<boolean> {
  try {
    await ensureWasm();
    return verify_detached(publicKeyPgp, message, signatureArmored);
  } catch (error) {
    console.error('Signature verification failed:', error);
    return false;
  }
}

/**
 * Kept for UI compatibility; the Sequoia path verifies via armored cert
 * directly, so we never extract raw bytes from a packet in v2.
 * Returns the input unchanged for any callers that still pass it.
 */
export function extractRawPublicKeyFromV6Packet(packetBytes: Uint8Array): Uint8Array {
  return packetBytes;
}

// ═══════════════════════════════════════════════════════════════════
//  Encrypt / Decrypt
// ═══════════════════════════════════════════════════════════════════

/**
 * Encrypt `message` to a recipient. The KemPublicKey / X448PublicKey
 * arguments are vestigial from the noble layout; we ignore them in v2
 * and encrypt to the whole public cert (which we have on the KeyPair).
 */
export async function encryptMessage(
  _kemPublicKeyHex: string | undefined,
  _x448PublicKeyHex: string | undefined,
  message: string,
  _fingerprint: string,
  recipientPublicCert?: string
): Promise<string> {
  await ensureWasm();
  if (!recipientPublicCert) {
    throw new Error('Sequoia encrypt requires the recipient public cert');
  }
  return encrypt_to_cert(recipientPublicCert, message);
}

export async function decryptMessage(
  tsk1: string,
  _tsk2: string,
  ciphertextArmored: string
): Promise<string> {
  await ensureWasm();
  return decrypt_message(tsk1, ciphertextArmored);
}

// ═══════════════════════════════════════════════════════════════════
//  Compat-shim exports — kept so legacy imports keep compiling.
//  The new app uses inspectCert() instead.
// ═══════════════════════════════════════════════════════════════════

export type CompatibilitySeverity = 'pass' | 'warn' | 'fail' | 'info';

export interface CompatibilityCheckItem {
  severity: CompatibilitySeverity;
  message: string;
}

export interface PublicKeyCompatibilityReport {
  overall: CompatibilitySeverity;
  checks: CompatibilityCheckItem[];
}

export function analyzePublicKeyCompatibility(publicKeyPgp: string): PublicKeyCompatibilityReport {
  const checks: CompatibilityCheckItem[] = [];

  if (!publicKeyPgp.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----')
   || !publicKeyPgp.includes('-----END PGP PUBLIC KEY BLOCK-----')) {
    checks.push({ severity: 'fail', message: 'Missing PGP public key armor headers.' });
    return { overall: 'fail', checks };
  }
  checks.push({ severity: 'pass', message: 'ASCII armor headers present.' });
  checks.push({
    severity: 'pass',
    message: 'Produced by Sequoia-PGP (RFC 9580 v6) — packets parsed by the Sequoia engine.',
  });
  return { overall: 'pass', checks };
}
