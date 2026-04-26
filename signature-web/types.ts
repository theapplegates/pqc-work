import { TABS } from './constants';

export type Tab = typeof TABS[keyof typeof TABS];

/**
 * KeyPair shape preserved from the noble-based version so existing UI
 * components continue to work. Fields are repurposed internally:
 *
 *   publicKeyPgp      — ASCII-armored public cert (was noble-produced v6 packet)
 *   privateKeyPgp     — ASCII-armored TSK if unencrypted, else unused
 *   publicKeyRaw      — marker "sequoia-pqc-cert" for presence checks in UI
 *   privateKeyRaw     — plaintext TSK if unencrypted, else base64(AES-GCM ciphertext)
 *   kemPublicKeyRaw   — marker "sequoia-pqc-kem" for "has encryption subkey" UI checks
 *   kemPrivateKeyRaw  — marker "sequoia-pqc-kem" (same)
 *   x448PublicKeyRaw  — marker "sequoia-pqc-x448"
 *   x448PrivateKeyRaw — marker "sequoia-pqc-x448"
 *   salt              — hex salt if envelope-encrypted; absence means plaintext
 *   iv                — hex IV for the TSK envelope
 *   kemIv / x448Iv    — unused in Sequoia model; kept for type compat, always empty
 */
export interface KeyPair {
  id: string;
  userId: string;
  algorithm: string;
  fingerprint: string;
  createdAt: string;
  publicKeyPgp: string;
  privateKeyPgp: string;
  publicKeyRaw: string;
  privateKeyRaw: string;
  kemPublicKeyRaw?: string;
  kemPrivateKeyRaw?: string;
  x448PublicKeyRaw?: string;
  x448PrivateKeyRaw?: string;
  salt?: string;
  iv?: string;
  kemIv?: string;
  x448Iv?: string;
}
