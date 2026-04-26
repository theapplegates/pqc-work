export const TABS = {
  KEY_MANAGEMENT: 'Key Management',
  SIGN: 'Sign',
  VERIFY: 'Verify',
  ENCRYPT: 'Encrypt',
  DECRYPT: 'Decrypt',
} as const;

export const ALGORITHM = {
  name: 'SLH-DSA-SHAKE-256s',
  displayName: 'Claude / SLH-DSA-SHAKE',
  marketingName: 'Claude Signatures',
  security: 256,
  type: 's',
};

export const CRYPTO_PROFILE = {
  primaryAlgorithm: 'SLH-DSA-SHAKE-256s',
  primaryCategory: 'NIST Category 5',
  subkeyAlgorithm: 'ML-KEM-1024+X448',
  subkeyCategory: 'NIST Category 5',
  hashAlgorithm: 'SHA3-512',
  hashId: 14,
  keyVersion: 'RFC 9580 version 6',
  engine: 'Sequoia-PGP (Rust, crypto-rust backend)',
};
