# Sequoia Test Bed — Post-Quantum OpenPGP in the Browser
Using Anthropic's (https://claude.com) I was able to get the following to work.


A working web application that generates real, interoperable post-quantum
OpenPGP keys entirely in the browser, with no server-side crypto and no
JavaScript-only crypto primitives.

**Live**: [slh-dsa.paulapplegate.com](https://slh-dsa.paulapplegate.com)

---

## What this is

A browser-based OpenPGP toolkit using [Sequoia-PGP](https://sequoia-pgp.org)
(Rust) compiled to WebAssembly. Generates RFC 9580 v6 certificates with the
full post-quantum cryptography suite:

- **Signing**: SLH-DSA-256s (FIPS 205, NIST Category 5)
- **Encryption**: ML-KEM-1024 + X448 hybrid (FIPS 203 + RFC 7748, NIST Category 5)
- **Hashing**: SHA3-512

Keys generated in the browser are bit-for-bit interoperable with native
Sequoia. A key produced here can be exported, imported into `sq` via
`sq key import`, and used immediately — sign with `sq`, verify in the
browser; encrypt in `sq`, decrypt in the browser. Round-trip verified.

Private keys are protected at rest with PBKDF2 (100,000 iterations,
SHA-256) + AES-GCM, layered on top of Sequoia's TSK format. Passphrases
never leave the browser. There is no backend.

## Why this is unusual

Until very recently, "post-quantum OpenPGP in the browser" required one
of two compromises:

1. Use a JavaScript crypto library (`@noble/post-quantum` or similar) and
   hand-roll the OpenPGP packet format yourself. Output is not
   interoperable with `sq`, `gpg`, or anything else.
2. Wait for an official browser SDK from a major OpenPGP project. None
   existed when this work started.

This project takes a third path: compile the reference Rust implementation
of OpenPGP to WebAssembly. The output is real OpenPGP. The 1.8 MB `.wasm`
binary contains Sequoia's full v6 packet handling, the RustCrypto PQC
crates (`ml-kem`, `ml-dsa`, `slh-dsa`), and pure-Rust X448/Ed448 — all
linked together and stripped down by `wasm-opt`.

The dependency chain that made this possible only became viable in 2025:

- **X448 and Ed448 in Sequoia's `crypto-rust` backend** — added in 2025,
  filling the last gap that had previously forced PQC builds through OpenSSL.
- **Sequoia's PQC branch** — implements ML-DSA, ML-KEM, and SLH-DSA against
  the experimental OpenPGP draft for post-quantum cryptography.
- **A fork ([`theapplegates/pqc-signature-toolkit`](https://github.com/theapplegates/pqc-signature-toolkit.git))
  combining the two** — landing PQC algorithms inside the `crypto-rust`
  backend rather than the OpenSSL backend, which is what makes a clean
  WASM build possible.

That fork is the foundation everything else rests on.

## Architecture

```
┌──────────────────────────────────────────────────┐
│  React + Vite + Tailwind UI                      │
│  (5 tabs: Keys, Sign, Verify, Encrypt, Decrypt)  │
└──────────────────────────────────────────────────┘
					  │
					  ▼
┌──────────────────────────────────────────────────┐
│  cryptoService.ts (~400 lines)                   │
│  - PBKDF2/AES-GCM envelope for at-rest storage   │
│  - Wraps the WASM exports                        │
└──────────────────────────────────────────────────┘
					  │
					  ▼
┌──────────────────────────────────────────────────┐
│  sequoia-wasm (Rust → 1.8 MB WebAssembly)        │
│  - generate / extract_public_cert                │
│  - sign_detached / verify_detached               │
│  - encrypt_to_cert / decrypt_message             │
│  - inspect_cert (for the packet inspector)       │
└──────────────────────────────────────────────────┘
					  │
					  ▼
┌──────────────────────────────────────────────────┐
│  sequoia-openpgp (pqc-signature-toolkit, crypto-rust)     │
│  RustCrypto: ml-kem, ml-dsa, slh-dsa, x448,      │
│  ed448, sha3, aes-gcm, etc.                      │
└──────────────────────────────────────────────────┘
```

## Performance (Apple M4 Max, Safari)

| Operation                          | Time         |
|------------------------------------|--------------|
| WASM module load                   | <1 s (cold)  |
| Key generation (SLH-DSA-256s)      | 10–30 s      |
| Detached signature                 | ~1.6 s       |
| Signature verification             | <10 ms       |
| Encryption (ML-KEM-1024+X448)      | <100 ms      |
| Decryption                         | <100 ms      |

Slow keygen and signing are inherent to SLH-DSA's hash-based design — not
a WASM overhead. Native `sq` shows similar timings on the same hardware.

## Building from source

git clone --recurse-submodules https://github.com/theapplegates/pqc-work.git ~/pqc-work

Layout:

```
~/pqc-work/
├── pqc-signature-toolkit/sequoia/      # Sequoia source tree
├── sequoia-wasm/              # Rust → WASM wrapper crate
│   ├── Cargo.toml             # depends on ../pqc-signature-toolkit/sequoia/openpgp
│   ├── src/lib.rs             # ~340 lines exposing 7 functions to JS
│   └── pkg/                   # wasm-pack output
└── signature-web/             # React app (this repo's web/)
	└── package.json           # depends on file:../sequoia-wasm/pkg
```

Build steps:

```bash
# 1. Build the WASM package
cd ~/pqc-work/sequoia-wasm
wasm-pack build --target web --release
# Produces pkg/sequoia_wasm_bg.wasm (~1.8 MB) and a JS shim

# 2. Install and run the web app
cd ~/pqc-work/signature-web
npm install
npm run dev
# Open http://localhost:3000
```

## Interop demo

Generate a key in the browser. In the Key Details modal, enter your
passphrase, click **Reveal Private Key**, then **Download**. In a terminal:

```bash
sq key import < ~/Downloads/private-key-XXXXXXXXXXXXXXXX.asc
sq key list
# Your browser-generated PQC v6 cert is now in your local Sequoia keystore.

# Round-trip check:
echo "hello from native sq" | sq sign --signer-file private-key-XXX.asc > signed.pgp
# Paste signed.pgp into the Verify tab — should validate.
```

## Project files

```
sequoia-wasm/
├── Cargo.toml                 # ~25 lines, points at ../pqc-signature-toolkit
└── src/lib.rs                 # ~340 lines, all 7 wasm-bindgen exports

signature-web/
├── App.tsx                    # Top-level layout, tabs, key list
├── components/
│   ├── KeyManagementTab.tsx   # Generate + list keys
│   ├── SignTab.tsx            # Detached + clearsigned messages
│   ├── VerifyTab.tsx          # Verify clearsigned or paste-separately
│   ├── EncryptTab.tsx         # Encrypt to a recipient cert
│   ├── DecryptTab.tsx         # Decrypt with passphrase prompt
│   ├── KeyDetailsModal.tsx    # Public/private blocks + packet inspector
│   ├── TabButton.tsx
│   └── icons/Icons.tsx
├── services/
│   └── cryptoService.ts       # PBKDF2/AES-GCM envelope + WASM bridge
├── hooks/useCopyToClipboard.ts
└── types.ts, constants.ts, vite.config.ts, tsconfig.json
```

## Acknowledgements

- The Sequoia-PGP team for an OpenPGP implementation that compiles to
  WASM at all, and for the PQC branch.
- The RustCrypto project for `ml-kem`, `ml-dsa`, `slh-dsa`, `x448`, and
  the rest of the symmetric/hash primitives.
- Whoever upstreamed X448 into Sequoia's crypto-rust backend in 2025 —
  that single commit is what made all of this possible without a
  patched OpenSSL. I think it was Gergely Nagy (@ngg1). Thanks!

## License

The application code in this repo is MIT-licensed. Sequoia-PGP is GPL.
The compiled WASM artifact distributed with the site inherits Sequoia's
license; see the upstream project for details.

---

*Built across two intense days in April 2026. The first day was getting
Sequoia to compile to WebAssembly with the full PQC stack — turning a
"someday, maybe" project into a working 1.8 MB binary. The second day
was wrapping it in a real production web application with passphrase
protection, encryption, and bit-for-bit interop with native `sq`.*
