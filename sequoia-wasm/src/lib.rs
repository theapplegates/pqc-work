//! Sequoia-PGP PQC WASM wrapper
//!
//! Exposes a minimal OpenPGP API to JavaScript:
//!   generate_pqc_key       — SLH-DSA-256s + ML-KEM-1024+X448 TSK
//!   extract_public_cert    — strip secret material, return public cert
//!   sign_detached          — detached ASCII-armored signature
//!   verify_detached        — verify a detached signature against a cert
//!   encrypt_to_cert        — encrypt plaintext to a cert's encryption subkey
//!   decrypt_message        — decrypt an armored PGP MESSAGE with a TSK
//!   inspect_cert           — JSON structural dump of a cert or TSK
//!
//! Keys and messages cross the JS/WASM boundary as ASCII armor strings.

use wasm_bindgen::prelude::*;

use sequoia_openpgp as openpgp;
use openpgp::armor;
use openpgp::Profile;
use openpgp::cert::{Cert, CertBuilder, CipherSuite};
use openpgp::crypto::SessionKey;
use openpgp::packet::prelude::*;
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, DetachedVerifierBuilder,
    MessageLayer, MessageStructure, VerificationHelper,
};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::{
    Serialize,
    stream::{Armorer, Encryptor, LiteralWriter, Message, Signer},
};
use openpgp::types::SymmetricAlgorithm;
use openpgp::KeyHandle;

use std::io::{Read, Write};

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// ───────────────────────── Key generation ─────────────────────────

/// Generate a PQC certificate (SLH-DSA-256s + ML-KEM-1024+X448).
/// Returns the ASCII-armored secret key (Transferable Secret Key).
#[wasm_bindgen]
pub fn generate_pqc_key(user_id: &str) -> Result<String, JsError> {
    let (cert, _rev) = CertBuilder::general_purpose(Some(user_id))
        .set_profile(Profile::RFC9580)
        .map_err(jserr("set_profile"))?
        .set_cipher_suite(CipherSuite::SLHDSA256s)
        .generate()
        .map_err(jserr("generate"))?;

    let mut buf = Vec::new();
    cert.as_tsk()
        .armored()
        .serialize(&mut buf)
        .map_err(jserr("serialize TSK"))?;
    String::from_utf8(buf).map_err(jserr("utf8"))
}

/// Extract the public certificate from a TSK. Returns ASCII-armored public cert.
#[wasm_bindgen]
pub fn extract_public_cert(tsk_armored: &str) -> Result<String, JsError> {
    let cert = Cert::from_bytes(tsk_armored.as_bytes()).map_err(jserr("parse TSK"))?;
    let mut buf = Vec::new();
    cert.armored().serialize(&mut buf).map_err(jserr("serialize cert"))?;
    String::from_utf8(buf).map_err(jserr("utf8"))
}

// ───────────────────────── Sign / Verify ─────────────────────────

/// Produce an ASCII-armored detached signature over `message` using the TSK.
#[wasm_bindgen]
pub fn sign_detached(tsk_armored: &str, message: &str) -> Result<String, JsError> {
    let cert = Cert::from_bytes(tsk_armored.as_bytes()).map_err(jserr("parse TSK"))?;
    let policy = &StandardPolicy::new();

    let keypair = cert
        .keys()
        .unencrypted_secret()
        .with_policy(policy, None)
        .alive()
        .revoked(false)
        .for_signing()
        .next()
        .ok_or_else(|| JsError::new("no signing-capable subkey found"))?
        .key()
        .clone()
        .into_keypair()
        .map_err(jserr("into_keypair"))?;

    let mut sink = Vec::new();
    {
        let msg = Message::new(&mut sink);
        let msg = Armorer::new(msg)
            .kind(armor::Kind::Signature)
            .build()
            .map_err(jserr("armorer"))?;
        let mut signer = Signer::new(msg, keypair)
            .map_err(jserr("new signer"))?
            .detached()
            .build()
            .map_err(jserr("build signer"))?;
        signer.write_all(message.as_bytes()).map_err(jserr("write message"))?;
        signer.finalize().map_err(jserr("finalize"))?;
    }
    String::from_utf8(sink).map_err(jserr("utf8"))
}

struct VerifyHelper {
    cert: Cert,
}

impl VerificationHelper for VerifyHelper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(vec![self.cert.clone()])
    }
    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure.into_iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                for r in results {
                    r.map_err(|e| anyhow::anyhow!("{e}"))?;
                }
                return Ok(());
            }
        }
        Err(anyhow::anyhow!("no signature found"))
    }
}

/// Verify a detached signature against a message and public cert.
#[wasm_bindgen]
pub fn verify_detached(
    cert_armored: &str,
    message: &str,
    signature_armored: &str,
) -> Result<bool, JsError> {
    let cert = Cert::from_bytes(cert_armored.as_bytes()).map_err(jserr("parse cert"))?;
    let policy = &StandardPolicy::new();

    let helper = VerifyHelper { cert };
    let mut verifier = DetachedVerifierBuilder::from_bytes(signature_armored.as_bytes())
        .map_err(jserr("verifier bytes"))?
        .with_policy(policy, None, helper)
        .map_err(jserr("with_policy"))?;

    verifier.verify_bytes(message.as_bytes()).map_err(jserr("verify"))?;
    Ok(true)
}

// ───────────────────────── Encrypt / Decrypt ─────────────────────────

/// Encrypt `message` to the recipient's public cert.
/// Returns an armored PGP MESSAGE block.
#[wasm_bindgen]
pub fn encrypt_to_cert(cert_armored: &str, message: &str) -> Result<String, JsError> {
    let cert = Cert::from_bytes(cert_armored.as_bytes()).map_err(jserr("parse cert"))?;
    let policy = &StandardPolicy::new();

    let recipients = cert
        .keys()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption();

    let mut sink = Vec::new();
    {
        let msg = Message::new(&mut sink);
        let msg = Armorer::new(msg).build().map_err(jserr("armorer"))?;
        let msg = Encryptor::for_recipients(msg, recipients)
            .build()
            .map_err(jserr("build encryptor"))?;
        let mut lit = LiteralWriter::new(msg).build().map_err(jserr("literal"))?;
        lit.write_all(message.as_bytes()).map_err(jserr("write plaintext"))?;
        lit.finalize().map_err(jserr("finalize"))?;
    }
    String::from_utf8(sink).map_err(jserr("utf8"))
}

struct DecryptHelper {
    cert: Cert,
}

impl VerificationHelper for DecryptHelper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(vec![])
    }
    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for DecryptHelper {
    fn decrypt(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<Cert>>
    {
        let policy = &StandardPolicy::new();

        // Collect decryption-capable keypairs from our cert.
        let mut keypairs: Vec<_> = self
            .cert
            .keys()
            .unencrypted_secret()
            .with_policy(policy, None)
            .supported()
            .for_transport_encryption()
            .filter_map(|ka| ka.key().clone().into_keypair().ok())
            .collect();

        // For each PKESK, try each keypair until one decrypts.
        for pkesk in pkesks {
            for keypair in keypairs.iter_mut() {
                if pkesk
                    .decrypt(keypair, sym_algo)
                    .map(|(sym, sk)| decrypt(sym, &sk))
                    .unwrap_or(false)
                {
                    return Ok(Some(self.cert.clone()));
                }
            }
        }
        Err(anyhow::anyhow!("no PKESK could be decrypted with this key"))
    }
}

/// Decrypt an armored PGP MESSAGE using the TSK.
#[wasm_bindgen]
pub fn decrypt_message(
    tsk_armored: &str,
    ciphertext_armored: &str,
) -> Result<String, JsError> {
    let cert = Cert::from_bytes(tsk_armored.as_bytes()).map_err(jserr("parse TSK"))?;
    let policy = &StandardPolicy::new();

    let helper = DecryptHelper { cert };
    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext_armored.as_bytes())
        .map_err(jserr("decryptor bytes"))?
        .with_policy(policy, None, helper)
        .map_err(jserr("with_policy"))?;

    let mut plaintext = Vec::new();
    decryptor.read_to_end(&mut plaintext).map_err(jserr("read plaintext"))?;
    String::from_utf8(plaintext).map_err(jserr("utf8 plaintext"))
}

// ───────────────────────── Cert inspector ─────────────────────────

/// Walk a cert or TSK and produce a JSON structural dump.
/// Keeps JSON hand-formatted so we don't pull in serde_json.
#[wasm_bindgen]
pub fn inspect_cert(input_armored: &str) -> Result<String, JsError> {
    let cert = Cert::from_bytes(input_armored.as_bytes()).map_err(jserr("parse"))?;
    let policy = &StandardPolicy::new();

    let mut out = String::new();
    out.push('{');

    // Primary fingerprint
    out.push_str(&format!(
        "\"fingerprint\":{},",
        json_str(&format!("{:X}", cert.fingerprint()))
    ));
    out.push_str(&format!(
        "\"keyid\":{},",
        json_str(&format!("{:X}", cert.keyid()))
    ));

    // Primary key details
    let primary = cert.primary_key().key();
    out.push_str("\"primary_key\":{");
    out.push_str(&format!(
        "\"algorithm\":{},",
        json_str(&pk_algo_name(primary.pk_algo()))
    ));
    out.push_str(&format!(
        "\"creation_time\":{},",
        json_str(&format_time(primary.creation_time()))
    ));
    out.push_str(&format!("\"version\":{}", primary.version()));
    if let Ok(has_secret) = std::panic::catch_unwind(|| primary.has_secret()) {
        out.push_str(&format!(",\"has_secret\":{}", has_secret));
    }
    out.push('}');

    // User IDs
    out.push_str(",\"user_ids\":[");
    let mut first = true;
    for uid in cert.userids() {
        if !first {
            out.push(',');
        }
        first = false;
        let value = String::from_utf8_lossy(uid.userid().value()).to_string();
        let sig_count = uid.self_signatures().count();
        let revoked = uid.self_revocations().count() > 0;
        out.push('{');
        out.push_str(&format!("\"value\":{},", json_str(&value)));
        out.push_str(&format!("\"self_signatures\":{},", sig_count));
        out.push_str(&format!("\"revoked\":{}", revoked));
        out.push('}');
    }
    out.push(']');

    // Subkeys
    out.push_str(",\"subkeys\":[");
    let mut first = true;
    for sk in cert.keys().subkeys() {
        if !first {
            out.push(',');
        }
        first = false;
        let k = sk.key();
        let fpr = format!("{:X}", k.fingerprint());
        let algo = pk_algo_name(k.pk_algo());
        let created = format_time(k.creation_time());

        // Derive flags from the subkey binding signature under the policy.
        let binding = sk.binding_signature(policy, None).ok();
        let for_signing = binding.and_then(|s| s.key_flags()).map(|f| f.for_signing()).unwrap_or(false);
        let for_transport = binding
            .and_then(|s| s.key_flags())
            .map(|f| f.for_transport_encryption())
            .unwrap_or(false);
        let for_storage = binding
            .and_then(|s| s.key_flags())
            .map(|f| f.for_storage_encryption())
            .unwrap_or(false);

        out.push('{');
        out.push_str(&format!("\"fingerprint\":{},", json_str(&fpr)));
        out.push_str(&format!("\"algorithm\":{},", json_str(&algo)));
        out.push_str(&format!("\"creation_time\":{},", json_str(&created)));
        out.push_str(&format!("\"for_signing\":{},", for_signing));
        out.push_str(&format!("\"for_transport_encryption\":{},", for_transport));
        out.push_str(&format!("\"for_storage_encryption\":{}", for_storage));
        out.push('}');
    }
    out.push(']');

    // Signature counts
    let primary_self_sigs = cert.primary_key().self_signatures().count();
    let primary_revocations = cert.primary_key().self_revocations().count();
    out.push_str(&format!(
        ",\"primary_self_signatures\":{}",
        primary_self_sigs
    ));
    out.push_str(&format!(",\"primary_revocations\":{}", primary_revocations));

    out.push('}');
    Ok(out)
}

// ───────────────────────── Small helpers ─────────────────────────

fn pk_algo_name(algo: openpgp::types::PublicKeyAlgorithm) -> String {
    format!("{:?}", algo)
}

fn format_time(t: std::time::SystemTime) -> String {
    use std::time::UNIX_EPOCH;
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            // RFC3339-ish without pulling in chrono.
            let secs = d.as_secs() as i64;
            format_rfc3339_utc(secs)
        }
        Err(_) => "unknown".to_string(),
    }
}

fn format_rfc3339_utc(secs: i64) -> String {
    // Minimal UTC formatter. Avoids chrono.
    // Valid for 1970-01-01 .. 9999-12-31.
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let hh = tod / 3600;
    let mm = (tod % 3600) / 60;
    let ss = tod % 60;

    // Civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hh, mm, ss
    )
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// Small helper to keep the error-mapping boilerplate readable.
fn jserr<E: std::fmt::Display>(ctx: &'static str) -> impl Fn(E) -> JsError {
    move |e| JsError::new(&format!("{ctx}: {e}"))
}
