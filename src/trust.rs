//! Is a signer's certificate trusted? Uses the macOS trust store (the same one Safari and Mail
//! use) plus issuers the user chose to trust in RockSign.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use core_foundation::date::CFDate;
use rocksign_core::Certificate;
use security_framework::certificate::SecCertificate;
use security_framework::policy::SecPolicy;
use security_framework::trust::SecTrust;

#[derive(Clone, Debug)]
pub struct TrustOutcome {
    pub trusted: bool,
    /// Why not, in macOS's words.
    pub problem: Option<String>,
    /// Signer first, root last (as far as it could be built).
    pub chain: Vec<Certificate>,
    /// Set when the chain leads to a CA on the Czech trusted list (a qualified certificate).
    pub qualified_provider: Option<&'static str>,
}

impl TrustOutcome {
    /// The certificate to trust to make this chain trusted: the top of the chain.
    pub fn anchor_candidate(&self) -> Option<&Certificate> {
        self.chain.last()
    }
}

/// Check `signer` against the macOS trust store, the built-in Czech qualified CAs and the
/// issuers the user trusted, at time `at` (the timestamp, or now).
pub fn evaluate(signer: &Certificate, others: &[Certificate], at: Option<DateTime<Utc>>, user_anchors: &[Certificate]) -> TrustOutcome {
    let anchors: Vec<&Certificate> = rocksign_core::anchors::czech_qualified().iter().map(|a| &a.certificate).chain(user_anchors.iter()).collect();
    let run = || -> Result<TrustOutcome, String> {
        let mut certs = vec![SecCertificate::from_der(&signer.der).map_err(|e| e.to_string())?];
        for c in others.iter().filter(|c| c.der != signer.der) {
            if let Ok(sc) = SecCertificate::from_der(&c.der) {
                certs.push(sc);
            }
        }
        let mut trust = SecTrust::create_with_certificates(&certs, &[SecPolicy::create_x509()]).map_err(|e| e.to_string())?;
        if let Some(t) = at {
            // CFAbsoluteTime counts seconds from 2001-01-01.
            let abs = t.timestamp() as f64 - 978_307_200.0;
            trust.set_trust_verify_date(&CFDate::new(abs)).map_err(|e| e.to_string())?;
        }
        if !anchors.is_empty() {
            let extra: Vec<SecCertificate> = anchors.iter().filter_map(|a| SecCertificate::from_der(&a.der).ok()).collect();
            trust.set_anchor_certificates(&extra).map_err(|e| e.to_string())?;
            trust.set_trust_anchor_certificates_only(false).map_err(|e| e.to_string())?;
        }
        let result = trust.evaluate_with_error();
        let chain: Vec<Certificate> = trust.chain().iter().filter_map(|c| Certificate::parse(&c.to_der()).ok()).collect();
        let chain = if chain.is_empty() { vec![signer.clone()] } else { chain };
        Ok(TrustOutcome {
            trusted: result.is_ok(),
            problem: result.err().map(|e| e.description().to_string()),
            qualified_provider: rocksign_core::anchors::qualified_provider(&chain),
            chain,
        })
    };
    run().unwrap_or_else(|e| TrustOutcome { trusted: false, problem: Some(e), chain: vec![signer.clone()], qualified_provider: None })
}

/// The chain to embed when signing (intermediates and root, found via the Keychain).
pub fn chain_for_signing(signer: &Certificate) -> Vec<Certificate> {
    evaluate(signer, &[], None, &[]).chain.into_iter().filter(|c| c.der != signer.der).collect()
}

fn anchors_dir() -> Option<PathBuf> {
    Some(dirs::config_dir()?.join("RockSign").join("trusted-issuers"))
}

/// Issuers the user chose to trust in RockSign.
pub fn load_anchors() -> Vec<Certificate> {
    let Some(dir) = anchors_dir() else { return Vec::new() };
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "der"))
        .filter_map(|e| std::fs::read(e.path()).ok())
        .filter_map(|der| Certificate::parse(&der).ok())
        .collect()
}

pub fn add_anchor(cert: &Certificate) -> anyhow::Result<()> {
    let dir = anchors_dir().ok_or_else(|| anyhow::anyhow!("no settings folder"))?;
    std::fs::create_dir_all(&dir)?;
    let name: String = cert.sha256_fingerprint().iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.join(format!("{name}.der")), &cert.der)?;
    Ok(())
}
