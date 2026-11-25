//! Signing identities (certificate + private key) from the macOS Keychain. The private key
//! never leaves the Keychain: macOS asks the user to allow each use (or once, "Always Allow").

use anyhow::{Result, anyhow};
use chrono::Utc;
use rocksign_core::Certificate;
use rocksign_core::cms::KeyKind;
use security_framework::identity::SecIdentity;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
use security_framework::key::Algorithm;

#[derive(Clone)]
pub struct Identity {
    pub cert: Certificate,
    pub identity: SecIdentity,
}

impl Identity {
    pub fn is_usable(&self) -> bool {
        self.cert.fits_document_signing() && self.cert.is_valid_at(Utc::now())
    }
}

/// All identities, usable ones for document signing first.
pub fn identities() -> Result<Vec<Identity>> {
    let results = match ItemSearchOptions::new().class(ItemClass::identity()).load_refs(true).limit(Limit::All).search() {
        Ok(r) => r,
        Err(e) if e.code() == -25300 => return Ok(Vec::new()), // errSecItemNotFound
        Err(e) => return Err(anyhow!("could not read the Keychain: {e}")),
    };
    let mut out: Vec<Identity> = Vec::new();
    for r in results {
        let SearchResult::Ref(Reference::Identity(identity)) = r else { continue };
        let Ok(cert) = identity.certificate() else { continue };
        let Ok(cert) = Certificate::parse(&cert.to_der()) else { continue };
        if !out.iter().any(|i| i.cert.der == cert.der) {
            out.push(Identity { cert, identity });
        }
    }
    // Usable first; for the same person, the certificate that lasts longest first.
    out.sort_by_key(|i| (!i.is_usable(), !i.cert.fits_document_signing(), i.cert.display_name().to_lowercase(), std::cmp::Reverse(i.cert.not_after)));
    Ok(out)
}

/// Sign `data` with the identity's private key (SHA-256). May show a Keychain prompt.
pub fn sign(identity: &SecIdentity, kind: KeyKind, data: &[u8]) -> Result<Vec<u8>> {
    let key = identity.private_key().map_err(|e| anyhow!("the Keychain has no private key for this certificate ({e})"))?;
    let algorithm = match kind {
        KeyKind::Rsa => Algorithm::RSASignatureMessagePKCS1v15SHA256,
        KeyKind::Ec => Algorithm::ECDSASignatureMessageX962SHA256,
    };
    key.create_signature(algorithm, data).map_err(|e| match e.code() {
        -128 => anyhow!("Signing was cancelled."),
        -25293 => anyhow!("The Keychain password was not accepted."),
        -25308 => anyhow!("The Keychain is locked and can't ask for permission right now."),
        _ => anyhow!("The Keychain could not sign: {}", e.description()),
    })
}
