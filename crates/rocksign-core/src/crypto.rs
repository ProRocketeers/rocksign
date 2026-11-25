//! Hashes and signature verification (RSA PKCS#1 v1.5, RSA-PSS, ECDSA P-256/P-384).

use anyhow::{Context, Result, anyhow, bail};
use rsa::{BigUint, Pkcs1v15Sign, Pss, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

use crate::asn1;
use crate::x509::PublicKeyInfo;

pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
pub const RSA_PSS: &str = "1.2.840.113549.1.1.10";
pub const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
pub const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
pub const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
pub const CURVE_P256: &str = "1.2.840.10045.3.1.7";
pub const CURVE_P384: &str = "1.3.132.0.34";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HashAlg {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    /// Accepts digest OIDs and, leniently, signature OIDs that some signers put in the
    /// digestAlgorithm field.
    pub fn from_oid(oid: &str) -> Option<Self> {
        Some(match oid {
            "1.3.14.3.2.26" | "1.2.840.113549.1.1.5" | "1.2.840.10045.4.1" => HashAlg::Sha1,
            "2.16.840.1.101.3.4.2.4" | "1.2.840.113549.1.1.14" | "1.2.840.10045.4.3.1" => HashAlg::Sha224,
            "2.16.840.1.101.3.4.2.1" | "1.2.840.113549.1.1.11" | "1.2.840.10045.4.3.2" => HashAlg::Sha256,
            "2.16.840.1.101.3.4.2.2" | "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" => HashAlg::Sha384,
            "2.16.840.1.101.3.4.2.3" | "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" => HashAlg::Sha512,
            _ => return None,
        })
    }

    pub fn oid(self) -> &'static str {
        match self {
            HashAlg::Sha1 => "1.3.14.3.2.26",
            HashAlg::Sha224 => "2.16.840.1.101.3.4.2.4",
            HashAlg::Sha256 => "2.16.840.1.101.3.4.2.1",
            HashAlg::Sha384 => "2.16.840.1.101.3.4.2.2",
            HashAlg::Sha512 => "2.16.840.1.101.3.4.2.3",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            HashAlg::Sha1 => "SHA-1",
            HashAlg::Sha224 => "SHA-224",
            HashAlg::Sha256 => "SHA-256",
            HashAlg::Sha384 => "SHA-384",
            HashAlg::Sha512 => "SHA-512",
        }
    }

    pub fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut h = D::new();
            for p in parts {
                h.update(p);
            }
            h.finalize().to_vec()
        }
        match self {
            HashAlg::Sha1 => run::<Sha1>(parts),
            HashAlg::Sha224 => run::<Sha224>(parts),
            HashAlg::Sha256 => run::<Sha256>(parts),
            HashAlg::Sha384 => run::<Sha384>(parts),
            HashAlg::Sha512 => run::<Sha512>(parts),
        }
    }
}

/// Human name of a signature algorithm, e.g. "RSA with SHA-256".
pub fn signature_algorithm_name(sig_alg: &str, digest: HashAlg) -> String {
    let hash = HashAlg::from_oid(sig_alg).unwrap_or(digest).name();
    match sig_alg {
        RSA_PSS => "RSA-PSS".to_string(),
        s if s.starts_with("1.2.840.113549.1.1.") => format!("RSA with {hash}"),
        s if s.starts_with("1.2.840.10045.") => format!("ECDSA with {hash}"),
        other => other.to_string(),
    }
}

fn rsa_key(key: &[u8]) -> Result<RsaPublicKey> {
    let (seq, _) = asn1::parse(key).context("RSA public key")?;
    let parts = seq.children()?;
    let n = parts.first().context("RSA key: missing modulus")?.uint_bytes()?;
    let e = parts.get(1).context("RSA key: missing exponent")?.uint_bytes()?;
    RsaPublicKey::new_with_max_size(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e), 16384).map_err(|e| anyhow!("RSA key: {e}"))
}

pub fn rsa_modulus_bits(key: &[u8]) -> Option<usize> {
    let (seq, _) = asn1::parse(key).ok()?;
    let n = seq.children().ok()?.first()?.uint_bytes().ok()?.to_vec();
    let lead = n.first()?.leading_zeros() as usize;
    Some(n.len() * 8 - lead)
}

/// RSASSA-PSS parameters: (hash, salt length).
fn pss_params(params: Option<&[u8]>) -> Result<(HashAlg, usize)> {
    let mut hash = HashAlg::Sha1;
    let mut salt = 20usize;
    if let Some(raw) = params {
        let (seq, _) = asn1::parse(raw)?;
        if seq.tag == asn1::SEQUENCE {
            for f in seq.children()? {
                let inner = f.children()?;
                match f.tag {
                    t if t == asn1::ctx(0, true) => {
                        let alg = inner.first().context("PSS hash")?.children()?;
                        let oid = alg.first().context("PSS hash OID")?.oid()?;
                        hash = HashAlg::from_oid(&oid).context("unsupported PSS hash")?;
                    }
                    t if t == asn1::ctx(2, true) => {
                        salt = inner.first().context("PSS salt")?.small_uint()? as usize;
                    }
                    _ => {}
                }
            }
        }
    }
    Ok((hash, salt))
}

/// What a signature was computed over.
pub enum Message<'a> {
    /// The data itself (CMS signed attributes).
    Data(&'a [u8]),
    /// Only its digest, made with the signer's digest algorithm (CMS without signed attributes).
    Digest(&'a [u8]),
}

impl Message<'_> {
    fn hashed(&self, hash: HashAlg, digest: HashAlg) -> Result<Vec<u8>> {
        match self {
            Message::Data(d) => Ok(hash.digest(&[d])),
            Message::Digest(d) if hash == digest => Ok(d.to_vec()),
            Message::Digest(_) => bail!("signature and digest algorithms disagree"),
        }
    }
}

/// Check `signature` over `message` with the certificate's public key.
pub fn verify(key: &PublicKeyInfo, sig_alg: &str, sig_alg_params: Option<&[u8]>, digest: HashAlg, message: Message, signature: &[u8]) -> Result<()> {
    match key.algorithm.as_str() {
        RSA_ENCRYPTION | RSA_PSS => {
            let pk = rsa_key(&key.key)?;
            if sig_alg == RSA_PSS {
                let (hash, salt) = pss_params(sig_alg_params)?;
                let hashed = message.hashed(hash, digest)?;
                let res = match hash {
                    HashAlg::Sha1 => pk.verify(Pss::new_with_salt::<Sha1>(salt), &hashed, signature),
                    HashAlg::Sha224 => pk.verify(Pss::new_with_salt::<Sha224>(salt), &hashed, signature),
                    HashAlg::Sha256 => pk.verify(Pss::new_with_salt::<Sha256>(salt), &hashed, signature),
                    HashAlg::Sha384 => pk.verify(Pss::new_with_salt::<Sha384>(salt), &hashed, signature),
                    HashAlg::Sha512 => pk.verify(Pss::new_with_salt::<Sha512>(salt), &hashed, signature),
                };
                return res.map_err(|_| anyhow!("the RSA-PSS signature does not match"));
            }
            let hash = HashAlg::from_oid(sig_alg).unwrap_or(digest);
            let hashed = message.hashed(hash, digest)?;
            let scheme = match hash {
                HashAlg::Sha1 => Pkcs1v15Sign::new::<Sha1>(),
                HashAlg::Sha224 => Pkcs1v15Sign::new::<Sha224>(),
                HashAlg::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
                HashAlg::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
                HashAlg::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
            };
            pk.verify(scheme, &hashed, signature).map_err(|_| anyhow!("the RSA signature does not match"))
        }
        EC_PUBLIC_KEY => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            let hash = HashAlg::from_oid(sig_alg).unwrap_or(digest);
            let hashed = message.hashed(hash, digest)?;
            let ok = match key.curve.as_deref() {
                Some(CURVE_P256) => {
                    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.key)?;
                    let sig = p256::ecdsa::Signature::from_der(signature)?;
                    vk.verify_prehash(&hashed, &sig).is_ok()
                }
                Some(CURVE_P384) => {
                    let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&key.key)?;
                    let sig = p384::ecdsa::Signature::from_der(signature)?;
                    vk.verify_prehash(&hashed, &sig).is_ok()
                }
                other => bail!("unsupported elliptic curve {}", other.unwrap_or("(none)")),
            };
            if ok { Ok(()) } else { bail!("the ECDSA signature does not match") }
        }
        other => bail!("unsupported key type {other}"),
    }
}
