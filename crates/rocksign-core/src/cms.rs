//! CMS SignedData: the signature container inside a PDF's /Contents.
//!
//! Reading is lenient (BER containers, unknown fields are skipped); writing produces the
//! PAdES baseline profile: SHA-256, contentType + messageDigest + signingCertificateV2 signed
//! attributes, and an optional RFC 3161 timestamp as an unsigned attribute.

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::asn1::{self, Tlv, alg_id, alg_id_null, ctx, octet_string, oid, seq, set_of, small_uint, tlv};
use crate::crypto::{self, HashAlg, Message};
use crate::x509::{self, Certificate};

pub const ID_DATA: &str = "1.2.840.113549.1.7.1";
pub const ID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
pub const ID_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
pub const ID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
pub const ID_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
pub const ID_SIGNING_CERT_V2: &str = "1.2.840.113549.1.9.16.2.47";
pub const ID_TIMESTAMP_TOKEN: &str = "1.2.840.113549.1.9.16.2.14";
pub const ID_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";

pub struct SignedData<'a> {
    pub econtent_type: String,
    /// Encapsulated content (absent for detached signatures).
    pub econtent: Option<Vec<u8>>,
    pub certificates: Vec<Certificate>,
    pub signers: Vec<SignerInfo<'a>>,
}

pub struct SignerInfo<'a> {
    pub sid: SignerId<'a>,
    pub digest_oid: String,
    pub signed_attrs: Option<Tlv<'a>>,
    pub sig_alg: String,
    pub sig_alg_params: Option<&'a [u8]>,
    pub signature: &'a [u8],
    pub unsigned_attrs: Option<Tlv<'a>>,
}

pub enum SignerId<'a> {
    IssuerSerial { issuer: &'a [u8], serial: &'a [u8] },
    KeyId(&'a [u8]),
}

/// Parse the ContentInfo at the start of `data`. Trailing bytes (PDF zero padding) are ignored.
pub fn parse_signed_data(data: &[u8]) -> Result<SignedData<'_>> {
    let (ci, _) = asn1::parse(data).context("signature container")?;
    let parts = ci.expect(asn1::SEQUENCE)?.children()?;
    let ct = parts.first().context("signature container is empty")?.oid()?;
    if ct != ID_SIGNED_DATA {
        bail!("signature container is not SignedData ({ct})");
    }
    let wrapper = parts.get(1).context("SignedData missing")?.expect(ctx(0, true))?;
    let sd = *wrapper.children()?.first().context("SignedData missing")?;
    let f = sd.expect(asn1::SEQUENCE)?.children()?;
    let encap = f.get(2).context("SignedData: missing content info")?.children()?;
    let econtent_type = encap.first().context("SignedData: missing content type")?.oid()?;
    let econtent = match encap.get(1) {
        Some(w) if w.tag == ctx(0, true) => Some(w.children()?.first().context("empty eContent")?.octets()?),
        _ => None,
    };
    let mut idx = 3;
    let mut certificates = Vec::new();
    if let Some(c) = f.get(idx).filter(|t| t.tag == ctx(0, true)) {
        for cert in c.children()? {
            if cert.tag == asn1::SEQUENCE
                && let Ok(parsed) = Certificate::parse(cert.raw)
            {
                certificates.push(parsed);
            }
        }
        idx += 1;
    }
    if f.get(idx).is_some_and(|t| t.tag == ctx(1, true)) {
        idx += 1; // CRLs
    }
    let infos = f.get(idx).context("SignedData: missing signer infos")?.expect(asn1::SET)?;
    let signers = infos.children()?.iter().map(parse_signer_info).collect::<Result<Vec<_>>>()?;
    Ok(SignedData { econtent_type, econtent, certificates, signers })
}

fn parse_signer_info<'a>(t: &Tlv<'a>) -> Result<SignerInfo<'a>> {
    let s = t.expect(asn1::SEQUENCE)?.children()?;
    let sid_t = s.get(1).context("SignerInfo: missing signer id")?;
    let sid = if sid_t.tag == asn1::SEQUENCE {
        let p = sid_t.children()?;
        SignerId::IssuerSerial {
            issuer: p.first().context("SignerInfo: missing issuer")?.raw,
            serial: p.get(1).context("SignerInfo: missing serial")?.uint_bytes()?,
        }
    } else if sid_t.tag == ctx(0, false) {
        SignerId::KeyId(sid_t.content)
    } else {
        bail!("SignerInfo: unknown signer id");
    };
    let digest_oid = s.get(2).context("SignerInfo: missing digest")?.children()?.first().context("digest")?.oid()?;
    let mut i = 3;
    let signed_attrs = s.get(i).filter(|t| t.tag == ctx(0, true)).copied();
    if signed_attrs.is_some() {
        i += 1;
    }
    let alg = s.get(i).context("SignerInfo: missing signature algorithm")?.children()?;
    let sig_alg = alg.first().context("signature algorithm")?.oid()?;
    let sig_alg_params = alg.get(1).filter(|p| p.tag != asn1::NULL).map(|p| p.raw);
    let signature = s.get(i + 1).context("SignerInfo: missing signature")?.expect(asn1::OCTET_STRING)?.content;
    let unsigned_attrs = s.get(i + 2).filter(|t| t.tag == ctx(1, true)).copied();
    Ok(SignerInfo { sid, digest_oid, signed_attrs, sig_alg, sig_alg_params, signature, unsigned_attrs })
}

/// First value of the attribute `id` in a signed or unsigned attribute set.
pub fn attribute<'a>(attrs: &Tlv<'a>, id: &str) -> Result<Option<Tlv<'a>>> {
    for a in attrs.children()? {
        let f = a.children()?;
        if f.first().map(|t| t.oid()).transpose()?.as_deref() == Some(id) {
            return Ok(f.get(1).map(|v| v.children()).transpose()?.and_then(|v| v.into_iter().next()));
        }
    }
    Ok(None)
}

impl SignerInfo<'_> {
    pub fn digest(&self) -> Result<HashAlg> {
        HashAlg::from_oid(&self.digest_oid).with_context(|| format!("unsupported digest algorithm {}", self.digest_oid))
    }

    /// The certificate that made this signature.
    pub fn find_certificate<'c>(&self, certs: &'c [Certificate]) -> Option<&'c Certificate> {
        certs.iter().find(|c| match &self.sid {
            SignerId::IssuerSerial { issuer, serial } => {
                c.serial == *serial && (c.issuer_raw == *issuer || x509::parse_name_raw(issuer).is_some_and(|n| n == c.issuer))
            }
            SignerId::KeyId(id) => c.subject_key_id.as_deref() == Some(*id),
        })
    }
}

/// Result of checking one SignerInfo.
#[derive(Clone, Debug)]
pub struct SignerCheck {
    pub certificate: Option<Certificate>,
    /// The digest in the signed attributes matches the signed content.
    pub digest_matches: bool,
    /// The signature itself verifies with the signer's public key.
    pub signature_valid: bool,
    pub problem: Option<String>,
    /// signingTime attribute (not used by PAdES, which keeps the time in /M).
    pub signing_time: Option<DateTime<Utc>>,
    pub digest: Option<HashAlg>,
    pub algorithm: String,
}

/// Check a signer against the digest of the content it claims to sign.
pub fn check_signer(sd: &SignedData, signer: &SignerInfo, content_digest: &[u8]) -> SignerCheck {
    let digest = signer.digest().ok();
    let mut check = SignerCheck {
        certificate: signer.find_certificate(&sd.certificates).cloned(),
        digest_matches: false,
        signature_valid: false,
        problem: None,
        signing_time: None,
        digest,
        algorithm: crypto::signature_algorithm_name(&signer.sig_alg, digest.unwrap_or(HashAlg::Sha256)),
    };
    let result = (|| -> Result<()> {
        let digest = signer.digest()?;
        let cert = check.certificate.as_ref().context("the signer's certificate is not included in the signature")?;
        let signed_der;
        let message = match &signer.signed_attrs {
            Some(sa) => {
                let md = attribute(sa, ID_MESSAGE_DIGEST)?.context("signed attributes lack a message digest")?;
                check.digest_matches = md.octets()? == content_digest;
                if let Some(t) = attribute(sa, ID_SIGNING_TIME)? {
                    check.signing_time = x509::parse_time(&t).ok();
                }
                // The signature covers the DER SET OF, not the [0] IMPLICIT tagged form.
                let mut der = sa.raw.to_vec();
                der[0] = asn1::SET;
                signed_der = der;
                Message::Data(&signed_der)
            }
            None => {
                check.digest_matches = true;
                Message::Digest(content_digest)
            }
        };
        crypto::verify(&cert.public_key, &signer.sig_alg, signer.sig_alg_params, digest, message, signer.signature)?;
        check.signature_valid = true;
        Ok(())
    })();
    if let Err(e) = result {
        check.problem = Some(e.to_string());
    } else if !check.digest_matches {
        check.problem = Some("the signed digest does not match the document".into());
    }
    check
}

// --- timestamps --------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct TimestampInfo {
    pub time: DateTime<Utc>,
    pub imprint_alg: HashAlg,
    pub imprint: Vec<u8>,
    /// Check of the timestamp authority's own signature.
    pub check: SignerCheck,
    pub certificates: Vec<Certificate>,
}

impl TimestampInfo {
    /// Whether the token timestamps exactly `data` (a signature value or a document range digest).
    pub fn covers(&self, data_digest_input: &[&[u8]]) -> bool {
        self.imprint == self.imprint_alg.digest(data_digest_input)
    }

    pub fn is_valid(&self) -> bool {
        self.check.signature_valid && self.check.digest_matches
    }
}

/// Parse and check an RFC 3161 TimeStampToken (a ContentInfo).
pub fn parse_timestamp_token(token: &[u8]) -> Result<TimestampInfo> {
    let sd = parse_signed_data(token)?;
    if sd.econtent_type != ID_TST_INFO {
        bail!("timestamp token does not contain TSTInfo");
    }
    let tst = sd.econtent.as_deref().context("timestamp token has no content")?;
    let (info, _) = asn1::parse(tst)?;
    let f = info.children()?;
    let imprint = f.get(2).context("TSTInfo: missing message imprint")?.children()?;
    let alg_oid = imprint.first().context("imprint algorithm")?.children()?.first().context("imprint OID")?.oid()?;
    let imprint_alg = HashAlg::from_oid(&alg_oid).context("unsupported timestamp hash")?;
    let imprint = imprint.get(1).context("imprint value")?.octets()?;
    let time = x509::parse_time(f.get(4).context("TSTInfo: missing time")?)?;
    let signer = sd.signers.first().context("timestamp token has no signer")?;
    let digest = signer.digest()?;
    let check = check_signer(&sd, signer, &digest.digest(&[tst]));
    Ok(TimestampInfo { time, imprint_alg, imprint, check, certificates: sd.certificates.clone() })
}

/// The timestamp token attached to a signer, if any.
pub fn signature_timestamp<'a>(signer: &SignerInfo<'a>) -> Result<Option<&'a [u8]>> {
    match &signer.unsigned_attrs {
        Some(u) => Ok(attribute(u, ID_TIMESTAMP_TOKEN)?.map(|t| t.raw)),
        None => Ok(None),
    }
}

/// RFC 3161 request for a timestamp over a signature value.
pub fn timestamp_request(signature: &[u8], nonce: u64) -> Vec<u8> {
    let imprint = seq(&[&alg_id(HashAlg::Sha256.oid()), &octet_string(&Sha256::digest(signature))]);
    seq(&[&small_uint(1), &imprint, &small_uint(nonce), &[asn1::BOOLEAN, 1, 0xff]])
}

/// Extract the token from an RFC 3161 response and check it timestamps `signature`.
pub fn timestamp_from_response(response: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
    let (resp, _) = asn1::parse(response).context("timestamp server sent an invalid response")?;
    let f = resp.children()?;
    let status = f.first().context("timestamp response: missing status")?.children()?;
    let code = status.first().context("timestamp response: missing status code")?.small_uint()?;
    if code > 1 {
        let text = status
            .get(1)
            .filter(|t| t.tag == asn1::SEQUENCE)
            .and_then(|t| t.children().ok())
            .map(|v| v.iter().map(x509::decode_string).collect::<Vec<_>>().join("; "))
            .unwrap_or_default();
        bail!("the timestamp server refused the request (status {code}) {text}");
    }
    let token = f.get(1).context("timestamp response has no token")?.raw.to_vec();
    let info = parse_timestamp_token(&token)?;
    if !info.covers(&[signature]) {
        bail!("the timestamp server returned a token for different data");
    }
    if !info.is_valid() {
        bail!("the timestamp token's signature is invalid");
    }
    Ok(token)
}

// --- building ----------------------------------------------------------------

/// The signed attributes for a PAdES baseline signature, DER-encoded as a SET.
/// These bytes are what the private key signs.
pub fn signed_attributes(content_sha256: &[u8], signer: &Certificate) -> Vec<u8> {
    let content_type = seq(&[&oid(ID_CONTENT_TYPE), &set_of(vec![oid(ID_DATA)])]);
    let message_digest = seq(&[&oid(ID_MESSAGE_DIGEST), &set_of(vec![octet_string(content_sha256)])]);
    // ESSCertIDv2 { certHash, issuerSerial }, hashAlgorithm omitted because SHA-256 is the default.
    let general_names = seq(&[&tlv(ctx(4, true), &signer.issuer_raw)]);
    let issuer_serial = seq(&[&general_names, &signer.serial_raw]);
    let cert_id = seq(&[&octet_string(&Sha256::digest(&signer.der)), &issuer_serial]);
    let signing_cert = seq(&[&oid(ID_SIGNING_CERT_V2), &set_of(vec![seq(&[&seq(&[&cert_id])])])]);
    set_of(vec![content_type, message_digest, signing_cert])
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyKind {
    Rsa,
    Ec,
}

impl KeyKind {
    pub fn of(cert: &Certificate) -> Result<Self> {
        match cert.public_key.algorithm.as_str() {
            crypto::RSA_ENCRYPTION => Ok(KeyKind::Rsa),
            crypto::EC_PUBLIC_KEY => Ok(KeyKind::Ec),
            other => bail!("this certificate's key type ({other}) cannot sign PDFs here"),
        }
    }
}

/// Assemble the final ContentInfo from the signed attributes and the key's signature over them.
pub fn signed_data(
    signed_attrs: &[u8],
    signature: &[u8],
    signer: &Certificate,
    chain: &[Certificate],
    timestamp_token: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let sig_alg = match KeyKind::of(signer)? {
        KeyKind::Rsa => alg_id_null(crypto::SHA256_WITH_RSA),
        KeyKind::Ec => alg_id(crypto::ECDSA_WITH_SHA256),
    };
    let mut tagged_attrs = signed_attrs.to_vec();
    tagged_attrs[0] = ctx(0, true);
    let sid = seq(&[&signer.issuer_raw, &signer.serial_raw]);
    let mut parts = vec![small_uint(1), sid, alg_id(HashAlg::Sha256.oid()), tagged_attrs, sig_alg, octet_string(signature)];
    if let Some(token) = timestamp_token {
        let attr = seq(&[&oid(ID_TIMESTAMP_TOKEN), &set_of(vec![token.to_vec()])]);
        parts.push(tlv(ctx(1, true), &attr));
    }
    let signer_info = tlv(asn1::SEQUENCE, &parts.concat());

    let mut certs: Vec<Vec<u8>> = vec![signer.der.clone()];
    for c in chain {
        if !certs.contains(&c.der) {
            certs.push(c.der.clone());
        }
    }
    certs.sort();
    let sd = seq(&[
        &small_uint(1),
        &set_of(vec![alg_id(HashAlg::Sha256.oid())]),
        &seq(&[&oid(ID_DATA)]),
        &tlv(ctx(0, true), &certs.concat()),
        &set_of(vec![signer_info]),
    ]);
    Ok(seq(&[&oid(ID_SIGNED_DATA), &tlv(ctx(0, true), &sd)]))
}
