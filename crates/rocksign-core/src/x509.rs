//! X.509 certificates: the fields the app shows, plus the raw parts CMS needs.

use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDate, Utc};
use sha2::{Digest, Sha256};

use crate::asn1::{self, Tlv};

pub const OID_CN: &str = "2.5.4.3";
pub const OID_O: &str = "2.5.4.10";
pub const OID_EMAIL: &str = "1.2.840.113549.1.9.1";

/// Key usage bits, as stored by [`Certificate::key_usage`].
pub const KU_DIGITAL_SIGNATURE: u16 = 0x8000;
pub const KU_NON_REPUDIATION: u16 = 0x4000;

/// Extended key usages that fit document signing.
const SIGNING_EKUS: &[&str] = &[
    "1.3.6.1.5.5.7.3.4",       // emailProtection (most personal certificates)
    "1.3.6.1.5.5.7.3.36",      // documentSigning
    "1.3.6.1.4.1.311.10.3.12", // Microsoft document signing
    "1.2.840.113583.1.1.5",    // Adobe Authentic Documents
    "2.5.29.37.0",             // anyExtendedKeyUsage
];

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DistinguishedName {
    /// (attribute OID, value) in encoding order (usually country first).
    pub attrs: Vec<(String, String)>,
}

impl DistinguishedName {
    pub fn get(&self, oid: &str) -> Option<&str> {
        self.attrs.iter().find(|(o, _)| o == oid).map(|(_, v)| v.as_str())
    }

    /// The most human name: common name, else organization, else anything.
    pub fn display_name(&self) -> String {
        self.get(OID_CN).or_else(|| self.get(OID_O)).or_else(|| self.attrs.last().map(|(_, v)| v.as_str())).unwrap_or("Unknown").to_string()
    }
}

impl std::fmt::Display for DistinguishedName {
    /// RFC 4514 order: most specific first ("CN=…, O=…, C=…").
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts: Vec<String> = self.attrs.iter().rev().map(|(oid, v)| format!("{}={}", attr_label(oid), v)).collect();
        f.write_str(&parts.join(", "))
    }
}

fn attr_label(oid: &str) -> String {
    match oid {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "street",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "title",
        "2.5.4.42" => "GN",
        "2.5.4.97" => "organizationIdentifier",
        "1.2.840.113549.1.9.1" => "E",
        "0.9.2342.19200300.100.1.25" => "DC",
        other => return other.to_string(),
    }
    .to_string()
}

#[derive(Clone, Debug)]
pub struct PublicKeyInfo {
    /// Algorithm OID: rsaEncryption, id-ecPublicKey, ...
    pub algorithm: String,
    /// Named curve for EC keys.
    pub curve: Option<String>,
    /// The subjectPublicKey bits (PKCS#1 RSAPublicKey or an EC point).
    pub key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Certificate {
    pub der: Vec<u8>,
    pub subject: DistinguishedName,
    pub issuer: DistinguishedName,
    /// Serial number magnitude (big-endian, no leading zeros).
    pub serial: Vec<u8>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub public_key: PublicKeyInfo,
    /// Key usage bits (`KU_*`), or None when the extension is absent.
    pub key_usage: Option<u16>,
    pub ext_key_usage: Vec<String>,
    pub is_ca: bool,
    pub subject_key_id: Option<Vec<u8>>,
    pub(crate) issuer_raw: Vec<u8>,
    pub(crate) subject_raw: Vec<u8>,
    pub(crate) serial_raw: Vec<u8>,
}

impl Certificate {
    pub fn parse(der: &[u8]) -> Result<Self> {
        let (cert, _) = asn1::parse(der).context("certificate")?;
        let cert = cert.expect(asn1::SEQUENCE)?;
        let parts = cert.children()?;
        let tbs = parts.first().context("certificate: missing tbsCertificate")?.children()?;
        let mut i = 0;
        if tbs.first().map(|t| t.tag) == Some(asn1::ctx(0, true)) {
            i += 1; // version
        }
        let serial_t = tbs.get(i).context("certificate: missing serial")?.expect(asn1::INTEGER)?;
        let issuer_t = tbs.get(i + 2).context("certificate: missing issuer")?;
        let validity = tbs.get(i + 3).context("certificate: missing validity")?.children()?;
        let subject_t = tbs.get(i + 4).context("certificate: missing subject")?;
        let spki = tbs.get(i + 5).context("certificate: missing public key")?.children()?;

        let alg = spki.first().context("certificate: missing key algorithm")?.children()?;
        let algorithm = alg.first().context("certificate: empty key algorithm")?.oid()?;
        let curve = alg.get(1).filter(|t| t.tag == asn1::OID).map(|t| t.oid()).transpose()?;
        let bits = spki.get(1).context("certificate: missing key")?.expect(asn1::BIT_STRING)?;
        let key = bits.content.get(1..).unwrap_or_default().to_vec();

        let mut key_usage = None;
        let mut ext_key_usage = Vec::new();
        let mut is_ca = false;
        let mut subject_key_id = None;
        if let Some(ext) = tbs[i + 6..].iter().find(|t| t.tag == asn1::ctx(3, true)) {
            let list = ext.children()?.first().context("certificate: empty extensions")?.children()?;
            for e in list {
                let fields = e.children()?;
                let id = fields.first().context("extension without OID")?.oid()?;
                let Some(value) = fields.iter().rev().find(|t| t.tag == asn1::OCTET_STRING) else { continue };
                let Ok((inner, _)) = asn1::parse(value.content) else { continue };
                match id.as_str() {
                    "2.5.29.15" if inner.tag == asn1::BIT_STRING => {
                        let b = inner.content;
                        let hi = *b.get(1).unwrap_or(&0) as u16;
                        let lo = *b.get(2).unwrap_or(&0) as u16;
                        key_usage = Some((hi << 8) | lo);
                    }
                    "2.5.29.37" => {
                        ext_key_usage = inner.children()?.iter().filter_map(|t| t.oid().ok()).collect();
                    }
                    "2.5.29.19" => {
                        is_ca = inner.children()?.first().is_some_and(|t| t.tag == asn1::BOOLEAN && t.content == [0xff]);
                    }
                    "2.5.29.14" if inner.tag == asn1::OCTET_STRING => subject_key_id = Some(inner.content.to_vec()),
                    _ => {}
                }
            }
        }

        Ok(Certificate {
            der: cert.raw.to_vec(),
            subject: parse_name(subject_t)?,
            issuer: parse_name(issuer_t)?,
            serial: serial_t.uint_bytes()?.to_vec(),
            not_before: parse_time(validity.first().context("certificate: missing notBefore")?)?,
            not_after: parse_time(validity.get(1).context("certificate: missing notAfter")?)?,
            public_key: PublicKeyInfo { algorithm, curve, key },
            key_usage,
            ext_key_usage,
            is_ca,
            subject_key_id,
            issuer_raw: issuer_t.raw.to_vec(),
            subject_raw: subject_t.raw.to_vec(),
            serial_raw: serial_t.raw.to_vec(),
        })
    }

    pub fn display_name(&self) -> String {
        self.subject.display_name()
    }

    pub fn sha256_fingerprint(&self) -> [u8; 32] {
        Sha256::digest(&self.der).into()
    }

    /// Uppercase hex with colons, like Keychain Access shows it.
    pub fn fingerprint_hex(&self) -> String {
        hex_colons(&self.sha256_fingerprint())
    }

    pub fn serial_hex(&self) -> String {
        hex_colons(&self.serial)
    }

    pub fn is_self_issued(&self) -> bool {
        self.issuer_raw == self.subject_raw
    }

    pub fn is_valid_at(&self, t: DateTime<Utc>) -> bool {
        self.not_before <= t && t <= self.not_after
    }

    /// Whether this certificate is meant for signing documents (not a CA, not a code-signing
    /// or TLS-only certificate).
    pub fn fits_document_signing(&self) -> bool {
        if self.is_ca {
            return false;
        }
        if let Some(ku) = self.key_usage
            && ku & (KU_DIGITAL_SIGNATURE | KU_NON_REPUDIATION) == 0
        {
            return false;
        }
        self.ext_key_usage.is_empty() || self.ext_key_usage.iter().any(|e| SIGNING_EKUS.contains(&e.as_str()))
    }

    pub fn key_description(&self) -> String {
        match self.public_key.algorithm.as_str() {
            "1.2.840.113549.1.1.1" => {
                let bits = crate::crypto::rsa_modulus_bits(&self.public_key.key).unwrap_or(0);
                format!("RSA {bits}")
            }
            "1.2.840.10045.2.1" => match self.public_key.curve.as_deref() {
                Some("1.2.840.10045.3.1.7") => "ECDSA P-256".into(),
                Some("1.3.132.0.34") => "ECDSA P-384".into(),
                Some("1.3.132.0.35") => "ECDSA P-521".into(),
                _ => "ECDSA".into(),
            },
            other => other.to_string(),
        }
    }
}

pub fn hex_colons(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// A Name from its encoding; names written with different string types compare by value.
pub(crate) fn parse_name_raw(raw: &[u8]) -> Option<DistinguishedName> {
    parse_name(&asn1::parse(raw).ok()?.0).ok()
}

fn parse_name(t: &Tlv) -> Result<DistinguishedName> {
    let mut attrs = Vec::new();
    for rdn in t.expect(asn1::SEQUENCE)?.children()? {
        for atv in rdn.children()? {
            let f = atv.children()?;
            let (Some(o), Some(v)) = (f.first(), f.get(1)) else { continue };
            attrs.push((o.oid()?, decode_string(v)));
        }
    }
    Ok(DistinguishedName { attrs })
}

/// Text of an ASN.1 string of any of the types used in names.
pub fn decode_string(v: &Tlv) -> String {
    match v.tag {
        asn1::BMP_STRING => {
            let units: Vec<u16> = v.content.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&units)
        }
        asn1::UNIVERSAL_STRING => v.content.chunks_exact(4).filter_map(|c| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]]))).collect(),
        asn1::TELETEX_STRING => match std::str::from_utf8(v.content) {
            Ok(s) => s.to_string(),
            Err(_) => v.content.iter().map(|b| *b as char).collect(),
        },
        _ => String::from_utf8_lossy(v.content).into_owned(),
    }
}

/// UTCTime or GeneralizedTime.
pub fn parse_time(t: &Tlv) -> Result<DateTime<Utc>> {
    let s = std::str::from_utf8(t.content).context("time is not ASCII")?;
    let full = match t.tag {
        asn1::UTC_TIME => {
            let yy: i32 = s.get(0..2).context("short UTCTime")?.parse()?;
            format!("{}{}", if yy >= 50 { 19 } else { 20 }, s)
        }
        asn1::GENERALIZED_TIME => s.to_string(),
        tag => bail!("expected a time, got tag {tag:#04x}"),
    };
    parse_generalized(&full)
}

/// "YYYYMMDDHHMM[SS][.fff](Z|±HHMM)"
pub fn parse_generalized(s: &str) -> Result<DateTime<Utc>> {
    let num = |a: usize, b: usize| -> Result<u32> { Ok(s.get(a..b).context("time too short")?.parse()?) };
    let date = NaiveDate::from_ymd_opt(num(0, 4)? as i32, num(4, 6)?, num(6, 8)?).context("bad date")?;
    let (h, m) = (num(8, 10)?, num(10, 12)?);
    let mut pos = 12;
    let mut sec = 0;
    if s.len() >= 14 && s.as_bytes()[12].is_ascii_digit() {
        sec = num(12, 14)?;
        pos = 14;
    }
    let mut nanos = 0;
    if s.as_bytes().get(pos) == Some(&b'.') {
        let digits: String = s[pos + 1..].chars().take_while(|c| c.is_ascii_digit()).collect();
        pos += 1 + digits.len();
        let frac = format!("{digits:0<9}");
        nanos = frac[..9].parse().unwrap_or(0);
    }
    let naive = date.and_hms_nano_opt(h, m, sec.min(59), nanos).context("bad time")?;
    let offset_secs = match s.as_bytes().get(pos) {
        None | Some(b'Z') => 0,
        Some(sign @ (b'+' | b'-')) => {
            let oh = num(pos + 1, pos + 3)? as i64;
            let om = s.get(pos + 3..pos + 5).and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
            let total = oh * 3600 + om * 60;
            if *sign == b'+' { total } else { -total }
        }
        _ => bail!("bad time zone in {s}"),
    };
    Ok(naive.and_utc() - chrono::Duration::seconds(offset_secs))
}

/// All certificates in a PEM text ("-----BEGIN CERTIFICATE-----" blocks).
pub fn certificates_from_pem(text: &str) -> Result<Vec<Certificate>> {
    let mut out = Vec::new();
    for block in text.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let body = block.split("-----END").next().unwrap_or_default();
        out.push(Certificate::parse(&base64_decode(body)?)?);
    }
    Ok(out)
}

/// Standard base64, ignoring whitespace and padding.
pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=') {
        let v = T.iter().position(|t| *t == c).context("invalid base64")? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}
