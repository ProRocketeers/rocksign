//! A small ASN.1 reader and writer, just enough for CMS signatures and X.509 certificates.
//!
//! The reader accepts BER indefinite lengths, which some real-world PDF signers use for the
//! outer CMS containers. It returns slices of the input, so signed data can be checked byte for
//! byte. The writer produces DER.

use anyhow::{Result, anyhow, bail};

pub const BOOLEAN: u8 = 0x01;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;
pub const UTF8_STRING: u8 = 0x0c;
pub const PRINTABLE_STRING: u8 = 0x13;
pub const TELETEX_STRING: u8 = 0x14;
pub const IA5_STRING: u8 = 0x16;
pub const UTC_TIME: u8 = 0x17;
pub const GENERALIZED_TIME: u8 = 0x18;
pub const UNIVERSAL_STRING: u8 = 0x1c;
pub const BMP_STRING: u8 = 0x1e;
pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;

/// Context-specific tag `[n]`.
pub const fn ctx(n: u8, constructed: bool) -> u8 {
    0x80 | if constructed { 0x20 } else { 0 } | n
}

/// One parsed element.
#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    pub tag: u8,
    /// The value octets. For an indefinite length this excludes the end-of-contents marker.
    pub content: &'a [u8],
    /// The whole element: header, value and (for indefinite lengths) the end-of-contents marker.
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn children(&self) -> Result<Vec<Tlv<'a>>> {
        if self.tag & 0x20 == 0 {
            bail!("ASN.1: expected a constructed element, got tag {:#04x}", self.tag);
        }
        parse_all(self.content)
    }

    pub fn expect(self, tag: u8) -> Result<Self> {
        if self.tag != tag {
            bail!("ASN.1: expected tag {tag:#04x}, got {:#04x}", self.tag);
        }
        Ok(self)
    }

    /// Dotted form of an OBJECT IDENTIFIER.
    pub fn oid(&self) -> Result<String> {
        if self.tag != OID {
            bail!("ASN.1: expected an OID, got tag {:#04x}", self.tag);
        }
        oid_to_string(self.content)
    }

    /// Bytes of an OCTET STRING, joining the pieces of a BER constructed string.
    pub fn octets(&self) -> Result<Vec<u8>> {
        match self.tag {
            OCTET_STRING => Ok(self.content.to_vec()),
            t if t == OCTET_STRING | 0x20 => {
                let mut out = Vec::new();
                for c in self.children()? {
                    out.extend(c.octets()?);
                }
                Ok(out)
            }
            t => bail!("ASN.1: expected an OCTET STRING, got tag {t:#04x}"),
        }
    }

    /// INTEGER value as an unsigned big-endian number without leading zeros.
    pub fn uint_bytes(&self) -> Result<&'a [u8]> {
        if self.tag != INTEGER {
            bail!("ASN.1: expected an INTEGER, got tag {:#04x}", self.tag);
        }
        let mut c = self.content;
        while c.len() > 1 && c[0] == 0 {
            c = &c[1..];
        }
        Ok(c)
    }

    pub fn small_uint(&self) -> Result<u64> {
        let b = self.uint_bytes()?;
        if b.len() > 8 {
            bail!("ASN.1: integer too large");
        }
        Ok(b.iter().fold(0u64, |acc, x| (acc << 8) | *x as u64))
    }
}

/// Parse one element from the start of `data`; returns it and the remaining bytes.
pub fn parse(data: &[u8]) -> Result<(Tlv<'_>, &[u8])> {
    if data.len() < 2 {
        bail!("ASN.1: truncated data");
    }
    let tag = data[0];
    if tag & 0x1f == 0x1f {
        bail!("ASN.1: high tag numbers are not supported");
    }
    let first = data[1];
    if first == 0x80 {
        if tag & 0x20 == 0 {
            bail!("ASN.1: indefinite length on a primitive element");
        }
        let mut rest = &data[2..];
        loop {
            if rest.len() >= 2 && rest[0] == 0 && rest[1] == 0 {
                break;
            }
            if rest.is_empty() {
                bail!("ASN.1: missing end-of-contents marker");
            }
            rest = parse(rest)?.1;
        }
        let content_len = data.len() - 2 - rest.len();
        let total = 2 + content_len + 2;
        return Ok((Tlv { tag, content: &data[2..2 + content_len], raw: &data[..total] }, &data[total..]));
    }
    let (len, header) = if first & 0x80 == 0 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || data.len() < 2 + n {
            bail!("ASN.1: bad length");
        }
        (data[2..2 + n].iter().fold(0usize, |acc, b| (acc << 8) | *b as usize), 2 + n)
    };
    let end = header.checked_add(len).filter(|&e| e <= data.len()).ok_or_else(|| anyhow!("ASN.1: element runs past the end of the data"))?;
    Ok((Tlv { tag, content: &data[header..end], raw: &data[..end] }, &data[end..]))
}

pub fn parse_all(mut data: &[u8]) -> Result<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let (t, rest) = parse(data)?;
        out.push(t);
        data = rest;
    }
    Ok(out)
}

pub fn oid_to_string(content: &[u8]) -> Result<String> {
    if content.is_empty() {
        bail!("ASN.1: empty OID");
    }
    let mut arcs: Vec<u64> = Vec::new();
    let mut value: u64 = 0;
    for (i, b) in content.iter().enumerate() {
        value = value.checked_mul(128).ok_or_else(|| anyhow!("ASN.1: OID arc too large"))? | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            if arcs.is_empty() {
                let (a, b) = if value < 40 {
                    (0, value)
                } else if value < 80 {
                    (1, value - 40)
                } else {
                    (2, value - 80)
                };
                arcs.push(a);
                arcs.push(b);
            } else {
                arcs.push(value);
            }
            value = 0;
        } else if i == content.len() - 1 {
            bail!("ASN.1: truncated OID");
        }
    }
    Ok(arcs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join("."))
}

// --- writer ------------------------------------------------------------------

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = (len as u64).to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (8 - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(SEQUENCE, &parts.concat())
}

/// DER SET OF: elements sorted by their encoding.
pub fn set_of(mut parts: Vec<Vec<u8>>) -> Vec<u8> {
    parts.sort();
    tlv(SET, &parts.concat())
}

pub fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').map(|a| a.parse().expect("valid OID literal")).collect();
    let mut content = Vec::new();
    let mut push = |mut v: u64| {
        let mut tmp = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            tmp.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        tmp.reverse();
        content.extend(tmp);
    };
    push(arcs[0] * 40 + arcs[1]);
    for a in &arcs[2..] {
        push(*a);
    }
    tlv(OID, &content)
}

pub fn octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, bytes)
}

pub fn null() -> Vec<u8> {
    vec![NULL, 0]
}

/// Non-negative INTEGER from big-endian magnitude bytes.
pub fn uint(magnitude: &[u8]) -> Vec<u8> {
    let mut m: &[u8] = magnitude;
    while m.len() > 1 && m[0] == 0 {
        m = &m[1..];
    }
    let mut content = Vec::with_capacity(m.len() + 1);
    if m.is_empty() || m[0] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(m);
    tlv(INTEGER, &content)
}

pub fn small_uint(n: u64) -> Vec<u8> {
    uint(&n.to_be_bytes())
}

/// AlgorithmIdentifier with no parameters.
pub fn alg_id(dotted: &str) -> Vec<u8> {
    seq(&[&oid(dotted)])
}

/// AlgorithmIdentifier with NULL parameters (RSA algorithms).
pub fn alg_id_null(dotted: &str) -> Vec<u8> {
    seq(&[&oid(dotted), &null()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_roundtrip() {
        for o in ["1.2.840.113549.1.7.2", "2.16.840.1.101.3.4.2.1", "1.3.6.1.5.5.7.3.36", "2.5.4.3"] {
            let enc = oid(o);
            let (t, rest) = parse(&enc).unwrap();
            assert!(rest.is_empty());
            assert_eq!(t.oid().unwrap(), o);
        }
    }

    #[test]
    fn long_lengths_and_indefinite() {
        let big = vec![7u8; 300];
        let enc = seq(&[&octet_string(&big)]);
        let (t, _) = parse(&enc).unwrap();
        assert_eq!(t.children().unwrap()[0].octets().unwrap(), big);

        // BER: SEQUENCE (indefinite) { constructed OCTET STRING (indefinite) { "ab", "c" } }
        let ber = [0x30, 0x80, 0x24, 0x80, 0x04, 0x02, b'a', b'b', 0x04, 0x01, b'c', 0, 0, 0, 0, 0xff];
        let (t, rest) = parse(&ber).unwrap();
        assert_eq!(rest, &[0xff]);
        assert_eq!(t.children().unwrap()[0].octets().unwrap(), b"abc");
    }

    #[test]
    fn integers() {
        assert_eq!(uint(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(small_uint(0), vec![0x02, 0x01, 0x00]);
        let enc = small_uint(65537);
        let (t, _) = parse(&enc).unwrap();
        assert_eq!(t.small_uint().unwrap(), 65537);
    }
}
