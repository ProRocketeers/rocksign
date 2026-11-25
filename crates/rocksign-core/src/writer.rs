//! Incremental updates: new and changed objects are appended after the original bytes, which
//! stay untouched, so every earlier signature keeps covering exactly what it signed.

use std::collections::{BTreeMap, HashMap};

use anyhow::{Context, Result, bail};
use lopdf::{Dictionary, Document, Object, ObjectId, StringFormat};

/// Serialize one object in PDF syntax.
pub fn serialize(obj: &Object) -> Vec<u8> {
    let mut out = Vec::new();
    write_object(&mut out, obj);
    out
}

pub fn write_object(out: &mut Vec<u8>, obj: &Object) {
    match obj {
        Object::Null => out.extend_from_slice(b"null"),
        Object::Boolean(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Object::Integer(i) => out.extend_from_slice(i.to_string().as_bytes()),
        Object::Real(r) => out.extend_from_slice(format_real(*r).as_bytes()),
        Object::Name(n) => write_name(out, n),
        Object::String(s, StringFormat::Hexadecimal) => {
            out.push(b'<');
            out.extend(hex(s).into_bytes());
            out.push(b'>');
        }
        Object::String(s, StringFormat::Literal) => {
            out.push(b'(');
            for &c in s {
                match c {
                    b'\\' | b'(' | b')' => out.extend_from_slice(&[b'\\', c]),
                    b'\r' => out.extend_from_slice(b"\\r"),
                    b'\n' => out.extend_from_slice(b"\\n"),
                    _ => out.push(c),
                }
            }
            out.push(b')');
        }
        Object::Array(a) => {
            out.push(b'[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                write_object(out, item);
            }
            out.push(b']');
        }
        Object::Dictionary(d) => write_dict(out, d),
        Object::Stream(s) => {
            let mut d = s.dict.clone();
            d.set("Length", Object::Integer(s.content.len() as i64));
            write_dict(out, &d);
            out.extend_from_slice(b"\nstream\n");
            out.extend_from_slice(&s.content);
            out.extend_from_slice(b"\nendstream");
        }
        Object::Reference((id, generation)) => out.extend_from_slice(format!("{id} {generation} R").as_bytes()),
    }
}

fn write_dict(out: &mut Vec<u8>, d: &Dictionary) {
    out.extend_from_slice(b"<<");
    for (k, v) in d.iter() {
        out.push(b' ');
        write_name(out, k);
        out.push(b' ');
        write_object(out, v);
    }
    out.extend_from_slice(b" >>");
}

fn write_name(out: &mut Vec<u8>, n: &[u8]) {
    out.push(b'/');
    for &c in n {
        if (0x21..=0x7e).contains(&c) && !b"()<>[]{}/%#".contains(&c) {
            out.push(c);
        } else {
            out.extend(format!("#{c:02X}").into_bytes());
        }
    }
}

pub fn format_real(r: f32) -> String {
    if !r.is_finite() {
        return "0".into();
    }
    if r.fract() == 0.0 && r.abs() < 1e9 {
        return format!("{}", r as i64);
    }
    let s = format!("{r:.4}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s == "-0" { "0".into() } else { s.to_string() }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Offset of the last cross-reference section, from the final `startxref`.
pub fn last_startxref(bytes: &[u8]) -> Result<usize> {
    let tail_start = bytes.len().saturating_sub(4096);
    let tail = &bytes[tail_start..];
    let pos = tail.windows(9).rposition(|w| w == b"startxref").context("the PDF has no startxref")?;
    let digits: String =
        tail[pos + 9..].iter().skip_while(|c| c.is_ascii_whitespace()).take_while(|c| c.is_ascii_digit()).map(|c| *c as char).collect();
    let off: usize = digits.parse().context("the PDF's startxref is unreadable")?;
    if off >= bytes.len() {
        bail!("the PDF's startxref points past the end of the file");
    }
    Ok(off)
}

pub struct Update<'a> {
    base: &'a [u8],
    next_id: u32,
    objects: BTreeMap<ObjectId, Vec<u8>>,
}

pub struct Written {
    pub bytes: Vec<u8>,
    /// Where each object's body starts (just after "n g obj\n").
    pub body_offsets: HashMap<ObjectId, usize>,
}

impl<'a> Update<'a> {
    pub fn new(base: &'a [u8], doc: &Document) -> Self {
        let size = doc.trailer.get(b"Size").ok().and_then(|s| s.as_i64().ok()).unwrap_or(0).max(0) as u32;
        Update { base, next_id: size.max(doc.max_id + 1), objects: BTreeMap::new() }
    }

    pub fn alloc(&mut self) -> ObjectId {
        let id = (self.next_id, 0);
        self.next_id += 1;
        id
    }

    pub fn set(&mut self, id: ObjectId, obj: &Object) {
        self.objects.insert(id, serialize(obj));
    }

    /// Set an object from already serialized bytes (used for the signature dictionary, whose
    /// placeholders are patched later).
    pub fn set_raw(&mut self, id: ObjectId, body: Vec<u8>) {
        self.objects.insert(id, body);
    }

    pub fn write(self, doc: &Document) -> Result<Written> {
        let prev = last_startxref(self.base)?;
        let at_prev = &self.base[prev..];
        let skip = at_prev.iter().take_while(|c| c.is_ascii_whitespace()).count();
        let xref_stream = !at_prev[skip..].starts_with(b"xref");

        let mut out = Vec::with_capacity(self.base.len() + self.objects.values().map(|b| b.len() + 32).sum::<usize>() + 512);
        out.extend_from_slice(self.base);
        if !matches!(out.last(), Some(b'\n' | b'\r')) {
            out.push(b'\n');
        }
        let mut entries: Vec<(u32, u16, usize)> = Vec::new();
        let mut body_offsets = HashMap::new();
        for (id, body) in &self.objects {
            entries.push((id.0, id.1, out.len()));
            out.extend(format!("{} {} obj\n", id.0, id.1).into_bytes());
            body_offsets.insert(*id, out.len());
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendobj\n");
        }

        let mut trailer = Dictionary::new();
        for key in [&b"Root"[..], b"Info", b"ID"] {
            if let Ok(v) = doc.trailer.get(key) {
                trailer.set(key, v.clone());
            }
        }
        trailer.set("Prev", Object::Integer(prev as i64));

        if xref_stream {
            let xref_id = self.next_id;
            let xref_offset = out.len();
            entries.push((xref_id, 0, xref_offset));
            entries.sort();
            let max_off = entries.iter().map(|e| e.2).max().unwrap_or(0) as u64;
            let width = (((64 - max_off.leading_zeros()) as usize).div_ceil(8)).max(1);
            let mut data = Vec::with_capacity(entries.len() * (width + 3));
            for (_, generation, off) in &entries {
                data.push(1u8);
                data.extend_from_slice(&(*off as u64).to_be_bytes()[8 - width..]);
                data.extend_from_slice(&generation.to_be_bytes());
            }
            let mut d = trailer;
            d.set("Type", Object::Name(b"XRef".to_vec()));
            d.set("Size", Object::Integer(xref_id as i64 + 1));
            d.set("W", Object::Array(vec![1.into(), (width as i64).into(), 2.into()]));
            d.set("Index", Object::Array(subsections(&entries).into_iter().flat_map(|(s, n)| [s.into(), n.into()]).collect()));
            out.extend(format!("{xref_id} 0 obj\n").into_bytes());
            write_object(&mut out, &Object::Stream(lopdf::Stream::new(d, data)));
            out.extend_from_slice(b"\nendobj\n");
            out.extend(format!("startxref\n{xref_offset}\n%%EOF\n").into_bytes());
        } else {
            entries.sort();
            let xref_offset = out.len();
            out.extend_from_slice(b"xref\n");
            let mut i = 0;
            for (start, count) in subsections(&entries) {
                out.extend(format!("{start} {count}\n").into_bytes());
                for (_, generation, off) in &entries[i..i + count as usize] {
                    out.extend(format!("{off:010} {generation:05} n\r\n").into_bytes());
                }
                i += count as usize;
            }
            trailer.set("Size", Object::Integer(self.next_id as i64));
            out.extend_from_slice(b"trailer\n");
            write_dict(&mut out, &trailer);
            out.extend(format!("\nstartxref\n{xref_offset}\n%%EOF\n").into_bytes());
        }
        Ok(Written { bytes: out, body_offsets })
    }
}

/// Runs of consecutive object numbers: (first, count).
fn subsections(sorted: &[(u32, u16, usize)]) -> Vec<(i64, i64)> {
    let mut out: Vec<(i64, i64)> = Vec::new();
    for (id, _, _) in sorted {
        match out.last_mut() {
            Some((start, count)) if *start + *count == *id as i64 => *count += 1,
            _ => out.push((*id as i64, 1)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reals_and_names() {
        assert_eq!(format_real(841.89), "841.89");
        assert_eq!(format_real(12.0), "12");
        assert_eq!(format_real(-0.00001), "0");
        assert_eq!(serialize(&Object::Name(b"A B#".to_vec())), b"/A#20B#23");
        assert_eq!(serialize(&Object::string_literal("a(b)\\")), b"(a\\(b\\)\\\\)");
    }

    #[test]
    fn subsection_runs() {
        let e = [(3, 0, 0), (4, 0, 0), (9, 0, 0)];
        assert_eq!(subsections(&e), vec![(3, 2), (9, 1)]);
    }
}
