//! Reading the parts of a PDF that signing cares about: page geometry, signature fields and
//! their signature dictionaries, encryption and certification (DocMDP) permissions.

use std::collections::{HashMap, HashSet};

use anyhow::{Result, anyhow};
use chrono::{DateTime, FixedOffset, NaiveDate, TimeZone};
use lopdf::{Dictionary, Document, Object, ObjectId};

/// Geometry of one page. User space is the PDF coordinate system (origin bottom-left,
/// unrotated); view space is how the page is shown (origin top-left, rotation applied), in points.
#[derive(Clone, Debug)]
pub struct PageGeom {
    pub id: ObjectId,
    /// Visible area in user space: [x0, y0, x1, y1].
    pub crop: [f32; 4],
    /// Clockwise rotation when shown: 0, 90, 180 or 270.
    pub rotate: u16,
}

impl PageGeom {
    pub fn width(&self) -> f32 {
        self.crop[2] - self.crop[0]
    }

    pub fn height(&self) -> f32 {
        self.crop[3] - self.crop[1]
    }

    /// Size as shown, in points.
    pub fn view_size(&self) -> (f32, f32) {
        if self.rotate % 180 == 90 { (self.height(), self.width()) } else { (self.width(), self.height()) }
    }

    pub fn view_to_user(&self, u: f32, v: f32) -> (f32, f32) {
        let [x0, y0, x1, y1] = self.crop;
        match self.rotate {
            90 => (x0 + v, y0 + u),
            180 => (x1 - u, y0 + v),
            270 => (x1 - v, y1 - u),
            _ => (x0 + u, y1 - v),
        }
    }

    pub fn user_to_view(&self, x: f32, y: f32) -> (f32, f32) {
        let [x0, y0, x1, y1] = self.crop;
        match self.rotate {
            90 => (y - y0, x - x0),
            180 => (x1 - x, y - y0),
            270 => (y1 - y, x1 - x),
            _ => (x - x0, y1 - y),
        }
    }

    /// User-space rect [x0 y0 x1 y1] to view [left, top, right, bottom].
    pub fn user_rect_to_view(&self, r: [f32; 4]) -> [f32; 4] {
        let (a, b) = self.user_to_view(r[0], r[1]);
        let (c, d) = self.user_to_view(r[2], r[3]);
        [a.min(c), b.min(d), a.max(c), b.max(d)]
    }

    /// View [left, top, right, bottom] to a normalized user-space rect.
    pub fn view_rect_to_user(&self, r: [f32; 4]) -> [f32; 4] {
        let (a, b) = self.view_to_user(r[0], r[1]);
        let (c, d) = self.view_to_user(r[2], r[3]);
        [a.min(c), b.min(d), a.max(c), b.max(d)]
    }
}

/// A signature form field, signed or not.
#[derive(Clone, Debug)]
pub struct SigField {
    /// Fully qualified field name.
    pub name: String,
    pub field_id: Option<ObjectId>,
    pub widget_id: Option<ObjectId>,
    /// Page index (0-based).
    pub page: Option<usize>,
    /// Widget rectangle in user space; zero-sized for invisible signatures.
    pub rect: Option<[f32; 4]>,
    /// The signature dictionary (/V), when signed.
    pub sig: Option<Dictionary>,
}

impl SigField {
    pub fn is_visible(&self) -> bool {
        self.rect.is_some_and(|r| r[2] - r[0] > 1.0 && r[3] - r[1] > 1.0)
    }
}

pub struct Pdf {
    pub doc: Document,
    pub pages: Vec<PageGeom>,
    pub fields: Vec<SigField>,
    pub encrypted: bool,
    /// DocMDP permission (1–3) when the document carries a certification signature.
    pub certification: Option<u8>,
}

impl Pdf {
    pub fn parse(bytes: &[u8]) -> Result<Pdf> {
        let doc = Document::load_mem(bytes).map_err(|e| anyhow!("This file is not a readable PDF ({e})"))?;
        let encrypted = doc.trailer.get(b"Encrypt").is_ok();

        let page_ids: Vec<ObjectId> = doc.get_pages().into_values().collect();
        let page_index: HashMap<ObjectId, usize> = page_ids.iter().enumerate().map(|(i, id)| (*id, i)).collect();
        let pages = page_ids.iter().map(|id| page_geom(&doc, *id)).collect();

        let mut annot_page = HashMap::new();
        for (i, id) in page_ids.iter().enumerate() {
            if let Some(Object::Dictionary(page)) = doc.objects.get(id) {
                for a in array(&doc, page.get(b"Annots").ok()) {
                    if let Object::Reference(r) = a {
                        annot_page.insert(*r, i);
                    }
                }
            }
        }

        let mut fields = Vec::new();
        let ctx = WalkCtx { doc: &doc, annot_page: &annot_page, page_index: &page_index };
        if let Some(form) = catalog(&doc).and_then(|c| dict(&doc, c.get(b"AcroForm").ok())) {
            let mut seen = HashSet::new();
            for f in array(&doc, form.get(b"Fields").ok()) {
                ctx.walk(f, "", None, &mut fields, &mut seen, 0);
            }
        }

        // Signature dictionaries that no form field points to (seen in damaged files).
        let known: HashSet<Vec<u8>> = fields.iter().filter_map(|f| f.sig.as_ref()).filter_map(contents).collect();
        let mut orphans = 0;
        for obj in doc.objects.values() {
            if let Object::Dictionary(d) = obj {
                let is_sig = matches!(name(d.get(b"Type").ok()), Some(b"Sig" | b"DocTimeStamp"));
                if is_sig
                    && d.has(b"ByteRange")
                    && let Some(c) = contents(d)
                    && !known.contains(&c)
                {
                    orphans += 1;
                    fields.push(SigField {
                        name: format!("Unlisted signature {orphans}"),
                        field_id: None,
                        widget_id: None,
                        page: None,
                        rect: None,
                        sig: Some(d.clone()),
                    });
                }
            }
        }

        let certification = catalog(&doc)
            .and_then(|c| dict(&doc, c.get(b"Perms").ok()))
            .and_then(|p| dict(&doc, p.get(b"DocMDP").ok()))
            .and_then(|sig| docmdp_permission(&doc, sig));

        Ok(Pdf { doc, pages, fields, encrypted, certification })
    }
}

struct WalkCtx<'a> {
    doc: &'a Document,
    annot_page: &'a HashMap<ObjectId, usize>,
    page_index: &'a HashMap<ObjectId, usize>,
}

impl WalkCtx<'_> {
    fn walk(&self, node: &Object, parent: &str, inherited_ft: Option<Vec<u8>>, out: &mut Vec<SigField>, seen: &mut HashSet<ObjectId>, depth: usize) {
        let id = match node {
            Object::Reference(r) => {
                if !seen.insert(*r) {
                    return;
                }
                Some(*r)
            }
            _ => None,
        };
        let Some(d) = dict(self.doc, Some(node)) else { return };
        if depth > 32 {
            return;
        }
        let full = match d.get(b"T").ok().and_then(|t| text(self.doc, t)) {
            Some(t) if parent.is_empty() => t,
            Some(t) => format!("{parent}.{t}"),
            None => parent.to_string(),
        };
        let ft = name(d.get(b"FT").ok()).map(|n| n.to_vec()).or(inherited_ft);
        let is_sig = ft.as_deref() == Some(b"Sig");
        let kids = array(self.doc, d.get(b"Kids").ok());
        if kids.is_empty() {
            if is_sig {
                out.push(self.field(full, id, d, id, d));
            }
            return;
        }
        let mut widget = None;
        for k in kids {
            let Some(kd) = dict(self.doc, Some(k)) else { continue };
            if kd.has(b"T") {
                self.walk(k, &full, ft.clone(), out, seen, depth + 1);
            } else if widget.is_none() {
                widget = Some((k.as_reference().ok(), kd));
            }
        }
        if is_sig {
            match widget {
                Some((wid, wd)) => out.push(self.field(full, id, d, wid, wd)),
                None => out.push(self.field(full, id, d, None, d)),
            }
        }
    }

    fn field(&self, name: String, field_id: Option<ObjectId>, field: &Dictionary, widget_id: Option<ObjectId>, widget: &Dictionary) -> SigField {
        let page = widget_id
            .and_then(|w| self.annot_page.get(&w).copied())
            .or_else(|| widget.get(b"P").ok().and_then(|p| p.as_reference().ok()).and_then(|p| self.page_index.get(&p).copied()));
        SigField {
            name,
            field_id,
            widget_id,
            page,
            rect: rect(self.doc, widget.get(b"Rect").ok()),
            sig: dict(self.doc, field.get(b"V").ok()).cloned(),
        }
    }
}

fn page_geom(doc: &Document, id: ObjectId) -> PageGeom {
    let inherited = |key: &[u8]| -> Option<&Object> {
        let mut cur = doc.objects.get(&id).and_then(|o| o.as_dict().ok());
        for _ in 0..64 {
            let d = cur?;
            if let Ok(v) = d.get(key) {
                return Some(v);
            }
            cur = dict(doc, d.get(b"Parent").ok());
        }
        None
    };
    let media = inherited(b"MediaBox").and_then(|o| rect(doc, Some(o))).unwrap_or([0.0, 0.0, 612.0, 792.0]);
    let crop = inherited(b"CropBox")
        .and_then(|o| rect(doc, Some(o)))
        .map(|c| [c[0].max(media[0]), c[1].max(media[1]), c[2].min(media[2]), c[3].min(media[3])])
        .filter(|c| c[2] > c[0] && c[3] > c[1])
        .unwrap_or(media);
    let rotate = inherited(b"Rotate").and_then(|o| number(doc, o)).unwrap_or(0.0) as i64;
    let rotate = (((rotate % 360) + 360) % 360 / 90 * 90) as u16;
    PageGeom { id, crop, rotate }
}

/// DocMDP /P value of a certification signature dictionary.
pub fn docmdp_permission(doc: &Document, sig: &Dictionary) -> Option<u8> {
    for r in array(doc, sig.get(b"Reference").ok()) {
        let Some(rd) = dict(doc, Some(r)) else { continue };
        if name(rd.get(b"TransformMethod").ok()) == Some(b"DocMDP") {
            let p = dict(doc, rd.get(b"TransformParams").ok()).and_then(|tp| tp.get(b"P").ok()).and_then(|p| number(doc, p)).unwrap_or(2.0);
            return Some(p.clamp(1.0, 3.0) as u8);
        }
    }
    None
}

// --- object helpers ----------------------------------------------------------

pub fn deref<'a>(doc: &'a Document, mut obj: &'a Object) -> &'a Object {
    for _ in 0..32 {
        match obj {
            Object::Reference(id) => match doc.objects.get(id) {
                Some(o) => obj = o,
                None => return &Object::Null,
            },
            _ => return obj,
        }
    }
    &Object::Null
}

pub fn catalog(doc: &Document) -> Option<&Dictionary> {
    dict(doc, doc.trailer.get(b"Root").ok())
}

pub fn dict<'a>(doc: &'a Document, obj: Option<&'a Object>) -> Option<&'a Dictionary> {
    match deref(doc, obj?) {
        Object::Dictionary(d) => Some(d),
        Object::Stream(s) => Some(&s.dict),
        _ => None,
    }
}

pub fn array<'a>(doc: &'a Document, obj: Option<&'a Object>) -> &'a [Object] {
    match obj.map(|o| deref(doc, o)) {
        Some(Object::Array(a)) => a,
        _ => &[],
    }
}

pub fn name(obj: Option<&Object>) -> Option<&[u8]> {
    match obj? {
        Object::Name(n) => Some(n),
        _ => None,
    }
}

pub fn number(doc: &Document, obj: &Object) -> Option<f32> {
    match deref(doc, obj) {
        Object::Integer(i) => Some(*i as f32),
        Object::Real(r) => Some(*r),
        _ => None,
    }
}

pub fn rect(doc: &Document, obj: Option<&Object>) -> Option<[f32; 4]> {
    let a = array(doc, obj);
    if a.len() != 4 {
        return None;
    }
    let v: Vec<f32> = a.iter().filter_map(|o| number(doc, o)).collect();
    if v.len() != 4 {
        return None;
    }
    Some([v[0].min(v[2]), v[1].min(v[3]), v[0].max(v[2]), v[1].max(v[3])])
}

/// Raw bytes of a signature dictionary's /Contents.
pub fn contents(sig: &Dictionary) -> Option<Vec<u8>> {
    match sig.get(b"Contents").ok()? {
        Object::String(s, _) => Some(s.clone()),
        _ => None,
    }
}

/// A PDF text string: UTF-16BE or UTF-8 with a byte order mark, else PDFDocEncoding.
pub fn text(doc: &Document, obj: &Object) -> Option<String> {
    let Object::String(b, _) = deref(doc, obj) else { return None };
    Some(decode_text(b))
}

pub fn decode_text(b: &[u8]) -> String {
    if b.starts_with(&[0xfe, 0xff]) {
        let units: Vec<u16> = b[2..].chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        return String::from_utf16_lossy(&units);
    }
    if b.starts_with(&[0xef, 0xbb, 0xbf]) {
        return String::from_utf8_lossy(&b[3..]).into_owned();
    }
    const HIGH: [char; 33] = [
        '•', '†', '‡', '…', '—', '–', 'ƒ', '⁄', '‹', '›', '−', '‰', '„', '“', '”', '‘', '’', '‚', '™', 'ﬁ', 'ﬂ', 'Ł', 'Œ', 'Š', 'Ÿ', 'Ž', 'ı', 'ł',
        'œ', 'š', 'ž', '\u{fffd}', '€',
    ];
    b.iter()
        .map(|&c| match c {
            0x80..=0xa0 => HIGH[(c - 0x80) as usize],
            _ => c as char,
        })
        .collect()
}

/// Encode text for a PDF string: plain when ASCII, otherwise UTF-16BE with a byte order mark.
pub fn encode_text(s: &str) -> Object {
    if s.chars().all(|c| (' '..='~').contains(&c)) {
        Object::String(s.as_bytes().to_vec(), lopdf::StringFormat::Literal)
    } else {
        let mut b = vec![0xfe, 0xff];
        for u in s.encode_utf16() {
            b.extend(u.to_be_bytes());
        }
        Object::String(b, lopdf::StringFormat::Hexadecimal)
    }
}

/// "D:YYYYMMDDHHmmSS+HH'mm'"
pub fn format_date(t: &DateTime<FixedOffset>) -> String {
    let off = t.offset().local_minus_utc();
    let sign = if off < 0 { '-' } else { '+' };
    let off = off.abs();
    format!("D:{}{}{:02}'{:02}'", t.format("%Y%m%d%H%M%S"), sign, off / 3600, (off % 3600) / 60)
}

pub fn parse_date(s: &str) -> Option<DateTime<FixedOffset>> {
    let s = s.trim().strip_prefix("D:").unwrap_or(s.trim());
    let digits = |a: usize, b: usize, default: u32| -> u32 { s.get(a..b).and_then(|v| v.parse().ok()).unwrap_or(default) };
    let year = s.get(0..4)?.parse::<i32>().ok()?;
    let date = NaiveDate::from_ymd_opt(year, digits(4, 6, 1), digits(6, 8, 1))?;
    let naive = date.and_hms_opt(digits(8, 10, 0), digits(10, 12, 0), digits(12, 14, 0).min(59))?;
    let rest: String = s.chars().skip_while(|c| c.is_ascii_digit()).collect();
    let offset = match rest.chars().next() {
        Some(sign @ ('+' | '-')) => {
            let nums: Vec<i32> = rest[1..].split(|c: char| !c.is_ascii_digit()).filter(|p| !p.is_empty()).filter_map(|p| p.parse().ok()).collect();
            let secs = nums.first().copied().unwrap_or(0) * 3600 + nums.get(1).copied().unwrap_or(0) * 60;
            if sign == '-' { -secs } else { secs }
        }
        _ => 0,
    };
    FixedOffset::east_opt(offset)?.from_local_datetime(&naive).single()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_roundtrip() {
        for rotate in [0, 90, 180, 270] {
            let p = PageGeom { id: (1, 0), crop: [10.0, 20.0, 610.0, 820.0], rotate };
            let (u, v) = (50.0, 70.0);
            let (x, y) = p.view_to_user(u, v);
            let (u2, v2) = p.user_to_view(x, y);
            assert!((u - u2).abs() < 1e-3 && (v - v2).abs() < 1e-3, "rotate {rotate}");
        }
        let p = PageGeom { id: (1, 0), crop: [0.0, 0.0, 600.0, 800.0], rotate: 0 };
        assert_eq!(p.view_rect_to_user([10.0, 10.0, 110.0, 60.0]), [10.0, 740.0, 110.0, 790.0]);
    }

    #[test]
    fn dates() {
        let d = parse_date("D:20261124123005+01'00'").unwrap();
        assert_eq!(format_date(&d), "D:20261124123005+01'00'");
        assert!(parse_date("D:2026").is_some());
    }

    #[test]
    fn text_strings() {
        let enc = encode_text("Jiří Dvořák");
        let Object::String(b, _) = &enc else { panic!() };
        assert_eq!(decode_text(b), "Jiří Dvořák");
        assert_eq!(decode_text(b"Plain"), "Plain");
    }
}
